"""Core hub-service types and the Service class.

Port of hub-service (TS reference). The wire contract matches the TS/Go
reference — hub/profile/update and hub/service/update are re-sent on every
(re)connect (the hub drops services on disconnect). Auth follows
Docs/Devices/protocol.md: v0 tokens until the hub key is pinned from
hub/info, hub-bound v1 tokens after that.
"""

from __future__ import annotations

import asyncio
import inspect
import os
import sys
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Awaitable, Callable

from channel_py.channel import Channel
from channel_py.client import ConnectOptions, connect_channel

from hub_service_py import keychain
from hub_service_py.device import Device
from hub_service_py.network import NetworkPublisher


class ServiceNotStartedError(RuntimeError):
    """Raised by send/values before start() has connected to the hub."""


@dataclass
class ServiceOptions:
    """Options for Service.

    address: a port (int) or a ws:// URL (string). Default: 1997 or $HUB.
    name:    profile name shown in the hub.
    icon:    profile icon: a string or {"symbol": ..., "text": ...}.
    hub_key: the hub's key when known up front (an invitation or config);
             otherwise it is learned from hub/info and pinned.
    instance: this service's name on its device, unique per device
             (``s3-local/Backup Disk``). Default: ``HUB_INSTANCE``, else
             name, else the cwd name, else ``service``.
    device:  True (default) certifies the service with this device's key
             (``~/.hub/device.key`` or ``HUB_DEVICE_KEY``) when it can be
             read or created; False sends no ``device`` header; a Device
             uses that device (and its key or key store).
    """

    address: int | str | None = None
    name: str | None = None
    icon: Any = None
    hub_key: str | None = None
    instance: str | None = None
    device: "bool | Device" = True


@dataclass
class Profile:
    """Sent to the hub as hub/profile/update on connect (only if set)."""

    name: str | None = None
    icon: Any = None


@dataclass
class AppHeader:
    """Identifies an app in the hub apps list."""

    type: str = "app"
    name: str = ""
    path: str = ""


@dataclass
class ServicePermissions:
    """Pro-only wire-parity field; hub-lite ignores it."""

    group: str | None = None
    name: str | None = None
    allows: bool | None = None


@dataclass
class ApiSettings:
    """Settings for a registered API path (pro-only fields, wire parity)."""

    permissions: ServicePermissions | None = None
    limit: int | None = None


@dataclass
class CallerDevice:
    """The caller's device, when its connection is device-attached."""

    id: str
    name: str


@dataclass
class Caller:
    """Who is calling, as the hub saw it (``context.hub.caller``).

    key:     the caller's SPKI; None for anonymous callers.
    device:  the caller's device; None for clients without one.
    groups:  every group the key or its device belongs to.
    owner:   whether the caller is in the owners group.
    via:     the merged hub's key, for calls that came through a merged hub.
    claimed: the merged hub's own caller claim (unverified).
    """

    key: str | None = None
    device: CallerDevice | None = None
    groups: list[str] = field(default_factory=list)
    owner: bool = False
    via: str | None = None
    claimed: "Caller | None" = None

    @staticmethod
    def parse(value: Any) -> "Caller | None":
        if not isinstance(value, dict):
            return None
        device = value.get("device")
        groups = value.get("groups")
        return Caller(
            key=value.get("key") if isinstance(value.get("key"), str) else None,
            device=CallerDevice(id=str(device.get("id", "")), name=str(device.get("name", "")))
            if isinstance(device, dict)
            else None,
            groups=[g for g in groups if isinstance(g, str)] if isinstance(groups, list) else [],
            owner=value.get("owner") is True,
            via=value.get("via") if isinstance(value.get("via"), str) else None,
            claimed=Caller.parse(value.get("claimed")),
        )


@dataclass
class Request:
    """What a two-argument handler gets next to the body.

    caller:  who is calling; None unless the hub that forwarded the request
             is the pinned hub (a hub that predates caller identity may pass
             a client's context.hub through unchanged).
    context: the request context without ``hub``.
    path:    the called path.
    """

    caller: Caller | None
    context: dict[str, Any]
    path: str

    @staticmethod
    def from_context(ctx: Any, hub_key: str | None) -> "Request":
        context = dict(ctx.context) if isinstance(ctx.context, dict) else {}
        hub = context.pop("hub", None)
        trusted = isinstance(hub, dict) and hub_key is not None and hub.get("hubKey") == hub_key
        return Request(
            caller=Caller.parse(hub.get("caller")) if trusted else None,
            context=context,
            path=ctx.path,
        )


class Service:
    """Registers API endpoints on a hub and serves calls forwarded by it.

    Usage::

        service = Service({"name": "Echo", "icon": {"symbol": "speaker.wave.2", "text": "E"}})
        service.post("echo", lambda body: body).start()
    """

    def __init__(
        self,
        options: ServiceOptions | dict[str, Any] | None = None,
        *,
        sign: Callable[..., str | Awaitable[str]] | None = None,
        sign_challenge: Callable[[str], str | Awaitable[str]] | None = None,
    ) -> None:
        """Create a service.

        options: ServiceOptions (address/name/icon/hub_key).
        sign:    optional token factory for hub-server auth (default: the
                 keychain ``auth`` file in the cwd, TS parity). The token is
                 attached as the ``auth`` header on every (re)connect. A
                 factory that takes one argument gets the pinned hub key (or
                 None) and must sign v1 when it is set; one without arguments
                 always connects with v0.
        sign_challenge: signs Hub Network agent challenges with the service
                 key (default: the keychain ``auth`` file).
        """
        if isinstance(options, dict):
            options = ServiceOptions(**options)
        opts = options or ServiceOptions()
        self.channel = Channel()
        env = os.environ.get("HUB")
        address = opts.address if opts.address is not None else (int(env) if env and env.isdigit() else env)
        self.address: int | str = address if address is not None else 1997
        # The hubs.json pin key for this hub.
        self.target = keychain.pin_address(self.address)
        self._hub_key = opts.hub_key
        self._pinned: str | None = None
        self._pin_loaded = False
        self._instance = opts.instance
        self.device: Device | None = (
            opts.device if isinstance(opts.device, Device) else Device() if opts.device else None
        )
        self.apps: list[AppHeader] = []
        self.settings: dict[str, ApiSettings] = {}
        # Every registered handler path (post, stream, app) in registration
        # order; the services list is built from it sorted by path (TS parity).
        self._paths: set[str] = set()
        self.sender: Any = None  # ClientSender once started
        self.profile: Profile | None = None
        self.sign = sign if sign is not None else (lambda hub_key=None: keychain.sign(hub_key=hub_key))
        self._sign_takes_hub_key = _takes_argument(self.sign)
        self.sign_challenge = sign_challenge if sign_challenge is not None else keychain.sign_data
        self._service_key: str | None = None
        # Hub Network shares; the agent socket is network.agent_socket.
        self.network = NetworkPublisher()
        if opts.name or opts.icon is not None:
            self.profile = Profile(name=opts.name, icon=opts.icon)

    def post(
        self,
        path: str,
        handler: Callable[[Any], Any],
        settings: ApiSettings | None = None,
    ) -> "Service":
        """Register a request/response API endpoint.

        handler receives the request body (may be sync or async) and returns
        the response body. A handler that takes a second argument also gets
        the Request (``request.caller``: who is calling).
        """
        self._add_path(path, settings)
        self.channel.post(path, self._with_request(handler))
        return self

    def stream(
        self,
        path: str,
        handler: Callable[[Any], AsyncIterator[Any] | Any],
        settings: ApiSettings | None = None,
    ) -> "Service":
        """Register a streaming API endpoint.

        handler receives the request body and returns an async iterator /
        async generator / generator of values to stream back. A handler that
        takes a second argument also gets the Request (as in post).
        """
        self._add_path(path, settings)
        self.channel.stream(path, self._with_request(handler))
        return self

    def app(self, app: Any) -> "Service":
        """Register an app: header goes to the hub apps list and its path
        serves the AppInterface as a stream (TS parity)."""
        self.apps.append(app.header)
        self._add_path(app.header.path, None)
        self.channel.stream(app.header.path, lambda ctx: _yield_app_interface(app))
        return self

    @property
    def instance(self) -> str:
        """The instance name sent in the certificate: the option, else
        ``HUB_INSTANCE`` (the launcher sets it), else the name, else the cwd
        name, else ``service``; at most 128 UTF-8 bytes."""
        name = (
            self._instance
            or os.environ.get("HUB_INSTANCE")
            or (self.profile.name if self.profile is not None else None)
            or os.path.basename(os.getcwd())
            or "service"
        )
        return name.encode()[:128].decode(errors="ignore") or "service"

    def _with_request(self, handler: Callable[..., Any]) -> Callable[[Any], Any]:
        """Adapt a ``(body)`` or ``(body, request)`` handler to a channel one."""
        if _positional_count(handler) >= 2:
            return lambda ctx: handler(ctx.body, Request.from_context(ctx, self.hub_key))
        return lambda ctx: handler(ctx.body)

    def _add_path(self, path: str, settings: ApiSettings | None) -> None:
        if settings is not None:
            if settings.permissions is not None and not settings.permissions.group:
                settings.permissions.group = path.split("/")[0]
            self.settings[path] = settings
        self._paths.add(path)

    def update(self) -> dict[str, Any]:
        """Build the current hub/service/update payload (services + apps)."""
        services = [
            self._service_header(path, self.settings.get(path))
            for path in sorted(self._paths)
        ]
        apps = [
            {"type": app.type, "name": app.name, "path": app.path}
            for app in self.apps
        ]
        return {"services": services, "apps": apps}

    @staticmethod
    def _service_header(path: str, settings: ApiSettings | None) -> dict[str, Any]:
        entry: dict[str, Any] = {"path": path}
        if settings is not None:
            if settings.permissions is not None:
                permissions: dict[str, Any] = {}
                if settings.permissions.group:
                    permissions["group"] = settings.permissions.group
                permissions["name"] = settings.permissions.name
                if settings.permissions.allows is not None:
                    permissions["allows"] = settings.permissions.allows
                entry["permissions"] = permissions
            if settings.limit is not None:
                entry["limit"] = settings.limit
        return entry

    def start(self) -> "Service":
        """Connect to the hub.

        On every (re)connect the profile update (if set) and the service
        update are re-sent — the hub drops services on disconnect. Requires a
        running asyncio event loop (call from an async context).
        """
        if self.sender is not None:
            return self
        self.sender = connect_channel(
            self.channel,
            self.address,
            ConnectOptions(
                on_connect=self._on_connect,
                headers=self._auth_headers,
            ),
        )
        return self

    @property
    def pins(self) -> keychain.HubPins:
        """Pinned hub keys: ``hubs.json`` beside the service key file."""
        return keychain.HubPins(keychain.key_path().parent / "hubs.json")

    @property
    def hub_key(self) -> str | None:
        """The hub key this service signs for: supplied, else pinned. The pin
        is read from hubs.json at each connect and kept in memory."""
        if self._hub_key:
            return self._hub_key
        if not self._pin_loaded:
            self._pinned = self.pins.get(self.target)
            self._pin_loaded = True
        return self._pinned

    def forget_hub_key(self) -> None:
        """Clear the pinned hub key; the next connect learns it again (v0)."""
        self._hub_key = None
        self._pinned = None
        self.pins.forget(self.target)

    @property
    def last_error(self) -> str | None:
        """Why the last connection attempt failed, if it did. A refused v1
        connect (``invalid signature``: the hub key changed or a different
        server answers) shows up here; the SDK never falls back to v0."""
        if self.sender is None:
            return None
        return self.sender.ws.close_error

    async def _auth_headers(self) -> dict[str, str]:
        """Auth headers for hub-server: a fresh signed token + protocol version."""
        self._pin_loaded = False  # pick up a pin another process wrote
        hub_key = self.hub_key if self._sign_takes_hub_key else None
        token = self.sign(hub_key) if self._sign_takes_hub_key else self.sign()
        if asyncio.iscoroutine(token) or hasattr(token, "__await__"):
            token = await token  # type: ignore[assignment]
        headers = {"auth": str(token), "v": "1" if hub_key else "0"}
        self._service_key = headers["auth"].split(".")[1]
        if self.device is not None:
            # The certificate names the key in the token, whoever signed it.
            service_key = headers["auth"].split(".")[1]
            try:
                headers["device"] = self.device.certificate(service_key, self.instance)
            except (OSError, ValueError):
                pass  # no readable or creatable device key: a plain key connection
        return headers

    def send(self, path: str, body: Any = None, context: Any = None) -> Any:
        """Call an API through the hub (client side). Await the result.

        Raises ServiceNotStartedError if start() has not been called.
        """
        sender = self._sender_or_error()
        return sender.send(path, body, context)

    def values(self, path: str, body: Any = None, context: Any = None) -> Any:
        """Open a stream call through the hub (client side).

        Returns an async iterator of values. Raises ServiceNotStartedError if
        start() has not been called.
        """
        sender = self._sender_or_error()
        return sender.values(path, body, context)

    def _sender_or_error(self) -> Any:
        if self.sender is None:
            raise ServiceNotStartedError("Service not started")
        return self.sender

    async def _on_connect(self, sender: Any) -> None:
        """Re-announce on every (re)connect.

        Fire-and-forget: the py client reads incoming messages only after the
        onopen callback returns, so awaiting a send (which waits for the hub's
        response) inside onopen would deadlock and the service update would
        never be sent. The enqueue happens synchronously in send(), so
        scheduling both sends as tasks is safe.
        """
        try:
            if self.profile is not None:
                profile: dict[str, Any] = {}
                if self.profile.name:
                    profile["name"] = self.profile.name
                if self.profile.icon is not None:
                    profile["icon"] = self.profile.icon
                asyncio.create_task(_quiet_send(sender, "hub/profile/update", profile))
        except Exception:
            pass
        try:
            asyncio.create_task(_quiet_send(sender, "hub/service/update", self.update()))
        except Exception:
            pass
        if self.hub_key is None and self._sign_takes_hub_key:
            asyncio.create_task(self._learn_hub_key(sender))
        if self.network.has_shares:
            asyncio.create_task(self._republish(sender))

    @property
    def service_key(self) -> str:
        """The key this service connects with (the key in its auth token)."""
        return self._service_key or keychain.public_key()

    async def _republish(self, sender: Any) -> None:
        try:
            await self.network.republish_all(self.service_key, self.sign_challenge, sender)
        except Exception as error:
            print(f"Failed to republish network shares: {error}", file=sys.stderr)

    def share(self, name: str, protocol: str, host: str, port: int, policy: dict[str, Any] | None = None) -> "Service":
        """Declare a Hub Network share before start(); the declared set is
        published on connect and after every reconnect. Default policy:
        private."""
        self.network.declare_share(_share(name, protocol, host, port, policy))
        return self

    async def publish_share(
        self, name: str, protocol: str, host: str, port: int, policy: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """Publish a local TCP/UDP port through Hub Network; returns every
        publication ({resourceId, authority, overlayAddress, port, ...})."""
        return await self.network.publish_share(
            _share(name, protocol, host, port, policy), self.service_key, self.sign_challenge, self._sender_or_error()
        )

    async def update_share(
        self, name: str, *, policy: dict[str, Any] | None = None, port: int | None = None
    ) -> list[dict[str, Any]]:
        """Change a share's policy or target port and republish it."""
        current = next((s for s in self.network.declared_shares if s["name"] == name), None)
        if current is None:
            raise KeyError(f"Share '{name}' not found")
        updated = dict(current)
        if policy is not None:
            updated["policy"] = policy
        if port is not None:
            updated["target"] = {**current["target"], "port": port}
        return await self.network.publish_share(updated, self.service_key, self.sign_challenge, self._sender_or_error())

    async def remove_share(self, name: str) -> list[dict[str, Any]]:
        """Remove a share from Hub Network."""
        return await self.network.remove_share(name, self.service_key, self.sign_challenge, self._sender_or_error())

    @property
    def share_publications(self) -> list[dict[str, Any]]:
        return self.network.publications

    def share_publication(self, name: str) -> dict[str, Any] | None:
        return self.network.publication(name)

    async def _learn_hub_key(self, sender: Any) -> None:
        """Pin the hub key from hub/info, then reconnect with v1 at once.
        hub-lite doesn't answer hub/info, so the service stays on v0 there."""
        try:
            info = await asyncio.wait_for(sender.send("hub/info"), 10)
        except Exception:
            return
        key = info.get("key") if isinstance(info, dict) else None
        if not isinstance(key, str) or not key or self.hub_key is not None:
            return
        self.pins.set(self.target, key)
        self._pinned, self._pin_loaded = key, True
        ws = self.sender.ws.ws if self.sender is not None else None
        if ws is not None:
            await ws.close()


def _share(name: str, protocol: str, host: str, port: int, policy: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "name": name,
        "protocol": protocol,
        "target": {"host": host, "port": port},
        "policy": policy if policy is not None else {"mode": "private"},
    }


def _positional_count(function: Callable[..., Any]) -> int:
    try:
        parameters = inspect.signature(function).parameters.values()
    except (TypeError, ValueError):
        return 1
    count = 0
    for p in parameters:
        if p.kind == p.VAR_POSITIONAL:
            return 2
        if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD):
            count += 1
    return count


def _takes_argument(function: Callable[..., Any]) -> bool:
    """Whether a sign factory accepts the hub key as its first argument."""
    try:
        parameters = inspect.signature(function).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(
        p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD, p.VAR_POSITIONAL) for p in parameters
    )


async def _quiet_send(sender: Any, path: str, body: Any) -> None:
    """Send a request, swallowing errors (connection may drop mid-send)."""
    try:
        await sender.send(path, body)
    except Exception:
        pass


async def _yield_app_interface(app: Any) -> AsyncIterator[Any]:
    """Async generator yielding the AppInterface once (stream endpoint)."""
    yield app.interface()
