"""Core hub-service types and the Service class.

Lite port of hub-service (TS reference): no auth, no keychain, no crypto.
The wire contract matches the TS/Go reference — hub/profile/update and
hub/service/update are re-sent on every (re)connect (the hub drops services
on disconnect).
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import Any, AsyncIterator, Awaitable, Callable

from channel_py.channel import Channel
from channel_py.client import ConnectOptions, connect_channel

from hub_service_py import keychain


class ServiceNotStartedError(RuntimeError):
    """Raised by send/values before start() has connected to the hub."""


@dataclass
class ServiceOptions:
    """Options for Service.

    address: a port (int) or a ws:// URL (string). Default: 1997 or $HUB.
    name:    profile name shown in the hub.
    icon:    profile icon: a string or {"symbol": ..., "text": ...}.
    """

    address: int | str | None = None
    name: str | None = None
    icon: Any = None


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
        sign: Callable[[], str | Awaitable[str]] | None = None,
    ) -> None:
        """Create a service.

        options: ServiceOptions (address/name/icon).
        sign:    optional token factory for hub-pro auth (default: the
                 keychain ``auth`` file in the cwd, TS parity). The token is
                 attached as the ``auth`` header on every (re)connect.
        """
        if isinstance(options, dict):
            options = ServiceOptions(**options)
        opts = options or ServiceOptions()
        self.channel = Channel()
        env = os.environ.get("HUB")
        address = opts.address if opts.address is not None else (int(env) if env and env.isdigit() else env)
        self.address: int | str = address if address is not None else 1997
        self.apps: list[AppHeader] = []
        self.settings: dict[str, ApiSettings] = {}
        # Every registered handler path (post, stream, app) in registration
        # order; the services list is built from it sorted by path (TS parity).
        self._paths: set[str] = set()
        self.sender: Any = None  # ClientSender once started
        self.profile: Profile | None = None
        self.sign = sign if sign is not None else (lambda: keychain.sign())
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
        the response body.
        """
        self._add_path(path, settings)
        self.channel.post(path, lambda ctx: handler(ctx.body))
        return self

    def stream(
        self,
        path: str,
        handler: Callable[[Any], AsyncIterator[Any] | Any],
        settings: ApiSettings | None = None,
    ) -> "Service":
        """Register a streaming API endpoint.

        handler receives the request body and returns an async iterator /
        async generator / generator of values to stream back.
        """
        self._add_path(path, settings)
        self.channel.stream(path, lambda ctx: handler(ctx.body))
        return self

    def app(self, app: Any) -> "Service":
        """Register an app: header goes to the hub apps list and its path
        serves the AppInterface as a stream (TS parity)."""
        self.apps.append(app.header)
        self._add_path(app.header.path, None)
        self.channel.stream(app.header.path, lambda ctx: _yield_app_interface(app))
        return self

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

    async def _auth_headers(self) -> dict[str, str]:
        """Auth headers for hub-pro: a fresh signed token + protocol version."""
        token = self.sign()
        if asyncio.iscoroutine(token) or hasattr(token, "__await__"):
            token = await token  # type: ignore[assignment]
        return {"auth": str(token), "v": "0"}

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


async def _quiet_send(sender: Any, path: str, body: Any) -> None:
    """Send a request, swallowing errors (connection may drop mid-send)."""
    try:
        await sender.send(path, body)
    except Exception:
        pass


async def _yield_app_interface(app: Any) -> AsyncIterator[Any]:
    """Async generator yielding the AppInterface once (stream endpoint)."""
    yield app.interface()
