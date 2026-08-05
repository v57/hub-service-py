"""Core hub-service types and the Service class.

Lite port of hub-service (TS reference): no auth, no keychain, no crypto.
The wire contract matches the TS/Go reference — hub/profile/update and
hub/service/update are re-sent on every (re)connect (the hub drops services
on disconnect).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, AsyncIterator, Callable

from channel_py.channel import Channel
from channel_py.client import ConnectOptions, connect_channel


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

    def __init__(self, options: ServiceOptions | dict[str, Any] | None = None) -> None:
        if isinstance(options, dict):
            options = ServiceOptions(**options)
        opts = options or ServiceOptions()
        self.channel = Channel()
        self.address: int | str = (
            opts.address if opts.address is not None else (os.environ.get("HUB") or 1997)
        )
        self.apps: list[AppHeader] = []
        self.settings: dict[str, ApiSettings] = {}
        # Every registered handler path (post, stream, app) in registration
        # order; the services list is built from it sorted by path (TS parity).
        self._paths: set[str] = set()
        self.sender: Any = None  # ClientSender once started
        self.profile: Profile | None = None
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
