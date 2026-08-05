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
