"""Device key and service certificates (Docs/Devices/protocol.md).

- The device key lives in ``~/.hub/device.key`` (``/var/lib/hub/device.key``
  for a Linux system service, ``HUB_DEVICE_KEY`` overrides both) in the same
  layout as the ``auth`` file. It is created atomically on first use.
- A service certificate is ``<base64url(JSON)>.<base64 signature>``, signed by
  the device key over the payload string, and sent in the ``device`` header.
  It names the service key, the instance and the device's suggested name.

Usage::

    device = Device()                       # ~/.hub/device.key
    header = device.certificate(service_key, "s3-local/Backup Disk")
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import platform as _platform
import socket
import subprocess
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hub_service_py import keychain

# Certificates live up to 7 days and are renewed at connect with < 24 h left.
CERTIFICATE_LIFETIME = 7 * 24 * 3600
CERTIFICATE_RENEWAL = 24 * 3600


def default_device_key_path() -> Path:
    """``HUB_DEVICE_KEY``, else the system or user location."""
    env = os.environ.get("HUB_DEVICE_KEY")
    if env:
        return Path(env)
    if sys.platform.startswith("linux") and os.geteuid() == 0:
        return Path("/var/lib/hub/device.key")
    return Path.home() / ".hub" / "device.key"


def device_id(public_key: str) -> str:
    """First 32 hex characters of SHA-256 over the device SPKI DER."""
    return hashlib.sha256(base64.b64decode(public_key)).hexdigest()[:32]


def safety_code(public_key: str) -> str:
    """The code shown on both sides when approving a device: ``"ddd ddd"``."""
    digest = hashlib.sha256(base64.b64decode(public_key)).hexdigest()
    n = int(digest[:8], 16) % 1_000_000
    return f"{n // 1000:03d} {n % 1000:03d}"


def default_platform() -> str:
    if sys.platform == "darwin":
        return "macos"
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform in ("win32", "cygwin"):
        return "windows"
    return "other"


def default_device_name() -> str:
    """The macOS computer name, else the host name."""
    if sys.platform == "darwin":
        try:
            name = subprocess.run(
                ["scutil", "--get", "ComputerName"], capture_output=True, text=True, timeout=2
            ).stdout.strip()
            if name:
                return name
        except (OSError, subprocess.SubprocessError):
            pass
    name = socket.gethostname() or _platform.node() or "device"
    return name.removesuffix(".local")


def _truncate(text: str, limit: int) -> str:
    """At most limit UTF-8 bytes, cut on a character boundary."""
    return text.encode()[:limit].decode(errors="ignore")


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def certificate(
    device_key: Ed25519PrivateKey,
    service: str,
    instance: str,
    iat: int,
    exp: int,
    device_name: str | None = None,
    platform: str | None = None,
    parent: str | None = None,
) -> str:
    """A service certificate, fields in protocol order with no whitespace."""
    if not 1 <= len(instance.encode()) <= 128:
        raise ValueError("instance must be 1-128 UTF-8 bytes")
    if parent is not None and len(parent.encode()) > 64:
        raise ValueError("parent must be at most 64 UTF-8 bytes")
    payload: dict[str, object] = {
        "v": 1,
        "device": keychain.spki(device_key),
        "service": service,
        "instance": instance,
    }
    if device_name is not None:
        payload["deviceName"] = device_name
    if platform is not None:
        payload["platform"] = platform
    if parent is not None:
        payload["parent"] = parent
    payload["iat"] = iat
    payload["exp"] = exp
    encoded = _base64url(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode())
    signature = base64.b64encode(device_key.sign(encoded.encode())).decode()
    return f"{encoded}.{signature}"


def certificate_expiry(header: str) -> int:
    """The ``exp`` of a certificate header."""
    payload = header.split(".", 1)[0]
    padded = payload + "=" * (-len(payload) % 4)
    return int(json.loads(base64.urlsafe_b64decode(padded))["exp"])


class Device:
    """This device's key and the certificates it issues to services.

    path:     the key file (default: :func:`default_device_key_path`).
    key:      use this key instead of a file (tests).
    name:     suggested device name (default: the host name).
    platform: protocol platform string (default: from the OS).
    parent:   declared parent device name, for containers and VMs.
    """

    def __init__(
        self,
        path: str | os.PathLike[str] | None = None,
        *,
        key: Ed25519PrivateKey | None = None,
        name: str | None = None,
        platform: str | None = None,
        parent: str | None = None,
    ) -> None:
        self.path = Path(path) if path is not None else None
        self._key = key
        self._name = name
        self.platform = platform if platform is not None else default_platform()
        self.parent = parent
        self._certificates: dict[tuple[str, str], str] = {}

    @property
    def name(self) -> str:
        if self._name is None:
            self._name = _truncate(default_device_name(), 64)
        return self._name

    @property
    def key(self) -> Ed25519PrivateKey:
        if self._key is None:
            self._key = keychain.load_key_file(self.path or default_device_key_path(), private=True)
        return self._key

    @property
    def public_key(self) -> str:
        return keychain.spki(self.key)

    @property
    def id(self) -> str:
        return device_id(self.public_key)

    @property
    def safety_code(self) -> str:
        return safety_code(self.public_key)

    def certificate(self, service: str, instance: str, now: int | None = None) -> str:
        """The certificate for a service key, renewed with < 24 h left."""
        now = int(time.time()) if now is None else now
        cached = self._certificates.get((service, instance))
        if cached is not None and certificate_expiry(cached) - now >= CERTIFICATE_RENEWAL:
            return cached
        issued = certificate(
            self.key,
            service,
            instance,
            iat=now,
            exp=now + CERTIFICATE_LIFETIME,
            device_name=self.name,
            platform=self.platform,
            parent=self.parent,
        )
        self._certificates[(service, instance)] = issued
        return issued
