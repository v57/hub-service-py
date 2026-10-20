"""ed25519 keychain: load-or-generate the ``auth`` key file and sign tokens.

Hub-pro auth parity with the TS reference (hub-service/keychain.ts):

- The key file (``auth`` in the working directory, matching the TS keychain)
  is the base64 encoding of the 48-byte PKCS8 DER private key followed by
  the 44-byte SPKI DER public key (92 bytes total, 124 base64 chars).
- A signed token has the shape ``key.<pub>.<sig>.<expiry>`` where:
    pub     = base64 of the 44-byte SPKI public key (bytes 48..92 of the file)
    sig     = base64 ed25519 signature over the signed data
    expiry  = DECIMAL epoch-seconds string of now + 60 (protocol default;
              hub-pro rejects it once expired or over 5 minutes ahead)
- The signed data depends on the ``v`` header (Docs/Devices/protocol.md):
    v: 0    the expiry string alone
    v: 1    ``hub1:<hub key>:<expiry>``, so the token only works on the hub
            whose key it names
- The hub verifies the signature against the embedded public key and treats
  the key as the connection identity (owner/host/group permissions).
- Hub keys learned from ``hub/info`` are pinned in ``hubs.json`` beside the
  key file: ``{"<address>": "<hub SPKI>"}`` (see :class:`HubPins`).

Usage::

    from hub_service_py.keychain import sign, public_key

    token = sign()                    # v0 token for a connect
    token = sign(hub_key=hub_key)     # v1 token bound to one hub
    pub = public_key()                # the service's public key (identity)
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# TS keychain layout: PKCS8 DER private key (48 bytes for ed25519) followed
# by SPKI DER public key (44 bytes for ed25519).
PRIVATE_DER_LENGTH = 48
PUBLIC_DER_LENGTH = 44

_key_path: Path | None = None
_private_key: Ed25519PrivateKey | None = None


def set_key_path(path: str | os.PathLike[str]) -> None:
    """Override the key file location (default: ``auth`` in the cwd)."""
    global _key_path, _private_key
    _key_path = Path(path)
    _private_key = None  # force reload on next use


def _load_or_generate() -> Ed25519PrivateKey:
    global _private_key
    if _private_key is None:
        _private_key = load_key_file(key_path())
    return _private_key


def load_key_file(path: str | os.PathLike[str], private: bool = False) -> Ed25519PrivateKey:
    """Load a key file in the TS layout, creating it if missing.

    private: create the file atomically with mode 0600 inside a 0700
    directory (device keys); the service ``auth`` file keeps the default mode
    (TS parity).
    """
    path = Path(path)
    if path.exists():
        return decode_key_file(path.read_text())
    key = Ed25519PrivateKey.generate()
    if not private:
        path.write_text(encode_key_file(key))
        return key
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".device.", dir=path.parent)  # mode 0600
    try:
        with os.fdopen(fd, "w") as file:
            file.write(encode_key_file(key))
        # link, not rename: a key another process created first wins.
        os.link(temp, path)
    except FileExistsError:
        return decode_key_file(path.read_text())
    finally:
        os.unlink(temp)
    return key


def decode_key_file(text: str) -> Ed25519PrivateKey:
    """The private key in a key file (base64 PKCS8 DER || SPKI DER)."""
    data = base64.b64decode(text.strip())
    if len(data) != PRIVATE_DER_LENGTH + PUBLIC_DER_LENGTH:
        raise ValueError(
            f"bad key file: expected {PRIVATE_DER_LENGTH + PUBLIC_DER_LENGTH} bytes, got {len(data)}"
        )
    loaded = serialization.load_der_private_key(data[:PRIVATE_DER_LENGTH], password=None)
    return Ed25519PrivateKey.from_private_bytes(
        loaded.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def encode_key_file(key: Ed25519PrivateKey) -> str:
    private_der = key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(private_der + public_der).decode()


def spki(key: Ed25519PrivateKey) -> str:
    """A key's public half: base64 of the 44-byte SPKI DER."""
    public_der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(public_der).decode()


def key_path() -> Path:
    """The service key file in use."""
    return _key_path or Path("auth")


def public_key() -> str:
    """The service's public key (base64 of the 44-byte SPKI DER)."""
    return spki(_load_or_generate())


def token(key: Ed25519PrivateKey, expiry: int, hub_key: str | None = None) -> str:
    """An auth token for an exact expiry; v1 (hub-bound) when hub_key is set."""
    data = f"hub1:{hub_key}:{expiry}" if hub_key else f"{expiry}"
    signature = key.sign(data.encode())
    return f"key.{spki(key)}.{base64.b64encode(signature).decode()}.{expiry}"


def sign(expires: int = 60, hub_key: str | None = None) -> str:
    """A fresh auth token: ``key.<pub>.<sig>.<expiry>``.

    hub_key: the pinned hub key; signs ``hub1:<hub key>:<expiry>`` (send it
    with ``v: 1``). Without it the token is v0 (the expiry alone).
    """
    return token(_load_or_generate(), int(time.time()) + expires, hub_key)


def pin_address(address: int | str) -> str:
    """The hubs.json key for a hub address: a bare port is
    ``ws://localhost:<port>``; a URL keeps its form with the scheme and host
    lowercased and no trailing slash (channel TS normalization)."""
    if isinstance(address, int) or str(address).isdigit():
        return f"ws://localhost:{address}"
    parts = urlsplit(str(address))
    netloc = parts.netloc
    if "@" in netloc:
        user, host = netloc.rsplit("@", 1)
        netloc = f"{user}@{host.lower()}"
    else:
        netloc = netloc.lower()
    url = urlunsplit((parts.scheme.lower(), netloc, parts.path, parts.query, parts.fragment))
    return url.rstrip("/")


class HubPins:
    """Hub keys pinned per address in ``hubs.json`` (beside the key file)."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)

    def _load(self) -> dict[str, str]:
        try:
            data = json.loads(self.path.read_text())
        except (FileNotFoundError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def get(self, address: str) -> str | None:
        value = self._load().get(address)
        return value if isinstance(value, str) else None

    def set(self, address: str, hub_key: str) -> None:
        pins = self._load()
        pins[address] = hub_key
        self._write(pins)

    def forget(self, address: str) -> None:
        pins = self._load()
        if pins.pop(address, None) is not None:
            self._write(pins)

    def _write(self, pins: dict[str, str]) -> None:
        directory = self.path.parent
        directory.mkdir(parents=True, exist_ok=True)
        fd, temp = tempfile.mkstemp(prefix=".hubs.", dir=directory)
        with os.fdopen(fd, "w") as file:
            json.dump(pins, file, indent=2)
        os.replace(temp, self.path)
