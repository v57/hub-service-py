"""ed25519 keychain: load-or-generate the ``auth`` key file and sign tokens.

Hub-pro auth parity with the TS reference (hub-service/keychain.ts):

- The key file (``auth`` in the working directory, matching the TS keychain)
  is the base64 encoding of the 48-byte PKCS8 DER private key followed by
  the 44-byte SPKI DER public key (92 bytes total, 124 base64 chars).
- A signed token has the shape ``key.<pub>.<sig>.<expiry>`` where:
    pub     = base64 of the 44-byte SPKI public key (bytes 48..92 of the file)
    sig     = base64 ed25519 signature over the expiry string
    expiry  = DECIMAL epoch-seconds string of now + 10 (TS parity; hub-pro
              reads it as base-36, so the decimal form never trips expiry)
- The hub verifies the signature against the embedded public key and treats
  the key as the connection identity (owner/host/group permissions).

Usage::

    from hub_service_py.keychain import sign, public_key

    token = await sign()          # fresh token for a connect
    pub = await public_key()      # the service's public key (identity)
"""

from __future__ import annotations

import base64
import os
import time
from pathlib import Path

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
    if _private_key is not None:
        return _private_key
    path = _key_path or Path("auth")
    if path.exists():
        data = base64.b64decode(path.read_text().strip())
        private_der = data[:PRIVATE_DER_LENGTH]
        loaded = serialization.load_der_private_key(private_der, password=None)
        _private_key = Ed25519PrivateKey.from_private_bytes(
            loaded.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    else:
        _private_key = Ed25519PrivateKey.generate()
        _save(path, _private_key)
    return _private_key


def _save(path: Path, key: Ed25519PrivateKey) -> None:
    private_der = key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_text(base64.b64encode(private_der + public_der).decode())


def public_key() -> str:
    """The service's public key (base64 of the 44-byte SPKI DER)."""
    key = _load_or_generate()
    public_der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(public_der).decode()


def sign(expires: int = 10) -> str:
    """A fresh auth token: ``key.<pub>.<sig>.<expiry>``."""
    key = _load_or_generate()
    data = f"{int(time.time()) + expires}"
    signature = key.sign(data.encode())
    return f"key.{public_key()}.{base64.b64encode(signature).decode()}.{data}"
