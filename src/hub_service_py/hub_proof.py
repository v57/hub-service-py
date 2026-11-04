"""Auth v2's client side (Docs/Devices/protocol.md section 2).

Before every connect the service asks hub/info on an anonymous connection with
a fresh nonce, and sends its token only if the hub proved the key it claims,
over that nonce.
"""

from __future__ import annotations

import asyncio
import base64
import re
import secrets
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from channel_py.channel import Channel
from channel_py.client import connect_channel
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key

# How long one hub/info question may take before a connect.
HUB_INFO_TIMEOUT = 5.0

_ADDRESS = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://(?:[^/?#@]*@)?(\[[^\]]*\]|[^/?#:]*)")


class HubTransport(StrEnum):
    """How a connection to an address travels. REFUSED is plain ws:// beyond
    loopback, the overlay and the LAN: it isn't dialed unless allow_plaintext
    says so."""

    ENCRYPTED = "encrypted"
    LOOPBACK = "loopback"
    OVERLAY = "overlay"
    LOCAL_NETWORK = "localNetwork"
    REFUSED = "refused"


def _ipv4(host: str) -> list[int] | None:
    parts = host.split(".")
    if len(parts) != 4 or not all(re.fullmatch(r"[0-9]{1,3}", part) for part in parts):
        return None
    numbers = [int(part) for part in parts]
    return numbers if all(number <= 255 for number in numbers) else None


def hub_transport_of(address: int | str) -> HubTransport:
    """Classifies an address before anything is dialed."""
    if isinstance(address, int) or re.fullmatch(r"[0-9]+", address):
        return HubTransport.LOOPBACK
    match = _ADDRESS.match(address)
    if match is None:
        return HubTransport.REFUSED
    scheme = match[1].lower()
    host = match[2].lower().removesuffix(".")
    if scheme in ("wss", "https", "quic"):
        return HubTransport.ENCRYPTED
    if scheme not in ("ws", "http"):
        return HubTransport.REFUSED
    if host.startswith("["):
        v6 = host[1:-1]
        if v6 == "::1":
            return HubTransport.LOOPBACK
        if re.match(r"f[cd]|fe[89ab]", v6):
            return HubTransport.LOCAL_NETWORK
        return HubTransport.REFUSED
    v4 = _ipv4(host)
    if v4 is not None:
        a, b = v4[0], v4[1]
        if a == 127:
            return HubTransport.LOOPBACK
        if a == 100 and 64 <= b <= 127:
            return HubTransport.OVERLAY
        if a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or (a == 169 and b == 254):
            return HubTransport.LOCAL_NETWORK
        return HubTransport.REFUSED
    if host == "localhost" or host.endswith(".localhost"):
        return HubTransport.LOOPBACK
    if host.endswith(".hub.invalid"):
        return HubTransport.OVERLAY
    if host.endswith(".local"):
        return HubTransport.LOCAL_NETWORK
    return HubTransport.REFUSED


def make_client_nonce() -> str:
    """The nonce for one hub/info: 32 fresh random bytes in base64url."""
    return secrets.token_urlsafe(32)


def hub_info_signed_data(hub_key: str, nonce: str) -> str:
    """The string a hub/info proof signs."""
    return f"hubinfo1:{hub_key}:{nonce}"


def verify_hub_proof(info: Any, nonce: str) -> bool:
    """Whether a hub/info answer proves its key over nonce. A relayed answer
    passes too, so it never decides which credentials a hub gets."""
    if not isinstance(info, dict):
        return False
    key, proof, challenge = info.get("key"), info.get("proof"), info.get("challenge")
    if not (isinstance(key, str) and isinstance(proof, str) and isinstance(challenge, str)):
        return False
    try:
        public = load_der_public_key(base64.b64decode(key, validate=True))
        if not isinstance(public, Ed25519PublicKey):
            return False
        public.verify(base64.b64decode(proof, validate=True), hub_info_signed_data(key, nonce).encode())
    except (ValueError, TypeError, InvalidSignature):
        return False
    return True


@dataclass(frozen=True)
class HubProof:
    """A hub/info answer whose proof checked out."""

    key: str
    challenge: str


async def ask_hub(address: int | str, timeout: float = HUB_INFO_TIMEOUT) -> HubProof:
    """Asks the hub at address for its key and a challenge, on a short anonymous
    connection, and returns the answer only with a valid proof."""
    nonce = make_client_nonce()
    probe = connect_channel(Channel(), address)
    try:
        info = await asyncio.wait_for(probe.send("hub/info", {"nonce": nonce}), timeout)
    except TimeoutError:
        raise ConnectionError("hub/info timed out") from None
    finally:
        probe.stop()
    if not verify_hub_proof(info, nonce):
        raise ConnectionError("hub didn't prove its key")
    return HubProof(key=info["key"], challenge=info["challenge"])
