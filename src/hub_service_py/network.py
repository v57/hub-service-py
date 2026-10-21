"""Hub Network share publication (TS network.ts parity).

A share makes a local TCP/UDP port reachable through Hub Network. For each
declared share the service asks the local hub-net agent (HTTP over its Unix
socket) for an attestation: ``/challenge`` returns a nonce, the service signs
it with its key, and ``/attest`` returns the agent-signed attestation. The
complete declared set then goes to the hub in one ``network/shares/replace``
call, which answers with one publication per share in request order. The set
is republished after every reconnect.

Usage::

    service.share("s3", "tcp", "127.0.0.1", 9001, {"mode": "hub"})  # before start()
    await service.publish_share("s3", "tcp", "127.0.0.1", 9001)     # after start()
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from datetime import datetime
from typing import Any, Awaitable, Callable

WIRE_VERSION = 1
AGENT_SOCKET = "/var/run/hub-net/agent.sock"
MAX_SHARE_NAME_LENGTH = 255

Sign = Callable[[str], str | Awaitable[str]]
AttestationProvider = Callable[[dict[str, Any], str, Sign], Awaitable[dict[str, Any]]]

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class LocalAgentError(Exception):
    """The local hub-net agent was unavailable, refused or answered badly.

    code: agent-unavailable, agent-timeout, agent-rejected,
          invalid-agent-response, attestation-mismatch, attestation-expired.
    """

    def __init__(self, code: str, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


def _string(value: Any, field: str, max_length: int | None = None) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or _CONTROL.search(value)
        or (max_length is not None and len(value) > max_length)
    ):
        raise TypeError(f"Invalid Hub Network {field}")
    return value


def _port(value: Any, field: str = "target port") -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535:
        raise TypeError(f"Invalid Hub Network {field}")


def validate_policy(value: Any) -> None:
    if not isinstance(value, dict) or not isinstance(value.get("mode"), str):
        raise TypeError("Invalid Hub Network policy")
    mode = value["mode"]
    if mode in ("hub", "private", "disabled"):
        return
    if mode == "group":
        _string(value.get("group"), "policy group")
        return
    if mode == "keys":
        keys = value.get("keys")
        if not isinstance(keys, list) or not keys:
            raise TypeError("Invalid Hub Network policy keys")
        for key in keys:
            try:
                _string(key, "policy key")
            except TypeError:
                raise TypeError("Invalid Hub Network policy keys") from None
        return
    raise TypeError("Invalid Hub Network policy mode")


def validate_share(value: Any) -> None:
    """A share: {name, protocol: tcp|udp, target: {host, port}, policy?}."""
    if not isinstance(value, dict):
        raise TypeError("Invalid Hub Network share")
    _string(value.get("name"), "share name", MAX_SHARE_NAME_LENGTH)
    if value.get("protocol") not in ("tcp", "udp"):
        raise TypeError("Invalid Hub Network protocol")
    target = value.get("target")
    if not isinstance(target, dict):
        raise TypeError("Invalid Hub Network target")
    _string(target.get("host"), "target host")
    _port(target.get("port"))
    if "policy" in value and value["policy"] is not None:
        validate_policy(value["policy"])


def _validate_publication(value: Any, share: dict[str, Any], index: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TypeError(f"Invalid Hub publication at share index {index}")
    if value.get("version") != WIRE_VERSION:
        raise TypeError(f"Invalid Hub publication version at share index {index}")
    resource = value.get("resourceId")
    if not isinstance(resource, str) or not resource.startswith("hnr1_") or resource == "hnr1_":
        raise TypeError(f"Invalid Hub publication resourceId at share index {index}")
    _string(value.get("authority"), f"publication authority at share index {index}")
    _string(value.get("providerId"), f"publication providerId at share index {index}")
    _string(value.get("overlayAddress"), f"publication overlayAddress at share index {index}")
    if value.get("protocol") != share["protocol"]:
        raise TypeError(f"Hub publication protocol mismatch at share index {index}")
    _port(value.get("port"), f"publication port at share index {index}")
    return value


def _parse_time(value: Any) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


async def _signed(sign: Sign, data: str) -> str:
    value = sign(data)
    if asyncio.iscoroutine(value) or hasattr(value, "__await__"):
        value = await value  # type: ignore[assignment]
    return str(value)


class NetworkPublisher:
    """Declared shares, their agent attestations and hub publications."""

    def __init__(
        self,
        attestation_provider: AttestationProvider | None = None,
        agent_socket: str = AGENT_SOCKET,
        agent_timeout: float = 5.0,
    ) -> None:
        self.attestation_provider = attestation_provider
        self.agent_socket = agent_socket
        self.agent_timeout = agent_timeout
        self._shares: dict[str, dict[str, Any]] = {}
        self._publications: dict[str, dict[str, Any]] = {}

    @property
    def declared_shares(self) -> list[dict[str, Any]]:
        return [self._shares[name] for name in sorted(self._shares)]

    @property
    def has_shares(self) -> bool:
        return bool(self._shares)

    def declare_share(self, share: dict[str, Any]) -> None:
        """Declare a share; the next connect publishes the whole set."""
        validate_share(share)
        self._shares[share["name"]] = share

    async def request_attestation(self, share: dict[str, Any], service_key: str, sign: Sign) -> dict[str, Any]:
        """Prove the service key to the local agent; returns its attestation."""
        validate_share(share)
        body = {
            "serviceKey": service_key,
            "shareName": share["name"],
            "protocol": share["protocol"],
            "target": share["target"],
        }
        challenge = await self._agent("/challenge", body, "challenge")
        nonce = challenge.get("nonce") if isinstance(challenge, dict) else None
        if not isinstance(nonce, str) or not nonce:
            raise LocalAgentError("invalid-agent-response", "Hub Network agent returned an invalid challenge")
        signature = await _signed(sign, nonce)
        attestation = await self._agent("/attest", {**body, "signature": signature}, "attestation")
        self._validate_attestation(attestation, share, service_key)
        return attestation

    async def publish_share(self, share: dict[str, Any], service_key: str, sign: Sign, sender: Any) -> list[dict[str, Any]]:
        validate_share(share)
        previous = self._shares.get(share["name"])
        self._shares[share["name"]] = share
        try:
            return await self._synchronize(service_key, sign, sender)
        except BaseException:
            if previous is not None:
                self._shares[share["name"]] = previous
            else:
                self._shares.pop(share["name"], None)
            raise

    async def republish_all(self, service_key: str, sign: Sign, sender: Any) -> list[dict[str, Any]]:
        return await self._synchronize(service_key, sign, sender)

    async def remove_share(self, name: str, service_key: str, sign: Sign, sender: Any) -> list[dict[str, Any]]:
        _string(name, "share name", MAX_SHARE_NAME_LENGTH)
        removed = self._shares.pop(name, None)
        if removed is None:
            raise KeyError(f"Share '{name}' not found")
        try:
            return await self._synchronize(service_key, sign, sender)
        except BaseException:
            self._shares[name] = removed
            raise

    @property
    def publications(self) -> list[dict[str, Any]]:
        return list(self._publications.values())

    def publication(self, name: str) -> dict[str, Any] | None:
        return self._publications.get(name)

    async def _synchronize(self, service_key: str, sign: Sign, sender: Any) -> list[dict[str, Any]]:
        shares = self.declared_shares
        wire = []
        for share in shares:
            if self.attestation_provider is not None:
                attestation = await self.attestation_provider(share, service_key, sign)
            else:
                attestation = await self.request_attestation(share, service_key, sign)
            self._validate_attestation(attestation, share, service_key)
            wire.append({**share, "version": WIRE_VERSION, "attestation": attestation})

        response = await sender.send("network/shares/replace", {"shares": wire})
        if not isinstance(response, dict) or not isinstance(response.get("shares"), list):
            raise TypeError("Hub returned an invalid shares/replace response")
        publications = response["shares"]
        if len(publications) != len(shares):
            raise ValueError(f"Hub returned {len(publications)} publications for {len(shares)} shares")
        # v1 publications carry no share name: the hub keeps request order.
        correlated: dict[str, dict[str, Any]] = {}
        resources: set[str] = set()
        for index, (share, publication) in enumerate(zip(shares, publications)):
            validated = _validate_publication(publication, share, index)
            if validated["resourceId"] in resources:
                raise TypeError(f"Hub returned duplicate resourceId at share index {index}")
            resources.add(validated["resourceId"])
            correlated[share["name"]] = validated
        self._publications = correlated
        return list(correlated.values())

    @staticmethod
    def _validate_attestation(attestation: Any, share: dict[str, Any], service_key: str) -> None:
        target = attestation.get("target") if isinstance(attestation, dict) else None
        if (
            not isinstance(attestation, dict)
            or attestation.get("version") != WIRE_VERSION
            or attestation.get("serviceKey") != service_key
            or attestation.get("shareName") != share["name"]
            or attestation.get("protocol") != share["protocol"]
            or not isinstance(target, dict)
            or target.get("host") != share["target"]["host"]
            or target.get("port") != share["target"]["port"]
        ):
            raise LocalAgentError("attestation-mismatch", "Local-agent attestation does not match the share")
        issued = _parse_time(attestation.get("issuedAt"))
        expires = _parse_time(attestation.get("expiresAt"))
        now = time.time()
        if issued is None or expires is None or expires <= issued or issued > now + 30 or expires <= now:
            raise LocalAgentError("attestation-expired", "Local-agent attestation is expired")

    async def _agent(self, path: str, body: dict[str, Any], operation: str) -> Any:
        """POST JSON to the agent over its Unix socket and decode the reply."""
        try:
            status, payload = await asyncio.wait_for(self._post(path, body), self.agent_timeout)
        except asyncio.TimeoutError:
            raise LocalAgentError(
                "agent-timeout", f"Hub Network agent timed out after {int(self.agent_timeout * 1000)} ms"
            ) from None
        except OSError as error:
            raise LocalAgentError(
                "agent-unavailable", f"Hub Network agent is unavailable at {self.agent_socket}"
            ) from error
        if not 200 <= status < 300:
            detail = payload.decode(errors="replace").strip()
            raise LocalAgentError(
                "agent-rejected",
                f"Hub Network agent rejected {operation} ({status})" + (f": {detail}" if detail else ""),
                status,
            )
        try:
            return json.loads(payload)
        except ValueError:
            raise LocalAgentError("invalid-agent-response", "Hub Network agent returned invalid JSON", status) from None

    async def _post(self, path: str, body: dict[str, Any]) -> tuple[int, bytes]:
        reader, writer = await asyncio.open_unix_connection(self.agent_socket)
        try:
            data = json.dumps(body).encode()
            writer.write(
                f"POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n".encode()
                + data
            )
            await writer.drain()
            raw = await reader.read()
        finally:
            writer.close()
        return _parse_response(raw)


def _parse_response(raw: bytes) -> tuple[int, bytes]:
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode(errors="replace").split("\r\n")
    match = re.match(r"HTTP/1\.[01] (\d{3})", lines[0] if lines else "")
    if not match:
        raise LocalAgentError("invalid-agent-response", "Hub Network agent returned an invalid HTTP response")
    headers = {k.strip().lower(): v.strip() for k, _, v in (line.partition(":") for line in lines[1:])}
    if headers.get("transfer-encoding", "").lower() == "chunked":
        decoded = b""
        while body:
            size_line, _, rest = body.partition(b"\r\n")
            size = int(size_line.split(b";")[0], 16)
            if size == 0:
                break
            decoded += rest[:size]
            body = rest[size + 2 :]
        body = decoded
    elif "content-length" in headers:
        body = body[: int(headers["content-length"])]
    return int(match.group(1)), body
