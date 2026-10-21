"""Hub Network share publication against a fake agent and hub (TS network.ts parity)."""

import asyncio
import base64
import json
import shutil
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
from channel_py.channel import Channel
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from hub_service_py import Service, ServiceOptions, keychain
from hub_service_py.network import LocalAgentError, NetworkPublisher, validate_share

HUB_KEY = "MCowBQYDK2VwAyEAiojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="


def iso(delta: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=delta)).isoformat().replace("+00:00", "Z")


class FakeAgent:
    """The hub-net agent's /challenge and /attest over a Unix socket."""

    def __init__(self, path: str, expired: bool = False) -> None:
        self.path = path
        self.expired = expired
        self.nonces: dict[str, str] = {}
        self.server = None

    async def start(self) -> None:
        self.server = await asyncio.start_unix_server(self._handle, self.path)

    async def stop(self) -> None:
        self.server.close()
        await self.server.wait_closed()

    async def _handle(self, reader, writer) -> None:
        head = await reader.readuntil(b"\r\n\r\n")
        lines = head.decode().split("\r\n")
        path = lines[0].split(" ")[1]
        length = next(int(l.split(":")[1]) for l in lines if l.lower().startswith("content-length"))
        body = json.loads(await reader.readexactly(length))
        status, reply = self._route(path, body)
        data = json.dumps(reply).encode() if not isinstance(reply, bytes) else reply
        writer.write(f"HTTP/1.1 {status} OK\r\nContent-Length: {len(data)}\r\n\r\n".encode() + data)
        await writer.drain()
        writer.close()

    def _route(self, path: str, body: dict):
        if path == "/challenge":
            self.nonces[body["shareName"]] = f"nonce-{body['shareName']}"
            return 200, {"nonce": self.nonces[body["shareName"]]}
        if path == "/attest":
            spki = base64.b64decode(body["serviceKey"])
            try:
                Ed25519PublicKey.from_public_bytes(spki[-32:]).verify(
                    base64.b64decode(body["signature"]), self.nonces[body["shareName"]].encode()
                )
            except Exception:
                return 403, b"bad signature"
            return 200, {
                "version": 1,
                "attestationId": f"att-{body['shareName']}",
                "serviceKey": body["serviceKey"],
                "key": "agent-key",
                "shareName": body["shareName"],
                "protocol": body["protocol"],
                "target": body["target"],
                "issuedAt": iso(-600 if self.expired else 0),
                "expiresAt": iso(-300 if self.expired else 300),
                "signature": "c2lnbmF0dXJl",
            }
        return 404, b"not found"


@pytest.fixture
def setup(tmp_path):
    keychain.set_key_path(tmp_path / "auth")
    socket_dir = tempfile.mkdtemp(prefix="hn", dir="/tmp")  # Unix socket paths are short
    yield socket_dir + "/agent.sock"
    shutil.rmtree(socket_dir)
    keychain.set_key_path("auth")


def hub_channel(replaced: list) -> Channel:
    hub = Channel()

    def replace(ctx):
        replaced.append(ctx.body)
        return {
            "shares": [
                {
                    "version": 1,
                    "resourceId": f"hnr1_{share['name']}",
                    "authority": f"{share['name']}.hub.invalid",
                    "providerId": "provider",
                    "protocol": share["protocol"],
                    "overlayAddress": "100.96.0.2",
                    "port": share["target"]["port"],
                }
                for share in ctx.body["shares"]
            ]
        }

    hub.post("network/shares/replace", replace)
    hub.post("hub/service/update", lambda ctx: None)
    return hub


def test_share_validation():
    validate_share({"name": "s3", "protocol": "tcp", "target": {"host": "127.0.0.1", "port": 9001}})
    for bad in (
        {"name": "", "protocol": "tcp", "target": {"host": "h", "port": 1}},
        {"name": "s3", "protocol": "sctp", "target": {"host": "h", "port": 1}},
        {"name": "s3", "protocol": "tcp", "target": {"host": "h", "port": 70000}},
        {"name": "s3", "protocol": "tcp", "target": {"host": "h", "port": 1}, "policy": {"mode": "keys", "keys": []}},
    ):
        with pytest.raises(TypeError):
            validate_share(bad)


async def test_declared_shares_publish_on_connect_and_update(setup):
    agent = FakeAgent(setup)
    await agent.start()
    replaced: list = []
    server = hub_channel(replaced).listen(0)
    await server.wait_started()
    service = Service(ServiceOptions(address=server.port, hub_key=HUB_KEY, device=False))
    service.network.agent_socket = setup
    service.share("s3", "tcp", "127.0.0.1", 9001, {"mode": "hub"})
    service.start()
    try:
        for _ in range(100):
            if replaced:
                break
            await asyncio.sleep(0.02)
        assert len(replaced) == 1
        wire = replaced[0]["shares"][0]
        assert wire["name"] == "s3" and wire["version"] == 1 and wire["policy"] == {"mode": "hub"}
        assert wire["attestation"]["serviceKey"] == keychain.public_key()
        assert service.share_publication("s3")["resourceId"] == "hnr1_s3"

        await service.publish_share("ssh", "tcp", "127.0.0.1", 22)
        assert [s["name"] for s in replaced[-1]["shares"]] == ["s3", "ssh"]
        assert replaced[-1]["shares"][1]["policy"] == {"mode": "private"}

        await service.update_share("ssh", port=2222)
        assert replaced[-1]["shares"][1]["target"] == {"host": "127.0.0.1", "port": 2222}
        assert service.share_publication("ssh")["port"] == 2222

        await service.remove_share("s3")
        assert [s["name"] for s in replaced[-1]["shares"]] == ["ssh"]
        assert [p["resourceId"] for p in service.share_publications] == ["hnr1_ssh"]
    finally:
        service.sender.stop()
        await server.stop_async()
        await agent.stop()


async def test_expired_attestation_is_refused_and_rolled_back(setup):
    agent = FakeAgent(setup, expired=True)
    await agent.start()
    publisher = NetworkPublisher(agent_socket=setup)
    share = {"name": "s3", "protocol": "tcp", "target": {"host": "127.0.0.1", "port": 9001}}
    try:
        with pytest.raises(LocalAgentError) as error:
            await publisher.publish_share(share, keychain.public_key(), keychain.sign_data, object())
        assert error.value.code == "attestation-expired"
        assert not publisher.has_shares
    finally:
        await agent.stop()


async def test_agent_unavailable_and_rejected(setup):
    share = {"name": "s3", "protocol": "tcp", "target": {"host": "127.0.0.1", "port": 9001}}
    publisher = NetworkPublisher(agent_socket=setup)
    with pytest.raises(LocalAgentError) as error:
        await publisher.request_attestation(share, keychain.public_key(), keychain.sign_data)
    assert error.value.code == "agent-unavailable"

    agent = FakeAgent(setup)
    await agent.start()
    try:
        with pytest.raises(LocalAgentError) as error:
            await publisher.request_attestation(share, keychain.public_key(), lambda nonce: "AAAA")
        assert error.value.code == "agent-rejected" and error.value.status == 403
    finally:
        await agent.stop()
