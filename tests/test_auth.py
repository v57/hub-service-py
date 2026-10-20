"""v1 hub-bound auth: hub/info pinning against a fake hub (protocol.md §2)."""

import asyncio
import base64
import json

import pytest
from channel_py.channel import Channel
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from hub_service_py import Service, ServiceOptions, keychain

HUB_KEY = "MCowBQYDK2VwAyEAiojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="


@pytest.fixture
def key_dir(tmp_path):
    keychain.set_key_path(tmp_path / "auth")
    yield tmp_path
    keychain.set_key_path("auth")


def verify(token: str, signed: str) -> None:
    _, pub, sig, _ = token.split(".")
    Ed25519PublicKey.from_public_bytes(base64.b64decode(pub)[-32:]).verify(
        base64.b64decode(sig), signed.encode()
    )


class FakeHub:
    """Records connect headers; answers hub/info unless lite."""

    def __init__(self, lite: bool = False) -> None:
        self.headers: list[dict] = []
        self.connected = asyncio.Event()
        channel = Channel()
        if not lite:
            channel.post("hub/info", lambda ctx: {"key": HUB_KEY, "protocol": 1, "pro": True, "mode": "default-allow"})
        channel.post("hub/service/update", lambda ctx: None)
        self.server = channel.listen(0, {"state": self._state})

    def _state(self, headers):
        self.headers.append(dict(headers))
        self.connected.set()
        return {}

    async def wait_connects(self, count: int) -> None:
        for _ in range(200):
            if len(self.headers) >= count:
                return
            await asyncio.sleep(0.02)
        raise AssertionError(f"expected {count} connects, got {len(self.headers)}")


def test_v0_token_signs_expiry(key_dir):
    token = keychain.sign()
    expiry = token.split(".")[3]
    verify(token, expiry)


def test_v1_token_signs_hub_and_expiry(key_dir):
    token = keychain.sign(hub_key=HUB_KEY)
    expiry = token.split(".")[3]
    verify(token, f"hub1:{HUB_KEY}:{expiry}")


def test_default_expiry_is_sixty_seconds(key_dir):
    import time

    expiry = int(keychain.sign().split(".")[3])
    assert 55 <= expiry - int(time.time()) <= 61


def test_pins_round_trip(key_dir):
    pins = keychain.HubPins(key_dir / "hubs.json")
    assert pins.get("ws://127.0.0.1:1997") is None
    pins.set("ws://127.0.0.1:1997", HUB_KEY)
    assert json.loads((key_dir / "hubs.json").read_text()) == {"ws://127.0.0.1:1997": HUB_KEY}
    pins.forget("ws://127.0.0.1:1997")
    assert pins.get("ws://127.0.0.1:1997") is None


def test_supplied_hub_key_connects_v1(key_dir):
    service = Service(ServiceOptions(address=1, hub_key=HUB_KEY))
    headers = asyncio.run(service._auth_headers())
    assert headers["v"] == "1"
    verify(headers["auth"], f"hub1:{HUB_KEY}:{headers['auth'].split('.')[3]}")


def test_sign_without_arguments_stays_v0(key_dir):
    service = Service(ServiceOptions(address=1, hub_key=HUB_KEY), sign=lambda: keychain.sign())
    assert asyncio.run(service._auth_headers())["v"] == "0"


async def test_learns_and_pins_hub_key_then_reconnects_v1(key_dir):
    hub = FakeHub()
    await hub.server.wait_started()
    service = Service(ServiceOptions(address=hub.server.port))
    service.start()
    try:
        await hub.wait_connects(2)
        assert hub.headers[0]["v"] == "0"
        assert hub.headers[1]["v"] == "1"
        verify(hub.headers[1]["auth"], f"hub1:{HUB_KEY}:{hub.headers[1]['auth'].split('.')[3]}")
        assert keychain.HubPins(key_dir / "hubs.json").get(service.target) == HUB_KEY
        service.forget_hub_key()
        assert service.hub_key is None
    finally:
        service.sender.stop()
        await hub.server.stop_async()


async def test_hub_lite_keeps_v0(key_dir):
    hub = FakeHub(lite=True)
    await hub.server.wait_started()
    service = Service(ServiceOptions(address=hub.server.port))
    service.start()
    try:
        await hub.wait_connects(1)
        await asyncio.sleep(0.3)
        assert [h["v"] for h in hub.headers] == ["0"]
        assert not (key_dir / "hubs.json").exists()
    finally:
        service.sender.stop()
        await hub.server.stop_async()
