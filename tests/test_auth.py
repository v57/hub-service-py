"""Auth v2: the hub's proof, its pin and one token per connect (protocol.md §2)."""

import asyncio
import base64
import json
import time

import pytest
from channel_py.channel import Channel
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fake_hub import HUB_KEY, KEYS, VECTORS, answer_hub_info, proving

from hub_service_py import (
    Service,
    ServiceNotStartedError,
    ServiceOptions,
    hub_info_signed_data,
    hub_transport_of,
    keychain,
    make_client_nonce,
    verify_hub_proof,
)


@pytest.fixture
def key_dir(tmp_path):
    keychain.set_key_path(tmp_path / "auth")
    yield tmp_path
    keychain.set_key_path("auth")


def verify(token: str, hub_key: str = HUB_KEY) -> None:
    _, pub, sig, expiry, nonce = token.split(".")
    Ed25519PublicKey.from_public_bytes(base64.b64decode(pub)[-32:]).verify(
        base64.b64decode(sig), f"hub1:{hub_key}:{nonce}:{expiry}".encode()
    )


class FakeHub:
    """Records connect headers; answers hub/info as answer says."""

    def __init__(self, answer=None) -> None:
        self.headers: list[dict] = []
        self.updates = 0
        channel = Channel()
        answer_hub_info(channel, answer)

        def update(ctx):
            self.updates += 1

        channel.post("hub/service/update", update)
        channel.post("test/echo", lambda ctx: ctx.body)
        self.server = channel.listen(0, {"state": self._state})

    def _state(self, headers):
        self.headers.append(dict(headers))
        return {}

    @property
    def credentials(self) -> list[dict]:
        return [h for h in self.headers if "auth" in h or "device" in h]

    async def wait_update(self, count: int = 1) -> None:
        for _ in range(250):
            if self.updates >= count:
                return
            await asyncio.sleep(0.02)
        raise AssertionError(f"expected {count} updates, got {self.updates}")


def test_token_matches_vector():
    auth = VECTORS["auth"]
    service = keychain.decode_key_file(KEYS["service"]["keyFile"])
    assert keychain.token(service, auth["expiry"], HUB_KEY, auth["nonce"]) == auth["v1"]["header"]


def test_proof_matches_vector():
    info = VECTORS["hubInfo"]
    assert hub_info_signed_data(HUB_KEY, info["nonce"]) == info["signedData"]
    answer = {"key": HUB_KEY, "proof": info["proof"], "challenge": "c"}
    assert verify_hub_proof(answer, info["nonce"])
    assert not verify_hub_proof(answer, "another-nonce-another-nonce")
    assert not verify_hub_proof({**answer, "key": KEYS["service"]["publicKey"]}, info["nonce"])
    assert not verify_hub_proof({"key": HUB_KEY, "challenge": "c"}, info["nonce"])
    assert not verify_hub_proof({"key": HUB_KEY, "proof": info["proof"]}, info["nonce"])
    assert not verify_hub_proof("no answer", info["nonce"])


@pytest.mark.parametrize("case", VECTORS["transport"], ids=lambda case: case["url"])
def test_transport_matches_vector(case):
    assert hub_transport_of(case["url"]) == case["transport"]


def test_bare_port_is_loopback():
    assert hub_transport_of(1997) == "loopback"
    assert hub_transport_of("1997") == "loopback"


def test_client_nonce_is_32_bytes_of_base64url():
    nonce = make_client_nonce()
    assert len(nonce) == 43 and "=" not in nonce and len(base64.urlsafe_b64decode(nonce + "=")) == 32
    assert nonce != make_client_nonce()


def test_token_lasts_thirty_seconds_over_the_challenge(key_dir):
    token = keychain.sign(HUB_KEY, "challenge")
    verify(token)
    parts = token.split(".")
    assert parts[4] == "challenge"
    assert 25 <= int(parts[3]) - int(time.time()) <= 31


def test_pins_round_trip(key_dir):
    pins = keychain.HubPins(key_dir / "hubs.json")
    assert pins.get("ws://127.0.0.1:1997") is None
    pins.set("ws://127.0.0.1:1997", HUB_KEY)
    assert json.loads((key_dir / "hubs.json").read_text()) == {"ws://127.0.0.1:1997": HUB_KEY}
    pins.forget("ws://127.0.0.1:1997")
    assert pins.get("ws://127.0.0.1:1997") is None


async def test_sends_a_token_only_after_proof_and_pins_the_key(key_dir):
    hub = FakeHub()
    await hub.server.wait_started()
    service = Service(ServiceOptions(address=hub.server.port))
    service.start()
    try:
        # A call made right away waits for the authenticated connection.
        assert await asyncio.wait_for(service.send("test/echo", "hi"), 5) == "hi"
        assert "auth" not in hub.headers[0] and "device" not in hub.headers[0]
        connect = hub.headers[-1]
        assert connect["v"] == "1" and "device" in connect
        verify(connect["auth"])
        assert connect["auth"].split(".")[4] == "challenge-1"
        assert keychain.HubPins(key_dir / "hubs.json").get(service.target) == HUB_KEY
        assert service.hub_key == HUB_KEY
        service.forget_hub_key()
        assert service.hub_key is None
    finally:
        service.sender.stop()
        await hub.server.stop_async()


async def test_each_connect_has_its_own_challenge(key_dir):
    nonces = []
    prove = proving()

    def answer(nonce, challenge):
        nonces.append(nonce)
        return prove(nonce, challenge)

    hub = FakeHub(answer)
    await hub.server.wait_started()
    service = Service(ServiceOptions(address=hub.server.port))
    service.start()
    try:
        await hub.wait_update()
        await service.sender.ws.ws.close()  # the reconnect asks again
        await hub.wait_update(2)
        assert len(nonces) == 2 and nonces[0] != nonces[1]
        tokens = [h["auth"] for h in hub.credentials]
        assert [t.split(".")[4] for t in tokens] == ["challenge-1", "challenge-2"]
        for token in tokens:
            verify(token)
    finally:
        service.sender.stop()
        await hub.server.stop_async()


def no_proof(nonce, challenge):
    return {"key": HUB_KEY, "protocol": 2, "challenge": challenge}


def anothers_proof(nonce, challenge):
    # Claims the real hub's key, signs with its own.
    return {**proving("service")(nonce, challenge), "key": HUB_KEY}


@pytest.mark.parametrize("answer", [no_proof, anothers_proof])
async def test_hub_without_a_proof_gets_nothing_and_is_not_pinned(key_dir, capsys, answer):
    hub = FakeHub(answer)
    await hub.server.wait_started()
    service = Service(ServiceOptions(address=hub.server.port))
    service.start()
    try:
        await asyncio.sleep(1.5)
        assert len(hub.headers) >= 2  # it keeps asking
        assert hub.credentials == [] and hub.updates == 0
        assert service.hub_key is None and not (key_dir / "hubs.json").exists()
        assert "didn't prove" in service.last_error
        assert capsys.readouterr().err.count("didn't prove") == 1
        # stop ends the wait at once
        task = service.sender.ws._run_task
        service.stop()
        await asyncio.wait_for(asyncio.wait([task]), 1)
    finally:
        service.stop()
        await hub.server.stop_async()


async def test_hub_with_another_key_than_the_pin_gets_nothing(key_dir):
    # Proves its own key, but this address is pinned to the real hub's.
    hub = FakeHub(proving("service"))
    await hub.server.wait_started()
    service = Service(ServiceOptions(address=hub.server.port))
    service.pins.set(service.target, HUB_KEY)
    service.start()
    try:
        await asyncio.sleep(1.2)
        assert hub.credentials == [] and hub.updates == 0
        assert service.pins.get(service.target) == HUB_KEY
        assert "not the pinned" in service.last_error
    finally:
        service.sender.stop()
        await hub.server.stop_async()


async def test_supplied_hub_key_is_a_pin(key_dir):
    hub = FakeHub(proving("service"))
    await hub.server.wait_started()
    service = Service(ServiceOptions(address=hub.server.port, hub_key=HUB_KEY))
    service.start()
    try:
        await asyncio.sleep(0.4)
        assert hub.credentials == []
        assert service.hub_key == HUB_KEY
    finally:
        service.sender.stop()
        await hub.server.stop_async()


async def test_custom_sign_gets_the_proven_key_and_challenge_after_the_proof(key_dir):
    calls = []

    def sign(hub_key, challenge):
        calls.append((hub_key, challenge))
        return keychain.sign(hub_key, challenge)

    hub = FakeHub()
    await hub.server.wait_started()
    service = Service(ServiceOptions(address=hub.server.port, device=False), sign=sign)
    service.start()
    try:
        await hub.wait_update()
        assert calls == [(HUB_KEY, "challenge-1")]
    finally:
        service.sender.stop()
        await hub.server.stop_async()

    calls.clear()
    silent = FakeHub(no_proof)
    await silent.server.wait_started()
    refused = Service(ServiceOptions(address=silent.server.port, device=False), sign=sign)
    refused.start()
    try:
        await asyncio.sleep(0.3)
        assert calls == []
    finally:
        refused.sender.stop()
        await silent.server.stop_async()


def test_public_plaintext_is_not_dialed(key_dir, capsys, monkeypatch):
    monkeypatch.delenv("HUB_ALLOW_PLAINTEXT", raising=False)
    service = Service(ServiceOptions(address="ws://hub.example.com:1997"))
    assert service.start() is service
    assert service.sender is None
    assert "unencrypted" in capsys.readouterr().err
    with pytest.raises(ServiceNotStartedError, match="unencrypted"):
        service.send("x")
    assert "unencrypted" in service.last_error


async def test_allow_plaintext_opts_out(key_dir, monkeypatch):
    monkeypatch.delenv("HUB_ALLOW_PLAINTEXT", raising=False)
    # No listener answers on port 1: dialing only has to start.
    for service in (
        Service(ServiceOptions(address="ws://hub.invalid-name:1", allow_plaintext=True)),
        _with_env(monkeypatch),
    ):
        service.start()
        assert service.sender is not None
        service.sender.stop()


def _with_env(monkeypatch) -> Service:
    monkeypatch.setenv("HUB_ALLOW_PLAINTEXT", "1")
    return Service(ServiceOptions(address="ws://hub:1"))


def test_pin_address_normalization():
    assert keychain.pin_address(1997) == "ws://localhost:1997"
    assert keychain.pin_address("1997") == "ws://localhost:1997"
    assert keychain.pin_address("WS://Hub.Example.COM:2000/") == "ws://hub.example.com:2000"
    assert keychain.pin_address("wss://hub.example.com/Path/") == "wss://hub.example.com/Path"
    assert Service(ServiceOptions(address=1997)).target == "ws://localhost:1997"
