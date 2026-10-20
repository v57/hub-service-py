"""Caller identity from context.hub.caller (protocol.md §4)."""

import asyncio
import json
from pathlib import Path

from channel_py.channel import Channel

from hub_service_py import Caller, CallerDevice, Service, ServiceOptions

VECTORS = json.loads((Path(__file__).parents[3] / "Docs" / "Devices" / "vectors.json").read_text())
CONTEXT = VECTORS["caller"]["context"]


def test_parse_caller():
    caller = Caller.parse(CONTEXT["hub"]["caller"])
    assert caller == Caller(
        key="MCowBQYDK2VwAyEAgTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=",
        device=CallerDevice(id="8cef065b7af83669150b7d32704d3d3e", name="Mac Studio"),
        groups=["owners"],
        owner=True,
    )


def test_parse_anonymous_and_merged_callers():
    assert Caller.parse({"groups": []}) == Caller()
    merged = Caller.parse({"key": "A", "via": "H", "claimed": {"key": "B", "owner": True}})
    assert merged.via == "H" and merged.claimed == Caller(key="B", owner=True)
    assert Caller.parse(None) is None


async def test_handlers_get_the_caller(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HUB_DEVICE_KEY", str(tmp_path / "device.key"))
    results: dict = {}
    done = asyncio.Event()
    hub = Channel()

    async def call_back(ctx):
        sender = ctx.sender
        try:
            results["post"] = await sender.send("whoami", "hi", CONTEXT)
            results["plain"] = await sender.send("echo", "hi", CONTEXT)
            results["stream"] = [v async for v in sender.values("whoami/values", None, CONTEXT)]
            results["anonymous"] = await sender.send("whoami", "hi", {"service": "x"})
            spoofed = {"hub": {**CONTEXT["hub"], "hubKey": "OTHER"}}
            results["spoofed"] = await sender.send("whoami", "hi", spoofed)
        except Exception as error:
            results["error"] = repr(error)
        done.set()

    hub.post("hub/service/update", lambda ctx: asyncio.ensure_future(call_back(ctx)) and None)
    server = hub.listen(0)
    await server.wait_started()

    async def whoami_values(body, request):
        yield request.caller.device.name

    service = Service(ServiceOptions(address=server.port, hub_key=CONTEXT["hub"]["hubKey"]))
    def whoami(body, request):
        caller = request.caller or Caller()
        return [body, caller.key, caller.owner, sorted(request.context)]

    service.post("whoami", whoami)
    service.post("echo", lambda body: body)
    service.stream("whoami/values", whoami_values)
    service.start()
    try:
        await asyncio.wait_for(done.wait(), 5)
    finally:
        service.sender.stop()
        await server.stop_async()
    assert "error" not in results, results
    assert results["post"] == ["hi", CONTEXT["hub"]["caller"]["key"], True, []]
    assert results["plain"] == "hi"
    assert results["stream"] == ["Mac Studio"]
    assert results["anonymous"] == ["hi", None, False, ["service"]]
    # A caller is trusted only from the pinned hub.
    assert results["spoofed"] == ["hi", None, False, []]
