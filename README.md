<h1>
  <img alt="Hub Service logo" src="./icon.png" width="70" valign="middle">
  &nbsp;hub-service-py
</h1>

Python port of [hub-service](https://github.com/v57/hub-service) — connect to a
[hub](https://github.com/v57/hub-lite) (default `ws://127.0.0.1:1997`), host
your own post/stream API endpoints, register apps, and call API through the hub.

The wire contract matches the TS reference (`hub/profile/update`,
`hub/service/update`, AppInterface + element DSL). Auth and devices follow
[`Docs/Devices/protocol.md`](../../Docs/Devices/protocol.md).

## Install

```bash
uv sync --extra dev   # path dependency on ../../Channel/channel-py (see [tool.uv.sources])
```

## Usage

Start a hub first (`new Hub()` from hub-lite, listens on 1997), then:

```python
import asyncio
from hub_service_py import Action, App, AppHeader, Service
from hub_service_py.app import button, cell, text_field

async def main():
    service = Service(
        {"name": "Echo", "icon": {"symbol": "speaker.wave.2", "text": "E"}}
    )
    service.post("echo", lambda body: body)
    service.post("echo/upper", lambda body: str(body).upper())
    service.app(
        App(
            AppHeader(type="app", name="Echo", path="echo/ui"),
            body=[
                "Hello from Python",
                text_field(
                    "echo",
                    placeholder="Text to echo",
                    action=Action(path="echo/upper", body="value", output="value"),
                ),
                cell("$Echo", "value"),
                button("Upper", Action(path="echo/upper", body="value", output="value")),
            ],
        )
    )
    service.start()
    await asyncio.Event().wait()  # run forever

asyncio.run(main())
```

Call it through the hub (any language):

```python
response = await service.send("echo/upper", "hello")  # "HELLO"
```

## API

- `Service(options?)` — `address` (port or ws:// URL; default `1997` or
  `$HUB`), `name`, `icon`
- `post(path, handler(body) -> resp, settings?) -> Service` — handler may be
  sync or async
- `stream(path, handler(body) -> async iterator of values, settings?) -> Service`
- Either handler may take a second argument, a `Request`: `request.caller`
  (`Caller`: `key`, `device` (`id`, `name`), `groups`, `owner`, `via`,
  `claimed`; None when the hub sends none), `request.hub_key`,
  `request.context`, `request.path`. The hub fills `context.hub`, so a
  service can trust it.
- `app(App) -> Service` — appends the header to the hub apps list and serves
  the AppInterface as a stream at `header.path`
- `send(path, body?, context?)` — client call through the hub (raises
  `ServiceNotStartedError` before `start()`)
- `values(path, body?, context?)` — stream call through the hub
- `start() -> Service` — connect; re-announces `hub/profile/update` (if set)
  and `hub/service/update` on every reconnect

`ApiSettings` carries `permissions` (group auto-filled from the first path
segment, TS parity) and `limit` — wire-parity fields that hub-lite ignores.
Element helpers (`text`, `progress`, `text_field`, `button`, `slider`,
`list_`, `picker`, `cell`, `files`, `file_operation`, `hstack`, `vstack`,
`zstack`, `spacer`) produce the exact TS wire shapes; plain strings are
shorthand text.

## Auth and devices

- **Service key:** the `auth` file in the cwd (TS layout), sent as a signed
  `auth` token on every connect.
- **Hub key:** the first connect uses `v: 0` and calls `hub/info`; the hub key
  is pinned in `hubs.json` beside the `auth` file and later connects sign
  `hub1:<hub key>:<expiry>` with `v: 1`. hub-lite stays on v0.
  `ServiceOptions(hub_key=...)` supplies it up front and
  `service.forget_hub_key()` clears the pin.
- **Device:** a certificate signed by `~/.hub/device.key` (`HUB_DEVICE_KEY`
  overrides it) goes in the `device` header and is renewed with less than a
  day left. `ServiceOptions(instance=..., device=False | Device(...))` sets
  the instance name or turns device mode off; `Device(name=, platform=,
  parent=, key=)` overrides the defaults.

## Test

```bash
./scripts/test                 # unit tests
uv run python example/echo.py  # example service (needs a hub on 1997)
# cross-language check (TS):
bun ../hub-service/tests/verify.ts echo echo/upper '"hello"' '"HELLO"'
bun ../hub-service/tests/appcheck.ts echo/ui Echo
```
