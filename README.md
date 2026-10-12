<h1>
  <img alt="Hub Service logo" src="./icon.png" width="70" valign="middle">
  &nbsp;hub-service-py
</h1>

Python port of [hub-service](https://github.com/v57/hub-service) — connect to a
[hub](https://github.com/v57/hub-lite) (default `ws://127.0.0.1:1997`), host
your own post/stream API endpoints, register apps, and call API through the hub.

Lite port: no auth, no keychain, no crypto (hub-pro territory). The wire
contract matches the TS reference (`hub/profile/update`, `hub/service/update`,
AppInterface + element DSL).

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

## Test

```bash
./scripts/test                 # unit tests
uv run python example/echo.py  # example service (needs a hub on 1997)
# cross-language check (TS):
bun ../hub-service/tests/verify.ts echo echo/upper '"hello"' '"HELLO"'
bun ../hub-service/tests/appcheck.ts echo/ui Echo
```
