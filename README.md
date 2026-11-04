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

Start a hub first (hub-server, listens on 1997), then:

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

- `Service(options?, sign=?)` — `address` (port or ws:// URL; default `1997` or
  `$HUB`), `name`, `icon`, `allow_plaintext`; `sign(hub_key, challenge)` is a
  custom token factory given the proven hub key and the challenge
- `post(path, handler(body) -> resp, settings?) -> Service` — handler may be
  sync or async
- `stream(path, handler(body) -> async iterator of values, settings?) -> Service`
- Either handler may take a second argument, a `Request`: `request.caller`
  (`Caller`: `key`, `device` (`id`, `name`), `groups`, `owner`, `via`,
  `claimed`), `request.context` (without `hub`), `request.path`. The caller
  is None unless `context.hub.hubKey` is the pinned hub key: a hub that
  predates caller identity may pass a client's `context.hub` through.
- `app(App) -> Service` — appends the header to the hub apps list and serves
  the AppInterface as a stream at `header.path`
- `send(path, body?, context?)` — client call through the hub (raises
  `ServiceNotStartedError` before `start()`)
- `values(path, body?, context?)` — stream call through the hub
- `start() -> Service` — connect; re-announces `hub/profile/update` (if set)
  and `hub/service/update` on every reconnect
- `stop()` — disconnect and stop reconnecting, ending a wait for the hub's proof

`ApiSettings` carries `permissions` (group auto-filled from the first path
segment, TS parity) and `limit` — wire-parity fields that hub-lite ignores.
Element helpers (`text`, `progress`, `text_field`, `button`, `slider`,
`list_`, `picker`, `cell`, `files`, `file_operation`, `hstack`, `vstack`,
`zstack`, `spacer`) produce the exact TS wire shapes; plain strings are
shorthand text.

## Auth and devices

- **Service key:** the `auth` file in the cwd (TS layout), sent as a signed
  `auth` token on every connect.
- **Hub key:** before every connect the service asks `hub/info` with a fresh
  nonce on a short anonymous connection. Only an answer with a valid proof of
  the key it claims gets a token, signing `hub1:<hub key>:<challenge>:<expiry>`
  with `v: 1`. The first proven key is pinned in `hubs.json` beside the `auth`
  file. A hub that doesn't prove its key, or answers with another than the
  pinned one, gets nothing and is reported while the service keeps trying, so
  calls made right after `start()` wait instead of being lost.
  `ServiceOptions(hub_key=...)` supplies it up front and
  `service.forget_hub_key()` clears the pin.
- **Transport:** plain `ws://` beyond loopback, the overlay and the LAN isn't
  dialed unless `ServiceOptions(allow_plaintext=True)` or
  `HUB_ALLOW_PLAINTEXT=1` says so; `hub_transport_of(address)` classifies an
  address.
- **Device:** a certificate signed by `~/.hub/device.key` (`HUB_DEVICE_KEY`
  overrides it) goes in the `device` header and is renewed with less than a
  day left. `ServiceOptions(instance=..., device=False | Device(...))` sets
  the instance name or turns device mode off; `Device(name=, platform=,
  parent=, key=)` overrides the defaults.

## Hub Network shares

A share makes a local TCP/UDP port reachable through Hub Network (TS
`publishShare` parity). The local hub-net agent attests each share over its
Unix socket (`/var/run/hub-net/agent.sock`, `service.network.agent_socket`),
then the declared set goes to the hub in one `network/shares/replace`, and it
is republished after every reconnect.

```python
service.share("s3", "tcp", "127.0.0.1", 9001, {"mode": "hub"})  # before start()
await service.publish_share("ssh", "tcp", "127.0.0.1", 22)     # after start()
await service.update_share("ssh", port=2222)
await service.remove_share("ssh")
service.share_publication("s3")  # {resourceId, authority, overlayAddress, port, ...}
```

The default policy is `{"mode": "private"}`; others are `hub`, `group`
(`group`), `keys` (`keys`) and `disabled`.

## Test

```bash
./scripts/test                 # unit tests
uv run python example/echo.py  # example service (needs a hub on 1997)
# cross-language check (TS):
bun ../hub-service/tests/verify.ts echo echo/upper '"hello"' '"HELLO"'
bun ../hub-service/tests/appcheck.ts echo/ui Echo
```
