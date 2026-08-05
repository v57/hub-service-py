"""Echo example service: registers echo/echo/upper posts and an app on the hub.

Run (needs a hub on 127.0.0.1:1997):
    uv run python example/echo.py
"""

import asyncio

from hub_service_py import Action, App, AppHeader, Service
from hub_service_py.app import button, cell, text_field


def upper(body):
    return str(body).upper()


async def main() -> None:
    service = Service(
        {"name": "Echo", "icon": {"symbol": "speaker.wave.2", "text": "E"}}
    )
    service.post("echo", lambda body: body)
    service.post("echo/upper", upper)
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
            data={"hello": "world"},
        )
    )
    service.start()
    print("echo service started (hub-lite :1997)")
    await asyncio.Event().wait()  # run forever


if __name__ == "__main__":
    asyncio.run(main())
