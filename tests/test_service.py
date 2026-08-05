import json

import pytest

from hub_service_py import (
    Action,
    ApiSettings,
    App,
    AppHeader,
    Service,
    ServiceNotStartedError,
    ServiceOptions,
    ServicePermissions,
)
from hub_service_py.app import button, cell, text_field


def test_services_list_includes_registered_paths():
    s = Service()
    s.post("echo", lambda body: body)
    s.stream("echo/values", lambda body: iter([body]))
    s.app(App(AppHeader(type="app", name="Echo", path="echo/ui"), body=["hi"]))
    u = s.update()
    assert [svc["path"] for svc in u["services"]] == ["echo", "echo/ui", "echo/values"]
    assert u["apps"] == [{"type": "app", "name": "Echo", "path": "echo/ui"}]


def test_services_sorted_by_path():
    s = Service()
    s.post("z", lambda body: body)
    s.post("echo", lambda body: body)
    s.post("echo/upper", lambda body: body)
    assert [svc["path"] for svc in s.update()["services"]] == ["echo", "echo/upper", "z"]


def test_settings_group_auto_fill_and_limit():
    s = Service()
    s.post(
        "echo",
        lambda body: body,
        ApiSettings(
            permissions=ServicePermissions(name="Echo", allows=True),
            limit=5,
        ),
    )
    svc = s.update()["services"][0]
    assert svc["permissions"] == {"group": "echo", "name": "Echo", "allows": True}
    assert svc["limit"] == 5


def test_settings_without_permissions_omit_both():
    s = Service()
    s.post("echo", lambda body: body, ApiSettings(limit=2))
    assert s.update()["services"][0] == {"path": "echo", "limit": 2}
    s2 = Service()
    s2.post("echo", lambda body: body)
    assert s2.update()["services"][0] == {"path": "echo"}


def test_update_json_matches_wire_contract():
    s = Service()
    s.post(
        "echo",
        lambda body: body,
        ApiSettings(
            permissions=ServicePermissions(name="Echo", allows=True),
            limit=5,
        ),
    )
    raw = json.dumps(s.update(), separators=(",", ":"))
    want = (
        '{"services":[{"path":"echo","permissions":'
        '{"group":"echo","name":"Echo","allows":true},"limit":5}],"apps":[]}'
    )
    assert raw == want


def test_profile_only_when_set():
    assert Service().profile is None
    named = Service(ServiceOptions(name="Echo"))
    assert named.profile is not None and named.profile.name == "Echo" and named.profile.icon is None
    iconed = Service(ServiceOptions(icon="E"))
    assert iconed.profile is not None and iconed.profile.icon == "E" and iconed.profile.name is None
    full = Service({"name": "Echo", "icon": {"symbol": "speaker.wave.2", "text": "E"}})
    assert full.profile is not None
    assert full.profile.name == "Echo"
    assert full.profile.icon == {"symbol": "speaker.wave.2", "text": "E"}


def test_send_before_start_errors():
    s = Service()
    with pytest.raises(ServiceNotStartedError):
        s.send("echo", "x")
    with pytest.raises(ServiceNotStartedError):
        s.values("echo", "x")


def test_app_interface_has_all_five_keys():
    app = App(
        AppHeader(type="app", name="Echo", path="echo/ui"),
        body=[
            "Hello",
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
    interface = app.interface()
    assert set(interface.keys()) == {"header", "body", "top", "bottom", "data"}
    assert interface["header"] == {"type": "app", "name": "Echo", "path": "echo/ui"}
    assert interface["top"] is None and interface["bottom"] is None
    assert interface["data"] == {"hello": "world"}
    types = ["string" if isinstance(e, str) else e["type"] for e in interface["body"]]
    assert types == ["string", "textField", "cell", "button"]
    # Optional keys in elements must be omitted, never null (top/bottom are
    # intentionally null in the interface).
    for element in interface["body"]:
        if not isinstance(element, str):
            assert "null" not in json.dumps(element)


def test_elements_omit_optional_keys():
    assert text_field("v", placeholder="p", action=Action(path="x")) == {
        "type": "textField",
        "value": "v",
        "placeholder": "p",
        "action": {"path": "x"},
    }
    assert text_field("v") == {"type": "textField", "value": "v"}
    assert cell("t") == {"type": "cell", "title": "t"}
    assert cell() == {"type": "cell"}
    assert button("Upper", Action(path="x", body="value", output="value")) == {
        "type": "button",
        "title": "Upper",
        "action": {"path": "x", "body": "value", "output": "value"},
    }
