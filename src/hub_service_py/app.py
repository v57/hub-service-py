"""App interface and element DSL (TS app.ts parity).

Element helpers produce dicts matching the TS wire shapes. Optional keys are
omitted (never null). The App interface dict always carries all five keys:
header, body, top, bottom, data.
"""

from __future__ import annotations

from typing import Any


class Action:
    """References an API call from a UI element: {path, body?, output?}."""

    def __init__(self, path: str, body: Any = None, output: Any = None) -> None:
        self.path = path
        self.body = body
        self.output = output

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"path": self.path}
        if self.body is not None:
            d["body"] = self.body
        if self.output is not None:
            d["output"] = self.output
        return d


class App:
    """A hub app: a header plus a UI body of elements."""

    def __init__(
        self,
        header: Any,
        body: list[Any],
        data: dict[str, Any] | None = None,
        top: Any = None,
        bottom: Any = None,
    ) -> None:
        self.header = header
        self.body = body
        self.data = data if data is not None else {}
        self.top = top
        self.bottom = bottom

    def interface(self) -> dict[str, Any]:
        """The AppInterface streamed at the app path (all 5 keys present)."""
        return {
            "header": {
                "type": self.header.type,
                "name": self.header.name,
                "path": self.header.path,
            },
            "body": self.body,
            "top": self.top,
            "bottom": self.bottom,
            "data": self.data,
        }


def _action_dict(action: Action | dict[str, Any]) -> Any:
    return action.to_dict() if isinstance(action, Action) else action


def text(value: str, secondary: bool | None = None) -> dict[str, Any]:
    e: dict[str, Any] = {"type": "text", "value": value}
    if secondary is not None:
        e["secondary"] = secondary
    return e


def progress(value: str, min: Any = None, max: Any = None) -> dict[str, Any]:
    e: dict[str, Any] = {"type": "progress", "value": value}
    if min is not None:
        e["min"] = min
    if max is not None:
        e["max"] = max
    return e


def text_field(
    value: str,
    placeholder: str | None = None,
    action: Action | dict[str, Any] | None = None,
) -> dict[str, Any]:
    e: dict[str, Any] = {"type": "textField", "value": value}
    if placeholder is not None:
        e["placeholder"] = placeholder
    if action is not None:
        e["action"] = _action_dict(action)
    return e


def button(title: str, action: Action | dict[str, Any]) -> dict[str, Any]:
    return {"type": "button", "title": title, "action": _action_dict(action)}


def slider(
    value: str,
    default_value: Any = None,
    min: Any = None,
    max: Any = None,
    step: Any = None,
    action: Action | dict[str, Any] | None = None,
) -> dict[str, Any]:
    e: dict[str, Any] = {"type": "slider", "value": value}
    if default_value is not None:
        e["defaultValue"] = default_value
    if min is not None:
        e["min"] = min
    if max is not None:
        e["max"] = max
    if step is not None:
        e["step"] = step
    if action is not None:
        e["action"] = _action_dict(action)
    return e


def list_(data: Any, content: Any) -> dict[str, Any]:
    return {"type": "list", "data": data, "content": content}


def picker(options: list[str], selected: str) -> dict[str, Any]:
    return {"type": "picker", "options": options, "selected": selected}


def cell(title: Any = None, subtitle: Any = None) -> dict[str, Any]:
    e: dict[str, Any] = {"type": "cell"}
    if title is not None:
        e["title"] = title
    if subtitle is not None:
        e["subtitle"] = subtitle
    return e


def files(
    value: str,
    title: Any = None,
    action: Action | dict[str, Any] | None = None,
) -> dict[str, Any]:
    e: dict[str, Any] = {"type": "files", "value": value}
    if title is not None:
        e["title"] = title
    if action is not None:
        e["action"] = _action_dict(action)
    return e


def file_operation(
    format: str | None = None,
    title: Any = None,
    action: Action | dict[str, Any] | None = None,
) -> dict[str, Any]:
    e: dict[str, Any] = {"type": "fileOperation"}
    if format is not None:
        e["format"] = format
    if title is not None:
        e["title"] = title
    if action is not None:
        e["action"] = _action_dict(action)
    return e


def hstack(content: list[Any], spacing: Any = None) -> dict[str, Any]:
    e: dict[str, Any] = {"type": "hstack", "content": content}
    if spacing is not None:
        e["spacing"] = spacing
    return e


def vstack(content: list[Any], spacing: Any = None) -> dict[str, Any]:
    e: dict[str, Any] = {"type": "vstack", "content": content}
    if spacing is not None:
        e["spacing"] = spacing
    return e


def zstack(content: list[Any]) -> dict[str, Any]:
    return {"type": "zstack", "content": content}


def spacer() -> dict[str, Any]:
    return {"type": "spacer"}
