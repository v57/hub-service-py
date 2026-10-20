import pytest


@pytest.fixture(autouse=True)
def private_device_key(tmp_path, monkeypatch):
    """Keep every test off the real ~/.hub/device.key."""
    monkeypatch.setenv("HUB_DEVICE_KEY", str(tmp_path / "device-key" / "device.key"))
