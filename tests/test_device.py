"""Device key file and service certificates (protocol.md §3)."""

import asyncio
import base64
import json
import os
import stat

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from hub_service_py import Device, Service, ServiceOptions, keychain
from hub_service_py.device import (
    CERTIFICATE_LIFETIME,
    certificate_expiry,
    default_device_key_path,
)


@pytest.fixture
def dirs(tmp_path, monkeypatch):
    monkeypatch.setenv("HUB_DEVICE_KEY", str(tmp_path / "hub" / "device.key"))
    keychain.set_key_path(tmp_path / "auth")
    yield tmp_path
    keychain.set_key_path("auth")


def decode(header: str) -> dict:
    payload = header.split(".")[0]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def test_key_path_override(dirs):
    assert default_device_key_path() == dirs / "hub" / "device.key"


def test_key_file_created_private_and_reused(dirs):
    device = Device()
    key = device.public_key
    path = dirs / "hub" / "device.key"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700
    assert len(base64.b64decode(path.read_text())) == 92
    assert Device().public_key == key
    assert [p.name for p in path.parent.iterdir()] == ["device.key"]


def test_certificate_signed_by_device_over_payload(dirs):
    device = Device(name="Mac Studio", platform="macos")
    header = device.certificate("SERVICE", "s3-local/Backup Disk", now=1792500000)
    payload, signature = header.split(".")
    Ed25519PublicKey.from_public_bytes(base64.b64decode(device.public_key)[-32:]).verify(
        base64.b64decode(signature), payload.encode()
    )
    body = decode(header)
    assert list(body) == ["v", "device", "service", "instance", "deviceName", "platform", "iat", "exp"]
    assert body["exp"] - body["iat"] == CERTIFICATE_LIFETIME


def test_certificate_renewed_with_less_than_a_day_left(dirs):
    device = Device()
    first = device.certificate("SERVICE", "echo", now=1000)
    assert device.certificate("SERVICE", "echo", now=1000 + 5 * 86400) == first
    renewed = device.certificate("SERVICE", "echo", now=1000 + 6 * 86400 + 1)
    assert renewed != first
    assert certificate_expiry(renewed) == 1000 + 6 * 86400 + 1 + CERTIFICATE_LIFETIME


def test_service_sends_device_header_for_its_key(dirs):
    service = Service(ServiceOptions(address=1, instance="echo/main"))
    headers = asyncio.run(service._auth_headers())
    body = decode(headers["device"])
    assert body["service"] == keychain.public_key() == headers["auth"].split(".")[1]
    assert body["instance"] == "echo/main"
    assert body["device"] == service.device.public_key


def test_instance_defaults_to_name(dirs):
    assert Service(ServiceOptions(address=1, name="Echo")).instance == "Echo"


def test_device_mode_off_sends_no_header(dirs):
    service = Service(ServiceOptions(address=1, device=False))
    assert "device" not in asyncio.run(service._auth_headers())
    assert not (dirs / "hub").exists()


def test_instance_defaults_to_first_path_segment(dirs):
    service = Service(ServiceOptions(address=1))
    assert service.instance == "service"
    service.post("s3/read", lambda body: body)
    service.post("echo", lambda body: body)
    assert service.instance == "s3"


def test_instance_length_checked(dirs):
    with pytest.raises(ValueError):
        Device().certificate("SERVICE", "x" * 129)


def test_unreadable_device_key_falls_back_to_plain_key(dirs, monkeypatch):
    blocked = dirs / "blocked"
    blocked.write_text("not a directory")
    monkeypatch.setenv("HUB_DEVICE_KEY", str(blocked / "device.key"))
    headers = asyncio.run(Service(ServiceOptions(address=1))._auth_headers())
    assert "device" not in headers and headers["auth"].startswith("key.")
