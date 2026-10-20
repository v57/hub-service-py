"""Docs/Devices/vectors.json: every string must match exactly."""

import json
from pathlib import Path

from hub_service_py import Device, keychain
from hub_service_py.device import certificate, device_id, safety_code

VECTORS = json.loads((Path(__file__).parents[3] / "Docs" / "Devices" / "vectors.json").read_text())
KEYS = VECTORS["keys"]


def key(name):
    return keychain.decode_key_file(KEYS[name]["keyFile"])


def test_key_files_and_public_keys():
    for name in ("hub", "service", "device"):
        k = key(name)
        assert keychain.spki(k) == KEYS[name]["publicKey"]
        assert keychain.encode_key_file(k) == KEYS[name]["keyFile"]


def test_device_id_and_safety_code():
    assert device_id(KEYS["device"]["publicKey"]) == KEYS["device"]["deviceId"]
    assert safety_code(KEYS["device"]["publicKey"]) == KEYS["device"]["safetyCode"]


def test_auth_tokens():
    auth = VECTORS["auth"]
    assert keychain.token(key("service"), auth["expiry"]) == auth["v0"]["header"]
    assert keychain.token(key("service"), auth["expiry"], KEYS["hub"]["publicKey"]) == auth["v1"]["header"]


def test_certificates():
    cert = VECTORS["certificate"]
    header = certificate(
        key("device"),
        KEYS["service"]["publicKey"],
        "s3-local/Backup Disk",
        iat=1792500000,
        exp=1793104800,
        device_name="Mac Studio",
        platform="macos",
    )
    assert header == cert["header"]
    assert header.split(".")[0] == cert["payload"]
    child = VECTORS["childCertificate"]
    assert (
        certificate(
            key("device"),
            KEYS["service"]["publicKey"],
            "builder",
            iat=1792500000,
            exp=1793104800,
            device_name="builder",
            platform="linux",
            parent="Mac Studio",
        )
        == child["header"]
    )


def test_device_issues_the_vector_certificate():
    device = Device(key=key("device"), name="Mac Studio", platform="macos")
    assert device.id == KEYS["device"]["deviceId"]
    header = device.certificate(KEYS["service"]["publicKey"], "s3-local/Backup Disk", now=1792500000)
    assert header == VECTORS["certificate"]["header"]
