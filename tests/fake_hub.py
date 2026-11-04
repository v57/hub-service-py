"""A fake hub's hub/info, answering with a proof and a fresh challenge per question."""

import base64
import json
from pathlib import Path

from channel_py.channel import Channel

from hub_service_py import hub_info_signed_data, keychain

VECTORS = json.loads((Path(__file__).parents[3] / "Docs" / "Devices" / "vectors.json").read_text())
KEYS = VECTORS["keys"]
HUB_KEY = KEYS["hub"]["publicKey"]


def proving(name: str = "hub"):
    """An answer that proves the key of a vector key."""
    key = keychain.decode_key_file(KEYS[name]["keyFile"])
    public = KEYS[name]["publicKey"]

    def answer(nonce, challenge):
        signed = hub_info_signed_data(public, nonce).encode()
        return {"key": public, "protocol": 2, "challenge": challenge, "proof": base64.b64encode(key.sign(signed)).decode()}

    return answer


def answer_hub_info(channel: Channel, answer=None) -> None:
    answer = answer or proving()
    asked = [0]

    def info(ctx):
        asked[0] += 1
        return answer(ctx.body["nonce"], f"challenge-{asked[0]}")

    channel.post("hub/info", info)
