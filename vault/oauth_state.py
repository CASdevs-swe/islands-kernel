from __future__ import annotations
import base64
import hashlib
import hmac
import json


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign_state(payload: dict, key: bytes) -> str:
    body = _b64(json.dumps(payload, sort_keys=True).encode())
    sig = _b64(hmac.new(key, body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def verify_state(token: str, key: bytes) -> dict:
    try:
        body, sig = token.split(".", 1)
        expected = _b64(hmac.new(key, body.encode(), hashlib.sha256).digest())
    except ValueError:
        raise ValueError("malformed state")
    if not hmac.compare_digest(sig, expected):
        raise ValueError("bad state signature")
    return json.loads(_unb64(body))
