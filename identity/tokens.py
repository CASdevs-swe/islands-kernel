import base64
import hashlib
import secrets


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def unb64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def hash_token(raw: str) -> str:
    return b64url(hashlib.sha256(raw.encode()).digest())


def generate_raw_token(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(32)}"
