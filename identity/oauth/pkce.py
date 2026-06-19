import hashlib
import hmac
from identity.tokens import b64url


def make_challenge(verifier: str) -> str:
    return b64url(hashlib.sha256(verifier.encode()).digest())


def verify_pkce_s256(*, verifier: str, challenge: str) -> bool:
    return hmac.compare_digest(make_challenge(verifier), challenge)
