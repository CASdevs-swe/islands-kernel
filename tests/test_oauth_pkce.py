import hashlib
from identity.tokens import b64url
from identity.oauth.pkce import verify_pkce_s256, make_challenge


def test_matching_verifier_passes():
    verifier = "a" * 64
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())
    assert verify_pkce_s256(verifier=verifier, challenge=challenge) is True


def test_make_challenge_roundtrip():
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert verify_pkce_s256(verifier=verifier,
                            challenge=make_challenge(verifier)) is True


def test_wrong_verifier_fails():
    assert verify_pkce_s256(verifier="wrong", challenge=make_challenge("right")) is False
