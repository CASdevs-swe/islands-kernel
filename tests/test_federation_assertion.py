import pytest
import jwt as pyjwt
from identity.keys import KeyManager
from identity.federation.assertion import verify_island_assertion, IslandAssertionError

ISS = "https://app.unnest.se"
AUD = "https://id.caputventi.com"


def _assert(km, *, sub="42", nonce="n1", aud=AUD, iss=ISS, exp=2000, email="a@b.se", workspace="ws_7"):
    claims = {"iss": iss, "sub": sub, "aud": aud, "nonce": nonce, "exp": exp,
              "email": email, "workspace": workspace}
    return pyjwt.encode(claims, km.private_pem(), algorithm="EdDSA", headers={"kid": km.kid})


def test_valid_assertion_returns_identity():
    km = KeyManager.generate("island-1")
    tok = _assert(km)
    out = verify_island_assertion(tok, jwks=km.jwks_document(), expected_iss=ISS,
                                  expected_aud=AUD, expected_nonce="n1", now=1000)
    assert out == {"island_user_id": "42", "email": "a@b.se", "workspace": "ws_7"}


def test_nonce_mismatch_is_rejected():
    km = KeyManager.generate("island-1")
    tok = _assert(km, nonce="other")
    with pytest.raises(IslandAssertionError):
        verify_island_assertion(tok, jwks=km.jwks_document(), expected_iss=ISS,
                                expected_aud=AUD, expected_nonce="n1", now=1000)


def test_wrong_issuer_is_rejected():
    km = KeyManager.generate("island-1")
    tok = _assert(km, iss="https://evil.example")
    with pytest.raises(IslandAssertionError):
        verify_island_assertion(tok, jwks=km.jwks_document(), expected_iss=ISS,
                                expected_aud=AUD, expected_nonce="n1", now=1000)


def test_expired_assertion_is_rejected():
    km = KeyManager.generate("island-1")
    tok = _assert(km, exp=900)
    with pytest.raises(IslandAssertionError):
        verify_island_assertion(tok, jwks=km.jwks_document(), expected_iss=ISS,
                                expected_aud=AUD, expected_nonce="n1", now=1000)


def test_signature_from_unknown_key_is_rejected():
    real, attacker = KeyManager.generate("island-1"), KeyManager.generate("island-1")
    tok = _assert(attacker)
    with pytest.raises(IslandAssertionError):
        verify_island_assertion(tok, jwks=real.jwks_document(), expected_iss=ISS,
                                expected_aud=AUD, expected_nonce="n1", now=1000)


def test_algorithm_confusion_hs256_is_rejected():
    km = KeyManager.generate("island-1")
    claims = {"iss": ISS, "sub": "42", "aud": AUD, "nonce": "n1", "exp": 2000}
    # >=32-byte secret so HS256 encode emits no InsecureKeyLengthWarning; the test
    # proves the algorithm (not the key) is rejected.
    tok = pyjwt.encode(claims, "x" * 32, algorithm="HS256", headers={"kid": km.kid})
    with pytest.raises(IslandAssertionError):
        verify_island_assertion(tok, jwks=km.jwks_document(), expected_iss=ISS,
                                expected_aud=AUD, expected_nonce="n1", now=1000)


def test_audience_mismatch_is_rejected():
    km = KeyManager.generate("island-1")
    tok = _assert(km, aud="https://wrong.audience.example")
    with pytest.raises(IslandAssertionError):
        verify_island_assertion(tok, jwks=km.jwks_document(), expected_iss=ISS,
                                expected_aud=AUD, expected_nonce="n1", now=1000)


def test_missing_kid_in_header_is_rejected():
    km = KeyManager.generate("island-1")
    claims = {"iss": ISS, "sub": "42", "aud": AUD, "nonce": "n1", "exp": 2000}
    tok = pyjwt.encode(claims, km.private_pem(), algorithm="EdDSA", headers={})
    with pytest.raises(IslandAssertionError):
        verify_island_assertion(tok, jwks=km.jwks_document(), expected_iss=ISS,
                                expected_aud=AUD, expected_nonce="n1", now=1000)
