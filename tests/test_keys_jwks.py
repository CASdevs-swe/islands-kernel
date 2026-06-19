from identity.keys import KeyManager
from identity.tokens import b64url


def test_jwks_document_shape():
    km = KeyManager.generate("kid-1")
    doc = km.jwks_document()
    jwk = doc["keys"][0]
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == "Ed25519"
    assert jwk["alg"] == "EdDSA"
    assert jwk["use"] == "sig"
    assert jwk["kid"] == "kid-1"
    assert "x" in jwk and "d" not in jwk  # public only, no private scalar


def test_from_seed_is_deterministic():
    seed = b64url(b"\x01" * 32)
    a = KeyManager.from_seed("kid-1", seed).public_jwk()
    b = KeyManager.from_seed("kid-1", seed).public_jwk()
    assert a == b


def test_private_pem_is_not_in_jwks():
    km = KeyManager.generate("kid-1")
    assert b"PRIVATE" in km.private_pem()
    assert "PRIVATE" not in str(km.jwks_document())
