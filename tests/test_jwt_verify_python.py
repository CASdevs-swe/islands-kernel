import pytest
from identity.keys import KeyManager
from identity.jwt_issuer import mint
from identity.jwt_verify import verify_island_jwt


def _token(km, now=1000, ttl=300, aud="https://mcp.x", org="org_1"):
    return mint(km=km, issuer="https://id.x", sub="prn_1", typ="human",
                audience=aud, org=org, roles=["owner"], ttl=ttl, now=now,
                email="a@b.se")


def test_valid_token_verifies():
    km = KeyManager.generate("kid-1")
    claims = verify_island_jwt(_token(km), jwks=km.jwks_document(),
                               audience="https://mcp.x", now=1100,
                               issuer="https://id.x")
    assert claims["sub"] == "prn_1"
    assert claims["org"] == "org_1"


def test_expired_token_is_rejected():
    km = KeyManager.generate("kid-1")
    with pytest.raises(ValueError):
        verify_island_jwt(_token(km, now=0, ttl=300), jwks=km.jwks_document(),
                          audience="https://mcp.x", now=10_000)


def test_wrong_audience_is_rejected():
    km = KeyManager.generate("kid-1")
    with pytest.raises(ValueError):
        verify_island_jwt(_token(km, aud="https://mcp.A"), jwks=km.jwks_document(),
                          audience="https://mcp.B", now=1100)


def test_unknown_kid_is_rejected():
    km1 = KeyManager.generate("kid-1")
    km2 = KeyManager.generate("kid-2")
    with pytest.raises(ValueError):
        verify_island_jwt(_token(km1), jwks=km2.jwks_document(),
                          audience="https://mcp.x", now=1100)


def test_tampered_signature_is_rejected():
    km1 = KeyManager.generate("kid-1")
    # sign with a different key but advertise kid-1 in the JWKS we present
    km_impostor = KeyManager.generate("kid-1")
    with pytest.raises(ValueError):
        verify_island_jwt(_token(km_impostor), jwks=km1.jwks_document(),
                          audience="https://mcp.x", now=1100)
