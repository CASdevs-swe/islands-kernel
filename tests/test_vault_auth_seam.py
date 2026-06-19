import pytest
from fastapi import HTTPException
from identity.keys import KeyManager
from identity.jwt_issuer import mint
from identity.deps import make_require_principal


def _dep(km, now=1100):
    return make_require_principal(jwks_provider=lambda: km.jwks_document(),
                                  audience="https://vault.x", now_fn=lambda: now,
                                  issuer="https://id.x")


def _token(km, aud="https://vault.x"):
    return mint(km=km, issuer="https://id.x", sub="prn_1", typ="human",
                audience=aud, org="org_1", roles=["owner"], ttl=300, now=1000)


def test_bearer_header_resolves_claims():
    km = KeyManager.generate("kid-1")
    dep = _dep(km)
    claims = dep(authorization=f"Bearer {_token(km)}", cookie_auth=None)
    assert claims["sub"] == "prn_1"


def test_cookie_fallback_resolves_claims():
    km = KeyManager.generate("kid-1")
    dep = _dep(km)
    claims = dep(authorization=None, cookie_auth=_token(km))
    assert claims["sub"] == "prn_1"


def test_missing_token_is_401():
    km = KeyManager.generate("kid-1")
    dep = _dep(km)
    with pytest.raises(HTTPException) as e:
        dep(authorization=None, cookie_auth=None)
    assert e.value.status_code == 401


def test_wrong_audience_is_401():
    km = KeyManager.generate("kid-1")
    dep = _dep(km)
    with pytest.raises(HTTPException) as e:
        dep(authorization=f"Bearer {_token(km, aud='https://other')}", cookie_auth=None)
    assert e.value.status_code == 401
