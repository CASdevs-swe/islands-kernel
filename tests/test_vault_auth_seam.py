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


# ---------------------------------------------------------------------------
# App-level tests (Task 12)
# ---------------------------------------------------------------------------
from fastapi.testclient import TestClient
from vault.app import build_app
from vault.access import AccessService
from vault.config import VaultConfig
from vault.store.memory import InMemoryStore
from vault.model import Connection, Token
from vault.providers.fortnox import FortnoxProvider
from vault.providers.base import AppCred


def _vault_service():
    store = InMemoryStore()
    store.put_connection(Connection(
        id="conn_1", org="org_1", provider="fortnox", account="559401-5157",
        scopes=["bookkeeping"], app_cred_ref="fortnox",
        token=Token("ACCESS", "REFRESH", 99999.0, "bookkeeping"),
        rotation="rotating", lease=None, created_by="prn_owner",
        created_at=0.0, updated_at=0.0))
    cfg = VaultConfig(now_fn=lambda: 1000.0, http_post=lambda *a: {},
                      app_creds={"fortnox": AppCred("cid", "secret")},
                      state_hmac_key=b"k", skew=60)
    return AccessService(store, {"fortnox": FortnoxProvider()}, cfg)


def test_access_token_route_requires_valid_jwt():
    km = KeyManager.generate("kid-1")
    dep = make_require_principal(jwks_provider=lambda: km.jwks_document(),
                                 audience="https://vault.x", now_fn=lambda: 1100.0,
                                 issuer="https://id.x")
    app = build_app(_vault_service(), require_principal=dep)
    client = TestClient(app)

    # no token -> 401
    r = client.post("/connections/org_1%2Ffortnox%2F559401-5157/access-token")
    assert r.status_code == 401

    # owner token -> 200, no refresh token leaked
    owner = mint(km=km, issuer="https://id.x", sub="prn_owner", typ="human",
                 audience="https://vault.x", org="org_1", roles=["owner"],
                 ttl=300, now=1000)
    r = client.post("/connections/org_1%2Ffortnox%2F559401-5157/access-token",
                    headers={"Authorization": f"Bearer {owner}"})
    assert r.status_code == 200
    assert r.json()["accessToken"] == "ACCESS"
    assert "refresh" not in r.text.lower()
