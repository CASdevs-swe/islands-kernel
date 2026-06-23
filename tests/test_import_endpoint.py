"""Endpoint tests for POST /connections/{conn_id}/import on both branches."""
from fastapi.testclient import TestClient

from identity.keys import KeyManager
from identity.store.memory import InMemoryIdentityStore
from identity.jwt_issuer import mint

from vault.app import build_app
from vault.access import AccessService
from vault.config import VaultConfig
from vault.store.memory import InMemoryStore
from vault.providers.fortnox import FortnoxProvider
from vault.providers.base import AppCred
from vault.kernel_auth import make_kernel_auth, make_manage_authorizer

ISSUER = "https://id.local"
AUD = "https://vault.local"
NOW = 1100.0
CONN = "caput-venti%2Ffortnox%2F559401-5157"
OTHER_CONN = "magic-studios%2Ffortnox%2F000000-0000"

BODY = {"accessToken": "ACC", "refreshToken": "REF", "expiresAt": 99999.0,
        "scope": "bookkeeping"}


def _stub_client():
    store = InMemoryStore()
    cfg = VaultConfig(now_fn=lambda: NOW, http_post=lambda *a: {},
                      app_creds={"fortnox": AppCred("c", "s")}, state_hmac_key=b"k", skew=60)
    svc = AccessService(store, {"fortnox": FortnoxProvider()}, cfg)
    return TestClient(build_app(svc)), store


def _authed_client():
    store = InMemoryStore()
    cfg = VaultConfig(now_fn=lambda: NOW, http_post=lambda *a: {},
                      app_creds={"fortnox": AppCred("c", "s")}, state_hmac_key=b"k", skew=60)
    svc = AccessService(store, {"fortnox": FortnoxProvider()}, cfg)
    km = KeyManager.generate("kid-1")
    ident = InMemoryIdentityStore()
    require_principal, authorizer = make_kernel_auth(
        jwks_provider=lambda: km.jwks_document(), audience=AUD, issuer=ISSUER,
        now_fn=lambda: NOW, identity_store=ident, vault_store=svc.store)
    manage_authorizer = make_manage_authorizer(
        now_fn=lambda: NOW, identity_store=ident, vault_store=svc.store)
    app = build_app(svc, require_principal=require_principal, authorizer=authorizer,
                    manage_authorizer=manage_authorizer)
    return TestClient(app), km, store


def _jwt(km, sub, org="caput-venti"):
    return mint(km=km, issuer=ISSUER, sub=sub, typ="human", audience=AUD,
                org=org, roles=["member"], ttl=300, now=int(NOW))


def test_stub_branch_import_returns_connection_id():
    client, store = _stub_client()
    r = client.post(f"/connections/{CONN}/import", headers={"X-Principal": "caput-venti"},
                    json=BODY)
    assert r.status_code == 200
    assert r.json()["connectionId"]
    # readable back through the access-token route
    a = client.post(f"/connections/{CONN}/access-token",
                    headers={"X-Principal": "caput-venti", "X-Island": "cutover"})
    assert a.status_code == 200 and a.json()["accessToken"] == "ACC"


def test_authed_branch_import_binds_created_by_to_sub():
    client, km, store = _authed_client()
    token = _jwt(km, "prn_owner")
    r = client.post(f"/connections/{CONN}/import",
                    headers={"Authorization": f"Bearer {token}"}, json=BODY)
    assert r.status_code == 200 and r.json()["connectionId"]
    from vault.model import ConnKey
    conn = store.get_connection(ConnKey("caput-venti", "fortnox", "559401-5157"))
    assert conn.created_by == "prn_owner"


def test_authed_branch_requires_bearer():
    client, _, _ = _authed_client()
    assert client.post(f"/connections/{CONN}/import", json=BODY).status_code == 401


def test_cross_org_import_is_403():
    client, km, store = _authed_client()
    token = _jwt(km, "prn_owner", org="caput-venti")
    # JWT org is caput-venti but the target connection is in magic-studios
    r = client.post(f"/connections/{OTHER_CONN}/import",
                    headers={"Authorization": f"Bearer {token}"}, json=BODY)
    assert r.status_code == 403


def test_malformed_body_is_400():
    client, km, _ = _authed_client()
    token = _jwt(km, "prn_owner")
    bad = dict(BODY, expiresAt="not-a-number")
    r = client.post(f"/connections/{CONN}/import",
                    headers={"Authorization": f"Bearer {token}"}, json=bad)
    assert r.status_code == 400
