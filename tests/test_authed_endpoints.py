# tests/test_authed_endpoints.py
from fastapi.testclient import TestClient

from identity.keys import KeyManager
from identity.store.memory import InMemoryIdentityStore
from identity.jwt_issuer import mint
from identity.service_principal import grant_connection_use

from vault.app import build_app
from vault.access import AccessService
from vault.config import VaultConfig
from vault.store.memory import InMemoryStore
from vault.model import Connection, Token
from vault.providers.fortnox import FortnoxProvider
from vault.providers.base import AppCred
from vault.kernel_auth import make_kernel_auth, make_manage_authorizer

ISSUER = "https://id.local"
AUD = "https://vault.local"
CONN = "caput-venti%2Ffortnox%2F559401-5157"
NOW = 1100.0


def _harness():
    store = InMemoryStore()
    store.put_connection(Connection(
        id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
        scopes=["bookkeeping"], app_cred_ref="fortnox",
        token=Token("A", "R", 99999.0, "bookkeeping"), rotation="rotating",
        lease=None, created_by="prn_owner", created_at=0.0, updated_at=0.0))
    cfg = VaultConfig(now_fn=lambda: NOW, http_post=lambda *a: {},
                      app_creds={"fortnox": AppCred("c", "s")}, state_hmac_key=b"k", skew=60)
    service = AccessService(store, {"fortnox": FortnoxProvider()}, cfg)
    km = KeyManager.generate("kid-1")
    ident = InMemoryIdentityStore()
    require_principal, authorizer = make_kernel_auth(
        jwks_provider=lambda: km.jwks_document(), audience=AUD, issuer=ISSUER,
        now_fn=lambda: NOW, identity_store=ident, vault_store=service.store)
    manage_authorizer = make_manage_authorizer(
        now_fn=lambda: NOW, identity_store=ident, vault_store=service.store)
    app = build_app(service, require_principal=require_principal, authorizer=authorizer,
                    manage_authorizer=manage_authorizer)
    return app, km, ident


def _jwt(km, sub, roles=("member",)):
    return mint(km=km, issuer=ISSUER, sub=sub, typ="human", audience=AUD,
                org="caput-venti", roles=list(roles), ttl=300, now=int(NOW))


def test_list_requires_bearer():
    app, _, _ = _harness()
    assert TestClient(app).get("/connections?org=caput-venti").status_code == 401


def test_revoke_requires_bearer():
    app, _, _ = _harness()
    assert TestClient(app).delete(f"/connections/{CONN}").status_code == 401


def test_grant_forbidden_without_manage_grant():
    app, km, _ = _harness()
    token = _jwt(km, "prn_nogrant")
    r = TestClient(app).post(f"/connections/{CONN}/grant",
                             headers={"Authorization": f"Bearer {token}"},
                             json={"principalId": "prn_z", "access": "use"})
    assert r.status_code == 403


def test_owner_can_list_and_grant():
    app, km, _ = _harness()
    token = _jwt(km, "prn_owner")
    h = {"Authorization": f"Bearer {token}"}
    assert TestClient(app).get("/connections?org=caput-venti", headers=h).status_code == 200
    r = TestClient(app).post(f"/connections/{CONN}/grant", headers=h,
                             json={"principalId": "prn_z", "access": "use"})
    assert r.status_code == 200 and r.json()["principalId"] == "prn_z"
