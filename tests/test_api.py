from fastapi.testclient import TestClient
from vault.store.memory import InMemoryStore
from vault.model import Connection, Token
from vault.providers.fortnox import FortnoxProvider
from vault.providers.base import AppCred
from vault.access import AccessService
from vault.config import VaultConfig
from vault.app import build_app


def _client():
    store = InMemoryStore()
    store.put_connection(Connection(
        id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
        scopes=["bookkeeping"], app_cred_ref="fortnox", token=Token("ACCESS", "REFRESH", 99999.0, "bookkeeping"),
        rotation="rotating", lease=None, created_by="owner", created_at=0.0, updated_at=0.0))
    cfg = VaultConfig(now_fn=lambda: 1000.0, http_post=lambda *a: {},
                      app_creds={"fortnox": AppCred("c", "s")}, state_hmac_key=b"k")
    svc = AccessService(store, {"fortnox": FortnoxProvider()}, cfg)
    return TestClient(build_app(svc)), store


CID = "caput-venti%2Ffortnox%2F559401-5157"


def test_access_token_endpoint_omits_refresh():
    client, _ = _client()
    r = client.post(f"/connections/{CID}/access-token",
                    headers={"X-Principal": "owner", "X-Island": "bookkeeping"})
    assert r.status_code == 200
    body = r.json()
    assert body == {"accessToken": "ACCESS", "scope": "bookkeeping", "expiresAt": 99999.0}
    assert "refresh" not in r.text.lower()


def test_access_token_denied_for_stranger_is_403():
    client, _ = _client()
    r = client.post(f"/connections/{CID}/access-token",
                    headers={"X-Principal": "stranger", "X-Island": "bookkeeping"})
    assert r.status_code == 403


def test_grant_then_use():
    client, _ = _client()
    g = client.post(f"/connections/{CID}/grant", headers={"X-Principal": "owner"},
                    json={"principalId": "mate", "access": "use"})
    assert g.status_code == 200
    r = client.post(f"/connections/{CID}/access-token",
                    headers={"X-Principal": "mate", "X-Island": "bookkeeping"})
    assert r.status_code == 200
