from fastapi.testclient import TestClient
from identity.app import build_identity_app
from identity.keys import KeyManager
from identity.store.memory import InMemoryIdentityStore


def _client():
    km = KeyManager.generate("kid-1")
    app = build_identity_app(store=InMemoryIdentityStore(), key_manager=km,
                             issuer="https://id.x", now_fn=lambda: 1000.0)
    return TestClient(app)


def test_exchange_missing_field_is_422_not_500():
    r = _client().post("/auth/exchange", json={"audience": "https://mcp.x"})
    assert r.status_code == 422


def test_authorize_missing_field_is_422_not_500():
    r = _client().post("/oauth/authorize", json={"client_id": "c1"})
    assert r.status_code == 422


def test_token_code_branch_missing_field_is_400_not_500():
    r = _client().post("/oauth/token", json={"code": "x"})
    assert r.status_code == 400


def test_token_refresh_branch_missing_field_is_400_not_500():
    r = _client().post("/oauth/token", json={"grant_type": "refresh_token"})
    assert r.status_code == 400
