from fastapi.testclient import TestClient
from identity.app import build_identity_app
from identity.keys import KeyManager
from identity.store.memory import InMemoryIdentityStore
from identity.model import McpToken, Membership
from identity.tokens import hash_token
from identity.jwt_verify import verify_island_jwt


def _app():
    s = InMemoryIdentityStore()
    s.put_mcp_token(McpToken(hash=hash_token("mcp_abc"), principal_id="prn_1",
                             org_id="org_1", audience="https://mcp.x", scope="mcp",
                             expires_at=10_000, revoked_at=None))
    s.put_membership(Membership("prn_1", "org_1", ["owner"], True, 0.0))
    km = KeyManager.generate("kid-1")
    app = build_identity_app(store=s, key_manager=km, issuer="https://id.x",
                             now_fn=lambda: 1000.0)
    return app, km


def test_jwks_endpoint_serves_public_key():
    app, km = _app()
    r = TestClient(app).get("/.well-known/jwks.json")
    assert r.status_code == 200
    assert r.json()["keys"][0]["kid"] == "kid-1"


def test_exchange_endpoint_mints_short_lived_jwt():
    app, km = _app()
    r = TestClient(app).post("/auth/exchange",
                             json={"opaque_token": "mcp_abc", "audience": "https://mcp.x"})
    assert r.status_code == 200
    token = r.json()["access_token"]
    claims = verify_island_jwt(token, jwks=km.jwks_document(),
                               audience="https://mcp.x", now=1100, issuer="https://id.x")
    assert claims["sub"] == "prn_1"
    assert claims["exp"] - claims["iat"] == 300   # 5-minute TTL


def test_exchange_rejects_audience_mismatch():
    app, _ = _app()
    r = TestClient(app).post("/auth/exchange",
                             json={"opaque_token": "mcp_abc", "audience": "https://other.x"})
    assert r.status_code == 400
