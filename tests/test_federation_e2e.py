import urllib.parse as up
import jwt as pyjwt
from fastapi.testclient import TestClient
from identity.app import build_identity_app
from identity.keys import KeyManager
from identity.store.memory import InMemoryIdentityStore
from identity.model import IslandRegistry, Org
from identity.oauth.clients import register_client
from identity.oauth.pkce import make_challenge
from identity.jwt_verify import verify_island_jwt

KERNEL_ISS = "https://id.caputventi.com"
ISLAND_ISS = "https://app.unnest.se"
AUD = "https://mcp.unnest.se/mcp"


def _build():
    island_km = KeyManager.generate("island-1")
    kernel_km = KeyManager.generate("kid-1")
    s = InMemoryIdentityStore()
    s.put_org(Org(id="org_unnest", name="unnest", created_at=0.0))
    register_client(s, client_id="cli_1", name="Claude", redirect_uris=["https://claude.ai/cb"], type="public")
    s.put_island(IslandRegistry(id="unnest", name="unnest", issuer=ISLAND_ISS,
        jwks_uri="https://app.unnest.se/jwks", audience=AUD,
        sso_authorize_url="https://app.unnest.se/sso/authorize",
        sso_token_url="https://app.unnest.se/sso/token", sso_client_secret_hash="x",
        org_id="org_unnest", session_ttl_days=30.0, created_at=0.0))

    # Stub island: signs an assertion for user "42" echoing whatever nonce it is told.
    def island_fetch(island, sso_code):
        return pyjwt.encode({"iss": ISLAND_ISS, "sub": "42", "aud": KERNEL_ISS,
            "nonce": island_fetch.nonce, "exp": 9_999_999_999, "email": "a@b.se", "workspace": "ws_7"},
            island_km.private_pem(), algorithm="EdDSA", headers={"kid": island_km.kid})

    app = build_identity_app(store=s, key_manager=kernel_km, issuer=KERNEL_ISS,
        now_fn=lambda: 1000.0, island_fetch=island_fetch,
        island_jwks_fetch=lambda island: island_km.jwks_document())
    return TestClient(app), kernel_km, island_fetch


def test_end_to_end_login_yields_jwt_with_island_native_id():
    client, kernel_km, island_fetch = _build()
    verifier = "v" * 64
    # 1. authorize -> island redirect
    r = client.get("/oauth/authorize", params={"client_id": "cli_1",
        "redirect_uri": "https://claude.ai/cb", "code_challenge": make_challenge(verifier),
        "code_challenge_method": "S256", "resource": AUD, "scope": "mcp", "state": "ST"},
        follow_redirects=False)
    q = dict(up.parse_qsl(up.urlsplit(r.headers["location"]).query))
    island_fetch.nonce = q["nonce"]
    # 2. island returns the user -> callback issues the OAuth code
    r2 = client.get("/oauth/callback", params={"txn": q["txn"], "sso_code": "c"}, follow_redirects=False)
    code = dict(up.parse_qsl(up.urlsplit(r2.headers["location"]).query))["code"]
    # 3. token exchange -> opaque access token
    r3 = client.post("/oauth/token", json={"grant_type": "authorization_code", "code": code,
        "code_verifier": verifier, "audience": AUD})
    at = r3.json()["access_token"]
    assert at.startswith("at_")
    # 4. island MCP exchanges the opaque token for a short-lived JWT carrying island_sub
    r4 = client.post("/auth/exchange", json={"opaque_token": at, "audience": AUD})
    jwt_tok = r4.json()["access_token"]
    claims = verify_island_jwt(jwt_tok, jwks=kernel_km.jwks_document(), audience=AUD,
                               now=1100, issuer=KERNEL_ISS)
    assert claims["island"] == "unnest"
    assert claims["island_sub"] == "42"
    assert claims["exp"] - claims["iat"] == 300
