import urllib.parse as up
import jwt as pyjwt
from fastapi.testclient import TestClient
from identity.app import build_identity_app
from identity.keys import KeyManager
from identity.store.memory import InMemoryIdentityStore
from identity.model import IslandRegistry, Org
from identity.oauth.clients import register_client
from identity.oauth.pkce import make_challenge
from identity.oauth.token_endpoint import redeem_code

KERNEL_ISS = "https://id.caputventi.com"
ISLAND_ISS = "https://app.unnest.se"
AUD = "https://mcp.unnest.se/mcp"


def _app(island_km):
    s = InMemoryIdentityStore()
    s.put_org(Org(id="org_unnest", name="unnest", created_at=0.0))
    register_client(s, client_id="cli_1", name="Claude", redirect_uris=["https://claude.ai/cb"], type="public")
    s.put_island(IslandRegistry(id="unnest", name="unnest", issuer=ISLAND_ISS,
        jwks_uri="https://app.unnest.se/jwks", audience=AUD,
        sso_authorize_url="https://app.unnest.se/sso/authorize",
        sso_token_url="https://app.unnest.se/sso/token", sso_client_secret_hash="x",
        org_id="org_unnest", session_ttl_days=30.0, created_at=0.0))

    def island_fetch(island, sso_code):
        # nonce is read from the redirect by the test and injected via a closure cell below
        return island_fetch.make(island_fetch.nonce)
    island_fetch.make = lambda nonce: pyjwt.encode(
        {"iss": ISLAND_ISS, "sub": "42", "aud": KERNEL_ISS, "nonce": nonce, "exp": 9999, "email": "a@b.se"},
        island_km.private_pem(), algorithm="EdDSA", headers={"kid": island_km.kid})

    app = build_identity_app(store=s, key_manager=KeyManager.generate("kid-1"),
        issuer=KERNEL_ISS, now_fn=lambda: 1000.0, island_fetch=island_fetch,
        island_jwks_fetch=lambda island: island_km.jwks_document())
    return app, s, island_fetch


def test_authorize_redirects_to_island_then_callback_issues_code():
    island_km = KeyManager.generate("island-1")
    app, s, island_fetch = _app(island_km)
    client = TestClient(app)
    verifier = "v" * 64
    r = client.get("/oauth/authorize", params={"client_id": "cli_1",
        "redirect_uri": "https://claude.ai/cb", "code_challenge": make_challenge(verifier),
        "code_challenge_method": "S256", "resource": AUD, "scope": "mcp", "state": "STATE"},
        follow_redirects=False)
    assert r.status_code in (302, 307)
    loc = r.headers["location"]
    assert loc.startswith("https://app.unnest.se/sso/authorize?")
    q = dict(up.parse_qsl(up.urlsplit(loc).query))
    island_fetch.nonce = q["nonce"]

    r2 = client.get("/oauth/callback", params={"txn": q["txn"], "sso_code": "c"}, follow_redirects=False)
    assert r2.status_code == 302
    cq = dict(up.parse_qsl(up.urlsplit(r2.headers["location"]).query))
    assert cq["state"] == "STATE"
    out = redeem_code(s, code=cq["code"], code_verifier=verifier, audience=AUD, now=1100)
    assert out["access_token"].startswith("at_")
