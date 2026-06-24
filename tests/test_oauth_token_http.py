"""App-level /oauth/token tests: a real OAuth client (Claude's connector) posts
application/x-www-form-urlencoded and uses RFC 8707 `resource`, not `audience`."""
from fastapi.testclient import TestClient
from identity.app import build_identity_app
from identity.keys import KeyManager
from identity.store.memory import InMemoryIdentityStore
from identity.oauth.clients import register_client
from identity.oauth.authorize_endpoint import issue_auth_code
from identity.oauth.pkce import make_challenge

VERIFIER = "v" * 64
MCP = "https://mcp.x"


def _client_with_code(audience=MCP):
    s = InMemoryIdentityStore()
    register_client(s, client_id="cli_1", name="Claude",
                    redirect_uris=["https://claude.ai/cb"], type="public")
    code = issue_auth_code(s, client_id="cli_1", principal_id="prn_1", org_id="org_1",
                           redirect_uri="https://claude.ai/cb",
                           code_challenge=make_challenge(VERIFIER),
                           audience=audience, scope="mcp", now=1000)
    km = KeyManager.generate("kid-1")
    app = build_identity_app(store=s, key_manager=km, issuer="https://id.x", now_fn=lambda: 1000.0)
    return TestClient(app), code


def test_token_endpoint_accepts_form_urlencoded():
    c, code = _client_with_code()
    r = c.post("/oauth/token", data={"grant_type": "authorization_code", "code": code,
                                     "code_verifier": VERIFIER, "audience": MCP})
    assert r.status_code == 200, r.text
    assert r.json()["access_token"].startswith("at_")


def test_token_endpoint_maps_rfc8707_resource_to_audience():
    # A spec-compliant client sends `resource`, not `audience`, in the token request.
    c, code = _client_with_code()
    r = c.post("/oauth/token", data={"grant_type": "authorization_code", "code": code,
                                     "code_verifier": VERIFIER, "resource": MCP})
    assert r.status_code == 200, r.text


def test_token_endpoint_tolerates_omitted_resource():
    # `resource` in the token request is optional; the audience is already bound to the code.
    c, code = _client_with_code()
    r = c.post("/oauth/token", data={"grant_type": "authorization_code", "code": code,
                                     "code_verifier": VERIFIER})
    assert r.status_code == 200, r.text


def test_token_endpoint_rejects_audience_mismatch_when_supplied():
    c, code = _client_with_code()
    r = c.post("/oauth/token", data={"grant_type": "authorization_code", "code": code,
                                     "code_verifier": VERIFIER, "resource": "https://evil.x"})
    assert r.status_code == 400, r.text


def test_token_endpoint_still_accepts_json():
    c, code = _client_with_code()
    r = c.post("/oauth/token", json={"grant_type": "authorization_code", "code": code,
                                     "code_verifier": VERIFIER, "audience": MCP})
    assert r.status_code == 200, r.text


def test_token_endpoint_ignores_unknown_client_fields():
    # OAuth clients also send client_id/redirect_uri in the token request — must be ignored.
    c, code = _client_with_code()
    r = c.post("/oauth/token", data={"grant_type": "authorization_code", "code": code,
                                     "code_verifier": VERIFIER, "resource": MCP,
                                     "client_id": "https://claude.ai/cimd", "redirect_uri": "https://claude.ai/cb"})
    assert r.status_code == 200, r.text
