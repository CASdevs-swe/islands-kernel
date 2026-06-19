import pytest
from identity.store.memory import InMemoryIdentityStore
from identity.oauth.clients import register_client
from identity.oauth.authorize_endpoint import issue_auth_code, build_consent
from identity.tokens import hash_token


def _store():
    s = InMemoryIdentityStore()
    register_client(s, client_id="cli_1", name="Claude",
                    redirect_uris=["https://claude.ai/cb"], type="public")
    return s


def test_issue_auth_code_persists_hashed_single_use_code():
    s = _store()
    code = issue_auth_code(s, client_id="cli_1", principal_id="prn_1",
                           org_id="org_1", redirect_uri="https://claude.ai/cb",
                           code_challenge="chal", audience="https://mcp.x",
                           scope="mcp", now=1000)
    row = s.get_auth_code(hash_token(code))
    assert row is not None
    assert row.consumed_at is None
    assert row.code_challenge == "chal"
    assert row.expires_at == 1600


def test_bad_redirect_uri_is_rejected():
    s = _store()
    with pytest.raises(ValueError):
        issue_auth_code(s, client_id="cli_1", principal_id="prn_1", org_id="org_1",
                        redirect_uri="https://evil.x/cb", code_challenge="chal",
                        audience="https://mcp.x", scope="mcp", now=1000)


def test_consent_payload_shape():
    s = _store()
    c = s.get_oauth_client("cli_1")
    payload = build_consent(client=c, scope="mcp", audience="https://mcp.x")
    assert payload["client_name"] == "Claude"
    assert payload["scope"] == "mcp"
