import pytest
from identity.store.memory import InMemoryIdentityStore
from identity.model import McpToken, Membership, OAuthAccessToken, Principal
from identity.tokens import hash_token
from identity.exchange import exchange, ExchangeError


def _store_with_mcp(raw="mcp_abc", aud="https://mcp.x", exp=2000, revoked=None):
    s = InMemoryIdentityStore()
    s.put_mcp_token(McpToken(hash=hash_token(raw), principal_id="prn_1",
                             org_id="org_1", audience=aud, scope="mcp",
                             expires_at=exp, revoked_at=revoked))
    s.put_membership(Membership("prn_1", "org_1", ["member"], True, 0.0))
    return s


def test_valid_mcp_token_resolves_principal_and_roles():
    s = _store_with_mcp()
    out = exchange(opaque_token="mcp_abc", audience="https://mcp.x", store=s, now=1000)
    assert out["principal_id"] == "prn_1"
    assert out["org_id"] == "org_1"
    assert out["roles"] == ["member"]
    assert out["sid"] is None


def test_audience_mismatch_rejected():
    s = _store_with_mcp(aud="https://mcp.A")
    with pytest.raises(ExchangeError):
        exchange(opaque_token="mcp_abc", audience="https://mcp.B", store=s, now=1000)


def test_expired_token_rejected():
    s = _store_with_mcp(exp=500)
    with pytest.raises(ExchangeError):
        exchange(opaque_token="mcp_abc", audience="https://mcp.x", store=s, now=1000)


def test_revoked_token_rejected():
    s = _store_with_mcp(revoked=900)
    with pytest.raises(ExchangeError):
        exchange(opaque_token="mcp_abc", audience="https://mcp.x", store=s, now=1000)


def test_unknown_token_rejected():
    s = _store_with_mcp()
    with pytest.raises(ExchangeError):
        exchange(opaque_token="mcp_nope", audience="https://mcp.x", store=s, now=1000)


def test_oauth_access_token_path():
    s = InMemoryIdentityStore()
    s.put_access_token(OAuthAccessToken(hash=hash_token("at_xyz"), client_id="cli",
                                        principal_id="prn_2", org_id="org_2",
                                        audience="https://mcp.x", scope="mcp",
                                        expires_at=2000, refresh=None))
    s.put_membership(Membership("prn_2", "org_2", ["admin"], True, 0.0))
    out = exchange(opaque_token="at_xyz", audience="https://mcp.x", store=s, now=1000)
    assert out["principal_id"] == "prn_2" and out["roles"] == ["admin"]


def test_type_is_service_when_principal_is_service():
    s = _store_with_mcp()
    s.put_principal(Principal(id="prn_1", type="service", email=None,
                              display_name=None, public_key=None, created_at=0.0))
    out = exchange(opaque_token="mcp_abc", audience="https://mcp.x", store=s, now=1000)
    assert out["type"] == "service"


def test_type_is_human_when_principal_is_human():
    s = _store_with_mcp()
    s.put_principal(Principal(id="prn_1", type="human", email=None,
                              display_name=None, public_key=None, created_at=0.0))
    out = exchange(opaque_token="mcp_abc", audience="https://mcp.x", store=s, now=1000)
    assert out["type"] == "human"


def test_type_defaults_to_human_when_no_principal_row():
    s = _store_with_mcp()
    # prn_1 has a token and membership but no Principal row in store
    out = exchange(opaque_token="mcp_abc", audience="https://mcp.x", store=s, now=1000)
    assert out["type"] == "human"
