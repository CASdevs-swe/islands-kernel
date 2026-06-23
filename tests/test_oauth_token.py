import pytest
from identity.store.memory import InMemoryIdentityStore
from identity.model import IslandRegistry
from identity.oauth.clients import register_client
from identity.oauth.authorize_endpoint import issue_auth_code
from identity.oauth.token_endpoint import redeem_code, refresh
from identity.oauth.pkce import make_challenge


def _setup(verifier="v" * 64):
    s = InMemoryIdentityStore()
    register_client(s, client_id="cli_1", name="Claude",
                    redirect_uris=["https://claude.ai/cb"], type="public")
    code = issue_auth_code(s, client_id="cli_1", principal_id="prn_1",
                           org_id="org_1", redirect_uri="https://claude.ai/cb",
                           code_challenge=make_challenge(verifier),
                           audience="https://mcp.x", scope="mcp", now=1000)
    return s, code, verifier


def test_redeem_code_issues_tokens():
    s, code, verifier = _setup()
    out = redeem_code(s, code=code, code_verifier=verifier,
                      audience="https://mcp.x", now=1001)
    assert out["token_type"] == "Bearer"
    assert out["expires_in"] == 3600
    assert out["access_token"].startswith("at_")
    assert out["refresh_token"].startswith("rt_")


def test_code_is_single_use():
    s, code, verifier = _setup()
    redeem_code(s, code=code, code_verifier=verifier, audience="https://mcp.x", now=1001)
    with pytest.raises(ValueError):
        redeem_code(s, code=code, code_verifier=verifier, audience="https://mcp.x", now=1002)


def test_bad_pkce_verifier_rejected():
    s, code, _ = _setup()
    with pytest.raises(ValueError):
        redeem_code(s, code=code, code_verifier="wrong", audience="https://mcp.x", now=1001)


def test_refresh_rotates_and_old_token_is_dead():
    s, code, verifier = _setup()
    issued = redeem_code(s, code=code, code_verifier=verifier,
                         audience="https://mcp.x", now=1001)
    rotated = refresh(s, refresh_token=issued["refresh_token"], now=2000)
    assert rotated["refresh_token"] != issued["refresh_token"]
    # replay of the old refresh token must fail
    with pytest.raises(ValueError):
        refresh(s, refresh_token=issued["refresh_token"], now=2001)


def _island(s, audience, days):
    s.put_island(IslandRegistry(id="unnest", name="unnest", issuer="https://app.unnest.se",
        jwks_uri="x", audience=audience, sso_authorize_url="x", sso_token_url="x",
        sso_client_secret_hash="x", org_id="org_unnest", session_ttl_days=days, created_at=0.0))


def test_refresh_ttl_is_sized_by_registered_island():
    s, code, verifier = _setup()  # audience="https://mcp.x"
    _island(s, "https://mcp.x", days=7.0)
    redeem_code(s, code=code, code_verifier=verifier, audience="https://mcp.x", now=1001)
    at_hash = next(iter(s.access_token_hashes()))
    row = s.get_access_token(at_hash)
    assert row.refresh["expires_at"] == 1001 + 7 * 86400


def test_refresh_ttl_defaults_to_30_days_when_no_island():
    s, code, verifier = _setup()
    redeem_code(s, code=code, code_verifier=verifier, audience="https://mcp.x", now=1001)
    row = s.get_access_token(next(iter(s.access_token_hashes())))
    assert row.refresh["expires_at"] == 1001 + 30 * 86400
