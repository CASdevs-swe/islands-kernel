import time
from identity.store.memory import InMemoryIdentityStore
from identity.model import IslandRegistry, Org
from identity.federation.principals import find_or_create_island_principal


def _store():
    s = InMemoryIdentityStore()
    s.put_org(Org(id="org_unnest", name="unnest", created_at=0.0))
    s.put_island(IslandRegistry(id="unnest", name="unnest", issuer="https://app.unnest.se",
        jwks_uri="x", audience="https://mcp.unnest.se/mcp", sso_authorize_url="x",
        sso_token_url="x", sso_client_secret_hash="x", org_id="org_unnest",
        session_ttl_days=30.0, created_at=0.0))
    return s


def test_first_call_creates_principal_link_and_membership():
    s = _store()
    pid = find_or_create_island_principal(s, island=s.get_island("unnest"),
                                          island_user_id="42", email="a@b.se", now=1000.0)
    assert pid.startswith("prn_")
    assert s.get_principal(pid).email == "a@b.se"
    assert s.get_membership(pid, "org_unnest").active is True
    assert s.get_principal_by_island("unnest", "42") == pid


def test_second_call_same_user_returns_same_principal():
    s = _store()
    a = find_or_create_island_principal(s, island=s.get_island("unnest"),
                                        island_user_id="42", email="a@b.se", now=1000.0)
    b = find_or_create_island_principal(s, island=s.get_island("unnest"),
                                        island_user_id="42", email="a@b.se", now=2000.0)
    assert a == b
