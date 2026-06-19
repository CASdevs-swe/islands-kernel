from identity.store.memory import InMemoryIdentityStore
from identity.model import (
    Principal, Org, Membership, Grant, GrantTarget, McpToken, AccessLog,
)


def _principal(pid="prn_1", email="a@b.se"):
    return Principal(id=pid, type="human", email=email,
                     display_name=None, public_key=None, created_at=0.0)


def _stores():
    return [InMemoryIdentityStore()]


def test_principal_put_get_and_by_email():
    for s in _stores():
        s.put_principal(_principal())
        assert s.get_principal("prn_1").email == "a@b.se"
        assert s.get_principal_by_email("a@b.se").id == "prn_1"
        assert s.get_principal("nope") is None


def test_membership_lookup():
    for s in _stores():
        s.put_membership(Membership("prn_1", "org_1", ["owner"], True, 0.0))
        assert s.get_membership("prn_1", "org_1").roles == ["owner"]
        assert len(s.list_memberships("prn_1")) == 1


def test_grant_add_list_revoke():
    for s in _stores():
        g = Grant("grant_1", "prn_1", GrantTarget("org", "org_1"),
                  "use", None, "prn_owner", 0.0, None)
        s.add_grant(g)
        assert len(s.list_grants("prn_1")) == 1
        s.revoke_grant("grant_1", at=5.0)
        assert s.list_grants("prn_1")[0].revoked_at == 5.0


def test_mcp_token_lookup_by_hash():
    for s in _stores():
        s.put_mcp_token(McpToken("h", "prn_1", "org_1", "aud", "mcp", None, None))
        assert s.get_mcp_token("h").principal_id == "prn_1"
        assert s.get_mcp_token("missing") is None


def test_log_is_append_only():
    for s in _stores():
        s.append_log(AccessLog("prn_1", "org_1", "bk", "reconcile", 0.0))
        s.append_log(AccessLog("prn_1", "org_1", "bk", "reconcile", 1.0))
        assert len(s.read_log("prn_1")) == 2
