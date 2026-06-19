from identity.model import Grant, GrantTarget
from identity.authorize import authorize, adapt_connection_grant, collect_grants
from identity.store.memory import InMemoryIdentityStore
from vault.model import ConnectionGrant


def _grant(target_kind, target_id, access="use", revoked=None, gid="g"):
    return Grant(id=gid, principal_id="prn_1",
                 target=GrantTarget(target_kind, target_id), access=access,
                 scopes_subset=None, granted_by="prn_o", granted_at=0.0,
                 revoked_at=revoked)


def test_exact_target_use_grant_authorizes_use():
    grants = [_grant("connection", "conn_1", "use")]
    assert authorize(grants=grants,
                     target=GrantTarget("connection", "conn_1"),
                     access="use", now=10) is True


def test_manage_satisfies_use():
    grants = [_grant("island", "smartcharge", "manage")]
    assert authorize(grants=grants, target=GrantTarget("island", "smartcharge"),
                     access="use", now=10) is True


def test_use_does_not_satisfy_manage():
    grants = [_grant("island", "smartcharge", "use")]
    assert authorize(grants=grants, target=GrantTarget("island", "smartcharge"),
                     access="manage", now=10) is False


def test_org_grant_covers_nested_target_when_request_org_given():
    grants = [_grant("org", "org_1", "use")]
    assert authorize(grants=grants, target=GrantTarget("connection", "conn_9"),
                     access="use", now=10, request_org="org_1") is True


def test_revoked_grant_is_ignored():
    grants = [_grant("connection", "conn_1", "use", revoked=5.0)]
    assert authorize(grants=grants, target=GrantTarget("connection", "conn_1"),
                     access="use", now=10) is False


def test_no_grant_denies():
    assert authorize(grants=[], target=GrantTarget("connection", "conn_1"),
                     access="use", now=10) is False


def test_adapt_connection_grant_owner_is_manage():
    g = adapt_connection_grant(None, owner_connection_id="conn_1")
    assert g.target == GrantTarget("connection", "conn_1") and g.access == "manage"


def test_adapt_connection_grant_from_row():
    cg = ConnectionGrant(connection_id="conn_1", principal_id="prn_1",
                         access="use", scopes_subset=["read"],
                         granted_by="prn_o", granted_at=0.0)
    g = adapt_connection_grant(cg)
    assert g.target == GrantTarget("connection", "conn_1")
    assert g.access == "use" and g.scopes_subset == ["read"]


def test_collect_merges_identity_and_connection_grants():
    s = InMemoryIdentityStore()
    s.add_grant(_grant("island", "smartcharge", "use", gid="g1"))
    cg = ConnectionGrant("conn_1", "prn_1", "use", None, "prn_o", 0.0)
    out = collect_grants(principal_id="prn_1", identity_store=s,
                         connection_grants=[cg])
    kinds = {g.target.kind for g in out}
    assert kinds == {"island", "connection"}


def test_org_grant_does_not_cover_different_org():
    grants = [_grant("org", "org_1", "use")]
    assert authorize(grants=grants, target=GrantTarget("connection", "conn_9"),
                     access="use", now=10, request_org="org_2") is False


def test_org_grant_does_not_cover_org_kind_target_via_nesting():
    grants = [_grant("org", "org_1", "use")]
    assert authorize(grants=grants, target=GrantTarget("org", "org_2"),
                     access="use", now=10, request_org="org_2") is False
