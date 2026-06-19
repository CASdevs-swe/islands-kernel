from identity.store.memory import InMemoryIdentityStore
from identity.service_principal import grant_connection_use
from identity.model import Grant, GrantTarget

from vault.kernel_auth import make_manage_authorizer, make_kernel_auth
from vault.store.memory import InMemoryStore
from vault.model import Connection, Token


def _conn(created_by="prn_owner"):
    return Connection(
        id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
        scopes=["bookkeeping"], app_cred_ref="fortnox",
        token=Token("A", "R", 99999.0, "bookkeeping"), rotation="rotating",
        lease=None, created_by=created_by, created_at=0.0, updated_at=0.0)


def _wiring():
    ident = InMemoryIdentityStore()
    vault = InMemoryStore()
    conn = _conn()
    vault.put_connection(conn)
    return ident, vault, conn


def test_manage_granted_principal_is_allowed():
    ident, vault, conn = _wiring()
    ident.add_grant(Grant(id="g1", principal_id="prn_mgr",
                          target=GrantTarget("connection", "conn_1"), access="manage",
                          scopes_subset=None, granted_by="prn_owner", granted_at=0.0,
                          revoked_at=None))
    mgr = make_manage_authorizer(now_fn=lambda: 1000.0, identity_store=ident, vault_store=vault)
    assert mgr(conn=conn, principal_id="prn_mgr", org="caput-venti") is True


def test_use_only_principal_cannot_manage():
    ident, vault, conn = _wiring()
    grant_connection_use(ident, principal_id="prn_use", connection_id="conn_1",
                         granted_by="prn_owner", now=1000.0)
    mgr = make_manage_authorizer(now_fn=lambda: 1000.0, identity_store=ident, vault_store=vault)
    assert mgr(conn=conn, principal_id="prn_use", org="caput-venti") is False


def test_owner_can_manage_and_use():
    ident, vault, conn = _wiring()
    mgr = make_manage_authorizer(now_fn=lambda: 1000.0, identity_store=ident, vault_store=vault)
    assert mgr(conn=conn, principal_id="prn_owner", org="caput-venti") is True
    _, use_authorizer = make_kernel_auth(
        jwks_provider=lambda: {"keys": []}, audience="https://vault.local",
        issuer="https://id.local", now_fn=lambda: 1000.0,
        identity_store=ident, vault_store=vault)
    assert use_authorizer(conn=conn, principal_id="prn_owner", org="caput-venti") is True


def test_org_grant_does_not_cross_orgs():
    # An org-scoped grant for "caput-venti" must NOT reach a connection in "other-org".
    ident, vault, _ = _wiring()
    # Put a separate connection whose org is different and created_by is someone else.
    other_conn = Connection(
        id="conn_other", org="other-org", provider="fortnox", account="000000-0000",
        scopes=["bookkeeping"], app_cred_ref="fortnox",
        token=Token("A", "R", 99999.0, "bookkeeping"), rotation="rotating",
        lease=None, created_by="prn_other_owner", created_at=0.0, updated_at=0.0)
    vault.put_connection(other_conn)
    # Grant: org-scoped manage over "caput-venti".
    ident.add_grant(Grant(id="g_org", principal_id="prn_org_admin",
                          target=GrantTarget("org", "caput-venti"), access="manage",
                          scopes_subset=None, granted_by="prn_owner", granted_at=0.0,
                          revoked_at=None))
    mgr = make_manage_authorizer(now_fn=lambda: 1000.0, identity_store=ident, vault_store=vault)
    # Caller asserts org="caput-venti" but the connection lives in "other-org" — must be False.
    assert mgr(conn=other_conn, principal_id="prn_org_admin", org="caput-venti") is False


def test_org_grant_covers_same_org_connection():
    # The same org-scoped grant must still reach a connection actually in that org.
    ident, vault, conn = _wiring()
    ident.add_grant(Grant(id="g_org", principal_id="prn_org_admin",
                          target=GrantTarget("org", "caput-venti"), access="manage",
                          scopes_subset=None, granted_by="prn_owner", granted_at=0.0,
                          revoked_at=None))
    mgr = make_manage_authorizer(now_fn=lambda: 1000.0, identity_store=ident, vault_store=vault)
    # conn.org == "caput-venti" matches the grant — must be True.
    assert mgr(conn=conn, principal_id="prn_org_admin", org="caput-venti") is True


def test_blank_principal_does_not_get_owner_grant():
    # Connection whose created_by is blank — owner injection must NOT fire for "" == "".
    ident = InMemoryIdentityStore()
    vault = InMemoryStore()
    conn = _conn(created_by="")
    vault.put_connection(conn)

    mgr = make_manage_authorizer(now_fn=lambda: 1000.0, identity_store=ident, vault_store=vault)
    assert mgr(conn=conn, principal_id="", org="caput-venti") is False

    _, use_authorizer = make_kernel_auth(
        jwks_provider=lambda: {"keys": []}, audience="https://vault.local",
        issuer="https://id.local", now_fn=lambda: 1000.0,
        identity_store=ident, vault_store=vault)
    assert use_authorizer(conn=conn, principal_id="", org="caput-venti") is False
