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
