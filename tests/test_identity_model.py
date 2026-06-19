# tests/test_identity_model.py
from identity.model import (
    Principal, Org, Membership, GrantTarget, Grant, McpToken, AccessLog,
)


def test_principal_defaults_to_no_org_fields():
    p = Principal(id="prn_1", type="human", email="a@b.se",
                  display_name="A", public_key=None, created_at=0.0)
    assert p.type == "human"
    assert p.email == "a@b.se"


def test_grant_targets_a_connection():
    g = Grant(id="grant_1", principal_id="prn_1",
              target=GrantTarget(kind="connection", id="conn_1"),
              access="use", scopes_subset=["read"],
              granted_by="prn_owner", granted_at=0.0, revoked_at=None)
    assert g.target.kind == "connection"
    assert g.target.id == "conn_1"
    assert g.revoked_at is None


def test_membership_roles_and_active():
    m = Membership(principal_id="prn_1", org_id="org_1",
                   roles=["owner", "member"], active=True, joined_at=0.0)
    assert "owner" in m.roles and m.active is True


def test_access_log_carries_no_secret_fields():
    log = AccessLog(principal_id="prn_1", org_id="org_1",
                    island="bookkeeping", capability="reconcile", at=0.0)
    blob = str(log)
    assert "token" not in blob.lower() and "secret" not in blob.lower()


def test_mcp_token_is_keyed_by_hash():
    t = McpToken(hash="h", principal_id="prn_1", org_id="org_1",
                 audience="https://mcp.x", scope="mcp",
                 expires_at=None, revoked_at=None)
    assert t.hash == "h"
