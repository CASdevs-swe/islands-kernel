"""Kernel-admin provisioning helpers.

Issue a machine service principal a credential it can exchange for a short-lived
kernel JWT, and grant it scoped `use` on a single connection. These are the
operations a kernel operator runs to onboard an island's background agent
(e.g. bookkeeping) onto the vault under a real audited identity.
"""
from __future__ import annotations
from typing import Optional

from identity.model import Principal, Membership, McpToken, Grant, GrantTarget
from identity.tokens import generate_raw_token, hash_token


def issue_service_credential(store, *, principal_id: str, display_name: str,
                             org_id: str, audience: str, now: float,
                             scope: str = "mcp",
                             expires_at: Optional[float] = None) -> str:
    """Create a service Principal + active Membership + an opaque MCP credential.

    Returns the RAW credential (the kernel stores only its hash). The caller hands
    the raw value to the island; the island exchanges it for a 5-min JWT.
    """
    store.put_principal(Principal(
        id=principal_id, type="service", email=None, display_name=display_name,
        public_key=None, created_at=now))
    store.put_membership(Membership(
        principal_id=principal_id, org_id=org_id, roles=["member"],
        active=True, joined_at=now))
    raw = generate_raw_token("mcp")
    store.put_mcp_token(McpToken(
        hash=hash_token(raw), principal_id=principal_id, org_id=org_id,
        audience=audience, scope=scope, expires_at=expires_at, revoked_at=None))
    return raw


def grant_connection_use(store, *, principal_id: str, connection_id: str,
                         granted_by: str, now: float) -> Grant:
    """Grant a principal scoped `use` on one connection (least-privilege share)."""
    g = Grant(
        id=generate_raw_token("grant"), principal_id=principal_id,
        target=GrantTarget(kind="connection", id=connection_id), access="use",
        scopes_subset=None, granted_by=granted_by, granted_at=now, revoked_at=None)
    store.add_grant(g)
    return g
