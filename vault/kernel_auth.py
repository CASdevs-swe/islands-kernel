"""Kernel-auth seam for the connector vault.

When `VAULT_REQUIRE_KERNEL` is on, the access-token route verifies a kernel JWT and
runs an `authorize()` grant check instead of the slice-1 header stub. The vault holds
only the kernel's PUBLIC JWKS (fetched from the identity service); the signing key
never leaves the kernel.
"""
from __future__ import annotations
from typing import Callable

from identity.deps import make_require_principal
from identity.authorize import authorize, collect_grants
from identity.model import GrantTarget


def make_kernel_auth(*, jwks_provider: Callable[[], dict], audience: str, issuer: str,
                     now_fn: Callable[[], float], identity_store, vault_store):
    """Return (require_principal, authorizer) for the authed access-token route.

    - require_principal: a FastAPI dependency verifying the kernel JWT via the public JWKS.
    - authorizer(conn, principal_id, org) -> bool: the grant check over the unified Grant
      table plus the vault's own connection grants (no data migration).
    """
    require_principal = make_require_principal(
        jwks_provider=jwks_provider, audience=audience, now_fn=now_fn, issuer=issuer)

    def authorizer(*, conn, principal_id: str, org) -> bool:
        grants = collect_grants(
            principal_id=principal_id, identity_store=identity_store,
            connection_grants=vault_store.get_grants(conn.id))
        return authorize(grants=grants, target=GrantTarget("connection", conn.id),
                         access="use", now=now_fn(), request_org=org)

    return require_principal, authorizer


def cached_jwks_provider(url: str, http=None) -> Callable[[], dict]:
    """A JWKS provider that fetches the kernel's public JWKS once and caches it.

    The vault verifies offline against this document; rotation is picked up by
    restarting the process (or a future TTL refresh)."""
    import httpx
    h = http or httpx
    cache: dict = {}

    def provider() -> dict:
        if "doc" not in cache:
            r = h.get(url)
            r.raise_for_status()
            cache["doc"] = r.json()
        return cache["doc"]

    return provider
