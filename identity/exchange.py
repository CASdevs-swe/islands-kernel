from identity.tokens import hash_token


class ExchangeError(ValueError):
    pass


def exchange(*, opaque_token: str, audience: str, store, now: float) -> dict:
    h = hash_token(opaque_token)
    row = store.get_mcp_token(h)
    if row is None:
        row = store.get_access_token(h)
    if row is None:
        raise ExchangeError("unknown token")
    if getattr(row, "revoked_at", None) is not None:
        raise ExchangeError("revoked token")
    if row.audience is not None and row.audience != audience:
        raise ExchangeError("audience mismatch")
    if row.expires_at is not None and now >= row.expires_at:
        raise ExchangeError("expired token")

    m = store.get_membership(row.principal_id, row.org_id) if row.org_id else None
    roles = m.roles if (m is not None and m.active) else []
    principal = store.get_principal(row.principal_id)
    typ = principal.type if principal is not None else "human"
    link_getter = getattr(store, "get_island_link_by_principal", None)
    link = link_getter(row.principal_id) if link_getter else None
    return {"principal_id": row.principal_id, "org_id": row.org_id,
            "roles": roles, "sid": None, "type": typ,
            "island": link.island_id if link else None,
            "island_sub": link.island_user_id if link else None,
            "island_org": None}
