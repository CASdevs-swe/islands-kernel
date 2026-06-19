from __future__ import annotations
from vault.model import Access, Connection
from vault.store.base import Store

_RANK = {"use": 1, "manage": 2}


def satisfies(grant_access: Access, need: Access) -> bool:
    return _RANK[grant_access] >= _RANK[need]


def require_access(store: Store, conn: Connection, principal_id: str, need: Access):
    if conn.created_by == principal_id:
        return "owner"
    for g in store.get_grants(conn.id):
        if g.principal_id == principal_id and satisfies(g.access, need):
            return g
    raise PermissionError(f"{principal_id} lacks {need} on {conn.id}")
