from typing import Optional, Iterable

from identity.model import Grant, GrantTarget, Access

_RANK: dict[str, int] = {"use": 1, "manage": 2}


def _satisfies(grant_access: Access, need: Access) -> bool:
    return _RANK[grant_access] >= _RANK[need]


def _covers(
    grant_target: GrantTarget,
    target: GrantTarget,
    request_org: Optional[str],
) -> bool:
    if grant_target.kind == target.kind and grant_target.id == target.id:
        return True
    # org-scoped grant nests over island/capability/connection in that org
    if (
        grant_target.kind == "org"
        and request_org is not None
        and grant_target.id == request_org
        and target.kind in ("island", "capability", "connection")
    ):
        return True
    return False


def authorize(
    *,
    grants: Iterable[Grant],
    target: GrantTarget,
    access: Access,
    now: float,
    request_org: Optional[str] = None,
) -> bool:
    for g in grants:
        if g.revoked_at is not None and g.revoked_at <= now:
            continue
        if _satisfies(g.access, access) and _covers(g.target, target, request_org):
            return True
    return False


def adapt_connection_grant(cg, *, owner_connection_id: Optional[str] = None) -> Grant:
    if owner_connection_id is not None:
        return Grant(
            id=f"owner:{owner_connection_id}",
            principal_id="",
            target=GrantTarget("connection", owner_connection_id),
            access="manage",
            scopes_subset=None,
            granted_by="",
            granted_at=0.0,
            revoked_at=None,
        )
    return Grant(
        id=f"cg:{cg.connection_id}:{cg.principal_id}",
        principal_id=cg.principal_id,
        target=GrantTarget("connection", cg.connection_id),
        access=cg.access,
        scopes_subset=cg.scopes_subset,
        granted_by=cg.granted_by,
        granted_at=cg.granted_at,
        revoked_at=None,
    )


def collect_grants(
    *,
    principal_id: str,
    identity_store,
    connection_grants: Iterable = (),
) -> list[Grant]:
    out = list(identity_store.list_grants(principal_id))
    out.extend(adapt_connection_grant(cg) for cg in connection_grants)
    return out
