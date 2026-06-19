from typing import Optional


class OrgRequired(ValueError):
    pass


def _is_active_member(store, principal_id: str, org_id: str) -> bool:
    m = store.get_membership(principal_id, org_id)
    return m is not None and m.active


def resolve_org(*, store, principal_id: str, jwt_org: Optional[str] = None,
                header_org_id: Optional[str] = None) -> str:
    if jwt_org and _is_active_member(store, principal_id, jwt_org):
        return jwt_org
    if header_org_id and _is_active_member(store, principal_id, header_org_id):
        return header_org_id
    active = [m.org_id for m in store.list_memberships(principal_id) if m.active]
    if len(active) == 1:
        return active[0]
    raise OrgRequired("ORG_REQUIRED")
