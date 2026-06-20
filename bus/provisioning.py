from __future__ import annotations

from identity.model import Grant, GrantTarget
from identity.tokens import generate_raw_token


def grant_event_type_use(store, *, principal_id: str, event_type: str,
                         granted_by: str, now: float) -> Grant:
    """Grant a principal scoped `use` on one event type (least-privilege pub/sub)."""
    g = Grant(id=generate_raw_token("grant"), principal_id=principal_id,
              target=GrantTarget(kind="event-type", id=event_type), access="use",
              scopes_subset=None, granted_by=granted_by, granted_at=now, revoked_at=None)
    store.add_grant(g)
    return g
