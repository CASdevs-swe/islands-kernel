from identity.model import IslandRegistry, IslandPrincipalLink, Principal, Membership
from identity.tokens import generate_raw_token


def find_or_create_island_principal(store, *, island: IslandRegistry, island_user_id: str,
                                    email, now: float) -> str:
    """Resolve (or lazily create) the kernel Principal for an island-native user.

    Keyed on (island.id, island_user_id), never on email: island users may share
    or lack an email. Ensures an active Membership in the island's org so the
    connector token carries a real org.
    """
    existing = store.get_principal_by_island(island.id, island_user_id)
    if existing is not None:
        return existing
    pid = generate_raw_token("prn")
    store.put_principal(Principal(id=pid, type="human", email=email, display_name=email,
                                  public_key=None, created_at=now))
    store.put_membership(Membership(principal_id=pid, org_id=island.org_id,
                                    roles=["member"], active=True, joined_at=now))
    store.put_island_principal_link(IslandPrincipalLink(island_id=island.id,
        island_user_id=island_user_id, principal_id=pid, created_at=now))
    return pid
