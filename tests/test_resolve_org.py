import pytest
from identity.store.memory import InMemoryIdentityStore
from identity.model import Membership
from identity.resolve import resolve_org, OrgRequired


def _store(*memberships):
    s = InMemoryIdentityStore()
    for m in memberships:
        s.put_membership(m)
    return s


def test_jwt_org_wins_when_member():
    s = _store(Membership("prn_1", "org_A", ["member"], True, 0.0),
               Membership("prn_1", "org_B", ["member"], True, 0.0))
    assert resolve_org(store=s, principal_id="prn_1", jwt_org="org_A") == "org_A"


def test_jwt_org_ignored_when_not_member_falls_to_header():
    s = _store(Membership("prn_1", "org_B", ["member"], True, 0.0))
    assert resolve_org(store=s, principal_id="prn_1", jwt_org="org_X",
                       header_org_id="org_B") == "org_B"


def test_sole_membership_is_used():
    s = _store(Membership("prn_1", "org_B", ["member"], True, 0.0))
    assert resolve_org(store=s, principal_id="prn_1") == "org_B"


def test_no_signal_and_multiple_memberships_raises():
    s = _store(Membership("prn_1", "org_A", ["member"], True, 0.0),
               Membership("prn_1", "org_B", ["member"], True, 0.0))
    with pytest.raises(OrgRequired):
        resolve_org(store=s, principal_id="prn_1")


def test_inactive_membership_does_not_count():
    s = _store(Membership("prn_1", "org_B", ["member"], False, 0.0))
    with pytest.raises(OrgRequired):
        resolve_org(store=s, principal_id="prn_1")
