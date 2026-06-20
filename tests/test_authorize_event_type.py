from identity.authorize import authorize
from identity.model import Grant, GrantTarget


def _grant(target, access="use"):
    return Grant(id="g1", principal_id="prn_a", target=target, access=access,
                 scopes_subset=None, granted_by="prn_owner", granted_at=0.0, revoked_at=None)


def test_direct_event_type_grant_authorizes():
    grants = [_grant(GrantTarget("event-type", "bookkeeping.voucher.posted"))]
    assert authorize(grants=grants, target=GrantTarget("event-type", "bookkeeping.voucher.posted"),
                     access="use", now=1.0, request_org="org_1") is True


def test_event_type_grant_does_not_authorize_other_type():
    grants = [_grant(GrantTarget("event-type", "bookkeeping.voucher.posted"))]
    assert authorize(grants=grants, target=GrantTarget("event-type", "smartcharge.deal.won"),
                     access="use", now=1.0, request_org="org_1") is False


def test_org_grant_nests_over_event_type():
    grants = [_grant(GrantTarget("org", "org_1"))]
    assert authorize(grants=grants, target=GrantTarget("event-type", "anything.happened"),
                     access="use", now=1.0, request_org="org_1") is True


def test_org_grant_does_not_nest_over_other_org_event_type():
    grants = [_grant(GrantTarget("org", "org_1"))]
    assert authorize(grants=grants, target=GrantTarget("event-type", "anything.happened"),
                     access="use", now=1.0, request_org="org_2") is False
