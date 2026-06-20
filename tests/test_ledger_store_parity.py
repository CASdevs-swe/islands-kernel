import pytest
from bus.model import Event, Subscription, Delivery, EventContract
from bus.store.memory import InMemoryLedgerStore


def _stores(tmp_path):
    return [InMemoryLedgerStore()]  # SQLite store appended in Task 5


@pytest.fixture(params=[0])
def store(request, tmp_path):
    return _stores(tmp_path)[request.param]


def _ev(eid="evt_1", source="bookkeeping", typ="bookkeeping.voucher.posted", org="org_1"):
    return Event(id=eid, type=typ, schema="voucher/v1", source=source, org=org,
                 principal="prn_a", occurred_at="2026-06-20T10:00:00Z",
                 trace={"store": "bk", "ref": "r1"}, data={"voucherId": "V-1"})


def test_record_event_dedups_on_source_and_id(store):
    assert store.record_event(_ev()) is True
    assert store.record_event(_ev()) is False           # same (source, id)
    assert store.record_event(_ev(source="smartcharge")) is True  # different source, same id

def test_get_event_roundtrips(store):
    store.record_event(_ev())
    got = store.get_event("bookkeeping", "evt_1")
    assert got is not None and got.type == "bookkeeping.voucher.posted"

def test_matching_subscriptions_exact_and_glob(store):
    store.put_subscription(Subscription("sub_1", "org_1", "smartcharge",
                                        "bookkeeping.voucher.posted", {"kind": "inprocess", "key": "h1"}, "g1"))
    store.put_subscription(Subscription("sub_2", "org_1", "nudge",
                                        "bookkeeping.*", {"kind": "inprocess", "key": "h2"}, "g2"))
    store.put_subscription(Subscription("sub_3", "org_2", "other",
                                        "bookkeeping.voucher.posted", {"kind": "inprocess", "key": "h3"}, "g3"))
    ids = {s.id for s in store.matching_subscriptions("org_1", "bookkeeping.voucher.posted")}
    assert ids == {"sub_1", "sub_2"}                    # org_2 excluded, glob included

def test_delete_subscription(store):
    store.put_subscription(Subscription("sub_1", "org_1", "x", "a.b", {"kind": "inprocess", "key": "h"}, "g"))
    store.delete_subscription("sub_1")
    assert store.get_subscription("sub_1") is None

def test_delivery_roundtrip_and_status_listing(store):
    store.record_event(_ev())
    store.put_delivery(Delivery("evt_1", "bookkeeping", "sub_1", "dead", 5, "TimeoutError", None))
    d = store.get_delivery("evt_1", "bookkeeping", "sub_1")
    assert d.status == "dead" and d.attempts == 5
    dead = store.list_deliveries_by_status("org_1", "dead")
    assert [x.subscription_id for x in dead] == ["sub_1"]

def test_contract_registry(store):
    store.put_contract(EventContract("bookkeeping", ["bookkeeping.voucher.posted"], []))
    store.put_contract(EventContract("smartcharge", ["smartcharge.deal.won"], ["bookkeeping.voucher.posted"]))
    islands = {c.island for c in store.list_contracts()}
    assert islands == {"bookkeeping", "smartcharge"}

def test_lease_is_exclusive(store):
    assert store.acquire_lease("k1", "h1", until=2000.0, now=1000.0) is True
    assert store.acquire_lease("k1", "h2", until=2000.0, now=1000.0) is False

def test_expired_lease_can_be_stolen(store):
    assert store.acquire_lease("k1", "h1", until=1500.0, now=1000.0) is True
    assert store.acquire_lease("k1", "h2", until=3000.0, now=2000.0) is True  # h1 expired
    assert store.lease_held("k1", now=2500.0) is True

def test_release_lease(store):
    store.acquire_lease("k1", "h1", until=2000.0, now=1000.0)
    store.release_lease("k1", "h1")
    assert store.lease_held("k1", now=1500.0) is False
