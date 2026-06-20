import itertools
from bus.model import Event, Subscription, Delivery
from bus.store.memory import InMemoryLedgerStore
from bus.dispatch import Dispatcher, InProcessDelivery, BackoffPolicy, RoutingDelivery


def _ev(eid="evt_1"):
    return Event(id=eid, type="bookkeeping.voucher.posted", schema="voucher/v1",
                 source="bookkeeping", org="org_1", principal="prn_a",
                 occurred_at="2026-06-20T10:00:00Z", trace={"store": "bk", "ref": "r1"},
                 data={"voucherId": "V-1"})


def _sub(key="h1"):
    return Subscription("sub_1", "org_1", "smartcharge", "bookkeeping.voucher.posted",
                        {"kind": "inprocess", "key": key}, "g1")


def _clock():
    c = itertools.count(1000.0, 1.0)
    return lambda: next(c)


def test_handler_runs_once_per_delivery():
    store = InMemoryLedgerStore(); store.record_event(_ev())
    store.put_subscription(_sub())
    seen = []
    deliv = InProcessDelivery(); deliv.register("h1", lambda e: seen.append(e.id))
    d = Dispatcher(store, deliv, now_fn=_clock())
    d.dispatch(_ev())
    d.dispatch(_ev())  # redelivery: already delivered -> no-op
    assert seen == ["evt_1"]
    row = store.get_delivery("evt_1", "bookkeeping", "sub_1")
    assert row.status == "delivered" and row.attempts == 1


def test_failing_handler_dead_letters_after_max_attempts():
    store = InMemoryLedgerStore(); store.record_event(_ev())
    store.put_subscription(_sub())
    deliv = InProcessDelivery()
    def boom(e):
        raise TimeoutError("upstream down")
    deliv.register("h1", boom)
    d = Dispatcher(store, deliv, now_fn=_clock(), backoff=BackoffPolicy(max_attempts=3))
    d.dispatch(_ev())                                   # attempt 1 -> pending
    row = store.get_delivery("evt_1", "bookkeeping", "sub_1")
    d.attempt_pending(row)                              # attempt 2 -> pending
    row = store.get_delivery("evt_1", "bookkeeping", "sub_1")
    d.attempt_pending(row)                              # attempt 3 -> dead
    row = store.get_delivery("evt_1", "bookkeeping", "sub_1")
    assert row.status == "dead" and row.attempts == 3
    assert row.last_error == "TimeoutError"             # error CLASS only, no message body


def test_recovering_handler_marks_delivered_on_retry():
    store = InMemoryLedgerStore(); store.record_event(_ev())
    store.put_subscription(_sub())
    calls = {"n": 0}
    deliv = InProcessDelivery()
    def flaky(e):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionError("transient")
    deliv.register("h1", flaky)
    d = Dispatcher(store, deliv, now_fn=_clock())
    d.dispatch(_ev())                                   # fails -> pending
    row = store.get_delivery("evt_1", "bookkeeping", "sub_1")
    d.attempt_pending(row)                              # succeeds -> delivered
    row = store.get_delivery("evt_1", "bookkeeping", "sub_1")
    assert row.status == "delivered" and row.attempts == 2


def test_backoff_is_capped_exponential():
    p = BackoffPolicy(max_attempts=10, base=1.0, cap=60.0)
    assert p.next_at(1, now=100.0) == 100.0 + 1.0
    assert p.next_at(2, now=100.0) == 100.0 + 2.0
    assert p.next_at(7, now=100.0) == 100.0 + 60.0     # 2**6 = 64 capped to 60


def test_routing_delivery_dispatches_by_kind():
    """RoutingDelivery picks http delivery for kind='http', inprocess otherwise."""
    calls = {"in": [], "http": []}

    class FakeInProcess:
        def deliver(self, sub, event):
            calls["in"].append(sub.target.get("kind"))

    class FakeHttp:
        def deliver(self, sub, event):
            calls["http"].append(sub.target.get("kind"))

    routing = RoutingDelivery(FakeInProcess(), FakeHttp())

    ev = _ev()
    sub_in = Subscription("sub_a", "org_1", "smartcharge", "bookkeeping.voucher.posted",
                          {"kind": "inprocess", "key": "counter"}, "g1")
    sub_http = Subscription("sub_b", "org_1", "node-island", "bookkeeping.voucher.posted",
                            {"kind": "http", "url": "http://127.0.0.1:9999/events", "audience": "node-island"}, "g2")

    routing.deliver(sub_in, ev)
    routing.deliver(sub_http, ev)

    assert calls["in"] == ["inprocess"]
    assert calls["http"] == ["http"]
