import itertools
import pytest
from identity.model import Grant, GrantTarget
from bus.model import EventContract
from bus.store.memory import InMemoryLedgerStore
from bus.schema_registry import SchemaRegistry
from bus.dispatch import Dispatcher, InProcessDelivery
from bus.service import BusService, AuthzDenied

VOUCHER = {"type": "object", "required": ["voucherId"],
           "properties": {"voucherId": {"type": "string"}}, "additionalProperties": False}


def _grant(principal, target):
    return Grant("g", principal, target, "use", None, "prn_owner", 0.0, None)


def _service(grants, delivery=None):
    store = InMemoryLedgerStore()
    reg = SchemaRegistry(); reg.register("voucher/v1", VOUCHER)
    deliv = delivery or InProcessDelivery()
    clock = itertools.count(1000.0, 1.0)
    disp = Dispatcher(store, deliv, now_fn=lambda: next(clock))
    svc = BusService(store, reg, disp, now_fn=lambda: 1000.0,
                     now_iso_fn=lambda: "2026-06-20T11:00:00Z",
                     grants_for=lambda pid: grants)
    return svc, store, deliv


def _body(**over):
    b = {"type": "bookkeeping.voucher.posted", "schema": "voucher/v1", "source": "bookkeeping",
         "trace": {"store": "bk", "ref": "r1"}, "data": {"voucherId": "V-1"}}
    b.update(over); return b


def test_publish_dispatches_to_subscriber_once():
    svc, store, deliv = _service([_grant("prn_a", GrantTarget("event-type", "bookkeeping.voucher.posted"))])
    seen = []
    deliv.register("h1", lambda e: seen.append(e.id))
    svc.subscribe(principal="prn_a", org="org_1", type="bookkeeping.voucher.posted",
                  consumer="smartcharge", target={"kind": "inprocess", "key": "h1"}, grant_ref="g")
    res = svc.publish(_body(), principal="prn_a", org="org_1")
    assert res["deduped"] is False and res["id"].startswith("evt_")
    assert seen == [res["id"]]


def test_republish_same_id_is_deduped_no_redispatch():
    svc, store, deliv = _service([_grant("prn_a", GrantTarget("event-type", "bookkeeping.voucher.posted"))])
    n = []
    deliv.register("h1", lambda e: n.append(1))
    svc.subscribe(principal="prn_a", org="org_1", type="bookkeeping.voucher.posted",
                  consumer="smartcharge", target={"kind": "inprocess", "key": "h1"}, grant_ref="g")
    r1 = svc.publish(_body(id="evt_fixed"), principal="prn_a", org="org_1")
    r2 = svc.publish(_body(id="evt_fixed"), principal="prn_a", org="org_1")
    assert r1["deduped"] is False and r2["deduped"] is True
    assert len(n) == 1


def test_publish_without_grant_is_denied():
    svc, store, deliv = _service([])  # no grants
    with pytest.raises(AuthzDenied):
        svc.publish(_body(), principal="prn_a", org="org_1")


def test_subscribe_without_grant_is_denied():
    svc, store, deliv = _service([])
    with pytest.raises(AuthzDenied):
        svc.subscribe(principal="prn_a", org="org_1", type="bookkeeping.voucher.posted",
                      consumer="smartcharge", target={"kind": "inprocess", "key": "h1"}, grant_ref="g")


def test_event_not_delivered_across_orgs():
    svc, store, deliv = _service([_grant("prn_a", GrantTarget("org", "org_1")),
                                  _grant("prn_a", GrantTarget("org", "org_2"))])
    seen = []
    deliv.register("h1", lambda e: seen.append(e.id))
    # subscriber in org_2, event published in org_1
    svc.subscribe(principal="prn_a", org="org_2", type="bookkeeping.voucher.posted",
                  consumer="smartcharge", target={"kind": "inprocess", "key": "h1"}, grant_ref="g")
    svc.publish(_body(), principal="prn_a", org="org_1")
    assert seen == []


def test_replay_reattempts_dead_letter():
    svc, store, deliv = _service([_grant("prn_a", GrantTarget("event-type", "bookkeeping.voucher.posted"))])
    state = {"fail": True}
    def handler(e):
        if state["fail"]:
            raise TimeoutError("down")
    deliv.register("h1", handler)
    svc.subscribe(principal="prn_a", org="org_1", type="bookkeeping.voucher.posted",
                  consumer="smartcharge", target={"kind": "inprocess", "key": "h1"}, grant_ref="g")
    # force quick dead-letter by setting max_attempts=1 on the dispatcher backoff
    svc._dispatcher._backoff.max_attempts = 1
    res = svc.publish(_body(id="evt_dl"), principal="prn_a", org="org_1")
    assert [d.status for d in svc.dead_letters("org_1")] == ["dead"]
    state["fail"] = False
    count = svc.replay("evt_dl", "bookkeeping", org="org_1")
    assert count == 1
    assert svc.dead_letters("org_1") == []
