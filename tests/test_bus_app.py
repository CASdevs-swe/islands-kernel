import itertools
from fastapi.testclient import TestClient
from identity.deps import Claims
from identity.model import Grant, GrantTarget
from bus.model import EventContract
from bus.store.memory import InMemoryLedgerStore
from bus.schema_registry import SchemaRegistry
from bus.dispatch import Dispatcher, InProcessDelivery
from bus.service import BusService
from bus.app import build_bus_app

VOUCHER = {"type": "object", "required": ["voucherId"],
           "properties": {"voucherId": {"type": "string"}}, "additionalProperties": False}


def _client(grants, deliv):
    store = InMemoryLedgerStore()
    reg = SchemaRegistry(); reg.register("voucher/v1", VOUCHER)
    clock = itertools.count(1000.0, 1.0)
    disp = Dispatcher(store, deliv, now_fn=lambda: next(clock))
    svc = BusService(store, reg, disp, now_fn=lambda: 1000.0,
                     now_iso_fn=lambda: "2026-06-20T11:00:00Z", grants_for=lambda pid: grants)
    svc.declare_contract(EventContract("bookkeeping", ["bookkeeping.voucher.posted"], []))

    def require_principal():
        return Claims({"sub": "prn_a", "org": "org_1"})

    app = build_bus_app(svc, require_principal=require_principal)
    return TestClient(app), svc


def _body(**over):
    b = {"type": "bookkeeping.voucher.posted", "schema": "voucher/v1", "source": "bookkeeping",
         "trace": {"store": "bk", "ref": "r1"}, "data": {"voucherId": "V-1"}}
    b.update(over); return b


def test_publish_route_dispatches():
    seen = []
    deliv = InProcessDelivery(); deliv.register("h1", lambda e: seen.append(e.id))
    c, svc = _client([Grant("g", "prn_a", GrantTarget("event-type", "bookkeeping.voucher.posted"),
                            "use", None, "o", 0.0, None)], deliv)
    c.post("/subscriptions", json={"type": "bookkeeping.voucher.posted", "consumer": "smartcharge",
                                   "target": {"kind": "inprocess", "key": "h1"}, "grant_ref": "g"})
    r = c.post("/events", json=_body())
    assert r.status_code == 200 and r.json()["deduped"] is False
    assert seen == [r.json()["id"]]


def test_publish_without_grant_is_403():
    c, svc = _client([], InProcessDelivery())
    r = c.post("/events", json=_body())
    assert r.status_code == 403


def test_bad_envelope_is_400():
    c, svc = _client([Grant("g", "prn_a", GrantTarget("event-type", "bookkeeping.voucher.posted"),
                            "use", None, "o", 0.0, None)], InProcessDelivery())
    r = c.post("/events", json=_body(trace={"store": "bk"}))  # missing ref
    assert r.status_code == 400


def test_events_registry_lists_contracts():
    c, svc = _client([], InProcessDelivery())
    r = c.get("/_events")
    assert r.status_code == 200
    islands = {i["island"] for i in r.json()["islands"]}
    assert "bookkeeping" in islands


def test_deadletter_and_replay_routes():
    deliv = InProcessDelivery()
    state = {"fail": True}
    deliv.register("h1", lambda e: (_ for _ in ()).throw(TimeoutError()) if state["fail"] else None)
    c, svc = _client([Grant("g", "prn_a", GrantTarget("event-type", "bookkeeping.voucher.posted"),
                            "use", None, "o", 0.0, None)], deliv)
    svc._dispatcher._backoff.max_attempts = 1
    c.post("/subscriptions", json={"type": "bookkeeping.voucher.posted", "consumer": "smartcharge",
                                   "target": {"kind": "inprocess", "key": "h1"}, "grant_ref": "g"})
    c.post("/events", json=_body(id="evt_dl"))
    dl = c.get("/deadletter").json()
    assert dl["dead"][0]["subscription_id"] and "data" not in dl["dead"][0]
    state["fail"] = False
    rep = c.post("/deadletter/evt_dl/replay", params={"source": "bookkeeping"})
    assert rep.json()["replayed"] == 1
