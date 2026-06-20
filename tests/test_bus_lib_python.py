import itertools
from identity.model import Grant, GrantTarget
from bus.store.memory import InMemoryLedgerStore
from bus.schema_registry import SchemaRegistry
from bus.dispatch import Dispatcher, InProcessDelivery
from bus.service import BusService
from islands_bus.client import BusClient, InProcessBusTransport

VOUCHER = {"type": "object", "required": ["voucherId"],
           "properties": {"voucherId": {"type": "string"}}, "additionalProperties": False}


def _svc(deliv):
    store = InMemoryLedgerStore()
    reg = SchemaRegistry(); reg.register("voucher/v1", VOUCHER)
    clock = itertools.count(1000.0, 1.0)
    disp = Dispatcher(store, deliv, now_fn=lambda: next(clock))
    grants = [Grant("g", "prn_a", GrantTarget("event-type", "bookkeeping.voucher.posted"),
                    "use", None, "o", 0.0, None)]
    return BusService(store, reg, disp, now_fn=lambda: 1000.0,
                      now_iso_fn=lambda: "2026-06-20T11:00:00Z", grants_for=lambda pid: grants)


def test_lib_publish_and_subscribe_roundtrip():
    deliv = InProcessDelivery()
    seen = []
    deliv.register("h1", lambda e: seen.append(e.data["voucherId"]))
    svc = _svc(deliv)
    client = BusClient(InProcessBusTransport(svc, principal="prn_a", org="org_1"))
    client.subscribe("bookkeeping.voucher.posted", consumer="smartcharge",
                     target={"kind": "inprocess", "key": "h1"}, grant_ref="g")
    res = client.publish("bookkeeping.voucher.posted", {"voucherId": "V-9"},
                         source="bookkeeping", schema="voucher/v1",
                         trace={"store": "bk", "ref": "r1"})
    assert res["deduped"] is False
    assert seen == ["V-9"]
