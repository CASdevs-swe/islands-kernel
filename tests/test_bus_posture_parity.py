import itertools
import pytest
from identity.model import Grant, GrantTarget
from bus.store.memory import InMemoryLedgerStore
from bus.store.server import ServerLedgerStore
from bus.schema_registry import SchemaRegistry
from bus.dispatch import Dispatcher, InProcessDelivery, HttpPushDelivery
from bus.service import BusService

VOUCHER = {"type": "object", "required": ["voucherId"],
           "properties": {"voucherId": {"type": "string"}}, "additionalProperties": False}


def _grants():
    return [Grant("g", "prn_a", GrantTarget("event-type", "bookkeeping.voucher.posted"),
                  "use", None, "o", 0.0, None)]


def _service(store, delivery):
    reg = SchemaRegistry(); reg.register("voucher/v1", VOUCHER)
    clock = itertools.count(1000.0, 1.0)
    disp = Dispatcher(store, delivery, now_fn=lambda: next(clock))
    return BusService(store, reg, disp, now_fn=lambda: 1000.0,
                      now_iso_fn=lambda: "2026-06-20T11:00:00Z", grants_for=lambda pid: _grants())


def _body(eid):
    return {"type": "bookkeeping.voucher.posted", "schema": "voucher/v1", "source": "bookkeeping",
            "trace": {"store": "bk", "ref": "r1"}, "data": {"voucherId": "V-1"}, "id": eid}


class _Recorder:
    def __init__(self): self.n = 0
    def deliver(self, sub, event): self.n += 1


@pytest.mark.parametrize("backend", ["embedded", "hosted"])
def test_dedup_and_exactly_once_hold_in_both_postures(backend, tmp_path):
    rec = _Recorder()
    if backend == "embedded":
        store = InMemoryLedgerStore()
    else:
        store = ServerLedgerStore(f"sqlite:///{tmp_path}/bus.sqlite")
    svc = _service(store, rec)
    svc.subscribe(principal="prn_a", org="org_1", type="bookkeeping.voucher.posted",
                  consumer="smartcharge", target={"kind": "inprocess", "key": "x"}, grant_ref="g")
    r1 = svc.publish(_body("evt_p"), principal="prn_a", org="org_1")
    r2 = svc.publish(_body("evt_p"), principal="prn_a", org="org_1")  # dedup
    assert r1["deduped"] is False and r2["deduped"] is True
    assert rec.n == 1                                  # exactly-once effect in both postures
