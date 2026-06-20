import itertools
import json
import shutil
from pathlib import Path

import pytest

from bus.store.memory import InMemoryLedgerStore
from bus.schema_registry import SchemaRegistry
from bus.dispatch import Dispatcher, InProcessDelivery
from bus.service import BusService
from identity.model import Grant, GrantTarget

from capture_bridge.schema import register_inbound_schema, INBOUND_EVENT_TYPE, INBOUND_SCHEMA_ID
from capture_bridge.principal_map import PrincipalMap
from capture_bridge.bridge import make_handler, BridgeDeps

ROUTE_MJS = Path(__file__).resolve().parents[3] / "cloud-hub" / "skills" / "capture-route" / "scripts" / "route.mjs"
FIXTURE_VAULT = Path(__file__).resolve().parent / "fixtures" / "sample-vault"
FIXTURE_EVENT = json.loads((Path(__file__).resolve().parent / "fixtures" / "telegram_text.json").read_text())

ALLOWED = ["work-task", "personal-task", "meal", "goal", "event", "team-knowledge", "private-journal"]


def _grants():
    return [
        Grant("g", "prn_sam", GrantTarget("event-type", INBOUND_EVENT_TYPE), "use", None, "org_caput", 0.0, None),
        Grant("g2", "prn_sam", GrantTarget("org", "org_caput"), "use", None, "org_caput", 0.0, None),
    ]


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
@pytest.mark.skipif(not ROUTE_MJS.exists(), reason="capture-route not checked out alongside")
def test_inbound_event_routes_through_to_a_contained_plan(tmp_path):
    vault = tmp_path / "vault"
    shutil.copytree(FIXTURE_VAULT, vault)

    store = InMemoryLedgerStore()
    delivery = InProcessDelivery()
    reg = SchemaRegistry()
    register_inbound_schema(reg)
    clock = itertools.count(1000.0, 1.0)
    disp = Dispatcher(store, delivery, now_fn=lambda: next(clock))
    # grants_for is principal-agnostic by design in this embedded harness.
    # Authorizing the real connector:telegram service principal is deferred to the served-bus cutover.
    svc = BusService(store, reg, disp, now_fn=lambda: 1000.0,
                     now_iso_fn=lambda: "2025-06-15T12:26:40Z",
                     grants_for=lambda pid: _grants())

    captured = {}
    deps = BridgeDeps(
        principal_map=PrincipalMap([
            {"channel": "telegram", "channelUserId": 111, "principal": "prn_sam", "org": "org_caput"},
        ]),
        allowed_types=ALLOWED,
        claude_bin="claude",
        route_mjs=str(ROUTE_MJS),
        vault_root=str(vault),
        classify_runner=lambda b, p: "personal-task",
    )
    handler = make_handler(deps)

    def recording_handler(event):
        captured["result"] = handler(event)

    delivery.register("capture_bridge", recording_handler)
    svc.subscribe(principal="prn_sam", org="org_caput", type="inbound.message.*",
                  consumer="capture-bridge", target={"kind": "inprocess", "key": "capture_bridge"}, grant_ref="g")

    body = {
        "type": FIXTURE_EVENT["type"], "schema": INBOUND_SCHEMA_ID, "source": FIXTURE_EVENT["source"],
        "trace": FIXTURE_EVENT["trace"], "data": FIXTURE_EVENT["data"], "id": "evt_in_1",
    }
    res = svc.publish(body, principal="connector:telegram", org="org_caput")
    assert res["deduped"] is False

    out = captured["result"]
    assert out["skipped"] is False
    assert out["principal"] == "prn_sam"
    assert out["org"] == "org_caput"
    assert out["type"] == "personal-task"
    assert out["plan"][0]["action"] == "delegate"
    inbox = vault / "raw" / "inbox" / "2025-06-15.md"
    assert inbox.exists()
    assert "kom ihag" in inbox.read_text()


def test_unresolved_sender_is_skipped_not_routed():
    deps = BridgeDeps(
        principal_map=PrincipalMap([]),  # empty -> nothing resolves
        allowed_types=ALLOWED, claude_bin="claude", route_mjs="unused",
        vault_root="/tmp/unused", classify_runner=lambda b, p: "personal-task",
    )
    handler = make_handler(deps)

    class FakeEvent:
        data = {"text": "x", "sender": {"channel": "telegram", "channelUserId": 999}}

    out = handler(FakeEvent())
    assert out["skipped"] is True
    assert "unresolved sender" in out["reason"]
