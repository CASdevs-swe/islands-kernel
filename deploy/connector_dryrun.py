"""Channel-agnostic connector harness: exercise the full inbound chain
in-process, without touching the real channel or any real destination.

Feed it an inbound-event JSON fixture (the connector<->bridge seam) and a
throwaway vault path. It builds an in-process bus, registers the capture-bridge
handler, publishes the fixture, and returns the stamped envelope + routing plan
+ the contained inbox path. Replay = pass a previously captured event JSON.

Discord and voice connectors reuse this unchanged — they only need to emit a
fixture of the same inbound-message shape.
"""
import itertools
import json
import shutil
import sys
from pathlib import Path

from bus.store.memory import InMemoryLedgerStore
from bus.schema_registry import SchemaRegistry
from bus.dispatch import Dispatcher, InProcessDelivery
from bus.service import BusService
from identity.model import Grant, GrantTarget

from capture_bridge.schema import register_inbound_schema, INBOUND_EVENT_TYPE, INBOUND_SCHEMA_ID
from capture_bridge.principal_map import PrincipalMap
from capture_bridge.bridge import make_handler, BridgeDeps

ALLOWED = ["work-task", "personal-task", "meal", "goal", "event", "team-knowledge", "private-journal"]
DEFAULT_ROUTE_MJS = str(
    Path(__file__).resolve().parents[2] / "cloud-hub" / "skills" / "capture-route" / "scripts" / "route.mjs"
)
_SAMPLE_VAULT = (
    Path(__file__).resolve().parents[1] / "tests" / "capture_bridge" / "fixtures" / "sample-vault"
)


def run(fixture_path: str, vault_path: str, *, classify_type: str = "personal-task",
        route_mjs: str | None = None) -> dict:
    fixture = json.loads(Path(fixture_path).read_text())
    sender = fixture["data"]["sender"]

    # Seed vault_path with the sample-vault so route.mjs can find .loom/manifest.yml.
    vault = Path(vault_path)
    if not vault.exists():
        if not _SAMPLE_VAULT.exists():
            raise RuntimeError(f"connector-dryrun sample vault not found at {_SAMPLE_VAULT}")
        shutil.copytree(_SAMPLE_VAULT, vault)

    store = InMemoryLedgerStore()
    delivery = InProcessDelivery()
    reg = SchemaRegistry()
    register_inbound_schema(reg)
    clock = itertools.count(1000, 1)
    disp = Dispatcher(store, delivery, now_fn=lambda: next(clock))
    svc = BusService(store, reg, disp, now_fn=lambda: 1000.0,
                     now_iso_fn=lambda: "2025-06-15T12:26:40Z",
                     # grants_for is principal-agnostic by design in this embedded harness.
                     # Authorizing the real connector:telegram service principal is deferred to the served-bus cutover.
                     grants_for=lambda pid: [
                         Grant("g", "prn_sam", GrantTarget("event-type", INBOUND_EVENT_TYPE),
                               "use", None, "org_caput", 0.0, None),
                         Grant("g2", "prn_sam", GrantTarget("org", "org_caput"),
                               "use", None, "org_caput", 0.0, None),
                     ])

    deps = BridgeDeps(
        principal_map=PrincipalMap([{**sender, "principal": "prn_sam", "org": "org_caput"}]),
        allowed_types=ALLOWED, claude_bin="claude",
        route_mjs=route_mjs or DEFAULT_ROUTE_MJS, vault_root=vault_path,
        classify_runner=lambda b, p: classify_type,
    )
    handler = make_handler(deps)

    box: dict = {}

    def recording(event):
        box["stamped"] = {
            "id": event.id, "type": event.type, "source": event.source,
            "principal": event.principal, "org": event.org,
        }
        box["result"] = handler(event)

    delivery.register("capture_bridge", recording)
    svc.subscribe(principal="prn_sam", org="org_caput", type="inbound.message.*",
                  consumer="capture-bridge",
                  target={"kind": "inprocess", "key": "capture_bridge"}, grant_ref="g")

    body = {
        "type": fixture["type"], "schema": INBOUND_SCHEMA_ID, "source": fixture["source"],
        "trace": fixture["trace"], "data": fixture["data"], "id": "evt_dryrun",
    }
    svc.publish(body, principal="connector:telegram", org="org_caput")

    result = box.get("result", {"skipped": True, "plan": [], "reason": "handler not invoked"})
    inbox = ""
    if not result.get("skipped"):
        today = fixture["data"].get("capturedAt", "")[:10]
        inbox = str(Path(vault_path) / "raw" / "inbox" / f"{today}.md")
    return {"stamped": box.get("stamped", {}), "plan": result.get("plan", []),
            "inbox": inbox, "skipped": result.get("skipped", True)}


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: python -m deploy.connector_dryrun <fixture.json> <vault_dir>", file=sys.stderr)
        sys.exit(2)
    out = run(sys.argv[1], sys.argv[2])
    print(json.dumps(out, indent=2))
