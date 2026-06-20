"""Capture-bridge handler: bus inbound event -> capture-route plan.

Owns the routing brain: resolve the channel sender to a kernel principal/org,
classify into the vault routing vocabulary, translate, and invoke capture-route.
Plan-only during soak — it writes nowhere real; capture-route's only write goes
to the throwaway vault at deps.vault_root.
"""
from dataclasses import dataclass

from .classify import classify
from .principal_map import PrincipalMap
from .route_caller import call_capture_route
from .translate import translate


@dataclass
class BridgeDeps:
    principal_map: PrincipalMap
    allowed_types: list[str]
    claude_bin: str
    route_mjs: str
    vault_root: str
    default_privacy: str = "private"
    classify_runner: object = None
    node_bin: str = "node"


def _today_from(event_data: dict) -> str:
    captured = event_data.get("capturedAt", "")
    # capturedAt is ISO 8601 with offset; the date prefix is the local day.
    return captured[:10] if len(captured) >= 10 else "1970-01-01"


def make_handler(deps: BridgeDeps):
    # InProcessDelivery.deliver calls handler(event) with a single arg
    # (bus/dispatch.py:24) — the subscription is not passed.
    def handler(event) -> dict:
        data = getattr(event, "data", None) or {}
        sender = data.get("sender", {})
        ident = deps.principal_map.resolve(sender)
        if ident is None:
            return {"principal": None, "org": None, "type": None, "plan": [],
                    "skipped": True, "reason": "unresolved sender"}
        text = data.get("text", "")
        ctype = classify(
            text, deps.allowed_types, deps.claude_bin,
            runner=deps.classify_runner,
        )
        payload = translate(
            {"data": data},
            type=ctype,
            privacy=deps.default_privacy,
            vault_root=deps.vault_root,
            today=_today_from(data),
        )
        result = call_capture_route(payload, deps.route_mjs, node_bin=deps.node_bin)
        return {"principal": ident["principal"], "org": ident["org"], "type": ctype,
                "plan": result.get("plan", []), "skipped": False, "reason": None}

    return handler
