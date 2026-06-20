from __future__ import annotations
import re

from bus.model import Event, EnvelopeError, new_event_id

_TYPE_RE = re.compile(r"^[a-z0-9]+(\.[a-z0-9-]+)+$")  # dotted, namespaced, >= 2 segments


def stamp_envelope(body: dict, *, principal: str, org: str, now_iso: str) -> Event:
    """Build an Event, stamping principal/org from the verified JWT (never the body)."""
    return Event(
        id=body.get("id") or new_event_id(),
        type=body.get("type", ""),
        schema=body.get("schema", ""),
        source=body.get("source", ""),
        org=org,                       # server-stamped
        principal=principal,           # server-stamped
        occurred_at=body.get("occurredAt") or now_iso,
        trace=body.get("trace") if isinstance(body.get("trace"), dict) else {},
        data=body.get("data"),
    )


def validate_envelope(ev: Event) -> None:
    if not isinstance(ev.type, str) or not _TYPE_RE.match(ev.type):
        raise EnvelopeError(f"invalid event type: {ev.type!r}")
    for field in ("id", "schema", "source", "org", "principal", "occurred_at"):
        val = getattr(ev, field)
        if not isinstance(val, str) or not val:
            raise EnvelopeError(f"missing/invalid field: {field}")
    if not isinstance(ev.trace, dict) or not ev.trace.get("store") or not ev.trace.get("ref"):
        raise EnvelopeError("trace must be { store, ref }")
    if not isinstance(ev.data, dict):
        raise EnvelopeError("data must be an object")
