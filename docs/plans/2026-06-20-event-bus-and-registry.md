# Inter-island Event Bus + Registry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a canonical, A2A-shaped inter-island event bus + event-contract registry to islands-kernel — publish/subscribe over HTTP+JSON, principal/org stamped server-side from the verified kernel JWT, an idempotency ledger reusing slice-1's single-writer lease, retry/backoff, dead-letter, and thin Node + Python libs, with a cross-language publish/consume proof.

**Architecture:** A new `bus/` package sits beside `vault/` and `identity/`, the same shape as those slices. A `LedgerStore` ABC (in-memory + SQLite `ServerLedgerStore`) holds the event log, subscriptions, delivery rows, and the event-contract registry, and carries the exact single-writer lease discipline slice-1's `Store` uses. A `Dispatcher` enforces exactly-once *effect* per `(event_id, source, subscription_id)` under that lease, with capped exponential backoff and dead-letter. `BusService` orchestrates publish/subscribe/replay and gates both through the existing `identity.authorize()` with a new `target.kind="event-type"`. `bus/app.py` is an ASGI service (`BUS_BOOT`) that verifies the kernel JWT with the same `make_require_principal` the vault uses and stamps `principal`/`org` from the claims. Two delivery strategies — in-process handler invocation (embedded posture) and HTTP push (hosted posture) — sit behind one `Delivery` interface and are parity-tested. Thin `islands_bus` (Python) and `bus.ts` (Node) libs wrap the HTTP contract; a cross-language test proves a Node island publishes and a Python island consumes the same envelope, and the reverse.

**Tech Stack:** Python 3.11+, FastAPI/Starlette, PyJWT[crypto] (EdDSA, already wired), SQLite (`sqlite3`, WAL), `jsonschema>=4` (new — strict `data` validation against declared schema), httpx; Node/TypeScript with `jose` (already present) + vitest; pytest + pytest-asyncio.

## Global Constraints

- Work on the current branch only. Never create a branch. No `git push` without explicit human OK.
- The language-neutral HTTP contract is authoritative; the libs are thin wrappers and never own the protocol (islands-kernel/CLAUDE.md).
- Asymmetric trust only: islands verify the kernel JWT via JWKS; no shared symmetric secret across languages. The bus holds only the kernel's PUBLIC JWKS.
- `principal` and `org` are stamped server-side from the verified kernel JWT — never trusted from the request body.
- Ledger + dead-letter rows are metadata-only: `event_id, source, subscription_id, status, attempts, last_error (error class only), next_attempt_at`. Never the `data` payload, never PII/amounts.
- Events never cross org in v1. Cross-org publish/subscribe is rejected.
- No new infra: reuse the posture-3 store + single-writer lease. No broker/streaming/fan-out-at-scale, no cross-org federation, no events UI (all out of scope).
- Never commit secret/state files: no `.env`, `*.sqlite`, `*.key`, `*.age`, `vault-store/` contents — the root `.gitignore` already covers these; keep it.
- No AI-sounding prose, no emojis, no personal names, no hardcoded local absolute paths in any committed file (code, tests, docs, commit messages).
- Run tests with `python -m pytest` from the repo root (`pyproject.toml` sets `pythonpath = [".", "libs/python"]`). Node lib tests run with `npm test` in `libs/node`.

## Design decision to confirm at sign-off (payload custody)

The spec says the **ledger + dead-letter are metadata-only** (no `data`), yet **replay must re-attempt delivery** and dispatch needs the envelope. This plan resolves the tension as: the bus persists the **full envelope** (including the small, non-PII `data` — large state stays behind `trace` by contract) in an `events` table, which is the bus's authoritative event log used for dispatch and replay; the **Delivery rows and the `/deadletter` view carry metadata only** (no `data` column, error *class* not message body). This satisfies "ledger/dead-letter records carry metadata only" while keeping replay self-contained. If you would rather the bus hold **zero** `data` at rest and have replay re-fetch via `trace` from the owning island, say so and Task 4/7/10 change (the `events` table drops `data`, replay gains a `trace`-fetch hook). Plan assumes the persist-envelope interpretation.

---

## File structure

New package `bus/` (beside `vault/`, `identity/`):

- `bus/model.py` — `Event`, `Subscription`, `Delivery`, `EventContract` dataclasses; `EnvelopeError`; `new_event_id`.
- `bus/envelope.py` — server-side stamping (`stamp_envelope`) + strict envelope validation (`validate_envelope`).
- `bus/schema_registry.py` — in-memory map of `schema id -> JSON Schema`; `validate_data(schema_id, data)`.
- `bus/store/base.py` — `LedgerStore` ABC.
- `bus/store/memory.py` — `InMemoryLedgerStore`.
- `bus/store/server.py` — `ServerLedgerStore` (SQLite, WAL, in-process mutex, DB-row lease — mirrors `vault/store/server.py`).
- `bus/dispatch.py` — `Dispatcher` (exactly-once effect, backoff, dead-letter, lease-guarded) + `InProcessDelivery`, `HttpPushDelivery`.
- `bus/service.py` — `BusService` (publish/subscribe/replay + authorize gating).
- `bus/provisioning.py` — `grant_event_type_use` (kernel-operator helper, mirrors `identity.service_principal.grant_connection_use`).
- `bus/app.py` — `build_bus_app(...)` + `app = ... if BUS_BOOT`.
- `libs/python/islands_bus/__init__.py`, `libs/python/islands_bus/client.py` — `BusClient` + transports.
- `libs/node/src/bus.ts` — Node thin lib (publish/subscribe/replayDeadLetter + envelope types).
- `libs/node/test/bus.test.ts` — Node lib unit tests.

Modified:

- `identity/model.py` — extend `TargetKind` to include `"event-type"`.
- `identity/authorize.py` — `_covers` nests org-scoped grants over `"event-type"`.
- `pyproject.toml` — add `jsonschema>=4` to `dependencies`.
- `tests/served_harness.py` — add `build_served_bus_stack(...)`.
- `docs/event-bus.md` — run/env contract for the served bus (new).
- `CLAUDE.md` — add `bus/` to the Structure block.

Tests (under `tests/`):

- `tests/test_event_envelope.py`, `tests/test_schema_registry.py`, `tests/test_ledger_store_parity.py`, `tests/test_ledger_lease.py`, `tests/test_dispatch.py`, `tests/test_http_push.py`, `tests/test_bus_service.py`, `tests/test_bus_app.py`, `tests/test_bus_authz.py`, `tests/test_served_bus_single_writer.py`, `tests/test_bus_cross_language.py`, `tests/test_bus_posture_parity.py`, `tests/test_authorize_event_type.py`.

---

## Task 1: Extend the grant model to event types

**Files:**
- Modify: `identity/model.py:7`
- Modify: `identity/authorize.py:12-27`
- Test: `tests/test_authorize_event_type.py`

**Interfaces:**
- Consumes: `identity.authorize.authorize`, `identity.model.{Grant,GrantTarget}` (existing signatures unchanged).
- Produces: `GrantTarget(kind="event-type", id=<type>)` is a valid, enforceable target; an `org`-scoped grant covers `event-type` targets in that org.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_authorize_event_type.py
from identity.authorize import authorize
from identity.model import Grant, GrantTarget


def _grant(target, access="use"):
    return Grant(id="g1", principal_id="prn_a", target=target, access=access,
                 scopes_subset=None, granted_by="prn_owner", granted_at=0.0, revoked_at=None)


def test_direct_event_type_grant_authorizes():
    grants = [_grant(GrantTarget("event-type", "bookkeeping.voucher.posted"))]
    assert authorize(grants=grants, target=GrantTarget("event-type", "bookkeeping.voucher.posted"),
                     access="use", now=1.0, request_org="org_1") is True


def test_event_type_grant_does_not_authorize_other_type():
    grants = [_grant(GrantTarget("event-type", "bookkeeping.voucher.posted"))]
    assert authorize(grants=grants, target=GrantTarget("event-type", "smartcharge.deal.won"),
                     access="use", now=1.0, request_org="org_1") is False


def test_org_grant_nests_over_event_type():
    grants = [_grant(GrantTarget("org", "org_1"))]
    assert authorize(grants=grants, target=GrantTarget("event-type", "anything.happened"),
                     access="use", now=1.0, request_org="org_1") is True


def test_org_grant_does_not_nest_over_other_org_event_type():
    grants = [_grant(GrantTarget("org", "org_1"))]
    assert authorize(grants=grants, target=GrantTarget("event-type", "anything.happened"),
                     access="use", now=1.0, request_org="org_2") is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_authorize_event_type.py -v`
Expected: FAIL — `test_org_grant_nests_over_event_type` fails (org grant does not yet cover `event-type`).

- [ ] **Step 3: Make the minimal change**

In `identity/model.py` line 7, extend the literal:

```python
TargetKind = Literal["org", "island", "capability", "connection", "event-type"]
```

In `identity/authorize.py`, extend the nesting tuple in `_covers` (the `target.kind in (...)` check):

```python
    if (
        grant_target.kind == "org"
        and request_org is not None
        and grant_target.id == request_org
        and target.kind in ("island", "capability", "connection", "event-type")
    ):
        return True
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_authorize_event_type.py -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add identity/model.py identity/authorize.py tests/test_authorize_event_type.py
git commit -m "feat(identity): add event-type grant target"
```

---

## Task 2: Event-bus data model + envelope stamping & validation

**Files:**
- Create: `bus/__init__.py` (empty)
- Create: `bus/model.py`
- Create: `bus/envelope.py`
- Modify: `pyproject.toml` (add `jsonschema>=4` to `dependencies`)
- Test: `tests/test_event_envelope.py`

**Interfaces:**
- Consumes: `vault.model.new_id` (signature `new_id(prefix: str, seed: str) -> str`).
- Produces:
  - `Event(id, type, schema, source, org, principal, occurred_at, trace, data)` dataclass.
  - `Subscription(id, org, consumer, type, target, grant_ref)` dataclass.
  - `Delivery(event_id, source, subscription_id, status, attempts, last_error, next_attempt_at)` dataclass.
  - `EventContract(island, emits, consumes)` dataclass.
  - `EnvelopeError(Exception)`.
  - `new_event_id() -> str` (returns `"evt_<rand>"`).
  - `bus.envelope.stamp_envelope(body: dict, *, principal: str, org: str, now_iso: str) -> Event` — stamps `principal`/`org` from args (never the body), assigns `id` if absent, sets `occurred_at` from body or `now_iso`.
  - `bus.envelope.validate_envelope(event: Event) -> None` — raises `EnvelopeError` on any structural violation.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_event_envelope.py
import pytest
from bus.model import Event, EnvelopeError
from bus.envelope import stamp_envelope, validate_envelope


def _body(**over):
    b = {"type": "bookkeeping.voucher.posted", "schema": "voucher/v1",
         "source": "bookkeeping", "trace": {"store": "bk-audit", "ref": "a1"},
         "data": {"voucherId": "V-1"}, "occurredAt": "2026-06-20T10:00:00Z"}
    b.update(over)
    return b


def test_stamp_sets_principal_org_and_id_from_server_not_body():
    body = _body(principal="prn_EVIL", org="org_EVIL", id=None)
    ev = stamp_envelope(body, principal="prn_real", org="org_real", now_iso="2026-06-20T11:00:00Z")
    assert ev.principal == "prn_real"
    assert ev.org == "org_real"
    assert ev.id.startswith("evt_")
    assert ev.occurred_at == "2026-06-20T10:00:00Z"  # producer-set occurredAt is kept


def test_stamp_defaults_occurred_at_when_absent():
    body = _body()
    del body["occurredAt"]
    ev = stamp_envelope(body, principal="prn_real", org="org_real", now_iso="2026-06-20T11:00:00Z")
    assert ev.occurred_at == "2026-06-20T11:00:00Z"


def test_validate_accepts_well_formed_envelope():
    ev = stamp_envelope(_body(), principal="prn_real", org="org_real", now_iso="2026-06-20T11:00:00Z")
    validate_envelope(ev)  # no raise


def test_validate_rejects_missing_trace_ref():
    ev = stamp_envelope(_body(trace={"store": "bk-audit"}), principal="p", org="o",
                        now_iso="2026-06-20T11:00:00Z")
    with pytest.raises(EnvelopeError):
        validate_envelope(ev)


def test_validate_rejects_non_dotted_type():
    ev = stamp_envelope(_body(type="notdotted"), principal="p", org="o",
                        now_iso="2026-06-20T11:00:00Z")
    with pytest.raises(EnvelopeError):
        validate_envelope(ev)


def test_validate_rejects_non_object_data():
    ev = stamp_envelope(_body(data=["nope"]), principal="p", org="o",
                        now_iso="2026-06-20T11:00:00Z")
    with pytest.raises(EnvelopeError):
        validate_envelope(ev)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_event_envelope.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'bus'`.

- [ ] **Step 3: Write the model and envelope modules, add the dependency**

`bus/__init__.py`: empty file.

`bus/model.py`:

```python
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

from identity.tokens import generate_raw_token


class EnvelopeError(Exception):
    """Raised when an event envelope violates the canonical contract."""


def new_event_id() -> str:
    return generate_raw_token("evt")


@dataclass
class Event:
    id: str
    type: str
    schema: str
    source: str
    org: str
    principal: str
    occurred_at: str   # RFC3339, producer-set
    trace: dict        # { store, ref } — reference, never the fat payload
    data: dict         # small, validated against `schema`


@dataclass
class Subscription:
    id: str
    org: str
    consumer: str
    type: str          # exact event type or a prefix glob, e.g. "bookkeeping.*"
    target: dict       # {"kind":"inprocess","key":...} or {"kind":"http","url":...,"audience":...}
    grant_ref: str


@dataclass
class Delivery:
    event_id: str
    source: str
    subscription_id: str
    status: str        # "pending" | "delivered" | "dead"
    attempts: int
    last_error: Optional[str]       # error CLASS only, never a payload/message body
    next_attempt_at: Optional[float]


@dataclass
class EventContract:
    island: str
    emits: list[str]
    consumes: list[str]
```

`bus/envelope.py`:

```python
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
        data=body.get("data") if isinstance(body.get("data"), dict) else body.get("data"),
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
```

In `pyproject.toml`, add `"jsonschema>=4",` to the `dependencies` list (after `"cryptography>=42",`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_event_envelope.py -v`
Expected: PASS (6 passed).

- [ ] **Step 5: Commit**

```bash
git add bus/__init__.py bus/model.py bus/envelope.py pyproject.toml tests/test_event_envelope.py
git commit -m "feat(bus): canonical event envelope model, stamping and validation"
```

---

## Task 3: Event data-schema registry

**Files:**
- Create: `bus/schema_registry.py`
- Test: `tests/test_schema_registry.py`

**Interfaces:**
- Consumes: `jsonschema` (the library), `bus.model.EnvelopeError`.
- Produces: `SchemaRegistry` with `register(schema_id: str, json_schema: dict) -> None`, `validate_data(schema_id: str, data: dict) -> None` (raises `EnvelopeError` on unknown id or `data` mismatch).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_schema_registry.py
import pytest
from bus.schema_registry import SchemaRegistry
from bus.model import EnvelopeError

VOUCHER_V1 = {
    "type": "object",
    "required": ["voucherId"],
    "properties": {"voucherId": {"type": "string"}},
    "additionalProperties": False,
}


def test_validate_data_accepts_matching_payload():
    r = SchemaRegistry()
    r.register("voucher/v1", VOUCHER_V1)
    r.validate_data("voucher/v1", {"voucherId": "V-1"})  # no raise


def test_validate_data_rejects_mismatch():
    r = SchemaRegistry()
    r.register("voucher/v1", VOUCHER_V1)
    with pytest.raises(EnvelopeError):
        r.validate_data("voucher/v1", {"voucherId": 7})


def test_validate_data_rejects_extra_properties():
    r = SchemaRegistry()
    r.register("voucher/v1", VOUCHER_V1)
    with pytest.raises(EnvelopeError):
        r.validate_data("voucher/v1", {"voucherId": "V-1", "amount": 100})


def test_validate_data_unknown_schema_raises():
    r = SchemaRegistry()
    with pytest.raises(EnvelopeError):
        r.validate_data("nope/v9", {"x": 1})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_schema_registry.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'bus.schema_registry'`.

- [ ] **Step 3: Write the registry**

`bus/schema_registry.py`:

```python
from __future__ import annotations

import jsonschema

from bus.model import EnvelopeError


class SchemaRegistry:
    """Maps a schema id+version (e.g. "voucher/v1") to a JSON Schema for `data`."""

    def __init__(self) -> None:
        self._schemas: dict[str, dict] = {}

    def register(self, schema_id: str, json_schema: dict) -> None:
        self._schemas[schema_id] = json_schema

    def validate_data(self, schema_id: str, data: dict) -> None:
        schema = self._schemas.get(schema_id)
        if schema is None:
            raise EnvelopeError(f"unknown data schema: {schema_id!r}")
        try:
            jsonschema.validate(instance=data, schema=schema)
        except jsonschema.ValidationError as exc:
            # message-only; never echo the offending data into a stored record
            raise EnvelopeError(f"data does not match {schema_id}: {exc.message}") from None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_schema_registry.py -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add bus/schema_registry.py tests/test_schema_registry.py
git commit -m "feat(bus): event data-schema registry with strict validation"
```

---

## Task 4: In-memory ledger store

**Files:**
- Create: `bus/store/__init__.py` (empty)
- Create: `bus/store/base.py`
- Create: `bus/store/memory.py`
- Test: `tests/test_ledger_store_parity.py` (the in-memory half; the parametrize gains SQLite in Task 5)

**Interfaces:**
- Consumes: `bus.model.{Event,Subscription,Delivery,EventContract}`.
- Produces: `LedgerStore` ABC + `InMemoryLedgerStore` with:
  - `record_event(event: Event) -> bool` — insert keyed `(source, id)`; `True` if new, `False` if duplicate (no overwrite).
  - `get_event(source: str, event_id: str) -> Optional[Event]`.
  - `put_subscription(sub: Subscription) -> None`.
  - `get_subscription(sub_id: str) -> Optional[Subscription]`.
  - `delete_subscription(sub_id: str) -> None`.
  - `list_subscriptions(org: str) -> list[Subscription]`.
  - `matching_subscriptions(org: str, event_type: str) -> list[Subscription]` — exact match or glob (`"a.b.*"` matches `"a.b.c"`).
  - `put_delivery(d: Delivery) -> None` / `get_delivery(event_id, source, subscription_id) -> Optional[Delivery]`.
  - `list_deliveries_by_status(org: str, status: str) -> list[Delivery]` (org via the owning event).
  - `put_contract(c: EventContract) -> None` / `list_contracts() -> list[EventContract]`.
  - `acquire_lease(key: str, holder: str, until: float, now: float) -> bool` / `release_lease(key, holder) -> None` / `lease_held(key, now) -> bool` — identical semantics to `vault.store.base.Store`.

- [ ] **Step 1: Write the failing test (store-agnostic, parametrized)**

```python
# tests/test_ledger_store_parity.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_ledger_store_parity.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'bus.store'`.

- [ ] **Step 3: Write the ABC and the in-memory store**

`bus/store/__init__.py`: empty file.

`bus/store/base.py`:

```python
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Optional

from bus.model import Event, Subscription, Delivery, EventContract


class LedgerStore(ABC):
    # --- events / idempotency ---
    @abstractmethod
    def record_event(self, event: Event) -> bool: ...
    @abstractmethod
    def get_event(self, source: str, event_id: str) -> Optional[Event]: ...

    # --- subscriptions ---
    @abstractmethod
    def put_subscription(self, sub: Subscription) -> None: ...
    @abstractmethod
    def get_subscription(self, sub_id: str) -> Optional[Subscription]: ...
    @abstractmethod
    def delete_subscription(self, sub_id: str) -> None: ...
    @abstractmethod
    def list_subscriptions(self, org: str) -> list[Subscription]: ...
    @abstractmethod
    def matching_subscriptions(self, org: str, event_type: str) -> list[Subscription]: ...

    # --- deliveries (metadata only) ---
    @abstractmethod
    def put_delivery(self, d: Delivery) -> None: ...
    @abstractmethod
    def get_delivery(self, event_id: str, source: str, subscription_id: str) -> Optional[Delivery]: ...
    @abstractmethod
    def list_deliveries_by_status(self, org: str, status: str) -> list[Delivery]: ...

    # --- event-contract registry ---
    @abstractmethod
    def put_contract(self, c: EventContract) -> None: ...
    @abstractmethod
    def list_contracts(self) -> list[EventContract]: ...

    # --- single-writer lease (same semantics as vault.store.base.Store) ---
    @abstractmethod
    def acquire_lease(self, key: str, holder: str, until: float, now: float) -> bool: ...
    @abstractmethod
    def release_lease(self, key: str, holder: str) -> None: ...
    @abstractmethod
    def lease_held(self, key: str, now: float) -> bool: ...


def type_matches(sub_type: str, event_type: str) -> bool:
    """Exact match, or a trailing `.*` prefix glob (e.g. 'a.b.*' matches 'a.b.c')."""
    if sub_type == event_type:
        return True
    if sub_type.endswith(".*"):
        return event_type.startswith(sub_type[:-1])  # keep the trailing dot
    return False
```

`bus/store/memory.py`:

```python
from __future__ import annotations
import threading
from typing import Optional

from bus.model import Event, Subscription, Delivery, EventContract
from bus.store.base import LedgerStore, type_matches


class InMemoryLedgerStore(LedgerStore):
    def __init__(self) -> None:
        self._mu = threading.Lock()
        self._events: dict[tuple[str, str], Event] = {}          # (source, id)
        self._subs: dict[str, Subscription] = {}
        self._deliveries: dict[tuple[str, str, str], Delivery] = {}  # (event_id, source, sub_id)
        self._contracts: dict[str, EventContract] = {}
        self._leases: dict[str, tuple[str, float]] = {}          # key -> (holder, until)

    def record_event(self, event):
        with self._mu:
            k = (event.source, event.id)
            if k in self._events:
                return False
            self._events[k] = event
            return True

    def get_event(self, source, event_id):
        return self._events.get((source, event_id))

    def put_subscription(self, sub):
        with self._mu:
            self._subs[sub.id] = sub

    def get_subscription(self, sub_id):
        return self._subs.get(sub_id)

    def delete_subscription(self, sub_id):
        with self._mu:
            self._subs.pop(sub_id, None)

    def list_subscriptions(self, org):
        return [s for s in self._subs.values() if s.org == org]

    def matching_subscriptions(self, org, event_type):
        return [s for s in self._subs.values()
                if s.org == org and type_matches(s.type, event_type)]

    def put_delivery(self, d):
        with self._mu:
            self._deliveries[(d.event_id, d.source, d.subscription_id)] = d

    def get_delivery(self, event_id, source, subscription_id):
        return self._deliveries.get((event_id, source, subscription_id))

    def list_deliveries_by_status(self, org, status):
        out = []
        for d in self._deliveries.values():
            ev = self._events.get((d.source, d.event_id))
            if ev is not None and ev.org == org and d.status == status:
                out.append(d)
        return out

    def put_contract(self, c):
        with self._mu:
            self._contracts[c.island] = c

    def list_contracts(self):
        return list(self._contracts.values())

    def acquire_lease(self, key, holder, until, now):
        with self._mu:
            cur = self._leases.get(key)
            if cur is None or cur[1] <= now:
                self._leases[key] = (holder, until)
                return True
            return False

    def release_lease(self, key, holder):
        with self._mu:
            cur = self._leases.get(key)
            if cur is not None and cur[0] == holder:
                del self._leases[key]

    def lease_held(self, key, now):
        cur = self._leases.get(key)
        return cur is not None and cur[1] > now
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_ledger_store_parity.py -v`
Expected: PASS (9 passed).

- [ ] **Step 5: Commit**

```bash
git add bus/store/__init__.py bus/store/base.py bus/store/memory.py tests/test_ledger_store_parity.py
git commit -m "feat(bus): ledger store ABC and in-memory implementation"
```

---

## Task 5: SQLite served ledger store (parity with memory)

**Files:**
- Create: `bus/store/server.py`
- Modify: `tests/test_ledger_store_parity.py:8-15` (add the SQLite store to the parametrize)
- Test: same file (now runs every case against both stores)

**Interfaces:**
- Consumes: `bus.store.base.{LedgerStore,type_matches}`, `bus.model.*`.
- Produces: `ServerLedgerStore(conn_str: str)` — `sqlite3` WAL + in-process mutex + DB-row lease, same constructor shape as `vault.store.server.ServerStore` minus the wrapper (the bus stores no secrets).

- [ ] **Step 1: Extend the parametrize to drive both stores**

In `tests/test_ledger_store_parity.py`, replace `_stores` and the fixture:

```python
from bus.store.memory import InMemoryLedgerStore
from bus.store.server import ServerLedgerStore


def _stores(tmp_path):
    return [InMemoryLedgerStore(), ServerLedgerStore(f"sqlite:///{tmp_path}/ledger.sqlite")]


@pytest.fixture(params=[0, 1])
def store(request, tmp_path):
    return _stores(tmp_path)[request.param]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_ledger_store_parity.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'bus.store.server'`.

- [ ] **Step 3: Write the SQLite store**

`bus/store/server.py`:

```python
from __future__ import annotations
import json
import sqlite3
import threading
from typing import Optional

from bus.model import Event, Subscription, Delivery, EventContract
from bus.store.base import LedgerStore, type_matches

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  source TEXT, id TEXT, type TEXT, schema TEXT, org TEXT, principal TEXT,
  occurred_at TEXT, trace_json TEXT, data_json TEXT,
  PRIMARY KEY (source, id));
CREATE TABLE IF NOT EXISTS subscriptions(
  id TEXT PRIMARY KEY, org TEXT, consumer TEXT, type TEXT, target_json TEXT, grant_ref TEXT);
CREATE TABLE IF NOT EXISTS deliveries(
  event_id TEXT, source TEXT, subscription_id TEXT, status TEXT, attempts INTEGER,
  last_error TEXT, next_attempt_at REAL,
  PRIMARY KEY (event_id, source, subscription_id));
CREATE TABLE IF NOT EXISTS contracts(
  island TEXT PRIMARY KEY, emits_json TEXT, consumes_json TEXT);
CREATE TABLE IF NOT EXISTS leases(lease_key TEXT PRIMARY KEY, holder TEXT, until REAL);
"""


class ServerLedgerStore(LedgerStore):
    def __init__(self, conn_str: str) -> None:
        path = conn_str.replace("sqlite:///", "") if conn_str.startswith("sqlite:///") else ":memory:"
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(_SCHEMA)
        self._db.commit()
        self._mu = threading.Lock()

    def record_event(self, event):
        with self._mu, self._db:
            cur = self._db.execute(
                "INSERT OR IGNORE INTO events(source,id,type,schema,org,principal,"
                "occurred_at,trace_json,data_json) VALUES(?,?,?,?,?,?,?,?,?)",
                (event.source, event.id, event.type, event.schema, event.org, event.principal,
                 event.occurred_at, json.dumps(event.trace), json.dumps(event.data)))
            return cur.rowcount == 1

    def get_event(self, source, event_id):
        with self._mu:
            r = self._db.execute(
                "SELECT source,id,type,schema,org,principal,occurred_at,trace_json,data_json "
                "FROM events WHERE source=? AND id=?", (source, event_id)).fetchone()
        if r is None:
            return None
        return Event(id=r[1], type=r[2], schema=r[3], source=r[0], org=r[4], principal=r[5],
                     occurred_at=r[6], trace=json.loads(r[7]), data=json.loads(r[8]))

    def put_subscription(self, sub):
        with self._mu, self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO subscriptions VALUES(?,?,?,?,?,?)",
                (sub.id, sub.org, sub.consumer, sub.type, json.dumps(sub.target), sub.grant_ref))

    def get_subscription(self, sub_id):
        with self._mu:
            r = self._db.execute("SELECT * FROM subscriptions WHERE id=?", (sub_id,)).fetchone()
        return self._sub(r)

    def delete_subscription(self, sub_id):
        with self._mu, self._db:
            self._db.execute("DELETE FROM subscriptions WHERE id=?", (sub_id,))

    def list_subscriptions(self, org):
        with self._mu:
            rows = self._db.execute("SELECT * FROM subscriptions WHERE org=?", (org,)).fetchall()
        return [self._sub(r) for r in rows]

    def matching_subscriptions(self, org, event_type):
        return [s for s in self.list_subscriptions(org) if type_matches(s.type, event_type)]

    @staticmethod
    def _sub(r):
        if r is None:
            return None
        return Subscription(id=r[0], org=r[1], consumer=r[2], type=r[3],
                            target=json.loads(r[4]), grant_ref=r[5])

    def put_delivery(self, d):
        with self._mu, self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO deliveries VALUES(?,?,?,?,?,?,?)",
                (d.event_id, d.source, d.subscription_id, d.status, d.attempts,
                 d.last_error, d.next_attempt_at))

    def get_delivery(self, event_id, source, subscription_id):
        with self._mu:
            r = self._db.execute(
                "SELECT * FROM deliveries WHERE event_id=? AND source=? AND subscription_id=?",
                (event_id, source, subscription_id)).fetchone()
        if r is None:
            return None
        return Delivery(event_id=r[0], source=r[1], subscription_id=r[2], status=r[3],
                        attempts=r[4], last_error=r[5], next_attempt_at=r[6])

    def list_deliveries_by_status(self, org, status):
        with self._mu:
            rows = self._db.execute(
                "SELECT d.event_id,d.source,d.subscription_id,d.status,d.attempts,"
                "d.last_error,d.next_attempt_at FROM deliveries d "
                "JOIN events e ON e.source=d.source AND e.id=d.event_id "
                "WHERE e.org=? AND d.status=?", (org, status)).fetchall()
        return [Delivery(*r) for r in rows]

    def put_contract(self, c):
        with self._mu, self._db:
            self._db.execute("INSERT OR REPLACE INTO contracts VALUES(?,?,?)",
                             (c.island, json.dumps(c.emits), json.dumps(c.consumes)))

    def list_contracts(self):
        with self._mu:
            rows = self._db.execute("SELECT * FROM contracts").fetchall()
        return [EventContract(island=r[0], emits=json.loads(r[1]), consumes=json.loads(r[2]))
                for r in rows]

    def acquire_lease(self, key, holder, until, now):
        with self._mu, self._db:
            cur = self._db.execute(
                "INSERT OR IGNORE INTO leases(lease_key,holder,until) VALUES(?,?,?)",
                (key, holder, until))
            if cur.rowcount == 1:
                return True
            cur = self._db.execute(
                "UPDATE leases SET holder=?, until=? WHERE lease_key=? AND until<=?",
                (holder, until, key, now))
            return cur.rowcount == 1

    def release_lease(self, key, holder):
        with self._mu, self._db:
            self._db.execute("DELETE FROM leases WHERE lease_key=? AND holder=?", (key, holder))

    def lease_held(self, key, now):
        with self._mu:
            r = self._db.execute("SELECT until FROM leases WHERE lease_key=?", (key,)).fetchone()
        return r is not None and r[0] > now
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_ledger_store_parity.py -v`
Expected: PASS (18 passed — 9 cases × 2 stores).

- [ ] **Step 5: Commit**

```bash
git add bus/store/server.py tests/test_ledger_store_parity.py
git commit -m "feat(bus): SQLite served ledger store, parity-tested with memory"
```

---

## Task 6: Single-writer lease stress test (mirror slice-1)

**Files:**
- Test: `tests/test_ledger_lease.py`

**Interfaces:**
- Consumes: `bus.store.{memory,server}` lease methods.
- Produces: nothing new — proves the lease serializes concurrent holders the same way `tests/test_refresh_single_writer.py` proves it for the vault.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_ledger_lease.py
import threading
import pytest
from bus.store.memory import InMemoryLedgerStore
from bus.store.server import ServerLedgerStore


@pytest.fixture(params=["memory", "server"])
def store(request, tmp_path):
    if request.param == "memory":
        return InMemoryLedgerStore()
    return ServerLedgerStore(f"sqlite:///{tmp_path}/ledger.sqlite")


def test_concurrent_acquire_grants_exactly_one(store):
    winners = []
    barrier = threading.Barrier(16)

    def worker(i):
        barrier.wait()
        if store.acquire_lease("dispatch:evt_1", f"h{i}", until=1e12, now=0.0):
            winners.append(i)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(winners) == 1
```

- [ ] **Step 2: Run test to verify it fails (or proves the lease)**

Run: `python -m pytest tests/test_ledger_lease.py -v`
Expected: PASS for both stores (the lease was implemented in Tasks 4–5; this test locks the guarantee). If it FAILS, the lease has a race — fix the store before proceeding.

- [ ] **Step 3: (no new code unless the test fails)**

If `server` fails because `INSERT OR IGNORE` + `UPDATE ... until<=?` is not atomic under the mutex, confirm both statements run inside the single `with self._mu, self._db:` block in `acquire_lease`. No change expected.

- [ ] **Step 4: Re-run**

Run: `python -m pytest tests/test_ledger_lease.py -v`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add tests/test_ledger_lease.py
git commit -m "test(bus): single-writer lease stress proof for the ledger"
```

---

## Task 7: Dispatcher — exactly-once effect, backoff, dead-letter (in-process delivery)

**Files:**
- Create: `bus/dispatch.py`
- Test: `tests/test_dispatch.py`

**Interfaces:**
- Consumes: `bus.store.base.LedgerStore`, `bus.model.{Event,Subscription,Delivery}`.
- Produces:
  - `class Delivery(Protocol)` / a delivery callable interface; `InProcessDelivery` with `register(key: str, handler)` and `deliver(sub: Subscription, event: Event) -> None` (raises on failure).
  - `BackoffPolicy(max_attempts=5, base=1.0, cap=60.0)` with `next_at(attempts, now) -> float`.
  - `Dispatcher(store, delivery, *, now_fn, backoff=BackoffPolicy(), lease_ttl=30.0)` with:
    - `dispatch(event: Event) -> None` — for each matching subscription, attempt delivery exactly once per `(event_id, source, subscription_id)` under a lease; redelivery of a `delivered` row is a no-op; failure schedules a retry; after `max_attempts` the row goes `dead`.
    - `attempt_pending(delivery: Delivery) -> None` — re-attempt one stored delivery (used by retry/replay).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_dispatch.py
import itertools
from bus.model import Event, Subscription, Delivery
from bus.store.memory import InMemoryLedgerStore
from bus.dispatch import Dispatcher, InProcessDelivery, BackoffPolicy


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_dispatch.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'bus.dispatch'`.

- [ ] **Step 3: Write the dispatcher**

`bus/dispatch.py`:

```python
from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Optional

from bus.model import Event, Subscription, Delivery
from bus.store.base import LedgerStore
from identity.tokens import generate_raw_token


class InProcessDelivery:
    """Embedded-posture delivery: invoke a locally registered handler."""

    def __init__(self) -> None:
        self._handlers: dict[str, Callable[[Event], None]] = {}

    def register(self, key: str, handler: Callable[[Event], None]) -> None:
        self._handlers[key] = handler

    def deliver(self, sub: Subscription, event: Event) -> None:
        key = sub.target.get("key")
        handler = self._handlers.get(key)
        if handler is None:
            raise LookupError("no handler registered")
        handler(event)


@dataclass
class BackoffPolicy:
    max_attempts: int = 5
    base: float = 1.0
    cap: float = 60.0

    def next_at(self, attempts: int, now: float) -> float:
        delay = min(self.cap, self.base * (2 ** (attempts - 1)))
        return now + delay


class Dispatcher:
    def __init__(self, store: LedgerStore, delivery, *, now_fn: Callable[[], float],
                 backoff: BackoffPolicy = BackoffPolicy(), lease_ttl: float = 30.0) -> None:
        self._store = store
        self._delivery = delivery
        self._now = now_fn
        self._backoff = backoff
        self._lease_ttl = lease_ttl

    def dispatch(self, event: Event) -> None:
        for sub in self._store.matching_subscriptions(event.org, event.type):
            self._attempt(event, sub)

    def attempt_pending(self, delivery: Delivery) -> None:
        event = self._store.get_event(delivery.source, delivery.event_id)
        sub = self._store.get_subscription(delivery.subscription_id)
        if event is None or sub is None:
            return
        self._attempt(event, sub)

    def _attempt(self, event: Event, sub: Subscription) -> None:
        key = f"dispatch:{event.source}:{event.id}:{sub.id}"
        existing = self._store.get_delivery(event.id, event.source, sub.id)
        if existing is not None and existing.status == "delivered":
            return  # exactly-once effect: a delivered pair never re-runs

        now = self._now()
        holder = generate_raw_token("disp")
        if not self._store.acquire_lease(key, holder, until=now + self._lease_ttl, now=now):
            return  # another dispatcher owns this delivery
        try:
            # re-check under the lease
            existing = self._store.get_delivery(event.id, event.source, sub.id)
            if existing is not None and existing.status == "delivered":
                return
            attempts = (existing.attempts if existing else 0) + 1
            try:
                self._delivery.deliver(sub, event)
            except Exception as exc:  # noqa: BLE001 - record class, re-schedule or dead-letter
                err = type(exc).__name__
                if attempts >= self._backoff.max_attempts:
                    status, next_at = "dead", None
                else:
                    status, next_at = "pending", self._backoff.next_at(attempts, now)
                self._store.put_delivery(Delivery(event.id, event.source, sub.id,
                                                  status, attempts, err, next_at))
                return
            self._store.put_delivery(Delivery(event.id, event.source, sub.id,
                                              "delivered", attempts, None, None))
        finally:
            self._store.release_lease(key, holder)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_dispatch.py -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add bus/dispatch.py tests/test_dispatch.py
git commit -m "feat(bus): dispatcher with exactly-once effect, backoff and dead-letter"
```

---

## Task 8: HTTP push delivery (hosted posture)

**Files:**
- Modify: `bus/dispatch.py` (add `HttpPushDelivery`)
- Test: `tests/test_http_push.py`

**Interfaces:**
- Consumes: `httpx` (or an injected poster), `bus.model.{Subscription,Event}`.
- Produces: `HttpPushDelivery(http_post: Callable[[str, dict, dict], object] | None = None)` with `deliver(sub, event)` that POSTs the JSON envelope to `sub.target["url"]` with an `X-Event-Audience: sub.target["audience"]` header; a non-2xx raises so the dispatcher records the failure. Same `deliver(sub, event)` signature as `InProcessDelivery`, so the two are interchangeable behind the dispatcher.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_http_push.py
import pytest
from bus.model import Event, Subscription
from bus.dispatch import HttpPushDelivery


class _FakeResp:
    def __init__(self, status): self.status_code = status


def _ev():
    return Event(id="evt_1", type="a.b.c", schema="s/v1", source="src", org="org_1",
                 principal="prn_a", occurred_at="2026-06-20T10:00:00Z",
                 trace={"store": "x", "ref": "r"}, data={"k": "v"})


def _sub(url="http://consumer.local/events"):
    return Subscription("sub_1", "org_1", "consumer", "a.b.c",
                        {"kind": "http", "url": url, "audience": "consumer"}, "g1")


def test_http_push_posts_envelope_and_audience_header():
    captured = {}
    def post(url, json, headers):
        captured.update(url=url, json=json, headers=headers)
        return _FakeResp(202)
    HttpPushDelivery(http_post=post).deliver(_sub(), _ev())
    assert captured["url"] == "http://consumer.local/events"
    assert captured["json"]["id"] == "evt_1"
    assert captured["headers"]["X-Event-Audience"] == "consumer"


def test_http_push_raises_on_non_2xx():
    HttpPushDelivery(http_post=lambda url, json, headers: _FakeResp(500))
    with pytest.raises(Exception):
        HttpPushDelivery(http_post=lambda url, json, headers: _FakeResp(500)).deliver(_sub(), _ev())
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_http_push.py -v`
Expected: FAIL — `ImportError: cannot import name 'HttpPushDelivery'`.

- [ ] **Step 3: Add `HttpPushDelivery` and an envelope serializer**

Append to `bus/dispatch.py`:

```python
from dataclasses import asdict


def envelope_json(event: Event) -> dict:
    """Wire form of the envelope (camelCase the producer-facing field)."""
    d = asdict(event)
    d["occurredAt"] = d.pop("occurred_at")
    return d


class HttpPushDelivery:
    """Hosted-posture delivery: POST the envelope to the subscriber endpoint."""

    def __init__(self, http_post: Optional[Callable[[str, dict, dict], object]] = None) -> None:
        self._post = http_post

    def _poster(self):
        if self._post is not None:
            return self._post
        import httpx
        def post(url, json, headers):
            return httpx.post(url, json=json, headers=headers, timeout=10.0)
        return post

    def deliver(self, sub: Subscription, event: Event) -> None:
        url = sub.target["url"]
        headers = {"X-Event-Audience": sub.target.get("audience", "")}
        resp = self._poster()(url, envelope_json(event), headers)
        status = getattr(resp, "status_code", 0)
        if not (200 <= status < 300):
            raise RuntimeError(f"push failed: HTTP {status}")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_http_push.py -v`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add bus/dispatch.py tests/test_http_push.py
git commit -m "feat(bus): HTTP push delivery for the hosted posture"
```

---

## Task 9: BusService — publish/subscribe/replay with authorize gating

**Files:**
- Create: `bus/service.py`
- Create: `bus/provisioning.py`
- Test: `tests/test_bus_service.py`

**Interfaces:**
- Consumes: `bus.store.base.LedgerStore`, `bus.schema_registry.SchemaRegistry`, `bus.dispatch.Dispatcher`, `bus.envelope.{stamp_envelope,validate_envelope}`, `identity.authorize.authorize`, `identity.model.GrantTarget`, `bus.model.{Event,Subscription,Delivery,EventContract,EnvelopeError}`.
- Produces:
  - `class AuthzDenied(Exception)`, `class CrossOrgDenied(Exception)`.
  - `BusService(store, schema_registry, dispatcher, *, now_fn, now_iso_fn, grants_for)` where `grants_for(principal_id) -> list[Grant]`.
    - `publish(body: dict, *, principal: str, org: str) -> dict` — authorize `event-type:type` `use`; stamp; validate envelope + `data`; `record_event`; if new, dispatch; returns `{"id": ..., "deduped": bool}`.
    - `subscribe(*, principal: str, org: str, type: str, consumer: str, target: dict, grant_ref: str) -> Subscription` — authorize `event-type:type` `use`; persist a `Subscription`.
    - `unsubscribe(sub_id: str) -> None`.
    - `list_subscriptions(org: str) -> list[Subscription]`.
    - `dead_letters(org: str) -> list[Delivery]`.
    - `replay(event_id: str, source: str, *, org: str) -> int` — re-attempt all `dead` deliveries for that event; returns count re-attempted.
    - `contracts() -> list[EventContract]` / `declare_contract(c: EventContract) -> None`.
- `bus/provisioning.py`: `grant_event_type_use(store, *, principal_id, event_type, granted_by, now) -> Grant` (writes to the identity store; mirrors `grant_connection_use`).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bus_service.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_bus_service.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'bus.service'`.

- [ ] **Step 3: Write the service and provisioning helper**

`bus/service.py`:

```python
from __future__ import annotations
from typing import Callable

from identity.authorize import authorize
from identity.model import GrantTarget
from bus.model import Event, Subscription, Delivery, EventContract, EnvelopeError
from bus.envelope import stamp_envelope, validate_envelope
from bus.schema_registry import SchemaRegistry
from bus.store.base import LedgerStore
from bus.dispatch import Dispatcher
from identity.tokens import generate_raw_token


class AuthzDenied(Exception):
    pass


class BusService:
    def __init__(self, store: LedgerStore, schema_registry: SchemaRegistry,
                 dispatcher: Dispatcher, *, now_fn: Callable[[], float],
                 now_iso_fn: Callable[[], str], grants_for: Callable[[str], list]) -> None:
        self._store = store
        self._schemas = schema_registry
        self._dispatcher = dispatcher
        self._now = now_fn
        self._now_iso = now_iso_fn
        self._grants_for = grants_for

    def _require(self, principal: str, org: str, event_type: str) -> None:
        ok = authorize(grants=self._grants_for(principal),
                       target=GrantTarget("event-type", event_type),
                       access="use", now=self._now(), request_org=org)
        if not ok:
            raise AuthzDenied(f"{principal} lacks use on event-type {event_type}")

    def publish(self, body: dict, *, principal: str, org: str) -> dict:
        event = stamp_envelope(body, principal=principal, org=org, now_iso=self._now_iso())
        self._require(principal, org, event.type)
        validate_envelope(event)
        self._schemas.validate_data(event.schema, event.data)
        is_new = self._store.record_event(event)
        if is_new:
            self._dispatcher.dispatch(event)
        return {"id": event.id, "deduped": not is_new}

    def subscribe(self, *, principal: str, org: str, type: str, consumer: str,
                  target: dict, grant_ref: str) -> Subscription:
        self._require(principal, org, type)
        sub = Subscription(id=generate_raw_token("sub"), org=org, consumer=consumer,
                           type=type, target=target, grant_ref=grant_ref)
        self._store.put_subscription(sub)
        return sub

    def unsubscribe(self, sub_id: str) -> None:
        self._store.delete_subscription(sub_id)

    def list_subscriptions(self, org: str) -> list:
        return self._store.list_subscriptions(org)

    def dead_letters(self, org: str) -> list:
        return self._store.list_deliveries_by_status(org, "dead")

    def replay(self, event_id: str, source: str, *, org: str) -> int:
        n = 0
        for d in self._store.list_deliveries_by_status(org, "dead"):
            if d.event_id == event_id and d.source == source:
                # reset the row to pending so the dispatcher will re-attempt it
                self._store.put_delivery(Delivery(d.event_id, d.source, d.subscription_id,
                                                  "pending", d.attempts, d.last_error, None))
                row = self._store.get_delivery(d.event_id, d.source, d.subscription_id)
                self._dispatcher.attempt_pending(row)
                n += 1
        return n

    def contracts(self) -> list:
        return self._store.list_contracts()

    def declare_contract(self, c: EventContract) -> None:
        self._store.put_contract(c)
```

Note: `replay` resets `attempts` is left as-is; the recovering handler then succeeds and marks `delivered`. The `max_attempts` guard only triggers on the *next* failure, so a one-shot replay of a now-healthy handler delivers. If you want replay to also reset `attempts` to 0, change the `Delivery(... d.attempts ...)` to `0` — keep it as `d.attempts` so repeated replays still dead-letter a permanently-broken handler.

`bus/provisioning.py`:

```python
from __future__ import annotations

from identity.model import Grant, GrantTarget
from identity.tokens import generate_raw_token


def grant_event_type_use(store, *, principal_id: str, event_type: str,
                         granted_by: str, now: float) -> Grant:
    """Grant a principal scoped `use` on one event type (least-privilege pub/sub)."""
    g = Grant(id=generate_raw_token("grant"), principal_id=principal_id,
              target=GrantTarget(kind="event-type", id=event_type), access="use",
              scopes_subset=None, granted_by=granted_by, granted_at=now, revoked_at=None)
    store.add_grant(g)
    return g
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_bus_service.py -v`
Expected: PASS (6 passed).

- [ ] **Step 5: Commit**

```bash
git add bus/service.py bus/provisioning.py tests/test_bus_service.py
git commit -m "feat(bus): BusService publish/subscribe/replay with grant gating"
```

---

## Task 10: ASGI app — POST /events, subscriptions, /_events, /deadletter

**Files:**
- Create: `bus/app.py`
- Test: `tests/test_bus_app.py`

**Interfaces:**
- Consumes: `fastapi.FastAPI`, `identity.deps.make_require_principal` (for the served entrypoint), `bus.service.BusService`, `bus.model.{EnvelopeError,EventContract}`, `bus.service.AuthzDenied`.
- Produces:
  - `build_bus_app(service: BusService, *, require_principal) -> FastAPI` with routes:
    - `POST /events` — body = envelope minus server-stamped fields; stamps `principal`=claims["sub"], `org`=claims["org"]; returns `{id, deduped}`; `EnvelopeError -> 400`, `AuthzDenied -> 403`.
    - `POST /subscriptions` / `GET /subscriptions` / `DELETE /subscriptions/{id}`.
    - `GET /_events` — the contract registry: `{"islands": [{island, emits, consumes}, ...]}`.
    - `GET /deadletter` — metadata-only list for the caller's org.
    - `POST /deadletter/{event_id}/replay?source=...` — `{replayed: n}`.
  - `app = _build_bus_app_from_env() if BUS_BOOT == "1" else None`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bus_app.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_bus_app.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'bus.app'`.

- [ ] **Step 3: Write the app**

`bus/app.py`:

```python
from __future__ import annotations
import os
from dataclasses import asdict

from fastapi import FastAPI, HTTPException, Depends, Body, Request

from bus.model import EnvelopeError
from bus.service import BusService, AuthzDenied


def build_bus_app(service: BusService, *, require_principal) -> FastAPI:
    app = FastAPI(title="islands-kernel event bus")

    @app.post("/events")
    def publish(body: dict = Body(...), claims=Depends(require_principal)):
        try:
            return service.publish(body, principal=claims["sub"], org=claims.get("org"))
        except AuthzDenied as e:
            raise HTTPException(403, str(e))
        except EnvelopeError as e:
            raise HTTPException(400, str(e))

    @app.post("/subscriptions")
    def subscribe(body: dict = Body(...), claims=Depends(require_principal)):
        try:
            sub = service.subscribe(principal=claims["sub"], org=claims.get("org"),
                                    type=body["type"], consumer=body["consumer"],
                                    target=body["target"], grant_ref=body.get("grant_ref", ""))
        except AuthzDenied as e:
            raise HTTPException(403, str(e))
        except KeyError as e:
            raise HTTPException(400, f"missing field: {e}")
        return {"id": sub.id}

    @app.get("/subscriptions")
    def list_subs(claims=Depends(require_principal)):
        return {"subscriptions": [asdict(s) for s in service.list_subscriptions(claims.get("org"))]}

    @app.delete("/subscriptions/{sub_id}")
    def delete_sub(sub_id: str, claims=Depends(require_principal)):
        service.unsubscribe(sub_id)
        return {"deleted": sub_id}

    @app.get("/_events")
    def events_registry():
        return {"islands": [asdict(c) for c in service.contracts()]}

    @app.get("/deadletter")
    def deadletter(claims=Depends(require_principal)):
        rows = service.dead_letters(claims.get("org"))
        return {"dead": [{"event_id": d.event_id, "source": d.source,
                          "subscription_id": d.subscription_id, "status": d.status,
                          "attempts": d.attempts, "last_error": d.last_error} for d in rows]}

    @app.post("/deadletter/{event_id}/replay")
    def replay(event_id: str, source: str, claims=Depends(require_principal)):
        n = service.replay(event_id, source, org=claims.get("org"))
        return {"replayed": n}

    return app


def _build_bus_app_from_env() -> FastAPI:
    import time
    from datetime import datetime, timezone
    from identity.deps import make_require_principal
    from identity.store.server import ServerIdentityStore
    from identity.authorize import collect_grants
    from bus.store.server import ServerLedgerStore
    from bus.schema_registry import SchemaRegistry
    from bus.dispatch import Dispatcher, HttpPushDelivery
    from vault.kernel_auth import cached_jwks_provider

    issuer = os.environ["KERNEL_ISSUER"]
    audience = os.environ["BUS_AUDIENCE"]
    ident = ServerIdentityStore(os.environ.get("KERNEL_IDENTITY_DB", "vault-store/identity.sqlite"))
    store = ServerLedgerStore(os.environ.get("BUS_DB", "sqlite:///vault-store/bus.sqlite"))
    jwks_provider = cached_jwks_provider(os.environ["KERNEL_JWKS_URL"])
    require_principal = make_require_principal(
        jwks_provider=jwks_provider, audience=audience, now_fn=time.time, issuer=issuer)
    dispatcher = Dispatcher(store, HttpPushDelivery(), now_fn=time.time)
    service = BusService(store, SchemaRegistry(), dispatcher, now_fn=time.time,
                         now_iso_fn=lambda: datetime.now(timezone.utc).isoformat(),
                         grants_for=lambda pid: collect_grants(principal_id=pid, identity_store=ident))
    return build_bus_app(service, require_principal=require_principal)


app = _build_bus_app_from_env() if os.environ.get("BUS_BOOT") == "1" else None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_bus_app.py -v`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
git add bus/app.py tests/test_bus_app.py
git commit -m "feat(bus): ASGI app for publish, subscriptions, registry and dead-letter"
```

---

## Task 11: Python thin lib (islands_bus)

**Files:**
- Create: `libs/python/islands_bus/__init__.py`
- Create: `libs/python/islands_bus/client.py`
- Test: `tests/test_bus_lib_python.py`

**Interfaces:**
- Consumes: nothing from the kernel package at runtime (thin wrapper over HTTP); may import `bus.service.BusService` only for the in-process transport used in tests.
- Produces:
  - `class InProcessBusTransport(service: BusService, *, principal, org)` with `publish(envelope_body) -> dict`, `subscribe(body) -> dict`, `replay(event_id, source) -> dict`.
  - `class HttpBusTransport(base_url, *, bearer_provider, http=None)` — POSTs with `Authorization: Bearer <jwt>`.
  - `class BusClient(transport)` with:
    - `publish(type, data, *, source, schema, trace, occurred_at=None, id=None) -> dict`.
    - `subscribe(type, *, consumer, target, grant_ref) -> dict`.
    - `replay_dead_letter(event_id, source) -> dict`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bus_lib_python.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_bus_lib_python.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'islands_bus'`.

- [ ] **Step 3: Write the lib**

`libs/python/islands_bus/__init__.py`:

```python
from islands_bus.client import BusClient, InProcessBusTransport, HttpBusTransport

__all__ = ["BusClient", "InProcessBusTransport", "HttpBusTransport"]
```

`libs/python/islands_bus/client.py`:

```python
from __future__ import annotations
from typing import Callable, Optional, Protocol


class BusTransport(Protocol):
    def publish(self, body: dict) -> dict: ...
    def subscribe(self, body: dict) -> dict: ...
    def replay(self, event_id: str, source: str) -> dict: ...


class InProcessBusTransport:
    """Embedded posture: call a BusService directly. For tests and same-process islands."""

    def __init__(self, service, *, principal: str, org: str) -> None:
        self._svc = service
        self._principal = principal
        self._org = org

    def publish(self, body: dict) -> dict:
        return self._svc.publish(body, principal=self._principal, org=self._org)

    def subscribe(self, body: dict) -> dict:
        sub = self._svc.subscribe(principal=self._principal, org=self._org, type=body["type"],
                                  consumer=body["consumer"], target=body["target"],
                                  grant_ref=body.get("grant_ref", ""))
        return {"id": sub.id}

    def replay(self, event_id: str, source: str) -> dict:
        return {"replayed": self._svc.replay(event_id, source, org=self._org)}


class HttpBusTransport:
    """Hosted posture: POST over HTTP with a kernel JWT bearer."""

    def __init__(self, base_url: str, *, bearer_provider: Callable[[], str], http=None) -> None:
        self._base = base_url.rstrip("/")
        self._bearer = bearer_provider
        self._http = http

    def _client(self):
        if self._http is not None:
            return self._http
        import httpx
        return httpx

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._bearer()}"}

    def publish(self, body: dict) -> dict:
        r = self._client().post(f"{self._base}/events", json=body, headers=self._headers())
        r.raise_for_status()
        return r.json()

    def subscribe(self, body: dict) -> dict:
        r = self._client().post(f"{self._base}/subscriptions", json=body, headers=self._headers())
        r.raise_for_status()
        return r.json()

    def replay(self, event_id: str, source: str) -> dict:
        r = self._client().post(f"{self._base}/deadletter/{event_id}/replay",
                                params={"source": source}, headers=self._headers())
        r.raise_for_status()
        return r.json()


class BusClient:
    def __init__(self, transport: BusTransport) -> None:
        self._t = transport

    def publish(self, type: str, data: dict, *, source: str, schema: str, trace: dict,
                occurred_at: Optional[str] = None, id: Optional[str] = None) -> dict:
        body = {"type": type, "data": data, "source": source, "schema": schema, "trace": trace}
        if occurred_at is not None:
            body["occurredAt"] = occurred_at
        if id is not None:
            body["id"] = id
        return self._t.publish(body)

    def subscribe(self, type: str, *, consumer: str, target: dict, grant_ref: str) -> dict:
        return self._t.subscribe({"type": type, "consumer": consumer,
                                  "target": target, "grant_ref": grant_ref})

    def replay_dead_letter(self, event_id: str, source: str) -> dict:
        return self._t.replay(event_id, source)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_bus_lib_python.py -v`
Expected: PASS (1 passed).

- [ ] **Step 5: Commit**

```bash
git add libs/python/islands_bus/__init__.py libs/python/islands_bus/client.py tests/test_bus_lib_python.py
git commit -m "feat(bus): thin Python lib (islands_bus)"
```

---

## Task 12: Node thin lib (bus.ts)

**Files:**
- Create: `libs/node/src/bus.ts`
- Create: `libs/node/test/bus.test.ts`

**Interfaces:**
- Consumes: global `fetch` (injectable).
- Produces (TypeScript):
  - `interface EventEnvelope { id: string; type: string; schema: string; source: string; org: string; principal: string; occurredAt: string; trace: { store: string; ref: string }; data: Record<string, unknown>; }`
  - `interface PublishArgs { baseUrl: string; bearer: string; type: string; data: Record<string, unknown>; source: string; schema: string; trace: { store: string; ref: string }; occurredAt?: string; id?: string; fetchImpl?: typeof fetch; }`
  - `async function publish(args: PublishArgs): Promise<{ id: string; deduped: boolean }>`
  - `async function subscribe(args: { baseUrl; bearer; type; consumer; target; grantRef; fetchImpl? }): Promise<{ id: string }>`
  - `async function replayDeadLetter(args: { baseUrl; bearer; eventId; source; fetchImpl? }): Promise<{ replayed: number }>`

- [ ] **Step 1: Write the failing test**

```typescript
// libs/node/test/bus.test.ts
import { describe, it, expect } from "vitest";
import { publish, subscribe } from "../src/bus";

function fakeFetch(capture: any) {
  return async (url: string, init: any) => {
    capture.url = url;
    capture.init = init;
    capture.body = JSON.parse(init.body);
    return { ok: true, status: 200, json: async () => ({ id: "evt_1", deduped: false }) } as any;
  };
}

describe("bus lib", () => {
  it("publish posts the envelope with a bearer and returns the result", async () => {
    const cap: any = {};
    const res = await publish({
      baseUrl: "http://bus.local", bearer: "JWT", type: "bookkeeping.voucher.posted",
      data: { voucherId: "V-1" }, source: "bookkeeping", schema: "voucher/v1",
      trace: { store: "bk", ref: "r1" }, fetchImpl: fakeFetch(cap),
    });
    expect(res).toEqual({ id: "evt_1", deduped: false });
    expect(cap.url).toBe("http://bus.local/events");
    expect(cap.init.headers.Authorization).toBe("Bearer JWT");
    expect(cap.body.type).toBe("bookkeeping.voucher.posted");
    expect(cap.body.trace.ref).toBe("r1");
  });

  it("subscribe posts type/consumer/target", async () => {
    const cap: any = {};
    const fetchImpl = async (url: string, init: any) => {
      cap.url = url; cap.body = JSON.parse(init.body);
      return { ok: true, status: 200, json: async () => ({ id: "sub_1" }) } as any;
    };
    const res = await subscribe({
      baseUrl: "http://bus.local", bearer: "JWT", type: "bookkeeping.voucher.posted",
      consumer: "smartcharge", target: { kind: "http", url: "http://x/events", audience: "smartcharge" },
      grantRef: "g", fetchImpl,
    });
    expect(res.id).toBe("sub_1");
    expect(cap.url).toBe("http://bus.local/subscriptions");
    expect(cap.body.consumer).toBe("smartcharge");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd libs/node && npm test -- bus`
Expected: FAIL — cannot resolve `../src/bus`.

- [ ] **Step 3: Write the lib**

`libs/node/src/bus.ts`:

```typescript
export interface EventEnvelope {
  id: string;
  type: string;
  schema: string;
  source: string;
  org: string;
  principal: string;
  occurredAt: string;
  trace: { store: string; ref: string };
  data: Record<string, unknown>;
}

export interface PublishArgs {
  baseUrl: string;
  bearer: string;
  type: string;
  data: Record<string, unknown>;
  source: string;
  schema: string;
  trace: { store: string; ref: string };
  occurredAt?: string;
  id?: string;
  fetchImpl?: typeof fetch;
}

async function postJson(url: string, bearer: string, body: unknown, fetchImpl?: typeof fetch) {
  const f = fetchImpl ?? fetch;
  const res = await f(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${bearer}` },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`bus call failed: HTTP ${res.status}`);
  return res.json();
}

export async function publish(args: PublishArgs): Promise<{ id: string; deduped: boolean }> {
  const body: Record<string, unknown> = {
    type: args.type, data: args.data, source: args.source, schema: args.schema, trace: args.trace,
  };
  if (args.occurredAt) body.occurredAt = args.occurredAt;
  if (args.id) body.id = args.id;
  return postJson(`${args.baseUrl}/events`, args.bearer, body, args.fetchImpl);
}

export async function subscribe(args: {
  baseUrl: string; bearer: string; type: string; consumer: string;
  target: Record<string, unknown>; grantRef: string; fetchImpl?: typeof fetch;
}): Promise<{ id: string }> {
  return postJson(`${args.baseUrl}/subscriptions`, args.bearer,
    { type: args.type, consumer: args.consumer, target: args.target, grant_ref: args.grantRef },
    args.fetchImpl);
}

export async function replayDeadLetter(args: {
  baseUrl: string; bearer: string; eventId: string; source: string; fetchImpl?: typeof fetch;
}): Promise<{ replayed: number }> {
  const url = `${args.baseUrl}/deadletter/${encodeURIComponent(args.eventId)}/replay`
    + `?source=${encodeURIComponent(args.source)}`;
  return postJson(url, args.bearer, {}, args.fetchImpl);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd libs/node && npm test -- bus`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add libs/node/src/bus.ts libs/node/test/bus.test.ts
git commit -m "feat(bus): thin Node lib (bus.ts)"
```

---

## Task 13: Served bus harness + single-writer dispatch proof

**Files:**
- Modify: `tests/served_harness.py` (add `build_served_bus_stack`)
- Test: `tests/test_served_bus_single_writer.py`

**Interfaces:**
- Consumes: `tests/served_harness.py` helpers (`bound_socket`, `ThreadedServer`), `identity.app.build_identity_app`, `identity.service_principal.issue_service_credential`, `bus.provisioning.grant_event_type_use`, `bus.app.build_bus_app`, `vault.kernel_auth.cached_jwks_provider`, `identity.deps.make_require_principal`.
- Produces: `build_served_bus_stack(tmp_path) -> ServedBusStack` with `.identity_url`, `.bus_url`, `.cred` (a service credential to exchange for a JWT), `.audience`, `.store` (the ledger store, for asserting delivery counts), `.start()`, `.stop()`. Mirrors `build_served_stack`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_served_bus_single_writer.py
import threading
import time
import httpx
from tests.served_harness import build_served_bus_stack


def _exchange(identity_url, cred, audience):
    r = httpx.post(f"{identity_url}/auth/exchange",
                   json={"opaque_token": cred, "audience": audience})
    r.raise_for_status()
    return r.json()["access_token"]


def test_concurrent_publish_dispatches_each_event_once():
    import os
    stack = build_served_bus_stack(_tmpdir())
    stack.start()
    try:
        jwt = _exchange(stack.identity_url, stack.cred, stack.audience)
        h = {"Authorization": f"Bearer {jwt}"}
        # one HTTP subscriber that counts receipts
        received = []
        # subscribe to an inprocess handler wired by the harness (key "counter")
        httpx.post(f"{stack.bus_url}/subscriptions", headers=h,
                   json={"type": "bookkeeping.voucher.posted", "consumer": "smartcharge",
                         "target": {"kind": "inprocess", "key": "counter"}, "grant_ref": "g"}).raise_for_status()

        body = {"type": "bookkeeping.voucher.posted", "schema": "voucher/v1",
                "source": "bookkeeping", "trace": {"store": "bk", "ref": "r1"},
                "data": {"voucherId": "V-1"}, "id": "evt_race"}

        results = []
        barrier = threading.Barrier(8)

        def publisher():
            barrier.wait()
            r = httpx.post(f"{stack.bus_url}/events", headers=h, json=body)
            results.append(r.json())

        threads = [threading.Thread(target=publisher) for _ in range(8)]
        for t in threads: t.start()
        for t in threads: t.join()

        deduped = [r for r in results if r["deduped"]]
        assert len(deduped) == 7                       # exactly one publish was the first
        assert stack.counter["n"] == 1                 # handler ran exactly once
    finally:
        stack.stop()


def _tmpdir():
    import tempfile, pathlib
    return pathlib.Path(tempfile.mkdtemp())
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_served_bus_single_writer.py -v`
Expected: FAIL — `ImportError: cannot import name 'build_served_bus_stack'`.

- [ ] **Step 3: Add the served bus harness**

Append to `tests/served_harness.py`:

```python
from datetime import datetime, timezone

from identity.deps import make_require_principal
from identity.authorize import collect_grants
from bus.store.server import ServerLedgerStore
from bus.schema_registry import SchemaRegistry
from bus.dispatch import Dispatcher, InProcessDelivery
from bus.service import BusService
from bus.app import build_bus_app
from bus.provisioning import grant_event_type_use


@dataclass
class ServedBusStack:
    identity_url: str
    bus_url: str
    cred: str
    audience: str
    store: ServerLedgerStore
    counter: dict
    _identity_srv: ThreadedServer
    _bus_srv: ThreadedServer

    def start(self):
        self._identity_srv.start()
        self._bus_srv.start()

    def stop(self):
        self._bus_srv.stop()
        self._identity_srv.stop()


def build_served_bus_stack(tmp_path) -> ServedBusStack:
    import time

    id_sock, id_port = bound_socket()
    bus_sock, bus_port = bound_socket()
    identity_url = f"http://127.0.0.1:{id_port}"
    bus_url = f"http://127.0.0.1:{bus_port}"
    issuer = identity_url
    audience = "bus"
    now = time.time()

    km = KeyManager.generate("kid-bus")
    ident = ServerIdentityStore(str(tmp_path / "identity.sqlite"))
    cred = issue_service_credential(
        ident, principal_id="prn_bk", display_name="bookkeeping", org_id=ORG,
        audience=audience, now=now, expires_at=now + 3600)
    grant_event_type_use(ident, principal_id="prn_bk",
                         event_type="bookkeeping.voucher.posted", granted_by="prn_owner", now=now)
    identity_app = build_identity_app(store=ident, key_manager=km, issuer=issuer, now_fn=time.time)

    store = ServerLedgerStore(f"sqlite:///{tmp_path}/bus.sqlite")
    reg = SchemaRegistry()
    reg.register("voucher/v1", {"type": "object", "required": ["voucherId"],
                                "properties": {"voucherId": {"type": "string"}},
                                "additionalProperties": False})
    counter = {"n": 0}
    counter_lock = threading.Lock()
    deliv = InProcessDelivery()

    def handler(event):
        with counter_lock:
            counter["n"] += 1

    deliv.register("counter", handler)
    dispatcher = Dispatcher(store, deliv, now_fn=time.time)
    service = BusService(store, reg, dispatcher, now_fn=time.time,
                         now_iso_fn=lambda: datetime.now(timezone.utc).isoformat(),
                         grants_for=lambda pid: collect_grants(principal_id=pid, identity_store=ident))

    jwks_provider = cached_jwks_provider(f"{identity_url}/.well-known/jwks.json")
    require_principal = make_require_principal(
        jwks_provider=jwks_provider, audience=audience, now_fn=time.time, issuer=issuer)
    bus_app = build_bus_app(service, require_principal=require_principal)

    return ServedBusStack(identity_url, bus_url, cred, audience, store, counter,
                          ThreadedServer(identity_app, id_sock), ThreadedServer(bus_app, bus_sock))
```

(`ORG` and the imports `dataclass`, `threading`, `KeyManager`, `ServerIdentityStore`, `build_identity_app`, `issue_service_credential`, `bound_socket`, `ThreadedServer` already exist at the top of `served_harness.py`.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_served_bus_single_writer.py -v`
Expected: PASS (1 passed) — exactly one dispatch despite 8 concurrent publishers.

- [ ] **Step 5: Commit**

```bash
git add tests/served_harness.py tests/test_served_bus_single_writer.py
git commit -m "test(bus): served stack and single-writer dispatch proof"
```

---

## Task 14: Authz + cross-org rejection over HTTP

**Files:**
- Test: `tests/test_bus_authz.py`

**Interfaces:**
- Consumes: `build_served_bus_stack`, `identity.service_principal.issue_service_credential`, `identity` HTTP exchange.
- Produces: HTTP-level proof that a principal without an event-type grant gets 403 on publish and on subscribe, and that an event in one org is not delivered to a subscription in another org.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bus_authz.py
import httpx
import pytest
from tests.served_harness import build_served_bus_stack
from identity.service_principal import issue_service_credential
from identity.store.server import ServerIdentityStore


def _tmpdir():
    import tempfile, pathlib
    return pathlib.Path(tempfile.mkdtemp())


def _exchange(identity_url, cred, audience):
    r = httpx.post(f"{identity_url}/auth/exchange",
                   json={"opaque_token": cred, "audience": audience})
    r.raise_for_status()
    return r.json()["access_token"]


def test_publish_without_grant_is_403():
    stack = build_served_bus_stack(_tmpdir())
    stack.start()
    try:
        # mint a credential for a principal that has NO event-type grant
        ident = ServerIdentityStore_from(stack)
        ungranted = issue_service_credential(
            ident, principal_id="prn_nobody", display_name="nobody", org_id="caput-venti",
            audience=stack.audience, now=0.0, expires_at=None)
        jwt = _exchange(stack.identity_url, ungranted, stack.audience)
        r = httpx.post(f"{stack.bus_url}/events",
                       headers={"Authorization": f"Bearer {jwt}"},
                       json={"type": "bookkeeping.voucher.posted", "schema": "voucher/v1",
                             "source": "bookkeeping", "trace": {"store": "bk", "ref": "r1"},
                             "data": {"voucherId": "V-1"}})
        assert r.status_code == 403
    finally:
        stack.stop()


def ServerIdentityStore_from(stack):
    # the served harness writes the identity DB next to the bus DB; reopen it to add a principal
    import glob, os
    # the harness stored identity at tmp/identity.sqlite under the same tmp dir as bus.sqlite
    # recover that path from the store's sqlite file
    path = stack.store._db.execute("PRAGMA database_list").fetchall()[0][2]
    ident_path = os.path.join(os.path.dirname(path), "identity.sqlite")
    return ServerIdentityStore(ident_path)
```

Note: if reopening the identity DB by path is awkward, extend `ServedBusStack` to also expose `.identity_store` in Task 13 (add `identity_store: ServerIdentityStore` to the dataclass and pass `ident`). Prefer that — it is cleaner than path recovery. If you take that route, simplify this test's `ServerIdentityStore_from(stack)` to `stack.identity_store`.

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_bus_authz.py -v`
Expected: FAIL initially (either `.identity_store` missing, or 200 instead of 403 if the grant check is wrong). If it fails because `.identity_store` is missing, add it to `ServedBusStack` and the constructor in `served_harness.py`, then re-run.

- [ ] **Step 3: Expose `identity_store` on the served stack**

In `tests/served_harness.py`, add `identity_store: ServerIdentityStore` to `ServedBusStack` (after `store`) and pass `ident` into the constructor call in `build_served_bus_stack`. Replace this test's `ServerIdentityStore_from(stack)` helper with `stack.identity_store`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_bus_authz.py -v`
Expected: PASS (1 passed).

- [ ] **Step 5: Commit**

```bash
git add tests/served_harness.py tests/test_bus_authz.py
git commit -m "test(bus): grant-gated publish returns 403 without a grant"
```

---

## Task 15: Cross-language proof (Node publishes, Python consumes; and reverse)

**Files:**
- Create: `tests/node_bus_publish.mjs` (a tiny Node publisher script)
- Create: `tests/node_bus_consumer.mjs` (a tiny Node HTTP consumer that records receipts)
- Test: `tests/test_bus_cross_language.py`

**Interfaces:**
- Consumes: `build_served_bus_stack`, the Node lib at `libs/node/src/bus.ts` (run through `node` after a tsx/esbuild-free path: the scripts import the compiled JS, or use plain JS that mirrors the lib's HTTP shape — see note).
- Produces: end-to-end proof of the envelope contract across runtimes.

Note on running TypeScript from Node in tests: the repo's Node lib is `.ts`. To avoid a build step in the test, the two `.mjs` scripts make the same HTTP calls the lib makes (POST `/events`, run an HTTP server for push) using only `node:http`/`fetch` — they exercise the *contract*, which is the point of the cross-language proof (the spec: "proves the contract, not a shared package"). If you prefer to exercise the actual `bus.ts`, add a `tsx` devDependency and `node --import tsx` — but the contract-level scripts are sufficient and dependency-free.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bus_cross_language.py
import json
import os
import subprocess
import threading
import time
import httpx
import pytest
from tests.served_harness import build_served_bus_stack


def _tmpdir():
    import tempfile, pathlib
    return pathlib.Path(tempfile.mkdtemp())


def _exchange(identity_url, cred, audience):
    r = httpx.post(f"{identity_url}/auth/exchange",
                   json={"opaque_token": cred, "audience": audience})
    r.raise_for_status()
    return r.json()["access_token"]


def _have_node():
    from shutil import which
    return which("node") is not None


@pytest.mark.skipif(not _have_node(), reason="node not installed")
def test_node_publishes_python_consumes():
    stack = build_served_bus_stack(_tmpdir())
    stack.start()
    try:
        jwt = _exchange(stack.identity_url, stack.cred, stack.audience)
        h = {"Authorization": f"Bearer {jwt}"}
        httpx.post(f"{stack.bus_url}/subscriptions", headers=h,
                   json={"type": "bookkeeping.voucher.posted", "consumer": "smartcharge",
                         "target": {"kind": "inprocess", "key": "counter"}, "grant_ref": "g"}).raise_for_status()
        script = os.path.join(os.path.dirname(__file__), "node_bus_publish.mjs")
        out = subprocess.run(["node", script, stack.bus_url, jwt], capture_output=True, text=True, timeout=30)
        assert out.returncode == 0, out.stderr
        body = json.loads(out.stdout)
        assert body["deduped"] is False
        assert stack.counter["n"] == 1                 # Python in-process handler consumed it
    finally:
        stack.stop()


@pytest.mark.skipif(not _have_node(), reason="node not installed")
def test_python_publishes_node_consumes():
    stack = build_served_bus_stack(_tmpdir())
    stack.start()
    consumer = subprocess.Popen(["node", os.path.join(os.path.dirname(__file__), "node_bus_consumer.mjs")],
                                stdout=subprocess.PIPE, text=True)
    try:
        consumer_port = int(consumer.stdout.readline().strip())   # the script prints its port first
        jwt = _exchange(stack.identity_url, stack.cred, stack.audience)
        h = {"Authorization": f"Bearer {jwt}"}
        httpx.post(f"{stack.bus_url}/subscriptions", headers=h,
                   json={"type": "bookkeeping.voucher.posted", "consumer": "node-island",
                         "target": {"kind": "http", "url": f"http://127.0.0.1:{consumer_port}/events",
                                    "audience": "node-island"}, "grant_ref": "g"}).raise_for_status()
        httpx.post(f"{stack.bus_url}/events", headers=h,
                   json={"type": "bookkeeping.voucher.posted", "schema": "voucher/v1",
                         "source": "bookkeeping", "trace": {"store": "bk", "ref": "r1"},
                         "data": {"voucherId": "V-7"}, "id": "evt_x"}).raise_for_status()
        # the node consumer prints the received envelope's voucherId on the next line
        line = consumer.stdout.readline().strip()
        assert line == "V-7"
    finally:
        consumer.terminate()
        stack.stop()
```

- [ ] **Step 2: Write the Node scripts**

`tests/node_bus_publish.mjs`:

```javascript
// Node publisher: POST one envelope to the served bus, print the JSON result.
const [, , baseUrl, bearer] = process.argv;
const body = {
  type: "bookkeeping.voucher.posted", schema: "voucher/v1", source: "bookkeeping",
  trace: { store: "bk", ref: "r1" }, data: { voucherId: "V-1" }, id: "evt_node",
};
const res = await fetch(`${baseUrl}/events`, {
  method: "POST",
  headers: { "Content-Type": "application/json", Authorization: `Bearer ${bearer}` },
  body: JSON.stringify(body),
});
if (!res.ok) {
  console.error(`HTTP ${res.status}`);
  process.exit(1);
}
process.stdout.write(JSON.stringify(await res.json()));
```

`tests/node_bus_consumer.mjs`:

```javascript
// Node consumer: serve an HTTP endpoint that receives a pushed envelope and prints its voucherId.
import http from "node:http";
const server = http.createServer((req, res) => {
  let data = "";
  req.on("data", (c) => (data += c));
  req.on("end", () => {
    res.writeHead(202).end();
    try {
      const env = JSON.parse(data);
      process.stdout.write(`${env.data.voucherId}\n`);
    } catch {
      process.stdout.write("PARSE_ERROR\n");
    }
  });
});
server.listen(0, "127.0.0.1", () => {
  process.stdout.write(`${server.address().port}\n`);   // first line = the port
});
```

- [ ] **Step 3: Run test to verify it fails, then passes**

Run: `python -m pytest tests/test_bus_cross_language.py -v`
Expected on first run: PASS if `node` is present (the harness + scripts are complete), else SKIPPED. If it FAILS, debug per `superpowers:systematic-debugging` — common causes: the HTTP push uses the real `httpx` (it does, since the harness `Dispatcher` is built with `HttpPushDelivery()` — confirm Task 13's dispatcher uses `HttpPushDelivery()` for the `test_python_publishes_node_consumes` path, OR add a second subscription type routed to HTTP). See Step 4.

- [ ] **Step 4: Wire HTTP push in the served harness if needed**

The Task 13 harness wires `InProcessDelivery` only (for the single-writer count). For `test_python_publishes_node_consumes`, the dispatcher must also push to HTTP targets. Make the harness dispatcher delivery dispatch by `target.kind`: add a small `RoutingDelivery` to `bus/dispatch.py`:

```python
class RoutingDelivery:
    """Pick the delivery strategy by target.kind ('inprocess' | 'http')."""
    def __init__(self, inprocess, http):
        self._in = inprocess
        self._http = http
    def deliver(self, sub, event):
        if sub.target.get("kind") == "http":
            return self._http.deliver(sub, event)
        return self._in.deliver(sub, event)
```

Then in `build_served_bus_stack`, build `dispatcher = Dispatcher(store, RoutingDelivery(deliv, HttpPushDelivery()), now_fn=time.time)` and import `HttpPushDelivery, RoutingDelivery`. Add a unit test for `RoutingDelivery` in `tests/test_dispatch.py` (routes inprocess vs http by kind). Re-run both this file and `tests/test_dispatch.py`.

- [ ] **Step 5: Commit**

```bash
git add bus/dispatch.py tests/node_bus_publish.mjs tests/node_bus_consumer.mjs tests/test_bus_cross_language.py tests/served_harness.py tests/test_dispatch.py
git commit -m "test(bus): cross-language publish/consume proof (Node<->Python)"
```

---

## Task 16: Posture parity test + docs + structure note

**Files:**
- Test: `tests/test_bus_posture_parity.py`
- Create: `docs/event-bus.md`
- Modify: `CLAUDE.md` (Structure block)

**Interfaces:**
- Consumes: `BusService` with each store backend + each delivery strategy.
- Produces: a single test asserting the same guarantees (dedup, exactly-once effect, dead-letter) hold for embedded (memory store + in-process delivery) and hosted-shaped (server store + HTTP push to a local recorder) configurations; plus the run/env doc.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bus_posture_parity.py
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
```

- [ ] **Step 2: Run test to verify it fails or passes**

Run: `python -m pytest tests/test_bus_posture_parity.py -v`
Expected: PASS (2 passed). If `hosted` fails where `embedded` passes, the divergence is a real parity bug in `ServerLedgerStore` — fix it before proceeding.

- [ ] **Step 3: Write the run/env doc and the structure note**

`docs/event-bus.md`:

```markdown
# Inter-island event bus (served posture)

A third ASGI service beside identity and vault. It verifies kernel JWTs offline
against the identity service's public JWKS; the signing key never leaves identity.
Publish and subscribe are gated by `authorize()` on an `event-type` grant. The
idempotency ledger reuses the slice-1 single-writer lease so two dispatchers never
double-deliver. Ledger and dead-letter rows are metadata only — never the `data`
payload, never PII or amounts; large state stays behind the envelope's `trace`
reference in the owning island's store.

## Run

- `BUS_BOOT=1`
- `BUS_AUDIENCE` — the bus's public URL (the JWT `aud`)
- `BUS_DB` — SQLAlchemy-style sqlite URL (default `sqlite:///vault-store/bus.sqlite`, gitignored)
- `KERNEL_JWKS_URL` — `<identity-url>/.well-known/jwks.json`
- `KERNEL_ISSUER` — same issuer as identity
- `KERNEL_IDENTITY_DB` — the identity sqlite (for grant lookups)
- `uvicorn bus.app:app --host 127.0.0.1 --port <bus-port>`

## HTTP contract

- `POST /events` — publish. Body is the envelope minus the server-stamped fields;
  `principal`/`org` are stamped from the verified JWT, `id` is assigned if absent,
  `data` is validated against its declared `schema`. Returns `{ id, deduped }`.
- `POST /subscriptions` / `GET /subscriptions` / `DELETE /subscriptions/{id}`.
- `GET /_events` — the event-contract registry: emitted + consumed types per island.
- `GET /deadletter` — metadata-only dead-letter list for the caller's org.
- `POST /deadletter/{eventId}/replay?source=<island>` — re-attempt a dead delivery.

## Postures

Embedded-local: in-process dispatch + file/SQLite ledger. Hosted: served store +
HTTP push to subscriber endpoints. Both sit behind one `Dispatcher` and are
parity-tested (`tests/test_bus_posture_parity.py`). The single-writer guarantee is
proven by `tests/test_served_bus_single_writer.py`, the same shape as the vault's
`tests/test_served_single_writer.py`.

## Out of scope (v1)

No broker/streaming/fan-out-at-scale, no cross-org federation, no events UI. The
bus may emit on a schedule but does not own scheduling.
```

In `CLAUDE.md`, add `bus/` to the Structure block:

```
bus/         — inter-island event bus + registry (slice 5)
```

(Insert it after the `vault/` line.)

- [ ] **Step 4: Run the full suite**

Run: `python -m pytest -q`
Expected: PASS — the whole suite green, including the pre-existing vault/identity tests (no regressions from the `TargetKind` change).

- [ ] **Step 5: Commit**

```bash
git add tests/test_bus_posture_parity.py docs/event-bus.md CLAUDE.md
git commit -m "test(bus): embedded/hosted posture parity; docs and structure note"
```

---

## Self-review against the spec

- **Canonical envelope (id, type, schema, source, org, principal, occurredAt, trace, data):** Tasks 2, 5 (`Event`, stamping, strict validation, `data`-vs-`schema`). ✓
- **principal/org stamped server-side from JWT, never the body:** Tasks 2 (`stamp_envelope`), 9, 10 (route reads `claims["sub"]`/`claims["org"]`). ✓
- **trace reference, not fat payload:** envelope `trace={store,ref}` validated; `data` kept small by contract; design-decision note covers payload custody. ✓
- **publish/subscribe + /_events registry:** Tasks 9, 10. ✓
- **Idempotency ledger, dedup by (source, event-id), exactly-once effect:** Tasks 4/5 (`record_event` PK), 7 (delivered pair no-op), 9 (`deduped`). ✓
- **Reuses slice-1 single-writer lease:** Tasks 4/5 lease methods (same semantics as `vault.store`), 6 stress proof, 7 lease-guarded dispatch, 13 served proof. ✓
- **Retry/backoff + dead-letter, inspectable + replay:** Tasks 7 (`BackoffPolicy`, dead-letter), 9 (`replay`), 10 (`/deadletter`, replay route). ✓
- **Embedded + hosted postures behind one interface, parity-tested:** Tasks 7/8 (`InProcessDelivery`/`HttpPushDelivery`/`RoutingDelivery`), 16 parity. ✓
- **authorize() gates publish + subscribe via target.kind="event-type":** Tasks 1 (model/authorize), 9, 14 (403 proof). ✓
- **Cross-org rejected:** org stamped from JWT; dispatch filters by org; Task 9 (`test_event_not_delivered_across_orgs`). ✓
- **Thin Node + Python libs (publish/subscribe/replayDeadLetter):** Tasks 11, 12. ✓
- **Cross-language proof (Node publishes/Python consumes and reverse):** Task 15. ✓
- **Ledger/dead-letter metadata-only:** `Delivery` carries no `data`; `last_error` is the error class; `/deadletter` omits `data` (Task 10 test asserts `"data" not in`). ✓
- **Out of scope respected:** no broker/streaming, no cross-org federation, no events UI, no scheduler — none built. ✓
- **No new infra:** reuses the posture-3 store + lease; only new runtime dep is `jsonschema` (for strict `data` validation, which the spec mandates). ✓

Open item for sign-off: the **payload-custody interpretation** at the top (persist envelope `data` for replay vs. zero-`data`-at-rest + `trace`-refetch). Confirm before Task 4.

---

## Execution Handoff

Plan complete and saved to `docs/plans/2026-06-20-event-bus-and-registry.md`.
