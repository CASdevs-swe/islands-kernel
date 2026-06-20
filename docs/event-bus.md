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
