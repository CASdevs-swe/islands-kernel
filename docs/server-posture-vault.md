# Server-posture vault + served kernel identity

Two ASGI services. The vault verifies kernel JWTs offline against the identity
service's public JWKS; the signing key never leaves the identity service.

## Run

Identity (signs tokens, publishes JWKS):
- `IDENTITY_BOOT=1`
- `KERNEL_SIGNING_SEED` — base64url Ed25519 32-byte seed. Crown jewel. Host secret store / KMS only; never committed, never logged.
- `KERNEL_ISSUER` — e.g. `https://id.<host>`
- `KERNEL_KID` — key id (default `kid-1`)
- `KERNEL_IDENTITY_DB` — sqlite path (default `vault-store/identity.sqlite`, gitignored)
- `uvicorn identity.app:app --host 127.0.0.1 --port <id-port>`

Vault (brokers Fortnox tokens, single writer):
- `VAULT_BOOT=1`, `VAULT_REQUIRE_KERNEL=1`, `VAULT_BACKEND=server`
- `VAULT_DB` — SQLAlchemy sqlite URL (default `sqlite:///vault-store/vault.sqlite`, gitignored)
- `VAULT_KEK` — base64 32-byte KEK. Crown jewel. Required when served (`VAULT_BACKEND=server` or `VAULT_REQUIRE_KERNEL=1`); no random fallback. Host secret store / KMS only.
- `KERNEL_JWKS_URL` — `<identity-url>/.well-known/jwks.json`
- `VAULT_AUDIENCE` — the vault's public URL (the JWT `aud`)
- A principal that also talks to the bus exchanges ONE token whose `aud` is the
  list of target service audiences (e.g. `["vault","bus"]`); the credential is
  issued unbound. See `docs/kernel-integration.md` for the combined model.
- `KERNEL_ISSUER` — same issuer as identity
- `KERNEL_IDENTITY_DB` — the identity sqlite (default `vault-store/identity.sqlite`, for grant lookups)
- `uvicorn vault.app:app --host 127.0.0.1 --port <vault-port>`

## Secret custody (KEK / signing seed)

`KERNEL_SIGNING_SEED` and `VAULT_KEK` are the only crown jewels. They are read
from the environment / host secret store (KMS seam) at boot and never written to
the repo, logs, or token files. `.gitignore` covers `*.age`, `*.key`, `*.ed25519`,
`.env`, `.env.*`, `*.sqlite`, `*.sqlite3`, `kernel-keys/`, `vault-store/`. Rotating
the KEK requires re-sealing envelopes (decrypt with the old KEK, re-seal with the
new); rotating the signing key uses publish-before-sign JWKS overlap (add the new
key to the document, let verifiers cache it, then sign with it).

## Single writer / multi-replica seam

Today the single served vault process is the single writer: HTTP is the fan-in and
the `ServerStore` SQLite DB-row lease + in-process mutex serialize refresh. Proven by
`tests/test_served_single_writer.py` (N client processes -> one refresh). For more than
one vault replica, swap the SQLite DB-row lease for a Postgres advisory lock behind the
same `Store` interface (`acquire_lease`/`release_lease`/`lease_held`) — the parity suite
(`tests/test_refresh_single_writer.py`) is the contract that swap must keep green. Not
built here.

Both access-token route handlers (`access_token_authed` and `access_token_stub` in
`vault/app.py`) are sync `def`, so Starlette runs them in its worker threadpool: concurrent
HTTP callers run in parallel and the refresh lease — not event-loop serialization — is what
enforces single-writer. This is intentional and applied to both handlers for one consistent
execution model; observable behaviour/output is unchanged. Leaving either handler `async def`
would block the event loop on the sync refresh and serialize all vault traffic, which silently
stops protecting single-writer the moment a second worker or replica is added.

## Gated live cutover — DO NOT run autonomously; run with the human present

Each step is a live-money action. Stop and confirm before each.

1. Bring up the served identity + vault locally. Issue bookkeeping a real service
   credential (`issue_service_credential`) and grant `use` on the real Fortnox
   connection (`grant_connection_use`). No prod flag flip yet.
   **STOP.**

2. Point bookkeeping-engine at the served vault with `BOOKKEEPING_VAULT_KERNEL_AUTH=1`
   + `VAULT_REQUIRE_KERNEL=1`. Prove a real Fortnox fetch works on -> off -> on. The
   in-process local path stays the fallback the whole time.
   **STOP.**

3. Remote: re-authorize Fortnox THROUGH the served connect flow (assume the May-10
   `tokens.age` is dead — confirm, do not import). Back it up first. Then flip
   research-engine's `RESEARCH_USE_VAULT` + the remote snapshot routine onto the served
   vault. The first refresh rotates + invalidates the on-disk token — the irreversible
   commit point. Show diffs and get explicit OK before it.
   **STOP.**
