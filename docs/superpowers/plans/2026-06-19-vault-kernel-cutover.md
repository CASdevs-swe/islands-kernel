# Vault kernel-auth cutover (slice-2 gated close-out) — plan

Goal: switch the live connector-vault access-token path off the slice-1 `require_access`
stub onto real kernel auth — a verified kernel JWT + an `authorize()` grant check — behind
the reversible `VAULT_REQUIRE_KERNEL` flag. Prove a bookkeeping service principal fetches a
Fortnox token through the vault both with the flag off (today's path) and with the flag on,
and that unauthenticated / unauthorized callers are rejected once tightened.

Implements the gated-cutover + prove-on-two-islands section of
`islands-platform/specs/2026-06-18-identity-sharing-design.md` and the access-token API of
`islands-platform/specs/2026-06-18-connector-vault-design.md`.

Constraints (binding): current branch only, never branch; no `git push`; the kernel private
signing key never leaves the kernel (the vault verifies against the public JWKS only);
no live `VAULT_REQUIRE_KERNEL` flip in prod from here — stop at the prod boundary and report;
no implicit clock; no AI-sounding prose, emojis, personal names, or hardcoded local paths.
TDD per task, commit per task.

Provider network I/O stays stubbed in every test (no real Fortnox call); the proof is the
identity→vault token flow with a stubbed provider, run in-process.

## Task C1 — service-principal credential + kernel-auth vault client; prove a fetch

- [x] `identity/service_principal.py`: `issue_service_credential(...)` + `grant_connection_use(...)`.
- [x] `libs/python/islands_vault/client.py`: `KernelAuthTransport` (exchange -> Bearer, cached JWT).
- [x] Prove end-to-end (in-process, stubbed provider): credential -> service-typ 5-min JWT -> Fortnox token.
- [x] Commit. (54b6592)

## Task C2 — tighten the endpoint behind VAULT_REQUIRE_KERNEL (authorize() replaces require_access)

- [x] `vault/access.py`: `get_access_token(..., *, grant_check=None)` — grant_check replaces require_access.
- [x] `vault/kernel_auth.py`: `make_kernel_auth(...)` + `cached_jwks_provider(...)`.
- [x] `vault/app.py`: `build_app(..., authorizer=None)` authed route grant_check; `_build_from_env` VAULT_REQUIRE_KERNEL.
- [x] Prove: flag-off path unchanged (148 green); flag-on authed path runs authorize().
- [x] Commit. (ee56f11)

## Task C3 — end-to-end cutover proof (before + after + rejection)

- [x] BEFORE baseline: stub-mode vault still returns a token for the existing local caller.
- [x] AFTER: the same service principal (credential -> JWT -> use grant) fetches through the authed vault.
- [x] Rejection: no Bearer -> 401; valid kernel JWT for an ungranted principal -> 403.
- [x] Commit. (77fbf4a) — full suite 152 passed.

## Stop here (prod boundary)

Do NOT set `VAULT_REQUIRE_KERNEL=1` in prod. Report the diffs + what is proven so the flip
can be gated: issue bookkeeping its real service credential, run the local/staging
before+after with the flag on against the real Fortnox connection, then flip.
