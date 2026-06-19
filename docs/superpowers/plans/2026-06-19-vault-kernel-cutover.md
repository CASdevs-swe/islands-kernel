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

- [ ] `identity/service_principal.py`: `issue_service_credential(store, *, principal_id,
      display_name, org_id, audience, now, scope="mcp", expires_at=None) -> str` creates a
      `Principal(type="service")` + active `Membership` + an `McpToken` (stored hashed) and
      returns the raw `mcp_` credential. `grant_connection_use(store, *, principal_id,
      connection_id, granted_by, now) -> Grant` adds a unified `use` grant on
      `connection:<id>` (the "share only what they need" unit).
- [ ] `libs/python/islands_vault/client.py`: `KernelAuthTransport` — exchanges the service
      credential at the identity app's `/auth/exchange` for a 5-min JWT (cached until within
      skew of expiry, injected clock), then POSTs the vault access-token endpoint with
      `Authorization: Bearer <jwt>`.
- [ ] Prove end-to-end (in-process, stubbed provider): a service principal exchanges its
      credential → a `typ="service"` 5-min JWT → fetches the Fortnox access token through a
      vault app built in authed mode. (This is the new mechanism working before the prod flag
      is touched.)
- [ ] Commit.

## Task C2 — tighten the endpoint behind VAULT_REQUIRE_KERNEL (authorize() replaces require_access)

- [ ] `vault/access.py`: `get_access_token(key, principal_id, island, *, grant_check=None)`
      — when `grant_check` is provided, call it (raises `PermissionError` on deny) instead of
      `require_access`. `grant_check=None` keeps the slice-1 behavior byte-identical.
- [ ] `vault/kernel_auth.py`: `make_kernel_auth(*, jwks_provider, audience, issuer, now_fn,
      identity_store, vault_store) -> (require_principal, authorizer)` where `authorizer`
      runs `authorize(collect_grants(...), target=connection:<id>, access="use",
      request_org=org)`.
- [ ] `vault/app.py`: `build_app(service, *, require_principal=None, authorizer=None)` — the
      authed route resolves principal/org/island from the verified claims and passes a
      `grant_check` built from `authorizer` into `get_access_token`. The stub route is
      unchanged. `_build_from_env` reads `VAULT_REQUIRE_KERNEL`: unset → stub (unchanged);
      set → assemble `make_kernel_auth` from env (`KERNEL_JWKS_URL` public fetch,
      `KERNEL_ISSUER`, `VAULT_AUDIENCE`, the identity store) and build the authed app.
- [ ] Prove: flag-off `build_app(service)` path unchanged (all slice-1 + Task-12 tests green);
      flag-on authed path runs `authorize()` (a granted principal passes; `require_access` is
      not consulted on this path).
- [ ] Commit.

## Task C3 — end-to-end cutover proof (before + after + rejection)

- [ ] BEFORE baseline: the stub-mode vault still returns a token for the existing local caller
      (regression guard for the live path when the flag is off).
- [ ] AFTER: the same service principal (credential → JWT → `use` grant) fetches the Fortnox
      token through the flag-on authed vault.
- [ ] Rejection: a request with no Bearer → 401; a request with a valid kernel JWT for a
      principal with no grant on the connection → 403.
- [ ] Commit.

## Stop here (prod boundary)

Do NOT set `VAULT_REQUIRE_KERNEL=1` in prod. Report the diffs + what is proven so the flip
can be gated: issue bookkeeping its real service credential, run the local/staging
before+after with the flag on against the real Fortnox connection, then flip.
