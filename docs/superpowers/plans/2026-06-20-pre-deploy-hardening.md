# Pre-deploy Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Burn down the security-relevant and trivial-safe backlog items filed across slices 2/4/5 + the integration pass, before the VPS deploy — without changing intended slice behaviour.

**Architecture:** Five independent, TDD-driven fixes. The only one with real security value is the provisioning credential (non-expiring + fake `granted_by`); the rest are robustness and trivial cleanups. Each fix is one commit. The full suite (245 baseline) stays green throughout.

**Tech Stack:** Python 3.14, FastAPI, pytest, sqlite3. Runner: `.venv/bin/python -m pytest`.

## Global Constraints

- Branch: `main` only. Never create a branch. No `git push` without explicit OK.
- Quality + hardening only. Do NOT change intended slice behaviour or add features.
- Do NOT touch the items classified INTENTIONAL-LEAVE or DEFER (unlocked store reads, O(n) refresh scan, owner-grant revocability, envelope id scheme, sync access-token handlers, 401 detail echo).
- The sm-brf JWKS in-flight-dedup item is in a different repo — out of scope.
- No AI-sounding prose, no emojis, no personal names, no hardcoded local paths.
- Full suite must stay green (245 baseline) before and after every task.

---

### Task 1: Expiring, audited provisioning credential

**Files:**
- Modify: `scripts/kernel_provision.py`
- Test: `tests/test_kernel_provision.py`

**Interfaces:**
- Consumes: `issue_service_credential(store, *, ..., expires_at)` and `grant_connection_use(store, *, granted_by, ...)` / `grant_event_type_use(...)` — all already accept the params; only `provision()` hardcodes them.
- Produces: `provision(store, *, principal_id, org_id, connection_id, event_type, now, granted_by, expires_at) -> str`; CLI flags `--granted-by` (required), `--ttl-days` (default 90), `--expires-at` (optional epoch override).

- [ ] **Step 1: Write the failing tests** — assert `provision()` threads `granted_by` onto both grants and `expires_at` onto the MCP token; assert CLI default TTL ≈ now + 90d and that `--expires-at` overrides it.
- [ ] **Step 2: Run to verify they fail** (`TypeError`/assertion on the new kwargs).
- [ ] **Step 3: Implement** — add `granted_by` + `expires_at` params to `provision()`, pass through; in `main()` add `--granted-by` (required), `--ttl-days` (default 90), `--expires-at`; compute `expires_at = a.expires_at if a.expires_at is not None else now + a.ttl_days*86400`.
- [ ] **Step 4: Run the new tests + full suite — green.**
- [ ] **Step 5: Commit** (`harden: bound provisioning credential lifetime + real granted_by`).

### Task 2: Pydantic validation on identity POST bodies

**Files:**
- Modify: `identity/app.py`
- Test: `tests/test_identity_app_validation.py` (create)

**Interfaces:**
- Produces: request models for `/auth/exchange`, `/oauth/authorize`, `/oauth/token`. Missing required field → FastAPI 422 (idiomatic), not 500.

- [ ] **Step 1: Write failing tests** — POST each route with a missing required key, assert status 422 (currently 500).
- [ ] **Step 2: Run to verify they fail** (got 500).
- [ ] **Step 3: Implement** — define Pydantic `BaseModel`s with the required/optional fields per route, replace `body: dict = Body(...)` with the typed model, index attributes instead of keys. Preserve optional fields (`org_id`, `scope` default `"mcp"`, `grant_type`).
- [ ] **Step 4: Run new tests + full suite — green.**
- [ ] **Step 5: Commit** (`harden: validate identity request bodies (422 not 500)`).

### Task 3: Readable vault audit-aud coercion

**Files:**
- Modify: `vault/app.py` (the `island = island_aud if ... else (...)` nested ternary)

**Interfaces:** behavior-preserving; existing aud-coercion tests cover scalar + list branches.

- [ ] **Step 1: Confirm coverage** — run the existing aud-coercion test(s) green first.
- [ ] **Step 2: Refactor** the nested ternary to a small `if/else` (or helper) producing the same value.
- [ ] **Step 3: Run full suite — green (no test change needed).**
- [ ] **Step 4: Commit** (`cleanup: readable aud coercion in vault audit path`).

### Task 4: Remove unused test imports

**Files:**
- Modify: `tests/test_bookkeeping_verify_path.py` (drop `import pytest`), `tests/test_identity_server_boot.py` (drop `import tempfile`).

- [ ] **Step 1: Confirm each import is unused** (grep usage in-file).
- [ ] **Step 2: Remove.**
- [ ] **Step 3: Run full suite — green.**
- [ ] **Step 4: Commit** (`cleanup: drop unused test imports`).

### Task 5: access_token_hashes store parity test

**Files:**
- Test: add to the existing store-parity test module (test-only; no production change).

**Interfaces:** asserts InMemory and SQLite `ServerIdentityStore` return identical `access_token_hashes()` after the same put/rotate sequence.

- [ ] **Step 1: Write the parity test** — put two access tokens in each backend, assert `set(access_token_hashes())` matches expected; rotate one, assert both backends reflect the rotation identically.
- [ ] **Step 2: Run — green on first try (contract already holds); if it fails, that is a real defect, stop and report.**
- [ ] **Step 3: Run full suite — green.**
- [ ] **Step 4: Commit** (`test: access_token_hashes InMemory/SQLite parity`).

---

## Self-Review

- Coverage: every FIX-NOW item from the approved triage maps to a task (1=provision, 2=identity bodies, 3=vault ternary, 4=unused imports, 5=parity test). INTENTIONAL-LEAVE/DEFER items deliberately have no task.
- No placeholders: each task names exact files and the concrete change.
- Type consistency: `provision()` new params (`granted_by`, `expires_at`) match the already-existing kwargs on `issue_service_credential` / `grant_*`.
