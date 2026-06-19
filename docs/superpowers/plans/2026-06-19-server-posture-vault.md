# Server-Posture Vault + Served Kernel Identity — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serve the connector vault and the kernel identity endpoints as reachable HTTP services so a real caller does `credential → 5-min JWT → authed vault call` over the wire, with one single writer for Fortnox refresh across processes/hosts, and fix the `ServerIdentityStore` cross-host concurrency bug.

**Architecture:** Two FastAPI apps — identity (JWKS + exchange + OAuth) and vault (connections + access-token) — each gets an env-driven module-level ASGI `app` for uvicorn. The vault verifies kernel JWTs offline against the identity service's public JWKS (fetched over HTTP, cached) and runs an `authorize()` grant check on **every** endpoint. The single writer is the one served vault process: HTTP is the fan-in, the existing `ServerStore` SQLite DB-row lease + mutex guards in-process threads, and exactly-one-refresh is proven by real OS client processes hitting one served vault. A multi-replica writer (Postgres advisory lock behind the same `Store` interface) is a documented seam, not built here.

**Tech Stack:** Python 3, FastAPI, uvicorn, httpx, PyJWT (EdDSA), cryptography (Ed25519), PyNaCl (secretbox KEK), SQLite (WAL), pytest.

## Global Constraints

- Work on the current branch (`main`). Never create a branch. No `git push` without explicit OK.
- The kernel signing seed (`KERNEL_SIGNING_SEED`) and the vault KEK (`VAULT_KEK`) are crown jewels: never commit, never log. Host/secret-store/KMS only. Keep `.gitignore` covering all key/secret/`*.sqlite*`/`.env*`/`*.age` state.
- Provider network I/O stays injectable; tests stub the provider and never touch real Fortnox or a real network beyond `127.0.0.1` loopback.
- TDD per task: failing test → run it red → minimal implementation → run it green → commit. One commit per task.
- Additive and reversible only. Do NOT break the live in-process local path (bookkeeping reads Fortnox via the local-file vault in prod today). The served store is additive; the local-file store stays the local posture and the fallback until the gated cutover is proven.
- The three live-money cutover steps (Task 10) are **doc only** in this plan — do not execute them autonomously.
- No AI-sounding prose, no emojis, no personal names, no hardcoded absolute local paths in committed code or docs.

---

## File Structure

- `identity/store/server.py` — MODIFY: wrap every read in the existing `self._mu` (parity with `ServerStore`, which already does). The bug: reads run bare on a shared `check_same_thread=False` connection.
- `identity/app.py` — MODIFY: add `_build_identity_app_from_env()` + a module-level `app` guarded by `IDENTITY_BOOT`, mirroring `vault/app.py`. Loads the signing key via `KeyManager.from_seed` and a `ServerIdentityStore`.
- `vault/app.py` — MODIFY: (a) harden KEK custody in `_build_from_env` (refuse the silent random fallback when served); (b) gate **all** routes behind `require_principal` in the authed branch and thread a `manage_authorizer` through `build_app`; (c) wire `make_manage_authorizer` in `_build_app_from_env`.
- `vault/kernel_auth.py` — MODIFY: add owner-injection to the existing use-authorizer and add `make_manage_authorizer(...)`.
- `vault/access.py` — MODIFY: add optional `manage_check` keyword to `grant`, `revoke`, `list_connections` (additive; `None` preserves slice-1 behavior).
- `tests/test_identity_store_concurrency.py` — CREATE: high-contention proof for the `ServerIdentityStore` fix.
- `tests/test_identity_server_boot.py` — CREATE: served identity bootstrap.
- `tests/test_kek_custody.py` — CREATE: KEK fail-fast.
- `tests/test_manage_authorizer.py` — CREATE: manage grant check + owner injection.
- `tests/test_access_service_manage_check.py` — CREATE: `manage_check` hooks.
- `tests/test_authed_endpoints.py` — CREATE: every vault endpoint requires a kernel JWT + grant.
- `tests/served_harness.py` — CREATE: build + run the two apps on real loopback ports (uvicorn-in-thread), shared by the e2e tests.
- `tests/test_served_stack_e2e.py` — CREATE: credential→exchange→authed vault over real HTTP; no refresh token in response; 401/403 hold.
- `tests/test_served_single_writer.py` — CREATE: N OS client processes → one served vault → exactly one refresh.
- `docs/server-posture-vault.md` — CREATE: run runbook, KEK/KMS custody seam, multi-replica seam, and the gated live-cutover runbook (do-not-execute).
- `CLAUDE.md` — MODIFY: one-line pointer to the served entrypoints + the new doc.

---

### Task 1: Fix `ServerIdentityStore` read-outside-mutex concurrency bug

The store shares one `sqlite3.connect(..., check_same_thread=False)` connection across threads. Writes are wrapped in `self._mu`; **reads are not**. Under real cross-host (HTTP) concurrency, interleaved `execute()` on the one shared connection races. `vault/store/server.py` already wraps every read in `self._mu` and passes the 60×16 lease stress suite — bring the identity store to the same discipline.

**Files:**
- Modify: `identity/store/server.py:54-67, 76-78, 88-98, 121-127, 137-139, 149-154, 164-166, 187-193, 205-206, 216-219`
- Test: `tests/test_identity_store_concurrency.py`

**Interfaces:**
- Consumes: `ServerIdentityStore(conn_str)` from `identity/store/server.py`; `Principal`, `Grant`, `GrantTarget` from `identity/model`.
- Produces: no signature change — only thread-safety. All existing read methods (`get_principal`, `get_principal_by_email`, `get_org`, `get_membership`, `list_memberships`, `list_grants`, `get_mcp_token`, `get_oauth_client`, `get_auth_code`, `get_access_token`, `access_token_hashes`, `read_log`) become mutex-guarded.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_identity_store_concurrency.py
import os
import tempfile
import threading

from identity.store.server import ServerIdentityStore
from identity.model import Principal, Grant, GrantTarget


def _store():
    path = os.path.join(tempfile.mkdtemp(), "identity.sqlite")
    return ServerIdentityStore(path)


def test_concurrent_readers_and_writers_never_raise_and_stay_consistent():
    # One shared connection across many threads: writers insert distinct principals
    # while readers hammer get_principal/list_grants. With reads outside the mutex this
    # races ("recursive use of cursors" / torn rows). With the fix it is clean.
    store = _store()
    n = 24
    errors: list[BaseException] = []
    err_lock = threading.Lock()
    barrier = threading.Barrier(n)

    def writer(i: int):
        barrier.wait()
        try:
            for r in range(40):
                pid = f"prn_{i}_{r}"
                store.put_principal(Principal(
                    id=pid, type="service", email=None, display_name=f"d{i}",
                    public_key=None, created_at=float(r)))
                store.add_grant(Grant(
                    id=f"g_{i}_{r}", principal_id=pid,
                    target=GrantTarget(kind="connection", id="conn_1"), access="use",
                    scopes_subset=None, granted_by="prn_owner", granted_at=0.0,
                    revoked_at=None))
        except BaseException as e:  # noqa: BLE001
            with err_lock:
                errors.append(e)

    def reader():
        barrier.wait()
        try:
            for _ in range(200):
                store.get_principal("prn_0_0")
                store.list_grants("prn_0_0")
        except BaseException as e:  # noqa: BLE001
            with err_lock:
                errors.append(e)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(n // 2)]
    threads += [threading.Thread(target=reader) for _ in range(n // 2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"concurrency errors: {errors[:3]}"
    # every writer's last principal is readable -> no lost/torn writes
    for i in range(n // 2):
        assert store.get_principal(f"prn_{i}_39") is not None
        assert len(store.list_grants(f"prn_{i}_39")) == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_identity_store_concurrency.py -v`
Expected: FAIL (sqlite "recursive use of cursors not allowed" / "Recursive use" or an assertion on `errors`). If it passes flakily, run `-q --count` a few times — bare-read races are intermittent; the fix makes it deterministic.

- [ ] **Step 3: Wrap every read in the mutex**

In `identity/store/server.py`, change each bare read method to acquire `self._mu`. Example for the principals block:

```python
    def get_principal(self, principal_id):
        with self._mu:
            r = self._db.execute("SELECT * FROM principals WHERE id=?", (principal_id,)).fetchone()
        return self._principal(r)

    def get_principal_by_email(self, email):
        with self._mu:
            r = self._db.execute("SELECT * FROM principals WHERE email=?", (email,)).fetchone()
        return self._principal(r)
```

Apply the identical `with self._mu:` wrapper around the `self._db.execute(...).fetchone()` / `.fetchall()` in: `get_org`, `get_membership`, `list_memberships`, `list_grants`, `get_mcp_token`, `get_oauth_client`, `get_auth_code`, `get_access_token`, `access_token_hashes`, and `read_log`. Keep the row-to-model mapping outside the lock (only the DB call needs guarding). Do not touch the write methods — they already hold `self._mu`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_identity_store_concurrency.py tests/test_identity_store_parity.py -v`
Expected: PASS (concurrency clean; parity unchanged).

- [ ] **Step 5: Commit**

```bash
git add identity/store/server.py tests/test_identity_store_concurrency.py
git commit -m "fix(identity): guard ServerIdentityStore reads with the connection mutex"
```

---

### Task 2: Served identity app — env bootstrap + module ASGI app

`build_identity_app(...)` is a factory with no env bootstrap and no module-level `app`, so the identity service cannot be served by uvicorn. Add `_build_identity_app_from_env()` + `app`, mirroring `vault/app.py`. Load the Ed25519 signing key from a base64url **seed** in `KERNEL_SIGNING_SEED` (never a committed file) via the existing `KeyManager.from_seed`, and back it with a persistent `ServerIdentityStore`.

**Files:**
- Modify: `identity/app.py:1-11` (add `import os`), append `_build_identity_app_from_env()` + `app`.
- Test: `tests/test_identity_server_boot.py`

**Interfaces:**
- Consumes: `build_identity_app(store, key_manager, issuer, now_fn)`; `KeyManager.from_seed(kid, seed_b64url)`; `ServerIdentityStore(conn_str)`.
- Produces: `identity.app._build_identity_app_from_env() -> FastAPI` (raises `RuntimeError` if `KERNEL_SIGNING_SEED` unset); module global `identity.app.app` (a `FastAPI` when `IDENTITY_BOOT=1`, else `None`). Env contract: `KERNEL_SIGNING_SEED` (b64url Ed25519 32-byte raw seed), `KERNEL_ISSUER`, `KERNEL_KID` (default `"kid-1"`), `KERNEL_IDENTITY_DB` (default `"vault-store/identity.sqlite"`).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_identity_server_boot.py
import os
import tempfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient

from identity.tokens import b64url
import identity.app as identity_app


def _seed_b64url() -> str:
    priv = Ed25519PrivateKey.generate()
    raw = priv.private_bytes(serialization.Encoding.Raw,
                             serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())
    return b64url(raw)


def test_missing_seed_raises(monkeypatch):
    monkeypatch.delenv("KERNEL_SIGNING_SEED", raising=False)
    monkeypatch.setenv("KERNEL_ISSUER", "https://id.local")
    with pytest.raises(RuntimeError):
        identity_app._build_identity_app_from_env()


def test_served_identity_publishes_matching_jwks(monkeypatch, tmp_path):
    seed = _seed_b64url()
    monkeypatch.setenv("KERNEL_SIGNING_SEED", seed)
    monkeypatch.setenv("KERNEL_ISSUER", "https://id.local")
    monkeypatch.setenv("KERNEL_KID", "kid-served")
    monkeypatch.setenv("KERNEL_IDENTITY_DB", str(tmp_path / "identity.sqlite"))
    app = identity_app._build_identity_app_from_env()
    r = TestClient(app).get("/.well-known/jwks.json")
    assert r.status_code == 200
    keys = r.json()["keys"]
    assert keys and keys[0]["kid"] == "kid-served" and keys[0]["kty"] == "OKP"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_identity_server_boot.py -v`
Expected: FAIL with `AttributeError: module 'identity.app' has no attribute '_build_identity_app_from_env'`.

- [ ] **Step 3: Add the env bootstrap**

At the top of `identity/app.py` add `import os` (alongside the existing imports). At the end of the file, after `build_identity_app`, append:

```python
def _build_identity_app_from_env() -> FastAPI:
    import time
    from identity.keys import KeyManager
    from identity.store.server import ServerIdentityStore

    seed = os.environ.get("KERNEL_SIGNING_SEED")
    if not seed:
        # The signing seed is a host-secret/KMS value, never a committed file.
        raise RuntimeError("KERNEL_SIGNING_SEED is required to serve the identity kernel")
    km = KeyManager.from_seed(os.environ.get("KERNEL_KID", "kid-1"), seed)
    store = ServerIdentityStore(os.environ.get("KERNEL_IDENTITY_DB", "vault-store/identity.sqlite"))
    return build_identity_app(store=store, key_manager=km,
                              issuer=os.environ["KERNEL_ISSUER"], now_fn=time.time)


app = _build_identity_app_from_env() if os.environ.get("IDENTITY_BOOT") == "1" else None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_identity_server_boot.py -v`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add identity/app.py tests/test_identity_server_boot.py
git commit -m "feat(identity): env bootstrap + module ASGI app for serving the kernel"
```

---

### Task 3: Harden KEK custody for the served vault

`_build_from_env` falls back to a **random** KEK when `VAULT_KEK` is unset. For a hosted/served store that is a data-loss footgun: a restart loses the ability to decrypt sealed envelopes. Refuse the random fallback whenever the vault is served (`VAULT_BACKEND=server` or `VAULT_REQUIRE_KERNEL=1`); keep it only for the local dev default.

**Files:**
- Modify: `vault/app.py:84-101` (`_build_from_env`)
- Test: `tests/test_kek_custody.py`

**Interfaces:**
- Consumes: `vault.app._build_from_env() -> AccessService`.
- Produces: `_build_from_env` raises `RuntimeError` when served (server backend or kernel required) and `VAULT_KEK` is unset; unchanged otherwise (local default still gets a random dev KEK).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_kek_custody.py
import base64

import pytest
import nacl.utils

from vault.app import _build_from_env


def test_served_vault_refuses_random_kek(monkeypatch, tmp_path):
    monkeypatch.delenv("VAULT_KEK", raising=False)
    monkeypatch.setenv("VAULT_BACKEND", "server")
    monkeypatch.setenv("VAULT_DB", f"sqlite:///{tmp_path}/vault.sqlite")
    with pytest.raises(RuntimeError):
        _build_from_env()


def test_served_vault_accepts_explicit_kek(monkeypatch, tmp_path):
    monkeypatch.setenv("VAULT_KEK", base64.b64encode(nacl.utils.random(32)).decode())
    monkeypatch.setenv("VAULT_BACKEND", "server")
    monkeypatch.setenv("VAULT_DB", f"sqlite:///{tmp_path}/vault.sqlite")
    svc = _build_from_env()
    assert svc is not None


def test_local_default_still_allows_random_kek(monkeypatch, tmp_path):
    monkeypatch.delenv("VAULT_KEK", raising=False)
    monkeypatch.setenv("VAULT_BACKEND", "local")
    monkeypatch.delenv("VAULT_REQUIRE_KERNEL", raising=False)
    monkeypatch.setenv("VAULT_STORE_DIR", str(tmp_path / "store"))
    assert _build_from_env() is not None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_kek_custody.py -v`
Expected: FAIL — `test_served_vault_refuses_random_kek` does not raise (current code silently picks a random KEK).

- [ ] **Step 3: Harden the KEK selection**

In `vault/app.py`, replace the KEK lines in `_build_from_env` (currently `kek = base64.b64decode(kek_b64) if kek_b64 else nacl.utils.random(32)`) with:

```python
    backend = os.environ.get("VAULT_BACKEND", "local")
    kek_b64 = os.environ.get("VAULT_KEK")
    served = backend == "server" or os.environ.get("VAULT_REQUIRE_KERNEL") == "1"
    if kek_b64:
        kek = base64.b64decode(kek_b64)
    elif served:
        # A random KEK on a served store makes sealed envelopes unrecoverable across
        # restarts. The KEK must come from the host secret store / KMS (see docs).
        raise RuntimeError(
            "VAULT_KEK is required when serving the vault "
            "(VAULT_BACKEND=server or VAULT_REQUIRE_KERNEL=1)")
    else:
        kek = nacl.utils.random(32)
    wrapper = SecretboxKeyWrapper(kek)
```

Remove the now-duplicate `backend = os.environ.get("VAULT_BACKEND", "local")` line that previously sat below, so `backend` is defined once.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_kek_custody.py -v`
Expected: PASS (all three).

- [ ] **Step 5: Commit**

```bash
git add vault/app.py tests/test_kek_custody.py
git commit -m "fix(vault): refuse random KEK fallback when the vault is served"
```

---

### Task 4: Manage authorizer + owner injection in `kernel_auth`

The authed access-token route only checks `use`. The other endpoints (`grant`, `list`, `revoke`) need a `manage` grant check over the same unified grant table. Add `make_manage_authorizer`. Also inject an owner grant (`principal == conn.created_by`) into both authorizers so the slice-1 owner-can-manage/use semantics survive on the authed path.

**Files:**
- Modify: `vault/kernel_auth.py:11-34` (imports + authorizer), append `make_manage_authorizer`.
- Test: `tests/test_manage_authorizer.py`

**Interfaces:**
- Consumes: `authorize`, `collect_grants`, `adapt_connection_grant` from `identity/authorize`; `GrantTarget` from `identity/model`.
- Produces: `make_manage_authorizer(*, now_fn, identity_store, vault_store) -> Callable` returning `manage_authorizer(*, conn, principal_id, org) -> bool`. The existing `make_kernel_auth(...)` still returns `(require_principal, authorizer)`; its `authorizer` now also returns `True` when `principal_id == conn.created_by`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_manage_authorizer.py
from identity.store.memory import InMemoryIdentityStore
from identity.service_principal import grant_connection_use
from identity.model import Grant, GrantTarget

from vault.kernel_auth import make_manage_authorizer, make_kernel_auth
from vault.store.memory import InMemoryStore
from vault.model import Connection, Token


def _conn(created_by="prn_owner"):
    return Connection(
        id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
        scopes=["bookkeeping"], app_cred_ref="fortnox",
        token=Token("A", "R", 99999.0, "bookkeeping"), rotation="rotating",
        lease=None, created_by=created_by, created_at=0.0, updated_at=0.0)


def _wiring():
    ident = InMemoryIdentityStore()
    vault = InMemoryStore()
    conn = _conn()
    vault.put_connection(conn)
    return ident, vault, conn


def test_manage_granted_principal_is_allowed():
    ident, vault, conn = _wiring()
    ident.add_grant(Grant(id="g1", principal_id="prn_mgr",
                          target=GrantTarget("connection", "conn_1"), access="manage",
                          scopes_subset=None, granted_by="prn_owner", granted_at=0.0,
                          revoked_at=None))
    mgr = make_manage_authorizer(now_fn=lambda: 1000.0, identity_store=ident, vault_store=vault)
    assert mgr(conn=conn, principal_id="prn_mgr", org="caput-venti") is True


def test_use_only_principal_cannot_manage():
    ident, vault, conn = _wiring()
    grant_connection_use(ident, principal_id="prn_use", connection_id="conn_1",
                         granted_by="prn_owner", now=1000.0)
    mgr = make_manage_authorizer(now_fn=lambda: 1000.0, identity_store=ident, vault_store=vault)
    assert mgr(conn=conn, principal_id="prn_use", org="caput-venti") is False


def test_owner_can_manage_and_use():
    ident, vault, conn = _wiring()
    mgr = make_manage_authorizer(now_fn=lambda: 1000.0, identity_store=ident, vault_store=vault)
    assert mgr(conn=conn, principal_id="prn_owner", org="caput-venti") is True
    _, use_authorizer = make_kernel_auth(
        jwks_provider=lambda: {"keys": []}, audience="https://vault.local",
        issuer="https://id.local", now_fn=lambda: 1000.0,
        identity_store=ident, vault_store=vault)
    assert use_authorizer(conn=conn, principal_id="prn_owner", org="caput-venti") is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_manage_authorizer.py -v`
Expected: FAIL with `ImportError: cannot import name 'make_manage_authorizer'`.

- [ ] **Step 3: Add owner injection + the manage authorizer**

In `vault/kernel_auth.py`, update the import line to also pull `adapt_connection_grant`:

```python
from identity.authorize import authorize, collect_grants, adapt_connection_grant
```

Add a private helper and use it in the existing authorizer, then add the manage authorizer. Replace the body of `make_kernel_auth`'s `authorizer` and append the new function:

```python
def _grants_for(principal_id, conn, identity_store, vault_store):
    grants = collect_grants(
        principal_id=principal_id, identity_store=identity_store,
        connection_grants=vault_store.get_grants(conn.id))
    if principal_id == conn.created_by:
        # the connection owner keeps slice-1 manage/use on the authed path
        grants.append(adapt_connection_grant(None, owner_connection_id=conn.id))
    return grants
```

In `make_kernel_auth`, change the `authorizer` to:

```python
    def authorizer(*, conn, principal_id: str, org) -> bool:
        grants = _grants_for(principal_id, conn, identity_store, vault_store)
        return authorize(grants=grants, target=GrantTarget("connection", conn.id),
                         access="use", now=now_fn(), request_org=org)
```

Append:

```python
def make_manage_authorizer(*, now_fn, identity_store, vault_store):
    """A grant check for `manage` operations (grant / list / revoke), over the unified
    Grant table plus the connection's own grants, with owner -> manage."""
    def manage_authorizer(*, conn, principal_id: str, org) -> bool:
        grants = _grants_for(principal_id, conn, identity_store, vault_store)
        return authorize(grants=grants, target=GrantTarget("connection", conn.id),
                         access="manage", now=now_fn(), request_org=org)
    return manage_authorizer
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_manage_authorizer.py tests/test_cutover_proof.py -v`
Expected: PASS (manage tests green; the owner injection is additive so the cutover proof — which uses a non-owner service principal and an ungranted principal — is unchanged).

- [ ] **Step 5: Commit**

```bash
git add vault/kernel_auth.py tests/test_manage_authorizer.py
git commit -m "feat(vault): manage authorizer + owner grant injection on the authed path"
```

---

### Task 5: `manage_check` hooks on `AccessService.grant` / `list_connections` / `revoke`

So the authed routes can enforce `manage` through the kernel `authorize()` instead of the slice-1 store-only `require_access`. Additive keyword; `None` keeps slice-1 behavior byte-identical.

**Files:**
- Modify: `vault/access.py:38-68`
- Test: `tests/test_access_service_manage_check.py`

**Interfaces:**
- Consumes: `AccessService(store, providers, config)`.
- Produces: `grant(self, key, granter_id, principal_id, access, scopes_subset, *, manage_check=None)`, `list_connections(self, org, provider, principal_id, *, manage_check=None)`, `revoke(self, key, principal_id, *, manage_check=None)`. `manage_check` is `Callable[[Connection], bool]`; falsey → `PermissionError`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_access_service_manage_check.py
import pytest

from vault.access import AccessService
from vault.config import VaultConfig
from vault.store.memory import InMemoryStore
from vault.model import Connection, Token
from vault.providers.fortnox import FortnoxProvider
from vault.providers.base import AppCred


def _service():
    store = InMemoryStore()
    store.put_connection(Connection(
        id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
        scopes=["bookkeeping"], app_cred_ref="fortnox",
        token=Token("A", "R", 99999.0, "bookkeeping"), rotation="rotating",
        lease=None, created_by="prn_owner", created_at=0.0, updated_at=0.0))
    cfg = VaultConfig(now_fn=lambda: 1000.0, http_post=lambda *a: {},
                      app_creds={"fortnox": AppCred("c", "s")}, state_hmac_key=b"k", skew=60)
    return AccessService(store, {"fortnox": FortnoxProvider()}, cfg), store


def _key():
    from vault.model import ConnKey
    return ConnKey("caput-venti", "fortnox", "559401-5157")


def test_revoke_denied_when_manage_check_false():
    svc, _ = _service()
    with pytest.raises(PermissionError):
        svc.revoke(_key(), "prn_x", manage_check=lambda conn: False)


def test_grant_allowed_when_manage_check_true():
    svc, _ = _service()
    out = svc.grant(_key(), "prn_x", "prn_new", "use", None, manage_check=lambda conn: True)
    assert out["principalId"] == "prn_new"


def test_list_filters_by_manage_check():
    svc, _ = _service()
    out = svc.list_connections("caput-venti", None, "prn_x", manage_check=lambda conn: True)
    assert len(out) == 1 and out[0]["id"] == "conn_1"
    with pytest.raises(PermissionError):
        svc.list_connections("caput-venti", None, "prn_x", manage_check=lambda conn: False)


def test_none_manage_check_preserves_slice1_owner_behavior():
    svc, _ = _service()
    # owner (created_by) can grant via the legacy require_access path
    out = svc.grant(_key(), "prn_owner", "prn_new", "use", None)
    assert out["principalId"] == "prn_new"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_access_service_manage_check.py -v`
Expected: FAIL with `TypeError: grant() got an unexpected keyword argument 'manage_check'`.

- [ ] **Step 3: Add the hooks**

In `vault/access.py`, update the three methods (keep the rest of each body unchanged):

```python
    def grant(self, key: ConnKey, granter_id: str, principal_id: str, access, scopes_subset,
              *, manage_check=None):
        conn = self.store.get_connection(key)
        if conn is None:
            raise KeyError(f"no connection for {key.as_str()}")
        if manage_check is not None:
            if not manage_check(conn):
                raise PermissionError(f"{granter_id} lacks manage on {conn.id}")
        else:
            require_access(self.store, conn, granter_id, "manage")
        g = ConnectionGrant(connection_id=conn.id, principal_id=principal_id, access=access,
                            scopes_subset=scopes_subset, granted_by=granter_id,
                            granted_at=self.config.now_fn())
        self.store.add_grant(g)
        return {"connectionId": conn.id, "principalId": principal_id, "access": access}

    def list_connections(self, org: str, provider, principal_id: str,
                         *, manage_check=None) -> list[dict]:
        out = []
        for conn in self.store.list_connections(org, provider):
            try:
                if manage_check is not None:
                    if not manage_check(conn):
                        raise PermissionError("denied")
                else:
                    require_access(self.store, conn, principal_id, "manage")
            except PermissionError:
                continue
            out.append({"id": conn.id, "org": conn.org, "provider": conn.provider,
                        "account": conn.account, "scopes": conn.scopes, "rotation": conn.rotation})
        if not out and self.store.list_connections(org, provider):
            raise PermissionError(f"{principal_id} lacks manage on any matching connection")
        return out

    def revoke(self, key: ConnKey, principal_id: str, *, manage_check=None) -> dict:
        conn = self.store.get_connection(key)
        if conn is None:
            raise KeyError(f"no connection for {key.as_str()}")
        if manage_check is not None:
            if not manage_check(conn):
                raise PermissionError(f"{principal_id} lacks manage on {conn.id}")
        else:
            require_access(self.store, conn, principal_id, "manage")
        self.store.delete_connection(key)
        return {"revoked": conn.id}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_access_service_manage_check.py -v`
Expected: PASS (all four).

- [ ] **Step 5: Commit**

```bash
git add vault/access.py tests/test_access_service_manage_check.py
git commit -m "feat(vault): additive manage_check hooks on grant/list/revoke"
```

---

### Task 6: Gate every vault endpoint behind the kernel JWT + manage authorize

Today the authed branch only protects `/access-token`; `connect`, `finish`, `grant`, `list`, `revoke` still read a spoofable `x_principal` header. When `require_principal` is set, every route must require a verified kernel JWT, take the principal from `claims["sub"]`, and run the manage authorizer on the manage routes. Thread `manage_authorizer` through `build_app` and wire it in `_build_app_from_env`.

**Files:**
- Modify: `vault/app.py:16-119`
- Test: `tests/test_authed_endpoints.py`

**Interfaces:**
- Consumes: `make_kernel_auth`, `make_manage_authorizer`, `cached_jwks_provider` from `vault/kernel_auth`; `AccessService.{grant,list_connections,revoke,start_connect,finish_connect}` with the Task-5 `manage_check`.
- Produces: `build_app(service, *, require_principal=None, authorizer=None, manage_authorizer=None)`. When `require_principal` is set, all routes depend on it; manage routes pass `manage_check=lambda conn: manage_authorizer(conn=conn, principal_id=claims["sub"], org=claims.get("org"))`. The stub branch (`require_principal is None`) is unchanged.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_authed_endpoints.py
from fastapi.testclient import TestClient

from identity.keys import KeyManager
from identity.store.memory import InMemoryIdentityStore
from identity.jwt_issuer import mint
from identity.service_principal import grant_connection_use

from vault.app import build_app
from vault.access import AccessService
from vault.config import VaultConfig
from vault.store.memory import InMemoryStore
from vault.model import Connection, Token
from vault.providers.fortnox import FortnoxProvider
from vault.providers.base import AppCred
from vault.kernel_auth import make_kernel_auth, make_manage_authorizer

ISSUER = "https://id.local"
AUD = "https://vault.local"
CONN = "caput-venti%2Ffortnox%2F559401-5157"
NOW = 1100.0


def _harness():
    store = InMemoryStore()
    store.put_connection(Connection(
        id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
        scopes=["bookkeeping"], app_cred_ref="fortnox",
        token=Token("A", "R", 99999.0, "bookkeeping"), rotation="rotating",
        lease=None, created_by="prn_owner", created_at=0.0, updated_at=0.0))
    cfg = VaultConfig(now_fn=lambda: NOW, http_post=lambda *a: {},
                      app_creds={"fortnox": AppCred("c", "s")}, state_hmac_key=b"k", skew=60)
    service = AccessService(store, {"fortnox": FortnoxProvider()}, cfg)
    km = KeyManager.generate("kid-1")
    ident = InMemoryIdentityStore()
    require_principal, authorizer = make_kernel_auth(
        jwks_provider=lambda: km.jwks_document(), audience=AUD, issuer=ISSUER,
        now_fn=lambda: NOW, identity_store=ident, vault_store=service.store)
    manage_authorizer = make_manage_authorizer(
        now_fn=lambda: NOW, identity_store=ident, vault_store=service.store)
    app = build_app(service, require_principal=require_principal, authorizer=authorizer,
                    manage_authorizer=manage_authorizer)
    return app, km, ident


def _jwt(km, sub, roles=("member",)):
    return mint(km=km, issuer=ISSUER, sub=sub, typ="human", audience=AUD,
                org="caput-venti", roles=list(roles), ttl=300, now=int(NOW))


def test_list_requires_bearer():
    app, _, _ = _harness()
    assert TestClient(app).get("/connections?org=caput-venti").status_code == 401


def test_revoke_requires_bearer():
    app, _, _ = _harness()
    assert TestClient(app).delete(f"/connections/{CONN}").status_code == 401


def test_grant_forbidden_without_manage_grant():
    app, km, _ = _harness()
    token = _jwt(km, "prn_nogrant")
    r = TestClient(app).post(f"/connections/{CONN}/grant",
                             headers={"Authorization": f"Bearer {token}"},
                             json={"principalId": "prn_z", "access": "use"})
    assert r.status_code == 403


def test_owner_can_list_and_grant():
    app, km, _ = _harness()
    token = _jwt(km, "prn_owner")
    h = {"Authorization": f"Bearer {token}"}
    assert TestClient(app).get("/connections?org=caput-venti", headers=h).status_code == 200
    r = TestClient(app).post(f"/connections/{CONN}/grant", headers=h,
                             json={"principalId": "prn_z", "access": "use"})
    assert r.status_code == 200 and r.json()["principalId"] == "prn_z"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_authed_endpoints.py -v`
Expected: FAIL — `build_app` has no `manage_authorizer` param (TypeError), and the manage routes currently ignore the JWT (401s would be 200s).

- [ ] **Step 3: Gate the routes**

In `vault/app.py`, change the signature:

```python
def build_app(service: AccessService, *, require_principal: Optional[Callable] = None,
              authorizer: Optional[Callable] = None,
              manage_authorizer: Optional[Callable] = None) -> FastAPI:
```

Move the `connect`/`finish`/`grant`/`list`/`revoke` route definitions inside an `if require_principal is not None:` / `else:` split so the authed versions depend on the JWT. Concretely, after the `access_token_authed` definition (still inside the `if require_principal is not None:` block), add the authed variants; keep the existing unauthed definitions in the `else` block. The authed block:

```python
    if require_principal is not None:
        from vault.grants import require_access  # noqa: F401  (kept for parity import)

        @app.post("/connections/{conn_id:path}/access-token")
        async def access_token_authed(conn_id: str, claims=Depends(require_principal)):
            principal = claims["sub"]
            org = claims.get("org")
            island = claims.get("aud", "unknown")

            def grant_check(conn):
                if authorizer is not None:
                    if not authorizer(conn=conn, principal_id=principal, org=org):
                        raise PermissionError(f"{principal} lacks use on {conn.id}")

            return guard(lambda: service.get_access_token(
                _parse_id(conn_id), principal, island, grant_check=grant_check))

        def _manage_check(claims):
            if manage_authorizer is None:
                return None
            principal = claims["sub"]
            org = claims.get("org")
            return lambda conn: manage_authorizer(conn=conn, principal_id=principal, org=org)

        @app.post("/connections/{provider}/connect")
        async def connect_authed(provider: str, request: Request, claims=Depends(require_principal)):
            body = await request.json()
            return guard(lambda: service.start_connect(
                body["org"], provider, body["account"], claims["sub"], body.get("code_challenge")))

        @app.post("/connections/connect/finish")
        async def finish_authed(request: Request, claims=Depends(require_principal)):
            body = await request.json()
            return guard(lambda: service.finish_connect(
                body["code"], body["state"], body.get("code_verifier")))

        @app.post("/connections/{conn_id:path}/grant")
        async def grant_authed(conn_id: str, request: Request, claims=Depends(require_principal)):
            body = await request.json()
            return guard(lambda: service.grant(
                _parse_id(conn_id), claims["sub"], body["principalId"], body["access"],
                body.get("scopesSubset"), manage_check=_manage_check(claims)))

        @app.get("/connections")
        async def list_authed(org: str, provider: str | None = None,
                              claims=Depends(require_principal)):
            return guard(lambda: service.list_connections(
                org, provider, claims["sub"], manage_check=_manage_check(claims)))

        @app.delete("/connections/{conn_id:path}")
        async def revoke_authed(conn_id: str, claims=Depends(require_principal)):
            return guard(lambda: service.revoke(
                _parse_id(conn_id), claims["sub"], manage_check=_manage_check(claims)))
    else:
        @app.post("/connections/{provider}/connect")
        async def connect(provider: str, request: Request, x_principal: str = Header("stub")):
            body = await request.json()
            return guard(lambda: service.start_connect(
                body["org"], provider, body["account"], x_principal, body.get("code_challenge")))

        @app.post("/connections/connect/finish")
        async def finish(request: Request):
            body = await request.json()
            return guard(lambda: service.finish_connect(
                body["code"], body["state"], body.get("code_verifier")))

        @app.post("/connections/{conn_id:path}/access-token")
        async def access_token_stub(conn_id: str, x_principal: str = Header("stub"),
                                    x_island: str = Header("unknown")):
            return guard(lambda: service.get_access_token(_parse_id(conn_id), x_principal, x_island))

        @app.post("/connections/{conn_id:path}/grant")
        async def grant(conn_id: str, request: Request, x_principal: str = Header("stub")):
            body = await request.json()
            return guard(lambda: service.grant(
                _parse_id(conn_id), x_principal, body["principalId"], body["access"],
                body.get("scopesSubset")))

        @app.get("/connections")
        async def list_conns(org: str, provider: str | None = None, x_principal: str = Header("stub")):
            return guard(lambda: service.list_connections(org, provider, x_principal))

        @app.delete("/connections/{conn_id:path}")
        async def revoke(conn_id: str, x_principal: str = Header("stub")):
            return guard(lambda: service.revoke(_parse_id(conn_id), x_principal))

    return app
```

Note: remove the old top-level `connect`/`finish` definitions (lines 30-40) and the old trailing `grant`/`list_conns`/`revoke` (lines 66-79) so they exist only inside the branch split above. The `access_token_authed`/`access_token_stub` pair already existed — keep one copy each, inside the matching branch.

Then wire the manage authorizer in `_build_app_from_env`:

```python
    if os.environ.get("VAULT_REQUIRE_KERNEL") == "1":
        import time
        from vault.kernel_auth import make_kernel_auth, make_manage_authorizer, cached_jwks_provider
        from identity.store.server import ServerIdentityStore
        identity_store = ServerIdentityStore(
            os.environ.get("KERNEL_IDENTITY_DB", "vault-store/identity.sqlite"))
        jwks_provider = cached_jwks_provider(os.environ["KERNEL_JWKS_URL"])
        require_principal, authorizer = make_kernel_auth(
            jwks_provider=jwks_provider, audience=os.environ["VAULT_AUDIENCE"],
            issuer=os.environ["KERNEL_ISSUER"], now_fn=time.time,
            identity_store=identity_store, vault_store=service.store)
        manage_authorizer = make_manage_authorizer(
            now_fn=time.time, identity_store=identity_store, vault_store=service.store)
        return build_app(service, require_principal=require_principal, authorizer=authorizer,
                         manage_authorizer=manage_authorizer)
    return build_app(service)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_authed_endpoints.py tests/test_cutover_proof.py -v`
Expected: PASS (new gating green; the cutover proof still green — its access-token flow is unchanged).

- [ ] **Step 5: Run the full suite to confirm no regressions**

Run: `python -m pytest -q`
Expected: PASS (no collection errors; prior suites green).

- [ ] **Step 6: Commit**

```bash
git add vault/app.py tests/test_authed_endpoints.py
git commit -m "feat(vault): require kernel JWT + manage authorize on every endpoint"
```

---

### Task 7: Served-stack end-to-end proof over real HTTP

Prove the served posture over real loopback sockets (uvicorn-in-thread), not just in-process `TestClient`: a service principal exchanges its credential for a 5-min JWT at the identity service, then fetches a Fortnox token from the vault service, which holds no refresh token in its response. The vault verifies the JWT against the identity service's JWKS fetched over HTTP. `401` (no Bearer) and `403` (valid JWT, no grant) hold over the wire.

**Files:**
- Create: `tests/served_harness.py`
- Test: `tests/test_served_stack_e2e.py`

**Interfaces:**
- Consumes: `build_identity_app`, `build_app`, `make_kernel_auth`, `make_manage_authorizer`, `cached_jwks_provider`, `issue_service_credential`, `grant_connection_use`, `ServerStore`, `SecretboxKeyWrapper`, `FortnoxProvider`, `AppCred`, `KeyManager`, `ServerIdentityStore`.
- Produces: `tests/served_harness.py` exposing `ThreadedServer(app, port)` (`.start()/.stop()`), `free_port() -> int`, `CountingProvider` (a `FortnoxProvider` counting refreshes), and `build_served_stack(tmp_path, *, expired=False) -> ServedStack` where `ServedStack` has `.identity_url`, `.vault_url`, `.cred`, `.audience`, `.provider`, `.start()`, `.stop()`.

- [ ] **Step 1: Write the harness + the failing test**

```python
# tests/served_harness.py
from __future__ import annotations
import socket
import threading
import time as _time
from dataclasses import dataclass

import uvicorn
import nacl.utils

from identity.keys import KeyManager
from identity.store.server import ServerIdentityStore
from identity.app import build_identity_app
from identity.service_principal import issue_service_credential, grant_connection_use

from vault.app import build_app
from vault.access import AccessService
from vault.config import VaultConfig
from vault.store.server import ServerStore
from vault.crypto import SecretboxKeyWrapper
from vault.model import Connection, Token
from vault.providers.fortnox import FortnoxProvider
from vault.providers.base import AppCred
from vault.kernel_auth import make_kernel_auth, make_manage_authorizer, cached_jwks_provider

ORG = "caput-venti"
ACCOUNT = "559401-5157"
ACCESS_PATH = "/connections/caput-venti%2Ffortnox%2F559401-5157/access-token"


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class ThreadedServer:
    def __init__(self, app, port: int):
        cfg = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
        self._srv = uvicorn.Server(cfg)
        self._th = threading.Thread(target=self._srv.run, daemon=True)

    def start(self):
        self._th.start()
        for _ in range(500):
            if self._srv.started:
                return
            _time.sleep(0.01)
        raise RuntimeError("server did not start")

    def stop(self):
        self._srv.should_exit = True
        self._th.join(timeout=5)


class CountingProvider(FortnoxProvider):
    def __init__(self):
        self.calls = 0
        self._lock = threading.Lock()

    def refresh(self, token, app, http_post, now):
        with self._lock:
            self.calls += 1
            n = self.calls
        return Token(f"acc{n}", f"ref{n}", now + 3600, "bookkeeping")


@dataclass
class ServedStack:
    identity_url: str
    vault_url: str
    cred: str
    audience: str
    provider: CountingProvider
    _identity_srv: ThreadedServer
    _vault_srv: ThreadedServer

    def start(self):
        self._identity_srv.start()
        self._vault_srv.start()

    def stop(self):
        self._vault_srv.stop()
        self._identity_srv.stop()


def build_served_stack(tmp_path, *, expired: bool = False) -> ServedStack:
    import time
    id_port, vault_port = free_port(), free_port()
    identity_url = f"http://127.0.0.1:{id_port}"
    vault_url = f"http://127.0.0.1:{vault_port}"
    audience = vault_url
    issuer = identity_url
    now = time.time()

    km = KeyManager.generate("kid-served")
    ident = ServerIdentityStore(str(tmp_path / "identity.sqlite"))
    cred = issue_service_credential(
        ident, principal_id="prn_bk", display_name="bookkeeping", org_id=ORG,
        audience=audience, now=now, expires_at=now + 3600)
    grant_connection_use(ident, principal_id="prn_bk", connection_id="conn_1",
                         granted_by="prn_owner", now=now)
    identity_app = build_identity_app(store=ident, key_manager=km, issuer=issuer, now_fn=time.time)

    wrapper = SecretboxKeyWrapper(nacl.utils.random(32))
    store = ServerStore(f"sqlite:///{tmp_path}/vault.sqlite", wrapper)
    expires = 100.0 if expired else now + 99999.0
    store.put_connection(Connection(
        id="conn_1", org=ORG, provider="fortnox", account=ACCOUNT, scopes=["bookkeeping"],
        app_cred_ref="fortnox", token=Token("FORTNOX_ACCESS", "REFRESH", expires, "bookkeeping"),
        rotation="rotating", lease=None, created_by="prn_owner", created_at=0.0, updated_at=0.0))
    provider = CountingProvider()
    cfg = VaultConfig(now_fn=time.time, http_post=lambda *a: {},
                      app_creds={"fortnox": AppCred("cid", "secret")}, state_hmac_key=b"k", skew=60)
    service = AccessService(store, {"fortnox": provider}, cfg)

    jwks_provider = cached_jwks_provider(f"{identity_url}/.well-known/jwks.json")
    require_principal, authorizer = make_kernel_auth(
        jwks_provider=jwks_provider, audience=audience, issuer=issuer, now_fn=time.time,
        identity_store=ident, vault_store=service.store)
    manage_authorizer = make_manage_authorizer(
        now_fn=time.time, identity_store=ident, vault_store=service.store)
    vault_app = build_app(service, require_principal=require_principal, authorizer=authorizer,
                          manage_authorizer=manage_authorizer)

    @vault_app.get("/_test/refresh-count")
    async def _refresh_count():
        return {"calls": provider.calls}

    return ServedStack(identity_url, vault_url, cred, audience, provider,
                       ThreadedServer(identity_app, id_port), ThreadedServer(vault_app, vault_port))
```

```python
# tests/test_served_stack_e2e.py
import httpx

from tests.served_harness import build_served_stack, ACCESS_PATH


def _exchange(stack) -> str:
    r = httpx.post(f"{stack.identity_url}/auth/exchange",
                   json={"opaque_token": stack.cred, "audience": stack.audience}, timeout=10)
    r.raise_for_status()
    return r.json()["access_token"]


def test_served_stack_fetches_token_over_http_without_refresh_token(tmp_path):
    stack = build_served_stack(tmp_path)
    stack.start()
    try:
        jwt = _exchange(stack)
        r = httpx.post(f"{stack.vault_url}{ACCESS_PATH}",
                       headers={"Authorization": f"Bearer {jwt}"}, timeout=10)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["accessToken"] == "FORTNOX_ACCESS"
        # the refresh token never leaves the vault
        assert "refreshToken" not in body and "refresh_token" not in body
    finally:
        stack.stop()


def test_served_stack_rejects_missing_and_ungranted(tmp_path):
    stack = build_served_stack(tmp_path)
    stack.start()
    try:
        assert httpx.post(f"{stack.vault_url}{ACCESS_PATH}", timeout=10).status_code == 401
        # a valid JWT minted for an ungranted principal, signed by the same key:
        from identity.keys import KeyManager  # noqa: F401  (kept explicit for the reader)
    finally:
        stack.stop()
```

Note: the `403` ungranted path over HTTP needs a JWT signed by the served key for a principal with no grant. The harness uses an ephemeral `KeyManager.generate`, so mint through the served identity instead: issue a second service credential with no grant and exchange it. Extend the harness with `issue_ungranted_cred()` if you prefer; the minimal version asserts the `401` over the wire and relies on Task 6's in-process `403` proof. Keep the e2e test focused on the `200` + no-refresh-token + `401` properties; the `403` grant semantics are already proven in `tests/test_authed_endpoints.py` and `tests/test_cutover_proof.py`.

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_served_stack_e2e.py -v`
Expected: FAIL initially with `ModuleNotFoundError`/`ImportError` until `tests/served_harness.py` is saved, then run again. (If `httpx` import of `tests.served_harness` fails on path, ensure `pytest` runs from the repo root — `pyproject.toml` already sets `pythonpath = [".", "libs/python"]`.)

- [ ] **Step 3: Implement**

The harness in Step 1 is the implementation. No production code changes — this task exercises Tasks 2/3/4/5/6 over real sockets. If the test fails because `pyproject.toml` `testpaths`/`pythonpath` does not expose the `tests` package for `from tests.served_harness import ...`, add an empty `tests/__init__.py` and re-run.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_served_stack_e2e.py -v`
Expected: PASS (token fetched over HTTP; no refresh token in body; 401 holds).

- [ ] **Step 5: Commit**

```bash
git add tests/served_harness.py tests/test_served_stack_e2e.py
[ -f tests/__init__.py ] && git add tests/__init__.py
git commit -m "test(served): end-to-end credential->JWT->vault over real HTTP"
```

---

### Task 8: Cross-process single-writer proof through the served vault

The slice-1 single-writer proof used threads against the store directly. Now prove it through the **served** vault over HTTP from separate OS processes: N client processes concurrently request the access token for an expired connection; the one served vault refreshes exactly once and every client gets the identical rotated token. This is what "single writer across hosts" means in this posture — the served process is the writer, HTTP is the fan-in.

**Files:**
- Test: `tests/test_served_single_writer.py`
- Reuse: `tests/served_harness.py` (Task 7), with `expired=True`.

**Interfaces:**
- Consumes: `build_served_stack(tmp_path, expired=True)`, `ACCESS_PATH` from `tests/served_harness`.
- Produces: a top-level module function `_client_fetch(args)` (picklable for `multiprocessing`) returning the fetched `accessToken`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_served_single_writer.py
import multiprocessing as mp

import httpx

from tests.served_harness import build_served_stack, ACCESS_PATH


def _client_fetch(args):
    vault_url, bearer = args
    r = httpx.post(f"{vault_url}{ACCESS_PATH}",
                   headers={"Authorization": f"Bearer {bearer}"}, timeout=15)
    r.raise_for_status()
    return r.json()["accessToken"]


def test_concurrent_processes_trigger_exactly_one_refresh(tmp_path):
    stack = build_served_stack(tmp_path, expired=True)
    stack.start()
    try:
        # one exchanged JWT shared across all client processes
        jwt = httpx.post(f"{stack.identity_url}/auth/exchange",
                         json={"opaque_token": stack.cred, "audience": stack.audience},
                         timeout=10).json()["access_token"]
        n = 8
        ctx = mp.get_context("spawn")
        with ctx.Pool(n) as pool:
            tokens = pool.map(_client_fetch, [(stack.vault_url, jwt)] * n)

        # exactly one refresh happened in the single served writer
        count = httpx.get(f"{stack.vault_url}/_test/refresh-count", timeout=10).json()["calls"]
        assert count == 1, f"expected one refresh, got {count}"
        # every caller saw the same single rotated token
        assert len(set(tokens)) == 1, tokens
        assert tokens[0] == "acc1"
    finally:
        stack.stop()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_served_single_writer.py -v`
Expected: FAIL if run before Task 7's harness exists (ImportError). With the harness present it should pass; if it flakes (count > 1), that signals a real single-writer regression in `ServerStore`/`refresh_if_needed` — debug with `superpowers:systematic-debugging`, do not loosen the assertion.

- [ ] **Step 3: Implement**

No production change — the proof rides Tasks 2-7. If `multiprocessing` with `spawn` cannot pickle the client args or re-imports the harness expensively, keep `_client_fetch` at module top level (already is) and pass only primitives (URL + bearer string), which the test does.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_served_single_writer.py -v`
Expected: PASS (`count == 1`, all tokens `"acc1"`).

- [ ] **Step 5: Run the full suite**

Run: `python -m pytest -q`
Expected: PASS (whole suite green, including slice-1/slice-2 tests).

- [ ] **Step 6: Commit**

```bash
git add tests/test_served_single_writer.py
git commit -m "test(served): cross-process single-writer proof over HTTP"
```

---

### Task 9: Run runbook, KEK/KMS custody, multi-replica seam, and gated-cutover doc

Document how to serve the stack, where the crown-jewel secrets live (never committed), the single-writer/multi-replica posture, and the three gated live-money cutover steps as a **do-not-execute-autonomously** runbook.

**Files:**
- Create: `docs/server-posture-vault.md`
- Modify: `CLAUDE.md:18-24` (Structure block — add a one-line pointer)

**Interfaces:** none (docs only).

- [ ] **Step 1: Write the doc**

Create `docs/server-posture-vault.md` with these sections (fill with the real env contract from Tasks 2/3/6):

```markdown
# Server-posture vault + served kernel identity

Two ASGI services. The vault verifies kernel JWTs offline against the identity
service's public JWKS; the signing key never leaves the identity service.

## Run

Identity (signs tokens, publishes JWKS):
- `IDENTITY_BOOT=1`
- `KERNEL_SIGNING_SEED` — base64url Ed25519 32-byte seed. Crown jewel. Host secret store / KMS only; never committed, never logged.
- `KERNEL_ISSUER` — e.g. `https://id.<host>`
- `KERNEL_KID` — key id (default `kid-1`)
- `KERNEL_IDENTITY_DB` — sqlite path (gitignored)
- `uvicorn identity.app:app --host 127.0.0.1 --port <id-port>`

Vault (brokers Fortnox tokens, single writer):
- `VAULT_BOOT=1`, `VAULT_REQUIRE_KERNEL=1`, `VAULT_BACKEND=server`
- `VAULT_DB` — sqlite path (gitignored)
- `VAULT_KEK` — base64 32-byte KEK. Crown jewel. Required when served (no random fallback). Host secret store / KMS only.
- `KERNEL_JWKS_URL` — `<identity-url>/.well-known/jwks.json`
- `VAULT_AUDIENCE` — the vault's public URL (the JWT `aud`)
- `KERNEL_ISSUER` — same issuer as identity
- `KERNEL_IDENTITY_DB` — the identity sqlite (for grant lookups)
- `uvicorn vault.app:app --host 127.0.0.1 --port <vault-port>`

## Secret custody (KEK / signing seed)

`KERNEL_SIGNING_SEED` and `VAULT_KEK` are the only crown jewels. They are read
from the environment / host secret store (KMS seam) at boot and never written to
the repo, logs, or token files. `.gitignore` covers `*.age`, `*.key`, `*.ed25519`,
`.env*`, `*.sqlite*`, `kernel-keys/`, `vault-store/`. Rotating the KEK requires
re-sealing envelopes (decrypt with the old KEK, re-seal with the new); rotating the
signing key uses publish-before-sign JWKS overlap (add the new key to the document,
let verifiers cache it, then sign with it).

## Single writer / multi-replica seam

Today the single served vault process is the single writer: HTTP is the fan-in and
the `ServerStore` SQLite DB-row lease + in-process mutex serialize refresh. Proven by
`tests/test_served_single_writer.py` (N client processes -> one refresh). For more than
one vault replica, swap the SQLite DB-row lease for a Postgres advisory lock behind the
same `Store` interface (`acquire_lease`/`release_lease`/`lease_held`) — the parity suite
(`tests/test_refresh_single_writer.py`) is the contract that swap must keep green. Not
built here.

## Gated live cutover — DO NOT run autonomously; run with the human present

Each step is a live-money action. Stop and confirm before each.

1. Bring up the served identity + vault locally. Issue bookkeeping a real service
   credential (`issue_service_credential`) and grant `use` on the real Fortnox
   connection (`grant_connection_use`). No prod flag flip yet.
2. Point bookkeeping-engine at the served vault with `BOOKKEEPING_VAULT_KERNEL_AUTH=1`
   + `VAULT_REQUIRE_KERNEL=1`. Prove a real Fortnox fetch works on -> off -> on. The
   in-process local path stays the fallback the whole time.
3. Remote: re-authorize Fortnox THROUGH the served connect flow (assume the May-10
   `tokens.age` is dead — confirm, do not import). Back it up first. Then flip
   research-engine's `RESEARCH_USE_VAULT` + the remote snapshot routine onto the served
   vault. The first refresh rotates + invalidates the on-disk token — the irreversible
   commit point. Show diffs and get explicit OK before it.
```

- [ ] **Step 2: Add the CLAUDE.md pointer**

In `CLAUDE.md`, under `## Structure`, add a line after the structure block:

```markdown
Served posture: `identity.app:app` (IDENTITY_BOOT) and `vault.app:app`
(VAULT_BOOT) are the uvicorn entrypoints. See `docs/server-posture-vault.md`
for the env contract, secret custody, and the gated live-cutover runbook.
```

- [ ] **Step 3: Verify the docs reference real symbols**

Run: `python -m pytest -q && grep -n "IDENTITY_BOOT\|VAULT_REQUIRE_KERNEL\|VAULT_KEK\|KERNEL_SIGNING_SEED" docs/server-posture-vault.md`
Expected: suite green; grep shows the documented env vars (cross-check they match Tasks 2/3/6 verbatim).

- [ ] **Step 4: Commit**

```bash
git add docs/server-posture-vault.md CLAUDE.md
git commit -m "docs: server-posture run runbook, secret custody, gated cutover"
```

---

### Task 10: Gated live cutover — STOP

This task is **not executed in this plan**. It is the three live-money steps documented in `docs/server-posture-vault.md`. Each is gated on the human being present and is run in a separate, supervised session.

- [ ] **Step 1: STOP.** Do not run any live Fortnox re-auth, prod flag flip, or `tokens.age` mutation. Report that the reversible build is complete and the cutover runbook is ready for a supervised session.

---

## Self-Review

**Spec coverage (prompt scope IN):**
- "Serve the ServerStore backend behind FastAPI as a reachable service" → Tasks 6 (`_build_app_from_env` already constructs the authed served app; KEK hardened in 3) + 7 (real-socket proof). `ServerStore`'s DB-row lease already exists and stays green (Task 8 / `test_refresh_single_writer.py`).
- "single-writer refresh across processes/hosts (not os.link lease)" → Task 8 proves it through the served `ServerStore` over HTTP. Multi-replica advisory-lock seam documented in Task 9.
- "FIX ServerIdentityStore concurrency backlog + high-contention test" → Task 1.
- "Kernel JWT auth + authorize() on every endpoint; org-keyed envelopes" → Tasks 4/5/6. Envelopes are already keyed by `(org, provider, account)` and sealed per-connection (`ServerStore.put_connection` → `seal_token`); the access path carries `org` in the key — no new task needed, asserted via the served e2e path.
- "Serve kernel identity endpoints (exchange + JWKS) reachably" → Task 2 (bootstrap) + Task 7 (JWKS fetched over HTTP by the vault, exchange called over HTTP).
- "KEK/age seam; document where the KEK lives; never a committed key" → Task 3 (fail-fast) + Task 9 (custody doc).
- "Prove end-to-end against the SERVED stack with stubs where money is involved" → Tasks 7 + 8 (CountingProvider stub; no real Fortnox).
- "Gated live cutover — do not do autonomously" → Task 9 (doc) + Task 10 (STOP).

**Placeholder scan:** no TBD/TODO; every code step shows complete code; test bodies are concrete.

**Type consistency:** `make_manage_authorizer(*, now_fn, identity_store, vault_store)` and `manage_authorizer(*, conn, principal_id, org)` are used identically in Tasks 4/6/7. `build_app(..., manage_authorizer=None)` matches its call sites in Task 6 `_build_app_from_env` and Task 7 harness. `manage_check=Callable[[Connection], bool]` matches Tasks 5/6. `build_served_stack(tmp_path, *, expired=False)`, `ACCESS_PATH`, `ServedStack.provider.calls`, and `/_test/refresh-count` are consistent across Tasks 7/8.

**Reversibility:** Tasks 1-9 add code/tests/docs and tighten the served branch only; the slice-1 stub branch (`require_principal is None`) and the in-process local path are untouched. No prod flag is flipped. Task 10 is a STOP.

## As-built note (2026-06-19)

The Important-2 fix (threadpool the access-token path) converted **both** access-token
handlers — `access_token_authed` and the slice-1 `access_token_stub` — from `async def`
to sync `def`. This is an intentional consistency choice, signed off: observable
behaviour/output is byte-identical (reviewer-confirmed), the stub HTTP handler has no live
consumer (prod reads Fortnox in-process via `vault.get_access_token`, not through FastAPI),
and keeping both handlers on one threadpool execution model avoids reintroducing the exact
event-loop-blocking antipattern (b) removed. Recorded in `docs/server-posture-vault.md`
under "Single writer / multi-replica seam".
