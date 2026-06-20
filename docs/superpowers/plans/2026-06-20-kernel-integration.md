# Kernel Integration + Hardening Pass Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the three served kernel services (identity, vault, bus) compose as one system under one shared identity, and capture a combined "kernel up" boot reference for the upcoming VPS deploy.

**Architecture:** Boot identity (signs tokens, publishes JWKS), vault (brokers Fortnox tokens), and bus (inter-island events) as three uvicorn services that share ONE signing key, ONE JWKS document, and ONE identity sqlite. Vault and bus verify kernel JWTs offline against the identity service's public JWKS; the signing seed never leaves identity. The proof is a cross-slice integration test over real sockets: one service principal → one kernel JWT → with that same token, fetch a vault access token AND publish+consume a bus event, with org scoping consistent across both. This is additive — tests, a provisioning helper, and docs. Slice internals are not changed.

**Tech Stack:** Python 3, FastAPI/Starlette, uvicorn, httpx, pyjwt (EdDSA), pynacl, SQLite, pytest.

## Global Constraints

- Branch policy: work on the current branch (`main`). Never create a branch.
- Crown jewels (`KERNEL_SIGNING_SEED`, `VAULT_KEK`) and raw service credentials are never committed, never logged, never written to the repo. `.gitignore` already covers `*.sqlite`, `vault-store/`, `*.key`, `*.age`, `.env*` — keep it.
- The language-neutral HTTP contract is authoritative; this is a thin Python wrapper. Do not change slice behaviour. If a real composition defect is found, fix it minimally and flag it for sign-off.
- No live Fortnox, no money, no VPS deploy, no Task 10 cutover. Providers are stubbed.
- No git push without explicit OK. Commit per task.
- Written-output rules: no AI-sounding prose, no emojis, no personal names, no hardcoded local absolute paths.

## How the slices compose (verified against the code)

- **One signing key / one JWKS:** identity holds the Ed25519 seed and serves `/.well-known/jwks.json`. Vault (`vault/app.py` `_build_app_from_env`) and bus (`bus/app.py` `_build_bus_app_from_env`) only get `KERNEL_JWKS_URL` and fetch the public document lazily via `cached_jwks_provider` (`vault/kernel_auth.py:55` — fetches on first call, not at construction).
- **One identity store:** all three open the same `KERNEL_IDENTITY_DB` sqlite. Identity writes principals/grants; vault and bus read grants for `authorize()` (`identity.authorize.collect_grants`).
- **One token, two audiences (the key fact):** the JWT `aud` is whatever audience the caller passes to `POST /auth/exchange` (`identity/app.py:31-38` → `identity/jwt_issuer.py` `build_claims` sets `"aud": audience` verbatim). pyjwt encodes a list `aud`, and `verify_island_jwt` (`identity/jwt_verify.py:28`) calls `pyjwt.decode(audience=<one>)`, which passes when the expected audience is a member of the token's `aud` list. So a single token minted with `aud=["vault","bus"]` satisfies vault (`audience="vault"`) AND bus (`audience="bus"`).
- **Audience binding:** the MCP credential's `audience` is a single `TEXT` column (`identity/store/server.py:23`), and `exchange()` rejects a mismatch only when `row.audience is not None` (`identity/exchange.py:17`). A credential issued **unbound** (`audience=None`) can therefore be exchanged for a multi-audience token with no slice change. This is the composition path the integration test exercises.

**Flagged for sign-off (the one design point):** the per-service docs describe `aud` as a single per-service URL. The combined deployment needs the multi-audience token model above. The chosen reconciliation is *unbound credential + list-audience exchange* — zero code change, grants still gate every action per service. Task 4 documents this. If TDD in Task 2 reveals the list-`aud` path actually breaks somewhere (it should not), stop, diagnose with systematic-debugging, apply the minimal fix in identity (the kernel, not a slice), and flag it before continuing.

## File Structure

- `tests/served_harness.py` — **modify.** Add `build_served_kernel_stack(tmp_path)` plus `ServedKernelStack`, `OTHER_ORG`, `OTHER_ORG_ACCESS_PATH`. Reuses every import already present in the file.
- `tests/test_kernel_stack_boot.py` — **create.** Smoke test: three services boot, one JWKS, both protected services gated.
- `tests/test_kernel_cross_slice.py` — **create.** The core proof + the org/grant-isolation negative.
- `tests/test_env_matrix_boot.py` — **create.** Drift guard: each `_build_*_from_env` reads exactly the documented env-var names.
- `scripts/__init__.py` — **create.** Make `scripts` importable from tests.
- `scripts/kernel_provision.py` — **create.** Provision one multi-service principal into the shared identity sqlite.
- `tests/test_kernel_provision.py` — **create.** Exercise the provisioning helper.
- `docs/kernel-integration.md` — **create.** Combined boot recipe + env matrix; the deploy reference.
- `docs/server-posture-vault.md`, `docs/event-bus.md` — **modify.** One cross-reference line each for the multi-audience token model.

---

### Task 1: Combined kernel stack harness + boot smoke test

**Files:**
- Modify: `tests/served_harness.py` (append after `build_served_bus_stack`, line ~226)
- Test: `tests/test_kernel_stack_boot.py`

**Interfaces:**
- Consumes: existing harness pieces — `bound_socket`, `ThreadedServer`, `CountingProvider`, `ORG`, `ACCOUNT`, `ACCESS_PATH`, and the already-imported `KeyManager`, `ServerIdentityStore`, `build_identity_app`, `issue_service_credential`, `grant_connection_use`, `grant_event_type_use`, `build_app`, `AccessService`, `VaultConfig`, `ServerStore`, `SecretboxKeyWrapper`, `Connection`, `Token`, `AppCred`, `make_kernel_auth`, `make_manage_authorizer`, `cached_jwks_provider`, `make_require_principal`, `collect_grants`, `ServerLedgerStore`, `SchemaRegistry`, `Dispatcher`, `InProcessDelivery`, `HttpPushDelivery`, `RoutingDelivery`, `BusService`, `build_bus_app`, `datetime`, `timezone`.
- Produces: `build_served_kernel_stack(tmp_path) -> ServedKernelStack`. `ServedKernelStack` fields: `identity_url: str`, `vault_url: str`, `bus_url: str`, `cred: str` (raw unbound credential), `seen: dict` (`{"n": int, "org": str|None}`, written by the in-process bus handler keyed `"counter"`), `identity_store: ServerIdentityStore`; methods `start()` / `stop()`. Module constants `OTHER_ORG = "magic-studios"` and `OTHER_ORG_ACCESS_PATH = "/connections/magic-studios%2Ffortnox%2F000000-0000/access-token"`.

- [ ] **Step 1: Write the failing test**

`tests/test_kernel_stack_boot.py`:

```python
import httpx

from tests.served_harness import build_served_kernel_stack, ACCESS_PATH


def test_three_services_boot_and_share_one_jwks(tmp_path):
    stack = build_served_kernel_stack(tmp_path)
    stack.start()
    try:
        jwks = httpx.get(f"{stack.identity_url}/.well-known/jwks.json", timeout=10).json()
        assert len(jwks["keys"]) == 1                 # one signing key
        assert jwks["keys"][0]["kid"] == "kid-kernel"
        # vault and bus are up and gated: no token -> 401
        assert httpx.post(f"{stack.vault_url}{ACCESS_PATH}", timeout=10).status_code == 401
        assert httpx.post(f"{stack.bus_url}/events", json={}, timeout=10).status_code == 401
    finally:
        stack.stop()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_kernel_stack_boot.py -v`
Expected: FAIL with `ImportError: cannot import name 'build_served_kernel_stack'`.

- [ ] **Step 3: Add the combined harness builder**

Append to `tests/served_harness.py`:

```python
OTHER_ORG = "magic-studios"
OTHER_ORG_ACCESS_PATH = "/connections/magic-studios%2Ffortnox%2F000000-0000/access-token"


@dataclass
class ServedKernelStack:
    identity_url: str
    vault_url: str
    bus_url: str
    cred: str
    seen: dict
    identity_store: ServerIdentityStore
    _identity_srv: ThreadedServer
    _vault_srv: ThreadedServer
    _bus_srv: ThreadedServer

    def start(self):
        self._identity_srv.start()
        self._vault_srv.start()
        self._bus_srv.start()

    def stop(self):
        self._bus_srv.stop()
        self._vault_srv.stop()
        self._identity_srv.stop()


def build_served_kernel_stack(tmp_path) -> ServedKernelStack:
    import time

    id_sock, id_port = bound_socket()
    vault_sock, vault_port = bound_socket()
    bus_sock, bus_port = bound_socket()
    identity_url = f"http://127.0.0.1:{id_port}"
    vault_url = f"http://127.0.0.1:{vault_port}"
    bus_url = f"http://127.0.0.1:{bus_port}"
    issuer = identity_url
    jwks_url = f"{identity_url}/.well-known/jwks.json"
    now = time.time()

    # ONE signing key, ONE identity store, ONE unbound service principal with both grants.
    km = KeyManager.generate("kid-kernel")
    ident = ServerIdentityStore(str(tmp_path / "identity.sqlite"))
    cred = issue_service_credential(
        ident, principal_id="prn_bk", display_name="bookkeeping", org_id=ORG,
        audience=None, now=now, expires_at=now + 3600)
    grant_connection_use(ident, principal_id="prn_bk", connection_id="conn_1",
                         granted_by="prn_owner", now=now)
    grant_event_type_use(ident, principal_id="prn_bk",
                         event_type="bookkeeping.voucher.posted", granted_by="prn_owner", now=now)
    identity_app = build_identity_app(store=ident, key_manager=km, issuer=issuer, now_fn=time.time)

    # vault wired to the shared identity (audience "vault")
    wrapper = SecretboxKeyWrapper(nacl.utils.random(32))
    vstore = ServerStore(f"sqlite:///{tmp_path}/vault.sqlite", wrapper)
    vstore.put_connection(Connection(
        id="conn_1", org=ORG, provider="fortnox", account=ACCOUNT, scopes=["bookkeeping"],
        app_cred_ref="fortnox", token=Token("FORTNOX_ACCESS", "REFRESH", now + 99999.0, "bookkeeping"),
        rotation="rotating", lease=None, created_by="prn_owner", created_at=0.0, updated_at=0.0))
    vstore.put_connection(Connection(
        id="conn_2", org=OTHER_ORG, provider="fortnox", account="000000-0000", scopes=["bookkeeping"],
        app_cred_ref="fortnox", token=Token("OTHER_ACCESS", "OTHER_REFRESH", now + 99999.0, "bookkeeping"),
        rotation="rotating", lease=None, created_by="prn_owner", created_at=0.0, updated_at=0.0))
    vcfg = VaultConfig(now_fn=time.time, http_post=lambda *a: {},
                       app_creds={"fortnox": AppCred("cid", "secret")}, state_hmac_key=b"k", skew=60)
    vservice = AccessService(vstore, {"fortnox": CountingProvider()}, vcfg)
    v_require, v_authorizer = make_kernel_auth(
        jwks_provider=cached_jwks_provider(jwks_url), audience="vault", issuer=issuer,
        now_fn=time.time, identity_store=ident, vault_store=vservice.store)
    v_manage = make_manage_authorizer(now_fn=time.time, identity_store=ident, vault_store=vservice.store)
    vault_app = build_app(vservice, require_principal=v_require, authorizer=v_authorizer,
                          manage_authorizer=v_manage)

    # bus wired to the same shared identity (audience "bus")
    bstore = ServerLedgerStore(f"sqlite:///{tmp_path}/bus.sqlite")
    reg = SchemaRegistry()
    reg.register("voucher/v1", {"type": "object", "required": ["voucherId"],
                                "properties": {"voucherId": {"type": "string"}},
                                "additionalProperties": False})
    seen = {"n": 0, "org": None}
    seen_lock = threading.Lock()
    deliv = InProcessDelivery()

    def handler(event):
        with seen_lock:
            seen["n"] += 1
            seen["org"] = event.org

    deliv.register("counter", handler)
    dispatcher = Dispatcher(bstore, RoutingDelivery(deliv, HttpPushDelivery()), now_fn=time.time)
    bservice = BusService(bstore, reg, dispatcher, now_fn=time.time,
                          now_iso_fn=lambda: datetime.now(timezone.utc).isoformat(),
                          grants_for=lambda pid: collect_grants(principal_id=pid, identity_store=ident))
    b_require = make_require_principal(
        jwks_provider=cached_jwks_provider(jwks_url), audience="bus", now_fn=time.time, issuer=issuer)
    bus_app = build_bus_app(bservice, require_principal=b_require)

    return ServedKernelStack(
        identity_url, vault_url, bus_url, cred, seen, ident,
        ThreadedServer(identity_app, id_sock),
        ThreadedServer(vault_app, vault_sock),
        ThreadedServer(bus_app, bus_sock))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_kernel_stack_boot.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/served_harness.py tests/test_kernel_stack_boot.py
git commit -m "test(kernel): combined identity+vault+bus stack harness and boot smoke test"
```

---

### Task 2: One token serves vault and bus (the core composition proof)

**Files:**
- Test: `tests/test_kernel_cross_slice.py`

**Interfaces:**
- Consumes: `build_served_kernel_stack`, `ACCESS_PATH`, `ORG` from `tests/served_harness`.
- Produces: nothing new; this task is a proof. It is also the defect-discovery gate for the multi-audience token path.

- [ ] **Step 1: Write the failing test**

`tests/test_kernel_cross_slice.py`:

```python
import httpx
import jwt as pyjwt

from tests.served_harness import build_served_kernel_stack, ACCESS_PATH, ORG


def _exchange(identity_url, cred, audience):
    r = httpx.post(f"{identity_url}/auth/exchange",
                   json={"opaque_token": cred, "audience": audience}, timeout=10)
    r.raise_for_status()
    return r.json()["access_token"]


def test_one_token_serves_vault_and_bus(tmp_path):
    stack = build_served_kernel_stack(tmp_path)
    stack.start()
    try:
        # ONE exchange -> ONE token carrying both audiences and one org
        token = _exchange(stack.identity_url, stack.cred, ["vault", "bus"])
        claims = pyjwt.decode(token, options={"verify_signature": False})
        assert {"vault", "bus"}.issubset(set(claims["aud"]))
        assert claims["org"] == ORG
        headers = {"Authorization": f"Bearer {token}"}

        # (a) vault: fetch an access token with that SAME token
        rv = httpx.post(f"{stack.vault_url}{ACCESS_PATH}", headers=headers, timeout=15)
        rv.raise_for_status()
        assert rv.json()["accessToken"]

        # (b) bus: subscribe, publish, consume with that SAME token
        httpx.post(f"{stack.bus_url}/subscriptions", headers=headers, json={
            "type": "bookkeeping.voucher.posted", "consumer": "smartcharge",
            "target": {"kind": "inprocess", "key": "counter"}, "grant_ref": "g"},
            timeout=10).raise_for_status()
        rb = httpx.post(f"{stack.bus_url}/events", headers=headers, json={
            "type": "bookkeeping.voucher.posted", "schema": "voucher/v1",
            "source": "bookkeeping", "trace": {"store": "bk", "ref": "r1"},
            "data": {"voucherId": "V-1"}, "id": "evt_xslice"}, timeout=10)
        rb.raise_for_status()
        assert rb.json()["deduped"] is False

        # org is consistent end to end: the consumed event was stamped with the token's org
        assert stack.seen["n"] == 1
        assert stack.seen["org"] == ORG
    finally:
        stack.stop()
```

- [ ] **Step 2: Run test to verify it fails (then confirm WHY)**

Run: `.venv/bin/pytest tests/test_kernel_cross_slice.py::test_one_token_serves_vault_and_bus -v`
Expected before the harness exists it would fail on import; with Task 1 merged it should drive real behaviour. If it fails on a 401 from vault or bus, that is the multi-audience composition defect — STOP and apply systematic-debugging. Expected outcome with the unbound-credential + list-audience path is PASS without any slice change. If a minimal identity fix is required, make it, flag it in the commit body, and get sign-off before proceeding.

- [ ] **Step 3: (Contingency only) minimal fix if list-`aud` is rejected**

No code change is expected. Only if Step 2 proves a real defect: fix it minimally inside identity (`identity/exchange.py` or `identity/jwt_issuer.py`), never inside a slice (`vault/`, `bus/`), keep the change additive, and record the defect + fix in the commit message.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_kernel_cross_slice.py::test_one_token_serves_vault_and_bus -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/test_kernel_cross_slice.py
git commit -m "test(kernel): one principal, one JWT proves vault+bus share identity and org"
```

---

### Task 3: Org / grant isolation is enforced through the shared identity

**Files:**
- Test: `tests/test_kernel_cross_slice.py` (add a second test)

**Interfaces:**
- Consumes: `build_served_kernel_stack`, `OTHER_ORG_ACCESS_PATH` from `tests/served_harness`; `_exchange` helper from the same test module.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_kernel_cross_slice.py`:

```python
from tests.served_harness import OTHER_ORG_ACCESS_PATH


def test_org_and_grant_scoping_enforced(tmp_path):
    stack = build_served_kernel_stack(tmp_path)
    stack.start()
    try:
        token = _exchange(stack.identity_url, stack.cred, ["vault", "bus"])
        headers = {"Authorization": f"Bearer {token}"}

        # vault: a connection in another org, no grant -> 403 (the principal cannot reach across orgs)
        r1 = httpx.post(f"{stack.vault_url}{OTHER_ORG_ACCESS_PATH}", headers=headers, timeout=10)
        assert r1.status_code == 403

        # bus: an event-type with no grant -> 403 (grant scoping flows through the shared identity)
        r2 = httpx.post(f"{stack.bus_url}/events", headers=headers, json={
            "type": "ungranted.type", "schema": "voucher/v1", "source": "bookkeeping",
            "trace": {"store": "bk", "ref": "r2"}, "data": {"voucherId": "V-2"}, "id": "evt_ng"},
            timeout=10)
        assert r2.status_code == 403
    finally:
        stack.stop()
```

- [ ] **Step 2: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_kernel_cross_slice.py::test_org_and_grant_scoping_enforced -v`
Expected: PASS. (`vault/app.py:25` maps `PermissionError` → HTTP 403; `bus` publish raises `AuthzDenied` → HTTP 403 before schema validation.)

- [ ] **Step 3: Commit**

```bash
git add tests/test_kernel_cross_slice.py
git commit -m "test(kernel): org and grant scoping enforced across the shared identity"
```

---

### Task 4: Env-matrix drift guard + reconcile the two service docs

**Files:**
- Test: `tests/test_env_matrix_boot.py`
- Modify: `docs/server-posture-vault.md`, `docs/event-bus.md`

**Interfaces:**
- Consumes: `identity.app._build_identity_app_from_env`, `vault.app._build_app_from_env`, `bus.app._build_bus_app_from_env`, `identity.tokens.b64url`.
- Produces: a test that fails if any service's `_build_*_from_env` stops reading a documented required env var under its documented name.

- [ ] **Step 1: Write the failing test**

`tests/test_env_matrix_boot.py`:

```python
import base64

import pytest

from identity.tokens import b64url
from identity.app import _build_identity_app_from_env
from vault.app import _build_app_from_env
from bus.app import _build_bus_app_from_env

VALID_SEED = b64url(b"\x00" * 32)          # KeyManager.from_seed expects b64url(32 bytes)
VALID_KEK = base64.b64encode(b"\x00" * 32).decode()  # VAULT_KEK expects base64(32 bytes)


def test_identity_requires_signing_seed(monkeypatch):
    monkeypatch.delenv("KERNEL_SIGNING_SEED", raising=False)
    monkeypatch.setenv("KERNEL_ISSUER", "https://id.example")
    with pytest.raises(RuntimeError, match="KERNEL_SIGNING_SEED"):
        _build_identity_app_from_env()


def test_identity_requires_issuer(monkeypatch):
    monkeypatch.setenv("KERNEL_SIGNING_SEED", VALID_SEED)
    monkeypatch.delenv("KERNEL_ISSUER", raising=False)
    with pytest.raises(KeyError, match="KERNEL_ISSUER"):
        _build_identity_app_from_env()


def test_vault_served_requires_kek(monkeypatch):
    monkeypatch.setenv("VAULT_REQUIRE_KERNEL", "1")
    monkeypatch.delenv("VAULT_KEK", raising=False)
    with pytest.raises(RuntimeError, match="VAULT_KEK"):
        _build_app_from_env()


def test_vault_served_requires_audience(monkeypatch, tmp_path):
    monkeypatch.setenv("VAULT_REQUIRE_KERNEL", "1")
    monkeypatch.setenv("VAULT_KEK", VALID_KEK)
    monkeypatch.setenv("VAULT_DB", f"sqlite:///{tmp_path}/vault.sqlite")
    monkeypatch.setenv("KERNEL_IDENTITY_DB", str(tmp_path / "identity.sqlite"))
    monkeypatch.setenv("KERNEL_JWKS_URL", "https://id.example/.well-known/jwks.json")
    monkeypatch.setenv("KERNEL_ISSUER", "https://id.example")
    monkeypatch.delenv("VAULT_AUDIENCE", raising=False)
    with pytest.raises(KeyError, match="VAULT_AUDIENCE"):
        _build_app_from_env()


def test_vault_served_requires_jwks_url(monkeypatch, tmp_path):
    monkeypatch.setenv("VAULT_REQUIRE_KERNEL", "1")
    monkeypatch.setenv("VAULT_KEK", VALID_KEK)
    monkeypatch.setenv("VAULT_DB", f"sqlite:///{tmp_path}/vault.sqlite")
    monkeypatch.setenv("KERNEL_IDENTITY_DB", str(tmp_path / "identity.sqlite"))
    monkeypatch.setenv("VAULT_AUDIENCE", "vault")
    monkeypatch.setenv("KERNEL_ISSUER", "https://id.example")
    monkeypatch.delenv("KERNEL_JWKS_URL", raising=False)
    with pytest.raises(KeyError, match="KERNEL_JWKS_URL"):
        _build_app_from_env()


def test_bus_requires_issuer(monkeypatch):
    monkeypatch.delenv("KERNEL_ISSUER", raising=False)
    with pytest.raises(KeyError, match="KERNEL_ISSUER"):
        _build_bus_app_from_env()


def test_bus_requires_audience(monkeypatch):
    monkeypatch.setenv("KERNEL_ISSUER", "https://id.example")
    monkeypatch.delenv("BUS_AUDIENCE", raising=False)
    with pytest.raises(KeyError, match="BUS_AUDIENCE"):
        _build_bus_app_from_env()
```

- [ ] **Step 2: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_env_matrix_boot.py -v`
Expected: PASS. (If any case raises a different error or names a different var, that is real drift — reconcile the code/doc and note it.)

- [ ] **Step 3: Reconcile the two service docs**

In `docs/server-posture-vault.md`, under the `VAULT_AUDIENCE` line, add:

```markdown
- A principal that also talks to the bus exchanges ONE token whose `aud` is the
  list of target service audiences (e.g. `["vault","bus"]`); the credential is
  issued unbound. See `docs/kernel-integration.md` for the combined model.
```

In `docs/event-bus.md`, under the `BUS_AUDIENCE` line, add:

```markdown
- A principal that also talks to the vault exchanges ONE token whose `aud` is the
  list of target service audiences (e.g. `["vault","bus"]`). See
  `docs/kernel-integration.md`.
```

- [ ] **Step 4: Commit**

```bash
git add tests/test_env_matrix_boot.py docs/server-posture-vault.md docs/event-bus.md
git commit -m "test(kernel): env-matrix drift guard; cross-reference multi-audience token model"
```

---

### Task 5: Combined boot recipe, provisioning helper, and deploy reference doc

**Files:**
- Create: `scripts/__init__.py` (empty)
- Create: `scripts/kernel_provision.py`
- Test: `tests/test_kernel_provision.py`
- Create: `docs/kernel-integration.md`

**Interfaces:**
- Consumes: `identity.store.server.ServerIdentityStore`, `identity.service_principal.issue_service_credential`, `identity.service_principal.grant_connection_use`, `bus.provisioning.grant_event_type_use`, `identity.authorize.collect_grants`.
- Produces: `scripts.kernel_provision.provision(store, *, principal_id, org_id, connection_id, event_type, now) -> str` (returns the raw credential) and a `main(argv)` CLI entry point.

- [ ] **Step 1: Write the failing test**

`tests/test_kernel_provision.py`:

```python
import time

from identity.store.server import ServerIdentityStore
from identity.authorize import collect_grants
from scripts.kernel_provision import provision


def test_provision_creates_principal_with_both_grants(tmp_path):
    store = ServerIdentityStore(str(tmp_path / "identity.sqlite"))
    cred = provision(store, principal_id="prn_x", org_id="caput-venti",
                     connection_id="conn_1", event_type="bookkeeping.voucher.posted",
                     now=time.time())
    assert isinstance(cred, str) and cred
    grants = collect_grants(principal_id="prn_x", identity_store=store)
    targets = {(g.target.kind, g.target.id) for g in grants}
    assert ("connection", "conn_1") in targets
    assert ("event-type", "bookkeeping.voucher.posted") in targets
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_kernel_provision.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'scripts.kernel_provision'`.

- [ ] **Step 3: Create the package marker and the provisioning helper**

`scripts/__init__.py`: empty file.

`scripts/kernel_provision.py`:

```python
"""Provision one service principal that can reach both the vault and the bus.

Reads KERNEL_IDENTITY_DB (the shared identity sqlite the served kernel uses),
issues an unbound service credential, and grants it connection-use + event-type
-use. Prints the raw credential ONCE to stdout. The raw credential is a secret:
capture it into the host secret store. It is never written to the repo or logs.
"""
from __future__ import annotations

import argparse
import os
import sys
import time

from identity.store.server import ServerIdentityStore
from identity.service_principal import issue_service_credential, grant_connection_use
from bus.provisioning import grant_event_type_use


def provision(store, *, principal_id, org_id, connection_id, event_type, now) -> str:
    cred = issue_service_credential(
        store, principal_id=principal_id, display_name=principal_id, org_id=org_id,
        audience=None, now=now, expires_at=None)
    grant_connection_use(store, principal_id=principal_id, connection_id=connection_id,
                         granted_by="prn_owner", now=now)
    grant_event_type_use(store, principal_id=principal_id, event_type=event_type,
                         granted_by="prn_owner", now=now)
    return cred


def main(argv) -> None:
    p = argparse.ArgumentParser(description="Provision a multi-service kernel principal")
    p.add_argument("--principal", required=True)
    p.add_argument("--org", required=True)
    p.add_argument("--connection", required=True)
    p.add_argument("--event-type", required=True)
    a = p.parse_args(argv)
    store = ServerIdentityStore(os.environ.get("KERNEL_IDENTITY_DB", "vault-store/identity.sqlite"))
    cred = provision(store, principal_id=a.principal, org_id=a.org,
                     connection_id=a.connection, event_type=a.event_type, now=time.time())
    sys.stdout.write(cred + "\n")


if __name__ == "__main__":
    main(sys.argv[1:])
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_kernel_provision.py -v`
Expected: PASS.

- [ ] **Step 5: Write the deploy reference doc**

`docs/kernel-integration.md`:

```markdown
# Kernel integration — combined boot reference

Three ASGI services compose into one kernel. Identity signs tokens and publishes
the public JWKS; vault and bus verify kernel JWTs offline against that JWKS and
read grants from the same identity sqlite. One signing key, one JWKS, one
identity store. This is the local multi-process boot reference for the upcoming
VPS deploy. The VPS deploy itself and the gated live-Fortnox cutover are out of
scope here — see `docs/server-posture-vault.md` for the gated cutover runbook.

## Secrets (crown jewels — host secret store / KMS only)

- `KERNEL_SIGNING_SEED` — base64url Ed25519 32-byte seed. Identity only.
- `VAULT_KEK` — base64 32-byte KEK. Vault only.

Generate locally for a throwaway dev kernel (do not commit the values):

    python -c "from identity.tokens import b64url; import os; print(b64url(os.urandom(32)))"   # KERNEL_SIGNING_SEED
    python -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"             # VAULT_KEK

The bus has no own secret; it reuses the served identity store for grant lookups.

## Env matrix

| Variable | identity | vault | bus | notes |
|---|:--:|:--:|:--:|---|
| `IDENTITY_BOOT` / `VAULT_BOOT` / `BUS_BOOT` | gate | gate | gate | set `=1` on the owning service |
| `KERNEL_SIGNING_SEED` | required | — | — | crown jewel |
| `KERNEL_KID` | default `kid-1` | — | — | JWT header `kid` |
| `KERNEL_ISSUER` | required | required | required | same value across all three |
| `KERNEL_JWKS_URL` | — | required | required | `<identity-url>/.well-known/jwks.json` |
| `KERNEL_IDENTITY_DB` | shared | shared | shared | identity writes; vault+bus read grants |
| `VAULT_BACKEND` | — | `server` | — | served single-writer store |
| `VAULT_REQUIRE_KERNEL` | — | `1` | — | turns on JWT + grant checking |
| `VAULT_KEK` | — | required | — | crown jewel |
| `VAULT_DB` | — | required | — | SQLAlchemy sqlite URL |
| `VAULT_AUDIENCE` | — | required | — | this vault's `aud` |
| `BUS_AUDIENCE` | — | — | required | this bus's `aud` |
| `BUS_DB` | — | — | required | SQLAlchemy sqlite URL |

`KERNEL_ISSUER`, `KERNEL_JWKS_URL`, and `KERNEL_IDENTITY_DB` use identical names
across all three services (verified by `tests/test_env_matrix_boot.py`).

## One token, two services

The JWT `aud` is the audience passed to `POST /auth/exchange`. A principal that
talks to both vault and bus exchanges ONCE for `aud: ["vault","bus"]`; pyjwt
verification passes when each service's single expected audience is a member of
that list. The service credential is issued unbound (`audience=None`) so the
exchange may request the audience list. Per-service grants (connection-use,
event-type-use) still gate every action.

## Bring the kernel up (three processes)

Shared env (identity URL fixed first so vault/bus can point `KERNEL_JWKS_URL` at it):

    export KERNEL_ISSUER="http://127.0.0.1:8081"
    export KERNEL_IDENTITY_DB="vault-store/identity.sqlite"
    export KERNEL_JWKS_URL="$KERNEL_ISSUER/.well-known/jwks.json"

Identity:

    IDENTITY_BOOT=1 KERNEL_SIGNING_SEED=<seed> \
      uvicorn identity.app:app --host 127.0.0.1 --port 8081

Vault:

    VAULT_BOOT=1 VAULT_BACKEND=server VAULT_REQUIRE_KERNEL=1 \
      VAULT_KEK=<kek> VAULT_DB="sqlite:///vault-store/vault.sqlite" VAULT_AUDIENCE="vault" \
      uvicorn vault.app:app --host 127.0.0.1 --port 8082

Bus:

    BUS_BOOT=1 BUS_AUDIENCE="bus" BUS_DB="sqlite:///vault-store/bus.sqlite" \
      uvicorn bus.app:app --host 127.0.0.1 --port 8083

## Provision a principal

After a connection exists in the vault, issue one principal that can reach both
services and capture the printed credential into the host secret store:

    python -m scripts.kernel_provision --principal prn_bk --org <org> \
      --connection <connection-id> --event-type bookkeeping.voucher.posted

## Proof

The combined posture is proven end to end by `tests/test_kernel_cross_slice.py`
(one principal → one JWT → vault access token + bus publish/consume, org
consistent) and `tests/test_kernel_stack_boot.py` (one JWKS shared by all three).
```

- [ ] **Step 6: Run the full suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: PASS (no regressions in the existing suite).

- [ ] **Step 7: Commit**

```bash
git add scripts/__init__.py scripts/kernel_provision.py tests/test_kernel_provision.py docs/kernel-integration.md
git commit -m "docs(kernel): combined boot reference, env matrix, and provisioning helper"
```

---

## Self-Review

**Spec coverage:**
- Combined local boot recipe (identity + vault + bus, one signing key, one JWKS, shared verification) → Task 5 doc + proven by Task 1.
- Cross-slice integration test over real sockets, providers stubbed, no Fortnox/money: one principal → one JWT → vault access token AND bus publish+consume, org consistent → Task 2.
- Org scoping consistent across both → Task 2 (positive) + Task 3 (negative isolation).
- Env/config drift check (issuer/audience/JWKS-URL naming + secret-var names consistent across two docs + three services; secret custody uniform, host-secret-store only) → Task 4 (executable drift guard) + Task 5 (env matrix + secret custody section).
- `docs/kernel-integration.md` combined boot + env matrix as deploy reference → Task 5.
- Out of scope respected: no VPS deploy, no Task 10, no live Fortnox, no new features, no slices 4/6/7. Slice internals untouched (only `tests/`, `scripts/`, `docs/`), with a flagged, sign-off-gated contingency for a minimal identity fix in Task 2 if the composition genuinely breaks.

**Placeholder scan:** none — every step carries real code or exact commands and expected output.

**Type consistency:** `build_served_kernel_stack` / `ServedKernelStack` / `provision` signatures and the `seen` dict shape are used identically across Tasks 1–5; constant names (`OTHER_ORG_ACCESS_PATH`, `ACCESS_PATH`, `ORG`) match the harness.
