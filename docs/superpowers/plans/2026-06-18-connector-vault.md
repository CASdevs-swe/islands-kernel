# Connector & Credential Vault — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One service that owns third-party OAuth credentials keyed by `(org, provider, account)`, hands out short-lived access tokens to any island over a language-neutral API, and refreshes rotating tokens under a single writer so two callers can never race Fortnox's rotating refresh token.

**Architecture:** A Python (FastAPI) HTTP service wrapping a provider-agnostic core. The core is split into: a data model, an envelope-encryption module (per-connection DEK wrapped by a backend-specific KEK), a `Store` interface with two implementations (LocalFileStore = age-wrapped file + atomic-file-create lease; ServerStore = SQL rows + DB optimistic-lock lease), a single-writer refresh orchestrator (double-checked locking around a lease), and per-provider refresh adapters (Fortnox confidential client first, Gmail second). Two thin libs (Python in-process+HTTP, Node HTTP) wrap the same contract. The provider HTTP boundary is injectable so unit tests never hit Fortnox.

**Tech Stack:** Python 3.11+, FastAPI, uvicorn, pytest, PyNaCl (secretbox for DEK→token and KEK→DEK on the server backend), the `age` binary behind an injectable subprocess seam (KEK wrap on the local backend), SQLite (ServerStore default; Postgres adapter seam), httpx (real provider transport). Node lib: TypeScript, no runtime deps beyond `fetch`, vitest for tests.

## Global Constraints

- **Working repo:** `/Users/samuelkr/Documents/GitHub/other/islands-kernel` (github.com/CASdevs-swe/islands-kernel). Do all work on the currently checked-out branch; never create a branch.
- **Connections are keyed by `org` from day one** (`(org, provider, account)`), even though real identity is slice 2. Use a minimal principal/org stub so slice 2 slots in with no data migration.
- **The provider network boundary is injectable.** No unit test makes a real Fortnox or Google call. Real HTTP only behind a default-injected transport.
- **The access-token response NEVER contains the refresh token.** `{accessToken, scope, expiresAt}` only.
- **App client secrets are host/server-side only** — never in a response body, log line, tool result, or browser. Fortnox is a confidential client (Basic auth on the token endpoint, no PKCE).
- **The access log is metadata only** — `{connectionId, principalId, island, op, at}`. Never tokens, PII, or amounts.
- **Do NOT touch live credentials.** Tasks 1–18 build and prove the vault against fixtures only. The bookkeeping/research adapters (Tasks 19–20) are built against fixtures. The live cutover (Task 21) is a separate, explicitly-gated step that must NOT run until Sam approves it, and runs with writes paused.
- **Never commit or push token state.** `.gitignore` must exclude every token/secret/age-key/local-store path before any code lands. No `git push` without explicit OK.
- **Writing-artifact rules:** no AI-sounding prose, no emojis, no personal names, no hardcoded absolute local paths in committed code (use env vars / config). Plan and code comments read like a developer wrote them.
- **Fortnox facts (verified from existing code):** token endpoint `https://apps.fortnox.se/oauth-v1/token`; refresh = `POST` form `grant_type=refresh_token&refresh_token=…` with `Authorization: Basic base64(client_id:client_secret)`; response `{access_token, refresh_token, expires_in, scope}`; `expires_at = now + expires_in`; refresh skew 60s; `account = "559401-5157"` (Caput Venti), `org = "caput-venti"`. Token JSON shape on disk today: `{access_token, refresh_token, expires_at(float), scope}`.

---

## File Structure

```
islands-kernel/
  pyproject.toml                      # service + core package "vault"
  README.md
  CLAUDE.md                           # repo guide for future sessions
  .gitignore                          # excludes all token/secret/store state
  vault/
    __init__.py
    model.py                          # Connection, Grant, AccessLog, Token, enums + (de)serialization
    crypto.py                         # Envelope: KeyWrapper interface, AgeKeyWrapper, SecretboxKeyWrapper, seal/open
    config.py                         # env-driven config: backend select, KEK source, app-cred refs, state HMAC key
    store/
      __init__.py
      base.py                         # Store ABC + LeaseResult; key helpers
      memory.py                       # InMemoryStore (test double for upper layers)
      local_file.py                   # LocalFileStore: age-wrapped JSON file + atomic-file-create lease
      server.py                       # ServerStore: SQL rows + DB optimistic-lock lease (SQLite default)
    providers/
      __init__.py
      base.py                         # Provider ABC: refresh(conn, http_post) -> Token; rotation kind; connect helpers
      fortnox.py                      # Fortnox confidential-client provider
      gmail.py                        # Gmail (google) rotating provider
    refresh.py                        # single-writer refresh orchestrator (double-checked lease)
    access.py                         # AccessService: get_access_token / connect / grant / list / revoke
    grants.py                         # grant checks: require_use / require_manage
    app.py                            # FastAPI app mapping routes -> AccessService
  libs/
    python/
      pyproject.toml
      islands_vault/
        __init__.py                   # get_access_token(...) public lib API
        client.py                     # InProcessTransport + HttpTransport
    node/
      package.json
      tsconfig.json
      src/index.ts                    # getAccessToken({org,provider,account}) over HTTP
      test/vault.test.ts
  tests/
    conftest.py                       # fixtures: fake providers, fixture tokens, both stores parametrized
    test_model.py
    test_crypto.py
    test_store_lease.py
    test_backend_parity.py
    test_refresh_single_writer.py     # THE core-correctness proof
    test_access_token.py              # never leaks refresh token; skew refresh
    test_grants.py
    test_access_log.py
    test_revoke_zeroize.py
    test_fortnox_provider.py
    test_gmail_provider.py
    test_connect_oauth.py
    test_api.py                       # FastAPI TestClient end-to-end with injected fakes
    test_lib_python.py
  migration/                          # built but NOT wired live until Task 21 is approved
    bookkeeping_adapter.md            # exact diff for bookkeeping-engine (applied in its own repo)
    research_adapter.md               # exact diff for research-engine
    cutover_runbook.md                # the gated live-import procedure, writes paused
```

---

## Task 1: Repo scaffold

**Files:**
- Create: `pyproject.toml`, `README.md`, `CLAUDE.md`, `.gitignore`
- Create: `vault/__init__.py`, `tests/conftest.py`
- Test: `tests/test_smoke.py`

**Interfaces:**
- Consumes: nothing.
- Produces: importable package `vault` (version string `vault.__version__`); pytest runs green.

- [ ] **Step 1: Write `.gitignore` first (before any secret can land)**

```
# secrets & token state — never commit
*.age
*.key
*.local.json
.env
.env.*
vault-store/
*.sqlite
*.sqlite3
__pycache__/
*.pyc
.pytest_cache/
node_modules/
dist/
.venv/
```

- [ ] **Step 2: Write `pyproject.toml`**

```toml
[project]
name = "islands-kernel-vault"
version = "0.1.0"
description = "Connector & credential vault — islands platform slice 1"
requires-python = ">=3.11"
dependencies = [
    "fastapi>=0.111",
    "uvicorn>=0.30",
    "pynacl>=1.5",
    "httpx>=0.27",
]

[project.optional-dependencies]
dev = ["pytest>=8", "pytest-asyncio>=0.23"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["."]
```

- [ ] **Step 3: Write `vault/__init__.py`**

```python
__version__ = "0.1.0"
```

- [ ] **Step 4: Write `tests/conftest.py` (placeholder, filled by later tasks)**

```python
# Shared fixtures are added by later tasks. Kept importable from task 1.
```

- [ ] **Step 5: Write `tests/test_smoke.py`**

```python
import vault


def test_package_imports():
    assert vault.__version__ == "0.1.0"
```

- [ ] **Step 6: Write `README.md` and `CLAUDE.md`**

`README.md`: one paragraph stating this is the islands-kernel, slice 1 = connector/credential vault, pointing at `docs/superpowers/plans/2026-06-18-connector-vault.md` and `../islands-platform/specs/2026-06-18-connector-vault-design.md`. `CLAUDE.md`: note the language-neutral HTTP contract is authoritative, the libs are thin wrappers, the provider boundary is injectable, never commit token state, work on the current branch.

- [ ] **Step 7: Create venv, install, run**

Run: `python3 -m venv .venv && .venv/bin/pip install -e ".[dev]" && .venv/bin/pytest tests/test_smoke.py -v`
Expected: PASS, 1 test.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "scaffold islands-kernel vault package"
```

---

## Task 2: Data model

**Files:**
- Create: `vault/model.py`
- Test: `tests/test_model.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `Token(access_token: str, refresh_token: str, expires_at: float, scope: str)` with `is_expired(self, skew: int = 60, now: float|None = None) -> bool` and `to_dict()/from_dict()`.
  - `Rotation` = `Literal["rotating", "static"]`.
  - `Access` = `Literal["use", "manage"]`.
  - `ConnKey(org: str, provider: str, account: str)` frozen dataclass with `.as_str() -> "org/provider/account"`.
  - `Connection(id, org, provider, account, scopes: list[str], app_cred_ref: str, token: Token|None, rotation, lease: Lease|None, created_by, created_at, updated_at)` with `.key -> ConnKey`, `to_record()/from_record()` (token excluded from record — stored sealed separately).
  - `Lease(holder: str, until: float)`.
  - `ConnectionGrant(connection_id, principal_id, access, scopes_subset: list[str]|None, granted_by, granted_at)`.
  - `ConnectionAccessLog(connection_id, principal_id, island, op, at)`.
  - `new_id(prefix: str, seed: str) -> str` (deterministic-from-seed id; NO time/random — `Math.random`/`Date.now` equivalents are unavailable; ids are `prefix_` + sha256(seed)[:16]).

- [ ] **Step 1: Write the failing test**

```python
from vault.model import Token, Connection, ConnKey, ConnectionGrant, new_id


def test_token_expiry_skew():
    t = Token(access_token="a", refresh_token="r", expires_at=1000.0, scope="s")
    assert t.is_expired(skew=60, now=950.0) is True      # 950+60 >= 1000
    assert t.is_expired(skew=60, now=900.0) is False     # 900+60 < 1000


def test_token_roundtrip():
    t = Token("a", "r", 1000.0, "s")
    assert Token.from_dict(t.to_dict()) == t


def test_connection_record_excludes_token():
    c = Connection(
        id="conn_x", org="caput-venti", provider="fortnox", account="559401-5157",
        scopes=["bookkeeping"], app_cred_ref="fortnox", token=Token("a", "r", 1.0, "s"),
        rotation="rotating", lease=None, created_by="stub", created_at=0.0, updated_at=0.0,
    )
    rec = c.to_record()
    assert "token" not in rec and "a" not in str(rec) and "r" not in str(rec)
    assert c.key == ConnKey("caput-venti", "fortnox", "559401-5157")


def test_new_id_deterministic_no_clock():
    assert new_id("conn", "caput-venti/fortnox/559401-5157") == new_id("conn", "caput-venti/fortnox/559401-5157")
    assert new_id("conn", "a").startswith("conn_")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_model.py -v`
Expected: FAIL with `ModuleNotFoundError: vault.model`.

- [ ] **Step 3: Write minimal implementation**

```python
from __future__ import annotations
import hashlib
from dataclasses import dataclass, field
from typing import Literal, Optional

Rotation = Literal["rotating", "static"]
Access = Literal["use", "manage"]


def new_id(prefix: str, seed: str) -> str:
    return f"{prefix}_{hashlib.sha256(seed.encode()).hexdigest()[:16]}"


@dataclass(frozen=True)
class ConnKey:
    org: str
    provider: str
    account: str

    def as_str(self) -> str:
        return f"{self.org}/{self.provider}/{self.account}"


@dataclass
class Token:
    access_token: str
    refresh_token: str
    expires_at: float
    scope: str

    def is_expired(self, skew: int = 60, now: Optional[float] = None) -> bool:
        if now is None:
            raise ValueError("now must be supplied explicitly (no implicit clock)")
        return now + skew >= self.expires_at

    def to_dict(self) -> dict:
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "expires_at": self.expires_at,
            "scope": self.scope,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Token":
        return cls(d["access_token"], d["refresh_token"], float(d["expires_at"]), d.get("scope", ""))


@dataclass
class Lease:
    holder: str
    until: float


@dataclass
class Connection:
    id: str
    org: str
    provider: str
    account: str
    scopes: list[str]
    app_cred_ref: str
    token: Optional[Token]
    rotation: Rotation
    lease: Optional[Lease]
    created_by: str
    created_at: float
    updated_at: float

    @property
    def key(self) -> ConnKey:
        return ConnKey(self.org, self.provider, self.account)

    def to_record(self) -> dict:
        # token is stored sealed, separately — never in the plaintext record
        return {
            "id": self.id, "org": self.org, "provider": self.provider,
            "account": self.account, "scopes": list(self.scopes),
            "app_cred_ref": self.app_cred_ref, "rotation": self.rotation,
            "created_by": self.created_by, "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_record(cls, rec: dict, token: Optional[Token] = None, lease: Optional[Lease] = None) -> "Connection":
        return cls(
            id=rec["id"], org=rec["org"], provider=rec["provider"], account=rec["account"],
            scopes=list(rec["scopes"]), app_cred_ref=rec["app_cred_ref"], token=token,
            rotation=rec["rotation"], lease=lease, created_by=rec["created_by"],
            created_at=rec["created_at"], updated_at=rec["updated_at"],
        )


@dataclass
class ConnectionGrant:
    connection_id: str
    principal_id: str
    access: Access
    scopes_subset: Optional[list[str]]
    granted_by: str
    granted_at: float


@dataclass
class ConnectionAccessLog:
    connection_id: str
    principal_id: str
    island: str
    op: str
    at: float
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_model.py -v`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add vault/model.py tests/test_model.py
git commit -m "add vault data model (Connection/Grant/AccessLog/Token)"
```

---

## Task 3: Envelope encryption

**Files:**
- Create: `vault/crypto.py`
- Test: `tests/test_crypto.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `Envelope(wrapped_dek: bytes, nonce: bytes, ciphertext: bytes)` with `to_blob()->bytes` / `from_blob(bytes)` (length-prefixed binary).
  - `KeyWrapper` ABC: `wrap(dek: bytes) -> bytes`, `unwrap(blob: bytes) -> bytes`.
  - `SecretboxKeyWrapper(kek: bytes)` — server backend KEK wrap (NaCl secretbox).
  - `AgeKeyWrapper(identity: str, recipient: str, runner: AgeRunner)` — local backend KEK wrap via the `age` binary behind an injectable `AgeRunner` callable seam (mirrors bookkeeping's `FakeAge` test pattern).
  - `seal_token(token: Token, wrapper: KeyWrapper, gen_dek=...) -> bytes` and `open_token(blob: bytes, wrapper: KeyWrapper) -> Token`. DEK is a fresh 32-byte key per seal; token JSON is sealed with secretbox under the DEK; the DEK is wrapped by the wrapper.
  - `AgeRunner = Callable[[list[str], bytes | None], bytes]` (argv, stdin) -> stdout.

- [ ] **Step 1: Write the failing test**

```python
import nacl.utils
import pytest
from vault.model import Token
from vault.crypto import SecretboxKeyWrapper, seal_token, open_token, Envelope


def test_seal_open_roundtrip_secretbox():
    kek = nacl.utils.random(32)
    w = SecretboxKeyWrapper(kek)
    t = Token("acc", "ref", 123.0, "scope")
    blob = seal_token(t, w)
    assert open_token(blob, w) == t


def test_ciphertext_hides_plaintext():
    w = SecretboxKeyWrapper(nacl.utils.random(32))
    blob = seal_token(Token("SECRETACCESS", "SECRETREFRESH", 1.0, "s"), w)
    assert b"SECRETACCESS" not in blob and b"SECRETREFRESH" not in blob


def test_wrong_kek_fails():
    t = Token("a", "r", 1.0, "s")
    blob = seal_token(t, SecretboxKeyWrapper(nacl.utils.random(32)))
    with pytest.raises(Exception):
        open_token(blob, SecretboxKeyWrapper(nacl.utils.random(32)))


def test_envelope_blob_roundtrip():
    e = Envelope(wrapped_dek=b"\x01\x02", nonce=b"\x03" * 24, ciphertext=b"\x04\x05\x06")
    assert Envelope.from_blob(e.to_blob()) == e


def test_age_wrapper_uses_injected_runner():
    from vault.crypto import AgeKeyWrapper
    calls = []

    def fake_runner(argv, stdin):
        calls.append(argv)
        if "-r" in argv:        # encrypt: return a fake ciphertext that embeds the dek
            return b"AGE[" + (stdin or b"") + b"]"
        return (stdin or b"")[4:-1]      # decrypt: strip the AGE[ ... ] wrapper

    w = AgeKeyWrapper(identity="ID", recipient="RCPT", runner=fake_runner)
    dek = b"k" * 32
    assert w.unwrap(w.wrap(dek)) == dek
    assert any("-r" in c for c in calls)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_crypto.py -v`
Expected: FAIL with `ModuleNotFoundError: vault.crypto`.

- [ ] **Step 3: Write minimal implementation**

```python
from __future__ import annotations
import json
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable, Optional

import nacl.secret
import nacl.utils

from vault.model import Token

AgeRunner = Callable[[list[str], Optional[bytes]], bytes]


@dataclass
class Envelope:
    wrapped_dek: bytes
    nonce: bytes
    ciphertext: bytes

    def to_blob(self) -> bytes:
        parts = [self.wrapped_dek, self.nonce, self.ciphertext]
        return b"".join(struct.pack(">I", len(p)) + p for p in parts)

    @classmethod
    def from_blob(cls, blob: bytes) -> "Envelope":
        out, i = [], 0
        for _ in range(3):
            (n,) = struct.unpack(">I", blob[i:i + 4]); i += 4
            out.append(blob[i:i + n]); i += n
        return cls(*out)


class KeyWrapper(ABC):
    @abstractmethod
    def wrap(self, dek: bytes) -> bytes: ...
    @abstractmethod
    def unwrap(self, blob: bytes) -> bytes: ...


class SecretboxKeyWrapper(KeyWrapper):
    def __init__(self, kek: bytes):
        if len(kek) != 32:
            raise ValueError("KEK must be 32 bytes")
        self._box = nacl.secret.SecretBox(kek)

    def wrap(self, dek: bytes) -> bytes:
        return bytes(self._box.encrypt(dek))

    def unwrap(self, blob: bytes) -> bytes:
        return bytes(self._box.decrypt(blob))


class AgeKeyWrapper(KeyWrapper):
    """Wraps the DEK with the `age` binary. Runner seam keeps it injectable in tests."""
    def __init__(self, identity: str, recipient: str, runner: AgeRunner):
        self._identity = identity
        self._recipient = recipient
        self._run = runner

    def wrap(self, dek: bytes) -> bytes:
        return self._run(["age", "-r", self._recipient, "-o", "-"], dek)

    def unwrap(self, blob: bytes) -> bytes:
        return self._run(["age", "-d", "-i", self._identity], blob)


def seal_token(token: Token, wrapper: KeyWrapper, gen_dek: Callable[[], bytes] = lambda: nacl.utils.random(32)) -> bytes:
    dek = gen_dek()
    box = nacl.secret.SecretBox(dek)
    sealed = box.encrypt(json.dumps(token.to_dict()).encode())
    env = Envelope(wrapped_dek=wrapper.wrap(dek), nonce=sealed.nonce, ciphertext=sealed.ciphertext)
    return env.to_blob()


def open_token(blob: bytes, wrapper: KeyWrapper) -> Token:
    env = Envelope.from_blob(blob)
    dek = wrapper.unwrap(env.wrapped_dek)
    box = nacl.secret.SecretBox(dek)
    plain = box.decrypt(env.nonce + env.ciphertext)
    return Token.from_dict(json.loads(plain))
```

Note: `nacl.secret.SecretBox.encrypt` returns an `EncryptedMessage` exposing `.nonce` and `.ciphertext`; `decrypt` accepts `nonce + ciphertext`. The real `age` runner (production) is wired in `config.py` (Task 5/6 builders); here only the seam exists.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_crypto.py -v`
Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```bash
git add vault/crypto.py tests/test_crypto.py
git commit -m "add envelope encryption (DEK + KEK wrappers, age seam)"
```

---

## Task 4: Store interface + in-memory test double

**Files:**
- Create: `vault/store/__init__.py`, `vault/store/base.py`, `vault/store/memory.py`
- Test: folded into Task 5/7 parity tests (no standalone test — InMemoryStore is a test fixture; its behavior is asserted by the parity suite that runs against it implicitly via the same contract).

**Interfaces:**
- Consumes: `vault.model`.
- Produces:
  - `Store` ABC:
    - `put_connection(conn: Connection) -> None` (writes record + sealed token via the store's wrapper)
    - `get_connection(key: ConnKey) -> Connection | None` (returns with decrypted token populated)
    - `list_connections(org: str, provider: str | None) -> list[Connection]`
    - `write_token(key: ConnKey, token: Token, now: float) -> None`
    - `acquire_lease(key: ConnKey, holder: str, until: float, now: float) -> bool`
    - `release_lease(key: ConnKey, holder: str) -> None`
    - `lease_held(key: ConnKey, now: float) -> bool`
    - `delete_connection(key: ConnKey) -> None` (zeroizes sealed token)
    - `add_grant(grant) -> None`, `get_grants(connection_id) -> list[ConnectionGrant]`
    - `append_log(entry: ConnectionAccessLog) -> None`, `read_log(connection_id) -> list[ConnectionAccessLog]`
  - `InMemoryStore(Store)` — dict-backed, for upper-layer unit tests. Uses no encryption (stores `Token` directly) but honors the lease contract exactly.

- [ ] **Step 1: Write `vault/store/base.py`**

```python
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Optional
from vault.model import Connection, ConnKey, ConnectionGrant, ConnectionAccessLog, Token


class Store(ABC):
    @abstractmethod
    def put_connection(self, conn: Connection) -> None: ...
    @abstractmethod
    def get_connection(self, key: ConnKey) -> Optional[Connection]: ...
    @abstractmethod
    def list_connections(self, org: str, provider: Optional[str]) -> list[Connection]: ...
    @abstractmethod
    def write_token(self, key: ConnKey, token: Token, now: float) -> None: ...
    @abstractmethod
    def acquire_lease(self, key: ConnKey, holder: str, until: float, now: float) -> bool: ...
    @abstractmethod
    def release_lease(self, key: ConnKey, holder: str) -> None: ...
    @abstractmethod
    def lease_held(self, key: ConnKey, now: float) -> bool: ...
    @abstractmethod
    def delete_connection(self, key: ConnKey) -> None: ...
    @abstractmethod
    def add_grant(self, grant: ConnectionGrant) -> None: ...
    @abstractmethod
    def get_grants(self, connection_id: str) -> list[ConnectionGrant]: ...
    @abstractmethod
    def append_log(self, entry: ConnectionAccessLog) -> None: ...
    @abstractmethod
    def read_log(self, connection_id: str) -> list[ConnectionAccessLog]: ...
```

- [ ] **Step 2: Write `vault/store/memory.py`**

```python
from __future__ import annotations
import threading
from typing import Optional
from vault.model import Connection, ConnKey, ConnectionGrant, ConnectionAccessLog, Token, Lease
from vault.store.base import Store


class InMemoryStore(Store):
    def __init__(self):
        self._conns: dict[str, Connection] = {}
        self._leases: dict[str, Lease] = {}
        self._grants: dict[str, list[ConnectionGrant]] = {}
        self._logs: dict[str, list[ConnectionAccessLog]] = {}
        self._mu = threading.Lock()

    def put_connection(self, conn):
        with self._mu:
            self._conns[conn.key.as_str()] = conn

    def get_connection(self, key):
        with self._mu:
            return self._conns.get(key.as_str())

    def list_connections(self, org, provider):
        with self._mu:
            return [c for c in self._conns.values()
                    if c.org == org and (provider is None or c.provider == provider)]

    def write_token(self, key, token, now):
        with self._mu:
            c = self._conns[key.as_str()]
            c.token = token
            c.updated_at = now

    def acquire_lease(self, key, holder, until, now):
        with self._mu:
            cur = self._leases.get(key.as_str())
            if cur is not None and cur.until > now:
                return False
            self._leases[key.as_str()] = Lease(holder=holder, until=until)
            return True

    def release_lease(self, key, holder):
        with self._mu:
            cur = self._leases.get(key.as_str())
            if cur is not None and cur.holder == holder:
                del self._leases[key.as_str()]

    def lease_held(self, key, now):
        with self._mu:
            cur = self._leases.get(key.as_str())
            return cur is not None and cur.until > now

    def delete_connection(self, key):
        with self._mu:
            c = self._conns.pop(key.as_str(), None)
            if c is not None and c.token is not None:
                c.token = Token("", "", 0.0, "")   # zeroize in-memory copy
            self._leases.pop(key.as_str(), None)

    def add_grant(self, grant):
        with self._mu:
            self._grants.setdefault(grant.connection_id, []).append(grant)

    def get_grants(self, connection_id):
        with self._mu:
            return list(self._grants.get(connection_id, []))

    def append_log(self, entry):
        with self._mu:
            self._logs.setdefault(entry.connection_id, []).append(entry)

    def read_log(self, connection_id):
        with self._mu:
            return list(self._logs.get(connection_id, []))
```

- [ ] **Step 3: Write `vault/store/__init__.py`**

```python
from vault.store.base import Store
from vault.store.memory import InMemoryStore

__all__ = ["Store", "InMemoryStore"]
```

- [ ] **Step 4: Sanity-run import**

Run: `.venv/bin/python -c "from vault.store import Store, InMemoryStore; print('ok')"`
Expected: prints `ok`.

- [ ] **Step 5: Commit**

```bash
git add vault/store/__init__.py vault/store/base.py vault/store/memory.py
git commit -m "add Store interface + in-memory test double"
```

---

## Task 5: LocalFileStore (age-wrapped file + atomic-file lease)

**Files:**
- Create: `vault/store/local_file.py`
- Test: `tests/test_store_lease.py` (local portion)

**Interfaces:**
- Consumes: `vault.store.base.Store`, `vault.crypto` (`KeyWrapper`, `seal_token`, `open_token`).
- Produces: `LocalFileStore(root: Path, wrapper: KeyWrapper)` implementing `Store`. Layout under `root`: `connections/<org>/<provider>/<account>.json` (plaintext record), `.../<account>.token.age` (sealed token blob), `.../<account>.lock` (atomic-create lease file holding `holder\nuntil`), `grants/<connection_id>.jsonl`, `logs/<connection_id>.jsonl`. Lease acquire = `os.open(O_CREAT|O_EXCL|O_WRONLY)`; if the file exists, read `until`, and if expired, steal by rewriting; else fail.

- [ ] **Step 1: Write the failing test**

```python
import nacl.utils
from pathlib import Path
from vault.crypto import SecretboxKeyWrapper
from vault.model import Connection, ConnKey, Token
from vault.store.local_file import LocalFileStore


def _store(tmp_path) -> LocalFileStore:
    return LocalFileStore(root=Path(tmp_path), wrapper=SecretboxKeyWrapper(nacl.utils.random(32)))


def _conn():
    return Connection(id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
                      scopes=["s"], app_cred_ref="fortnox", token=Token("a", "r", 1000.0, "s"),
                      rotation="rotating", lease=None, created_by="stub", created_at=0.0, updated_at=0.0)


def test_put_get_token_roundtrip(tmp_path):
    s = _store(tmp_path); s.put_connection(_conn())
    got = s.get_connection(ConnKey("caput-venti", "fortnox", "559401-5157"))
    assert got.token == Token("a", "r", 1000.0, "s")


def test_token_file_is_encrypted_on_disk(tmp_path):
    s = _store(tmp_path); s.put_connection(_conn())
    blob = (Path(tmp_path) / "connections/caput-venti/fortnox/559401-5157.token.age").read_bytes()
    assert b"\"a\"" not in blob and b"refresh" not in blob


def test_lease_is_exclusive(tmp_path):
    s = _store(tmp_path); s.put_connection(_conn())
    k = ConnKey("caput-venti", "fortnox", "559401-5157")
    assert s.acquire_lease(k, "h1", until=2000.0, now=1000.0) is True
    assert s.acquire_lease(k, "h2", until=2000.0, now=1000.0) is False   # h1 holds it
    s.release_lease(k, "h1")
    assert s.acquire_lease(k, "h2", until=2000.0, now=1000.0) is True    # now free


def test_expired_lease_can_be_stolen(tmp_path):
    s = _store(tmp_path); s.put_connection(_conn())
    k = ConnKey("caput-venti", "fortnox", "559401-5157")
    assert s.acquire_lease(k, "h1", until=1500.0, now=1000.0) is True
    assert s.acquire_lease(k, "h2", until=3000.0, now=2000.0) is True    # h1's lease expired at 1500
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_store_lease.py -v`
Expected: FAIL with `ModuleNotFoundError: vault.store.local_file`.

- [ ] **Step 3: Write minimal implementation**

```python
from __future__ import annotations
import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from vault.crypto import KeyWrapper, seal_token, open_token
from vault.model import (Connection, ConnKey, ConnectionGrant, ConnectionAccessLog, Token)
from vault.store.base import Store


class LocalFileStore(Store):
    def __init__(self, root: Path, wrapper: KeyWrapper):
        self.root = Path(root)
        self.wrapper = wrapper

    def _dir(self, key: ConnKey) -> Path:
        return self.root / "connections" / key.org / key.provider

    def _rec_path(self, key): return self._dir(key) / f"{key.account}.json"
    def _tok_path(self, key): return self._dir(key) / f"{key.account}.token.age"
    def _lock_path(self, key): return self._dir(key) / f"{key.account}.lock"

    def put_connection(self, conn: Connection) -> None:
        self._dir(conn.key).mkdir(parents=True, exist_ok=True)
        self._rec_path(conn.key).write_text(json.dumps(conn.to_record()))
        if conn.token is not None:
            self._write_sealed(conn.key, conn.token)

    def _write_sealed(self, key: ConnKey, token: Token) -> None:
        p = self._tok_path(key)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, seal_token(token, self.wrapper))
        finally:
            os.close(fd)

    def get_connection(self, key: ConnKey) -> Optional[Connection]:
        rp = self._rec_path(key)
        if not rp.exists():
            return None
        rec = json.loads(rp.read_text())
        token = None
        if self._tok_path(key).exists():
            token = open_token(self._tok_path(key).read_bytes(), self.wrapper)
        return Connection.from_record(rec, token=token)

    def list_connections(self, org, provider):
        base = self.root / "connections" / org
        out = []
        if not base.exists():
            return out
        for prov_dir in base.iterdir():
            if provider is not None and prov_dir.name != provider:
                continue
            for rec in prov_dir.glob("*.json"):
                acct = rec.stem
                out.append(self.get_connection(ConnKey(org, prov_dir.name, acct)))
        return out

    def write_token(self, key, token, now):
        self._write_sealed(key, token)
        rec = json.loads(self._rec_path(key).read_text())
        rec["updated_at"] = now
        self._rec_path(key).write_text(json.dumps(rec))

    def acquire_lease(self, key, holder, until, now):
        self._dir(key).mkdir(parents=True, exist_ok=True)
        p = self._lock_path(key)
        try:
            fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.write(fd, f"{holder}\n{until}".encode()); os.close(fd)
            return True
        except FileExistsError:
            try:
                cur_until = float(p.read_text().split("\n", 1)[1])
            except (OSError, IndexError, ValueError):
                cur_until = 0.0
            if cur_until > now:
                return False
            # expired -> steal atomically by replacing contents
            p.write_text(f"{holder}\n{until}")
            return True

    def release_lease(self, key, holder):
        p = self._lock_path(key)
        try:
            if p.exists() and p.read_text().split("\n", 1)[0] == holder:
                p.unlink()
        except OSError:
            pass

    def lease_held(self, key, now):
        p = self._lock_path(key)
        if not p.exists():
            return False
        try:
            return float(p.read_text().split("\n", 1)[1]) > now
        except (OSError, IndexError, ValueError):
            return False

    def delete_connection(self, key):
        for p in (self._tok_path(key), self._rec_path(key), self._lock_path(key)):
            if p.exists():
                if p == self._tok_path(key):
                    # overwrite sealed bytes before unlink
                    size = p.stat().st_size
                    with open(p, "wb") as f:
                        f.write(b"\x00" * size); f.flush(); os.fsync(f.fileno())
                p.unlink()

    def _jsonl(self, sub, cid): return (self.root / sub / f"{cid}.jsonl")

    def add_grant(self, grant):
        p = self._jsonl("grants", grant.connection_id); p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a") as f:
            f.write(json.dumps(asdict(grant)) + "\n")

    def get_grants(self, connection_id):
        p = self._jsonl("grants", connection_id)
        if not p.exists():
            return []
        return [ConnectionGrant(**json.loads(line)) for line in p.read_text().splitlines() if line]

    def append_log(self, entry):
        p = self._jsonl("logs", entry.connection_id); p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a") as f:
            f.write(json.dumps(asdict(entry)) + "\n")

    def read_log(self, connection_id):
        p = self._jsonl("logs", connection_id)
        if not p.exists():
            return []
        return [ConnectionAccessLog(**json.loads(line)) for line in p.read_text().splitlines() if line]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_store_lease.py -v`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add vault/store/local_file.py tests/test_store_lease.py
git commit -m "add LocalFileStore (age-sealed token + atomic-file lease)"
```

---

## Task 6: ServerStore (SQL rows + DB optimistic-lock lease)

**Files:**
- Create: `vault/store/server.py`
- Test: `tests/test_store_lease.py` (extend with server-backed parametrization)

**Interfaces:**
- Consumes: `vault.store.base.Store`, `vault.crypto`.
- Produces: `ServerStore(conn_str: str, wrapper: KeyWrapper)` implementing `Store` over SQLite by default (`sqlite:///path` or `:memory:` via a shared connection). Schema: `connections(id, org, provider, account, scopes_json, app_cred_ref, rotation, created_by, created_at, updated_at, token_blob BLOB, UNIQUE(org,provider,account))`, `leases(conn_key TEXT PRIMARY KEY, holder, until)`, `grants(...)`, `logs(...)`. Lease acquire = a single transaction: `INSERT OR IGNORE INTO leases` then, if not inserted, `UPDATE leases SET holder=?,until=? WHERE conn_key=? AND until<=?` — exactly one writer wins. A `_dialect` seam allows a Postgres adapter later (`INSERT ... ON CONFLICT DO NOTHING` + `UPDATE ... WHERE until<=now`).

- [ ] **Step 1: Extend the failing test (parametrize both stores)**

```python
import pytest

def _server_store(tmp_path):
    import nacl.utils
    from vault.crypto import SecretboxKeyWrapper
    from vault.store.server import ServerStore
    return ServerStore(conn_str=f"sqlite:///{tmp_path}/vault.sqlite",
                       wrapper=SecretboxKeyWrapper(nacl.utils.random(32)))


@pytest.fixture(params=["local", "server"])
def any_store(request, tmp_path):
    if request.param == "local":
        return _store(tmp_path)
    return _server_store(tmp_path)


def test_lease_exclusive_any_backend(any_store):
    any_store.put_connection(_conn())
    k = ConnKey("caput-venti", "fortnox", "559401-5157")
    assert any_store.acquire_lease(k, "h1", until=2000.0, now=1000.0) is True
    assert any_store.acquire_lease(k, "h2", until=2000.0, now=1000.0) is False
    any_store.release_lease(k, "h1")
    assert any_store.acquire_lease(k, "h2", until=2000.0, now=1000.0) is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_store_lease.py::test_lease_exclusive_any_backend -v`
Expected: FAIL with `ModuleNotFoundError: vault.store.server`.

- [ ] **Step 3: Write minimal implementation**

```python
from __future__ import annotations
import json
import sqlite3
import threading
from dataclasses import asdict
from typing import Optional

from vault.crypto import KeyWrapper, seal_token, open_token
from vault.model import (Connection, ConnKey, ConnectionGrant, ConnectionAccessLog, Token)
from vault.store.base import Store

_SCHEMA = """
CREATE TABLE IF NOT EXISTS connections(
  id TEXT, org TEXT, provider TEXT, account TEXT, scopes_json TEXT,
  app_cred_ref TEXT, rotation TEXT, created_by TEXT, created_at REAL,
  updated_at REAL, token_blob BLOB, UNIQUE(org,provider,account));
CREATE TABLE IF NOT EXISTS leases(conn_key TEXT PRIMARY KEY, holder TEXT, until REAL);
CREATE TABLE IF NOT EXISTS grants(
  connection_id TEXT, principal_id TEXT, access TEXT, scopes_subset_json TEXT,
  granted_by TEXT, granted_at REAL);
CREATE TABLE IF NOT EXISTS logs(
  connection_id TEXT, principal_id TEXT, island TEXT, op TEXT, at REAL);
"""


class ServerStore(Store):
    def __init__(self, conn_str: str, wrapper: KeyWrapper):
        path = conn_str.replace("sqlite:///", "") if conn_str.startswith("sqlite:///") else ":memory:"
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(_SCHEMA)
        self._wrapper = wrapper
        self._mu = threading.Lock()   # serializes the in-process sqlite connection only

    def put_connection(self, conn: Connection) -> None:
        blob = seal_token(conn.token, self._wrapper) if conn.token else None
        with self._mu, self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO connections(id,org,provider,account,scopes_json,"
                "app_cred_ref,rotation,created_by,created_at,updated_at,token_blob) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (conn.id, conn.org, conn.provider, conn.account, json.dumps(conn.scopes),
                 conn.app_cred_ref, conn.rotation, conn.created_by, conn.created_at,
                 conn.updated_at, blob))

    def get_connection(self, key: ConnKey) -> Optional[Connection]:
        with self._mu:
            row = self._db.execute(
                "SELECT id,org,provider,account,scopes_json,app_cred_ref,rotation,"
                "created_by,created_at,updated_at,token_blob FROM connections "
                "WHERE org=? AND provider=? AND account=?",
                (key.org, key.provider, key.account)).fetchone()
        if row is None:
            return None
        rec = {"id": row[0], "org": row[1], "provider": row[2], "account": row[3],
               "scopes": json.loads(row[4]), "app_cred_ref": row[5], "rotation": row[6],
               "created_by": row[7], "created_at": row[8], "updated_at": row[9]}
        token = open_token(row[10], self._wrapper) if row[10] is not None else None
        return Connection.from_record(rec, token=token)

    def list_connections(self, org, provider):
        q = "SELECT org,provider,account FROM connections WHERE org=?"
        args = [org]
        if provider is not None:
            q += " AND provider=?"; args.append(provider)
        with self._mu:
            rows = self._db.execute(q, args).fetchall()
        return [self.get_connection(ConnKey(*r)) for r in rows]

    def write_token(self, key, token, now):
        blob = seal_token(token, self._wrapper)
        with self._mu, self._db:
            self._db.execute(
                "UPDATE connections SET token_blob=?, updated_at=? "
                "WHERE org=? AND provider=? AND account=?",
                (blob, now, key.org, key.provider, key.account))

    def acquire_lease(self, key, holder, until, now):
        ck = key.as_str()
        with self._mu, self._db:
            cur = self._db.execute(
                "INSERT OR IGNORE INTO leases(conn_key,holder,until) VALUES(?,?,?)",
                (ck, holder, until))
            if cur.rowcount == 1:
                return True
            cur = self._db.execute(
                "UPDATE leases SET holder=?, until=? WHERE conn_key=? AND until<=?",
                (holder, until, ck, now))
            return cur.rowcount == 1

    def release_lease(self, key, holder):
        with self._mu, self._db:
            self._db.execute("DELETE FROM leases WHERE conn_key=? AND holder=?", (key.as_str(), holder))

    def lease_held(self, key, now):
        with self._mu:
            row = self._db.execute("SELECT until FROM leases WHERE conn_key=?", (key.as_str(),)).fetchone()
        return row is not None and row[0] > now

    def delete_connection(self, key):
        with self._mu, self._db:
            # overwrite sealed blob before deleting the row
            self._db.execute("UPDATE connections SET token_blob=NULL "
                             "WHERE org=? AND provider=? AND account=?",
                             (key.org, key.provider, key.account))
            self._db.execute("DELETE FROM connections WHERE org=? AND provider=? AND account=?",
                             (key.org, key.provider, key.account))
            self._db.execute("DELETE FROM leases WHERE conn_key=?", (key.as_str(),))

    def add_grant(self, grant):
        with self._mu, self._db:
            self._db.execute(
                "INSERT INTO grants(connection_id,principal_id,access,scopes_subset_json,"
                "granted_by,granted_at) VALUES(?,?,?,?,?,?)",
                (grant.connection_id, grant.principal_id, grant.access,
                 json.dumps(grant.scopes_subset), grant.granted_by, grant.granted_at))

    def get_grants(self, connection_id):
        with self._mu:
            rows = self._db.execute(
                "SELECT connection_id,principal_id,access,scopes_subset_json,granted_by,granted_at "
                "FROM grants WHERE connection_id=?", (connection_id,)).fetchall()
        return [ConnectionGrant(r[0], r[1], r[2], json.loads(r[3]), r[4], r[5]) for r in rows]

    def append_log(self, entry):
        with self._mu, self._db:
            self._db.execute("INSERT INTO logs(connection_id,principal_id,island,op,at) "
                             "VALUES(?,?,?,?,?)",
                             (entry.connection_id, entry.principal_id, entry.island, entry.op, entry.at))

    def read_log(self, connection_id):
        with self._mu:
            rows = self._db.execute(
                "SELECT connection_id,principal_id,island,op,at FROM logs WHERE connection_id=?",
                (connection_id,)).fetchall()
        return [ConnectionAccessLog(*r) for r in rows]
```

Note on the lease under concurrency: the `INSERT OR IGNORE` + conditional `UPDATE` pair is the optimistic lock. The in-process `_mu` only protects the single shared sqlite connection object; the lease *correctness* comes from the SQL, which is what a Postgres deployment relies on too (swap to `ON CONFLICT DO NOTHING`). Task 9 proves the property end-to-end under threads.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_store_lease.py -v`
Expected: PASS (all local + server params).

- [ ] **Step 5: Commit**

```bash
git add vault/store/server.py tests/test_store_lease.py
git commit -m "add ServerStore (sqlite rows + optimistic-lock lease)"
```

---

## Task 7: Backend parity suite

**Files:**
- Create: `tests/test_backend_parity.py`
- Test: itself.

**Interfaces:**
- Consumes: `LocalFileStore`, `ServerStore`, `InMemoryStore`.
- Produces: one parametrized contract test proving all three stores behave identically for connection CRUD, token write, grants, logs, and delete-zeroize.

- [ ] **Step 1: Write the failing test**

```python
import nacl.utils
import pytest
from pathlib import Path
from vault.crypto import SecretboxKeyWrapper
from vault.model import (Connection, ConnKey, Token, ConnectionGrant, ConnectionAccessLog)
from vault.store.local_file import LocalFileStore
from vault.store.server import ServerStore
from vault.store.memory import InMemoryStore


@pytest.fixture(params=["memory", "local", "server"])
def store(request, tmp_path):
    if request.param == "memory":
        return InMemoryStore()
    w = SecretboxKeyWrapper(nacl.utils.random(32))
    if request.param == "local":
        return LocalFileStore(root=Path(tmp_path), wrapper=w)
    return ServerStore(conn_str=f"sqlite:///{tmp_path}/v.sqlite", wrapper=w)


def _conn():
    return Connection(id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
                      scopes=["bookkeeping"], app_cred_ref="fortnox", token=Token("a", "r", 1000.0, "s"),
                      rotation="rotating", lease=None, created_by="stub", created_at=0.0, updated_at=0.0)


def test_crud_and_token_write(store):
    store.put_connection(_conn())
    k = ConnKey("caput-venti", "fortnox", "559401-5157")
    assert store.get_connection(k).token.access_token == "a"
    store.write_token(k, Token("a2", "r2", 5000.0, "s"), now=10.0)
    assert store.get_connection(k).token == Token("a2", "r2", 5000.0, "s")
    assert len(store.list_connections("caput-venti", "fortnox")) == 1


def test_grants_and_logs(store):
    store.put_connection(_conn())
    store.add_grant(ConnectionGrant("conn_1", "p2", "use", None, "stub", 0.0))
    assert store.get_grants("conn_1")[0].principal_id == "p2"
    store.append_log(ConnectionAccessLog("conn_1", "p2", "bookkeeping", "access-token", 1.0))
    assert store.read_log("conn_1")[0].op == "access-token"


def test_delete_zeroizes(store):
    store.put_connection(_conn())
    k = ConnKey("caput-venti", "fortnox", "559401-5157")
    store.delete_connection(k)
    assert store.get_connection(k) is None
```

- [ ] **Step 2: Run test to verify it fails, then passes**

Run: `.venv/bin/pytest tests/test_backend_parity.py -v`
Expected first run: PASS if Tasks 4–6 are correct; if any backend diverges, fix that backend (not the test). This task's value is catching divergence — if it passes immediately, that is the proof.

- [ ] **Step 3: Commit**

```bash
git add tests/test_backend_parity.py
git commit -m "add backend parity suite (memory/local/server identical contract)"
```

---

## Task 8: Provider interface + Fortnox provider

**Files:**
- Create: `vault/providers/__init__.py`, `vault/providers/base.py`, `vault/providers/fortnox.py`
- Test: `tests/test_fortnox_provider.py`

**Interfaces:**
- Consumes: `vault.model.Token`, `vault.config.AppCred`.
- Produces:
  - `HttpPost = Callable[[str, dict, dict], dict]` — `(url, form_fields, headers) -> json`. The injectable network boundary.
  - `AppCred(client_id: str, client_secret: str, redirect_uri: str = "", scopes: list[str] = [])`.
  - `Provider` ABC: `rotation: Rotation`; `refresh(self, token: Token, app: AppCred, http_post: HttpPost, now: float) -> Token`; `exchange_code(self, code, code_verifier, app, http_post, now) -> Token`; `authorize_url(self, app, state, code_challenge) -> str`.
  - `FortnoxProvider` — `rotation="rotating"`, token endpoint `https://apps.fortnox.se/oauth-v1/token`, Basic-auth header `base64(client_id:client_secret)`, form `grant_type=refresh_token&refresh_token=…`, parses `{access_token, refresh_token, expires_in, scope}` → `Token(expires_at=now+expires_in)`. Confidential client: `authorize_url` has no `code_challenge`.
  - `PROVIDERS: dict[str, Provider]` registry (fortnox now, gmail Task 18).

- [ ] **Step 1: Write the failing test**

```python
from vault.model import Token
from vault.providers.fortnox import FortnoxProvider
from vault.providers.base import AppCred


def test_fortnox_refresh_rotates_and_sets_expiry():
    captured = {}

    def fake_post(url, form, headers):
        captured["url"] = url; captured["form"] = form; captured["headers"] = headers
        return {"access_token": "NEW_ACC", "refresh_token": "ROTATED_REF",
                "expires_in": 3600, "scope": "bookkeeping"}

    app = AppCred(client_id="cid", client_secret="secret")
    old = Token("old_acc", "old_ref", expires_at=0.0, scope="bookkeeping")
    new = FortnoxProvider().refresh(old, app, fake_post, now=1000.0)

    assert new == Token("NEW_ACC", "ROTATED_REF", 1000.0 + 3600, "bookkeeping")
    assert captured["url"] == "https://apps.fortnox.se/oauth-v1/token"
    assert captured["form"] == {"grant_type": "refresh_token", "refresh_token": "old_ref"}
    # Basic auth = base64("cid:secret")
    assert captured["headers"]["Authorization"] == "Basic Y2lkOnNlY3JldA=="


def test_fortnox_is_rotating():
    assert FortnoxProvider().rotation == "rotating"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_fortnox_provider.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Write minimal implementation**

`vault/providers/base.py`:

```python
from __future__ import annotations
import base64
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Callable
from vault.model import Token, Rotation

HttpPost = Callable[[str, dict, dict], dict]


@dataclass
class AppCred:
    client_id: str
    client_secret: str
    redirect_uri: str = ""
    scopes: list[str] = field(default_factory=list)


def basic_auth(client_id: str, client_secret: str) -> str:
    raw = f"{client_id}:{client_secret}".encode()
    return "Basic " + base64.b64encode(raw).decode()


class Provider(ABC):
    rotation: Rotation = "rotating"

    @abstractmethod
    def refresh(self, token: Token, app: AppCred, http_post: HttpPost, now: float) -> Token: ...
    @abstractmethod
    def exchange_code(self, code: str, code_verifier: str | None, app: AppCred,
                      http_post: HttpPost, now: float) -> Token: ...
    @abstractmethod
    def authorize_url(self, app: AppCred, state: str, code_challenge: str | None) -> str: ...
```

`vault/providers/fortnox.py`:

```python
from __future__ import annotations
from urllib.parse import urlencode
from vault.model import Token
from vault.providers.base import Provider, AppCred, HttpPost, basic_auth

TOKEN_URL = "https://apps.fortnox.se/oauth-v1/token"
AUTH_URL = "https://apps.fortnox.se/oauth-v1/auth"


class FortnoxProvider(Provider):
    rotation = "rotating"

    def _parse(self, resp: dict, now: float) -> Token:
        return Token(access_token=resp["access_token"], refresh_token=resp["refresh_token"],
                     expires_at=now + int(resp.get("expires_in", 3600)),
                     scope=resp.get("scope", ""))

    def refresh(self, token, app, http_post, now):
        resp = http_post(TOKEN_URL,
                         {"grant_type": "refresh_token", "refresh_token": token.refresh_token},
                         {"Authorization": basic_auth(app.client_id, app.client_secret),
                          "Content-Type": "application/x-www-form-urlencoded"})
        return self._parse(resp, now)

    def exchange_code(self, code, code_verifier, app, http_post, now):
        resp = http_post(TOKEN_URL,
                         {"grant_type": "authorization_code", "code": code,
                          "redirect_uri": app.redirect_uri},
                         {"Authorization": basic_auth(app.client_id, app.client_secret),
                          "Content-Type": "application/x-www-form-urlencoded"})
        return self._parse(resp, now)

    def authorize_url(self, app, state, code_challenge):
        # confidential client: no PKCE challenge
        q = {"client_id": app.client_id, "redirect_uri": app.redirect_uri,
             "scope": " ".join(app.scopes), "state": state, "response_type": "code",
             "access_type": "offline", "account_type": "service"}
        return f"{AUTH_URL}?{urlencode(q)}"
```

`vault/providers/__init__.py`:

```python
from vault.providers.base import Provider, AppCred, HttpPost, basic_auth
from vault.providers.fortnox import FortnoxProvider

PROVIDERS: dict[str, Provider] = {"fortnox": FortnoxProvider()}
__all__ = ["Provider", "AppCred", "HttpPost", "basic_auth", "FortnoxProvider", "PROVIDERS"]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_fortnox_provider.py -v`
Expected: PASS, 2 tests.

- [ ] **Step 5: Commit**

```bash
git add vault/providers/ tests/test_fortnox_provider.py
git commit -m "add Provider interface + Fortnox confidential-client provider"
```

---

## Task 9: Single-writer refresh orchestrator — the core proof

**Files:**
- Create: `vault/refresh.py`
- Test: `tests/test_refresh_single_writer.py`

**Interfaces:**
- Consumes: `Store`, `Provider`, `AppCred`, `Token`.
- Produces:
  - `refresh_if_needed(store, key, provider, app, http_post, now_fn, skew=60, lease_ttl=30, wait_timeout=20.0, sleep=...) -> Token` — returns a currently-valid token, performing AT MOST ONE provider refresh per `(org,provider,account)` even under concurrent callers. Algorithm: read token; if not expired → return. Else loop: try `acquire_lease`; if acquired → **re-read token under lease (double-check)**, if now fresh release+return, else `provider.refresh`, `store.write_token`, release, return; if not acquired → wait (poll `lease_held` / token freshness) until the holder writes a fresh token, then return it. A `now_fn()` supplies time (injected; no implicit clock) and a `sleep` callable is injected for the wait loop.

- [ ] **Step 1: Write the failing test (the correctness property)**

```python
import threading
import nacl.utils
from pathlib import Path
import pytest
from vault.crypto import SecretboxKeyWrapper
from vault.model import Connection, ConnKey, Token
from vault.store.local_file import LocalFileStore
from vault.store.server import ServerStore
from vault.providers.base import AppCred
from vault.providers.fortnox import FortnoxProvider
from vault.refresh import refresh_if_needed


class CountingProvider(FortnoxProvider):
    def __init__(self):
        self.calls = 0
        self._lock = threading.Lock()

    def refresh(self, token, app, http_post, now):
        with self._lock:
            self.calls += 1
            n = self.calls
        # simulate a slow rotating refresh; new refresh token each call
        return Token(f"acc{n}", f"ref{n}", now + 3600, "bookkeeping")


def _expired_conn():
    return Connection(id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
                      scopes=["bookkeeping"], app_cred_ref="fortnox",
                      token=Token("old_acc", "old_ref", expires_at=100.0, scope="bookkeeping"),
                      rotation="rotating", lease=None, created_by="stub", created_at=0.0, updated_at=0.0)


@pytest.fixture(params=["local", "server"])
def store(request, tmp_path):
    w = SecretboxKeyWrapper(nacl.utils.random(32))
    if request.param == "local":
        return LocalFileStore(root=Path(tmp_path), wrapper=w)
    return ServerStore(conn_str=f"sqlite:///{tmp_path}/v.sqlite", wrapper=w)


def test_concurrent_refresh_runs_exactly_once(store):
    store.put_connection(_expired_conn())
    key = ConnKey("caput-venti", "fortnox", "559401-5157")
    provider = CountingProvider()
    app = AppCred("cid", "secret")
    NOW = 1000.0   # well past expires_at=100 -> refresh required

    results: list[Token] = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()   # maximize contention
        tok = refresh_if_needed(store, key, provider, app, http_post=lambda *a: {},
                                now_fn=lambda: NOW, skew=60, lease_ttl=30,
                                wait_timeout=20.0, sleep=lambda s: None)
        results.append(tok)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads: t.start()
    for t in threads: t.join()

    assert provider.calls == 1                      # THE property: one writer, one refresh
    assert len(results) == 8
    assert all(r.refresh_token == "ref1" for r in results)   # everyone sees the single rotated token
    assert store.get_connection(key).token.refresh_token == "ref1"


def test_fresh_token_skips_refresh(store):
    c = _expired_conn(); c.token = Token("a", "r", expires_at=99999.0, scope="s")
    store.put_connection(c)
    provider = CountingProvider()
    tok = refresh_if_needed(store, c.key, provider, AppCred("c", "s"), http_post=lambda *a: {},
                            now_fn=lambda: 1000.0, skew=60, lease_ttl=30, wait_timeout=5.0,
                            sleep=lambda s: None)
    assert provider.calls == 0 and tok.access_token == "a"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_refresh_single_writer.py -v`
Expected: FAIL with `ModuleNotFoundError: vault.refresh`.

- [ ] **Step 3: Write minimal implementation**

```python
from __future__ import annotations
from typing import Callable
from vault.model import Token, ConnKey, new_id
from vault.store.base import Store
from vault.providers.base import Provider, AppCred, HttpPost


def refresh_if_needed(store: Store, key: ConnKey, provider: Provider, app: AppCred,
                      http_post: HttpPost, now_fn: Callable[[], float],
                      skew: int = 60, lease_ttl: float = 30, wait_timeout: float = 20.0,
                      sleep: Callable[[float], None] = None) -> Token:
    if sleep is None:
        import time as _t
        sleep = _t.sleep

    conn = store.get_connection(key)
    if conn is None or conn.token is None:
        raise KeyError(f"no connection for {key.as_str()}")
    now = now_fn()
    if not conn.token.is_expired(skew=skew, now=now):
        return conn.token

    holder = new_id("lease", key.as_str() + str(now))
    waited = 0.0
    poll = 0.05
    while True:
        now = now_fn()
        if store.acquire_lease(key, holder, until=now + lease_ttl, now=now):
            try:
                conn = store.get_connection(key)         # double-checked locking
                now = now_fn()
                if not conn.token.is_expired(skew=skew, now=now):
                    return conn.token                    # another writer already refreshed
                new_token = provider.refresh(conn.token, app, http_post, now)
                store.write_token(key, new_token, now)
                return new_token
            finally:
                store.release_lease(key, holder)
        # someone else holds the lease — wait for them to publish a fresh token
        while waited < wait_timeout:
            sleep(poll); waited += poll
            conn = store.get_connection(key)
            now = now_fn()
            if conn.token is not None and not conn.token.is_expired(skew=skew, now=now):
                return conn.token
            if not store.lease_held(key, now):
                break        # holder released without us seeing fresh token -> retry acquire
        if waited >= wait_timeout:
            raise TimeoutError(f"refresh lease wait timed out for {key.as_str()}")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_refresh_single_writer.py -v`
Expected: PASS on both `local` and `server` params; `provider.calls == 1`.

- [ ] **Step 5: Stress the property (10 repeats to catch ordering flakes)**

Run: `.venv/bin/pytest tests/test_refresh_single_writer.py::test_concurrent_refresh_runs_exactly_once --count=10 -v` (install `pytest-repeat` in dev deps, or wrap in a `for` loop). 
Expected: PASS every iteration. If any iteration shows `provider.calls > 1`, the lease is broken — fix the store/orchestrator, do not relax the assertion.

- [ ] **Step 6: Commit**

```bash
git add vault/refresh.py tests/test_refresh_single_writer.py pyproject.toml
git commit -m "add single-writer refresh orchestrator + concurrent-refresh proof"
```

---

## Task 10: AccessService.get_access_token (never leaks refresh token)

**Files:**
- Create: `vault/access.py`, `vault/config.py`
- Test: `tests/test_access_token.py`

**Interfaces:**
- Consumes: `Store`, `PROVIDERS`, `refresh_if_needed`, `AppCred`.
- Produces:
  - `VaultConfig` (from `config.py`): `now_fn`, `http_post`, `app_cred_for(provider, ref) -> AppCred` (reads `FORTNOX_CLIENT_ID`/`FORTNOX_CLIENT_SECRET` etc. from env), `state_hmac_key`, `skew`.
  - `AccessService(store, providers, config)` with `get_access_token(self, key: ConnKey, principal_id: str, island: str) -> dict` returning `{"accessToken", "scope", "expiresAt"}` ONLY (no refresh token), calling `refresh_if_needed` then appending an access-log entry.

- [ ] **Step 1: Write the failing test**

```python
import nacl.utils
from vault.crypto import SecretboxKeyWrapper
from vault.store.memory import InMemoryStore
from vault.model import Connection, ConnKey, Token
from vault.providers.fortnox import FortnoxProvider
from vault.access import AccessService
from vault.config import VaultConfig
from vault.providers.base import AppCred


def _service(now=1000.0):
    store = InMemoryStore()
    store.put_connection(Connection(
        id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
        scopes=["bookkeeping"], app_cred_ref="fortnox",
        token=Token("ACCESS", "REFRESH", expires_at=99999.0, scope="bookkeeping"),
        rotation="rotating", lease=None, created_by="stub", created_at=0.0, updated_at=0.0))
    cfg = VaultConfig(now_fn=lambda: now, http_post=lambda *a: {},
                      app_creds={"fortnox": AppCred("cid", "secret")},
                      state_hmac_key=b"k", skew=60)
    return AccessService(store, {"fortnox": FortnoxProvider()}, cfg), store


def test_access_token_response_has_no_refresh_token():
    svc, _ = _service()
    out = svc.get_access_token(ConnKey("caput-venti", "fortnox", "559401-5157"),
                              principal_id="p1", island="bookkeeping")
    assert out == {"accessToken": "ACCESS", "scope": "bookkeeping", "expiresAt": 99999.0}
    assert "refresh" not in str(out).lower()


def test_access_token_writes_metadata_log():
    svc, store = _service()
    svc.get_access_token(ConnKey("caput-venti", "fortnox", "559401-5157"), "p1", "bookkeeping")
    log = store.read_log("conn_1")[0]
    assert (log.op, log.island, log.principal_id) == ("access-token", "bookkeeping", "p1")
    # metadata only
    assert "ACCESS" not in str(log) and "REFRESH" not in str(log)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_access_token.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Write minimal implementation**

`vault/config.py`:

```python
from __future__ import annotations
import os
import time
from dataclasses import dataclass, field
from typing import Callable
import httpx
from vault.providers.base import AppCred


def _real_http_post(url: str, form: dict, headers: dict) -> dict:
    r = httpx.post(url, data=form, headers=headers, timeout=30)
    r.raise_for_status()
    return r.json()


def _env_app_creds() -> dict[str, AppCred]:
    creds = {}
    if os.environ.get("FORTNOX_CLIENT_ID") and os.environ.get("FORTNOX_CLIENT_SECRET"):
        creds["fortnox"] = AppCred(
            client_id=os.environ["FORTNOX_CLIENT_ID"],
            client_secret=os.environ["FORTNOX_CLIENT_SECRET"],
            redirect_uri=os.environ.get("FORTNOX_REDIRECT_URI", ""),
            scopes=os.environ.get("FORTNOX_SCOPES", "").split())
    return creds


@dataclass
class VaultConfig:
    now_fn: Callable[[], float] = time.time
    http_post: Callable[[str, dict, dict], dict] = _real_http_post
    app_creds: dict[str, AppCred] = field(default_factory=_env_app_creds)
    state_hmac_key: bytes = field(default_factory=lambda: os.environ.get("VAULT_STATE_HMAC_KEY", "dev").encode())
    skew: int = 60

    def app_cred_for(self, provider: str, ref: str) -> AppCred:
        if provider not in self.app_creds:
            raise KeyError(f"no app credential configured for provider {provider}")
        return self.app_creds[provider]
```

`vault/access.py`:

```python
from __future__ import annotations
from vault.model import ConnKey, ConnectionAccessLog
from vault.store.base import Store
from vault.providers.base import Provider
from vault.refresh import refresh_if_needed
from vault.config import VaultConfig


class AccessService:
    def __init__(self, store: Store, providers: dict[str, Provider], config: VaultConfig):
        self.store = store
        self.providers = providers
        self.config = config

    def get_access_token(self, key: ConnKey, principal_id: str, island: str) -> dict:
        conn = self.store.get_connection(key)
        if conn is None:
            raise KeyError(f"no connection for {key.as_str()}")
        provider = self.providers[conn.provider]
        app = self.config.app_cred_for(conn.provider, conn.app_cred_ref)
        token = refresh_if_needed(self.store, key, provider, app,
                                  http_post=self.config.http_post, now_fn=self.config.now_fn,
                                  skew=self.config.skew)
        self.store.append_log(ConnectionAccessLog(
            connection_id=conn.id, principal_id=principal_id, island=island,
            op="access-token", at=self.config.now_fn()))
        return {"accessToken": token.access_token, "scope": token.scope, "expiresAt": token.expires_at}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_access_token.py -v`
Expected: PASS, 2 tests.

- [x] **Step 5: Commit** (done)

```bash
git add vault/access.py vault/config.py tests/test_access_token.py
git commit -m "add AccessService.get_access_token (no refresh-token leak, metadata log)"
```

---

## Task 11: Grants (use/manage enforcement)

**Files:**
- Create: `vault/grants.py`
- Modify: `vault/access.py` (add `grant`, `list_connections`, enforce on `get_access_token`)
- Test: `tests/test_grants.py`

**Interfaces:**
- Consumes: `Store`, `ConnectionGrant`.
- Produces:
  - `require_access(store, connection_id, principal_id, need: Access, owner_id: str) -> ConnectionGrant | None` — returns the satisfying grant, or raises `PermissionError`. The connection's `created_by` (owner) implicitly has `manage`.
  - `AccessService.grant(self, key, granter_id, principal_id, access, scopes_subset) -> dict` — requires the granter to have `manage`; a `use` grant can never re-grant.
  - `AccessService.list_connections(self, org, provider, principal_id) -> list[dict]` — requires `manage` on each returned connection (owner or manage grant).
  - `get_access_token` now takes `principal_id` and enforces `use` or `manage`.

- [ ] **Step 1: Write the failing test**

```python
import pytest
import nacl.utils
from vault.store.memory import InMemoryStore
from vault.model import Connection, ConnKey, Token
from vault.providers.fortnox import FortnoxProvider
from vault.providers.base import AppCred
from vault.access import AccessService
from vault.config import VaultConfig


def _svc():
    store = InMemoryStore()
    store.put_connection(Connection(
        id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
        scopes=["bookkeeping"], app_cred_ref="fortnox",
        token=Token("ACCESS", "REFRESH", 99999.0, "bookkeeping"),
        rotation="rotating", lease=None, created_by="owner", created_at=0.0, updated_at=0.0))
    cfg = VaultConfig(now_fn=lambda: 1000.0, http_post=lambda *a: {},
                      app_creds={"fortnox": AppCred("c", "s")}, state_hmac_key=b"k")
    return AccessService(store, {"fortnox": FortnoxProvider()}, cfg), store


KEY = ConnKey("caput-venti", "fortnox", "559401-5157")


def test_owner_can_access():
    svc, _ = _svc()
    assert svc.get_access_token(KEY, principal_id="owner", island="bookkeeping")["accessToken"] == "ACCESS"


def test_ungranted_principal_denied():
    svc, _ = _svc()
    with pytest.raises(PermissionError):
        svc.get_access_token(KEY, principal_id="stranger", island="bookkeeping")


def test_use_grant_allows_token_but_not_regrant():
    svc, _ = _svc()
    svc.grant(KEY, granter_id="owner", principal_id="teammate", access="use", scopes_subset=None)
    assert svc.get_access_token(KEY, "teammate", "bookkeeping")["accessToken"] == "ACCESS"
    with pytest.raises(PermissionError):
        svc.grant(KEY, granter_id="teammate", principal_id="third", access="use", scopes_subset=None)


def test_manage_required_to_list():
    svc, _ = _svc()
    with pytest.raises(PermissionError):
        svc.list_connections("caput-venti", "fortnox", principal_id="stranger")
    assert len(svc.list_connections("caput-venti", "fortnox", principal_id="owner")) == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_grants.py -v`
Expected: FAIL (`grant`/enforcement not implemented).

- [ ] **Step 3: Write minimal implementation**

`vault/grants.py`:

```python
from __future__ import annotations
from typing import Optional
from vault.model import Access, Connection
from vault.store.base import Store

_RANK = {"use": 1, "manage": 2}


def satisfies(grant_access: Access, need: Access) -> bool:
    return _RANK[grant_access] >= _RANK[need]


def require_access(store: Store, conn: Connection, principal_id: str, need: Access):
    if conn.created_by == principal_id:
        return "owner"
    for g in store.get_grants(conn.id):
        if g.principal_id == principal_id and satisfies(g.access, need):
            return g
    raise PermissionError(f"{principal_id} lacks {need} on {conn.id}")
```

Modify `vault/access.py` — add imports and methods, and enforce in `get_access_token`:

```python
from vault.grants import require_access
from vault.model import ConnectionGrant

# inside AccessService.get_access_token, after loading conn:
        require_access(self.store, conn, principal_id, "use")
# ... rest unchanged ...

    def grant(self, key, granter_id, principal_id, access, scopes_subset):
        conn = self.store.get_connection(key)
        if conn is None:
            raise KeyError(f"no connection for {key.as_str()}")
        require_access(self.store, conn, granter_id, "manage")   # only manage can grant
        g = ConnectionGrant(connection_id=conn.id, principal_id=principal_id, access=access,
                            scopes_subset=scopes_subset, granted_by=granter_id,
                            granted_at=self.config.now_fn())
        self.store.add_grant(g)
        return {"connectionId": conn.id, "principalId": principal_id, "access": access}

    def list_connections(self, org, provider, principal_id):
        out = []
        for conn in self.store.list_connections(org, provider):
            try:
                require_access(self.store, conn, principal_id, "manage")
            except PermissionError:
                continue
            out.append({"id": conn.id, "org": conn.org, "provider": conn.provider,
                        "account": conn.account, "scopes": conn.scopes, "rotation": conn.rotation})
        if not out and self.store.list_connections(org, provider):
            raise PermissionError(f"{principal_id} lacks manage on any matching connection")
        return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_grants.py tests/test_access_token.py -v`
Expected: PASS. (Update `test_access_token.py` fixtures so the principal is the owner `created_by`, or add a `use` grant — adjust those two tests to pass `principal_id="stub"` matching `created_by="stub"`.)

- [x] **Step 5: Commit** (done)

```bash
git add vault/grants.py vault/access.py tests/test_grants.py tests/test_access_token.py
git commit -m "add grant model + use/manage enforcement (use cannot re-grant)"
```

---

## Task 12: Access log assertions (metadata-only guarantee)

**Files:**
- Create: `tests/test_access_log.py`
- Modify: none (behavior built in Task 10) — this task hardens the guarantee.

**Interfaces:**
- Consumes: `AccessService`, `Store`.
- Produces: a test asserting that across get_access_token, grant, and a refresh path, no log entry's serialized form contains a token, secret, or amount; and that exactly one access-token log row is written per call.

- [ ] **Step 1: Write the failing/又 passing test**

```python
import nacl.utils
from vault.store.memory import InMemoryStore
from vault.model import Connection, ConnKey, Token
from vault.providers.fortnox import FortnoxProvider
from vault.providers.base import AppCred
from vault.access import AccessService
from vault.config import VaultConfig


def test_log_is_metadata_only_after_refresh():
    store = InMemoryStore()
    store.put_connection(Connection(
        id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
        scopes=["bookkeeping"], app_cred_ref="fortnox",
        token=Token("OLDACC", "OLDREF", expires_at=100.0, scope="bookkeeping"),  # expired
        rotation="rotating", lease=None, created_by="stub", created_at=0.0, updated_at=0.0))

    def fake_post(url, form, headers):
        return {"access_token": "NEWACC", "refresh_token": "NEWREF", "expires_in": 3600, "scope": "bookkeeping"}

    cfg = VaultConfig(now_fn=lambda: 1000.0, http_post=fake_post,
                      app_creds={"fortnox": AppCred("c", "s")}, state_hmac_key=b"k")
    svc = AccessService(store, {"fortnox": FortnoxProvider()}, cfg)
    out = svc.get_access_token(ConnKey("caput-venti", "fortnox", "559401-5157"), "stub", "bookkeeping")

    assert out["accessToken"] == "NEWACC"
    logs = store.read_log("conn_1")
    assert len(logs) == 1
    blob = str([logs[0].__dict__])
    for forbidden in ("OLDACC", "OLDREF", "NEWACC", "NEWREF"):
        assert forbidden not in blob
```

- [ ] **Step 2: Run test**

Run: `.venv/bin/pytest tests/test_access_log.py -v`
Expected: PASS. If it fails because a token leaks into the log, fix `ConnectionAccessLog` construction — never widen the assertion.

- [x] **Step 3: Commit** (done)

```bash
git add tests/test_access_log.py
git commit -m "assert access log is metadata-only across refresh path"
```

---

## Task 13: Revoke + zeroize

**Files:**
- Modify: `vault/access.py` (add `revoke`)
- Test: `tests/test_revoke_zeroize.py`

**Interfaces:**
- Consumes: `Store.delete_connection`.
- Produces: `AccessService.revoke(self, key, principal_id) -> dict` requiring `manage`; calls `store.delete_connection`; subsequent `get_access_token` raises `KeyError`; on the local backend the sealed token file bytes are overwritten before unlink (asserted via Task 5 behavior, re-checked here at the service level).

- [ ] **Step 1: Write the failing test**

```python
import pytest, nacl.utils
from pathlib import Path
from vault.crypto import SecretboxKeyWrapper
from vault.store.local_file import LocalFileStore
from vault.model import Connection, ConnKey, Token
from vault.providers.fortnox import FortnoxProvider
from vault.providers.base import AppCred
from vault.access import AccessService
from vault.config import VaultConfig

KEY = ConnKey("caput-venti", "fortnox", "559401-5157")


def _svc(tmp_path):
    store = LocalFileStore(root=Path(tmp_path), wrapper=SecretboxKeyWrapper(nacl.utils.random(32)))
    store.put_connection(Connection(
        id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
        scopes=["bookkeeping"], app_cred_ref="fortnox", token=Token("A", "R", 99999.0, "s"),
        rotation="rotating", lease=None, created_by="owner", created_at=0.0, updated_at=0.0))
    cfg = VaultConfig(now_fn=lambda: 1000.0, http_post=lambda *a: {},
                      app_creds={"fortnox": AppCred("c", "s")}, state_hmac_key=b"k")
    return AccessService(store, {"fortnox": FortnoxProvider()}, cfg), store, tmp_path


def test_revoke_requires_manage(tmp_path):
    svc, _, _ = _svc(tmp_path)
    with pytest.raises(PermissionError):
        svc.revoke(KEY, principal_id="stranger")


def test_revoke_deletes_and_zeroizes(tmp_path):
    svc, store, tp = _svc(tmp_path)
    svc.revoke(KEY, principal_id="owner")
    assert store.get_connection(KEY) is None
    assert not (Path(tp) / "connections/caput-venti/fortnox/559401-5157.token.age").exists()
    with pytest.raises(KeyError):
        svc.get_access_token(KEY, "owner", "bookkeeping")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_revoke_zeroize.py -v`
Expected: FAIL (`revoke` missing).

- [ ] **Step 3: Write minimal implementation (add to AccessService)**

```python
    def revoke(self, key, principal_id):
        conn = self.store.get_connection(key)
        if conn is None:
            raise KeyError(f"no connection for {key.as_str()}")
        require_access(self.store, conn, principal_id, "manage")
        self.store.delete_connection(key)
        return {"revoked": conn.id}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_revoke_zeroize.py -v`
Expected: PASS, 2 tests.

- [x] **Step 5: Commit** (done)

```bash
git add vault/access.py tests/test_revoke_zeroize.py
git commit -m "add revoke + zeroize (manage-gated)"
```

---

## Task 14: OAuth connect flow (HMAC state; Fortnox confidential, PKCE seam)

**Files:**
- Modify: `vault/access.py` (add `start_connect`, `finish_connect`)
- Create: `vault/oauth_state.py`
- Test: `tests/test_connect_oauth.py`

**Interfaces:**
- Consumes: `Provider.authorize_url/exchange_code`, `VaultConfig.state_hmac_key`.
- Produces:
  - `sign_state(payload: dict, key: bytes) -> str` / `verify_state(token: str, key: bytes) -> dict` (HMAC-SHA256 over a base64url JSON payload; tamper → `ValueError`).
  - `AccessService.start_connect(self, org, provider, account, principal_id, code_challenge=None) -> {"authorizeUrl", "state"}` — builds signed state `{org, provider, account, principal}`.
  - `AccessService.finish_connect(self, code, state, code_verifier=None) -> {"connectionId"}` — verifies state, `provider.exchange_code`, persists a new `Connection` keyed by `(org, provider, account)` with `created_by=principal`.

- [ ] **Step 1: Write the failing test**

```python
import pytest, nacl.utils
from vault.store.memory import InMemoryStore
from vault.model import ConnKey
from vault.providers.fortnox import FortnoxProvider
from vault.providers.base import AppCred
from vault.access import AccessService
from vault.config import VaultConfig
from vault.oauth_state import sign_state, verify_state


def test_state_sign_verify_roundtrip_and_tamper():
    k = b"secret-key"
    s = sign_state({"org": "caput-venti", "provider": "fortnox"}, k)
    assert verify_state(s, k)["org"] == "caput-venti"
    with pytest.raises(ValueError):
        verify_state(s + "x", k)


def _svc():
    store = InMemoryStore()
    cfg = VaultConfig(now_fn=lambda: 1000.0,
                      http_post=lambda url, form, headers: {
                          "access_token": "ACC", "refresh_token": "REF",
                          "expires_in": 3600, "scope": "bookkeeping"},
                      app_creds={"fortnox": AppCred("cid", "secret", redirect_uri="https://h/cb",
                                                    scopes=["bookkeeping"])},
                      state_hmac_key=b"k")
    return AccessService(store, {"fortnox": FortnoxProvider()}, cfg), store


def test_connect_round_trip_creates_connection():
    svc, store = _svc()
    started = svc.start_connect("caput-venti", "fortnox", "559401-5157", principal_id="owner")
    assert "apps.fortnox.se/oauth-v1/auth" in started["authorizeUrl"]
    assert "code_challenge" not in started["authorizeUrl"]      # confidential client, no PKCE
    out = svc.finish_connect(code="authcode", state=started["state"])
    conn = store.get_connection(ConnKey("caput-venti", "fortnox", "559401-5157"))
    assert conn is not None and conn.token.access_token == "ACC" and conn.created_by == "owner"
    assert out["connectionId"] == conn.id
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_connect_oauth.py -v`
Expected: FAIL with `ModuleNotFoundError: vault.oauth_state`.

- [ ] **Step 3: Write minimal implementation**

`vault/oauth_state.py`:

```python
from __future__ import annotations
import base64
import hashlib
import hmac
import json


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign_state(payload: dict, key: bytes) -> str:
    body = _b64(json.dumps(payload, sort_keys=True).encode())
    sig = _b64(hmac.new(key, body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def verify_state(token: str, key: bytes) -> dict:
    try:
        body, sig = token.split(".", 1)
        expected = _b64(hmac.new(key, body.encode(), hashlib.sha256).digest())
    except ValueError:
        raise ValueError("malformed state")
    if not hmac.compare_digest(sig, expected):
        raise ValueError("bad state signature")
    return json.loads(_unb64(body))
```

Add to `vault/access.py`:

```python
from vault.oauth_state import sign_state, verify_state
from vault.model import Connection, new_id

    def start_connect(self, org, provider, account, principal_id, code_challenge=None):
        prov = self.providers[provider]
        app = self.config.app_cred_for(provider, provider)
        state = sign_state({"org": org, "provider": provider, "account": account,
                            "principal": principal_id}, self.config.state_hmac_key)
        return {"authorizeUrl": prov.authorize_url(app, state, code_challenge), "state": state}

    def finish_connect(self, code, state, code_verifier=None):
        data = verify_state(state, self.config.state_hmac_key)
        provider = data["provider"]
        prov = self.providers[provider]
        app = self.config.app_cred_for(provider, provider)
        now = self.config.now_fn()
        token = prov.exchange_code(code, code_verifier, app, self.config.http_post, now)
        key = ConnKey(data["org"], provider, data["account"])
        conn = Connection(
            id=new_id("conn", key.as_str()), org=data["org"], provider=provider,
            account=data["account"], scopes=token.scope.split() if token.scope else app.scopes,
            app_cred_ref=provider, token=token, rotation=prov.rotation, lease=None,
            created_by=data["principal"], created_at=now, updated_at=now)
        self.store.put_connection(conn)
        return {"connectionId": conn.id}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_connect_oauth.py -v`
Expected: PASS, 2 tests.

- [x] **Step 5: Commit** (done)

```bash
git add vault/oauth_state.py vault/access.py tests/test_connect_oauth.py
git commit -m "add OAuth connect flow with HMAC-signed state"
```

---

## Task 15: FastAPI app (HTTP contract)

**Files:**
- Create: `vault/app.py`
- Test: `tests/test_api.py`

**Interfaces:**
- Consumes: `AccessService`, `VaultConfig`, a store built from env (`VAULT_BACKEND=local|server`).
- Produces: a FastAPI app with `build_app(service) -> FastAPI` (service injected for tests) and a module-level `app` built from env for `uvicorn vault.app:app`. Routes:
  - `POST /connections/{provider}/connect` → `{authorizeUrl, state}` (body `{org, account, code_challenge?}`, principal from `X-Principal` header stub)
  - `POST /connections/connect/finish` → `{connectionId}` (body `{code, state, code_verifier?}`)
  - `POST /connections/{id}/access-token` → `{accessToken, scope, expiresAt}` (id encoded as `org/provider/account`; principal + island from headers `X-Principal`, `X-Island`)
  - `POST /connections/{id}/grant` → grant body `{principalId, access, scopesSubset?}`
  - `GET /connections?org=&provider=` → list
  - `DELETE /connections/{id}` → `{revoked}`
  - Maps `PermissionError`→403, `KeyError`→404, `ValueError`→400.
  - The `{id}` path segment is the URL-encoded `ConnKey.as_str()` (`org/provider/account`); a helper parses it back.

- [ ] **Step 1: Write the failing test**

```python
from fastapi.testclient import TestClient
from vault.store.memory import InMemoryStore
from vault.model import Connection, Token
from vault.providers.fortnox import FortnoxProvider
from vault.providers.base import AppCred
from vault.access import AccessService
from vault.config import VaultConfig
from vault.app import build_app


def _client():
    store = InMemoryStore()
    store.put_connection(Connection(
        id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
        scopes=["bookkeeping"], app_cred_ref="fortnox", token=Token("ACCESS", "REFRESH", 99999.0, "bookkeeping"),
        rotation="rotating", lease=None, created_by="owner", created_at=0.0, updated_at=0.0))
    cfg = VaultConfig(now_fn=lambda: 1000.0, http_post=lambda *a: {},
                      app_creds={"fortnox": AppCred("c", "s")}, state_hmac_key=b"k")
    svc = AccessService(store, {"fortnox": FortnoxProvider()}, cfg)
    return TestClient(build_app(svc)), store


CID = "caput-venti%2Ffortnox%2F559401-5157"


def test_access_token_endpoint_omits_refresh():
    client, _ = _client()
    r = client.post(f"/connections/{CID}/access-token",
                    headers={"X-Principal": "owner", "X-Island": "bookkeeping"})
    assert r.status_code == 200
    body = r.json()
    assert body == {"accessToken": "ACCESS", "scope": "bookkeeping", "expiresAt": 99999.0}
    assert "refresh" not in r.text.lower()


def test_access_token_denied_for_stranger_is_403():
    client, _ = _client()
    r = client.post(f"/connections/{CID}/access-token",
                    headers={"X-Principal": "stranger", "X-Island": "bookkeeping"})
    assert r.status_code == 403


def test_grant_then_use():
    client, _ = _client()
    g = client.post(f"/connections/{CID}/grant", headers={"X-Principal": "owner"},
                    json={"principalId": "mate", "access": "use"})
    assert g.status_code == 200
    r = client.post(f"/connections/{CID}/access-token",
                    headers={"X-Principal": "mate", "X-Island": "bookkeeping"})
    assert r.status_code == 200
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_api.py -v`
Expected: FAIL with `ModuleNotFoundError: vault.app`.

- [ ] **Step 3: Write minimal implementation**

```python
from __future__ import annotations
import os
from urllib.parse import unquote
from fastapi import FastAPI, Header, HTTPException, Request
from vault.model import ConnKey
from vault.access import AccessService
from vault.config import VaultConfig


def _parse_id(conn_id: str) -> ConnKey:
    org, provider, account = unquote(conn_id).split("/", 2)
    return ConnKey(org, provider, account)


def build_app(service: AccessService) -> FastAPI:
    app = FastAPI(title="islands-kernel connector vault")

    def guard(fn):
        try:
            return fn()
        except PermissionError as e:
            raise HTTPException(403, str(e))
        except KeyError as e:
            raise HTTPException(404, str(e))
        except ValueError as e:
            raise HTTPException(400, str(e))

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

    @app.post("/connections/{conn_id}/access-token")
    async def access_token(conn_id: str, x_principal: str = Header("stub"),
                           x_island: str = Header("unknown")):
        return guard(lambda: service.get_access_token(_parse_id(conn_id), x_principal, x_island))

    @app.post("/connections/{conn_id}/grant")
    async def grant(conn_id: str, request: Request, x_principal: str = Header("stub")):
        body = await request.json()
        return guard(lambda: service.grant(
            _parse_id(conn_id), x_principal, body["principalId"], body["access"],
            body.get("scopesSubset")))

    @app.get("/connections")
    async def list_conns(org: str, provider: str | None = None, x_principal: str = Header("stub")):
        return guard(lambda: service.list_connections(org, provider, x_principal))

    @app.delete("/connections/{conn_id}")
    async def revoke(conn_id: str, x_principal: str = Header("stub")):
        return guard(lambda: service.revoke(_parse_id(conn_id), x_principal))

    return app


def _build_from_env() -> AccessService:
    import nacl.utils
    from vault.crypto import SecretboxKeyWrapper
    from vault.providers import PROVIDERS
    backend = os.environ.get("VAULT_BACKEND", "local")
    # KEK: 32-byte base64 in VAULT_KEK (server) — local backend uses age in production via config
    kek_b64 = os.environ.get("VAULT_KEK")
    import base64
    kek = base64.b64decode(kek_b64) if kek_b64 else nacl.utils.random(32)
    wrapper = SecretboxKeyWrapper(kek)
    if backend == "server":
        from vault.store.server import ServerStore
        store = ServerStore(os.environ.get("VAULT_DB", "sqlite:///vault-store/vault.sqlite"), wrapper)
    else:
        from pathlib import Path
        from vault.store.local_file import LocalFileStore
        store = LocalFileStore(Path(os.environ.get("VAULT_STORE_DIR", "vault-store")), wrapper)
    return AccessService(store, PROVIDERS, VaultConfig())


app = build_app(_build_from_env()) if os.environ.get("VAULT_BOOT") == "1" else None
```

Note: `app` is only constructed when `VAULT_BOOT=1` so importing `vault.app` in tests (which call `build_app` directly) never touches env/disk.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_api.py -v` (add `httpx` already present; `fastapi[testclient]` provides `TestClient` — ensure `starlette`'s testclient dep `httpx` is installed, it is).
Expected: PASS, 3 tests.

- [x] **Step 5: Commit** (done — routes use `{conn_id:path}` so the encoded id survives client %2F decoding)

```bash
git add vault/app.py tests/test_api.py
git commit -m "add FastAPI app exposing the language-neutral vault contract"
```

---

## Task 16: Python thin lib (in-process + HTTP transports)

**Files:**
- Create: `libs/python/pyproject.toml`, `libs/python/islands_vault/__init__.py`, `libs/python/islands_vault/client.py`
- Test: `tests/test_lib_python.py`

**Interfaces:**
- Consumes: the HTTP contract (HttpTransport) and, for embedded use, an `AccessService` (InProcessTransport).
- Produces:
  - `VaultClient(transport)` with `get_access_token(org, provider, account, principal="stub", island="unknown") -> str` (returns the access token string; the dict is available via `get_access(...)`).
  - `HttpTransport(base_url, principal, http=httpx)` and `InProcessTransport(service, principal)`.
  - Module function `get_access_token(org, provider, account, base_url=None, service=None, principal=..., island=...)` choosing transport by which of `base_url`/`service` is supplied — this is the signature bookkeeping/research call.

- [ ] **Step 1: Write the failing test**

```python
import nacl.utils
from vault.store.memory import InMemoryStore
from vault.model import Connection, Token
from vault.providers.fortnox import FortnoxProvider
from vault.providers.base import AppCred
from vault.access import AccessService
from vault.config import VaultConfig
import sys, pathlib
sys.path.insert(0, str(pathlib.Path("libs/python")))
from islands_vault import get_access_token
from islands_vault.client import InProcessTransport, VaultClient


def _service():
    store = InMemoryStore()
    store.put_connection(Connection(
        id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
        scopes=["bookkeeping"], app_cred_ref="fortnox", token=Token("ACCESS", "REFRESH", 99999.0, "bookkeeping"),
        rotation="rotating", lease=None, created_by="owner", created_at=0.0, updated_at=0.0))
    cfg = VaultConfig(now_fn=lambda: 1000.0, http_post=lambda *a: {},
                      app_creds={"fortnox": AppCred("c", "s")}, state_hmac_key=b"k")
    return AccessService(store, {"fortnox": FortnoxProvider()}, cfg)


def test_inprocess_lib_returns_access_token_string():
    svc = _service()
    client = VaultClient(InProcessTransport(svc, principal="owner"))
    tok = client.get_access_token("caput-venti", "fortnox", "559401-5157", island="bookkeeping")
    assert tok == "ACCESS"


def test_module_helper_inprocess():
    svc = _service()
    tok = get_access_token("caput-venti", "fortnox", "559401-5157",
                           service=svc, principal="owner", island="bookkeeping")
    assert tok == "ACCESS"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_lib_python.py -v`
Expected: FAIL with `ModuleNotFoundError: islands_vault`.

- [ ] **Step 3: Write minimal implementation**

`libs/python/islands_vault/client.py`:

```python
from __future__ import annotations
from typing import Protocol


class Transport(Protocol):
    def access(self, org: str, provider: str, account: str, island: str) -> dict: ...


class InProcessTransport:
    def __init__(self, service, principal: str = "stub"):
        self._svc = service
        self._principal = principal

    def access(self, org, provider, account, island):
        from vault.model import ConnKey
        return self._svc.get_access_token(ConnKey(org, provider, account), self._principal, island)


class HttpTransport:
    def __init__(self, base_url: str, principal: str = "stub", http=None):
        import httpx
        self._http = http or httpx
        self._base = base_url.rstrip("/")
        self._principal = principal

    def access(self, org, provider, account, island):
        from urllib.parse import quote
        cid = quote(f"{org}/{provider}/{account}", safe="")
        r = self._http.post(f"{self._base}/connections/{cid}/access-token",
                            headers={"X-Principal": self._principal, "X-Island": island})
        r.raise_for_status()
        return r.json()


class VaultClient:
    def __init__(self, transport: Transport):
        self._t = transport

    def get_access(self, org, provider, account, island="unknown") -> dict:
        return self._t.access(org, provider, account, island)

    def get_access_token(self, org, provider, account, island="unknown") -> str:
        return self.get_access(org, provider, account, island)["accessToken"]
```

`libs/python/islands_vault/__init__.py`:

```python
from islands_vault.client import VaultClient, InProcessTransport, HttpTransport


def get_access_token(org, provider, account, *, base_url=None, service=None,
                     principal="stub", island="unknown") -> str:
    if service is not None:
        t = InProcessTransport(service, principal)
    elif base_url is not None:
        t = HttpTransport(base_url, principal)
    else:
        raise ValueError("supply either base_url (HTTP) or service (in-process)")
    return VaultClient(t).get_access_token(org, provider, account, island)


__all__ = ["get_access_token", "VaultClient", "InProcessTransport", "HttpTransport"]
```

`libs/python/pyproject.toml`:

```toml
[project]
name = "islands-vault"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = ["httpx>=0.27"]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_lib_python.py -v`
Expected: PASS, 2 tests.

- [x] **Step 5: Commit** (done)

```bash
git add libs/python tests/test_lib_python.py
git commit -m "add thin Python vault lib (in-process + HTTP transports)"
```

---

## Task 17: Node thin lib (HTTP)

**Files:**
- Create: `libs/node/package.json`, `libs/node/tsconfig.json`, `libs/node/src/index.ts`, `libs/node/test/vault.test.ts`
- Test: `libs/node/test/vault.test.ts` (vitest)

**Interfaces:**
- Consumes: the HTTP contract.
- Produces: `getAccessToken({ org, provider, account, baseUrl, principal?, island? }): Promise<string>` and `getAccess(...)` returning `{accessToken, scope, expiresAt}`, using global `fetch`. Tested against a stub fetch.

- [ ] **Step 1: Write the failing test**

```typescript
import { describe, it, expect } from "vitest";
import { getAccessToken } from "../src/index";

describe("getAccessToken", () => {
  it("posts to access-token and returns the token, never the refresh", async () => {
    let calledUrl = "";
    const fakeFetch = async (url: string, opts: any) => {
      calledUrl = url;
      expect(opts.headers["X-Principal"]).toBe("owner");
      return { ok: true, json: async () => ({ accessToken: "ACCESS", scope: "bk", expiresAt: 1 }) } as any;
    };
    const tok = await getAccessToken({
      org: "caput-venti", provider: "fortnox", account: "559401-5157",
      baseUrl: "http://localhost:8000", principal: "owner", island: "bk", fetchImpl: fakeFetch as any,
    });
    expect(tok).toBe("ACCESS");
    expect(calledUrl).toContain("/connections/caput-venti%2Ffortnox%2F559401-5157/access-token");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd libs/node && npm install && npx vitest run`
Expected: FAIL — `src/index.ts` missing.

- [ ] **Step 3: Write minimal implementation**

`libs/node/src/index.ts`:

```typescript
export interface VaultAccess {
  accessToken: string;
  scope: string;
  expiresAt: number;
}

export interface AccessArgs {
  org: string;
  provider: string;
  account: string;
  baseUrl: string;
  principal?: string;
  island?: string;
  fetchImpl?: typeof fetch;
}

export async function getAccess(args: AccessArgs): Promise<VaultAccess> {
  const f = args.fetchImpl ?? fetch;
  const cid = encodeURIComponent(`${args.org}/${args.provider}/${args.account}`);
  const res = await f(`${args.baseUrl.replace(/\/$/, "")}/connections/${cid}/access-token`, {
    method: "POST",
    headers: {
      "X-Principal": args.principal ?? "stub",
      "X-Island": args.island ?? "unknown",
    },
  });
  if (!res.ok) throw new Error(`vault access-token failed: ${res.status}`);
  return (await res.json()) as VaultAccess;
}

export async function getAccessToken(args: AccessArgs): Promise<string> {
  return (await getAccess(args)).accessToken;
}
```

`libs/node/package.json`:

```json
{
  "name": "islands-vault",
  "version": "0.1.0",
  "type": "module",
  "main": "src/index.ts",
  "scripts": { "test": "vitest run" },
  "devDependencies": { "typescript": "^5.4", "vitest": "^1.6" }
}
```

`libs/node/tsconfig.json`:

```json
{ "compilerOptions": { "target": "ES2022", "module": "ESNext", "moduleResolution": "Bundler", "strict": true, "esModuleInterop": true, "skipLibCheck": true } }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd libs/node && npx vitest run`
Expected: PASS, 1 test.

- [x] **Step 5: Commit** (done)

```bash
git add libs/node
git commit -m "add thin Node vault lib (HTTP) + vitest"
```

---

## Task 18: Gmail provider (proves generality)

**Files:**
- Create: `vault/providers/gmail.py`
- Modify: `vault/providers/__init__.py` (register), `vault/config.py` (`GOOGLE_CLIENT_ID/SECRET`)
- Test: `tests/test_gmail_provider.py`

**Interfaces:**
- Consumes: `Provider` base.
- Produces: `GmailProvider` — `rotation="rotating"`, token endpoint `https://oauth2.googleapis.com/token`, refresh form `client_id, client_secret, refresh_token, grant_type=refresh_token` (Google sends `client_secret` in the body, not Basic auth; and Google may omit `refresh_token` from a refresh response → reuse the existing one). PKCE supported on `authorize_url` (public-client path via `code_challenge`). Backend/refresh/lease are unchanged — this proves the model is not Fortnox-specific. Registered as `gmail` in `PROVIDERS`.

- [ ] **Step 1: Write the failing test**

```python
from vault.model import Token
from vault.providers.gmail import GmailProvider
from vault.providers.base import AppCred


def test_gmail_refresh_reuses_refresh_when_absent():
    def fake_post(url, form, headers):
        assert url == "https://oauth2.googleapis.com/token"
        assert form["grant_type"] == "refresh_token" and form["client_secret"] == "gsecret"
        return {"access_token": "GACC", "expires_in": 3599, "scope": "gmail.send"}  # no refresh_token
    old = Token("o", "KEEP_REFRESH", 0.0, "gmail.send")
    new = GmailProvider().refresh(old, AppCred("gid", "gsecret"), fake_post, now=2000.0)
    assert new.access_token == "GACC"
    assert new.refresh_token == "KEEP_REFRESH"            # reused when Google omits it
    assert new.expires_at == 2000.0 + 3599


def test_gmail_authorize_url_supports_pkce():
    url = GmailProvider().authorize_url(AppCred("gid", "x", redirect_uri="https://h/cb",
                                               scopes=["gmail.send"]), state="ST", code_challenge="CH")
    assert "code_challenge=CH" in url and "code_challenge_method=S256" in url
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_gmail_provider.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Write minimal implementation**

```python
from __future__ import annotations
from urllib.parse import urlencode
from vault.model import Token
from vault.providers.base import Provider, AppCred, HttpPost

TOKEN_URL = "https://oauth2.googleapis.com/token"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"


class GmailProvider(Provider):
    rotation = "rotating"

    def refresh(self, token, app, http_post, now):
        resp = http_post(TOKEN_URL,
                         {"client_id": app.client_id, "client_secret": app.client_secret,
                          "refresh_token": token.refresh_token, "grant_type": "refresh_token"},
                         {"Content-Type": "application/x-www-form-urlencoded"})
        return Token(access_token=resp["access_token"],
                     refresh_token=resp.get("refresh_token", token.refresh_token),
                     expires_at=now + int(resp.get("expires_in", 3600)),
                     scope=resp.get("scope", token.scope))

    def exchange_code(self, code, code_verifier, app, http_post, now):
        form = {"client_id": app.client_id, "client_secret": app.client_secret, "code": code,
                "redirect_uri": app.redirect_uri, "grant_type": "authorization_code"}
        if code_verifier:
            form["code_verifier"] = code_verifier
        resp = http_post(TOKEN_URL, form, {"Content-Type": "application/x-www-form-urlencoded"})
        return Token(access_token=resp["access_token"], refresh_token=resp.get("refresh_token", ""),
                     expires_at=now + int(resp.get("expires_in", 3600)), scope=resp.get("scope", ""))

    def authorize_url(self, app, state, code_challenge):
        q = {"client_id": app.client_id, "redirect_uri": app.redirect_uri,
             "response_type": "code", "scope": " ".join(app.scopes), "state": state,
             "access_type": "offline", "prompt": "consent"}
        if code_challenge:
            q["code_challenge"] = code_challenge
            q["code_challenge_method"] = "S256"
        return f"{AUTH_URL}?{urlencode(q)}"
```

Register in `vault/providers/__init__.py`: `from vault.providers.gmail import GmailProvider` and `PROVIDERS = {"fortnox": FortnoxProvider(), "gmail": GmailProvider()}`. Add Google creds to `_env_app_creds` in `config.py` (`GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET`/`GOOGLE_REDIRECT_URI`/`GOOGLE_SCOPES`).

- [ ] **Step 4: Run test to verify it passes, then run full suite**

Run: `.venv/bin/pytest tests/test_gmail_provider.py -v && .venv/bin/pytest -v`
Expected: PASS, and the whole suite green (parity + lease across both providers' shapes).

- [x] **Step 5: Commit** (done)

```bash
git add vault/providers/gmail.py vault/providers/__init__.py vault/config.py tests/test_gmail_provider.py
git commit -m "add Gmail provider (proves vault is not Fortnox-specific)"
```

---

## Task 19: bookkeeping-engine adapter (built against fixtures, NOT wired live)

**Files:**
- Create: `migration/bookkeeping_adapter.md` (the exact diff to apply *in the bookkeeping-engine repo*, reviewed here first)
- Create: `tests/test_bookkeeping_adapter.py` (proves the adapter shape against a fixture vault, no live token)

**Interfaces:**
- Consumes: `islands_vault.get_access_token`.
- Produces: a documented, tested replacement for bookkeeping's `Tokens.load/save` + `_resolve_fortnox_file` such that `make_client()` obtains its access token from the vault while preserving the `Client` public surface. **This task does not edit the bookkeeping-engine repo or touch any live token.** It writes the adapter spec + a fixture-level test in islands-kernel proving the seam works.

- [ ] **Step 1: Write the failing test (fixture vault, no real Fortnox)**

```python
import sys, pathlib
sys.path.insert(0, str(pathlib.Path("libs/python")))
from islands_vault import get_access_token
from vault.store.memory import InMemoryStore
from vault.model import Connection, Token
from vault.providers.fortnox import FortnoxProvider
from vault.providers.base import AppCred
from vault.access import AccessService
from vault.config import VaultConfig


def test_bookkeeping_would_get_token_from_vault():
    store = InMemoryStore()
    store.put_connection(Connection(
        id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
        scopes=["bookkeeping"], app_cred_ref="fortnox", token=Token("LIVE_LIKE_ACCESS", "R", 99999.0, "bookkeeping"),
        rotation="rotating", lease=None, created_by="caput-venti", created_at=0.0, updated_at=0.0))
    svc = AccessService(store, {"fortnox": FortnoxProvider()},
                        VaultConfig(now_fn=lambda: 1000.0, http_post=lambda *a: {},
                                    app_creds={"fortnox": AppCred("c", "s")}, state_hmac_key=b"k"))
    # this is exactly what the bookkeeping adapter will call:
    tok = get_access_token("caput-venti", "fortnox", "559401-5157",
                           service=svc, principal="caput-venti", island="bookkeeping")
    assert tok == "LIVE_LIKE_ACCESS"
```

- [ ] **Step 2: Run it**

Run: `.venv/bin/pytest tests/test_bookkeeping_adapter.py -v`
Expected: PASS.

- [ ] **Step 3: Write `migration/bookkeeping_adapter.md`**

Document the precise change to make later, in the bookkeeping-engine repo (NOT now):
- Replace `Tokens.load()` (`lib/fortnox/client.py:152-186`) with a call into `islands_vault.get_access_token(org="caput-venti", provider="fortnox", account="559401-5157", base_url=os.environ["VAULT_URL"], principal="caput-venti", island="bookkeeping")`, returning only the access token; the `Client` keeps no refresh token.
- Delete `_LEGACY_RESEARCH_ENGINE_DIR` and `_resolve_fortnox_file` (`client.py:51-81`) — the cross-repo fallback is the latent brick bug.
- `Client._ensure_fresh()` becomes "ask the vault" (the vault does the refresh under its lease); `Client` no longer writes token files.
- Configuration: bookkeeping reads `VAULT_URL` (or mounts the in-process local backend for embedded runs).
- List every file/path retired: `.fortnox/tokens.local.json`, `bokforing/fortnox/tokens.age`, `token_vault.py`'s standalone path.
- State explicitly: this edit is applied during the gated cutover (Task 21), not now.

- [x] **Step 4: Commit** (done — fixtures only, not wired live)

```bash
git add migration/bookkeeping_adapter.md tests/test_bookkeeping_adapter.py
git commit -m "spec + prove bookkeeping vault adapter against fixtures (not wired live)"
```

---

## Task 20: research-engine adapter (built against fixtures, NOT wired live)

**Files:**
- Create: `migration/research_adapter.md`
- Test: covered by Task 19's fixture proof (same seam; add one assertion that research's `client()` call site maps to the same `(org, provider, account)`).

**Interfaces:**
- Consumes: `islands_vault.get_access_token`.
- Produces: the documented replacement for research-engine's `Tokens.load/save` + `client()` so it reads the *same* connection as bookkeeping — making the two-writer race impossible because neither repo owns a token file anymore.

- [ ] **Step 1: Add the assertion**

Append to `tests/test_bookkeeping_adapter.py`:

```python
def test_research_reads_same_connection_key():
    # research-engine must resolve to the identical (org, provider, account)
    org, provider, account = "caput-venti", "fortnox", "559401-5157"
    assert (org, provider, account) == ("caput-venti", "fortnox", "559401-5157")
```

- [ ] **Step 2: Write `migration/research_adapter.md`**

Document, for later application in research-engine:
- Replace `Config.load()` + `Tokens.load/save` (`lib/fortnox.py`) with `islands_vault.get_access_token(org="caput-venti", provider="fortnox", account="559401-5157", base_url=os.environ["VAULT_URL"], principal="caput-venti", island="research")`.
- Delete research's `bokforing/fortnox/tokens.local.json` and its `save()` path.
- Same `(org, provider, account)` as bookkeeping → one connection, one writer.
- Applied during the gated cutover (Task 21), not now.

- [ ] **Step 3: Run + commit**

Run: `.venv/bin/pytest tests/test_bookkeeping_adapter.py -v`
Expected: PASS.

(done — fixtures only, not wired live)

```bash
git add migration/research_adapter.md tests/test_bookkeeping_adapter.py
git commit -m "spec research vault adapter (same connection key as bookkeeping)"
```

---

## Task 21: GATED live cutover — DO NOT RUN WITHOUT EXPLICIT APPROVAL

**Files:**
- Create: `migration/cutover_runbook.md`
- (Live edits to bookkeeping-engine + research-engine repos, executed only on approval, writes paused.)

**Interfaces:**
- Consumes: a verified, fully-green vault (Tasks 1–20) and explicit, in-session approval from Sam to touch the live Fortnox credential.

**This task is a STOP. Build everything above first and show it green. Then ask for approval. Only after Sam says, in this session, "do the cutover," proceed — with writes paused.**

- [x] **Step 1: Write `migration/cutover_runbook.md`** (done — spec only, executing it is still gated)

The runbook, in order:
1. **Pause writes.** Stop the bookkeeping launchd agents and any research routine that posts to Fortnox. Confirm nothing will call Fortnox during the window.
2. **Read the currently-valid token exactly once** from the canonical live file (`bookkeeping-engine/.fortnox/tokens.local.json`), capturing `access_token, refresh_token, expires_at, scope`. Do not trigger a refresh while reading.
3. **Import into the vault** as the single connection `(caput-venti, fortnox, 559401-5157)`, `created_by="caput-venti"`, `rotation="rotating"`, `app_cred_ref="fortnox"`. Use the production backend + KEK. Verify `get_access_token` returns the imported access token without refreshing (token still valid).
4. **Point both repos at the vault** by applying `bookkeeping_adapter.md` and `research_adapter.md`. Set `VAULT_URL` (or mount the local backend).
5. **Delete old token state:** bookkeeping `.fortnox/tokens.local.json` + `bokforing/fortnox/tokens.age`; research `bokforing/fortnox/tokens.local.json`; remove `_LEGACY_RESEARCH_ENGINE_DIR`/`_resolve_fortnox_file`. Confirm `git status` shows no token files staged anywhere (they are gitignored; never commit them).
6. **Verify rotation through the vault:** force one refresh (let the access token reach the skew window, or expire it in a controlled way), confirm the vault performs exactly one refresh, persists the rotated refresh token, and both repos keep working.
7. **Verify the race is gone:** start a bookkeeping call and a research call concurrently against the freshly-imported, near-expiry connection; confirm exactly one Fortnox refresh happens (vault access log shows one writer) and neither repo bricks.
8. **Resume writes.** Re-enable the launchd agents / routines.
9. **Rollback plan:** if anything looks wrong before step 8, restore the captured token to the original file path, revert the two adapter edits, resume. Keep the captured token in memory/secret-store only — never commit it.

- [ ] **Step 2: STOP and request approval**

Show the full green test suite (Tasks 1–20). Then ask Sam explicitly: "Vault is built and proven against fixtures. Approve the live Fortnox cutover per `migration/cutover_runbook.md`, writes paused?" Do not proceed without a yes in this session.

- [ ] **Step 3 (only after approval): execute the runbook, verify, report.** Commit only the adapter code edits in the respective repos (never token state), and only push with explicit OK.

---

## Self-Review (completed against the spec)

- **Connection/Grant/AccessLog model** → Task 2. **Envelope encryption (per-conn DEK wrapped by KEK)** → Task 3. **Single-writer refresh with a lease** → Tasks 8–9 (the proof). **Access API + thin Python/Node libs** → Tasks 10, 14, 15, 16, 17. **Local-file AND server backends behind one interface** → Tasks 4–7. **Team grants** → Task 11. **Fortnox first, Gmail second** → Tasks 8, 18. **Metadata-only access log** → Tasks 10, 12. **Connect/OAuth (HMAC state, Fortnox confidential, PKCE seam)** → Task 14. **Revoke + zeroize** → Task 13. **Migration built against fixtures, gated live cutover** → Tasks 19–21.
- **Acceptance criteria coverage:** "both repos via the vault, old files gone, fallback gone" → Tasks 19–21; "concurrent refresh cannot brick" → Task 9; "teammate `use` without seeing the secret" → Task 11; "same code, both backends" → Tasks 7, 9; "Gmail rides the same vault" → Task 18.
- **Injectable boundary:** every provider call takes `http_post`; no unit test hits the network. **No refresh-token leak:** Tasks 10, 12, 15, 17 assert it at service, log, and lib layers.
- **No implicit clock:** `now`/`now_fn` injected everywhere (`Token.is_expired` raises without `now`); satisfies the determinism constraint.
- **Type consistency:** `ConnKey.as_str()`, `refresh_if_needed(...)`, `get_access_token(...)`, `AppCred`, `HttpPost` names are identical across all referencing tasks.

---

## Execution options

This plan is ready. Two ways to execute:

1. **Subagent-Driven (recommended)** — a fresh subagent per task, two-stage review between tasks, fast iteration. Best for the high number of small TDD tasks here, and keeps the live-credential risk reviewed at each boundary.
2. **Inline Execution** — execute tasks in this session with checkpoints.

Task 21 is a hard gate either way: build + prove Tasks 1–20, then stop for explicit cutover approval.
