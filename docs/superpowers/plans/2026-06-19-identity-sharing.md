# Identity, Tenancy & Sharing (Slice 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the islands platform a real identity kernel — Principal/Org/Membership, a unified Grant model, an EdDSA-signed JWT verified via JWKS by both Node and Python, an MCP-token→short-lived-JWT exchange, and an OAuth 2.1 authorization server — then put the slice-1 vault behind real kernel auth instead of the `Header("stub")` placeholder.

**Architecture:** A new top-level `identity/` package in islands-kernel holds the models, key custody, JWT issuer/verify, org-resolution, generalized `authorize()`, the exchange, and an `oauth/` subpackage for the AS. The slice-1 `vault/` package is touched only at its auth seam: `Header("stub")` becomes a FastAPI dependency that verifies a kernel JWT and runs `authorize()` against the existing grants — no data migration. Thin verify libs land in the existing `libs/node` (jose) and `libs/python` so islands trust the same token offline. The kernel alone holds the Ed25519 private key; islands only verify.

**Tech Stack:** Python 3 / FastAPI / pytest (matching slice 1); PyJWT[crypto] + cryptography for EdDSA mint/verify and JWKS; PyNaCl (already present) for the existing envelope crypto; `jose` + vitest for the Node verify lib.

## Global Constraints

- Always work on the current branch. Never create a new branch.
- The kernel Ed25519 private signing key is the crown jewel: never commit it, never log it, host/secret-store only. Keep `.gitignore` covering all key/secret state (`.env`, `*.key`, `*.age`, `vault-store/`, plus any new key file pattern).
- No implicit clock. Every time-dependent function takes `now: float` (or a `now_fn`) explicitly — matches `Token.is_expired` in `vault/model.py`. PyJWT's own `exp` validation is disabled (`options={"verify_exp": False}`); expiry is checked against the injected `now`.
- Provider/JWKS/network I/O is injectable. Tests stub it; production wires the real fetch. No test hits the network.
- Tests: pytest, `InMemory*` stores, helper-function fixtures (no `@pytest.fixture` decorators), exactly the style in `tests/test_access_token.py`.
- Asymmetric signing only (EdDSA/Ed25519). No symmetric secret is ever shared across languages; islands receive verify-only keys via JWKS.
- Back-compat shim: every minted token also carries legacy `userId` (= `sub`) and `workspaceId` (= `org`).
- `AccessLog` is metadata only — never tokens, PII, or amounts.
- No AI-sounding prose, no emojis, no personal names, no hardcoded absolute local paths in committed code or docs.
- TDD per task: failing test → run it red → minimal implementation → run it green → commit. One commit per task.

---

## File Structure

New package `identity/` (all created unless noted):

```
identity/
  __init__.py
  model.py            — Principal, Org, Membership, GrantTarget, Grant, Session,
                        McpToken, IdentityBinding, OAuthClient, OAuthAuthCode,
                        OAuthAccessToken, AccessLog; the Literal type aliases
  tokens.py           — b64url helpers, hash_token, generate_raw_token
  store/
    __init__.py
    base.py           — IdentityStore ABC
    memory.py         — InMemoryIdentityStore
    server.py         — ServerIdentityStore (SQLite WAL, mirrors vault/store/server.py)
  keys.py             — KeyManager: Ed25519 custody, kid, sign, public_jwk, jwks_document
  jwt_issuer.py       — build_claims, mint_island_jwt
  jwt_verify.py       — verify_island_jwt (Python, offline via a JWKS dict)
  resolve.py          — resolve_org
  authorize.py        — adapt_connection_grant, collect_grants, authorize
  exchange.py         — exchange (opaque MCP/OAuth token -> resolved principal)
  deps.py             — FastAPI require_principal dependency (Claims)
  app.py              — build_identity_app: /.well-known/jwks.json, /auth/exchange, OAuth routes
  oauth/
    __init__.py
    clients.py        — OAuthClient registry + Client ID Metadata Document fetch
    pkce.py           — verify_pkce_s256
    authorize_endpoint.py — /oauth/authorize (auth-code + PKCE, single-use codes, consent payload)
    token_endpoint.py — /oauth/token (authorization_code + refresh rotation)
    metadata.py       — RFC 8414, RFC 9728, OIDC discovery documents

libs/node/src/
  verify.ts           — verifyIslandJwt (jose), JWKS fetch+cache  (Create)
libs/node/test/
  verify.test.ts      — verifies the cross-language golden fixture  (Create)
libs/python/islands_vault/
  verify.py           — thin re-export of identity.jwt_verify for island importers  (Create)

vault/
  app.py              — Modify: replace Header("stub") with require_principal dependency
  access.py           — Modify: get_access_token takes verified Claims; authorize() seam

tests/
  test_identity_model.py
  test_tokens.py
  test_identity_store_parity.py
  test_keys_jwks.py
  test_jwt_roundtrip.py
  test_jwt_verify_python.py
  test_resolve_org.py
  test_authorize.py
  test_exchange.py
  test_vault_auth_seam.py
  test_bookkeeping_verify_path.py
  test_oauth_clients.py
  test_oauth_pkce.py
  test_oauth_authorize.py
  test_oauth_token.py
  test_oauth_metadata.py
  test_cross_language.py
  fixtures/
    cross_lang/        — golden token + jwks written by test_cross_language.py, read by Node
```

Pinned key facts from the slice-1 code this plan extends:
- `vault/grants.py`: `require_access(store, conn, principal_id, need)` returns `"owner"` or the matching `ConnectionGrant`, raises `PermissionError`. `satisfies(grant_access, need)` ranks `manage(2) > use(1)`.
- `vault/model.py`: `Connection.created_by` (str), `ConnectionGrant(connection_id, principal_id, access, scopes_subset, granted_by, granted_at)`. `org` is a bare string everywhere.
- `vault/store/base.py`: `Store.get_grants(connection_id) -> list[ConnectionGrant]`.
- `vault/app.py`: `build_app(service)`, an inner `guard(fn)` maps `PermissionError→403, KeyError→404, ValueError→400`. The access-token route reads `x_principal: str = Header("stub")`, `x_island: str = Header("unknown")`.
- `vault/oauth_state.py`: `_b64`, `_unb64` base64url helpers (no padding) — match this style in `identity/tokens.py`.

---

# Phase A — Identity core

## Task 1: Identity data model

**Files:**
- Create: `identity/__init__.py` (empty)
- Create: `identity/model.py`
- Test: `tests/test_identity_model.py`

**Interfaces:**
- Produces: the dataclasses and type aliases every later task consumes. Exact names:
  `PrincipalType = Literal["human","service"]`, `Role = Literal["owner","admin","member","viewer"]`,
  `Access = Literal["use","manage"]`, `TargetKind = Literal["org","island","capability","connection"]`.
  `Principal(id, type, email, display_name, public_key, created_at)`;
  `Org(id, name, created_at)`; `Membership(principal_id, org_id, roles, active, joined_at)`;
  `GrantTarget(kind, id)`; `Grant(id, principal_id, target, access, scopes_subset, granted_by, granted_at, revoked_at)`;
  `Session(id, principal_id, org_id, expires_at, invalidated_at)`;
  `McpToken(hash, principal_id, org_id, audience, scope, expires_at, revoked_at)`;
  `IdentityBinding(principal_id, kind, ref, created_at)`;
  `OAuthClient(id, name, redirect_uris, type, client_id_metadata_url)`;
  `OAuthAuthCode(hash, client_id, principal_id, org_id, code_challenge, audience, scope, expires_at, consumed_at)`;
  `OAuthAccessToken(hash, client_id, principal_id, org_id, audience, scope, expires_at, refresh)`;
  `AccessLog(principal_id, org_id, island, capability, at)`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_identity_model.py
from identity.model import (
    Principal, Org, Membership, GrantTarget, Grant, McpToken, AccessLog,
)


def test_principal_defaults_to_no_org_fields():
    p = Principal(id="prn_1", type="human", email="a@b.se",
                  display_name="A", public_key=None, created_at=0.0)
    assert p.type == "human"
    assert p.email == "a@b.se"


def test_grant_targets_a_connection():
    g = Grant(id="grant_1", principal_id="prn_1",
              target=GrantTarget(kind="connection", id="conn_1"),
              access="use", scopes_subset=["read"],
              granted_by="prn_owner", granted_at=0.0, revoked_at=None)
    assert g.target.kind == "connection"
    assert g.target.id == "conn_1"
    assert g.revoked_at is None


def test_membership_roles_and_active():
    m = Membership(principal_id="prn_1", org_id="org_1",
                   roles=["owner", "member"], active=True, joined_at=0.0)
    assert "owner" in m.roles and m.active is True


def test_access_log_carries_no_secret_fields():
    log = AccessLog(principal_id="prn_1", org_id="org_1",
                    island="bookkeeping", capability="reconcile", at=0.0)
    blob = str(log)
    assert "token" not in blob.lower() and "secret" not in blob.lower()


def test_mcp_token_is_keyed_by_hash():
    t = McpToken(hash="h", principal_id="prn_1", org_id="org_1",
                 audience="https://mcp.x", scope="mcp",
                 expires_at=None, revoked_at=None)
    assert t.hash == "h"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_identity_model.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'identity'`.

- [ ] **Step 3: Write minimal implementation**

```python
# identity/model.py
from dataclasses import dataclass
from typing import Literal, Optional

PrincipalType = Literal["human", "service"]
Role = Literal["owner", "admin", "member", "viewer"]
Access = Literal["use", "manage"]
TargetKind = Literal["org", "island", "capability", "connection"]
IdentityKind = Literal["passkey", "google", "password"]


@dataclass
class Principal:
    id: str
    type: PrincipalType
    email: Optional[str]
    display_name: Optional[str]
    public_key: Optional[str]
    created_at: float


@dataclass
class Org:
    id: str
    name: str
    created_at: float


@dataclass
class Membership:
    principal_id: str
    org_id: str
    roles: list[Role]
    active: bool
    joined_at: float


@dataclass(frozen=True)
class GrantTarget:
    kind: TargetKind
    id: str


@dataclass
class Grant:
    id: str
    principal_id: str
    target: GrantTarget
    access: Access
    scopes_subset: Optional[list[str]]
    granted_by: str
    granted_at: float
    revoked_at: Optional[float] = None


@dataclass
class Session:
    id: str
    principal_id: str
    org_id: Optional[str]
    expires_at: float
    invalidated_at: Optional[float] = None


@dataclass
class McpToken:
    hash: str
    principal_id: str
    org_id: Optional[str]
    audience: Optional[str]
    scope: str
    expires_at: Optional[float]
    revoked_at: Optional[float] = None


@dataclass
class IdentityBinding:
    principal_id: str
    kind: IdentityKind
    ref: str
    created_at: float


@dataclass
class OAuthClient:
    id: str
    name: str
    redirect_uris: list[str]
    type: Literal["public", "confidential"]
    client_id_metadata_url: Optional[str] = None


@dataclass
class OAuthAuthCode:
    hash: str
    client_id: str
    principal_id: str
    org_id: Optional[str]
    code_challenge: str
    audience: str
    scope: str
    expires_at: float
    consumed_at: Optional[float] = None


@dataclass
class OAuthAccessToken:
    hash: str
    client_id: str
    principal_id: str
    org_id: Optional[str]
    audience: str
    scope: str
    expires_at: float
    refresh: Optional[dict] = None


@dataclass
class AccessLog:
    principal_id: str
    org_id: Optional[str]
    island: str
    capability: str
    at: float
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_identity_model.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add identity/__init__.py identity/model.py tests/test_identity_model.py
git commit -m "feat(identity): slice-2 identity data model"
```

---

## Task 2: Token helpers (hashToken / generateRawToken)

**Files:**
- Create: `identity/tokens.py`
- Test: `tests/test_tokens.py`

**Interfaces:**
- Produces: `b64url(b: bytes) -> str` and `unb64url(s: str) -> bytes` (no padding, mirror `vault/oauth_state.py`);
  `hash_token(raw: str) -> str` (sha256 → base64url, no padding — byte-identical to sm-brf/nudge);
  `generate_raw_token(prefix: str) -> str` returning `"<prefix>_<urlsafe-random>"`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_tokens.py
import hashlib
import base64
from identity.tokens import b64url, unb64url, hash_token, generate_raw_token


def test_b64url_roundtrip_no_padding():
    raw = b"\x00\x01\x02hello"
    enc = b64url(raw)
    assert "=" not in enc
    assert unb64url(enc) == raw


def test_hash_token_is_sha256_base64url():
    raw = "mcp_abc"
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(raw.encode()).digest()).decode().rstrip("=")
    assert hash_token(raw) == expected


def test_hash_token_is_deterministic():
    assert hash_token("mcp_abc") == hash_token("mcp_abc")


def test_generate_raw_token_has_prefix_and_entropy():
    a = generate_raw_token("mcp")
    b = generate_raw_token("mcp")
    assert a.startswith("mcp_") and b.startswith("mcp_")
    assert a != b
    assert len(a) > len("mcp_") + 20
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_tokens.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'identity.tokens'`.

- [ ] **Step 3: Write minimal implementation**

```python
# identity/tokens.py
import base64
import hashlib
import secrets


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def unb64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def hash_token(raw: str) -> str:
    return b64url(hashlib.sha256(raw.encode()).digest())


def generate_raw_token(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(32)}"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_tokens.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add identity/tokens.py tests/test_tokens.py
git commit -m "feat(identity): token hashing and raw-token generation helpers"
```

---

## Task 3: IdentityStore ABC + InMemory backend

**Files:**
- Create: `identity/store/__init__.py` (empty)
- Create: `identity/store/base.py`
- Create: `identity/store/memory.py`
- Test: `tests/test_identity_store_parity.py` (InMemory portion; ServerIdentityStore added in Task 4)

**Interfaces:**
- Produces: `IdentityStore` ABC with:
  `put_principal(p)`, `get_principal(id) -> Optional[Principal]`, `get_principal_by_email(email) -> Optional[Principal]`;
  `put_org(o)`, `get_org(id)`;
  `put_membership(m)`, `get_membership(principal_id, org_id) -> Optional[Membership]`, `list_memberships(principal_id) -> list[Membership]`;
  `add_grant(g)`, `revoke_grant(grant_id, at)`, `list_grants(principal_id) -> list[Grant]`;
  `put_mcp_token(t)`, `get_mcp_token(hash) -> Optional[McpToken]`;
  `put_oauth_client(c)`, `get_oauth_client(id)`;
  `put_auth_code(c)`, `get_auth_code(hash)`, `consume_auth_code(hash, at)`;
  `put_access_token(t)`, `get_access_token(hash)`, `rotate_refresh(old_hash, new_token)`;
  `append_log(entry)`, `read_log(principal_id) -> list[AccessLog]`.
- `InMemoryIdentityStore()` implements all of the above with dicts.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_identity_store_parity.py
from identity.store.memory import InMemoryIdentityStore
from identity.model import (
    Principal, Org, Membership, Grant, GrantTarget, McpToken, AccessLog,
)


def _principal(pid="prn_1", email="a@b.se"):
    return Principal(id=pid, type="human", email=email,
                     display_name=None, public_key=None, created_at=0.0)


def _stores():
    return [InMemoryIdentityStore()]


def test_principal_put_get_and_by_email():
    for s in _stores():
        s.put_principal(_principal())
        assert s.get_principal("prn_1").email == "a@b.se"
        assert s.get_principal_by_email("a@b.se").id == "prn_1"
        assert s.get_principal("nope") is None


def test_membership_lookup():
    for s in _stores():
        s.put_membership(Membership("prn_1", "org_1", ["owner"], True, 0.0))
        assert s.get_membership("prn_1", "org_1").roles == ["owner"]
        assert len(s.list_memberships("prn_1")) == 1


def test_grant_add_list_revoke():
    for s in _stores():
        g = Grant("grant_1", "prn_1", GrantTarget("org", "org_1"),
                  "use", None, "prn_owner", 0.0, None)
        s.add_grant(g)
        assert len(s.list_grants("prn_1")) == 1
        s.revoke_grant("grant_1", at=5.0)
        assert s.list_grants("prn_1")[0].revoked_at == 5.0


def test_mcp_token_lookup_by_hash():
    for s in _stores():
        s.put_mcp_token(McpToken("h", "prn_1", "org_1", "aud", "mcp", None, None))
        assert s.get_mcp_token("h").principal_id == "prn_1"
        assert s.get_mcp_token("missing") is None


def test_log_is_append_only():
    for s in _stores():
        s.append_log(AccessLog("prn_1", "org_1", "bk", "reconcile", 0.0))
        s.append_log(AccessLog("prn_1", "org_1", "bk", "reconcile", 1.0))
        assert len(s.read_log("prn_1")) == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_identity_store_parity.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'identity.store'`.

- [ ] **Step 3: Write minimal implementation**

```python
# identity/store/base.py
from abc import ABC, abstractmethod
from typing import Optional
from identity.model import (
    Principal, Org, Membership, Grant, McpToken, OAuthClient,
    OAuthAuthCode, OAuthAccessToken, AccessLog,
)


class IdentityStore(ABC):
    @abstractmethod
    def put_principal(self, p: Principal) -> None: ...
    @abstractmethod
    def get_principal(self, principal_id: str) -> Optional[Principal]: ...
    @abstractmethod
    def get_principal_by_email(self, email: str) -> Optional[Principal]: ...

    @abstractmethod
    def put_org(self, o: Org) -> None: ...
    @abstractmethod
    def get_org(self, org_id: str) -> Optional[Org]: ...

    @abstractmethod
    def put_membership(self, m: Membership) -> None: ...
    @abstractmethod
    def get_membership(self, principal_id: str, org_id: str) -> Optional[Membership]: ...
    @abstractmethod
    def list_memberships(self, principal_id: str) -> list[Membership]: ...

    @abstractmethod
    def add_grant(self, g: Grant) -> None: ...
    @abstractmethod
    def revoke_grant(self, grant_id: str, at: float) -> None: ...
    @abstractmethod
    def list_grants(self, principal_id: str) -> list[Grant]: ...

    @abstractmethod
    def put_mcp_token(self, t: McpToken) -> None: ...
    @abstractmethod
    def get_mcp_token(self, token_hash: str) -> Optional[McpToken]: ...

    @abstractmethod
    def put_oauth_client(self, c: OAuthClient) -> None: ...
    @abstractmethod
    def get_oauth_client(self, client_id: str) -> Optional[OAuthClient]: ...

    @abstractmethod
    def put_auth_code(self, c: OAuthAuthCode) -> None: ...
    @abstractmethod
    def get_auth_code(self, code_hash: str) -> Optional[OAuthAuthCode]: ...
    @abstractmethod
    def consume_auth_code(self, code_hash: str, at: float) -> bool: ...

    @abstractmethod
    def put_access_token(self, t: OAuthAccessToken) -> None: ...
    @abstractmethod
    def get_access_token(self, token_hash: str) -> Optional[OAuthAccessToken]: ...
    @abstractmethod
    def rotate_refresh(self, old_hash: str, new_token: OAuthAccessToken) -> None: ...

    @abstractmethod
    def append_log(self, entry: AccessLog) -> None: ...
    @abstractmethod
    def read_log(self, principal_id: str) -> list[AccessLog]: ...
```

```python
# identity/store/memory.py
import threading
from typing import Optional
from identity.store.base import IdentityStore
from identity.model import (
    Principal, Org, Membership, Grant, McpToken, OAuthClient,
    OAuthAuthCode, OAuthAccessToken, AccessLog,
)


class InMemoryIdentityStore(IdentityStore):
    def __init__(self) -> None:
        self._mu = threading.Lock()
        self._principals: dict[str, Principal] = {}
        self._orgs: dict[str, Org] = {}
        self._memberships: dict[tuple[str, str], Membership] = {}
        self._grants: dict[str, Grant] = {}
        self._mcp: dict[str, McpToken] = {}
        self._clients: dict[str, OAuthClient] = {}
        self._codes: dict[str, OAuthAuthCode] = {}
        self._at: dict[str, OAuthAccessToken] = {}
        self._logs: list[AccessLog] = []

    def put_principal(self, p): 
        with self._mu: self._principals[p.id] = p
    def get_principal(self, principal_id):
        return self._principals.get(principal_id)
    def get_principal_by_email(self, email):
        return next((p for p in self._principals.values() if p.email == email), None)

    def put_org(self, o):
        with self._mu: self._orgs[o.id] = o
    def get_org(self, org_id):
        return self._orgs.get(org_id)

    def put_membership(self, m):
        with self._mu: self._memberships[(m.principal_id, m.org_id)] = m
    def get_membership(self, principal_id, org_id):
        return self._memberships.get((principal_id, org_id))
    def list_memberships(self, principal_id):
        return [m for (pid, _), m in self._memberships.items() if pid == principal_id]

    def add_grant(self, g):
        with self._mu: self._grants[g.id] = g
    def revoke_grant(self, grant_id, at):
        with self._mu:
            g = self._grants.get(grant_id)
            if g is not None:
                g.revoked_at = at
    def list_grants(self, principal_id):
        return [g for g in self._grants.values() if g.principal_id == principal_id]

    def put_mcp_token(self, t):
        with self._mu: self._mcp[t.hash] = t
    def get_mcp_token(self, token_hash):
        return self._mcp.get(token_hash)

    def put_oauth_client(self, c):
        with self._mu: self._clients[c.id] = c
    def get_oauth_client(self, client_id):
        return self._clients.get(client_id)

    def put_auth_code(self, c):
        with self._mu: self._codes[c.hash] = c
    def get_auth_code(self, code_hash):
        return self._codes.get(code_hash)
    def consume_auth_code(self, code_hash, at):
        with self._mu:
            c = self._codes.get(code_hash)
            if c is None or c.consumed_at is not None:
                return False
            c.consumed_at = at
            return True

    def put_access_token(self, t):
        with self._mu: self._at[t.hash] = t
    def get_access_token(self, token_hash):
        return self._at.get(token_hash)
    def rotate_refresh(self, old_hash, new_token):
        with self._mu:
            self._at.pop(old_hash, None)
            self._at[new_token.hash] = new_token

    def append_log(self, entry):
        with self._mu: self._logs.append(entry)
    def read_log(self, principal_id):
        return [e for e in self._logs if e.principal_id == principal_id]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_identity_store_parity.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add identity/store/__init__.py identity/store/base.py identity/store/memory.py tests/test_identity_store_parity.py
git commit -m "feat(identity): IdentityStore ABC and in-memory backend"
```

---

## Task 4: ServerIdentityStore (SQLite) + backend parity

**Files:**
- Create: `identity/store/server.py`
- Modify: `tests/test_identity_store_parity.py:` extend `_stores()` to include the SQLite backend.

**Interfaces:**
- Consumes: `IdentityStore` (Task 3).
- Produces: `ServerIdentityStore(conn_str: str)` — SQLite WAL, same contract as `InMemoryIdentityStore`. Mirrors the shape of `vault/store/server.py` (a `threading.Lock`, `PRAGMA journal_mode=WAL`, JSON columns for list fields).

- [ ] **Step 1: Write the failing test** — extend the parity helper so every existing test runs against both backends.

```python
# tests/test_identity_store_parity.py  (replace _stores)
import tempfile, os
from identity.store.server import ServerIdentityStore

def _stores():
    mem = InMemoryIdentityStore()
    path = os.path.join(tempfile.mkdtemp(), "identity.sqlite")
    return [mem, ServerIdentityStore(path)]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_identity_store_parity.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'identity.store.server'`.

- [ ] **Step 3: Write minimal implementation**

```python
# identity/store/server.py
import json
import sqlite3
import threading
from typing import Optional
from identity.store.base import IdentityStore
from identity.model import (
    Principal, Org, Membership, Grant, GrantTarget, McpToken, OAuthClient,
    OAuthAuthCode, OAuthAccessToken, AccessLog,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS principals(
  id TEXT PRIMARY KEY, type TEXT, email TEXT, display_name TEXT,
  public_key TEXT, created_at REAL);
CREATE TABLE IF NOT EXISTS orgs(id TEXT PRIMARY KEY, name TEXT, created_at REAL);
CREATE TABLE IF NOT EXISTS memberships(
  principal_id TEXT, org_id TEXT, roles_json TEXT, active INTEGER, joined_at REAL,
  PRIMARY KEY (principal_id, org_id));
CREATE TABLE IF NOT EXISTS grants(
  id TEXT PRIMARY KEY, principal_id TEXT, target_kind TEXT, target_id TEXT,
  access TEXT, scopes_subset_json TEXT, granted_by TEXT, granted_at REAL, revoked_at REAL);
CREATE TABLE IF NOT EXISTS mcp_tokens(
  hash TEXT PRIMARY KEY, principal_id TEXT, org_id TEXT, audience TEXT,
  scope TEXT, expires_at REAL, revoked_at REAL);
CREATE TABLE IF NOT EXISTS oauth_clients(
  id TEXT PRIMARY KEY, name TEXT, redirect_uris_json TEXT, type TEXT, cid_meta_url TEXT);
CREATE TABLE IF NOT EXISTS auth_codes(
  hash TEXT PRIMARY KEY, client_id TEXT, principal_id TEXT, org_id TEXT,
  code_challenge TEXT, audience TEXT, scope TEXT, expires_at REAL, consumed_at REAL);
CREATE TABLE IF NOT EXISTS access_tokens(
  hash TEXT PRIMARY KEY, client_id TEXT, principal_id TEXT, org_id TEXT,
  audience TEXT, scope TEXT, expires_at REAL, refresh_json TEXT);
CREATE TABLE IF NOT EXISTS logs(
  principal_id TEXT, org_id TEXT, island TEXT, capability TEXT, at REAL);
"""


class ServerIdentityStore(IdentityStore):
    def __init__(self, conn_str: str) -> None:
        self._db = sqlite3.connect(conn_str, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(_SCHEMA)
        self._db.commit()
        self._mu = threading.Lock()

    # --- principals ---
    def put_principal(self, p):
        with self._mu:
            self._db.execute(
                "INSERT OR REPLACE INTO principals VALUES (?,?,?,?,?,?)",
                (p.id, p.type, p.email, p.display_name, p.public_key, p.created_at))
            self._db.commit()

    def get_principal(self, principal_id):
        r = self._db.execute("SELECT * FROM principals WHERE id=?", (principal_id,)).fetchone()
        return self._principal(r)

    def get_principal_by_email(self, email):
        r = self._db.execute("SELECT * FROM principals WHERE email=?", (email,)).fetchone()
        return self._principal(r)

    @staticmethod
    def _principal(r):
        if r is None:
            return None
        return Principal(id=r[0], type=r[1], email=r[2], display_name=r[3],
                         public_key=r[4], created_at=r[5])

    # --- orgs ---
    def put_org(self, o):
        with self._mu:
            self._db.execute("INSERT OR REPLACE INTO orgs VALUES (?,?,?)",
                             (o.id, o.name, o.created_at))
            self._db.commit()

    def get_org(self, org_id):
        r = self._db.execute("SELECT * FROM orgs WHERE id=?", (org_id,)).fetchone()
        return Org(*r) if r else None

    # --- memberships ---
    def put_membership(self, m):
        with self._mu:
            self._db.execute("INSERT OR REPLACE INTO memberships VALUES (?,?,?,?,?)",
                             (m.principal_id, m.org_id, json.dumps(m.roles),
                              1 if m.active else 0, m.joined_at))
            self._db.commit()

    def get_membership(self, principal_id, org_id):
        r = self._db.execute(
            "SELECT * FROM memberships WHERE principal_id=? AND org_id=?",
            (principal_id, org_id)).fetchone()
        return self._membership(r)

    def list_memberships(self, principal_id):
        rows = self._db.execute(
            "SELECT * FROM memberships WHERE principal_id=?", (principal_id,)).fetchall()
        return [self._membership(r) for r in rows]

    @staticmethod
    def _membership(r):
        if r is None:
            return None
        return Membership(principal_id=r[0], org_id=r[1], roles=json.loads(r[2]),
                          active=bool(r[3]), joined_at=r[4])

    # --- grants ---
    def add_grant(self, g):
        with self._mu:
            self._db.execute(
                "INSERT OR REPLACE INTO grants VALUES (?,?,?,?,?,?,?,?,?)",
                (g.id, g.principal_id, g.target.kind, g.target.id, g.access,
                 json.dumps(g.scopes_subset) if g.scopes_subset is not None else None,
                 g.granted_by, g.granted_at, g.revoked_at))
            self._db.commit()

    def revoke_grant(self, grant_id, at):
        with self._mu:
            self._db.execute("UPDATE grants SET revoked_at=? WHERE id=?", (at, grant_id))
            self._db.commit()

    def list_grants(self, principal_id):
        rows = self._db.execute(
            "SELECT * FROM grants WHERE principal_id=?", (principal_id,)).fetchall()
        return [Grant(id=r[0], principal_id=r[1],
                      target=GrantTarget(kind=r[2], id=r[3]), access=r[4],
                      scopes_subset=json.loads(r[5]) if r[5] else None,
                      granted_by=r[6], granted_at=r[7], revoked_at=r[8]) for r in rows]

    # --- mcp tokens ---
    def put_mcp_token(self, t):
        with self._mu:
            self._db.execute("INSERT OR REPLACE INTO mcp_tokens VALUES (?,?,?,?,?,?,?)",
                             (t.hash, t.principal_id, t.org_id, t.audience,
                              t.scope, t.expires_at, t.revoked_at))
            self._db.commit()

    def get_mcp_token(self, token_hash):
        r = self._db.execute("SELECT * FROM mcp_tokens WHERE hash=?", (token_hash,)).fetchone()
        return McpToken(*r) if r else None

    # --- oauth clients ---
    def put_oauth_client(self, c):
        with self._mu:
            self._db.execute("INSERT OR REPLACE INTO oauth_clients VALUES (?,?,?,?,?)",
                             (c.id, c.name, json.dumps(c.redirect_uris), c.type,
                              c.client_id_metadata_url))
            self._db.commit()

    def get_oauth_client(self, client_id):
        r = self._db.execute("SELECT * FROM oauth_clients WHERE id=?", (client_id,)).fetchone()
        if r is None:
            return None
        return OAuthClient(id=r[0], name=r[1], redirect_uris=json.loads(r[2]),
                           type=r[3], client_id_metadata_url=r[4])

    # --- auth codes ---
    def put_auth_code(self, c):
        with self._mu:
            self._db.execute("INSERT OR REPLACE INTO auth_codes VALUES (?,?,?,?,?,?,?,?,?)",
                             (c.hash, c.client_id, c.principal_id, c.org_id,
                              c.code_challenge, c.audience, c.scope, c.expires_at, c.consumed_at))
            self._db.commit()

    def get_auth_code(self, code_hash):
        r = self._db.execute("SELECT * FROM auth_codes WHERE hash=?", (code_hash,)).fetchone()
        return OAuthAuthCode(*r) if r else None

    def consume_auth_code(self, code_hash, at):
        with self._mu:
            r = self._db.execute("SELECT consumed_at FROM auth_codes WHERE hash=?",
                                 (code_hash,)).fetchone()
            if r is None or r[0] is not None:
                return False
            self._db.execute("UPDATE auth_codes SET consumed_at=? WHERE hash=?", (at, code_hash))
            self._db.commit()
            return True

    # --- access tokens ---
    def put_access_token(self, t):
        with self._mu:
            self._db.execute("INSERT OR REPLACE INTO access_tokens VALUES (?,?,?,?,?,?,?,?)",
                             (t.hash, t.client_id, t.principal_id, t.org_id, t.audience,
                              t.scope, t.expires_at,
                              json.dumps(t.refresh) if t.refresh is not None else None))
            self._db.commit()

    def get_access_token(self, token_hash):
        r = self._db.execute("SELECT * FROM access_tokens WHERE hash=?", (token_hash,)).fetchone()
        if r is None:
            return None
        return OAuthAccessToken(hash=r[0], client_id=r[1], principal_id=r[2], org_id=r[3],
                                audience=r[4], scope=r[5], expires_at=r[6],
                                refresh=json.loads(r[7]) if r[7] else None)

    def rotate_refresh(self, old_hash, new_token):
        with self._mu:
            self._db.execute("DELETE FROM access_tokens WHERE hash=?", (old_hash,))
            self._db.execute("INSERT OR REPLACE INTO access_tokens VALUES (?,?,?,?,?,?,?,?)",
                             (new_token.hash, new_token.client_id, new_token.principal_id,
                              new_token.org_id, new_token.audience, new_token.scope,
                              new_token.expires_at,
                              json.dumps(new_token.refresh) if new_token.refresh else None))
            self._db.commit()

    # --- logs ---
    def append_log(self, entry):
        with self._mu:
            self._db.execute("INSERT INTO logs VALUES (?,?,?,?,?)",
                             (entry.principal_id, entry.org_id, entry.island,
                              entry.capability, entry.at))
            self._db.commit()

    def read_log(self, principal_id):
        rows = self._db.execute("SELECT * FROM logs WHERE principal_id=?",
                                (principal_id,)).fetchall()
        return [AccessLog(*r) for r in rows]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_identity_store_parity.py -v`
Expected: PASS — every test now runs twice (InMemory + Server).

- [ ] **Step 5: Commit**

```bash
git add identity/store/server.py tests/test_identity_store_parity.py
git commit -m "feat(identity): SQLite ServerIdentityStore with backend parity"
```

---

# Phase B — JWT issuer + verify

## Task 5: KeyManager — Ed25519 custody + JWKS document

**Files:**
- Create: `identity/keys.py`
- Modify: `pyproject.toml` (add `PyJWT[crypto]>=2.8` and `cryptography>=42` to dependencies)
- Modify: `.gitignore` (add `*.ed25519`, `kernel-keys/`)
- Test: `tests/test_keys_jwks.py`

**Interfaces:**
- Produces:
  `KeyManager.generate(kid: str) -> KeyManager` (random Ed25519 keypair, in-memory);
  `KeyManager.from_seed(kid: str, seed_b64url: str) -> KeyManager` (deterministic — for tests/golden fixtures and for loading from a secret store);
  `km.kid -> str`; `km.private_pem() -> bytes` (never logged/committed);
  `km.sign(message: bytes) -> bytes`;
  `km.public_jwk() -> dict` (`{"kty":"OKP","crv":"Ed25519","x":<b64url>,"kid":...,"use":"sig","alg":"EdDSA"}`);
  `km.jwks_document() -> dict` (`{"keys": [public_jwk()]}`).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_keys_jwks.py
from identity.keys import KeyManager
from identity.tokens import b64url


def test_jwks_document_shape():
    km = KeyManager.generate("kid-1")
    doc = km.jwks_document()
    jwk = doc["keys"][0]
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == "Ed25519"
    assert jwk["alg"] == "EdDSA"
    assert jwk["use"] == "sig"
    assert jwk["kid"] == "kid-1"
    assert "x" in jwk and "d" not in jwk  # public only, no private scalar


def test_from_seed_is_deterministic():
    seed = b64url(b"\x01" * 32)
    a = KeyManager.from_seed("kid-1", seed).public_jwk()
    b = KeyManager.from_seed("kid-1", seed).public_jwk()
    assert a == b


def test_private_pem_is_not_in_jwks():
    km = KeyManager.generate("kid-1")
    assert b"PRIVATE" in km.private_pem()
    assert "PRIVATE" not in str(km.jwks_document())
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_keys_jwks.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'identity.keys'`.

- [ ] **Step 3: Write minimal implementation**

First add the deps to `pyproject.toml` (under `dependencies`):
```toml
    "PyJWT[crypto]>=2.8",
    "cryptography>=42",
```
Then install: `pip install -e .` (or `pip install 'PyJWT[crypto]>=2.8' 'cryptography>=42'`).

```python
# identity/keys.py
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives import serialization
from identity.tokens import b64url, unb64url


class KeyManager:
    def __init__(self, kid: str, private_key: Ed25519PrivateKey) -> None:
        self.kid = kid
        self._priv = private_key

    @classmethod
    def generate(cls, kid: str) -> "KeyManager":
        return cls(kid, Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, kid: str, seed_b64url: str) -> "KeyManager":
        return cls(kid, Ed25519PrivateKey.from_private_bytes(unb64url(seed_b64url)))

    def private_pem(self) -> bytes:
        return self._priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())

    def sign(self, message: bytes) -> bytes:
        return self._priv.sign(message)

    def _public_raw(self) -> bytes:
        return self._priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def public_jwk(self) -> dict:
        return {
            "kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA",
            "kid": self.kid, "x": b64url(self._public_raw()),
        }

    def jwks_document(self) -> dict:
        return {"keys": [self.public_jwk()]}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_keys_jwks.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add identity/keys.py pyproject.toml .gitignore tests/test_keys_jwks.py
git commit -m "feat(identity): Ed25519 KeyManager and JWKS document"
```

---

## Task 6: mint_island_jwt + build_claims (with back-compat shim)

**Files:**
- Create: `identity/jwt_issuer.py`
- Test: `tests/test_jwt_roundtrip.py`

**Interfaces:**
- Consumes: `KeyManager` (Task 5).
- Produces:
  `build_claims(*, issuer, sub, typ, email, org, roles, perms, sid, audience, scope, iat, exp) -> dict`
  — the spec claim shape, plus the back-compat `userId=sub` and `workspaceId=org`.
  `mint_island_jwt(claims: dict, km: KeyManager) -> str` — PyJWT EdDSA, header `{"kid": km.kid, "alg": "EdDSA"}`.
  A convenience `mint(*, km, issuer, sub, typ, audience, org, roles, ttl, now, email=None, perms=None, sid=None, scope="mcp") -> str` that calls `build_claims` with `iat=now`, `exp=now+ttl`, then `mint_island_jwt`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_jwt_roundtrip.py
import jwt as pyjwt
from identity.keys import KeyManager
from identity.jwt_issuer import build_claims, mint_island_jwt, mint


def test_build_claims_has_spec_shape_and_backcompat():
    c = build_claims(issuer="https://id.x", sub="prn_1", typ="human",
                     email="a@b.se", org="org_1", roles=["owner"], perms=["deals:write"],
                     sid="ses_1", audience="https://mcp.x", scope="mcp",
                     iat=100, exp=400)
    assert c["iss"] == "https://id.x"
    assert c["sub"] == "prn_1"
    assert c["org"] == "org_1"
    assert c["aud"] == "https://mcp.x"
    assert c["userId"] == "prn_1"        # back-compat
    assert c["workspaceId"] == "org_1"   # back-compat
    assert c["exp"] == 400


def test_single_tenant_org_may_be_null():
    c = build_claims(issuer="https://id.x", sub="svc_1", typ="service",
                     email=None, org=None, roles=[], perms=None, sid=None,
                     audience="https://vault.x", scope="mcp", iat=0, exp=300)
    assert c["org"] is None
    assert c["workspaceId"] is None


def test_mint_produces_verifiable_eddsa_token():
    km = KeyManager.generate("kid-1")
    token = mint(km=km, issuer="https://id.x", sub="prn_1", typ="human",
                 audience="https://mcp.x", org="org_1", roles=["owner"],
                 ttl=300, now=1000, email="a@b.se")
    header = pyjwt.get_unverified_header(token)
    assert header["alg"] == "EdDSA"
    assert header["kid"] == "kid-1"
    # verify signature with the public key
    decoded = pyjwt.decode(token, km._priv.public_key(), algorithms=["EdDSA"],
                           audience="https://mcp.x", options={"verify_exp": False})
    assert decoded["sub"] == "prn_1" and decoded["exp"] == 1300
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_jwt_roundtrip.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'identity.jwt_issuer'`.

- [ ] **Step 3: Write minimal implementation**

```python
# identity/jwt_issuer.py
from typing import Optional
import jwt as pyjwt
from identity.keys import KeyManager


def build_claims(*, issuer: str, sub: str, typ: str, email: Optional[str],
                 org: Optional[str], roles: list, perms: Optional[list],
                 sid: Optional[str], audience: str, scope: str,
                 iat: int, exp: int) -> dict:
    claims = {
        "iss": issuer, "sub": sub, "typ": typ, "email": email,
        "org": org, "roles": roles, "sid": sid,
        "aud": audience, "scope": scope, "iat": iat, "exp": exp,
        # back-compat shim — sm-brf reads userId, nudge reads workspaceId
        "userId": sub, "workspaceId": org,
    }
    if perms is not None:
        claims["perms"] = perms
    return claims


def mint_island_jwt(claims: dict, km: KeyManager) -> str:
    return pyjwt.encode(claims, km.private_pem(), algorithm="EdDSA",
                        headers={"kid": km.kid})


def mint(*, km: KeyManager, issuer: str, sub: str, typ: str, audience: str,
         org: Optional[str], roles: list, ttl: int, now: int,
         email: Optional[str] = None, perms: Optional[list] = None,
         sid: Optional[str] = None, scope: str = "mcp") -> str:
    claims = build_claims(issuer=issuer, sub=sub, typ=typ, email=email, org=org,
                          roles=roles, perms=perms, sid=sid, audience=audience,
                          scope=scope, iat=int(now), exp=int(now) + int(ttl))
    return mint_island_jwt(claims, km)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_jwt_roundtrip.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add identity/jwt_issuer.py tests/test_jwt_roundtrip.py
git commit -m "feat(identity): EdDSA JWT minting with legacy back-compat claims"
```

---

## Task 7: verify_island_jwt (Python, offline via JWKS dict)

**Files:**
- Create: `identity/jwt_verify.py`
- Test: `tests/test_jwt_verify_python.py`

**Interfaces:**
- Consumes: a JWKS document dict (from `KeyManager.jwks_document()` or fetched/cached by an island).
- Produces:
  `Claims` = a thin `dict` alias (return the decoded payload).
  `verify_island_jwt(token: str, *, jwks: dict, audience: str, now: float, issuer: Optional[str] = None) -> dict`
  — selects the JWK by the token's `kid`, verifies the EdDSA signature and `aud` (and `iss` if given),
  checks `exp` against the injected `now` (PyJWT `verify_exp` disabled), raises `ValueError` on any failure.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_jwt_verify_python.py
import pytest
from identity.keys import KeyManager
from identity.jwt_issuer import mint
from identity.jwt_verify import verify_island_jwt


def _token(km, now=1000, ttl=300, aud="https://mcp.x", org="org_1"):
    return mint(km=km, issuer="https://id.x", sub="prn_1", typ="human",
                audience=aud, org=org, roles=["owner"], ttl=ttl, now=now,
                email="a@b.se")


def test_valid_token_verifies():
    km = KeyManager.generate("kid-1")
    claims = verify_island_jwt(_token(km), jwks=km.jwks_document(),
                               audience="https://mcp.x", now=1100,
                               issuer="https://id.x")
    assert claims["sub"] == "prn_1"
    assert claims["org"] == "org_1"


def test_expired_token_is_rejected():
    km = KeyManager.generate("kid-1")
    with pytest.raises(ValueError):
        verify_island_jwt(_token(km, now=0, ttl=300), jwks=km.jwks_document(),
                          audience="https://mcp.x", now=10_000)


def test_wrong_audience_is_rejected():
    km = KeyManager.generate("kid-1")
    with pytest.raises(ValueError):
        verify_island_jwt(_token(km, aud="https://mcp.A"), jwks=km.jwks_document(),
                          audience="https://mcp.B", now=1100)


def test_unknown_kid_is_rejected():
    km1 = KeyManager.generate("kid-1")
    km2 = KeyManager.generate("kid-2")
    with pytest.raises(ValueError):
        verify_island_jwt(_token(km1), jwks=km2.jwks_document(),
                          audience="https://mcp.x", now=1100)


def test_tampered_signature_is_rejected():
    km1 = KeyManager.generate("kid-1")
    # sign with a different key but advertise kid-1 in the JWKS we present
    km_impostor = KeyManager.generate("kid-1")
    with pytest.raises(ValueError):
        verify_island_jwt(_token(km_impostor), jwks=km1.jwks_document(),
                          audience="https://mcp.x", now=1100)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_jwt_verify_python.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'identity.jwt_verify'`.

- [ ] **Step 3: Write minimal implementation**

```python
# identity/jwt_verify.py
from typing import Optional
import jwt as pyjwt
from jwt.algorithms import OKPAlgorithm


def _public_key_for_kid(jwks: dict, kid: str):
    for jwk in jwks.get("keys", []):
        if jwk.get("kid") == kid:
            return OKPAlgorithm.from_jwk(jwk)
    raise ValueError(f"no JWK for kid={kid}")


def verify_island_jwt(token: str, *, jwks: dict, audience: str, now: float,
                      issuer: Optional[str] = None) -> dict:
    try:
        kid = pyjwt.get_unverified_header(token).get("kid")
    except pyjwt.PyJWTError as e:
        raise ValueError(f"bad token header: {e}")
    if not kid:
        raise ValueError("token missing kid")

    pub = _public_key_for_kid(jwks, kid)
    try:
        claims = pyjwt.decode(
            token, pub, algorithms=["EdDSA"], audience=audience,
            issuer=issuer,
            options={"verify_exp": False, "verify_iss": issuer is not None,
                     "require": ["exp", "sub", "aud"]})
    except pyjwt.PyJWTError as e:
        raise ValueError(f"jwt verification failed: {e}")

    if now >= claims["exp"]:
        raise ValueError("token expired")
    return claims
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_jwt_verify_python.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add identity/jwt_verify.py tests/test_jwt_verify_python.py
git commit -m "feat(identity): offline Python JWT verification via JWKS"
```

---

## Task 8: resolve_org (org-resolution rule)

**Files:**
- Create: `identity/resolve.py`
- Test: `tests/test_resolve_org.py`

**Interfaces:**
- Consumes: `IdentityStore` (for membership checks).
- Produces:
  `class OrgRequired(ValueError)` — raised as `400 ORG_REQUIRED` at the HTTP edge.
  `resolve_org(*, store, principal_id, jwt_org=None, header_org_id=None) -> str` implementing:
  `jwt.org` if active member → else `X-Org-Id` header if active member → else the sole active membership → else raise `OrgRequired`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_resolve_org.py
import pytest
from identity.store.memory import InMemoryIdentityStore
from identity.model import Membership
from identity.resolve import resolve_org, OrgRequired


def _store(*memberships):
    s = InMemoryIdentityStore()
    for m in memberships:
        s.put_membership(m)
    return s


def test_jwt_org_wins_when_member():
    s = _store(Membership("prn_1", "org_A", ["member"], True, 0.0),
               Membership("prn_1", "org_B", ["member"], True, 0.0))
    assert resolve_org(store=s, principal_id="prn_1", jwt_org="org_A") == "org_A"


def test_jwt_org_ignored_when_not_member_falls_to_header():
    s = _store(Membership("prn_1", "org_B", ["member"], True, 0.0))
    assert resolve_org(store=s, principal_id="prn_1", jwt_org="org_X",
                       header_org_id="org_B") == "org_B"


def test_sole_membership_is_used():
    s = _store(Membership("prn_1", "org_B", ["member"], True, 0.0))
    assert resolve_org(store=s, principal_id="prn_1") == "org_B"


def test_no_signal_and_multiple_memberships_raises():
    s = _store(Membership("prn_1", "org_A", ["member"], True, 0.0),
               Membership("prn_1", "org_B", ["member"], True, 0.0))
    with pytest.raises(OrgRequired):
        resolve_org(store=s, principal_id="prn_1")


def test_inactive_membership_does_not_count():
    s = _store(Membership("prn_1", "org_B", ["member"], False, 0.0))
    with pytest.raises(OrgRequired):
        resolve_org(store=s, principal_id="prn_1")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_resolve_org.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'identity.resolve'`.

- [ ] **Step 3: Write minimal implementation**

```python
# identity/resolve.py
from typing import Optional


class OrgRequired(ValueError):
    pass


def _is_active_member(store, principal_id: str, org_id: str) -> bool:
    m = store.get_membership(principal_id, org_id)
    return m is not None and m.active


def resolve_org(*, store, principal_id: str, jwt_org: Optional[str] = None,
                header_org_id: Optional[str] = None) -> str:
    if jwt_org and _is_active_member(store, principal_id, jwt_org):
        return jwt_org
    if header_org_id and _is_active_member(store, principal_id, header_org_id):
        return header_org_id
    active = [m.org_id for m in store.list_memberships(principal_id) if m.active]
    if len(active) == 1:
        return active[0]
    raise OrgRequired("ORG_REQUIRED")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_resolve_org.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add identity/resolve.py tests/test_resolve_org.py
git commit -m "feat(identity): org-resolution rule with ORG_REQUIRED"
```

---

## Task 9: authorize() — generalized grant check + connection-grant adapter

**Files:**
- Create: `identity/authorize.py`
- Test: `tests/test_authorize.py`

**Interfaces:**
- Consumes: `Grant`, `GrantTarget`, `Access` (Task 1); slice-1 `ConnectionGrant` (`vault/model.py`).
- Produces:
  `adapt_connection_grant(cg, *, owner_principal_id=None) -> Grant` — view a slice-1 `ConnectionGrant` as a unified `Grant` with `target.kind="connection"` (no data migration). An owner is rendered as a synthetic `manage` grant.
  `collect_grants(*, principal_id, identity_store, connection_grants=()) -> list[Grant]` — unified grants from the identity store plus adapted connection grants.
  `authorize(*, grants, target, access, now) -> bool` — pure policy. Authority nests: a `manage`/`use` grant on `org:O` covers `island`/`capability`/`connection` targets in scope of `O` **when the grant's target id matches by the nesting rule below**; same-kind id match otherwise; revoked grants (`revoked_at` set and `<= now`) are ignored; `manage` satisfies `use`.

  Nesting rule (kept explicit and minimal for this slice): a grant authorizes a request when, for the request `target`/`access`:
  - `satisfies(grant.access, access)` is true, AND
  - the grant's target **covers** the request target: exact `(kind,id)` match, OR `grant.target.kind=="org"` and `grant.target.id == org_of(target)` for `island`/`capability`/`connection` requests. For this slice, `org`-scoped grants pass an explicit `org_id` alongside the target (callers that need org-nesting pass `request_org`). Connection/island/capability ids are matched exactly; org coverage is opt-in via `request_org`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_authorize.py
from identity.model import Grant, GrantTarget
from identity.authorize import authorize, adapt_connection_grant, collect_grants
from identity.store.memory import InMemoryIdentityStore
from vault.model import ConnectionGrant


def _grant(target_kind, target_id, access="use", revoked=None, gid="g"):
    return Grant(id=gid, principal_id="prn_1",
                 target=GrantTarget(target_kind, target_id), access=access,
                 scopes_subset=None, granted_by="prn_o", granted_at=0.0,
                 revoked_at=revoked)


def test_exact_target_use_grant_authorizes_use():
    grants = [_grant("connection", "conn_1", "use")]
    assert authorize(grants=grants,
                     target=GrantTarget("connection", "conn_1"),
                     access="use", now=10) is True


def test_manage_satisfies_use():
    grants = [_grant("island", "smartcharge", "manage")]
    assert authorize(grants=grants, target=GrantTarget("island", "smartcharge"),
                     access="use", now=10) is True


def test_use_does_not_satisfy_manage():
    grants = [_grant("island", "smartcharge", "use")]
    assert authorize(grants=grants, target=GrantTarget("island", "smartcharge"),
                     access="manage", now=10) is False


def test_org_grant_covers_nested_target_when_request_org_given():
    grants = [_grant("org", "org_1", "use")]
    assert authorize(grants=grants, target=GrantTarget("connection", "conn_9"),
                     access="use", now=10, request_org="org_1") is True


def test_revoked_grant_is_ignored():
    grants = [_grant("connection", "conn_1", "use", revoked=5.0)]
    assert authorize(grants=grants, target=GrantTarget("connection", "conn_1"),
                     access="use", now=10) is False


def test_no_grant_denies():
    assert authorize(grants=[], target=GrantTarget("connection", "conn_1"),
                     access="use", now=10) is False


def test_adapt_connection_grant_owner_is_manage():
    g = adapt_connection_grant(None, owner_connection_id="conn_1")
    assert g.target == GrantTarget("connection", "conn_1") and g.access == "manage"


def test_adapt_connection_grant_from_row():
    cg = ConnectionGrant(connection_id="conn_1", principal_id="prn_1",
                         access="use", scopes_subset=["read"],
                         granted_by="prn_o", granted_at=0.0)
    g = adapt_connection_grant(cg)
    assert g.target == GrantTarget("connection", "conn_1")
    assert g.access == "use" and g.scopes_subset == ["read"]


def test_collect_merges_identity_and_connection_grants():
    s = InMemoryIdentityStore()
    s.add_grant(_grant("island", "smartcharge", "use", gid="g1"))
    cg = ConnectionGrant("conn_1", "prn_1", "use", None, "prn_o", 0.0)
    out = collect_grants(principal_id="prn_1", identity_store=s,
                         connection_grants=[cg])
    kinds = {g.target.kind for g in out}
    assert kinds == {"island", "connection"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_authorize.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'identity.authorize'`.

- [ ] **Step 3: Write minimal implementation**

```python
# identity/authorize.py
from typing import Optional, Iterable
from identity.model import Grant, GrantTarget, Access

_RANK = {"use": 1, "manage": 2}


def _satisfies(grant_access: Access, need: Access) -> bool:
    return _RANK[grant_access] >= _RANK[need]


def _covers(grant_target: GrantTarget, target: GrantTarget,
            request_org: Optional[str]) -> bool:
    if grant_target.kind == target.kind and grant_target.id == target.id:
        return True
    # org-scoped grant nests over island/capability/connection in that org
    if (grant_target.kind == "org" and request_org is not None
            and grant_target.id == request_org
            and target.kind in ("island", "capability", "connection")):
        return True
    return False


def authorize(*, grants: Iterable[Grant], target: GrantTarget, access: Access,
              now: float, request_org: Optional[str] = None) -> bool:
    for g in grants:
        if g.revoked_at is not None and g.revoked_at <= now:
            continue
        if _satisfies(g.access, access) and _covers(g.target, target, request_org):
            return True
    return False


def adapt_connection_grant(cg, *, owner_connection_id: Optional[str] = None) -> Grant:
    if owner_connection_id is not None:
        return Grant(id=f"owner:{owner_connection_id}", principal_id="",
                     target=GrantTarget("connection", owner_connection_id),
                     access="manage", scopes_subset=None, granted_by="",
                     granted_at=0.0, revoked_at=None)
    return Grant(id=f"cg:{cg.connection_id}:{cg.principal_id}",
                 principal_id=cg.principal_id,
                 target=GrantTarget("connection", cg.connection_id),
                 access=cg.access, scopes_subset=cg.scopes_subset,
                 granted_by=cg.granted_by, granted_at=cg.granted_at, revoked_at=None)


def collect_grants(*, principal_id: str, identity_store,
                   connection_grants: Iterable = ()) -> list[Grant]:
    out = list(identity_store.list_grants(principal_id))
    out.extend(adapt_connection_grant(cg) for cg in connection_grants)
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_authorize.py -v`
Expected: PASS (9 tests).

- [ ] **Step 5: Commit**

```bash
git add identity/authorize.py tests/test_authorize.py
git commit -m "feat(identity): generalized authorize() with connection-grant adapter"
```

---

# Phase C — Exchange, vault retrofit, bookkeeping path

## Task 10: exchange (opaque MCP/OAuth token → resolved principal)

**Files:**
- Create: `identity/exchange.py`
- Test: `tests/test_exchange.py`

**Interfaces:**
- Consumes: `IdentityStore`, `hash_token` (Task 2), `McpToken`/`OAuthAccessToken` (Task 1).
- Produces:
  `class ExchangeError(ValueError)`.
  `exchange(*, opaque_token, audience, store, now) -> dict` returning `{"principal_id", "org_id", "roles", "sid"}`.
  Looks up by `hash_token(opaque)` in mcp tokens then oauth access tokens; rejects unknown, expired, revoked, or audience-mismatched tokens. `roles`/`sid` come from the principal's membership in `org_id` (roles) — `sid` is `None` for stateless MCP tokens. The caller mints the 5-min JWT from this result.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_exchange.py
import pytest
from identity.store.memory import InMemoryIdentityStore
from identity.model import McpToken, Membership, OAuthAccessToken
from identity.tokens import hash_token
from identity.exchange import exchange, ExchangeError


def _store_with_mcp(raw="mcp_abc", aud="https://mcp.x", exp=2000, revoked=None):
    s = InMemoryIdentityStore()
    s.put_mcp_token(McpToken(hash=hash_token(raw), principal_id="prn_1",
                             org_id="org_1", audience=aud, scope="mcp",
                             expires_at=exp, revoked_at=revoked))
    s.put_membership(Membership("prn_1", "org_1", ["member"], True, 0.0))
    return s


def test_valid_mcp_token_resolves_principal_and_roles():
    s = _store_with_mcp()
    out = exchange(opaque_token="mcp_abc", audience="https://mcp.x", store=s, now=1000)
    assert out["principal_id"] == "prn_1"
    assert out["org_id"] == "org_1"
    assert out["roles"] == ["member"]
    assert out["sid"] is None


def test_audience_mismatch_rejected():
    s = _store_with_mcp(aud="https://mcp.A")
    with pytest.raises(ExchangeError):
        exchange(opaque_token="mcp_abc", audience="https://mcp.B", store=s, now=1000)


def test_expired_token_rejected():
    s = _store_with_mcp(exp=500)
    with pytest.raises(ExchangeError):
        exchange(opaque_token="mcp_abc", audience="https://mcp.x", store=s, now=1000)


def test_revoked_token_rejected():
    s = _store_with_mcp(revoked=900)
    with pytest.raises(ExchangeError):
        exchange(opaque_token="mcp_abc", audience="https://mcp.x", store=s, now=1000)


def test_unknown_token_rejected():
    s = _store_with_mcp()
    with pytest.raises(ExchangeError):
        exchange(opaque_token="mcp_nope", audience="https://mcp.x", store=s, now=1000)


def test_oauth_access_token_path():
    s = InMemoryIdentityStore()
    s.put_access_token(OAuthAccessToken(hash=hash_token("at_xyz"), client_id="cli",
                                        principal_id="prn_2", org_id="org_2",
                                        audience="https://mcp.x", scope="mcp",
                                        expires_at=2000, refresh=None))
    s.put_membership(Membership("prn_2", "org_2", ["admin"], True, 0.0))
    out = exchange(opaque_token="at_xyz", audience="https://mcp.x", store=s, now=1000)
    assert out["principal_id"] == "prn_2" and out["roles"] == ["admin"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_exchange.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'identity.exchange'`.

- [ ] **Step 3: Write minimal implementation**

```python
# identity/exchange.py
from identity.tokens import hash_token


class ExchangeError(ValueError):
    pass


def exchange(*, opaque_token: str, audience: str, store, now: float) -> dict:
    h = hash_token(opaque_token)
    row = store.get_mcp_token(h)
    if row is None:
        row = store.get_access_token(h)
    if row is None:
        raise ExchangeError("unknown token")
    if getattr(row, "revoked_at", None) is not None:
        raise ExchangeError("revoked token")
    if row.audience is not None and row.audience != audience:
        raise ExchangeError("audience mismatch")
    if row.expires_at is not None and now >= row.expires_at:
        raise ExchangeError("expired token")

    m = store.get_membership(row.principal_id, row.org_id) if row.org_id else None
    roles = m.roles if (m is not None and m.active) else []
    return {"principal_id": row.principal_id, "org_id": row.org_id,
            "roles": roles, "sid": None}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_exchange.py -v`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add identity/exchange.py tests/test_exchange.py
git commit -m "feat(identity): opaque-token exchange to resolved principal"
```

---

## Task 11: FastAPI require_principal dependency

**Files:**
- Create: `identity/deps.py`
- Test: `tests/test_vault_auth_seam.py` (dependency-level tests; the vault wiring lands in Task 12)

**Interfaces:**
- Consumes: `verify_island_jwt` (Task 7).
- Produces:
  `class Claims(dict)` (typed marker).
  `make_require_principal(*, jwks_provider, audience, now_fn, issuer=None) -> Depends-callable` where `jwks_provider() -> dict` (injectable so tests pass a static JWKS and production caches a fetched one). The returned dependency reads `Authorization: Bearer <jwt>` (falling back to `Cookie: auth=<jwt>`), verifies it, and returns the `Claims`. Missing/invalid → `HTTPException(401)`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_vault_auth_seam.py
import pytest
from fastapi import HTTPException
from identity.keys import KeyManager
from identity.jwt_issuer import mint
from identity.deps import make_require_principal


def _dep(km, now=1100):
    return make_require_principal(jwks_provider=lambda: km.jwks_document(),
                                  audience="https://vault.x", now_fn=lambda: now,
                                  issuer="https://id.x")


def _token(km, aud="https://vault.x"):
    return mint(km=km, issuer="https://id.x", sub="prn_1", typ="human",
                audience=aud, org="org_1", roles=["owner"], ttl=300, now=1000)


def test_bearer_header_resolves_claims():
    km = KeyManager.generate("kid-1")
    dep = _dep(km)
    claims = dep(authorization=f"Bearer {_token(km)}", cookie_auth=None)
    assert claims["sub"] == "prn_1"


def test_cookie_fallback_resolves_claims():
    km = KeyManager.generate("kid-1")
    dep = _dep(km)
    claims = dep(authorization=None, cookie_auth=_token(km))
    assert claims["sub"] == "prn_1"


def test_missing_token_is_401():
    km = KeyManager.generate("kid-1")
    dep = _dep(km)
    with pytest.raises(HTTPException) as e:
        dep(authorization=None, cookie_auth=None)
    assert e.value.status_code == 401


def test_wrong_audience_is_401():
    km = KeyManager.generate("kid-1")
    dep = _dep(km)
    with pytest.raises(HTTPException) as e:
        dep(authorization=f"Bearer {_token(km, aud='https://other')}", cookie_auth=None)
    assert e.value.status_code == 401
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_vault_auth_seam.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'identity.deps'`.

- [ ] **Step 3: Write minimal implementation**

```python
# identity/deps.py
from typing import Optional, Callable
from fastapi import Header, Cookie, HTTPException
from identity.jwt_verify import verify_island_jwt


class Claims(dict):
    pass


def make_require_principal(*, jwks_provider: Callable[[], dict], audience: str,
                           now_fn: Callable[[], float], issuer: Optional[str] = None):
    def require_principal(
        authorization: Optional[str] = Header(default=None),
        cookie_auth: Optional[str] = Cookie(default=None, alias="auth"),
    ) -> Claims:
        token = None
        if authorization and authorization.lower().startswith("bearer "):
            token = authorization[7:]
        elif cookie_auth:
            token = cookie_auth
        if not token:
            raise HTTPException(401, "missing bearer token")
        try:
            claims = verify_island_jwt(token, jwks=jwks_provider(),
                                       audience=audience, now=now_fn(),
                                       issuer=issuer)
        except ValueError as e:
            raise HTTPException(401, str(e))
        return Claims(claims)

    return require_principal
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_vault_auth_seam.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add identity/deps.py tests/test_vault_auth_seam.py
git commit -m "feat(identity): FastAPI require_principal JWT dependency"
```

---

## Task 12: Vault retrofit — replace Header("stub") with real auth + authorize()

> **GUARDED STEP.** This is the change that puts the live bookkeeping vault behind real kernel auth. Do NOT push or deploy from this task. The plan's wiring is flag-gated: the new dependency is mounted only when a JWKS provider is configured; with no kernel configured, `access.py` keeps accepting the legacy principal string so the in-process slice-1 callers and existing tests stay green. The live cutover (issuing bookkeeping a service-principal credential and flipping the flag in prod) is a separate, human-run gated step described at the end of this task — stop and check before doing it.

**Files:**
- Modify: `vault/access.py` — `get_access_token` accepts a resolved `principal_id` (unchanged) but the caller now derives it from verified `Claims`; add an `authorize()`-based check path alongside the existing `require_access`.
- Modify: `vault/app.py` — add an optional kernel-auth dependency; when configured, the access-token route resolves the principal from the JWT instead of `Header("stub")`.
- Test: `tests/test_vault_auth_seam.py` (extend with an app-level test using FastAPI `TestClient`).

**Interfaces:**
- Consumes: `make_require_principal` (Task 11), `authorize`/`collect_grants` (Task 9), `resolve_org` (Task 8).
- Produces: `build_app(service, *, require_principal=None)` — when `require_principal` is provided, the access-token route depends on it and uses `claims["sub"]` as the principal and `claims["org"]` as the org; when `None`, the legacy `Header("stub")` path is preserved unchanged.

- [ ] **Step 1: Write the failing test** (append to `tests/test_vault_auth_seam.py`)

```python
from fastapi.testclient import TestClient
from vault.app import build_app
from vault.access import AccessService
from vault.config import VaultConfig
from vault.store.memory import InMemoryStore
from vault.model import Connection, Token
from vault.providers.fortnox import FortnoxProvider
from vault.providers.base import AppCred


def _vault_service():
    store = InMemoryStore()
    store.put_connection(Connection(
        id="conn_1", org="org_1", provider="fortnox", account="559401-5157",
        scopes=["bookkeeping"], app_cred_ref="fortnox",
        token=Token("ACCESS", "REFRESH", 99999.0, "bookkeeping"),
        rotation="rotating", lease=None, created_by="prn_owner",
        created_at=0.0, updated_at=0.0))
    cfg = VaultConfig(now_fn=lambda: 1000.0, http_post=lambda *a: {},
                      app_creds={"fortnox": AppCred("cid", "secret")},
                      state_hmac_key=b"k", skew=60)
    return AccessService(store, {"fortnox": FortnoxProvider()}, cfg)


def test_access_token_route_requires_valid_jwt():
    km = KeyManager.generate("kid-1")
    dep = make_require_principal(jwks_provider=lambda: km.jwks_document(),
                                 audience="https://vault.x", now_fn=lambda: 1100.0,
                                 issuer="https://id.x")
    app = build_app(_vault_service(), require_principal=dep)
    client = TestClient(app)

    # no token -> 401
    r = client.post("/connections/org_1%2Ffortnox%2F559401-5157/access-token")
    assert r.status_code == 401

    # owner token -> 200, no refresh token leaked
    owner = mint(km=km, issuer="https://id.x", sub="prn_owner", typ="human",
                 audience="https://vault.x", org="org_1", roles=["owner"],
                 ttl=300, now=1000)
    r = client.post("/connections/org_1%2Ffortnox%2F559401-5157/access-token",
                    headers={"Authorization": f"Bearer {owner}"})
    assert r.status_code == 200
    assert r.json()["accessToken"] == "ACCESS"
    assert "refresh" not in r.text.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_vault_auth_seam.py -v`
Expected: FAIL — `build_app()` does not yet accept `require_principal`.

- [ ] **Step 3: Write minimal implementation**

In `vault/app.py`, thread an optional dependency into the access-token route. Keep every other route and the `guard()` helper unchanged.

```python
# vault/app.py  (access-token route — conditional auth)
from typing import Optional, Callable
from fastapi import Depends

def build_app(service, *, require_principal: Optional[Callable] = None) -> FastAPI:
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

    if require_principal is not None:
        @app.post("/connections/{conn_id:path}/access-token")
        async def access_token_authed(conn_id: str, claims=Depends(require_principal)):
            principal = claims["sub"]
            island = claims.get("aud", "unknown")
            return guard(lambda: service.get_access_token(
                _parse_id(conn_id), principal, island))
    else:
        @app.post("/connections/{conn_id:path}/access-token")
        async def access_token_stub(conn_id: str,
                                    x_principal: str = Header("stub"),
                                    x_island: str = Header("unknown")):
            return guard(lambda: service.get_access_token(
                _parse_id(conn_id), x_principal, x_island))

    # ... all other existing routes unchanged ...
    return app
```

`vault/access.py` is unchanged in behavior: `get_access_token` still calls `require_access(self.store, conn, principal_id, "use")`, which already authorizes owner-or-connection-grant. The unified `authorize()` is exercised through the connection-grant adapter in the cross-language proof (Task 16); the vault's hot path keeps the slice-1 `require_access` for the connection target with no migration.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/ -v`
Expected: PASS — the new app-level tests pass AND every pre-existing slice-1 test (which calls `build_app(service)` with no `require_principal`) still passes unchanged.

- [ ] **Step 5: Commit**

```bash
git add vault/app.py tests/test_vault_auth_seam.py
git commit -m "feat(vault): optional kernel-JWT auth on the access-token route"
```

**Live cutover (separate, human-run — do NOT do it in this task):**
1. Create a service `Principal` for bookkeeping and an active `Membership` in its `Org`; grant it `use` on the Fortnox connection (or rely on owner).
2. Issue bookkeeping a long-lived MCP/credential it can `exchange` for a 5-min JWT (audience = the vault).
3. Verify bookkeeping fetches a Fortnox token BEFORE the flip (legacy path) and AFTER (kernel path) — show diffs, prove both.
4. Only then set the vault's `VAULT_REQUIRE_KERNEL=1` flag in prod. Stop and check before this step.

---

## Task 13: Python verify lib + bookkeeping-style access-matrix path (proof)

**Files:**
- Create: `libs/python/islands_vault/verify.py`
- Test: `tests/test_bookkeeping_verify_path.py`

**Interfaces:**
- Consumes: `verify_island_jwt` (Task 7).
- Produces: `libs/python/islands_vault/verify.py` re-exporting `verify_island_jwt` as the island-facing import surface (`from islands_vault.verify import verify_island_jwt`). The test proves a bookkeeping-style FastAPI dependency keys an `access-matrix` decision on `claims["email"]` (the verified principal), replacing `X-User-Email` header-trust.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bookkeeping_verify_path.py
import pytest
from identity.keys import KeyManager
from identity.jwt_issuer import mint
from islands_vault.verify import verify_island_jwt

# a stand-in for bookkeeping's policies/access-matrix.yml, keyed on email
ACCESS_MATRIX = {"reconcile": ["bookkeeper@caput-venti.se"]}


def _bookkeeping_authorize(claims: dict, capability: str) -> bool:
    allowed = ACCESS_MATRIX.get(capability, [])
    return claims.get("email") in allowed


def test_verified_principal_drives_access_matrix():
    km = KeyManager.generate("kid-1")
    token = mint(km=km, issuer="https://id.x", sub="prn_bk", typ="human",
                 audience="https://bk.x", org="caput-venti", roles=["member"],
                 ttl=300, now=1000, email="bookkeeper@caput-venti.se")
    claims = verify_island_jwt(token, jwks=km.jwks_document(),
                               audience="https://bk.x", now=1100, issuer="https://id.x")
    assert _bookkeeping_authorize(claims, "reconcile") is True


def test_unlisted_principal_denied():
    km = KeyManager.generate("kid-1")
    token = mint(km=km, issuer="https://id.x", sub="prn_x", typ="human",
                 audience="https://bk.x", org="caput-venti", roles=["member"],
                 ttl=300, now=1000, email="intruder@example.com")
    claims = verify_island_jwt(token, jwks=km.jwks_document(),
                               audience="https://bk.x", now=1100, issuer="https://id.x")
    assert _bookkeeping_authorize(claims, "reconcile") is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_bookkeeping_verify_path.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'islands_vault.verify'` (or import path error).

- [ ] **Step 3: Write minimal implementation**

```python
# libs/python/islands_vault/verify.py
"""Island-facing verify surface. Islands import this, not the kernel internals.

The kernel signs; islands only verify, offline, against the published JWKS.
"""
from identity.jwt_verify import verify_island_jwt

__all__ = ["verify_island_jwt"]
```

Ensure the test can import both `identity` and `islands_vault` (the latter lives under `libs/python/`). Add `libs/python` to the test path via `pyproject.toml` `[tool.pytest.ini_options] pythonpath = [".", "libs/python"]` if not already resolvable.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_bookkeeping_verify_path.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add libs/python/islands_vault/verify.py pyproject.toml tests/test_bookkeeping_verify_path.py
git commit -m "feat(libs): python verify surface + bookkeeping access-matrix proof"
```

---

## Task 14: Node verify lib (jose)

**Files:**
- Create: `libs/node/src/verify.ts`
- Modify: `libs/node/package.json` (add `jose` dependency)
- Test: `libs/node/test/verify.test.ts`

**Interfaces:**
- Produces:
  `verifyIslandJwt(token: string, opts: { jwks: JSONWebKeySet; audience: string; issuer?: string; now?: number }): Promise<JWTPayload>` — verifies EdDSA via a local JWKS (offline), checks `aud`/`iss`/`exp` (against `opts.now` if given, else current time), throws on failure.
  `fetchJwks(url: string, fetchImpl?): Promise<JSONWebKeySet>` — fetch + return the JWKS (caching is the caller's concern; injectable fetch for tests).

- [ ] **Step 1: Write the failing test**

```typescript
// libs/node/test/verify.test.ts
import { describe, it, expect } from "vitest";
import { generateKeyPair, SignJWT, exportJWK } from "jose";
import { verifyIslandJwt } from "../src/verify";

async function setup() {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", { crv: "Ed25519" });
  const jwk = await exportJWK(publicKey);
  jwk.kid = "kid-1"; jwk.alg = "EdDSA"; jwk.use = "sig";
  const jwks = { keys: [jwk] };
  const token = await new SignJWT({ org: "org_1" })
    .setProtectedHeader({ alg: "EdDSA", kid: "kid-1" })
    .setIssuer("https://id.x").setSubject("prn_1")
    .setAudience("https://mcp.x").setIssuedAt(1000).setExpirationTime(1300)
    .sign(privateKey);
  return { jwks, token };
}

describe("verifyIslandJwt", () => {
  it("verifies a valid EdDSA token offline", async () => {
    const { jwks, token } = await setup();
    const claims = await verifyIslandJwt(token, {
      jwks, audience: "https://mcp.x", issuer: "https://id.x", now: 1100,
    });
    expect(claims.sub).toBe("prn_1");
    expect(claims.org).toBe("org_1");
  });

  it("rejects a wrong audience", async () => {
    const { jwks, token } = await setup();
    await expect(verifyIslandJwt(token, {
      jwks, audience: "https://other", now: 1100,
    })).rejects.toThrow();
  });

  it("rejects an expired token", async () => {
    const { jwks, token } = await setup();
    await expect(verifyIslandJwt(token, {
      jwks, audience: "https://mcp.x", now: 9999,
    })).rejects.toThrow();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd libs/node && npm install && npx vitest run test/verify.test.ts`
Expected: FAIL — `../src/verify` does not exist.

- [ ] **Step 3: Write minimal implementation**

Add `jose` to `libs/node/package.json` dependencies, then:

```typescript
// libs/node/src/verify.ts
import { jwtVerify, importJWK, type JSONWebKeySet, type JWTPayload } from "jose";

export interface VerifyOpts {
  jwks: JSONWebKeySet;
  audience: string;
  issuer?: string;
  now?: number; // seconds; defaults to current time
}

export async function verifyIslandJwt(token: string, opts: VerifyOpts): Promise<JWTPayload> {
  const getKey = async (header: { kid?: string; alg?: string }) => {
    const jwk = opts.jwks.keys.find((k) => (k as any).kid === header.kid);
    if (!jwk) throw new Error(`no JWK for kid=${header.kid}`);
    return importJWK(jwk, "EdDSA");
  };
  const { payload } = await jwtVerify(token, getKey, {
    audience: opts.audience,
    issuer: opts.issuer,
    algorithms: ["EdDSA"],
    currentDate: opts.now !== undefined ? new Date(opts.now * 1000) : undefined,
  });
  return payload;
}

export async function fetchJwks(
  url: string,
  fetchImpl: typeof fetch = fetch,
): Promise<JSONWebKeySet> {
  const res = await fetchImpl(url);
  if (!res.ok) throw new Error(`jwks fetch failed: ${res.status}`);
  return (await res.json()) as JSONWebKeySet;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd libs/node && npx vitest run test/verify.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add libs/node/src/verify.ts libs/node/package.json libs/node/package-lock.json libs/node/test/verify.test.ts
git commit -m "feat(libs): node EdDSA JWT verify via jose"
```

---

# Phase D — OAuth 2.1 authorization server (claude.ai)

> Phase D gates claude.ai *consumption* only. Nothing in the locked 2→3→6 critical path or the server-posture vault (prompt 4) blocks on it, so it lands last. It can be split into its own session if Phases A–C are landed first.

## Task 15: OAuth client registry + Client ID Metadata Documents

**Files:**
- Create: `identity/oauth/__init__.py` (empty)
- Create: `identity/oauth/clients.py`
- Test: `tests/test_oauth_clients.py`

**Interfaces:**
- Consumes: `IdentityStore` (`put_oauth_client`/`get_oauth_client`), `OAuthClient` (Task 1).
- Produces:
  `register_client(store, *, client_id, name, redirect_uris, type) -> OAuthClient`.
  `resolve_client(store, *, client_id, fetch=None) -> OAuthClient` — local lookup; if absent and `client_id` is an https URL, fetch it as a **Client ID Metadata Document** (the `fetch(url) -> dict` is injectable), validate `redirect_uris`, persist, return.
  `validate_redirect_uri(client, redirect_uri) -> None` — raises `ValueError` if not registered.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_oauth_clients.py
import pytest
from identity.store.memory import InMemoryIdentityStore
from identity.oauth.clients import (
    register_client, resolve_client, validate_redirect_uri,
)


def test_register_and_resolve_local_client():
    s = InMemoryIdentityStore()
    register_client(s, client_id="cli_1", name="Dash",
                    redirect_uris=["https://app.x/cb"], type="public")
    c = resolve_client(s, client_id="cli_1")
    assert c.redirect_uris == ["https://app.x/cb"]


def test_validate_redirect_uri_rejects_unregistered():
    s = InMemoryIdentityStore()
    c = register_client(s, client_id="cli_1", name="Dash",
                        redirect_uris=["https://app.x/cb"], type="public")
    with pytest.raises(ValueError):
        validate_redirect_uri(c, "https://evil.x/cb")


def test_client_id_metadata_document_is_fetched_and_cached():
    s = InMemoryIdentityStore()
    url = "https://claude.ai/.well-known/oauth-client"
    doc = {"client_name": "Claude", "redirect_uris": ["https://claude.ai/cb"],
           "token_endpoint_auth_method": "none"}
    c = resolve_client(s, client_id=url, fetch=lambda u: doc)
    assert c.id == url
    assert c.redirect_uris == ["https://claude.ai/cb"]
    # cached: a second resolve does not need fetch
    assert resolve_client(s, client_id=url).redirect_uris == ["https://claude.ai/cb"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_oauth_clients.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'identity.oauth'`.

- [ ] **Step 3: Write minimal implementation**

```python
# identity/oauth/clients.py
from typing import Callable, Optional
from identity.model import OAuthClient


def register_client(store, *, client_id, name, redirect_uris, type) -> OAuthClient:
    c = OAuthClient(id=client_id, name=name, redirect_uris=list(redirect_uris),
                    type=type, client_id_metadata_url=None)
    store.put_oauth_client(c)
    return c


def validate_redirect_uri(client: OAuthClient, redirect_uri: str) -> None:
    if redirect_uri not in client.redirect_uris:
        raise ValueError("unregistered redirect_uri")


def resolve_client(store, *, client_id: str,
                   fetch: Optional[Callable[[str], dict]] = None) -> OAuthClient:
    existing = store.get_oauth_client(client_id)
    if existing is not None:
        return existing
    if client_id.startswith("https://") and fetch is not None:
        doc = fetch(client_id)
        redirect_uris = doc.get("redirect_uris") or []
        if not redirect_uris:
            raise ValueError("client metadata has no redirect_uris")
        c = OAuthClient(id=client_id, name=doc.get("client_name", client_id),
                        redirect_uris=list(redirect_uris), type="public",
                        client_id_metadata_url=client_id)
        store.put_oauth_client(c)
        return c
    raise ValueError(f"unknown client {client_id}")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_oauth_clients.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add identity/oauth/__init__.py identity/oauth/clients.py tests/test_oauth_clients.py
git commit -m "feat(oauth): client registry + Client ID Metadata Documents"
```

---

## Task 16: PKCE S256 verification

**Files:**
- Create: `identity/oauth/pkce.py`
- Test: `tests/test_oauth_pkce.py`

**Interfaces:**
- Produces: `verify_pkce_s256(*, verifier: str, challenge: str) -> bool` — `b64url(sha256(verifier)) == challenge`. `make_challenge(verifier) -> str` (test helper, also usable by clients).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_oauth_pkce.py
import hashlib
from identity.tokens import b64url
from identity.oauth.pkce import verify_pkce_s256, make_challenge


def test_matching_verifier_passes():
    verifier = "a" * 64
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())
    assert verify_pkce_s256(verifier=verifier, challenge=challenge) is True


def test_make_challenge_roundtrip():
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert verify_pkce_s256(verifier=verifier,
                            challenge=make_challenge(verifier)) is True


def test_wrong_verifier_fails():
    assert verify_pkce_s256(verifier="wrong", challenge=make_challenge("right")) is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_oauth_pkce.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'identity.oauth.pkce'`.

- [ ] **Step 3: Write minimal implementation**

```python
# identity/oauth/pkce.py
import hashlib
import hmac
from identity.tokens import b64url


def make_challenge(verifier: str) -> str:
    return b64url(hashlib.sha256(verifier.encode()).digest())


def verify_pkce_s256(*, verifier: str, challenge: str) -> bool:
    return hmac.compare_digest(make_challenge(verifier), challenge)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_oauth_pkce.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add identity/oauth/pkce.py tests/test_oauth_pkce.py
git commit -m "feat(oauth): PKCE S256 verification"
```

---

## Task 17: /oauth/authorize — auth-code issuance (PKCE, single-use)

**Files:**
- Create: `identity/oauth/authorize_endpoint.py`
- Test: `tests/test_oauth_authorize.py`

**Interfaces:**
- Consumes: `resolve_client`/`validate_redirect_uri` (Task 15), `generate_raw_token`/`hash_token` (Task 2), `OAuthAuthCode` (Task 1), `IdentityStore`.
- Produces:
  `issue_auth_code(store, *, client_id, principal_id, org_id, redirect_uri, code_challenge, audience, scope, now, ttl=600, fetch=None) -> str` — validates client + redirect, persists an `OAuthAuthCode` (hashed), returns the raw code. The consent decision is the caller's (this slice returns the consent payload via `build_consent(...)`).
  `build_consent(*, client, scope, audience) -> dict` — the data a consent screen renders (no HTML in the kernel).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_oauth_authorize.py
import pytest
from identity.store.memory import InMemoryIdentityStore
from identity.oauth.clients import register_client
from identity.oauth.authorize_endpoint import issue_auth_code, build_consent
from identity.tokens import hash_token


def _store():
    s = InMemoryIdentityStore()
    register_client(s, client_id="cli_1", name="Claude",
                    redirect_uris=["https://claude.ai/cb"], type="public")
    return s


def test_issue_auth_code_persists_hashed_single_use_code():
    s = _store()
    code = issue_auth_code(s, client_id="cli_1", principal_id="prn_1",
                           org_id="org_1", redirect_uri="https://claude.ai/cb",
                           code_challenge="chal", audience="https://mcp.x",
                           scope="mcp", now=1000)
    row = s.get_auth_code(hash_token(code))
    assert row is not None
    assert row.consumed_at is None
    assert row.code_challenge == "chal"
    assert row.expires_at == 1600


def test_bad_redirect_uri_is_rejected():
    s = _store()
    with pytest.raises(ValueError):
        issue_auth_code(s, client_id="cli_1", principal_id="prn_1", org_id="org_1",
                        redirect_uri="https://evil.x/cb", code_challenge="chal",
                        audience="https://mcp.x", scope="mcp", now=1000)


def test_consent_payload_shape():
    s = _store()
    c = s.get_oauth_client("cli_1")
    payload = build_consent(client=c, scope="mcp", audience="https://mcp.x")
    assert payload["client_name"] == "Claude"
    assert payload["scope"] == "mcp"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_oauth_authorize.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'identity.oauth.authorize_endpoint'`.

- [ ] **Step 3: Write minimal implementation**

```python
# identity/oauth/authorize_endpoint.py
from typing import Callable, Optional
from identity.model import OAuthAuthCode, OAuthClient
from identity.tokens import generate_raw_token, hash_token
from identity.oauth.clients import resolve_client, validate_redirect_uri


def build_consent(*, client: OAuthClient, scope: str, audience: str) -> dict:
    return {"client_name": client.name, "client_id": client.id,
            "scope": scope, "audience": audience,
            "redirect_uris": client.redirect_uris}


def issue_auth_code(store, *, client_id, principal_id, org_id, redirect_uri,
                    code_challenge, audience, scope, now, ttl: int = 600,
                    fetch: Optional[Callable[[str], dict]] = None) -> str:
    client = resolve_client(store, client_id=client_id, fetch=fetch)
    validate_redirect_uri(client, redirect_uri)
    raw = generate_raw_token("ac")
    store.put_auth_code(OAuthAuthCode(
        hash=hash_token(raw), client_id=client.id, principal_id=principal_id,
        org_id=org_id, code_challenge=code_challenge, audience=audience,
        scope=scope, expires_at=now + ttl, consumed_at=None))
    return raw
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_oauth_authorize.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add identity/oauth/authorize_endpoint.py tests/test_oauth_authorize.py
git commit -m "feat(oauth): authorization endpoint with single-use auth codes"
```

---

## Task 18: /oauth/token — code exchange + refresh rotation

**Files:**
- Create: `identity/oauth/token_endpoint.py`
- Test: `tests/test_oauth_token.py`

**Interfaces:**
- Consumes: `consume_auth_code`/`get_auth_code` + `put_access_token`/`get_access_token`/`rotate_refresh` (IdentityStore), `verify_pkce_s256` (Task 16), `generate_raw_token`/`hash_token` (Task 2), `OAuthAccessToken` (Task 1).
- Produces:
  `redeem_code(store, *, code, code_verifier, audience, now, access_ttl=3600) -> dict` returning `{"access_token","refresh_token","token_type":"Bearer","expires_in"}`. Verifies PKCE, marks the code consumed atomically (single-use; replay → `ValueError`), persists hashed access + refresh tokens.
  `refresh(store, *, refresh_token, now, access_ttl=3600) -> dict` — rotates: the old refresh token is invalidated, a new access+refresh pair is issued (RFC: refresh rotation). Replay of a rotated refresh → `ValueError`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_oauth_token.py
import pytest
from identity.store.memory import InMemoryIdentityStore
from identity.oauth.clients import register_client
from identity.oauth.authorize_endpoint import issue_auth_code
from identity.oauth.token_endpoint import redeem_code, refresh
from identity.oauth.pkce import make_challenge


def _setup(verifier="v" * 64):
    s = InMemoryIdentityStore()
    register_client(s, client_id="cli_1", name="Claude",
                    redirect_uris=["https://claude.ai/cb"], type="public")
    code = issue_auth_code(s, client_id="cli_1", principal_id="prn_1",
                           org_id="org_1", redirect_uri="https://claude.ai/cb",
                           code_challenge=make_challenge(verifier),
                           audience="https://mcp.x", scope="mcp", now=1000)
    return s, code, verifier


def test_redeem_code_issues_tokens():
    s, code, verifier = _setup()
    out = redeem_code(s, code=code, code_verifier=verifier,
                      audience="https://mcp.x", now=1001)
    assert out["token_type"] == "Bearer"
    assert out["expires_in"] == 3600
    assert out["access_token"].startswith("at_")
    assert out["refresh_token"].startswith("rt_")


def test_code_is_single_use():
    s, code, verifier = _setup()
    redeem_code(s, code=code, code_verifier=verifier, audience="https://mcp.x", now=1001)
    with pytest.raises(ValueError):
        redeem_code(s, code=code, code_verifier=verifier, audience="https://mcp.x", now=1002)


def test_bad_pkce_verifier_rejected():
    s, code, _ = _setup()
    with pytest.raises(ValueError):
        redeem_code(s, code=code, code_verifier="wrong", audience="https://mcp.x", now=1001)


def test_refresh_rotates_and_old_token_is_dead():
    s, code, verifier = _setup()
    issued = redeem_code(s, code=code, code_verifier=verifier,
                         audience="https://mcp.x", now=1001)
    rotated = refresh(s, refresh_token=issued["refresh_token"], now=2000)
    assert rotated["refresh_token"] != issued["refresh_token"]
    # replay of the old refresh token now fails
    with pytest.raises(ValueError):
        refresh(s, refresh_token=issued["refresh_token"], now=2001)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_oauth_token.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'identity.oauth.token_endpoint'`.

- [ ] **Step 3: Write minimal implementation**

```python
# identity/oauth/token_endpoint.py
from identity.model import OAuthAccessToken
from identity.tokens import generate_raw_token, hash_token
from identity.oauth.pkce import verify_pkce_s256


def _issue_pair(store, *, client_id, principal_id, org_id, audience, scope,
                now, access_ttl):
    access_raw = generate_raw_token("at")
    refresh_raw = generate_raw_token("rt")
    store.put_access_token(OAuthAccessToken(
        hash=hash_token(access_raw), client_id=client_id, principal_id=principal_id,
        org_id=org_id, audience=audience, scope=scope,
        expires_at=now + access_ttl,
        refresh={"hash": hash_token(refresh_raw), "expires_at": now + 30 * 86400}))
    return {"access_token": access_raw, "refresh_token": refresh_raw,
            "token_type": "Bearer", "expires_in": access_ttl}


def redeem_code(store, *, code, code_verifier, audience, now, access_ttl=3600) -> dict:
    row = store.get_auth_code(hash_token(code))
    if row is None:
        raise ValueError("unknown code")
    if now >= row.expires_at:
        raise ValueError("code expired")
    if row.audience != audience:
        raise ValueError("audience mismatch")
    if not verify_pkce_s256(verifier=code_verifier, challenge=row.code_challenge):
        raise ValueError("pkce verification failed")
    if not store.consume_auth_code(row.hash, now):   # atomic single-use
        raise ValueError("code already used")
    return _issue_pair(store, client_id=row.client_id, principal_id=row.principal_id,
                       org_id=row.org_id, audience=row.audience, scope=row.scope,
                       now=now, access_ttl=access_ttl)


def refresh(store, *, refresh_token, now, access_ttl=3600) -> dict:
    rh = hash_token(refresh_token)
    # find the access-token row whose refresh hash matches
    current = None
    for cand_hash in _all_access_hashes(store):
        row = store.get_access_token(cand_hash)
        if row and row.refresh and row.refresh.get("hash") == rh:
            current = row
            break
    if current is None:
        raise ValueError("unknown or rotated refresh token")
    if now >= current.refresh.get("expires_at", 0):
        raise ValueError("refresh token expired")
    issued = _issue_pair(store, client_id=current.client_id,
                         principal_id=current.principal_id, org_id=current.org_id,
                         audience=current.audience, scope=current.scope,
                         now=now, access_ttl=access_ttl)
    store.rotate_refresh(current.hash, store.get_access_token(hash_token(issued["access_token"])))
    return issued


def _all_access_hashes(store):
    # InMemory + Server both expose iteration via a small helper added below.
    return store.access_token_hashes()
```

Add the iteration helper to the `IdentityStore` ABC and both backends (small, mechanical):
```python
# identity/store/base.py — add:
    @abstractmethod
    def access_token_hashes(self) -> list[str]: ...
# identity/store/memory.py — add:
    def access_token_hashes(self):
        return list(self._at.keys())
# identity/store/server.py — add:
    def access_token_hashes(self):
        return [r[0] for r in self._db.execute("SELECT hash FROM access_tokens").fetchall()]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_oauth_token.py tests/test_identity_store_parity.py -v`
Expected: PASS — token tests pass and the store-parity suite still passes with the new method.

- [ ] **Step 5: Commit**

```bash
git add identity/oauth/token_endpoint.py identity/store/base.py identity/store/memory.py identity/store/server.py tests/test_oauth_token.py
git commit -m "feat(oauth): token endpoint with single-use codes and refresh rotation"
```

---

## Task 19: OAuth metadata documents (RFC 8414, RFC 9728, OIDC discovery)

**Files:**
- Create: `identity/oauth/metadata.py`
- Test: `tests/test_oauth_metadata.py`

**Interfaces:**
- Produces:
  `authorization_server_metadata(*, issuer) -> dict` (RFC 8414: `/.well-known/oauth-authorization-server`).
  `protected_resource_metadata(*, resource, authorization_servers) -> dict` (RFC 9728).
  `openid_configuration(*, issuer) -> dict` (OIDC discovery subset). All advertise `EdDSA`, `S256`, `code`, `authorization_code`/`refresh_token`, and the JWKS URI.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_oauth_metadata.py
from identity.oauth.metadata import (
    authorization_server_metadata, protected_resource_metadata, openid_configuration,
)


def test_as_metadata_advertises_pkce_and_eddsa():
    m = authorization_server_metadata(issuer="https://id.x")
    assert m["issuer"] == "https://id.x"
    assert m["authorization_endpoint"] == "https://id.x/oauth/authorize"
    assert m["token_endpoint"] == "https://id.x/oauth/token"
    assert m["jwks_uri"] == "https://id.x/.well-known/jwks.json"
    assert "S256" in m["code_challenge_methods_supported"]
    assert "EdDSA" in m["id_token_signing_alg_values_supported"]
    assert "refresh_token" in m["grant_types_supported"]


def test_protected_resource_metadata_shape():
    m = protected_resource_metadata(resource="https://mcp.x",
                                    authorization_servers=["https://id.x"])
    assert m["resource"] == "https://mcp.x"
    assert m["authorization_servers"] == ["https://id.x"]


def test_oidc_discovery_subset():
    m = openid_configuration(issuer="https://id.x")
    assert m["issuer"] == "https://id.x"
    assert m["jwks_uri"] == "https://id.x/.well-known/jwks.json"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_oauth_metadata.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'identity.oauth.metadata'`.

- [ ] **Step 3: Write minimal implementation**

```python
# identity/oauth/metadata.py
def authorization_server_metadata(*, issuer: str) -> dict:
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oauth/authorize",
        "token_endpoint": f"{issuer}/oauth/token",
        "jwks_uri": f"{issuer}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_basic"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
    }


def protected_resource_metadata(*, resource: str, authorization_servers: list) -> dict:
    return {"resource": resource, "authorization_servers": list(authorization_servers),
            "bearer_methods_supported": ["header"]}


def openid_configuration(*, issuer: str) -> dict:
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oauth/authorize",
        "token_endpoint": f"{issuer}/oauth/token",
        "jwks_uri": f"{issuer}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_oauth_metadata.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add identity/oauth/metadata.py tests/test_oauth_metadata.py
git commit -m "feat(oauth): RFC 8414 / RFC 9728 / OIDC discovery metadata"
```

---

## Task 20: identity app — wire jwks, exchange, and OAuth routes

**Files:**
- Create: `identity/app.py`
- Test: extend `tests/test_oauth_metadata.py` or a new `tests/test_identity_app.py` with FastAPI `TestClient`.

**Interfaces:**
- Consumes: every Phase B/D piece.
- Produces:
  `build_identity_app(*, store, key_manager, issuer, now_fn) -> FastAPI` exposing:
  `GET /.well-known/jwks.json` → `key_manager.jwks_document()`;
  `GET /.well-known/oauth-authorization-server` → `authorization_server_metadata`;
  `GET /.well-known/openid-configuration` → `openid_configuration`;
  `POST /auth/exchange` (body `{opaque_token, audience}`) → mints a 5-min JWT from `exchange(...)`;
  `POST /oauth/authorize` (issue code; consent assumed granted in this slice) and `POST /oauth/token` (redeem/refresh).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_identity_app.py
from fastapi.testclient import TestClient
from identity.app import build_identity_app
from identity.keys import KeyManager
from identity.store.memory import InMemoryIdentityStore
from identity.model import McpToken, Membership
from identity.tokens import hash_token
from identity.jwt_verify import verify_island_jwt


def _app():
    s = InMemoryIdentityStore()
    s.put_mcp_token(McpToken(hash=hash_token("mcp_abc"), principal_id="prn_1",
                             org_id="org_1", audience="https://mcp.x", scope="mcp",
                             expires_at=10_000, revoked_at=None))
    s.put_membership(Membership("prn_1", "org_1", ["owner"], True, 0.0))
    km = KeyManager.generate("kid-1")
    app = build_identity_app(store=s, key_manager=km, issuer="https://id.x",
                             now_fn=lambda: 1000.0)
    return app, km


def test_jwks_endpoint_serves_public_key():
    app, km = _app()
    r = TestClient(app).get("/.well-known/jwks.json")
    assert r.status_code == 200
    assert r.json()["keys"][0]["kid"] == "kid-1"


def test_exchange_endpoint_mints_short_lived_jwt():
    app, km = _app()
    r = TestClient(app).post("/auth/exchange",
                             json={"opaque_token": "mcp_abc", "audience": "https://mcp.x"})
    assert r.status_code == 200
    token = r.json()["access_token"]
    claims = verify_island_jwt(token, jwks=km.jwks_document(),
                               audience="https://mcp.x", now=1100, issuer="https://id.x")
    assert claims["sub"] == "prn_1"
    assert claims["exp"] - claims["iat"] == 300   # 5-minute TTL


def test_exchange_rejects_audience_mismatch():
    app, _ = _app()
    r = TestClient(app).post("/auth/exchange",
                             json={"opaque_token": "mcp_abc", "audience": "https://other"})
    assert r.status_code == 400
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_identity_app.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'identity.app'`.

- [ ] **Step 3: Write minimal implementation**

```python
# identity/app.py
from fastapi import FastAPI, HTTPException, Body
from identity.exchange import exchange, ExchangeError
from identity.jwt_issuer import mint
from identity.oauth.metadata import (
    authorization_server_metadata, openid_configuration,
)
from identity.oauth.authorize_endpoint import issue_auth_code
from identity.oauth.token_endpoint import redeem_code, refresh


def build_identity_app(*, store, key_manager, issuer: str, now_fn) -> FastAPI:
    app = FastAPI(title="islands-kernel identity")

    @app.get("/.well-known/jwks.json")
    async def jwks():
        return key_manager.jwks_document()

    @app.get("/.well-known/oauth-authorization-server")
    async def as_meta():
        return authorization_server_metadata(issuer=issuer)

    @app.get("/.well-known/openid-configuration")
    async def oidc():
        return openid_configuration(issuer=issuer)

    @app.post("/auth/exchange")
    async def auth_exchange(body: dict = Body(...)):
        try:
            resolved = exchange(opaque_token=body["opaque_token"],
                                audience=body["audience"], store=store, now=now_fn())
        except ExchangeError as e:
            raise HTTPException(400, str(e))
        token = mint(km=key_manager, issuer=issuer, sub=resolved["principal_id"],
                     typ="human", audience=body["audience"], org=resolved["org_id"],
                     roles=resolved["roles"], ttl=300, now=int(now_fn()),
                     sid=resolved["sid"])
        return {"access_token": token, "token_type": "Bearer", "expires_in": 300}

    @app.post("/oauth/authorize")
    async def oauth_authorize(body: dict = Body(...)):
        try:
            code = issue_auth_code(store, client_id=body["client_id"],
                                   principal_id=body["principal_id"],
                                   org_id=body.get("org_id"),
                                   redirect_uri=body["redirect_uri"],
                                   code_challenge=body["code_challenge"],
                                   audience=body["audience"], scope=body.get("scope", "mcp"),
                                   now=now_fn())
        except ValueError as e:
            raise HTTPException(400, str(e))
        return {"code": code}

    @app.post("/oauth/token")
    async def oauth_token(body: dict = Body(...)):
        try:
            if body.get("grant_type") == "refresh_token":
                return refresh(store, refresh_token=body["refresh_token"], now=now_fn())
            return redeem_code(store, code=body["code"],
                               code_verifier=body["code_verifier"],
                               audience=body["audience"], now=now_fn())
        except ValueError as e:
            raise HTTPException(400, str(e))

    return app
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_identity_app.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add identity/app.py tests/test_identity_app.py
git commit -m "feat(identity): FastAPI app wiring jwks, exchange, and OAuth routes"
```

---

## Task 21: Cross-language proof — same token verifies in Python and Node

**Files:**
- Create: `tests/test_cross_language.py`
- Create: `tests/fixtures/cross_lang/.gitkeep`
- Modify: `libs/node/test/verify.test.ts` — add a test that reads the golden fixture.

**Interfaces:**
- Consumes: `KeyManager.from_seed` (deterministic), `mint` (Task 6), `verify_island_jwt` (Task 7), Node `verifyIslandJwt` (Task 14).
- Produces: a golden fixture `tests/fixtures/cross_lang/token.json` = `{"token": <jwt>, "jwks": <doc>, "audience": "https://mcp.x", "issuer": "https://id.x", "now": 1100}` written deterministically by the Python test, read and verified by the Node test. The same bytes verify in both runtimes — the cross-language acceptance criterion.

- [ ] **Step 1: Write the failing test (Python side writes + verifies the fixture)**

```python
# tests/test_cross_language.py
import json
import os
from identity.keys import KeyManager
from identity.jwt_issuer import mint
from identity.jwt_verify import verify_island_jwt
from identity.tokens import b64url

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "cross_lang", "token.json")


def test_python_writes_and_verifies_golden_token():
    km = KeyManager.from_seed("kid-1", b64url(b"\x07" * 32))
    token = mint(km=km, issuer="https://id.x", sub="prn_1", typ="human",
                 audience="https://mcp.x", org="org_1", roles=["owner"],
                 ttl=300, now=1000, email="a@b.se")
    fixture = {"token": token, "jwks": km.jwks_document(),
               "audience": "https://mcp.x", "issuer": "https://id.x", "now": 1100}
    os.makedirs(os.path.dirname(FIX), exist_ok=True)
    with open(FIX, "w") as f:
        json.dump(fixture, f, indent=2)

    claims = verify_island_jwt(token, jwks=km.jwks_document(),
                               audience="https://mcp.x", now=1100, issuer="https://id.x")
    assert claims["sub"] == "prn_1"
```

```typescript
// libs/node/test/verify.test.ts  (append)
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

it("verifies the cross-language golden token from the Python issuer", async () => {
  const path = resolve(__dirname, "../../../tests/fixtures/cross_lang/token.json");
  const fx = JSON.parse(readFileSync(path, "utf8"));
  const claims = await verifyIslandJwt(fx.token, {
    jwks: fx.jwks, audience: fx.audience, issuer: fx.issuer, now: fx.now,
  });
  expect(claims.sub).toBe("prn_1");
  expect(claims.org).toBe("org_1");
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/test_cross_language.py -v` (passes, writes the fixture), then
`cd libs/node && npx vitest run test/verify.test.ts`
Expected: the Node test FAILS first if run before the fixture exists; after the Python test writes it, the Node test PASSES. (Document the ordering: Python test must run first to emit the golden file.)

- [ ] **Step 3: Implementation** — none beyond Steps 1–2; this task is the integration proof. Ensure `tests/fixtures/cross_lang/token.json` is git-ignored OR committed as a regenerated artifact. Decision: commit it (it contains only a public JWKS + a token signed by a throwaway fixed seed — no real secret, no live key) so the Node suite can run standalone in CI. Add a note that the seed is a test-only constant, never a production key.

- [ ] **Step 4: Run both suites green**

Run: `python -m pytest tests/ -v && cd libs/node && npx vitest run`
Expected: full Python suite green; full Node suite green including the cross-language test.

- [ ] **Step 5: Commit**

```bash
git add tests/test_cross_language.py tests/fixtures/cross_lang/token.json libs/node/test/verify.test.ts
git commit -m "test: cross-language proof — one token verifies in Python and Node"
```

---

## Task 22: Full-suite gate + plan close-out

**Files:** none (verification only).

- [ ] **Step 1: Run the entire Python suite**

Run: `python -m pytest tests/ -v`
Expected: every test green (slice-1 tests untouched and still passing; all slice-2 tests passing).

- [ ] **Step 2: Run the entire Node suite**

Run: `cd libs/node && npx vitest run`
Expected: green, including `verify.test.ts` cross-language.

- [ ] **Step 3: Secret-hygiene check**

Run: `git status --porcelain && git ls-files | grep -E '\.(key|age|ed25519)$|^kernel-keys/|^vault-store/' || echo "no secret files tracked"`
Expected: `no secret files tracked`. Confirm `.gitignore` covers `*.ed25519`, `kernel-keys/`. Confirm no private key, KEK, or token appears in any committed file or test fixture (the fixture carries only a public JWKS + a token from a throwaway fixed seed).

- [ ] **Step 4: Confirm acceptance criteria** (from the spec) — tick each:
  - One EdDSA JWT verified via JWKS by both a Node island and the Python path (Task 21, Task 13). ✓ when green.
  - The vault requires a real kernel JWT + grant check; access-matrix keys on the verified principal; service-principal seam exists (Task 12, Task 13). ✓
  - MCP-token→5-min-JWT exchange and the OAuth 2.1 AS both work end to end (Task 20, Tasks 15–19). ✓
  - A teammate granted scoped `use` can use it and have it revoked within the token TTL (Task 9 authorize + revoke; Task 10 exchange). ✓
  - No symmetric secret shared across languages (Tasks 5–7, 14 all verify-only on islands). ✓

- [ ] **Step 5: Stop for sign-off before any push or live cutover.** Report the green suites and the staged commit list. Do NOT `git push`. The live bookkeeping cutover (Task 12 close-out steps) is a separate, human-gated session.

---

## Self-review notes (author pass)

- **Spec coverage:** Principal/Org/Membership/roles (Task 1); unified Grant + `target.kind="connection"` no-migration adapter (Tasks 1, 9, 12); EdDSA + claim shape + JWKS (Tasks 5–6, 20); thin verify libs Node+Python (Tasks 7, 13, 14); MCP-token→5-min-JWT exchange (Tasks 10, 20); OAuth 2.1 AS with PKCE S256 + refresh rotation + single-use codes + RFC 8414/9728 + Client ID Metadata Docs + OIDC discovery (Tasks 15–20); org-resolution rule incl. `ORG_REQUIRED` (Task 8); two-island cross-language proof — vault access-token behind real JWT+authorize (Task 12) and Python access-matrix path (Task 13) + golden cross-language token (Task 21); back-compat `userId`/`workspaceId` shim (Task 6); `AccessLog` metadata-only (Task 1, slice-1 log untouched). Session `sid` is optional and threaded through `exchange`/`mint` (defaults `None`) per "session is optional."
- **Out-of-scope kept out:** no live sm-brf/nudge prod retrofit; no member/grant UI; no per-island permission catalogs; venti untouched. The bookkeeping live cutover is documented as a separate human-gated step, not built here.
- **Type consistency:** `Access`/`Role`/`TargetKind`/`GrantTarget`/`Grant` defined once in `identity/model.py` and reused; `verify_island_jwt` signature identical across Tasks 7/11/13/21; `mint`/`build_claims` signatures stable across Tasks 6/20/21; store method names match between ABC and both backends (incl. the `access_token_hashes` addition in Task 18, mirrored in both backends and re-run against the parity suite).
- **Known seam:** the vault hot path (Task 12) keeps slice-1 `require_access` for the connection target rather than routing through `authorize()`, to honour "no data migration." `authorize()` + the connection-grant adapter are proven in Task 9 and are the path later slices use for island/capability/org targets. If a future task wants the vault to use `authorize()` uniformly, it wires `collect_grants(connection_grants=store.get_grants(conn.id))` — a small, non-migrating change.
