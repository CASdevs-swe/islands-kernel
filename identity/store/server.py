import json
import sqlite3
import threading
from typing import Optional
from identity.store.base import IdentityStore
from identity.model import (
    Principal, Org, Membership, Grant, GrantTarget, McpToken, OAuthClient,
    OAuthAuthCode, OAuthAccessToken, AccessLog, IslandRegistry, IslandPrincipalLink,
    FederationTxn,
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
CREATE TABLE IF NOT EXISTS islands(
  id TEXT PRIMARY KEY, name TEXT, issuer TEXT, jwks_uri TEXT, audience TEXT,
  sso_authorize_url TEXT, sso_token_url TEXT, sso_client_secret_hash TEXT,
  org_id TEXT, session_ttl_days REAL, created_at REAL, disabled_at REAL,
  assertion_secret TEXT
);
CREATE TABLE IF NOT EXISTS island_principal_links(
  island_id TEXT, island_user_id TEXT, principal_id TEXT, created_at REAL,
  PRIMARY KEY(island_id, island_user_id)
);
CREATE TABLE IF NOT EXISTS federation_txns(
  hash TEXT PRIMARY KEY, client_id TEXT, redirect_uri TEXT, code_challenge TEXT,
  audience TEXT, scope TEXT, client_state TEXT, island_id TEXT, nonce TEXT,
  expires_at REAL, consumed_at REAL
);
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
        with self._mu:
            r = self._db.execute("SELECT * FROM principals WHERE id=?", (principal_id,)).fetchone()
        return self._principal(r)

    def get_principal_by_email(self, email):
        with self._mu:
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
        with self._mu:
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
        with self._mu:
            r = self._db.execute(
                "SELECT * FROM memberships WHERE principal_id=? AND org_id=?",
                (principal_id, org_id)).fetchone()
        return self._membership(r)

    def list_memberships(self, principal_id):
        with self._mu:
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
        with self._mu:
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
        with self._mu:
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
        with self._mu:
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
        with self._mu:
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
        with self._mu:
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
                              json.dumps(new_token.refresh) if new_token.refresh is not None else None))
            self._db.commit()

    def access_token_hashes(self):
        with self._mu:
            rows = self._db.execute("SELECT hash FROM access_tokens").fetchall()
        return [r[0] for r in rows]

    # --- logs ---
    def append_log(self, entry):
        with self._mu:
            self._db.execute("INSERT INTO logs VALUES (?,?,?,?,?)",
                             (entry.principal_id, entry.org_id, entry.island,
                              entry.capability, entry.at))
            self._db.commit()

    def read_log(self, principal_id):
        with self._mu:
            rows = self._db.execute("SELECT * FROM logs WHERE principal_id=?",
                                    (principal_id,)).fetchall()
        return [AccessLog(*r) for r in rows]

    # --- islands ---
    def put_island(self, i):
        with self._mu:
            self._db.execute(
                "INSERT OR REPLACE INTO islands VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (i.id, i.name, i.issuer, i.jwks_uri, i.audience, i.sso_authorize_url,
                 i.sso_token_url, i.sso_client_secret_hash, i.org_id, i.session_ttl_days,
                 i.created_at, i.disabled_at, i.assertion_secret))
            self._db.commit()

    def _row_to_island(self, r):
        return IslandRegistry(id=r[0], name=r[1], issuer=r[2], jwks_uri=r[3], audience=r[4],
            sso_authorize_url=r[5], sso_token_url=r[6], sso_client_secret_hash=r[7],
            org_id=r[8], session_ttl_days=r[9], created_at=r[10], disabled_at=r[11],
            assertion_secret=r[12])

    def get_island(self, island_id):
        r = self._db.execute("SELECT * FROM islands WHERE id=?", (island_id,)).fetchone()
        return self._row_to_island(r) if r else None

    def get_island_by_audience(self, audience):
        r = self._db.execute("SELECT * FROM islands WHERE audience=?", (audience,)).fetchone()
        return self._row_to_island(r) if r else None

    def list_islands(self):
        return [self._row_to_island(r) for r in self._db.execute("SELECT * FROM islands").fetchall()]

    def disable_island(self, island_id, at):
        with self._mu:
            self._db.execute("UPDATE islands SET disabled_at=? WHERE id=?", (at, island_id))
            self._db.commit()

    # --- island principal links ---
    def put_island_principal_link(self, link):
        with self._mu:
            self._db.execute("INSERT OR REPLACE INTO island_principal_links VALUES (?,?,?,?)",
                (link.island_id, link.island_user_id, link.principal_id, link.created_at))
            self._db.commit()

    def get_principal_by_island(self, island_id, island_user_id):
        r = self._db.execute(
            "SELECT principal_id FROM island_principal_links WHERE island_id=? AND island_user_id=?",
            (island_id, island_user_id)).fetchone()
        return r[0] if r else None

    def get_island_link_by_principal(self, principal_id):
        r = self._db.execute(
            "SELECT * FROM island_principal_links WHERE principal_id=?",
            (principal_id,)).fetchone()
        return IslandPrincipalLink(island_id=r[0], island_user_id=r[1],
                                   principal_id=r[2], created_at=r[3]) if r else None

    # --- federation txns ---
    def put_federation_txn(self, t):
        with self._mu:
            self._db.execute("INSERT OR REPLACE INTO federation_txns VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (t.hash, t.client_id, t.redirect_uri, t.code_challenge, t.audience, t.scope,
                 t.client_state, t.island_id, t.nonce, t.expires_at, t.consumed_at))
            self._db.commit()

    def get_federation_txn(self, txn_hash):
        r = self._db.execute("SELECT * FROM federation_txns WHERE hash=?", (txn_hash,)).fetchone()
        if not r:
            return None
        return FederationTxn(hash=r[0], client_id=r[1], redirect_uri=r[2], code_challenge=r[3],
            audience=r[4], scope=r[5], client_state=r[6], island_id=r[7], nonce=r[8],
            expires_at=r[9], consumed_at=r[10])

    def consume_federation_txn(self, txn_hash, at):
        with self._mu:
            r = self._db.execute("SELECT consumed_at FROM federation_txns WHERE hash=?", (txn_hash,)).fetchone()
            if r is None or r[0] is not None:
                return False
            self._db.execute("UPDATE federation_txns SET consumed_at=? WHERE hash=?", (at, txn_hash))
            self._db.commit()
            return True
