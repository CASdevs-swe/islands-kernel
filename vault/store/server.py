from __future__ import annotations
import json
import sqlite3
import threading
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

    def list_connections(self, org: str, provider: Optional[str]) -> list[Connection]:
        q = "SELECT org,provider,account FROM connections WHERE org=?"
        args: list = [org]
        if provider is not None:
            q += " AND provider=?"; args.append(provider)
        with self._mu:
            rows = self._db.execute(q, args).fetchall()
        return [self.get_connection(ConnKey(*r)) for r in rows]

    def write_token(self, key: ConnKey, token: Token, now: float) -> None:
        blob = seal_token(token, self._wrapper)
        with self._mu, self._db:
            self._db.execute(
                "UPDATE connections SET token_blob=?, updated_at=? "
                "WHERE org=? AND provider=? AND account=?",
                (blob, now, key.org, key.provider, key.account))

    def acquire_lease(self, key: ConnKey, holder: str, until: float, now: float) -> bool:
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

    def release_lease(self, key: ConnKey, holder: str) -> None:
        with self._mu, self._db:
            self._db.execute("DELETE FROM leases WHERE conn_key=? AND holder=?", (key.as_str(), holder))

    def lease_held(self, key: ConnKey, now: float) -> bool:
        with self._mu:
            row = self._db.execute(
                "SELECT until FROM leases WHERE conn_key=?", (key.as_str(),)).fetchone()
        return row is not None and row[0] > now

    def delete_connection(self, key: ConnKey) -> None:
        with self._mu, self._db:
            self._db.execute(
                "UPDATE connections SET token_blob=NULL WHERE org=? AND provider=? AND account=?",
                (key.org, key.provider, key.account))
            self._db.execute(
                "DELETE FROM connections WHERE org=? AND provider=? AND account=?",
                (key.org, key.provider, key.account))
            self._db.execute("DELETE FROM leases WHERE conn_key=?", (key.as_str(),))

    def add_grant(self, grant: ConnectionGrant) -> None:
        with self._mu, self._db:
            self._db.execute(
                "INSERT INTO grants(connection_id,principal_id,access,scopes_subset_json,"
                "granted_by,granted_at) VALUES(?,?,?,?,?,?)",
                (grant.connection_id, grant.principal_id, grant.access,
                 json.dumps(grant.scopes_subset), grant.granted_by, grant.granted_at))

    def get_grants(self, connection_id: str) -> list[ConnectionGrant]:
        with self._mu:
            rows = self._db.execute(
                "SELECT connection_id,principal_id,access,scopes_subset_json,granted_by,granted_at "
                "FROM grants WHERE connection_id=?", (connection_id,)).fetchall()
        return [ConnectionGrant(r[0], r[1], r[2], json.loads(r[3]), r[4], r[5]) for r in rows]

    def append_log(self, entry: ConnectionAccessLog) -> None:
        with self._mu, self._db:
            self._db.execute("INSERT INTO logs(connection_id,principal_id,island,op,at) "
                             "VALUES(?,?,?,?,?)",
                             (entry.connection_id, entry.principal_id, entry.island, entry.op, entry.at))

    def read_log(self, connection_id: str) -> list[ConnectionAccessLog]:
        with self._mu:
            rows = self._db.execute(
                "SELECT connection_id,principal_id,island,op,at FROM logs WHERE connection_id=?",
                (connection_id,)).fetchall()
        return [ConnectionAccessLog(*r) for r in rows]
