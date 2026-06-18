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
