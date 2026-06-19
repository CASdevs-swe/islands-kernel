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
