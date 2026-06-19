from __future__ import annotations
from vault.model import ConnKey, ConnectionAccessLog, ConnectionGrant, Connection, new_id
from vault.store.base import Store
from vault.providers.base import Provider
from vault.refresh import refresh_if_needed
from vault.config import VaultConfig
from vault.grants import require_access
from vault.oauth_state import sign_state, verify_state


class AccessService:
    def __init__(self, store: Store, providers: dict[str, Provider], config: VaultConfig):
        self.store = store
        self.providers = providers
        self.config = config

    def get_access_token(self, key: ConnKey, principal_id: str, island: str,
                         *, grant_check=None) -> dict:
        conn = self.store.get_connection(key)
        if conn is None:
            raise KeyError(f"no connection for {key.as_str()}")
        # grant_check (kernel authorize()) replaces the slice-1 require_access on the
        # authed path; with no grant_check the legacy owner-or-connection-grant check stands.
        if grant_check is not None:
            grant_check(conn)
        else:
            require_access(self.store, conn, principal_id, "use")
        provider = self.providers[conn.provider]
        app = self.config.app_cred_for(conn.provider, conn.app_cred_ref)
        token = refresh_if_needed(self.store, key, provider, app,
                                  http_post=self.config.http_post, now_fn=self.config.now_fn,
                                  skew=self.config.skew)
        self.store.append_log(ConnectionAccessLog(
            connection_id=conn.id, principal_id=principal_id, island=island,
            op="access-token", at=self.config.now_fn()))
        return {"accessToken": token.access_token, "scope": token.scope, "expiresAt": token.expires_at}

    def grant(self, key: ConnKey, granter_id: str, principal_id: str, access, scopes_subset):
        conn = self.store.get_connection(key)
        if conn is None:
            raise KeyError(f"no connection for {key.as_str()}")
        require_access(self.store, conn, granter_id, "manage")   # only manage can grant
        g = ConnectionGrant(connection_id=conn.id, principal_id=principal_id, access=access,
                            scopes_subset=scopes_subset, granted_by=granter_id,
                            granted_at=self.config.now_fn())
        self.store.add_grant(g)
        return {"connectionId": conn.id, "principalId": principal_id, "access": access}

    def list_connections(self, org: str, provider, principal_id: str) -> list[dict]:
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

    def revoke(self, key: ConnKey, principal_id: str) -> dict:
        conn = self.store.get_connection(key)
        if conn is None:
            raise KeyError(f"no connection for {key.as_str()}")
        require_access(self.store, conn, principal_id, "manage")
        self.store.delete_connection(key)
        return {"revoked": conn.id}

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
