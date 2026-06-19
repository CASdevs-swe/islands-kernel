from __future__ import annotations
from vault.model import ConnKey, ConnectionAccessLog, ConnectionGrant
from vault.store.base import Store
from vault.providers.base import Provider
from vault.refresh import refresh_if_needed
from vault.config import VaultConfig
from vault.grants import require_access


class AccessService:
    def __init__(self, store: Store, providers: dict[str, Provider], config: VaultConfig):
        self.store = store
        self.providers = providers
        self.config = config

    def get_access_token(self, key: ConnKey, principal_id: str, island: str) -> dict:
        conn = self.store.get_connection(key)
        if conn is None:
            raise KeyError(f"no connection for {key.as_str()}")
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
