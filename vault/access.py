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
