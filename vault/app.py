from __future__ import annotations
import os
from typing import Optional, Callable
from urllib.parse import unquote
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from vault.model import ConnKey
from vault.access import AccessService
from vault.config import VaultConfig


def _parse_id(conn_id: str) -> ConnKey:
    org, provider, account = unquote(conn_id).split("/", 2)
    return ConnKey(org, provider, account)


def build_app(service: AccessService, *, require_principal: Optional[Callable] = None) -> FastAPI:
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

    if require_principal is not None:
        @app.post("/connections/{conn_id:path}/access-token")
        async def access_token_authed(conn_id: str, claims=Depends(require_principal)):
            principal = claims["sub"]
            island = claims.get("aud", "unknown")
            return guard(lambda: service.get_access_token(_parse_id(conn_id), principal, island))
    else:
        @app.post("/connections/{conn_id:path}/access-token")
        async def access_token_stub(conn_id: str, x_principal: str = Header("stub"),
                                    x_island: str = Header("unknown")):
            return guard(lambda: service.get_access_token(_parse_id(conn_id), x_principal, x_island))

    @app.post("/connections/{conn_id:path}/grant")
    async def grant(conn_id: str, request: Request, x_principal: str = Header("stub")):
        body = await request.json()
        return guard(lambda: service.grant(
            _parse_id(conn_id), x_principal, body["principalId"], body["access"],
            body.get("scopesSubset")))

    @app.get("/connections")
    async def list_conns(org: str, provider: str | None = None, x_principal: str = Header("stub")):
        return guard(lambda: service.list_connections(org, provider, x_principal))

    @app.delete("/connections/{conn_id:path}")
    async def revoke(conn_id: str, x_principal: str = Header("stub")):
        return guard(lambda: service.revoke(_parse_id(conn_id), x_principal))

    return app


def _build_from_env() -> AccessService:
    import base64
    import nacl.utils
    from vault.crypto import SecretboxKeyWrapper
    from vault.providers import PROVIDERS
    backend = os.environ.get("VAULT_BACKEND", "local")
    # KEK: 32-byte base64 in VAULT_KEK (server); local backend uses age in production via config.
    kek_b64 = os.environ.get("VAULT_KEK")
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
