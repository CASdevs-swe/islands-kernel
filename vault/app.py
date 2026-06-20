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


def build_app(service: AccessService, *, require_principal: Optional[Callable] = None,
              authorizer: Optional[Callable] = None,
              manage_authorizer: Optional[Callable] = None) -> FastAPI:
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
        def access_token_authed(conn_id: str, claims=Depends(require_principal)):
            principal = claims["sub"]
            org = claims.get("org")
            # aud is a str for single-audience tokens and a list for multi-audience
            # ones; the audit log records a single island, so take the first.
            island_aud = claims.get("aud", "unknown")
            if isinstance(island_aud, str):
                island = island_aud
            elif island_aud:
                island = island_aud[0]
            else:
                island = "unknown"

            def grant_check(conn):
                if authorizer is not None:
                    if not authorizer(conn=conn, principal_id=principal, org=org):
                        raise PermissionError(f"{principal} lacks use on {conn.id}")

            return guard(lambda: service.get_access_token(
                _parse_id(conn_id), principal, island, grant_check=grant_check))

        def _manage_check(claims):
            if manage_authorizer is None:
                return None
            principal = claims["sub"]
            org = claims.get("org")
            return lambda conn: manage_authorizer(conn=conn, principal_id=principal, org=org)

        @app.post("/connections/{provider}/connect")
        async def connect_authed(provider: str, request: Request, claims=Depends(require_principal)):
            body = await request.json()
            return guard(lambda: service.start_connect(
                body["org"], provider, body["account"], claims["sub"], body.get("code_challenge")))

        @app.post("/connections/connect/finish")
        async def finish_authed(request: Request, claims=Depends(require_principal)):
            body = await request.json()
            return guard(lambda: service.finish_connect(
                body["code"], body["state"], body.get("code_verifier")))

        @app.post("/connections/{conn_id:path}/grant")
        async def grant_authed(conn_id: str, request: Request, claims=Depends(require_principal)):
            body = await request.json()
            return guard(lambda: service.grant(
                _parse_id(conn_id), claims["sub"], body["principalId"], body["access"],
                body.get("scopesSubset"), manage_check=_manage_check(claims)))

        @app.get("/connections")
        async def list_authed(org: str, provider: str | None = None,
                              claims=Depends(require_principal)):
            return guard(lambda: service.list_connections(
                org, provider, claims["sub"], manage_check=_manage_check(claims)))

        @app.delete("/connections/{conn_id:path}")
        async def revoke_authed(conn_id: str, claims=Depends(require_principal)):
            return guard(lambda: service.revoke(
                _parse_id(conn_id), claims["sub"], manage_check=_manage_check(claims)))
    else:
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

        @app.post("/connections/{conn_id:path}/access-token")
        def access_token_stub(conn_id: str, x_principal: str = Header("stub"),
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
    kek_b64 = os.environ.get("VAULT_KEK")
    served = backend == "server" or os.environ.get("VAULT_REQUIRE_KERNEL") == "1"
    if kek_b64:
        kek = base64.b64decode(kek_b64)
    elif served:
        # A random KEK on a served store makes sealed envelopes unrecoverable across
        # restarts. The KEK must come from the host secret store / KMS (see docs).
        raise RuntimeError(
            "VAULT_KEK is required when serving the vault "
            "(VAULT_BACKEND=server or VAULT_REQUIRE_KERNEL=1)")
    else:
        kek = nacl.utils.random(32)
    wrapper = SecretboxKeyWrapper(kek)
    if backend == "server":
        from vault.store.server import ServerStore
        store = ServerStore(os.environ.get("VAULT_DB", "sqlite:///vault-store/vault.sqlite"), wrapper)
    else:
        from pathlib import Path
        from vault.store.local_file import LocalFileStore
        store = LocalFileStore(Path(os.environ.get("VAULT_STORE_DIR", "vault-store")), wrapper)
    return AccessService(store, PROVIDERS, VaultConfig())


def _build_app_from_env() -> FastAPI:
    service = _build_from_env()
    # VAULT_REQUIRE_KERNEL is the reversible cutover flag: unset -> slice-1 stub path
    # (unchanged); set -> verify a kernel JWT (public JWKS only) + authorize() grant check.
    if os.environ.get("VAULT_REQUIRE_KERNEL") == "1":
        import time
        from vault.kernel_auth import make_kernel_auth, make_manage_authorizer, cached_jwks_provider
        from identity.store.server import ServerIdentityStore
        identity_store = ServerIdentityStore(
            os.environ.get("KERNEL_IDENTITY_DB", "vault-store/identity.sqlite"))
        jwks_provider = cached_jwks_provider(os.environ["KERNEL_JWKS_URL"])
        require_principal, authorizer = make_kernel_auth(
            jwks_provider=jwks_provider, audience=os.environ["VAULT_AUDIENCE"],
            issuer=os.environ["KERNEL_ISSUER"], now_fn=time.time,
            identity_store=identity_store, vault_store=service.store)
        manage_authorizer = make_manage_authorizer(
            now_fn=time.time, identity_store=identity_store, vault_store=service.store)
        return build_app(service, require_principal=require_principal, authorizer=authorizer,
                         manage_authorizer=manage_authorizer)
    return build_app(service)


app = _build_app_from_env() if os.environ.get("VAULT_BOOT") == "1" else None
