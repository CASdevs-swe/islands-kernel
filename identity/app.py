import os
from typing import Optional, Union

from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from identity.exchange import exchange, ExchangeError
from identity.jwt_issuer import mint
from identity.oauth.metadata import authorization_server_metadata, openid_configuration, protected_resource_metadata
from identity.oauth.authorize_endpoint import issue_auth_code
from identity.oauth.token_endpoint import redeem_code, refresh
from identity.federation.flow import start_federation, complete_federation, FederationError


class ExchangeRequest(BaseModel):
    opaque_token: str
    # str or list[str]: a single principal can exchange for a multi-audience token
    audience: Union[str, list[str]]


class AuthorizeRequest(BaseModel):
    client_id: str
    principal_id: str
    redirect_uri: str
    code_challenge: str
    audience: str
    org_id: Optional[str] = None
    scope: str = "mcp"


class TokenRequest(BaseModel):
    grant_type: Optional[str] = None
    # authorization_code branch
    code: Optional[str] = None
    code_verifier: Optional[str] = None
    audience: Optional[str] = None
    # refresh_token branch
    refresh_token: Optional[str] = None


def build_identity_app(*, store, key_manager, issuer: str, now_fn,
                       client_fetch=None, island_fetch=None, island_jwks_fetch=None) -> FastAPI:
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
    async def auth_exchange(body: ExchangeRequest):
        now = now_fn()
        try:
            resolved = exchange(opaque_token=body.opaque_token,
                                audience=body.audience, store=store, now=now)
        except ExchangeError as e:
            raise HTTPException(400, str(e))
        token = mint(km=key_manager, issuer=issuer, sub=resolved["principal_id"],
                     typ=resolved["type"], audience=body.audience, org=resolved["org_id"],
                     roles=resolved["roles"], ttl=300, now=int(now),
                     sid=resolved["sid"],
                     island=resolved.get("island"), island_sub=resolved.get("island_sub"),
                     island_org=resolved.get("island_org"))
        return {"access_token": token, "token_type": "Bearer", "expires_in": 300}

    @app.post("/oauth/authorize")
    async def oauth_authorize(body: AuthorizeRequest):
        try:
            code = issue_auth_code(store, client_id=body.client_id,
                                   principal_id=body.principal_id,
                                   org_id=body.org_id,
                                   redirect_uri=body.redirect_uri,
                                   code_challenge=body.code_challenge,
                                   audience=body.audience,
                                   scope=body.scope,
                                   now=now_fn())
        except ValueError as e:
            raise HTTPException(400, str(e))
        return {"code": code}

    @app.post("/oauth/token")
    async def oauth_token(body: TokenRequest):
        try:
            if body.grant_type == "refresh_token":
                if body.refresh_token is None:
                    raise ValueError("refresh_token is required")
                return refresh(store, refresh_token=body.refresh_token, now=now_fn())
            if None in (body.code, body.code_verifier, body.audience):
                raise ValueError("code, code_verifier and audience are required")
            return redeem_code(store, code=body.code,
                               code_verifier=body.code_verifier,
                               audience=body.audience, now=now_fn())
        except ValueError as e:
            raise HTTPException(400, str(e))

    @app.get("/oauth/authorize")
    async def oauth_authorize_browser(client_id: str, redirect_uri: str, code_challenge: str,
            resource: str, scope: str = "mcp", state: str = "",
            code_challenge_method: str = "S256"):
        if code_challenge_method != "S256":
            raise HTTPException(400, "unsupported code_challenge_method")
        try:
            target = start_federation(store, client_id=client_id, redirect_uri=redirect_uri,
                code_challenge=code_challenge, audience=resource, scope=scope, client_state=state,
                return_uri=f"{issuer}/oauth/callback", now=now_fn(), client_fetch=client_fetch)
        except FederationError as e:
            raise HTTPException(400, str(e))
        return RedirectResponse(target, status_code=302)

    @app.get("/oauth/callback")
    async def oauth_callback(txn: str, sso_code: str):
        try:
            target = complete_federation(store, txn_id=txn, sso_code=sso_code, now=now_fn(),
                island_fetch=island_fetch, island_jwks_fetch=island_jwks_fetch,
                kernel_issuer=issuer)
        except FederationError as e:
            raise HTTPException(400, str(e))
        return RedirectResponse(target, status_code=302)

    @app.get("/.well-known/oauth-protected-resource")
    async def oauth_protected_resource():
        return protected_resource_metadata(resource=issuer, authorization_servers=[issuer])

    return app


def _build_identity_app_from_env() -> FastAPI:
    import time
    import httpx
    from identity.keys import KeyManager
    from identity.store.server import ServerIdentityStore

    seed = os.environ.get("KERNEL_SIGNING_SEED")
    if not seed:
        # The signing seed is a host-secret/KMS value, never a committed file.
        raise RuntimeError("KERNEL_SIGNING_SEED is required to serve the identity kernel")
    km = KeyManager.from_seed(os.environ.get("KERNEL_KID", "kid-1"), seed)
    store = ServerIdentityStore(os.environ.get("KERNEL_IDENTITY_DB", "vault-store/identity.sqlite"))

    def client_fetch(url):
        return httpx.get(url, timeout=10).raise_for_status().json()

    def island_fetch(island, sso_code):
        r = httpx.post(island.sso_token_url, json={"sso_code": sso_code},
                       headers={"x-kernel-secret": os.environ.get("KERNEL_SSO_SECRET", "")}, timeout=10)
        r.raise_for_status()
        return r.json()["assertion"]

    def island_jwks_fetch(island):
        return httpx.get(island.jwks_uri, timeout=10).raise_for_status().json()

    return build_identity_app(store=store, key_manager=km,
                              issuer=os.environ["KERNEL_ISSUER"], now_fn=time.time,
                              client_fetch=client_fetch, island_fetch=island_fetch,
                              island_jwks_fetch=island_jwks_fetch)


app = _build_identity_app_from_env() if os.environ.get("IDENTITY_BOOT") == "1" else None
