from fastapi import FastAPI, HTTPException, Body

from identity.exchange import exchange, ExchangeError
from identity.jwt_issuer import mint
from identity.oauth.metadata import authorization_server_metadata, openid_configuration
from identity.oauth.authorize_endpoint import issue_auth_code
from identity.oauth.token_endpoint import redeem_code, refresh


def build_identity_app(*, store, key_manager, issuer: str, now_fn) -> FastAPI:
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
    async def auth_exchange(body: dict = Body(...)):
        try:
            resolved = exchange(opaque_token=body["opaque_token"],
                                audience=body["audience"], store=store, now=now_fn())
        except ExchangeError as e:
            raise HTTPException(400, str(e))
        token = mint(km=key_manager, issuer=issuer, sub=resolved["principal_id"],
                     typ="human", audience=body["audience"], org=resolved["org_id"],
                     roles=resolved["roles"], ttl=300, now=int(now_fn()),
                     sid=resolved["sid"])
        return {"access_token": token, "token_type": "Bearer", "expires_in": 300}

    @app.post("/oauth/authorize")
    async def oauth_authorize(body: dict = Body(...)):
        try:
            code = issue_auth_code(store, client_id=body["client_id"],
                                   principal_id=body["principal_id"],
                                   org_id=body.get("org_id"),
                                   redirect_uri=body["redirect_uri"],
                                   code_challenge=body["code_challenge"],
                                   audience=body["audience"],
                                   scope=body.get("scope", "mcp"),
                                   now=now_fn())
        except ValueError as e:
            raise HTTPException(400, str(e))
        return {"code": code}

    @app.post("/oauth/token")
    async def oauth_token(body: dict = Body(...)):
        try:
            if body.get("grant_type") == "refresh_token":
                return refresh(store, refresh_token=body["refresh_token"], now=now_fn())
            return redeem_code(store, code=body["code"],
                               code_verifier=body["code_verifier"],
                               audience=body["audience"], now=now_fn())
        except ValueError as e:
            raise HTTPException(400, str(e))

    return app
