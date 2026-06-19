from typing import Optional, Callable

from fastapi import Header, Cookie, HTTPException

from identity.jwt_verify import verify_island_jwt


class Claims(dict):
    pass


def make_require_principal(
    *,
    jwks_provider: Callable[[], dict],
    audience: str,
    now_fn: Callable[[], float],
    issuer: Optional[str] = None,
):
    def require_principal(
        authorization: Optional[str] = Header(default=None),
        cookie_auth: Optional[str] = Cookie(default=None, alias="auth"),
    ) -> Claims:
        token = None
        if authorization and authorization.lower().startswith("bearer "):
            token = authorization[7:]
        elif cookie_auth:
            token = cookie_auth
        if not token:
            raise HTTPException(401, "missing bearer token")
        try:
            claims = verify_island_jwt(
                token,
                jwks=jwks_provider(),
                audience=audience,
                now=now_fn(),
                issuer=issuer,
            )
        except ValueError as exc:
            raise HTTPException(401, str(exc))
        return Claims(claims)

    return require_principal
