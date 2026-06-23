from typing import Optional

import jwt as pyjwt

from identity.keys import KeyManager


def build_claims(
    *,
    issuer: str,
    sub: str,
    typ: str,
    email: Optional[str],
    org: Optional[str],
    roles: list,
    perms: Optional[list],
    sid: Optional[str],
    audience: str,
    scope: str,
    iat: int,
    exp: int,
    island: Optional[str] = None,
    island_sub: Optional[str] = None,
    island_org: Optional[str] = None,
) -> dict:
    claims = {
        "iss": issuer,
        "sub": sub,
        "typ": typ,
        "email": email,
        "org": org,
        "roles": roles,
        "sid": sid,
        "aud": audience,
        "scope": scope,
        "iat": iat,
        "exp": exp,
        # back-compat shim — sm-brf reads userId, nudge reads workspaceId
        "userId": sub,
        "workspaceId": org,
    }
    if perms is not None:
        claims["perms"] = perms
    if island is not None:
        claims["island"] = island
        claims["island_sub"] = island_sub
        claims["island_org"] = island_org
    return claims


def mint_island_jwt(claims: dict, km: KeyManager) -> str:
    return pyjwt.encode(
        claims,
        km.private_pem(),
        algorithm="EdDSA",
        headers={"kid": km.kid},
    )


def mint(
    *,
    km: KeyManager,
    issuer: str,
    sub: str,
    typ: str,
    audience: str,
    org: Optional[str],
    roles: list,
    ttl: int,
    now: int,
    email: Optional[str] = None,
    perms: Optional[list] = None,
    sid: Optional[str] = None,
    scope: str = "mcp",
    island: Optional[str] = None,
    island_sub: Optional[str] = None,
    island_org: Optional[str] = None,
) -> str:
    claims = build_claims(
        issuer=issuer,
        sub=sub,
        typ=typ,
        email=email,
        org=org,
        roles=roles,
        perms=perms,
        sid=sid,
        audience=audience,
        scope=scope,
        iat=int(now),
        exp=int(now) + int(ttl),
        island=island,
        island_sub=island_sub,
        island_org=island_org,
    )
    return mint_island_jwt(claims, km)
