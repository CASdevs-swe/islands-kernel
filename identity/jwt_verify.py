from typing import Optional

import jwt as pyjwt
from jwt.algorithms import OKPAlgorithm


def _public_key_for_kid(jwks: dict, kid: str):
    for jwk in jwks.get("keys", []):
        if jwk.get("kid") == kid:
            return OKPAlgorithm.from_jwk(jwk)
    raise ValueError(f"no JWK for kid={kid}")


def verify_island_jwt(token: str, *, jwks: dict, audience: str, now: float,
                      issuer: Optional[str] = None) -> dict:
    try:
        kid = pyjwt.get_unverified_header(token).get("kid")
    except pyjwt.PyJWTError as e:
        raise ValueError(f"bad token header: {e}")
    if not kid:
        raise ValueError("token missing kid")

    pub = _public_key_for_kid(jwks, kid)
    try:
        claims = pyjwt.decode(
            token, pub, algorithms=["EdDSA"], audience=audience,
            issuer=issuer,
            options={"verify_exp": False, "verify_iss": issuer is not None,
                     "require": ["exp", "sub", "aud"]})
    except pyjwt.PyJWTError as e:
        raise ValueError(f"jwt verification failed: {e}")

    if now >= claims["exp"]:
        raise ValueError("token expired")
    return claims
