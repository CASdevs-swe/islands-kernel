import jwt as pyjwt
from jwt.algorithms import OKPAlgorithm


class IslandAssertionError(ValueError):
    pass


def _public_key_for_kid(jwks: dict, kid: str):
    for jwk in jwks.get("keys", []):
        if jwk.get("kid") == kid:
            try:
                return OKPAlgorithm.from_jwk(jwk)
            except Exception as e:
                raise IslandAssertionError(f"malformed JWK for kid={kid}: {e}")
    raise IslandAssertionError(f"no JWK for kid={kid}")


def verify_island_assertion(token: str, *, jwks: dict, expected_iss: str, expected_aud: str,
                            expected_nonce: str, now: float) -> dict:
    try:
        kid = pyjwt.get_unverified_header(token).get("kid")
    except pyjwt.PyJWTError as e:
        raise IslandAssertionError(f"bad token header: {e}")
    if not kid:
        raise IslandAssertionError("assertion missing kid")
    pub = _public_key_for_kid(jwks, kid)
    try:
        claims = pyjwt.decode(token, pub, algorithms=["EdDSA"], audience=expected_aud,
                              issuer=expected_iss,
                              options={"verify_exp": False, "require": ["exp", "sub", "aud", "iss"]})
    except pyjwt.PyJWTError as e:
        raise IslandAssertionError(f"assertion verification failed: {e}")
    if now >= claims["exp"]:
        raise IslandAssertionError("assertion expired")
    if claims.get("nonce") != expected_nonce:
        raise IslandAssertionError("nonce mismatch")
    return {"island_user_id": claims["sub"], "email": claims.get("email"),
            "workspace": claims.get("workspace")}
