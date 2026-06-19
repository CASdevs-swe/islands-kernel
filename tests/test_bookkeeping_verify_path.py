from identity.keys import KeyManager
from identity.jwt_issuer import mint
from islands_vault.verify import verify_island_jwt

# stand-in for bookkeeping's policies/access-matrix.yml, keyed on email
ACCESS_MATRIX = {"reconcile": ["bookkeeper@caput-venti.se"]}


def _bookkeeping_authorize(claims: dict, capability: str) -> bool:
    allowed = ACCESS_MATRIX.get(capability, [])
    return claims.get("email") in allowed


def test_verified_principal_drives_access_matrix():
    km = KeyManager.generate("kid-1")
    token = mint(km=km, issuer="https://id.x", sub="prn_bk", typ="human",
                 audience="https://bk.x", org="caput-venti", roles=["member"],
                 ttl=300, now=1000, email="bookkeeper@caput-venti.se")
    claims = verify_island_jwt(token, jwks=km.jwks_document(),
                               audience="https://bk.x", now=1100, issuer="https://id.x")
    assert _bookkeeping_authorize(claims, "reconcile") is True


def test_unlisted_principal_denied():
    km = KeyManager.generate("kid-1")
    token = mint(km=km, issuer="https://id.x", sub="prn_x", typ="human",
                 audience="https://bk.x", org="caput-venti", roles=["member"],
                 ttl=300, now=1000, email="intruder@example.com")
    claims = verify_island_jwt(token, jwks=km.jwks_document(),
                               audience="https://bk.x", now=1100, issuer="https://id.x")
    assert _bookkeeping_authorize(claims, "reconcile") is False
