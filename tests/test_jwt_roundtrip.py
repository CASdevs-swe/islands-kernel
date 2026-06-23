import jwt as pyjwt
from identity.keys import KeyManager
from identity.jwt_issuer import build_claims, mint_island_jwt, mint


def test_build_claims_has_spec_shape_and_backcompat():
    c = build_claims(issuer="https://id.x", sub="prn_1", typ="human",
                     email="a@b.se", org="org_1", roles=["owner"], perms=["deals:write"],
                     sid="ses_1", audience="https://mcp.x", scope="mcp",
                     iat=100, exp=400)
    assert c["iss"] == "https://id.x"
    assert c["sub"] == "prn_1"
    assert c["org"] == "org_1"
    assert c["aud"] == "https://mcp.x"
    assert c["userId"] == "prn_1"        # back-compat
    assert c["workspaceId"] == "org_1"   # back-compat
    assert c["exp"] == 400


def test_single_tenant_org_may_be_null():
    c = build_claims(issuer="https://id.x", sub="svc_1", typ="service",
                     email=None, org=None, roles=[], perms=None, sid=None,
                     audience="https://vault.x", scope="mcp", iat=0, exp=300)
    assert c["org"] is None
    assert c["workspaceId"] is None


def test_mint_produces_verifiable_eddsa_token():
    km = KeyManager.generate("kid-1")
    token = mint(km=km, issuer="https://id.x", sub="prn_1", typ="human",
                 audience="https://mcp.x", org="org_1", roles=["owner"],
                 ttl=300, now=1000, email="a@b.se")
    header = pyjwt.get_unverified_header(token)
    assert header["alg"] == "EdDSA"
    assert header["kid"] == "kid-1"
    # verify signature with the public key
    decoded = pyjwt.decode(token, km._priv.public_key(), algorithms=["EdDSA"],
                           audience="https://mcp.x", options={"verify_exp": False})
    assert decoded["sub"] == "prn_1" and decoded["exp"] == 1300


def test_build_claims_includes_island_native_id_when_present():
    c = build_claims(issuer="https://id.x", sub="prn_1", typ="human", email=None, org="org_unnest",
                     roles=["member"], perms=None, sid=None, audience="https://mcp.unnest.se/mcp",
                     scope="mcp", iat=100, exp=400, island="unnest", island_sub="42", island_org="ws_7")
    assert c["island"] == "unnest"
    assert c["island_sub"] == "42"
    assert c["island_org"] == "ws_7"


def test_build_claims_omits_island_keys_when_absent():
    c = build_claims(issuer="https://id.x", sub="prn_1", typ="service", email=None, org=None,
                     roles=[], perms=None, sid=None, audience="https://mcp.x", scope="mcp",
                     iat=100, exp=400)
    assert "island" not in c and "island_sub" not in c and "island_org" not in c
