import urllib.parse as up
import jwt as pyjwt
import pytest
from identity.store.memory import InMemoryIdentityStore
from identity.keys import KeyManager
from identity.model import IslandRegistry, Org, OAuthClient
from identity.tokens import hash_token
from identity.oauth.clients import register_client
from identity.oauth.pkce import make_challenge
from identity.oauth.token_endpoint import redeem_code
from identity.federation.flow import start_federation, complete_federation, FederationError

KERNEL_ISS = "https://id.caputventi.com"
ISLAND_ISS = "https://app.unnest.se"
AUD = "https://mcp.unnest.se/mcp"
RETURN = f"{KERNEL_ISS}/oauth/callback"


def _store(island_km):
    s = InMemoryIdentityStore()
    s.put_org(Org(id="org_unnest", name="unnest", created_at=0.0))
    register_client(s, client_id="cli_1", name="Claude", redirect_uris=["https://claude.ai/cb"], type="public")
    s.put_island(IslandRegistry(id="unnest", name="unnest", issuer=ISLAND_ISS,
        jwks_uri="https://app.unnest.se/jwks", audience=AUD,
        sso_authorize_url="https://app.unnest.se/sso/authorize",
        sso_token_url="https://app.unnest.se/sso/token", sso_client_secret_hash="x",
        org_id="org_unnest", session_ttl_days=30.0, created_at=0.0))
    return s


def _full_flow(s, island_km, *, verifier="v" * 64):
    redirect = start_federation(s, client_id="cli_1", redirect_uri="https://claude.ai/cb",
        code_challenge=make_challenge(verifier), audience=AUD, scope="mcp",
        client_state="STATE", return_uri=RETURN, now=1000)
    q = dict(up.parse_qsl(up.urlsplit(redirect).query))
    assert redirect.startswith("https://app.unnest.se/sso/authorize?")
    txn_id, nonce = q["txn"], q["nonce"]

    def island_fetch(island, sso_code):
        claims = {"iss": ISLAND_ISS, "sub": "42", "aud": KERNEL_ISS, "nonce": nonce,
                  "exp": 9999, "email": "a@b.se"}
        return pyjwt.encode(claims, island_km.private_pem(), algorithm="EdDSA",
                            headers={"kid": island_km.kid})

    final = complete_federation(s, txn_id=txn_id, sso_code="islandcode", now=1100,
        island_fetch=island_fetch, island_jwks_fetch=lambda island: island_km.jwks_document(),
        kernel_issuer=KERNEL_ISS)
    return final, verifier


def test_full_federation_issues_code_for_island_user():
    island_km = KeyManager.generate("island-1")
    s = _store(island_km)
    final, verifier = _full_flow(s, island_km)
    q = dict(up.parse_qsl(up.urlsplit(final).query))
    assert final.startswith("https://claude.ai/cb?")
    assert q["state"] == "STATE"
    # the issued code redeems to a token bound to a real (created) principal
    out = redeem_code(s, code=q["code"], code_verifier=verifier, audience=AUD, now=1200)
    assert out["access_token"].startswith("at_")
    assert s.get_principal_by_island("unnest", "42") is not None


def test_unknown_audience_is_rejected():
    s = _store(KeyManager.generate("island-1"))
    with pytest.raises(FederationError):
        start_federation(s, client_id="cli_1", redirect_uri="https://claude.ai/cb",
            code_challenge="c", audience="https://unknown", scope="mcp",
            client_state="x", return_uri=RETURN, now=1000)


def test_island_fetch_transport_error_becomes_federation_error():
    island_km = KeyManager.generate("island-1")
    s = _store(island_km)
    redirect = start_federation(s, client_id="cli_1", redirect_uri="https://claude.ai/cb",
        code_challenge=make_challenge("v" * 64), audience=AUD, scope="mcp",
        client_state="STATE", return_uri=RETURN, now=1000)
    txn_id = dict(up.parse_qsl(up.urlsplit(redirect).query))["txn"]

    def bad_fetch(island, sso_code):
        raise RuntimeError("island 503")

    with pytest.raises(FederationError):
        complete_federation(s, txn_id=txn_id, sso_code="c", now=1100,
            island_fetch=bad_fetch,
            island_jwks_fetch=lambda island: island_km.jwks_document(),
            kernel_issuer=KERNEL_ISS)


def test_full_federation_with_symmetric_island():
    s = InMemoryIdentityStore()
    s.put_org(Org(id="org_unnest", name="unnest", created_at=0.0))
    register_client(s, client_id="cli_1", name="Claude", redirect_uris=["https://claude.ai/cb"], type="public")
    SHARED = "k" * 32
    s.put_island(IslandRegistry(id="unnest", name="unnest", issuer=ISLAND_ISS,
        jwks_uri="https://app.unnest.se/jwks", audience=AUD,
        sso_authorize_url="https://app.unnest.se/sso/authorize",
        sso_token_url="https://app.unnest.se/sso/token", sso_client_secret_hash="x",
        org_id="org_unnest", session_ttl_days=30.0, created_at=0.0, assertion_secret=SHARED))
    verifier = "v" * 64
    redirect = start_federation(s, client_id="cli_1", redirect_uri="https://claude.ai/cb",
        code_challenge=make_challenge(verifier), audience=AUD, scope="mcp",
        client_state="STATE", return_uri=RETURN, now=1000)
    q = dict(up.parse_qsl(up.urlsplit(redirect).query))
    nonce = q["nonce"]

    def island_fetch(island, sso_code):
        claims = {"iss": ISLAND_ISS, "sub": "42", "aud": KERNEL_ISS, "nonce": nonce,
                  "exp": 9999, "email": "a@b.se"}
        return pyjwt.encode(claims, island.assertion_secret, algorithm="HS256")

    def boom_jwks(island):
        raise AssertionError("jwks must not be fetched for a symmetric island")

    final = complete_federation(s, txn_id=q["txn"], sso_code="c", now=1100,
        island_fetch=island_fetch, island_jwks_fetch=boom_jwks, kernel_issuer=KERNEL_ISS)
    cq = dict(up.parse_qsl(up.urlsplit(final).query))
    assert cq["state"] == "STATE"
    out = redeem_code(s, code=cq["code"], code_verifier=verifier, audience=AUD, now=1200)
    assert out["access_token"].startswith("at_")
    assert s.get_principal_by_island("unnest", "42") is not None


def test_replayed_txn_is_rejected():
    island_km = KeyManager.generate("island-1")
    s = _store(island_km)
    redirect = start_federation(s, client_id="cli_1", redirect_uri="https://claude.ai/cb",
        code_challenge=make_challenge("v" * 64), audience=AUD, scope="mcp",
        client_state="STATE", return_uri=RETURN, now=1000)
    txn_id = dict(up.parse_qsl(up.urlsplit(redirect).query))["txn"]
    nonce = dict(up.parse_qsl(up.urlsplit(redirect).query))["nonce"]
    fetch = lambda island, sso_code: pyjwt.encode(
        {"iss": ISLAND_ISS, "sub": "42", "aud": KERNEL_ISS, "nonce": nonce, "exp": 9999},
        island_km.private_pem(), algorithm="EdDSA", headers={"kid": island_km.kid})
    jwks = lambda island: island_km.jwks_document()
    complete_federation(s, txn_id=txn_id, sso_code="c", now=1100, island_fetch=fetch,
                        island_jwks_fetch=jwks, kernel_issuer=KERNEL_ISS)
    with pytest.raises(FederationError):
        complete_federation(s, txn_id=txn_id, sso_code="c", now=1100, island_fetch=fetch,
                            island_jwks_fetch=jwks, kernel_issuer=KERNEL_ISS)
