import urllib.parse as up

from identity.tokens import generate_raw_token, hash_token
from identity.model import FederationTxn
from identity.oauth.clients import resolve_client, validate_redirect_uri
from identity.oauth.authorize_endpoint import issue_auth_code
from identity.federation.assertion import (verify_island_assertion,
    verify_island_assertion_symmetric, IslandAssertionError)
from identity.federation.principals import find_or_create_island_principal


class FederationError(ValueError):
    pass


def start_federation(store, *, client_id, redirect_uri, code_challenge, audience, scope,
                     client_state, return_uri, now, client_fetch=None, txn_ttl=600) -> str:
    try:
        client = resolve_client(store, client_id=client_id, fetch=client_fetch)
        validate_redirect_uri(client, redirect_uri)
    except ValueError as e:
        raise FederationError(str(e))
    island = store.get_island_by_audience(audience)
    if island is None:
        raise FederationError(f"no island registered for audience {audience}")
    if island.disabled_at is not None:
        raise FederationError("island disabled")
    txn_id = generate_raw_token("ftx")
    nonce = generate_raw_token("non")
    store.put_federation_txn(FederationTxn(hash=hash_token(txn_id), client_id=client.id,
        redirect_uri=redirect_uri, code_challenge=code_challenge, audience=audience, scope=scope,
        client_state=client_state, island_id=island.id, nonce=nonce, expires_at=now + txn_ttl))
    query = up.urlencode({"return_uri": return_uri, "txn": txn_id, "nonce": nonce})
    sep = "&" if "?" in island.sso_authorize_url else "?"
    return f"{island.sso_authorize_url}{sep}{query}"


def complete_federation(store, *, txn_id, sso_code, now, island_fetch, island_jwks_fetch,
                        kernel_issuer) -> str:
    txn = store.get_federation_txn(hash_token(txn_id))
    if txn is None:
        raise FederationError("unknown transaction")
    if now >= txn.expires_at:
        raise FederationError("transaction expired")
    if not store.consume_federation_txn(txn.hash, now):
        raise FederationError("transaction already used")
    island = store.get_island(txn.island_id)
    if island is None or island.disabled_at is not None:
        raise FederationError("island unavailable")
    try:
        assertion = island_fetch(island, sso_code)
        jwks = None if island.assertion_secret else island_jwks_fetch(island)
    except FederationError:
        raise
    except Exception:
        raise FederationError("island token exchange failed")
    try:
        if island.assertion_secret:
            identity = verify_island_assertion_symmetric(assertion, secret=island.assertion_secret,
                expected_iss=island.issuer, expected_aud=kernel_issuer,
                expected_nonce=txn.nonce, now=now)
        else:
            # the assertion's audience is the kernel issuer; passed in explicitly by the route layer
            identity = verify_island_assertion(assertion, jwks=jwks,
                expected_iss=island.issuer, expected_aud=kernel_issuer,
                expected_nonce=txn.nonce, now=now)
    except IslandAssertionError as e:
        raise FederationError(str(e))
    principal_id = find_or_create_island_principal(store, island=island,
        island_user_id=identity["island_user_id"], email=identity.get("email"), now=now)
    code = issue_auth_code(store, client_id=txn.client_id, principal_id=principal_id,
        org_id=island.org_id, redirect_uri=txn.redirect_uri, code_challenge=txn.code_challenge,
        audience=txn.audience, scope=txn.scope, now=now)
    query = up.urlencode({"code": code, "state": txn.client_state})
    sep = "&" if "?" in txn.redirect_uri else "?"
    return f"{txn.redirect_uri}{sep}{query}"
