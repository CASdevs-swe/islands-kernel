from identity.model import OAuthAccessToken
from identity.tokens import generate_raw_token, hash_token
from identity.oauth.pkce import verify_pkce_s256


def _issue_pair(store, *, client_id, principal_id, org_id, audience, scope,
                now, access_ttl):
    access_raw = generate_raw_token("at")
    refresh_raw = generate_raw_token("rt")
    store.put_access_token(OAuthAccessToken(
        hash=hash_token(access_raw),
        client_id=client_id,
        principal_id=principal_id,
        org_id=org_id,
        audience=audience,
        scope=scope,
        expires_at=now + access_ttl,
        refresh={"hash": hash_token(refresh_raw), "expires_at": now + 30 * 86400},
    ))
    return {
        "access_token": access_raw,
        "refresh_token": refresh_raw,
        "token_type": "Bearer",
        "expires_in": access_ttl,
    }


def redeem_code(store, *, code, code_verifier, audience, now, access_ttl=3600) -> dict:
    row = store.get_auth_code(hash_token(code))
    if row is None:
        raise ValueError("unknown code")
    if now >= row.expires_at:
        raise ValueError("code expired")
    if row.audience != audience:
        raise ValueError("audience mismatch")
    if not verify_pkce_s256(verifier=code_verifier, challenge=row.code_challenge):
        raise ValueError("pkce verification failed")
    if not store.consume_auth_code(row.hash, now):   # atomic single-use gate
        raise ValueError("code already used")
    return _issue_pair(
        store,
        client_id=row.client_id,
        principal_id=row.principal_id,
        org_id=row.org_id,
        audience=row.audience,
        scope=row.scope,
        now=now,
        access_ttl=access_ttl,
    )


def refresh(store, *, refresh_token, now, access_ttl=3600) -> dict:
    rh = hash_token(refresh_token)
    current = None
    for cand_hash in store.access_token_hashes():
        row = store.get_access_token(cand_hash)
        if row and row.refresh and row.refresh.get("hash") == rh:
            current = row
            break
    if current is None:
        raise ValueError("unknown or rotated refresh token")
    if now >= current.refresh.get("expires_at", 0):
        raise ValueError("refresh token expired")
    issued = _issue_pair(
        store,
        client_id=current.client_id,
        principal_id=current.principal_id,
        org_id=current.org_id,
        audience=current.audience,
        scope=current.scope,
        now=now,
        access_ttl=access_ttl,
    )
    new_row = store.get_access_token(hash_token(issued["access_token"]))
    store.rotate_refresh(current.hash, new_row)
    return issued
