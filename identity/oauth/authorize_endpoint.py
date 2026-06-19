from typing import Callable, Optional

from identity.model import OAuthAuthCode, OAuthClient
from identity.tokens import generate_raw_token, hash_token
from identity.oauth.clients import resolve_client, validate_redirect_uri


def build_consent(*, client: OAuthClient, scope: str, audience: str) -> dict:
    return {
        "client_name": client.name,
        "client_id": client.id,
        "scope": scope,
        "audience": audience,
        "redirect_uris": client.redirect_uris,
    }


def issue_auth_code(
    store,
    *,
    client_id: str,
    principal_id: str,
    org_id: Optional[str],
    redirect_uri: str,
    code_challenge: str,
    audience: str,
    scope: str,
    now: float,
    ttl: int = 600,
    fetch: Optional[Callable[[str], dict]] = None,
) -> str:
    client = resolve_client(store, client_id=client_id, fetch=fetch)
    validate_redirect_uri(client, redirect_uri)
    raw = generate_raw_token("ac")
    store.put_auth_code(OAuthAuthCode(
        hash=hash_token(raw),
        client_id=client.id,
        principal_id=principal_id,
        org_id=org_id,
        code_challenge=code_challenge,
        audience=audience,
        scope=scope,
        expires_at=now + ttl,
        consumed_at=None,
    ))
    return raw
