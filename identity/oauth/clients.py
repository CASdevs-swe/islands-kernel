from typing import Callable, Optional
from identity.model import OAuthClient


def register_client(store, *, client_id: str, name: str,
                    redirect_uris: list, type: str) -> OAuthClient:
    c = OAuthClient(id=client_id, name=name, redirect_uris=list(redirect_uris),
                    type=type, client_id_metadata_url=None)
    store.put_oauth_client(c)
    return c


def validate_redirect_uri(client: OAuthClient, redirect_uri: str) -> None:
    if redirect_uri not in client.redirect_uris:
        raise ValueError("unregistered redirect_uri")


def resolve_client(store, *, client_id: str,
                   fetch: Optional[Callable[[str], dict]] = None) -> OAuthClient:
    existing = store.get_oauth_client(client_id)
    if existing is not None:
        return existing
    if client_id.startswith("https://") and fetch is not None:
        doc = fetch(client_id)
        redirect_uris = doc.get("redirect_uris") or []
        if not redirect_uris:
            raise ValueError("client metadata has no redirect_uris")
        c = OAuthClient(id=client_id, name=doc.get("client_name", client_id),
                        redirect_uris=list(redirect_uris), type="public",
                        client_id_metadata_url=client_id)
        store.put_oauth_client(c)
        return c
    raise ValueError(f"unknown client {client_id}")
