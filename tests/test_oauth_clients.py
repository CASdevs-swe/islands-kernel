import pytest
from identity.store.memory import InMemoryIdentityStore
from identity.oauth.clients import (
    register_client, resolve_client, validate_redirect_uri,
)


def test_register_and_resolve_local_client():
    s = InMemoryIdentityStore()
    register_client(s, client_id="cli_1", name="Dash",
                    redirect_uris=["https://app.x/cb"], type="public")
    c = resolve_client(s, client_id="cli_1")
    assert c.redirect_uris == ["https://app.x/cb"]


def test_validate_redirect_uri_rejects_unregistered():
    s = InMemoryIdentityStore()
    c = register_client(s, client_id="cli_1", name="Dash",
                        redirect_uris=["https://app.x/cb"], type="public")
    with pytest.raises(ValueError):
        validate_redirect_uri(c, "https://evil.x/cb")


def test_client_id_metadata_document_is_fetched_and_cached():
    s = InMemoryIdentityStore()
    url = "https://claude.ai/.well-known/oauth-client"
    doc = {"client_name": "Claude", "redirect_uris": ["https://claude.ai/cb"],
           "token_endpoint_auth_method": "none"}
    c = resolve_client(s, client_id=url, fetch=lambda u: doc)
    assert c.id == url
    assert c.redirect_uris == ["https://claude.ai/cb"]
    # cached: a second resolve does not need fetch
    assert resolve_client(s, client_id=url).redirect_uris == ["https://claude.ai/cb"]
