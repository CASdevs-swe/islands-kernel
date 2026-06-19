from identity.oauth.metadata import (
    authorization_server_metadata, protected_resource_metadata, openid_configuration,
)


def test_as_metadata_advertises_pkce_and_eddsa():
    m = authorization_server_metadata(issuer="https://id.x")
    assert m["issuer"] == "https://id.x"
    assert m["authorization_endpoint"] == "https://id.x/oauth/authorize"
    assert m["token_endpoint"] == "https://id.x/oauth/token"
    assert m["jwks_uri"] == "https://id.x/.well-known/jwks.json"
    assert "S256" in m["code_challenge_methods_supported"]
    assert "EdDSA" in m["id_token_signing_alg_values_supported"]
    assert "refresh_token" in m["grant_types_supported"]


def test_protected_resource_metadata_shape():
    m = protected_resource_metadata(resource="https://mcp.x",
                                    authorization_servers=["https://id.x"])
    assert m["resource"] == "https://mcp.x"
    assert m["authorization_servers"] == ["https://id.x"]


def test_oidc_discovery_subset():
    m = openid_configuration(issuer="https://id.x")
    assert m["issuer"] == "https://id.x"
    assert m["jwks_uri"] == "https://id.x/.well-known/jwks.json"
