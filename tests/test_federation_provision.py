import time
from identity.store.server import ServerIdentityStore
from identity.tokens import hash_token
from scripts.federation_provision import provision_island, main


def test_provision_island_registers_and_creates_org(tmp_path):
    store = ServerIdentityStore(str(tmp_path / "identity.sqlite"))
    provision_island(store, island_id="unnest", name="unnest", issuer="https://app.unnest.se",
        jwks_uri="https://app.unnest.se/.well-known/jwks.json", audience="https://mcp.unnest.se/mcp",
        sso_authorize_url="https://app.unnest.se/sso/authorize",
        sso_token_url="https://app.unnest.se/sso/token", sso_client_secret="s3cr3t",
        org_id="org_unnest", org_name="unnest", session_ttl_days=30.0, now=time.time())
    isl = store.get_island_by_audience("https://mcp.unnest.se/mcp")
    assert isl.id == "unnest"
    assert isl.sso_client_secret_hash == hash_token("s3cr3t")  # raw secret never stored
    assert store.get_org("org_unnest").name == "unnest"


def test_main_prints_island_id_once(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("KERNEL_IDENTITY_DB", str(tmp_path / "identity.sqlite"))
    main(["--island", "unnest", "--name", "unnest", "--issuer", "https://app.unnest.se",
          "--jwks-uri", "https://app.unnest.se/jwks", "--audience", "https://mcp.unnest.se/mcp",
          "--sso-authorize-url", "https://app.unnest.se/sso/authorize",
          "--sso-token-url", "https://app.unnest.se/sso/token", "--sso-client-secret", "s3cr3t",
          "--org", "org_unnest", "--org-name", "unnest", "--session-ttl-days", "30"])
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "unnest"
    assert len(lines) == 2  # second line is the generated assertion secret


def test_provision_island_stores_assertion_secret(tmp_path):
    store = ServerIdentityStore(str(tmp_path / "identity.sqlite"))
    provision_island(store, island_id="unnest", name="unnest", issuer="https://app.unnest.se",
        jwks_uri="https://app.unnest.se/jwks", audience="https://mcp.unnest.se/mcp",
        sso_authorize_url="https://app.unnest.se/sso/authorize",
        sso_token_url="https://app.unnest.se/sso/token", sso_client_secret="s3cr3t",
        org_id="org_unnest", org_name="unnest", session_ttl_days=30.0, now=time.time(),
        assertion_secret="shared-xyz")
    assert store.get_island_by_audience("https://mcp.unnest.se/mcp").assertion_secret == "shared-xyz"
