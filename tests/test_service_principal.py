from identity.store.memory import InMemoryIdentityStore
from identity.tokens import hash_token
from identity.exchange import exchange
from identity.service_principal import issue_service_credential, grant_connection_use


def test_issue_service_credential_creates_service_principal_and_token():
    s = InMemoryIdentityStore()
    raw = issue_service_credential(
        s, principal_id="prn_bk", display_name="bookkeeping",
        org_id="caput-venti", audience="https://vault.local", now=1000.0,
        expires_at=10_000.0)

    assert raw.startswith("mcp_")
    p = s.get_principal("prn_bk")
    assert p is not None and p.type == "service"
    m = s.get_membership("prn_bk", "caput-venti")
    assert m is not None and m.active is True
    tok = s.get_mcp_token(hash_token(raw))
    assert tok is not None
    assert tok.principal_id == "prn_bk"
    assert tok.audience == "https://vault.local"


def test_issued_credential_exchanges_as_service_type():
    s = InMemoryIdentityStore()
    raw = issue_service_credential(
        s, principal_id="prn_bk", display_name="bookkeeping",
        org_id="caput-venti", audience="https://vault.local", now=1000.0,
        expires_at=10_000.0)

    resolved = exchange(opaque_token=raw, audience="https://vault.local",
                        store=s, now=1100.0)
    assert resolved["principal_id"] == "prn_bk"
    assert resolved["org_id"] == "caput-venti"
    assert resolved["type"] == "service"


def test_grant_connection_use_adds_unified_use_grant():
    s = InMemoryIdentityStore()
    issue_service_credential(
        s, principal_id="prn_bk", display_name="bookkeeping",
        org_id="caput-venti", audience="https://vault.local", now=1000.0)

    g = grant_connection_use(s, principal_id="prn_bk", connection_id="conn_1",
                             granted_by="prn_owner", now=1000.0)
    assert g.target.kind == "connection" and g.target.id == "conn_1"
    assert g.access == "use"
    grants = s.list_grants("prn_bk")
    assert any(x.target.id == "conn_1" and x.access == "use" for x in grants)
