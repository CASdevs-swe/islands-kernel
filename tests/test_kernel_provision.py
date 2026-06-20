import time

from identity.store.server import ServerIdentityStore
from identity.authorize import collect_grants
from identity.tokens import hash_token
from scripts.kernel_provision import provision, main


def test_provision_creates_principal_with_both_grants(tmp_path):
    store = ServerIdentityStore(str(tmp_path / "identity.sqlite"))
    cred = provision(store, principal_id="prn_x", org_id="caput-venti",
                     connection_id="conn_1", event_type="bookkeeping.voucher.posted",
                     now=time.time())
    assert isinstance(cred, str) and cred
    grants = collect_grants(principal_id="prn_x", identity_store=store)
    targets = {(g.target.kind, g.target.id) for g in grants}
    assert ("connection", "conn_1") in targets
    assert ("event-type", "bookkeeping.voucher.posted") in targets


def test_provision_threads_granted_by_and_expiry(tmp_path):
    store = ServerIdentityStore(str(tmp_path / "identity.sqlite"))
    now = 1_000_000.0
    cred = provision(store, principal_id="prn_y", org_id="caput-venti",
                     connection_id="conn_1", event_type="bookkeeping.voucher.posted",
                     now=now, granted_by="prn_operator", expires_at=now + 3600)
    for g in collect_grants(principal_id="prn_y", identity_store=store):
        assert g.granted_by == "prn_operator"
    token = store.get_mcp_token(hash_token(cred))
    assert token.expires_at == now + 3600


def test_main_defaults_to_bounded_ttl(tmp_path, monkeypatch, capsys):
    db = str(tmp_path / "identity.sqlite")
    monkeypatch.setenv("KERNEL_IDENTITY_DB", db)
    before = time.time()
    main(["--principal", "prn_z", "--org", "caput-venti", "--connection", "conn_1",
          "--event-type", "bookkeeping.voucher.posted", "--granted-by", "prn_operator"])
    after = time.time()
    cred = capsys.readouterr().out.strip()
    token = ServerIdentityStore(db).get_mcp_token(hash_token(cred))
    ninety_days = 90 * 86400
    assert before + ninety_days <= token.expires_at <= after + ninety_days


def test_main_expires_at_overrides_ttl(tmp_path, monkeypatch, capsys):
    db = str(tmp_path / "identity.sqlite")
    monkeypatch.setenv("KERNEL_IDENTITY_DB", db)
    main(["--principal", "prn_w", "--org", "caput-venti", "--connection", "conn_1",
          "--event-type", "bookkeeping.voucher.posted", "--granted-by", "prn_operator",
          "--expires-at", "2000000000"])
    cred = capsys.readouterr().out.strip()
    token = ServerIdentityStore(db).get_mcp_token(hash_token(cred))
    assert token.expires_at == 2000000000.0
