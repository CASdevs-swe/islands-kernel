import time

from identity.store.server import ServerIdentityStore
from identity.authorize import collect_grants
from scripts.kernel_provision import provision


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
