import time
from pathlib import Path

from identity.store.server import ServerIdentityStore
from identity.authorize import collect_grants
from deploy.soak_provision import soak_provision


def test_provision_creates_an_org_scoped_grant(tmp_path):
    store = ServerIdentityStore(str(tmp_path / "identity.sqlite"))
    cred = soak_provision(store, principal_id="connector:telegram", org_id="org_caput",
                          now=time.time(), granted_by="prn_owner")
    assert isinstance(cred, str) and cred
    grants = collect_grants(principal_id="connector:telegram", identity_store=store)
    org_grants = [g for g in grants if g.target.kind == "org" and g.target.id == "org_caput"]
    assert len(org_grants) == 1
    assert org_grants[0].access == "use"
