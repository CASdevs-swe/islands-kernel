import pytest

from vault.access import AccessService
from vault.config import VaultConfig
from vault.store.memory import InMemoryStore
from vault.model import Connection, Token
from vault.providers.fortnox import FortnoxProvider
from vault.providers.base import AppCred


def _service():
    store = InMemoryStore()
    store.put_connection(Connection(
        id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
        scopes=["bookkeeping"], app_cred_ref="fortnox",
        token=Token("A", "R", 99999.0, "bookkeeping"), rotation="rotating",
        lease=None, created_by="prn_owner", created_at=0.0, updated_at=0.0))
    cfg = VaultConfig(now_fn=lambda: 1000.0, http_post=lambda *a: {},
                      app_creds={"fortnox": AppCred("c", "s")}, state_hmac_key=b"k", skew=60)
    return AccessService(store, {"fortnox": FortnoxProvider()}, cfg), store


def _key():
    from vault.model import ConnKey
    return ConnKey("caput-venti", "fortnox", "559401-5157")


def test_revoke_denied_when_manage_check_false():
    svc, _ = _service()
    with pytest.raises(PermissionError):
        svc.revoke(_key(), "prn_x", manage_check=lambda conn: False)


def test_grant_allowed_when_manage_check_true():
    svc, _ = _service()
    out = svc.grant(_key(), "prn_x", "prn_new", "use", None, manage_check=lambda conn: True)
    assert out["principalId"] == "prn_new"


def test_list_filters_by_manage_check():
    svc, _ = _service()
    out = svc.list_connections("caput-venti", None, "prn_x", manage_check=lambda conn: True)
    assert len(out) == 1 and out[0]["id"] == "conn_1"
    with pytest.raises(PermissionError):
        svc.list_connections("caput-venti", None, "prn_x", manage_check=lambda conn: False)


def test_none_manage_check_preserves_slice1_owner_behavior():
    svc, _ = _service()
    # owner (created_by) can grant via the legacy require_access path
    out = svc.grant(_key(), "prn_owner", "prn_new", "use", None)
    assert out["principalId"] == "prn_new"
