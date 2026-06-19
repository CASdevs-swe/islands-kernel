import pytest
import nacl.utils
from vault.store.memory import InMemoryStore
from vault.model import Connection, ConnKey, Token
from vault.providers.fortnox import FortnoxProvider
from vault.providers.base import AppCred
from vault.access import AccessService
from vault.config import VaultConfig


def _svc():
    store = InMemoryStore()
    store.put_connection(Connection(
        id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
        scopes=["bookkeeping"], app_cred_ref="fortnox",
        token=Token("ACCESS", "REFRESH", 99999.0, "bookkeeping"),
        rotation="rotating", lease=None, created_by="owner", created_at=0.0, updated_at=0.0))
    cfg = VaultConfig(now_fn=lambda: 1000.0, http_post=lambda *a: {},
                      app_creds={"fortnox": AppCred("c", "s")}, state_hmac_key=b"k")
    return AccessService(store, {"fortnox": FortnoxProvider()}, cfg), store


KEY = ConnKey("caput-venti", "fortnox", "559401-5157")


def test_owner_can_access():
    svc, _ = _svc()
    assert svc.get_access_token(KEY, principal_id="owner", island="bookkeeping")["accessToken"] == "ACCESS"


def test_ungranted_principal_denied():
    svc, _ = _svc()
    with pytest.raises(PermissionError):
        svc.get_access_token(KEY, principal_id="stranger", island="bookkeeping")


def test_use_grant_allows_token_but_not_regrant():
    svc, _ = _svc()
    svc.grant(KEY, granter_id="owner", principal_id="teammate", access="use", scopes_subset=None)
    assert svc.get_access_token(KEY, "teammate", "bookkeeping")["accessToken"] == "ACCESS"
    with pytest.raises(PermissionError):
        svc.grant(KEY, granter_id="teammate", principal_id="third", access="use", scopes_subset=None)


def test_manage_required_to_list():
    svc, _ = _svc()
    with pytest.raises(PermissionError):
        svc.list_connections("caput-venti", "fortnox", principal_id="stranger")
    assert len(svc.list_connections("caput-venti", "fortnox", principal_id="owner")) == 1
