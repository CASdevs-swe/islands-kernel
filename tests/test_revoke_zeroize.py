import pytest, nacl.utils
from pathlib import Path
from vault.crypto import SecretboxKeyWrapper
from vault.store.local_file import LocalFileStore
from vault.model import Connection, ConnKey, Token
from vault.providers.fortnox import FortnoxProvider
from vault.providers.base import AppCred
from vault.access import AccessService
from vault.config import VaultConfig

KEY = ConnKey("caput-venti", "fortnox", "559401-5157")


def _svc(tmp_path):
    store = LocalFileStore(root=Path(tmp_path), wrapper=SecretboxKeyWrapper(nacl.utils.random(32)))
    store.put_connection(Connection(
        id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
        scopes=["bookkeeping"], app_cred_ref="fortnox", token=Token("A", "R", 99999.0, "s"),
        rotation="rotating", lease=None, created_by="owner", created_at=0.0, updated_at=0.0))
    cfg = VaultConfig(now_fn=lambda: 1000.0, http_post=lambda *a: {},
                      app_creds={"fortnox": AppCred("c", "s")}, state_hmac_key=b"k")
    return AccessService(store, {"fortnox": FortnoxProvider()}, cfg), store, tmp_path


def test_revoke_requires_manage(tmp_path):
    svc, _, _ = _svc(tmp_path)
    with pytest.raises(PermissionError):
        svc.revoke(KEY, principal_id="stranger")


def test_revoke_deletes_and_zeroizes(tmp_path):
    svc, store, tp = _svc(tmp_path)
    svc.revoke(KEY, principal_id="owner")
    assert store.get_connection(KEY) is None
    assert not (Path(tp) / "connections/caput-venti/fortnox/559401-5157.token.age").exists()
    with pytest.raises(KeyError):
        svc.get_access_token(KEY, "owner", "bookkeeping")
