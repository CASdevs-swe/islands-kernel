import nacl.utils
from vault.crypto import SecretboxKeyWrapper
from vault.store.memory import InMemoryStore
from vault.model import Connection, ConnKey, Token
from vault.providers.fortnox import FortnoxProvider
from vault.access import AccessService
from vault.config import VaultConfig
from vault.providers.base import AppCred


def _service(now=1000.0):
    store = InMemoryStore()
    store.put_connection(Connection(
        id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
        scopes=["bookkeeping"], app_cred_ref="fortnox",
        token=Token("ACCESS", "REFRESH", expires_at=99999.0, scope="bookkeeping"),
        rotation="rotating", lease=None, created_by="stub", created_at=0.0, updated_at=0.0))
    cfg = VaultConfig(now_fn=lambda: now, http_post=lambda *a: {},
                      app_creds={"fortnox": AppCred("cid", "secret")},
                      state_hmac_key=b"k", skew=60)
    return AccessService(store, {"fortnox": FortnoxProvider()}, cfg), store


def test_access_token_response_has_no_refresh_token():
    svc, _ = _service()
    out = svc.get_access_token(ConnKey("caput-venti", "fortnox", "559401-5157"),
                               principal_id="stub", island="bookkeeping")
    assert out == {"accessToken": "ACCESS", "scope": "bookkeeping", "expiresAt": 99999.0}
    assert "refresh" not in str(out).lower()


def test_access_token_writes_metadata_log():
    svc, store = _service()
    svc.get_access_token(ConnKey("caput-venti", "fortnox", "559401-5157"), "stub", "bookkeeping")
    log = store.read_log("conn_1")[0]
    assert (log.op, log.island, log.principal_id) == ("access-token", "bookkeeping", "stub")
    # metadata only
    assert "ACCESS" not in str(log) and "REFRESH" not in str(log)
