import nacl.utils
from vault.store.memory import InMemoryStore
from vault.model import Connection, Token
from vault.providers.fortnox import FortnoxProvider
from vault.providers.base import AppCred
from vault.access import AccessService
from vault.config import VaultConfig
import sys, pathlib
sys.path.insert(0, str(pathlib.Path("libs/python")))
from islands_vault import get_access_token
from islands_vault.client import InProcessTransport, VaultClient


def _service():
    store = InMemoryStore()
    store.put_connection(Connection(
        id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
        scopes=["bookkeeping"], app_cred_ref="fortnox", token=Token("ACCESS", "REFRESH", 99999.0, "bookkeeping"),
        rotation="rotating", lease=None, created_by="owner", created_at=0.0, updated_at=0.0))
    cfg = VaultConfig(now_fn=lambda: 1000.0, http_post=lambda *a: {},
                      app_creds={"fortnox": AppCred("c", "s")}, state_hmac_key=b"k")
    return AccessService(store, {"fortnox": FortnoxProvider()}, cfg)


def test_inprocess_lib_returns_access_token_string():
    svc = _service()
    client = VaultClient(InProcessTransport(svc, principal="owner"))
    tok = client.get_access_token("caput-venti", "fortnox", "559401-5157", island="bookkeeping")
    assert tok == "ACCESS"


def test_module_helper_inprocess():
    svc = _service()
    tok = get_access_token("caput-venti", "fortnox", "559401-5157",
                           service=svc, principal="owner", island="bookkeeping")
    assert tok == "ACCESS"
