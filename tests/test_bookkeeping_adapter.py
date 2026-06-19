import sys, pathlib
sys.path.insert(0, str(pathlib.Path("libs/python")))
from islands_vault import get_access_token
from vault.store.memory import InMemoryStore
from vault.model import Connection, Token
from vault.providers.fortnox import FortnoxProvider
from vault.providers.base import AppCred
from vault.access import AccessService
from vault.config import VaultConfig


def test_bookkeeping_would_get_token_from_vault():
    store = InMemoryStore()
    store.put_connection(Connection(
        id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
        scopes=["bookkeeping"], app_cred_ref="fortnox", token=Token("LIVE_LIKE_ACCESS", "R", 99999.0, "bookkeeping"),
        rotation="rotating", lease=None, created_by="caput-venti", created_at=0.0, updated_at=0.0))
    svc = AccessService(store, {"fortnox": FortnoxProvider()},
                        VaultConfig(now_fn=lambda: 1000.0, http_post=lambda *a: {},
                                    app_creds={"fortnox": AppCred("c", "s")}, state_hmac_key=b"k"))
    # this is exactly what the bookkeeping adapter will call:
    tok = get_access_token("caput-venti", "fortnox", "559401-5157",
                           service=svc, principal="caput-venti", island="bookkeeping")
    assert tok == "LIVE_LIKE_ACCESS"
