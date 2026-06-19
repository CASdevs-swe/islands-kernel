import nacl.utils
from vault.store.memory import InMemoryStore
from vault.model import Connection, ConnKey, Token
from vault.providers.fortnox import FortnoxProvider
from vault.providers.base import AppCred
from vault.access import AccessService
from vault.config import VaultConfig


def test_log_is_metadata_only_after_refresh():
    store = InMemoryStore()
    store.put_connection(Connection(
        id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
        scopes=["bookkeeping"], app_cred_ref="fortnox",
        token=Token("OLDACC", "OLDREF", expires_at=100.0, scope="bookkeeping"),  # expired
        rotation="rotating", lease=None, created_by="stub", created_at=0.0, updated_at=0.0))

    def fake_post(url, form, headers):
        return {"access_token": "NEWACC", "refresh_token": "NEWREF", "expires_in": 3600, "scope": "bookkeeping"}

    cfg = VaultConfig(now_fn=lambda: 1000.0, http_post=fake_post,
                      app_creds={"fortnox": AppCred("c", "s")}, state_hmac_key=b"k")
    svc = AccessService(store, {"fortnox": FortnoxProvider()}, cfg)
    out = svc.get_access_token(ConnKey("caput-venti", "fortnox", "559401-5157"), "stub", "bookkeeping")

    assert out["accessToken"] == "NEWACC"
    logs = store.read_log("conn_1")
    assert len(logs) == 1
    blob = str([logs[0].__dict__])
    for forbidden in ("OLDACC", "OLDREF", "NEWACC", "NEWREF"):
        assert forbidden not in blob
