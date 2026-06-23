"""Integration coverage for import against the real served ServerStore (sealed sqlite).

The unit tests run on InMemoryStore; this proves the Move-3 path end to end on the
store the box actually runs: import seals a retrievable token (no provider refresh),
and the importing principal (created_by) then holds `manage` via the kernel-auth
owner shim — the prerequisite for issuing the service principal its `use` grant."""
import nacl.utils

from identity.store.memory import InMemoryIdentityStore

from vault.access import AccessService
from vault.config import VaultConfig
from vault.store.server import ServerStore
from vault.crypto import SecretboxKeyWrapper
from vault.model import ConnKey
from vault.providers.base import AppCred
from vault.kernel_auth import make_manage_authorizer

KEY = ConnKey("caput-venti", "fortnox", "559401-5157")
NOW = 1000.0


class StubProvider:
    rotation = "rotating"

    def refresh(self, token, app, http_post, now):
        raise AssertionError("import path must not refresh against the served store")


def _service(tmp_path):
    wrapper = SecretboxKeyWrapper(nacl.utils.random(32))
    store = ServerStore(f"sqlite:///{tmp_path}/vault.sqlite", wrapper)
    cfg = VaultConfig(now_fn=lambda: NOW, http_post=lambda *a: {},
                      app_creds={"fortnox": AppCred("c", "s")}, state_hmac_key=b"k", skew=60)
    return AccessService(store, {"fortnox": StubProvider()}, cfg), store


def test_import_seals_and_reads_back_on_server_store(tmp_path):
    svc, store = _service(tmp_path)
    svc.import_connection(KEY, access_token="ACC", refresh_token="REF",
                          expires_at=99999.0, scope="bookkeeping", principal_id="caput-venti")
    # sealed token round-trips off the encrypted sqlite, no provider refresh
    got = svc.get_access_token(KEY, principal_id="caput-venti", island="cutover")
    assert got["accessToken"] == "ACC"
    # the sealed blob must not contain the plaintext token bytes
    conn = store.get_connection(KEY)
    raw = store._db.execute(
        "SELECT token_blob FROM connections WHERE id=?", (conn.id,)).fetchone()[0]
    assert b"ACC" not in raw and b"REF" not in raw


def test_importing_principal_holds_manage_after_import(tmp_path):
    svc, store = _service(tmp_path)
    svc.import_connection(KEY, access_token="ACC", refresh_token="REF",
                          expires_at=99999.0, scope="bookkeeping", principal_id="caput-venti")
    conn = store.get_connection(KEY)
    manage = make_manage_authorizer(
        now_fn=lambda: NOW, identity_store=InMemoryIdentityStore(), vault_store=store)
    assert manage(conn=conn, principal_id="caput-venti", org=conn.org) is True
    assert manage(conn=conn, principal_id="stranger", org=conn.org) is False
