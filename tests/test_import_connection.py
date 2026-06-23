"""Service-level tests for AccessService.import_connection — the no-OAuth path that
seals an existing token into the store without any provider network call."""
from vault.store.memory import InMemoryStore
from vault.access import AccessService
from vault.config import VaultConfig
from vault.model import ConnKey
from vault.providers.base import AppCred


class StubProvider:
    rotation = "rotating"

    def __init__(self):
        self.refresh_calls = 0

    def refresh(self, token, app, http_post, now):
        self.refresh_calls += 1
        raise AssertionError("import_connection must not trigger a provider refresh")


def _svc(now=1000.0):
    store = InMemoryStore()
    provider = StubProvider()
    cfg = VaultConfig(now_fn=lambda: now, http_post=lambda *a: {},
                      app_creds={"fortnox": AppCred("cid", "secret")},
                      state_hmac_key=b"k", skew=60)
    return AccessService(store, {"fortnox": provider}, cfg), store, provider


KEY = ConnKey("caput-venti", "fortnox", "559401-5157")


def test_import_seals_retrievable_connection_no_refresh():
    svc, store, provider = _svc(now=1000.0)
    out = svc.import_connection(KEY, access_token="ACC", refresh_token="REF",
                                expires_at=5000.0, scope="bookkeeping",
                                principal_id="caput-venti")
    assert out["connectionId"]
    # owner (created_by) can read it back; token not expired -> no provider refresh
    got = svc.get_access_token(KEY, principal_id="caput-venti", island="cutover")
    assert got["accessToken"] == "ACC"
    assert got["scope"] == "bookkeeping"
    assert provider.refresh_calls == 0


def test_import_round_trips_token_material():
    svc, store, _ = _svc()
    svc.import_connection(KEY, access_token="ACC", refresh_token="REF",
                          expires_at=5000.0, scope="bookkeeping a b",
                          principal_id="caput-venti")
    conn = store.get_connection(KEY)
    assert conn is not None
    assert conn.token.access_token == "ACC"
    assert conn.token.refresh_token == "REF"
    assert conn.token.expires_at == 5000.0
    assert conn.token.scope == "bookkeeping a b"


def test_import_defaults_rotation_appcred_and_scopes():
    svc, store, _ = _svc()
    svc.import_connection(KEY, access_token="ACC", refresh_token="REF",
                          expires_at=5000.0, scope="a b c",
                          principal_id="caput-venti")
    conn = store.get_connection(KEY)
    assert conn.rotation == "rotating"          # from provider.rotation
    assert conn.app_cred_ref == "fortnox"       # defaults to provider name
    assert conn.scopes == ["a", "b", "c"]       # from scope.split()
    assert conn.created_by == "caput-venti"


def test_import_honours_explicit_overrides():
    svc, store, _ = _svc()
    svc.import_connection(KEY, access_token="ACC", refresh_token="REF",
                          expires_at=5000.0, scope="a b",
                          principal_id="caput-venti", rotation="static",
                          scopes=["x"], app_cred_ref="other")
    conn = store.get_connection(KEY)
    assert conn.rotation == "static"
    assert conn.scopes == ["x"]
    assert conn.app_cred_ref == "other"


def test_reimport_overwrites_with_updated_timestamps():
    svc, store, _ = _svc(now=1000.0)
    svc.import_connection(KEY, access_token="ACC1", refresh_token="REF1",
                          expires_at=5000.0, scope="a", principal_id="caput-venti")
    first = store.get_connection(KEY)
    # second import of the same key overwrites the token material in place
    svc.config.now_fn = lambda: 2000.0
    svc.import_connection(KEY, access_token="ACC2", refresh_token="REF2",
                          expires_at=6000.0, scope="a", principal_id="caput-venti")
    second = store.get_connection(KEY)
    assert second.id == first.id
    assert second.token.access_token == "ACC2"
    assert second.updated_at == 2000.0
