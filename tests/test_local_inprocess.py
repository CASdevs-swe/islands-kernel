import nacl.utils
from pathlib import Path
from vault.crypto import SecretboxKeyWrapper
from vault.model import Connection, ConnKey, Token
from vault.providers.base import AppCred
from vault.providers.fortnox import FortnoxProvider
from vault.local_inprocess import build_inprocess_service, age_wrapper


def _seed(store):
    store.put_connection(Connection(
        id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
        scopes=["bookkeeping"], app_cred_ref="fortnox",
        token=Token("ACCESS", "REFRESH", 99999.0, "bookkeeping"),
        rotation="rotating", lease=None, created_by="caput-venti", created_at=0.0, updated_at=0.0))


def test_build_inprocess_service_serves_token_from_local_store(tmp_path):
    wrapper = SecretboxKeyWrapper(nacl.utils.random(32))   # fixture KEK, not age
    svc = build_inprocess_service(
        store_dir=str(tmp_path / "vs"), wrapper=wrapper,
        app_creds={"fortnox": AppCred("c", "s")}, now_fn=lambda: 1000.0,
        http_post=lambda *a: {}, providers={"fortnox": FortnoxProvider()})
    _seed(svc.store)
    out = svc.get_access_token(ConnKey("caput-venti", "fortnox", "559401-5157"),
                               "caput-venti", "bookkeeping")
    assert out["accessToken"] == "ACCESS" and "refresh" not in str(out).lower()


def test_two_services_share_one_store_single_writer(tmp_path):
    # Two in-process services (mimicking two engine processes) over the same store dir.
    wrapper = SecretboxKeyWrapper(nacl.utils.random(32))
    store_dir = str(tmp_path / "shared")
    a = build_inprocess_service(store_dir=store_dir, wrapper=wrapper,
                                app_creds={"fortnox": AppCred("c", "s")},
                                now_fn=lambda: 1000.0, http_post=lambda *a: {},
                                providers={"fortnox": FortnoxProvider()})
    b = build_inprocess_service(store_dir=store_dir, wrapper=wrapper,
                                app_creds={"fortnox": AppCred("c", "s")},
                                now_fn=lambda: 1000.0, http_post=lambda *a: {},
                                providers={"fortnox": FortnoxProvider()})
    _seed(a.store)
    k = ConnKey("caput-venti", "fortnox", "559401-5157")
    assert a.get_access_token(k, "caput-venti", "bookkeeping")["accessToken"] == "ACCESS"
    assert b.get_access_token(k, "caput-venti", "research")["accessToken"] == "ACCESS"


def test_age_wrapper_argv_wiring_with_fake_runner():
    calls = []

    def fake(argv, stdin):
        calls.append(argv)
        if "-r" in argv:
            return b"WRAP[" + (stdin or b"") + b"]"
        return (stdin or b"")[5:-1]

    w = age_wrapper("/path/to/age.key", recipient="age1xxx", runner=fake)
    dek = b"k" * 32
    assert w.unwrap(w.wrap(dek)) == dek
    assert any("-r" in c and "age1xxx" in c for c in calls)
