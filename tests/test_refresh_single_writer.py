import threading
import nacl.utils
from pathlib import Path
import pytest
from vault.crypto import SecretboxKeyWrapper
from vault.model import Connection, ConnKey, Token
from vault.store.local_file import LocalFileStore
from vault.store.server import ServerStore
from vault.providers.base import AppCred
from vault.providers.fortnox import FortnoxProvider
from vault.refresh import refresh_if_needed


class CountingProvider(FortnoxProvider):
    def __init__(self):
        self.calls = 0
        self._lock = threading.Lock()

    def refresh(self, token, app, http_post, now):
        with self._lock:
            self.calls += 1
            n = self.calls
        # simulate a slow rotating refresh; new refresh token each call
        return Token(f"acc{n}", f"ref{n}", now + 3600, "bookkeeping")


def _expired_conn():
    return Connection(
        id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
        scopes=["bookkeeping"], app_cred_ref="fortnox",
        token=Token("old_acc", "old_ref", expires_at=100.0, scope="bookkeeping"),
        rotation="rotating", lease=None, created_by="stub", created_at=0.0, updated_at=0.0,
    )


@pytest.fixture(params=["local", "server"])
def store(request, tmp_path):
    w = SecretboxKeyWrapper(nacl.utils.random(32))
    if request.param == "local":
        return LocalFileStore(root=Path(tmp_path), wrapper=w)
    return ServerStore(conn_str=f"sqlite:///{tmp_path}/v.sqlite", wrapper=w)


def test_concurrent_refresh_runs_exactly_once(store):
    store.put_connection(_expired_conn())
    key = ConnKey("caput-venti", "fortnox", "559401-5157")
    provider = CountingProvider()
    app = AppCred("cid", "secret")
    NOW = 1000.0   # well past expires_at=100 -> refresh required

    results: list[Token] = []
    lock = threading.Lock()
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()   # maximize contention
        tok = refresh_if_needed(
            store, key, provider, app, http_post=lambda *a: {},
            now_fn=lambda: NOW, skew=60, lease_ttl=30,
            wait_timeout=20.0, sleep=lambda s: None,
        )
        with lock:
            results.append(tok)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert provider.calls == 1                      # THE property: one writer, one refresh
    assert len(results) == 8
    assert all(r.refresh_token == "ref1" for r in results)   # everyone sees the single rotated token


def test_concurrent_refresh_runs_exactly_once_under_stress(store):
    # Tight create/acquire contention is what flakes the file lease: many rounds,
    # a fresh expired connection each round, exactly one refresh required every time.
    key = ConnKey("caput-venti", "fortnox", "559401-5157")
    app = AppCred("cid", "secret")
    NOW = 1000.0
    n_workers = 16

    for round_no in range(60):
        store.delete_connection(key)
        store.put_connection(_expired_conn())
        provider = CountingProvider()
        barrier = threading.Barrier(n_workers)

        def worker():
            barrier.wait()
            refresh_if_needed(
                store, key, provider, app, http_post=lambda *a: {},
                now_fn=lambda: NOW, skew=60, lease_ttl=30,
                wait_timeout=20.0, sleep=lambda s: None,
            )

        threads = [threading.Thread(target=worker) for _ in range(n_workers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert provider.calls == 1, f"round {round_no}: {provider.calls} refreshes"
        assert store.get_connection(key).token.refresh_token == "ref1"


def test_fresh_token_skips_refresh(store):
    c = _expired_conn()
    c.token = Token("a", "r", expires_at=99999.0, scope="s")
    store.put_connection(c)
    provider = CountingProvider()
    tok = refresh_if_needed(
        store, c.key, provider, AppCred("c", "s"), http_post=lambda *a: {},
        now_fn=lambda: 1000.0, skew=60, lease_ttl=30, wait_timeout=5.0,
        sleep=lambda s: None,
    )
    assert provider.calls == 0 and tok.access_token == "a"
