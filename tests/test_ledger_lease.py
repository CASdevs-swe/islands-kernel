# tests/test_ledger_lease.py
import threading
import pytest
from bus.store.memory import InMemoryLedgerStore
from bus.store.server import ServerLedgerStore


@pytest.fixture(params=["memory", "server"])
def store(request, tmp_path):
    if request.param == "memory":
        return InMemoryLedgerStore()
    return ServerLedgerStore(f"sqlite:///{tmp_path}/ledger.sqlite")


def test_concurrent_acquire_grants_exactly_one(store):
    winners = []
    barrier = threading.Barrier(16)

    def worker(i):
        barrier.wait()
        if store.acquire_lease("dispatch:evt_1", f"h{i}", until=1e12, now=0.0):
            winners.append(i)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(winners) == 1
