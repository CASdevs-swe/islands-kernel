import os
import tempfile
import threading

from identity.store.server import ServerIdentityStore
from identity.model import Principal, Grant, GrantTarget


def _store():
    path = os.path.join(tempfile.mkdtemp(), "identity.sqlite")
    return ServerIdentityStore(path)


def test_concurrent_readers_and_writers_never_raise_and_stay_consistent():
    # One shared connection across many threads: writers insert distinct principals
    # while readers hammer get_principal/list_grants. With reads outside the mutex this
    # races ("recursive use of cursors" / torn rows). With the fix it is clean.
    store = _store()
    n = 24
    errors: list[BaseException] = []
    err_lock = threading.Lock()
    barrier = threading.Barrier(n)

    def writer(i: int):
        barrier.wait()
        try:
            for r in range(40):
                pid = f"prn_{i}_{r}"
                store.put_principal(Principal(
                    id=pid, type="service", email=None, display_name=f"d{i}",
                    public_key=None, created_at=float(r)))
                store.add_grant(Grant(
                    id=f"g_{i}_{r}", principal_id=pid,
                    target=GrantTarget(kind="connection", id="conn_1"), access="use",
                    scopes_subset=None, granted_by="prn_owner", granted_at=0.0,
                    revoked_at=None))
        except BaseException as e:  # noqa: BLE001
            with err_lock:
                errors.append(e)

    def reader():
        barrier.wait()
        try:
            for _ in range(200):
                store.get_principal("prn_0_0")
                store.list_grants("prn_0_0")
        except BaseException as e:  # noqa: BLE001
            with err_lock:
                errors.append(e)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(n // 2)]
    threads += [threading.Thread(target=reader) for _ in range(n // 2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"concurrency errors: {errors[:3]}"
    # every writer's last principal is readable -> no lost/torn writes
    for i in range(n // 2):
        assert store.get_principal(f"prn_{i}_39") is not None
        assert len(store.list_grants(f"prn_{i}_39")) == 1
