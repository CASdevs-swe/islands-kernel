import threading
import time
import httpx
from tests.served_harness import build_served_bus_stack


def _exchange(identity_url, cred, audience):
    r = httpx.post(f"{identity_url}/auth/exchange",
                   json={"opaque_token": cred, "audience": audience})
    r.raise_for_status()
    return r.json()["access_token"]


def test_concurrent_publish_dispatches_each_event_once():
    stack = build_served_bus_stack(_tmpdir())
    stack.start()
    try:
        jwt = _exchange(stack.identity_url, stack.cred, stack.audience)
        h = {"Authorization": f"Bearer {jwt}"}
        # subscribe to an inprocess handler wired by the harness (key "counter")
        httpx.post(f"{stack.bus_url}/subscriptions", headers=h,
                   json={"type": "bookkeeping.voucher.posted", "consumer": "smartcharge",
                         "target": {"kind": "inprocess", "key": "counter"}, "grant_ref": "g"}).raise_for_status()

        body = {"type": "bookkeeping.voucher.posted", "schema": "voucher/v1",
                "source": "bookkeeping", "trace": {"store": "bk", "ref": "r1"},
                "data": {"voucherId": "V-1"}, "id": "evt_race"}

        results = []
        results_lock = threading.Lock()
        barrier = threading.Barrier(8)

        def publisher():
            barrier.wait()
            r = httpx.post(f"{stack.bus_url}/events", headers=h, json=body)
            with results_lock:
                results.append(r.json())

        threads = [threading.Thread(target=publisher) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        deduped = [r for r in results if r["deduped"]]
        assert len(deduped) == 7                   # exactly one publish was the first
        assert stack.counter["n"] == 1             # handler ran exactly once
    finally:
        stack.stop()


def _tmpdir():
    import tempfile
    import pathlib
    return pathlib.Path(tempfile.mkdtemp())
