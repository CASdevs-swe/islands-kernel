import multiprocessing as mp

import httpx

from tests.served_harness import build_served_stack, ACCESS_PATH


def _client_fetch(args):
    barrier, vault_url, bearer = args
    # All workers rendezvous here so every HTTP POST arrives concurrently,
    # making the single-writer lease a structural requirement rather than a
    # timing accident. BrokenBarrierError propagates as a real failure.
    barrier.wait(timeout=30)
    r = httpx.post(f"{vault_url}{ACCESS_PATH}",
                   headers={"Authorization": f"Bearer {bearer}"}, timeout=15)
    r.raise_for_status()
    return r.json()["accessToken"]


def test_concurrent_processes_trigger_exactly_one_refresh(tmp_path):
    stack = build_served_stack(tmp_path, expired=True)
    stack.start()
    ctx = mp.get_context("spawn")
    manager = ctx.Manager()
    try:
        # one exchanged JWT shared across all client processes
        jwt = httpx.post(f"{stack.identity_url}/auth/exchange",
                         json={"opaque_token": stack.cred, "audience": stack.audience},
                         timeout=10).json()["access_token"]
        n = 8
        barrier = manager.Barrier(n)
        with ctx.Pool(n) as pool:
            tokens = pool.map(_client_fetch, [(barrier, stack.vault_url, jwt)] * n)

        # exactly one refresh happened in the single served writer
        count = httpx.get(f"{stack.vault_url}/_test/refresh-count", timeout=10).json()["calls"]
        assert count == 1, f"expected one refresh, got {count}"
        # every caller saw the same single rotated token
        assert len(set(tokens)) == 1, tokens
        assert tokens[0] == "acc1"
    finally:
        manager.shutdown()
        stack.stop()
