from __future__ import annotations
from typing import Callable
from vault.model import Token, ConnKey, new_id
from vault.store.base import Store
from vault.providers.base import Provider, AppCred, HttpPost


def refresh_if_needed(
    store: Store,
    key: ConnKey,
    provider: Provider,
    app: AppCred,
    http_post: HttpPost,
    now_fn: Callable[[], float],
    skew: int = 60,
    lease_ttl: float = 30,
    wait_timeout: float = 20.0,
    sleep: Callable[[float], None] = None,
) -> Token:
    if sleep is None:
        import time as _t
        sleep = _t.sleep

    conn = store.get_connection(key)
    if conn is None or conn.token is None:
        raise KeyError(f"no connection for {key.as_str()}")

    now = now_fn()
    if not conn.token.is_expired(skew=skew, now=now):
        return conn.token

    holder = new_id("lease", key.as_str() + str(now))
    waited = 0.0
    poll = 0.05

    while True:
        now = now_fn()
        if store.acquire_lease(key, holder, until=now + lease_ttl, now=now):
            try:
                conn = store.get_connection(key)         # double-checked locking
                now = now_fn()
                if not conn.token.is_expired(skew=skew, now=now):
                    return conn.token                    # another writer already refreshed
                new_token = provider.refresh(conn.token, app, http_post, now)
                store.write_token(key, new_token, now)
                return new_token
            finally:
                store.release_lease(key, holder)

        # someone else holds the lease — wait for them to publish a fresh token
        while waited < wait_timeout:
            sleep(poll)
            waited += poll
            conn = store.get_connection(key)
            now = now_fn()
            if conn.token is not None and not conn.token.is_expired(skew=skew, now=now):
                return conn.token
            if not store.lease_held(key, now):
                break        # holder released without us seeing fresh token -> retry acquire

        if waited >= wait_timeout:
            raise TimeoutError(f"refresh lease wait timed out for {key.as_str()}")
