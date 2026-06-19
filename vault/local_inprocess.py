"""Build an in-process AccessService over a local-file store with an age KEK.

This is the seam the embedded engines (bookkeeping, research) mount: each engine
process constructs its own AccessService against the same on-disk store dir, and
the file lease in LocalFileStore is the single writer across processes. No HTTP
service and no daemon.
"""
from __future__ import annotations
import os
import subprocess
import time
from pathlib import Path
from typing import Callable, Optional

from vault.crypto import AgeKeyWrapper, AgeRunner, KeyWrapper
from vault.store.local_file import LocalFileStore
from vault.access import AccessService
from vault.config import VaultConfig, _real_http_post
from vault.providers import PROVIDERS
from vault.providers.base import AppCred


def real_age_runner(argv: list[str], stdin: Optional[bytes]) -> bytes:
    return subprocess.run(argv, input=stdin, stdout=subprocess.PIPE, check=True).stdout


def age_recipient_for(key_file: str) -> str:
    out = subprocess.run(["age-keygen", "-y", key_file], stdout=subprocess.PIPE, check=True).stdout
    return out.decode().strip()


def age_wrapper(key_file: str, recipient: Optional[str] = None,
                runner: AgeRunner = real_age_runner) -> AgeKeyWrapper:
    if recipient is None:
        recipient = age_recipient_for(key_file)
    return AgeKeyWrapper(identity=key_file, recipient=recipient, runner=runner)


def build_inprocess_service(store_dir: str, wrapper: KeyWrapper, *,
                            app_creds: Optional[dict[str, AppCred]] = None,
                            now_fn: Callable[[], float] = time.time,
                            http_post: Callable[[str, dict, dict], dict] = _real_http_post,
                            providers: Optional[dict] = None,
                            state_hmac_key: bytes = b"local-inprocess") -> AccessService:
    store = LocalFileStore(Path(store_dir), wrapper)
    cfg = VaultConfig(now_fn=now_fn, http_post=http_post,
                      app_creds=app_creds or {}, state_hmac_key=state_hmac_key)
    return AccessService(store, providers or PROVIDERS, cfg)


def build_from_env(app_creds: Optional[dict[str, AppCred]] = None) -> AccessService:
    """Wire from env: VAULT_STORE_DIR, VAULT_AGE_KEY (identity file),
    optional VAULT_AGE_RECIPIENT (cached public recipient to skip a subprocess)."""
    store_dir = os.environ["VAULT_STORE_DIR"]
    key_file = os.environ["VAULT_AGE_KEY"]
    recipient = os.environ.get("VAULT_AGE_RECIPIENT")
    wrapper = age_wrapper(key_file, recipient=recipient)
    return build_inprocess_service(store_dir, wrapper, app_creds=app_creds)
