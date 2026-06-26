from __future__ import annotations
import os
import time
from dataclasses import dataclass, field
from typing import Callable
import httpx
from vault.providers.base import AppCred


def _real_http_post(url: str, form: dict, headers: dict) -> dict:
    r = httpx.post(url, data=form, headers=headers, timeout=30)
    r.raise_for_status()
    return r.json()


def _env_app_creds() -> dict[str, AppCred]:
    creds = {}
    if os.environ.get("FORTNOX_CLIENT_ID") and os.environ.get("FORTNOX_CLIENT_SECRET"):
        creds["fortnox"] = AppCred(
            client_id=os.environ["FORTNOX_CLIENT_ID"],
            client_secret=os.environ["FORTNOX_CLIENT_SECRET"],
            redirect_uri=os.environ.get("FORTNOX_REDIRECT_URI", ""),
            scopes=os.environ.get("FORTNOX_SCOPES", "").split())
    if os.environ.get("GOOGLE_CLIENT_ID") and os.environ.get("GOOGLE_CLIENT_SECRET"):
        creds["gmail"] = AppCred(
            client_id=os.environ["GOOGLE_CLIENT_ID"],
            client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
            redirect_uri=os.environ.get("GOOGLE_REDIRECT_URI", ""),
            scopes=os.environ.get("GOOGLE_SCOPES", "").split())
    return creds


@dataclass
class VaultConfig:
    now_fn: Callable[[], float] = time.time
    http_post: Callable[[str, dict, dict], dict] = _real_http_post
    app_creds: dict[str, AppCred] = field(default_factory=_env_app_creds)
    state_hmac_key: bytes = field(
        default_factory=lambda: os.environ.get("VAULT_STATE_HMAC_KEY", "dev").encode())
    skew: int = 60

    def app_cred_for(self, provider: str, ref: str) -> AppCred:
        # Honor the per-connection app-cred ref (falling back to the provider
        # default) so a connection refreshes with the app that minted it.
        cred = self.app_creds.get(ref) or self.app_creds.get(provider)
        if cred is None:
            raise KeyError(
                f"no app credential configured for provider {provider} (ref {ref})")
        return cred
