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
        if provider not in self.app_creds:
            raise KeyError(f"no app credential configured for provider {provider}")
        return self.app_creds[provider]
