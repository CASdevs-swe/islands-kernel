from __future__ import annotations
import time
from typing import Callable, Optional, Protocol


class Transport(Protocol):
    def access(self, org: str, provider: str, account: str, island: str) -> dict: ...


class InProcessTransport:
    def __init__(self, service, principal: str = "stub"):
        self._svc = service
        self._principal = principal

    def access(self, org, provider, account, island):
        from vault.model import ConnKey
        return self._svc.get_access_token(ConnKey(org, provider, account), self._principal, island)


class HttpTransport:
    def __init__(self, base_url: str, principal: str = "stub", http=None):
        import httpx
        self._http = http or httpx
        self._base = base_url.rstrip("/")
        self._principal = principal

    def access(self, org, provider, account, island):
        from urllib.parse import quote
        cid = quote(f"{org}/{provider}/{account}", safe="")
        r = self._http.post(f"{self._base}/connections/{cid}/access-token",
                            headers={"X-Principal": self._principal, "X-Island": island})
        r.raise_for_status()
        return r.json()


class KernelAuthTransport:
    """Obtains a short-lived kernel JWT from the identity service's exchange and
    presents it as a Bearer token to the vault.

    The island holds an opaque service credential; this transport trades it for a
    5-minute JWT (cached until within `skew` of expiry) and never sees the kernel
    signing key. This is how a background island agent (e.g. bookkeeping) calls the
    vault under a real, audited identity instead of a header stub.
    """

    def __init__(self, *, vault_base_url: str, identity_base_url: str,
                 service_credential: str, audience: str, http=None,
                 now_fn: Callable[[], float] = time.time, skew: int = 30):
        import httpx
        self._http = http or httpx
        self._vault = vault_base_url.rstrip("/")
        self._identity = identity_base_url.rstrip("/")
        self._cred = service_credential
        self._aud = audience
        self._now = now_fn
        self._skew = skew
        self._jwt: Optional[str] = None
        self._jwt_exp = 0.0

    def _bearer(self) -> str:
        now = self._now()
        if self._jwt is not None and now < self._jwt_exp - self._skew:
            return self._jwt
        r = self._http.post(f"{self._identity}/auth/exchange",
                            json={"opaque_token": self._cred, "audience": self._aud})
        r.raise_for_status()
        data = r.json()
        self._jwt = data["access_token"]
        self._jwt_exp = now + data["expires_in"]
        return self._jwt

    def access(self, org, provider, account, island):
        from urllib.parse import quote
        cid = quote(f"{org}/{provider}/{account}", safe="")
        r = self._http.post(f"{self._vault}/connections/{cid}/access-token",
                            headers={"Authorization": f"Bearer {self._bearer()}"})
        r.raise_for_status()
        return r.json()


class VaultClient:
    def __init__(self, transport: Transport):
        self._t = transport

    def get_access(self, org, provider, account, island="unknown") -> dict:
        return self._t.access(org, provider, account, island)

    def get_access_token(self, org, provider, account, island="unknown") -> str:
        return self.get_access(org, provider, account, island)["accessToken"]
