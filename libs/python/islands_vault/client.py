from __future__ import annotations
from typing import Protocol


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


class VaultClient:
    def __init__(self, transport: Transport):
        self._t = transport

    def get_access(self, org, provider, account, island="unknown") -> dict:
        return self._t.access(org, provider, account, island)

    def get_access_token(self, org, provider, account, island="unknown") -> str:
        return self.get_access(org, provider, account, island)["accessToken"]
