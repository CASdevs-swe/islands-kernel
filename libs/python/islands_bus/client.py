from __future__ import annotations
from typing import Callable, Optional, Protocol


class BusTransport(Protocol):
    def publish(self, body: dict) -> dict: ...
    def subscribe(self, body: dict) -> dict: ...
    def replay(self, event_id: str, source: str) -> dict: ...


class InProcessBusTransport:
    """Embedded posture: call a BusService directly. For tests and same-process islands."""

    def __init__(self, service, *, principal: str, org: str) -> None:
        self._svc = service
        self._principal = principal
        self._org = org

    def publish(self, body: dict) -> dict:
        return self._svc.publish(body, principal=self._principal, org=self._org)

    def subscribe(self, body: dict) -> dict:
        sub = self._svc.subscribe(principal=self._principal, org=self._org, type=body["type"],
                                  consumer=body["consumer"], target=body["target"],
                                  grant_ref=body.get("grant_ref", ""))
        return {"id": sub.id}

    def replay(self, event_id: str, source: str) -> dict:
        return {"replayed": self._svc.replay(event_id, source, org=self._org)}


class HttpBusTransport:
    """Hosted posture: POST over HTTP with a kernel JWT bearer."""

    def __init__(self, base_url: str, *, bearer_provider: Callable[[], str], http=None) -> None:
        self._base = base_url.rstrip("/")
        self._bearer = bearer_provider
        self._http = http

    def _client(self):
        if self._http is not None:
            return self._http
        import httpx
        return httpx

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._bearer()}"}

    def publish(self, body: dict) -> dict:
        r = self._client().post(f"{self._base}/events", json=body, headers=self._headers())
        r.raise_for_status()
        return r.json()

    def subscribe(self, body: dict) -> dict:
        r = self._client().post(f"{self._base}/subscriptions", json=body, headers=self._headers())
        r.raise_for_status()
        return r.json()

    def replay(self, event_id: str, source: str) -> dict:
        r = self._client().post(f"{self._base}/deadletter/{event_id}/replay",
                                params={"source": source}, headers=self._headers())
        r.raise_for_status()
        return r.json()


class BusClient:
    def __init__(self, transport: BusTransport) -> None:
        self._t = transport

    def publish(self, type: str, data: dict, *, source: str, schema: str, trace: dict,
                occurred_at: Optional[str] = None, id: Optional[str] = None) -> dict:
        body = {"type": type, "data": data, "source": source, "schema": schema, "trace": trace}
        if occurred_at is not None:
            body["occurredAt"] = occurred_at
        if id is not None:
            body["id"] = id
        return self._t.publish(body)

    def subscribe(self, type: str, *, consumer: str, target: dict, grant_ref: str) -> dict:
        return self._t.subscribe({"type": type, "consumer": consumer,
                                  "target": target, "grant_ref": grant_ref})

    def replay_dead_letter(self, event_id: str, source: str) -> dict:
        return self._t.replay(event_id, source)
