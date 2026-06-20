from __future__ import annotations
from typing import Callable

from identity.authorize import authorize
from identity.model import GrantTarget
from bus.model import Event, Subscription, Delivery, EventContract, EnvelopeError
from bus.envelope import stamp_envelope, validate_envelope
from bus.schema_registry import SchemaRegistry
from bus.store.base import LedgerStore
from bus.dispatch import Dispatcher
from identity.tokens import generate_raw_token


class AuthzDenied(Exception):
    pass


class BusService:
    def __init__(self, store: LedgerStore, schema_registry: SchemaRegistry,
                 dispatcher: Dispatcher, *, now_fn: Callable[[], float],
                 now_iso_fn: Callable[[], str], grants_for: Callable[[str], list]) -> None:
        self._store = store
        self._schemas = schema_registry
        self._dispatcher = dispatcher
        self._now = now_fn
        self._now_iso = now_iso_fn
        self._grants_for = grants_for

    def _require(self, principal: str, org: str, event_type: str) -> None:
        ok = authorize(grants=self._grants_for(principal),
                       target=GrantTarget("event-type", event_type),
                       access="use", now=self._now(), request_org=org)
        if not ok:
            raise AuthzDenied(f"{principal} lacks use on event-type {event_type}")

    def publish(self, body: dict, *, principal: str, org: str) -> dict:
        event = stamp_envelope(body, principal=principal, org=org, now_iso=self._now_iso())
        self._require(principal, org, event.type)
        validate_envelope(event)
        self._schemas.validate_data(event.schema, event.data)
        is_new = self._store.record_event(event)
        if is_new:
            self._dispatcher.dispatch(event)
        return {"id": event.id, "deduped": not is_new}

    def subscribe(self, *, principal: str, org: str, type: str, consumer: str,
                  target: dict, grant_ref: str) -> Subscription:
        self._require(principal, org, type)
        sub = Subscription(id=generate_raw_token("sub"), org=org, consumer=consumer,
                           type=type, target=target, grant_ref=grant_ref)
        self._store.put_subscription(sub)
        return sub

    def unsubscribe(self, sub_id: str) -> None:
        self._store.delete_subscription(sub_id)

    def list_subscriptions(self, org: str) -> list:
        return self._store.list_subscriptions(org)

    def dead_letters(self, org: str) -> list:
        return self._store.list_deliveries_by_status(org, "dead")

    def replay(self, event_id: str, source: str, *, org: str) -> int:
        n = 0
        for d in self._store.list_deliveries_by_status(org, "dead"):
            if d.event_id == event_id and d.source == source:
                self._store.put_delivery(Delivery(d.event_id, d.source, d.subscription_id,
                                                  "pending", d.attempts, d.last_error, None))
                row = self._store.get_delivery(d.event_id, d.source, d.subscription_id)
                self._dispatcher.attempt_pending(row)
                n += 1
        return n

    def contracts(self) -> list:
        return self._store.list_contracts()

    def declare_contract(self, c: EventContract) -> None:
        self._store.put_contract(c)
