from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Optional

from bus.model import Event, Subscription, Delivery
from bus.store.base import LedgerStore
from identity.tokens import generate_raw_token


class InProcessDelivery:
    """Embedded-posture delivery: invoke a locally registered handler."""

    def __init__(self) -> None:
        self._handlers: dict[str, Callable[[Event], None]] = {}

    def register(self, key: str, handler: Callable[[Event], None]) -> None:
        self._handlers[key] = handler

    def deliver(self, sub: Subscription, event: Event) -> None:
        key = sub.target.get("key")
        handler = self._handlers.get(key)
        if handler is None:
            raise LookupError("no handler registered")
        handler(event)


@dataclass
class BackoffPolicy:
    max_attempts: int = 5
    base: float = 1.0
    cap: float = 60.0

    def next_at(self, attempts: int, now: float) -> float:
        delay = min(self.cap, self.base * (2 ** (attempts - 1)))
        return now + delay


class Dispatcher:
    def __init__(self, store: LedgerStore, delivery, *, now_fn: Callable[[], float],
                 backoff: BackoffPolicy = BackoffPolicy(), lease_ttl: float = 30.0) -> None:
        self._store = store
        self._delivery = delivery
        self._now = now_fn
        self._backoff = backoff
        self._lease_ttl = lease_ttl

    def dispatch(self, event: Event) -> None:
        for sub in self._store.matching_subscriptions(event.org, event.type):
            self._attempt(event, sub)

    def attempt_pending(self, delivery: Delivery) -> None:
        event = self._store.get_event(delivery.source, delivery.event_id)
        sub = self._store.get_subscription(delivery.subscription_id)
        if event is None or sub is None:
            return
        self._attempt(event, sub)

    def _attempt(self, event: Event, sub: Subscription) -> None:
        # fast path: skip before acquiring lease
        existing = self._store.get_delivery(event.id, event.source, sub.id)
        if existing is not None and existing.status == "delivered":
            return

        now = self._now()
        holder = generate_raw_token("disp")
        lease_key = f"dispatch:{event.source}:{event.id}:{sub.id}"
        if not self._store.acquire_lease(lease_key, holder, until=now + self._lease_ttl, now=now):
            return  # another dispatcher owns this delivery
        try:
            # double-checked locking: re-read under the lease
            existing = self._store.get_delivery(event.id, event.source, sub.id)
            if existing is not None and existing.status == "delivered":
                return

            attempts = (existing.attempts if existing else 0) + 1
            try:
                self._delivery.deliver(sub, event)
            except Exception as exc:
                err = type(exc).__name__
                if attempts >= self._backoff.max_attempts:
                    status, next_at = "dead", None
                else:
                    status, next_at = "pending", self._backoff.next_at(attempts, now)
                self._store.put_delivery(Delivery(
                    event.id, event.source, sub.id, status, attempts, err, next_at,
                ))
                return
            self._store.put_delivery(Delivery(
                event.id, event.source, sub.id, "delivered", attempts, None, None,
            ))
        finally:
            self._store.release_lease(lease_key, holder)
