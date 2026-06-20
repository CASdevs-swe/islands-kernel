from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Optional

from bus.model import Event, Subscription, Delivery, EventContract


class LedgerStore(ABC):
    # --- events / idempotency ---
    @abstractmethod
    def record_event(self, event: Event) -> bool: ...
    @abstractmethod
    def get_event(self, source: str, event_id: str) -> Optional[Event]: ...

    # --- subscriptions ---
    @abstractmethod
    def put_subscription(self, sub: Subscription) -> None: ...
    @abstractmethod
    def get_subscription(self, sub_id: str) -> Optional[Subscription]: ...
    @abstractmethod
    def delete_subscription(self, sub_id: str) -> None: ...
    @abstractmethod
    def list_subscriptions(self, org: str) -> list[Subscription]: ...
    @abstractmethod
    def matching_subscriptions(self, org: str, event_type: str) -> list[Subscription]: ...

    # --- deliveries (metadata only) ---
    @abstractmethod
    def put_delivery(self, d: Delivery) -> None: ...
    @abstractmethod
    def get_delivery(self, event_id: str, source: str, subscription_id: str) -> Optional[Delivery]: ...
    @abstractmethod
    def list_deliveries_by_status(self, org: str, status: str) -> list[Delivery]: ...

    # --- event-contract registry ---
    @abstractmethod
    def put_contract(self, c: EventContract) -> None: ...
    @abstractmethod
    def list_contracts(self) -> list[EventContract]: ...

    # --- single-writer lease (same semantics as vault.store.base.Store) ---
    @abstractmethod
    def acquire_lease(self, key: str, holder: str, until: float, now: float) -> bool: ...
    @abstractmethod
    def release_lease(self, key: str, holder: str) -> None: ...
    @abstractmethod
    def lease_held(self, key: str, now: float) -> bool: ...


def type_matches(sub_type: str, event_type: str) -> bool:
    """Exact match, or a trailing `.*` prefix glob (e.g. 'a.b.*' matches 'a.b.c')."""
    if sub_type == event_type:
        return True
    if sub_type.endswith(".*"):
        return event_type.startswith(sub_type[:-1])  # keep the trailing dot
    return False
