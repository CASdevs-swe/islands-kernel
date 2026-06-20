from __future__ import annotations
import threading
from typing import Optional

from bus.model import Event, Subscription, Delivery, EventContract
from bus.store.base import LedgerStore, type_matches


class InMemoryLedgerStore(LedgerStore):
    def __init__(self) -> None:
        self._mu = threading.Lock()
        self._events: dict[tuple[str, str], Event] = {}          # (source, id)
        self._subs: dict[str, Subscription] = {}
        self._deliveries: dict[tuple[str, str, str], Delivery] = {}  # (event_id, source, sub_id)
        self._contracts: dict[str, EventContract] = {}
        self._leases: dict[str, tuple[str, float]] = {}          # key -> (holder, until)

    def record_event(self, event):
        with self._mu:
            k = (event.source, event.id)
            if k in self._events:
                return False
            self._events[k] = event
            return True

    def get_event(self, source, event_id):
        return self._events.get((source, event_id))

    def put_subscription(self, sub):
        with self._mu:
            self._subs[sub.id] = sub

    def get_subscription(self, sub_id):
        return self._subs.get(sub_id)

    def delete_subscription(self, sub_id):
        with self._mu:
            self._subs.pop(sub_id, None)

    def list_subscriptions(self, org):
        return [s for s in self._subs.values() if s.org == org]

    def matching_subscriptions(self, org, event_type):
        return [s for s in self._subs.values()
                if s.org == org and type_matches(s.type, event_type)]

    def put_delivery(self, d):
        with self._mu:
            self._deliveries[(d.event_id, d.source, d.subscription_id)] = d

    def get_delivery(self, event_id, source, subscription_id):
        return self._deliveries.get((event_id, source, subscription_id))

    def list_deliveries_by_status(self, org, status):
        out = []
        for d in self._deliveries.values():
            ev = self._events.get((d.source, d.event_id))
            if ev is not None and ev.org == org and d.status == status:
                out.append(d)
        return out

    def put_contract(self, c):
        with self._mu:
            self._contracts[c.island] = c

    def list_contracts(self):
        return list(self._contracts.values())

    def acquire_lease(self, key, holder, until, now):
        with self._mu:
            cur = self._leases.get(key)
            if cur is None or cur[1] <= now:
                self._leases[key] = (holder, until)
                return True
            return False

    def release_lease(self, key, holder):
        with self._mu:
            cur = self._leases.get(key)
            if cur is not None and cur[0] == holder:
                del self._leases[key]

    def lease_held(self, key, now):
        cur = self._leases.get(key)
        return cur is not None and cur[1] > now
