from __future__ import annotations
import json
import sqlite3
import threading
from typing import Optional

from bus.model import Event, Subscription, Delivery, EventContract
from bus.store.base import LedgerStore, type_matches

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  source TEXT, id TEXT, type TEXT, schema TEXT, org TEXT, principal TEXT,
  occurred_at TEXT, trace_json TEXT, data_json TEXT,
  PRIMARY KEY (source, id));
CREATE TABLE IF NOT EXISTS subscriptions(
  id TEXT PRIMARY KEY, org TEXT, consumer TEXT, type TEXT,
  target_json TEXT, grant_ref TEXT);
CREATE TABLE IF NOT EXISTS deliveries(
  event_id TEXT, source TEXT, subscription_id TEXT, status TEXT, attempts INTEGER,
  last_error TEXT, next_attempt_at REAL,
  PRIMARY KEY (event_id, source, subscription_id));
CREATE TABLE IF NOT EXISTS contracts(
  island TEXT PRIMARY KEY, emits_json TEXT, consumes_json TEXT);
CREATE TABLE IF NOT EXISTS leases(lease_key TEXT PRIMARY KEY, holder TEXT, until REAL);
"""


class ServerLedgerStore(LedgerStore):
    def __init__(self, conn_str: str) -> None:
        path = conn_str.replace("sqlite:///", "") if conn_str.startswith("sqlite:///") else ":memory:"
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(_SCHEMA)
        self._db.commit()
        self._mu = threading.Lock()

    # --- events ---

    def record_event(self, event: Event) -> bool:
        with self._mu, self._db:
            cur = self._db.execute(
                "INSERT OR IGNORE INTO events"
                "(source,id,type,schema,org,principal,occurred_at,trace_json,data_json)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (event.source, event.id, event.type, event.schema, event.org,
                 event.principal, event.occurred_at,
                 json.dumps(event.trace), json.dumps(event.data)))
        return cur.rowcount == 1

    def get_event(self, source: str, event_id: str) -> Optional[Event]:
        with self._mu:
            row = self._db.execute(
                "SELECT source,id,type,schema,org,principal,occurred_at,trace_json,data_json"
                " FROM events WHERE source=? AND id=?",
                (source, event_id)).fetchone()
        if row is None:
            return None
        return Event(id=row[1], type=row[2], schema=row[3], source=row[0],
                     org=row[4], principal=row[5], occurred_at=row[6],
                     trace=json.loads(row[7]), data=json.loads(row[8]))

    # --- subscriptions ---

    def put_subscription(self, sub: Subscription) -> None:
        with self._mu, self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO subscriptions(id,org,consumer,type,target_json,grant_ref)"
                " VALUES(?,?,?,?,?,?)",
                (sub.id, sub.org, sub.consumer, sub.type,
                 json.dumps(sub.target), sub.grant_ref))

    def get_subscription(self, sub_id: str) -> Optional[Subscription]:
        with self._mu:
            row = self._db.execute(
                "SELECT id,org,consumer,type,target_json,grant_ref"
                " FROM subscriptions WHERE id=?", (sub_id,)).fetchone()
        if row is None:
            return None
        return Subscription(id=row[0], org=row[1], consumer=row[2], type=row[3],
                            target=json.loads(row[4]), grant_ref=row[5])

    def delete_subscription(self, sub_id: str) -> None:
        with self._mu, self._db:
            self._db.execute("DELETE FROM subscriptions WHERE id=?", (sub_id,))

    def list_subscriptions(self, org: str) -> list[Subscription]:
        with self._mu:
            rows = self._db.execute(
                "SELECT id,org,consumer,type,target_json,grant_ref"
                " FROM subscriptions WHERE org=?", (org,)).fetchall()
        return [Subscription(id=r[0], org=r[1], consumer=r[2], type=r[3],
                             target=json.loads(r[4]), grant_ref=r[5]) for r in rows]

    def matching_subscriptions(self, org: str, event_type: str) -> list[Subscription]:
        return [s for s in self.list_subscriptions(org) if type_matches(s.type, event_type)]

    # --- deliveries ---

    def put_delivery(self, d: Delivery) -> None:
        with self._mu, self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO deliveries"
                "(event_id,source,subscription_id,status,attempts,last_error,next_attempt_at)"
                " VALUES(?,?,?,?,?,?,?)",
                (d.event_id, d.source, d.subscription_id, d.status, d.attempts,
                 d.last_error, d.next_attempt_at))

    def get_delivery(self, event_id: str, source: str, subscription_id: str) -> Optional[Delivery]:
        with self._mu:
            row = self._db.execute(
                "SELECT event_id,source,subscription_id,status,attempts,last_error,next_attempt_at"
                " FROM deliveries WHERE event_id=? AND source=? AND subscription_id=?",
                (event_id, source, subscription_id)).fetchone()
        if row is None:
            return None
        return Delivery(event_id=row[0], source=row[1], subscription_id=row[2],
                        status=row[3], attempts=row[4], last_error=row[5],
                        next_attempt_at=row[6])

    def list_deliveries_by_status(self, org: str, status: str) -> list[Delivery]:
        with self._mu:
            rows = self._db.execute(
                "SELECT d.event_id, d.source, d.subscription_id, d.status,"
                "       d.attempts, d.last_error, d.next_attempt_at"
                " FROM deliveries d"
                " JOIN events e ON e.source=d.source AND e.id=d.event_id"
                " WHERE e.org=? AND d.status=?",
                (org, status)).fetchall()
        return [Delivery(event_id=r[0], source=r[1], subscription_id=r[2],
                         status=r[3], attempts=r[4], last_error=r[5],
                         next_attempt_at=r[6]) for r in rows]

    # --- contracts ---

    def put_contract(self, c: EventContract) -> None:
        with self._mu, self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO contracts(island,emits_json,consumes_json) VALUES(?,?,?)",
                (c.island, json.dumps(c.emits), json.dumps(c.consumes)))

    def list_contracts(self) -> list[EventContract]:
        with self._mu:
            rows = self._db.execute("SELECT island,emits_json,consumes_json FROM contracts").fetchall()
        return [EventContract(island=r[0], emits=json.loads(r[1]), consumes=json.loads(r[2]))
                for r in rows]

    # --- leases ---

    def acquire_lease(self, key: str, holder: str, until: float, now: float) -> bool:
        with self._mu, self._db:
            cur = self._db.execute(
                "INSERT OR IGNORE INTO leases(lease_key,holder,until) VALUES(?,?,?)",
                (key, holder, until))
            if cur.rowcount == 1:
                return True
            cur = self._db.execute(
                "UPDATE leases SET holder=?, until=? WHERE lease_key=? AND until<=?",
                (holder, until, key, now))
            return cur.rowcount == 1

    def release_lease(self, key: str, holder: str) -> None:
        with self._mu, self._db:
            self._db.execute("DELETE FROM leases WHERE lease_key=? AND holder=?", (key, holder))

    def lease_held(self, key: str, now: float) -> bool:
        with self._mu:
            r = self._db.execute("SELECT until FROM leases WHERE lease_key=?", (key,)).fetchone()
        return r is not None and r[0] > now
