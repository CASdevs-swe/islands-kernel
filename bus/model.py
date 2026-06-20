from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

from identity.tokens import generate_raw_token


class EnvelopeError(Exception):
    """Raised when an event envelope violates the canonical contract."""


def new_event_id() -> str:
    return generate_raw_token("evt")


@dataclass
class Event:
    id: str
    type: str
    schema: str
    source: str
    org: str
    principal: str
    occurred_at: str   # RFC3339, producer-set
    trace: dict        # { store, ref } — reference, never the fat payload
    data: dict         # small, validated against `schema`


@dataclass
class Subscription:
    id: str
    org: str
    consumer: str
    type: str          # exact event type or a prefix glob, e.g. "bookkeeping.*"
    target: dict       # {"kind":"inprocess","key":...} or {"kind":"http","url":...,"audience":...}
    grant_ref: str


@dataclass
class Delivery:
    event_id: str
    source: str
    subscription_id: str
    status: str        # "pending" | "delivered" | "dead"
    attempts: int
    last_error: Optional[str]       # error CLASS only, never a payload/message body
    next_attempt_at: Optional[float]


@dataclass
class EventContract:
    island: str
    emits: list[str]
    consumes: list[str]
