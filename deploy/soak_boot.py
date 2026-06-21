"""Custom soak boot: bus + capture-bridge co-hosted with in-process delivery.

Promotes the connector_dryrun wiring to a long-lived hosted entrypoint. The Node
bot publishes over loopback HTTP to the JWT-authed POST /events (mounted via
build_bus_app); the bus stamps principal/org from the verified JWT; an
inbound.message.* subscription delivers IN-PROCESS to the capture-bridge handler,
which routes observe-only into a throwaway observation vault and appends a record
to a soak log. Additive: writes nowhere real. Ephemeral transport (InMemory
ledger, re-subscribed each boot); the durable record is the observation vault.
"""
from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from identity.deps import make_require_principal
from identity.store.server import ServerIdentityStore
from identity.authorize import collect_grants
from identity.tokens import generate_raw_token
from bus.app import build_bus_app
from bus.schema_registry import SchemaRegistry
from bus.service import BusService
from bus.store.memory import InMemoryLedgerStore
from bus.dispatch import Dispatcher, InProcessDelivery, HttpPushDelivery, RoutingDelivery
from bus.model import Subscription
from vault.kernel_auth import cached_jwks_provider

from capture_bridge.schema import register_inbound_schema
from capture_bridge.principal_map import PrincipalMap
from capture_bridge.bridge import make_handler, BridgeDeps

_SUBSCRIPTION_KEY = "capture_bridge"
_SAMPLE_VAULT = Path(__file__).resolve().parents[1] / "tests" / "capture_bridge" / "fixtures" / "sample-vault"


@dataclass
class SoakConfig:
    issuer: str
    audience: str
    observation_vault: str
    real_vault: str | None
    soak_log: str
    route_mjs: str
    claude_bin: str
    connector_principal: str
    org: str
    principal_map_entries: list
    allowed_types: list
    classify_type: str | None = None  # None = real Claude CLI; a string = deterministic stub (tests)
    node_bin: str = "node"


def assert_observation_isolated(observation_vault: str, real_vault: str | None) -> None:
    """Refuse to run if the observation vault could be a real vault root."""
    obs = Path(observation_vault).resolve()
    if real_vault is None:
        return
    real = Path(real_vault).resolve()
    if obs == real or obs in real.parents or real in obs.parents:
        raise RuntimeError(
            f"observation vault {obs} overlaps the real vault {real}; refusing to run the soak")


def _seed_observation_vault(path: str) -> None:
    vault = Path(path)
    if not vault.exists():
        if not _SAMPLE_VAULT.exists():
            raise RuntimeError(f"soak sample vault not found at {_SAMPLE_VAULT}")
        shutil.copytree(_SAMPLE_VAULT, vault)
    (vault / ".soak-observation").write_text("soak observation vault — not a real surface\n")


def _observation_handler(bridge_handler, soak_log: str):
    def handler(event) -> None:
        result = bridge_handler(event)
        record = {
            "eventId": event.id, "principal": event.principal, "org": event.org,
            "type": result.get("type"), "skipped": result.get("skipped"),
            "reason": result.get("reason"), "plan": result.get("plan"),
        }
        with open(soak_log, "a") as f:
            f.write(json.dumps(record) + "\n")
    return handler


def build_soak_app(cfg: SoakConfig, *, identity_db: str, jwks_url: str):
    assert_observation_isolated(cfg.observation_vault, cfg.real_vault)
    _seed_observation_vault(cfg.observation_vault)

    store = InMemoryLedgerStore()
    reg = SchemaRegistry()
    register_inbound_schema(reg)
    in_delivery = InProcessDelivery()
    dispatcher = Dispatcher(store, RoutingDelivery(in_delivery, HttpPushDelivery()), now_fn=time.time)
    ident = ServerIdentityStore(identity_db)
    service = BusService(
        store, reg, dispatcher,
        now_fn=time.time,
        now_iso_fn=lambda: datetime.now(timezone.utc).isoformat(),
        grants_for=lambda pid: collect_grants(principal_id=pid, identity_store=ident),
    )

    deps = BridgeDeps(
        principal_map=PrincipalMap(cfg.principal_map_entries),
        allowed_types=cfg.allowed_types,
        claude_bin=cfg.claude_bin,
        route_mjs=cfg.route_mjs,
        vault_root=cfg.observation_vault,
        classify_runner=(lambda b, p: cfg.classify_type) if cfg.classify_type else None,
        node_bin=cfg.node_bin,
    )
    in_delivery.register(_SUBSCRIPTION_KEY, _observation_handler(make_handler(deps), cfg.soak_log))
    # Wire the in-process subscription directly on the store — this is an internal
    # self-owned subscription, not an external caller; bypassing the auth check is correct.
    sub = Subscription(
        id=generate_raw_token("sub"), org=cfg.org, consumer="capture-bridge",
        type="inbound.message.*",
        target={"kind": "inprocess", "key": _SUBSCRIPTION_KEY}, grant_ref="soak",
    )
    store.put_subscription(sub)

    jwks_provider = cached_jwks_provider(jwks_url)
    require_principal = make_require_principal(
        jwks_provider=jwks_provider, audience=cfg.audience, now_fn=time.time, issuer=cfg.issuer)
    app = build_bus_app(service, require_principal=require_principal)
    return app, service, in_delivery


def _cfg_from_env() -> SoakConfig:
    return SoakConfig(
        issuer=os.environ["KERNEL_ISSUER"],
        audience=os.environ.get("BUS_AUDIENCE", "bus"),
        observation_vault=os.environ["SOAK_OBSERVATION_VAULT"],
        real_vault=os.environ.get("SOAK_REAL_VAULT"),
        soak_log=os.environ.get("SOAK_LOG", "soak.log"),
        route_mjs=os.environ["SOAK_ROUTE_MJS"],
        claude_bin=os.environ.get("CLAUDE_CLI_BIN", "claude"),
        connector_principal=os.environ.get("SOAK_CONNECTOR_PRINCIPAL", "connector:telegram"),
        org=os.environ["SOAK_ORG"],
        principal_map_entries=json.loads(os.environ["SOAK_PRINCIPAL_MAP"]),
        allowed_types=json.loads(os.environ.get(
            "SOAK_ALLOWED_TYPES",
            '["work-task","personal-task","meal","goal","event","team-knowledge","private-journal"]')),
        classify_type=None,
        node_bin=os.environ.get("NODE_BIN", "node"),
    )


# uvicorn entrypoint: `uvicorn deploy.soak_boot:app`
if os.environ.get("SOAK_BOOT") == "1":
    app, _service, _in = build_soak_app(
        _cfg_from_env(),
        identity_db=os.environ.get("KERNEL_IDENTITY_DB", "vault-store/identity.sqlite"),
        jwks_url=os.environ["KERNEL_JWKS_URL"],
    )
