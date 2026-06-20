from __future__ import annotations
import os
from dataclasses import asdict

from fastapi import FastAPI, HTTPException, Depends, Body

from bus.model import EnvelopeError
from bus.service import BusService, AuthzDenied


def build_bus_app(service: BusService, *, require_principal) -> FastAPI:
    app = FastAPI(title="islands-kernel event bus")

    @app.post("/events")
    def publish(body: dict = Body(...), claims=Depends(require_principal)):
        try:
            return service.publish(body, principal=claims["sub"], org=claims.get("org"))
        except AuthzDenied as e:
            raise HTTPException(403, str(e))
        except EnvelopeError as e:
            raise HTTPException(400, str(e))

    @app.post("/subscriptions")
    def subscribe(body: dict = Body(...), claims=Depends(require_principal)):
        try:
            sub = service.subscribe(
                principal=claims["sub"],
                org=claims.get("org"),
                type=body["type"],
                consumer=body["consumer"],
                target=body["target"],
                grant_ref=body.get("grant_ref", ""),
            )
        except AuthzDenied as e:
            raise HTTPException(403, str(e))
        except KeyError as e:
            raise HTTPException(400, f"missing field: {e}")
        return {"id": sub.id}

    @app.get("/subscriptions")
    def list_subs(claims=Depends(require_principal)):
        return {"subscriptions": [asdict(s) for s in service.list_subscriptions(claims.get("org"))]}

    @app.delete("/subscriptions/{sub_id}")
    def delete_sub(sub_id: str, claims=Depends(require_principal)):
        service.unsubscribe(sub_id)
        return {"deleted": sub_id}

    @app.get("/_events")
    def events_registry():
        return {"islands": [asdict(c) for c in service.contracts()]}

    @app.get("/deadletter")
    def deadletter(claims=Depends(require_principal)):
        rows = service.dead_letters(claims.get("org"))
        return {"dead": [
            {
                "event_id": d.event_id,
                "source": d.source,
                "subscription_id": d.subscription_id,
                "status": d.status,
                "attempts": d.attempts,
                "last_error": d.last_error,
            }
            for d in rows
        ]}

    @app.post("/deadletter/{event_id}/replay")
    def replay(event_id: str, source: str, claims=Depends(require_principal)):
        n = service.replay(event_id, source, org=claims.get("org"))
        return {"replayed": n}

    return app


def _build_bus_app_from_env() -> FastAPI:
    import time
    from datetime import datetime, timezone

    from identity.deps import make_require_principal
    from identity.store.server import ServerIdentityStore
    from identity.authorize import collect_grants
    from bus.store.server import ServerLedgerStore
    from bus.schema_registry import SchemaRegistry
    from bus.dispatch import Dispatcher, HttpPushDelivery
    from vault.kernel_auth import cached_jwks_provider

    issuer = os.environ["KERNEL_ISSUER"]
    audience = os.environ["BUS_AUDIENCE"]
    ident = ServerIdentityStore(os.environ.get("KERNEL_IDENTITY_DB", "vault-store/identity.sqlite"))
    store = ServerLedgerStore(os.environ.get("BUS_DB", "sqlite:///vault-store/bus.sqlite"))
    jwks_provider = cached_jwks_provider(os.environ["KERNEL_JWKS_URL"])
    require_principal = make_require_principal(
        jwks_provider=jwks_provider, audience=audience, now_fn=time.time, issuer=issuer,
    )
    dispatcher = Dispatcher(store, HttpPushDelivery(), now_fn=time.time)
    service = BusService(
        store,
        SchemaRegistry(),
        dispatcher,
        now_fn=time.time,
        now_iso_fn=lambda: datetime.now(timezone.utc).isoformat(),
        grants_for=lambda pid: collect_grants(principal_id=pid, identity_store=ident),
    )
    return build_bus_app(service, require_principal=require_principal)


app = _build_bus_app_from_env() if os.environ.get("BUS_BOOT") == "1" else None
