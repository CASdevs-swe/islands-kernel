from __future__ import annotations
import socket
import threading
import time as _time
from dataclasses import dataclass

import uvicorn
import nacl.utils

from identity.keys import KeyManager
from identity.store.server import ServerIdentityStore
from identity.app import build_identity_app
from identity.service_principal import issue_service_credential, grant_connection_use

from vault.app import build_app
from vault.access import AccessService
from vault.config import VaultConfig
from vault.store.server import ServerStore
from vault.crypto import SecretboxKeyWrapper
from vault.model import Connection, Token
from vault.providers.fortnox import FortnoxProvider
from vault.providers.base import AppCred
from vault.kernel_auth import make_kernel_auth, make_manage_authorizer, cached_jwks_provider

ORG = "caput-venti"
ACCOUNT = "559401-5157"
ACCESS_PATH = "/connections/caput-venti%2Ffortnox%2F559401-5157/access-token"


def bound_socket() -> tuple[socket.socket, int]:
    """Return a TCP socket already bound to a free port on loopback.

    The socket stays open so the OS keeps the port reserved until uvicorn
    takes ownership, eliminating the TOCTOU window of the old close/rebind
    pattern.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    return s, s.getsockname()[1]


class ThreadedServer:
    def __init__(self, app, sock: socket.socket):
        cfg = uvicorn.Config(app, log_level="warning")
        self._srv = uvicorn.Server(cfg)
        self._sock = sock
        self._th = threading.Thread(
            target=self._srv.run, kwargs={"sockets": [sock]}, daemon=True
        )

    def start(self):
        self._th.start()
        for _ in range(500):
            if self._srv.started:
                return
            _time.sleep(0.01)
        raise RuntimeError("server did not start")

    def stop(self):
        self._srv.should_exit = True
        self._th.join(timeout=5)


class CountingProvider(FortnoxProvider):
    def __init__(self):
        self.calls = 0
        self._lock = threading.Lock()

    def refresh(self, token, app, http_post, now):
        with self._lock:
            self.calls += 1
            n = self.calls
        import time
        time.sleep(0.1)
        return Token(f"acc{n}", f"ref{n}", now + 3600, "bookkeeping")


@dataclass
class ServedStack:
    identity_url: str
    vault_url: str
    cred: str
    audience: str
    provider: CountingProvider
    _identity_srv: ThreadedServer
    _vault_srv: ThreadedServer

    def start(self):
        self._identity_srv.start()
        self._vault_srv.start()

    def stop(self):
        self._vault_srv.stop()
        self._identity_srv.stop()


def build_served_stack(tmp_path, *, expired=False) -> ServedStack:
    import time

    id_sock, id_port = bound_socket()
    vault_sock, vault_port = bound_socket()
    identity_url = f"http://127.0.0.1:{id_port}"
    vault_url = f"http://127.0.0.1:{vault_port}"
    issuer = identity_url
    audience = "vault"
    now = time.time()

    km = KeyManager.generate("kid-served")
    ident = ServerIdentityStore(str(tmp_path / "identity.sqlite"))
    cred = issue_service_credential(
        ident, principal_id="prn_bk", display_name="bookkeeping", org_id=ORG,
        audience=audience, now=now, expires_at=now + 3600)
    grant_connection_use(ident, principal_id="prn_bk", connection_id="conn_1",
                         granted_by="prn_owner", now=now)
    identity_app = build_identity_app(store=ident, key_manager=km, issuer=issuer, now_fn=time.time)

    wrapper = SecretboxKeyWrapper(nacl.utils.random(32))
    store = ServerStore(f"sqlite:///{tmp_path}/vault.sqlite", wrapper)
    expires = 100.0 if expired else now + 99999.0
    store.put_connection(Connection(
        id="conn_1", org=ORG, provider="fortnox", account=ACCOUNT, scopes=["bookkeeping"],
        app_cred_ref="fortnox", token=Token("FORTNOX_ACCESS", "REFRESH", expires, "bookkeeping"),
        rotation="rotating", lease=None, created_by="prn_owner", created_at=0.0, updated_at=0.0))
    provider = CountingProvider()
    cfg = VaultConfig(now_fn=time.time, http_post=lambda *a: {},
                      app_creds={"fortnox": AppCred("cid", "secret")}, state_hmac_key=b"k", skew=60)
    service = AccessService(store, {"fortnox": provider}, cfg)

    jwks_provider = cached_jwks_provider(f"{identity_url}/.well-known/jwks.json")
    require_principal, authorizer = make_kernel_auth(
        jwks_provider=jwks_provider, audience=audience, issuer=issuer, now_fn=time.time,
        identity_store=ident, vault_store=service.store)
    manage_authorizer = make_manage_authorizer(
        now_fn=time.time, identity_store=ident, vault_store=service.store)
    vault_app = build_app(service, require_principal=require_principal, authorizer=authorizer,
                          manage_authorizer=manage_authorizer)

    @vault_app.get("/_test/refresh-count")
    async def _refresh_count():
        return {"calls": provider.calls}

    return ServedStack(identity_url, vault_url, cred, audience, provider,
                       ThreadedServer(identity_app, id_sock), ThreadedServer(vault_app, vault_sock))


from datetime import datetime, timezone

from identity.deps import make_require_principal
from identity.authorize import collect_grants
from bus.store.server import ServerLedgerStore
from bus.schema_registry import SchemaRegistry
from bus.dispatch import Dispatcher, InProcessDelivery, HttpPushDelivery, RoutingDelivery
from bus.service import BusService
from bus.app import build_bus_app
from bus.provisioning import grant_event_type_use


@dataclass
class ServedBusStack:
    identity_url: str
    bus_url: str
    cred: str
    audience: str
    store: ServerLedgerStore
    identity_store: ServerIdentityStore
    counter: dict
    _identity_srv: ThreadedServer
    _bus_srv: ThreadedServer

    def start(self):
        self._identity_srv.start()
        self._bus_srv.start()

    def stop(self):
        self._bus_srv.stop()
        self._identity_srv.stop()


def build_served_bus_stack(tmp_path) -> ServedBusStack:
    import time

    id_sock, id_port = bound_socket()
    bus_sock, bus_port = bound_socket()
    identity_url = f"http://127.0.0.1:{id_port}"
    bus_url = f"http://127.0.0.1:{bus_port}"
    issuer = identity_url
    audience = "bus"
    now = time.time()

    km = KeyManager.generate("kid-bus")
    ident = ServerIdentityStore(str(tmp_path / "identity.sqlite"))
    cred = issue_service_credential(
        ident, principal_id="prn_bk", display_name="bookkeeping", org_id=ORG,
        audience=audience, now=now, expires_at=now + 3600)
    grant_event_type_use(ident, principal_id="prn_bk",
                         event_type="bookkeeping.voucher.posted", granted_by="prn_owner", now=now)
    identity_app = build_identity_app(store=ident, key_manager=km, issuer=issuer, now_fn=time.time)

    store = ServerLedgerStore(f"sqlite:///{tmp_path}/bus.sqlite")
    reg = SchemaRegistry()
    reg.register("voucher/v1", {"type": "object", "required": ["voucherId"],
                                "properties": {"voucherId": {"type": "string"}},
                                "additionalProperties": False})
    counter = {"n": 0}
    counter_lock = threading.Lock()
    deliv = InProcessDelivery()

    def handler(event):
        with counter_lock:
            counter["n"] += 1

    deliv.register("counter", handler)
    dispatcher = Dispatcher(store, RoutingDelivery(deliv, HttpPushDelivery()), now_fn=time.time)
    service = BusService(store, reg, dispatcher, now_fn=time.time,
                         now_iso_fn=lambda: datetime.now(timezone.utc).isoformat(),
                         grants_for=lambda pid: collect_grants(principal_id=pid, identity_store=ident))

    jwks_provider = cached_jwks_provider(f"{identity_url}/.well-known/jwks.json")
    require_principal = make_require_principal(
        jwks_provider=jwks_provider, audience=audience, now_fn=time.time, issuer=issuer)
    bus_app = build_bus_app(service, require_principal=require_principal)

    return ServedBusStack(identity_url, bus_url, cred, audience, store, ident, counter,
                          ThreadedServer(identity_app, id_sock), ThreadedServer(bus_app, bus_sock))
