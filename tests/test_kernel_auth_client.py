"""C1: the kernel-auth vault client exchanges a service credential for a 5-min JWT
and fetches a Fortnox token through the vault. Proven in-process with a stubbed
provider (no real Fortnox network) against the existing authed vault route."""
from fastapi.testclient import TestClient

from identity.keys import KeyManager
from identity.store.memory import InMemoryIdentityStore
from identity.app import build_identity_app
from identity.deps import make_require_principal
from identity.service_principal import issue_service_credential

from islands_vault.client import KernelAuthTransport, VaultClient

from vault.app import build_app
from vault.access import AccessService
from vault.config import VaultConfig
from vault.store.memory import InMemoryStore
from vault.model import Connection, Token
from vault.providers.fortnox import FortnoxProvider
from vault.providers.base import AppCred

ISSUER = "https://id.local"
AUD = "https://vault.local"


class _DualClient:
    """Routes httpx-style POSTs to the identity or vault TestClient by base URL."""
    def __init__(self, identity_base, identity_client, vault_base, vault_client):
        self._map = [(identity_base.rstrip("/"), identity_client),
                     (vault_base.rstrip("/"), vault_client)]

    def post(self, url, **kw):
        for base, client in self._map:
            if url.startswith(base):
                return client.post(url[len(base):], **kw)
        raise AssertionError(f"no client for {url}")


def _harness(now=1100.0):
    km = KeyManager.generate("kid-1")
    ident = InMemoryIdentityStore()
    # bookkeeping's machine credential; it owns the Fortnox connection in this proof
    cred = issue_service_credential(
        ident, principal_id="prn_bk", display_name="bookkeeping",
        org_id="caput-venti", audience=AUD, now=now, expires_at=10_000.0)

    vstore = InMemoryStore()
    vstore.put_connection(Connection(
        id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
        scopes=["bookkeeping"], app_cred_ref="fortnox",
        token=Token("FORTNOX_ACCESS", "REFRESH", 99999.0, "bookkeeping"),
        rotation="rotating", lease=None, created_by="prn_bk",
        created_at=0.0, updated_at=0.0))
    cfg = VaultConfig(now_fn=lambda: now, http_post=lambda *a: {},
                      app_creds={"fortnox": AppCred("cid", "secret")},
                      state_hmac_key=b"k", skew=60)
    service = AccessService(vstore, {"fortnox": FortnoxProvider()}, cfg)

    require_principal = make_require_principal(
        jwks_provider=lambda: km.jwks_document(), audience=AUD,
        now_fn=lambda: now, issuer=ISSUER)

    identity_app = build_identity_app(store=ident, key_manager=km, issuer=ISSUER,
                                      now_fn=lambda: now)
    vault_app = build_app(service, require_principal=require_principal)
    http = _DualClient(ISSUER, TestClient(identity_app), AUD, TestClient(vault_app))
    return cred, http, now


def test_kernel_auth_client_fetches_fortnox_token_through_vault():
    cred, http, now = _harness()
    transport = KernelAuthTransport(
        vault_base_url=AUD, identity_base_url=ISSUER, service_credential=cred,
        audience=AUD, http=http, now_fn=lambda: now)
    client = VaultClient(transport)

    out = client.get_access("caput-venti", "fortnox", "559401-5157", island="bookkeeping")
    assert out["accessToken"] == "FORTNOX_ACCESS"
    assert "refresh" not in str(out).lower()


def test_transport_caches_the_jwt_across_calls():
    cred, http, now = _harness()
    calls = {"n": 0}
    inner = http.post

    def counting_post(url, **kw):
        if url.endswith("/auth/exchange"):
            calls["n"] += 1
        return inner(url, **kw)

    http.post = counting_post
    transport = KernelAuthTransport(
        vault_base_url=AUD, identity_base_url=ISSUER, service_credential=cred,
        audience=AUD, http=http, now_fn=lambda: now)
    client = VaultClient(transport)

    client.get_access_token("caput-venti", "fortnox", "559401-5157")
    client.get_access_token("caput-venti", "fortnox", "559401-5157")
    assert calls["n"] == 1  # second fetch reuses the cached 5-min JWT
