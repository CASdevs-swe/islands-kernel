"""C3: end-to-end cutover proof.

BEFORE (flag off): the existing local caller still fetches a Fortnox token through
the stub path. AFTER (flag on): the same bookkeeping service principal — credential
-> 5-min JWT -> use grant -> fetches through the authed vault. Rejection: no Bearer
-> 401; a valid kernel JWT for an ungranted principal -> 403. Stubbed provider; no
real Fortnox network; no prod flag flip (this is the local proof that gates it)."""
from fastapi.testclient import TestClient

from identity.keys import KeyManager
from identity.store.memory import InMemoryIdentityStore
from identity.jwt_issuer import mint
from identity.app import build_identity_app
from identity.service_principal import issue_service_credential, grant_connection_use

from islands_vault.client import KernelAuthTransport, VaultClient, HttpTransport

from vault.app import build_app
from vault.access import AccessService
from vault.config import VaultConfig
from vault.store.memory import InMemoryStore
from vault.model import Connection, Token
from vault.providers.fortnox import FortnoxProvider
from vault.providers.base import AppCred
from vault.kernel_auth import make_kernel_auth

ISSUER = "https://id.local"
AUD = "https://vault.local"
PATH = "/connections/caput-venti%2Ffortnox%2F559401-5157/access-token"


def _vault_service(created_by, now=1100.0):
    store = InMemoryStore()
    store.put_connection(Connection(
        id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
        scopes=["bookkeeping"], app_cred_ref="fortnox",
        token=Token("FORTNOX_ACCESS", "REFRESH", 99999.0, "bookkeeping"),
        rotation="rotating", lease=None, created_by=created_by,
        created_at=0.0, updated_at=0.0))
    cfg = VaultConfig(now_fn=lambda: now, http_post=lambda *a: {},
                      app_creds={"fortnox": AppCred("cid", "secret")},
                      state_hmac_key=b"k", skew=60)
    return AccessService(store, {"fortnox": FortnoxProvider()}, cfg)


class _DualClient:
    def __init__(self, identity_base, identity_client, vault_base, vault_client):
        self._map = [(identity_base.rstrip("/"), identity_client),
                     (vault_base.rstrip("/"), vault_client)]

    def post(self, url, **kw):
        for base, client in self._map:
            if url.startswith(base):
                return client.post(url[len(base):], **kw)
        raise AssertionError(f"no client for {url}")


def test_before_flag_off_stub_path_still_fetches():
    # The local caller bookkeeping uses today: stub path, owner principal. Must keep working.
    service = _vault_service(created_by="prn_owner")
    app = build_app(service)  # flag OFF: no require_principal
    client = VaultClient(HttpTransport(AUD, principal="prn_owner",
                                       http=_DualClient(ISSUER, TestClient(app), AUD, TestClient(app))))
    out = client.get_access("caput-venti", "fortnox", "559401-5157", island="bookkeeping")
    assert out["accessToken"] == "FORTNOX_ACCESS"


def _authed_harness(now=1100.0):
    km = KeyManager.generate("kid-1")
    ident = InMemoryIdentityStore()
    cred = issue_service_credential(
        ident, principal_id="prn_bk", display_name="bookkeeping", org_id="caput-venti",
        audience=AUD, now=now, expires_at=10_000.0)
    # service principal is NOT the connection owner; it holds a scoped use grant only
    service = _vault_service(created_by="prn_owner", now=now)
    grant_connection_use(ident, principal_id="prn_bk", connection_id="conn_1",
                         granted_by="prn_owner", now=now)
    require_principal, authorizer = make_kernel_auth(
        jwks_provider=lambda: km.jwks_document(), audience=AUD, issuer=ISSUER,
        now_fn=lambda: now, identity_store=ident, vault_store=service.store)
    identity_app = build_identity_app(store=ident, key_manager=km, issuer=ISSUER, now_fn=lambda: now)
    vault_app = build_app(service, require_principal=require_principal, authorizer=authorizer)
    return km, cred, identity_app, vault_app, now


def test_after_flag_on_same_service_principal_fetches():
    km, cred, identity_app, vault_app, now = _authed_harness()
    http = _DualClient(ISSUER, TestClient(identity_app), AUD, TestClient(vault_app))
    client = VaultClient(KernelAuthTransport(
        vault_base_url=AUD, identity_base_url=ISSUER, service_credential=cred,
        audience=AUD, http=http, now_fn=lambda: now))
    out = client.get_access("caput-venti", "fortnox", "559401-5157", island="bookkeeping")
    assert out["accessToken"] == "FORTNOX_ACCESS"


def test_after_flag_on_unauthenticated_is_rejected():
    _, _, _, vault_app, _ = _authed_harness()
    r = TestClient(vault_app).post(PATH)  # no Authorization header
    assert r.status_code == 401


def test_after_flag_on_authenticated_but_ungranted_is_forbidden():
    km, _, _, vault_app, now = _authed_harness()
    token = mint(km=km, issuer=ISSUER, sub="prn_nogrant", typ="human", audience=AUD,
                 org="caput-venti", roles=["member"], ttl=300, now=1000)
    r = TestClient(vault_app).post(PATH, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
