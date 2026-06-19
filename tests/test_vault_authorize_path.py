"""C2: the authed access-token path runs an authorize() grant check (replacing the
slice-1 require_access stub), wired behind an injected authorizer."""
import pytest
from fastapi.testclient import TestClient

from identity.keys import KeyManager
from identity.store.memory import InMemoryIdentityStore
from identity.jwt_issuer import mint
from identity.service_principal import grant_connection_use

from vault.access import AccessService
from vault.config import VaultConfig
from vault.store.memory import InMemoryStore
from vault.model import Connection, ConnKey, Token
from vault.providers.fortnox import FortnoxProvider
from vault.providers.base import AppCred
from vault.app import build_app
from vault.kernel_auth import make_kernel_auth, cached_jwks_provider

ISSUER = "https://id.local"
AUD = "https://vault.local"


def _service(created_by="prn_other", now=1100.0):
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


def _key():
    return ConnKey("caput-venti", "fortnox", "559401-5157")


def test_grant_check_replaces_require_access():
    # connection owned by someone else, no connection grant: require_access would deny.
    service = _service(created_by="prn_other")
    seen = {"conn": None}

    def gc(conn):
        seen["conn"] = conn.id  # passes (no raise) -> authorize() said yes

    out = service.get_access_token(_key(), "prn_bk", "bk", grant_check=gc)
    assert out["accessToken"] == "FORTNOX_ACCESS"
    assert seen["conn"] == "conn_1"


def test_grant_check_denial_raises_permission_error():
    service = _service(created_by="prn_other")

    def gc(conn):
        raise PermissionError("denied")

    with pytest.raises(PermissionError):
        service.get_access_token(_key(), "prn_bk", "bk", grant_check=gc)


def test_legacy_path_unchanged_without_grant_check():
    # owner still passes via require_access when no grant_check is supplied.
    service = _service(created_by="prn_owner")
    out = service.get_access_token(_key(), "prn_owner", "bk")
    assert out["accessToken"] == "FORTNOX_ACCESS"


def test_make_kernel_auth_authorizer_allows_only_granted_principal():
    ident = InMemoryIdentityStore()
    grant_connection_use(ident, principal_id="prn_bk", connection_id="conn_1",
                         granted_by="prn_owner", now=0.0)
    vstore = InMemoryStore()
    km = KeyManager.generate("kid-1")
    _, authorizer = make_kernel_auth(
        jwks_provider=lambda: km.jwks_document(), audience=AUD, issuer=ISSUER,
        now_fn=lambda: 100.0, identity_store=ident, vault_store=vstore)

    conn = Connection(id="conn_1", org="caput-venti", provider="fortnox",
                      account="559401-5157", scopes=[], app_cred_ref="fortnox",
                      token=None, rotation="rotating", lease=None,
                      created_by="prn_owner", created_at=0.0, updated_at=0.0)
    assert authorizer(conn=conn, principal_id="prn_bk", org="caput-venti") is True
    assert authorizer(conn=conn, principal_id="prn_nogrant", org="caput-venti") is False


def test_authed_route_uses_authorizer_grant_and_403_without():
    service = _service(created_by="prn_owner")  # service principal is NOT the owner
    ident = InMemoryIdentityStore()
    grant_connection_use(ident, principal_id="prn_bk", connection_id="conn_1",
                         granted_by="prn_owner", now=0.0)
    km = KeyManager.generate("kid-1")
    require_principal, authorizer = make_kernel_auth(
        jwks_provider=lambda: km.jwks_document(), audience=AUD, issuer=ISSUER,
        now_fn=lambda: 1100.0, identity_store=ident, vault_store=service.store)
    app = build_app(service, require_principal=require_principal, authorizer=authorizer)
    client = TestClient(app)

    def _tok(sub):
        return mint(km=km, issuer=ISSUER, sub=sub, typ="service", audience=AUD,
                    org="caput-venti", roles=["member"], ttl=300, now=1000)

    granted = client.post("/connections/caput-venti%2Ffortnox%2F559401-5157/access-token",
                          headers={"Authorization": f"Bearer {_tok('prn_bk')}"})
    assert granted.status_code == 200
    assert granted.json()["accessToken"] == "FORTNOX_ACCESS"

    ungranted = client.post("/connections/caput-venti%2Ffortnox%2F559401-5157/access-token",
                            headers={"Authorization": f"Bearer {_tok('prn_nogrant')}"})
    assert ungranted.status_code == 403


def test_cached_jwks_provider_fetches_once():
    calls = {"n": 0}

    class _Resp:
        def raise_for_status(self): pass
        def json(self): return {"keys": []}

    class _Http:
        def get(self, url):
            calls["n"] += 1
            return _Resp()

    provider = cached_jwks_provider("https://id.local/.well-known/jwks.json", http=_Http())
    assert provider() == {"keys": []}
    provider()
    assert calls["n"] == 1
