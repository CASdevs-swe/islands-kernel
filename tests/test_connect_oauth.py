import pytest, nacl.utils
from vault.store.memory import InMemoryStore
from vault.model import ConnKey
from vault.providers.fortnox import FortnoxProvider
from vault.providers.base import AppCred
from vault.access import AccessService
from vault.config import VaultConfig
from vault.oauth_state import sign_state, verify_state


def test_state_sign_verify_roundtrip_and_tamper():
    k = b"secret-key"
    s = sign_state({"org": "caput-venti", "provider": "fortnox"}, k)
    assert verify_state(s, k)["org"] == "caput-venti"
    with pytest.raises(ValueError):
        verify_state(s + "x", k)


def _svc():
    store = InMemoryStore()
    cfg = VaultConfig(now_fn=lambda: 1000.0,
                      http_post=lambda url, form, headers: {
                          "access_token": "ACC", "refresh_token": "REF",
                          "expires_in": 3600, "scope": "bookkeeping"},
                      app_creds={"fortnox": AppCred("cid", "secret", redirect_uri="https://h/cb",
                                                    scopes=["bookkeeping"])},
                      state_hmac_key=b"k")
    return AccessService(store, {"fortnox": FortnoxProvider()}, cfg), store


def test_connect_round_trip_creates_connection():
    svc, store = _svc()
    started = svc.start_connect("caput-venti", "fortnox", "559401-5157", principal_id="owner")
    assert "apps.fortnox.se/oauth-v1/auth" in started["authorizeUrl"]
    assert "code_challenge" not in started["authorizeUrl"]      # confidential client, no PKCE
    out = svc.finish_connect(code="authcode", state=started["state"])
    conn = store.get_connection(ConnKey("caput-venti", "fortnox", "559401-5157"))
    assert conn is not None and conn.token.access_token == "ACC" and conn.created_by == "owner"
    assert out["connectionId"] == conn.id
