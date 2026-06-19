from vault.model import Token
from vault.providers.fortnox import FortnoxProvider
from vault.providers.base import AppCred


def test_fortnox_refresh_rotates_and_sets_expiry():
    captured = {}

    def fake_post(url, form, headers):
        captured["url"] = url; captured["form"] = form; captured["headers"] = headers
        return {"access_token": "NEW_ACC", "refresh_token": "ROTATED_REF",
                "expires_in": 3600, "scope": "bookkeeping"}

    app = AppCred(client_id="cid", client_secret="secret")
    old = Token("old_acc", "old_ref", expires_at=0.0, scope="bookkeeping")
    new = FortnoxProvider().refresh(old, app, fake_post, now=1000.0)

    assert new == Token("NEW_ACC", "ROTATED_REF", 1000.0 + 3600, "bookkeeping")
    assert captured["url"] == "https://apps.fortnox.se/oauth-v1/token"
    assert captured["form"] == {"grant_type": "refresh_token", "refresh_token": "old_ref"}
    # Basic auth = base64("cid:secret")
    assert captured["headers"]["Authorization"] == "Basic Y2lkOnNlY3JldA=="


def test_fortnox_is_rotating():
    assert FortnoxProvider().rotation == "rotating"


def test_fortnox_authorize_url_is_user_mode_no_service_account():
    url = FortnoxProvider().authorize_url(
        AppCred("cid", "secret", redirect_uri="http://localhost:8123/callback",
                scopes=["bookkeeping", "invoice"]),
        state="STATE", code_challenge=None)
    # user-mode: Fortnox rejects account_type=service for this client
    assert "account_type" not in url
    assert "response_type=code" in url
    assert "access_type=offline" in url      # required to receive a refresh token
    assert "code_challenge" not in url       # confidential client, no PKCE
