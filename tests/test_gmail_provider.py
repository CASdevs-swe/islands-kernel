from vault.model import Token
from vault.providers.gmail import GmailProvider
from vault.providers.base import AppCred


def test_gmail_refresh_reuses_refresh_when_absent():
    def fake_post(url, form, headers):
        assert url == "https://oauth2.googleapis.com/token"
        assert form["grant_type"] == "refresh_token" and form["client_secret"] == "gsecret"
        return {"access_token": "GACC", "expires_in": 3599, "scope": "gmail.send"}  # no refresh_token
    old = Token("o", "KEEP_REFRESH", 0.0, "gmail.send")
    new = GmailProvider().refresh(old, AppCred("gid", "gsecret"), fake_post, now=2000.0)
    assert new.access_token == "GACC"
    assert new.refresh_token == "KEEP_REFRESH"            # reused when Google omits it
    assert new.expires_at == 2000.0 + 3599


def test_gmail_authorize_url_supports_pkce():
    url = GmailProvider().authorize_url(AppCred("gid", "x", redirect_uri="https://h/cb",
                                               scopes=["gmail.send"]), state="ST", code_challenge="CH")
    assert "code_challenge=CH" in url and "code_challenge_method=S256" in url
