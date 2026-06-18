from __future__ import annotations
from urllib.parse import urlencode
from vault.model import Token
from vault.providers.base import Provider, AppCred, HttpPost, basic_auth

TOKEN_URL = "https://apps.fortnox.se/oauth-v1/token"
AUTH_URL = "https://apps.fortnox.se/oauth-v1/auth"


class FortnoxProvider(Provider):
    rotation = "rotating"

    def _parse(self, resp: dict, now: float) -> Token:
        return Token(access_token=resp["access_token"], refresh_token=resp["refresh_token"],
                     expires_at=now + int(resp.get("expires_in", 3600)),
                     scope=resp.get("scope", ""))

    def refresh(self, token, app, http_post, now):
        resp = http_post(TOKEN_URL,
                         {"grant_type": "refresh_token", "refresh_token": token.refresh_token},
                         {"Authorization": basic_auth(app.client_id, app.client_secret),
                          "Content-Type": "application/x-www-form-urlencoded"})
        return self._parse(resp, now)

    def exchange_code(self, code, code_verifier, app, http_post, now):
        resp = http_post(TOKEN_URL,
                         {"grant_type": "authorization_code", "code": code,
                          "redirect_uri": app.redirect_uri},
                         {"Authorization": basic_auth(app.client_id, app.client_secret),
                          "Content-Type": "application/x-www-form-urlencoded"})
        return self._parse(resp, now)

    def authorize_url(self, app, state, code_challenge):
        # confidential client: no PKCE challenge
        q = {"client_id": app.client_id, "redirect_uri": app.redirect_uri,
             "scope": " ".join(app.scopes), "state": state, "response_type": "code",
             "access_type": "offline", "account_type": "service"}
        return f"{AUTH_URL}?{urlencode(q)}"
