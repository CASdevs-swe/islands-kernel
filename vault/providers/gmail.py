from __future__ import annotations
from urllib.parse import urlencode
from vault.model import Token
from vault.providers.base import Provider, AppCred, HttpPost

TOKEN_URL = "https://oauth2.googleapis.com/token"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"


class GmailProvider(Provider):
    rotation = "rotating"

    def refresh(self, token, app, http_post, now):
        resp = http_post(TOKEN_URL,
                         {"client_id": app.client_id, "client_secret": app.client_secret,
                          "refresh_token": token.refresh_token, "grant_type": "refresh_token"},
                         {"Content-Type": "application/x-www-form-urlencoded"})
        return Token(access_token=resp["access_token"],
                     refresh_token=resp.get("refresh_token", token.refresh_token),
                     expires_at=now + int(resp.get("expires_in", 3600)),
                     scope=resp.get("scope", token.scope))

    def exchange_code(self, code, code_verifier, app, http_post, now):
        form = {"client_id": app.client_id, "client_secret": app.client_secret, "code": code,
                "redirect_uri": app.redirect_uri, "grant_type": "authorization_code"}
        if code_verifier:
            form["code_verifier"] = code_verifier
        resp = http_post(TOKEN_URL, form, {"Content-Type": "application/x-www-form-urlencoded"})
        return Token(access_token=resp["access_token"], refresh_token=resp.get("refresh_token", ""),
                     expires_at=now + int(resp.get("expires_in", 3600)), scope=resp.get("scope", ""))

    def authorize_url(self, app, state, code_challenge):
        q = {"client_id": app.client_id, "redirect_uri": app.redirect_uri,
             "response_type": "code", "scope": " ".join(app.scopes), "state": state,
             "access_type": "offline", "prompt": "consent"}
        if code_challenge:
            q["code_challenge"] = code_challenge
            q["code_challenge_method"] = "S256"
        return f"{AUTH_URL}?{urlencode(q)}"
