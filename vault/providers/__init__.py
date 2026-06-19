from vault.providers.base import Provider, AppCred, HttpPost, basic_auth
from vault.providers.fortnox import FortnoxProvider
from vault.providers.gmail import GmailProvider

PROVIDERS: dict[str, Provider] = {"fortnox": FortnoxProvider(), "gmail": GmailProvider()}
__all__ = ["Provider", "AppCred", "HttpPost", "basic_auth", "FortnoxProvider", "GmailProvider", "PROVIDERS"]
