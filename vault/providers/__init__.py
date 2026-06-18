from vault.providers.base import Provider, AppCred, HttpPost, basic_auth
from vault.providers.fortnox import FortnoxProvider

PROVIDERS: dict[str, Provider] = {"fortnox": FortnoxProvider()}
__all__ = ["Provider", "AppCred", "HttpPost", "basic_auth", "FortnoxProvider", "PROVIDERS"]
