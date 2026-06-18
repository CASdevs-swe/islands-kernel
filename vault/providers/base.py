from __future__ import annotations
import base64
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Callable
from vault.model import Token, Rotation

HttpPost = Callable[[str, dict, dict], dict]


@dataclass
class AppCred:
    client_id: str
    client_secret: str
    redirect_uri: str = ""
    scopes: list[str] = field(default_factory=list)


def basic_auth(client_id: str, client_secret: str) -> str:
    raw = f"{client_id}:{client_secret}".encode()
    return "Basic " + base64.b64encode(raw).decode()


class Provider(ABC):
    rotation: Rotation = "rotating"

    @abstractmethod
    def refresh(self, token: Token, app: AppCred, http_post: HttpPost, now: float) -> Token: ...
    @abstractmethod
    def exchange_code(self, code: str, code_verifier: str | None, app: AppCred,
                      http_post: HttpPost, now: float) -> Token: ...
    @abstractmethod
    def authorize_url(self, app: AppCred, state: str, code_challenge: str | None) -> str: ...
