from __future__ import annotations
import hashlib
from dataclasses import dataclass, field
from typing import Literal, Optional

Rotation = Literal["rotating", "static"]
Access = Literal["use", "manage"]


def new_id(prefix: str, seed: str) -> str:
    return f"{prefix}_{hashlib.sha256(seed.encode()).hexdigest()[:16]}"


@dataclass(frozen=True)
class ConnKey:
    org: str
    provider: str
    account: str

    def as_str(self) -> str:
        return f"{self.org}/{self.provider}/{self.account}"


@dataclass
class Token:
    access_token: str
    refresh_token: str
    expires_at: float
    scope: str

    def is_expired(self, skew: int = 60, now: Optional[float] = None) -> bool:
        if now is None:
            raise ValueError("now must be supplied explicitly (no implicit clock)")
        return now + skew >= self.expires_at

    def to_dict(self) -> dict:
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "expires_at": self.expires_at,
            "scope": self.scope,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Token":
        return cls(d["access_token"], d["refresh_token"], float(d["expires_at"]), d.get("scope", ""))


@dataclass
class Lease:
    holder: str
    until: float


@dataclass
class Connection:
    id: str
    org: str
    provider: str
    account: str
    scopes: list[str]
    app_cred_ref: str
    token: Optional[Token]
    rotation: Rotation
    lease: Optional[Lease]
    created_by: str
    created_at: float
    updated_at: float

    @property
    def key(self) -> ConnKey:
        return ConnKey(self.org, self.provider, self.account)

    def to_record(self) -> dict:
        # token is stored sealed, separately — never in the plaintext record
        return {
            "id": self.id, "org": self.org, "provider": self.provider,
            "account": self.account, "scopes": list(self.scopes),
            "app_cred_ref": self.app_cred_ref, "rotation": self.rotation,
            "created_by": self.created_by, "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_record(cls, rec: dict, token: Optional[Token] = None, lease: Optional[Lease] = None) -> "Connection":
        return cls(
            id=rec["id"], org=rec["org"], provider=rec["provider"], account=rec["account"],
            scopes=list(rec["scopes"]), app_cred_ref=rec["app_cred_ref"], token=token,
            rotation=rec["rotation"], lease=lease, created_by=rec["created_by"],
            created_at=rec["created_at"], updated_at=rec["updated_at"],
        )


@dataclass
class ConnectionGrant:
    connection_id: str
    principal_id: str
    access: Access
    scopes_subset: Optional[list[str]]
    granted_by: str
    granted_at: float


@dataclass
class ConnectionAccessLog:
    connection_id: str
    principal_id: str
    island: str
    op: str
    at: float
