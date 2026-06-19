from dataclasses import dataclass
from typing import Literal, Optional

PrincipalType = Literal["human", "service"]
Role = Literal["owner", "admin", "member", "viewer"]
Access = Literal["use", "manage"]
TargetKind = Literal["org", "island", "capability", "connection"]
IdentityKind = Literal["passkey", "google", "password"]


@dataclass
class Principal:
    id: str
    type: PrincipalType
    email: Optional[str]
    display_name: Optional[str]
    public_key: Optional[str]
    created_at: float


@dataclass
class Org:
    id: str
    name: str
    created_at: float


@dataclass
class Membership:
    principal_id: str
    org_id: str
    roles: list[Role]
    active: bool
    joined_at: float


@dataclass(frozen=True)
class GrantTarget:
    kind: TargetKind
    id: str


@dataclass
class Grant:
    id: str
    principal_id: str
    target: GrantTarget
    access: Access
    scopes_subset: Optional[list[str]]
    granted_by: str
    granted_at: float
    revoked_at: Optional[float] = None


@dataclass
class Session:
    id: str
    principal_id: str
    org_id: Optional[str]
    expires_at: float
    invalidated_at: Optional[float] = None


@dataclass
class McpToken:
    hash: str
    principal_id: str
    org_id: Optional[str]
    audience: Optional[str]
    scope: str
    expires_at: Optional[float]
    revoked_at: Optional[float] = None


@dataclass
class IdentityBinding:
    principal_id: str
    kind: IdentityKind
    ref: str
    created_at: float


@dataclass
class OAuthClient:
    id: str
    name: str
    redirect_uris: list[str]
    type: Literal["public", "confidential"]
    client_id_metadata_url: Optional[str] = None


@dataclass
class OAuthAuthCode:
    hash: str
    client_id: str
    principal_id: str
    org_id: Optional[str]
    code_challenge: str
    audience: str
    scope: str
    expires_at: float
    consumed_at: Optional[float] = None


@dataclass
class OAuthAccessToken:
    hash: str
    client_id: str
    principal_id: str
    org_id: Optional[str]
    audience: str
    scope: str
    expires_at: float
    refresh: Optional[dict] = None


@dataclass
class AccessLog:
    principal_id: str
    org_id: Optional[str]
    island: str
    capability: str
    at: float
