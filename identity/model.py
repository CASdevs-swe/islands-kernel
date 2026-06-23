from dataclasses import dataclass
from typing import Literal, Optional

PrincipalType = Literal["human", "service"]
Role = Literal["owner", "admin", "member", "viewer"]
Access = Literal["use", "manage"]
TargetKind = Literal["org", "island", "capability", "connection", "event-type"]
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
class IslandRegistry:
    id: str
    name: str
    issuer: str                 # expected `iss` of the island's assertion JWT
    jwks_uri: str               # where to fetch the island's assertion-verification JWKS
    audience: str               # the MCP resource string that maps an OAuth request to this island
    sso_authorize_url: str      # where the kernel redirects the user-agent to log in
    sso_token_url: str          # server-to-server: exchange the island sso_code for an assertion
    sso_client_secret_hash: str # hash of the secret the kernel presents to the island /sso/token
    org_id: str                 # kernel Org this island's users belong to
    session_ttl_days: float     # sizes the refresh token for this island
    created_at: float
    disabled_at: Optional[float] = None


@dataclass
class IslandPrincipalLink:
    island_id: str
    island_user_id: str
    principal_id: str
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
