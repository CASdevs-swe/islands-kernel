import argparse
import os
import secrets
import sys
import time

from identity.model import IslandRegistry, Org
from identity.store.server import ServerIdentityStore
from identity.tokens import hash_token


def provision_island(store, *, island_id, name, issuer, jwks_uri, audience, sso_authorize_url,
                     sso_token_url, sso_client_secret, org_id, org_name, session_ttl_days, now,
                     assertion_secret=None) -> None:
    if store.get_org(org_id) is None:
        store.put_org(Org(id=org_id, name=org_name, created_at=now))
    store.put_island(IslandRegistry(id=island_id, name=name, issuer=issuer, jwks_uri=jwks_uri,
        audience=audience, sso_authorize_url=sso_authorize_url, sso_token_url=sso_token_url,
        sso_client_secret_hash=hash_token(sso_client_secret), org_id=org_id,
        session_ttl_days=session_ttl_days, created_at=now, assertion_secret=assertion_secret))


def main(argv) -> None:
    p = argparse.ArgumentParser(description="Register an island as a federated login provider")
    p.add_argument("--island", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--issuer", required=True)
    p.add_argument("--jwks-uri", required=True)
    p.add_argument("--audience", required=True)
    p.add_argument("--sso-authorize-url", required=True)
    p.add_argument("--sso-token-url", required=True)
    p.add_argument("--sso-client-secret", required=True)
    p.add_argument("--org", required=True)
    p.add_argument("--org-name", required=True)
    p.add_argument("--session-ttl-days", type=float, default=30.0)
    p.add_argument("--assertion-secret", default=None)
    a = p.parse_args(argv)
    secret = a.assertion_secret or secrets.token_urlsafe(32)
    store = ServerIdentityStore(os.environ.get("KERNEL_IDENTITY_DB", "vault-store/identity.sqlite"))
    provision_island(store, island_id=a.island, name=a.name, issuer=a.issuer, jwks_uri=a.jwks_uri,
        audience=a.audience, sso_authorize_url=a.sso_authorize_url, sso_token_url=a.sso_token_url,
        sso_client_secret=a.sso_client_secret, org_id=a.org, org_name=a.org_name,
        session_ttl_days=a.session_ttl_days, now=time.time(), assertion_secret=secret)
    sys.stdout.write(a.island + "\n")
    sys.stdout.write(secret + "\n")


if __name__ == "__main__":
    main(sys.argv[1:])
