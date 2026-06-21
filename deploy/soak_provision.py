"""Provision the Telegram connector's service principal for the soak.

Issues a service credential for `connector:telegram` (NO vault connection — the
connector only publishes to the bus) and adds an ORG-scoped `use` grant so the
wildcard `inbound.message.*` publish + subscription authorize (an event-type
grant would not cover the glob). Prints the raw credential ONCE to stdout — it is
a secret; capture it into the bot's env, never the repo or logs.
"""
from __future__ import annotations

import argparse
import os
import sys
import time

from identity.store.server import ServerIdentityStore
from identity.service_principal import issue_service_credential
from identity.model import Grant, GrantTarget
from identity.tokens import generate_raw_token


def soak_provision(store, *, principal_id: str, org_id: str, now: float,
                   granted_by: str = "prn_owner", expires_at: float | None = None) -> str:
    cred = issue_service_credential(
        store, principal_id=principal_id, display_name=principal_id, org_id=org_id,
        audience=None, now=now, expires_at=expires_at)
    g = Grant(
        id=generate_raw_token("grant"), principal_id=principal_id,
        target=GrantTarget(kind="org", id=org_id), access="use",
        scopes_subset=None, granted_by=granted_by, granted_at=now, revoked_at=None)
    store.add_grant(g)
    return cred


def main(argv: list[str]) -> None:
    p = argparse.ArgumentParser(description="Provision the soak connector principal")
    p.add_argument("--principal", default="connector:telegram")
    p.add_argument("--org", required=True)
    p.add_argument("--granted-by", required=True, help="operator principal id (audit trail)")
    p.add_argument("--ttl-days", type=float, default=90.0)
    a = p.parse_args(argv)
    now = time.time()
    store = ServerIdentityStore(os.environ.get("KERNEL_IDENTITY_DB", "vault-store/identity.sqlite"))
    cred = soak_provision(store, principal_id=a.principal, org_id=a.org, now=now,
                          granted_by=a.granted_by, expires_at=now + a.ttl_days * 86400)
    sys.stdout.write(cred + "\n")


if __name__ == "__main__":
    main(sys.argv[1:])
