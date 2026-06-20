"""Provision one service principal that can reach both the vault and the bus.

Reads KERNEL_IDENTITY_DB (the shared identity sqlite the served kernel uses),
issues an unbound service credential, and grants it connection-use + event-type
-use. Prints the raw credential ONCE to stdout. The raw credential is a secret:
capture it into the host secret store. It is never written to the repo or logs.
"""
from __future__ import annotations

import argparse
import os
import sys
import time

from identity.store.server import ServerIdentityStore
from identity.service_principal import issue_service_credential, grant_connection_use
from bus.provisioning import grant_event_type_use


def provision(store, *, principal_id, org_id, connection_id, event_type, now,
              granted_by="prn_owner", expires_at=None) -> str:
    cred = issue_service_credential(
        store, principal_id=principal_id, display_name=principal_id, org_id=org_id,
        audience=None, now=now, expires_at=expires_at)
    grant_connection_use(store, principal_id=principal_id, connection_id=connection_id,
                         granted_by=granted_by, now=now)
    grant_event_type_use(store, principal_id=principal_id, event_type=event_type,
                         granted_by=granted_by, now=now)
    return cred


def main(argv) -> None:
    p = argparse.ArgumentParser(description="Provision a multi-service kernel principal")
    p.add_argument("--principal", required=True)
    p.add_argument("--org", required=True)
    p.add_argument("--connection", required=True)
    p.add_argument("--event-type", required=True)
    p.add_argument("--granted-by", required=True,
                   help="principal id of the operator issuing this credential (audit trail)")
    p.add_argument("--ttl-days", type=float, default=90.0,
                   help="credential lifetime in days (default 90); ignored if --expires-at is set")
    p.add_argument("--expires-at", type=float, default=None,
                   help="absolute expiry epoch seconds; overrides --ttl-days")
    a = p.parse_args(argv)
    now = time.time()
    expires_at = a.expires_at if a.expires_at is not None else now + a.ttl_days * 86400
    store = ServerIdentityStore(os.environ.get("KERNEL_IDENTITY_DB", "vault-store/identity.sqlite"))
    cred = provision(store, principal_id=a.principal, org_id=a.org,
                     connection_id=a.connection, event_type=a.event_type, now=now,
                     granted_by=a.granted_by, expires_at=expires_at)
    sys.stdout.write(cred + "\n")


if __name__ == "__main__":
    main(sys.argv[1:])
