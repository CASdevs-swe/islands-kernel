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


def provision(store, *, principal_id, org_id, connection_id, event_type, now) -> str:
    cred = issue_service_credential(
        store, principal_id=principal_id, display_name=principal_id, org_id=org_id,
        audience=None, now=now, expires_at=None)
    grant_connection_use(store, principal_id=principal_id, connection_id=connection_id,
                         granted_by="prn_owner", now=now)
    grant_event_type_use(store, principal_id=principal_id, event_type=event_type,
                         granted_by="prn_owner", now=now)
    return cred


def main(argv) -> None:
    p = argparse.ArgumentParser(description="Provision a multi-service kernel principal")
    p.add_argument("--principal", required=True)
    p.add_argument("--org", required=True)
    p.add_argument("--connection", required=True)
    p.add_argument("--event-type", required=True)
    a = p.parse_args(argv)
    store = ServerIdentityStore(os.environ.get("KERNEL_IDENTITY_DB", "vault-store/identity.sqlite"))
    cred = provision(store, principal_id=a.principal, org_id=a.org,
                     connection_id=a.connection, event_type=a.event_type, now=time.time())
    sys.stdout.write(cred + "\n")


if __name__ == "__main__":
    main(sys.argv[1:])
