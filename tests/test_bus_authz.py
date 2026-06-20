import tempfile
import pathlib

import httpx
import pytest

from tests.served_harness import build_served_bus_stack
from identity.service_principal import issue_service_credential


def _tmpdir():
    return pathlib.Path(tempfile.mkdtemp())


def _exchange(identity_url, cred, audience):
    r = httpx.post(
        f"{identity_url}/auth/exchange",
        json={"opaque_token": cred, "audience": audience},
    )
    r.raise_for_status()
    return r.json()["access_token"]


def test_publish_without_grant_is_403():
    stack = build_served_bus_stack(_tmpdir())
    stack.start()
    try:
        ungranted = issue_service_credential(
            stack.identity_store,
            principal_id="prn_nobody",
            display_name="nobody",
            org_id="caput-venti",
            audience=stack.audience,
            now=0.0,
            expires_at=None,
        )
        jwt = _exchange(stack.identity_url, ungranted, stack.audience)
        r = httpx.post(
            f"{stack.bus_url}/events",
            headers={"Authorization": f"Bearer {jwt}"},
            json={
                "type": "bookkeeping.voucher.posted",
                "schema": "voucher/v1",
                "source": "bookkeeping",
                "trace": {"store": "bk", "ref": "r1"},
                "data": {"voucherId": "V-1"},
            },
        )
        assert r.status_code == 403
    finally:
        stack.stop()
