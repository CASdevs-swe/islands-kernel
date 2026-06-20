import httpx
import jwt as pyjwt

from tests.served_harness import build_served_kernel_stack, ACCESS_PATH, ORG
from tests.served_harness import OTHER_ORG_ACCESS_PATH


def _exchange(identity_url, cred, audience):
    r = httpx.post(f"{identity_url}/auth/exchange",
                   json={"opaque_token": cred, "audience": audience}, timeout=10)
    r.raise_for_status()
    return r.json()["access_token"]


def test_one_token_serves_vault_and_bus(tmp_path):
    stack = build_served_kernel_stack(tmp_path)
    stack.start()
    try:
        # ONE exchange -> ONE token carrying both audiences and one org
        token = _exchange(stack.identity_url, stack.cred, ["vault", "bus"])
        claims = pyjwt.decode(token, options={"verify_signature": False})
        assert {"vault", "bus"}.issubset(set(claims["aud"]))
        assert claims["org"] == ORG
        headers = {"Authorization": f"Bearer {token}"}

        # (a) vault: fetch an access token with that SAME token
        rv = httpx.post(f"{stack.vault_url}{ACCESS_PATH}", headers=headers, timeout=15)
        rv.raise_for_status()
        assert rv.json()["accessToken"]

        # (b) bus: subscribe, publish, consume with that SAME token
        httpx.post(f"{stack.bus_url}/subscriptions", headers=headers, json={
            "type": "bookkeeping.voucher.posted", "consumer": "smartcharge",
            "target": {"kind": "inprocess", "key": "counter"}, "grant_ref": "g"},
            timeout=10).raise_for_status()
        rb = httpx.post(f"{stack.bus_url}/events", headers=headers, json={
            "type": "bookkeeping.voucher.posted", "schema": "voucher/v1",
            "source": "bookkeeping", "trace": {"store": "bk", "ref": "r1"},
            "data": {"voucherId": "V-1"}, "id": "evt_xslice"}, timeout=10)
        rb.raise_for_status()
        assert rb.json()["deduped"] is False

        # org is consistent end to end: the consumed event was stamped with the token's org
        assert stack.seen["n"] == 1
        assert stack.seen["org"] == ORG
    finally:
        stack.stop()


def test_org_and_grant_scoping_enforced(tmp_path):
    stack = build_served_kernel_stack(tmp_path)
    stack.start()
    try:
        token = _exchange(stack.identity_url, stack.cred, ["vault", "bus"])
        headers = {"Authorization": f"Bearer {token}"}

        # vault: a connection in another org, no grant -> 403 (the principal cannot reach across orgs)
        r1 = httpx.post(f"{stack.vault_url}{OTHER_ORG_ACCESS_PATH}", headers=headers, timeout=10)
        assert r1.status_code == 403

        # bus: an event-type with no grant -> 403 (grant scoping flows through the shared identity)
        r2 = httpx.post(f"{stack.bus_url}/events", headers=headers, json={
            "type": "ungranted.type", "schema": "voucher/v1", "source": "bookkeeping",
            "trace": {"store": "bk", "ref": "r2"}, "data": {"voucherId": "V-2"}, "id": "evt_ng"},
            timeout=10)
        assert r2.status_code == 403
    finally:
        stack.stop()
