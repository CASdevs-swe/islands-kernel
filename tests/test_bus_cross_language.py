# tests/test_bus_cross_language.py
import json
import os
import subprocess
import threading
import time
import httpx
import pytest
from tests.served_harness import build_served_bus_stack


def _readline_with_timeout(stream, timeout=15.0):
    result = {}

    def run():
        result["line"] = stream.readline()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise TimeoutError("node consumer produced no output within timeout")
    return result.get("line", "")


def _tmpdir():
    import tempfile, pathlib
    return pathlib.Path(tempfile.mkdtemp())


def _exchange(identity_url, cred, audience):
    r = httpx.post(f"{identity_url}/auth/exchange",
                   json={"opaque_token": cred, "audience": audience})
    r.raise_for_status()
    return r.json()["access_token"]


def _have_node():
    from shutil import which
    return which("node") is not None


@pytest.mark.skipif(not _have_node(), reason="node not installed")
def test_node_publishes_python_consumes():
    stack = build_served_bus_stack(_tmpdir())
    stack.start()
    try:
        jwt = _exchange(stack.identity_url, stack.cred, stack.audience)
        h = {"Authorization": f"Bearer {jwt}"}
        httpx.post(f"{stack.bus_url}/subscriptions", headers=h,
                   json={"type": "bookkeeping.voucher.posted", "consumer": "smartcharge",
                         "target": {"kind": "inprocess", "key": "counter"}, "grant_ref": "g"}).raise_for_status()
        script = os.path.join(os.path.dirname(__file__), "node_bus_publish.mjs")
        out = subprocess.run(["node", script, stack.bus_url, jwt], capture_output=True, text=True, timeout=30)
        assert out.returncode == 0, out.stderr
        body = json.loads(out.stdout)
        assert body["deduped"] is False
        assert stack.counter["n"] == 1                 # Python in-process handler consumed it
    finally:
        stack.stop()


@pytest.mark.skipif(not _have_node(), reason="node not installed")
def test_python_publishes_node_consumes():
    stack = build_served_bus_stack(_tmpdir())
    stack.start()
    consumer = subprocess.Popen(["node", os.path.join(os.path.dirname(__file__), "node_bus_consumer.mjs")],
                                stdout=subprocess.PIPE, text=True)
    try:
        consumer_port = int(_readline_with_timeout(consumer.stdout).strip())   # the script prints its port first
        jwt = _exchange(stack.identity_url, stack.cred, stack.audience)
        h = {"Authorization": f"Bearer {jwt}"}
        httpx.post(f"{stack.bus_url}/subscriptions", headers=h,
                   json={"type": "bookkeeping.voucher.posted", "consumer": "node-island",
                         "target": {"kind": "http", "url": f"http://127.0.0.1:{consumer_port}/events",
                                    "audience": "node-island"}, "grant_ref": "g"}).raise_for_status()
        httpx.post(f"{stack.bus_url}/events", headers=h,
                   json={"type": "bookkeeping.voucher.posted", "schema": "voucher/v1",
                         "source": "bookkeeping", "trace": {"store": "bk", "ref": "r1"},
                         "data": {"voucherId": "V-7"}, "id": "evt_x"}).raise_for_status()
        # the node consumer prints the received envelope's voucherId on the next line
        line = _readline_with_timeout(consumer.stdout).strip()
        assert line == "V-7"
    finally:
        consumer.terminate()
        stack.stop()
