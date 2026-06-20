"""Local dry-run of the served-kernel deploy recipe.

Boots identity + vault + bus as three real uvicorn subprocesses on loopback,
using the same env var set the deploy templates define, then runs the
kernel-integration smoke end to end:

    one principal -> one JWT (aud: vault+bus) -> vault access-token + bus event

No VPS, no pm2/Caddy, no live Fortnox. The vault connection is seeded with a
far-future token so `get_access_token` returns it without any provider/network
call; the bus schema registry is seeded from deploy/schemas.json. Crown-jewel
values (signing seed, KEK) are generated fresh per run into a 0600 temp env file
and discarded on exit — nothing real, nothing committed.

Run standalone:  python -m deploy.dryrun
Run as a test:   pytest tests/test_deploy_dryrun.py
"""
from __future__ import annotations

import base64
import contextlib
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

REPO = Path(__file__).resolve().parent.parent
TEMPLATE = REPO / "deploy" / ".env.template"
SCHEMAS = REPO / "deploy" / "schemas.json"

ORG = "dryrun-org"
PROVIDER = "fortnox"
ACCOUNT = "000000-0000"
CONN_ID = "conn_dryrun"
PRINCIPAL = "prn_dryrun"
EVENT_TYPE = "bookkeeping.voucher.posted"
ACCESS_PATH = f"/connections/{ORG}%2F{PROVIDER}%2F{ACCOUNT}/access-token"

# The core matrix vars the boot code reads. The dry-run asserts every one of
# these is declared in deploy/.env.template, so the template can't drift from
# what the services actually require.
CORE_VARS = {
    "BIND_HOST", "IDENTITY_PORT", "VAULT_PORT", "BUS_PORT",
    "KERNEL_ISSUER", "KERNEL_JWKS_URL", "KERNEL_KID", "KERNEL_IDENTITY_DB",
    "IDENTITY_BOOT", "KERNEL_SIGNING_SEED",
    "VAULT_BOOT", "VAULT_BACKEND", "VAULT_REQUIRE_KERNEL", "VAULT_AUDIENCE",
    "VAULT_DB", "VAULT_KEK",
    "BUS_BOOT", "BUS_AUDIENCE", "BUS_DB", "BUS_SCHEMAS_FILE",
}


def _template_var_names() -> set[str]:
    names = set()
    for line in TEMPLATE.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            names.add(line.split("=", 1)[0])
    return names


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _gen_seed() -> str:
    from identity.tokens import b64url
    return b64url(os.urandom(32))


def _gen_kek() -> str:
    return base64.b64encode(os.urandom(32)).decode()


def _seed_vault_connection(vault_db_url: str, kek_b64: str, now: float) -> None:
    """Put one connection with a far-future token directly into the vault store."""
    from vault.crypto import SecretboxKeyWrapper
    from vault.store.server import ServerStore
    from vault.model import Connection, Token

    wrapper = SecretboxKeyWrapper(base64.b64decode(kek_b64))
    store = ServerStore(vault_db_url, wrapper)
    store.put_connection(Connection(
        id=CONN_ID, org=ORG, provider=PROVIDER, account=ACCOUNT, scopes=["bookkeeping"],
        app_cred_ref="fortnox",
        token=Token("DRYRUN_ACCESS", "DRYRUN_REFRESH", now + 99999.0, "bookkeeping"),
        rotation="rotating", lease=None, created_by="prn_owner",
        created_at=0.0, updated_at=0.0))


def _provision(env: dict) -> str:
    """Issue one multi-service principal via the real provisioning CLI."""
    out = subprocess.run(
        [sys.executable, "-m", "scripts.kernel_provision",
         "--principal", PRINCIPAL, "--org", ORG, "--connection", CONN_ID,
         "--event-type", EVENT_TYPE, "--granted-by", "prn_owner", "--ttl-days", "1"],
        cwd=str(REPO), env=env, capture_output=True, text=True, check=True)
    return out.stdout.strip()


def _wait_port(port: int, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with contextlib.suppress(OSError):
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        time.sleep(0.1)
    raise RuntimeError(f"port {port} did not open within {timeout}s")


def _wait_jwks(url: str, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        with contextlib.suppress(Exception):
            r = httpx.get(url, timeout=1.0)
            if r.status_code == 200 and r.json().get("keys"):
                return
            last = r.status_code
        time.sleep(0.1)
    raise RuntimeError(f"JWKS not serving at {url} (last status {last})")


def _spawn(module: str, env: dict, port: int, log: Path) -> subprocess.Popen:
    fh = open(log, "w")
    return subprocess.Popen(
        [sys.executable, "-m", "uvicorn", module,
         "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=str(REPO), env=env, stdout=fh, stderr=subprocess.STDOUT)


def run() -> dict:
    # template completeness: every core var the code reads is declared in the template
    missing = CORE_VARS - _template_var_names()
    if missing:
        raise AssertionError(f".env.template missing core vars: {sorted(missing)}")

    id_port, vault_port, bus_port = _free_port(), _free_port(), _free_port()
    issuer = f"http://127.0.0.1:{id_port}"
    jwks_url = f"{issuer}/.well-known/jwks.json"
    seed, kek = _gen_seed(), _gen_kek()
    now = time.time()

    workdir = Path(tempfile.mkdtemp(prefix="kernel-dryrun-"))
    state = workdir / "state"
    state.mkdir()
    identity_db = str(state / "identity.sqlite")
    vault_db = f"sqlite:///{state / 'vault.sqlite'}"
    bus_db = f"sqlite:///{state / 'bus.sqlite'}"

    # 0600 env file written from generated throwaway values (proves the file shape)
    env_file = workdir / "kernel.env"
    env_file.write_text(
        f"BIND_HOST=127.0.0.1\nIDENTITY_PORT={id_port}\nVAULT_PORT={vault_port}\n"
        f"BUS_PORT={bus_port}\nKERNEL_ISSUER={issuer}\nKERNEL_JWKS_URL={jwks_url}\n")
    os.chmod(env_file, 0o600)

    shared = {
        **os.environ,
        "KERNEL_ISSUER": issuer,
        "KERNEL_JWKS_URL": jwks_url,
        "KERNEL_KID": "kid-1",
        "KERNEL_IDENTITY_DB": identity_db,
    }
    identity_env = {**shared, "IDENTITY_BOOT": "1", "KERNEL_SIGNING_SEED": seed,
                    "VAULT_BOOT": "", "BUS_BOOT": ""}
    vault_env = {**shared, "VAULT_BOOT": "1", "VAULT_BACKEND": "server",
                 "VAULT_REQUIRE_KERNEL": "1", "VAULT_AUDIENCE": "vault",
                 "VAULT_DB": vault_db, "VAULT_KEK": kek,
                 "FORTNOX_CLIENT_ID": "dryrun", "FORTNOX_CLIENT_SECRET": "dryrun",
                 "IDENTITY_BOOT": "", "BUS_BOOT": ""}
    bus_env = {**shared, "BUS_BOOT": "1", "BUS_AUDIENCE": "bus", "BUS_DB": bus_db,
               "BUS_SCHEMAS_FILE": str(SCHEMAS), "IDENTITY_BOOT": "", "VAULT_BOOT": ""}

    # seed state BEFORE boot: a far-future connection + one provisioned principal.
    _seed_vault_connection(vault_db, kek, now)
    cred = _provision({**identity_env})
    if not cred:
        raise RuntimeError("provisioning produced no credential")

    procs = []
    try:
        procs.append(_spawn("identity.app:app", identity_env, id_port, workdir / "identity.log"))
        procs.append(_spawn("vault.app:app", vault_env, vault_port, workdir / "vault.log"))
        procs.append(_spawn("bus.app:app", bus_env, bus_port, workdir / "bus.log"))

        _wait_jwks(jwks_url)
        _wait_port(vault_port)
        _wait_port(bus_port)
        for name, p, log in zip(("identity", "vault", "bus"), procs,
                                ("identity.log", "vault.log", "bus.log")):
            if p.poll() is not None:
                raise RuntimeError(
                    f"{name} exited early ({p.returncode}):\n{(workdir / log).read_text()}")

        # ONE exchange -> ONE token carrying both audiences
        r = httpx.post(f"{issuer}/auth/exchange",
                       json={"opaque_token": cred, "audience": ["vault", "bus"]}, timeout=10)
        r.raise_for_status()
        token = r.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # vault: the same token fetches an access token
        rv = httpx.post(f"http://127.0.0.1:{vault_port}{ACCESS_PATH}", headers=headers, timeout=15)
        rv.raise_for_status()
        access_token = rv.json()["accessToken"]
        assert access_token, "vault returned an empty access token"

        # bus: the same token subscribes + publishes one event
        httpx.post(f"http://127.0.0.1:{bus_port}/subscriptions", headers=headers, json={
            "type": EVENT_TYPE, "consumer": "dryrun",
            "target": {"kind": "inprocess", "key": "noop"}, "grant_ref": "g"},
            timeout=10).raise_for_status()
        rb = httpx.post(f"http://127.0.0.1:{bus_port}/events", headers=headers, json={
            "type": EVENT_TYPE, "schema": "voucher/v1", "source": "bookkeeping",
            "trace": {"store": "bk", "ref": "r1"}, "data": {"voucherId": "V-1"},
            "id": "evt_dryrun"}, timeout=10)
        rb.raise_for_status()
        assert rb.json()["deduped"] is False, "bus did not accept the event"

        return {"ports": (id_port, vault_port, bus_port),
                "access_token_prefix": access_token[:8], "event_accepted": True}
    finally:
        for p in procs:
            with contextlib.suppress(Exception):
                p.terminate()
        for p in procs:
            with contextlib.suppress(Exception):
                p.wait(timeout=5)
        with contextlib.suppress(Exception):
            import shutil
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    result = run()
    print("dry-run OK:", result)
