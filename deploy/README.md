# Served-kernel deploy

Automation for running the three kernel services — identity, vault, bus — on a
host behind Caddy. Authoritative env contract: `docs/kernel-integration.md`
(env matrix + combined boot) and `docs/server-posture-vault.md` (secret custody
+ gated cutover). This directory is the turnkey wrapper around those docs.

## Artifacts

| File | What it is |
|---|---|
| `.env.template` | Every env-matrix var + topology (host/ports/subdomains/ACME). Crown jewels are REQUIRED placeholders. Copy to a 0600 host file; never commit the filled copy. |
| `schemas.json` | Event-data schemas seeded into the served bus (`BUS_SCHEMAS_FILE`). Without it the bus rejects every publish. |
| `ecosystem.config.js` | pm2 process file: one app per service, each binding `127.0.0.1` on its own port. Reads only `KERNEL_ENV_FILE`'s path, never secret values. |
| `run-service.sh` | Per-service launcher pm2 invokes: sources the env file, execs `uvicorn <module>:app`. |
| `Caddyfile` | Auto-TLS on `id./vault./bus.<domain>`, reverse-proxying to the loopback ports. |
| `deploy.sh` | Idempotent deploy: pull → uv sync → state dir → pm2 → health → optional provision → STOP. |
| `dryrun.py` | Local end-to-end proof of the recipe with no VPS and no live Fortnox. |

## Posture

- Services bind loopback only. Caddy terminates TLS and is the only public surface.
- Identity's public JWKS is the sole world-readable endpoint. `/auth/exchange`
  and `/oauth/*` carry their credential in the request body.
- Vault and bus require a kernel JWT (verified in-app against the JWKS); Caddy
  also rejects any request without an `Authorization` header at the edge.
- `KERNEL_SIGNING_SEED` and `VAULT_KEK` are the only crown jewels — host secret
  store / KMS only, never committed or logged. Rotation notes are in the template
  footer and `docs/server-posture-vault.md`.

## Deploy (host)

```sh
cp deploy/.env.template /etc/islands-kernel/kernel.env
chmod 0600 /etc/islands-kernel/kernel.env
# fill KERNEL_SIGNING_SEED + VAULT_KEK from the secret store, set the domains/ports

export KERNEL_ENV_FILE=/etc/islands-kernel/kernel.env
export KERNEL_REPO_DIR=/opt/islands-kernel
deploy/deploy.sh                       # up to the STOP banner
caddy run --config deploy/Caddyfile    # (or `caddy reload`) with the env exported
```

`deploy.sh` stops before any live-money step. Issuing a real Fortnox connection
and the gated cutover are run by a human per `docs/server-posture-vault.md`.

### Optional: provision a principal

Once a connection exists (created via the gated connect flow), set
`KERNEL_PROVISION_CONNECTION` (+ principal/org) in the env file and re-run
`deploy.sh`. It issues one multi-service principal and writes the raw credential
to a `0600` file under the state dir; move it into the secret store and delete.

## Dry-run (local, no VPS, no live Fortnox)

```sh
make dry-run        # or: uv run python -m deploy.dryrun
```

Boots identity + vault + bus as real uvicorn subprocesses on loopback from the
template's env var set, seeds a far-future (no-network) connection and the bus
schema registry, provisions one principal through the real `kernel_provision`
CLI, then runs the smoke: one principal → one JWT (`aud: vault+bus`) → vault
access-token + bus event. Crown jewels are generated fresh per run and discarded.
The same flow runs in CI as `tests/test_deploy_dryrun.py`.
