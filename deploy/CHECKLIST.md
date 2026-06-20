# Served-kernel deploy checklist (caputventi.com)

Turnkey ordered path for the gated VPS deploy. Authoritative source:
`islands-platform/specs/2026-06-20-kernel-deploy-runbook.md` (decisions locked
2026-06-20). This is the operator's tick-list; the runbook holds the why.

Target: the existing MCP VPS (already runs mcp.smartcharge.nu under pm2). Proxy:
extend the box's existing nginx — no Caddy. Process manager: pm2. Secrets: a
`0600` env file outside any repo.

Reversible build/boot first; the live cutover stays gated to the end.

## 0. Push (precondition, gated on OK)
- [ ] Push islands-kernel. The 7 deploy-automation commits (`89e4488..3f99517`)
      are unpushed; the host cannot run `deploy/` it does not have. Held until
      the go-ahead.

## 1. Host prereqs
- [ ] Python + uv present; pm2 present (already there for the MCP).
- [ ] `git pull` islands-kernel into `/opt/islands-kernel`; `uv sync`.

## 2. Secrets (0600 env file)
- [ ] `cp deploy/kernel.env.caputventi.example /etc/islands-kernel/kernel.env`
      then `chmod 0600`.
- [ ] Generate + install `KERNEL_SIGNING_SEED` and `VAULT_KEK` from the host
      secret store. Never committed, never logged.
- [ ] `export KERNEL_ENV_FILE=/etc/islands-kernel/kernel.env` and
      `KERNEL_REPO_DIR=/opt/islands-kernel`.

## 3. Seed identity
- [ ] `scripts/kernel_provision.py` creates the identity DB. For the rehearsal
      the bookkeeping credential can target a stub; the LIVE Fortnox grant is the
      gated step (section 7), not here.

## 4. Start services (pm2, loopback)
- [ ] `deploy/deploy.sh` — runs up to the hard STOP banner (pull → uv sync →
      state dir → pm2 → health → STOP). Services bind 127.0.0.1 on 8081/8082/8083.

## 5. Reverse proxy (nginx, not Caddy)
- [ ] Confirm the box's ACTUAL layout first: how existing sites are included,
      the real cert/key paths, that mcp.smartcharge.nu stays untouched, and that
      8081/8082/8083 are free on loopback.
- [ ] Add the three server blocks from `deploy/nginx.conf.example`
      (id./vault./bus.caputventi.com), swapping the PLACEHOLDER cert paths for
      the box's real certs.
- [ ] `nginx -t`, then reload (never blind-restart a box serving live MCP).

## 6. Health-check + smoke
- [ ] JWKS reachable over HTTPS at `https://id.caputventi.com/.well-known/jwks.json`.
- [ ] vault up; bus up (401 without an Authorization header, as designed).
- [ ] Smoke over the public URLs: one service principal → one JWT
      (`aud=[vault,bus]`) → fetch a vault token AND publish+consume a bus event
      (the `kernel-integration.md` proof against the deployed URLs).

## 7. Gated live cutover — STOP, Sam present
- [ ] Do NOT proceed past here without the Task-10 stop-and-confirm gates.
      Re-authorize Fortnox through the deployed served connect flow, repoint
      bookkeeping at the served vault over HTTPS, prove on→off→on, accept the
      irreversible first-remote-refresh. Follow the Task-10 prompt; do not improvise.

## Rollback
- [ ] Stop the three pm2 services. Bookkeeping falls back to its in-process LOCAL
      vault (verified-healthy). No Fortnox grant is consumed before section 7, so
      nothing irreversible happens during build/boot.
