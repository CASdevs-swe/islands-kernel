# Served-kernel deploy checklist (caputventi.com)

Turnkey ordered path for the gated VPS deploy. Authoritative source:
`islands-platform/specs/2026-06-20-kernel-deploy-runbook.md` (decisions locked
2026-06-20). This is the operator's tick-list; the runbook holds the why.

Target: the existing MCP VPS (already runs mcp.smartcharge.nu under pm2). Proxy:
extend the box's existing nginx — no Caddy. Process manager: pm2. Secrets: a
`0600` env file outside any repo.

Reversible build/boot first; the live cutover stays gated to the end.

## 0. Push (precondition) — SATISFIED
- [x] islands-kernel is on `origin/main`, tree clean (the deploy-automation
      commits are already pushed). The host can `git pull` and run `deploy/`.

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

## 7. Gated live cutover — STOP, Sam present. MIGRATE, do NOT re-auth.
- [ ] This is a MIGRATION of the existing Fortnox token, NOT a re-authorization.
      Re-auth revokes the live refresh chain (the Fortnox single-chain finding) —
      one revoked chain and there is no back-out. Do NOT run the served connect
      flow. Follow `migration/cutover_runbook.md` step-for-step: pause writes,
      read the existing token once, seal it into the vault, prove a live read-only
      GET 200 BEFORE deleting anything, repoint bookkeeping (then research +
      snapshot routine) at the served vault over HTTPS. The vault's first refresh
      is the one-way commit; the step-2 backup is the only rollback.

## Rollback
- [ ] Stop the three pm2 services. Bookkeeping falls back to its in-process LOCAL
      vault (verified-healthy). No Fortnox grant is consumed before section 7, so
      nothing irreversible happens during build/boot.
