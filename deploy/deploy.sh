#!/usr/bin/env bash
# Served-kernel deploy — brings up identity + vault + bus under pm2 behind the
# box's existing nginx (no Caddy; see deploy/nginx.conf.example).
# Idempotent: safe to re-run. It STOPS before any live-money / live-Fortnox step;
# the connect flow and the gated cutover (docs/server-posture-vault.md) are run
# by a human, separately.
#
#   KERNEL_ENV_FILE   path to the 0600 env file (required)
#   KERNEL_REPO_DIR   repo checkout root (default: parent of this script)
#
# Order: preflight -> git pull -> uv sync -> state dir -> pm2 (start|reload)
#        -> health -> [optional] provision principal -> STOP.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="${KERNEL_REPO_DIR:-$(cd "$here/.." && pwd)}"
env_file="${KERNEL_ENV_FILE:-$here/.env}"

log() { printf '\n=== %s\n' "$*"; }
die() { printf 'deploy: %s\n' "$*" >&2; exit 1; }

# ── 0. preflight ────────────────────────────────────────────────────────────
log "preflight"
[[ -f "$env_file" ]] || die "env file not found: $env_file (cp deploy/.env.template and fill it)"
command -v uv  >/dev/null 2>&1 || die "uv not found on PATH"
command -v pm2 >/dev/null 2>&1 || die "pm2 not found on PATH"

# shellcheck disable=SC1090
set -a; source "$env_file"; set +a

# Crown jewels must be real, not the template placeholders.
for v in KERNEL_SIGNING_SEED VAULT_KEK; do
  val="${!v:-}"
  [[ -n "$val" ]] || die "$v is empty — set it from the host secret store"
  [[ "$val" == REQUIRED__* ]] && die "$v still holds the template placeholder"
done
: "${KERNEL_IDENTITY_DB:?}"; : "${VAULT_DB:?}"; : "${BUS_DB:?}"

cd "$repo"

# ── 1. pull ─────────────────────────────────────────────────────────────────
log "git pull"
if [[ -d .git ]]; then
  git pull --ff-only
else
  echo "not a git checkout, skipping pull"
fi

# ── 2. dependencies ─────────────────────────────────────────────────────────
log "uv sync"
uv sync --frozen

# ── 3. state dir (0700) ─────────────────────────────────────────────────────
log "state dir"
# Derive the dir from the sqlite paths in the env (strip the sqlite URL prefix).
state_dir="$(dirname "${KERNEL_IDENTITY_DB#sqlite://}")"
mkdir -p "$state_dir"
chmod 0700 "$state_dir" || true
echo "state dir: $state_dir"

# ── 4. pm2 start / reload (idempotent) ──────────────────────────────────────
log "pm2"
export KERNEL_ENV_FILE="$env_file" KERNEL_REPO_DIR="$repo"
if pm2 describe kernel-identity >/dev/null 2>&1; then
  pm2 reload "$here/ecosystem.config.js" --update-env
else
  pm2 start "$here/ecosystem.config.js"
fi
pm2 save

# ── 5. health: identity JWKS must serve ─────────────────────────────────────
log "health"
jwks="http://${BIND_HOST:-127.0.0.1}:${IDENTITY_PORT:?}/.well-known/jwks.json"
ok=0
for _ in $(seq 1 30); do
  if curl -fsS "$jwks" >/dev/null 2>&1; then ok=1; break; fi
  sleep 1
done
[[ "$ok" == 1 ]] || die "identity JWKS not reachable at $jwks (check: pm2 logs kernel-identity)"
echo "identity JWKS reachable"

# ── 6. optional: provision one principal for an EXISTING connection ──────────
# Only runs if KERNEL_PROVISION_CONNECTION is set. The connection must already
# exist (created via the gated connect flow). The raw credential is written to a
# 0600 file under the state dir, never to stdout/logs.
if [[ -n "${KERNEL_PROVISION_CONNECTION:-}" ]]; then
  log "provision principal"
  : "${KERNEL_PROVISION_PRINCIPAL:?}"; : "${KERNEL_PROVISION_ORG:?}"
  cred_file="$state_dir/${KERNEL_PROVISION_PRINCIPAL}.cred"
  umask 077
  uv run python -m scripts.kernel_provision \
    --principal "$KERNEL_PROVISION_PRINCIPAL" \
    --org "$KERNEL_PROVISION_ORG" \
    --connection "$KERNEL_PROVISION_CONNECTION" \
    --event-type "${KERNEL_PROVISION_EVENT_TYPE:-bookkeeping.voucher.posted}" \
    --granted-by "${KERNEL_PROVISION_GRANTED_BY:-prn_owner}" \
    --ttl-days "${KERNEL_PROVISION_TTL_DAYS:-90}" \
    > "$cred_file"
  chmod 0600 "$cred_file"
  echo "credential written to $cred_file (0600) — move it into the host secret store, then delete"
else
  echo "KERNEL_PROVISION_CONNECTION unset — skipping (no connection to grant against yet)"
fi

# ── STOP ────────────────────────────────────────────────────────────────────
cat <<'STOP'

=== STOP — automated deploy complete ===

The served kernel is up under pm2 behind the box's nginx. The next steps are
LIVE-MONEY actions and are NOT automated. The cutover is a MIGRATION of the
existing Fortnox token, NOT a re-authorization — re-auth revokes the live refresh
chain and there is no back-out. Run with a human present, following
migration/cutover_runbook.md (authoritative) + docs/server-posture-vault.md:

  1. Issue a real service credential and grant `use` on the real Fortnox
     connection. No prod flag flip yet.
  2. Pause writes, read the EXISTING token once, seal it into the vault, and
     prove a live read-only GET 200 BEFORE deleting anything.
  3. Point bookkeeping-engine at the served vault and prove a real Fortnox
     fetch on -> off -> on; then flip research-engine + the snapshot routine.
     The vault's first refresh rotates the imported token — the one-way commit.
     The step-2 on-disk backup is the only rollback.

Do not proceed past this banner from a script.
STOP
