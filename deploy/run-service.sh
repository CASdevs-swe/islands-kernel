#!/usr/bin/env bash
# Launch one served-kernel service under its env file. Invoked by pm2 (one app
# per service) and by the deploy/dry-run paths. Secrets stay in the 0600 env
# file; nothing is hardcoded here.
#
# Usage: run-service.sh <identity|vault|bus>
#   KERNEL_ENV_FILE  path to the 0600 env file (default: <repo>/deploy/.env)
set -euo pipefail

service="${1:?usage: run-service.sh <identity|vault|bus>}"

# Repo root is the parent of this script's dir — no absolute path baked in.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
cd "$repo"

env_file="${KERNEL_ENV_FILE:-$here/.env}"
if [[ ! -f "$env_file" ]]; then
  echo "run-service: env file not found: $env_file" >&2
  exit 1
fi
# shellcheck disable=SC1090
set -a; source "$env_file"; set +a

case "$service" in
  identity) module="identity.app:app"; port="${IDENTITY_PORT:?}";;
  vault)    module="vault.app:app";    port="${VAULT_PORT:?}";;
  bus)      module="bus.app:app";      port="${BUS_PORT:?}";;
  *) echo "run-service: unknown service '$service'" >&2; exit 1;;
esac

host="${BIND_HOST:-127.0.0.1}"

# Prefer uv if present (matches the deploy recipe); fall back to the venv python.
if command -v uv >/dev/null 2>&1; then
  exec uv run uvicorn "$module" --host "$host" --port "$port"
else
  exec python -m uvicorn "$module" --host "$host" --port "$port"
fi
