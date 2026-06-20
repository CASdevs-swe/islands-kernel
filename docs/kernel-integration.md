# Kernel integration — combined boot reference

Three ASGI services compose into one kernel. Identity signs tokens and publishes
the public JWKS; vault and bus verify kernel JWTs offline against that JWKS and
read grants from the same identity sqlite. One signing key, one JWKS, one
identity store. This is the local multi-process boot reference for the upcoming
VPS deploy. The VPS deploy itself and the gated live-Fortnox cutover are out of
scope here — see `docs/server-posture-vault.md` for the gated cutover runbook.

## Secrets (crown jewels — host secret store / KMS only)

- `KERNEL_SIGNING_SEED` — base64url Ed25519 32-byte seed. Identity only.
- `VAULT_KEK` — base64 32-byte KEK. Vault only.

Generate locally for a throwaway dev kernel (do not commit the values):

    python -c "from identity.tokens import b64url; import os; print(b64url(os.urandom(32)))"   # KERNEL_SIGNING_SEED
    python -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"             # VAULT_KEK

The bus has no own secret; it reuses the served identity store for grant lookups.

## Env matrix

| Variable | identity | vault | bus | notes |
|---|:--:|:--:|:--:|---|
| `IDENTITY_BOOT` / `VAULT_BOOT` / `BUS_BOOT` | gate | gate | gate | set `=1` on the owning service |
| `KERNEL_SIGNING_SEED` | required | — | — | crown jewel |
| `KERNEL_KID` | default `kid-1` | — | — | JWT header `kid` |
| `KERNEL_ISSUER` | required | required | required | same value across all three |
| `KERNEL_JWKS_URL` | — | required | required | `<identity-url>/.well-known/jwks.json` |
| `KERNEL_IDENTITY_DB` | shared | shared | shared | identity writes; vault+bus read grants |
| `VAULT_BACKEND` | — | `server` | — | served single-writer store |
| `VAULT_REQUIRE_KERNEL` | — | `1` | — | turns on JWT + grant checking |
| `VAULT_KEK` | — | required | — | crown jewel |
| `VAULT_DB` | — | required | — | SQLAlchemy sqlite URL |
| `VAULT_AUDIENCE` | — | required | — | this vault's `aud` |
| `BUS_AUDIENCE` | — | — | required | this bus's `aud` |
| `BUS_DB` | — | — | required | SQLAlchemy sqlite URL |

`KERNEL_ISSUER`, `KERNEL_JWKS_URL`, and `KERNEL_IDENTITY_DB` use identical names
across all three services (verified by `tests/test_env_matrix_boot.py`).

## One token, two services

The JWT `aud` is the audience passed to `POST /auth/exchange`. A principal that
talks to both vault and bus exchanges ONCE for `aud: ["vault","bus"]`; pyjwt
verification passes when each service's single expected audience is a member of
that list. The service credential is issued unbound (`audience=None`) so the
exchange may request the audience list. Per-service grants (connection-use,
event-type-use) still gate every action.

## Bring the kernel up (three processes)

Shared env (identity URL fixed first so vault/bus can point `KERNEL_JWKS_URL` at it):

    export KERNEL_ISSUER="http://127.0.0.1:8081"
    export KERNEL_IDENTITY_DB="vault-store/identity.sqlite"
    export KERNEL_JWKS_URL="$KERNEL_ISSUER/.well-known/jwks.json"

Identity:

    IDENTITY_BOOT=1 KERNEL_SIGNING_SEED=<seed> \
      uvicorn identity.app:app --host 127.0.0.1 --port 8081

Vault:

    VAULT_BOOT=1 VAULT_BACKEND=server VAULT_REQUIRE_KERNEL=1 \
      VAULT_KEK=<kek> VAULT_DB="sqlite:///vault-store/vault.sqlite" VAULT_AUDIENCE="vault" \
      uvicorn vault.app:app --host 127.0.0.1 --port 8082

Bus:

    BUS_BOOT=1 BUS_AUDIENCE="bus" BUS_DB="sqlite:///vault-store/bus.sqlite" \
      uvicorn bus.app:app --host 127.0.0.1 --port 8083

## Provision a principal

After a connection exists in the vault, issue one principal that can reach both
services and capture the printed credential into the host secret store:

    python -m scripts.kernel_provision --principal prn_bk --org <org> \
      --connection <connection-id> --event-type bookkeeping.voucher.posted \
      --granted-by <operator-principal-id> --ttl-days 90

`--granted-by` records which operator issued the credential (audit trail).
The credential expires after `--ttl-days` (default 90); rotate it before then,
or pass `--expires-at <epoch>` for an explicit cutoff.

## Proof

The combined posture is proven end to end by `tests/test_kernel_cross_slice.py`
(one principal → one JWT → vault access token + bus publish/consume, org
consistent) and `tests/test_kernel_stack_boot.py` (one JWKS shared by all three).
