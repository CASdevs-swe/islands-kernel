# islands-kernel — working notes

## Contract

The language-neutral HTTP contract is authoritative. This Python package is a thin wrapper; it does not own the protocol. Any other service that integrates the vault does so over HTTP, not by importing this library.

## Boundaries

- Provider network I/O is injectable. Tests stub the provider; production wires the real client.
- Never commit token or secret state: no `.env`, no `*.key`, no `*.age`, no `vault-store/` contents.
- The `.gitignore` at the root covers all secret file patterns — keep it.

## Branch policy

Always work on the current branch. Never create a new branch.

## Structure

```
vault/       — core package
tests/       — pytest suite
docs/        — plan and design documents
```

Served posture: `identity.app:app` (IDENTITY_BOOT) and `vault.app:app`
(VAULT_BOOT) are the uvicorn entrypoints. See `docs/server-posture-vault.md`
for the env contract, secret custody, and the gated live-cutover runbook.
