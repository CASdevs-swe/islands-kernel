# islands-kernel

Slice 1 of the islands platform: connector and credential vault.

The vault stores and retrieves provider credentials (tokens, API keys, secrets) via a language-neutral HTTP contract. Other services consume it over HTTP — they do not link against this package directly.

**Plan:** `docs/superpowers/plans/2026-06-18-connector-vault.md`
**Design spec:** `../islands-platform/specs/2026-06-18-connector-vault-design.md`
