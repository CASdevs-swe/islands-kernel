# bookkeeping-engine → vault adapter

Status: spec only. Applied during the gated cutover (Task 21), NOT now. No live
token is touched by writing or reviewing this document.

Goal: `make_client()` obtains its Fortnox access token from the vault while the
`Client` public surface is unchanged. `Client` stops owning or writing token
files; the vault is the single writer and performs the rotation under its lease.

## Connection key

One connection: `(org="caput-venti", provider="fortnox", account="559401-5157")`,
`app_cred_ref="fortnox"`, `rotation="rotating"`. research-engine resolves to the
same key — one connection, one writer.

## Changes in `lib/fortnox/client.py`

1. Delete the cross-repo fallback — this is the latent brick bug. Remove
   `_LEGACY_RESEARCH_ENGINE_DIR` (currently lines 51-53) and the legacy branch in
   `_resolve_fortnox_file` (lines 71-81). If its own token file is missing today,
   the engine silently starts refreshing research-engine's file and rotates one of
   the two into invalidity.

2. Replace token loading. `make_client()` (line ~607) currently does
   `tokens = Tokens.load()`. Instead obtain only the access token from the vault:

   ```python
   from islands_vault import get_access_token
   access_token = get_access_token(
       org="caput-venti", provider="fortnox", account="559401-5157",
       base_url=os.environ["VAULT_URL"], principal="caput-venti", island="bookkeeping")
   ```

   The `Client` keeps no refresh token. For embedded/local runs, mount the
   in-process backend instead and pass `service=<AccessService>` rather than
   `base_url`.

3. `Client._ensure_fresh()` (line ~347) becomes "ask the vault": call
   `get_access_token(...)` again, which refreshes under the vault's lease if the
   token is at/over the skew window. `Client` no longer calls `_refresh` and no
   longer writes token files. The `Tokens.save()` path (line ~162) is removed from
   the token lifecycle.

4. `Config.load()` (Fortnox client_id/secret) is unchanged in the engine for now;
   the secret moves host-side into the vault's `FORTNOX_CLIENT_ID/SECRET` env at
   cutover. The engine only needs `VAULT_URL` (or the mounted local backend).

## Files retired at cutover

- `bookkeeping-engine/.fortnox/tokens.local.json`
- `bokforing/fortnox/tokens.age` and `token_vault.py`'s standalone path
- the `_LEGACY_RESEARCH_ENGINE_DIR` / `_resolve_fortnox_file` legacy branch

These are gitignored and must never be committed. They are deleted, not migrated,
once the vault holds the imported token (Task 21 runbook, steps 2-5).

## Proof

`tests/test_bookkeeping_adapter.py::test_bookkeeping_would_get_token_from_vault`
exercises the exact `get_access_token(...)` call shape against a fixture vault, no
real Fortnox call.
