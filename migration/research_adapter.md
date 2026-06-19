# research-engine → vault adapter

Status: spec only. Applied during the gated cutover (Task 21), NOT now. No live
token is touched by writing or reviewing this document.

Goal: research-engine reads the *same* Fortnox connection as bookkeeping-engine,
so neither repo owns a token file and the two-writer rotation race is structurally
gone.

## Connection key

Identical to bookkeeping: `(org="caput-venti", provider="fortnox",
account="559401-5157")`. One connection, one writer (the vault).

## Changes in `lib/fortnox.py`

1. Replace token loading in `client()` (currently line ~294). Today it builds a
   `Client` from `Config.load()` + `Tokens.load()` reading `TOKENS_PATH`
   (`tokens.local.json`, line 36). Instead obtain only the access token from the
   vault:

   ```python
   from islands_vault import get_access_token
   access_token = get_access_token(
       org="caput-venti", provider="fortnox", account="559401-5157",
       base_url=os.environ["VAULT_URL"], principal="caput-venti", island="research")
   ```

   For embedded runs, mount the in-process backend and pass `service=` instead of
   `base_url`.

2. Remove the `Tokens.save()` path (line ~77) from the token lifecycle. research
   no longer persists or rotates tokens; the vault does, under its lease.

3. `Config.load()` (line ~52) is unchanged in the engine; the Fortnox client
   secret moves host-side into the vault at cutover. research only needs
   `VAULT_URL` (or the mounted local backend).

## Files retired at cutover

- `research-engine` `bokforing/fortnox/tokens.local.json` (`TOKENS_PATH`)

Gitignored; deleted, not migrated, once the vault holds the imported token
(Task 21 runbook). Because bookkeeping resolves to the same `(org, provider,
account)`, there is exactly one writer afterwards.

## Proof

`tests/test_bookkeeping_adapter.py::test_research_reads_same_connection_key`
pins research to the identical connection key; the `get_access_token(...)` seam is
proven by `test_bookkeeping_would_get_token_from_vault` (same call shape).
