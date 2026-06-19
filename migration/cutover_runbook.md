# Fortnox live cutover runbook — GATED

Status: spec only. This runbook MUST NOT be executed without explicit, in-session
approval to touch the live Fortnox credential. It runs with writes paused. This
file documents the procedure; writing it changes nothing live.

Touches a live financial credential. The single hazard is the rotating refresh
token: read it exactly once, import it once, never let two processes refresh it.

## Order of operations

1. Pause writes. Stop the bookkeeping launchd agents and any research routine
   that posts to Fortnox. Confirm nothing will call Fortnox during the window
   (no due-runner, no overnight research, no manual session).

2. Read the currently-valid token exactly once from the canonical live file,
   `bookkeeping-engine/.fortnox/tokens.local.json`, capturing `access_token`,
   `refresh_token`, `expires_at`, `scope`. Do NOT trigger a refresh while reading.
   Immediately copy every live token file verbatim to a timestamped on-disk
   backup OUTSIDE any repo (e.g. `~/.fortnox-cutover-backup/<ts>/`, mode 0600):
   bookkeeping `.fortnox/tokens.local.json`, `bokforing/fortnox/tokens.age`, and
   research `bokforing/fortnox/tokens.local.json`. The backup is the rollback
   source of truth; it is never committed and is shredded once the cutover is
   confirmed good.

3. Import into the vault as the single connection
   `(caput-venti, fortnox, 559401-5157)`, `created_by="caput-venti"`,
   `rotation="rotating"`, `app_cred_ref="fortnox"`, using the production backend
   and KEK. Verify `get_access_token(...)` returns the imported access token
   WITHOUT refreshing (token still valid, outside the skew window).

3.5 Live read-only check BEFORE any delete. Using the access token the vault
   just handed out, make one read-only Fortnox API call (e.g.
   `GET https://api.fortnox.se/3/companyinformation`, or `/3/financialyears`)
   with the engine's existing auth header convention. Confirm HTTP 200 and a
   sane body. This proves the imported token authenticates against LIVE Fortnox
   end to end. No writes, no POST. If this call does not return 200, STOP: delete
   nothing, restore from the step-2 backup if anything was moved, and abort.

4. Point both repos at the vault by applying `bookkeeping_adapter.md` and
   `research_adapter.md`. Set `VAULT_URL` (or mount the local backend). Move the
   Fortnox client_id/secret host-side into the vault env (`FORTNOX_CLIENT_ID`,
   `FORTNOX_CLIENT_SECRET`); remove them from the engine repos.

5. Delete old token state:
   - bookkeeping `.fortnox/tokens.local.json` and `bokforing/fortnox/tokens.age`
   - research `bokforing/fortnox/tokens.local.json`
   - remove `_LEGACY_RESEARCH_ENGINE_DIR` / `_resolve_fortnox_file` legacy branch
   Confirm `git status` shows no token files staged in any repo (they are
   gitignored; never commit them).

6. Verify rotation through the vault: drive the access token to the skew window
   (or expire it in a controlled way), confirm the vault performs exactly one
   refresh, persists the rotated refresh token, and both repos keep working.

7. Verify the race is gone: start a bookkeeping call and a research call
   concurrently against the freshly-imported, near-expiry connection; confirm
   exactly one Fortnox refresh happens (the vault access log shows one writer per
   `(org, provider, account)`) and neither repo bricks.

8. Resume writes. Re-enable the launchd agents / routines.

9. Rollback: if anything looks wrong before step 8, restore the token files from
   the step-2 on-disk backup to their original paths, revert the two adapter
   edits, resume. The backup (not the vault) is the rollback source of truth.
   Keep it out of any repo; never commit it; shred it only once the cutover is
   confirmed good (step 7 passed and writes resumed).

## Approval gate

Do not execute steps 1-9 until Sam says, in-session, to do the cutover. Adapter
code edits in the engine repos are committed only after a successful cutover, and
only pushed with explicit OK. Token state is never committed anywhere.
