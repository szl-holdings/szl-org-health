# BETTERWITHAGE — Crashpad Read-Only Health Gate

**Status: operational observation; destructive cleanup on HOLD.** Never treat a
UUID filename, age, size, or an unlocked handle as proof that a Crashpad report
is disposable. The Windows Crashpad database tracks **PENDING** and
**COMPLETED** reports in its metadata; the supported database state must be
verified before disposal.

## Measured incident (2026-11-18 UTC)

- C: total: 1,021,821,579,264 bytes.
- C: free at 05:02:34Z: 31,563,763,712 bytes (~29.4 GiB), **below 50 GiB**.
- Edge automation-profile Crashpad reports: **1,364**, totaling ~5.77 GB.
- Reports modified within preceding 10 minutes: **235**.
- Installed Microsoft Edge version: **157.0.4341.60** (05:03 UTC).
- Crash-loop root cause and parent agent ownership: **UNVERIFIED**.
- No verified completed/disposable reports: **0**.
- An audited `crashpad_database_util.exe` was not found on PATH or in the
  installed Edge application tree.

### Historical correction

Older v1 cleanup executions directly unlinked several thousand older
GUID-named `.dmp` files based on heuristic metadata and exclusive-access
checks. Those actions have independent local before/after byte receipts, but
**did not prove** each deleted Crashpad report was in the COMPLETED state.
Their receipts must be retained without rewriting history. No further
heuristic deletion is permitted.

## Current implementation

`tools/crashpad_steward.py` was reduced to a **read-only monitor**.
Its runtime can:
- Verify literal Edge profile path and its directory identity; reject
  reparse points, Git worktrees and missing Crashpad metadata.
- Count UUID `.dmp` files using timestamps and sizes only.
- Collect bounded spaced disk-capacity and report-rate samples.
- Emit explicit `database_states_verified=false`,
  `verified_completed_count=0`, `disposable_count=0`.
- Reject `--execute` with exit 2 and `CRASHPAD_DB_STATE_UNVERIFIED`.

It **cannot** call `unlink`, remove directories, inspect dump contents,
read command-line credentials, inspect browser cookies, stop processes,
change browser policy, alter pagefiles, or mutate any OS, Git, HF or user data.
Read-only invocation:

    python -B tools/crashpad_steward.py --dry-run

The existing hourly SZL Safe Scratch Steward automation was separately
reconfigured to perform read-only monitoring rather than deletion. No
second scheduler or deployment is introduced by this PR.

## Specific next admission steps

1. Identify the owner of the Edge automation session and correlate timestamp
   bursts against sanitized Windows Application Error event identifiers,
   Edge version, and authorized agent run evidence. No browser dump content
   or credentials should be exposed.
2. Obtain a pinned, trustworthy Crashpad database-aware utility and first
   verify PENDING vs COMPLETED states **read-only**. The Chromium reference
   implementation offers `--show-pending-reports` and
   `--show-completed-reports`; it is **not installed** on this machine.
3. Reproduce the failure in a separately authorized isolated browser test
   profile without disturbing active Edge sessions. Correct the agent
   launcher / browser issue at the source.
4. Propose a separately reviewed database-aware cleanup implementation only
   after it proves state, retention, ownership and atomic database/file
   consistency. A raw `.dmp` unlink is not adequate.
5. Hold admission of **new disk-intensive workloads** below the 50 GiB
   C: threshold; do not stop running work or touch OneDrive, pagefile,
   Recycle Bin, worktrees, model weights, Hugging Face caches or receipts.

## Sources

- Crashpad database utility:
  https://github.com/chromium/crashpad/blob/main/tools/crashpad_database_util.md
- Chromium crash report diagnostics:
  https://www.chromium.org/developers/crash-reports/
- Microsoft Edge crash troubleshooting:
  https://learn.microsoft.com/en-us/troubleshoot/microsoft-edge/performance/edge-crashes-fails-to-launch
- Microsoft Edge crash-data privacy:
  https://learn.microsoft.com/en-us/legal/microsoft-edge/privacy

## Evidence preservation

Historical C: receipts:
`C:\SZL\EstateOps\disk-hygiene\2026-11-17\final_verification.json`
and the dated `2026-11-18\crashpad-*.json` local cleanup logs.

The nine unadmitted Khipu/energy ledger files in the
`meter-repair-20261008` residual Git worktree remain on explicit HOLD.
No proof of canonical archival or safe disposal has been established.

**No production restoration, crash root-cause fix, database-state proof,
or disposal authorization is claimed by this PR.**
