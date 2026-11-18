# SZL BETTERWITHAGE disk-hygiene control plane

## Purpose
Keep C: capacity available without treating Git worktrees, scientific data,
models, receipts, credentials, OneDrive, or other user data as disposable.
The safety property is *not* "delete anything with a cache-like name".

## Fixed-scope, test-backed steward
Source: tools/crashpad_steward.py
Contract tests: tests/test_crashpad_steward.py
Run read-only: python -B tools/crashpad_steward.py --dry-run
Run if approved and disk <50 GiB: python -B tools/crashpad_steward.py --execute

The only removal capability is for old, completed, UUID-named ".dmp" files
under C:\SZL\edge-cdp-profile-ops\Crashpad\reports. Reports are generated
automatically by the SZL-specific Edge automation profile. Only files older
than 30 minutes, between 1 KiB and 10 MiB, with unchanged inode/mtime/size
and exclusive-open checks are eligible; the 200 newest eligible-format files
are always preserved. Execution is bounded at 1,200 entries and is serialized
with an exclusive local lock. No recursive deletion or arbitrary path flag.
At or above 50 GiB free the program never executes deletions. Neither dry
run nor execution opens or parses dump contents. The program does not change
the Crashpad process or browser launch settings.

The steward's current release has 17 Windows unit tests: 15 passed and two
symlink-specific tests skipped because this user lacks symlink privileges.
Ruff passed. These results demonstrate local unit behavior, NOT an independent
security audit or operational proof that the Edge crash loop is repaired.

## Evidence
2026-11-17/final_verification.json is the original disk-hygiene source
receipt, timestamped 2026-11-17T14:35:22Z. Preserve it unchanged.
2026-11-18/crashpad-cleanup-*.json record earlier verified manual cleanups.
2026-11-18/crashpad-steward-*.json are small unsigned local tool receipts.
For each cleanup the steward first writes and fsyncs an unsigned PREPARED
intent receipt with candidate-metadata SHA-256, then writes the outcome
receipt after the bounded operation. Neither one proves file content hashes,
signed custody, source admission, or that the Edge crash cause is repaired.

Any HOLD or discrepancy with the receipts requires read-only investigation.
Disk free bytes are sampled directly before and after. Actual observed free
change is not necessarily equal to sum of removed file lengths because other
processes concurrently allocate or release space.

## Current diagnostic gaps
- Hundreds of Crashpad diagnostics were produced in a short interval while
  C: fell below 50 GiB. Root cause is UNVERIFIED. Crashdump retention is a
  capacity mitigation, not a crash fix.
- At 2026-11-18T04:40Z, process metadata showed two msedge.exe root process
  groups, one started around 21:19 local time on Nov 17; no process command
  lines were consulted and neither group is conclusively identified as the
  owner of the Crashpad profile.
- Preserve the nine unadmitted Khipu/energy ledger files in
  <USER_HOME>\szl-work\meter-repair-20261008 until proof of canonical
  ownership, durable copy and verified source admission is established.
- Do not change pagefile.sys or WSL/Docker disk images as a workaround.

## Ongoing task
The existing 'SZL Safe Scratch Steward' recurring automation performs
bounded hourly maintenance when BETTERWITHAGE is accessible. The existing
disk-health automations remain separate and read-only. Never create a
second overlapping scheduler to manipulate the same Crashpad directory.

## Next operational improvement
Diagnose the automation Edge crash/restart loop through non-sensitive
Windows event/error telemetry, deployment/source identity and reproducible
isolated test runs, then roll out a reviewed fix. Do not suppress error
reporting as a substitute for a root-cause fix.