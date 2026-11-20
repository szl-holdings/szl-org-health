# GitHub credential-scope reconciliation

**Purpose:** When the SZL GitHub App and an authenticated workstation CLI
report different repository counts, do not attribute the difference to new
creation, deletions, failed CI, or completeness without proving it.

The existing census promises all repositories **visible to its credential**.
The optional zero-network tool at tools/connector_scope_audit.py compares two
independently timestamped authenticated inventories, without mutation or private
repository name disclosure. It does not replace census/github.py or HF source
binding.

## Input contract and use

Each locally retained private JSON input requires a source value of github_cli
or github_app, observed_at_utc with an explicit UTC offset, and repositories
containing name, archived (boolean), and visibility (public/private), or
a private (boolean) field. Do not commit private input manifests.

    python tools/connector_scope_audit.py --cli private_cli_manifest.json --app private_app_manifest.json --output redacted_report.json

Default inter-snapshot skew is 300 seconds. Larger values are diagnostic only,
not a proof of contemporaneous view or release authority.

Outcome states:
- CONSISTENT_VISIBLE_SETS_NOT_ORG_COMPLETENESS: equal observed sets, which
  does not prove entire-org access.
- SCOPE_OR_INVENTORY_DIVERGENCE: unequal names, visibility, or archive status
  at comparable times; cause unknown (permissions, churn, propagation).
- STALE_SNAPSHOT_UNAVAILABLE: timestamp skew exceeds accepted window.
- UNAVAILABLE: invalid/duplicate/malformed, unknown source or flags, or empty
  inventory.

The report contains **counts only**, with public/private and archive
classifications, timestamp skew, metadata differences, input SHA-256 digests.
No private repo names, credentials, owner secrets, or raw files are emitted.
Organization completeness and enforcement authorization remain unset/false.

## Actual bounded observation, 2026-11-20

A workstation CLI inventory returned **184 repositories**
(155 active / 29 archived / 7 private). The connected App initially returned
181 (4 private), and on another reading returned 182 (5 private).
All views contained 177 public repos. Comparing the earlier CLI and later App
snapshots yielded three CLI-only private names and one App-only private name;
shared metadata flags agreed. The default 5-minute skew rule reported
STALE_SNAPSHOT_UNAVAILABLE. A widened one-hour **diagnostic** reported
SCOPE_OR_INVENTORY_DIVERGENCE, not a confirmed root cause.

Re-observe both views within a short window and verify App installations and
owner-granted access. Do not interpret absent-to-one-client private repos as
deleted, unhealthy, or safe to archive. This tool never changes any privacy,
branch-protection, revocation, Cloudflare, or deployment state.
