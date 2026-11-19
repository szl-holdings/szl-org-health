# Neon Recovery & Security Admission v1

Status: SOURCE-CONTROLLED OFFLINE POLICY. NOT production authorization. No database credentials, business rows, provider IDs, or connection strings belong in this repository.

## Separate from schema admission
The existing Database Catalog Admission (docs/DATABASE_CATALOG_ADMISSION_V1.md) checks the reviewed Memory Covenant schema and catalog readback. This new tools/neon_resilience_admission.py checks provider recovery posture against an operator-provided sanitized metadata observation. Neither substitutes for the other.

Key gaps: short point-in-time-recovery history, a single manual snapshot mistaken for a tested backup program, missing branch protection, unreviewed network exposure, public database grants, and absent restore-drill proof. A snapshot count is not proof of successful recovery. A SHA-256 digest of metadata is not a provider signature.

## Production thresholds

Policy: governance/database_contracts/neon_resilience_production_v1.json.

| Dimension | Gate |
| --- | --- |
| Freshness | OBSERVED within 15 minutes; bounded UTC clock skew |
| Recovery history | At least 7 days |
| Branch | Protected default production branch |
| Snapshot | At least one created in the last 24 hours, not expiring within 48 hours |
| Automatic backups | Provider schedule present |
| Recovery drill | Independently reviewed successful restoration, no more than 30 days old |
| Network | Block public connections, restrict by IP, or record independent exception approval |
| Database access | No public-table privilege grants or unreviewed RLS exceptions |
| Schema source | Separate CATALOG_MATCH_ONLY result from the SQL contract gate |

A public PostgreSQL endpoint with strong authentication can be intentional. The network condition signals an ACCESS REVIEW, not an exploit claim. Table-level RLS exceptions can also be reviewed designs; do not automatically rewrite migrations or break worker-only transactions. The 7-day requirement may exceed Free-tier capabilities and can require owner-approved plan or budget changes. Do not weaken the gate just to label an account green.

Neon plan, PITR, snapshot and scheduled-backup limitations: https://neon.com/docs/introduction/plans .

## Exact private readback contract
Construct ONE bounded JSON document offline from authorized, metadata-only Neon control-plane reads. Do not include user data or project identifiers.

Top-level required keys:
schema, environment, observed_at, source_state, history_retention_seconds, default_branch_protected, snapshots, network, catalog, credentials_recorded.

Snapshots object keys:
count, latest_created_at, latest_expires_at, automatic_schedule_count, last_restore_drill_at.

Network object keys:
public_connections_blocked, ip_allowlist_count, independent_network_exception_approved.

Catalog object keys:
public_table_acl_entries, unreviewed_rls_exceptions, catalog_state.

schema = szl.neon-resilience-readback/v1.
environment = PRODUCTION.
source_state = OBSERVED only for an authorized control-plane observation; otherwise UNAVAILABLE.
credentials_recorded = false exactly.
last_restore_drill_at = null unless a separately approved recovery drill actually succeeded.
catalog_state = CATALOG_MATCH_ONLY only from the independent existing schema verifier; table counts are insufficient.

Run the offline admission from repository root against an owner-private evidence file:

    python -I -B tools/neon_resilience_admission.py --policy governance/database_contracts/neon_resilience_production_v1.json --readback /owner-private-evidence/neon-readback.json
    python -B -m unittest discover -s tests -p test_neon_resilience_admission.py -v

Exit 0: SCOPED_METADATA_MATCH_ONLY (never production authorization).
Exit 2: HOLD.
Exit 3: UNAVAILABLE or malformed input. No input paths, raw SQL, secrets or exception messages are echoed.

The verifier never connects to Neon or runs SQL. Its output always includes production_authorized=false, control_plane_identity_independently_verified=false, and restore_independently_verified_by_this_verifier=false. Preserve the private observation and independently verify source identity.

## Systems to study and adapt
Neon: branch-based migrations, PITR and restore validation. Google SRE: product SLOs and error budgets rather than green dashboards. Temporal: durable retries and idempotent activities. Cloudflare: Zero Trust, mTLS and explicitly reviewed access exceptions. OpenSSF: signed artifact provenance, SBOMs and hardened builds.

Neon https://neon.com/docs/introduction/plans
Google SRE https://sre.google/workbook/implementing-slos/
Temporal https://docs.temporal.io/encyclopedia/retry-policies
Cloudflare https://developers.cloudflare.com/reference-architecture/architectures/security/
SLSA https://slsa.dev/spec/v1.2/

No plan change, backup scheduling, schema mutation, role change, production deployment, IP allowlist modification, or restore is authorized by this offline result. This document intentionally omits account-specific security settings; keep those in private operator records.
