# Database Catalog Admission v1 — evidence, not authority

**Source-of-truth boundary:** GitHub `szl-holdings` supplies the reviewed *schema contract*, while live Postgres/Neon catalog reads supply independent *observations*. A verified checksum is not a signature, a schema comparison is not an application migration, and a successful query cannot prove a DB is production-ready.

## Why this exists

Kirk Borne's [November 17, 2026 post](https://x.com/KirkDBorne/status/2122490501828059535) highlights [Coder-World04/Complete-System-Design](https://github.com/Coder-World04/Complete-System-Design). That repository is a curated README with case-study links—not a deployable distributed database. Its database, caching, replication, sharding, load balancing, and consistency topics are useful **review questions**. The implementation here is original SZL code, scoped to an observed schema contract.

## Current measured gap (private readback, no credential material)

On November 18, 2026, one authorized **Neon A11oy validation** database was observed with seven Memory Covenant tables and a helper dependent only on user-settable session GUCs. The reviewed A11oy migration already requires `public.memory_context_bindings` and a principal-bound `a11oy_memory_context_matches`. The live validation database lacked the bindings table; this is a **HOLD**, not proof that any customer data was exposed. The private incident is [szl-org-health #372](https://github.com/szl-holdings/szl-org-health/issues/372). Do not apply the corrective SQL on production without independent backup, ownership, and protected migration review.

## Offline source-controlled verifier

`tools/database_catalog_admission.py` reads only explicitly supplied, sanitized JSON files. It never connects to Postgres or Cloudflare, executes SQL, handles credentials, changes provider state, or grants execution authority. It compares reviewed table RLS/force/policy/public-grant/index states and required SQL helper behavior against a bounded read-only `pg_catalog` export. An unavailable, stale, future-dated, malformed, duplicated, source-mismatched, or non-compliant export is refused.

Policy: `governance/database_contracts/memory_covenant_v2.json` pins the exact source migration Git **blob** (not a deployment signature) and eight required table surfaces. The worker-only `memory_outbox` explicitly retains its source-controlled NO FORCE RLS exception. All other base memory tables require forced RLS; context binding uses a reviewed owner-only nonforced state. The helper must be `SECURITY DEFINER` and reference durable principal bindings. No raw tenant identifiers, row payloads, credentials, role names, query text, or business data belong in a catalog fixture.

Input JSON structure (illustrative only; **not** a measured catalog):

```json
{
  "schema": "szl.database-catalog-readback/v1",
  "observed_at": "2026-11-18T00:00:00+00:00",
  "state": "OBSERVED",
  "scope": "NEON_VALIDATION_READ_ONLY",
  "source_binding": {
    "repository": "szl-holdings/a11oy",
    "path": "migrations/20260820_memory_covenant_v2_postmerge_hardening.sql",
    "git_blob_sha1": "162cd077150c58f008b568bb530628ec799ecdff"
  },
  "tables": [{"name":"public.memory_records","rls_enabled":true,"rls_forced":true,"policy_count":1,"public_grants":0,"invalid_indexes":0}],
  "functions": [{"name":"public.a11oy_memory_context_matches","security_definer":true,"binds_principal":true,"references_context_bindings":true}],
  "credentials_recorded": false
}
```

The example intentionally covers one table only; the verifier will refuse it because the complete eight-table contract is not observed.

Run from repository root with a **verified exported catalog**:

```bash
python -I -B tools/database_catalog_admission.py \
  --policy governance/database_contracts/memory_covenant_v2.json \
  --catalog /protected/read-only-catalog.json \
  --output /protected/unique-receipt.json
python -I -B -m unittest discover -s tests -p test_database_catalog_admission.py -v
```

Exit 0 = `CATALOG_MATCH_ONLY` (never production authorization); exit 2 = `HOLD`; exit 3 = input unavailable/invalid. Output uses exclusive file creation to avoid overwriting receipts. CLI reports only typed finding codes and SQL object identifiers, never provider errors or credentials.

### Source-versus-runtime admission remains distinct

- This verifier **trusts neither the provided origin claim nor a reported Git SHA as independent attestation**. It explicitly emits `source_identity_independently_verified=false` and `database_queried_by_this_verifier=false` even when all table checks match.
- Collectors must use *read-only*, least-privilege queries against `pg_class`, `pg_policy`, `pg_index`, and `pg_proc`, with bounded rows/timeouts. Any insufficient privileges must yield `UNAVAILABLE`; do not retry through a broader role.
- For actual runtime admission, require separate authenticated source/owner/connection evidence, the exact protected migration history, validated service role, isolation tests on a disposable database, and independently proved restoration from backup.
- Never run destructive acceptance SQL on production or label a test database as the canonical product store.

### Design insights from the referenced case studies

Use **PostgreSQL as the transactional authority**, transactional outbox with idempotency and fencing, a rebuildable search/vector projection, append-only evidence edges, query-plan/index measurements, bounded cache TTL/invalidation, and independent failure/restore drills. Do not add sharding, a graph database, Kafka, or a vector store simply to add a logo: require a workload and measurable acceptance objective. Preserve observed/unknown/denied states across ingest → store → index → retrieval → API → UI.
