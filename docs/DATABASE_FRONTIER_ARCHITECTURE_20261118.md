# SZL database frontier — architecture and source-bound admission

**Date:** 2026-11-18 UTC · **Classification:** private internal architecture research · **State:** proposed and partly verified, **not** deployed production architecture.

The object of this work is *not* to import every database technology. It is to build an evidence-bound, tenant-safe data plane where a query result, an automated action and its model-derived explanation can be attributed to the exact authorized source and revision.

This read-only `pg_catalog` layer complements the independently source-owned [SZL Database Causal Frontier](DATABASE_LEADERS_AND_CAUSAL_FRONTIER_20261117.md) (merged in governance PR #376). That module checks claimed `[since, upper)` causal stage intervals. Neither module connects directly to a database or is a complete runtime admission authority; the source-owned chain is **catalog SELECT → offline schema HOLD/MATCH → offline causal frontier HOLD/MATCH → separately governed release**, with role, backup, signer and runtime gates still independent.

## 1. Review of leading implementations and their reusable principles

| System / implementation / research | Core mechanism | Original SZL adaptation | Non-adoption gate |
|---|---|---|---|
| [PostgreSQL MVCC / Serializable Snapshot Isolation](https://www.postgresql.org/docs/18/transaction-iso.html) | MVCC and SSI make successfully committed serializable transactions consistent with some serial execution; application must retry serialization failures. | Keep transactional tenant state and authorization in Postgres, and use **read-only repeatable/serializable snapshots** when the same temporal catalog view is required. | Different independent SELECTs must not be presented as one atomic snapshot. No new isolation setting without test. |
| [Neon](https://github.com/neondatabase/neon) and [Neon architecture](https://neon.tech/docs/introduction/architecture-overview) | Stateless compute, safekeeper WAL durability, pageserver materialization, copy-on-write database branching. | Admit schema changes against a disposable, source-bound branch first; keep base-parent/branch identity and recovery point separate from application rollout. | Require owner-approved branch, real migration role, backup/restore proof, and acceptance before production mutation. |
| [Citus distributed PostgreSQL](https://github.com/citusdata/citus) | Tenant-key hash sharding and colocated joins can avoid cross-shard fanout for tenant-scoped transactions. | Standardize tenant + security-domain keys and FK joins in Postgres. Use observed query plans to evaluate co-location *before* adding a distributed coordinator. | No measured cross-node bottleneck or safe shard move: **do not add Citus**. |
| [DuckDB](https://github.com/duckdb/duckdb), [vectorization and morsel-driven scheduling](https://github.com/duckdb/duckdb-web/blob/main/why_duckdb.md) | Vectorized analytical operators and bounded parallel work units. | Candidate for local, pinned Parquet/NDJSON diligence queries over authorized SZL Lake snapshots; current source already has an in-memory SQLite read-only projection. | No canonical snapshot, measured speedup, or rights proof: keep existing ledger authoritative. |
| [ClickHouse MergeTree](https://github.com/ClickHouse/ClickHouse), [parts and sparse indexes](https://clickhouse.com/docs/en/engines/table-engines/mergetree-family/mergetree) | Immutable sorted parts, background merges, sparse indexes and partition pruning. | Candidate for high-volume telemetry aggregates only after ingestion, retention and reproducible performance receipts. | No observed throughput need or replication/egress budget: **do not deploy ClickHouse**. |
| [Materialize](https://github.com/MaterializeInc/materialize), [arrangements](https://materialize.com/docs/fundamentals/concepts/arrangements/), [DBSP paper](https://docs.feldera.com/literature/papers/) | Incremental views update collections using signed multiplicities over logical time. | Model receipt-index updates as append/retract deltas with replay and late-arrival tests, leaving current persistent SQL authoritative. | No ordered authenticated CDC stream: do not claim a live incremental-materialized view. |
| [Apache Iceberg](https://iceberg.apache.org/spec/) | Snapshot metadata pointers advance via optimistic atomic commits; readers keep an immutable snapshot until refreshed. | Design an immutable, content-addressed SZL Lake receipt manifest with expected-parent CAS on future reviewed publication paths. | Hash alone does not authenticate signer or establish independent backup. |
| [pgvector](https://github.com/pgvector/pgvector) | Exact nearest neighbor by default, optional HNSW/IVFFlat trade latency for recall and can lose tenant-filtered candidates. | Keep tenant partitions, rights and exact-match source identity before ANN; compare filtered recall@k with a ground truth reference. | Neither connected Neon project presently has the vector extension installed; this is **not** a license to install it. |
| [CockroachDB](https://github.com/cockroachdb/cockroach) | Replicated Raft key ranges and distributed SQL/transactions. | Adopt the test discipline of failure injection, idempotency, and transactional retries for the SZL-mesh coordination boundary. | Do not replace existing Postgres transaction authority without topology/failure evidence. |
| [Palantir Ontology Actions](https://www.palantir.com/docs/foundry/action-types/overview) and [action authorization](https://www.palantir.com/docs/foundry/action-types/permissions) | Explicit typed actions, submission criteria, transactional changes and authorization boundaries. | Treat every model-proposed database mutation as a typed *governed action* requiring policy, actor authorization, source hash, transaction + outbox, and independently observed readback. | No code from Palantir imported; action records do not grant privilege. |

These are **research references** and infrastructure design candidates, not code dependencies or evidence that those platforms are part of SZL's running stack.

## 2. The architecture to build, from SZL's actual source owners

```text
GitHub protected source and reviewed schema-contract SHA
                 |
        separate owner-owned migration admission
                 |           (Neon branch + backup + role proof)
                 v
  Neon/Postgres ─┴─ transactional RLS / principal-bound authorizations
                 |
                 +--- receipts + transactional outbox (source owner)
                 |         |
                 |         +---- signed/hashed immutable evidence references
                 |                       |
                 |                       v
                 |                  SZL Lake
                 |             manifest / immutable snapshot
                 |                    /             \
                 v            read-only SQL       future CDC/IVM
        controlled API / ACL         |                  |
                 |             source-bound        candidate projections
        a11oy governed actions     analyst
                 |
              Cloudflare verification / settlement — separate acceptance
```

**Source ownership:** `szl-holdings/a11oy` owns Memory Covenant v2 migration and policy semantics. `szl-org-health` owns the *offline, no-provider-write* catalog readback and admission proof. `szl-lake` owns immutable evidence and its read-only SQLite projection. `szl-mesh` owns eventual coordination/replay, not a replacement for ACID tenant isolation. The HF models and Cloudflare payment surfaces do **not** inherit SQL permission merely from source or an HTTP 200.

## 3. Mathematical acceptance and cost model

**Temporal observation:** A DB catalog observation `O = (provider, project, branch, database, t, source_claim, rows, hash)` has explicit source and time. `hash = SHA256(UTF8(canonical_json(O)))` gives byte identity, **not a signature**. Two independent requests at `t1 != t2` are not a transactionally consistent snapshot. For a consistent multi-query readback use a bounded `SERIALIZABLE READ ONLY DEFERRABLE` transaction with a documented executor/owner, not independent connector calls.

**Tenant authorization:** A row is eligible for an action only if `A = identity_bound ∧ policy_allows ∧ tenant_matches ∧ rights_current ∧ source_pinned`. Custom `current_setting` tenant/domain GUCs cannot establish identity by themselves; they are inputs to a check that must also validate the actual session principal against a trusted binding. A SECURITY DEFINER function must lock `search_path`, use reviewed ownership, and have negative-role tests. A boolean substring check from `pg_get_functiondef` is only a *structural lead*.

**Evidence gate:** `G_prod = G_source ∧ G_role_isolation ∧ G_schema ∧ G_backup_restore ∧ G_runtime ∧ G_eval ∧ G_settlement`. In three-valued logic, `UNKNOWN` or `DENIED` in any mandatory gate implies `HOLD`. A standalone `CATALOG_MATCH_ONLY` cannot set any of these gates to production true.

**Incremental view candidate:** For each logical key `k`, `count_t(k) = count_(t-1)(k) + Σ_i delta_i(k,t)`, where `delta` is +1 for a newly admitted record, -1 for a properly authenticated retraction. Idempotency keys and parent revisions prevent duplicate increments. The current SQLite summary is a full bounded replay; this formula is **not yet implemented as a production continuous query**.

**Performance:** Measure `T_request = T_auth + T_plan + T_scan + T_join + T_transfer + T_serialize + T_edge` on each request, then compute p50/p95/p99 empirically from sufficient samples. Do not add component p95 values and call the sum the end-to-end p95. For potential tenant colocations, compare observed shard fanout `F = count(distinct touched_shards)` against one-shard candidate joins. For vector filters, record recall@k relative to exact, tenant-scoped search before tuning HNSW.

**Optimistic publication:** A snapshot change is accepted only when `CAS(expected_parent, new_content_root)` succeeds and a separately trusted signer and remote readback verify the exact bytes. A later GitHub or HF metadata change is not automatically a new SQL rollout.

## 4. New source-delivered connector contract

The adjacent `tools/database_catalog_probe.py` turns the exact, reviewed `governance/database_contracts/memory_covenant_v2.json` policy into **one bounded SELECT** against `pg_catalog`: it reads table RLS/FORCE flags, required policies, invalid indexes, explicit PUBLIC grants, and one known helper's security properties without reading user rows, tokens, role names, tenant identifiers or business payloads.

It produces only the JSON schema consumed by the existing `tools/database_catalog_admission.py` checker. The `source_binding` field is **copied from the supplied policy**, not obtained from the DB — therefore `source_identity_independently_verified = false` regardless of catalog-match. The helper's `binds_principal` field is a **conservative syntactic indication** (SECURITY DEFINER, constrained `proconfig.search_path`, session_user and binding-reference text); it is not a semantic proof that session principals cannot be spoofed or that SQL comments/branches are correct.

From the repository root, generate an exclusive file under private local evidence:

```powershell
python -B -m tools.database_catalog_probe --policy governance/database_contracts/memory_covenant_v2.json --scope NEON_VALIDATION_READ_ONLY --output C:\<private-evidence>\new-read-only-catalog.sql
```

An authorized Neon/PostgreSQL catalog-only connection must execute that *exact* SELECT once, without elevated-role retry, and preserve its returned single JSON cell plus the source/query hashes. Then run the existing offline checker with `--catalog` and `--output`. **Generating SQL is not executing it. Running SELECT is not running the migration.**

## 5. Actual bounded provider observations and required next gates

Between 2026-11-18 01:23:37 and 01:29:20 UTC, connected Neon catalog-only SQL queries observed two accessible projects (separate request timestamps, not a common transaction):

- The A11oy Memory Covenant **validation** project (PostgreSQL 18): seven public memory tables with RLS and six FORCE RLS, no observed invalid indexes, no `memory_context_bindings` table, and the existing helper not SECURITY DEFINER. **HOLD.** This is *not* evidence of a production compromise.
- `david-leads-production` (PostgreSQL 17): 17 public user tables, 14 with RLS, zero FORCE RLS and no invalid public indexes. Those counts **do not prove** a vulnerability: policy, role, ownership and business requirements must first be inspected. No DDL or role change was authorized or performed.
- Neither observed database has `pg_stat_statements` or `pgvector` installed. Avoid blind extension installation or inference about query latency.
- **Crucial role boundary:** the available authenticated Neon *catalog observer* reports `BYPASSRLS=true` and owns all inspected public tables in both projects (7 in the validation DB, 17 in david-leads). The validation DB has one owner-held RLS table without FORCE and david-leads has 14. A privileged catalog connection therefore **cannot be used as evidence that the least-privilege application role is tenant-isolated**, even if the RLS metadata matches. Determine the real app login/role path, owner/BYPASSRLS separation, pool/session impersonation constraints, and negative tenant-access tests before declaring SQL security. This observation does **not** prove the runtime application uses that privileged connection or that tenant records were exposed.
- **Source-controlled runtime guard already exists:** In `szl-holdings/david-leads` protected source, `connect_postgres_ledger` calls `verify_runtime_contract` before returning the connection. That function rejects `rolbypassrls`, superuser/role-create/database-create/replication privileges, privileged role membership, schema CREATE, table ownership and unexpected RLS grants/policies; dedicated tests reject a privileged admin DSN. This materially narrows the source-level concern. **Deployment and actual application DSN-role parity are still unverified**, so the privileged Neon catalog-observer role cannot be assumed to be the service login. Source: https://github.com/szl-holdings/david-leads/blob/main/app/domain/david_postgres.py and https://github.com/szl-holdings/david-leads/blob/main/tests/test_david_postgres_v2.py.

Before migration: verify branch ownership, source migration commit/blob, runtime roles, `search_path`, existing policy bodies, actual dependencies, backup restoration and lease/maintenance window. Validate full source SQL and acceptance tests in a **disposable branch**; preserve a deterministic rollback plan; get required approval for any DDL, grants, role mutations or production changes. After applying a reviewed migration, independently re-read catalog state and test forbidden cross-tenant access under the actual least-privilege role. Keep all user row data and exact provider connection details in private evidence.

## 6. End-to-end acceptance sequence (future implementation, not an accomplished run)

1. Source SHA and migration Git blob verified from protected main; recorded owner and approval.
2. Same-snapshot catalog readback, least-privilege role proof, all required tables/policies/indexes; deny on any unknown.
3. Disposable migration and backup restoration; approved production window only afterward.
4. Read-only ledger replay, exact source/receipt hashes; no duplicates, missing rows, or unowned writes.
5. Tenant isolation negative tests, SQL injection tests, concurrent serializable transactions and retry/idempotency.
6. Measured `EXPLAIN (FORMAT JSON)` without ANALYZE as a safe planning read; separate, authorized load/stress harness for timings; no destructive EXPLAIN ANALYZE on production.
7. SQL-to-API-to-web UI integration and exact provider revision in application runtime, including disabled write paths on unverified identity.
8. Only then Cloudflare authenticated challenge, successful paid fulfillment, settled payment, exact PyPI OIDC/build/source provenance, and public sanitized proof.
9. Re-run after a failure injection, rollback, source update, credential revocation, and loss of one provider; no hidden green fallback.
10. Keep monitoring through existing source owners and schedulers; no competing watcher or duplicate live database.

**No installed add-on database, migrations, new SLA, new production API or new compute claims result from this research.**