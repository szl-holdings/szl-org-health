# SZL Database Frontier Research — Papers, Code, Mathematics and Implemented Guard

**Research date:** 2026-11-17 (America/New_York); checks continued 2026-11-18 UTC. **Status:** source-only comparative research and a bounded offline admission feature, **not** production deployment or an independently approved database migration.

## 0. Exact referral and research method

Kirk Borne's [2026-11-17 X post](https://x.com/KirkDBorne/status/2122490501828059535) points to [Coder-World04/Complete-System-Design](https://github.com/Coder-World04/Complete-System-Design). It is a **curated index of system-design case studies**, not a novel published database engine or a certified systems design. The research below follows original university/industry publications and upstream open-source source trees. Papers inform measurable constraints; no third-party code or proprietary algorithms are copied into SZL.

## 1. Leaders, primary publications, formulas, and what we actually adopt

| Group / researchers | Original source and GitHub code | Mathematical or operational invariant | SZL adaptation — never confuse with implementing the original system |
| --- | --- | --- | --- |
| **PostgreSQL** — Dan R. K. Ports and Kevin Grittner, SSI | [*Serializable Snapshot Isolation in PostgreSQL* (PVLDB 2012)](https://wiki.postgresql.org/wiki/Serializable) · [PostgreSQL's own SSI design/source](https://github.com/postgres/postgres/blob/master/src/backend/storage/lmgr/README-SSI) | Dangerous serialization-anomaly structure: **T_in --rw--> T_pivot --rw--> T_out**. SSI tracks read/write conflicts and aborts when necessary. A green schema check does not guarantee transactional serializability. | Use Postgres/Neon as the transactional authority; separately test concurrent tenant writes and idempotent outbox transitions under isolation-level contract, not in production. Never infer serializable behavior from RLS policy presence. |
| **Google Spanner** — James Corbett, Jeffrey Dean et al. | [*Spanner: Google's Globally-Distributed Database* (OSDI 2012)](https://research.google/pubs/spanner-googles-globally-distributed-database-2/) · [archival paper](https://research.google.com/archive/spanner-osdi2012.pdf); Google's production core is not open source | `TT.now() = [earliest, latest]`, clock uncertainty **epsilon = (latest - earliest)/2**. A transaction uses commit-wait until **TT.after(commit_timestamp)**. | **Do not claim TrueTime or external consistency**. Separate observation wall-clock age from logical data versions; refuse future/stale timestamps; require independently proven clock bounds before cross-region time-order claims. |
| **Amazon Dynamo** — Giuseppe DeCandia, Werner Vogels et al. | [*Dynamo: Amazon's Highly Available Key-Value Store* (SOSP 2007)](https://www.amazon.science/publications/dynamo-amazons-highly-available-key-value-store) · [original-paper reprint](https://docs.riak.com/riak/kv/2.2.3/learn/dynamo/index.html) · [Riak derived store code](https://github.com/basho/riak_kv) (not Amazon Dynamo's source) | Under fixed intersecting replica sets, the usual quorum intersection condition is **R + W > N**; a majority write quorum often requires **W > N/2**. *Sloppy quorums, hinted handoff and conflict versions can invalidate simplistic strong-consistency claims.* | Keep payment, receipts, authorization and principal-bound memory on a strongly scoped transactional owner; use eventual, replicated cache only for explicitly rebuildable derived data. No speculative Dynamo clone or claimed quorum. |
| **Apple / Snowflake / FoundationDB** — Jingyu Zhou, Meng Xu et al. | [*FoundationDB: A Distributed Unbundled Transactional Key Value Store* (SIGMOD 2021)](https://www.foundationdb.org/files/fdb-paper.pdf) · [Apple FoundationDB source](https://github.com/apple/foundationdb) · [transaction conflict documentation](https://apple.github.io/foundationdb/developer-guide.html) | Conceptual conflict test: **ReadSet(T) intersects WritesCommittedAfter(read_version(T)) = empty**, otherwise abort/retry. Read and commit version are explicitly distinct. FDB uses deterministic fault simulation. | Introduce an independently verified source→outbox→projection ledger and deliberate fault injection in disposable test databases. Retry only safe idempotent transactions; never replay an unknown external side effect. No FoundationDB server deployed. |
| **Materialize / differential dataflow** — Frank McSherry, Derek Murray et al. | [*Differential Dataflow* (CIDR 2013)](https://www.microsoft.com/en-us/research/publication/differential-dataflow/) · [Materialize source](https://github.com/MaterializeInc/materialize) · [formal frontier model](https://github.com/MaterializeInc/materialize/blob/main/doc/developer/platform/formalism.md) | For a *shared comparable logical timeline*, reads are structurally eligible only when **max(since_i) <= v < min(upper_i)** across every required input. `upper` is exclusive; `since` advances as history compacts. | **Implemented now:** `tools/database_causal_frontier.py` calculates the exact intersection, checks all required stages, rejects incompatible timelines, missing catalog approval, stale proofs, and logical-version skew. Output is `STRUCTURAL_FRONTIER_MATCH_ONLY`, **never production authority**. |
| **MIT CSAIL JetStream (2026)** ? Akhilesh Balasingam, Amadou Ngom, Geoffrey X. Yu, Tim Kraska | [*JetStream: Generating Verified Query Accelerators for Existing Database Systems* (arXiv 2610.20527; verify revision)](https://arxiv.org/abs/2610.20527) ? [author-referenced experimental artifact](https://github.com/akhileshvb/accelerator-codegen/tree/artifact) (availability/rights not independently qualified) | For every database state D and parameters p, the generated accelerator should satisfy **A_Q(D,p) = Q_DBMS(D,p)**. With committed delta d, the result must also equal **Q_DBMS(D plus d,p)**. Authors distinguish differential tests from machine-checked proofs. | Preserve the existing DBMS as authority. Propose a separately evaluated, read-only query specialization only after measuring a real costly template; keep generator/optimizer separate from immutable independent tests. No runtime acceleration, code adoption, or formal proof is claimed. |
| **DuckDB** — Mark Raasveldt and Hannes Mühleisen | [*DuckDB: an Embeddable Analytical Database* (SIGMOD 2019)](https://duckdb.org/library/?type=paper) · [source](https://github.com/duckdb/duckdb) | Vectorized processing amortizes operator overhead across batches; execution costs should be measured with scanned rows, latency percentiles and actual memory. The original paper's default vector width is *historical*, not a timeless SLA. | Evaluate DuckDB on sanitized **Parquet snapshots** of receipts only if SQL analytics dominates the tested SQLite projection; benchmark exact corpus, p50/p95 and memory against the existing SQLite code before selecting a second engine. |
| **RocksDB / LSM** — Meta RocksDB maintainers | [RocksDB tuning guide](https://github.com/facebook/rocksdb/wiki/RocksDB-Tuning-Guide) · [engine source](https://github.com/facebook/rocksdb) | **Write amplification = bytes written by storage / bytes ingested**, for matching measurement windows. Leveled compaction trades write amplification for read amplification. | Monitor actual bytes and compaction debt on any *existing* LSM-backed index before tuning; never claim index speed from source filename or add RocksDB without observed workload. |
| **ClickHouse** — Robert Schulze, Alexey Milovidov et al. | [*ClickHouse: Lightning Fast Analytics for Everyone* (PVLDB 2024)](https://www.vldb.org/pvldb/vol17/p3731-schulze.pdf) · [source](https://github.com/ClickHouse/ClickHouse) | Columnar scan, vectorized execution, partition/sort-key pruning. **SZL's prospective measurement**, not a theorem from the paper: fraction scanned = scanned_rows / eligible_rows (same query/corpus). | Only test ClickHouse after measured time-series scan volumes and budgets justify a dedicated OLAP server; keep transactional receipts on Postgres and deterministic source revisions. |
| **Neon (actual connected provider)** — Neon engineering | [Neon open source](https://github.com/neondatabase/neon) · [WAL/pageserver/safekeeper architecture](https://neon.com/blog/how-we-scale-an-open-source-multi-tenant-storage-engine-for-postgres-written-rust) | WAL durability and replay are different from SQL schema readiness. WAL LSN/timelines cannot be silently compared to app receipt ordinal or HTTP timestamps. | Use a disposable Neon branch for forward migration rehearsal, and require an independently tested restore. Present validation vs production connection as separate scopes; no provider schema/network mutation authorized by this research. |
| **Raft / etcd** — Diego Ongaro and John Ousterhout | [*In Search of an Understandable Consensus Algorithm* (USENIX ATC 2014)](https://www.usenix.org/conference/atc14/technical-sessions/presentation/ongaro) · [etcd-io/raft](https://github.com/etcd-io/raft) | For fixed odd-member consensus cluster size N, majority quorum is **floor(N/2) + 1**. Elections and durable replicated log have other safety conditions. | Do not introduce Raft or cross-cloud state replicas until SLA, partition model, membership and tested recovery make them necessary. The existing database is the source of transactional truth. |

### 2026 advanced query specialization ? experimental lane only

JetStream's reported 2026 contribution is to keep native transactional storage while generating query-specific accelerators with externally owned correctness tests and, optionally, machine-checked proofs. Its independent evaluator freezes SQL-derived specifications before the optimizer runs, rather than allowing an agent to change its own test. Updates to committed base data invalidate or repair auxiliary state. The paper reports large TPC-H speedups on its own benchmarks; **no SZL workload has been shown equivalent**.

A future SZL experiment needs one sanitized query template and immutable parameter/data/update fixtures, an unmodified Postgres baseline, isolated candidate worktrees, a separate evaluator owner, mutation rollback cases, and p50/p95/p99 latency and resource evidence. All results must be compared at the **same logical source frontier**. The current verifier is *not* a JetStream implementation, and has *no* Verus-style machine-checked proof. Until real workload, source versions and independent evaluation exist, no SQL accelerator is admitted.

## 2. Actual SZL estate readback vs source-level candidates

An authenticated path-only audit enumerated **174 GitHub records (146 public, 28 private including 3 advisory workspaces), 52,529 file paths, 174 complete tree reads**, with 25 filename-level database candidates. This is **source topology**, not 174 verified live services. Do not publish the identities of private repositories or exposure details in the investor dashboard.

| Existing SZL subsystem | Independently observed vs declared | Decision |
| --- | --- | --- |
| A11oy Memory Covenant v2 | **One Neon validation** project had 7 memory tables, RLS on, 6 forced; `memory_context_bindings` absent and helper not principal-bound. Exact reviewed A11oy correction requires 8 tables plus signed-off security semantics. [Private issue #372](https://github.com/szl-holdings/szl-org-health/issues/372). | **HOLD:** verify intent/history, rehearse migration on disposable branch, assess privileges and backups; do not mutate the source of truth just to make CI green. |
| David Leads | Second accessible Neon project, 17 tables. Three deal-desk tables lacked RLS; the source uses separate schema and runtime-role privileges. Current role-grant effectiveness has not been independently proved. | Verify least-privileged role and table ACLs, and whether the three non-RLS tables are intentionally service-internal. Don't claim a security incident from RLS flags alone. |
| `platform` | Source documentation describes 799+ Drizzle tables and a migration strategy; not established that any current remote database has that many tables. | Review source migration journals vs provider, verify backup-before-migrate, avoid `drizzle push --force` without deliberate review. |
| `nexus` | Source code uses real Neon when `DATABASE_URL` exists and otherwise an **in-memory** PGlite preview. | Label preview data ephemeral; production DB requires independently verified URL, migration, readiness, and recovery. |
| `szl-lake` | Current Python source validates NDJSON ledger heads before and after reading, then builds an **in-memory SQLite** read-only SQL summary. | Preserve its safe source-of-truth boundary; prove larger analytical workload before proposing DuckDB/ClickHouse. |
| `agents-studio` | Source Snowflake reconciliation document says destination readback and writer query ID were missing for an uncertain export. | Preserve `WRITE_UNCERTAIN`; bind query identity/payload digest and read back a *single* outcome before any retry. |

## 3. NEW SZL formula: source-bound causal read frontier

Let each **required** instrumented projection report a trusted-to-its-collector logical interval `I_i = [since_i, upper_i)`. For a single *identical* timeline, the testable **structural** intersection is:

```text
since_global = max_i(since_i)
upper_global = min_i(upper_i)
eligible(read_version v) = AND_i OBSERVED_i
                           AND since_global <= v < upper_global
                           AND max_i(upper_i) - min_i(upper_i) <= skew_limit
                           AND every stage observed within max_age_seconds
                           AND catalog_admission == CATALOG_MATCH_ONLY
                           AND source subject matches the reviewed blob
coverage = observed_required_stages / required_stages
```

The denominator must be positive. The maximum-minus-minimum `upper` difference is measured in **logical versions, not seconds**; cross-database WAL LSNs, wall-clock times, commit IDs and receipt indices are **not** automatically comparable. This is an **original SZL structural control** inspired by Materialize frontiers; it does not implement Materialize's incremental dataflow, PostgreSQL SSI, Spanner TrueTime or FoundationDB's optimistic commit protocol.

Every stage also contains a sanitized source digest and wall-clock observation time. Both are **reported**, not independently signed; the offline script explicitly returns:

```json
{"state":"STRUCTURAL_FRONTIER_MATCH_ONLY","production_authorized":false,
 "effects_authorized":false,"database_queried":false,
 "source_identity_independently_verified":false,
 "stage_digests_independently_verified":false,
 "external_consistency_proven":false,"true_time_available":false}
```

This illustrative status is not the current provider verdict. Real frontiers need source-owned generation IDs captured at the transaction boundary, idempotent outbox replay/cursor receipts, index acknowledgement, API readback, and separately verified catalog and signer provenance. Until these are instrumented, **set stages to `UNAVAILABLE`; never invent `upper` values.**

## 4. Reproduce offline (no provider state changes)

```bash
python -I -B -m unittest discover -s tests -p test_database_causal_frontier.py -v
python -I -B tools/database_causal_frontier.py \
  --policy governance/database_contracts/memory_causal_frontier_v1.json \
  --readback /protected/sanitized-readback.json \
  --output /protected/unique-causal-receipt.json
```

Exit `0` means *structural match only*, exit `2` is HOLD and exit `3` is unavailable/invalid. Receipt output is create-exclusive. The policy is intentionally pinned to A11oy's reviewed corrective migration **blob**, not a pretend live database or a runtime signer. No SQL text, credentials, customer rows, private tenant IDs, model keys or source readback is ever requested by this script.

## 5. Exact production/scale path (not completed)

1. Finish schema/tenant principal-binding drift and role least-privilege checks in a disposable validation branch; backup and restore test first.
2. Implement transactionally durable outbox + monotone source-owned logical generation, with observed conflict/commit behaviour and no replay of uncertain external writes.
3. Wire *bounded, signed or independently verified* source generation → outbox acknowledgement → derived retrieval index frontier → API response generation, with all evidence scoped to the same logical timeline. Do not trust source-reported digests by themselves.
4. Run read-after-write, replay, duplicate message, failover, crash, stale-index and cross-tenant denial tests against isolated fixtures. Measure P50/P95/P99 latency, throughput, actual bytes, write/read amplification, loss window RPO, recovery time RTO and change-data-capture lag on the same controlled workload.
5. Independently observe current protected GitHub source, HF/Cloudflare runtime and database source. Keep migration, model quality, deployment, payment settlement, signed receipts, performance, and production admission as **separate gates**. Only then expose a truthful investor-facing database topology projection.

**Decision:** Add an auditable read frontier to the *existing* evidence stack, not an unneeded new distributed SQL database. New algorithm improves refusal semantics and reproducibility; it does not make the entire estate production-ready.