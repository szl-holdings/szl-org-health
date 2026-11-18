# SZL Agentic Database — Source-Bound Autonomous Planning (v1)

**Evidence date:** November 17, 2026 (America/New_York); source work continued November 18 UTC. **Release state:** source-controlled offline planner, not a self-modifying database, autonomous DDL engine, authorized production gateway, measured optimizer, or permission to query tenant data.

## Why a DB agent is more than text-to-SQL

The desired loop is **Observe → Diagnose → Propose → Adversarially Verify → Human Admission → Effect → Independent Readback**. This change implements the bounded first four phases using sanitized Postgres catalog and causal-frontier receipts. No LLM gains a database credential. The finite action registry lives in reviewed code, not prompts, and the output is **inert**. Actual database changes, serving and retrieval queries remain outside this capability.

### 2026 leaders: source evidence, strengths, adoption boundaries

| Leader | Observed current public design | Original SZL adaptation | Evidence / limitation |
| --- | --- | --- | --- |
| **DB-GPT** | Agentic data assistant, multi-source planning, tool/skills execution, sandboxed code/SQL. | Use distinct observe/plan/evaluator stages but no arbitrary agent-generated SQL executor. | [eosphoros-ai/DB-GPT](https://github.com/eosphoros-ai/DB-GPT) — upstream self-description; no DB-GPT code has been copied or deployed. |
| **pganalyze Index Advisor** | Deterministic workload and Postgres planner/what-if index selection with write-cost penalties; operator manually benchmarks and applies changes. | Rank bounded *recommendations*, not auto-create indexes or use self-grading LLM claims. Introduce query plan tuning only when a workload trace, baseline and disposable evaluation exist. | [pganalyze Indexing Engine](https://pganalyze.com/docs/indexing-engine), [Getting Started](https://pganalyze.com/docs/index-advisor/getting-started). Its proprietary advisor is **not** embedded here. |
| **Graphiti / Zep** | Episode-sourced temporally invalidated entity/fact edges; hybrid retrieval and explicit temporal filters. | Use append-only, provenance-linked *findings* with observation-time and source revision; never overwrite revoked facts in the source store. Future governed graph only after tenant/temporal enforcement passes. | [getzep/graphiti](https://github.com/getzep/graphiti), [Zep paper](https://arxiv.org/abs/2501.13956). No Graphiti graph is live in this patch. |
| **Mem0** | Atomic memory extraction plus semantic/BM25/entity retrieval and temporal matching in the documented implementation. | Memory summaries may help an analyst, but must never reclassify an old `HOLD` as `VERIFIED`. Require an episode and source digest; retain original SQL catalog as the authority. | [mem0ai/mem0](https://github.com/mem0ai/mem0); managed benchmark claims do not transfer automatically to self-hosted SZL. |
| **LlamaIndex SQL Query Engine** | NL-to-SQL retrieval, with explicit warnings that raw execution must be sandboxed with restricted roles. | No unbounded agent-to-SQL bridge: current plan contains *no SQL text*, tool invocations, credentials or user queries. | [LlamaIndex SQL source](https://github.com/run-llama/llama_index/blob/main/llama-index-core/llama_index/core/indices/struct_store/sql_query.py). |
| **Spider 2.0** | Complex enterprise text-to-SQL workflows spanning real schemas and cloud providers. | Evaluate SQL planning separately on sanctioned synthetic, disposable data, not production; exact success depends on benchmark/version/method. | [xlang-ai/Spider2](https://github.com/xlang-ai/Spider2). |
| **DSABench (2026)** | Harder multi-database routing, coordination and execution tasks; the paper's study reports low end-to-end success despite stronger source identification. | Require explicit source participation/graph and clarification/denial before agent can combine Neon validation, David Leads, Snowflake and receipt ledgers. **This planner is deliberately A11oy-scoped.** | [DSABench paper](https://arxiv.org/abs/2610.14700). Authors' results, not SZL measurements. |
| **Vanna historical source** | Agentic SQL access and per-user-aware permissions, but its original GitHub repository is archived as of March 2026. | Do not adopt an archived repository as a production dependency without independent maintained replacement and security review. | [vanna-ai/vanna](https://github.com/vanna-ai/vanna). |

### Existing SZL truth (read-only source and provider measurements)

Protected GitHub owns the source. The public A11oy migration declares `public.memory_context_bindings` plus a principal-bound `SECURITY DEFINER` helper. The connected **validation** Neon project still reports **seven memory tables, no bindings table, and `SECURITY INVOKER` helper**. The reviewed Postgres catalog guard returned four typed HOLD findings; that is drift in validation, not proof of production compromise. Its role inventory did not establish a least-privilege login role under the conservative current predicate. Separately the four proposed causal stages — source ledger, outbox, retrieval index and API — were **0/4 independently version-verified**. The ledger's namespace sequence and outbox's text `generation_id` do **not** constitute one shared logical timeline. [Private issue #372](https://github.com/szl-holdings/szl-org-health/issues/372), [A11oy version closure issue #3684](https://github.com/szl-holdings/a11oy/issues/3684).

## Implemented: an independently checked finite agent plan

`tools/database_agentic_planner.py` consumes the already-reviewed sanitized outputs of `tools/database_catalog_admission.py` and `tools/database_causal_frontier.py`; optional `szl.database-audit-role-posture/v1` reports only a scoped numeric role-candidate count. All inputs use a closed-schema, duplicate-key rejecting loader and size budgets. Both predecessor policy digests must match **exact** source-controlled policy bytes before a CLI plan can be written. No database connection, LLM, plugin or SQL is launched by this module.

Rules are allowlisted in source and source policy `governance/database_contracts/database_agentic_actions_v1.json`. Possible inert actions include a disposable binding migration rehearsal, restricted auditor-role qualification, source-version instrumentation, outbox fencing, retrieval frontier acknowledgement, API version readback, RLS review and bounded re-observation. Unsupported gap codes trigger **ESCALATE_UNMAPPED_FINDINGS**, never an arbitrary tool call. A separate `verify_plan()` checks the complete action contract, output shape, effect flags, ordering and content hash. Even a plan with a recomputed attacker-chosen hash is refused if the owner/scope/effect contract differs from reviewed rules.

### Original SZL evidence-constrained triage mathematics

Let catalog coverage be `C_cat = min(n_observed, n_required) / n_required`, and causal stage coverage `C_front = n_observed_stages / n_required_stages`. Both are **counts of claimed/observed structures, not security probabilities**. The work queue sorts by **reviewed severity ordinal** and stable action identifier; severity is a deterministic ordering preference, not risk, benefit or expected revenue.

`G_prod = G_source ∧ G_role ∧ G_schema ∧ G_frontier ∧ G_restore ∧ G_eval ∧ G_runtime` under three-valued, fail-closed evidence semantics. A missing or denied input makes `G_prod` **HOLD**. No numeric score can override a failed gate. The current tool **never** computes or grants `G_prod=true`; it can return only `HOLD`, `STRUCTURAL_ONLY`, or `UNAVAILABLE` and always emits `production_authorized=false`.

Plan identity is `H_plan = SHA256(canonical_JSON(plan_without_hash_and_signature_state))`. Hash is only a **structural fingerprint**, never a signature, trusted database measurement, validated wall clock, proof of no data exposure or permission to perform an effect. Input receipt hashes and policy blob are recorded independently; there is no model-internal self-attestation.

### Reproduce (only on an authorized private operator machine)

```powershell
python -I -B -m unittest discover -s tests -p test_database_agentic_planner.py -v
python -I -B tools/database_agentic_planner.py `
  --catalog C:\SZL\edge-debug\<fresh-private-catalog-admission>.json `
  --frontier C:\SZL\edge-debug\<fresh-private-causal-admission>.json `
  --role-posture C:\SZL\edge-debug\<fresh-private-role-posture>.json `
  --policy governance/database_contracts/database_agentic_actions_v1.json `
  --source-policy governance/database_contracts/memory_covenant_v2.json `
  --output C:\SZL\edge-debug\<unique-private-agent-plan>.json
```

Exit `0` = STRUCTURAL_ONLY (still no effect authority); `2` = HOLD; `3` = INVALID/UNAVAILABLE. The output path must be new, outside the repo, and is opened exclusively. Nothing is sent to a public frontend; the CLI emits only sanitized state and counts.

## What would make this a fully operational autonomous database

1. **Repair source/branch divergence correctly:** confirm that the Neon validation branch is intended for the current Memory Covenant release, establish a disposable backup+restore rehearsal, reviewed principal-binding migration, exact SQL role/row policy evidence and fresh nonprivileged catalog auditor. No direct production policy changes from an agent.
2. **Instrument a true shared source epoch:** atomic version assignment at receipt+outbox commit, a durable fenced index-applied watermark, matching API readback and rejection of gaps/replays. Preserve the four-stage causal guard as HOLD until those live values exist.
3. **Read-only observe+plan automation:** extend the existing authorized SZL Database Admission Watch (do not create a duplicate) to feed the same fixed receipts to this planner and send a private action summary only when there is a meaningful changed finding; command execution remains a separate approval path.
4. **Query performance optimization as controlled research:** collect bounded non-PII workload statistics and `EXPLAIN` on a disposable replica. Compare measured read cost versus index write amplification, never use `EXPLAIN ANALYZE` or `CREATE INDEX` automatically against production.
5. **Reproducible agent eval:** evaluate failures on a synthetic data clone—stale/forged digest, clock/timeline mismatch, prompt injection in a field, tenant isolation, idempotency, false graph edge, cross-source selection and outbox replay. Keep model-generated narrative as *commentary*, not authority.
6. **Recovery / capacity:** physical workstation C: is under the 50 GiB capacity gate. Avoid additional Docker/embedding downloads and expensive training/stress until disk hygiene and operator-approved retention/backup reconciliation restore headroom.

**No production DB is installed or migrated by this PR; no automatic SQL writes, tenant reads, Access-policy changes, cloud settlement or model training took place.**