# Live PostgreSQL Catalog Collector — bounded, private, read-only

**Status:** Source-controlled collection path for the merged [database catalog admission contract](../governance/database_contracts/memory_covenant_v2.json). It is **not** a migration, a runtime health check, a signer, a cross-tenant authorization proof, or production admission.

## Exact boundary

`tools/postgres_catalog_observer.py` runs **three fixed SELECT statements** inside one PostgreSQL `REPEATABLE READ READ ONLY` transaction: a read-only/least-privilege privilege check, a bounded `pg_catalog` table/RLS/policy/grant/index census, and a bounded `pg_proc` helper-definition read. It never queries user-table rows. The full reconstructed function body is inspected **only in memory**; it is never included in a receipt or log.

It produces two **private, create-exclusive** JSON files, both under an existing directory outside the GitHub source checkout: a sanitized catalog and its outcome from the existing offline `database_catalog_admission.assess`. It uses strict closed fields, limited function names, bounded query and connection timeouts, and refuses unverified inputs. Collection fails if the runtime role has `rolsuper=true`, `rolbypassrls=true`, or the SQL transaction is not read-only.

The collector accepts one credential only through the existing host environment variable **`SZL_DATABASE_AUDIT_DSN`**. This DSN must be a PostgreSQL URI, authenticate to the intended database, require hostname-verified TLS (`sslmode=verify-full`), and use a least-privileged read-only database role. It rejects insecure sslmode, unapproved libpq options/hostaddr/service overrides, unsupported ports, missing credentials, and non-Neon hostnames for a Neon scope. **Never pass a DSN on the command line, in CI logs, issue bodies, receipts, or chat.** The operator establishes this secret in an approved protected runtime outside GitHub.

The collector returns **only** a typed state, observed table/function counts, and a gap count to stdout. It suppresses provider exceptions that could embed hostnames, role names, query text or credentials. There is no automatic credential discovery or provider fallback.

## Run — only in an explicitly configured, authorized environment

```bash
# Python 3.12+, optional Psycopg 3; provision separately from the core org-health app.
# Supply a protected SZL_DATABASE_AUDIT_DSN outside the command/log; never echo it.
python -I -B tools/postgres_catalog_observer.py \
  --policy governance/database_contracts/memory_covenant_v2.json \
  --scope NEON_VALIDATION_READ_ONLY \
  --catalog-output /private/operator/unique-catalog-UTC.json \
  --admission-output /private/operator/unique-admission-UTC.json
python -I -B -m unittest discover -s tests -p test_postgres_catalog_observer.py -v
```

Source-backed contracts: [PostgreSQL 18 pg_policy](https://www.postgresql.org/docs/18/catalog-pg-policy.html), [pg_proc](https://www.postgresql.org/docs/18/catalog-pg-proc.html), and [Psycopg 3 transaction characteristics](https://www.psycopg.org/psycopg3/docs/basic/transactions.html).

The procedure does **not** install Psycopg into the production container. Local operator tooling may use separately pinned `psycopg[binary]`, matching the separately approved dependency lock. If the module is absent it returns `DATABASE_DRIVER_NOT_INSTALLED` (UNAVAILABLE), rather than installing packages at execution time.

## Interpreting the result

- **Exit 0 / CATALOG_MATCH_ONLY:** All *declared* schema fields matched the *observed* metadata. The helper's binding checks are **lexical and structural**, not a formal SQL proof. Source-binding blob identity is taken from the reviewed policy; this collector cannot independently verify which migration actually ran. **Production authorization is always false.**
- **Exit 2 / HOLD:** A valid bounded readback identified missing tables, RLS/forced-RLS drift, policy/grant/index drift or an unmatched context helper. Preserve the HOLD; do not auto-run migrations.
- **Exit 3 / UNAVAILABLE:** Missing/invalid credential, privilege, TLS, provider transport, parser or output preflight issue. No database connectivity should be implied.

The two receipt files are not signed, and an interrupted write can leave a catalog without its companion admission: such a pair is **incomplete**, never a release receipt. Keep local files private; do not publish private project IDs, function definitions, role identities or tenant/customer data.

## Actual SZL remediation

The existing **A11oy Memory Covenant validation project** was observed with seven memory tables but no `memory_context_bindings`, and with a helper that did not match the reviewed principal-binding contract. It is a **validation drift**, not a proven production compromise. Private issue: [szl-org-health #372](https://github.com/szl-holdings/szl-org-health/issues/372).

Next, the authorized database owner must determine whether the validation project is intentionally pinned to an old migration; rehearse the exact reviewed correction on an isolated disposable branch with backup and restore evidence; verify service roles and tenant denies; then independently read back the production branch before any promotion. **This observer cannot authorize any SQL DDL or policy change.**

For the **causal read frontier**, the observed `memory_receipts.seq` is a per-namespace receipt ordinal, while `memory_outbox.generation_id` is text. Neither is a shared source-owned version across ledger → outbox → index → API. Keep all four frontiers **UNAVAILABLE**, and refuse causal-read eligibility until that common lineage is implemented and independently read back.

Do not publish an optimistic public frontend database badge from this private file. Investor display must distinguish **source-tested**, **catalog-observed**, **runtime query verified**, **migration admitted**, **independently attested**, and **production-serving**.