# SZL estate authority and convergence audit — 2026-11-17

**Scope:** bounded, read-only connected GitHub App census, plus targeted source/run
and PR verification. **Admission: HOLD** for any undocumented coverage, protected
merge gate or runtime publisher readback. This note is diagnostic evidence, not a
production report, signed receipt, organization-wide security attestation or
authorization to deploy.

## Observed repository denominator

- Connected GitHub installation: **164 accessible repositories** — **135 active,
  29 archived**. The list is an installation-visible snapshot, not an independently
  complete organization census.
- Three previously named GHSA/advisory repositories return **HTTP 403** for the
  linked integration; no inferred archive/active status or workflow count is assigned
  to those repositories. The earlier 167-repository count and today's 164 accessible
  count must not be silently reconciled as deletions.
- Enabled/disabled workflow definitions: **UNAVAILABLE in this connector readback**.
  GitHub Actions run history is not a definition inventory; no total from an earlier
  observation is refreshed or reused as a live count.
- No private repository identities or private-credential observations are published
  here. No claim that all 164 source trees were code-reviewed.

## One owned authority per concern, without cloning or wholesale cherry-picks

Existing canonical map:
[.github/estate/alignment.v1.json](https://github.com/szl-holdings/.github/blob/de92c7a0f80a858bc6a875b793ad05dbdc47b96a/estate/alignment.v1.json).
It identifies A11oy as product fabric, Hatun as policy veto, the second brain as
memory, SZL Forge as qualification, SZL Serve as serving, SZL Kernels as compute,
SZL Receipt as receipt software, SZL Formulas as formula authority, Anatomy as
anatomy and SZL Frontier as admission.

The **readers/witnesses** are complementary, not competing owners:
- [szl-org-health](https://github.com/szl-holdings/szl-org-health) collects
  dynamic organization evidence with partial and unavailable classifications.
- [szl-pin](https://github.com/szl-holdings/szl-pin) commits to *supplied*
  immutable repository SHAs; a pin is never a claim of census completeness.
- [szl-ci-witness](https://github.com/szl-holdings/szl-ci-witness) retains
  hash-chained test-step receipts; unsigned retention-limited artifacts cannot
  substitute for cryptographic release signatures.
- [lutar-lean](https://github.com/szl-holdings/lutar-lean) is the formal
  mathematics authority. Its locked eight, experimental theorems and open
  uniqueness conjecture must remain distinct.
- [szl-lake](https://github.com/szl-holdings/szl-lake) owns receipt anchoring;
  no simulated append and no duplicate ledger writers.
- [.github](https://github.com/szl-holdings/.github) owns reusable workflow and
  authority manifests, not application runtime.

**Convergence design:** source readers → validated observations → role/policy
veto → immutable per-repo pins → proof/receipt admission → authorized publisher →
post-deploy exact-runtime readback. A passing workflow is a *necessary source
observation*, never sufficient release admission. No copying of entire repos,
duplicate publisher creation, blind workflow reruns or bypass of reviews.

## Specific sampled blockers, with primary run links

| Source | Evidence | Required next action |
| --- | --- | --- |
| `platform@966fb4c71243` | [Deploy — Staging run 44013759754](https://github.com/szl-holdings/platform/actions/runs/44013759754) failed; staging trigger returned HTTP 401 | Recover approved staging authentication, verify separately from source tests. |
| `killinchu@1dc7473e043e` | [Observational GET contracts run 44019577376](https://github.com/szl-holdings/killinchu/actions/runs/44019577376) failed | [PR #637](https://github.com/szl-holdings/killinchu/pull/637) supersedes both attestation-test and vendor-source drift and has 33/33 completed successful PR-run heads; protected-main remains unchanged while merge is blocked. |
| `szl-org-health` | [Earlier PyPI release-path run 43983074558](https://github.com/szl-holdings/szl-org-health/actions/runs/43983074558) failed closed on unverifiable ruleset metadata; later main push did not prove a recovered audit run | Preserve `UNKNOWN`; obtain authorized ruleset readback. Do not disable audit. |
| `a11oy` | Earlier [HF parity run 44019268151](https://github.com/szl-holdings/a11oy/actions/runs/44019268151) had publication lag | Recheck exact current protected main versus Hub artifact and runtime, require signed receipt and permitted publisher window. |
| `.github` | [PR #1025](https://github.com/szl-holdings/.github/pull/1025) has failing required governance checks | Repair metadata and tests, not protections. |

This is a **sample**, not a complete latest-per-workflow survey of all 164
repositories. Reusing historical run URLs here documents observed failures, not
that those historical attempts remain the latest on the current head.

## Cherry-pick and deduplication result

[Killinchu PR #638](https://github.com/szl-holdings/killinchu/pull/638)
was closed **unmerged** as a strict two-file subset of #637. Its head still
failed `vendor-sync-check`, while #637 includes the missing immutable vendor
repair and has 33/33 completed successful PR workflow runs. Closing the
duplicate did **not** change protected main or deploy to HF.

## Operational HOLD and frontier next gate

- Never derive *production ready* from green source CI, old successes, a Space
  RUNNING response, unsigned HF publisher artifacts or an expired receipt.
- Missing required-branch CI status, source head drift, missing signature,
  publisher/runtime mismatch, stale evidence, closed maintenance window and
  inaccessible rulesets remain **HOLD or UNAVAILABLE**, not success.
- Adopt provenance-linked ownership and typed evidence as *interfaces*, not
  wholesale duplicated source code. Experimental Lean proof candidate
  [#369](https://github.com/szl-holdings/lutar-lean/pull/369) remains separate
  until verified and merged under the existing guard.
- This PR tightens a **specific false-green hole** in census logic: a source
  branch with only neutral/skipped workflow outcomes can no longer be graded
  `success`. Required-check interpretation and exact-tip attestation are
  deliberately left for an owned follow-on change.

