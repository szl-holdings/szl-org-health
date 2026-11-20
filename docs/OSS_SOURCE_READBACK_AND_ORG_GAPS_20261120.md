# SZL OSS frontier: exact-revision license readback and organization audit

**Observation window:** 2026-11-20 05:23–05:33 UTC. **Source owner:** szl-holdings/szl-org-health. This is a bounded research/source cycle, not a complete source-code audit of all repositories, legal review, customer-launch certificate, or training authorization.

## GitHub census with denominators

Connected GitHub repository search: page 1 returned 100 records, page 2 returned 79 records. **179 unique search-visible repositories** = **177 public + 2 private**, **150 active + 29 archived**, and all returned default branch main. Independently, anonymous GitHub organization metadata reported **177 public repositories** at 05:32:19 UTC. The historical 181-repository baseline with five private repos differs; the discrepancy is **UNRESOLVED ACCESS/INVENTORY SCOPE DRIFT**, not confirmed deletion. The connector's offset-based list stopped after its first 100, so that result must not be presented as a complete census. This measured coverage is metadata only: no full-repository code, workflow, dependency or license scan was claimed.

## Four highest-risk findings

1. **Staging visibility: security HOLD.** An anonymous Hugging Face API call at **05:32:39 UTC** returned **HTTP 200, private=false, RUNNING** and SHA **cce209a9ee6cd2d6806ddc9833e74934431500c0** for the SZLHOLDINGS constellation staging Space. Protected-source [constellation_targets.py](https://github.com/szl-holdings/szl-constellation/blob/main/tools/constellation_targets.py) declares it **private**; existing [draft PR #56](https://github.com/szl-holdings/szl-constellation/pull/56) records the mismatch. No Space files or protected contents were read. Only the owner can decide intended visibility; no automated access change.
2. **Consumer runtime admission: HOLD.** [A11oy draft PR #3801](https://github.com/szl-holdings/a11oy/pull/3801) repairs compute-pool event-loop blocking. At head 79adcb5109a9a4315b28b322c1ea20739c7c99ae, the 52 returned associated workflows included **48 success, 3 skipped, 1 failed**. The failed check was **HF Space module-drift guard**. Green unit tests cannot replace this.
3. **GPU training lease and paid worker boot: HOLD.** [GPU bridge draft #303](https://github.com/szl-holdings/szl-gpu-bridge/pull/303) addresses non-atomic daemon single-flight locking; [draft #304](https://github.com/szl-holdings/szl-gpu-bridge/pull/304) rejects a known unsafe TRL recipe and floating-main fetch. Both had 3/3 returned associated CI success, but are draft, not deployed or proof of exclusive dispatcher control. No paid/training job was started.
4. **Source and licensing gaps.** The prior 12-upstream scout found three automated GitHub license fields as NOASSERTION. This is neither a blanket prohibition on learning nor permission to copy. Three accessible estate license-remediation PRs remain draft, including owner-controlled private remediation. Separately verify rights, notices, patent/trademark, weights, data and transitive dependencies.

Authenticated Cloudflare settlements, Snowflake workloads, PyPI cryptographic signature validity, source-to-HF full parity, private training rights, consumer conversion and support readiness were **not** verified in this cycle.

## Actual Kimi/Mistral contribution

The authorized BETTERWITHAGE workstation executed public-source-only, sanitized peer-review prompts through existing Kimi K3.1 Pro and Mistral Large 4 Ollama cloud aliases. Both returned finite critiques. Kimi proposed separating caller-declared license hashes from a trusted exact-commit source readback, and found that Python JSON parsing can accept nonfinite exponent literals (for example 1e999) without a parse_float guard. Mistral recommended immutable GitHub source pinning, byte comparison, strict redirect denial, and never granting licensing or deployment authority from evidence matching. These are **untrusted model proposals**, not independent legal, source-code, identity or release attestations. Cloud prompts may leave the workstation; none contained private repo content, credentials or personal records.

## Source-only engineering improvement

This branch adds tools/oss_license_byte_witness.py plus tests/test_oss_license_byte_witness.py. It first requires an accepted *syntactic* candidate from the existing offline gate. Only then may it perform two bounded **public** GitHub API GETs: one resolving the exact immutable commit SHA and one reading the declared root LICENSE/COPYING file at that exact SHA. No credentials, alternate hosts, redirects, subprocesses, source execution, filesystem writes or retries. Network timeout: 8 seconds per request; response cap: 196,608 bytes each; license file cap: 65,536 bytes.

The observer verifies provider-reported commit identity, path/type, base64, byte count, calculated Git blob SHA-1 and calculated SHA-256 against the earlier declaration. Output contains hashes and a pinned public source URL, **not** redistributed LICENSE text. Even a perfect match returns **EXACT_COMMIT_LICENSE_BYTES_MATCH_REVIEW_ONLY** and leaves all rights, signing, dependency, code-copy, merge, deployment and training authorization flags **false**. HTTPS GitHub observations are not independent signature verification, legal interpretation or proof of publisher identity. The Git blob SHA-1 is consistency evidence, not a collision-resistant security signature.

The original offline intake gate is strengthened to reject **all numeric JSON tokens**, including nonfinite exponents, fail predictably on excessive JSON depth and reject an explicitly invalid clock rather than silently substituting the current time.

### Reproducibility

From the repository root, with an authorized, non-secret JSON candidate supplied via stdin:

    python -B -m tools.oss_license_byte_witness < candidate.json
    python -B -m unittest discover -s tests -p test_oss_license_byte_witness.py -v
    python -B -m unittest discover -s tests -p test_open_source_frontier_gate.py -v

Exit 0 from the byte-observer CLI means byte matching for **research only**, never legal approval. Invalid or unavailable observation returns HOLD, exit 78. The network observer is not run in CI; its 25 source tests mock provider readback.

**Executed on BETTERWITHAGE:** 87/87 targeted offline unit tests passed (25 new byte-witness, 29 offline candidate-gate, 33 pre-existing OSS leader-intake tests); Ruff lint and formatting passed on four relevant files. A real public readback of langchain-ai/langgraph at pinned GitHub commit **58a6e1cc5b7dfc3619fc6e7e7573b040d554649b**, root LICENSE **1,072 bytes**, SHA-256 **d9bb52f2e3540d60ff50d8f0f5b6ba649b7fd346948c4c3d086c8afb120763c7**, returned **EXACT_COMMIT_LICENSE_BYTES_MATCH_REVIEW_ONLY** at **05:31:48 UTC**. All legal and merge authorization flags remained false. Both declared and observed license digests were fetched from GitHub; they do not independently certify SPDX obligations.

## Competitive transfer and next admission

Build an **evidence-licensed adoption ledger**, not a scraped/rebranded code pile: exact third-party Git SHA, actual LICENSE/NOTICE byte witness, SBOM/transitive-licenses, OpenSSF Scorecard security posture, signed build provenance where independently available, deterministic reproduction, adversarial counterexamples, and rights-cleared original SZL implementation. Potential offerings are an A11oy Proof API, enterprise Agent Reliability Foundry, and simulator-first embodied A11oy. These are commercialization hypotheses requiring customer, cost and billing experiments.

Reference sources: [SPDX License List](https://spdx.org/licenses/), [OpenSSF Scorecard](https://scorecard.dev/), [SLSA v1.2 provenance](https://slsa.dev/spec/v1.2/build-provenance), and [GitHub Contents API](https://docs.github.com/en/rest/repos/contents). External best practices are references, not SZL certifications.

Next: owner-reviewed intent for the staging visibility mismatch, repair the A11oy HF drift check, qualify the two GPU source PRs without starting jobs, obtain independent source/license and CODEOWNERS reviews, prove real x402 settlement and exact GH→HF source binding before a customer rollout. **Nothing was deployed, trained, deleted, copied from upstream or published to PyPI; Flagship54 was not changed.**
