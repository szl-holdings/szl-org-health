# Open-source frontier scout — proof-carrying adoption, not unattributed cloning

**Observed:** 2026-11-20 02:25:45 UTC. **Lane:** source-only research in szl-org-health. **Coverage:** 12/12 public GitHub repository metadata queries plus five original research papers. This is a bounded sample, NOT a worldwide exhaustive source audit, license opinion, or production qualification. No upstream code was copied.

## Live public GitHub inventory

The values below came from the *public GitHub repository API* on BETTERWITHAGE. \`license.spdx_id\` is automated repository metadata, not independent review of the license file, subdependencies, notices, models or datasets. For all reuse, pin an exact upstream revision, verify the actual LICENSE/NOTICE files and transitive terms, and preserve attribution. **NOASSERTION means HOLD for copying/integration** even if a LICENSE file appears to say MIT/BSD/etc.

| Project | GitHub metadata license | Technique to study | Original SZL experiment (not deployed) |
|---|---|---|---|
| [OpenHands/OpenHands](https://github.com/OpenHands/OpenHands) | MIT | Agent/server/workspace separation | Isolated, source-only coding proposals with no ambient cloud authority |
| [SWE-agent/mini-swe-agent](https://github.com/SWE-agent/mini-swe-agent) | MIT | Issue-based agent benchmarks and bounded tool interfaces | Replayable task fixtures with failure denominators |
| [langchain-ai/langgraph](https://github.com/langchain-ai/langgraph) | MIT | Durable execution, checkpoints and human oversight | Verified-revision resume boundary for evidence |
| [huggingface/smolagents](https://github.com/huggingface/smolagents) | Apache-2.0 | Model-independent agent tools; genuine execution sandbox | Capabilities firewall around Kimi/Mistral proposals |
| [vllm-project/vllm](https://github.com/vllm-project/vllm) | Apache-2.0 | Measurable KV-cache/inference performance | Hardware-budgeted throughput/latency benchmark |
| [in-toto/attestation](https://github.com/in-toto/attestation) | **NOASSERTION — HOLD** | Attestation subject, predicate, envelope separation | Revision-bound proof schemas; do not infer signature from checksum |
| [sigstore/cosign](https://github.com/sigstore/cosign) | Apache-2.0 | Keyless/hardware-backed signing and verification | Independent signing authority, apart from evidence transport |
| [open-telemetry/semantic-conventions](https://github.com/open-telemetry/semantic-conventions) | Apache-2.0 | Cross-stack telemetry semantics | Trace reviewer dissent, source revision, tests and release decision |
| [a2aproject/A2A](https://github.com/a2aproject/A2A) | Apache-2.0 | Interoperability between agents | Typed peer envelopes with provenance and lease verification |
| [modelcontextprotocol/modelcontextprotocol](https://github.com/modelcontextprotocol/modelcontextprotocol) | **NOASSERTION — HOLD** | Interoperable tool contracts | Explicit allowlist/least-privilege tool catalog |
| [open-rmf/rmf_ros2](https://github.com/open-rmf/rmf_ros2) | Apache-2.0 | Robotics fleet scheduling | Simulator-only task contract; physical actuation stays denied |
| [isaac-sim/IsaacLab](https://github.com/isaac-sim/IsaacLab) | **NOASSERTION — HOLD** | Robot simulation and embodied learning | Seeded safety-negative-control simulator experiments |

The upstream project LICENSE may disagree with API-detected SPDX. For example the public IsaacLab LICENSE page identifies BSD-3-Clause while GitHub metadata returned NOASSERTION; **this difference requires file-level review**, not an automatic commercial grant. Papers and research ideas do not carry automatic code/weight/data redistribution permission.

## Primary research and what to test

- [SWE-agent: Agent-Computer Interfaces Enable Automated Software Engineering](https://arxiv.org/abs/2405.15793) — Yang et al., NeurIPS 2024. Evaluate whether constraining the agent/tool interface improves reproducible issue fixes.
- [Efficient Memory Management for Large Language Model Serving with PagedAttention](https://arxiv.org/abs/2309.06180) — Kwon et al., SOSP 2023. Benchmark GPU/CPU memory and serving throughput on *authorized SZL hardware*; paper performance is not SZL performance.
- [ReAct: Synergizing Reasoning and Acting in Language Models](https://arxiv.org/abs/2210.03629) — Yao et al. Distinguish model suggestions from actual tool observations and authorization.
- [Reflexion: Language Agents with Verbal Reinforcement Learning](https://arxiv.org/abs/2303.11366) — Shinn et al. Replay episode/counterexample feedback to measure improvement; this is not evidence of model-weight training.
- [OpenVLA: An Open-Source Vision-Language-Action Model](https://arxiv.org/abs/2406.09246) — Kim et al. Simulation-first robotics; separately clear backbone, checkpoint, dataset and physical-actuation rights and safety.

## Native SZL product differentiation: proof-carrying Ouroboros

The proposal is **not** another unbounded scraper or multi-model consensus wrapper. Build this chain:

\`public research observation → exact upstream revision → rights/attribution review → isolated SZL hypothesis → adversarial counterexample → reproducible benchmark → independent signed owner receipt → separately authorized release\`

Each transition is an independently checked witness, with origin and freshness. The same system should explicitly represent an UNKNOWN or HOLD instead of a green status when no verifier was run. **Kimi/Mistral agreement is not a signer, a CODEOWNER, a legal review or a capacity check.**

### Three commercialization hypotheses (not deployed, no revenue claims)

1. **A11oy Proof API:** consumers pay for replayable provenance/reliability receipts attached to governed inference or research outputs. Measure independently replayable receipts over all eligible outputs; separately prove Cloudflare x402 settlements, not just payment prompts.
2. **SZL Agent Reliability Foundry:** hosted or on-prem agent regression and red-team replay for source-grounded software decisions. Measure counterexample detection, false-pass rate and owner sign-off time.
3. **Simulation-first Embodied A11oy:** evidence-aware digital twins and safe robotics-policy testing. Measure seeded simulation replay and dangerous-action denial before physical robot connections.

Rights-cleared integration and differentiated implementation, not renaming/copying others' software, constitutes SZL's own IP. Pricing, margins, competitive advantage and customer willingness to pay require experiments.

## Source-only intake gate and explicit limitations

This draft includes \`tools/open_source_frontier_gate.py\` and \`tests/test_open_source_frontier_gate.py\`. The stdlib CLI reads a max-16-KiB JSON declaration from stdin, makes **zero** external calls and accepts only exact candidate keys. It rejects duplicate JSON keys/NaN, invalid URLs, missing Git SHA, malformed license hash/path, unsupported or unknown declared SPDX, missing negative tests, stale timestamps and authority-spoofing fields. A structurally valid declaration returns only **RESEARCH_CANDIDATE_ONLY** with every source/rights/signer/test/merge/deploy/training authorization flag false. A malformed declaration returns HOLD, exit 78. The tests are synthetic: no real upstream source SHA or license digest is asserted verified.

This gate **cannot authenticate** source or license digests: an attacker can fabricate a self-consistent hash and must be caught by separately fetching exact upstream bytes and validating provenance. It does not scan transitive dependencies, resolve licenses, execute tests, authorize copying or grant a release. Permissive SPDX declarations are a *triage fast lane* only, not an automatic permission or legal determination; other licenses go to manual counsel/owner review rather than being declared universally incompatible.

### Verification and launch sequence

1. Source-owner and rights review: immutable upstream commit, actual license/NOTICE, dependencies, trademark, patent, separate model/data permissions. Keep original attribution and source history.
2. Reproducibility and security: exact source pin, negative and malformed-input tests, dependency/SBOM and vulnerability triage, isolated sandbox, cost budget, deterministic test replay; reject untrusted agent authority.
3. Operations: consumer workflow smoke, canary, load/soak/failover, error budget and rollback; model READY labels and HTTP 200 are insufficient.
4. Product: accessibility, privacy/security review, documentation, billing/settlement, support, incident response and customer acceptance.
5. Governance: CODEOWNERS + protected CI, source-to-Hugging-Face parity, signed artifacts and human-controlled deployment. Never bypass a protected branch, create duplicate dispatch, start training or edit Flagship54 from this scout.

## Kimi/Mistral peer brainstorming — observed, not an independent audit

At 2026-11-20 02:23 UTC, the existing Ollama API on BETTERWITHAGE was used with **public sanitized prompts** and model aliases \`kimi-k3.1-pro:cloud\` and \`mistral-large-4:cloud\`. Both completed on a second attempt (the initial low-token calls produced no final text). Kimi highlighted license/dependency provenance and nondeterministic tool drift; Mistral highlighted license/provenance drift and nondeterministic agent output. Both suggested replayable proofs tied to versions. These model outputs are *untrusted design proposals*, not proof of model identity, execution, source ownership, test results or code authorization. Cloud prompts may leave the machine; no private files, credentials or lab data were supplied.

**Next bounded iteration:** expand the sample with documented per-repo coverage and publication dates using rate-limited public APIs; validate actual LICENSE contents and exact Git SHAs before considering one original SZL experiment per domain. Honor site rules and do not scrape gated/private material. A 12-project source-metadata census must never be described as a worldwide complete scan.
