# SZL Open-Source Leader Intake — Cohort 1/10

**Source owner:** szl-holdings/szl-org-health. **Observed:** November 19, 2026 EDT (November 20 UTC). **Authority:** RESEARCH ONLY.

This is a deliberately bounded public-source survey using the existing robots-aware tools/web_evidence.py and GitHub unauthenticated metadata. The new tools/oss_leader_intake.py joins an explicitly pinned upstream commit, source visibility, official documentation receipt, observed license tag, and named SZL source owner. All metadata remains reported, unauthenticated evidence. No third-party source code, model weights, private data, or build artifacts were copied, and no release or reuse has been authorized.

## Ten observed leaders

The first ten upstream repositories were sampled at immutable GitHub-reported SHAs. The initial NVIDIA-Omniverse/IsaacSim URL returned HTTP 301 and was individually recovered using the canonical isaac-sim/IsaacSim repository. The web-evidence collector fetched **8/10** official reference pages with HTTP 200, robots permission and a bounded SHA-256 digest; SGLang's docs redirect failed the approved-host check, while NVIDIA Dynamo's documentation exceeded the response byte budget. Those two remain BLOCKED, not absent.

| Open-source leader | Public GitHub revision (prefix) | Official reference | GitHub license metadata | Proposed SZL experiment |
| --- | --- | --- | --- | --- |
| [OpenSSF Scorecard](https://github.com/ossf/scorecard) | b62c617675f5 | [Scorecard](https://scorecard.dev/) — MEASURED | Apache-2.0 | org-health security control mapping |
| [OpenTelemetry specification](https://github.com/open-telemetry/opentelemetry-specification) | a0c5323bbc7f | [GenAI instrumentation, Nov 2026](https://opentelemetry.io/blog/2026/agent-harness-genai-instrumentation/) — MEASURED | Apache-2.0 | privacy-safe agent traces in szl-mesh |
| [SLSA](https://github.com/slsa-framework/slsa) | 8c3161670b7a | [Build provenance v1.2](https://slsa.dev/spec/v1.2/build-provenance) — MEASURED | NOASSERTION | distinguish source, build and runtime claims |
| [Sigstore Cosign](https://github.com/sigstore/cosign) | 339a3ca85413 | [Verification docs](https://docs.sigstore.dev/cosign/verifying/verify/) — MEASURED | Apache-2.0 | independent signature checks in szl-trust |
| [vLLM](https://github.com/vllm-project/vllm) | 898a7c68c2d1 | [PagedAttention](https://docs.vllm.ai/en/latest/design/paged_attention/) — MEASURED | Apache-2.0 | conservative KV budget in szl-router |
| [SGLang](https://github.com/sgl-project/sglang) | ae69db457eaa | [Official docs](https://docs.sglang.ai/) — BLOCKED | Apache-2.0 | exact prefix-cache witness/negative tests |
| [Hugging Face Hub docs](https://github.com/huggingface/hub-docs) | 37ae8ca81450 | [Model cards](https://huggingface.co/docs/hub/model-cards) — MEASURED | Apache-2.0 | correct cards and training/eval provenance |
| [ROS 2](https://github.com/ros2/ros2) | f6edfcd522ab | [Jazzy docs](https://docs.ros.org/en/jazzy/) — MEASURED | No top-level GitHub license tag returned | lifecycle and simulator-test discipline |
| [NVIDIA Isaac Sim](https://github.com/isaac-sim/IsaacSim) | 9160c0e95d85 | [Isaac docs](https://docs.isaacsim.omniverse.nvidia.com/latest/) — MEASURED | NOASSERTION | simulation-only evidence packets; review Omniverse license |
| [NVIDIA Dynamo](https://github.com/ai-dynamo/dynamo) | 74211ced6370 | [Dynamo docs](https://docs.nvidia.com/dynamo/latest/) — BLOCKED | NOASSERTION | cache/load observations with no falsely measured SLO |

All pins are historical public-GitHub observations, not signed source attestations. License tags are declarations, never legal analysis; missing tags do not prove a repository is unlicensed. These evidence classes overlap, and the candidate tally is not a complete audit of the global OSS ecosystem.

## Complementary stages in existing org-health PR

The already-open org-health PR #396 introduces
tools/open_source_frontier_gate.py for ONE proposed SZL adaptation: exact
declared upstream commit/license-file hash plus a hypothesis and a negative
test. This additional tools/oss_leader_intake.py is deliberately a different,
earlier stage: a bounded MULTI-REPOSITORY evidence census joined to the
existing robots-aware web collector, with per-upstream source and official
reference freshness, explicit blocked pages, and a reported 1/10 pass index.
It cannot verify a license file or a test and does not override the proposal
gate. Combining two unsigned structural records never manufactures a
signature, counsel decision or protected-main approval.

## Original SZL contribution — split evidence/rights gate

**Research evidence** can become REPORTED_RESEARCH_EVIDENCE_REVIEWABLE only with an explicitly known public upstream repo, immutable 40-hex source URL, fresh metadata, and fresh measured official documentation with robots approval and bounded content hash. A missing commit, moving branch URL, stale record, denied robots request, cross-domain redirect, or oversized page remains HOLD. Research status is *not* source authenticity or scientific reproducibility.

**Rights and reuse** always remain INDEPENDENT_HUMAN_RIGHTS_REVIEW_REQUIRED. Neither an Apache-2.0 label, an LLM verdict, nor a hashed HTML response authorizes copying upstream code, model weights, vendor libraries, or commercial redistribution. The output permanently denies code-copy, dependency admission, model training, inference, merge, deployment, monetization, and production readiness. The domain-separated output SHA-256 is structural and unsigned.

All references come from a fixed, reviewed project-to-exact-official-document URL allowlist. The parser forbids unknown fields, duplicate JSON keys, NaN/infinity, unbounded inputs, unsafe URLs, same-host unrelated-document substitution and incoherent HTTP-success/robots states. A later cohort must introduce additional target entries through normal reviewed source changes, not widen the crawler at model discretion.

The local first-pass sample yields **8/10 research-reviewable records, 2/10 evidence HOLD, and 0/10 authorized for reuse**. Passing one cohort does not establish ten completed passes, estate convergence, consumer readiness, training results, settled revenue, or an independently verified signature.

## Peer design review and external research

Kimi (via Ollama cloud model) and Mistral Large 4 independently challenged this approach using *public* brief information. The most important findings were to prevent WebReceipt spoofing from becoming an authentication claim, preserve separate license metadata and rights states, and avoid miscounting repeated candidates across ten cycles. Their suggestions were advisory, not authenticated reviewer approvals.

- [OpenSSF OSPS baseline v2026.08.28](https://baseline.openssf.org/) and [Scorecard](https://scorecard.dev/) motivate dated controls, not blanket certification.
- [SLSA v1.2](https://slsa.dev/spec/v1.2/build-provenance) distinguishes signed build provenance from an arbitrary content digest.
- [OpenTelemetry's 2026 agent instrumentation harness](https://opentelemetry.io/blog/2026/agent-harness-genai-instrumentation/) motivates testable semantic spans while redacting prompts and customer context.
- [PagedAttention](https://arxiv.org/abs/2309.06180) and [SGLang / RadixAttention](https://arxiv.org/abs/2312.07104) motivate prefix reuse but do not prove SZL latency gains or model compatibility.
- [Hugging Face model cards](https://huggingface.co/docs/hub/model-cards) explain metadata, intended uses, limitations and source-attributed evaluations.
- [NVIDIA Isaac Sim license FAQ](https://docs.isaacsim.omniverse.nvidia.com/6.0.0/common/license-faq.html) distinguishes Apache-2.0 simulator source from separately licensed Omniverse Kit/assets; evaluate redistribution rights with counsel.

## Reproduce, no network needed in evaluator

Run the offline module on BETTERWITHAGE against its operator-owned first-pass JSON, using a current independent clock. Retain input/output digests, selected official receipts and exact source version. The parser itself performs no crawling, subprocess, provider, code-fetch, authentication, or publishing.

Tests: python -B -m pytest -q tests/test_oss_leader_intake.py tests/test_web_evidence.py

Next experiment: bridge this closed evidence state to Holo so any 3D robotics/AI claim lacking an independently observed source, artifact, license and signature shows HOLD, not cosmetic green. That visualization is proposed, not shipped or model-safety certified.