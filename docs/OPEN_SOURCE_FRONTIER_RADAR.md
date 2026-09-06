# Open-Source Frontier Radar

The frontier radar turns “find the best open-source software” into a repeatable evidence process rather than a package-installing agent or an undifferentiated list of popular projects.

## Contract

The radar reads an explicit allowlist of official upstream GitHub repositories. For every entry it records:

- the official repository and intended SZL capability;
- the latest non-invented GitHub release, or the latest tag when no GitHub Release exists;
- the exact commit reached by the release tag, including annotated-tag dereferencing;
- repository archive/disable state and recent maintenance evidence;
- SPDX license evidence and a permissive-versus-review-required classification;
- whether the matching capability was observed by the exact-source deep estate audit;
- a bounded deployment plane such as inference, release, telemetry, data, tool, training, or governance.

A missing tag, unresolved commit, ambiguous license, archived upstream, draft or prerelease, stale maintenance signal, or unavailable API response remains `REVIEW_REQUIRED`, `UNKNOWN`, or `INCOMPLETE`. The radar never rewrites uncertainty as approval.

## Initial capability set

The source allowlist covers official projects in these lanes:

| Lane | Representative capabilities |
|---|---|
| Supply chain | Sigstore/Cosign, in-toto, SLSA verifier, Syft, Grype, Trivy, Gitleaks |
| Policy and identity | Open Policy Agent, Kyverno, SPIFFE/SPIRE |
| Observability | OpenTelemetry, Phoenix, Langfuse, Prometheus, Tempo, Loki |
| Evaluation | lm-evaluation-harness, HELM, RAGAS, promptfoo |
| Serving | vLLM, SGLang, llama.cpp, KServe, llm-d, Dynamo |
| Orchestration | Ray, Temporal, Dagster, OpenLineage |
| Training | Transformers, TRL, PEFT, Accelerate, DeepSpeed, Axolotl |
| Retrieval and data | Qdrant, pgvector, LanceDB, DuckDB |
| Agents and protocols | MCP Python SDK, LangGraph, AutoGen, OpenAI Agents SDK |

The list is intentionally source-controlled. New projects require a reviewed code change that names the official upstream repository, capability, role, and deployment boundary. Search-engine popularity, social attention, or an agent-generated name is not enough.

## Adoption states

`ADOPT_CANDIDATE` means only that the current evidence bundle contains an exact release commit, observable maintenance, a non-draft/non-prerelease release, and identifiable license evidence. It does **not** mean the software is installed, vulnerability-free, compatible with the estate, approved by counsel, or safe for production.

`REVIEW_REQUIRED` means at least one use-specific decision remains, including copyleft licensing, maintenance age, tag resolution, release status, or upstream lifecycle.

`UNKNOWN` means the upstream could not be resolved without guessing.

`INCOMPLETE` means the overall run lacked complete upstream evidence.

## No-bandaid adoption gate

Before any candidate is merged into an owning repository, the implementation PR must establish all of the following:

1. Pin the exact upstream commit, package hash, OCI digest, or immutable artifact digest.
2. Verify the license for the intended distribution and deployment mode.
3. Produce or update an SBOM and run secret, source, dependency, and container scans.
4. Define the owning SZL repository and one deployment plane; do not create a duplicate flagship.
5. Add deterministic unit, integration, negative, and rollback tests.
6. Emit OpenTelemetry-compatible traces, metrics, and logs where runtime behavior changes.
7. Preserve tenant, authentication, receipt, policy, and fail-closed boundaries.
8. Benchmark against the current implementation using measured inputs and retained raw results.
9. Merge through the repository’s normal protected checks and verify the deployed source revision.

The radar performs none of these mutations. It produces a review queue and immutable receipt for later, repository-specific implementation waves.

## Runtime placement

The scheduled provider workflow runs the exact-source deep repository audit first. The verified `technology-capability-index.json` then becomes the sole estate-presence input to the radar. The radar outputs:

- `frontier-radar.json` — machine-readable upstream and estate comparison;
- `FRONTIER_RADAR.md` — prioritized human review surface;
- `receipt.json` — hashes, source workflow identity, summary counts, and authority declaration.

The workflow uploads these files as evidence. It does not commit generated snapshots, edit dependency files, open mass pull requests, change Hugging Face assets, touch DNS, or deploy production services.
