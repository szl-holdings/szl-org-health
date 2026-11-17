# SZL Public Evidence Topology — architecture and admission plan (2026-11-17)

**Status: source-only candidate, not an operational/production qualification.**
GitHub is source authority. Hugging Face, Cloudflare and PyPI are independently
observed providers; publishing, API reachability, signed provenance, revenue,
and actual scientific evidence must never be collapsed into one green badge.

## Public architectures studied, with independently owned adaptations

| Public reference | Publicly documented pattern | SZL adaptation | What is not claimed |
| --- | --- | --- | --- |
| Palantir Foundry/AIP: https://www.palantir.com/docs/foundry/platform-overview/overview | Typed Objects/Links/Actions; context attached to operational AI; evaluations and lifecycle controls | Evidence nodes/edges with an immutable source identifier and explicit admission, authorization, effect, receipt and post-action readback | No Palantir code, interoperability guarantee, parity or product equivalence |
| Anduril Lattice developer guide: https://developer.anduril.com/guides/concepts/overview | Entities, Tasks and Objects; REST/gRPC interoperability, sensor provenance and task boundaries | A Python API control plane with typed JSON, optional gRPC/Protobuf for sensor-rate transport; explicit action ownership and source-update timestamps/expiry | No Lattice integration, defense-certified system or live control claims |
| NVIDIA Holoscan SDK 5: https://docs.nvidia.com/holoscan/sdk-user-guide/introduction/overview | Typed operator graphs; temporal contracts; compose/compile/run split; separately scoped inference/vision/visualization | Add temporal/size bounds to evidence ingestion and testable graph compilation before authorized execution; use existing GPU-native modules where justified | No Holoscan SDK 5 deployment, timing guarantee, GPU benchmark, or NVIDIA hardware proof |

Use **Python for APIs, audit, orchestration, ML, and reproducible tooling**;
retain TypeScript/React for browser applications, WebGL/WebGPU for capable
3D rendering, and C++/Rust/CUDA/Triton for measured high-throughput kernels.
Do not mechanically convert a tested, source-owned frontend or kernel to Python.

## Five bounded evidence passes (one snapshot, not five blind reruns)

1. **GitHub source truth**: enumerate each accessible repository by exact org
   identity and default branch, preserve archived/private states, capture file
   structure as a declaration only; never infer missing files from a truncated
   Git tree. Private inventory stays in an internal file outside the source
   repository and outside the public HTTP API.
2. **Workflow/CI truth**: count enabled/disabled GitHub Actions definitions,
   retaining per-repository `UNAVAILABLE` on 403/404/rate limits. For a
   bounded high-impact PR and protected-main sample, compare exact head SHA
   and status; a failed older SHA does not make the current SHA red.
   Manual/skipped/neutral jobs are not mandatory-red by default. Native rulesets
   and approvals must be separately checked before any merge.
3. **Frontend/backend contracts and links**: independently test machine-readable
   route schemas, auth and failure shape, link status, HTML/CSP and usable keyboard
   paths. This collector performs only seven allowlisted anonymous HEAD reads;
   browser execution, accessibility and full-site link discovery remain
   independently unverified until the relevant CI/browser lane passes.
   The exact public source-identity JSON URL allows one bounded anonymous GET
   after an observed HEAD 405; this is a method-specific fallback, never an
   inference/payment request or a signed source readback.
4. **HF and Cloudflare publication boundary**: bind exact Git tree,
   artifact digest, HF repository revision, runtime identity, Cloudflare
   route/worker revision, and human-authorized maintenance window through
   separate signed/effective receipts. An HTTP 200 is a transport observation,
   an HTTP 402 is an unpaid challenge, and neither proves a paid settlement.
   `SOURCE_AHEAD`, stale evidence, publisher drift and missing signatures
   remain `HOLD` pending owned repair and post-deploy readback.
5. **PyPI, citations and accounting**: preserve canonical bytes for
   Trusted Publishing workflows, tag-rulesets, package import integrity, wheel
   content, OIDC Sigstore attestations and actual PyPI readback. Kernel-Hub-only
   source must never be relabeled as a qualified wheel. Scientific claims
   require datasets, methods, model revisions and reproducible benchmarks;
   conjectures must not appear as proven theorems.

## Read-only public evidence graph

The new `GET /api/proof-graph` projection is derived **only** from the
existing closed public census, sharing one bounded cached provider collection
with `/api/health` and `/api/portal`. It adds no credential access. The
`/proof-graph` canvas is a dependency-free, self-hosted, interactive 3D
illustration with search, orbit, filters, and exact public source links.

- Solid edges mean *public membership observed*. The three dashed edges
  between GitHub, HF, product and proof mean *parity not established*.
- Nodes are publicly identified repository or Hub records; URLs are
  allowlisted HTTPS, source identity is never inferred from title text.
- An observation older than 24 hours is **UNKNOWN**, not current.
- SHA-256 covers a deterministic public graph representation but is
  explicitly **UNSIGNED**. It is not a signature, a measured artifact
  binding, a certified live digital twin or a production release receipt.
- No input can dispatch CI, merge a PR, release a package, write to HF/CF,
  request inference, initiate a wallet transaction, or change an action.

## Gates to expand the graph beyond this source-only slice

Each promoted relationship needs independent `observer`, `source_revision`,
`target_revision`, `payload_digest`, `signature_verification`,
`observed_at`, `expires_at`, `scope`, `owner`, `action_effect`,
`readback`, and `failure_reason`. Missing evidence remains UNKNOWN/HOLD.
Add signed edge admission only through an independently reviewed schema and
tests, then compare actual provider bytes. Do not add speculative same-SHA
edges across providers with different Git histories.

Investor view should distinguish: **implemented**, **source-tested**,
**CI-passing**, **runtime-observed**, **independently verified**,
**commercially settled**, and **scientifically reproduced**. The current
new graph is a source-topology tool in the first two categories; it does
not assert any of the remaining five.

**Execution:** Run `python -B tools/estate_frontier_readback.py --output
C:/SZL/estate-audit/internal-YYYYMMDD.json --public-graph
C:/SZL/estate-audit/public-YYYYMMDD.json` from an authorized owner machine
with a GitHub CLI connection. Respect the 850-call default cap; results
remain private to that machine. The public projection served from
`/api/proof-graph` never reads that private audit file.
