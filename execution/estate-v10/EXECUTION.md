# SZL Estate v10 — Executable Consolidation Program

**Owner:** Stephen Lutar / SZL Holdings  
**Control authority:** `szl-holdings/szl-org-health`  
**Snapshot seed:** 2026-08-29 audit; every mutation must re-observe live state immediately before execution  
**Execution start:** 2026-08-30  
**Commercial product:** A11oy  
**Policy:** protected PRs, exact-head checks, immutable evidence, no destructive migration without parity proof

## Objective

Turn the existing GitHub and Hugging Face estate into one investor-readable, production-operable company:

> A11oy is the governed AI action-assurance platform for consequential enterprise workflows.

The platform, proof front, model factory, kernel release train, evidence registry, owner-GPU bridge, and vertical packages support that product. They are not independent companies.

## Canonical authorities

| Responsibility | Canonical authority |
|---|---|
| Commercial control plane | `a11oy` |
| Product foundation | `platform` |
| Independent proof front | `a11oy-net` |
| Organization policy and reusable workflows | `.github` |
| Private mutation/release authority | `szl-org-health` |
| Model training, evaluation, promotion and publication | `szl-forge` |
| Kernel source, qualification and publication | `szl-kernels` |
| Evidence, datasets and immutable indexes | `szl-lake` |
| Receipt implementation | `szl-receipt` |
| Receipt interoperability specification | `governed-receipt-spec` |
| Formal proof authority | `lutar-lean` |
| Research/papers authority | `szl-papers` |
| Owner-metal GPU execution | `szl-gpu-bridge` |
| Company front door | `szl-holdings.github.io` |
| Investor data room | `pitch-collateral` |

## Non-negotiable execution invariants

1. Never push implementation directly to a protected default branch.
2. Never force-merge a red, stale, unsigned, unreviewed, or unresolved PR.
3. Never archive a repository until source, history, releases, issues, artifacts, citations, and live routes have an evidenced successor.
4. Never label a model supported or production from a development split, README claim, build result, or successful import alone.
5. Never label a kernel operational without exact revision, reference equivalence, device/dtype/shape support, failure boundaries, benchmark receipt, signed artifact and publication readback.
6. Never treat a Hugging Face Space “Running” badge as production evidence; probe health, readiness, exact source, persistence, restart, dependency failure and rollback.
7. Never print or copy secret values. Record only owner, consumer, scope, rotation date and revocation evidence.
8. Every mutation produces a durable receipt containing actor, exact before/after SHA, tests, checks, deployment observation, rollback and timestamp.
9. Every public claim must resolve to measured evidence, a bounded modeled statement, or an explicit unknown/roadmap state.
10. The audit controller remains read-only. Execution occurs through dedicated branches, workflows and reviewed pull requests.

## Estate target

The audit seed contains 98 GitHub repositories: 20 retained public authorities, five retained private controls, 39 migrate-then-archive candidates, and 34 existing archives retained as history.

### Retain as active public authorities (20)

`platform`, `.github`, `a11oy`, `lutar-lean`, `killinchu`, `hatun-mcp`, `szl-lake`, `szl-papers`, `szl-energy-attest`, `szl-receipt`, `immune`, `szl-holdings.github.io`, `governed-receipt-spec`, `szl-forge`, `szl-quant`, `szl-quant-witness`, `a11oy-net`, `szl-gpu-bridge`, `szl-kernels`, `szl-khipu`

### Retain as private controls/incubators (5)

`pitch-collateral`, `szl-org-health`, `gdw-frontier`, `szl-estate-os`, `szl-defensive-control-plane`

### Migrate, prove parity, then archive (39)

`szl-trust`, `szl-brand`, `khipu-consensus`, `szl-doctrine`, `anatomy`, `yarqa`, `khipu-sda-core`, `szl-governed-norm`, `szl-lambda-gate`, `governed-inference-meter`, `szl-substrate`, `szl-guardrail-receipt`, `evidence-doctrine`, `sda`, `szl-receipt-attn`, `szl-maskmod`, `szl-block-kv`, `szl-serve`, `szl-govsign`, `szl-blocked`, `szl-provctl`, `szl-invariants`, `szl-ouroboros`, `szl-formulas`, `YARQA-ATTN`, `szl-nemo`, `nexus`, `ayllu`, `szl-sovereign-os`, `szl-real-estate`, `a11oy-factory`, `szl-second-brain`, `puriq-live`, `szl-command-lab`, `szl-drift`, `lyte-services`, `evidence-studio`, `szl-frontier`, `lyte-lattice`

### Preserve as immutable history (34)

`ouroboros`, `szl-cookbook`, `vsp-otel`, `szl-otel-mesh`, `szl-uds-deployment`, `docs-site`, `uds-bundles`, `lean-kernel`, `developers`, `warhacker-demo`, `szl-mesh`, `szl-fleet-overlay`, `szl-build-env`, `szl-router`, `david-leads`, `szl-formula-ledger`, `energy-attest-holo`, `governed-norm-holo`, `lambda-gate-holo`, `receipt-chain-live`, `szl-provctl-live`, `szl-kernels-live`, `evidence-typed-formula-governance`, `fail-closed-governed-ai-services`, `szl-telemetry`, `szl-organ-integrity`, `szl-atelier`, `szl-experiments`, `counsel`, `khipu-lab`, `cosmos`, `immune-lattice`, `khipu-pages`, `holographic-unify`

## Hugging Face target

Seed inventory: 43 model-namespace artifacts, 28 datasets, 14 kernels, seven Spaces, 18 collections and one storage bucket.

Regenerate the information architecture as five journeys:

1. Supported Models & Derivatives
2. Data, Evaluations & Outcomes
3. Software, Kernels & Verifiers
4. Product & Pilot Spaces
5. Research, Failures & History

The model namespace must contain actual weights/derivatives only. Software, kernels, recipes, surrogate cards and historical mirrors must be reclassified without erasing history.

## Gate sequence

### G0 — Live truth and admission freeze

- Regenerate GitHub and Hugging Face inventory from live APIs.
- Compare live assets to the seed audit and record drift.
- Add an admission registry requiring user/buyer, accountable owner, canonical parent, license/data rights, threat model, SLO, support plan, test/evaluation plan and sunset.
- Block net-new public repositories, models, datasets, Spaces, kernels and collections that are not admitted.
- Generate public counts and product cards from the canonical manifest.

**Exit:** one machine-readable inventory; zero unclassified assets; no hand-maintained public counts.

### G1 — Green protected delivery

- Repair existing red default-branch baselines before merging dependent PRs.
- Standardize aggregate CI gates: clean clone, format/lint/typecheck, unit/integration/e2e, accessibility, security, secrets, dependency/license, SBOM, provenance, exact-source deployment preview and claim drift.
- Require resolved conversations, exact-head checks and signed commits.
- Replace unrestricted permanent bypass with expiring break-glass receipts.

**Exit:** protected branches reject red/stale/unsigned heads; emergency use is time-bounded and auditable.

### G2 — Repository convergence

For every migrate-then-archive repository:

1. Freeze net-new feature work.
2. Identify canonical destination and owning package.
3. Preserve git history, tags, releases, issues, citations and license attribution.
4. Migrate source/tests/docs/receipts.
5. Prove API/CLI/import/route/artifact parity.
6. Publish successor pointer and final immutable tag.
7. Disable misleading workflows, badges, deployment claims and duplicate front doors.
8. Archive only after live/readback evidence is sealed.

**Exit:** 20 active public authorities and five private controls; no deleted history; all old URLs have truthful successors.

### G3 — Models

Implement fail-closed promotion:

`ROADMAP -> EXPERIMENTAL -> CANDIDATE -> SUPPORTED -> PRODUCTION`

Promotion requires exact base/tokenizer revision, sealed data split hashes, rights/privacy clearance, deterministic environment, untouched held-out evaluation, structured-output validity, abstention and citation integrity, misuse/privacy/adversarial tests, latency/memory/cost envelope, clean reload, artifact hashes, SBOM, signature, publication readback, rollback and deprecation.

Priority families:

- **Khipu:** bounded proposal model; current weak abstention must remain visible until a sealed rerun passes.
- **ReceiptAgent:** compare v2, v3 and Forge 1.5B on one sealed corpus; select one winner or no winner.
- **Chaski:** repair immutable lineage, preserve failed qualification, and do not promote without independent passing evidence.

**Exit:** unsupported artifacts cannot enter production config or supported collections.

### G4 — Kernels

`szl-kernels` becomes the only source and release train. Each of 14 Hub kernel endpoints is generated from a versioned registry and must include:

- exact source/release SHA;
- reference implementation and numerical equivalence;
- supported devices, dtypes, shapes and deterministic mode;
- explicit CPU/GPU unavailable boundaries;
- unit/property/adversarial/fuzz tests;
- named-hardware benchmark receipt;
- package/container SBOM and vulnerability/license report;
- signed build and immutable Hub readback;
- compatibility/deprecation pointer.

Folded/deprecated entries remain visible but cannot advertise a second release authority.

**Exit:** all 14 endpoints resolve to canonical source and independently reproducible receipts.

### G5 — CPU/GPU execution

CPU lane: data validation, deduplication, contamination checks, split sealing, reference tests, lightweight evaluation, GGUF smoke inference, receipt verification, SBOM/signing/readback.

Owner-GPU lane: bounded LoRA/QLoRA candidates only after environment/VRAM/license/data preflight. Run smoke training first; seal config, seed, image, lockfile, logs, hardware, checkpoints and measured energy; clean-reload and evaluate before publication.

Cloud/multi-GPU lane: admitted only after local gates pass; every job has budget cap, immutable job spec, exact image/source, checkpoint/restart contract, failure receipt and publication disabled by default.

Serving lane: local llama.cpp/Ollama for bounded GGUF; vLLM as primary qualified GPU OpenAI-compatible candidate. Schema/policy gates remain outside weights. Require health/readiness, request limits, telemetry, canary and rollback.

### G6 — Runtime production readiness

For A11oy, a11oy.net, retained Spaces and vertical packages:

- documented owner and support boundary;
- SLO/SLI/error budget;
- health/readiness/startup/liveness;
- exact source/build/runtime identity;
- persistence and backup/restore;
- dependency-failure and degraded-mode tests;
- multi-region external probes;
- accessibility and mobile checks;
- load/capacity/cost envelope;
- canary, rollback and incident runbooks;
- public claims checked against live responses.

### G7 — Investor readiness

Investor material must show one product, buyer, urgent workflow, differentiated proof, deployment evidence and commercial plan. Maintain a controlled data room with:

- formation, cap table and equity records;
- founder/employee/contractor IP assignments;
- code/model/data/dependency license schedule;
- customer/design-partner contracts and evidence;
- revenue reconciliation, gross margin, compute/support cost, burn and runway;
- security/privacy posture and incident history;
- architecture, roadmap and product demonstration;
- source citation and reconciliation date for every number.

Unknown private facts remain `UNKNOWN`, never inferred green.

## Vertical packaging

| Package | Commercial boundary |
|---|---|
| Terra | First design-partner candidate; one narrow public-record underwriting workflow before expansion. |
| Aegis / IMMUNE | Safety and cyber-governance proof; separate trust roots, readiness and simulation from operator authority. |
| Puriq / Quant | Signed research and paper-only portfolio; no orders, custody, financial advice or performance claim. |
| Counsel | Private attorney-led assurance; no autonomous legal conclusion, deadline authority, filing or client actuation. |
| Vessels / Killinchu | Detection, classification, simulation and recommendations; no physical effector or weapons authorization. |
| Lyte | Business-observability decision cell inside A11oy, not a second flagship. |

## Current live blocker ledger

- `a11oy#1517` is a one-file security pin with passing security/provenance checks, but GitHub correctly blocks merge because the inherited `Tests` baseline is red.
- The red baseline includes missing Khipu routes, investor/estate routes, shared command-bar wiring, IA/deep-link/empty-state contracts, trust canonical copy and stale Killinchu claims.
- Repair baseline source through a dedicated PR, rerun exact-head checks, then update/merge `a11oy#1517`; do not bypass.
- Hugging Face mutations remain blocked until an authenticated Hub write transport or existing protected GitHub publication workflow is available. GitHub-side source/registry work proceeds meanwhile.

## Execution order

1. Land this control-plane program and validator.
2. Repair A11oy default-branch baseline via a dedicated source-restoration PR.
3. Rebase and green `a11oy#1517`; merge exact head.
4. Regenerate live estate inventory and mark drift.
5. Add admission control and organization-wide required workflow.
6. Converge receipt/kernel/model registries in canonical authorities.
7. Migrate candidates in dependency order; archive only after parity/readback.
8. Qualify Khipu and ReceiptAgent; preserve failures honestly.
9. Qualify all 14 kernel endpoints under one release train.
10. Prove retained runtimes with production-readiness receipts.
11. Regenerate GitHub/Hugging Face/website/investor surfaces from one truth manifest.
12. Seal investor data-room index and evidence scorecard.

## Completion definition

The program is complete only when:

- all protected default branches are green;
- no open PR is merged red or stale;
- one current estate manifest reconciles every GitHub/HF asset;
- target repository lifecycle is achieved with history and successor evidence;
- supported models and kernels have immutable promotion receipts;
- retained runtimes pass production-readiness and live negative verification;
- public/investor claims are generated from evidence;
- customer, financial, legal and IP diligence fields are either evidenced or explicitly unknown;
- every mutation and release is independently auditable.
