# SZL database Ouroboros evidence braid (v1)

**Execution class:** bounded read-only governance. **Not** database migration, proof promotion, GPU inference, Lake append, Hatun tool call, or historical manuscript interpretation.

## Source owners and pinned components

The policy `governance/database_contracts/ouroboros_braid_v1.json` enumerates **33 immutable source anchors spanning 11 first-party SZL repositories**: `szl-ouroboros` (Muyu kernel), `szl-khipu` (loop arithmetic and numerical lineage), `szl-lake` (canonical receipt adapter), `hatun-mcp` (bounded loop and governance), `lutar-lean` (Khipu sum-of-sums and cross-component carriers), `szl-formulas` (locked reference and atlas), `szl-invariants` (falsifiable ledger tests), `a11oy` (ancient-text lineage), `szl-papers` (experimental-versus-locked proof caveats), and `szl-org-health` (the agentic DB planner).

`tools/database_braid_source_readback.py` makes fixed authenticated **GET-only** GitHub requests for those exact commits and paths. It recomputes Git blob SHA-1 and SHA-256 in memory and exports **only** source IDs, byte counts, hashes, and MATCHED/UNAVAILABLE/MISMATCH to a private exclusive file. It never imports or runs the downloaded code. A byte-match proves a pinned GitHub source response, **not** live deployment, signer identity, or Lean elaboration.

`tools/database_ouroboros_braid.py` validates the merged agentic planner's inert work orders, the pinned family policy, and the source observation. It runs exactly five finite phases: plan intake, source reconciliation, Khipu unit-cord reconciliation, Lean/Hatun/Lake authority boundary, and terminal closure. It emits a SHA-256-linked **unsigned** five-step receipt. **Never mark a closed loop as a repaired database.**

## Corrected foundational mathematics and codex coverage

The initial 14-anchor selection omitted mathematical foundations because it chose only one Lean Khipu carrier and one historical-lineage document. This was a **coverage defect**; it should not have been described as the full SZL mathematical archive. This revision adds **19 independently located first-party Git blobs**, with source tiers:

| Added tier | Actual sources pinned | Status and boundaries |
| --- | --- | --- |
| **AXIOM_SOURCE (4)** | `lutar-lean/Lutar/Axioms.lean` (A1?A5), `Lutar/Uniqueness/AxiomCheck.lean`, `Lutar/Wave11/AxiomDisclosure.lean`, `Lutar/Wave16/Cut1MeanAxioms.lean` | Axioms are postulates/specifications, not theorems. A1?A5 meanings changed across historical revisions. Disclosures do not replace a fresh kernel readback. Unconditional Lambda uniqueness is **disproved as stated**; conditional Theorem U is distinct. |
| **EGYPTIAN_MATH (4)** | `Lutar/Egyptian.lean`, `Lutar/Egyptian/HorusEye.lean`, `Lutar/Egyptian/AkhmimTable.lean`, `Lutar/Thesis/TH_V18_04_EgyptianWeightSum.lean` | Unit-fraction weights, the six-term Horus-Eye arithmetic sum 63/64, and representative Rhind/Akhmim 2/n decompositions are visible in source. They are neither fresh checker proofs in this run nor new archaeological discoveries. |
| **GREEK_MATH (2)** | `a11oy/Lutar/Innovations/round6/PythagorasHarmonicMean.lean` and `lutar-lean/Lutar/Innovations/round4/YBCHeronConvergence.lean` | **PythagorasHarmonicMean currently contains open Lean `sorry` holes; PARTIAL.** YBC/Heron spans different historic mathematical lineages, not all Greek. No math proof is promoted by a source SHA. |
| **GREEK_LOGIC (4)** | `platform/packages/ouroboros-aristotle/src/axiom-posit-separator.ts`, `pnc-bedrock-axiom-guard.ts`, `platform/packages/ouroboros-socrates/src/elenchus.ts`, `hypothesis-ledger.ts` | These are TypeScript inquiry and logic gates, **not** Lean mathematical theorems or current runtime evidence. |
| **CODEX_ANALOGY (5)** | `lutar-lean/Lutar/Innovations/round4/CopperScrollDAGHeight.lean`, `MasoreticChecksum.lean`, `PlimptonReciprocal.lean`, `MayaLCMEpochSync.lean`, `SexagesimalReciprocal.lean` | Engineering analogies to the Copper Scroll, Masoretic scribal tradition, Babylonian tablet/sexagesimal mathematics, and Maya calendar cycles. These are **not digitized ancient codices** and carry no manuscript copying, training, decoding or cultural-data license. |

**14 original + 19 newly scoped = 33 exact Git source pins across 11 repositories.** The readback requires all named families and refuses tier mismatches. Khipu's unit-cord count reaches 33 only if the 33 bytes-pinned source objects really match. Missing sources remain UNAVAILABLE rather than zero. The Ouroboros loop remains five bounded steps with explicit HOLD.

This representative source selection is **not an exhaustive census** of the 513-path Lean repository or every ancient/math source. Further corpus intake requires identified works, trustworthy scholarly or archival citations, rights and culturally appropriate stewardship. Source files do not independently prove theorem execution.

## Modern engineering mathematics

Each matched pinned source contributes exactly one unit cord; unmatched or absent sources contribute **UNAVAILABLE**, not zero. `K_observed = sum(1 for each byte-matched source)`, `K_required = 33`; `C_source = K_observed / K_required`. The arithmetic is a **modern source-count conservation check** inspired by documented Inka khipu accounting—not an ancient cipher or a new archaeological decipherment.

A five-step trace uses `h_0 = 000...000` and `h_i = SHA256(canonicalJSON(step_i including h_(i-1)))`. The chain is **not a DSSE signature**, independent witness, or cryptographic proof of runtime execution.

All five stages terminate. Loop duration, GPU joules, model energy, loop tax and theoretical speedup are **UNAVAILABLE** unless independently measured. This adapter does not call the actual Ouroboros kernel, Hatun MCP, Lean checker, or Lake canonical receipt library.

**Proof levels remain separate:** Lean source carriers do not establish that a fresh `lake build`, `Lean.collectAxioms`, `lean4checker` or refinement proof ran here. The `szl-formulas` source distinguishes eight locked theorem carriers from experimental Lean statements; unconditional Λ uniqueness is disproved as stated and cannot be promoted to a theorem by an agent. The actual validated result is `NO_FRESH_LEAN_CHECKER_OR_RUNTIME_REFINEMENT`.

**Historical research is attributed, not imported as training data.** A11oy's documented lineage references the Rhind/Akhmim mathematical sources, Inka khipu, Liu Hui, and Madhava/Kerala materials. The records do **not** show that any ancient text contained SZL software, modern cryptography, or secret formulas. Archaeological dataset rights are `NOT_GRANTED` until separately reviewed.

## Reproduction, receipt and gates

```powershell
python -I -B tools/database_braid_source_readback.py --policy governance/database_contracts/ouroboros_braid_v1.json --output C:\SZL\edge-debug\<new-source-readback>.json
python -I -B tools/database_ouroboros_braid.py --braid-policy governance/database_contracts/ouroboros_braid_v1.json --source-readback C:\SZL\edge-debug\<new-source-readback>.json --db-plan C:\SZL\edge-debug\<private-db-plan>.json --db-action-policy governance/database_contracts/database_agentic_actions_v1.json --source-policy governance/database_contracts/memory_covenant_v2.json --output C:\SZL\edge-debug\<new-braid-receipt>.json
```

All output goes to unique private files **outside** GitHub. Exit 0 from GitHub source readback means only its 33 immutable blobs matched. The braid always returns exit 2 / `CLOSED_WITH_HOLD` or exit 3 / `UNAVAILABLE`: it cannot grant effect authority. Source runtime refinement, independent Lean kernel check, Hatun signer, Lake PCGI signing, production DB role/tenant isolation, and approved external actions remain separate.

**Known live gates:** A11oy validation Postgres has 7/8 required memory tables, principal-binding helper mismatches, 0/4 real causal stages and no admitted unprivileged auditor role under a conservative predicate. See private `szl-org-health#372` and `a11oy#3684`. Workstation C: remains under the 50 GiB safety threshold; do not download models, launch containers, or run GPU stress from this module.

**Scope of novelty:** a compositional *evidence braid* for SZL's existing systems, not a claim that SHA-256 chains, fixed-point loops, arithmetic summaries or proof assistants were invented here. The boundary is useful precisely because missing evidence stays missing.
