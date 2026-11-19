# SZL database Ouroboros evidence braid (v2)

**Execution class:** bounded, read-only governance evidence. **Not** a database migration, a repaired database, a proof promotion, a production admission, a signature, a deployed-service check, or an interpretation of any historical manuscript. v1 (`docs/OUROBOROS_DB_BRAID_20261118.md`, `tools/database_ouroboros_braid.py`) is unchanged and still valid; v2 is additive.

## Why v2 exists

v1 pinned 33 hand-picked source files and recorded, correctly, that nothing behind them had been exercised: its fourth phase is a constant `HOLD` with the detail `LEAN_KERNEL_NOT_RUN_HATUN_NO_AUTHORITY_LAKE_NOT_SIGNED`. v2 replaces each of those "not run" statements with the output of a tool that does run the thing, and replaces the hand-picked list with a census of every file the policy puts in scope.

| | v1 | v2 |
| --- | --- | --- |
| Sources | 33 pinned files, chosen by hand | every in-scope file of 12 repositories, byte-checked from committed git objects |
| Khipu | one unit per matched source | three-tier sum tree: cords carry integer knots, pendants and the primary cord carry their sums, partition identities hold at every node, each node hash binds its children's sums |
| Lean | "not executed this run" | the kernel is run over the corpus, including modules the default build never reaches; every tracked `.lean` file gets one status; every theorem's axiom dependencies are read from the kernel |
| Hatun | "not attached" | the committed veto ladder is executed locally (gate primitives, bounded loop, and a real in-memory MCP session); effect authority stays `NOT_ATTACHED` |
| Lake | "not emitted" | the canonical receipt is emitted by the committed adapter; it is `UNSIGNED` and nothing is appended to a live Lake |
| Decision | constant `HOLD` | exact weighted geometric mean over eight axes, zero-pinned, refused outright when evidence is missing |
| Loop | one run | chained turns; each turn consumes the previous turn's receipt; proof debt may not rise without the policy saying so |

## Tools and contracts

| File | Role |
| --- | --- |
| `tools/database_braid_source_census.py` | census from local git checkouts; recomputes each blob id and a SHA-256 |
| `tools/database_braid_khipu_tree.py` | sum tree, conservation checks, inclusion-with-sum proofs, diff |
| `tools/database_braid_lean_witness.py` | default build, guard scripts, executables, on-request builds, kernel axiom census |
| `tools/database_braid_codex_kat.py` | exact known-answer checks bound to source lines |
| `tools/database_braid_hatun_gate.py` | local Hatun veto-ladder conformance, no network |
| `tools/database_braid_lake_receipt.py` | unsigned canonical Lake receipt for a turn |
| `tools/database_braid_exact.py` | float-free decision |
| `tools/database_ouroboros_braid_v2.py` | the five-phase turn and its independent verifier |
| `tools/database_braid_turn.py` | one command that runs all of the above into one new directory |
| `governance/database_contracts/ouroboros_braid_v2.json` | reviewed policy: scope, knots, probes, threshold, ratchet floor |
| `governance/database_contracts/braid_family_map_v1.json` | file-to-family labels for the Lean corpus (`MACHINE_PROPOSED_UNRATIFIED`) |
| `governance/database_contracts/braid_codex_known_answers_v1.json` | known answers (`MACHINE_TRANSCRIBED_UNRATIFIED`) |
| `.github/workflows/ouroboros-braid-turn.yml`, `requirements-braid.lock` | scheduled turn; hash-locked optional libraries |

All tools import with the standard library only. The two optional libraries (the estate receipt library and the MCP SDK) are needed only inside child interpreters; when they are absent the affected stage reports `UNAVAILABLE`.

## The five phases of a turn

1. `PLAN_AND_SCOPE` validates the policy and consumes the previous turn (the tail): the previous report must re-verify, and the previous Lake receipt, when supplied, must bind that exact report.
2. `SOURCE_CENSUS_RECONCILIATION` accepts a census in which every tracked file is accounted for: in scope, out of scope, or not a regular blob. A repository with no checkout is `UNAVAILABLE`, never empty.
3. `KHIPU_SUM_TREE_CONSERVATION` builds the tree and re-verifies every hash, every sum and both partition identities.
4. `LEAN_HATUN_PROOF_BOUNDARY` binds the Lean witness to the census commit and reads the Hatun witness. This phase can now be `OBSERVED`.
5. `TERMINAL_RECEIPT_CLOSURE` checks the ratchet, forms or refuses the decision, and derives the turn id from content. The Lake receipt wraps the finished turn afterwards and is verified by the next turn.

The loop always terminates after exactly five phases.

## Mathematics

**Sum of sums.** Each cord `c` carries a vector of non-negative integers `k(c)`. A pendant `P` carries `K(P) = sum of k(c) for c in P`, and the primary cord carries `K = sum of K(P)`. Two partition identities are required at every cord, pendant and at the primary cord:

- `lean_files = accepted_default + accepted_on_request + accepted_standalone + rejected + not_checked_by_policy + not_judged`
- `user_theorems = trust_base_only + sorry_tainted + declared_axiom_dependent + native_decide`

A missing cord is listed and contributes nothing; it is never a zero.

**Binding.** `h(c) = SHA256(tag_c || canon(key, digest, k))`, `h(P) = SHA256(tag_P || canon(label, [(h(c), k(c))]))`, `h = SHA256(tag || canon(names, [(h(P), K(P))]))`. Because a parent binds each child's sum, one cord can be shown to belong to a stated total by revealing only its siblings' hashes and sums.

**Exact decision.** With axes `x_i` in `[0, 1]` as exact rationals, integer weights `w_i`, `W = sum of w_i` and threshold `tau = p/q`:

`G >= tau  <=>  prod(num_i^w_i) * q^W >= p^W * prod(den_i^w_i)`

which is a comparison of two integers. A zero axis pins the aggregate (`ZERO_PINNED`). The ordering harmonic <= geometric <= arithmetic mean is used only to explain the verdict and is re-checked against the integer comparison on every call. `dang` is `AM >= tau and GM < tau`: evidence that looks fine on average while one link is weak.

**Refusal before aggregation.** If any required evidence is absent, stale against the census, or violates the ratchet, no aggregate is formed (`PRE_AGGREGATION`, with named reasons). A missing score is never replaced by zero, because under zero-pinning a substituted zero is indistinguishable from a real veto.

**Ratchet.** The policy carries a reviewed floor (kernel-accepted files, rejected files, sorry-tainted theorems, direct `sorry` declarations, the allowed set of declared axioms, the locked-set guard count). A turn worse than the floor is a violation; a turn better than the floor is reported as `can_tighten`. Between two turns a cord may not vanish unless the policy retires it, and kernel-measured debt may not rise.

**Fixed point.** `state_digest` covers the evidence and the decision and excludes clocks, ordinals and the link to the previous turn. Unchanged evidence therefore reproduces the same digest, and `ouroboros_fixed_point` is true.

## Prior art (not ours)

Hash trees are due to Merkle (1987). Hash trees whose nodes carry sums are the Merkle-sum tree used for proof of liabilities (Maxwell 2013; Dagher, Bunz, Bonneau, Clark and Boneh 2015). The three-tier summation structure follows published descriptions of Inka khipu accounting (Locke 1923; Ascher and Ascher 1981; Urton 2003); the estate's own Lean carrier for the summation law is `Lutar/Khipu/SummationInvariant.lean` in `lutar-lean`. The three classical means and their ordering are ancient and standard, and non-compensating aggregation by a geometric mean is standard. Reading a theorem's axiom dependencies uses Lean's own `collectAxioms`. What is new here is only the composition: applying those pieces to account for proof debt across this estate and to chain the result.

## Measured on 2026-11-19

Every number below was produced in one container by the tools in this change and is labelled MEASURED unless stated. They describe the commits named, and nothing later.

- **Census.** 758 cords across 12 repositories, state `COMPLETE`, 0 unavailable. `lutar-lean` at `98f1735bb23085a2979e0a22643a032ce98a27c9` contributes 317 `.lean` files of 514 tracked files.
- **Lean kernel** (Lean 4.35.0, Mathlib at `56a005855ea17e0b0958f73ec801ae140b0a1679`, dependencies from the published cache): default `lake build` exit 0. Of 317 files: 187 accepted by the default build, 65 accepted only when asked (62 library modules the default build does not reach and 3 built with the two executables), **57 rejected** by the elaborator, 8 not checked by policy (4 scratch mirrors, the build file, 3 guard scripts). Locked-set guard 24 of 24 inside `{propext, Classical.choice, Quot.sound}`; no `sorryAx` in the Theorem U axiom check.
- **Kernel axiom census** over 247 modules and 5,732 constants: 1,767 user-facing theorems, of which 1,702 depend only on the trust base, 25 depend on `sorryAx`, 37 depend on a declared axiom and 3 on a `native_decide` auxiliary axiom; 23 declarations contain `sorry` in their own proof; 31 axioms are declared, 3 of which are auxiliary axioms that `native_decide` generates.
- **Several counts of "sorry" coexist for the same commit.** Text: 53 tokens outside comments across the tree, plus 6 in the scratch-mirror directory. Elaborator: 25 "declaration uses sorry" warnings in files it accepted, and 20 more in files it then rejected. Kernel: 23 declarations whose own proof term contains `sorryAx`, and 25 user-facing theorems that reach `sorryAx` through any chain of lemmas. The repository's canonical counter (`.github/scripts/lean_numbers.py`) reports 304 raw and 253 outside line comments, because it also counts the word inside block comments and documentation. Only the kernel numbers say what is actually unproved, and only for files the kernel accepted.
- **v1's pins.** Of the 16 `lutar-lean` files v1 pinned, 8 are never compiled by the default build, and the kernel rejects 7 of those 8 as written at this commit.
- **Hatun** at `1cec84742e07c151a34c329ae2fb50dd5f87c7ab`: `VETO_LADDER_CONFORMS`, 8 of 8 probes. The bounded loop walked the five phases and exited `converged`. Over a real in-memory MCP session (server 1.0.4, 38 tools) the ladder declined an injected instruction (`yuyay_axis_below_floor`), a state-changing tool without a second approver (`two_person_gate_required`) and an anonymous caller (`no_api_key`), each before any backend call. Signer mode `PLACEHOLDER`.
- **Lake** adapter at `7e19e7f0d56d98fb78c7af6b9369819edaf37262` with `szl-receipt-dsse` 0.3.1: `CANONICAL_RECEIPT_EMITTED_UNSIGNED`; the receipt digest was re-derived independently and matched.
- **Known answers.** 46 claims transcribed from the Lean sources: 45 hold in exact arithmetic, 1 does not. `Lutar/Innovations/round4/YBCHeronConvergence.lean` line 6 calls `1;24,51,10` the second Heron iterate from 1. From 1 the iterates are `3/2`, `17/12`, `577/408`; the second is `17/12`, and it is the third, `577/408`, that agrees with `1;24,51,10 = 30547/21600` after truncation to three sexagesimal places (it exceeds it by exactly `1/367200`). Started from `3/2` instead, `577/408` would be the second iterate; that reading is ours, not the file's. The file's theorems use `577/408`; the comment is the discrepancy. Reported, not corrected.
- **The loop closes.** Two complete, independent executions of the whole pipeline (including a fresh kernel run) produced the same `state_digest`; the second turn had ordinal 2, verified the first turn's Lake receipt and reported `ouroboros_fixed_point: true`.
- **Outcome of those turns:** `HOLD`, `PRE_AGGREGATION`, reasons `KNOWN_ANSWERS_NOT_SUPPLIED` (those two runs were made before the known-answer set was assembled) and `DATABASE_PLAN_NOT_SUPPLIED`. The second reason is the correct result for any turn run here: the database plan belongs to the database-admission lane and was not available to this run.
- **A negative result, recorded.** We looked for a threshold defect in the estate's floating-point admit rule (`a11oy/szl_verify_nine.py`) by comparing it with the exact rule at τ = 0.80 on 312,601 two-decimal inputs (every multiset of one to three axes on [0.01, 1.00], and of four axes on [0.60, 1.00]), and on all 316 inputs with up to nine axes whose geometric mean equals τ exactly, at τ = 0.80 and 0.70 (164 unweighted, 152 weighted). Disagreements: 0. The exact rule is used here for reproducible receipts, not because the floating-point rule was found wrong.

## What a turn does not establish

- It does not show that a checkout equals the protected remote branch, who authored a commit, or that any file is deployed.
- It is one elaboration by one toolchain on one machine. It is not an independent second kernel (`independent_kernel_replay: false`) and not a review of what any theorem means. A theorem with a clean footprint can still say less than its name suggests.
- The Hatun result is about committed source run locally with a demo context. No deployed Hatun runtime was contacted, no identity was established, and no second approver exists or is claimed. Hatun does not understand action text; the braid classifies effects itself and treats every database work order as state-changing.
- The Lake receipt is unsigned. An unsigned receipt identifies content; it is never a pass. A signature requires the keyless attestation job (off until the owner enables it) or the estate signer.
- Database verdicts are REPORTED inputs from another lane. This tool never queries a database and cannot upgrade them.
- The family labels and the known-answer set are machine-proposed and unratified.
- 196 further `.lean` files in the census are counted as `lean_not_judged`, because no witness covers them in this turn: in `a11oy`, a vendored copy of the Lean corpus pinned to Lean 4.13 (177 files), a policy model (17 files) and the copy of `PythagorasHarmonicMean.lean`; and the heritage project in `szl-khipu-scholar/codices` (1 file).
- The known answers check numbers written in modern source files that cite historical mathematics. They assert nothing about any manuscript, tablet or khipu. Archaeological data rights remain `NOT_GRANTED`.
- Unconditional Lambda uniqueness remains `UNCONDITIONAL_UNIQUENESS_DISPROVEN_AS_STATED`, and khipu consensus safety remains a conjecture. Nothing here promotes either.
- Energy, timing and loop cost are not measured and are `null`, not zero.

## Reproduction

```bash
python -I -B tools/database_braid_turn.py \
  --policy governance/database_contracts/ouroboros_braid_v2.json \
  --family-map governance/database_contracts/braid_family_map_v1.json \
  --answers governance/database_contracts/braid_codex_known_answers_v1.json \
  --checkout szl-holdings/lutar-lean=<clean checkout with its dependency cache> \
  --checkout szl-holdings/hatun-mcp=<checkout> --checkout szl-holdings/szl-lake=<checkout> \
  --checkout <one per remaining policy repository> \
  --lean-toolchain-bin <absolute directory holding lake and lean> \
  --python <absolute interpreter installed from requirements-braid.lock> \
  --previous-dir <directory of the previous turn, omit for a genesis turn> \
  --out-dir <new empty directory outside every checkout>
```

Exit 0 means the turn closed and re-verified, on `HOLD` or on `EVIDENCE_THRESHOLD_MET_NO_AUTHORITY`; read `turn.json` for which. Exit 3 means a refusal and nothing usable was written. Each tool also runs on its own. The orchestrator alone returns 2 for a closed turn and never 0, like v1. All output goes to new files outside every checkout.

The scheduled workflow performs the same turn weekly and on dispatch. It has not run yet at the time of writing, so nothing here is evidence that it works on a hosted runner.

## Open gates

1. The database-admission lane's plan (catalog coverage, causal frontier, auditor role). Until it is supplied the turn refuses the aggregate; with the reported 7 of 8 tables and 0 of 4 causal stages the aggregate would be zero-pinned.
2. A real signature on the turn's receipt.
3. An independent kernel replay.
4. Owner ratification of the family map and the known-answer set.
5. The 57 files the kernel rejects, the 25 theorems that rest on `sorryAx`, and the 31 declared axioms. These are measurements of `lutar-lean`, tracked by the ratchet floor in the policy; lowering them is work in that repository.

**Scope of novelty:** a composition that makes existing SZL systems account for themselves in one bounded loop. Hash trees, sum trees, bounded loops, proof assistants and geometric means were not invented here. The value is that missing evidence stays missing and measured debt cannot rise quietly.
