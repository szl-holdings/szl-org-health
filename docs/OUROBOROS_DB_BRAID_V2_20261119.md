# SZL database Ouroboros evidence braid (v2)

**Execution class:** bounded, read-only governance evidence. **Not** a database migration, a repaired database, a proof promotion, a production admission, a signature, a deployed-service check, or an interpretation of any historical manuscript. v1 (`docs/OUROBOROS_DB_BRAID_20261118.md`, `tools/database_ouroboros_braid.py`) is unchanged and still valid; v2 is additive.

## Why v2 exists

v1 pinned 33 hand-picked source files and recorded, correctly, that nothing behind them had been exercised: its fourth phase is a constant `HOLD` with the detail `LEAN_KERNEL_NOT_RUN_HATUN_NO_AUTHORITY_LAKE_NOT_SIGNED`. v2 replaces each of those "not run" statements with the output of a tool that does run the thing, and replaces the hand-picked list with a census of every file the policy puts in scope.

| | v1 | v2 |
| --- | --- | --- |
| Sources | 33 pinned files, chosen by hand | every in-scope file of 12 repositories, byte-checked from committed git objects, with each commit's root tree id and a digest of its full listing |
| Khipu | one unit per matched source | three-tier sum tree: cords carry integer knots, pendants and the primary cord carry their sums, partition identities hold at every node, each node hash binds its children's sums, and the primary hash also binds the partitions and the list of unavailable cords |
| Lean | "not executed this run" | a fresh export of the commit is built with an empty build directory, so every project module the kernel accepts was elaborated by this run; modules the default build never reaches are built on request; every tracked `.lean` file gets one status; every theorem's axiom dependencies are read from the kernel. Mathlib and the other dependencies come from their published `.olean` cache and are trusted, not re-checked |
| Hatun | "not attached" | the committed veto ladder runs locally from a fresh export of the commit (gate primitives, the bounded loop, and a real in-memory MCP session), in an empty network namespace when the host provides one; effect authority stays `NOT_ATTACHED` |
| Lake | "not emitted" | the committed adapter emits the canonical receipt from a fresh export; the braid re-hashes the decoded payload itself; the receipt is `UNSIGNED` and nothing is appended to a live Lake |
| Decision | constant `HOLD` | exact weighted geometric mean over eight axes, zero-pinned, refused outright when evidence is missing, unbound, stale or non-conforming |
| Verification | re-check of one report | `verify_turn` re-derives every verdict field from the report's own observed sections; `replay_turn` re-runs the turn from its evidence files and requires identical bytes |
| Loop | one run | chained turns; each turn consumes the previous turn's receipt; proof debt is compared with the last turn that had a bound kernel witness and may not rise |

## Tools and contracts

| File | Role |
| --- | --- |
| `tools/database_braid_common.py` | canonical JSON, exclusive writes, Lean lexing, and `bounded_run`: a child in its own session, killed as a group on timeout or output overflow, inside an empty network namespace when the host allows one |
| `tools/database_braid_source_census.py` | census from local git checkouts; recomputes each blob id and a SHA-256; records each commit's root tree id and a digest of its full listing; exports a commit byte for byte |
| `tools/database_braid_khipu_tree.py` | sum tree, conservation checks, inclusion-with-sum proofs, diff |
| `tools/database_braid_lean_witness.py` | fresh-export default build, guard scripts, executables, on-request builds, standalone files, kernel axiom census |
| `tools/database_braid_codex_kat.py` | exact known-answer checks bound to source bytes and lines |
| `tools/database_braid_hatun_gate.py` | local Hatun veto-ladder conformance from a fresh export |
| `tools/database_braid_lake_receipt.py` | unsigned canonical Lake receipt for a turn, re-hashed by the parent |
| `tools/database_braid_exact.py` | float-free decision |
| `tools/database_ouroboros_braid_v2.py` | the five-phase turn, its verifier and its replay |
| `tools/database_braid_turn.py` | one command that runs all of the above into one new directory |
| `governance/database_contracts/ouroboros_braid_v2.json` | reviewed policy: scope, knots, probes, threshold, evidence window, ratchet floor |
| `governance/database_contracts/braid_family_map_v1.json` | file-to-family labels for the Lean corpus (`MACHINE_PROPOSED_UNRATIFIED`) |
| `governance/database_contracts/braid_codex_known_answers_v1.json` | known answers (`MACHINE_TRANSCRIBED_UNRATIFIED`) |
| `.github/workflows/ouroboros-braid-turn.yml`, `requirements-braid.lock` | scheduled turn; hash-locked optional libraries |
| `execution/ouroboros-braid-v2/` | the evidence behind the numbers below: turns, counters, the admit experiment, soundness checks |

All tools import with the standard library only. The two optional libraries (the estate receipt library and the MCP SDK) are needed only inside child interpreters; when they are absent the affected stage reports `UNAVAILABLE`.

## The five phases of a turn

1. `PLAN_AND_SCOPE` validates the policy and consumes the previous turn (the tail): the previous report must re-verify, and the previous Lake receipt, when supplied, must re-hash and bind that exact report and the adapter commit that report's census saw. A receipt that does not validate is `RECEIPT_INVALID`, one that does not bind is `MISMATCH`; both hold the turn.
2. `SOURCE_CENSUS_RECONCILIATION` accepts a census in which every tracked file is accounted for: in scope, out of scope, or not a regular blob. A repository with no checkout is `UNAVAILABLE`, never empty.
3. `KHIPU_SUM_TREE_CONSERVATION` builds the tree and re-verifies every hash, every sum and both partition identities.
4. `LEAN_HATUN_PROOF_BOUNDARY` is `OBSERVED` only when the Lean witness is bound to the census commit and `KERNEL_EXECUTED`, and the Hatun witness is bound to the census commit and `VETO_LADDER_CONFORMS`.
5. `TERMINAL_RECEIPT_CLOSURE` checks the ratchet, forms or refuses the decision, and derives the turn id from content. The Lake receipt wraps the finished turn afterwards and is verified by the next turn.

The loop always terminates after exactly five phases.

## Mathematics

**Sum of sums.** Each cord `c` carries a vector of non-negative integers `k(c)`. A pendant `P` carries `K(P) = sum of k(c) for c in P`, and the primary cord carries `K = sum of K(P)`. Two partition identities are required at every cord, pendant and at the primary cord:

- `lean_files = accepted_default + accepted_on_request + accepted_standalone + rejected + not_checked_by_policy + not_judged`
- `user_theorems = trust_base_only + sorry_tainted + declared_axiom_dependent + native_decide`

A missing cord is listed and contributes nothing; it is never a zero. Theorem counts exist only for modules the kernel accepted; every other Lean file carries `lean_theorem_counts_unknown = 1`, so a zero in a theorem knot never stands for "not judged".

**Binding.** `h(c) = SHA256(tag_c || canon(key, digest, k))`, `h(P) = SHA256(tag_P || canon(label, [(h(c), k(c))]))`, and the primary hash covers the knot names, the partitions, the unavailable cords and every `(h(P), K(P))`. Because a parent binds each child's sum, one cord can be shown to belong to a stated total without revealing other cords' keys or content digests; the siblings' hashes, sums and knot vectors are revealed.

**Exact decision.** With axes `x_i` in `[0, 1]` as exact rationals, integer weights `w_i`, `W = sum of w_i` and threshold `tau = p/q`:

`G >= tau  <=>  prod(num_i^w_i) * q^W >= p^W * prod(den_i^w_i)`

which is a comparison of two integers. A zero axis pins the aggregate (`ZERO_PINNED`). The ordering harmonic <= geometric <= arithmetic mean is used only to explain the verdict and is re-checked against the integer comparison on every call. `dang` is `AM >= tau and GM < tau`: evidence that looks fine on average while one link is weak.

**Refusal before aggregation.** No aggregate is formed, and the reasons are named, when any of these holds: evidence is absent; a witness is bound to another commit, or known answers to another census; a witness was taken outside the policy's evidence window around the census (24 hours); the kernel witness is not `KERNEL_EXECUTED`; the Hatun ladder did not conform (a veto that did not hold is a refusal, never partial credit); a known answer is stale, misplaced or unread; the database lane itself says `HOLD`; the ratchet is violated; or the previous receipt is invalid or does not bind. A missing score is never replaced by zero, because under zero-pinning a substituted zero is indistinguishable from a real veto.

**Ratchet.** The policy carries a reviewed floor for nine quantities: kernel-accepted files, rejected files, sorry-tainted theorems, direct `sorry` declarations, axiom-dependent theorems, `native_decide` theorems, trust-base-only theorems, the allowed set of declared axioms and the locked-set guard count (24 theorems covering the 8 locked formulas `{F1, F4, F7, F11, F12, F18, F19, F22}`). A turn worse than the floor is a violation; a turn better than the floor is reported as `can_tighten`. Between turns, a cord may not vanish unless the policy retires it, and no debt quantity may rise and no credit quantity fall against the last turn that had a bound kernel witness. That baseline is carried through turns without a witness, so debt cannot be laundered through one.

**Fixed point.** `state_digest` covers the evidence summaries and the decision and excludes clocks, file digests, ordinals and the relation to earlier turns. Unchanged evidence therefore reproduces the same digest, and `ouroboros_fixed_point` is true.

**Verification and replay.** `verify_turn` re-derives the guards, axes, decision, state, termination, state digest, turn id and all five trace steps from the report's own observed sections and compares bytes. With the policy it also re-derives the ratchet floor; with the previous turn it checks the chain link, the baseline and the fixed point. An edited verdict therefore does not verify, and a consistent forgery must rewrite the observed sections themselves. `replay_turn` closes that gap for anyone holding the evidence files: it re-runs the turn from them and requires identical bytes. The runner replays every turn it writes before it publishes it.

**Labels.** Evidence produced by the runner in the same invocation as the turn is `MEASURED`. Evidence supplied as a file is `REPORTED`: shape-checked, digest-bound and commit-bound where the census allows, but not re-observed. Database verdicts are always `REPORTED`. Each axis carries the label of its source.

## Prior art (not ours)

Hash trees are due to Merkle (1987). Hash trees whose nodes also carry sums were proposed by Maxwell for proof of reserves (as described by Wilcox, "Proving your bitcoin reserves", 2014) and are discussed in Dagher, Bünz, Bonneau, Clark and Boneh, "Provisions" (CCS 2015), who build a different, zero-knowledge protocol. The three-tier summation structure follows published descriptions of Inka khipu accounting (Locke 1923; Ascher and Ascher 1981; Urton and Brezine 2005). The estate's Lean carrier `Lutar.Khipu.khipuReceipt_checksum_invariant` is a theorem about a related model, that bumping one entry changes a khipu root total; it is not a proof about this Python tree, which has no Lean proof. The three classical means and their ordering are ancient and standard, and non-compensating aggregation by a geometric mean is standard. Reading a theorem's axiom dependencies uses Lean's own `collectAxioms`. Running a child in a new network namespace uses the Linux `unshare` facility. What is new here is only the composition: applying those pieces to account for proof debt across this estate, to verify a turn by re-deriving it, and to chain the result.

## Measured

Every number below was produced by the tools in this change, from committed bytes, and is labelled MEASURED unless stated. The turns were run in one container on 2026-11-24 with the code at `e1164ca`; the counter, the admit experiment and the soundness checks on 2026-11-19; the hosted turn on a GitHub runner on 2026-11-23. The evidence is under `execution/ouroboros-braid-v2/`. The numbers describe the commits named, and nothing later.

**Census.** 772 cords across 12 repositories, state `COMPLETE`, 0 unavailable:

| Repository | Commit | In-scope files (cords) | Tracked files |
| --- | --- | --- | --- |
| `szl-holdings/a11oy` | `02fe78903c85` | 198 | 6940 |
| `szl-holdings/hatun-mcp` | `1cec84742e07` | 30 | 137 |
| `szl-holdings/lutar-lean` | `98f1735bb230` | 317 | 514 |
| `szl-holdings/platform` | `1a9f5732b84f` | 136 | 10485 |
| `szl-holdings/szl-formulas` | `9c74b29de9c0` | 5 | 74 |
| `szl-holdings/szl-invariants` | `233833d00163` | 1 | 52 |
| `szl-holdings/szl-khipu` | `923b25a9e62c` | 44 | 493 |
| `szl-holdings/szl-khipu-scholar` | `3eea52221b00` | 6 | 25 |
| `szl-holdings/szl-lake` | `7e19e7f0d56d` | 9 | 498 |
| `szl-holdings/szl-org-health` | `e1164ca133c7` | 24 | 309 |
| `szl-holdings/szl-ouroboros` | `f3713283d6ef` | 1 | 54 |
| `szl-holdings/szl-papers` | `c27a18f1f3aa` | 1 | 180 |

All twelve checkouts' `origin` matches the repository named in the policy (`ORIGIN_MATCHES`). The census predates the commit that adds this document, so `szl-org-health` appears at the commit before it.

**Lean kernel** (`lutar-lean` at `98f1735bb23085a2979e0a22643a032ce98a27c9`, Lean 4.35.0, Lake 5.0.0, Mathlib `56a005855ea17e0b0958f73ec801ae140b0a1679`):

- The commit was exported byte for byte (514 files) into an empty directory and built there. All 252 accepted project modules were built by this run and none was replayed from an earlier build. Every Lean and Lake step ran in an empty network namespace.
- Dependencies came from the published cache: the 9 manifest packages are at their pinned revisions, with 9,049 dependency `.olean` files, trusted and not re-checked.
- Of 317 `.lean` files: 187 accepted by the default build, 65 accepted only when asked (62 library modules the default build never reaches and 3 built with the two executables), **57 rejected** by the elaborator (53 on request and the 4 standalone `TH8` files), 8 not checked by policy (4 scratch mirrors, the build file, 3 guard scripts).
- Locked-set guard: 24 of 24 theorems, covering the 8 locked formulas `{F1, F4, F7, F11, F12, F18, F19, F22}`, depend only on `{propext, Classical.choice, Quot.sound}`. The Theorem U axiom check finds no `sorryAx`. Both executables pass.
- Kernel axiom census over 247 modules and 5,732 constants: 1,767 user-facing theorems, of which 1,702 depend only on the trust base, 25 reach `sorryAx`, 37 rest on a declared axiom and 3 on a `native_decide` auxiliary axiom. 23 declarations contain `sorry` in their own proof. 31 axioms are declared, 3 of which `native_decide` generates.
- The Lean steps took 211 s in the genesis turn. The same 317 statuses and a byte-identical census digest (`rows_sha256` `1cb01f14…`) came out of an earlier cached run of the same commit, so the fresh build changed no verdict.

**Several counts of `sorry` coexist for the same commit.** Text: 53 tokens outside comments and strings across the tree, plus 6 in the scratch-mirror directory. Elaborator, with each warning counted once: 23 "declaration uses sorry" warnings in 14 files it accepted, and 35 more in 15 files it then rejected (15 of them in `TH8/lean_v2/GradedSemiring.lean`). Kernel: 23 declarations whose own proof term contains `sorryAx`, and 25 user-facing theorems that reach it through any chain of lemmas. The repository's canonical counter (`.github/scripts/lean_numbers.py`, output in `execution/ouroboros-braid-v2/counters/`) reports 304 raw and 253 outside line comments, because it also counts the word inside block comments and documentation. Only the kernel numbers say what is actually unproved, and only for files the kernel accepted. An earlier version of this document gave 25 and 20 elaborator warnings; that parser counted replayed warnings twice and missed the standalone log format.

**v1's pins.** Of the 16 `lutar-lean` files v1 pinned, 8 are never compiled by the default build, and the kernel rejects 7 of those 8 as written at this commit.

**Hatun** at `1cec84742e07c151a34c329ae2fb50dd5f87c7ab`, run from an export of the commit (137 files) in an empty network namespace: `VETO_LADDER_CONFORMS`, 8 of 8 probes. The bounded loop walked the five phases and exited `converged`. Over a real in-memory MCP session (server 1.0.4, 38 tools), the ladder declined three requests, each before any backend call:

- an injected instruction (`yuyay_axis_below_floor`);
- a state-changing tool without a second approver (`two_person_gate_required`);
- an anonymous caller (`no_api_key`).

The caller context came from hatun-mcp's own test hooks. Signer mode `PLACEHOLDER`.

**Lake** adapter at `7e19e7f0d56d98fb78c7af6b9369819edaf37262` with `szl-receipt-dsse` 0.3.1, run from an export in an empty network namespace: `CANONICAL_RECEIPT_EMITTED_UNSIGNED`. The braid re-hashed the decoded payload itself and it matched the envelope digest. The payload is the canonical JSON of the receipt body. The adapter's own same-process re-derivation also matched.

**Known answers.** 46 claims transcribed from the Lean sources, all bound to the exact bytes and lines they cite: 45 hold in exact arithmetic, 1 does not. `Lutar/Innovations/round4/YBCHeronConvergence.lean` line 6 calls `1;24,51,10` the second Heron iterate from 1. From 1 the iterates are `3/2`, `17/12`, `577/408`. The second is `17/12`. It is the third, `577/408`, that agrees with `1;24,51,10 = 30547/21600` after truncation to three sexagesimal places, and it exceeds that value by exactly `1/367200`. Started from `3/2` instead, `577/408` would be the second iterate; that reading is ours, not the file's. The file's theorems use `577/408`; the comment is the discrepancy. Reported, not corrected.

**The loop closes.** Two complete, independent executions of the whole pipeline were run, each with its own fresh kernel build:

- the genesis turn `final-1` (`braid-turn:d610f2a2e33c7144ff5519ac7a20e833`);
- the next turn `final-2` (`braid-turn:534db3c682e658a095ee32cde13911dd`).

They produced the same `state_digest` (`8b978e27d7912517…`). `final-2` had ordinal 2, verified `final-1`'s Lake receipt (`VERIFIED_UNSIGNED_BINDS_PREVIOUS_TURN`), compared its proof debt with `final-1` (every difference 0) and reported `ouroboros_fixed_point: true`. Each turn was verified from its written files and replayed byte for byte before it was published, and `execution/ouroboros-braid-v2/README.md` shows how to repeat the replay.

**Outcome:** `HOLD`, refused before aggregation, with one reason left: `DATABASE_PLAN_NOT_SUPPLIED`. Every other input binds to the census and is MEASURED in the same run. Six of the eight axes were formed, and none of them is an aggregate:

- source cords 1/1;
- kernel-accepted files 252 of 309 judged (84/103);
- trust-base-only theorems 1702/1767;
- locked-set guard 1/1;
- known answers 45/46;
- Hatun ladder 1/1.

The database plan belongs to the database-admission lane. No plan was supplied here, so no aggregate is formed and no score is implied.

**The first hosted turn.** On 2026-11-23 the scheduled workflow ran once on a GitHub-hosted `ubuntu-24.04` runner, on `main` at `67fda94` (run [45117369582](https://github.com/szl-holdings/szl-org-health/actions/runs/45117369582), artifact `braid-turn`, digest `sha256:774ca539b8b6cd33ae9d5388e885c9c3818bef2648b2bd72b706d60b558cbf91`):

- The runner granted an empty network namespace (`EMPTY_NETWORK_NAMESPACE`).
- Census `COMPLETE`, Hatun `VETO_LADDER_CONFORMS`, known answers 45 of 46, Lake receipt `CANONICAL_RECEIPT_EMITTED_UNSIGNED`.
- The turn was re-verified from its written files and replayed byte for byte.
- The Lean witness was `UNAVAILABLE`, so the turn held with `LEAN_WITNESS_NOT_BOUND_TO_CENSUS` and `DATABASE_PLAN_NOT_SUPPLIED`. The merged code started Lean in a new PID namespace, where Lean cannot locate its own binary through `/proc`; this change returns Lean to a network-only namespace. The next hosted turn rejects that turn as a previous turn (it has an older shape), records the rejection and starts a new chain.

**A repair candidate, and why it is not ready.** A local commit repairs 46 `lutar-lean` files. The patch and its tree id are in `execution/ouroboros-braid-v2/lutar-lean-candidate/`, and it has not been pushed to `lutar-lean`. Its turn, `candidate-final`, shows the following.

- **Acceptance:** the kernel now accepts 44 files it rejected at `98f1735`. Rejected files fall from 57 to 13, all 296 accepted modules were built by this run, and no file outside the patch changed status.
- **Census:** the axiom census fails, so the witness is `HOLD` (`AXIOM_CENSUS_UNAVAILABLE`). The census imports every accepted module together, and two of them, `Lutar/PACBayes.lean` (line 103) and the newly compiling `Lutar/PACBayes/PACBayes.lean` (line 94), both define `Lutar.PACBayes.pacBayesBound`. Each builds alone; together they cannot be imported.
- **Consequences:** the theorem classes of the candidate are unknown, the ratchet does not compare it with the floor (`NOT_COMPARABLE_NO_EXECUTED_KERNEL_WITNESS`) and the carrier is unknown.
- **Known answers:** 8 of the 46 go stale, because the repairs edited the lines they cite, and the remaining 37 of 38 hold.

The turn holds with `LEAN_WITNESS_NOT_KERNEL_EXECUTED`, `KHIPU_LEAN_CARRIER_NOT_KERNEL_CLEAN`, `KNOWN_ANSWERS_NOT_ALL_BOUND` and `DATABASE_PLAN_NOT_SUPPLIED`. The next step for the candidate is to resolve the duplicate declaration.

**A negative result, recorded.** We looked for a threshold defect in the estate's floating-point admit rule (`a11oy/szl_verify_nine.py` at `02fe789`, blob `fa3291b5`) by comparing it with the exact rule at τ = 0.80. The inputs were 312,601 two-decimal multisets: every multiset of one to three axes on [0.01, 1.00], and of four axes on [0.60, 1.00]. We also tried all 316 inputs with up to nine axes whose geometric mean equals τ exactly, at τ = 0.80 and 0.70 (164 unweighted, 152 weighted). Disagreements: 0. The script and its result are in `execution/ouroboros-braid-v2/experiments/`. The exact rule is used here for reproducible receipts, not because the floating-point rule was found wrong.

**Three statements in `lutar-lean` cannot be what their names say.** Each check below is a Lean file the kernel accepted against the commit above; the files and their full outputs are in `execution/ouroboros-braid-v2/soundness/`.

- The declared axiom `Lutar.Wave4.BlockConsistency.A6'_block_consistent` is inconsistent. `theorem a6_inconsistent : False` is accepted using only that axiom and the standard three, with the corpus's own `Lutar.Round13.maxAgg` as the counterexample. Its one dependent, `lambda_unique_under_block`, therefore holds only vacuously.
- `Lutar.Lambda.Majorises y x` holds exactly when `y = x`. So the axiom `lambda_schur_concave_n_axis` is provable from reflexivity with no axiom of its own. For the usual majorisation order, its inequality would point the wrong way for Schur concavity.
- The statement of `Lutar.lutar_is_geomean` is false (the two-axis maximum at (1,0) satisfies all five axioms but is not `Λ 2`), and so is the statement of `lutar_unique`. The corpus's own comments already say the five axioms do not pin down `Λ`.

None of this changes the locked count (8). Unconditional Λ-uniqueness stays disproven as stated; uniqueness under further axioms stays Conjecture 1, and one proposed further axiom is now shown inconsistent.

## What a turn does not establish

- It does not show that a checkout equals the protected remote branch, who authored a commit, or that any file is deployed.
- It is one elaboration by one toolchain on one machine. It is not an independent second kernel (`independent_kernel_replay: false`) and not a review of what any theorem means. A theorem with a clean footprint can still say less than its name suggests; three examples are in `execution/ouroboros-braid-v2/soundness/`.
- Dependency `.olean` files (Mathlib and the rest of the manifest) come from their published cache and are trusted, not re-checked. The witness records the manifest digest, each package's pinned and checked-out revision and how many dependency objects it found.
- The dependency cache is trusted as code, not only as data: Lean runs the initializer code of every `.olean` it imports, so whoever can write into the cache can make the Lean witness report anything. The witness runs the pinned toolchain's `lean` directly, checks Lean's search path for project namespaces and proves every project module was loaded from the fresh export, which closes the routes that do not need that capability. Pinning a digest of the cache's build products is ROADMAP.
- Theorem classes are as the kernel census program reported them. The witness carries the digest of the census rows, not the rows. Re-running the witness on the same commit reproduces that digest; the cached run and the fresh run here both gave `1cb01f14…`.
- Network isolation is what the host gave. On this container every Lean, Hatun and Lake child ran in an empty network namespace (`EMPTY_NETWORK_NAMESPACE`). A runner without unprivileged user namespaces records `NOT_AVAILABLE_ON_THIS_HOST`; isolation is recorded, it is not a gate. Filesystem UNIX sockets stay reachable because no mount namespace is created.
- The Hatun result is about committed source run locally. The caller context was set through hatun-mcp's own test hooks (`SET_THROUGH_HATUN_TEST_HOOKS`); the API-key authentication path itself was not exercised. No deployed Hatun runtime was contacted, no identity was established, and no second approver exists or is claimed. Hatun does not understand action text; the braid classifies effects itself and treats every database work order as state-changing.
- The Lake receipt is unsigned. The parent re-hashed the decoded payload and it matched, the payload is the canonical JSON of the receipt body, and the adapter's own same-process re-derivation also matched. An unsigned receipt identifies content; it is never a pass. A signature requires the keyless attestation job (off until the owner enables it) or the estate signer.
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
  --checkout szl-holdings/lutar-lean=<clean checkout> \
  --lean-packages-dir <its .lake/packages, from `lake exe cache get`> \
  --checkout szl-holdings/hatun-mcp=<checkout> --checkout szl-holdings/szl-lake=<checkout> \
  --checkout <one per remaining policy repository> \
  --lean-toolchain-bin <absolute directory holding lake and lean> \
  --python <absolute interpreter installed from requirements-braid.lock> \
  --previous-dir <directory of the previous turn, omit for a genesis turn> \
  --out-dir <new or empty directory outside every checkout>
```

Exit 0 means the turn closed, re-verified from its written files and replayed byte for byte, on `HOLD` or on `EVIDENCE_THRESHOLD_MET_NO_AUTHORITY`; read `turn.json` for which. Exit 3 means a refusal: `--out-dir` stays empty, and any partial files are kept in `<out-dir>.refused` next to a `REFUSED.json`, so they can never be mistaken for a turn. A previous turn that does not verify (edited, or written by an older shape of these tools) is not consumed: the new turn records it in `previous_turn_rejected`, holds with `PREVIOUS_TURN_REJECTED` and starts a new chain, so the weekly loop keeps running visibly instead of failing. Each tool also runs on its own. The orchestrator alone returns 2 for a closed turn and never 0, like v1, and `--replay TURN.json` re-runs a recorded turn from the same evidence and compares bytes.

The scheduled workflow performs the same turn weekly and on dispatch. Its first run is described above under *The first hosted turn*. Its Lean witness was `UNAVAILABLE` for a reason this change fixes. No hosted run of this change exists yet.

## Open gates

1. The database-admission lane's plan (catalog coverage, causal frontier, auditor role). Until a plan is supplied, every turn here refuses the aggregate with `DATABASE_PLAN_NOT_SUPPLIED`, and on the evidence above that is the only reason left. A plan whose lane itself says `HOLD` would refuse with `DATABASE_LANE_HOLD`.
2. A real signature on the turn's receipt.
3. An independent kernel replay, and re-checking the dependency `.olean` files instead of trusting the cache.
4. Owner ratification of the family map and the known-answer set.
5. The 57 files the kernel rejects, the 25 theorems that rest on `sorryAx`, and the 31 declared axioms, one of which is inconsistent. These are measurements of `lutar-lean`, tracked by the ratchet floor in the policy. Lowering them is work in that repository: the candidate above is offered as a patch and has not been pushed there.
6. Process-tree isolation for long-running children (a cgroup or container). A descendant that leaves its process group with `setsid()` survives a timeout today; the Hatun and Lake children add a PID namespace where the host allows it, the Lean children cannot (Lean locates its own binary through `/proc`).

**Scope of novelty:** a composition that makes existing SZL systems account for themselves in one bounded loop. Hash trees, sum trees, bounded loops, proof assistants, namespaces and geometric means were not invented here. The value is that missing evidence stays missing, a verdict cannot be edited without the verifier noticing, and measured debt cannot rise quietly.
