<!-- SPDX-License-Identifier: Apache-2.0 -->
# Soundness checks of three lutar-lean statements

Each `.lean` file here was elaborated with Lean 4.35.0 against `szl-holdings/lutar-lean` at
`98f1735bb23085a2979e0a22643a032ce98a27c9`. It used that commit's `.olean` files, built in the
same container, and `lake env lean <file>`. The `.out` file next to each file is the complete
kernel output of that run, including `#print axioms` lines. Each `.out` ends with the run's
wall-clock time from `time -p`. None of these files changes lutar-lean. They are reports for
its owner, not repairs.

To reproduce, run `lake env lean /path/to/File.lean` from a lutar-lean checkout at that commit
after `lake build`.

| File | What the kernel accepted | Axioms used |
| --- | --- | --- |
| `A6BlockConsistentInconsistent.lean` | `theorem a6_inconsistent : False`. The declared axiom `Lutar.Wave4.BlockConsistency.A6'_block_consistent`, applied to the corpus's own `Lutar.Round13.maxAgg` (which satisfies all of `Lutar.LutarAxioms`), forces `max` on two axes to factor as `x0^a * x1^b`. The points (1,0), (0,1) and (0,0) refute that. | the standard three plus `A6'_block_consistent` |
| `A6BlockConsistentDependents.lean` | A scan of every constant in a module under `Lutar` for transitive use of that axiom. | none (it only reads the environment) |
| `MajorisesIsEquality.lean` | `Lutar.Lambda.Majorises y x ↔ y = x`. The axiom `Lutar.Lambda.lambda_schur_concave_n_axis`, stated verbatim, is then a theorem proved from reflexivity with no axiom of its own. The standard majorisation pair (1,0) ≻ (1/2,1/2) is not related by `Majorises`. | the standard three only |
| `SchurDirection.lean` | For that standard pair, `¬ (Λ 2 (1/2,1/2) ≤ Λ 2 (1,0))`. For the usual majorisation order, the inequality the axiom states would run the wrong way for Schur concavity. | the standard three only |
| `LutarIsGeomeanStatementFalse.lean` | The statement of `Lutar.lutar_is_geomean` (and of its only dependent, `Lutar.lutar_unique`) is false. The two-axis maximum satisfies A1 to A5 of `Lutar.LutarAxioms` but differs from `Λ 2` at (1,0). The proposition is checked against the constant's own type by `rfl`. | the standard three only |

What this means:

- An inconsistent axiom proves anything. Any theorem that depends on `A6'_block_consistent`
  holds only vacuously. The scan in `A6BlockConsistentDependents.out` lists those dependents.
  `Lutar.lean` imports the module that declares the axiom.
- `lambda_schur_concave_n_axis` costs nothing to remove: its statement is already provable.
  It also says less than its name suggests, because `Majorises` as defined is equality.
- `lutar_is_geomean` is proved with `sorry` in the corpus. Its statement is false, so it cannot
  be proved. The corpus's own comments already record that the five axioms do not pin down `Λ`.

The standard three axioms are `propext`, `Classical.choice` and `Quot.sound`. Nothing here
touches the locked count (8 locked-proven formulas `{F1, F4, F7, F11, F12, F18, F19, F22}`).
Unconditional Λ-uniqueness is disproven as stated, which is the braid policy's fixed claim
`UNCONDITIONAL_UNIQUENESS_DISPROVEN_AS_STATED`. Uniqueness under further axioms remains
Conjecture 1. These checks show that one proposed further axiom (`A6'_block_consistent`) is
inconsistent, so it cannot be the one.
