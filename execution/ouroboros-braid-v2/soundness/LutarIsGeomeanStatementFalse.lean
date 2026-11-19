-- SPDX-License-Identifier: Apache-2.0
/-
Soundness check: the statement of `Lutar.lutar_is_geomean` is false.
Kernel-checks that the STATEMENT of `Lutar.lutar_is_geomean` is false by exhibiting
the 2-axis maximum aggregator, which satisfies every field of `Lutar.LutarAxioms`
(A1 monotone, A2 1-homogeneous, A3 diagonal normalization, A4 bounded by max axis,
A5 permutation invariant) but differs from `Lutar.Λ 2` at the input (1, 0).
No sorry / axiom / native_decide is used here.
-/
import Lutar.Uniqueness

open NNReal

namespace Soundness.LutarIsGeomeanFalse

/-- Counterexample aggregator on k = 2 axes: the maximum of the two axes. -/
noncomputable def maxAgg2 : Lutar.Aggregator 2 := fun x => x 0 ⊔ x 1

/-- A1: monotone. -/
theorem maxAgg2_A1 : Lutar.IsMonotone maxAgg2 :=
  fun _ _ h => sup_le_sup (h 0) (h 1)

/-- A2: positive homogeneity of degree 1. -/
theorem maxAgg2_A2 : Lutar.IsHomogeneous maxAgg2 := by
  intro c x
  show (c * x 0) ⊔ (c * x 1) = c * (x 0 ⊔ x 1)
  exact (NNReal.mul_sup c (x 0) (x 1)).symm

/-- A3: k > 0 and the diagonal normalization `Φ (fun _ => c) = c`. -/
theorem maxAgg2_A3 : Lutar.IsEgyptianExact 2 maxAgg2 :=
  { k_pos := by decide
    A3_normalize := fun c => sup_idem c }

/-- A4: bounded by the max axis, stated exactly with the `IsBounded` definition. -/
theorem maxAgg2_A4 : Lutar.IsBounded maxAgg2_A3.k_pos maxAgg2 := by
  intro x
  show x 0 ⊔ x 1 ≤ _
  exact sup_le (Finset.le_sup' x (Finset.mem_univ 0)) (Finset.le_sup' x (Finset.mem_univ 1))

/-- A5: permutation invariance. Any permutation of `Fin 2` fixes or swaps 0 and 1. -/
theorem maxAgg2_A5 : Lutar.IsPermutationInvariant maxAgg2 := by
  intro x σ
  show x (σ 0) ⊔ x (σ 1) = x 0 ⊔ x 1
  have hne : (σ 0).val ≠ (σ 1).val := fun h =>
    absurd (σ.injective (Fin.ext h)) (by decide)
  have v0 := (σ 0).isLt
  have v1 := (σ 1).isLt
  have hcases : ((σ 0).val = 0 ∧ (σ 1).val = 1) ∨ ((σ 0).val = 1 ∧ (σ 1).val = 0) := by
    omega
  rcases hcases with ⟨a, b⟩ | ⟨a, b⟩
  · have a' : σ 0 = 0 := Fin.ext a
    have b' : σ 1 = 1 := Fin.ext b
    rw [a', b']
  · have a' : σ 0 = 1 := Fin.ext a
    have b' : σ 1 = 0 := Fin.ext b
    rw [a', b', sup_comm]

/-- The max aggregator satisfies all of `Lutar.LutarAxioms` (A1–A5). -/
theorem maxAgg2_lutarAxioms : Lutar.LutarAxioms maxAgg2 :=
  { A1 := maxAgg2_A1
    A2 := maxAgg2_A2
    A3 := maxAgg2_A3
    A4 := maxAgg2_A4
    A5 := maxAgg2_A5 }

/-- At (1, 0): max = 1 but the geometric mean Λ 2 = (1·0)^(1/2) = 0. -/
theorem maxAgg2_ne_Lambda : maxAgg2 ≠ Lutar.Λ 2 := by
  intro h
  have hx := congrFun h (![1, 0] : Lutar.Axes 2)
  have hL : maxAgg2 (![1, 0] : Lutar.Axes 2) = 1 := by
    show (1 : NNReal) ⊔ 0 = 1
    exact sup_of_le_left zero_le
  have hR : Lutar.Λ 2 (![1, 0] : Lutar.Axes 2) = 0 := by
    rw [Lutar.Λ_def (by decide : 0 < 2)]
    have hprod : (∏ i, (![1, 0] : Lutar.Axes 2) i) = 0 := by
      rw [Fin.prod_univ_two]
      show (1 : NNReal) * 0 = 0
      exact mul_zero 1
    rw [hprod]
    exact NNReal.zero_rpow (by norm_num)
  rw [hL, hR] at hx
  exact one_ne_zero hx

/-- Verbatim transcription of the statement of `Lutar.lutar_is_geomean`, under a "not". -/
theorem lutar_is_geomean_statement_false :
    ¬ (∀ {k : Nat} (_hk : 0 < k) (Phi : Lutar.Aggregator k) (_hL : Lutar.LutarAxioms Phi),
        Phi = Lutar.Λ k) := by
  intro h
  exact maxAgg2_ne_Lambda (h (k := 2) (by decide) maxAgg2 maxAgg2_lutarAxioms)

/-- No transcription gap: the transcribed proposition is definitionally the type of the
    existing constant (checked by `rfl` on `Prop`). -/
theorem transcription_matches :
    (type_of% @Lutar.lutar_is_geomean) =
      (∀ {k : Nat} (_hk : 0 < k) (Phi : Lutar.Aggregator k) (_hL : Lutar.LutarAxioms Phi),
        Phi = Lutar.Λ k) := rfl

/-- Negation stated directly against the type of the existing constant. -/
theorem lutar_is_geomean_type_false : ¬ (type_of% @Lutar.lutar_is_geomean) := by
  intro h
  exact maxAgg2_ne_Lambda (h (k := 2) (by decide) maxAgg2 maxAgg2_lutarAxioms)

example (h : type_of% @Lutar.lutar_is_geomean) : False :=
  lutar_is_geomean_type_false h

/-- Any proof of the statement, such as the corpus's `sorry`-backed one, yields `False`
    when applied to the counterexample. -/
theorem lutar_is_geomean_implies_false
    (h : ∀ {k : Nat} (_hk : 0 < k) (Phi : Lutar.Aggregator k) (_hL : Lutar.LutarAxioms Phi),
        Phi = Lutar.Λ k) : False :=
  lutar_is_geomean_statement_false h

/-- Bonus: the statement of the sole corpus dependent, `Lutar.lutar_unique`, is also false:
    `maxAgg2` and `Lutar.Λ 2` both satisfy A1–A5 (the latter by the corpus's own
    `Lutar.lambda_satisfiesAxioms`) yet differ. -/
theorem lutar_unique_type_false : ¬ (type_of% @Lutar.lutar_unique) := by
  intro h
  exact maxAgg2_ne_Lambda
    (h (k := 2) (by decide) maxAgg2 (Lutar.Λ 2) maxAgg2_lutarAxioms
      (Lutar.lambda_satisfiesAxioms (by decide)))

end Soundness.LutarIsGeomeanFalse

#print axioms Soundness.LutarIsGeomeanFalse.maxAgg2_lutarAxioms
#print axioms Soundness.LutarIsGeomeanFalse.maxAgg2_ne_Lambda
#print axioms Soundness.LutarIsGeomeanFalse.transcription_matches
#print axioms Soundness.LutarIsGeomeanFalse.lutar_unique_type_false
#print axioms Soundness.LutarIsGeomeanFalse.lutar_is_geomean_type_false
#print axioms Soundness.LutarIsGeomeanFalse.lutar_is_geomean_statement_false
