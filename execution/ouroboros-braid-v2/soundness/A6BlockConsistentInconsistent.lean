-- SPDX-License-Identifier: Apache-2.0
import Lutar.Wave4.LambdaBlockConsistency

/-!
Soundness probe for the declared axiom
`Lutar.Wave4.BlockConsistency.A6'_block_consistent`.

`Lutar.Round13.maxAgg` (x ↦ x 0 ⊔ x 1 on two axes) satisfies all five predicates
bundled in `Lutar.LutarAxioms`. The corpus proves A2, A3, A5 for it; A1 and A4 are
proved here. Instantiating the axiom at `maxAgg` yields a power-product
factorization of `max`, which is refuted at the points (1,0), (0,1), (0,0).
-/

open NNReal

namespace Soundness.A6BlockConsistent

theorem maxAgg_A1 : Lutar.IsMonotone Lutar.Round13.maxAgg := by
  intro x y hxy
  simp only [Lutar.Round13.maxAgg]
  exact sup_le_sup (hxy 0) (hxy 1)

theorem maxAgg_A4 : Lutar.IsBounded (by norm_num : 0 < 2) Lutar.Round13.maxAgg := by
  intro x
  simp only [Lutar.Round13.maxAgg]
  exact sup_le (Finset.le_sup' x (Finset.mem_univ 0)) (Finset.le_sup' x (Finset.mem_univ 1))

theorem maxAgg_lutarAxioms : Lutar.LutarAxioms Lutar.Round13.maxAgg where
  A1 := maxAgg_A1
  A2 := Lutar.Round13.maxAgg_A2
  A3 := { k_pos := by norm_num, A3_normalize := Lutar.Round13.maxAgg_A3 }
  A4 := maxAgg_A4
  A5 := Lutar.Round13.maxAgg_A5

/-- `max` on two axes is not a power product `x 0 ^ a * x 1 ^ b` for any exponents. -/
theorem maxAgg_not_factors (αs : Fin 2 → NNReal) :
    ¬ Lutar.Round13.Factors Lutar.Round13.maxAgg αs := by
  intro hfac
  have h10 := hfac ![1, 0]
  have h01 := hfac ![0, 1]
  have h00 := hfac ![0, 0]
  simp only [Lutar.Round13.maxAgg, Fin.prod_univ_two, Matrix.cons_val_zero,
    Matrix.cons_val_one] at h10 h01 h00
  have ha1 : ((αs 1 : NNReal) : ℝ) = 0 := by
    by_contra hne
    rw [NNReal.zero_rpow hne, NNReal.one_rpow, mul_zero] at h10
    simp at h10
  have ha0 : ((αs 0 : NNReal) : ℝ) = 0 := by
    by_contra hne
    rw [NNReal.zero_rpow hne, NNReal.one_rpow, zero_mul] at h01
    simp at h01
  rw [ha0, ha1, NNReal.rpow_zero, mul_one] at h00
  simp at h00

/-- The declared axiom `A6'_block_consistent` is inconsistent with the corpus
    definitions: it forces `maxAgg` to factor, which it does not. -/
theorem a6_inconsistent : False := by
  obtain ⟨αs, hfac⟩ :=
    Lutar.Wave4.BlockConsistency.A6'_block_consistent (k := 2) (by norm_num)
      Lutar.Round13.maxAgg maxAgg_lutarAxioms
  exact maxAgg_not_factors αs hfac

/-- Second route, through the corpus's own conditional theorem
    `lambda_unique_under_block` (axiom + `lambda_unique_of_factors`) and the
    corpus counterexample `maxAgg_ne_Lambda`. -/
theorem a6_inconsistent_via_corpus_uniqueness : False :=
  Lutar.Round13.maxAgg_ne_Lambda
    (Lutar.Wave4.BlockConsistency.lambda_unique_under_block (by norm_num)
      Lutar.Round13.maxAgg maxAgg_lutarAxioms)

end Soundness.A6BlockConsistent

#print axioms Soundness.A6BlockConsistent.maxAgg_lutarAxioms
#print axioms Soundness.A6BlockConsistent.maxAgg_not_factors
#print axioms Soundness.A6BlockConsistent.a6_inconsistent_via_corpus_uniqueness
#print axioms Soundness.A6BlockConsistent.a6_inconsistent
