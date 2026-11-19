-- SPDX-License-Identifier: Apache-2.0
import Lutar.Lambda.SchurConcave

namespace Probe

open Lutar Lutar.Lambda NNReal Finset

/-- Singleton subsets alone force pointwise domination `x i ≤ y i`. -/
theorem majorises_pointwise_le {k : ℕ} {y x : Axes k} (h : Majorises y x) (i : Fin k) :
    x i ≤ y i := by
  have := h.2 {i}
  simpa using this

/-- MAJORISES_FORCES_EQUALITY: the corpus's `Majorises` relation is equality. -/
theorem majorises_forces_eq {k : ℕ} {y x : Axes k} (h : Majorises y x) : y = x := by
  have hle : ∀ i ∈ (univ : Finset (Fin k)), x i ≤ y i :=
    fun i _ => majorises_pointwise_le h i
  have hall := (Finset.sum_eq_sum_iff_of_le hle).mp h.1.symm
  funext i
  exact (hall i (mem_univ i)).symm

/-- Conversely every vector majorises itself, so `Majorises y x ↔ y = x`. -/
theorem majorises_iff_eq {k : ℕ} (y x : Axes k) : Majorises y x ↔ y = x := by
  constructor
  · exact majorises_forces_eq
  · rintro rfl
    exact ⟨rfl, fun S => le_refl _⟩

/-- AXIOM_STATEMENT_PROVABLE_WITHOUT_AXIOM: the exact statement of
`Lutar.Lambda.lambda_schur_concave_n_axis`, proved from reflexivity. -/
theorem lambda_schur_concave_n_axis_thm (k : ℕ) (_hk : 0 < k) (x y : Axes k)
    (h_major : Majorises y x) :
    Lutar.Λ k x ≤ Lutar.Λ k y := by
  rw [majorises_forces_eq h_major]

/-- Sanity: the axiom's own type (read off by `type_of%`, which puts only the type, not the
axiom constant, into the term) is inhabited by the axiom-free theorem above. -/
theorem axiom_type_inhabited_without_axiom :
    type_of% @Lutar.Lambda.lambda_schur_concave_n_axis :=
  lambda_schur_concave_n_axis_thm

/-- A genuine majorisation pair (y = (1,0) ≻ x = (1/2,1/2)) is NOT related by `Majorises`;
the corpus relation misses the standard example. -/
theorem standard_pair_not_majorises :
    ¬ Majorises (k := 2) ![1, 0] ![1/2, 1/2] := by
  intro h
  have := congrFun (majorises_forces_eq h) 1
  simp at this

end Probe

#print axioms Probe.majorises_pointwise_le
#print axioms Probe.majorises_forces_eq
#print axioms Probe.majorises_iff_eq
#print axioms Probe.lambda_schur_concave_n_axis_thm
#print axioms Probe.axiom_type_inhabited_without_axiom
#print axioms Probe.standard_pair_not_majorises
#print axioms Lutar.Lambda.lambda_schur_concave_n_axis
