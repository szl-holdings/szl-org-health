-- SPDX-License-Identifier: Apache-2.0
import Lutar.Lambda.SchurConcave

open Lutar NNReal Finset

-- With standard majorisation y=(1,0) ≻ x=(1/2,1/2), the axiom's conclusion Λ x ≤ Λ y would be false.
theorem direction_check : ¬ (Lutar.Λ 2 ![1/2, 1/2] ≤ Lutar.Λ 2 ![1, 0]) := by
  have h0 : Lutar.Λ 2 ![1, 0] = 0 := by
    simp [Lutar.Λ, Fin.prod_univ_two]
  have h1 : Lutar.Λ 2 ![1/2, 1/2] ≠ 0 := by
    simp [Lutar.Λ, Fin.prod_univ_two]
  rw [h0]; intro h; exact h1 (le_antisymm h zero_le)

#print axioms direction_check
