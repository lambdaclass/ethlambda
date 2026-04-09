/-
Copyright (c) 2026 ethlambda contributors. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import EthLambdaProofs.Justifiability.PronicDetection

/-!
# Classification Theorem
-/

/-- The classification theorem: `Justifiable` ↔ computable sqrt-based check. -/
theorem justifiable_iff (d : ℕ) :
    Justifiable d ↔
      (d ≤ 5 ∨ Nat.sqrt d ^ 2 = d ∨
        (Nat.sqrt (4 * d + 1) ^ 2 = 4 * d + 1 ∧
         (4 * d + 1) % 2 = 1)) := by
  unfold Justifiable
  constructor
  · rintro (h | h | h)
    · exact Or.inl h
    · exact Or.inr (Or.inl ((isSquare_iff_sqrt d).mp h))
    · exact Or.inr (Or.inr ((isPronic_iff_sqrt d).mp h))
  · rintro (h | h | h)
    · exact Or.inl h
    · exact Or.inr (Or.inl ((isSquare_iff_sqrt d).mpr h))
    · exact Or.inr (Or.inr ((isPronic_iff_sqrt d).mpr h))
