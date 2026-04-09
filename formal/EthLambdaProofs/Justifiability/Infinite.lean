/-
Copyright (c) 2026 ethlambda contributors. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import EthLambdaProofs.Justifiability.Defs

/-!
# Justifiable Slots Are Infinite
-/

/-- Perfect squares are always justifiable. -/
theorem justifiable_of_sq (n : ℕ) : Justifiable (n ^ 2) :=
  Or.inr (Or.inl ⟨n, by ring⟩)

/-- There are arbitrarily large justifiable deltas. -/
theorem justifiable_unbounded : ∀ N : ℕ, ∃ d, d > N ∧ Justifiable d := by
  intro N
  refine ⟨(N + 1) ^ 2, ?_, justifiable_of_sq (N + 1)⟩
  nlinarith [Nat.zero_le N]
