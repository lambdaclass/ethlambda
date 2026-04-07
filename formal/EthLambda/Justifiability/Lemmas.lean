/-
Copyright (c) 2026 ethlambda contributors. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import EthLambda.Justifiability.Defs

/-!
# Core Algebraic Lemmas for Justifiability

Foundational lemmas used by the pronic detection and classification theorems.
-/

/-- The fundamental identity: `4 * n * (n + 1) + 1 = (2 * n + 1) ^ 2`.
    This connects pronic numbers to odd perfect squares. -/
theorem pronic_identity (n : ℕ) : 4 * (n * (n + 1)) + 1 = (2 * n + 1) ^ 2 := by
  ring

/-- A number is a perfect square iff `Nat.sqrt` round-trips. -/
theorem isSquare_iff_sqrt (k : ℕ) : IsSquare k ↔ Nat.sqrt k ^ 2 = k := by
  rw [IsSquare, ← Nat.exists_mul_self']
  constructor
  · rintro ⟨r, rfl⟩; exact ⟨r, sq r⟩
  · rintro ⟨n, hn⟩; exact ⟨n, by nlinarith [hn]⟩

/-- All deltas 0 through 5 are justifiable. -/
theorem small_justifiable (d : ℕ) (h : d ≤ 5) : Justifiable d := Or.inl h
