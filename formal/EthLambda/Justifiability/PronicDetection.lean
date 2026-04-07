/-
Copyright (c) 2026 ethlambda contributors. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import EthLambda.Justifiability.Lemmas

/-!
# Pronic Number Detection via Integer Square Root

Proves that the Rust `isqrt`-based trick correctly detects pronic numbers:
  `k` is pronic ↔ `4*k + 1` is an odd perfect square.

The key identity is `4 * n * (n+1) + 1 = (2*n+1)^2`.
-/

/-- `k` is pronic iff `4*k+1` is an odd perfect square.
    This is the mathematical justification for the Rust isqrt trick. -/
theorem isPronic_iff_sqrt (k : ℕ) :
    IsPronic k ↔
      Nat.sqrt (4 * k + 1) ^ 2 = 4 * k + 1 ∧
      (4 * k + 1) % 2 = 1 := by
  constructor
  · -- Forward: k = n*(n+1) implies 4k+1 = (2n+1)^2 (odd perfect square)
    rintro ⟨n, rfl⟩
    refine ⟨?_, by omega⟩
    have h1 : 4 * (n * (n + 1)) + 1 = (2 * n + 1) * (2 * n + 1) := by ring
    rw [h1, Nat.sqrt_eq, sq]
  · -- Backward: 4k+1 is an odd perfect square implies k is pronic
    intro ⟨hsq, hodd⟩
    set s := Nat.sqrt (4 * k + 1) with hs_def
    -- s^2 = 4k+1 is odd, so s must be odd (even^2 is even)
    have s_odd : s % 2 = 1 := by
      rcases Nat.even_or_odd s with ⟨t, ht⟩ | ⟨t, ht⟩
      · exfalso
        have : s ^ 2 % 2 = 0 := by rw [ht]; ring_nf; omega
        omega
      · omega
    -- Write s = 2*m + 1, then (2m+1)^2 = 4k+1, so k = m*(m+1)
    refine ⟨s / 2, ?_⟩
    have hm : s = 2 * (s / 2) + 1 := by omega
    have key : (2 * (s / 2) + 1) ^ 2 = 4 * k + 1 := by rw [← hm]; exact hsq
    nlinarith [key]
