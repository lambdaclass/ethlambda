/-
Copyright (c) 2026 ethlambda contributors. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import EthLambdaProofs.Justifiability.Lemmas

/-!
# Pronic Number Detection via Integer Square Root
-/

/-- `k` is pronic iff `4*k+1` is an odd perfect square. -/
theorem isPronic_iff_sqrt (k : ℕ) :
    IsPronic k ↔
      Nat.sqrt (4 * k + 1) ^ 2 = 4 * k + 1 ∧
      (4 * k + 1) % 2 = 1 := by
  constructor
  · rintro ⟨n, rfl⟩
    refine ⟨?_, by omega⟩
    have h1 : 4 * (n * (n + 1)) + 1 = (2 * n + 1) * (2 * n + 1) := by ring
    rw [h1, Nat.sqrt_eq, sq]
  · intro ⟨hsq, hodd⟩
    set s := Nat.sqrt (4 * k + 1) with hs_def
    have s_odd : s % 2 = 1 := by
      rcases Nat.even_or_odd s with ⟨t, ht⟩ | ⟨t, ht⟩
      · exfalso
        have : s ^ 2 % 2 = 0 := by rw [ht]; ring_nf; omega
        omega
      · omega
    refine ⟨s / 2, ?_⟩
    have hm : s = 2 * (s / 2) + 1 := by omega
    have key : (2 * (s / 2) + 1) ^ 2 = 4 * k + 1 := by rw [← hm]; exact hsq
    nlinarith [key]
