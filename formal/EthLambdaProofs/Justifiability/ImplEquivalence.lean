/-
Copyright (c) 2026 ethlambda contributors. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import EthLambdaProofs.Justifiability.Classification

set_option linter.style.whitespace false
set_option linter.style.show false

/-!
# Bridge: Connecting the Implementation to the Proofs

This module closes the trust gap between the two Lean libraries:
- `EthLambda.Justifiability`: UInt64 implementation (compiled into Rust binary)
- `EthLambdaProofs.Justifiability`: Nat-based proofs (verification only)

## Trust Chain

```
  Rust FFI → UInt64 justifiable → Nat Justifiable → mathematical definition
               (justifiable_equiv)    (justifiable_iff, Classification.lean)
```

## Overflow Safety

The implementation uses division-based correction (`r+1 ≤ n/(r+1)` instead of
`(r+1)*(r+1) ≤ n`) and starts Newton's method from `n/2+1` instead of `n`,
which avoids all UInt64 overflow. The `isqrt_correct` theorem holds for ALL
UInt64 inputs with no bound restriction. The only bound in `justifiable_equiv`
is `d < 2^62`, which ensures `4*d+1` doesn't overflow.
-/

/-! ## Helper: uniqueness of integer square root -/

theorem nat_sqrt_unique (n r : ℕ) (h1 : r * r ≤ n) (h2 : n < (r + 1) * (r + 1)) :
    r = Nat.sqrt n := by
  have hr_le : r ≤ Nat.sqrt n := Nat.le_sqrt.mpr h1
  have hsqrt_le : Nat.sqrt n ≤ r := by
    by_contra h
    push Not at h
    have : (r + 1) * (r + 1) ≤ n := Nat.le_sqrt.mp (by omega)
    linarith
  omega

/-! ## isqrt correctness proof -/

/-! ### Nat-level mirror functions for reasoning -/

/-- Nat-level mirror of `isqrtLoop` for reasoning about the algorithm
    without UInt64 modular arithmetic. -/
private def natIsqrtLoop (n r : Nat) : Nat → Nat
  | 0 => r
  | fuel + 1 =>
    let new_r := (r + n / r) / 2
    if new_r >= r then r
    else natIsqrtLoop n new_r fuel

/-- Nat-level mirror of `isqrt`. -/
private def natIsqrt (n : Nat) : Nat :=
  if n ≤ 1 then n
  else
    let r := natIsqrtLoop n (n / 2 + 1) 64
    if r + 1 ≤ n / (r + 1) then r + 1 else r

/-! ### Newton's method: integer AM-GM and convergence -/

private lemma diff_mul_sum_le_sq (s k : Nat) (hsk : s ≥ k) :
    (s - k) * (s + k) ≤ s * s := by
  obtain ⟨d, rfl⟩ := Nat.exists_eq_add_of_le hsk
  simp only [Nat.add_sub_cancel_left]; nlinarith [k * k]

private lemma div_ge_diff (s k : Nat) (hsk : s ≥ k) (hs_pos : s + k > 0) :
    s * s / (s + k) ≥ s - k := by
  show s - k ≤ s * s / (s + k)
  rw [Nat.le_div_iff_mul_le hs_pos]
  exact diff_mul_sum_le_sq s k hsk

/-- Integer AM-GM for Newton's method: `r + n/r >= 2s` when `r >= s`, `s^2 <= n`, `r > 0`. -/
private lemma newton_amgm (n r s : Nat) (hr_ge : r ≥ s) (hs_sq : s * s ≤ n) (hr_pos : r > 0) :
    r + n / r ≥ 2 * s := by
  have h1 : n / r ≥ s * s / r := Nat.div_le_div_right hs_sq
  suffices h : r + s * s / r ≥ 2 * s by omega
  obtain ⟨k, rfl⟩ := Nat.exists_eq_add_of_le hr_ge
  by_cases hks : k ≤ s
  · have := div_ge_diff s k hks (by omega); omega
  · push Not at hks; have := Nat.zero_le (s * s / (s + k)); omega

/-- Newton step preserves lower bound: `(r + n/r)/2 >= sqrt(n)` when `r >= sqrt(n)`. -/
private theorem newton_step_ge_sqrt (n r : Nat) (hr_ge : r ≥ Nat.sqrt n) (hr_pos : r > 0) :
    (r + n / r) / 2 ≥ Nat.sqrt n := by
  have := newton_amgm n r (Nat.sqrt n) hr_ge (Nat.sqrt_le n) hr_pos; omega

/-- When `r > sqrt(n)`, `n/r <= sqrt(n)` (used to show excess halves). -/
private lemma div_le_sqrt (n r : Nat) (hr : r > Nat.sqrt n) :
    n / r ≤ Nat.sqrt n := by
  have hlt : n < (Nat.sqrt n + 1) * (Nat.sqrt n + 1) := Nat.sqrt_lt.mp (by omega)
  have h1 : n / r ≤ n / (Nat.sqrt n + 1) := Nat.div_le_div_left (by omega) (by omega)
  have h2 : n / (Nat.sqrt n + 1) < Nat.sqrt n + 1 := Nat.div_lt_of_lt_mul hlt
  omega

/-- Each Newton step halves the excess `r - sqrt(n)` (key for logarithmic convergence). -/
private lemma newton_excess_halves (n r : Nat) (hr : r > Nat.sqrt n) :
    (r + n / r) / 2 - Nat.sqrt n ≤ (r - Nat.sqrt n) / 2 := by
  have := div_le_sqrt n r hr; omega

/-! ### Loop convergence -/

/-- `natIsqrtLoop` converges to `Nat.sqrt n` when fuel >= log2(excess).
    Each Newton step halves the distance to the true sqrt, so
    `log2(n - sqrt(n))` steps suffice. With fuel = 64 and n < 2^63,
    the excess is < 2^63 < 2^64, so convergence is guaranteed. -/
private theorem natIsqrtLoop_correct (n r : Nat) (fuel : Nat)
    (hn : n > 0) (hr_pos : r > 0) (hr_ge : r ≥ Nat.sqrt n)
    (hfuel : r - Nat.sqrt n < 2 ^ fuel) :
    natIsqrtLoop n r fuel = Nat.sqrt n := by
  induction fuel generalizing r with
  | zero =>
    simp only [Nat.pow_zero] at hfuel
    simp [natIsqrtLoop]; omega
  | succ k ih =>
    simp only [natIsqrtLoop]
    split
    · -- Stopped: new_r >= r. Must have r = sqrt(n) (otherwise new_r < r by AM-GM).
      rename_i hstop
      by_contra hne
      have hr_gt : r > Nat.sqrt n := by omega
      have : n < r * r := Nat.sqrt_lt.mp hr_gt
      have : n / r < r := by rwa [Nat.div_lt_iff_lt_mul (by omega)]
      omega
    · -- Continued: new_r < r. Show r > sqrt(n), then recurse with halved excess.
      rename_i hcont
      push Not at hcont
      have hr_gt : r > Nat.sqrt n := by
        by_contra hle; push Not at hle
        have heq : r = Nat.sqrt n := Nat.le_antisymm hle hr_ge
        rw [heq] at hcont
        have hpos := Nat.sqrt_pos.mpr hn
        have : n / Nat.sqrt n ≥ Nat.sqrt n :=
          Nat.le_div_iff_mul_le hpos |>.mpr (Nat.sqrt_le n)
        omega
      exact ih _ (by
          have := newton_step_ge_sqrt n r hr_ge hr_pos
          have := Nat.sqrt_pos.mpr hn; omega)
        (newton_step_ge_sqrt n r hr_ge hr_pos) (by
          have := newton_excess_halves n r hr_gt; omega)

/-! ### natIsqrt correctness -/

/-- The starting value `n / 2 + 1 ≥ sqrt(n)` for all `n ≥ 2`. -/
private lemma half_plus_one_ge_sqrt (n : Nat) (hn : n ≥ 2) :
    n / 2 + 1 ≥ Nat.sqrt n := by
  by_contra h
  push Not at h
  -- If sqrt(n) > n/2 + 1, then n/2 + 2 ≤ sqrt(n), so (n/2+2)^2 ≤ n
  have h2 : n / 2 + 2 ≤ Nat.sqrt n := by omega
  have hsq := Nat.le_sqrt.mp h2
  -- (n/2+2)^2 ≥ 3(n/2+2) ≥ 3(n/2) + 6 ≥ n + 6 > n, contradiction
  have : n / 2 + 2 ≥ 3 := by omega
  have : (n / 2 + 2) * (n / 2 + 2) ≥ 3 * (n / 2 + 2) := by nlinarith
  have : 3 * (n / 2) ≥ n := by omega
  omega

/-- The starting value `n / 2 + 1 ≤ n` for `n ≥ 2`. -/
private lemma half_plus_one_le (n : Nat) (hn : n ≥ 2) : n / 2 + 1 ≤ n := by omega

/-- The starting value excess fits in 64 bits of fuel. -/
private lemma half_plus_one_fuel (n : Nat) (hn : n < 2 ^ 64) :
    n / 2 + 1 - Nat.sqrt n < 2 ^ 64 := by omega

/-- `natIsqrt` computes `Nat.sqrt` for all n < 2^64. The correction step handles
    the case where Newton's method undershoots by 1. -/
private theorem natIsqrt_eq_sqrt (n : Nat) (hn : n < 2 ^ 64) :
    natIsqrt n = Nat.sqrt n := by
  simp only [natIsqrt]
  split
  · rename_i hle
    interval_cases n <;> simp
  · rename_i hgt
    push Not at hgt
    have hn2 : n ≥ 2 := by omega
    have hpos : n > 0 := by omega
    have hstart_pos : n / 2 + 1 > 0 := by omega
    have hstart_ge : n / 2 + 1 ≥ Nat.sqrt n := half_plus_one_ge_sqrt n hn2
    have hloop : natIsqrtLoop n (n / 2 + 1) 64 = Nat.sqrt n :=
      natIsqrtLoop_correct n (n / 2 + 1) 64 hpos hstart_pos hstart_ge
        (half_plus_one_fuel n hn)
    simp only [hloop]
    -- The correction step: r+1 ≤ n/(r+1) ↔ (r+1)^2 ≤ n
    have hsqrt_sq : Nat.sqrt n * Nat.sqrt n ≤ n := Nat.sqrt_le n
    have hlt : n < (Nat.sqrt n + 1) * (Nat.sqrt n + 1) := Nat.sqrt_lt.mp (by omega)
    have hpos_s : Nat.sqrt n + 1 > 0 := by omega
    -- n / (sqrt(n) + 1) < sqrt(n) + 1, so ¬(sqrt(n) + 1 ≤ n / (sqrt(n) + 1))
    have : ¬ (Nat.sqrt n + 1 ≤ n / (Nat.sqrt n + 1)) := by
      intro h
      have := (Nat.le_div_iff_mul_le hpos_s).mp h
      omega
    simp [this]

/-! ### UInt64-to-Nat bridge -/

private lemma uint64_ge_iff (a b : UInt64) : (a ≥ b) ↔ (a.toNat ≥ b.toNat) :=
  ⟨UInt64.le_iff_toNat_le_toNat.mp, UInt64.le_iff_toNat_le_toNat.mpr⟩

private lemma uint64_le_iff (a b : UInt64) : (a ≤ b) ↔ (a.toNat ≤ b.toNat) :=
  UInt64.le_iff_toNat_le_toNat

private lemma uint64_toNat_zero_eq (n : UInt64) (h : n.toNat = 0) : n = 0 := by
  cases n; rename_i bv; ext; simp only [UInt64.toNat, BitVec.toNat] at h; exact h

/-- For `r ≥ sqrt(n)` with `r > 0` and `n > 0`, `n/r ≤ sqrt(n) + 2`. -/
private lemma div_le_sqrt_add_two (n r : Nat) (hge : r ≥ Nat.sqrt n)
    (_hr_pos : r > 0) (hn_pos : n > 0) :
    n / r ≤ Nat.sqrt n + 2 := by
  have hsqrt_pos : Nat.sqrt n > 0 := Nat.sqrt_pos.mpr hn_pos
  have hlt : n < (Nat.sqrt n + 1) * (Nat.sqrt n + 1) :=
    Nat.sqrt_lt.mp (by omega)
  have h_bound : n ≤ Nat.sqrt n * Nat.sqrt n + 2 * Nat.sqrt n :=
    by nlinarith
  have h_div_eq :
      (Nat.sqrt n * Nat.sqrt n + 2 * Nat.sqrt n) / Nat.sqrt n =
        Nat.sqrt n + 2 := by
    have : Nat.sqrt n * Nat.sqrt n + 2 * Nat.sqrt n =
        (Nat.sqrt n + 2) * Nat.sqrt n := by ring
    rw [this, Nat.mul_div_cancel _ hsqrt_pos]
  calc n / r
      ≤ n / Nat.sqrt n := Nat.div_le_div_left hge hsqrt_pos
    _ ≤ (Nat.sqrt n * Nat.sqrt n + 2 * Nat.sqrt n) / Nat.sqrt n :=
        Nat.div_le_div_right h_bound
    _ = Nat.sqrt n + 2 := h_div_eq

/-- The sum `r + n/r` is bounded when `r ≤ n/2 + 1` and `r ≥ sqrt(n)`. -/
private lemma newton_sum_lt_pow64 (n r : Nat) (hn : n < 2 ^ 64)
    (hge : r ≥ Nat.sqrt n) (hr_le : r ≤ n / 2 + 1)
    (hr_pos : r > 0) (hn_pos : n > 0) :
    r + n / r < 2 ^ 64 := by
  have h_sqrt_lt : Nat.sqrt n < 2 ^ 32 := by
    rw [Nat.sqrt_lt]
    calc n < 2 ^ 64 := hn
      _ = 2 ^ 32 * 2 ^ 32 := by norm_num
  have h_div : n / r ≤ Nat.sqrt n + 2 :=
    div_le_sqrt_add_two n r hge hr_pos hn_pos
  calc r + n / r
      ≤ (n / 2 + 1) + (Nat.sqrt n + 2) := by omega
    _ < 2 ^ 63 + 2 ^ 32 + 3 := by omega
    _ < 2 ^ 64 := by norm_num

/-- Newton step preserves `r ≤ n/2 + 1` (since `new_r < r`). -/
private lemma newton_step_le_half (n r : Nat)
    (hr_le : r ≤ n / 2 + 1)
    (hcont : ¬ (r + n / r) / 2 ≥ r) :
    (r + n / r) / 2 ≤ n / 2 + 1 := by omega

/-- Newton step is positive when `n ≥ r` and `r > 0`. -/
private lemma newton_step_pos' (n r : Nat) (hn_ge : n ≥ r) (hr_pos : r > 0) :
    (r + n / r) / 2 > 0 := by
  have : n / r ≥ 1 := (Nat.le_div_iff_mul_le hr_pos).mpr (by omega)
  omega

/-- `isqrtLoop` on UInt64 equals `natIsqrtLoop` on Nat for all UInt64 inputs,
    when `r ≤ n/2 + 1` and `r ≥ sqrt(n)` (ensures `r + n/r < 2^64`). -/
private theorem isqrtLoop_bridge (n r : UInt64) (fuel : Nat)
    (hn_pos : n.toNat > 0)
    (hge : r.toNat ≥ Nat.sqrt n.toNat)
    (hr_le : r.toNat ≤ n.toNat / 2 + 1)
    (hr_pos : r.toNat > 0) :
    (isqrtLoop n r fuel).toNat = natIsqrtLoop n.toNat r.toNat fuel := by
  have hn64 : n.toNat < 2 ^ 64 := n.toNat_lt
  induction fuel generalizing r with
  | zero => simp [isqrtLoop, natIsqrtLoop]
  | succ k ih =>
    unfold isqrtLoop natIsqrtLoop; simp only []
    -- No-overflow arithmetic
    have hdiv_eq : (n / r).toNat = n.toNat / r.toNat := UInt64.toNat_div n r
    have hsum_lt : r.toNat + n.toNat / r.toNat < 2 ^ 64 :=
      newton_sum_lt_pow64 n.toNat r.toNat hn64 hge hr_le hr_pos hn_pos
    have hsum_eq : (r + n / r).toNat = r.toNat + n.toNat / r.toNat := by
      rw [UInt64.toNat_add, hdiv_eq, Nat.mod_eq_of_lt hsum_lt]
    have hnewton_eq : ((r + n / r) / 2).toNat = (r.toNat + n.toNat / r.toNat) / 2 := by
      rw [UInt64.toNat_div, hsum_eq]; rfl
    -- The branching condition `new_r >= r` matches between UInt64 and Nat
    have hcond : ((r + n / r) / 2 ≥ r) ↔ ((r.toNat + n.toNat / r.toNat) / 2 ≥ r.toNat) := by
      rw [uint64_ge_iff, hnewton_eq]
    split
    · -- UInt64 stops
      rename_i hstop
      split
      · rfl
      · exact absurd (hcond.mp hstop) ‹_›
    · -- UInt64 continues
      rename_i hcont_u64
      split
      · exact absurd (hcond.mpr ‹_›) hcont_u64
      · -- Both continue: the new r satisfies the loop invariants
        rename_i hcont_nat
        have hge_new : ((r + n / r) / 2).toNat ≥ Nat.sqrt n.toNat := by
          rw [hnewton_eq]; exact newton_step_ge_sqrt n.toNat r.toNat hge hr_pos
        have hle_new : ((r + n / r) / 2).toNat ≤ n.toNat / 2 + 1 := by
          rw [hnewton_eq]; exact newton_step_le_half n.toNat r.toNat hr_le hcont_nat
        have hpos_new : ((r + n / r) / 2).toNat > 0 := by
          rw [hnewton_eq]
          have : n.toNat / r.toNat ≥ 1 :=
            (Nat.le_div_iff_mul_le hr_pos).mpr (by omega)
          omega
        have h := ih ((r + n / r) / 2) hge_new hle_new hpos_new
        rwa [hnewton_eq] at h

private lemma sqrt_lt_pow32 (n : Nat) (h : n < 2 ^ 64) : Nat.sqrt n < 2 ^ 32 := by
  rw [Nat.sqrt_lt]
  calc n < 2 ^ 64 := h
    _ = 2 ^ 32 * 2 ^ 32 := by norm_num

/-! ## Core bridge theorems -/

/-- `isqrt` computes `Nat.sqrt` for all UInt64 inputs. The new implementation avoids
    overflow by using division instead of multiplication in the correction step, and
    starts Newton's method from `n/2 + 1` instead of `n`.

    **Proof strategy:**
    1. Mirror the algorithm at the Nat level (`natIsqrtLoop`, `natIsqrt`)
    2. Prove Nat version = `Nat.sqrt` (Newton's method convergence via integer AM-GM)
    3. Bridge: UInt64 version = Nat version (no-overflow arithmetic) -/
theorem isqrt_correct (n : UInt64) :
    (isqrt n).toNat = Nat.sqrt n.toNat := by
  -- Decompose: isqrt on UInt64 = natIsqrt on Nat = Nat.sqrt
  suffices hsuff : (isqrt n).toNat = natIsqrt n.toNat by
    rw [hsuff, natIsqrt_eq_sqrt _ n.toNat_lt]
  simp only [isqrt, natIsqrt]
  -- Bridge the base case: n ≤ 1
  by_cases hn_le1 : n.toNat ≤ 1
  · -- Both branches take the base case
    have hu_le : n ≤ 1 := UInt64.le_iff_toNat_le_toNat.mpr hn_le1
    simp [hu_le, hn_le1]
  · -- n ≥ 2: both branches take the else
    push Not at hn_le1
    have hn2 : n.toNat ≥ 2 := by omega
    have hn_pos : n.toNat > 0 := by omega
    have hu_nle : ¬ (n ≤ 1) := by
      intro hle
      have := UInt64.le_iff_toNat_le_toNat.mp hle
      simp only [UInt64.toNat_one] at this; omega
    have hn_nat_nle : ¬ (n.toNat ≤ 1) := by omega
    simp only [hu_nle, hn_nat_nle, ↓reduceIte]
    -- Bridge the starting value n/2 + 1
    have hdiv2_eq : (n / 2).toNat = n.toNat / 2 := UInt64.toNat_div n 2
    have hstart_lt : n.toNat / 2 + 1 < 2 ^ 64 := by
      have := n.toNat_lt; omega
    have hstart_eq : (n / 2 + 1).toNat = n.toNat / 2 + 1 := by
      rw [UInt64.toNat_add, hdiv2_eq, UInt64.toNat_one, Nat.mod_eq_of_lt hstart_lt]
    -- Starting value properties
    have hstart_pos : (n / 2 + 1).toNat > 0 := by rw [hstart_eq]; omega
    have hstart_ge : (n / 2 + 1).toNat ≥ Nat.sqrt n.toNat := by
      rw [hstart_eq]; exact half_plus_one_ge_sqrt n.toNat hn2
    have hstart_le : (n / 2 + 1).toNat ≤ n.toNat / 2 + 1 := by rw [hstart_eq]
    -- Bridge the Newton loop
    have hloop_eq : (isqrtLoop n (n / 2 + 1) 64).toNat =
        natIsqrtLoop n.toNat (n.toNat / 2 + 1) 64 := by
      have h := isqrtLoop_bridge n (n / 2 + 1) 64 hn_pos hstart_ge hstart_le hstart_pos
      rwa [hstart_eq] at h
    set r_u := isqrtLoop n (n / 2 + 1) 64
    set r_n := natIsqrtLoop n.toNat (n.toNat / 2 + 1) 64
    -- Bridge the correction step: r+1 ≤ n/(r+1)
    -- First, bridge r+1 on UInt64
    have hr_val : r_n = Nat.sqrt n.toNat :=
      natIsqrtLoop_correct n.toNat (n.toNat / 2 + 1) 64 hn_pos (by omega)
        (half_plus_one_ge_sqrt n.toNat hn2)
        (half_plus_one_fuel n.toNat n.toNat_lt)
    have hr_lt : r_n < 2 ^ 32 := by rw [hr_val]; exact sqrt_lt_pow32 n.toNat n.toNat_lt
    have hadd_eq : (r_u + 1).toNat = r_n + 1 := by
      rw [UInt64.toNat_add, hloop_eq, UInt64.toNat_one, Nat.mod_eq_of_lt (by omega)]
    -- Bridge n/(r+1) on UInt64
    have hdiv_rhs_eq : (n / (r_u + 1)).toNat = n.toNat / (r_n + 1) := by
      rw [UInt64.toNat_div, hadd_eq]
    -- The correction condition: r+1 ≤ n/(r+1) ↔ (r+1)*(r+1) ≤ n
    have hcond_eq : (r_u + 1 ≤ n / (r_u + 1)) ↔ (r_n + 1 ≤ n.toNat / (r_n + 1)) := by
      rw [uint64_le_iff, hadd_eq, hdiv_rhs_eq]
    -- The Nat-level condition r+1 ≤ n/(r+1) ↔ (r+1)^2 ≤ n
    have hnat_equiv :
        (r_n + 1 ≤ n.toNat / (r_n + 1)) ↔
        ((r_n + 1) * (r_n + 1) ≤ n.toNat) := by
      rw [Nat.le_div_iff_mul_le (by omega)]
    -- Both branches produce the same Nat value
    split
    · rename_i hcorr
      have hcorr_nat := hcond_eq.mp hcorr
      rw [hadd_eq]; simp [hcorr_nat]
    · rename_i hnocorr
      have hnocorr_nat : ¬ (r_n + 1 ≤ n.toNat / (r_n + 1)) :=
        fun hh => hnocorr (hcond_eq.mpr hh)
      rw [hloop_eq]; simp [hnocorr_nat]

/-- Squaring a small UInt64 commutes with `toNat` (no overflow when < 2^32). -/
private lemma uint64_sq_toNat (a : UInt64) (ha : a.toNat < 2 ^ 32) :
    (a ^ 2).toNat = a.toNat ^ 2 := by
  have hsq_lt : a.toNat * a.toNat < 2 ^ 64 := by nlinarith
  change (a ^ (1 + 1)).toNat = _
  simp only [pow_succ, pow_zero, one_mul]
  rw [UInt64.toNat_mul, Nat.mod_eq_of_lt hsq_lt]

/-- The UInt64 `justifiable` function agrees with the Prop `Justifiable`.
    The bound ensures `4 * d + 1` doesn't overflow UInt64. -/
theorem justifiable_equiv (d : UInt64) (h : d.toNat < 2 ^ 62) :
    justifiable d = true ↔ Justifiable d.toNat := by
  rw [justifiable_iff]
  -- Bounds for 4 * d + 1 not overflowing
  have hval_nat : (4 * d + 1).toNat = 4 * d.toNat + 1 := by
    have h4_eq : (4 : UInt64).toNat = 4 := by decide
    rw [UInt64.toNat_add, UInt64.toNat_mul, h4_eq, UInt64.toNat_one,
        Nat.mod_eq_of_lt (by omega), Nat.mod_eq_of_lt (by omega)]
  -- isqrt results (no bound needed)
  have hisqrt_d : (isqrt d).toNat = Nat.sqrt d.toNat := isqrt_correct d
  have hisqrt_v : (isqrt (4 * d + 1)).toNat = Nat.sqrt (4 * d.toNat + 1) := by
    rw [← hval_nat]; exact isqrt_correct (4 * d + 1)
  -- sqrt bounds (< 2^32)
  have hsqrt_d_lt : (isqrt d).toNat < 2 ^ 32 := by
    rw [hisqrt_d]; exact sqrt_lt_pow32 _ d.toNat_lt
  have hsqrt_v_lt : (isqrt (4 * d + 1)).toNat < 2 ^ 32 := by
    rw [hisqrt_v]; exact sqrt_lt_pow32 _ (by rw [← hval_nat]; exact (4 * d + 1).toNat_lt)
  -- Bridge each UInt64 condition to Nat
  have h_le5 : (d ≤ 5) ↔ (d.toNat ≤ 5) := UInt64.le_iff_toNat_le_toNat
  have h_sq_d : (isqrt d ^ 2 = d) ↔ (Nat.sqrt d.toNat ^ 2 = d.toNat) := by
    rw [UInt64.ext_iff, uint64_sq_toNat _ hsqrt_d_lt, hisqrt_d]
  have h_sq_v : (isqrt (4 * d + 1) ^ 2 = 4 * d + 1) ↔
      (Nat.sqrt (4 * d.toNat + 1) ^ 2 = 4 * d.toNat + 1) := by
    rw [UInt64.ext_iff, uint64_sq_toNat _ hsqrt_v_lt, hisqrt_v, hval_nat]
  have h_mod_v : ((4 * d + 1) % 2 = (1 : UInt64)) ↔ ((4 * d.toNat + 1) % 2 = 1) := by
    rw [UInt64.ext_iff, UInt64.toNat_mod, hval_nat]
    simp [UInt64.toNat_one]
  -- Unfold justifiable and convert Bool to Prop
  unfold justifiable
  simp only [Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq]
  -- The let binding in justifiable introduces `val := 4 * d + 1`; after simp, it becomes
  -- direct UInt64 expressions that we can rewrite with our bridge lemmas
  constructor
  · rintro ((h1 | h2) | ⟨h3, h4⟩)
    · exact Or.inl (h_le5.mp h1)
    · exact Or.inr (Or.inl (h_sq_d.mp h2))
    · exact Or.inr (Or.inr ⟨h_sq_v.mp h3, h_mod_v.mp h4⟩)
  · rintro (h1 | h2 | ⟨h3, h4⟩)
    · exact Or.inl (Or.inl (h_le5.mpr h1))
    · exact Or.inl (Or.inr (h_sq_d.mpr h2))
    · exact Or.inr ⟨h_sq_v.mpr h3, h_mod_v.mpr h4⟩
