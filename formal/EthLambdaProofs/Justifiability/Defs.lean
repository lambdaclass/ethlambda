/-
Copyright (c) 2026 ethlambda contributors. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Mathlib
import EthLambda.Justifiability

/-!
# 3SF-mini Justifiability: Prop-level Definitions

Prop-level definitions that require Mathlib (for `IsSquare`, `Nat.sqrt`).
These are used by the proof modules but never compiled into the binary.

The computable definitions (`justifiable`, `isqrt`, etc.) live in
`EthLambda.Justifiability.Defs` (no Mathlib).
-/

/-- A natural number is pronic if it equals `n * (n + 1)` for some `n`. -/
def IsPronic (k : ℕ) : Prop := ∃ n : ℕ, k = n * (n + 1)

/-- A delta value is justifiable under 3SF-mini rules. -/
def Justifiable (delta : ℕ) : Prop :=
  delta ≤ 5 ∨ IsSquare delta ∨ IsPronic delta
