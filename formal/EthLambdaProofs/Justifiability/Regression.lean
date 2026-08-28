/-
Copyright (c) 2026 ethlambda contributors. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import EthLambda.Justifiability

/-!
# Fixed-Width Arithmetic Regression

The pronic discriminant for this value overflows UInt64. Rust uses checked
arithmetic, so the Lean FFI implementation must reject it as well.
-/

/-- `4 * delta + 1` would wrap to `9` under unchecked UInt64 arithmetic. -/
example : justifiable 4611686018427387906 = false := by
  decide

/-- The largest delta whose pronic discriminant fits remains evaluable. -/
example : justifiable 4611686018427387903 = false := by
  decide

/-- Perfect-square detection remains valid at the first overflowing-pronic delta. -/
example : justifiable 4611686018427387904 = true := by
  decide

/-- Values above the checked-pronic range do not wrap into false positives. -/
example : justifiable 18446744073709551615 = false := by
  decide
