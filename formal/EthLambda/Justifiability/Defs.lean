/-
Copyright (c) 2026 ethlambda contributors. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Mathlib

/-!
# 3SF-mini Justifiability Definitions

Core definitions for the justifiability predicate used in 3SF-mini consensus.

A slot at distance `delta` from the finalized slot is justifiable iff:
- `delta ≤ 5` (immediate vicinity), OR
- `delta` is a perfect square (`∃ n, delta = n^2`), OR
- `delta` is a pronic number (`∃ n, delta = n * (n + 1)`)

## References

* Rust implementation: `crates/blockchain/state_transition/src/lib.rs:499-523`
* 3SF-mini spec: `ethereum/research/3sf-mini/consensus.py`
-/

/-- A natural number is pronic if it equals `n * (n + 1)` for some `n`.
    Examples: 0, 2, 6, 12, 20, 30, 42, 56, ... -/
def IsPronic (k : ℕ) : Prop := ∃ n : ℕ, k = n * (n + 1)

/-- A delta value is justifiable under 3SF-mini rules. -/
def Justifiable (delta : ℕ) : Prop :=
  delta ≤ 5 ∨ IsSquare delta ∨ IsPronic delta

/-- Computable justifiability check, mirroring the Rust implementation.
    Uses `Nat.sqrt` for both perfect square and pronic detection. -/
def justifiable (delta : ℕ) : Bool :=
  delta ≤ 5
    || Nat.sqrt delta ^ 2 == delta
    || (let val := 4 * delta + 1
        Nat.sqrt val ^ 2 == val && val % 2 == 1)

/-- Full slot-level function matching the Rust `slot_is_justifiable_after` API.
    Returns `false` if `slot < finalizedSlot`. -/
def slotIsJustifiableAfter (slot finalizedSlot : ℕ) : Bool :=
  if finalizedSlot ≤ slot then
    justifiable (slot - finalizedSlot)
  else
    false
