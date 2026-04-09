/-
Copyright (c) 2026 ethlambda contributors. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/

/-!
# 3SF-mini Justifiability

Computable implementation of the justifiability check used in 3SF-mini consensus.
No Mathlib dependency; compiled into the Rust binary via FFI.

A slot at distance `delta` from the finalized slot is justifiable iff:
- `delta ≤ 5` (immediate vicinity), OR
- `delta` is a perfect square, OR
- `delta` is a pronic number n*(n+1), detected via: 4*delta+1 is an odd perfect square
-/

/-- Integer square root via Newton's method (bounded iteration).
    Returns the largest `r` such that `r * r ≤ n`.
    Starts from `n/2 + 1` (not `n`) to avoid overflow in the first step. -/
def isqrtLoop (n : UInt64) (r : UInt64) : (fuel : Nat) → UInt64
  | 0 => r
  | fuel + 1 =>
    let new_r := (r + n / r) / 2
    if new_r >= r then r
    else isqrtLoop n new_r fuel

def isqrt (n : UInt64) : UInt64 :=
  if n <= 1 then n
  else
    let r := isqrtLoop n (n / 2 + 1) 64
    -- Use division instead of multiplication to avoid overflow in correction:
    -- r+1 ≤ n/(r+1)  ↔  (r+1)*(r+1) ≤ n  (when r+1 > 0)
    if r + 1 <= n / (r + 1) then r + 1 else r

/-- Computable justifiability check mirroring the Rust implementation. -/
def justifiable (delta : UInt64) : Bool :=
  delta <= 5
    || isqrt delta ^ 2 == delta
    || (let val := 4 * delta + 1
        isqrt val ^ 2 == val && val % 2 == 1)

/-- Full slot-level function matching the Rust `slot_is_justifiable_after` API. -/
def slotIsJustifiableAfter (slot finalizedSlot : UInt64) : Bool :=
  if slot < finalizedSlot then false
  else justifiable (slot - finalizedSlot)

-- FFI exports for Rust
@[export lean_justifiable]
def leanJustifiable (delta : UInt64) : UInt8 :=
  if justifiable delta then 1 else 0

@[export lean_slot_is_justifiable_after]
def leanSlotIsJustifiableAfter (slot finalizedSlot : UInt64) : UInt8 :=
  if slotIsJustifiableAfter slot finalizedSlot then 1 else 0
