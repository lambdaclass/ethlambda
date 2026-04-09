# Formal Verification Development Guide

Lean 4 formal verification of ethlambda consensus functions.

## Project Structure

Two libraries in one Lake project:

| Library | Mathlib | Purpose |
|---------|---------|---------|
| `EthLambda` | No | Computable functions + `@[export]` FFI. Compiled into Rust binary. |
| `EthLambdaProofs` | Yes | Theorems about those functions. Never linked into binary. |

```
EthLambda/
  Justifiability.lean          # isqrt, justifiable, slotIsJustifiableAfter, @[export]

EthLambdaProofs/
  Justifiability/
    Defs.lean                  # IsPronic, Justifiable (Prop, uses IsSquare from Mathlib)
    Lemmas.lean                # pronic_identity, isSquare_iff_sqrt
    PronicDetection.lean       # isPronic_iff_sqrt
    Classification.lean        # justifiable_iff (algorithm correctness)
    Infinite.lean              # justifiable_unbounded (liveness)
    Density.lean               # justifiable_density (vote funneling bound)
    ImplEquivalence.lean       # isqrt_correct, justifiable_equiv (impl = spec)
```

## Why Two Libraries

Importing any Mathlib module (even `Mathlib.Data.Nat.Notation`) pulls in tactic/linter
initializer chains that add ~50 MB to the binary. Keeping `EthLambda` Mathlib-free
keeps the FFI overhead at ~2 MB (Lean runtime only).

`Nat.sqrt` is in Mathlib, not core Lean. The impl lib uses a custom `isqrt`
(Newton's method on UInt64). `ImplEquivalence.lean` proves `isqrt` equals `Nat.sqrt`.

## Building

```bash
lake exe cache get    # fetch prebuilt Mathlib (first time)
lake build            # both libraries
lake build EthLambda  # impl only (fast, no Mathlib)
```

## Lean Tooling

- **Lean version:** 4.29.0 (pinned in `lean-toolchain`)
- **Mathlib version:** v4.29.0 (pinned in `lakefile.toml`)
- **LSP tools:** `lean_goal`, `lean_loogle`, `lean_run_code` from lean4-toolkit plugin

## Key Mathlib Lemmas

| Lemma | Used in |
|-------|---------|
| `Nat.exists_mul_self'` | `isSquare_iff_sqrt` (bridges `IsSquare` with `Nat.sqrt`) |
| `Nat.sqrt_eq` | `isPronic_iff_sqrt` (forward direction) |
| `Nat.le_sqrt` | `Density.lean` (counting squares/pronics below N) |
| `Finset.card_image_le` | `Density.lean` (injection-based cardinality bounds) |

## Currently Verified Functions

- `slot_is_justifiable_after` (3SF-mini justifiability check)

## Adding a New Verified Function

1. Add the UInt64 implementation to `EthLambda/` with `@[export lean_function_name]`
2. Add Prop-level definitions to `EthLambdaProofs/.../Defs.lean`
3. Prove algorithm correctness in `EthLambdaProofs/.../*.lean`
4. Prove implementation equivalence (UInt64 function = Prop definition)
5. On the Rust side: add `extern "C"` + safe wrapper to `formal/lean-ffi/src/lib.rs`
6. Feature-gate the call site with `#[cfg(feature = "lean-ffi")]`

C IR files under `EthLambda/` are auto-discovered by `lean-ffi/build.rs`.

## FFI Details

- `@[export symbol_name]` produces unmangled C symbols callable from Rust
- UInt64 → u64 and UInt8 → u8 map directly (no `lean_object*` boxing)
- The Lean runtime must be initialized once before any FFI call (`lean_initialize_runtime_module` + module initializer + `lean_io_mark_end_initialization`)
- `lean_glue.c` wraps `lean_dec_ref` (which is `static inline` in `lean.h`) into a real symbol
- Module initializer symbol: `initialize_EthLambda_EthLambda`

## Common Gotchas

- **`Nat.sqrt` needs Mathlib**: Don't import it in the `EthLambda` lib. Use the custom `isqrt`.
- **`isqrt` overflow**: The original had bugs near UInt64.max. Fixed by starting Newton from `n/2+1` and using division in the correction step.
- **`import Mathlib` vs specific imports**: Even minimal Mathlib imports pull in linter infrastructure. Use `import Mathlib` in proofs (it's cached), but never in `EthLambda`.
- **Private defs**: Don't use `private` on definitions that proofs need to unfold. `isqrtLoop` was made public for this reason.
- **Module initializer names**: Check generated C IR with `grep "initialize_" .lake/build/ir/EthLambda.c` to find the exact symbol.
