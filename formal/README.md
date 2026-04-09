# Formal Verification

Lean 4 formal verification of ethlambda's consensus protocol.

The package is split into two libraries: one for the implementation and one for
the proofs. The implementation library does not depend on Mathlib, while the
proofs library uses Mathlib to verify the correctness of the implementation.

## Two Libraries

| Library | Mathlib | Purpose | In binary? |
|---------|---------|---------|------------|
| `EthLambda` | No | Computable functions + FFI exports | Yes |
| `EthLambdaProofs` | Yes | Theorems about those functions | No |

The reason for this split is to control binary size. Mathlib's module
initializer chain pulls in tactic and linter infrastructure that inflates the
binary even when unused at runtime:

| Variant | Binary size |
|---------|------------|
| No Lean (baseline) | ~28 MB |
| Lean runtime, no Mathlib (current) | ~30 MB |
| Lean runtime + minimal Mathlib import | ~40 MB |
| Lean runtime + full Mathlib | ~250 MB |

## Building

Requires [elan](https://github.com/leanprover/elan). Run `lake exe cache get`
to fetch prebuilt Mathlib on first setup, then `lake build`.

## Rust FFI

The `lean-ffi` Cargo feature compiles `EthLambda` into the ethlambda binary via
C FFI. The Lean runtime is statically linked. Without the feature, the native
Rust implementation is used.

