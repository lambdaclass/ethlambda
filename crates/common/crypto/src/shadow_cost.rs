//! Shadow-simulator sim-cost + fake-proof backend. Compiled only under the
//! `shadow-integration` feature. Ported from zeam's shadow_cost.zig.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use ethlambda_types::block::ByteList512KiB;

// =====================================================================
// Process-global config
// =====================================================================
//
// Set once at startup via `init`, then read lock-free from every
// aggregation/verification call site. Rates are stored as the raw bits of
// an `f64` (via `to_bits`/`from_bits`) since `AtomicU64` has no `AtomicF64`
// counterpart; `0` bits encodes both `0.0` and "unset" (disabled).

static FAKE_ENABLED: AtomicBool = AtomicBool::new(false);
static AGG_RATE: AtomicU64 = AtomicU64::new(0);
static VERIFY_RATE: AtomicU64 = AtomicU64::new(0);
static MERGE_RATE: AtomicU64 = AtomicU64::new(0);

/// Convert an optional rate into the bit pattern stored in the atomic.
///
/// Only finite, strictly positive rates are kept; anything else (`None`,
/// `NaN`, `Infinity`, zero, negative) collapses to `0`, which `compute_delay`
/// treats as "disabled".
fn rate_bits(v: Option<f64>) -> u64 {
    match v {
        Some(v) if v.is_finite() && v > 0.0 => v.to_bits(),
        _ => 0,
    }
}

/// Configure the shadow sim-cost backend.
///
/// Call exactly once at node startup, before any aggregation runs.
///
/// `fake` switches the prover/verifier to the deterministic stub backend.
/// `agg`/`verify`/`merge` are the modeled operation rates (units per
/// second) used to compute sim-cost sleeps; `None` (or a non-finite /
/// non-positive value) disables the sleep for that operation.
pub fn init(fake: bool, agg: Option<f64>, verify: Option<f64>, merge: Option<f64>) {
    FAKE_ENABLED.store(fake, Ordering::Relaxed);
    AGG_RATE.store(rate_bits(agg), Ordering::Relaxed);
    VERIFY_RATE.store(rate_bits(verify), Ordering::Relaxed);
    MERGE_RATE.store(rate_bits(merge), Ordering::Relaxed);
}

/// Whether the fake-XMSS stub backend is active.
pub fn fake_xmss() -> bool {
    FAKE_ENABLED.load(Ordering::Relaxed)
}

/// Compute the sim-cost delay for processing `n` units at the rate stored
/// in `rate` (units per second), or `Duration::ZERO` if the rate is unset
/// or there is nothing to process.
fn compute_delay(rate: &AtomicU64, n: usize) -> Duration {
    let r = f64::from_bits(rate.load(Ordering::Relaxed));
    if r <= 0.0 || n == 0 {
        return Duration::ZERO;
    }

    let ns = (n as f64 / r) * 1e9;
    if !ns.is_finite() || ns <= 0.0 {
        return Duration::ZERO;
    }

    // Clamp before the f64 -> u64 cast: an out-of-range cast is a saturating
    // cast in Rust, but staying above `u64::MAX` risks precision surprises,
    // so clamp explicitly for clarity.
    Duration::from_nanos(ns.min(u64::MAX as f64) as u64)
}

/// Nanoseconds to sleep to model aggregating `n` raw signatures.
pub fn aggregate_delay(n: usize) -> Duration {
    compute_delay(&AGG_RATE, n)
}

/// Nanoseconds to sleep to model verifying `n` signatures/proofs.
pub fn verify_delay(n: usize) -> Duration {
    compute_delay(&VERIFY_RATE, n)
}

/// Nanoseconds to sleep to model merging `n` proofs.
pub fn merge_delay(n: usize) -> Duration {
    compute_delay(&MERGE_RATE, n)
}

/// Fixed size of every fake stub proof; well under the 512 KiB
/// `ByteList512KiB` wire cap.
pub const FAKE_PROOF_SIZE: usize = 32 * 1024;

/// Produce a deterministic `len`-byte stub proof derived only from
/// `seed_parts`.
///
/// # Determinism contract
///
/// Callers MUST seed this only from values the real FFI binds — the
/// message hash, slot, child-proof bytes, participant counts, and similar
/// — and MUST NEVER seed from a pointer/handle address or from randomness.
/// A stub proof carries no cryptographic strength; its only job is to let
/// every node compute the *same* bytes for the *same* logical inputs, so
/// fake proofs remain deterministic and consensus-safe across nodes.
///
/// Uses a dependency-free FNV-1a fold of the seed bytes into a 64-bit seed,
/// then a SplitMix64 stream to fill the output buffer.
pub fn fill_fake_proof(len: usize, seed_parts: &[&[u8]]) -> ByteList512KiB {
    const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut state = FNV_OFFSET_BASIS;
    for part in seed_parts {
        for &byte in *part {
            state ^= u64::from(byte);
            state = state.wrapping_mul(FNV_PRIME);
        }
    }

    let mut bytes = Vec::with_capacity(len);
    while bytes.len() < len {
        let z = state.wrapping_add(0x9E3779B97F4A7C15);
        state = z;
        let z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        let z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        let z = z ^ (z >> 31);

        let chunk = z.to_le_bytes();
        let remaining = len - bytes.len();
        bytes.extend_from_slice(&chunk[..remaining.min(chunk.len())]);
    }

    ByteList512KiB::try_from(bytes).expect("FAKE_PROOF_SIZE fits ByteList512KiB cap")
}
