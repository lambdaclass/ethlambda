//! FFI bindings to the formally verified Lean4 justifiability implementation.
//!
//! The Lean4 code at `formal/ffi/LeanFFI/Justifiability.lean` implements the
//! 3SF-mini justifiability check. The algorithm has been formally verified
//! in `formal/EthLambda/Justifiability/` (zero sorry, zero axioms):
//!
//! - `Classification.lean`: computable check == mathematical definition
//! - `PronicDetection.lean`: the isqrt trick correctly detects pronic numbers
//! - `Infinite.lean`: justifiable slots are infinite (liveness)
//! - `Density.lean`: O(sqrt(n)) density bound (vote funneling)

use std::ffi::c_void;
use std::sync::Once;

type LeanObj = *mut c_void;

unsafe extern "C" {
    // Lean runtime lifecycle
    fn lean_initialize_runtime_module();
    fn lean_io_mark_end_initialization();
    fn initialize_EthLambda_EthLambda(builtin: u8) -> LeanObj;
    fn lean_ffi_dec_ref(o: LeanObj);

    // Exported Lean functions (scalar types, no lean_object*)
    fn lean_justifiable(delta: u64) -> u8;
    fn lean_slot_is_justifiable_after(slot: u64, finalized_slot: u64) -> u8;
}

static INIT: Once = Once::new();

fn init_lean() {
    INIT.call_once(|| unsafe {
        lean_initialize_runtime_module();
        let res = initialize_EthLambda_EthLambda(1);
        lean_ffi_dec_ref(res);
        lean_io_mark_end_initialization();
    });
}

/// Check if `delta` is justifiable under 3SF-mini rules.
///
/// Calls the formally verified Lean4 implementation via FFI.
pub fn justifiable(delta: u64) -> bool {
    init_lean();
    unsafe { lean_justifiable(delta) != 0 }
}

/// Check if a slot is justifiable after a given finalized slot.
///
/// Calls the formally verified Lean4 implementation via FFI.
pub fn slot_is_justifiable_after(slot: u64, finalized_slot: u64) -> bool {
    init_lean();
    unsafe { lean_slot_is_justifiable_after(slot, finalized_slot) != 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_small_deltas() {
        for d in 0..=5 {
            assert!(justifiable(d), "delta={d} should be justifiable");
        }
    }

    #[test]
    fn test_perfect_squares() {
        for &d in &[9, 16, 25, 36, 49, 64, 100] {
            assert!(
                justifiable(d),
                "delta={d} (perfect square) should be justifiable"
            );
        }
    }

    #[test]
    fn test_pronic_numbers() {
        for n in 2..=10u64 {
            let d = n * (n + 1);
            assert!(
                justifiable(d),
                "delta={d} (pronic {n}*{}) should be justifiable",
                n + 1
            );
        }
    }

    #[test]
    fn test_non_justifiable() {
        for &d in &[7, 8, 10, 11, 13, 14, 15] {
            assert!(!justifiable(d), "delta={d} should NOT be justifiable");
        }
    }

    #[test]
    fn test_slot_api() {
        assert!(slot_is_justifiable_after(100, 100)); // delta=0
        assert!(slot_is_justifiable_after(109, 100)); // delta=9 (square)
        assert!(!slot_is_justifiable_after(107, 100)); // delta=7
        assert!(!slot_is_justifiable_after(50, 100)); // slot < finalized
    }
}
