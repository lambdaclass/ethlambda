//! Helper functions for absolute-indexed JustifiedSlots operations.
//!
//! The bitlist stores justification status using absolute slot indices:
//! - Index 0 = slot 0
//! - Index N = slot N
//!
//! This matches the Python spec's representation for SSZ compatibility.

use ethlambda_types::state::JustifiedSlots;

/// Check if a slot is justified using absolute slot index.
pub fn is_slot_justified(slots: &JustifiedSlots, _finalized_slot: u64, target_slot: u64) -> bool {
    slots.get(target_slot as usize).unwrap_or(false)
}

/// Mark a slot as justified using absolute slot index.
pub fn set_justified(slots: &mut JustifiedSlots, _finalized_slot: u64, target_slot: u64) {
    slots
        .set(target_slot as usize, true)
        .expect("index out of bounds");
}

/// Extend capacity to cover slots up to and including target_slot.
/// New slots are initialized to false (unjustified).
pub fn extend_to_slot(slots: &mut JustifiedSlots, _finalized_slot: u64, target_slot: u64) {
    let required_capacity = (target_slot + 1) as usize;
    if slots.len() >= required_capacity {
        return;
    }
    // Create a new bitlist with the required capacity (all bits default to false).
    // Union preserves existing bits and extends the length.
    let extended =
        JustifiedSlots::with_capacity(required_capacity).expect("capacity limit exceeded");
    *slots = slots.union(&extended);
}

/// Shift window by dropping finalized slots when finalization advances.
/// Note: This shifts absolute indices, removing slots 0..delta from the front.
pub fn shift_window(slots: &mut JustifiedSlots, delta: usize) {
    if delta == 0 {
        return;
    }
    if delta >= slots.len() {
        *slots = JustifiedSlots::with_capacity(0).unwrap();
        return;
    }
    // Create new bitlist with shifted data
    let remaining = slots.len() - delta;
    let mut new_bits = JustifiedSlots::with_capacity(remaining).unwrap();
    for i in 0..remaining {
        if slots.get(i + delta).unwrap_or(false) {
            new_bits.set(i, true).unwrap();
        }
    }
    *slots = new_bits;
}
