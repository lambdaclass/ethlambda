//! Helper functions for relative-indexed JustifiedSlots operations.
//!
//! The bitlist stores justification status relative to the finalized boundary:
//! - Index 0 = finalized_slot + 1
//! - Slots ≤ finalized_slot are implicitly justified (no storage needed)

use ethlambda_types::state::JustifiedSlots;

/// Calculate relative index for a slot after finalization.
/// Returns None if slot <= finalized_slot (implicitly justified).
fn relative_index(target_slot: u64, finalized_slot: u64) -> Option<usize> {
    target_slot
        .checked_sub(finalized_slot)?
        .checked_sub(1)
        .map(|idx| idx as usize)
}

/// Check if a slot is justified (finalized slots are implicitly justified).
pub fn is_slot_justified(slots: &JustifiedSlots, finalized_slot: u64, target_slot: u64) -> bool {
    relative_index(target_slot, finalized_slot)
        .map(|idx| slots.get(idx).unwrap_or(false))
        .unwrap_or(true) // Finalized slots are implicitly justified
}

/// Mark a slot as justified. No-op if slot is finalized.
pub fn set_justified(slots: &mut JustifiedSlots, finalized_slot: u64, target_slot: u64) {
    if let Some(idx) = relative_index(target_slot, finalized_slot) {
        slots.set(idx, true).expect("index out of bounds");
    }
}

/// Extend capacity to cover slots up to target_slot relative to finalized boundary.
/// New slots are initialized to false (unjustified).
pub fn extend_to_slot(slots: &mut JustifiedSlots, finalized_slot: u64, target_slot: u64) {
    let Some(required_idx) = relative_index(target_slot, finalized_slot) else {
        return;
    };
    let required_capacity = required_idx + 1;
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
