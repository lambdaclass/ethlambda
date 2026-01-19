//! Helper functions for relative-indexed JustifiedSlots operations.
//!
//! The bitlist stores justification status relative to the finalized boundary:
//! - Index 0 = finalized_slot + 1
//! - Slots ≤ finalized_slot are implicitly justified (no storage needed)

use ethlambda_types::state::JustifiedSlots;

/// Calculate relative index for a slot after finalization.
/// Returns None if slot <= finalized_slot (implicitly justified).
fn relative_index(target_slot: u64, finalized_slot: u64) -> Option<usize> {
    if target_slot <= finalized_slot {
        return None;
    }
    Some((target_slot - finalized_slot - 1) as usize)
}

/// Check if a slot is justified (finalized slots are implicitly justified).
pub fn is_slot_justified(slots: &JustifiedSlots, finalized_slot: u64, target_slot: u64) -> bool {
    match relative_index(target_slot, finalized_slot) {
        None => true, // Finalized slots are implicitly justified
        Some(idx) => slots.get(idx).unwrap_or(false),
    }
}

/// Set justification status for a slot. Returns true if set, false if slot is finalized.
pub fn set_justified(
    slots: &mut JustifiedSlots,
    finalized_slot: u64,
    target_slot: u64,
    value: bool,
) -> bool {
    if let Some(idx) = relative_index(target_slot, finalized_slot) {
        slots.set(idx, value).expect("index out of bounds");
        true
    } else {
        false
    }
}

/// Extend capacity to cover slots up to target_slot relative to finalized boundary.
/// New slots are initialized to the given default value.
pub fn extend_to_slot(
    slots: &mut JustifiedSlots,
    finalized_slot: u64,
    target_slot: u64,
    default: bool,
) {
    if let Some(required_idx) = relative_index(target_slot, finalized_slot) {
        let required_capacity = required_idx + 1;
        if slots.len() >= required_capacity {
            return;
        }
        // Create a new bitlist with the required capacity.
        // All new bits are initialized to 0, then we optionally set them to 1 if default is true.
        let mut extended =
            JustifiedSlots::with_capacity(required_capacity).expect("capacity limit exceeded");
        if default {
            for i in slots.len()..required_capacity {
                extended.set(i, true).expect("within capacity");
            }
        }
        // Union preserves existing bits and adds new ones
        *slots = slots.union(&extended);
    }
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
