//! Slot and epoch arithmetic, signing domains, and merkle branch verification.
//!
//! These are the helpers that depend on nothing but their arguments, so unlike
//! the accessors in [`super::accessors`] they never take a state. Slot/epoch
//! arithmetic and the signing domains now live in `ethlambda-types` and are
//! re-exported below at their old path. What is still implemented here is
//! merkle branch verification, which needs this crate's `hash`, and
//! [`compute_activation_exit_epoch`], which reads this crate's preset.

use crate::beacon::hash::hash;
use crate::beacon::preset;
use crate::beacon::primitives::{Bytes32, Epoch, Root};

// Relocated to `ethlambda-types` so that consumers which only sign or verify a
// message can reach them without this crate's `blst`, `c-kzg` and RocksDB
// dependencies. Re-exported at the old path so every use site inside this
// module is unchanged.
pub use ethlambda_types::beacon::signing::{
    compute_deposit_domain, compute_domain, compute_epoch_at_slot, compute_signing_root,
    compute_start_slot_at_epoch, fork_version_at_epoch,
};

/// The epoch at which an activation or exit initiated during `epoch` takes
/// effect.
///
/// The delay exists so that the committee shuffling for an epoch is already
/// settled before validators can join or leave it, which is what stops an
/// attacker from steering their own committee assignment.
pub fn compute_activation_exit_epoch(epoch: Epoch) -> Epoch {
    epoch + 1 + preset::MAX_SEED_LOOKAHEAD
}

// The root binding a fork version to a chain's genesis validator set, which
// mixes both into every signing domain. It lives in `ethlambda-types` beside
// `compute_fork_digest`, which needs it and which the networking crate needs in
// turn; re-exported here at its old path, since every signing domain below is
// built from it.
pub use ethlambda_types::beacon::fork_digest::compute_fork_data_root;

/// Whether `leaf` at `index` is proven by `branch` against `root`.
///
/// The bit of `index` at each level decides which side the sibling goes on, so a
/// branch only verifies at the position it was generated for.
pub fn is_valid_merkle_branch(
    leaf: Bytes32,
    branch: &[Bytes32],
    depth: u64,
    index: u64,
    root: Root,
) -> bool {
    if branch.len() < depth as usize {
        return false;
    }

    let mut value = leaf;
    for level in 0..depth {
        let sibling = branch[level as usize];
        // Whether this leaf is the right child at this level.
        let on_the_right = (index / 2u64.pow(level as u32)) % 2 == 1;
        value = if on_the_right {
            hash(&[sibling.0, value.0].concat())
        } else {
            hash(&[value.0, sibling.0].concat())
        };
    }
    value == root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_branch_verifies_only_at_its_own_index() {
        // A two-leaf tree: root = hash(left + right).
        let left = Bytes32::repeat_byte(1);
        let right = Bytes32::repeat_byte(2);
        let root = hash(&[left.0, right.0].concat());

        assert!(is_valid_merkle_branch(left, &[right], 1, 0, root));
        assert!(is_valid_merkle_branch(right, &[left], 1, 1, root));
        // The same leaf and branch at the wrong index must not verify.
        assert!(!is_valid_merkle_branch(left, &[right], 1, 1, root));
    }

    #[test]
    fn merkle_branch_rejects_a_short_branch() {
        // A branch shorter than the claimed depth would index out of bounds, so
        // it has to be rejected rather than panicking.
        assert!(!is_valid_merkle_branch(
            Bytes32::ZERO,
            &[],
            1,
            0,
            Root::ZERO
        ));
    }
}
