//! Slot and epoch arithmetic, signing domains, and merkle branch verification.
//!
//! These are the helpers that depend on nothing but their arguments, so unlike
//! the accessors in [`super::accessors`] they never take a state.

use crate::constants;
use crate::containers::shared::{ForkData, SigningData};
use crate::hash::hash;
use crate::preset;
use crate::primitives::{
    Bytes32, Domain, DomainType, Epoch, HashTreeRoot as _, Root, Slot, Version,
};

/// The epoch containing `slot`.
pub fn compute_epoch_at_slot(slot: Slot) -> Epoch {
    slot / preset::SLOTS_PER_EPOCH
}

/// The first slot of `epoch`.
pub fn compute_start_slot_at_epoch(epoch: Epoch) -> Slot {
    epoch * preset::SLOTS_PER_EPOCH
}

/// The epoch at which an activation or exit initiated during `epoch` takes
/// effect.
///
/// The delay exists so that the committee shuffling for an epoch is already
/// settled before validators can join or leave it, which is what stops an
/// attacker from steering their own committee assignment.
pub fn compute_activation_exit_epoch(epoch: Epoch) -> Epoch {
    epoch + 1 + preset::MAX_SEED_LOOKAHEAD
}

/// The root binding a fork version to a chain's genesis validator set.
///
/// Mixing both into every signing domain is what keeps a signature from one
/// chain or fork from verifying on another.
pub fn compute_fork_data_root(current_version: Version, genesis_validators_root: Root) -> Root {
    ForkData {
        current_version,
        genesis_validators_root,
    }
    .hash_tree_root()
}

/// The signing domain for a message type on a particular fork and chain.
///
/// The domain is the four-byte domain type followed by the first 28 bytes of the
/// fork data root, so it fits in 32 bytes while still committing to both.
pub fn compute_domain(
    domain_type: DomainType,
    fork_version: Version,
    genesis_validators_root: Root,
) -> Domain {
    let fork_data_root = compute_fork_data_root(fork_version, genesis_validators_root);
    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&domain_type);
    domain[4..].copy_from_slice(&fork_data_root.0[..28]);
    domain
}

/// The root a signature is actually computed over: the message's root combined
/// with its domain.
pub fn compute_signing_root(object_root: Root, domain: Domain) -> Root {
    SigningData {
        object_root,
        domain,
    }
    .hash_tree_root()
}

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

/// The fork version in effect at `epoch`, given the state's fork schedule.
///
/// A message signed just before a fork boundary must still verify just after it,
/// which is why the state keeps the previous version at all.
pub fn fork_version_at_epoch(fork: &crate::containers::shared::Fork, epoch: Epoch) -> Version {
    if epoch < fork.epoch {
        fork.previous_version
    } else {
        fork.current_version
    }
}

/// The domain for a deposit signature.
///
/// Deposits are the one message signed under a genesis-independent domain, since
/// a deposit has to be valid before the chain it funds has started, so it cannot
/// commit to a genesis validators root.
pub fn compute_deposit_domain(genesis_fork_version: Version) -> Domain {
    compute_domain(
        constants::DOMAIN_DEPOSIT,
        genesis_fork_version,
        Root::zero(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::containers::shared::Fork;

    #[test]
    fn slot_and_epoch_arithmetic_round_trips() {
        for epoch in 0u64..5 {
            let start = compute_start_slot_at_epoch(epoch);
            assert_eq!(compute_epoch_at_slot(start), epoch);
            // The last slot of an epoch still belongs to it.
            assert_eq!(
                compute_epoch_at_slot(start + preset::SLOTS_PER_EPOCH - 1),
                epoch
            );
        }
    }

    #[test]
    fn domain_carries_the_type_then_the_fork_data_prefix() {
        let domain = compute_domain(
            constants::DOMAIN_BEACON_ATTESTER,
            [1, 0, 0, 0],
            Root::repeat_byte(9),
        );
        assert_eq!(&domain[..4], &constants::DOMAIN_BEACON_ATTESTER);

        let fork_data_root = compute_fork_data_root([1, 0, 0, 0], Root::repeat_byte(9));
        assert_eq!(&domain[4..], &fork_data_root.0[..28]);
    }

    #[test]
    fn domain_separates_forks_and_chains() {
        let a = compute_domain(constants::DOMAIN_RANDAO, [1, 0, 0, 0], Root::zero());
        let b = compute_domain(constants::DOMAIN_RANDAO, [2, 0, 0, 0], Root::zero());
        let c = compute_domain(constants::DOMAIN_RANDAO, [1, 0, 0, 0], Root::repeat_byte(1));
        assert_ne!(
            a, b,
            "a different fork version must give a different domain"
        );
        assert_ne!(a, c, "a different chain must give a different domain");
    }

    #[test]
    fn fork_version_switches_at_the_boundary() {
        let fork = Fork {
            previous_version: [1, 0, 0, 0],
            current_version: [2, 0, 0, 0],
            epoch: 10,
        };
        assert_eq!(fork_version_at_epoch(&fork, 9), [1, 0, 0, 0]);
        assert_eq!(fork_version_at_epoch(&fork, 10), [2, 0, 0, 0]);
    }

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
            Bytes32::zero(),
            &[],
            1,
            0,
            Root::zero()
        ));
    }
}
