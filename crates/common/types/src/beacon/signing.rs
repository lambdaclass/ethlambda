//! Slot and epoch arithmetic, the signing domains built from them, and the
//! signing root that combines a message with one.
//!
//! These helpers depend on nothing but their arguments, so unlike the state
//! accessors they need no `BeaconState`. They live here rather than in
//! `ethlambda-state-transition` so that a consumer which only signs or verifies
//! a message, such as a validator client, can reach them without taking on that
//! crate's `blst`, `c-kzg` and RocksDB dependencies.

use crate::beacon::constants::DOMAIN_DEPOSIT;
use crate::beacon::containers::shared::{Fork, SigningData};
use crate::beacon::fork_digest::compute_fork_data_root;
use crate::beacon::preset;
use crate::beacon::primitives::{
    Domain, DomainType, Epoch, HashTreeRoot as _, Root, Slot, Version,
};

/// The epoch containing `slot`.
pub fn compute_epoch_at_slot(slot: Slot) -> Epoch {
    slot / preset::SLOTS_PER_EPOCH
}

/// The first slot of `epoch`.
pub fn compute_start_slot_at_epoch(epoch: Epoch) -> Slot {
    epoch * preset::SLOTS_PER_EPOCH
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

/// The fork version in effect at `epoch`, given the state's fork schedule.
///
/// A message signed just before a fork boundary must still verify just after it,
/// which is why the state keeps the previous version at all.
pub fn fork_version_at_epoch(fork: &Fork, epoch: Epoch) -> Version {
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
    compute_domain(DOMAIN_DEPOSIT, genesis_fork_version, Root::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fork_version_switches_at_the_boundary() {
        let fork = Fork {
            previous_version: [0, 0, 0, 0],
            current_version: [1, 0, 0, 0],
            epoch: 10,
        };
        assert_eq!(fork_version_at_epoch(&fork, 9), [0, 0, 0, 0]);
        assert_eq!(fork_version_at_epoch(&fork, 10), [1, 0, 0, 0]);
        assert_eq!(fork_version_at_epoch(&fork, 11), [1, 0, 0, 0]);
    }

    #[test]
    fn domain_carries_the_type_then_the_fork_data_prefix() {
        let domain = compute_domain([1, 0, 0, 0], [2, 0, 0, 0], Root::repeat_byte(9));
        assert_eq!(&domain[..4], &[1, 0, 0, 0]);

        let fork_data_root = compute_fork_data_root([2, 0, 0, 0], Root::repeat_byte(9));
        assert_eq!(&domain[4..], &fork_data_root.0[..28]);
    }

    #[test]
    fn domain_separates_forks_and_chains() {
        let a = compute_domain([1, 0, 0, 0], [2, 0, 0, 0], Root::ZERO);
        let b = compute_domain([1, 0, 0, 0], [3, 0, 0, 0], Root::ZERO);
        let c = compute_domain([1, 0, 0, 0], [2, 0, 0, 0], Root::repeat_byte(1));
        assert_ne!(
            a, b,
            "a different fork version must give a different domain"
        );
        assert_ne!(a, c, "a different chain must give a different domain");
    }

    #[test]
    fn signing_root_commits_to_both_the_object_and_the_domain() {
        let domain = compute_domain([1, 0, 0, 0], [2, 0, 0, 0], Root::ZERO);
        let other_domain = compute_domain([9, 0, 0, 0], [2, 0, 0, 0], Root::ZERO);
        let a = compute_signing_root(Root::repeat_byte(1), domain);
        let b = compute_signing_root(Root::repeat_byte(2), domain);
        let c = compute_signing_root(Root::repeat_byte(1), other_domain);
        assert_ne!(
            a, b,
            "a different object root must give a different signing root"
        );
        assert_ne!(
            a, c,
            "a different domain must give a different signing root"
        );
    }

    #[test]
    fn epoch_and_start_slot_round_trip() {
        let epoch = 42;
        let start = compute_start_slot_at_epoch(epoch);
        assert_eq!(compute_epoch_at_slot(start), epoch);
        assert_eq!(
            compute_epoch_at_slot(start + preset::SLOTS_PER_EPOCH - 1),
            epoch
        );
    }
}
