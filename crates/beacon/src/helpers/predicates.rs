//! Predicates over validators and attestations.

use crate::constants::FAR_FUTURE_EPOCH;
use crate::containers::shared::{AttestationData, Validator};
use crate::preset;
use crate::primitives::Epoch;

/// Whether `validator` is active at `epoch`.
pub fn is_active_validator(validator: &Validator, epoch: Epoch) -> bool {
    validator.activation_epoch <= epoch && epoch < validator.exit_epoch
}

/// Whether `validator` may join the activation queue.
///
/// Requires the full effective balance, not merely a positive one: a partially
/// funded validator waits until its balance is topped up.
pub fn is_eligible_for_activation_queue(validator: &Validator) -> bool {
    validator.activation_eligibility_epoch == FAR_FUTURE_EPOCH
        && validator.effective_balance == preset::MAX_EFFECTIVE_BALANCE
}

/// Whether `validator` may be activated, given the finalized epoch.
///
/// Activation waits for the queue placement itself to be finalized, so that a
/// reorg cannot retroactively change who was activated when.
pub fn is_eligible_for_activation(validator: &Validator, finalized_epoch: Epoch) -> bool {
    validator.activation_eligibility_epoch <= finalized_epoch
        && validator.activation_epoch == FAR_FUTURE_EPOCH
}

/// Whether `validator` can still be slashed at `epoch`.
///
/// Remains true until the withdrawable epoch rather than the exit epoch, which is
/// what keeps an offence punishable for a while after the validator leaves.
pub fn is_slashable_validator(validator: &Validator, epoch: Epoch) -> bool {
    !validator.slashed
        && validator.activation_epoch <= epoch
        && epoch < validator.withdrawable_epoch
}

/// Whether two attestations are slashable under the Casper FFG rules.
///
/// Two cases. A double vote is two different attestations for the same target
/// epoch. A surround vote is one attestation whose source and target strictly
/// enclose the other's, which is the equivocation that would let a validator
/// support two conflicting finalizations.
pub fn is_slashable_attestation_data(data_1: &AttestationData, data_2: &AttestationData) -> bool {
    let double_vote = data_1 != data_2 && data_1.target.epoch == data_2.target.epoch;
    let surround_vote =
        data_1.source.epoch < data_2.source.epoch && data_2.target.epoch < data_1.target.epoch;
    double_vote || surround_vote
}

/// Whether a list of attesting indices is sorted and free of duplicates, which
/// the specification requires of an `IndexedAttestation`.
///
/// Canonical ordering matters because the attestation's root, and therefore
/// slashing evidence built on it, would otherwise depend on the order a client
/// happened to produce.
pub fn are_indices_sorted_and_unique(indices: &[u64]) -> bool {
    !indices.is_empty() && indices.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::containers::shared::Checkpoint;

    fn validator() -> Validator {
        Validator {
            activation_epoch: 5,
            exit_epoch: 10,
            withdrawable_epoch: 20,
            effective_balance: preset::MAX_EFFECTIVE_BALANCE,
            activation_eligibility_epoch: FAR_FUTURE_EPOCH,
            ..Default::default()
        }
    }

    #[test]
    fn activity_is_a_half_open_interval() {
        let validator = validator();
        assert!(!is_active_validator(&validator, 4));
        assert!(is_active_validator(&validator, 5));
        assert!(is_active_validator(&validator, 9));
        assert!(!is_active_validator(&validator, 10));
    }

    #[test]
    fn slashability_outlasts_activity() {
        let validator = validator();
        // Past the exit epoch but before the withdrawable epoch: no longer
        // active, still slashable.
        assert!(!is_active_validator(&validator, 15));
        assert!(is_slashable_validator(&validator, 15));
        assert!(!is_slashable_validator(&validator, 20));
    }

    #[test]
    fn an_already_slashed_validator_is_not_slashable_again() {
        let mut validator = validator();
        validator.slashed = true;
        assert!(!is_slashable_validator(&validator, 6));
    }

    #[test]
    fn activation_queue_eligibility_needs_the_full_balance() {
        let mut validator = validator();
        assert!(is_eligible_for_activation_queue(&validator));

        validator.effective_balance -= 1;
        assert!(!is_eligible_for_activation_queue(&validator));
    }

    fn data(source: Epoch, target: Epoch, root: u8) -> AttestationData {
        AttestationData {
            source: Checkpoint {
                epoch: source,
                root: Default::default(),
            },
            target: Checkpoint {
                epoch: target,
                root: crate::primitives::Root::repeat_byte(root),
            },
            ..Default::default()
        }
    }

    #[test]
    fn identical_attestations_are_not_slashable() {
        let one = data(1, 2, 0);
        assert!(!is_slashable_attestation_data(&one, &one));
    }

    #[test]
    fn a_double_vote_is_slashable() {
        // Same target epoch, different content.
        let a = data(1, 2, 1);
        let b = data(1, 2, 2);
        assert!(is_slashable_attestation_data(&a, &b));
    }

    #[test]
    fn a_surround_vote_is_slashable_in_one_direction_only() {
        // a's span strictly encloses b's.
        let a = data(1, 6, 1);
        let b = data(2, 5, 2);
        assert!(is_slashable_attestation_data(&a, &b));
        // The predicate is asymmetric: the caller checks both orders.
        assert!(!is_slashable_attestation_data(&b, &a));
    }

    #[test]
    fn non_overlapping_attestations_are_not_slashable() {
        let a = data(1, 2, 1);
        let b = data(3, 4, 2);
        assert!(!is_slashable_attestation_data(&a, &b));
    }

    #[test]
    fn indices_must_be_sorted_unique_and_non_empty() {
        assert!(are_indices_sorted_and_unique(&[0, 1, 5]));
        assert!(!are_indices_sorted_and_unique(&[]));
        assert!(!are_indices_sorted_and_unique(&[1, 1]));
        assert!(!are_indices_sorted_and_unique(&[5, 1]));
    }
}
