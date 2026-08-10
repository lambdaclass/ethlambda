//! Capella's new predicates: the three checks that decide whether a validator
//! is owed a payout from the withdrawal sweep.
//!
//! Before this fork a validator's balance could shrink but never leave the
//! consensus layer, so nothing needed to ask "is this validator owed money
//! right now". Capella's sweep (`get_expected_withdrawals`, not implemented in
//! this file) asks exactly that once per validator it visits, and these three
//! predicates are the answer: [`has_eth1_withdrawal_credential`] gates the
//! other two on the validator having upgraded its withdrawal credentials at
//! all, [`is_fully_withdrawable_validator`] is true once the validator has
//! exited and its withdrawable epoch has passed, and
//! [`is_partially_withdrawable_validator`] is true for a still-active
//! validator sitting on more balance than it can earn rewards on.
//!
//! These three versions serve capella through deneb. Electra replaces all
//! three ([`crate::helpers::electra::has_execution_withdrawal_credential`],
//! `is_fully_withdrawable_validator`, `is_partially_withdrawable_validator`)
//! rather than reusing them: EIP-7251 adds a second, compounding withdrawal
//! credential prefix that the fully- and partially-withdrawable checks also
//! need to accept, and replaces the flat [`preset::MAX_EFFECTIVE_BALANCE`]
//! ceiling in the partial check with a per-validator maximum that depends on
//! which credential a validator holds. That is different enough in shape
//! (an extra prefix to check, and a ceiling that is no longer a single
//! constant) that sharing an implementation between the two forks would mean
//! threading electra's parameters through capella's call sites for no benefit
//! to either; the specification itself lists electra's versions as replacing
//! these outright rather than extending them, so this module and electra's
//! coexist rather than one calling the other.

use crate::constants;
use crate::containers::shared::Validator;
use crate::preset;
use crate::primitives::{Epoch, Gwei};

/// Whether `validator`'s withdrawal credentials have been upgraded to an
/// execution address.
///
/// Until this is true, the validator's stake has nowhere to be paid out to:
/// the raw BLS credential every validator starts with names a public key, not
/// an execution-layer account, so `has_eth1_withdrawal_credential`'s two
/// callers below both gate on it first.
pub fn has_eth1_withdrawal_credential(validator: &Validator) -> bool {
    validator.withdrawal_credentials.0[0] == constants::ETH1_ADDRESS_WITHDRAWAL_PREFIX
}

/// Whether `validator` should have its entire balance swept out.
///
/// True once the validator is both past its withdrawable epoch (so it is done
/// being slashable, see [`super::predicates::is_slashable_validator`]) and
/// still holding a positive balance: a validator already swept to zero has
/// nothing left to pay out, so the sweep can skip it without checking the
/// epoch condition again.
pub fn is_fully_withdrawable_validator(validator: &Validator, balance: Gwei, epoch: Epoch) -> bool {
    has_eth1_withdrawal_credential(validator)
        && validator.withdrawable_epoch <= epoch
        && balance > 0
}

/// Whether `validator` should have its excess balance (above
/// [`preset::MAX_EFFECTIVE_BALANCE`]) swept out while it keeps validating.
///
/// Restricted to a validator already at the full effective balance: a
/// validator below that ceiling is still earning rewards on every increment
/// of its actual balance, so nothing above the ceiling exists yet to call
/// excess.
pub fn is_partially_withdrawable_validator(validator: &Validator, balance: Gwei) -> bool {
    let has_max_effective_balance = validator.effective_balance == preset::MAX_EFFECTIVE_BALANCE;
    let has_excess_balance = balance > preset::MAX_EFFECTIVE_BALANCE;
    has_eth1_withdrawal_credential(validator) && has_max_effective_balance && has_excess_balance
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validator_with_prefix(prefix: u8) -> Validator {
        let mut withdrawal_credentials = crate::primitives::Bytes32::zero();
        withdrawal_credentials.0[0] = prefix;
        Validator {
            withdrawal_credentials,
            effective_balance: preset::MAX_EFFECTIVE_BALANCE,
            withdrawable_epoch: 10,
            ..Default::default()
        }
    }

    #[test]
    fn only_the_eth1_prefix_counts_as_an_eth1_withdrawal_credential() {
        assert!(!has_eth1_withdrawal_credential(&validator_with_prefix(
            constants::BLS_WITHDRAWAL_PREFIX
        )));
        assert!(has_eth1_withdrawal_credential(&validator_with_prefix(
            constants::ETH1_ADDRESS_WITHDRAWAL_PREFIX
        )));
        // Electra's compounding prefix is not eth1: this predicate serves
        // capella through deneb only, and never sees that prefix in practice,
        // but it should not be mistaken for the one it does recognize.
        assert!(!has_eth1_withdrawal_credential(&validator_with_prefix(
            constants::COMPOUNDING_WITHDRAWAL_PREFIX
        )));
    }

    #[test]
    fn full_withdrawability_needs_the_credential_the_epoch_and_a_balance() {
        let validator = validator_with_prefix(constants::ETH1_ADDRESS_WITHDRAWAL_PREFIX);

        // Before the withdrawable epoch: not yet.
        assert!(!is_fully_withdrawable_validator(&validator, 1, 5));
        // At and after the withdrawable epoch, with a balance: withdrawable.
        assert!(is_fully_withdrawable_validator(&validator, 1, 10));
        assert!(is_fully_withdrawable_validator(&validator, 1, 20));
        // Nothing left to pay out.
        assert!(!is_fully_withdrawable_validator(&validator, 0, 20));

        // Without the eth1 credential, never withdrawable regardless of epoch
        // or balance.
        let bls_validator = validator_with_prefix(constants::BLS_WITHDRAWAL_PREFIX);
        assert!(!is_fully_withdrawable_validator(&bls_validator, 1, 20));
    }

    #[test]
    fn partial_withdrawability_needs_the_credential_and_excess_above_the_ceiling() {
        let mut validator = validator_with_prefix(constants::ETH1_ADDRESS_WITHDRAWAL_PREFIX);

        // At the ceiling, no excess yet.
        assert!(!is_partially_withdrawable_validator(
            &validator,
            preset::MAX_EFFECTIVE_BALANCE
        ));
        // Above the ceiling: the excess is withdrawable.
        assert!(is_partially_withdrawable_validator(
            &validator,
            preset::MAX_EFFECTIVE_BALANCE + 1
        ));

        // Below the full effective balance, excess balance does not count:
        // the validator has not maxed out what it can earn rewards on yet.
        validator.effective_balance -= 1;
        assert!(!is_partially_withdrawable_validator(
            &validator,
            preset::MAX_EFFECTIVE_BALANCE + 1
        ));
    }
}
