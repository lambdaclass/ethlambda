//! A minimal state builder shared by the helper tests.
//!
//! Several helpers can only be exercised against a state with a populated
//! validator registry and correctly sized history vectors, and building one by
//! hand in each test would bury the assertion under setup. Test-only: nothing in
//! the crate's public surface depends on it.

use crate::constants;
use crate::containers::BeaconState;
use crate::containers::phase0;
use crate::containers::shared::Validator;
use crate::preset;
use crate::primitives::{Bytes32, Root};

/// A phase0 state with `count` fully active, full-balance validators, positioned
/// one epoch in so that the previous epoch exists and the block root window has
/// entries behind it.
pub fn with_validators(count: usize) -> BeaconState {
    let validators: Vec<Validator> = (0..count)
        .map(|_| Validator {
            effective_balance: preset::MAX_EFFECTIVE_BALANCE,
            activation_eligibility_epoch: 0,
            activation_epoch: 0,
            exit_epoch: constants::FAR_FUTURE_EPOCH,
            withdrawable_epoch: constants::FAR_FUTURE_EPOCH,
            ..Default::default()
        })
        .collect();

    BeaconState::Phase0(phase0::BeaconState {
        genesis_time: 0,
        genesis_validators_root: Root::zero(),
        slot: preset::SLOTS_PER_EPOCH,
        fork: Default::default(),
        latest_block_header: Default::default(),
        block_roots: vec![Root::zero(); preset::SLOTS_PER_HISTORICAL_ROOT]
            .try_into()
            .expect("the vector is built at its exact length"),
        state_roots: vec![Root::zero(); preset::SLOTS_PER_HISTORICAL_ROOT]
            .try_into()
            .expect("the vector is built at its exact length"),
        historical_roots: Default::default(),
        eth1_data: Default::default(),
        eth1_data_votes: Default::default(),
        eth1_deposit_index: 0,
        validators: validators
            .try_into()
            .expect("count is far below VALIDATOR_REGISTRY_LIMIT"),
        balances: vec![preset::MAX_EFFECTIVE_BALANCE; count]
            .try_into()
            .expect("count is far below VALIDATOR_REGISTRY_LIMIT"),
        randao_mixes: vec![Bytes32::zero(); preset::EPOCHS_PER_HISTORICAL_VECTOR]
            .try_into()
            .expect("the vector is built at its exact length"),
        slashings: vec![0; preset::EPOCHS_PER_SLASHINGS_VECTOR]
            .try_into()
            .expect("the vector is built at its exact length"),
        previous_epoch_attestations: Default::default(),
        current_epoch_attestations: Default::default(),
        justification_bits: Default::default(),
        previous_justified_checkpoint: Default::default(),
        current_justified_checkpoint: Default::default(),
        finalized_checkpoint: Default::default(),
    })
}
