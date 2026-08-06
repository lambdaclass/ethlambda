//! Genesis: building the first `BeaconState` from Eth1 deposit history, and
//! deciding when a candidate built that way is allowed to become the real
//! genesis.
//!
//! Two functions, matching the specification's own split. Building a
//! candidate never fails because the chain is not ready yet: every deposit
//! given to it is replayed exactly as the deposit contract received it, so
//! this can only produce *a* state, not necessarily one old enough or with
//! enough validators to actually start a chain. Whether it may start is
//! [`is_valid_genesis_state`]'s job, checked separately (in practice, against
//! every candidate as new Eth1 blocks arrive) so the same construction logic
//! runs whether or not this particular candidate turns out to be the one that
//! finally crosses the threshold.

use libssz_types::SszList;

use crate::config::Config;
use crate::constants;
use crate::containers::shared::{BeaconBlockHeader, Deposit, DepositData, Eth1Data, Fork};
use crate::containers::{BeaconState, phase0};
use crate::error::Result;
use crate::helpers::accessors::get_active_validator_indices;
use crate::preset;
use crate::primitives::{HashTreeRoot as _, Root, ValidatorIndex};
use crate::stf::operations::process_deposit;

/// The deposit data list [`initialize_beacon_state_from_eth1`] rebuilds one
/// leaf larger at every step while replaying Eth1 deposit history, so that
/// each deposit's merkle proof can be checked against the root as it stood
/// right after the deposit before it, exactly as the deposit contract's own
/// incremental tree would have it.
///
/// Bounded by two to the power of `DEPOSIT_CONTRACT_TREE_DEPTH`, the deposit
/// contract's own tree capacity: this list can never need to hold more leaves
/// than the tree has room for. Not a preset value: the specification gives
/// this bound as an inline formula on this one list rather than as a named
/// preset entry, so it is defined here rather than in `crate::preset`.
type GenesisDepositDataList =
    SszList<DepositData, { 2usize.pow(constants::DEPOSIT_CONTRACT_TREE_DEPTH as u32) }>;

/// Builds a candidate genesis state from Eth1 deposit history.
///
/// `deposits` must be every deposit up to and including `eth1_block_hash`, in
/// the order the deposit contract received them: each one is checked against
/// the merkle root of every deposit before it, so an out-of-order or
/// truncated history fails a later deposit's proof rather than silently
/// producing a different, still internally consistent, state.
///
/// The result is a candidate only. Call [`is_valid_genesis_state`] on it, with
/// the same configuration, to find out whether the chain may actually start
/// from it.
pub fn initialize_beacon_state_from_eth1(
    eth1_block_hash: Root,
    eth1_timestamp: u64,
    deposits: &[Deposit],
    config: &Config,
) -> Result<BeaconState> {
    let fork = Fork {
        previous_version: config.genesis_fork_version,
        current_version: config.genesis_fork_version,
        epoch: constants::GENESIS_EPOCH,
    };

    let empty_body_root = phase0::BeaconBlockBody {
        randao_reveal: Default::default(),
        eth1_data: Default::default(),
        graffiti: Default::default(),
        proposer_slashings: Default::default(),
        attester_slashings: Default::default(),
        attestations: Default::default(),
        deposits: Default::default(),
        voluntary_exits: Default::default(),
    }
    .hash_tree_root();

    let mut state = BeaconState::Phase0(phase0::BeaconState {
        // `eth1_timestamp` comes from outside the chain, so it is treated the
        // same as any other externally supplied value: saturating rather than
        // wrapping past `u64::MAX`.
        genesis_time: eth1_timestamp.saturating_add(config.genesis_delay),
        genesis_validators_root: Root::zero(),
        slot: constants::GENESIS_SLOT,
        fork,
        latest_block_header: BeaconBlockHeader {
            body_root: empty_body_root,
            ..Default::default()
        },
        // The rolling root windows start zeroed: nothing has been processed
        // yet for `process_slot` to have filled them with.
        block_roots: vec![Root::zero(); preset::SLOTS_PER_HISTORICAL_ROOT]
            .try_into()
            .expect("the vector is built at its exact length"),
        state_roots: vec![Root::zero(); preset::SLOTS_PER_HISTORICAL_ROOT]
            .try_into()
            .expect("the vector is built at its exact length"),
        historical_roots: Default::default(),
        eth1_data: Eth1Data {
            deposit_root: Root::zero(),
            deposit_count: deposits.len() as u64,
            block_hash: eth1_block_hash,
        },
        eth1_data_votes: Default::default(),
        eth1_deposit_index: 0,
        validators: Default::default(),
        balances: Default::default(),
        // Seeded with the Eth1 block hash in every position, not only the
        // first. This is deliberate: it is what makes the very first epoch's
        // shuffling unpredictable before any validator has produced a randao
        // reveal of its own.
        randao_mixes: vec![eth1_block_hash; preset::EPOCHS_PER_HISTORICAL_VECTOR]
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
    });

    // Replay deposit history, growing the merkle tree one leaf at a time so
    // that `process_deposit` checks each deposit's proof against the root as
    // it stood right after the deposit before it, not the final root every
    // deposit would otherwise be checked against.
    let mut deposit_data_list = GenesisDepositDataList::default();
    for deposit in deposits {
        deposit_data_list.push(deposit.data.clone())?;
        let deposit_root = deposit_data_list.hash_tree_root();
        state.eth1_data_mut().deposit_root = deposit_root;
        process_deposit(&mut state, deposit, config)?;
    }

    // Activate every validator whose deposits reached the cap. Genesis is the
    // one moment effective balance is set directly from the raw balance
    // rather than eased toward it over time: there is no previous effective
    // balance yet for hysteresis to protect.
    for index in 0..state.validators().len() as ValidatorIndex {
        let balance = state.balance(index)?;
        let effective_balance = (balance - balance % preset::EFFECTIVE_BALANCE_INCREMENT)
            .min(preset::MAX_EFFECTIVE_BALANCE);

        let validator = state.validator_mut(index)?;
        validator.effective_balance = effective_balance;
        if effective_balance == preset::MAX_EFFECTIVE_BALANCE {
            validator.activation_eligibility_epoch = constants::GENESIS_EPOCH;
            validator.activation_epoch = constants::GENESIS_EPOCH;
        }
    }

    // Last, not first: everything above can still change which validators
    // exist and what their keys are, and this root is what permanently
    // separates this chain, and every signature made on it, from any other
    // network that happens to run the same fork schedule.
    let genesis_validators_root = state.validators().hash_tree_root();
    *state.genesis_validators_root_mut() = genesis_validators_root;

    Ok(state)
}

/// Whether a candidate genesis state may actually become the chain's genesis.
///
/// Checked against every candidate as Eth1 deposit history grows; the first
/// one for which this returns `true` is genesis. Both conditions are about
/// the chain being old enough and big enough to be worth starting, not about
/// the candidate being internally well-formed, which
/// [`initialize_beacon_state_from_eth1`] already guarantees by construction.
pub fn is_valid_genesis_state(state: &BeaconState, config: &Config) -> bool {
    if state.genesis_time() < config.min_genesis_time {
        return false;
    }
    let active_validator_count =
        get_active_validator_indices(state, constants::GENESIS_EPOCH).len() as u64;
    if active_validator_count < config.min_genesis_active_validator_count {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_state_is_invalid_before_the_configured_genesis_time() {
        let config = Config::minimal();
        let mut state = crate::helpers::test_state::with_validators(
            config.min_genesis_active_validator_count as usize,
        );

        *state.genesis_time_mut() = config.min_genesis_time - 1;
        assert!(!is_valid_genesis_state(&state, &config));

        *state.genesis_time_mut() = config.min_genesis_time;
        assert!(is_valid_genesis_state(&state, &config));
    }

    #[test]
    fn genesis_state_is_invalid_with_too_few_active_validators() {
        let config = Config::minimal();
        let mut state = crate::helpers::test_state::with_validators(
            config.min_genesis_active_validator_count as usize - 1,
        );
        *state.genesis_time_mut() = config.min_genesis_time;

        assert!(!is_valid_genesis_state(&state, &config));
    }
}
