//! Epoch processing.
//!
//! Runs on the last slot of every epoch. Phase0 does the bulk of its accounting
//! here rather than as attestations arrive, because the reward an attestation
//! earns depends on facts that are not settled when it is included: whether its
//! target became the canonical block for the epoch, and whether the chain is
//! finalizing at all. So attestations accumulate in the state and are replayed
//! here.
//!
//! Order matters between these steps, and in two places it is load-bearing:
//!
//! - Justification and finalization runs before rewards, so rewards are computed
//!   against the finality state the attestations themselves produced.
//! - Registry updates run before slashings, so a validator that exits this epoch
//!   is already exiting when the slashing penalty is scaled.

pub mod justification;
pub mod registry;
pub mod rewards;

use crate::containers::phase0::PendingAttestation;
use crate::containers::{BeaconState, HistoricalBatch};
use crate::error::{Result, verify};
use crate::helpers::accessors::{
    get_block_root, get_block_root_at_slot, get_current_epoch, get_previous_epoch, get_randao_mix,
    get_total_balance,
};
use crate::preset;
use crate::primitives::{Epoch, Gwei, HashTreeRoot as _, ValidatorIndex};
use crate::{config::Config, constants};

use super::phase0_state;

/// Runs every epoch-boundary step, in the specification's order.
pub fn process_epoch(state: &mut BeaconState, config: &Config) -> Result<()> {
    justification::process_justification_and_finalization(state, config)?;
    rewards::process_rewards_and_penalties(state, config)?;
    registry::process_registry_updates(state, config)?;
    registry::process_slashings(state, config)?;
    process_eth1_data_reset(state)?;
    process_effective_balance_updates(state)?;
    process_slashings_reset(state)?;
    process_randao_mixes_reset(state)?;
    process_historical_roots_update(state)?;
    process_participation_record_updates(state)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Attestation matching
// ---------------------------------------------------------------------------

/// The attestations the state retained for `epoch`.
///
/// Only the current and previous epoch are available, since those are the only
/// two the state keeps.
pub fn get_matching_source_attestations(
    state: &BeaconState,
    epoch: Epoch,
) -> Result<Vec<PendingAttestation>> {
    let current = get_current_epoch(state);
    verify(
        epoch == current || epoch == get_previous_epoch(state),
        "attestations are only retained for the current and previous epoch",
    )?;

    let state = super::phase0_state_ref(state, "get_matching_source_attestations")?;
    let attestations = if epoch == current {
        &state.current_epoch_attestations
    } else {
        &state.previous_epoch_attestations
    };
    Ok(attestations.to_vec())
}

/// Those whose target is the epoch's canonical block, meaning the attester agreed
/// with this chain about what the epoch's checkpoint is.
pub fn get_matching_target_attestations(
    state: &BeaconState,
    epoch: Epoch,
) -> Result<Vec<PendingAttestation>> {
    let source = get_matching_source_attestations(state, epoch)?;

    // The early return is load-bearing, not an optimization. The specification
    // writes this as a list comprehension, so `get_block_root` is evaluated per
    // element and never at all when there are no attestations. It has its own
    // range assertion, which fails for the epoch a state sits at the very start
    // of, so hoisting the call out of the loop would reject states the
    // specification accepts.
    if source.is_empty() {
        return Ok(Vec::new());
    }

    let block_root = get_block_root(state, epoch)?;
    Ok(source
        .into_iter()
        .filter(|attestation| attestation.data.target.root == block_root)
        .collect())
}

/// Those that also agreed about the head block at their own slot, which is the
/// strictest of the three and the only one that depends on the attester having
/// been up to date at the time.
pub fn get_matching_head_attestations(
    state: &BeaconState,
    epoch: Epoch,
) -> Result<Vec<PendingAttestation>> {
    let mut matching = Vec::new();
    for attestation in get_matching_target_attestations(state, epoch)? {
        let root = get_block_root_at_slot(state, attestation.data.slot)?;
        if attestation.data.beacon_block_root == root {
            matching.push(attestation);
        }
    }
    Ok(matching)
}

/// The union of the attesters in `attestations`, minus those since slashed.
///
/// Sorted and deduplicated, since callers use it both as a set and to index the
/// registry in order.
pub fn get_unslashed_attesting_indices(
    state: &BeaconState,
    attestations: &[PendingAttestation],
) -> Result<Vec<ValidatorIndex>> {
    let mut indices = Vec::new();
    for attestation in attestations {
        let committee = crate::helpers::accessors::get_beacon_committee(
            state,
            attestation.data.slot,
            attestation.data.index,
        )?;
        for (position, index) in committee.into_iter().enumerate() {
            if attestation.aggregation_bits.get(position).unwrap_or(false) {
                indices.push(index);
            }
        }
    }

    indices.sort_unstable();
    indices.dedup();
    indices.retain(|index| {
        state
            .validator(*index)
            .is_ok_and(|validator| !validator.slashed)
    });
    Ok(indices)
}

/// The combined effective balance of the unslashed attesters in `attestations`.
pub fn get_attesting_balance(
    state: &BeaconState,
    attestations: &[PendingAttestation],
) -> Result<Gwei> {
    let indices = get_unslashed_attesting_indices(state, attestations)?;
    get_total_balance(state, &indices)
}

// ---------------------------------------------------------------------------
// Resets and rotations
// ---------------------------------------------------------------------------

/// Clears the eth1 vote tally at the end of each voting period.
pub fn process_eth1_data_reset(state: &mut BeaconState) -> Result<()> {
    let next_epoch = get_current_epoch(state) + 1;
    if next_epoch.is_multiple_of(preset::EPOCHS_PER_ETH1_VOTING_PERIOD) {
        *state.eth1_data_votes_mut() = Default::default();
    }
    Ok(())
}

/// Moves each validator's effective balance toward its actual balance.
///
/// The two thresholds are hysteresis: a balance has to move meaningfully past the
/// boundary before the effective balance follows it. Without that, a validator
/// hovering at an increment boundary would change effective balance every epoch,
/// and since effective balance feeds the shuffling seed's weighting and every
/// reward, that would churn far more than it measures.
pub fn process_effective_balance_updates(state: &mut BeaconState) -> Result<()> {
    const HYSTERESIS_INCREMENT: Gwei =
        preset::EFFECTIVE_BALANCE_INCREMENT / preset::HYSTERESIS_QUOTIENT;
    const DOWNWARD_THRESHOLD: Gwei = HYSTERESIS_INCREMENT * preset::HYSTERESIS_DOWNWARD_MULTIPLIER;
    const UPWARD_THRESHOLD: Gwei = HYSTERESIS_INCREMENT * preset::HYSTERESIS_UPWARD_MULTIPLIER;

    // Decided in one pass and applied in another. The state is an enum over
    // per-fork structs, so the accessors hand out a borrow of the whole state
    // rather than of one field, and there is no way to hold `validators` mutably
    // while reading `balances`. Collecting the decisions first keeps this
    // fork-independent, which matters because every fork runs this step
    // unchanged.
    let mut updates = Vec::new();
    for (index, validator) in state.validators().iter().enumerate() {
        let balance = state.balances()[index];
        if balance + DOWNWARD_THRESHOLD < validator.effective_balance
            || validator.effective_balance + UPWARD_THRESHOLD < balance
        {
            let effective = (balance - balance % preset::EFFECTIVE_BALANCE_INCREMENT)
                .min(preset::MAX_EFFECTIVE_BALANCE);
            updates.push((index, effective));
        }
    }

    let validators = state.validators_mut();
    for (index, effective) in updates {
        validators[index].effective_balance = effective;
    }
    Ok(())
}

/// Zeroes the slot the slashings ring buffer is about to reuse.
pub fn process_slashings_reset(state: &mut BeaconState) -> Result<()> {
    let next_epoch = get_current_epoch(state) + 1;
    let position = next_epoch as usize % preset::EPOCHS_PER_SLASHINGS_VECTOR;
    state.slashings_mut()[position] = 0;
    Ok(())
}

/// Seeds the next epoch's randao slot with the current epoch's mix.
pub fn process_randao_mixes_reset(state: &mut BeaconState) -> Result<()> {
    let current_epoch = get_current_epoch(state);
    let mix = get_randao_mix(state, current_epoch);
    let position = (current_epoch + 1) as usize % preset::EPOCHS_PER_HISTORICAL_VECTOR;
    state.randao_mixes_mut()[position] = mix;
    Ok(())
}

/// Folds the block and state root vectors into one historical root when they are
/// about to wrap.
///
/// This is what keeps history provable after the ring buffers overwrite it: the
/// roots themselves are dropped, but a commitment to them is kept forever.
pub fn process_historical_roots_update(state: &mut BeaconState) -> Result<()> {
    let next_epoch = get_current_epoch(state) + 1;
    let epochs_per_historical_root =
        (preset::SLOTS_PER_HISTORICAL_ROOT / preset::SLOTS_PER_EPOCH as usize) as Epoch;
    if next_epoch.is_multiple_of(epochs_per_historical_root) {
        let batch = HistoricalBatch {
            block_roots: state.block_roots().clone(),
            state_roots: state.state_roots().clone(),
        };
        state.historical_roots_mut().push(batch.hash_tree_root())?;
    }
    Ok(())
}

/// Rotates the retained attestations, discarding those two epochs old.
pub fn process_participation_record_updates(state: &mut BeaconState) -> Result<()> {
    let state = phase0_state(state, "process_participation_record_updates")?;
    state.previous_epoch_attestations = core::mem::take(&mut state.current_epoch_attestations);
    Ok(())
}

/// The number of epochs of attestation history the justification bitfield holds.
pub(crate) const JUSTIFICATION_BITS: usize = constants::JUSTIFICATION_BITS_LENGTH;
