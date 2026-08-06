//! Fork-boundary state upgrades.
//!
//! `process_slots` runs an irregular state change whenever it advances the
//! state across a fork's activation epoch: the state's shape itself changes,
//! which an ordinary block-driven mutation can never do. Each fork that
//! changes the state's shape gets one function here, named and structured
//! after the specification's own `upgrade_to_<fork>`, plus one arm in
//! [`upgrade_state`] so a caller that only knows the target [`ForkName`] does
//! not have to match on it itself.
//!
//! Every upgrade function takes the pre-state by reference and returns a new
//! post-state rather than mutating in place. The two states are different
//! Rust types (`phase0::BeaconState` and `altair::BeaconState` are not the
//! same struct), so an in-place upgrade is not expressible in the type system
//! to begin with, and returning a value keeps the field-by-field mapping laid
//! out once, in one place, checkable against the specification's own
//! constructor line by line.

use crate::config::Config;
use crate::containers::{BeaconState, EpochParticipation, Fork, InactivityScores, altair, phase0};
use crate::error::{Error, Result};
use crate::fork::ForkName;
use crate::helpers::attestation::get_attesting_indices;
use crate::helpers::misc::compute_epoch_at_slot;
use crate::preset;
use crate::primitives::BlsPubkey;
use crate::primitives::BlsSignature;

/// Replays `pending_attestations` into `post`'s `previous_epoch_participation`.
///
/// Phase0 scores an attestation only at the epoch boundary, by replaying
/// whatever accumulated in `previous_epoch_attestations`. Altair scores one
/// the moment it is processed and keeps no backlog, so without this step the
/// upgrade would silently discard the attestations phase0 was still holding
/// for the epoch that was in progress when the fork activated: those flags
/// are exactly what the next epoch boundary's rewards pass reads.
///
/// Takes `post` as the enum rather than the concrete altair struct because
/// [`get_attestation_participation_flag_indices`](crate::helpers::altair::get_attestation_participation_flag_indices)
/// and [`get_attesting_indices`] both read only fields every fork shares
/// (justified checkpoints, block roots, committees), so they are written
/// against `&BeaconState` like every other state accessor in this crate. The
/// match is repeated once per attestation rather than hoisted above the loop
/// so that each iteration's immutable borrow (for those two calls) ends
/// before the mutable borrow (for writing the flags) begins; a single match
/// held across the whole loop would keep the mutable borrow alive throughout
/// and rule out the immutable calls entirely.
fn translate_participation(
    post: &mut BeaconState,
    pending_attestations: &[phase0::PendingAttestation],
) -> Result<()> {
    for attestation in pending_attestations {
        let participation_flag_indices =
            crate::helpers::altair::get_attestation_participation_flag_indices(
                post,
                &attestation.data,
                attestation.inclusion_delay,
            )?;

        // `get_attesting_indices` is typed for a phase0 `Attestation`, not a
        // `PendingAttestation`. The two carry exactly the fields it reads
        // (`data` and `aggregation_bits`); a signature-less `Attestation`
        // assembled from them stands in rather than adding a second,
        // decomposed entry point for one caller.
        let attestation_for_indices = phase0::Attestation {
            aggregation_bits: attestation.aggregation_bits.clone(),
            data: attestation.data,
            signature: BlsSignature::default(),
        };
        let attesting_indices = get_attesting_indices(post, &attestation_for_indices)?;

        let altair_state = match post {
            BeaconState::Altair(state) => state,
            other => {
                return Err(Error::UnsupportedForFork {
                    function: "translate_participation",
                    fork: other.fork_name(),
                });
            }
        };
        for index in attesting_indices {
            let entry = altair_state
                .previous_epoch_participation
                .get_mut(index as usize)
                .ok_or(Error::UnknownValidator(index))?;
            for &flag_index in &participation_flag_indices {
                *entry = crate::helpers::altair::add_flag(*entry, flag_index);
            }
        }
    }

    Ok(())
}

/// Upgrades a phase0 state to altair's shape.
///
/// Transcribed from `specs/altair/fork.md`'s `upgrade_to_altair`. Fields
/// through `slashings` carry over unchanged; `previous_epoch_attestations`
/// and `current_epoch_attestations` have no altair counterpart and are
/// dropped, replaced by freshly zeroed participation flags one entry per
/// validator (never left empty, since every validator needs a flag byte from
/// the moment the fork activates); `inactivity_scores` is likewise zeroed at
/// one entry per validator, since inactivity leak accounting starts fresh
/// here. `fork` is rebuilt rather than carried over: its `previous_version`
/// becomes the pre-state's `current_version`, and `current_version` becomes
/// `config.altair_fork_version`, which is what makes this the fork boundary
/// rather than a same-fork slot advance.
pub fn upgrade_to_altair(
    pre: &phase0::BeaconState,
    config: &Config,
) -> Result<altair::BeaconState> {
    // Equivalent to the spec's `phase0.get_current_epoch(pre)`: computed
    // straight from `pre.slot` rather than through the `get_current_epoch`
    // accessor, which needs `&BeaconState` and so would otherwise force a
    // whole-state clone just to read one field of it.
    let epoch = compute_epoch_at_slot(pre.slot);
    let validator_count = pre.validators.len();

    let fork = Fork {
        previous_version: pre.fork.current_version,
        current_version: config.altair_fork_version,
        epoch,
    };

    // `SyncCommittee` has no `Default` impl (its `SszVector` field does not,
    // unlike `SszList`, since a vector can never be validly empty). This
    // placeholder exists only so the struct literal below type-checks before
    // the real committees, derived a few lines down from `post` itself, are
    // known. It is never observed: `get_next_sync_committee` reads
    // `validators`, `slot`, and `randao_mixes`, none of which are the sync
    // committee fields it is about to overwrite.
    let placeholder_sync_committee = altair::SyncCommittee {
        pubkeys: altair::SyncCommitteePubkeys::try_from(vec![
            BlsPubkey::default();
            preset::SYNC_COMMITTEE_SIZE
        ])?,
        aggregate_pubkey: BlsPubkey::default(),
    };

    let post = altair::BeaconState {
        genesis_time: pre.genesis_time,
        genesis_validators_root: pre.genesis_validators_root,
        slot: pre.slot,
        fork,
        latest_block_header: pre.latest_block_header.clone(),
        block_roots: pre.block_roots.clone(),
        state_roots: pre.state_roots.clone(),
        historical_roots: pre.historical_roots.clone(),
        eth1_data: pre.eth1_data.clone(),
        eth1_data_votes: pre.eth1_data_votes.clone(),
        eth1_deposit_index: pre.eth1_deposit_index,
        validators: pre.validators.clone(),
        balances: pre.balances.clone(),
        randao_mixes: pre.randao_mixes.clone(),
        slashings: pre.slashings.clone(),
        previous_epoch_participation: EpochParticipation::try_from(vec![0u8; validator_count])?,
        current_epoch_participation: EpochParticipation::try_from(vec![0u8; validator_count])?,
        justification_bits: pre.justification_bits.clone(),
        previous_justified_checkpoint: pre.previous_justified_checkpoint,
        current_justified_checkpoint: pre.current_justified_checkpoint,
        finalized_checkpoint: pre.finalized_checkpoint,
        inactivity_scores: InactivityScores::try_from(vec![0u64; validator_count])?,
        current_sync_committee: placeholder_sync_committee.clone(),
        next_sync_committee: placeholder_sync_committee,
    };
    let mut post = BeaconState::Altair(post);

    // Fill in previous epoch participation from the pre-state's pending
    // attestations, before the sync committees below: matches the spec's own
    // ordering, and neither step depends on the other's result.
    translate_participation(&mut post, &pre.previous_epoch_attestations)?;

    // Fill in sync committees. The specification calls `get_next_sync_committee`
    // twice rather than computing it once and cloning the result, and its own
    // comment says why: at the fork boundary there has been no sync-committee
    // period boundary yet, so the current and next committees are the *same*
    // committee by construction, not merely equal by coincidence. Calling
    // the function twice keeps that guarantee explicit rather than relying on
    // a clone to preserve it.
    let current_sync_committee = crate::helpers::altair::get_next_sync_committee(&post)?;
    let next_sync_committee = crate::helpers::altair::get_next_sync_committee(&post)?;

    let BeaconState::Altair(mut post) = post else {
        unreachable!("post was constructed as BeaconState::Altair immediately above")
    };
    post.current_sync_committee = current_sync_committee;
    post.next_sync_committee = next_sync_committee;

    Ok(post)
}

/// Applies the fork upgrade that produces `to`'s state shape from `state`.
///
/// Dispatches over the per-fork upgrade functions by [`ForkName`] so a caller
/// that only knows the target fork as a name, such as `process_slots`
/// crossing a fork boundary mid-loop, does not have to match on it itself.
/// Only the phase0-to-altair upgrade exists yet; later forks add an arm each
/// as their own upgrade function lands.
pub fn upgrade_state(state: &BeaconState, to: ForkName, config: &Config) -> Result<BeaconState> {
    match to {
        ForkName::Altair => {
            let pre = crate::stf::phase0_state_ref(state, "upgrade_state")?;
            Ok(BeaconState::Altair(upgrade_to_altair(pre, config)?))
        }
        _ => Err(Error::UnsupportedForFork {
            function: "upgrade_state",
            fork: to,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Extracts the phase0 state `with_validators` builds, for tests that need
    /// the concrete struct `upgrade_to_altair` takes rather than the enum.
    fn phase0_test_state(count: usize) -> phase0::BeaconState {
        match crate::helpers::test_state::with_validators(count) {
            BeaconState::Phase0(state) => state,
            _ => panic!("with_validators returns a phase0 state"),
        }
    }

    #[test]
    fn previous_version_carries_the_pre_states_current_version() {
        let mut pre = phase0_test_state(4);
        // `with_validators` leaves `fork` at its all-zero default, which would
        // make `previous_version == current_version` trivially true even if
        // the upgrade forgot to read `pre` at all. A distinct sentinel value
        // rules that out.
        pre.fork.current_version = [9, 9, 9, 9];

        let config = Config::mainnet();
        let post = upgrade_to_altair(&pre, &config).expect("upgrade succeeds");

        assert_eq!(post.fork.previous_version, [9, 9, 9, 9]);
        assert_eq!(post.fork.current_version, config.altair_fork_version);
    }

    #[test]
    fn participation_and_inactivity_lists_have_one_entry_per_validator() {
        let pre = phase0_test_state(7);
        let config = Config::mainnet();

        let post = upgrade_to_altair(&pre, &config).expect("upgrade succeeds");

        assert_eq!(
            post.previous_epoch_participation.len(),
            pre.validators.len()
        );
        assert_eq!(post.current_epoch_participation.len(), pre.validators.len());
        assert_eq!(post.inactivity_scores.len(), pre.validators.len());
    }
}
