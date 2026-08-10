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
use crate::constants;
use crate::containers::{
    BeaconState, EpochParticipation, Fork, InactivityScores, altair, bellatrix, capella, deneb,
    electra, fulu, phase0,
};
use crate::error::{Error, Result};
use crate::fork::ForkName;
use crate::helpers::attestation::get_attesting_indices;
use crate::helpers::misc::{compute_activation_exit_epoch, compute_epoch_at_slot};
use crate::preset;
use crate::primitives::{
    BlsPubkey, BlsSignature, Bytes32, ExecutionAddress, ExecutionBlockHash, Root, Uint256,
    ValidatorIndex,
};

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

// ---------------------------------------------------------------------------
// Fork-state projections
// ---------------------------------------------------------------------------
//
// `upgrade_to_altair` takes its pre-state as the concrete `phase0::BeaconState`
// because phase0 already has a crate-wide projection to reuse
// (`crate::stf::phase0_state_ref`). Every upgrade below instead takes
// `pre: &BeaconState`, the enum, and projects down to the concrete struct
// itself: `upgrade_state` calls every one of these through the same
// signature, and threading the enum through uniformly is what lets it
// dispatch on `to: ForkName` alone rather than also matching on `pre`'s own
// shape at each call site. Altair and fulu already have a crate-wide
// projection of their own to reuse (`crate::helpers::altair::altair_state_ref`,
// `crate::helpers::fulu::fulu_state_ref`); bellatrix, capella, deneb, and
// electra do not, so those four are projected locally here, on the same
// pattern `crate::stf::phase0_state`/`phase0_state_ref` set. None of the four
// needs a mutable counterpart: [`upgrade_to_electra`] is the one function
// here that mutates a post-state field-by-field rather than only building
// one, and the fields it reaches for that [`BeaconState`]'s own accessors do
// not cover (`exit_balance_to_consume`, `consolidation_balance_to_consume`,
// `pending_deposits`) already have a projection to reuse in
// `crate::helpers::electra` (`electra_state`, returning `ElectraOrFuluMut`),
// so this file does not need a second one of its own.

/// The bellatrix state, or an error naming the function that needs one.
fn bellatrix_state_ref<'a>(
    state: &'a BeaconState,
    function: &'static str,
) -> Result<&'a bellatrix::BeaconState> {
    match state {
        BeaconState::Bellatrix(state) => Ok(state),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

/// The capella state, or an error naming the function that needs one.
fn capella_state_ref<'a>(
    state: &'a BeaconState,
    function: &'static str,
) -> Result<&'a capella::BeaconState> {
    match state {
        BeaconState::Capella(state) => Ok(state),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

/// The deneb state, or an error naming the function that needs one.
fn deneb_state_ref<'a>(
    state: &'a BeaconState,
    function: &'static str,
) -> Result<&'a deneb::BeaconState> {
    match state {
        BeaconState::Deneb(state) => Ok(state),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

/// The electra state, or an error naming the function that needs one.
///
/// [`upgrade_to_fulu`]'s only use: fulu's pre-state is electra's shape.
/// [`upgrade_to_electra`] never needs this projection for its own `pre`
/// (that is [`deneb_state_ref`]'s job) or for reading back its freshly built
/// `post` (every read there goes through [`BeaconState`]'s fork-invariant
/// accessors or `crate::helpers::electra::electra_state`).
fn electra_state_ref<'a>(
    state: &'a BeaconState,
    function: &'static str,
) -> Result<&'a electra::BeaconState> {
    match state {
        BeaconState::Electra(state) => Ok(state),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Execution payload header helpers
// ---------------------------------------------------------------------------

/// An all-zero bellatrix execution payload header.
///
/// `specs/bellatrix/fork.md`'s `upgrade_to_bellatrix` writes this as the bare
/// constructor call `ExecutionPayloadHeader()`, meaning every field at its
/// type's default. That is not `#[derive(Default)]` here: `logs_bloom` is an
/// [`libssz_types::SszVector`], which the patched `libssz` this crate builds
/// against gives no `Default` impl (a vector, unlike a list, can never be
/// validly empty, so there is no such thing as *the* default one), so its
/// all-zero value is built explicitly at its exact length instead.
fn empty_bellatrix_execution_payload_header() -> Result<bellatrix::ExecutionPayloadHeader> {
    Ok(bellatrix::ExecutionPayloadHeader {
        parent_hash: ExecutionBlockHash::zero(),
        fee_recipient: ExecutionAddress::zero(),
        state_root: Bytes32::zero(),
        receipts_root: Bytes32::zero(),
        logs_bloom: bellatrix::LogsBloom::try_from(vec![0u8; preset::BYTES_PER_LOGS_BLOOM])?,
        prev_randao: Bytes32::zero(),
        block_number: 0,
        gas_limit: 0,
        gas_used: 0,
        timestamp: 0,
        extra_data: bellatrix::ExtraData::default(),
        base_fee_per_gas: Uint256::zero(),
        block_hash: ExecutionBlockHash::zero(),
        transactions_root: Root::zero(),
    })
}

/// Upgrades an altair state to bellatrix's shape.
///
/// Transcribed from `specs/bellatrix/fork.md`'s `upgrade_to_bellatrix`. Every
/// field through `next_sync_committee` carries over unchanged: bellatrix (the
/// Merge) changes no field altair already had. It adds exactly one,
/// `latest_execution_payload_header`, and that one starts as the all-zero
/// [`empty_bellatrix_execution_payload_header`] rather than anything copied
/// from `pre`: proof-of-work blocks were never beacon-chain execution
/// payloads, so there is no earlier payload for this field to summarize until
/// the first post-Merge block supplies one.
pub fn upgrade_to_bellatrix(pre: &BeaconState, config: &Config) -> Result<BeaconState> {
    let pre = crate::helpers::altair::altair_state_ref(pre, "upgrade_to_bellatrix")?;
    let epoch = compute_epoch_at_slot(pre.slot);

    let fork = Fork {
        previous_version: pre.fork.current_version,
        current_version: config.bellatrix_fork_version,
        epoch,
    };

    let post = bellatrix::BeaconState {
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
        previous_epoch_participation: pre.previous_epoch_participation.clone(),
        current_epoch_participation: pre.current_epoch_participation.clone(),
        justification_bits: pre.justification_bits.clone(),
        previous_justified_checkpoint: pre.previous_justified_checkpoint,
        current_justified_checkpoint: pre.current_justified_checkpoint,
        finalized_checkpoint: pre.finalized_checkpoint,
        inactivity_scores: pre.inactivity_scores.clone(),
        current_sync_committee: pre.current_sync_committee.clone(),
        next_sync_committee: pre.next_sync_committee.clone(),
        // [New in Bellatrix]
        latest_execution_payload_header: empty_bellatrix_execution_payload_header()?,
    };

    Ok(BeaconState::Bellatrix(post))
}

/// Upgrades a bellatrix state to capella's shape.
///
/// Transcribed from `specs/capella/fork.md`'s `upgrade_to_capella`. Every
/// field through `next_sync_committee` carries over unchanged, including
/// `historical_roots`: the specification copies it as-is rather than
/// truncating it. Freezing it in place (never appended to again, from this
/// fork on) is capella's actual change to it; `historical_summaries` (added
/// below) is where new history accumulates instead, which is why the two
/// coexist rather than one replacing the other outright.
///
/// `latest_execution_payload_header` keeps its name and position but is
/// rebuilt as capella's own container, carrying every one of bellatrix's
/// header fields across individually and appending an empty
/// `withdrawals_root`: withdrawals are capella's new operation, so there is
/// no earlier payload's withdrawal root for this field to summarize yet, the
/// same reasoning [`upgrade_to_bellatrix`] applies to its own brand new
/// field. `next_withdrawal_index`, `next_withdrawal_validator_index`, and
/// `historical_summaries` are capella's other three additions, all starting
/// at their type's zero: the withdrawal sweep and the history it accumulates
/// both begin only once this fork is active.
pub fn upgrade_to_capella(pre: &BeaconState, config: &Config) -> Result<BeaconState> {
    let pre = bellatrix_state_ref(pre, "upgrade_to_capella")?;
    let epoch = compute_epoch_at_slot(pre.slot);

    let fork = Fork {
        previous_version: pre.fork.current_version,
        current_version: config.capella_fork_version,
        epoch,
    };

    let execution_header = &pre.latest_execution_payload_header;
    let latest_execution_payload_header = capella::ExecutionPayloadHeader {
        parent_hash: execution_header.parent_hash,
        fee_recipient: execution_header.fee_recipient,
        state_root: execution_header.state_root,
        receipts_root: execution_header.receipts_root,
        logs_bloom: execution_header.logs_bloom.clone(),
        prev_randao: execution_header.prev_randao,
        block_number: execution_header.block_number,
        gas_limit: execution_header.gas_limit,
        gas_used: execution_header.gas_used,
        timestamp: execution_header.timestamp,
        extra_data: execution_header.extra_data.clone(),
        base_fee_per_gas: execution_header.base_fee_per_gas,
        block_hash: execution_header.block_hash,
        transactions_root: execution_header.transactions_root,
        // [New in Capella]
        withdrawals_root: Root::zero(),
    };

    let post = capella::BeaconState {
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
        previous_epoch_participation: pre.previous_epoch_participation.clone(),
        current_epoch_participation: pre.current_epoch_participation.clone(),
        justification_bits: pre.justification_bits.clone(),
        previous_justified_checkpoint: pre.previous_justified_checkpoint,
        current_justified_checkpoint: pre.current_justified_checkpoint,
        finalized_checkpoint: pre.finalized_checkpoint,
        inactivity_scores: pre.inactivity_scores.clone(),
        current_sync_committee: pre.current_sync_committee.clone(),
        next_sync_committee: pre.next_sync_committee.clone(),
        latest_execution_payload_header,
        // [New in Capella]
        next_withdrawal_index: 0,
        // [New in Capella]
        next_withdrawal_validator_index: 0,
        // [New in Capella]
        historical_summaries: Default::default(),
    };

    Ok(BeaconState::Capella(post))
}

/// Upgrades a capella state to deneb's shape.
///
/// Transcribed from `specs/deneb/fork.md`'s `upgrade_to_deneb`. The state's
/// field count does not change: every field through `historical_summaries`
/// carries over unchanged, and the only reshaping is
/// `latest_execution_payload_header`, rebuilt as deneb's own container with
/// every one of capella's header fields (now including `withdrawals_root`)
/// carried across individually, plus `blob_gas_used` and `excess_blob_gas`
/// starting at zero: deneb's blob fee market has no history to inherit
/// either, the same reasoning [`upgrade_to_bellatrix`] and
/// [`upgrade_to_capella`] apply to their own brand new fields.
pub fn upgrade_to_deneb(pre: &BeaconState, config: &Config) -> Result<BeaconState> {
    let pre = capella_state_ref(pre, "upgrade_to_deneb")?;
    let epoch = compute_epoch_at_slot(pre.slot);

    let fork = Fork {
        previous_version: pre.fork.current_version,
        current_version: config.deneb_fork_version,
        epoch,
    };

    let execution_header = &pre.latest_execution_payload_header;
    let latest_execution_payload_header = deneb::ExecutionPayloadHeader {
        parent_hash: execution_header.parent_hash,
        fee_recipient: execution_header.fee_recipient,
        state_root: execution_header.state_root,
        receipts_root: execution_header.receipts_root,
        logs_bloom: execution_header.logs_bloom.clone(),
        prev_randao: execution_header.prev_randao,
        block_number: execution_header.block_number,
        gas_limit: execution_header.gas_limit,
        gas_used: execution_header.gas_used,
        timestamp: execution_header.timestamp,
        extra_data: execution_header.extra_data.clone(),
        base_fee_per_gas: execution_header.base_fee_per_gas,
        block_hash: execution_header.block_hash,
        transactions_root: execution_header.transactions_root,
        withdrawals_root: execution_header.withdrawals_root,
        // [New in Deneb:EIP4844]
        blob_gas_used: 0,
        // [New in Deneb:EIP4844]
        excess_blob_gas: 0,
    };

    let post = deneb::BeaconState {
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
        previous_epoch_participation: pre.previous_epoch_participation.clone(),
        current_epoch_participation: pre.current_epoch_participation.clone(),
        justification_bits: pre.justification_bits.clone(),
        previous_justified_checkpoint: pre.previous_justified_checkpoint,
        current_justified_checkpoint: pre.current_justified_checkpoint,
        finalized_checkpoint: pre.finalized_checkpoint,
        inactivity_scores: pre.inactivity_scores.clone(),
        current_sync_committee: pre.current_sync_committee.clone(),
        next_sync_committee: pre.next_sync_committee.clone(),
        latest_execution_payload_header,
        next_withdrawal_index: pre.next_withdrawal_index,
        next_withdrawal_validator_index: pre.next_withdrawal_validator_index,
        historical_summaries: pre.historical_summaries.clone(),
    };

    Ok(BeaconState::Deneb(post))
}

/// Upgrades a deneb state to electra's shape.
///
/// Transcribed from `specs/electra/fork.md`'s `upgrade_to_electra`. Fields
/// through `historical_summaries` carry over unchanged; the nine electra
/// appends need more than a copy, because EIP-7251 changes what "how much
/// stake may enter or leave the validator set this epoch" even means.
///
/// Before electra, activation and exit churn is a *count* of validators:
/// every validator activates at the same effective balance, so bounding how
/// many validators move per epoch bounds how much stake moves too. EIP-7251
/// lets a validator's effective balance grow past that floor (given a
/// compounding withdrawal credential), which breaks the equivalence: one
/// large validator activating could move as much stake as thousands of
/// ordinary ones, so the churn limit has to be denominated in balance
/// instead. Electra cannot apply that retroactively: a validator already
/// active before this fork was admitted under the old count-based
/// accounting, which kept no record of how much of its stake that admitted.
/// Two migrations below are what electra does instead of pretending
/// otherwise:
///
/// - A validator not yet active (`activation_epoch` still
///   [`constants::FAR_FUTURE_EPOCH`]) has its whole balance zeroed and
///   reinstated as a synthetic [`electra::PendingDeposit`], via
///   [`crate::helpers::electra::queue_entire_balance_and_reset_validator`],
///   so it re-enters through the queue the balance-based churn limit
///   actually governs, instead of activating under rules that no longer
///   exist.
/// - A validator that already upgraded to a compounding withdrawal
///   credential, and so is already sitting above
///   [`preset::MIN_ACTIVATION_BALANCE`], has that excess queued the same way
///   by [`crate::helpers::electra::queue_excess_active_balance`]: the
///   balance is real and already credited, but the count-based accounting
///   that admitted it never subjected it to any churn limit at all, so it
///   has to pass through the new one now, after the fact, rather than being
///   grandfathered in as if it already had.
///
/// The two churn fields this upgrade sets, `exit_balance_to_consume` and
/// `consolidation_balance_to_consume`, are computed by calling
/// [`crate::helpers::electra::get_activation_exit_churn_limit`] and
/// [`crate::helpers::electra::get_consolidation_churn_limit`] on `post`
/// itself, after every fork-invariant field (crucially, `validators` and
/// `balances`) has already been copied across from `pre`, not on `pre`
/// directly. The specification's own pseudocode does this too, for a reason
/// invisible from the field values alone: those two helpers read through
/// `&BeaconState`, matching against the electra variant internally, so they
/// cannot run at all until the state they are reading exists as
/// `BeaconState::Electra` rather than still being `pre`'s
/// `deneb::BeaconState`. Numerically the two states agree at this exact
/// point (the validator-and-balance migrations below have not run yet), but
/// the ordering the specification chose is load-bearing for a different
/// reason than the numbers: it is the earliest point at which a value of the
/// right *type* exists to call them with.
///
/// [`crate::helpers::electra::switch_to_compounding_validator`] is not
/// called here: the specification calls it from a validator's own
/// credential-switch request, not from this fork boundary.
pub fn upgrade_to_electra(pre: &BeaconState, config: &Config) -> Result<BeaconState> {
    let pre = deneb_state_ref(pre, "upgrade_to_electra")?;
    // Reused for every one of the specification's own repeated
    // `get_current_epoch(pre)` calls below: `pre` is never mutated between
    // them, so recomputing it each time would just recompute this same
    // value.
    let epoch = compute_epoch_at_slot(pre.slot);

    let fork = Fork {
        previous_version: pre.fork.current_version,
        current_version: config.electra_fork_version,
        epoch,
    };

    let mut earliest_exit_epoch = compute_activation_exit_epoch(epoch);
    for validator in pre.validators.iter() {
        if validator.exit_epoch != constants::FAR_FUTURE_EPOCH
            && validator.exit_epoch > earliest_exit_epoch
        {
            earliest_exit_epoch = validator.exit_epoch;
        }
    }
    earliest_exit_epoch = earliest_exit_epoch
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("earliest_exit_epoch + 1"))?;

    let post = electra::BeaconState {
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
        previous_epoch_participation: pre.previous_epoch_participation.clone(),
        current_epoch_participation: pre.current_epoch_participation.clone(),
        justification_bits: pre.justification_bits.clone(),
        previous_justified_checkpoint: pre.previous_justified_checkpoint,
        current_justified_checkpoint: pre.current_justified_checkpoint,
        finalized_checkpoint: pre.finalized_checkpoint,
        inactivity_scores: pre.inactivity_scores.clone(),
        current_sync_committee: pre.current_sync_committee.clone(),
        next_sync_committee: pre.next_sync_committee.clone(),
        latest_execution_payload_header: pre.latest_execution_payload_header.clone(),
        next_withdrawal_index: pre.next_withdrawal_index,
        next_withdrawal_validator_index: pre.next_withdrawal_validator_index,
        historical_summaries: pre.historical_summaries.clone(),
        // [New in Electra:EIP6110]
        deposit_requests_start_index: constants::UNSET_DEPOSIT_REQUESTS_START_INDEX,
        // [New in Electra:EIP7251] Never overwritten: unlike the two fields
        // below, the specification has no post-construction assignment for
        // this one.
        deposit_balance_to_consume: 0,
        // [New in Electra:EIP7251] Overwritten below, once `post` exists as
        // an electra state; see this function's own doc for why that
        // ordering is load-bearing.
        exit_balance_to_consume: 0,
        // [New in Electra:EIP7251]
        earliest_exit_epoch,
        // [New in Electra:EIP7251] Overwritten below; see
        // `exit_balance_to_consume` above.
        consolidation_balance_to_consume: 0,
        // [New in Electra:EIP7251]
        earliest_consolidation_epoch: compute_activation_exit_epoch(epoch),
        // [New in Electra:EIP7251]
        pending_deposits: Default::default(),
        // [New in Electra:EIP7251]
        pending_partial_withdrawals: Default::default(),
        // [New in Electra:EIP7251]
        pending_consolidations: Default::default(),
    };
    let mut post = BeaconState::Electra(post);

    // Churn is computed from `post`, not `pre`: see this function's own doc
    // for why the ordering is load-bearing even though the two states still
    // agree numerically at this point.
    let exit_balance_to_consume =
        crate::helpers::electra::get_activation_exit_churn_limit(&post, config)?;
    let consolidation_balance_to_consume =
        crate::helpers::electra::get_consolidation_churn_limit(&post, config)?;
    {
        let mut fields = crate::helpers::electra::electra_state(&mut post, "upgrade_to_electra")?;
        *fields.exit_balance_to_consume_mut() = exit_balance_to_consume;
        *fields.consolidation_balance_to_consume_mut() = consolidation_balance_to_consume;
    }

    // Add validators that are not yet active to the pending deposit queue:
    // see this function's own doc for why a not-yet-active validator cannot
    // simply keep activating under rules the state no longer tracks. Sorted
    // by `(activation_eligibility_epoch, index)`, matching the
    // specification's own tie-break exactly.
    let mut pre_activation: Vec<ValidatorIndex> = post
        .validators()
        .iter()
        .enumerate()
        .filter(|(_, validator)| validator.activation_epoch == constants::FAR_FUTURE_EPOCH)
        .map(|(index, _)| index as ValidatorIndex)
        .collect();
    pre_activation.sort_by_key(|&index| {
        let eligibility_epoch = post
            .validator(index)
            .expect("index was read from post.validators() above")
            .activation_eligibility_epoch;
        (eligibility_epoch, index)
    });
    for index in pre_activation {
        crate::helpers::electra::queue_entire_balance_and_reset_validator(&mut post, index)?;
    }

    // Ensure early adopters of a compounding withdrawal credential go
    // through the same activation churn: a fresh pass over every validator
    // (including the ones the loop above already zeroed, matching the
    // specification's own unconditional second loop) rather than folded into
    // it, since compounding eligibility and pre-activation are independent
    // conditions on the same registry.
    let compounding_indices: Vec<ValidatorIndex> = post
        .validators()
        .iter()
        .enumerate()
        .filter(|(_, validator)| {
            crate::helpers::electra::has_compounding_withdrawal_credential(validator)
        })
        .map(|(index, _)| index as ValidatorIndex)
        .collect();
    for index in compounding_indices {
        crate::helpers::electra::queue_excess_active_balance(&mut post, index)?;
    }

    Ok(post)
}

/// Upgrades an electra state to fulu's shape.
///
/// Transcribed from `specs/fulu/fork.md`'s `upgrade_to_fulu`. Every field
/// through `pending_consolidations` carries over unchanged; the one addition
/// is `proposer_lookahead`, filled by
/// [`crate::helpers::fulu::initialize_proposer_lookahead`] rather than left
/// empty, since [`crate::helpers::fulu::get_beacon_proposer_index`] reads it
/// as a lookup from the moment this fork activates and has no on-demand
/// fallback to compute it from if it were left blank (see that module's own
/// docs for why the two coexist rather than one calling the other).
///
/// [`initialize_proposer_lookahead`](crate::helpers::fulu::initialize_proposer_lookahead)
/// is called on `pre` while it is still electra's shape, one statement before
/// a `proposer_lookahead` field exists anywhere in `post` to write into: it
/// reads through fork-invariant accessors only, never a fulu-only field, so
/// there is nothing circular about calling it on a pre-fulu state.
pub fn upgrade_to_fulu(pre: &BeaconState, config: &Config) -> Result<BeaconState> {
    let pre_state = electra_state_ref(pre, "upgrade_to_fulu")?;
    let epoch = compute_epoch_at_slot(pre_state.slot);

    let fork = Fork {
        previous_version: pre_state.fork.current_version,
        current_version: config.fulu_fork_version,
        epoch,
    };

    // Called on the original enum-typed `pre`, not `pre_state`: see this
    // function's own doc for why that is safe one statement before `post`'s
    // `proposer_lookahead` field exists.
    let proposer_lookahead = crate::helpers::fulu::initialize_proposer_lookahead(pre)?;

    let post = fulu::BeaconState {
        genesis_time: pre_state.genesis_time,
        genesis_validators_root: pre_state.genesis_validators_root,
        slot: pre_state.slot,
        fork,
        latest_block_header: pre_state.latest_block_header.clone(),
        block_roots: pre_state.block_roots.clone(),
        state_roots: pre_state.state_roots.clone(),
        historical_roots: pre_state.historical_roots.clone(),
        eth1_data: pre_state.eth1_data.clone(),
        eth1_data_votes: pre_state.eth1_data_votes.clone(),
        eth1_deposit_index: pre_state.eth1_deposit_index,
        validators: pre_state.validators.clone(),
        balances: pre_state.balances.clone(),
        randao_mixes: pre_state.randao_mixes.clone(),
        slashings: pre_state.slashings.clone(),
        previous_epoch_participation: pre_state.previous_epoch_participation.clone(),
        current_epoch_participation: pre_state.current_epoch_participation.clone(),
        justification_bits: pre_state.justification_bits.clone(),
        previous_justified_checkpoint: pre_state.previous_justified_checkpoint,
        current_justified_checkpoint: pre_state.current_justified_checkpoint,
        finalized_checkpoint: pre_state.finalized_checkpoint,
        inactivity_scores: pre_state.inactivity_scores.clone(),
        current_sync_committee: pre_state.current_sync_committee.clone(),
        next_sync_committee: pre_state.next_sync_committee.clone(),
        latest_execution_payload_header: pre_state.latest_execution_payload_header.clone(),
        next_withdrawal_index: pre_state.next_withdrawal_index,
        next_withdrawal_validator_index: pre_state.next_withdrawal_validator_index,
        historical_summaries: pre_state.historical_summaries.clone(),
        deposit_requests_start_index: pre_state.deposit_requests_start_index,
        deposit_balance_to_consume: pre_state.deposit_balance_to_consume,
        exit_balance_to_consume: pre_state.exit_balance_to_consume,
        earliest_exit_epoch: pre_state.earliest_exit_epoch,
        consolidation_balance_to_consume: pre_state.consolidation_balance_to_consume,
        earliest_consolidation_epoch: pre_state.earliest_consolidation_epoch,
        pending_deposits: pre_state.pending_deposits.clone(),
        pending_partial_withdrawals: pre_state.pending_partial_withdrawals.clone(),
        pending_consolidations: pre_state.pending_consolidations.clone(),
        // [New in Fulu:EIP7917]
        proposer_lookahead: proposer_lookahead.try_into()?,
    };

    Ok(BeaconState::Fulu(post))
}

/// Applies the fork upgrade that produces `to`'s state shape from `state`.
///
/// Dispatches over the per-fork upgrade functions by [`ForkName`] so a caller
/// that only knows the target fork as a name, such as `process_slots`
/// crossing a fork boundary mid-loop, does not have to match on it itself.
///
/// Rejects any `to` whose upgrade does not apply to `state`'s current shape,
/// which covers both ways a caller could misuse this: skipping a fork (asking
/// for capella's shape from a still-altair state, say) and going backwards
/// (asking for bellatrix's shape from a state already past it). Neither needs
/// a check here: every `upgrade_to_<fork>` function already requires its
/// specific predecessor's shape (via its own fork-state projection), so a
/// mismatched `to` fails inside whichever function this dispatches to, with
/// the same [`Error::UnsupportedForFork`] any other fork-mismatched call in
/// this crate produces.
pub fn upgrade_state(state: &BeaconState, to: ForkName, config: &Config) -> Result<BeaconState> {
    match to {
        ForkName::Phase0 => Err(Error::UnsupportedForFork {
            function: "upgrade_state",
            fork: to,
        }),
        ForkName::Altair => {
            let pre = crate::stf::phase0_state_ref(state, "upgrade_state")?;
            Ok(BeaconState::Altair(upgrade_to_altair(pre, config)?))
        }
        ForkName::Bellatrix => upgrade_to_bellatrix(state, config),
        ForkName::Capella => upgrade_to_capella(state, config),
        ForkName::Deneb => upgrade_to_deneb(state, config),
        ForkName::Electra => upgrade_to_electra(state, config),
        ForkName::Fulu => upgrade_to_fulu(state, config),
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

    /// Advances a fresh phase0 test state through every upgrade up to and
    /// including `to`, via [`upgrade_state`] itself.
    ///
    /// Chaining the real upgrade functions rather than hand-writing a struct
    /// literal for each fork keeps every fixture below a state some upgrade
    /// function in this file actually produced, which is exactly the kind of
    /// input the function under test in each case below is checked against.
    fn advance_to(to: ForkName, count: usize) -> (BeaconState, Config) {
        let config = Config::mainnet();
        let mut state = crate::helpers::test_state::with_validators(count);
        for fork in ForkName::ALL.into_iter().skip(1) {
            state = upgrade_state(&state, fork, &config).expect("upgrade succeeds");
            if fork == to {
                break;
            }
        }
        (state, config)
    }

    #[test]
    fn bellatrix_carries_altairs_fields_and_starts_an_empty_payload_header() {
        let (altair_state, config) = advance_to(ForkName::Altair, 4);
        let BeaconState::Altair(altair_state) = altair_state else {
            panic!("advance_to(Altair) returns an altair state");
        };

        let post = upgrade_to_bellatrix(&BeaconState::Altair(altair_state.clone()), &config)
            .expect("upgrade succeeds");
        let BeaconState::Bellatrix(post) = post else {
            panic!("upgrade_to_bellatrix returns a bellatrix state");
        };

        assert_eq!(
            post.fork.previous_version,
            altair_state.fork.current_version
        );
        assert_eq!(post.fork.current_version, config.bellatrix_fork_version);
        assert_eq!(post.validators.len(), altair_state.validators.len());
        assert_eq!(post.genesis_time, altair_state.genesis_time);
        assert_eq!(post.latest_execution_payload_header.block_number, 0);
        assert!(post.latest_execution_payload_header.block_hash.is_zero());
    }

    #[test]
    fn bellatrix_rejects_a_state_that_skipped_altair() {
        let phase0_state = crate::helpers::test_state::with_validators(4);
        let config = Config::mainnet();
        assert!(upgrade_to_bellatrix(&phase0_state, &config).is_err());
    }

    #[test]
    fn capella_carries_the_execution_header_across_and_leaves_historical_roots_alone() {
        let (bellatrix_state, config) = advance_to(ForkName::Bellatrix, 4);
        let BeaconState::Bellatrix(mut bellatrix_state) = bellatrix_state else {
            panic!("advance_to(Bellatrix) returns a bellatrix state");
        };
        // A field genuinely carried across, distinguishable from the header's
        // otherwise all-zero starting value.
        bellatrix_state.latest_execution_payload_header.block_number = 42;
        bellatrix_state
            .historical_roots
            .push(crate::primitives::Root::repeat_byte(7))
            .expect("well below HISTORICAL_ROOTS_LIMIT");

        let post = upgrade_to_capella(&BeaconState::Bellatrix(bellatrix_state.clone()), &config)
            .expect("upgrade succeeds");
        let BeaconState::Capella(post) = post else {
            panic!("upgrade_to_capella returns a capella state");
        };

        assert_eq!(post.fork.current_version, config.capella_fork_version);
        assert_eq!(post.latest_execution_payload_header.block_number, 42);
        assert!(
            post.latest_execution_payload_header
                .withdrawals_root
                .is_zero()
        );
        // Left alone, not truncated: capella freezes `historical_roots` in
        // place rather than clearing it, since `historical_summaries` is
        // where new history accumulates from here on.
        assert_eq!(
            post.historical_roots.into_inner(),
            bellatrix_state.historical_roots.into_inner()
        );
        assert_eq!(post.next_withdrawal_index, 0);
        assert_eq!(post.next_withdrawal_validator_index, 0);
        assert!(post.historical_summaries.is_empty());
    }

    #[test]
    fn capella_rejects_a_state_that_skipped_bellatrix() {
        let (altair_state, config) = advance_to(ForkName::Altair, 4);
        assert!(upgrade_to_capella(&altair_state, &config).is_err());
    }

    #[test]
    fn deneb_gains_blob_gas_fields_at_zero_and_carries_withdrawals_root() {
        let (capella_state, config) = advance_to(ForkName::Capella, 4);
        let BeaconState::Capella(mut capella_state) = capella_state else {
            panic!("advance_to(Capella) returns a capella state");
        };
        capella_state
            .latest_execution_payload_header
            .withdrawals_root = crate::primitives::Root::repeat_byte(3);
        capella_state.next_withdrawal_index = 5;

        let post = upgrade_to_deneb(&BeaconState::Capella(capella_state.clone()), &config)
            .expect("upgrade succeeds");
        let BeaconState::Deneb(post) = post else {
            panic!("upgrade_to_deneb returns a deneb state");
        };

        assert_eq!(post.fork.current_version, config.deneb_fork_version);
        assert_eq!(post.latest_execution_payload_header.blob_gas_used, 0);
        assert_eq!(post.latest_execution_payload_header.excess_blob_gas, 0);
        assert_eq!(
            post.latest_execution_payload_header.withdrawals_root,
            capella_state
                .latest_execution_payload_header
                .withdrawals_root
        );
        // The state's own field count does not change at this fork: only
        // `latest_execution_payload_header`'s shape does.
        assert_eq!(
            post.next_withdrawal_index,
            capella_state.next_withdrawal_index
        );
    }

    #[test]
    fn deneb_rejects_a_state_that_skipped_capella() {
        let (bellatrix_state, config) = advance_to(ForkName::Bellatrix, 4);
        assert!(upgrade_to_deneb(&bellatrix_state, &config).is_err());
    }

    #[test]
    fn upgrade_state_rejects_phase0_as_a_target() {
        let phase0_state = crate::helpers::test_state::with_validators(4);
        let config = Config::mainnet();
        assert!(upgrade_state(&phase0_state, ForkName::Phase0, &config).is_err());
    }

    #[test]
    fn upgrade_state_rejects_going_backwards() {
        let (deneb_state, config) = advance_to(ForkName::Deneb, 4);
        // `deneb_state` is already past bellatrix; asking to upgrade it *to*
        // bellatrix is a backwards move, and must fail the same way skipping
        // a fork does.
        assert!(upgrade_state(&deneb_state, ForkName::Bellatrix, &config).is_err());
    }

    #[test]
    fn electra_sets_the_fork_version_and_deposit_requests_sentinel() {
        let (deneb_state, config) = advance_to(ForkName::Deneb, 4);
        let post = upgrade_to_electra(&deneb_state, &config).expect("upgrade succeeds");
        let BeaconState::Electra(post) = post else {
            panic!("upgrade_to_electra returns an electra state");
        };

        assert_eq!(post.fork.current_version, config.electra_fork_version);
        assert_eq!(
            post.deposit_requests_start_index,
            constants::UNSET_DEPOSIT_REQUESTS_START_INDEX
        );
        // Never overwritten by this upgrade; see its own doc.
        assert_eq!(post.deposit_balance_to_consume, 0);
    }

    #[test]
    fn electra_earliest_exit_epoch_tracks_the_largest_pending_exit() {
        let (deneb_state, config) = advance_to(ForkName::Deneb, 4);
        let BeaconState::Deneb(mut deneb_state) = deneb_state else {
            panic!("advance_to(Deneb) returns a deneb state");
        };
        let epoch = compute_epoch_at_slot(deneb_state.slot);
        let default_earliest_exit_epoch = compute_activation_exit_epoch(epoch);
        // Comfortably past the default, so the scan over `pre.validators`
        // below is what has to produce this value, not the epoch-only
        // fallback every other validator would leave it at.
        let sentinel_exit_epoch = default_earliest_exit_epoch + 100;
        deneb_state.validators[0].exit_epoch = sentinel_exit_epoch;

        let post = upgrade_to_electra(&BeaconState::Deneb(deneb_state), &config)
            .expect("upgrade succeeds");
        let BeaconState::Electra(post) = post else {
            panic!("upgrade_to_electra returns an electra state");
        };

        assert_eq!(post.earliest_exit_epoch, sentinel_exit_epoch + 1);
    }

    #[test]
    fn electra_migrates_a_not_yet_active_validator_into_pending_deposits() {
        let (deneb_state, config) = advance_to(ForkName::Deneb, 4);
        let BeaconState::Deneb(mut deneb_state) = deneb_state else {
            panic!("advance_to(Deneb) returns a deneb state");
        };
        let migrated_pubkey = deneb_state.validators[0].pubkey;
        let migrated_credentials = deneb_state.validators[0].withdrawal_credentials;
        deneb_state.validators[0].activation_epoch = constants::FAR_FUTURE_EPOCH;
        deneb_state.balances[0] = 1_000_000_000;

        let post = upgrade_to_electra(&BeaconState::Deneb(deneb_state), &config)
            .expect("upgrade succeeds");
        let BeaconState::Electra(post) = post else {
            panic!("upgrade_to_electra returns an electra state");
        };

        assert_eq!(post.balances[0], 0);
        assert_eq!(post.validators[0].effective_balance, 0);
        assert_eq!(
            post.validators[0].activation_eligibility_epoch,
            constants::FAR_FUTURE_EPOCH
        );
        assert_eq!(post.pending_deposits.len(), 1);
        let deposit = &post.pending_deposits[0];
        assert_eq!(deposit.amount, 1_000_000_000);
        assert_eq!(deposit.pubkey, migrated_pubkey);
        assert_eq!(deposit.withdrawal_credentials, migrated_credentials);
    }

    #[test]
    fn electra_churn_fields_are_populated_from_the_post_state() {
        let (deneb_state, config) = advance_to(ForkName::Deneb, 4);
        let post = upgrade_to_electra(&deneb_state, &config).expect("upgrade succeeds");
        let BeaconState::Electra(electra_post) = &post else {
            panic!("upgrade_to_electra returns an electra state");
        };

        // None of `advance_to`'s validators are pre-activation or
        // compounding, so both migrations below ran as no-ops and total
        // active balance is unchanged from the moment churn was computed:
        // recomputing the churn limits against the finished state must
        // reproduce exactly what `upgrade_to_electra` already stored, which
        // is what proves the two calls were actually wired in rather than
        // leaving the fields at their zero placeholder.
        let expected_exit_churn =
            crate::helpers::electra::get_activation_exit_churn_limit(&post, &config).unwrap();
        let expected_consolidation_churn =
            crate::helpers::electra::get_consolidation_churn_limit(&post, &config).unwrap();

        assert_eq!(electra_post.exit_balance_to_consume, expected_exit_churn);
        assert_eq!(
            electra_post.consolidation_balance_to_consume,
            expected_consolidation_churn
        );
        assert!(expected_exit_churn > 0);
    }

    #[test]
    fn electra_rejects_a_state_that_skipped_deneb() {
        let (capella_state, config) = advance_to(ForkName::Capella, 4);
        assert!(upgrade_to_electra(&capella_state, &config).is_err());
    }

    #[test]
    fn fulu_proposer_lookahead_matches_initialize_proposer_lookahead() {
        let (electra_state, config) = advance_to(ForkName::Electra, 4);
        let post = upgrade_to_fulu(&electra_state, &config).expect("upgrade succeeds");
        let BeaconState::Fulu(post) = post else {
            panic!("upgrade_to_fulu returns a fulu state");
        };

        let expected = crate::helpers::fulu::initialize_proposer_lookahead(&electra_state)
            .expect("initialize_proposer_lookahead succeeds");
        assert_eq!(post.proposer_lookahead.into_inner(), expected);
        assert_eq!(post.fork.current_version, config.fulu_fork_version);
    }

    #[test]
    fn fulu_rejects_a_state_that_skipped_electra() {
        let (deneb_state, config) = advance_to(ForkName::Deneb, 4);
        assert!(upgrade_to_fulu(&deneb_state, &config).is_err());
    }

    #[test]
    fn upgrade_state_walks_every_fork_boundary_end_to_end() {
        // A cheap integration check on top of the per-function tests above:
        // `advance_to` already exercises every arm of `upgrade_state`, so
        // reaching fulu without an error proves the whole dispatch chain
        // (not just each function in isolation) is wired correctly.
        let (fulu_state, _config) = advance_to(ForkName::Fulu, 4);
        assert_eq!(fulu_state.fork_name(), ForkName::Fulu);
    }
}
