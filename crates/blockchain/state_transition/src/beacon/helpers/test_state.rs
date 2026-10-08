//! A minimal state builder shared by the helper tests.
//!
//! Several helpers can only be exercised against a state with a populated
//! validator registry and correctly sized history vectors, and building one by
//! hand in each test would bury the assertion under setup. Test-only: compiled
//! for this crate's tests, and for other crates' tests through the `test-utils`
//! feature (the Beacon API's endpoints need a real registry too); nothing in the
//! crate's public surface depends on it.
//!
//! [`with_validators`] builds a phase0 state; [`with_validators_at`]
//! generalises it to every other fork. Each fork used to grow its own
//! near-duplicate of the same struct literal, one per test module that first
//! needed a state in that fork's shape: `crate::beacon::helpers::altair`,
//! `crate::beacon::stf::bellatrix`, `crate::beacon::stf::capella` and
//! `crate::beacon::stf::epoch::capella` (identical to each other),
//! `crate::beacon::stf::epoch::registry`, `crate::beacon::helpers::electra` (which grew two,
//! electra's and a fulu one) and `crate::beacon::stf::epoch::electra` (identical to
//! `helpers::electra`'s electra one), and `crate::beacon::stf::fulu`,
//! `crate::beacon::helpers::fulu`, and `crate::beacon::stf::epoch::fulu` (the latter two
//! identical to each other). This module is now the one place that shape is
//! built; a caller whose test needs something beyond the default (a
//! caller-supplied execution payload header, real BLS pubkeys, a state
//! positioned many epochs past genesis) builds the default here and then
//! applies its own small, documented override, the same way it would change
//! any other already-built state's field.

use crate::beacon::constants;
use crate::beacon::containers::shared::{
    Balances, EpochParticipation, InactivityScores, Validator,
};
use crate::beacon::containers::{
    BeaconState, BlockRoots, RandaoMixes, Slashings, altair, bellatrix, capella, deneb, electra,
    fulu, phase0,
};
use crate::beacon::fork::ForkName;
use crate::beacon::lean_fork_unreachable;
use crate::beacon::preset;
use crate::beacon::primitives::{
    BlsPubkey, BlsSignature, Bytes32, ExecutionAddress, ExecutionBlockHash, Gwei, Root, Uint256,
};

/// A deterministic but genuinely valid BLS public key for validator `index`.
///
/// A zero pubkey is not a curve point, so anything that aggregates or validates
/// keys rejects it. That makes the all-default validator unusable for the sync
/// committee, which aggregates its members' keys, and it would silently limit
/// every later fork's tests in the same way. Deriving a real key from the index
/// keeps the state reproducible while letting the BLS paths run.
fn pubkey_for(index: usize) -> BlsPubkey {
    BlsPubkey(secret_key_for(index).sk_to_pk().to_bytes())
}

/// Validator `index`'s signature over `message`, under the key every state this
/// module builds registers for it, so a test can produce signatures those
/// states verify.
pub fn sign_for(index: usize, message: Root) -> BlsSignature {
    let signature = secret_key_for(index).sign(message.as_slice(), crate::beacon::bls::DST, &[]);
    BlsSignature(signature.to_bytes())
}

/// The secret key behind [`pubkey_for`]`(index)`, for a test that needs a
/// validator's signature to verify.
pub fn secret_key_for(index: usize) -> blst::min_pk::SecretKey {
    let mut ikm = [0u8; 32];
    ikm[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
    blst::min_pk::SecretKey::key_gen(&ikm, &[])
        .expect("32 bytes of input material is enough for key generation")
}

/// A phase0 state with `count` fully active, full-balance validators, positioned
/// one epoch in so that the previous epoch exists and the block root window has
/// entries behind it.
pub fn with_validators(count: usize) -> BeaconState {
    let validators: Vec<Validator> = (0..count)
        .map(|index| Validator {
            pubkey: pubkey_for(index),
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
        genesis_validators_root: Root::ZERO,
        slot: preset::SLOTS_PER_EPOCH,
        fork: Default::default(),
        latest_block_header: Default::default(),
        block_roots: vec![Root::ZERO; preset::SLOTS_PER_HISTORICAL_ROOT]
            .try_into()
            .expect("the vector is built at its exact length"),
        state_roots: vec![Root::ZERO; preset::SLOTS_PER_HISTORICAL_ROOT]
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
        randao_mixes: vec![Bytes32::ZERO; preset::EPOCHS_PER_HISTORICAL_VECTOR]
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

/// The [`with_validators`] counterpart for every fork phase0 through fulu.
///
/// Builds `count` fully active, full-balance validators, positioned one epoch
/// in exactly like [`with_validators`], with every field a later fork adds
/// (participation flags, inactivity scores, sync committees, an execution
/// payload header, the withdrawal cursor and historical summaries, the
/// electra pending queues, fulu's proposer lookahead) left at its own
/// all-default placeholder. A test that needs one of those fields to hold
/// something other than the placeholder builds this and overrides it
/// afterward; see `crate::beacon::stf::electra::tests::electra_state_with_validators`
/// for an example that overrides several at once.
pub fn with_validators_at(fork: ForkName, count: usize) -> BeaconState {
    match fork {
        ForkName::Phase0 => with_validators(count),
        ForkName::Altair => BeaconState::Altair(altair_state(count)),
        ForkName::Bellatrix => BeaconState::Bellatrix(bellatrix_state(count)),
        ForkName::Capella => BeaconState::Capella(capella_state(count)),
        ForkName::Deneb => BeaconState::Deneb(deneb_state(count)),
        ForkName::Electra => BeaconState::Electra(electra_state(count)),
        ForkName::Fulu => BeaconState::Fulu(fulu_state(count)),
        // A test asking for a lean state from a beacon builder, which no fixture
        // fork name can produce; the `fork:` form, since the argument is the
        // whole input.
        ForkName::Lean => lean_fork_unreachable("with_validators_at"),
    }
}

/// [`with_validators_at`], with every validator's public key replaced by the
/// real one [`sign_for`] signs under.
///
/// Every fork but phase0 leaves the keys at the all-zero default, which is
/// cheaper to build and all most tests need; a test that looks validators up
/// by key, or verifies their signatures, needs them distinct and real.
pub fn with_signing_validators_at(fork: ForkName, count: usize) -> BeaconState {
    let mut state = with_validators_at(fork, count);
    for index in 0..count {
        state
            .validator_mut(index as u64)
            .expect("index is within the registry just built")
            .pubkey = pubkey_for(index);
    }
    state
}

// -- Pieces shared by every fork's state literal below -----------------------
//
// None of these are fork-specific on their own; what varies fork to fork is
// which of them a given `BeaconState` variant has a field for, which is why
// `with_validators_at`'s match arms below still need one struct literal per
// fork rather than a single generic constructor.

/// `count` validators, each with `effective_balance` and otherwise eligible,
/// active since genesis, and never exiting.
fn full_validators(
    count: usize,
    effective_balance: Gwei,
) -> crate::beacon::containers::shared::Validators {
    let validators: Vec<Validator> = (0..count)
        .map(|_| Validator {
            effective_balance,
            activation_eligibility_epoch: 0,
            activation_epoch: 0,
            exit_epoch: constants::FAR_FUTURE_EPOCH,
            withdrawable_epoch: constants::FAR_FUTURE_EPOCH,
            ..Default::default()
        })
        .collect();
    validators
        .try_into()
        .expect("count is far below VALIDATOR_REGISTRY_LIMIT")
}

/// `count` balances, each matching [`full_validators`]'s `effective_balance`.
fn full_balances(count: usize, effective_balance: Gwei) -> Balances {
    vec![effective_balance; count]
        .try_into()
        .expect("count is far below VALIDATOR_REGISTRY_LIMIT")
}

/// An all-zero `block_roots`/`state_roots` vector: both fields share this
/// exact type, so one builder serves either.
fn zero_root_vector() -> BlockRoots {
    vec![Root::ZERO; preset::SLOTS_PER_HISTORICAL_ROOT]
        .try_into()
        .expect("the vector is built at its exact length")
}

fn zero_randao_mixes() -> RandaoMixes {
    vec![Bytes32::ZERO; preset::EPOCHS_PER_HISTORICAL_VECTOR]
        .try_into()
        .expect("the vector is built at its exact length")
}

fn zero_slashings() -> Slashings {
    vec![0; preset::EPOCHS_PER_SLASHINGS_VECTOR]
        .try_into()
        .expect("the vector is built at its exact length")
}

/// An all-zero `previous_epoch_participation`/`current_epoch_participation`
/// vector, one entry per validator.
fn zero_participation(count: usize) -> EpochParticipation {
    vec![0; count]
        .try_into()
        .expect("count is far below VALIDATOR_REGISTRY_LIMIT")
}

fn zero_inactivity_scores(count: usize) -> InactivityScores {
    vec![0; count]
        .try_into()
        .expect("count is far below VALIDATOR_REGISTRY_LIMIT")
}

/// A sync committee with every seat at its all-default (invalid-as-a-curve-
/// point) pubkey. Good enough for tests that only need the field populated at
/// the right length, not for anything that aggregates or verifies against it.
fn empty_sync_committee() -> altair::SyncCommittee {
    altair::SyncCommittee {
        pubkeys: vec![BlsPubkey::default(); preset::SYNC_COMMITTEE_SIZE]
            .try_into()
            .expect("built at exactly SYNC_COMMITTEE_SIZE"),
        aggregate_pubkey: BlsPubkey::default(),
    }
}

/// An all-default execution payload header in bellatrix's shape (no
/// `withdrawals_root`, no blob fields), standing in for the genesis payload.
fn empty_bellatrix_execution_payload_header() -> bellatrix::ExecutionPayloadHeader {
    bellatrix::ExecutionPayloadHeader {
        parent_hash: ExecutionBlockHash::ZERO,
        fee_recipient: ExecutionAddress::ZERO,
        state_root: Bytes32::ZERO,
        receipts_root: Bytes32::ZERO,
        logs_bloom: vec![0u8; preset::BYTES_PER_LOGS_BLOOM]
            .try_into()
            .expect("built at exactly BYTES_PER_LOGS_BLOOM"),
        prev_randao: Bytes32::ZERO,
        block_number: 0,
        gas_limit: 0,
        gas_used: 0,
        timestamp: 0,
        extra_data: Default::default(),
        base_fee_per_gas: Uint256::ZERO,
        block_hash: ExecutionBlockHash::ZERO,
        transactions_root: Root::ZERO,
    }
}

/// The capella-shaped counterpart of
/// [`empty_bellatrix_execution_payload_header`]: adds `withdrawals_root`.
fn empty_capella_execution_payload_header() -> capella::ExecutionPayloadHeader {
    capella::ExecutionPayloadHeader {
        parent_hash: ExecutionBlockHash::ZERO,
        fee_recipient: ExecutionAddress::ZERO,
        state_root: Bytes32::ZERO,
        receipts_root: Bytes32::ZERO,
        logs_bloom: vec![0u8; preset::BYTES_PER_LOGS_BLOOM]
            .try_into()
            .expect("built at exactly BYTES_PER_LOGS_BLOOM"),
        prev_randao: Bytes32::ZERO,
        block_number: 0,
        gas_limit: 0,
        gas_used: 0,
        timestamp: 0,
        extra_data: Default::default(),
        base_fee_per_gas: Uint256::ZERO,
        block_hash: ExecutionBlockHash::ZERO,
        transactions_root: Root::ZERO,
        withdrawals_root: Root::ZERO,
    }
}

/// The deneb-shaped counterpart of [`empty_capella_execution_payload_header`]:
/// adds the blob fields. Electra and fulu keep this same shape unchanged (see
/// `crate::beacon::containers` module docs), so this builds their header too.
fn empty_deneb_execution_payload_header() -> deneb::ExecutionPayloadHeader {
    deneb::ExecutionPayloadHeader {
        parent_hash: ExecutionBlockHash::ZERO,
        fee_recipient: ExecutionAddress::ZERO,
        state_root: Bytes32::ZERO,
        receipts_root: Bytes32::ZERO,
        logs_bloom: vec![0u8; preset::BYTES_PER_LOGS_BLOOM]
            .try_into()
            .expect("built at exactly BYTES_PER_LOGS_BLOOM"),
        prev_randao: Bytes32::ZERO,
        block_number: 0,
        gas_limit: 0,
        gas_used: 0,
        timestamp: 0,
        extra_data: Default::default(),
        base_fee_per_gas: Uint256::ZERO,
        block_hash: ExecutionBlockHash::ZERO,
        transactions_root: Root::ZERO,
        withdrawals_root: Root::ZERO,
        blob_gas_used: 0,
        excess_blob_gas: 0,
    }
}

// -- One struct literal per fork ---------------------------------------------

fn altair_state(count: usize) -> altair::BeaconState {
    altair::BeaconState {
        genesis_time: 0,
        genesis_validators_root: Root::ZERO,
        slot: preset::SLOTS_PER_EPOCH,
        fork: Default::default(),
        latest_block_header: Default::default(),
        block_roots: zero_root_vector(),
        state_roots: zero_root_vector(),
        historical_roots: Default::default(),
        eth1_data: Default::default(),
        eth1_data_votes: Default::default(),
        eth1_deposit_index: 0,
        validators: full_validators(count, preset::MAX_EFFECTIVE_BALANCE),
        balances: full_balances(count, preset::MAX_EFFECTIVE_BALANCE),
        randao_mixes: zero_randao_mixes(),
        slashings: zero_slashings(),
        previous_epoch_participation: zero_participation(count),
        current_epoch_participation: zero_participation(count),
        justification_bits: Default::default(),
        previous_justified_checkpoint: Default::default(),
        current_justified_checkpoint: Default::default(),
        finalized_checkpoint: Default::default(),
        inactivity_scores: zero_inactivity_scores(count),
        current_sync_committee: empty_sync_committee(),
        next_sync_committee: empty_sync_committee(),
    }
}

fn bellatrix_state(count: usize) -> bellatrix::BeaconState {
    bellatrix::BeaconState {
        genesis_time: 0,
        genesis_validators_root: Root::ZERO,
        slot: preset::SLOTS_PER_EPOCH,
        fork: Default::default(),
        latest_block_header: Default::default(),
        block_roots: zero_root_vector(),
        state_roots: zero_root_vector(),
        historical_roots: Default::default(),
        eth1_data: Default::default(),
        eth1_data_votes: Default::default(),
        eth1_deposit_index: 0,
        validators: full_validators(count, preset::MAX_EFFECTIVE_BALANCE),
        balances: full_balances(count, preset::MAX_EFFECTIVE_BALANCE),
        randao_mixes: zero_randao_mixes(),
        slashings: zero_slashings(),
        previous_epoch_participation: zero_participation(count),
        current_epoch_participation: zero_participation(count),
        justification_bits: Default::default(),
        previous_justified_checkpoint: Default::default(),
        current_justified_checkpoint: Default::default(),
        finalized_checkpoint: Default::default(),
        inactivity_scores: zero_inactivity_scores(count),
        current_sync_committee: empty_sync_committee(),
        next_sync_committee: empty_sync_committee(),
        // Thrown away by every real caller, which needs a specific payload
        // (or lack of one) under test and overrides this right after; see
        // `crate::beacon::stf::bellatrix::tests::bellatrix_state_with_validators`.
        latest_execution_payload_header: empty_bellatrix_execution_payload_header(),
    }
}

fn capella_state(count: usize) -> capella::BeaconState {
    capella::BeaconState {
        genesis_time: 0,
        genesis_validators_root: Root::ZERO,
        slot: preset::SLOTS_PER_EPOCH,
        fork: Default::default(),
        latest_block_header: Default::default(),
        block_roots: zero_root_vector(),
        state_roots: zero_root_vector(),
        historical_roots: Default::default(),
        eth1_data: Default::default(),
        eth1_data_votes: Default::default(),
        eth1_deposit_index: 0,
        validators: full_validators(count, preset::MAX_EFFECTIVE_BALANCE),
        balances: full_balances(count, preset::MAX_EFFECTIVE_BALANCE),
        randao_mixes: zero_randao_mixes(),
        slashings: zero_slashings(),
        previous_epoch_participation: zero_participation(count),
        current_epoch_participation: zero_participation(count),
        justification_bits: Default::default(),
        previous_justified_checkpoint: Default::default(),
        current_justified_checkpoint: Default::default(),
        finalized_checkpoint: Default::default(),
        inactivity_scores: zero_inactivity_scores(count),
        current_sync_committee: empty_sync_committee(),
        next_sync_committee: empty_sync_committee(),
        latest_execution_payload_header: empty_capella_execution_payload_header(),
        next_withdrawal_index: 0,
        next_withdrawal_validator_index: 0,
        historical_summaries: Default::default(),
    }
}

fn deneb_state(count: usize) -> deneb::BeaconState {
    deneb::BeaconState {
        genesis_time: 0,
        genesis_validators_root: Root::ZERO,
        slot: preset::SLOTS_PER_EPOCH,
        fork: Default::default(),
        latest_block_header: Default::default(),
        block_roots: zero_root_vector(),
        state_roots: zero_root_vector(),
        historical_roots: Default::default(),
        eth1_data: Default::default(),
        eth1_data_votes: Default::default(),
        eth1_deposit_index: 0,
        validators: full_validators(count, preset::MAX_EFFECTIVE_BALANCE),
        balances: full_balances(count, preset::MAX_EFFECTIVE_BALANCE),
        randao_mixes: zero_randao_mixes(),
        slashings: zero_slashings(),
        previous_epoch_participation: zero_participation(count),
        current_epoch_participation: zero_participation(count),
        justification_bits: Default::default(),
        previous_justified_checkpoint: Default::default(),
        current_justified_checkpoint: Default::default(),
        finalized_checkpoint: Default::default(),
        inactivity_scores: zero_inactivity_scores(count),
        current_sync_committee: empty_sync_committee(),
        next_sync_committee: empty_sync_committee(),
        latest_execution_payload_header: empty_deneb_execution_payload_header(),
        next_withdrawal_index: 0,
        next_withdrawal_validator_index: 0,
        historical_summaries: Default::default(),
    }
}

fn electra_state(count: usize) -> electra::BeaconState {
    electra::BeaconState {
        genesis_time: 0,
        genesis_validators_root: Root::ZERO,
        slot: preset::SLOTS_PER_EPOCH,
        fork: Default::default(),
        latest_block_header: Default::default(),
        block_roots: zero_root_vector(),
        state_roots: zero_root_vector(),
        historical_roots: Default::default(),
        eth1_data: Default::default(),
        eth1_data_votes: Default::default(),
        eth1_deposit_index: 0,
        validators: full_validators(count, preset::MIN_ACTIVATION_BALANCE),
        balances: full_balances(count, preset::MIN_ACTIVATION_BALANCE),
        randao_mixes: zero_randao_mixes(),
        slashings: zero_slashings(),
        previous_epoch_participation: zero_participation(count),
        current_epoch_participation: zero_participation(count),
        justification_bits: Default::default(),
        previous_justified_checkpoint: Default::default(),
        current_justified_checkpoint: Default::default(),
        finalized_checkpoint: Default::default(),
        inactivity_scores: zero_inactivity_scores(count),
        current_sync_committee: empty_sync_committee(),
        next_sync_committee: empty_sync_committee(),
        latest_execution_payload_header: empty_deneb_execution_payload_header(),
        next_withdrawal_index: 0,
        next_withdrawal_validator_index: 0,
        historical_summaries: Default::default(),
        deposit_requests_start_index: constants::UNSET_DEPOSIT_REQUESTS_START_INDEX,
        deposit_balance_to_consume: 0,
        exit_balance_to_consume: 0,
        earliest_exit_epoch: 0,
        consolidation_balance_to_consume: 0,
        earliest_consolidation_epoch: 0,
        pending_deposits: Default::default(),
        pending_partial_withdrawals: Default::default(),
        pending_consolidations: Default::default(),
    }
}

fn fulu_state(count: usize) -> fulu::BeaconState {
    fulu::BeaconState {
        genesis_time: 0,
        genesis_validators_root: Root::ZERO,
        slot: preset::SLOTS_PER_EPOCH,
        fork: Default::default(),
        latest_block_header: Default::default(),
        block_roots: zero_root_vector(),
        state_roots: zero_root_vector(),
        historical_roots: Default::default(),
        eth1_data: Default::default(),
        eth1_data_votes: Default::default(),
        eth1_deposit_index: 0,
        validators: full_validators(count, preset::MAX_EFFECTIVE_BALANCE),
        balances: full_balances(count, preset::MAX_EFFECTIVE_BALANCE),
        randao_mixes: zero_randao_mixes(),
        slashings: zero_slashings(),
        previous_epoch_participation: zero_participation(count),
        current_epoch_participation: zero_participation(count),
        justification_bits: Default::default(),
        previous_justified_checkpoint: Default::default(),
        current_justified_checkpoint: Default::default(),
        finalized_checkpoint: Default::default(),
        inactivity_scores: zero_inactivity_scores(count),
        current_sync_committee: empty_sync_committee(),
        next_sync_committee: empty_sync_committee(),
        latest_execution_payload_header: empty_deneb_execution_payload_header(),
        next_withdrawal_index: 0,
        next_withdrawal_validator_index: 0,
        historical_summaries: Default::default(),
        deposit_requests_start_index: constants::UNSET_DEPOSIT_REQUESTS_START_INDEX,
        deposit_balance_to_consume: 0,
        exit_balance_to_consume: 0,
        earliest_exit_epoch: 0,
        consolidation_balance_to_consume: 0,
        earliest_consolidation_epoch: 0,
        pending_deposits: Default::default(),
        pending_partial_withdrawals: Default::default(),
        pending_consolidations: Default::default(),
        // Left at zero rather than run through `initialize_proposer_lookahead`:
        // that is a derived value a fulu-specific test can compute for itself
        // and override (see `crate::beacon::helpers::fulu::tests::fulu_state_with_validators`),
        // and this builder has no fulu-specific import to spare for it.
        proposer_lookahead: vec![0; preset::PROPOSER_LOOKAHEAD_LENGTH]
            .try_into()
            .expect("the vector is built at its exact length"),
    }
}
