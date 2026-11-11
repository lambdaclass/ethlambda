//! Containers EIP-8483 (post-quantum material registration) introduces.
//!
//! Transcribed from consensus-specs #5809 (`specs/_features/eip8483/`, head
//! `a043fda6`), which builds the feature on heze. Two execution layer
//! triggered requests let a validator's withdrawal address register 64 bytes
//! of opaque post-quantum material, and a builder's execution address 32
//! bytes, ahead of a later fork that migrates to post-quantum signatures. The
//! state keeps one entry per validator (keyed by index) and one per builder
//! (keyed by public key, since builder indices are reused).
//!
//! The two request lists ride in [`super::gloas::ExecutionRequests`] as one
//! `Option` ([`PQRegistrationRequests`]) rather than in a restated container:
//! the same choice heze made for the bid's `inclusion_list_bits`, so the
//! envelope, the block body's `parent_execution_requests` and the engine's
//! `NewPayloadRequest` keep serving every fork from gloas on. See that type's
//! doc for how the two shapes are told apart.

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::ProgressiveList;

use super::altair::SyncCommittee;
use super::fulu::ProposerLookahead;
use super::gloas::{
    BuilderIndex, BuilderPendingPayments, BuilderPendingWithdrawals, Builders, EpochParticipation,
    ExecutionPayloadAvailability, ExecutionPayloadBid, InactivityScores,
    PayloadTimelinessCommitteeWindow, PendingConsolidations, PendingDeposits,
    PendingPartialWithdrawals, Withdrawals,
};
use super::shared::{
    BeaconBlockHeader, BlockRoots, Checkpoint, Fork, HistoricalRoots, HistoricalSummaries,
    JustificationBits, ProgressiveBalances, ProgressiveValidators, RandaoMixes, Slashings,
    StateRoots,
};
use crate::beacon::primitives::{
    BlsPubkey, Bytes32, Bytes64, Epoch, ExecutionAddress, ExecutionBlockHash, Gwei, Root, Slot,
    ValidatorIndex, WithdrawalIndex,
};

/// The validator PQ registration requests pertaining to a single execution
/// payload.
pub type ValidatorPQRegistrationRequests = ProgressiveList<ValidatorPQRegistrationRequest>;
/// The registered validator PQ material, at most one entry per validator.
pub type ValidatorPQRegistrations = ProgressiveList<ValidatorPQRegistration>;
/// The builder PQ registration requests pertaining to a single execution
/// payload.
pub type BuilderPQRegistrationRequests = ProgressiveList<BuilderPQRegistrationRequest>;
/// The registered builder PQ material, at most one entry per builder.
pub type BuilderPQRegistrations = ProgressiveList<BuilderPQRegistration>;

/// A request from a validator's withdrawal address to register `pq_data` for
/// that validator.
///
/// Its SSZ serialization is the 132-byte record the validator predeploy
/// contract returns (`source_address ++ validator_pubkey ++ pq_data`).
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct ValidatorPQRegistrationRequest {
    pub source_address: ExecutionAddress,
    pub validator_pubkey: BlsPubkey,
    pub pq_data: Bytes64,
}

/// One validator's registered PQ material.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct ValidatorPQRegistration {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub validator_index: ValidatorIndex,
    pub pq_data: Bytes64,
}

/// A request from a builder's execution address to register `pq_data` for
/// that builder.
///
/// Its SSZ serialization is the 100-byte record the builder predeploy
/// contract returns (`source_address ++ builder_pubkey ++ pq_data`).
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct BuilderPQRegistrationRequest {
    pub source_address: ExecutionAddress,
    pub builder_pubkey: BlsPubkey,
    pub pq_data: Bytes32,
}

/// One builder's registered PQ material, keyed by public key: a builder index
/// is reused once its builder has withdrawn, so an index-keyed entry could be
/// inherited by an unrelated builder.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct BuilderPQRegistration {
    pub builder_pubkey: BlsPubkey,
    pub pq_data: Bytes32,
}

/// The two request lists EIP-8483 appends to `ExecutionRequests`, held
/// together so that a value carries both or neither.
///
/// `ExecutionRequests` flattens this into its own JSON object, so the Beacon
/// API sees the specification's two field names side by side with the other
/// request kinds.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PQRegistrationRequests {
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub validator_pq_registrations: ValidatorPQRegistrationRequests,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub builder_pq_registrations: BuilderPQRegistrationRequests,
}

impl PQRegistrationRequests {
    /// Whether both lists are empty.
    pub fn is_empty(&self) -> bool {
        self.validator_pq_registrations.is_empty() && self.builder_pq_registrations.is_empty()
    }
}

/// The EIP-8483 beacon state: heze's, plus `validator_pq_registrations` and
/// `builder_pq_registrations` appended (`active_fields(width=48, gaps=(8, 9,
/// 10, 28))`).
///
/// The four gaps are heze's (EIP-8015's removed eth1 and deposit-index
/// fields), so every field heze carries keeps its generalized index. Not
/// `#[derive(Default)]`, for the reason gloas's state gives.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot)]
#[ssz(progressive_container, active_fields = [1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])]
pub struct BeaconState {
    // -- Versioning --
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub genesis_time: u64,
    /// The root of the genesis validator registry, which separates this
    /// chain from any other running the same fork schedule.
    pub genesis_validators_root: Root,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub slot: Slot,
    pub fork: Fork,

    // -- History --
    /// The most recent block's header, with `state_root` left zero until the
    /// slot advances, since a block cannot commit to the root of the state
    /// containing it.
    pub latest_block_header: BeaconBlockHeader,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub block_roots: BlockRoots,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub state_roots: StateRoots,
    /// Frozen since capella: further history is committed to by
    /// `historical_summaries` instead.
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub historical_roots: HistoricalRoots,

    // -- Registry (EIP-7688) --
    /// The validator registry, tree-backed and progressively merkleized. See
    /// [`ProgressiveValidators`].
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub validators: ProgressiveValidators,
    #[serde(with = "crate::beacon::serde_helpers::quoted_u64_seq")]
    pub balances: ProgressiveBalances,

    // -- Randomness --
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub randao_mixes: RandaoMixes,

    // -- Slashings --
    #[serde(with = "crate::beacon::serde_helpers::quoted_u64_seq")]
    pub slashings: Slashings,

    // -- Participation (EIP-7688) --
    #[serde(with = "crate::beacon::serde_helpers::quoted_u64_seq")]
    pub previous_epoch_participation: EpochParticipation,
    #[serde(with = "crate::beacon::serde_helpers::quoted_u64_seq")]
    pub current_epoch_participation: EpochParticipation,

    // -- Finality --
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex")]
    pub justification_bits: JustificationBits,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,

    // -- Inactivity (EIP-7688) --
    #[serde(with = "crate::beacon::serde_helpers::quoted_u64_seq")]
    pub inactivity_scores: InactivityScores,

    // -- Sync committees --
    pub current_sync_committee: SyncCommittee,
    pub next_sync_committee: SyncCommittee,

    // -- Execution (EIP-7732) --
    /// The most recently revealed payload's own hash. Replaces
    /// `latest_execution_payload_header`: a gloas state no longer holds a
    /// payload header, only this hash and `latest_execution_payload_bid`.
    pub latest_block_hash: ExecutionBlockHash,

    // -- Withdrawals --
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub next_withdrawal_index: WithdrawalIndex,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub next_withdrawal_validator_index: ValidatorIndex,

    // -- History (capella) --
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub historical_summaries: HistoricalSummaries,

    // -- Deposits, exits, and consolidations (electra) --
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub deposit_balance_to_consume: Gwei,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub exit_balance_to_consume: Gwei,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub earliest_exit_epoch: Epoch,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub consolidation_balance_to_consume: Gwei,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub earliest_consolidation_epoch: Epoch,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub pending_deposits: PendingDeposits,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub pending_partial_withdrawals: PendingPartialWithdrawals,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub pending_consolidations: PendingConsolidations,

    // -- Proposer lookahead (fulu) --
    #[serde(with = "crate::beacon::serde_helpers::quoted_u64_seq")]
    pub proposer_lookahead: ProposerLookahead,

    // -- Builders (EIP-7732) --
    /// The builder registry.
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub builders: Builders,
    /// Where the builder withdrawal sweep last stopped, the builder-side
    /// counterpart of `next_withdrawal_validator_index`.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub next_withdrawal_builder_index: BuilderIndex,
    /// Bits tracking, for each of the last `SLOTS_PER_HISTORICAL_ROOT` slots,
    /// whether that slot's payload was made available.
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex")]
    pub execution_payload_availability: ExecutionPayloadAvailability,
    /// Builder payments owed for the previous and current epoch, settled by
    /// `process_builder_pending_payments`.
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub builder_pending_payments: BuilderPendingPayments,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub builder_pending_withdrawals: BuilderPendingWithdrawals,
    /// The bid the payload currently expected for this slot, if any, was
    /// bought under.
    pub latest_execution_payload_bid: ExecutionPayloadBid,
    /// The withdrawals `get_expected_withdrawals` computed for the payload
    /// this slot expects, cached here so a late-revealed payload's
    /// `process_execution_payload` does not have to recompute the sweep.
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub payload_expected_withdrawals: Withdrawals,
    /// The cached window of payload timeliness committees for the previous,
    /// current, and lookahead epochs, refreshed each epoch by
    /// `process_ptc_window`.
    #[serde(serialize_with = "crate::beacon::serde_helpers::nested_quoted_u64_seq::serialize")]
    pub ptc_window: PayloadTimelinessCommitteeWindow,

    // -- Post-quantum registrations (EIP-8483) --
    /// The registered validator PQ material, at most one entry per
    /// validator.
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub validator_pq_registrations: ValidatorPQRegistrations,
    /// The registered builder PQ material, at most one entry per builder
    /// public key.
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub builder_pq_registrations: BuilderPQRegistrations,
}

impl From<super::heze::BeaconState> for BeaconState {
    /// Heze's state with both registries empty. Every other field carries
    /// over untouched, `fork` included: `upgrade_to_eip8483` sets that one
    /// itself.
    fn from(pre: super::heze::BeaconState) -> Self {
        Self {
            genesis_time: pre.genesis_time,
            genesis_validators_root: pre.genesis_validators_root,
            slot: pre.slot,
            fork: pre.fork,
            latest_block_header: pre.latest_block_header,
            block_roots: pre.block_roots,
            state_roots: pre.state_roots,
            historical_roots: pre.historical_roots,
            validators: pre.validators,
            balances: pre.balances,
            randao_mixes: pre.randao_mixes,
            slashings: pre.slashings,
            previous_epoch_participation: pre.previous_epoch_participation,
            current_epoch_participation: pre.current_epoch_participation,
            justification_bits: pre.justification_bits,
            previous_justified_checkpoint: pre.previous_justified_checkpoint,
            current_justified_checkpoint: pre.current_justified_checkpoint,
            finalized_checkpoint: pre.finalized_checkpoint,
            inactivity_scores: pre.inactivity_scores,
            current_sync_committee: pre.current_sync_committee,
            next_sync_committee: pre.next_sync_committee,
            latest_block_hash: pre.latest_block_hash,
            next_withdrawal_index: pre.next_withdrawal_index,
            next_withdrawal_validator_index: pre.next_withdrawal_validator_index,
            historical_summaries: pre.historical_summaries,
            deposit_balance_to_consume: pre.deposit_balance_to_consume,
            exit_balance_to_consume: pre.exit_balance_to_consume,
            earliest_exit_epoch: pre.earliest_exit_epoch,
            consolidation_balance_to_consume: pre.consolidation_balance_to_consume,
            earliest_consolidation_epoch: pre.earliest_consolidation_epoch,
            pending_deposits: pre.pending_deposits,
            pending_partial_withdrawals: pre.pending_partial_withdrawals,
            pending_consolidations: pre.pending_consolidations,
            proposer_lookahead: pre.proposer_lookahead,
            builders: pre.builders,
            next_withdrawal_builder_index: pre.next_withdrawal_builder_index,
            execution_payload_availability: pre.execution_payload_availability,
            builder_pending_payments: pre.builder_pending_payments,
            builder_pending_withdrawals: pre.builder_pending_withdrawals,
            latest_execution_payload_bid: pre.latest_execution_payload_bid,
            payload_expected_withdrawals: pre.payload_expected_withdrawals,
            ptc_window: pre.ptc_window,
            validator_pq_registrations: Default::default(),
            builder_pq_registrations: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use libssz::{SszDecode as _, SszEncode as _};

    use super::*;

    /// The request containers' encodings are the predeploy contracts' records,
    /// so their sizes are part of the cross-layer contract.
    #[test]
    fn request_records_have_the_contracts_sizes() {
        assert!(<ValidatorPQRegistrationRequest as libssz::SszEncode>::is_fixed_size());
        assert!(<BuilderPQRegistrationRequest as libssz::SszEncode>::is_fixed_size());
        assert_eq!(
            <ValidatorPQRegistrationRequest as libssz::SszEncode>::fixed_size(),
            132
        );
        assert_eq!(
            <BuilderPQRegistrationRequest as libssz::SszEncode>::fixed_size(),
            100
        );
        assert_eq!(
            <ValidatorPQRegistration as libssz::SszEncode>::fixed_size(),
            72
        );
        assert_eq!(
            <BuilderPQRegistration as libssz::SszEncode>::fixed_size(),
            80
        );
    }

    #[test]
    fn a_validator_request_encodes_as_address_then_pubkey_then_data() {
        let request = ValidatorPQRegistrationRequest {
            source_address: ExecutionAddress::from_slice(&[0x11; 20]),
            validator_pubkey: BlsPubkey([0x22; 48]),
            pq_data: Bytes64([0x33; 64]),
        };
        let bytes = request.to_ssz();
        let mut expected = vec![0x11; 20];
        expected.extend([0x22; 48]);
        expected.extend([0x33; 64]);
        assert_eq!(bytes, expected);
        assert_eq!(
            ValidatorPQRegistrationRequest::from_ssz_bytes(&bytes).unwrap(),
            request
        );
    }

    #[test]
    fn a_builder_request_encodes_as_address_then_pubkey_then_data() {
        let request = BuilderPQRegistrationRequest {
            source_address: ExecutionAddress::from_slice(&[0x11; 20]),
            builder_pubkey: BlsPubkey([0x22; 48]),
            pq_data: Bytes32::repeat_byte(0x33),
        };
        let bytes = request.to_ssz();
        let mut expected = vec![0x11; 20];
        expected.extend([0x22; 48]);
        expected.extend([0x33; 32]);
        assert_eq!(bytes, expected);
        assert_eq!(
            BuilderPQRegistrationRequest::from_ssz_bytes(&bytes).unwrap(),
            request
        );
    }
}
