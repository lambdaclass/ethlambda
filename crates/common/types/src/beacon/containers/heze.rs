//! Containers heze introduces or reshapes.
//!
//! EIP-7805 (fork-choice enforced inclusion lists) adds the inclusion list
//! containers, and one field on the execution payload bid:
//! [`super::gloas::ExecutionPayloadBid`] carries `inclusion_list_bits` as an
//! `Option` rather than this module restating the bid. See that type's doc
//! for how the two shapes are told apart on the wire.
//!
//! EIP-8015 removes `eth1_data` and `deposits` from the block body and four
//! eth1 and deposit-index fields from the state, so the block body, block,
//! signed block and state are heze's own containers, with the removed fields
//! left as gaps in their progressive layouts.

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::{SszBitvector, SszVector};

use super::altair::{SyncAggregate, SyncCommittee};
use super::fulu::ProposerLookahead;
use super::gloas::{
    Attestations, AttesterSlashings, BlsToExecutionChanges, BuilderIndex, BuilderPendingPayments,
    BuilderPendingWithdrawals, Builders, EpochParticipation, ExecutionPayloadAvailability,
    ExecutionPayloadBid, ExecutionRequests, InactivityScores, PayloadAttestations,
    PayloadTimelinessCommitteeWindow, PendingConsolidations, PendingDeposits,
    PendingPartialWithdrawals, ProposerSlashings, SignedExecutionPayloadBid, Transactions,
    VoluntaryExits, Withdrawals,
};
use super::shared::{
    BeaconBlockHeader, BlockRoots, Checkpoint, Fork, HistoricalRoots, HistoricalSummaries,
    JustificationBits, ProgressiveBalances, ProgressiveValidators, RandaoMixes, Slashings,
    StateRoots,
};
use crate::beacon::preset;
use crate::beacon::primitives::{
    BlsSignature, Bytes32, Epoch, ExecutionBlockHash, Gwei, Root, Slot, ValidatorIndex,
    WithdrawalIndex,
};

/// A bitfield over the inclusion list committee, one bit per member in
/// committee order.
pub type InclusionListBits = SszBitvector<{ preset::INCLUSION_LIST_COMMITTEE_SIZE }>;

/// The inclusion list committee of a slot: every beacon committee of the slot
/// concatenated in order, cycled to `INCLUSION_LIST_COMMITTEE_SIZE` members.
pub type InclusionListCommittee =
    SszVector<ValidatorIndex, { preset::INCLUSION_LIST_COMMITTEE_SIZE }>;

/// The transactions one inclusion list committee member asks the next
/// payload to include.
///
/// `dependent_root` pins the shuffling the member's committee seat was drawn
/// from, so lists built on different branches are kept apart in the
/// inclusion list store rather than compared against each other.
#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct InclusionList {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub slot: Slot,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub validator_index: ValidatorIndex,
    pub dependent_root: Root,
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex_seq")]
    pub transactions: Transactions,
}

#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct SignedInclusionList {
    pub message: InclusionList,
    pub signature: BlsSignature,
}

/// Heze's block body: gloas's without `eth1_data` and `deposits` (EIP-8015).
///
/// The two removed fields stay as gaps in the progressive container's
/// `active_fields`, so every remaining field keeps its generalized index.
#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
#[ssz(progressive_container, active_fields = [1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1])]
pub struct BeaconBlockBody {
    /// The proposer's contribution to the chain's randomness, which is a
    /// signature over the current epoch and so cannot be chosen freely.
    pub randao_reveal: BlsSignature,
    /// Arbitrary proposer-chosen bytes, which consensus never reads.
    pub graffiti: Bytes32,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub proposer_slashings: ProposerSlashings,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub attester_slashings: AttesterSlashings,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub attestations: Attestations,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub voluntary_exits: VoluntaryExits,
    /// The aggregated sync committee signature over the previous slot's
    /// block root, plus which members contributed.
    pub sync_aggregate: SyncAggregate,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub bls_to_execution_changes: BlsToExecutionChanges,
    /// The proposer's binding commitment to the builder's bid for this
    /// slot's payload (EIP-7732); the payload itself is revealed afterward
    /// in a [`SignedExecutionPayloadEnvelope`].
    pub signed_execution_payload_bid: SignedExecutionPayloadBid,
    /// The payload timeliness committee's votes on the *previous* slot's
    /// payload.
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub payload_attestations: PayloadAttestations,
    /// The previous slot's execution-layer-triggered requests, carried
    /// forward so `process_payload_attestation` and friends do not need a
    /// separate fetch of the previous envelope.
    pub parent_execution_requests: ExecutionRequests,
}

impl BeaconBlockBody {
    /// An empty body: no operations, and a default execution payload bid
    /// carrying an all-zero `inclusion_list_bits`, the shape every heze bid has.
    pub fn empty() -> Self {
        let mut body = Self::default();
        body.signed_execution_payload_bid
            .message
            .inclusion_list_bits = Some(InclusionListBits::new());
        body
    }
}

/// Heze's block: gloas's, over [`BeaconBlockBody`].
#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct BeaconBlock {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub slot: Slot,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub proposer_index: ValidatorIndex,
    pub parent_root: Root,
    /// The root of the state after this block is applied, which the state
    /// transition recomputes and compares.
    pub state_root: Root,
    pub body: BeaconBlockBody,
}

#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct SignedBeaconBlock {
    pub message: BeaconBlock,
    pub signature: BlsSignature,
}

/// Heze's beacon state: gloas's without `eth1_data`, `eth1_data_votes`,
/// `eth1_deposit_index` and `deposit_requests_start_index` (EIP-8015).
///
/// Those four fields are gaps in the progressive container's `active_fields`
/// (46 wide, 42 present), so every remaining field keeps its generalized
/// index. Everything else is gloas's field for field, including the
/// `latest_execution_payload_bid`, whose heze shape carries
/// `inclusion_list_bits` (see [`super::gloas::ExecutionPayloadBid`]).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot)]
#[ssz(progressive_container, active_fields = [1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])]
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
}

impl From<super::gloas::BeaconBlockBody> for BeaconBlockBody {
    /// Drops `eth1_data` and `deposits`, the two fields EIP-8015 removes. The
    /// bid is carried over as is: a caller building a heze body gives it its
    /// heze shape (`inclusion_list_bits`) first.
    fn from(body: super::gloas::BeaconBlockBody) -> Self {
        Self {
            randao_reveal: body.randao_reveal,
            graffiti: body.graffiti,
            proposer_slashings: body.proposer_slashings,
            attester_slashings: body.attester_slashings,
            attestations: body.attestations,
            voluntary_exits: body.voluntary_exits,
            sync_aggregate: body.sync_aggregate,
            bls_to_execution_changes: body.bls_to_execution_changes,
            signed_execution_payload_bid: body.signed_execution_payload_bid,
            payload_attestations: body.payload_attestations,
            parent_execution_requests: body.parent_execution_requests,
        }
    }
}

impl From<BeaconBlockBody> for super::gloas::BeaconBlockBody {
    /// The reverse of the conversion above, with the removed fields at their
    /// defaults, for code that reads a body through gloas's shape.
    fn from(body: BeaconBlockBody) -> Self {
        Self {
            randao_reveal: body.randao_reveal,
            eth1_data: Default::default(),
            graffiti: body.graffiti,
            proposer_slashings: body.proposer_slashings,
            attester_slashings: body.attester_slashings,
            attestations: body.attestations,
            deposits: Default::default(),
            voluntary_exits: body.voluntary_exits,
            sync_aggregate: body.sync_aggregate,
            bls_to_execution_changes: body.bls_to_execution_changes,
            signed_execution_payload_bid: body.signed_execution_payload_bid,
            payload_attestations: body.payload_attestations,
            parent_execution_requests: body.parent_execution_requests,
        }
    }
}

impl From<super::gloas::BeaconState> for BeaconState {
    /// Drops the four fields EIP-8015 removes (`eth1_data`, `eth1_data_votes`,
    /// `eth1_deposit_index`, `deposit_requests_start_index`) and keeps the rest
    /// untouched, `fork` and the bid's shape included: `upgrade_to_heze` sets
    /// those two itself.
    fn from(pre: super::gloas::BeaconState) -> Self {
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
        }
    }
}
