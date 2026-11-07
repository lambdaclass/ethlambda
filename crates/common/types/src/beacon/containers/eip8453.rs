//! Containers EIP-8453 ("Decoupled Consensus") introduces or reshapes.
//!
//! Transcribed from `specs/_features/eip8453/beacon-chain.md` at
//! ethereum/consensus-specs commit `0f4fa3ffdd26ec083ff4dba65645d81433178413`
//! (branch `decoupled-consensus`); see [`crate::beacon::fork::ForkName::Eip8453`].
//!
//! The fork replaces Casper FFG with a finality gadget whose chain state lives
//! in the beacon state: the attestation names a height pair (a target vote or
//! a timeout, [`AttestationData::target`]/[`AttestationData::timeout`]) and an
//! optional finality pair ([`AttestationData::finality`]), and the state keeps
//! the target, justified and finalized [`HeightCheckpoint`]s, the per-height
//! participation lists, and the pending justifications
//! ([`PendingFinality`]). It also adds the available chain's payload to the
//! block: [`HeadVote`]s with their support bits.
//!
//! [`BeaconState`] removes the epoch participation and Casper FFG fields and
//! leaves their positions as gaps in its progressive layout (width 57, gaps at
//! 8, 9, 10, 15, 16, 17, 18, 19, 20 and 28), so no generalized index is
//! reused; `finalized_checkpoint` keeps its name but moves, with a new type.
//! [`BeaconBlockBody`] appends three fields to heze's (width 16, gaps at 1
//! and 6). Every container here that the specification does not redefine is
//! heze's (and gloas's) own, reused from [`super::gloas`] and
//! [`super::heze`].

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::{ProgressiveBitlist, ProgressiveList, SszBitvector, SszList, SszVector};

use super::altair::{SyncAggregate, SyncCommittee};
use super::fulu::ProposerLookahead;
use super::gloas::{
    BlsToExecutionChanges, BuilderIndex, BuilderPendingPayments, BuilderPendingWithdrawals,
    Builders, ExecutionPayloadAvailability, ExecutionPayloadBid, ExecutionRequests,
    InactivityScores, PayloadAttestations, PayloadTimelinessCommitteeWindow, PendingConsolidations,
    PendingDeposits, PendingPartialWithdrawals, ProposerSlashings, SignedExecutionPayloadBid,
    VoluntaryExits, Withdrawals,
};
use super::heze::InclusionListBits;
use super::shared::{
    BeaconBlockHeader, BlockRoots, Fork, HistoricalRoots, HistoricalSummaries, ProgressiveBalances,
    ProgressiveValidators, RandaoMixes, Slashings, StateRoots,
};
use crate::beacon::preset;
use crate::beacon::primitives::{
    BlsSignature, Bytes32, CommitteeIndex, Epoch, ExecutionBlockHash, Gwei, ParticipationFlags,
    Root, Slot, ValidatorIndex, WithdrawalIndex,
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// `Height`: a height of the finality gadget. A plain `u64` alias, the
/// convention [`crate::beacon::primitives`] uses for every spec integer type.
pub type Height = u64;

/// `Round`: a round number. A round spans `SLOTS_PER_ROUND` slots, in which
/// each active validator casts one FG attestation and after which the FG
/// settles rewards and inactivity.
pub type Round = u64;

/// `AttestationCommittee`: an attestation committee of an epoch. Built by
/// `get_attestation_committee`; never part of a container, so a plain list.
pub type AttestationCommittee = ProgressiveList<ValidatorIndex>;

/// `AttestationCommitteeBits`: which attestation committees of an epoch
/// participate in an [`Attestation`].
pub type AttestationCommitteeBits = SszBitvector<{ preset::ATTESTATION_COMMITTEES_PER_ROUND }>;

/// `HeadVoteCommittee`: the head vote committee of a slot.
pub type HeadVoteCommittee = SszVector<ValidatorIndex, { preset::HEAD_VOTE_COMMITTEE_SIZE }>;

/// `HeadVoteCommitteeBits`: one bit per head vote committee member, in
/// committee order.
pub type HeadVoteCommitteeBits = SszBitvector<{ preset::HEAD_VOTE_COMMITTEE_SIZE }>;

/// `HeadVoteCommitteeIndices`: the validators participating in a head vote.
pub type HeadVoteCommitteeIndices = SszList<ValidatorIndex, { preset::HEAD_VOTE_COMMITTEE_SIZE }>;

/// `HeadVoteCommitteeWindow`: the cached head vote committees of the
/// previous, current, and lookahead epochs.
pub type HeadVoteCommitteeWindow =
    SszVector<HeadVoteCommittee, { preset::HEAD_VOTE_COMMITTEE_WINDOW_LENGTH }>;

/// `HeadVoteParticipation`: the seats of each slot's head vote committee that
/// voted for the block of that slot, for the previous and current epochs.
pub type HeadVoteParticipation =
    SszVector<HeadVoteCommitteeBits, { preset::HEAD_VOTE_PARTICIPATION_LENGTH }>;

/// `HeadVoteSupportBits`: one bit per voter of a head vote, in the order of
/// its `voter_indices`, set when the proposer counted that vote as support.
pub type HeadVoteSupportBits = ProgressiveBitlist;

/// `HeadVoteSupport`: the support bits of each head vote in a block.
pub type HeadVoteSupport = ProgressiveList<HeadVoteSupportBits>;

/// `HeadVotes`: the head votes included in a block.
pub type HeadVotes = ProgressiveList<HeadVote>;

/// `HeightParticipation`: whether each validator in the registry voted at a
/// height, in validator index order.
pub type HeightParticipation = ProgressiveList<bool>;

/// `LegacyAttesterSlashings`: slashings of attestations made before the
/// upgrade, in heze's (and gloas's) [`super::gloas::AttesterSlashing`] shape.
pub type LegacyAttesterSlashings = ProgressiveList<super::gloas::AttesterSlashing>;

/// `PendingFinalities`: the justifications on the chain that are not yet
/// finalized, in increasing order of height.
pub type PendingFinalities = SszList<PendingFinality, { preset::PENDING_FINALITY_WINDOW }>;

/// `RoundParticipation`: the participation flags of each validator for a
/// round.
pub type RoundParticipation = ProgressiveList<ParticipationFlags>;

/// The attesters an [`Attestation`] covers, one bit per member of the
/// committees its `committee_bits` names, concatenated. Gloas's progressive
/// bitlist, unchanged.
pub type AggregationBits = ProgressiveBitlist;
/// The attesters an [`IndexedAttestation`] names. Gloas's, unchanged.
pub type AttestingIndices = ProgressiveList<ValidatorIndex>;
/// Attestations included in a block, of this fork's [`Attestation`].
pub type Attestations = ProgressiveList<Attestation>;
/// Attester slashings included in a block, of this fork's [`AttesterSlashing`].
pub type AttesterSlashings = ProgressiveList<AttesterSlashing>;

// ---------------------------------------------------------------------------
// Containers
// ---------------------------------------------------------------------------

/// `HeightCheckpoint`: a height of the finality gadget and the block root at
/// it. The all-zero value, [`HeightCheckpoint::empty`], stands for an absent
/// finality pair.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct HeightCheckpoint {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub height: Height,
    pub root: Root,
}

impl HeightCheckpoint {
    /// `HeightCheckpoint.empty()`: height zero, zero root.
    pub const fn empty() -> Self {
        Self {
            height: 0,
            root: Root::ZERO,
        }
    }

    /// Whether this is [`Self::empty`].
    pub fn is_empty(&self) -> bool {
        *self == Self::empty()
    }
}

/// `PendingFinality`: a justification the chain has not finalized yet, with
/// the slot of its target block and which validators' finality pairs for it
/// have been counted.
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
pub struct PendingFinality {
    pub checkpoint: HeightCheckpoint,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub slot: Slot,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub participation: HeightParticipation,
}

/// `HeadVoteData`: what a head vote is cast for. `payload_status` is the
/// byte gloas's fork choice gives its `PayloadStatus`
/// (`crate::beacon::constants::PAYLOAD_STATUS_*`); any other value decodes
/// and is refused by `process_head_vote`.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct HeadVoteData {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub slot: Slot,
    pub beacon_block_root: Root,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub payload_status: u8,
}

/// `HeadVote`: an aggregate head vote, as included in a block.
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
#[ssz(progressive_container)]
pub struct HeadVote {
    #[serde(with = "crate::beacon::serde_helpers::quoted_u64_seq")]
    pub voter_indices: HeadVoteCommitteeIndices,
    pub data: HeadVoteData,
    pub signature: BlsSignature,
}

/// `HeadVoteMessage`: one committee member's head vote, as gossiped.
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
pub struct HeadVoteMessage {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub validator_index: ValidatorIndex,
    pub data: HeadVoteData,
    pub signature: BlsSignature,
}

/// `AttestationData` (modified): the height pair (`target`, `timeout`) and
/// the finality pair (`finality`). `slot`, `index`, `beacon_block_root`,
/// `source` and the epoch `target` are gone.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct AttestationData {
    pub target: HeightCheckpoint,
    pub timeout: bool,
    pub finality: HeightCheckpoint,
}

/// `SingleAttestation` (modified): electra's, over this fork's
/// [`AttestationData`], plus the `epoch` whose committees `committee_index`
/// refers to.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct SingleAttestation {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub committee_index: CommitteeIndex,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub attester_index: ValidatorIndex,
    pub data: AttestationData,
    pub signature: BlsSignature,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub epoch: Epoch,
}

/// `Attestation` (modified): `committee_bits` now selects attestation
/// committees ([`AttestationCommitteeBits`]), and `epoch`, which is not
/// signed, says which epoch's committees `committee_bits` and
/// `aggregation_bits` refer to and selects the signature domain.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
#[ssz(progressive_container)]
pub struct Attestation {
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex")]
    pub aggregation_bits: AggregationBits,
    pub data: AttestationData,
    pub signature: BlsSignature,
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex")]
    pub committee_bits: AttestationCommitteeBits,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub epoch: Epoch,
}

/// `IndexedAttestation` (modified): gloas's, plus `epoch`.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
#[ssz(progressive_container)]
pub struct IndexedAttestation {
    #[serde(
        serialize_with = "crate::beacon::serde_helpers::quoted_u64_seq::serialize",
        deserialize_with = "crate::beacon::serde_helpers::quoted_u64_seq::deserialize_progressive"
    )]
    pub attesting_indices: AttestingIndices,
    pub data: AttestationData,
    pub signature: BlsSignature,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub epoch: Epoch,
}

/// `AttesterSlashing`: the same container as every earlier fork's, over this
/// fork's [`IndexedAttestation`]. The specification does not restate it; it
/// changes because `IndexedAttestation` does.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct AttesterSlashing {
    pub attestation_1: IndexedAttestation,
    pub attestation_2: IndexedAttestation,
}

// ---------------------------------------------------------------------------
// Blocks
// ---------------------------------------------------------------------------

/// `BeaconBlockBody` (modified): heze's, with `attester_slashings` now over
/// this fork's attestations, plus `head_votes`, `head_vote_support` and
/// `legacy_attester_slashings` appended. `eth1_data` and `deposits` stay gaps
/// (positions 1 and 6).
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
#[ssz(progressive_container, active_fields = [1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1])]
pub struct BeaconBlockBody {
    pub randao_reveal: BlsSignature,
    pub graffiti: Bytes32,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub proposer_slashings: ProposerSlashings,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub attester_slashings: AttesterSlashings,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub attestations: Attestations,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub voluntary_exits: VoluntaryExits,
    pub sync_aggregate: SyncAggregate,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub bls_to_execution_changes: BlsToExecutionChanges,
    pub signed_execution_payload_bid: SignedExecutionPayloadBid,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub payload_attestations: PayloadAttestations,
    pub parent_execution_requests: ExecutionRequests,
    /// The available chain's head votes of the previous and current epochs.
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub head_votes: HeadVotes,
    /// One support bitlist per entry of `head_votes`.
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex_seq")]
    pub head_vote_support: HeadVoteSupport,
    /// Slashings of attestations made before the upgrade, in heze's shape.
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub legacy_attester_slashings: LegacyAttesterSlashings,
}

impl BeaconBlockBody {
    /// An empty body: no operations, and a default execution payload bid in
    /// heze's shape (an all-zero `inclusion_list_bits`), which this fork
    /// keeps.
    pub fn empty() -> Self {
        let mut body = Self::default();
        body.signed_execution_payload_bid
            .message
            .inclusion_list_bits = Some(InclusionListBits::new());
        body
    }
}

/// The block, over [`BeaconBlockBody`].
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

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// `BeaconState` (modified): heze's without the epoch participation lists
/// and the Casper FFG fields, which stay as gaps (positions 15 to 20; 8, 9,
/// 10 and 28 are heze's own eth1 gaps), plus the finality gadget's and the
/// head votes' fields appended at positions 46 to 56.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot)]
#[ssz(progressive_container, active_fields = [1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])]
pub struct BeaconState {
    // -- Versioning --
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub genesis_time: u64,
    pub genesis_validators_root: Root,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub slot: Slot,
    pub fork: Fork,

    // -- History --
    pub latest_block_header: BeaconBlockHeader,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub block_roots: BlockRoots,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub state_roots: StateRoots,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub historical_roots: HistoricalRoots,

    // -- Registry --
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

    // -- Inactivity --
    #[serde(with = "crate::beacon::serde_helpers::quoted_u64_seq")]
    pub inactivity_scores: InactivityScores,

    // -- Sync committees --
    pub current_sync_committee: SyncCommittee,
    pub next_sync_committee: SyncCommittee,

    // -- Execution --
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
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub builders: Builders,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub next_withdrawal_builder_index: BuilderIndex,
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex")]
    pub execution_payload_availability: ExecutionPayloadAvailability,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub builder_pending_payments: BuilderPendingPayments,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub builder_pending_withdrawals: BuilderPendingWithdrawals,
    pub latest_execution_payload_bid: ExecutionPayloadBid,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub payload_expected_withdrawals: Withdrawals,
    #[serde(serialize_with = "crate::beacon::serde_helpers::nested_quoted_u64_seq::serialize")]
    pub ptc_window: PayloadTimelinessCommitteeWindow,

    // -- Finality gadget (EIP-8453) --
    /// The target of the current height. Its root is left empty by
    /// `advance_height` and filled in by the next `process_slot`, since a
    /// post-state cannot hold its own block's root.
    pub target_checkpoint: HeightCheckpoint,
    /// The latest justified checkpoint.
    pub justified_checkpoint: HeightCheckpoint,
    /// The latest finalized checkpoint: same name as Casper FFG's, new type
    /// and position.
    pub finalized_checkpoint: HeightCheckpoint,
    /// The slot of the block that brought the chain into the current height.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub target_slot: Slot,
    /// The slot of the finalized block.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub finalized_slot: Slot,
    /// Which validators cast a target vote for the current target.
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub target_participation: HeightParticipation,
    /// Which validators cast a target vote or a timeout at the current height.
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub progress_participation: HeightParticipation,
    /// The participation flags of the current round.
    #[serde(with = "crate::beacon::serde_helpers::quoted_u64_seq")]
    pub round_participation: RoundParticipation,
    /// The unfinalized justifications, oldest first.
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub pending_finality: PendingFinalities,

    // -- Head votes (EIP-8453) --
    /// Per slot of the previous and current epochs, the committee seats whose
    /// head vote for that slot's block a block recorded.
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex_seq")]
    pub head_vote_participation: HeadVoteParticipation,
    /// The cached head vote committees, refreshed each epoch by
    /// `process_head_vote_committee_window`.
    #[serde(serialize_with = "crate::beacon::serde_helpers::nested_quoted_u64_seq::serialize")]
    pub head_vote_committee_window: HeadVoteCommitteeWindow,
}

/// An all-zero [`HeadVoteParticipation`], the value `HeadVoteParticipation()`
/// takes in the specification.
pub fn empty_head_vote_participation() -> HeadVoteParticipation {
    vec![HeadVoteCommitteeBits::new(); preset::HEAD_VOTE_PARTICIPATION_LENGTH]
        .try_into()
        .expect("the vector is built at its exact length")
}

/// An all-zero [`HeadVoteCommittee`], the value `HeadVoteCommittee()` takes in
/// the specification.
pub fn empty_head_vote_committee() -> HeadVoteCommittee {
    vec![0; preset::HEAD_VOTE_COMMITTEE_SIZE]
        .try_into()
        .expect("the vector is built at its exact length")
}

/// An all-zero [`HeadVoteCommitteeWindow`], `HeadVoteCommitteeWindow()`.
pub fn empty_head_vote_committee_window() -> HeadVoteCommitteeWindow {
    vec![empty_head_vote_committee(); preset::HEAD_VOTE_COMMITTEE_WINDOW_LENGTH]
        .try_into()
        .expect("the vector is built at its exact length")
}

// The fork choice engine (`ethlambda-decoupled`) works on the chain-agnostic
// copies in `crate::decoupled`, which have the same fields (the engine names
// `beacon_block_root` `block_root`, since lean votes for its own blocks).

impl From<HeightCheckpoint> for crate::decoupled::HeightCheckpoint {
    fn from(checkpoint: HeightCheckpoint) -> Self {
        Self::new(checkpoint.height, checkpoint.root)
    }
}

impl From<crate::decoupled::HeightCheckpoint> for HeightCheckpoint {
    fn from(checkpoint: crate::decoupled::HeightCheckpoint) -> Self {
        Self {
            height: checkpoint.height,
            root: checkpoint.root,
        }
    }
}

impl From<HeadVoteData> for crate::decoupled::HeadVoteData {
    fn from(data: HeadVoteData) -> Self {
        Self {
            slot: data.slot,
            block_root: data.beacon_block_root,
            payload_status: data.payload_status,
        }
    }
}

impl From<crate::decoupled::HeadVoteData> for HeadVoteData {
    fn from(data: crate::decoupled::HeadVoteData) -> Self {
        Self {
            slot: data.slot,
            beacon_block_root: data.block_root,
            payload_status: data.payload_status,
        }
    }
}

impl From<&HeadVoteMessage> for crate::decoupled::HeadVoteMessage {
    /// The engine's message is the unsigned part: the signature is checked
    /// before a message reaches the engine.
    fn from(message: &HeadVoteMessage) -> Self {
        Self {
            validator_index: message.validator_index,
            data: message.data.into(),
        }
    }
}

impl From<AttestationData> for crate::decoupled::AttestationData {
    fn from(data: AttestationData) -> Self {
        Self {
            target: data.target.into(),
            timeout: data.timeout,
            finality: data.finality.into(),
        }
    }
}

impl From<crate::decoupled::AttestationData> for AttestationData {
    fn from(data: crate::decoupled::AttestationData) -> Self {
        Self {
            target: data.target.into(),
            timeout: data.timeout,
            finality: data.finality.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use libssz::{SszDecode as _, SszEncode as _};

    use super::*;

    #[test]
    fn the_engines_copies_hash_and_encode_like_the_beacon_containers() {
        let data = HeadVoteData {
            slot: 9,
            beacon_block_root: Root::repeat_byte(3),
            payload_status: 1,
        };
        let engine: crate::decoupled::HeadVoteData = data.into();
        assert_eq!(engine.to_ssz(), data.to_ssz());
        assert_eq!(engine.hash_tree_root(), data.hash_tree_root());
        assert_eq!(HeadVoteData::from(engine), data);

        let checkpoint = HeightCheckpoint {
            height: 4,
            root: Root::repeat_byte(5),
        };
        let engine: crate::decoupled::HeightCheckpoint = checkpoint.into();
        assert_eq!(engine.hash_tree_root(), checkpoint.hash_tree_root());
        assert_eq!(HeightCheckpoint::from(engine), checkpoint);

        let attestation = AttestationData {
            target: checkpoint,
            timeout: true,
            finality: HeightCheckpoint::empty(),
        };
        let engine: crate::decoupled::AttestationData = attestation.into();
        assert_eq!(engine.hash_tree_root(), attestation.hash_tree_root());
        assert_eq!(AttestationData::from(engine), attestation);
    }
    use crate::beacon::primitives::HashTreeRoot as _;

    #[test]
    fn the_empty_height_checkpoint_is_all_zero() {
        assert_eq!(HeightCheckpoint::empty(), HeightCheckpoint::default());
        assert!(HeightCheckpoint::empty().is_empty());
        let named = HeightCheckpoint {
            height: 1,
            root: Root::ZERO,
        };
        assert!(!named.is_empty());
    }

    #[test]
    fn attestation_data_is_fixed_size_and_round_trips() {
        let data = AttestationData {
            target: HeightCheckpoint {
                height: 7,
                root: Root::repeat_byte(1),
            },
            timeout: true,
            finality: HeightCheckpoint {
                height: 3,
                root: Root::repeat_byte(2),
            },
        };
        let bytes = data.to_ssz();
        // Two 40-byte checkpoints around a one-byte boolean.
        assert_eq!(bytes.len(), 40 + 1 + 40);
        assert_eq!(AttestationData::from_ssz_bytes(&bytes).unwrap(), data);
    }

    #[test]
    fn a_body_round_trips_with_head_votes_and_support() {
        let mut body = BeaconBlockBody::empty();
        let mut voter_indices = HeadVoteCommitteeIndices::default();
        voter_indices.push(3).unwrap();
        voter_indices.push(5).unwrap();
        body.head_votes.push(HeadVote {
            voter_indices,
            data: HeadVoteData {
                slot: 9,
                beacon_block_root: Root::repeat_byte(4),
                payload_status: crate::beacon::constants::PAYLOAD_STATUS_PENDING,
            },
            signature: BlsSignature::default(),
        });
        let mut support = HeadVoteSupportBits::with_length(2);
        support.set(1, true).unwrap();
        body.head_vote_support.push(support);

        let bytes = body.to_ssz();
        let decoded = BeaconBlockBody::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(decoded, body);
        assert_eq!(decoded.hash_tree_root(), body.hash_tree_root());
    }

    /// The gaps keep a field's generalized index: a body with the three new
    /// fields empty does not share heze's root (more active fields are mixed
    /// in), but every field it shares with heze sits at the same position, so
    /// the two encodings agree byte for byte up to heze's last field.
    #[test]
    fn the_body_extends_hezes_encoding() {
        let heze_body = super::super::heze::BeaconBlockBody::empty();
        let body = BeaconBlockBody::empty();
        let heze_bytes = heze_body.to_ssz();
        let bytes = body.to_ssz();
        // Heze's fixed part holds 11 fields; this one adds three offsets, so
        // the variable-size tails shift by 12 bytes but the fixed-size prefix
        // (randao reveal and graffiti) matches.
        assert_eq!(bytes[..96 + 32], heze_bytes[..96 + 32]);
        assert_ne!(body.hash_tree_root(), heze_body.hash_tree_root());
    }

    #[test]
    fn empty_vectors_have_their_preset_lengths() {
        assert_eq!(
            empty_head_vote_participation().len(),
            2 * preset::SLOTS_PER_EPOCH as usize
        );
        assert_eq!(
            empty_head_vote_committee_window().len(),
            (preset::MIN_SEED_LOOKAHEAD as usize + 2) * preset::SLOTS_PER_EPOCH as usize
        );
        assert_eq!(
            empty_head_vote_committee().len(),
            preset::HEAD_VOTE_COMMITTEE_SIZE
        );
    }
}
