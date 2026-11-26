//! Containers whose shape is specific to gloas.
//!
//! Gloas bundles several EIPs. EIP-7732 (ePBS: enshrined proposer-builder
//! separation) moves the execution payload out of the beacon block and into
//! a separate, builder-signed [`ExecutionPayloadEnvelope`]: a proposer now
//! only commits to a builder's [`ExecutionPayloadBid`] at block-production
//! time, and the payload itself is revealed and attested to afterward, by a
//! payload timeliness committee ([`PayloadAttestation`]) rather than by the
//! attesters who voted on the block. [`Builder`] and its pending-payment and
//! pending-withdrawal queues are the registry this introduces alongside the
//! validator one, since a builder now escrows a balance and receives
//! payments the same way a validator earns rewards.
//!
//! EIP-7688 makes most of the specification's lists, and every "big"
//! container (`Attestation`, `BeaconBlockBody`, `BeaconState`,
//! `ExecutionPayload`, `ExecutionRequests`, `NewPayloadRequest`, and their
//! nested attestation containers), progressive: an EIP-7916 `ProgressiveList`
//! or an EIP-7495 progressive container in place of a bounded `SszList` or a
//! fixed field layout. `BeaconState.validators` and `.balances` are the one
//! exception that stays tree-backed rather than becoming a plain
//! `libssz_types::ProgressiveList`: see [`super::shared::ProgressiveValidators`]
//! and [`super::shared::ProgressiveBalances`].
//!
//! EIP-8282 adds builder deposit and exit requests to [`ExecutionRequests`],
//! the execution-layer-triggered path [`Builder`]s are onboarded and retired
//! through (mirroring EIP-6110/7002/7251's validator deposit, withdrawal, and
//! consolidation requests). EIP-8045 and EIP-8061 do not reshape any
//! container this module defines.
//!
//! `BeaconBlockBody`, `Attestation`, `IndexedAttestation`, and
//! `AttesterSlashing` are the phase0/electra shapes that gained the fields
//! ePBS moves out or in (`signed_execution_payload_bid`,
//! `payload_attestations`, `parent_execution_requests` on the body) or that
//! EIP-7688 alone reshapes into a progressive container without changing a
//! single field. `AggregateAndProof` and `SignedAggregateAndProof` are the
//! electra shape, unmodified except that `aggregate` is now this module's own
//! wider [`Attestation`]. `DataColumnSidecar` drops the header and inclusion
//! proof fulu's carried, since a Gloas sidecar no longer needs to prove its
//! commitments against a block body directly: they are read from
//! `signed_execution_payload_bid.message.blob_kzg_commitments` instead.
//! `PartialDataColumnSidecar`, `PartialDataColumnPartsMetadata`, and
//! `PartialDataColumnGroupID` are gloas's own versions of fulu's Partial
//! Message Extension wire types (`gloas/partial-columns/p2p-interface.md`),
//! not reused from [`super::fulu`]: `CellsBitList` becomes progressive here,
//! which changes the merkleization of every container holding one even where
//! its field list looks unchanged, `PartialDataColumnSidecar` drops `header`
//! entirely, and `PartialDataColumnGroupID` gains `slot`.

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::{ProgressiveBitlist, ProgressiveList};

use super::altair::{SyncAggregate, SyncCommittee};
use super::bellatrix::{ExtraData, LogsBloom};
use super::capella::{SignedBLSToExecutionChange, Withdrawal};
use super::deneb::VersionedHashes;
use super::electra::{
    CommitteeBits, ConsolidationRequest, DepositRequest, PendingConsolidation, PendingDeposit,
    PendingPartialWithdrawal, WithdrawalRequest,
};
use super::fulu::{Cell, ProposerLookahead};
use super::shared::{
    AttestationData, BeaconBlockHeader, BlockRoots, Checkpoint, Deposit, Eth1Data, Eth1DataVotes,
    Fork, HistoricalRoots, HistoricalSummaries, JustificationBits, ProgressiveBalances,
    ProgressiveValidators, ProposerSlashing, RandaoMixes, SignedVoluntaryExit, Slashings,
    StateRoots,
};
use crate::beacon::config::Config;
use crate::beacon::preset;
use crate::beacon::preset_sized::{PresetBitvector, PresetList, PresetVector};
use crate::beacon::primitives::{
    BlsPubkey, BlsSignature, Bytes32, ColumnIndex, Epoch, ExecutionAddress, ExecutionBlockHash,
    Gwei, KzgCommitment, KzgProof, Root, Slot, Uint256, ValidatorIndex, WithdrawalIndex,
};
use crate::beacon::signing::compute_epoch_at_slot;

// ---------------------------------------------------------------------------
// Collection aliases (EIP-7688: progressive where the spec says so)
// ---------------------------------------------------------------------------

/// The index of a [`Builder`] in the builder registry. A plain `u64` alias,
/// the same convention [`crate::beacon::primitives`] uses for every other
/// spec index type, kept here rather than there because nothing outside
/// gloas reads it.
pub type BuilderIndex = u64;

/// The attesters covered by an [`Attestation`]. Unbounded from gloas on,
/// unlike every earlier fork's `SszBitlist<MAX_VALIDATORS_PER_SLOT>`.
pub type AggregationBits = ProgressiveBitlist;
/// The attesters covered by an [`IndexedAttestation`], named explicitly.
pub type AttestingIndices = ProgressiveList<ValidatorIndex>;
/// Attestations included in a block.
pub type Attestations = ProgressiveList<Attestation>;
/// Evidence of conflicting attestations included in a block.
pub type AttesterSlashings = ProgressiveList<AttesterSlashing>;
/// Proposer slashings included in a block.
pub type ProposerSlashings = ProgressiveList<ProposerSlashing>;
/// Deposits included in a block.
pub type Deposits = ProgressiveList<Deposit>;
/// Voluntary exits included in a block.
pub type VoluntaryExits = ProgressiveList<SignedVoluntaryExit>;
/// BLS-to-execution changes included in a block.
pub type BlsToExecutionChanges = ProgressiveList<SignedBLSToExecutionChange>;
/// The KZG commitments an [`ExecutionPayloadBid`] carries for the blobs its
/// payload will reveal.
pub type BlobKzgCommitments = ProgressiveList<KzgCommitment>;
/// An opaque execution-layer transaction. Unbounded from gloas on, unlike
/// [`super::bellatrix::Transaction`]'s `SszList<u8, MAX_BYTES_PER_TRANSACTION>`.
pub type Transaction = ProgressiveList<u8>;
/// The transactions in an [`ExecutionPayload`].
pub type Transactions = ProgressiveList<Transaction>;
/// The withdrawals in an [`ExecutionPayload`], or the sweep's expected set
/// cached on the state ([`BeaconState::payload_expected_withdrawals`]).
pub type Withdrawals = ProgressiveList<Withdrawal>;
/// The serialized block access list of an [`ExecutionPayload`] (EIP-7928).
pub type BlockAccessList = ProgressiveList<u8>;
/// One dependency witness of an [`ExecutionPayload`]: a byte string only the
/// execution layer interprets, like a [`Transaction`].
pub type DependencyWitness = ProgressiveList<u8>;
/// The dependency witnesses in an [`ExecutionPayload`].
pub type DependencyWitnesses = ProgressiveList<DependencyWitness>;
/// Execution-layer-triggered deposit requests.
pub type DepositRequests = ProgressiveList<DepositRequest>;
/// Execution-layer-triggered withdrawal requests.
pub type WithdrawalRequests = ProgressiveList<WithdrawalRequest>;
/// Execution-layer-triggered consolidation requests.
pub type ConsolidationRequests = ProgressiveList<ConsolidationRequest>;
/// Execution-layer-triggered builder deposit requests (EIP-8282).
pub type BuilderDepositRequests = ProgressiveList<BuilderDepositRequest>;
/// Execution-layer-triggered builder exit requests (EIP-8282).
pub type BuilderExitRequests = ProgressiveList<BuilderExitRequest>;
/// Per-validator participation flags for one epoch, positionally parallel to
/// the registry.
pub type EpochParticipation = super::shared::ProgressiveEpochParticipation;
/// Per-validator inactivity scores, positionally parallel to the registry.
pub type InactivityScores = ProgressiveList<u64>;
/// Deposits known but not yet credited to the validator registry.
pub type PendingDeposits = ethlambda_ssz_tree::ProgressiveList<
    PendingDeposit,
    std::collections::BTreeMap<usize, PendingDeposit>,
>;
/// Partial withdrawals known but not yet paid out.
pub type PendingPartialWithdrawals = ProgressiveList<PendingPartialWithdrawal>;
/// Validator consolidations known but not yet applied.
pub type PendingConsolidations = ProgressiveList<PendingConsolidation>;
/// The builder registry (EIP-7732), the builder-side counterpart of the
/// validator registry.
pub type Builders = ProgressiveList<Builder>;
/// Builder withdrawals known but not yet paid out, the builder-side
/// counterpart of [`PendingPartialWithdrawals`].
pub type BuilderPendingWithdrawals = ProgressiveList<BuilderPendingWithdrawal>;
/// Builder payments owed for the previous and current epoch. A fixed-length
/// vector rather than a progressive list: the specification bounds it to
/// exactly two epochs' worth, since a payment is settled well before a third
/// epoch could accumulate.
pub type BuilderPendingPayments =
    PresetVector<BuilderPendingPayment, preset::BuilderPendingPaymentsLength>;
/// Bits tracking payload availability for recent slots, indexed by slot
/// modulo `SLOTS_PER_HISTORICAL_ROOT`, the same indexing [`BlockRoots`] uses.
pub type ExecutionPayloadAvailability = PresetBitvector<preset::SlotsPerHistoricalRoot>;
/// Payload attestations included in a block.
pub type PayloadAttestations = ProgressiveList<PayloadAttestation>;
/// The payload timeliness committee of a slot, named explicitly.
pub type PayloadTimelinessCommittee = PresetVector<ValidatorIndex, preset::PtcSize>;
/// The payload timeliness committee members an [`IndexedPayloadAttestation`]
/// names, as a bounded list rather than the fixed-size
/// [`PayloadTimelinessCommittee`]: an attester subset, not the whole
/// committee.
pub type PayloadTimelinessCommitteeIndices = PresetList<ValidatorIndex, preset::PtcSize>;
/// One bit per payload timeliness committee member, in committee order.
pub type PayloadTimelinessCommitteeBits = PresetBitvector<preset::PtcSize>;
/// The cached window of payload timeliness committees
/// [`BeaconState::ptc_window`] holds: the previous, current, and lookahead
/// epochs.
pub type PayloadTimelinessCommitteeWindow =
    PresetVector<PayloadTimelinessCommittee, preset::PtcWindowLength>;
/// One data column, with at most one cell per blob. Unbounded from gloas on,
/// unlike fulu's `SszList<Cell, MAX_BLOB_COMMITMENTS_PER_BLOCK>`.
pub type DataColumn = ProgressiveList<Cell>;
/// The KZG cell proofs behind a [`DataColumn`].
pub type KzgProofs = ProgressiveList<KzgProof>;
/// A bitfield over the cells of a column, one bit per blob (`fulu/partial-columns/p2p-interface.md`,
/// modified for gloas). Unbounded from gloas on, unlike fulu's
/// `SszBitlist<MAX_BLOB_COMMITMENTS_PER_BLOCK>`.
pub type CellsBitList = ProgressiveBitlist;

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

/// A registered builder's record in the builder registry (EIP-7732), the
/// builder-side counterpart of [`super::shared::Validator`].
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
pub struct Builder {
    pub pubkey: BlsPubkey,
    /// Which shape this record is in. Only [`crate::beacon::constants::PAYLOAD_BUILDER_VERSION`]
    /// exists today; the field exists so a future format change has
    /// somewhere to record it.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub version: u8,
    pub execution_address: ExecutionAddress,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub balance: Gwei,
    /// The epoch this builder's deposit was placed, which
    /// `is_active_builder` compares against the finalized checkpoint before
    /// treating the builder as eligible.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub deposit_epoch: Epoch,
    /// `FAR_FUTURE_EPOCH` until this builder initiates an exit, the same
    /// sentinel convention [`super::shared::Validator::withdrawable_epoch`]
    /// uses.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub withdrawable_epoch: Epoch,
}

/// A builder payment owed to a proposer, not yet settled.
///
/// `weight` accumulates the attesting stake behind the block the payment is
/// for, so `settle_builder_payment` can compare it against the quorum
/// threshold before paying `withdrawal` out.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot,
)]
pub struct BuilderPendingPayment {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub weight: Gwei,
    pub withdrawal: BuilderPendingWithdrawal,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub proposer_index: ValidatorIndex,
}

/// A builder withdrawal queued but not yet paid out, the builder-side
/// counterpart of [`super::capella::Withdrawal`].
#[derive(
    Debug, Clone, Default, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot,
)]
pub struct BuilderPendingWithdrawal {
    pub fee_recipient: ExecutionAddress,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub amount: Gwei,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub builder_index: BuilderIndex,
}

/// An execution-layer-triggered builder deposit (EIP-8282), the builder-side
/// counterpart of [`super::electra::DepositRequest`].
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
pub struct BuilderDepositRequest {
    pub pubkey: BlsPubkey,
    pub withdrawal_credentials: Bytes32,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub amount: Gwei,
    pub signature: BlsSignature,
}

/// An execution-layer-triggered builder exit (EIP-8282), the builder-side
/// counterpart of [`super::electra::WithdrawalRequest`]'s full-exit case.
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
pub struct BuilderExitRequest {
    pub source_address: ExecutionAddress,
    pub pubkey: BlsPubkey,
}

// ---------------------------------------------------------------------------
// Payload attestations
// ---------------------------------------------------------------------------

/// What the payload timeliness committee attests to: whether the slot's
/// payload was revealed on time and whether its blob data is available.
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
pub struct PayloadAttestationData {
    pub beacon_block_root: Root,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub slot: Slot,
    pub payload_present: bool,
    pub blob_data_available: bool,
}

/// An aggregate payload timeliness attestation, as included in a block.
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
pub struct PayloadAttestation {
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex")]
    pub aggregation_bits: PayloadTimelinessCommitteeBits,
    pub data: PayloadAttestationData,
    pub signature: BlsSignature,
}

/// One payload timeliness committee member's unaggregated vote, gossiped
/// before an aggregator folds it into a [`PayloadAttestation`].
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
pub struct PayloadAttestationMessage {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub validator_index: ValidatorIndex,
    pub data: PayloadAttestationData,
    pub signature: BlsSignature,
}

/// A [`PayloadAttestation`] with its attesters named rather than bit-encoded,
/// the payload-attestation counterpart of [`IndexedAttestation`].
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
pub struct IndexedPayloadAttestation {
    #[serde(with = "crate::beacon::serde_helpers::quoted_u64_seq")]
    pub attesting_indices: PayloadTimelinessCommitteeIndices,
    pub data: PayloadAttestationData,
    pub signature: BlsSignature,
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

/// A builder's commitment to reveal a payload for a slot (EIP-7732): what a
/// proposer chooses among, and signs over, in place of embedding a payload in
/// the block directly.
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
pub struct ExecutionPayloadBid {
    pub parent_block_hash: ExecutionBlockHash,
    pub parent_block_root: Root,
    pub block_hash: ExecutionBlockHash,
    pub prev_randao: Bytes32,
    pub fee_recipient: ExecutionAddress,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub gas_limit: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub builder_index: BuilderIndex,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub slot: Slot,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub value: Gwei,
    /// What the builder is actually paid, which may fall short of `value` if
    /// the payload is never revealed or attested to as available.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub execution_payment: Gwei,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub blob_kzg_commitments: BlobKzgCommitments,
    /// The root of the [`ExecutionRequests`] this payload's envelope will
    /// carry, committed to here so the bid is binding on the requests too,
    /// not only the payload itself.
    pub execution_requests_root: Root,
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
pub struct SignedExecutionPayloadBid {
    pub message: ExecutionPayloadBid,
    pub signature: BlsSignature,
}

/// The execution-layer-triggered deposit, withdrawal, consolidation, builder
/// deposit, and builder exit requests carried by one execution payload.
///
/// Electra's three request kinds (EIP-6110/7002/7251), plus `builder_deposits`
/// and `builder_exits` (EIP-8282), the execution-layer path [`Builder`]s are
/// onboarded and retired through from the fork onward.
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
pub struct ExecutionRequests {
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub deposits: DepositRequests,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub withdrawals: WithdrawalRequests,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub consolidations: ConsolidationRequests,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub builder_deposits: BuilderDepositRequests,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub builder_exits: BuilderExitRequests,
}

/// The execution layer's block contents, no longer carried inside
/// [`BeaconBlockBody`] but revealed afterward in an [`ExecutionPayloadEnvelope`]
/// (EIP-7732).
///
/// Bellatrix's fields through `block_hash`, unchanged; `transactions` and
/// `withdrawals` become progressive (EIP-7688); `block_access_list`
/// (EIP-7928) and `slot_number` (EIP-8061) are appended. Those nineteen
/// fields are the specification's container. From
/// [`Config::heze_fork_epoch`](crate::beacon::config::Config::heze_fork_epoch)
/// on, a payload has a twentieth, `dependency_witnesses`, which the
/// specification's container does not have (see the field).
///
/// A payload is therefore one of two containers ([`PayloadContainer`]), and
/// which one is a property of the value: `dependency_witnesses` is `None` in
/// the first and `Some` in the second. Its SSZ encoding, decoding and hash
/// tree root are written out below rather than derived, because a derived
/// container has a fixed set of fields. Whether a payload of a given slot may
/// be the one or the other is not decided here: see
/// [`Config::payload_container`].
///
/// There is no `SszDecode` for it, nor for a container that holds one: the
/// bytes do not say which container they are, so a decoder is told
/// ([`Self::from_ssz`]) or works it out from the payload's own slot
/// ([`Self::from_ssz_by_slot`]).
///
/// Not `#[derive(Default)]`: `logs_bloom` is an [`SszVector`], which, like
/// every earlier fork's payload, has no meaningful empty value.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExecutionPayload {
    pub parent_hash: ExecutionBlockHash,
    pub fee_recipient: ExecutionAddress,
    pub state_root: Bytes32,
    pub receipts_root: Bytes32,
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex")]
    pub logs_bloom: LogsBloom,
    pub prev_randao: Bytes32,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub block_number: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub gas_limit: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub gas_used: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub timestamp: u64,
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex")]
    pub extra_data: ExtraData,
    pub base_fee_per_gas: Uint256,
    pub block_hash: ExecutionBlockHash,
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex_seq")]
    pub transactions: Transactions,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub withdrawals: Withdrawals,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub blob_gas_used: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub excess_blob_gas: u64,
    /// The serialized block access list this payload's execution produced
    /// (EIP-7928).
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex")]
    pub block_access_list: BlockAccessList,
    /// The slot this payload was built for (EIP-8061's gas limit schedule
    /// reads it against the schedule rather than the enclosing block's own
    /// slot, since a payload can be revealed a slot late).
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub slot_number: u64,
    /// The execution block's dependency witnesses: post-quantum signatures
    /// the block carries outside its transactions, which the execution
    /// client verifies and the execution block header commits to. Consensus
    /// never reads their contents: it takes them from `engine_getPayloadV6`,
    /// carries them in the envelope, and hands them to `engine_newPayloadV5`.
    ///
    /// `None` is a payload from before
    /// [`Config::heze_fork_epoch`](crate::beacon::config::Config::heze_fork_epoch):
    /// the specification's container, with no such field. `Some` is a payload
    /// from that epoch on, whose container has the field even when the list
    /// is empty, so `Some` of an empty list and `None` encode and hash
    /// differently. It is the last field because a progressive container can
    /// only grow at its end (EIP-7495): every field before it keeps its
    /// generalized index.
    ///
    /// In JSON a payload without the field has no such key.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::beacon::serde_helpers::optional_ssz_hex_seq"
    )]
    pub dependency_witnesses: Option<DependencyWitnesses>,
}

/// Which of its two containers an [`ExecutionPayload`] is. A decoder has to
/// be told, as it is told the fork of a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadContainer {
    /// The specification's nineteen fields.
    Specification,
    /// Those, then `dependency_witnesses`.
    WithWitnesses,
}

/// One variable-size field of a container, kept as its bytes.
///
/// For a container that holds an [`ExecutionPayload`], whose decoder is
/// written out with [`libssz::ContainerDecoder`]: that decoder hands each
/// variable-size field its bytes and nothing else, and a payload needs to be
/// told its container too. The field is taken as this, and decoded from the
/// bytes afterward.
pub struct UndecodedField(pub Vec<u8>);

impl libssz::SszDecode for UndecodedField {
    fn is_fixed_size() -> bool {
        false
    }

    fn fixed_size() -> usize {
        0
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, libssz::DecodeError> {
        Ok(Self(bytes.to_vec()))
    }
}

/// A payload holds dependency witnesses and belongs to a slot whose payloads
/// do not have the field, so no container can hold it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the payload holds dependency witnesses before the epoch payloads carry them from")]
pub struct DependencyWitnessesTooEarly;

impl ExecutionPayload {
    /// The number of fields of the container without `dependency_witnesses`.
    const FIELDS_BEFORE_DEPENDENCY_WITNESSES: usize = 19;

    /// This payload as the container its slot calls for: the one with
    /// `dependency_witnesses` when `carries_witnesses`, the specification's
    /// otherwise.
    ///
    /// For a payload read from an execution client, which says whether the
    /// block has a witness list by sending or leaving out a JSON key. The two
    /// sides must agree on the epoch the list starts at, and this is where
    /// the consensus side has the say. A payload that should have the field
    /// and came without one gets the empty list. A payload that should not
    /// have it loses an empty list. A list that holds witnesses cannot be
    /// dropped, because the execution block commits to it, so that payload is
    /// refused.
    pub fn with_dependency_witnesses_field(
        mut self,
        carries_witnesses: bool,
    ) -> Result<Self, DependencyWitnessesTooEarly> {
        self.dependency_witnesses = match (self.dependency_witnesses.take(), carries_witnesses) {
            (witnesses, true) => Some(witnesses.unwrap_or_default()),
            (Some(witnesses), false) if !witnesses.is_empty() => {
                return Err(DependencyWitnessesTooEarly);
            }
            (_, false) => None,
        };
        Ok(self)
    }

    /// Which container this payload is.
    pub fn container(&self) -> PayloadContainer {
        match self.dependency_witnesses {
            None => PayloadContainer::Specification,
            Some(_) => PayloadContainer::WithWitnesses,
        }
    }

    /// Decodes `bytes` as `container`.
    ///
    /// SSZ carries no tag for the container, so it comes from context, as a
    /// block's fork does in
    /// [`SignedBeaconBlock::from_ssz`](super::SignedBeaconBlock::from_ssz).
    /// The context is the payload's epoch ([`Config::payload_container`]),
    /// which a caller that asked for a payload of some slot knows, and which
    /// [`Self::from_ssz_by_slot`] reads off the bytes for one that does not.
    pub fn from_ssz(
        container: PayloadContainer,
        bytes: &[u8],
    ) -> Result<Self, libssz::DecodeError> {
        Self::decode_container(bytes, container == PayloadContainer::WithWitnesses)
    }

    /// Decodes `bytes` as the container `config` gives the payload's own
    /// slot.
    ///
    /// For a payload that comes with nothing to say which epoch it is of:
    /// from gossip, from a peer's answer, from storage. Both containers hold
    /// `slot_number` at one place, the end of the specification's fixed
    /// part, so it is read before the container is known. The slot is the
    /// payload's word alone: holding it to the slot of the payload's block
    /// is the envelope's rules' to do, as it was.
    pub fn from_ssz_by_slot(config: &Config, bytes: &[u8]) -> Result<Self, libssz::DecodeError> {
        let end = Self::fixed_part_len(false);
        let start = end - <Slot as libssz::SszEncode>::fixed_size();
        let slot_number = bytes
            .get(start..end)
            .ok_or(libssz::DecodeError::InvalidByteLength {
                expected: end,
                got: bytes.len(),
            })?;
        let slot = <Slot as libssz::SszDecode>::from_ssz_bytes(slot_number)?;
        let container = config.payload_container(compute_epoch_at_slot(slot));
        Self::from_ssz(container, bytes)
    }

    /// The length of the container's fixed part: every fixed-size field, and
    /// one offset for each variable-size one. `carries_witnesses` says
    /// whether `dependency_witnesses`, a variable-size field, is one of them.
    fn fixed_part_len(carries_witnesses: bool) -> usize {
        fn fixed<T: libssz::SszEncode>() -> usize {
            T::fixed_size()
        }
        const OFFSET: usize = libssz::BYTES_PER_LENGTH_OFFSET;

        let without_witnesses = fixed::<ExecutionBlockHash>() // parent_hash
            + fixed::<ExecutionAddress>() // fee_recipient
            + fixed::<Bytes32>() // state_root
            + fixed::<Bytes32>() // receipts_root
            + fixed::<LogsBloom>() // logs_bloom
            + fixed::<Bytes32>() // prev_randao
            + fixed::<u64>() // block_number
            + fixed::<u64>() // gas_limit
            + fixed::<u64>() // gas_used
            + fixed::<u64>() // timestamp
            + OFFSET // extra_data
            + fixed::<Uint256>() // base_fee_per_gas
            + fixed::<ExecutionBlockHash>() // block_hash
            + OFFSET // transactions
            + OFFSET // withdrawals
            + fixed::<u64>() // blob_gas_used
            + fixed::<u64>() // excess_blob_gas
            + OFFSET // block_access_list
            + fixed::<u64>(); // slot_number
        if carries_witnesses {
            without_witnesses + OFFSET
        } else {
            without_witnesses
        }
    }

    /// Decodes `bytes` as the container with or without
    /// `dependency_witnesses`, as `carries_witnesses` says.
    fn decode_container(
        bytes: &[u8],
        carries_witnesses: bool,
    ) -> Result<Self, libssz::DecodeError> {
        let mut decoder =
            libssz::ContainerDecoder::new(bytes, Self::fixed_part_len(carries_witnesses))?;

        // The fixed part, in field order: a fixed-size field's value, or a
        // variable-size field's offset.
        let parent_hash = decoder.decode_fixed()?;
        let fee_recipient = decoder.decode_fixed()?;
        let state_root = decoder.decode_fixed()?;
        let receipts_root = decoder.decode_fixed()?;
        let logs_bloom = decoder.decode_fixed()?;
        let prev_randao = decoder.decode_fixed()?;
        let block_number = decoder.decode_fixed()?;
        let gas_limit = decoder.decode_fixed()?;
        let gas_used = decoder.decode_fixed()?;
        let timestamp = decoder.decode_fixed()?;
        decoder.read_variable_offset()?; // extra_data
        let base_fee_per_gas = decoder.decode_fixed()?;
        let block_hash = decoder.decode_fixed()?;
        decoder.read_variable_offset()?; // transactions
        decoder.read_variable_offset()?; // withdrawals
        let blob_gas_used = decoder.decode_fixed()?;
        let excess_blob_gas = decoder.decode_fixed()?;
        decoder.read_variable_offset()?; // block_access_list
        let slot_number = decoder.decode_fixed()?;
        if carries_witnesses {
            decoder.read_variable_offset()?; // dependency_witnesses
        }

        // The variable part, in the order the offsets were read.
        let extra_data = decoder.decode_variable()?;
        let transactions = decoder.decode_variable()?;
        let withdrawals = decoder.decode_variable()?;
        let block_access_list = decoder.decode_variable()?;
        let dependency_witnesses = if carries_witnesses {
            Some(decoder.decode_variable()?)
        } else {
            None
        };

        Ok(Self {
            parent_hash,
            fee_recipient,
            state_root,
            receipts_root,
            logs_bloom,
            prev_randao,
            block_number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            base_fee_per_gas,
            block_hash,
            transactions,
            withdrawals,
            blob_gas_used,
            excess_blob_gas,
            block_access_list,
            slot_number,
            dependency_witnesses,
        })
    }
}

impl libssz::SszEncode for ExecutionPayload {
    fn is_fixed_size() -> bool {
        false
    }

    fn fixed_size() -> usize {
        0
    }

    fn encoded_len(&self) -> usize {
        Self::fixed_part_len(self.dependency_witnesses.is_some())
            + self.extra_data.encoded_len()
            + self.transactions.encoded_len()
            + self.withdrawals.encoded_len()
            + self.block_access_list.encoded_len()
            + self
                .dependency_witnesses
                .as_ref()
                .map_or(0, libssz::SszEncode::encoded_len)
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let fixed_part_len = Self::fixed_part_len(self.dependency_witnesses.is_some());
        let mut encoder =
            libssz::ContainerEncoder::with_capacity(buf, fixed_part_len, self.encoded_len());
        encoder.append_fixed(&self.parent_hash);
        encoder.append_fixed(&self.fee_recipient);
        encoder.append_fixed(&self.state_root);
        encoder.append_fixed(&self.receipts_root);
        encoder.append_fixed(&self.logs_bloom);
        encoder.append_fixed(&self.prev_randao);
        encoder.append_fixed(&self.block_number);
        encoder.append_fixed(&self.gas_limit);
        encoder.append_fixed(&self.gas_used);
        encoder.append_fixed(&self.timestamp);
        encoder.append_variable(&self.extra_data);
        encoder.append_fixed(&self.base_fee_per_gas);
        encoder.append_fixed(&self.block_hash);
        encoder.append_variable(&self.transactions);
        encoder.append_variable(&self.withdrawals);
        encoder.append_fixed(&self.blob_gas_used);
        encoder.append_fixed(&self.excess_blob_gas);
        encoder.append_variable(&self.block_access_list);
        encoder.append_fixed(&self.slot_number);
        if let Some(dependency_witnesses) = &self.dependency_witnesses {
            encoder.append_variable(dependency_witnesses);
        }
        encoder.finalize();
    }
}

impl libssz_merkle::HashTreeRoot for ExecutionPayload {
    /// A progressive container's root (EIP-7495): the progressive
    /// merkleization of its fields' roots, mixed in with which fields are
    /// active. Every field of either container is active, so the second
    /// value is one bit per field: nineteen bits without
    /// `dependency_witnesses`, twenty with it.
    fn hash_tree_root(&self, hasher: &impl libssz_merkle::Sha256Hasher) -> libssz_merkle::Node {
        let mut field_roots = vec![
            self.parent_hash.hash_tree_root(hasher),
            self.fee_recipient.hash_tree_root(hasher),
            self.state_root.hash_tree_root(hasher),
            self.receipts_root.hash_tree_root(hasher),
            self.logs_bloom.hash_tree_root(hasher),
            self.prev_randao.hash_tree_root(hasher),
            self.block_number.hash_tree_root(hasher),
            self.gas_limit.hash_tree_root(hasher),
            self.gas_used.hash_tree_root(hasher),
            self.timestamp.hash_tree_root(hasher),
            self.extra_data.hash_tree_root(hasher),
            self.base_fee_per_gas.hash_tree_root(hasher),
            self.block_hash.hash_tree_root(hasher),
            self.transactions.hash_tree_root(hasher),
            self.withdrawals.hash_tree_root(hasher),
            self.blob_gas_used.hash_tree_root(hasher),
            self.excess_blob_gas.hash_tree_root(hasher),
            self.block_access_list.hash_tree_root(hasher),
            self.slot_number.hash_tree_root(hasher),
        ];
        debug_assert_eq!(field_roots.len(), Self::FIELDS_BEFORE_DEPENDENCY_WITNESSES);
        if let Some(dependency_witnesses) = &self.dependency_witnesses {
            field_roots.push(dependency_witnesses.hash_tree_root(hasher));
        }

        let mut active_fields = [0u8; 32];
        for field in 0..field_roots.len() {
            active_fields[field / 8] |= 1 << (field % 8);
        }
        let root = libssz_merkle::merkleize_progressive(hasher, &field_roots);
        libssz_merkle::hash_nodes(hasher, &root, &active_fields)
    }
}

/// A builder-signed reveal of the payload it bid for: the payload itself,
/// the execution-layer-triggered requests it carries, and enough to bind it
/// to the block whose [`ExecutionPayloadBid`] it fulfills.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, SszEncode, HashTreeRoot,
)]
#[ssz(progressive_container)]
pub struct ExecutionPayloadEnvelope {
    pub payload: ExecutionPayload,
    pub execution_requests: ExecutionRequests,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub builder_index: BuilderIndex,
    pub beacon_block_root: Root,
    pub parent_beacon_block_root: Root,
}

impl ExecutionPayloadEnvelope {
    /// Decodes `bytes` as an envelope whose payload is `container`: see
    /// [`ExecutionPayload::from_ssz`].
    pub fn from_ssz(
        container: PayloadContainer,
        bytes: &[u8],
    ) -> Result<Self, libssz::DecodeError> {
        Self::decode(bytes, |payload| {
            ExecutionPayload::from_ssz(container, payload)
        })
    }

    /// Decodes `bytes` as an envelope whose payload is the container
    /// `config` gives its own slot: see
    /// [`ExecutionPayload::from_ssz_by_slot`].
    pub fn from_ssz_by_slot(config: &Config, bytes: &[u8]) -> Result<Self, libssz::DecodeError> {
        Self::decode(bytes, |payload| {
            ExecutionPayload::from_ssz_by_slot(config, payload)
        })
    }

    /// The container's decoding, with `payload` to decode its first field.
    /// Written out because a derived decoder has no way to tell that field
    /// its container.
    fn decode(
        bytes: &[u8],
        payload: impl FnOnce(&[u8]) -> Result<ExecutionPayload, libssz::DecodeError>,
    ) -> Result<Self, libssz::DecodeError> {
        let fixed_part_len = 2 * libssz::BYTES_PER_LENGTH_OFFSET
            + <BuilderIndex as libssz::SszEncode>::fixed_size()
            + 2 * <Root as libssz::SszEncode>::fixed_size();
        let mut decoder = libssz::ContainerDecoder::new(bytes, fixed_part_len)?;
        decoder.read_variable_offset()?; // payload
        decoder.read_variable_offset()?; // execution_requests
        let builder_index = decoder.decode_fixed()?;
        let beacon_block_root = decoder.decode_fixed()?;
        let parent_beacon_block_root = decoder.decode_fixed()?;
        let UndecodedField(payload_bytes) = decoder.decode_variable()?;
        let execution_requests = decoder.decode_variable()?;
        Ok(Self {
            payload: payload(&payload_bytes)?,
            execution_requests,
            builder_index,
            beacon_block_root,
            parent_beacon_block_root,
        })
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, SszEncode, HashTreeRoot,
)]
pub struct SignedExecutionPayloadEnvelope {
    pub message: ExecutionPayloadEnvelope,
    pub signature: BlsSignature,
}

impl SignedExecutionPayloadEnvelope {
    /// Decodes `bytes` as a signed envelope whose payload is `container`:
    /// see [`ExecutionPayload::from_ssz`].
    pub fn from_ssz(
        container: PayloadContainer,
        bytes: &[u8],
    ) -> Result<Self, libssz::DecodeError> {
        Self::decode(bytes, |message| {
            ExecutionPayloadEnvelope::from_ssz(container, message)
        })
    }

    /// Decodes `bytes` as a signed envelope whose payload is the container
    /// `config` gives its own slot: see
    /// [`ExecutionPayload::from_ssz_by_slot`].
    pub fn from_ssz_by_slot(config: &Config, bytes: &[u8]) -> Result<Self, libssz::DecodeError> {
        Self::decode(bytes, |message| {
            ExecutionPayloadEnvelope::from_ssz_by_slot(config, message)
        })
    }

    /// The container's decoding, with `message` to decode its first field,
    /// for the reason [`ExecutionPayloadEnvelope::decode`] gives.
    fn decode(
        bytes: &[u8],
        message: impl FnOnce(&[u8]) -> Result<ExecutionPayloadEnvelope, libssz::DecodeError>,
    ) -> Result<Self, libssz::DecodeError> {
        let fixed_part_len =
            libssz::BYTES_PER_LENGTH_OFFSET + <BlsSignature as libssz::SszEncode>::fixed_size();
        let mut decoder = libssz::ContainerDecoder::new(bytes, fixed_part_len)?;
        decoder.read_variable_offset()?; // message
        let signature = decoder.decode_fixed()?;
        let UndecodedField(message_bytes) = decoder.decode_variable()?;
        Ok(Self {
            message: message(&message_bytes)?,
            signature,
        })
    }
}

/// What `process_execution_payload` hands `execution_engine.verify_and_notify_new_payload`
/// to validate a revealed payload, gloas `beacon-chain.md`.
///
/// Electra's fields (deneb's blob versioned hashes and beacon root, electra's
/// execution requests), with `execution_payload` and `execution_requests` now
/// this module's own progressive shapes. Not `#[derive(Default)]`, for the
/// reason [`ExecutionPayload`]'s own doc gives.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, SszEncode, HashTreeRoot)]
#[ssz(progressive_container)]
pub struct NewPayloadRequest {
    pub execution_payload: ExecutionPayload,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub versioned_hashes: VersionedHashes,
    pub parent_beacon_block_root: Root,
    pub execution_requests: ExecutionRequests,
}

impl NewPayloadRequest {
    /// Decodes `bytes` as a request whose payload is `container`: see
    /// [`ExecutionPayload::from_ssz`].
    pub fn from_ssz(
        container: PayloadContainer,
        bytes: &[u8],
    ) -> Result<Self, libssz::DecodeError> {
        let fixed_part_len =
            3 * libssz::BYTES_PER_LENGTH_OFFSET + <Root as libssz::SszEncode>::fixed_size();
        let mut decoder = libssz::ContainerDecoder::new(bytes, fixed_part_len)?;
        decoder.read_variable_offset()?; // execution_payload
        decoder.read_variable_offset()?; // versioned_hashes
        let parent_beacon_block_root = decoder.decode_fixed()?;
        decoder.read_variable_offset()?; // execution_requests
        let UndecodedField(payload_bytes) = decoder.decode_variable()?;
        let versioned_hashes = decoder.decode_variable()?;
        let execution_requests = decoder.decode_variable()?;
        Ok(Self {
            execution_payload: ExecutionPayload::from_ssz(container, &payload_bytes)?,
            versioned_hashes,
            parent_beacon_block_root,
            execution_requests,
        })
    }
}

// ---------------------------------------------------------------------------
// Attestations
// ---------------------------------------------------------------------------

/// An aggregate attestation, as gossiped and as included in a block.
///
/// Electra's shape (EIP-7549's wide `committee_bits`/`aggregation_bits`),
/// with `aggregation_bits` now the unbounded [`AggregationBits`] rather than
/// electra's bounded `SszBitlist<MAX_VALIDATORS_PER_SLOT>`.
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
    pub committee_bits: CommitteeBits,
}

impl From<&super::electra::Attestation> for Attestation {
    /// The same vote in gloas's container: every field carries over unchanged,
    /// only `aggregation_bits` moves from electra's bounded bitlist to the
    /// progressive one. A pool that holds electra-shaped aggregates (the
    /// shape gossip and the Beacon API agree on until the fork) serves gloas
    /// readers through this.
    fn from(attestation: &super::electra::Attestation) -> Self {
        let source = &attestation.aggregation_bits;
        let mut aggregation_bits = AggregationBits::with_length(source.len());
        for index in (0..source.len()).filter(|&index| source.get(index) == Some(true)) {
            aggregation_bits
                .set(index, true)
                .expect("the index is below the length the bitlist was built with");
        }
        Self {
            aggregation_bits,
            data: attestation.data,
            signature: attestation.signature,
            committee_bits: attestation.committee_bits.clone(),
        }
    }
}

impl TryFrom<&Attestation> for super::electra::Attestation {
    type Error = libssz_types::TypeError;

    /// The inverse of the conversion above, for a gloas aggregate entering a
    /// pool that stores electra's shape. Fails only when the bits exceed
    /// electra's `MAX_VALIDATORS_PER_SLOT` bound, which no aggregate a real
    /// committee assignment produces can reach.
    fn try_from(attestation: &Attestation) -> Result<Self, Self::Error> {
        let source = &attestation.aggregation_bits;
        let mut aggregation_bits = super::electra::AggregationBits::with_length(source.len())?;
        for index in (0..source.len()).filter(|&index| source.get(index) == Some(true)) {
            aggregation_bits
                .set(index, true)
                .expect("the index is below the length the bitlist was built with");
        }
        Ok(Self {
            aggregation_bits,
            data: attestation.data,
            signature: attestation.signature,
            committee_bits: attestation.committee_bits.clone(),
        })
    }
}

/// An attestation with its attesters named rather than bit-encoded, the same
/// role electra's plays, with `attesting_indices` now the unbounded
/// [`AttestingIndices`].
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
}

/// Evidence that a set of validators made two conflicting attestations.
/// Unchanged in shape from electra; what changed is [`IndexedAttestation`]
/// itself.
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

/// An aggregate together with proof that its aggregator was selected to
/// produce it. Unchanged in shape from electra: `aggregate` simply carries
/// gloas's own, wider [`Attestation`] now.
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
pub struct AggregateAndProof {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub aggregator_index: ValidatorIndex,
    pub aggregate: Attestation,
    pub selection_proof: BlsSignature,
}

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
pub struct SignedAggregateAndProof {
    pub message: AggregateAndProof,
    pub signature: BlsSignature,
}

// ---------------------------------------------------------------------------
// Blocks
// ---------------------------------------------------------------------------

/// The contents of a block.
///
/// *Removed* relative to electra: `execution_payload`, `blob_kzg_commitments`,
/// and `execution_requests`, which now live in [`ExecutionPayloadEnvelope`]
/// instead, revealed by the builder after the block itself is. *Added*:
/// `signed_execution_payload_bid` (the proposer's binding commitment to a
/// builder's bid), `payload_attestations` (the payload timeliness
/// committee's votes on the *previous* slot's payload), and
/// `parent_execution_requests` (the previous slot's execution requests,
/// carried forward so a payload attestation can be checked without a
/// separate fetch). Every other field is electra's, now progressive
/// (EIP-7688).
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
pub struct BeaconBlockBody {
    /// The proposer's contribution to the chain's randomness, which is a
    /// signature over the current epoch and so cannot be chosen freely.
    pub randao_reveal: BlsSignature,
    /// The proposer's vote on the execution chain's deposit state.
    pub eth1_data: Eth1Data,
    /// Arbitrary proposer-chosen bytes, which consensus never reads.
    pub graffiti: Bytes32,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub proposer_slashings: ProposerSlashings,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub attester_slashings: AttesterSlashings,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub attestations: Attestations,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub deposits: Deposits,
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
    /// An empty body: no operations of any kind, and a default (all-zero)
    /// execution payload bid. Unlike every earlier fork's `empty()`, this can
    /// delegate to `Default::default()`: `execution_payload` is no longer a
    /// field of this container, so nothing here is an [`SszVector`] without
    /// a meaningful empty value the way `execution_payload.logs_bloom` was.
    /// Kept as its own method, rather than leaving callers to write
    /// `BeaconBlockBody::default()`, for parity with every earlier fork's
    /// `BeaconBlockBody::empty()`, which callers building a block for a test
    /// already reach for by that name.
    pub fn empty() -> Self {
        Self::default()
    }
}

/// A block.
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

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// The gloas beacon state: 46 fields, in the specification's order.
///
/// Field order is load-bearing, as in every fork: SSZ encoding and this
/// progressive container's merkleization both follow declaration order.
///
/// Fields through `pending_consolidations` are fulu's, field for field, with
/// `validators`, `balances`, `previous_epoch_participation`,
/// `current_epoch_participation`, `inactivity_scores`, `pending_deposits`,
/// `pending_partial_withdrawals`, and `pending_consolidations` now
/// progressive (EIP-7688). `proposer_lookahead` is unchanged from fulu.
/// `latest_execution_payload_header` is *removed*: a gloas state no longer
/// holds a payload header at all, only `latest_block_hash` (the previous
/// payload's own hash) and `latest_execution_payload_bid` (the bid the
/// *current* payload, if any, was bought under). Every field from `builders`
/// onward is new, EIP-7732's builder registry, payment queues, availability
/// tracking, and cached payload timeliness committee window. Not
/// `#[derive(Default)]`: `block_roots`, `state_roots`, `randao_mixes`,
/// `slashings`, `builder_pending_payments`, and `ptc_window` are all
/// [`SszVector`]s, none of which has a meaningful empty value.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot)]
#[ssz(progressive_container)]
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

    // -- Eth1 --
    pub eth1_data: Eth1Data,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub eth1_data_votes: Eth1DataVotes,
    /// How many deposits from the contract have been processed, which is
    /// where the next one will be read from.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub eth1_deposit_index: u64,

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
    pub deposit_requests_start_index: u64,
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

// ---------------------------------------------------------------------------
// Data columns
// ---------------------------------------------------------------------------

/// One column's worth of one block's blob data, as gossiped and served over
/// request-response.
///
/// Drops the `signed_block_header`, `kzg_commitments`, and
/// `kzg_commitments_inclusion_proof` fields fulu's carried: those existed to
/// let a sidecar prove its commitments against a block body on its own, and
/// gloas no longer needs that proof, since the commitments a sidecar's
/// column must match are read from
/// `block.body.signed_execution_payload_bid.message.blob_kzg_commitments`
/// for the block named by `beacon_block_root` instead. `slot` and
/// `beacon_block_root` are new, naming that block directly.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot,
)]
pub struct DataColumnSidecar {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub index: ColumnIndex,
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex_seq")]
    pub column: DataColumn,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub kzg_proofs: KzgProofs,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub slot: Slot,
    pub beacon_block_root: Root,
}

// ---------------------------------------------------------------------------
// Partial columns
// ---------------------------------------------------------------------------
//
// Transcribed from `gloas/partial-columns/p2p-interface.md`, which modifies
// fulu's own partial-column wire types (see [`super::fulu`]'s module doc):
// `CellsBitList` becomes progressive, so every container holding one gains a
// different merkleization even where its field list is textually unchanged,
// and `PartialDataColumnSidecar` drops `header` entirely (no header/inclusion
// proof survives in gloas; see [`DataColumnSidecar`]'s own doc for why).
// `PartialDataColumnGroupID` gains `slot`, since a partial message can no
// longer be reasoned about by block root alone once payloads are revealed a
// slot after the block that bid for them.

/// One column's worth of cells and proofs sent as a gossipsub partial
/// message, carrying only the cells `cells_present_bitmap` names rather than
/// a full [`DataColumn`].
///
/// Unlike fulu's, this carries no `header`: a partial message's cells are
/// checked against `signed_execution_payload_bid.message.blob_kzg_commitments`
/// on the block named by the enclosing [`PartialDataColumnGroupID`], the same
/// way [`DataColumnSidecar`] no longer carries its own header either.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot,
)]
pub struct PartialDataColumnSidecar {
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex")]
    pub cells_present_bitmap: CellsBitList,
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex_seq")]
    pub partial_column: DataColumn,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub kzg_proofs: KzgProofs,
}

/// The two bitmaps peers exchange to negotiate which cells to send. Same
/// field list as fulu's, but a different shape underneath: both fields are
/// now the progressive [`CellsBitList`].
#[derive(
    Debug, Clone, Default, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot,
)]
pub struct PartialDataColumnPartsMetadata {
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex")]
    pub available: CellsBitList,
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex")]
    pub requests: CellsBitList,
}

/// The gossipsub Partial Message group ID for a block's columns.
///
/// `slot` is new relative to fulu's: a payload can be revealed a slot after
/// the block whose bid it fulfills, so naming the block root alone no longer
/// pins down which slot's partial messages a group covers.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot,
)]
pub struct PartialDataColumnGroupID {
    pub beacon_block_root: Root,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub slot: Slot,
}

// ---------------------------------------------------------------------------
// Proposer preferences
// ---------------------------------------------------------------------------

/// A proposer's broadcast, ahead of its slot, of the fee recipient and gas
/// limit it wants a builder's bid to target (EIP-7732 p2p-interface.md).
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
pub struct ProposerPreferences {
    /// The root of the beacon state the proposer duty this message announces
    /// was computed from, so a receiver can check the message against its
    /// own view of the same duty.
    pub dependent_root: Root,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub proposal_slot: Slot,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub validator_index: ValidatorIndex,
    pub fee_recipient: ExecutionAddress,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub target_gas_limit: u64,
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
pub struct SignedProposerPreferences {
    pub message: ProposerPreferences,
    pub signature: BlsSignature,
}

#[cfg(test)]
mod tests {
    use libssz::{SszDecode as _, SszEncode as _};

    use super::*;
    use crate::beacon::primitives::HashTreeRoot as _;

    /// A zeroed [`LogsBloom`], built explicitly rather than through
    /// `Default`: [`SszVector`] has none, the same reason every earlier
    /// fork's `BeaconBlockBody::empty()` builds one by hand.
    fn zero_logs_bloom() -> LogsBloom {
        LogsBloom::try_from(vec![0u8; preset::BYTES_PER_LOGS_BLOOM])
            .expect("BYTES_PER_LOGS_BLOOM zeros fit LogsBloom's exact length")
    }

    /// A default-valued [`ExecutionPayload`], filling in only the one field
    /// `#[derive(Default)]` cannot reach: `logs_bloom`.
    fn zero_execution_payload() -> ExecutionPayload {
        ExecutionPayload {
            parent_hash: Default::default(),
            fee_recipient: Default::default(),
            state_root: Default::default(),
            receipts_root: Default::default(),
            logs_bloom: zero_logs_bloom(),
            prev_randao: Default::default(),
            block_number: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: 0,
            extra_data: Default::default(),
            base_fee_per_gas: Default::default(),
            block_hash: Default::default(),
            transactions: Default::default(),
            withdrawals: Default::default(),
            blob_gas_used: 0,
            excess_blob_gas: 0,
            block_access_list: Default::default(),
            slot_number: 0,
            dependency_witnesses: Default::default(),
        }
    }

    /// The specification's gloas `ExecutionPayload`, with the derived SSZ
    /// implementations [`ExecutionPayload`]'s hand-written ones must agree
    /// with when it has no `dependency_witnesses`.
    #[derive(Debug, PartialEq, SszEncode, SszDecode, HashTreeRoot)]
    #[ssz(progressive_container)]
    struct PayloadWithoutWitnesses {
        parent_hash: ExecutionBlockHash,
        fee_recipient: ExecutionAddress,
        state_root: Bytes32,
        receipts_root: Bytes32,
        logs_bloom: LogsBloom,
        prev_randao: Bytes32,
        block_number: u64,
        gas_limit: u64,
        gas_used: u64,
        timestamp: u64,
        extra_data: ExtraData,
        base_fee_per_gas: Uint256,
        block_hash: ExecutionBlockHash,
        transactions: Transactions,
        withdrawals: Withdrawals,
        blob_gas_used: u64,
        excess_blob_gas: u64,
        block_access_list: BlockAccessList,
        slot_number: u64,
    }

    /// The same container with `dependency_witnesses` appended, which
    /// [`ExecutionPayload`] must agree with when it has the field.
    #[derive(Debug, PartialEq, SszEncode, SszDecode, HashTreeRoot)]
    #[ssz(progressive_container)]
    struct PayloadWithWitnesses {
        parent_hash: ExecutionBlockHash,
        fee_recipient: ExecutionAddress,
        state_root: Bytes32,
        receipts_root: Bytes32,
        logs_bloom: LogsBloom,
        prev_randao: Bytes32,
        block_number: u64,
        gas_limit: u64,
        gas_used: u64,
        timestamp: u64,
        extra_data: ExtraData,
        base_fee_per_gas: Uint256,
        block_hash: ExecutionBlockHash,
        transactions: Transactions,
        withdrawals: Withdrawals,
        blob_gas_used: u64,
        excess_blob_gas: u64,
        block_access_list: BlockAccessList,
        slot_number: u64,
        dependency_witnesses: DependencyWitnesses,
    }

    /// A payload whose every field holds a value of its own, so a field
    /// encoded or hashed out of place shows.
    fn distinct_execution_payload() -> ExecutionPayload {
        let mut logs_bloom = vec![0u8; preset::BYTES_PER_LOGS_BLOOM];
        logs_bloom[3] = 0x5a;
        ExecutionPayload {
            parent_hash: ExecutionBlockHash::repeat_byte(1),
            fee_recipient: ExecutionAddress::repeat_byte(2),
            state_root: Bytes32::repeat_byte(3),
            receipts_root: Bytes32::repeat_byte(4),
            logs_bloom: LogsBloom::try_from(logs_bloom).expect("an exact-length bloom"),
            prev_randao: Bytes32::repeat_byte(5),
            block_number: 6,
            gas_limit: 7,
            gas_used: 8,
            timestamp: 9,
            extra_data: vec![0x0a, 0x0b].try_into().expect("fits"),
            base_fee_per_gas: zero_execution_payload().base_fee_per_gas,
            block_hash: ExecutionBlockHash::repeat_byte(12),
            transactions: vec![
                Transaction::from(vec![0x02, 0xab]),
                Transaction::from(vec![0x06]),
            ]
            .into(),
            withdrawals: vec![Withdrawal {
                index: 13,
                validator_index: 14,
                address: ExecutionAddress::repeat_byte(15),
                amount: 16,
            }]
            .into(),
            blob_gas_used: 17,
            excess_blob_gas: 18,
            block_access_list: vec![0xc1, 0x80].into(),
            slot_number: 19,
            dependency_witnesses: None,
        }
    }

    fn two_witnesses() -> DependencyWitnesses {
        vec![
            DependencyWitness::from(vec![0xaa; 7_740]),
            DependencyWitness::from(vec![0xbb; 7_740]),
        ]
        .into()
    }

    fn without_witnesses(payload: &ExecutionPayload) -> PayloadWithoutWitnesses {
        let payload = payload.clone();
        PayloadWithoutWitnesses {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom,
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data,
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash,
            transactions: payload.transactions,
            withdrawals: payload.withdrawals,
            blob_gas_used: payload.blob_gas_used,
            excess_blob_gas: payload.excess_blob_gas,
            block_access_list: payload.block_access_list,
            slot_number: payload.slot_number,
        }
    }

    fn with_witnesses(payload: &ExecutionPayload) -> PayloadWithWitnesses {
        let payload = payload.clone();
        PayloadWithWitnesses {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom,
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data,
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash,
            transactions: payload.transactions,
            withdrawals: payload.withdrawals,
            blob_gas_used: payload.blob_gas_used,
            excess_blob_gas: payload.excess_blob_gas,
            block_access_list: payload.block_access_list,
            slot_number: payload.slot_number,
            dependency_witnesses: payload
                .dependency_witnesses
                .expect("the payload has the field"),
        }
    }

    #[test]
    fn a_payload_without_dependency_witnesses_is_the_specifications_container() {
        let payload = distinct_execution_payload();
        let reference = without_witnesses(&payload);

        assert_eq!(payload.to_ssz(), reference.to_ssz());
        assert_eq!(payload.encoded_len(), reference.to_ssz().len());
        assert_eq!(payload.hash_tree_root(), reference.hash_tree_root());
        assert_eq!(payload.container(), PayloadContainer::Specification);
        assert_eq!(
            ExecutionPayload::from_ssz(PayloadContainer::Specification, &reference.to_ssz()),
            Ok(payload)
        );
    }

    #[test]
    fn a_payload_with_dependency_witnesses_is_the_container_with_the_field_appended() {
        for witnesses in [DependencyWitnesses::default(), two_witnesses()] {
            let mut payload = distinct_execution_payload();
            payload.dependency_witnesses = Some(witnesses);
            let reference = with_witnesses(&payload);

            assert_eq!(payload.to_ssz(), reference.to_ssz());
            assert_eq!(payload.encoded_len(), reference.to_ssz().len());
            assert_eq!(payload.hash_tree_root(), reference.hash_tree_root());
            assert_eq!(payload.container(), PayloadContainer::WithWitnesses);
            assert_eq!(
                ExecutionPayload::from_ssz(PayloadContainer::WithWitnesses, &reference.to_ssz()),
                Ok(payload)
            );
        }
    }

    #[test]
    fn an_empty_dependency_witnesses_list_is_not_the_same_payload_as_no_field() {
        let without = distinct_execution_payload();
        let mut with_empty = without.clone();
        with_empty.dependency_witnesses = Some(Default::default());

        assert_ne!(without.to_ssz(), with_empty.to_ssz());
        assert_ne!(without.hash_tree_root(), with_empty.hash_tree_root());
        // Each decodes as its own container and not as the other's, whose
        // fixed part is of another length.
        use PayloadContainer::{Specification, WithWitnesses};
        assert!(ExecutionPayload::from_ssz(WithWitnesses, &without.to_ssz()).is_err());
        assert!(ExecutionPayload::from_ssz(Specification, &with_empty.to_ssz()).is_err());
        assert_eq!(
            ExecutionPayload::from_ssz(Specification, &without.to_ssz()),
            Ok(without)
        );
        assert_eq!(
            ExecutionPayload::from_ssz(WithWitnesses, &with_empty.to_ssz()),
            Ok(with_empty)
        );
    }

    #[test]
    fn a_payload_is_decoded_as_the_container_of_its_own_slot() {
        let without = distinct_execution_payload();
        let mut with_two = without.clone();
        with_two.dependency_witnesses = Some(two_witnesses());
        let epoch = compute_epoch_at_slot(without.slot_number);

        // No epoch scheduled, or one after the payload's: the specification's
        // container, and the other's bytes do not decode.
        let mut config = Config::minimal();
        for heze_fork_epoch in [config.heze_fork_epoch, epoch + 1] {
            config.heze_fork_epoch = heze_fork_epoch;
            assert_eq!(
                ExecutionPayload::from_ssz_by_slot(&config, &without.to_ssz()),
                Ok(without.clone())
            );
            assert!(ExecutionPayload::from_ssz_by_slot(&config, &with_two.to_ssz()).is_err());
        }

        // Scheduled at the payload's epoch: the container with the list.
        config.heze_fork_epoch = epoch;
        assert_eq!(
            ExecutionPayload::from_ssz_by_slot(&config, &with_two.to_ssz()),
            Ok(with_two.clone())
        );
        assert!(ExecutionPayload::from_ssz_by_slot(&config, &without.to_ssz()).is_err());

        // Bytes too short to hold the slot say nothing of their container.
        assert!(ExecutionPayload::from_ssz_by_slot(&config, &with_two.to_ssz()[..100]).is_err());
    }

    #[test]
    fn a_payload_keeps_its_container_inside_an_envelope() {
        for witnesses in [
            None,
            Some(DependencyWitnesses::default()),
            Some(two_witnesses()),
        ] {
            let mut payload = distinct_execution_payload();
            payload.dependency_witnesses = witnesses;
            let envelope = ExecutionPayloadEnvelope {
                payload,
                execution_requests: Default::default(),
                builder_index: 1,
                beacon_block_root: Bytes32::repeat_byte(2),
                parent_beacon_block_root: Bytes32::repeat_byte(3),
            };
            let container = envelope.payload.container();
            assert_eq!(
                ExecutionPayloadEnvelope::from_ssz(container, &envelope.to_ssz()),
                Ok(envelope.clone())
            );

            // The same through the containers that hold an envelope or a
            // payload, each told the payload's container.
            let signed = SignedExecutionPayloadEnvelope {
                message: envelope.clone(),
                signature: BlsSignature([7; 96]),
            };
            assert_eq!(
                SignedExecutionPayloadEnvelope::from_ssz(container, &signed.to_ssz()),
                Ok(signed.clone())
            );
            let request = NewPayloadRequest {
                execution_payload: envelope.payload.clone(),
                versioned_hashes: vec![Bytes32::repeat_byte(4)].try_into().unwrap(),
                parent_beacon_block_root: Bytes32::repeat_byte(5),
                execution_requests: Default::default(),
            };
            assert_eq!(
                NewPayloadRequest::from_ssz(container, &request.to_ssz()),
                Ok(request)
            );

            // And by the payload's own slot, from the outermost container in.
            let mut config = Config::minimal();
            if container == PayloadContainer::WithWitnesses {
                config.heze_fork_epoch = compute_epoch_at_slot(envelope.payload.slot_number);
            }
            assert_eq!(
                ExecutionPayloadEnvelope::from_ssz_by_slot(&config, &envelope.to_ssz()),
                Ok(envelope)
            );
            assert_eq!(
                SignedExecutionPayloadEnvelope::from_ssz_by_slot(&config, &signed.to_ssz()),
                Ok(signed)
            );
        }
    }

    #[test]
    fn a_malformed_envelope_does_not_decode() {
        let envelope = SignedExecutionPayloadEnvelope {
            message: ExecutionPayloadEnvelope {
                payload: distinct_execution_payload(),
                execution_requests: Default::default(),
                builder_index: 1,
                beacon_block_root: Bytes32::repeat_byte(2),
                parent_beacon_block_root: Bytes32::repeat_byte(3),
            },
            signature: BlsSignature([7; 96]),
        };
        let container = PayloadContainer::Specification;
        let bytes = envelope.to_ssz();
        let decode = |bytes: &[u8]| SignedExecutionPayloadEnvelope::from_ssz(container, bytes);
        assert_eq!(decode(&bytes), Ok(envelope));

        // Cut short anywhere: inside the signed envelope's fixed part, the
        // envelope's, or the payload's.
        for len in [0, 50, 100, 150, bytes.len() - 1] {
            assert!(decode(&bytes[..len]).is_err(), "{len} bytes");
        }
        // The signed envelope's one offset, then the envelope's two (at the
        // start of the message, after the 4-byte offset and the 96-byte
        // signature): none may point anywhere but where its field starts.
        for offset_at in [0, 100, 104] {
            let mut wrong = bytes.clone();
            wrong[offset_at] ^= 0x01;
            assert!(decode(&wrong).is_err(), "offset at {offset_at}");
        }
    }

    #[test]
    fn payload_bytes_with_a_first_offset_of_neither_container_do_not_decode() {
        let mut bytes = distinct_execution_payload().to_ssz();
        // The first offset is `extra_data`'s, after the ten fixed-size fields
        // before it: four 32-byte values, the address, the bloom and four
        // `u64`s. Two bytes more than the container without the field is the
        // fixed part of neither.
        let first_offset = 4 * 32 + 20 + preset::BYTES_PER_LOGS_BLOOM + 4 * 8;
        let wrong = (ExecutionPayload::fixed_part_len(false) + 2) as u32;
        bytes[first_offset..first_offset + 4].copy_from_slice(&wrong.to_le_bytes());
        for container in [
            PayloadContainer::Specification,
            PayloadContainer::WithWitnesses,
        ] {
            assert!(matches!(
                ExecutionPayload::from_ssz(container, &bytes),
                Err(libssz::DecodeError::InvalidFirstOffset { .. })
            ));
            assert!(ExecutionPayload::from_ssz(container, &bytes[..100]).is_err());
        }
    }

    #[test]
    fn a_payload_is_made_the_container_its_slot_calls_for() {
        let without = distinct_execution_payload();
        let mut with_empty = without.clone();
        with_empty.dependency_witnesses = Some(Default::default());
        let mut with_two = without.clone();
        with_two.dependency_witnesses = Some(two_witnesses());

        // A slot whose payloads have the field: a payload without one gets
        // the empty list, and a list is kept as it is.
        assert_eq!(
            without.clone().with_dependency_witnesses_field(true),
            Ok(with_empty.clone())
        );
        assert_eq!(
            with_empty.clone().with_dependency_witnesses_field(true),
            Ok(with_empty.clone())
        );
        assert_eq!(
            with_two.clone().with_dependency_witnesses_field(true),
            Ok(with_two.clone())
        );

        // A slot whose payloads do not: an empty list is dropped, and a list
        // that holds witnesses has no container to go in.
        assert_eq!(
            without.clone().with_dependency_witnesses_field(false),
            Ok(without.clone())
        );
        assert_eq!(
            with_empty.with_dependency_witnesses_field(false),
            Ok(without)
        );
        assert_eq!(
            with_two.with_dependency_witnesses_field(false),
            Err(DependencyWitnessesTooEarly)
        );
    }

    /// A minimal but complete gloas state, every field present at an
    /// all-zero or empty placeholder. Built field by field rather than
    /// through `Default`, which [`BeaconState`] cannot derive: `block_roots`,
    /// `state_roots`, `randao_mixes`, `slashings`,
    /// `builder_pending_payments`, and `ptc_window` are all [`SszVector`]s,
    /// none of which has a meaningful empty value.
    fn zero_state() -> BeaconState {
        let zero_root_vector = || -> BlockRoots {
            vec![Root::ZERO; preset::slots_per_historical_root()]
                .try_into()
                .expect("the vector is built at its exact length")
        };
        let empty_sync_committee = || SyncCommittee {
            pubkeys: vec![Default::default(); preset::sync_committee_size()]
                .try_into()
                .expect("built at exactly SYNC_COMMITTEE_SIZE"),
            aggregate_pubkey: Default::default(),
        };
        let empty_ptc: PayloadTimelinessCommittee = vec![0u64; preset::ptc_size()]
            .try_into()
            .expect("built at exactly PTC_SIZE");

        BeaconState {
            genesis_time: 0,
            genesis_validators_root: Root::ZERO,
            slot: 0,
            fork: Default::default(),
            latest_block_header: Default::default(),
            block_roots: zero_root_vector(),
            state_roots: zero_root_vector(),
            historical_roots: Default::default(),
            eth1_data: Default::default(),
            eth1_data_votes: Default::default(),
            eth1_deposit_index: 0,
            validators: Default::default(),
            balances: Default::default(),
            randao_mixes: vec![Bytes32::ZERO; preset::epochs_per_historical_vector()]
                .try_into()
                .expect("the vector is built at its exact length"),
            slashings: vec![0; preset::epochs_per_slashings_vector()]
                .try_into()
                .expect("the vector is built at its exact length"),
            previous_epoch_participation: Default::default(),
            current_epoch_participation: Default::default(),
            justification_bits: Default::default(),
            previous_justified_checkpoint: Default::default(),
            current_justified_checkpoint: Default::default(),
            finalized_checkpoint: Default::default(),
            inactivity_scores: Default::default(),
            current_sync_committee: empty_sync_committee(),
            next_sync_committee: empty_sync_committee(),
            latest_block_hash: ExecutionBlockHash::ZERO,
            next_withdrawal_index: 0,
            next_withdrawal_validator_index: 0,
            historical_summaries: Default::default(),
            deposit_requests_start_index:
                crate::beacon::constants::UNSET_DEPOSIT_REQUESTS_START_INDEX,
            deposit_balance_to_consume: 0,
            exit_balance_to_consume: 0,
            earliest_exit_epoch: 0,
            consolidation_balance_to_consume: 0,
            earliest_consolidation_epoch: 0,
            pending_deposits: Default::default(),
            pending_partial_withdrawals: Default::default(),
            pending_consolidations: Default::default(),
            proposer_lookahead: vec![0; preset::proposer_lookahead_length()]
                .try_into()
                .expect("the vector is built at its exact length"),
            builders: Default::default(),
            next_withdrawal_builder_index: 0,
            execution_payload_availability: Default::default(),
            builder_pending_payments: vec![
                BuilderPendingPayment::default();
                preset::builder_pending_payments_length()
            ]
            .try_into()
            .expect("the vector is built at its exact length"),
            builder_pending_withdrawals: Default::default(),
            latest_execution_payload_bid: Default::default(),
            payload_expected_withdrawals: Default::default(),
            ptc_window: vec![empty_ptc; preset::ptc_window_length()]
                .try_into()
                .expect("the vector is built at its exact length"),
        }
    }

    #[test]
    fn a_zeroed_state_round_trips_through_ssz() {
        let state = zero_state();
        let bytes = state.to_ssz();
        let decoded = BeaconState::from_ssz_bytes(&bytes).expect("decodes");
        assert_eq!(decoded, state);
        assert_eq!(decoded.hash_tree_root(), state.hash_tree_root());
    }

    #[test]
    fn a_bid_and_an_envelope_round_trip_through_ssz() {
        let bid = SignedExecutionPayloadBid::default();
        assert_eq!(
            SignedExecutionPayloadBid::from_ssz_bytes(&bid.to_ssz()).unwrap(),
            bid
        );

        // `SignedExecutionPayloadEnvelope` cannot derive `Default` (its
        // `ExecutionPayload` holds a `logs_bloom` `SszVector`), so its
        // payload is built explicitly instead.
        let envelope = SignedExecutionPayloadEnvelope {
            message: ExecutionPayloadEnvelope {
                payload: zero_execution_payload(),
                execution_requests: Default::default(),
                builder_index: 0,
                beacon_block_root: Root::ZERO,
                parent_beacon_block_root: Root::ZERO,
            },
            signature: Default::default(),
        };
        assert_eq!(
            SignedExecutionPayloadEnvelope::from_ssz(
                PayloadContainer::Specification,
                &envelope.to_ssz()
            )
            .unwrap(),
            envelope
        );
    }

    #[test]
    fn an_empty_block_body_round_trips_through_ssz() {
        let body = BeaconBlockBody::empty();
        let bytes = body.to_ssz();
        assert_eq!(BeaconBlockBody::from_ssz_bytes(&bytes).unwrap(), body);
    }

    #[test]
    fn a_data_column_sidecar_round_trips_through_ssz() {
        let sidecar = DataColumnSidecar {
            index: 3,
            column: vec![Cell::try_from(vec![7u8; preset::BYTES_PER_CELL]).unwrap(); 2].into(),
            kzg_proofs: vec![KzgProof([1; crate::beacon::primitives::KZG_POINT_SIZE]); 2].into(),
            slot: 9,
            beacon_block_root: Root::repeat_byte(4),
        };

        let bytes = sidecar.to_ssz();
        assert_eq!(DataColumnSidecar::from_ssz_bytes(&bytes).unwrap(), sidecar);
    }

    #[test]
    fn variable_length_containers_carry_offsets() {
        assert!(!<BeaconState as libssz::SszEncode>::is_fixed_size());
        assert!(!<BeaconBlockBody as libssz::SszEncode>::is_fixed_size());
        assert!(!<Attestation as libssz::SszEncode>::is_fixed_size());
        assert!(!<IndexedAttestation as libssz::SszEncode>::is_fixed_size());
        assert!(!<AttesterSlashing as libssz::SszEncode>::is_fixed_size());
        assert!(!<ExecutionRequests as libssz::SszEncode>::is_fixed_size());
        assert!(!<ExecutionPayload as libssz::SszEncode>::is_fixed_size());
        assert!(!<ExecutionPayloadEnvelope as libssz::SszEncode>::is_fixed_size());
        assert!(!<DataColumnSidecar as libssz::SszEncode>::is_fixed_size());
    }

    #[test]
    fn new_fixed_size_containers_have_no_offsets() {
        assert!(<Builder as libssz::SszEncode>::is_fixed_size());
        assert!(<BuilderPendingPayment as libssz::SszEncode>::is_fixed_size());
        assert!(<BuilderPendingWithdrawal as libssz::SszEncode>::is_fixed_size());
        assert!(<BuilderDepositRequest as libssz::SszEncode>::is_fixed_size());
        assert!(<BuilderExitRequest as libssz::SszEncode>::is_fixed_size());
        assert!(<PayloadAttestationData as libssz::SszEncode>::is_fixed_size());
        assert!(<PayloadAttestationMessage as libssz::SszEncode>::is_fixed_size());
        assert!(<ProposerPreferences as libssz::SszEncode>::is_fixed_size());
    }
}
