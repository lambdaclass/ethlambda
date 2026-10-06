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
use libssz_types::{ProgressiveBitlist, ProgressiveList, SszBitvector, SszList, SszVector};

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
use crate::beacon::preset;
use crate::beacon::primitives::{
    BlsPubkey, BlsSignature, Bytes32, ColumnIndex, Epoch, ExecutionAddress, ExecutionBlockHash,
    Gwei, KzgCommitment, KzgProof, ParticipationFlags, Root, Slot, Uint256, ValidatorIndex,
    WithdrawalIndex,
};

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
pub type EpochParticipation = ProgressiveList<ParticipationFlags>;
/// Per-validator inactivity scores, positionally parallel to the registry.
pub type InactivityScores = ProgressiveList<u64>;
/// Deposits known but not yet credited to the validator registry.
pub type PendingDeposits = ProgressiveList<PendingDeposit>;
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
    SszVector<BuilderPendingPayment, { preset::BUILDER_PENDING_PAYMENTS_LENGTH }>;
/// Bits tracking payload availability for recent slots, indexed by slot
/// modulo `SLOTS_PER_HISTORICAL_ROOT`, the same indexing [`BlockRoots`] uses.
pub type ExecutionPayloadAvailability = SszBitvector<{ preset::SLOTS_PER_HISTORICAL_ROOT }>;
/// Payload attestations included in a block.
pub type PayloadAttestations = ProgressiveList<PayloadAttestation>;
/// The payload timeliness committee of a slot, named explicitly.
pub type PayloadTimelinessCommittee = SszVector<ValidatorIndex, { preset::PTC_SIZE }>;
/// The payload timeliness committee members an [`IndexedPayloadAttestation`]
/// names, as a bounded list rather than the fixed-size
/// [`PayloadTimelinessCommittee`]: an attester subset, not the whole
/// committee.
pub type PayloadTimelinessCommitteeIndices = SszList<ValidatorIndex, { preset::PTC_SIZE }>;
/// One bit per payload timeliness committee member, in committee order.
pub type PayloadTimelinessCommitteeBits = SszBitvector<{ preset::PTC_SIZE }>;
/// The cached window of payload timeliness committees
/// [`BeaconState::ptc_window`] holds: the previous, current, and lookahead
/// epochs.
pub type PayloadTimelinessCommitteeWindow =
    SszVector<PayloadTimelinessCommittee, { preset::PTC_WINDOW_LENGTH }>;
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
    Debug, Clone, Default, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot,
)]
pub struct Builder {
    pub pubkey: BlsPubkey,
    /// Which shape this record is in. Only [`crate::beacon::constants::PAYLOAD_BUILDER_VERSION`]
    /// exists today; the field exists so a future format change has
    /// somewhere to record it.
    pub version: u8,
    pub execution_address: ExecutionAddress,
    pub balance: Gwei,
    /// The epoch this builder's deposit was placed, which
    /// `is_active_builder` compares against the finalized checkpoint before
    /// treating the builder as eligible.
    pub deposit_epoch: Epoch,
    /// `FAR_FUTURE_EPOCH` until this builder initiates an exit, the same
    /// sentinel convention [`super::shared::Validator::withdrawable_epoch`]
    /// uses.
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
/// (EIP-7928) and `slot_number` (EIP-8061) are appended. Not
/// `#[derive(Default)]`: `logs_bloom` is an [`SszVector`], which, like every
/// earlier fork's payload, has no meaningful empty value.
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
}

/// A builder-signed reveal of the payload it bid for: the payload itself,
/// the execution-layer-triggered requests it carries, and enough to bind it
/// to the block whose [`ExecutionPayloadBid`] it fulfills.
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
pub struct ExecutionPayloadEnvelope {
    pub payload: ExecutionPayload,
    pub execution_requests: ExecutionRequests,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub builder_index: BuilderIndex,
    pub beacon_block_root: Root,
    pub parent_beacon_block_root: Root,
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
pub struct SignedExecutionPayloadEnvelope {
    pub message: ExecutionPayloadEnvelope,
    pub signature: BlsSignature,
}

/// What `process_execution_payload` hands `execution_engine.verify_and_notify_new_payload`
/// to validate a revealed payload, gloas `beacon-chain.md`.
///
/// Electra's fields (deneb's blob versioned hashes and beacon root, electra's
/// execution requests), with `execution_payload` and `execution_requests` now
/// this module's own progressive shapes. Not `#[derive(Default)]`, for the
/// reason [`ExecutionPayload`]'s own doc gives.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot)]
#[ssz(progressive_container)]
pub struct NewPayloadRequest {
    pub execution_payload: ExecutionPayload,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub versioned_hashes: VersionedHashes,
    pub parent_beacon_block_root: Root,
    pub execution_requests: ExecutionRequests,
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
    Debug, Clone, Default, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot,
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
    Debug, Clone, Default, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot,
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
        }
    }

    /// A minimal but complete gloas state, every field present at an
    /// all-zero or empty placeholder. Built field by field rather than
    /// through `Default`, which [`BeaconState`] cannot derive: `block_roots`,
    /// `state_roots`, `randao_mixes`, `slashings`,
    /// `builder_pending_payments`, and `ptc_window` are all [`SszVector`]s,
    /// none of which has a meaningful empty value.
    fn zero_state() -> BeaconState {
        let zero_root_vector = || -> BlockRoots {
            vec![Root::ZERO; preset::SLOTS_PER_HISTORICAL_ROOT]
                .try_into()
                .expect("the vector is built at its exact length")
        };
        let empty_sync_committee = || SyncCommittee {
            pubkeys: vec![Default::default(); preset::SYNC_COMMITTEE_SIZE]
                .try_into()
                .expect("built at exactly SYNC_COMMITTEE_SIZE"),
            aggregate_pubkey: Default::default(),
        };
        let empty_ptc: PayloadTimelinessCommittee = vec![0u64; preset::PTC_SIZE]
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
            randao_mixes: vec![Bytes32::ZERO; preset::EPOCHS_PER_HISTORICAL_VECTOR]
                .try_into()
                .expect("the vector is built at its exact length"),
            slashings: vec![0; preset::EPOCHS_PER_SLASHINGS_VECTOR]
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
            proposer_lookahead: vec![0; preset::PROPOSER_LOOKAHEAD_LENGTH]
                .try_into()
                .expect("the vector is built at its exact length"),
            builders: Default::default(),
            next_withdrawal_builder_index: 0,
            execution_payload_availability: Default::default(),
            builder_pending_payments: vec![
                BuilderPendingPayment::default();
                preset::BUILDER_PENDING_PAYMENTS_LENGTH
            ]
            .try_into()
            .expect("the vector is built at its exact length"),
            builder_pending_withdrawals: Default::default(),
            latest_execution_payload_bid: Default::default(),
            payload_expected_withdrawals: Default::default(),
            ptc_window: vec![empty_ptc; preset::PTC_WINDOW_LENGTH]
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
            SignedExecutionPayloadEnvelope::from_ssz_bytes(&envelope.to_ssz()).unwrap(),
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
