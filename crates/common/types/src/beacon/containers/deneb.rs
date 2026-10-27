//! Containers whose shape is specific to deneb.
//!
//! Deneb's headline change is data blobs: temporary storage for rollup data
//! that consensus commits to but never processes itself. A blob is far larger
//! than everything else a block carries, so the specification never puts one
//! in the block. Instead the block commits only to a KZG commitment per blob,
//! appended to [`BeaconBlockBody`] as `blob_kzg_commitments`, and each blob is
//! propagated separately as a [`BlobSidecar`] over its own gossip subnet,
//! carrying enough of the block's header to prove the sidecar's commitment
//! really is the one the block committed to. [`BlobIdentifier`] is the
//! request-side counterpart: naming one blob of one block without shipping
//! the blob, for the request-response protocol that backfills sidecars gossip
//! missed.
//!
//! [`ExecutionPayload`] and [`ExecutionPayloadHeader`] both gain
//! `blob_gas_used` and `excess_blob_gas`, deneb's per-block blob fee-market
//! accounting: EIP-4844's analogue of EIP-1559's base fee, scoped to blob
//! space instead of execution gas. [`BeaconState`] otherwise keeps
//! [`super::capella::BeaconState`]'s shape, field for field: only the
//! container held in `latest_execution_payload_header` changes.
//!
//! [`BlobIdentifier`] and [`BlobSidecar`] are transcribed from
//! `p2p-interface.md` rather than `beacon-chain.md`, since the specification
//! defines the wire-level blob types in the networking document rather than
//! the state transition document. Neither is ever stored in the state or a
//! block body; a block only ever holds the commitments the sidecars are
//! checked against.
//!
//! [`VersionedHash`] and [`VersionedHashes`] are new too: the versioned
//! hashes `kzg_commitment_to_versioned_hash` derives from
//! `blob_kzg_commitments`, which [`NewPayloadRequest`] passes to the
//! execution engine alongside `parent_beacon_block_root` so it can check a
//! payload's blob commitments without the blobs themselves.

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::{SszList, SszVector};

use super::altair::{SyncAggregate, SyncCommittee};
use super::bellatrix::{ExtraData, LogsBloom, Transactions};
use super::capella::{SignedBLSToExecutionChange, Withdrawals};
use super::phase0::{Attestation, AttesterSlashing};
use super::shared::{
    Balances, BeaconBlockHeader, BlockRoots, Checkpoint, Deposit, EpochParticipation, Eth1Data,
    Eth1DataVotes, Fork, HistoricalRoots, HistoricalSummaries, InactivityScores, JustificationBits,
    ProposerSlashing, RandaoMixes, SignedBeaconBlockHeader, SignedVoluntaryExit, Slashings,
    StateRoots, Validators,
};
use crate::beacon::preset;
use crate::beacon::primitives::{
    BlobIndex, BlsSignature, Bytes32, ExecutionAddress, ExecutionBlockHash, KzgCommitment,
    KzgProof, Root, Slot, Uint256, ValidatorIndex, VersionedHash, WithdrawalIndex,
};

// ---------------------------------------------------------------------------
// Collection aliases
// ---------------------------------------------------------------------------

/// Raw blob bytes, as propagated in a [`BlobSidecar`] rather than in the block
/// itself.
///
/// Bounded by `BYTES_PER_BLOB`, which is large enough that a derived
/// `Default` would zero that many bytes on every construction for no reason.
/// That is why [`BlobSidecar`], the only container that holds one, does not
/// derive `Default`.
pub type Blob = SszVector<u8, { preset::BYTES_PER_BLOB }>;

/// The KZG commitments a block makes to its blobs, one per blob, carried in
/// [`BeaconBlockBody::blob_kzg_commitments`] instead of the blobs themselves.
pub type KzgCommitments = SszList<KzgCommitment, { preset::MAX_BLOB_COMMITMENTS_PER_BLOCK }>;

/// The merkle path proving a [`BlobSidecar`]'s commitment sits at its claimed
/// index in the block body's `blob_kzg_commitments`, which is what lets a
/// sidecar be checked against a block header without holding the rest of
/// that block's body.
pub type BlobKzgCommitmentInclusionProof =
    SszVector<Bytes32, { preset::KZG_COMMITMENT_INCLUSION_PROOF_DEPTH }>;

/// The versioned hashes [`NewPayloadRequest`] passes to the execution engine,
/// one per blob committed to by [`BeaconBlockBody::blob_kzg_commitments`],
/// computed from those commitments by `kzg_commitment_to_versioned_hash`.
pub type VersionedHashes = SszList<VersionedHash, { preset::MAX_BLOB_COMMITMENTS_PER_BLOCK }>;

// ---------------------------------------------------------------------------
// Execution payload
// ---------------------------------------------------------------------------

/// The execution layer's contribution to a block: [`super::capella::ExecutionPayload`]'s
/// fields, with deneb's blob gas accounting appended.
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
    /// How much blob gas this block's blob transactions consumed.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub blob_gas_used: u64,
    /// The blob gas market's excess entering this block. Plays the same role
    /// for blob space that the base fee's excess plays for execution gas: it
    /// sets the blob base fee the next block's transactions pay, so blob
    /// space is priced by an independent market from execution gas.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub excess_blob_gas: u64,
}

/// [`ExecutionPayload`] with the bulky fields replaced by their roots, which
/// is what the state retains once a payload is no longer the newest one.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot)]
pub struct ExecutionPayloadHeader {
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
    pub transactions_root: Root,
    pub withdrawals_root: Root,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub blob_gas_used: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub excess_blob_gas: u64,
}

/// What `process_execution_payload` hands `execution_engine.verify_and_notify_new_payload`
/// to validate a proposed payload, deneb `beacon-chain.md`.
///
/// Bellatrix's version carries only `execution_payload`; deneb appends
/// `versioned_hashes` (EIP-4844, so the engine can check blob commitments
/// against the payload without the blobs themselves) and
/// `parent_beacon_block_root` (EIP-4788, exposing the beacon root to the EVM).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot)]
pub struct NewPayloadRequest {
    pub execution_payload: ExecutionPayload,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub versioned_hashes: VersionedHashes,
    pub parent_beacon_block_root: Root,
}

// ---------------------------------------------------------------------------
// Blocks
// ---------------------------------------------------------------------------

/// The contents of a block: capella's operations, with the blob commitments
/// deneb adds appended.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot)]
pub struct BeaconBlockBody {
    /// The proposer's contribution to the chain's randomness, which is a
    /// signature over the current epoch and so cannot be chosen freely.
    pub randao_reveal: BlsSignature,
    /// The proposer's vote on the execution chain's deposit state.
    pub eth1_data: Eth1Data,
    /// Arbitrary proposer-chosen bytes, which consensus never reads.
    pub graffiti: Bytes32,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub proposer_slashings: SszList<ProposerSlashing, { preset::MAX_PROPOSER_SLASHINGS }>,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub attester_slashings: SszList<AttesterSlashing, { preset::MAX_ATTESTER_SLASHINGS }>,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub attestations: SszList<Attestation, { preset::MAX_ATTESTATIONS }>,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub deposits: SszList<Deposit, { preset::MAX_DEPOSITS }>,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub voluntary_exits: SszList<SignedVoluntaryExit, { preset::MAX_VOLUNTARY_EXITS }>,
    /// The aggregated sync committee signature over the previous slot's block
    /// root, plus which members contributed.
    pub sync_aggregate: SyncAggregate,
    pub execution_payload: ExecutionPayload,
    /// Capella's withdrawal-credential-change operations, unchanged in deneb:
    /// each [`SignedBLSToExecutionChange`] wraps a
    /// [`super::capella::BLSToExecutionChange`] with a signature proving its
    /// holder controls the credential being changed.
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub bls_to_execution_changes:
        SszList<SignedBLSToExecutionChange, { preset::MAX_BLS_TO_EXECUTION_CHANGES }>,
    /// One KZG commitment per blob this block's proposer chose to include.
    /// Never the blobs themselves: those are propagated separately as
    /// [`BlobSidecar`]s, which is what keeps a block's own size independent
    /// of how much blob data it references.
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub blob_kzg_commitments: KzgCommitments,
}

impl BeaconBlockBody {
    /// An empty body: no operations of any kind, and an all-zero execution
    /// payload.
    ///
    /// Not `#[derive(Default)]`: `execution_payload.logs_bloom` is an
    /// [`SszVector`](libssz_types::SszVector), and unlike a list, a vector can
    /// never validly be empty, so libssz gives it no `Default` impl. Its
    /// all-zero value is built explicitly at its exact length instead.
    pub fn empty() -> Self {
        Self {
            randao_reveal: Default::default(),
            eth1_data: Default::default(),
            graffiti: Default::default(),
            proposer_slashings: Default::default(),
            attester_slashings: Default::default(),
            attestations: Default::default(),
            deposits: Default::default(),
            voluntary_exits: Default::default(),
            sync_aggregate: Default::default(),
            execution_payload: ExecutionPayload {
                parent_hash: ExecutionBlockHash::ZERO,
                fee_recipient: ExecutionAddress::ZERO,
                state_root: Bytes32::ZERO,
                receipts_root: Bytes32::ZERO,
                logs_bloom: LogsBloom::try_from(vec![0u8; preset::BYTES_PER_LOGS_BLOOM])
                    .expect("BYTES_PER_LOGS_BLOOM zeros fit LogsBloom's exact length"),
                prev_randao: Bytes32::ZERO,
                block_number: 0,
                gas_limit: 0,
                gas_used: 0,
                timestamp: 0,
                extra_data: Default::default(),
                base_fee_per_gas: Uint256::ZERO,
                block_hash: ExecutionBlockHash::ZERO,
                transactions: Default::default(),
                withdrawals: Default::default(),
                blob_gas_used: 0,
                excess_blob_gas: 0,
            },
            bls_to_execution_changes: Default::default(),
            blob_kzg_commitments: Default::default(),
        }
    }
}

/// A block.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot)]
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

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot)]
pub struct SignedBeaconBlock {
    pub message: BeaconBlock,
    pub signature: BlsSignature,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// The deneb beacon state: 28 fields, in the specification's order.
///
/// Field order is load-bearing. SSZ encoding and merkleization both follow
/// declaration order, so reordering or omitting a field silently produces a
/// wrong `hash_tree_root`.
///
/// Identical to [`super::capella::BeaconState`], field for field: only the
/// type held in `latest_execution_payload_header` changes, to deneb's
/// [`ExecutionPayloadHeader`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot)]
pub struct BeaconState {
    // -- Versioning --
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub genesis_time: u64,
    /// The root of the genesis validator registry, which separates this chain
    /// from any other running the same fork schedule.
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

    // -- Registry --
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub validators: Validators,
    #[serde(with = "crate::beacon::serde_helpers::quoted_u64_seq")]
    pub balances: Balances,

    // -- Randomness --
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub randao_mixes: RandaoMixes,

    // -- Slashings --
    #[serde(with = "crate::beacon::serde_helpers::quoted_u64_seq")]
    pub slashings: Slashings,

    // -- Participation --
    /// Per-validator participation flags for the previous epoch, positionally
    /// parallel to `validators`.
    #[serde(with = "crate::beacon::serde_helpers::quoted_u64_seq")]
    pub previous_epoch_participation: EpochParticipation,
    /// Flags for the current epoch, which become
    /// `previous_epoch_participation` at the next epoch boundary.
    #[serde(with = "crate::beacon::serde_helpers::quoted_u64_seq")]
    pub current_epoch_participation: EpochParticipation,

    // -- Finality --
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex")]
    pub justification_bits: JustificationBits,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,

    // -- Inactivity --
    /// Per-validator inactivity score, positionally parallel to `validators`.
    #[serde(with = "crate::beacon::serde_helpers::quoted_u64_seq")]
    pub inactivity_scores: InactivityScores,

    // -- Sync committees --
    /// The committee currently signing sync aggregates.
    pub current_sync_committee: SyncCommittee,
    /// The committee that takes over from `current_sync_committee` at the
    /// next sync committee period boundary.
    pub next_sync_committee: SyncCommittee,

    // -- Execution --
    /// The most recent execution payload's header, replacing the whole
    /// payload with its roots once the block containing it is no longer new.
    pub latest_execution_payload_header: ExecutionPayloadHeader,

    // -- Withdrawals --
    /// The index the next withdrawal will be assigned, so consecutive
    /// withdrawals get consecutive indices even though which validators are
    /// due one changes from slot to slot.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub next_withdrawal_index: WithdrawalIndex,
    /// Where the validator sweep for withdrawals resumes next slot.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub next_withdrawal_validator_index: ValidatorIndex,

    // -- History --
    /// Capella's replacement for whole [`super::shared::HistoricalBatch`]
    /// roots: one summary per historical window, appended the same way.
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub historical_summaries: HistoricalSummaries,
}

// ---------------------------------------------------------------------------
// Blob sidecars
// ---------------------------------------------------------------------------
//
// Both containers are transcribed from `p2p-interface.md` rather than
// `beacon-chain.md`: the specification defines the wire-level blob types in
// the networking document, and neither is ever stored in the state or a
// block body.

/// A request for one blob of one block, without shipping the blob itself.
///
/// The unit the `BlobSidecarsByRoot` request-response protocol asks for: a
/// peer that already knows a block's root and which blob index it is missing
/// names exactly that, rather than the slot-range-based
/// `BlobSidecarsByRange` protocol or a fresh gossip subscription.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot,
)]
pub struct BlobIdentifier {
    pub block_root: Root,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub index: BlobIndex,
}

/// One blob, plus everything needed to check it belongs to a specific block
/// without holding the rest of that block's body.
///
/// `signed_block_header` and `kzg_commitment_inclusion_proof` are what make a
/// sidecar self-verifying: a node that only ever receives this sidecar, never
/// the full [`BeaconBlockBody`], can still check `kzg_commitment` against the
/// block's `body_root` via the merkle proof, and the header itself against
/// the proposer's signature.
///
/// Does not derive `Default`: `blob` is a [`Blob`], bounded by
/// `BYTES_PER_BLOB`, so a derived default would zero that many bytes for no
/// reason every time a placeholder value is needed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot)]
pub struct BlobSidecar {
    /// This blob's position among the block's `blob_kzg_commitments`, which
    /// is also its leaf index for `kzg_commitment_inclusion_proof`.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub index: BlobIndex,
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex")]
    pub blob: Blob,
    pub kzg_commitment: KzgCommitment,
    /// A KZG proof that `blob` evaluates to `kzg_commitment`, checkable
    /// without recomputing the commitment from the whole blob.
    pub kzg_proof: KzgProof,
    /// The header of the block this blob belongs to, signed by its proposer,
    /// which is what `kzg_commitment_inclusion_proof` terminates at.
    pub signed_block_header: SignedBeaconBlockHeader,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub kzg_commitment_inclusion_proof: BlobKzgCommitmentInclusionProof,
}

#[cfg(test)]
mod tests {
    use libssz::{SszDecode as _, SszEncode as _};

    use super::*;

    #[test]
    fn blob_identifier_round_trips_through_ssz() {
        let identifier = BlobIdentifier {
            block_root: Root::repeat_byte(9),
            index: 3,
        };

        let bytes = identifier.to_ssz();
        assert_eq!(BlobIdentifier::from_ssz_bytes(&bytes).unwrap(), identifier);
    }

    #[test]
    fn blob_identifier_is_fixed_size() {
        // A root and an index, with nothing variable-length, so the encoding
        // has one length for every value.
        assert!(<BlobIdentifier as libssz::SszEncode>::is_fixed_size());
        assert_eq!(<BlobIdentifier as libssz::SszEncode>::fixed_size(), 32 + 8);
    }

    #[test]
    fn kzg_commitments_list_round_trips_through_ssz() {
        // Exercises the collection alias directly, without needing a whole
        // block body around it.
        let commitments: KzgCommitments = vec![KzgCommitment([1; 48]), KzgCommitment([2; 48])]
            .try_into()
            .unwrap();

        let bytes = commitments.to_ssz();
        assert_eq!(
            KzgCommitments::from_ssz_bytes(&bytes).unwrap().into_inner(),
            commitments.into_inner()
        );
    }

    #[test]
    fn blob_sidecar_is_fixed_size_despite_carrying_a_blob() {
        // Every field, including `blob` and the inclusion proof, is a fixed-
        // length vector of fixed-size elements, so the whole sidecar encodes
        // with no offsets. Checked at the type level rather than by building
        // an instance, since constructing a full `Blob` (bounded by
        // `BYTES_PER_BLOB`) is unnecessary work for a fact the types already
        // guarantee.
        assert!(<Blob as libssz::SszEncode>::is_fixed_size());
        assert!(<BlobKzgCommitmentInclusionProof as libssz::SszEncode>::is_fixed_size());
        assert!(<BlobSidecar as libssz::SszEncode>::is_fixed_size());
    }

    #[test]
    fn variable_length_containers_carry_offsets() {
        // Each of these holds at least one list, so its encoding begins with
        // offsets rather than being a fixed layout. `ExecutionPayloadHeader`
        // is variable-size too, despite looking header-shaped: `extra_data`
        // is a byte list, not a vector.
        assert!(!<BeaconState as libssz::SszEncode>::is_fixed_size());
        assert!(!<BeaconBlockBody as libssz::SszEncode>::is_fixed_size());
        assert!(!<BeaconBlock as libssz::SszEncode>::is_fixed_size());
        assert!(!<ExecutionPayload as libssz::SszEncode>::is_fixed_size());
        assert!(!<ExecutionPayloadHeader as libssz::SszEncode>::is_fixed_size());
    }
}
