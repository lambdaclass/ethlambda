//! Containers whose shape is specific to bellatrix.
//!
//! Bellatrix is the merge: block production moves from proof-of-work mining on
//! the execution side to proposal by the beacon chain's validators, and the
//! execution chain's block becomes an opaque payload the beacon block carries
//! rather than a chain validated on its own. Concretely, [`BeaconBlockBody`]
//! appends `execution_payload`, an [`ExecutionPayload`], and [`BeaconState`]
//! appends `latest_execution_payload_header`, an [`ExecutionPayloadHeader`]:
//! the header is what lets a later payload be checked against the one before
//! it (its `parent_hash` must chain to the header's `block_hash`) without the
//! state having to keep the whole payload, transactions included, around.
//!
//! [`ExecutionPayloadHeader`] is otherwise identical to [`ExecutionPayload`]:
//! it replaces `transactions` with `transactions_root`, the same substitution
//! [`super::shared::BeaconBlockHeader`] makes for a beacon block's body.
//!
//! [`PowBlock`] is unrelated to either: it is transcribed from
//! `fork-choice.md` rather than `beacon-chain.md`, and exists only to let fork
//! choice check a candidate terminal proof-of-work block's total difficulty
//! against `TERMINAL_TOTAL_DIFFICULTY` while validating the merge transition
//! block, the one time consensus has to reason about a chain it does not
//! itself produce.
//!
//! Everything else bellatrix touches, sync committees, attestations, and the
//! rest of the block body and state, is unchanged from altair, so this module
//! imports rather than redefines it.

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::{SszList, SszVector};

use super::altair::{SyncAggregate, SyncCommittee};
use super::phase0::{Attestation, AttesterSlashing};
use super::shared::{
    Balances, BeaconBlockHeader, BlockRoots, Checkpoint, Deposit, EpochParticipation, Eth1Data,
    Eth1DataVotes, Fork, HistoricalRoots, InactivityScores, JustificationBits, ProposerSlashing,
    RandaoMixes, SignedVoluntaryExit, Slashings, StateRoots, Validators,
};
use crate::preset;
use crate::primitives::{
    BlsSignature, Bytes32, ExecutionAddress, ExecutionBlockHash, Root, Slot, Uint256,
    ValidatorIndex,
};

// ---------------------------------------------------------------------------
// Execution payload collection aliases
// ---------------------------------------------------------------------------
//
// A const-generic argument that is a path needs braces, so these read
// `{ preset::X }` rather than `preset::X`.

/// One execution-layer transaction, opaque to consensus.
///
/// The specification's `ByteList[MAX_BYTES_PER_TRANSACTION]` rather than a
/// structured type, since consensus never decodes a transaction; it only
/// carries the bytes the execution engine will.
pub type Transaction = SszList<u8, { preset::MAX_BYTES_PER_TRANSACTION }>;

/// The transactions in one [`ExecutionPayload`], in execution order.
pub type Transactions = SszList<Transaction, { preset::MAX_TRANSACTIONS_PER_PAYLOAD }>;

/// Arbitrary proposer-chosen bytes on the execution side of a payload, the
/// execution analogue of a beacon block's `graffiti`.
pub type ExtraData = SszList<u8, { preset::MAX_EXTRA_DATA_BYTES }>;

/// A Bloom filter summarizing this payload's transaction logs, fixed-length
/// because it is a filter rather than a list of entries.
pub type LogsBloom = SszVector<u8, { preset::BYTES_PER_LOGS_BLOOM }>;

// ---------------------------------------------------------------------------
// Execution payload
// ---------------------------------------------------------------------------

/// An execution block, carried inside a [`BeaconBlockBody`] rather than
/// gossiped and validated on its own chain.
///
/// Field order and naming otherwise follow the execution block header; the
/// specification notes that `fee_recipient`, `prev_randao`, and
/// `block_number` correspond to `beneficiary`, `difficulty`, and `number` in
/// the yellow paper, carried over under new names now that consensus, not
/// proof-of-work mining, produces them.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct ExecutionPayload {
    pub parent_hash: ExecutionBlockHash,
    /// Where this block's fees are paid; `beneficiary` in the yellow paper.
    pub fee_recipient: ExecutionAddress,
    /// The execution layer's post-state root, unrelated to the beacon block's
    /// own `state_root`.
    pub state_root: Bytes32,
    pub receipts_root: Bytes32,
    pub logs_bloom: LogsBloom,
    /// The randomness the beacon chain exposes to the EVM for this block;
    /// `difficulty` in the yellow paper before the merge repurposed the
    /// field, since proof-of-work difficulty no longer exists.
    pub prev_randao: Bytes32,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: ExtraData,
    /// This block's EIP-1559 base fee, a `uint256` because the execution
    /// layer's fee market is not bounded to fit a `uint64`.
    pub base_fee_per_gas: Uint256,
    /// This payload's own hash, which the next payload's `parent_hash` must
    /// equal.
    pub block_hash: ExecutionBlockHash,
    pub transactions: Transactions,
}

/// An [`ExecutionPayload`] with its transaction list replaced by a merkle
/// root, so [`BeaconState::latest_execution_payload_header`] can commit to
/// the previous payload without the state growing with every transaction
/// ever included.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct ExecutionPayloadHeader {
    pub parent_hash: ExecutionBlockHash,
    pub fee_recipient: ExecutionAddress,
    pub state_root: Bytes32,
    pub receipts_root: Bytes32,
    pub logs_bloom: LogsBloom,
    pub prev_randao: Bytes32,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: ExtraData,
    pub base_fee_per_gas: Uint256,
    /// The hash of the execution block this header summarizes.
    pub block_hash: ExecutionBlockHash,
    /// The root of the full transaction list [`ExecutionPayload::transactions`]
    /// would have carried, so the header stays a fixed shape regardless of
    /// how many transactions the block had.
    pub transactions_root: Root,
}

// ---------------------------------------------------------------------------
// Blocks
// ---------------------------------------------------------------------------

/// The contents of a block: altair's operations, plus this slot's execution
/// payload.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct BeaconBlockBody {
    /// The proposer's contribution to the chain's randomness, which is a
    /// signature over the current epoch and so cannot be chosen freely.
    pub randao_reveal: BlsSignature,
    /// The proposer's vote on the execution chain's deposit state.
    pub eth1_data: Eth1Data,
    /// Arbitrary proposer-chosen bytes, which consensus never reads.
    pub graffiti: Bytes32,
    pub proposer_slashings: SszList<ProposerSlashing, { preset::MAX_PROPOSER_SLASHINGS }>,
    pub attester_slashings: SszList<AttesterSlashing, { preset::MAX_ATTESTER_SLASHINGS }>,
    pub attestations: SszList<Attestation, { preset::MAX_ATTESTATIONS }>,
    pub deposits: SszList<Deposit, { preset::MAX_DEPOSITS }>,
    pub voluntary_exits: SszList<SignedVoluntaryExit, { preset::MAX_VOLUNTARY_EXITS }>,
    /// The aggregated sync committee signature over the previous slot's block
    /// root, plus which members contributed.
    pub sync_aggregate: SyncAggregate,
    /// This slot's execution block, carried rather than referenced, since a
    /// beacon block and the execution block it produces are proposed and
    /// gossiped together.
    pub execution_payload: ExecutionPayload,
}

/// A block.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct BeaconBlock {
    pub slot: Slot,
    pub proposer_index: ValidatorIndex,
    pub parent_root: Root,
    /// The root of the state after this block is applied, which the state
    /// transition recomputes and compares.
    pub state_root: Root,
    pub body: BeaconBlockBody,
}

#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct SignedBeaconBlock {
    pub message: BeaconBlock,
    pub signature: BlsSignature,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// The bellatrix beacon state: 25 fields, in the specification's order.
///
/// Field order is load-bearing. SSZ encoding and merkleization both follow
/// declaration order, so reordering or omitting a field silently produces a
/// wrong `hash_tree_root`.
///
/// Every field through `next_sync_committee` is identical to altair's, field
/// for field. Bellatrix appends `latest_execution_payload_header`, which is
/// what lets `process_execution_payload` check a proposed block's payload
/// chains to the one actually applied, without the state keeping a full
/// payload's transactions around.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct BeaconState {
    // -- Versioning --
    pub genesis_time: u64,
    /// The root of the genesis validator registry, which separates this chain
    /// from any other running the same fork schedule.
    pub genesis_validators_root: Root,
    pub slot: Slot,
    pub fork: Fork,

    // -- History --
    /// The most recent block's header, with `state_root` left zero until the
    /// slot advances, since a block cannot commit to the root of the state
    /// containing it.
    pub latest_block_header: BeaconBlockHeader,
    pub block_roots: BlockRoots,
    pub state_roots: StateRoots,
    pub historical_roots: HistoricalRoots,

    // -- Eth1 --
    pub eth1_data: Eth1Data,
    pub eth1_data_votes: Eth1DataVotes,
    /// How many deposits from the contract have been processed, which is where
    /// the next one will be read from.
    pub eth1_deposit_index: u64,

    // -- Registry --
    pub validators: Validators,
    pub balances: Balances,

    // -- Randomness --
    pub randao_mixes: RandaoMixes,

    // -- Slashings --
    pub slashings: Slashings,

    // -- Participation --
    /// Per-validator participation flags for the previous epoch, positionally
    /// parallel to `validators`.
    pub previous_epoch_participation: EpochParticipation,
    /// Flags for the current epoch, which become `previous_epoch_participation`
    /// at the next epoch boundary.
    pub current_epoch_participation: EpochParticipation,

    // -- Finality --
    pub justification_bits: JustificationBits,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,

    // -- Inactivity --
    /// Per-validator inactivity score, positionally parallel to `validators`.
    pub inactivity_scores: InactivityScores,

    // -- Sync committees --
    /// The committee currently signing sync aggregates.
    pub current_sync_committee: SyncCommittee,
    /// The committee that takes over from `current_sync_committee` at the next
    /// sync committee period boundary.
    pub next_sync_committee: SyncCommittee,

    // -- Execution --
    /// A commitment to the most recently applied execution payload, so a
    /// later block's payload can be checked against it without the state
    /// keeping the whole payload around.
    pub latest_execution_payload_header: ExecutionPayloadHeader,
}

// ---------------------------------------------------------------------------
// Fork choice
// ---------------------------------------------------------------------------
//
// Transcribed from `fork-choice.md` rather than `beacon-chain.md`, since it
// belongs to the merge transition handshake rather than to ordinary block
// processing.

/// One execution-layer (proof-of-work) block, as reported by
/// `get_pow_block`.
///
/// Fork choice's `is_valid_terminal_pow_block` uses this to check a candidate
/// merge transition block's total difficulty against
/// `TERMINAL_TOTAL_DIFFICULTY`, and its parent's difficulty against the same
/// bound, which is what pins the merge to one specific proof-of-work block
/// rather than any block heavy enough on its own.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct PowBlock {
    pub block_hash: ExecutionBlockHash,
    pub parent_hash: ExecutionBlockHash,
    /// The cumulative proof-of-work difficulty of the chain up to and
    /// including this block, which is what `TERMINAL_TOTAL_DIFFICULTY`
    /// bounds.
    pub total_difficulty: Uint256,
}

#[cfg(test)]
mod tests {
    use libssz::{SszDecode as _, SszEncode as _};

    use super::*;

    /// Builds an otherwise-empty payload with a correctly sized, all-zero
    /// `logs_bloom`, since [`LogsBloom`] is a fixed-length vector rather than
    /// a list and so has no `Default`.
    fn empty_execution_payload() -> ExecutionPayload {
        ExecutionPayload {
            parent_hash: ExecutionBlockHash::zero(),
            fee_recipient: ExecutionAddress::zero(),
            state_root: Bytes32::zero(),
            receipts_root: Bytes32::zero(),
            logs_bloom: LogsBloom::try_from(vec![0u8; preset::BYTES_PER_LOGS_BLOOM]).unwrap(),
            prev_randao: Bytes32::zero(),
            block_number: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: 0,
            extra_data: Default::default(),
            base_fee_per_gas: Uint256::default(),
            block_hash: ExecutionBlockHash::zero(),
            transactions: Default::default(),
        }
    }

    #[test]
    fn sync_committee_and_pow_block_are_fixed_size() {
        // A sync committee is unchanged from altair, and a pow block is three
        // fixed-width fields: neither carries anything variable-length, unlike
        // the execution payload, block, and state that surround them.
        assert!(<SyncCommittee as libssz::SszEncode>::is_fixed_size());
        assert!(<PowBlock as libssz::SszEncode>::is_fixed_size());
    }

    #[test]
    fn variable_length_containers_carry_offsets() {
        // Both the payload and its header hold `extra_data`, a list, so even
        // the header (whose `transactions_root` is fixed-size) begins its
        // encoding with offsets. The state and body inherit variability the
        // same way altair's do, now compounded by the payload they carry.
        assert!(!<ExecutionPayload as libssz::SszEncode>::is_fixed_size());
        assert!(!<ExecutionPayloadHeader as libssz::SszEncode>::is_fixed_size());
        assert!(!<BeaconState as libssz::SszEncode>::is_fixed_size());
        assert!(!<BeaconBlockBody as libssz::SszEncode>::is_fixed_size());
        assert!(!<BeaconBlock as libssz::SszEncode>::is_fixed_size());
    }

    #[test]
    fn execution_payload_round_trips_while_empty() {
        let payload = empty_execution_payload();

        let bytes = payload.to_ssz();
        assert_eq!(ExecutionPayload::from_ssz_bytes(&bytes).unwrap(), payload);
    }

    #[test]
    fn block_body_round_trips_while_empty() {
        // An empty body is the common case for a skipped-operation slot, and it
        // exercises every offset in the encoding with zero-length payloads,
        // plus the fixed-size sync aggregate and the execution payload
        // bellatrix adds alongside them.
        let body = BeaconBlockBody {
            randao_reveal: BlsSignature::default(),
            eth1_data: Eth1Data::default(),
            graffiti: Bytes32::zero(),
            proposer_slashings: Default::default(),
            attester_slashings: Default::default(),
            attestations: Default::default(),
            deposits: Default::default(),
            voluntary_exits: Default::default(),
            sync_aggregate: SyncAggregate::default(),
            execution_payload: empty_execution_payload(),
        };

        let bytes = body.to_ssz();
        assert_eq!(BeaconBlockBody::from_ssz_bytes(&bytes).unwrap(), body);
    }
}
