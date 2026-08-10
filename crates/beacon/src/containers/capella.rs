//! Containers whose shape is specific to capella.
//!
//! Capella's headline change is validator withdrawals: until this fork, a
//! validator's stake could shrink (via slashing or penalties) but never leave
//! the consensus layer, since there was nowhere for it to go. Capella gives it
//! somewhere to go by having every block sweep a bounded slice of the
//! validator registry for anyone who is fully or partially withdrawable and
//! pay them out on the execution side. Concretely: [`ExecutionPayload`] and
//! [`ExecutionPayloadHeader`] gain a `withdrawals`/`withdrawals_root` field so
//! the payout is part of the execution block, [`Withdrawal`] is the payout
//! itself, and [`BeaconState`] gains `next_withdrawal_index` and
//! `next_withdrawal_validator_index` as the sweep's persistent cursor. Keeping
//! a cursor rather than rescanning the whole registry every block is what
//! bounds the sweep's cost regardless of how large the registry grows.
//! [`BLSToExecutionChange`] and [`SignedBLSToExecutionChange`] are the other
//! new operation: a one-time switch from a raw BLS withdrawal credential to
//! an execution address, which is what makes a validator eligible for the
//! sweep in the first place.
//!
//! The other change is `historical_summaries`, imported unchanged from
//! [`super::shared`] rather than redefined here: `historical_roots` is frozen
//! in place at its bellatrix position and slot, and `historical_summaries`
//! takes over accumulating new history from this fork on. The specification
//! notes the two are `hash_tree_root`-compatible (a [`super::shared::HistoricalSummary`]
//! has the same two fields as phase0's `HistoricalBatch`), which is what lets a
//! verifier that only knows one of the two forms still check a historical
//! proof against either.
//!
//! [`ExtraData`](super::bellatrix::ExtraData), [`LogsBloom`](super::bellatrix::LogsBloom),
//! and [`Transactions`](super::bellatrix::Transactions) are unchanged from
//! bellatrix, so this module imports them rather than redefining them.
//! [`ExecutionPayload`] and [`ExecutionPayloadHeader`] themselves are not
//! imported, since every field of both is repeated here with `withdrawals`
//! (respectively `withdrawals_root`) appended, and a derive needs the whole
//! field list in one struct.

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::SszList;

use super::altair::{SyncAggregate, SyncCommittee};
use super::bellatrix::{ExtraData, LogsBloom, Transactions};
use super::phase0::{Attestation, AttesterSlashing};
use super::shared::{
    Balances, BeaconBlockHeader, BlockRoots, Checkpoint, Deposit, EpochParticipation, Eth1Data,
    Eth1DataVotes, Fork, HistoricalRoots, HistoricalSummaries, InactivityScores, JustificationBits,
    ProposerSlashing, RandaoMixes, SignedVoluntaryExit, Slashings, StateRoots, Validators,
};
use crate::preset;
use crate::primitives::{
    BlsPubkey, BlsSignature, Bytes32, ExecutionAddress, ExecutionBlockHash, Gwei, Root, Slot,
    Uint256, ValidatorIndex, WithdrawalIndex,
};

/// Withdrawals a block applies, bounded the same way every other operation
/// list is.
///
/// Unlike the other lists in [`BeaconBlockBody`], a proposer does not choose
/// these: `process_withdrawals` recomputes the expected set from the sweep
/// cursor and rejects a block whose `withdrawals` does not match exactly.
pub type Withdrawals = SszList<Withdrawal, { preset::MAX_WITHDRAWALS_PER_PAYLOAD }>;

// ---------------------------------------------------------------------------
// New containers
// ---------------------------------------------------------------------------

/// One validator's payout, included in an [`ExecutionPayload`] and applied by
/// decreasing the validator's balance by `amount`.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct Withdrawal {
    /// This withdrawal's position in the chain-wide withdrawal sequence,
    /// monotonically increasing and never reused.
    pub index: WithdrawalIndex,
    pub validator_index: ValidatorIndex,
    /// Where the payout is sent, taken from the low bytes of the validator's
    /// eth1 withdrawal credentials.
    pub address: ExecutionAddress,
    pub amount: Gwei,
}

/// A validator's one-time request to switch its withdrawal credentials from a
/// raw BLS public key hash to an execution address.
///
/// Before this operation, a validator's withdrawal credentials commit only to
/// a BLS key, which the execution layer has no way to pay out to. Processing
/// it is what makes a validator eligible for the withdrawal sweep at all: the
/// sweep only considers credentials already in the eth1 form this operation
/// produces.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct BLSToExecutionChange {
    pub validator_index: ValidatorIndex,
    /// The key whose hash the validator's current withdrawal credentials must
    /// match, proving whoever submits this message actually controls them.
    pub from_bls_pubkey: BlsPubkey,
    pub to_execution_address: ExecutionAddress,
}

#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct SignedBLSToExecutionChange {
    pub message: BLSToExecutionChange,
    pub signature: BlsSignature,
}

// ---------------------------------------------------------------------------
// Execution payload
// ---------------------------------------------------------------------------

/// The execution layer's block contents, carried inside [`BeaconBlockBody`].
///
/// Bellatrix's payload, with `withdrawals` appended: an execution block can
/// now retire validator balances directly, so the payload has to carry the
/// withdrawals it applies alongside the transactions it applies.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct ExecutionPayload {
    pub parent_hash: ExecutionBlockHash,
    pub fee_recipient: ExecutionAddress,
    /// The execution layer's own state root, unrelated to the enclosing
    /// [`BeaconBlock`]'s `state_root`: the two layers keep separate state and
    /// neither commits to the other's.
    pub state_root: Bytes32,
    pub receipts_root: Bytes32,
    pub logs_bloom: LogsBloom,
    /// The randao mix consensus supplied for this slot, which the execution
    /// layer must be given so it can be verified against
    /// `get_randao_mix(state, get_current_epoch(state))`.
    pub prev_randao: Bytes32,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    /// Arbitrary bytes the execution client attaches to the block; consensus
    /// never reads them.
    pub extra_data: ExtraData,
    pub base_fee_per_gas: Uint256,
    pub block_hash: ExecutionBlockHash,
    pub transactions: Transactions,
    /// The payouts this block applies, computed deterministically by
    /// `get_expected_withdrawals` from the state's sweep cursor rather than
    /// chosen by the proposer.
    pub withdrawals: Withdrawals,
}

/// What the state retains of an [`ExecutionPayload`] after processing it: the
/// same fields, but with `transactions` and `withdrawals` replaced by their
/// roots so the state does not have to keep every payload in full forever.
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
    pub block_hash: ExecutionBlockHash,
    /// The merkle root of the corresponding [`ExecutionPayload::transactions`].
    pub transactions_root: Root,
    /// The merkle root of the corresponding [`ExecutionPayload::withdrawals`].
    pub withdrawals_root: Root,
}

// ---------------------------------------------------------------------------
// Blocks
// ---------------------------------------------------------------------------

/// The contents of a block: bellatrix's operations, plus a validator's
/// withdrawal credential switch.
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
    /// The execution layer block this beacon block wraps.
    pub execution_payload: ExecutionPayload,
    /// A validator's one-time withdrawal credential switch, capella's new
    /// operation type. `process_operations` runs it last, the same position it
    /// holds here, so it never affects this same slot's withdrawal sweep: that
    /// sweep already ran, against whatever credentials were in effect before
    /// this block.
    pub bls_to_execution_changes:
        SszList<SignedBLSToExecutionChange, { preset::MAX_BLS_TO_EXECUTION_CHANGES }>,
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

/// The capella beacon state: 28 fields, in the specification's order.
///
/// Field order is load-bearing. SSZ encoding and merkleization both follow
/// declaration order, so reordering or omitting a field silently produces a
/// wrong `hash_tree_root`.
///
/// Fields through `next_sync_committee` are identical to bellatrix's, field for
/// field, including `historical_roots`: it keeps its bellatrix position but is
/// frozen from this fork on, since `historical_summaries` (appended below) is
/// where new history accumulates instead. `latest_execution_payload_header`
/// also keeps its name and position, but changes type: it is this module's own
/// [`ExecutionPayloadHeader`], with `withdrawals_root` appended, not
/// bellatrix's. Capella then appends `next_withdrawal_index`,
/// `next_withdrawal_validator_index`, and `historical_summaries`.
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
    /// Frozen as of this fork: no longer appended to. See
    /// [`Self::historical_summaries`].
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
    /// The most recently processed execution payload, kept as a header rather
    /// than in full.
    pub latest_execution_payload_header: ExecutionPayloadHeader,

    // -- Withdrawals --
    /// The index the next withdrawal will use.
    pub next_withdrawal_index: WithdrawalIndex,
    /// Where the next withdrawal sweep resumes, wrapping around the validator
    /// registry. Advancing a persistent cursor rather than rescanning from
    /// index zero every block is what bounds `get_expected_withdrawals`' work
    /// regardless of how large the registry grows.
    pub next_withdrawal_validator_index: ValidatorIndex,

    // -- History (continued) --
    /// Accumulated block/state root commitments, one appended per historical
    /// root period, replacing the growth of `historical_roots` as of this
    /// fork. See [`super::shared::HistoricalSummary`] for why the two forms
    /// are `hash_tree_root`-compatible.
    pub historical_summaries: HistoricalSummaries,
}

#[cfg(test)]
mod tests {
    use libssz::{SszDecode as _, SszEncode as _};
    use libssz_types::SszVector;

    use super::*;

    fn empty_execution_payload() -> ExecutionPayload {
        ExecutionPayload {
            parent_hash: ExecutionBlockHash::zero(),
            fee_recipient: ExecutionAddress::zero(),
            state_root: Bytes32::zero(),
            receipts_root: Bytes32::zero(),
            logs_bloom: SszVector::try_from(vec![0u8; preset::BYTES_PER_LOGS_BLOOM]).unwrap(),
            prev_randao: Bytes32::zero(),
            block_number: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: 0,
            extra_data: Default::default(),
            base_fee_per_gas: Uint256::zero(),
            block_hash: ExecutionBlockHash::zero(),
            transactions: Default::default(),
            withdrawals: Default::default(),
        }
    }

    #[test]
    fn withdrawal_round_trips_through_ssz() {
        let withdrawal = Withdrawal {
            index: 5,
            validator_index: 9,
            address: ExecutionAddress::repeat_byte(0xab),
            amount: 32_000_000_000,
        };

        let bytes = withdrawal.to_ssz();
        assert_eq!(Withdrawal::from_ssz_bytes(&bytes).unwrap(), withdrawal);
    }

    #[test]
    fn signed_bls_to_execution_change_round_trips_through_ssz() {
        let signed_change = SignedBLSToExecutionChange {
            message: BLSToExecutionChange {
                validator_index: 3,
                from_bls_pubkey: BlsPubkey([1; 48]),
                to_execution_address: ExecutionAddress::repeat_byte(0xcd),
            },
            signature: BlsSignature([2; 96]),
        };

        let bytes = signed_change.to_ssz();
        assert_eq!(
            SignedBLSToExecutionChange::from_ssz_bytes(&bytes).unwrap(),
            signed_change
        );
    }

    #[test]
    fn fixed_and_variable_length_containers() {
        // Withdrawal and the BLS-to-execution-change pair hold nothing
        // variable-length, unlike the payload, body, block, and state that
        // carry lists.
        assert!(<Withdrawal as libssz::SszEncode>::is_fixed_size());
        assert!(<BLSToExecutionChange as libssz::SszEncode>::is_fixed_size());
        assert!(<SignedBLSToExecutionChange as libssz::SszEncode>::is_fixed_size());

        // Both payload containers carry at least one list (`extra_data`, at a
        // minimum), so both begin their encoding with offsets.
        assert!(!<ExecutionPayload as libssz::SszEncode>::is_fixed_size());
        assert!(!<ExecutionPayloadHeader as libssz::SszEncode>::is_fixed_size());
        assert!(!<BeaconState as libssz::SszEncode>::is_fixed_size());
        assert!(!<BeaconBlockBody as libssz::SszEncode>::is_fixed_size());
        assert!(!<BeaconBlock as libssz::SszEncode>::is_fixed_size());
    }

    #[test]
    fn block_body_round_trips_while_empty() {
        // An empty body is the common case for a skipped-operation slot, and it
        // exercises every offset in the encoding with zero-length payloads,
        // including the nested offsets inside `execution_payload`.
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
            bls_to_execution_changes: Default::default(),
        };

        let bytes = body.to_ssz();
        assert_eq!(BeaconBlockBody::from_ssz_bytes(&bytes).unwrap(), body);
    }
}
