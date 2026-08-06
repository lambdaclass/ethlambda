//! Containers whose shape is specific to fulu.
//!
//! Fulu's headline change is how blob data reaches the network. Through
//! electra, verifying a block's blobs means downloading every one of them in
//! full, which stops scaling as the per-block blob count grows. Fulu instead
//! erasure-codes each blob into a wide row of an extended data matrix and
//! slices the matrix into columns, so a node can sample a handful of columns
//! and gain the same statistical confidence that all the data behind them is
//! available, without ever holding the whole matrix itself. [`DataColumnSidecar`]
//! is what a node gossips and serves per column; [`MatrixEntry`] is the
//! row-and-column-addressed cell the matrix is built from, the form
//! `compute_matrix` and `recover_matrix` (`das-core.md`) operate on rather than
//! the per-column grouping a sidecar presents; [`DataColumnsByRootIdentifier`]
//! is how a request-response peer asks for specific columns of a specific
//! block. `BeaconBlockBody`, `BeaconBlock`, `SignedBeaconBlock`,
//! `ExecutionPayload`, and `ExecutionPayloadHeader` are unchanged from electra:
//! a block still commits to the same `blob_kzg_commitments` it always has,
//! since sampling changes how the data behind those commitments travels over
//! the network, not what the block itself contains. This module defines none
//! of those five; state transition code should import them from
//! [`super::electra`] and [`super::deneb`] instead.
//!
//! The other change is [`BeaconState::proposer_lookahead`]. Every fork through
//! electra computes each slot's proposer on demand from the active set and the
//! shuffling seed, so anything that needs to know a proposer ahead of time has
//! to redo that computation itself. Fulu instead has the state precompute a
//! window of upcoming proposers at each epoch boundary, so
//! `get_beacon_proposer_index` becomes a lookup into that window rather than a
//! shuffle.

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::{SszList, SszVector};

use super::altair::SyncCommittee;
use super::deneb::{ExecutionPayloadHeader, KzgCommitments};
use super::electra::{PendingConsolidations, PendingDeposits, PendingPartialWithdrawals};
use super::shared::{
    Balances, BlockRoots, EpochParticipation, Eth1DataVotes, HistoricalRoots, HistoricalSummaries,
    InactivityScores, JustificationBits, RandaoMixes, Slashings, StateRoots, Validators,
};
use super::shared::{BeaconBlockHeader, Checkpoint, Eth1Data, Fork, SignedBeaconBlockHeader};
use crate::preset;
use crate::primitives::{
    Bytes32, ColumnIndex, Epoch, Gwei, KzgProof, Root, Slot, ValidatorIndex, WithdrawalIndex,
};

// ---------------------------------------------------------------------------
// Collection aliases
// ---------------------------------------------------------------------------

/// The window of upcoming proposer indices `BeaconState::proposer_lookahead`
/// precomputes: the rest of the current epoch plus `MIN_SEED_LOOKAHEAD` full
/// epochs beyond it.
pub type ProposerLookahead = SszVector<ValidatorIndex, { preset::PROPOSER_LOOKAHEAD_LENGTH }>;

/// One cell of the extended data matrix: a fixed-size slice of a blob's
/// Reed-Solomon extension, small enough that a node can fetch and verify one
/// without fetching the blob it came from.
pub type Cell = SszVector<u8, { preset::BYTES_PER_CELL }>;

/// One data column: the same-indexed cell from every blob in a block, which is
/// what a [`DataColumnSidecar`] actually carries.
///
/// Bounded by `MAX_BLOB_COMMITMENTS_PER_BLOCK` rather than a column-specific
/// constant, since a column holds exactly one cell per blob in the block, and
/// a block can hold at most that many blobs.
pub type DataColumn = SszList<Cell, { preset::MAX_BLOB_COMMITMENTS_PER_BLOCK }>;

/// The KZG proofs accompanying a [`DataColumn`], one per cell in the same
/// order, so `verify_data_column_sidecar_kzg_proofs` can batch-verify the
/// column against `DataColumnSidecar::kzg_commitments` without a separate
/// lookup.
pub type KzgProofs = SszList<KzgProof, { preset::MAX_BLOB_COMMITMENTS_PER_BLOCK }>;

/// The merkle path proving a [`DataColumnSidecar`]'s `kzg_commitments` sit at
/// their claimed position in the block body.
///
/// Shallower than deneb's per-commitment inclusion proof, because this one
/// proves the root of the whole `blob_kzg_commitments` list at once rather
/// than one leaf: every sidecar of the same block shares the same commitment
/// list, so proving the list once and repeating it in each sidecar is cheaper
/// than a per-commitment proof would be.
pub type KzgCommitmentsInclusionProof =
    SszVector<Bytes32, { preset::KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH }>;

/// The column indices a [`DataColumnsByRootIdentifier`] request asks for.
pub type ColumnIndices = SszList<ColumnIndex, { preset::NUMBER_OF_COLUMNS }>;

/// A row identifier in the extended data matrix, naming which blob in the
/// block a [`MatrixEntry`] belongs to.
///
/// `das-core.md` lists this as a custom type alongside
/// [`crate::primitives::ColumnIndex`], but only [`MatrixEntry`] needs it, so it
/// is defined here instead of in `crate::primitives`.
pub type RowIndex = u64;

// ---------------------------------------------------------------------------
// Data availability sampling
// ---------------------------------------------------------------------------

/// One column's worth of one block's blob data, as gossiped and served over
/// request-response.
///
/// Self-verifying without a separate fetch of the block: `column`,
/// `kzg_commitments`, and `kzg_proofs` are enough to check the cells against
/// the commitments directly, and `kzg_commitments_inclusion_proof` is enough
/// to check that those commitments are the ones the block actually committed
/// to, via `signed_block_header`.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct DataColumnSidecar {
    pub index: ColumnIndex,
    pub column: DataColumn,
    /// The block's full `blob_kzg_commitments`, repeated in every one of that
    /// block's sidecars rather than fetched separately, which is what lets a
    /// sidecar be checked on its own.
    pub kzg_commitments: KzgCommitments,
    pub kzg_proofs: KzgProofs,
    pub signed_block_header: SignedBeaconBlockHeader,
    pub kzg_commitments_inclusion_proof: KzgCommitmentsInclusionProof,
}

/// One cell of the extended data matrix, addressed by which blob it belongs to
/// and which column it sits in.
///
/// What [`DataColumnSidecar::column`] is assembled from: a sidecar groups
/// every blob's cell at one column index together, while a `MatrixEntry`
/// names a single cell independent of that grouping, which is the form
/// `compute_matrix` and `recover_matrix` operate on when demonstrating how a
/// node might store and reconstruct the matrix.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct MatrixEntry {
    pub cell: Cell,
    pub kzg_proof: KzgProof,
    pub column_index: ColumnIndex,
    pub row_index: RowIndex,
}

/// A request for specific columns of a specific block, used by the
/// `DataColumnSidecarsByRoot` request-response protocol.
#[derive(Debug, Clone, Default, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct DataColumnsByRootIdentifier {
    pub block_root: Root,
    pub columns: ColumnIndices,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// The fulu beacon state: electra's 37 fields plus `proposer_lookahead`, 38
/// total, in the specification's order.
///
/// Field order is load-bearing. SSZ encoding and merkleization both follow
/// declaration order, so reordering or omitting a field silently produces a
/// wrong `hash_tree_root`.
///
/// Every field through `pending_consolidations` is identical to electra's,
/// field for field; `proposer_lookahead` is appended after it rather than
/// inserted anywhere earlier, so nothing electra already committed to shifts
/// position.
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
    /// Frozen since capella: further history is committed to by
    /// `historical_summaries` instead. Kept rather than removed so a fulu
    /// state's shape stays hash-tree-root-compatible with every root
    /// committed while this field was still growing.
    pub historical_roots: HistoricalRoots,

    // -- Eth1 --
    pub eth1_data: Eth1Data,
    pub eth1_data_votes: Eth1DataVotes,
    /// How many deposits from the contract have been processed, which is
    /// where the next one will be read from.
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
    /// parallel to `validators`. See altair for why this replaces phase0's
    /// accumulated attestations.
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
    /// The committee that takes over from `current_sync_committee` at the
    /// next sync committee period boundary.
    pub next_sync_committee: SyncCommittee,

    // -- Execution --
    /// The most recently applied execution payload, retained as a header so
    /// the beacon state never has to hold a full payload's transactions and
    /// withdrawals, which consensus never reads back out of the state once
    /// the payload has been applied.
    pub latest_execution_payload_header: ExecutionPayloadHeader,

    // -- Withdrawals --
    /// Where the withdrawal sweep across `validators` last stopped, so
    /// `get_expected_withdrawals` resumes from here each slot instead of
    /// rescanning the registry from the start.
    pub next_withdrawal_index: WithdrawalIndex,
    pub next_withdrawal_validator_index: ValidatorIndex,

    // -- History (capella) --
    /// The commitment to history from capella onward, appended to instead of
    /// `historical_roots` once that field was frozen.
    pub historical_summaries: HistoricalSummaries,

    // -- Deposits, exits, and consolidations (electra) --
    /// The deposit contract log index at which the state switched from
    /// crediting `Eth1Data` votes to crediting execution layer deposit
    /// requests directly, or `UNSET_DEPOSIT_REQUESTS_START_INDEX` before the
    /// first request arrives.
    pub deposit_requests_start_index: u64,
    /// Deposit churn left over from the current epoch's activation queue,
    /// carried into the next epoch rather than wasted.
    pub deposit_balance_to_consume: Gwei,
    /// Exit churn left over from the current epoch's exit queue, carried
    /// forward the same way as `deposit_balance_to_consume`.
    pub exit_balance_to_consume: Gwei,
    /// The earliest epoch the exit queue has not yet exhausted its churn for.
    pub earliest_exit_epoch: Epoch,
    /// Consolidation churn left over from the current epoch's consolidation
    /// queue.
    pub consolidation_balance_to_consume: Gwei,
    /// The earliest epoch the consolidation queue has not yet exhausted its
    /// churn for.
    pub earliest_consolidation_epoch: Epoch,
    /// Deposits credited on the execution layer but not yet applied to the
    /// registry, drained a bounded number at a time each epoch.
    pub pending_deposits: PendingDeposits,
    /// Partial withdrawals requested but not yet paid out.
    pub pending_partial_withdrawals: PendingPartialWithdrawals,
    /// Validator consolidations requested but not yet applied.
    pub pending_consolidations: PendingConsolidations,

    // -- Proposer lookahead (fulu) --
    /// The proposer for every slot from the start of the current epoch
    /// through `MIN_SEED_LOOKAHEAD` full epochs ahead, precomputed at each
    /// epoch boundary by `process_proposer_lookahead` so that
    /// `get_beacon_proposer_index` becomes a lookup into this vector rather
    /// than a shuffle computed on demand.
    pub proposer_lookahead: ProposerLookahead,
}

#[cfg(test)]
mod tests {
    use libssz::{SszDecode as _, SszEncode as _};

    use super::*;

    #[test]
    fn beacon_state_and_data_column_sidecar_are_variable_size() {
        // Both hold at least one list, so both begin their encoding with
        // offsets rather than a fixed layout. Checked at the type level, since
        // building a full state or a full sidecar is not needed to know this.
        assert!(!<BeaconState as libssz::SszEncode>::is_fixed_size());
        assert!(!<DataColumnSidecar as libssz::SszEncode>::is_fixed_size());
        // A request identifier holds a list of columns too.
        assert!(!<DataColumnsByRootIdentifier as libssz::SszEncode>::is_fixed_size());
    }

    #[test]
    fn matrix_entry_is_fixed_size() {
        // A cell, a proof, and two indices: nothing variable-length, unlike
        // the sidecar that groups many matrix entries together per column.
        assert!(<MatrixEntry as libssz::SszEncode>::is_fixed_size());
    }

    #[test]
    fn matrix_entry_round_trips_through_ssz() {
        // One cell is small enough to build directly in a test, unlike a full
        // data column, which would need one cell per blob in a block.
        let cell = Cell::try_from(vec![7u8; preset::BYTES_PER_CELL]).unwrap();
        let entry = MatrixEntry {
            cell,
            kzg_proof: KzgProof([1; crate::primitives::KZG_POINT_SIZE]),
            column_index: 3,
            row_index: 0,
        };

        let bytes = entry.to_ssz();
        assert_eq!(MatrixEntry::from_ssz_bytes(&bytes).unwrap(), entry);
    }

    #[test]
    fn data_columns_by_root_identifier_round_trips_with_some_columns() {
        let identifier = DataColumnsByRootIdentifier {
            block_root: Root::repeat_byte(9),
            columns: ColumnIndices::try_from(vec![0, 1, 42]).unwrap(),
        };

        let bytes = identifier.to_ssz();
        assert_eq!(
            DataColumnsByRootIdentifier::from_ssz_bytes(&bytes).unwrap(),
            identifier
        );
    }

    #[test]
    fn data_columns_by_root_identifier_round_trips_while_empty() {
        let identifier = DataColumnsByRootIdentifier::default();

        let bytes = identifier.to_ssz();
        assert_eq!(
            DataColumnsByRootIdentifier::from_ssz_bytes(&bytes).unwrap(),
            identifier
        );
    }
}
