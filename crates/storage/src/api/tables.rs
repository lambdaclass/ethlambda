/// Tables in the storage layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Table {
    /// Block header storage: H256 -> BlockHeader
    BlockHeaders,
    /// Block body storage: H256 -> BlockBody
    BlockBodies,
    /// Block proof storage: (slot || root) -> BlockProof
    ///
    /// Stored separately from blocks because the genesis block has no proof.
    /// Keyed by slot || root so pruning can scan in slot order and stop early.
    /// Non-genesis blocks have an entry until finalized: proofs below the
    /// finalized boundary are pruned (`prune_old_block_proofs`), while
    /// headers and bodies are kept forever.
    BlockProof,
    /// Canonical block index: slot -> block root
    BlockRoots,
    /// State storage: H256 -> State
    ///
    /// Holds full-state snapshots only: the bootstrap anchor plus one anchor
    /// every `SNAPSHOT_ANCHOR_INTERVAL` slots. Never pruned. Non-anchor states live in `StateDiffs` and
    /// are reconstructed on demand (memoized by an in-memory cache).
    States,
    /// State diffs: H256 -> StateDiff
    ///
    /// Parent-linked diff written for every non-genesis state. Never pruned, so
    /// it preserves full state history. See `get_state` for reconstruction.
    StateDiffs,
    /// Metadata: string keys -> various scalar values
    Metadata,
    /// Live chain index: (slot || root) -> parent_root
    ///
    /// Fast lookup for fork choice without deserializing full blocks.
    /// Includes finalized blocks (anchor) and all non-finalized blocks.
    /// Pruned when slots become finalized (keeps finalized block itself).
    LiveChain,
    /// Data column sidecars: (slot || block_root || column_index) -> DataColumnSidecar
    ///
    /// Written on arrival rather than at block import, so the availability
    /// check can read them before the block they belong to is imported, and so
    /// a restart keeps what this node already paid to verify. Keyed slot-first
    /// for the same reason `BlockProof` is: the by-range handler scans a slot
    /// window, and a future pruner scans in slot order and stops early.
    ///
    /// The only table with no pruning rule. Growth is bounded by nothing yet;
    /// `MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS` is where a pruner lands.
    DataColumns,
    /// Data column sidecars parked until their parent block has a post-state:
    /// (slot || block_root || column_index) -> DataColumnSidecar
    ///
    /// Deliberately not `DataColumns`. A sidecar lands here before its
    /// inclusion proof, its KZG batch and its proposer signature have been
    /// checked, because the proposer check needs a post-state the parent does
    /// not have yet, and the other two are held back so a replay pays for them
    /// once rather than once per attempt. `DataColumns` is what
    /// [`Store::data_column_indices_for`] reads and so what the data
    /// availability gate believes; an unverified row there would let a peer
    /// satisfy the gate with a column nothing ever judged.
    ///
    /// Same key as `DataColumns`, so a row moves between the two without
    /// re-deriving anything. Emptied by the replay that verifies a row and by
    /// the finality eviction that gives up on one.
    PendingDataColumns,
}

/// All table variants.
pub const ALL_TABLES: [Table; 10] = [
    Table::BlockHeaders,
    Table::BlockBodies,
    Table::BlockProof,
    Table::BlockRoots,
    Table::States,
    Table::StateDiffs,
    Table::Metadata,
    Table::LiveChain,
    Table::DataColumns,
    Table::PendingDataColumns,
];

impl Table {
    /// Human-readable name for metrics labels.
    pub fn name(self) -> &'static str {
        match self {
            Table::BlockHeaders => "block_headers",
            Table::BlockBodies => "block_bodies",
            Table::BlockProof => "block_proof",
            Table::BlockRoots => "block_roots",
            Table::States => "states",
            Table::StateDiffs => "state_diffs",
            Table::Metadata => "metadata",
            Table::LiveChain => "live_chain",
            Table::DataColumns => "data_columns",
            Table::PendingDataColumns => "pending_data_columns",
        }
    }
}
