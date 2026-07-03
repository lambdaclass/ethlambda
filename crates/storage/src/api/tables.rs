/// Tables in the storage layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Table {
    /// Block header storage: H256 -> BlockHeader
    BlockHeaders,
    /// Block body storage: H256 -> BlockBody
    BlockBodies,
    /// Block signatures storage: H256 -> BlockSignatures
    ///
    /// Stored separately from blocks because the genesis block has no signatures.
    /// All other blocks must have an entry in this table.
    BlockSignatures,
    /// Canonical block index: slot -> block root
    BlockRoots,
    /// State storage: H256 -> State
    ///
    /// Holds full-state snapshots only: the bootstrap anchor plus one anchor per
    /// 1024-slot window. Never pruned. Non-anchor states live in `StateDiffs` and
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
}

/// All table variants.
pub const ALL_TABLES: [Table; 7] = [
    Table::BlockHeaders,
    Table::BlockBodies,
    Table::BlockSignatures,
    Table::BlockRoots,
    Table::States,
    Table::StateDiffs,
    Table::Metadata,
    Table::LiveChain,
];

impl Table {
    /// Human-readable name for metrics labels.
    pub fn name(self) -> &'static str {
        match self {
            Table::BlockHeaders => "block_headers",
            Table::BlockBodies => "block_bodies",
            Table::BlockSignatures => "block_signatures",
            Table::BlockRoots => "block_roots",
            Table::States => "states",
            Table::StateDiffs => "state_diffs",
            Table::Metadata => "metadata",
            Table::LiveChain => "live_chain",
        }
    }
}
