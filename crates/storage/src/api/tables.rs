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
    /// State storage: H256 -> State
    States,
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
pub const ALL_TABLES: [Table; 6] = [
    Table::BlockHeaders,
    Table::BlockBodies,
    Table::BlockSignatures,
    Table::States,
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
            Table::States => "states",
            Table::Metadata => "metadata",
            Table::LiveChain => "live_chain",
        }
    }
}
