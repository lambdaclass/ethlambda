/// Tables in the storage layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Table {
    /// Block header storage: H256 -> BlockHeader
    BlockHeaders,
    /// Block body storage: H256 -> BlockBody
    BlockBodies,
    /// Block signatures storage: H256 -> BlockSignaturesWithAttestation
    ///
    /// Stored separately from blocks because the genesis block has no signatures.
    /// All other blocks must have an entry in this table.
    BlockSignatures,
    /// State storage: H256 -> State
    States,
    /// Gossip signatures: SignatureKey -> ValidatorSignature
    GossipSignatures,
    /// Attestation data indexed by tree hash root: H256 -> AttestationData
    AttestationDataByRoot,
    /// Pending aggregated payloads (not yet active in fork choice):
    /// SignatureKey -> Vec<StoredAggregatedPayload>
    LatestNewAggregatedPayloads,
    /// Active aggregated payloads (counted in fork choice):
    /// SignatureKey -> Vec<StoredAggregatedPayload>
    LatestKnownAggregatedPayloads,
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
pub const ALL_TABLES: [Table; 10] = [
    Table::BlockHeaders,
    Table::BlockBodies,
    Table::BlockSignatures,
    Table::States,
    Table::GossipSignatures,
    Table::AttestationDataByRoot,
    Table::LatestNewAggregatedPayloads,
    Table::LatestKnownAggregatedPayloads,
    Table::Metadata,
    Table::LiveChain,
];
