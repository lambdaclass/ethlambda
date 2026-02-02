/// Tables in the storage layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Table {
    /// Block storage: H256 -> Block
    Blocks,
    /// Block signatures storage: H256 -> BlockSignaturesWithAttestation
    ///
    /// Stored separately from blocks because the genesis block has no signatures.
    /// All other blocks must have an entry in this table.
    BlockSignatures,
    /// State storage: H256 -> State
    States,
    /// Known attestations: u64 -> AttestationData
    LatestKnownAttestations,
    /// Pending attestations: u64 -> AttestationData
    LatestNewAttestations,
    /// Gossip signatures: SignatureKey -> ValidatorSignature
    GossipSignatures,
    /// Aggregated proofs: SignatureKey -> Vec<AggregatedSignatureProof>
    AggregatedPayloads,
    /// Metadata: string keys -> various scalar values
    Metadata,
    /// Non-finalized chain index: (slot || root) -> parent_root
    ///
    /// Fast lookup for fork choice without deserializing full blocks.
    /// Pruned when slots become finalized.
    NonFinalizedChain,
}

/// All table variants.
pub const ALL_TABLES: [Table; 9] = [
    Table::Blocks,
    Table::BlockSignatures,
    Table::States,
    Table::LatestKnownAttestations,
    Table::LatestNewAttestations,
    Table::GossipSignatures,
    Table::AggregatedPayloads,
    Table::Metadata,
    Table::NonFinalizedChain,
];
