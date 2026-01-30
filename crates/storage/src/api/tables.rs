/// Tables in the storage layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Table {
    /// Block storage: H256 -> Block
    Blocks,
    /// Block signatures storage: H256 -> BlockSignaturesWithAttestation
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
}

/// All table variants.
pub const ALL_TABLES: [Table; 8] = [
    Table::Blocks,
    Table::BlockSignatures,
    Table::States,
    Table::LatestKnownAttestations,
    Table::LatestNewAttestations,
    Table::GossipSignatures,
    Table::AggregatedPayloads,
    Table::Metadata,
];
