/// Topic kind for block gossip
pub const BLOCK_TOPIC_KIND: &str = "block";
/// Topic kind prefix for per-committee attestation subnets.
///
/// Full topic format: `/leanconsensus/{network}/attestation_{subnet_id}/ssz_snappy`
pub const ATTESTATION_SUBNET_TOPIC_PREFIX: &str = "attestation";
/// Topic kind for aggregated attestation gossip.
///
/// Full topic format: `/leanconsensus/{network}/aggregation/ssz_snappy`
pub const AGGREGATION_TOPIC_KIND: &str = "aggregation";

// TODO: make this configurable (e.g., via GenesisConfig or CLI)
pub const NETWORK_NAME: &str = "devnet0";

/// Build an attestation subnet topic for the given subnet ID.
pub fn attestation_subnet_topic(subnet_id: u64) -> libp2p::gossipsub::IdentTopic {
    libp2p::gossipsub::IdentTopic::new(format!(
        "/leanconsensus/{NETWORK_NAME}/{ATTESTATION_SUBNET_TOPIC_PREFIX}_{subnet_id}/ssz_snappy"
    ))
}
