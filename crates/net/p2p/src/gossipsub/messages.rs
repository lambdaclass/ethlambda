pub use ethlambda_types::constants::FORK_DIGEST;

/// Topic kind for block gossip
pub const BLOCK_TOPIC_KIND: &str = "block";
/// Topic kind prefix for per-committee attestation subnets.
///
/// Full topic format: `/leanconsensus/{FORK_DIGEST}/attestation_{subnet_id}/ssz_snappy`
pub const ATTESTATION_SUBNET_TOPIC_PREFIX: &str = "attestation";
/// Topic kind for aggregated attestation gossip.
///
/// Full topic format: `/leanconsensus/{FORK_DIGEST}/aggregation/ssz_snappy`
pub const AGGREGATION_TOPIC_KIND: &str = "aggregation";

/// Build the block gossipsub topic.
pub fn block_topic() -> libp2p::gossipsub::IdentTopic {
    libp2p::gossipsub::IdentTopic::new(format!(
        "/leanconsensus/{FORK_DIGEST}/{BLOCK_TOPIC_KIND}/ssz_snappy"
    ))
}

/// Build the aggregated-attestation gossipsub topic.
pub fn aggregation_topic() -> libp2p::gossipsub::IdentTopic {
    libp2p::gossipsub::IdentTopic::new(format!(
        "/leanconsensus/{FORK_DIGEST}/{AGGREGATION_TOPIC_KIND}/ssz_snappy"
    ))
}

/// Build an attestation subnet gossipsub topic for the given subnet.
pub fn attestation_subnet_topic(subnet_id: u64) -> libp2p::gossipsub::IdentTopic {
    libp2p::gossipsub::IdentTopic::new(format!(
        "/leanconsensus/{FORK_DIGEST}/{ATTESTATION_SUBNET_TOPIC_PREFIX}_{subnet_id}/ssz_snappy"
    ))
}
