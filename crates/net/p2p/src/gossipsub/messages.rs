/// Fork digest embedded in every gossipsub topic string, as lowercase hex
/// without a `0x` prefix.
///
/// The [leanSpec](https://github.com/leanEthereum/leanSpec/pull/622)
/// currently mandates a dummy value shared across all clients; this will
/// eventually be derived from the fork version and genesis validators root.
// TODO: derive dynamically once the spec defines fork identification.
pub const FORK_DIGEST: &str = "12345678";

/// Topic name for block gossip.
pub const BLOCK_TOPIC_KIND: &str = "block";
/// Topic name prefix for per-committee attestation subnets.
///
/// Full topic format: `/leanconsensus/{FORK_DIGEST}/attestation_{subnet_id}/ssz_snappy`
pub const ATTESTATION_SUBNET_TOPIC_PREFIX: &str = "attestation";
/// Topic name for aggregated attestation gossip.
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
