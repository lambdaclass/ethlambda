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
