/// Gossipsub topic prefix identifying the Lean consensus network.
pub const TOPIC_PREFIX: &str = "leanconsensus";
/// Encoding suffix shared by every gossipsub topic (SSZ + snappy).
pub const ENCODING_POSTFIX: &str = "ssz_snappy";

/// Topic name for block gossip.
pub const BLOCK_TOPIC_KIND: &str = "block";
/// Topic name prefix for per-committee attestation subnets.
///
/// Full topic format: `/leanconsensus/{fork_digest}/attestation_{subnet_id}/ssz_snappy`
pub const ATTESTATION_SUBNET_TOPIC_PREFIX: &str = "attestation";
/// Topic name for aggregated attestation gossip.
///
/// Full topic format: `/leanconsensus/{fork_digest}/aggregation/ssz_snappy`
pub const AGGREGATION_TOPIC_KIND: &str = "aggregation";

/// Four-byte fork digest embedded in gossipsub topic strings.
///
/// The spec currently mandates a dummy value ([`ForkDigest::DUMMY`]) until
/// fork identification is properly specified. Displayed as lowercase hex
/// without a `0x` prefix, matching the beacon chain convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ForkDigest(pub [u8; 4]);

impl ForkDigest {
    /// Placeholder fork digest used across Lean consensus clients.
    ///
    /// See <https://github.com/leanEthereum/leanSpec/pull/622>.
    pub const DUMMY: Self = Self([0x12, 0x34, 0x56, 0x78]);
}

impl std::fmt::Display for ForkDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Build the block gossipsub topic for the given fork.
pub fn block_topic(fork_digest: &ForkDigest) -> libp2p::gossipsub::IdentTopic {
    libp2p::gossipsub::IdentTopic::new(format!(
        "/{TOPIC_PREFIX}/{fork_digest}/{BLOCK_TOPIC_KIND}/{ENCODING_POSTFIX}"
    ))
}

/// Build the aggregated-attestation gossipsub topic for the given fork.
pub fn aggregation_topic(fork_digest: &ForkDigest) -> libp2p::gossipsub::IdentTopic {
    libp2p::gossipsub::IdentTopic::new(format!(
        "/{TOPIC_PREFIX}/{fork_digest}/{AGGREGATION_TOPIC_KIND}/{ENCODING_POSTFIX}"
    ))
}

/// Build an attestation subnet gossipsub topic for the given fork and subnet.
pub fn attestation_subnet_topic(
    fork_digest: &ForkDigest,
    subnet_id: u64,
) -> libp2p::gossipsub::IdentTopic {
    libp2p::gossipsub::IdentTopic::new(format!(
        "/{TOPIC_PREFIX}/{fork_digest}/{ATTESTATION_SUBNET_TOPIC_PREFIX}_{subnet_id}/{ENCODING_POSTFIX}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fork_digest_display_is_lowercase_hex_no_prefix() {
        assert_eq!(ForkDigest::DUMMY.to_string(), "12345678");
        assert_eq!(ForkDigest([0x00, 0x00, 0x00, 0x00]).to_string(), "00000000");
        assert_eq!(ForkDigest([0xff, 0xff, 0xff, 0xff]).to_string(), "ffffffff");
        assert_eq!(ForkDigest([0xaa, 0xbb, 0xcc, 0xdd]).to_string(), "aabbccdd");
    }

    #[test]
    fn topics_embed_fork_digest_per_spec() {
        let fd = ForkDigest::DUMMY;
        assert_eq!(
            block_topic(&fd).to_string(),
            "/leanconsensus/12345678/block/ssz_snappy"
        );
        assert_eq!(
            aggregation_topic(&fd).to_string(),
            "/leanconsensus/12345678/aggregation/ssz_snappy"
        );
        assert_eq!(
            attestation_subnet_topic(&fd, 3).to_string(),
            "/leanconsensus/12345678/attestation_3/ssz_snappy"
        );
    }
}
