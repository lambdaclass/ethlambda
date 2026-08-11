//! The gossipsub topics `ethlambda beacon` subscribes to.
//!
//! Seven global topics and no subnet family. The rule is that this node
//! subscribes only to what it consumes, so `beacon_attestation_{0..63}`,
//! `sync_committee_{0..3}`, `data_column_sidecar_{0..127}` and
//! `blob_sidecar_{subnet_id}` are all absent; each arrives with the sub-project
//! that reads it. That is 7 subscriptions rather than 203.

use ethlambda_types::beacon::primitives::ForkDigest;
use libp2p::gossipsub::IdentTopic;

/// Topic kind for beacon block gossip.
pub const BEACON_BLOCK: &str = "beacon_block";
/// Topic kind for aggregated attestations with their selection proofs.
pub const BEACON_AGGREGATE_AND_PROOF: &str = "beacon_aggregate_and_proof";
/// Topic kind for voluntary exits.
pub const VOLUNTARY_EXIT: &str = "voluntary_exit";
/// Topic kind for proposer slashings.
pub const PROPOSER_SLASHING: &str = "proposer_slashing";
/// Topic kind for attester slashings.
pub const ATTESTER_SLASHING: &str = "attester_slashing";
/// Topic kind for BLS-to-execution withdrawal credential changes.
pub const BLS_TO_EXECUTION_CHANGE: &str = "bls_to_execution_change";
/// Topic kind for aggregated sync committee contributions.
pub const SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF: &str = "sync_committee_contribution_and_proof";

/// Every topic kind this node subscribes to, in the order they are subscribed.
pub const SUBSCRIBED_TOPIC_KINDS: [&str; 7] = [
    BEACON_BLOCK,
    BEACON_AGGREGATE_AND_PROOF,
    VOLUNTARY_EXIT,
    PROPOSER_SLASHING,
    ATTESTER_SLASHING,
    BLS_TO_EXECUTION_CHANGE,
    SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF,
];

/// Build one topic name: `/eth2/{fork_digest}/{kind}/ssz_snappy`.
///
/// `fork_digest` is lowercase hex with no `0x` prefix, which is what every
/// beacon client emits and what the topic hash is therefore taken over.
pub fn topic_name(fork_digest: ForkDigest, kind: &str) -> String {
    format!("/eth2/{}/{kind}/ssz_snappy", hex::encode(fork_digest))
}

/// The topic kind embedded in a full topic name, or `None` if the name is not
/// shaped like a beacon topic.
///
/// `/eth2/{digest}/{kind}/ssz_snappy` splits on `/` into
/// `["", "eth2", digest, kind, "ssz_snappy"]`, so the kind is at index 3 —
/// the same index lean's `/leanconsensus/…` names put it at.
pub fn topic_kind(topic: &str) -> Option<&str> {
    topic.split('/').nth(3)
}

/// The subscribed topics for one fork digest, built once at startup.
#[derive(Debug, Clone)]
pub struct BeaconTopics {
    pub fork_digest: ForkDigest,
    /// Parallel to [`SUBSCRIBED_TOPIC_KINDS`].
    pub topics: Vec<IdentTopic>,
}

impl BeaconTopics {
    pub fn new(fork_digest: ForkDigest) -> Self {
        let topics = SUBSCRIBED_TOPIC_KINDS
            .iter()
            .map(|kind| IdentTopic::new(topic_name(fork_digest, kind)))
            .collect();
        Self {
            fork_digest,
            topics,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mainnet's current digest, per docs/discovery.md.
    const MAINNET: ForkDigest = [0x8c, 0x9f, 0x62, 0xfe];

    #[test]
    fn topic_names_are_the_mainnet_strings() {
        assert_eq!(
            topic_name(MAINNET, BEACON_BLOCK),
            "/eth2/8c9f62fe/beacon_block/ssz_snappy"
        );
        assert_eq!(
            topic_name(MAINNET, BEACON_AGGREGATE_AND_PROOF),
            "/eth2/8c9f62fe/beacon_aggregate_and_proof/ssz_snappy"
        );
        assert_eq!(
            topic_name(MAINNET, SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF),
            "/eth2/8c9f62fe/sync_committee_contribution_and_proof/ssz_snappy"
        );
    }

    #[test]
    fn the_digest_is_lowercase_hex_without_a_prefix() {
        // A leading 0x, uppercase, or a Debug-formatted byte array would all
        // produce a topic hash no peer agrees with, and gossipsub would report
        // a healthy mesh of zero peers rather than an error.
        let name = topic_name([0x0a, 0xbc, 0xde, 0xf0], BEACON_BLOCK);
        assert!(name.starts_with("/eth2/0abcdef0/"), "got {name}");
    }

    #[test]
    fn subscriptions_are_exactly_the_seven_global_topics() {
        let topics = BeaconTopics::new(MAINNET);
        assert_eq!(topics.topics.len(), 7);
    }

    #[test]
    fn no_subnet_family_is_subscribed() {
        // The narrow subscription set is a design decision, not an accident of
        // how many topics happened to be listed: widening it is what pulls in
        // ~30k BLS verifications per epoch and the whole column bandwidth.
        let excluded = [
            "beacon_attestation_",
            "sync_committee_",
            "blob_sidecar_",
            "data_column_sidecar_",
        ];
        for topic in BeaconTopics::new(MAINNET).topics {
            let name = topic.to_string();
            let kind = topic_kind(&name).expect("a well-formed topic name");
            for prefix in excluded {
                // A subnet topic is the family prefix followed by its index and
                // nothing else, as in `sync_committee_3`. The digit check is
                // load-bearing: the global `sync_committee_contribution_and_proof`
                // shares the family prefix and *is* legitimately subscribed.
                let is_subnet = kind.strip_prefix(prefix).is_some_and(|index| {
                    !index.is_empty() && index.bytes().all(|b| b.is_ascii_digit())
                });
                assert!(!is_subnet, "{name} is a {prefix} subnet topic");
            }
        }
    }

    #[test]
    fn topic_kind_reads_the_name_back() {
        for kind in SUBSCRIBED_TOPIC_KINDS {
            assert_eq!(topic_kind(&topic_name(MAINNET, kind)), Some(kind));
        }
    }
}
