//! The gossipsub topics `ethlambda beacon` subscribes to.
//!
//! Seven global topics, plus two families this node's own node id selects a
//! narrow slice of: the data column subnets it custodies, and the
//! `SUBNETS_PER_NODE` attestation subnets it backbones.
//!
//! "Only what it consumes" is no longer the whole rule, and
//! `beacon_attestation_{subnet_id}` is where it stops applying.
//! `p2p-interface.md` asks every beacon node to hold a long-lived subscription
//! to `SUBNETS_PER_NODE` of these, chosen from its node id, precisely so that
//! the subnets have a stable membership for validators to publish into; phase 0
//! has no shard committees to give them one. That subscription is owed to the
//! network rather than to this node's own head, so what arrives on it is
//! relayed but never applied to fork choice, which is what a lighthouse node
//! with no validators does too.
//!
//! `sync_committee_{0..3}` and `blob_sidecar_{subnet_id}` stay absent; the
//! first arrives with the work that reads it and the second is deneb's format
//! for blobs, deprecated at fulu in favour of the column matrix. Both subnet
//! families that *are* subscribed are subscribed narrowly: this node's sampling
//! size worth of columns rather than the whole matrix, and two attestation
//! subnets rather than all sixty-four, since widening either is what turns this
//! node into a supernode.
//!
//! Publishing is wider than subscribing: the Beacon API gossips a validator
//! client's attestations on whichever subnet each belongs to, through gossipsub
//! fanout, which needs only peers subscribed to that subnet, not this node.

use std::collections::BTreeMap;

use ethlambda_types::beacon::fork::ForkName;
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

/// Topic kind for gloas execution payload envelopes.
pub const EXECUTION_PAYLOAD: &str = "execution_payload";
/// Topic kind for gloas payload timeliness committee votes.
pub const PAYLOAD_ATTESTATION_MESSAGE: &str = "payload_attestation_message";

/// The topic kinds gloas adds to [`SUBSCRIBED_TOPIC_KINDS`], subscribed from
/// the gloas digest on and never under an earlier one.
pub const GLOAS_TOPIC_KINDS: [&str; 2] = [EXECUTION_PAYLOAD, PAYLOAD_ATTESTATION_MESSAGE];

/// Every topic kind this node subscribes to at every fork, in the order they
/// are subscribed. [`GLOAS_TOPIC_KINDS`] follow from gloas.
pub const SUBSCRIBED_TOPIC_KINDS: [&str; 7] = [
    BEACON_BLOCK,
    BEACON_AGGREGATE_AND_PROOF,
    VOLUNTARY_EXIT,
    PROPOSER_SLASHING,
    ATTESTER_SLASHING,
    BLS_TO_EXECUTION_CHANGE,
    SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF,
];

/// The metric label every data column subnet shares, so the column subnets
/// add one label value rather than one per subnet.
pub const DATA_COLUMN_SIDECAR_KIND: &str = "data_column_sidecar";

/// The metric label every attestation subnet shares, so the backbone subnets
/// add one label value rather than one per subnet. See
/// [`DATA_COLUMN_SIDECAR_KIND`].
pub const BEACON_ATTESTATION_KIND: &str = "beacon_attestation";

/// The metric label for a topic kind this node subscribes to on the beacon
/// wire: the kind itself for a global topic, [`DATA_COLUMN_SIDECAR_KIND`] for
/// a column subnet, [`BEACON_ATTESTATION_KIND`] for an attestation subnet.
/// `None` for anything else, lean kinds included, which is what tells the
/// gossip handler a message needs no verdict.
pub fn metric_kind(kind: &str) -> Option<&'static str> {
    if let Some(&global) = SUBSCRIBED_TOPIC_KINDS
        .iter()
        .chain(GLOAS_TOPIC_KINDS.iter())
        .find(|&&known| known == kind)
    {
        return Some(global);
    }
    if data_column_subnet(kind).is_some() {
        return Some(DATA_COLUMN_SIDECAR_KIND);
    }
    attestation_subnet(kind).map(|_| BEACON_ATTESTATION_KIND)
}

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
    crate::gossipsub::topic_kind(topic)
}

/// The fork digest embedded in a full topic name, or `None` if the name is not
/// shaped like a beacon topic or carries something other than four hex bytes.
///
/// A message's fork is the fork its topic's digest names, which is not the
/// digest this node currently advertises while a fork boundary's subscription
/// window is open.
pub fn topic_digest(topic: &str) -> Option<ForkDigest> {
    let digest = topic.split('/').nth(2)?;
    hex::decode(digest).ok()?.try_into().ok()
}

/// The column subnets a custody set maps onto, in custody order.
///
/// A column's subnet is the specification's
/// `compute_subnet_for_data_column_sidecar`, computed rather than assumed so a
/// network that ever separates the two counts still subscribes to the right
/// topic. `BeaconTopics::new` deduplicates.
pub fn column_subnets(custody_columns: &[u64]) -> Vec<u64> {
    custody_columns
        .iter()
        .map(|&column| {
            ethlambda_state_transition::beacon::das::compute_subnet_for_data_column_sidecar(column)
        })
        .collect()
}

/// Topic family for unaggregated attestations, one topic per subnet.
pub const BEACON_ATTESTATION_PREFIX: &str = "beacon_attestation_";

/// The topic carrying one attestation subnet.
pub fn attestation_topic_name(fork_digest: ForkDigest, subnet_id: u64) -> String {
    topic_name(
        fork_digest,
        &format!("{BEACON_ATTESTATION_PREFIX}{subnet_id}"),
    )
}

/// The subnet an attestation topic kind names, or `None` if the kind is not one.
///
/// The digit check keeps a hypothetical global `beacon_attestation_something`
/// from being read as a subnet, the same guard [`data_column_subnet`] has and
/// for the same reason.
pub fn attestation_subnet(kind: &str) -> Option<u64> {
    let suffix = kind.strip_prefix(BEACON_ATTESTATION_PREFIX)?;
    if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    suffix.parse().ok()
}

/// Topic family for data column sidecars, one subnet per column index.
pub const DATA_COLUMN_SIDECAR_PREFIX: &str = "data_column_sidecar_";

/// The topic carrying one column subnet's sidecars.
///
/// Takes the subnet id itself, already reduced: a column index becomes a
/// subnet id via `column_index % DATA_COLUMN_SIDECAR_SUBNET_COUNT` one layer
/// up, in `crate::build_swarm`, since more than one column can share a
/// subnet. This function only ever sees the result.
pub fn data_column_topic_name(fork_digest: ForkDigest, subnet_id: u64) -> String {
    topic_name(
        fork_digest,
        &format!("{DATA_COLUMN_SIDECAR_PREFIX}{subnet_id}"),
    )
}

/// The subnet a column topic kind names, or `None` if the kind is not one.
///
/// The digit check is load-bearing: it is what keeps a future
/// `data_column_sidecar_something` global topic from being read as a subnet.
pub fn data_column_subnet(kind: &str) -> Option<u64> {
    let suffix = kind.strip_prefix(DATA_COLUMN_SIDECAR_PREFIX)?;
    if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    suffix.parse().ok()
}

/// The subscribed topics for one fork digest, built once at startup.
#[derive(Debug, Clone)]
pub struct BeaconTopics {
    pub fork_digest: ForkDigest,
    /// Parallel to [`SUBSCRIBED_TOPIC_KINDS`], then `column_topics`'s values in
    /// ascending subnet order. Derived from `column_topics` rather than built
    /// alongside it, so the two cannot disagree about how many column topics
    /// there are: pushing one entry per `column_subnets` element here, while a
    /// map dedupes the same input, is exactly how the two would drift the
    /// moment a caller ever passed a repeated subnet id.
    pub topics: Vec<IdentTopic>,
    /// The column subnets this node custodies, by subnet id, so a publish or a
    /// re-emission can find its topic without rebuilding the name.
    ///
    /// A `BTreeMap` rather than a `HashMap` so `topics` derives from it in a
    /// stable ascending order, matching `custody_columns`'s own
    /// sorted-ascending convention.
    pub column_topics: BTreeMap<u64, IdentTopic>,
    /// The attestation subnets this node holds a long-lived subscription to,
    /// by subnet id.
    ///
    /// `p2p-interface.md` asks every beacon node to hold `SUBNETS_PER_NODE` of
    /// these whether or not it runs validators, so the subnets have a stable
    /// backbone for validators to publish into; phase 0 has no shard committees
    /// to give them one otherwise. This node subscribes and relays on them
    /// without applying what arrives to its own fork choice, which is what a
    /// lighthouse node with no validators does too.
    ///
    /// A `BTreeMap` for the reason `column_topics` is one.
    pub attestation_topics: BTreeMap<u64, IdentTopic>,
}

impl BeaconTopics {
    /// The topics to hold under `fork_digest`, for the fork that digest names.
    ///
    /// The one place a fork may change which topic kinds exist: a fork that adds
    /// a kind extends its own arm, and the transition then joins those topics
    /// ahead of the boundary as the spec asks. Every arm is named so a new fork
    /// forces a decision here.
    pub fn for_fork(
        fork: ForkName,
        fork_digest: ForkDigest,
        column_subnets: &[u64],
        attestation_subnets: &[u64],
    ) -> Self {
        match fork {
            ForkName::Phase0
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb
            | ForkName::Electra
            | ForkName::Fulu => Self::new(fork_digest, column_subnets, attestation_subnets),
            // Gloas adds the payload envelope and the payload attestation
            // topics, which the follower consumes.
            ForkName::Gloas => Self::with_extra_kinds(
                fork_digest,
                &GLOAS_TOPIC_KINDS,
                column_subnets,
                attestation_subnets,
            ),
            ForkName::Lean => {
                unreachable!("a beacon topic's fork is never Lean: it is absent from ForkName::ALL")
            }
        }
    }

    pub fn new(
        fork_digest: ForkDigest,
        column_subnets: &[u64],
        attestation_subnets: &[u64],
    ) -> Self {
        Self::with_extra_kinds(fork_digest, &[], column_subnets, attestation_subnets)
    }

    /// [`Self::new`] plus the global topic `extra_kinds` a fork adds, placed
    /// after [`SUBSCRIBED_TOPIC_KINDS`] and ahead of the subnet families.
    fn with_extra_kinds(
        fork_digest: ForkDigest,
        extra_kinds: &[&str],
        column_subnets: &[u64],
        attestation_subnets: &[u64],
    ) -> Self {
        // Built first so the map's own key semantics do the deduplication;
        // `topics` below only ever sees what survived that.
        let mut column_topics = BTreeMap::new();
        for &subnet_id in column_subnets {
            column_topics
                .entry(subnet_id)
                .or_insert_with(|| IdentTopic::new(data_column_topic_name(fork_digest, subnet_id)));
        }

        let mut attestation_topics = BTreeMap::new();
        for &subnet_id in attestation_subnets {
            attestation_topics
                .entry(subnet_id)
                .or_insert_with(|| IdentTopic::new(attestation_topic_name(fork_digest, subnet_id)));
        }

        let mut topics: Vec<IdentTopic> = SUBSCRIBED_TOPIC_KINDS
            .iter()
            .chain(extra_kinds)
            .map(|kind| IdentTopic::new(topic_name(fork_digest, kind)))
            .collect();
        topics.extend(column_topics.values().cloned());
        topics.extend(attestation_topics.values().cloned());

        Self {
            fork_digest,
            topics,
            column_topics,
            attestation_topics,
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
        let topics = BeaconTopics::new(MAINNET, &[], &[]);
        assert_eq!(topics.topics.len(), 7);
    }

    #[test]
    fn gloas_adds_the_envelope_and_payload_attestation_topics() {
        let fork_topics = |fork| {
            BeaconTopics::for_fork(fork, MAINNET, &[], &[])
                .topics
                .iter()
                .map(|topic| topic.to_string())
                .collect::<Vec<_>>()
        };
        let gloas = fork_topics(ForkName::Gloas);
        let fulu = fork_topics(ForkName::Fulu);
        assert_eq!(gloas.len(), SUBSCRIBED_TOPIC_KINDS.len() + 2);
        assert_eq!(fulu.len(), SUBSCRIBED_TOPIC_KINDS.len());
        for kind in GLOAS_TOPIC_KINDS {
            let name = topic_name(MAINNET, kind);
            assert!(gloas.contains(&name), "gloas lacks {name}");
            assert!(!fulu.contains(&name), "fulu holds {name}");
            assert_eq!(metric_kind(kind), Some(kind));
        }
        assert_eq!(
            topic_name(MAINNET, EXECUTION_PAYLOAD),
            "/eth2/8c9f62fe/execution_payload/ssz_snappy"
        );
        assert_eq!(
            topic_name(MAINNET, PAYLOAD_ATTESTATION_MESSAGE),
            "/eth2/8c9f62fe/payload_attestation_message/ssz_snappy"
        );
    }

    #[test]
    fn no_subnet_family_is_subscribed() {
        // The narrow subscription set is a design decision, not an accident of
        // how many topics happened to be listed: widening it is what pulls in
        // ~30k BLS verifications per epoch and the whole column bandwidth.
        // `data_column_sidecar_` is no longer in this list: that family is now
        // legitimately subscribed, narrowly, by `only_the_custodied_subnets_are_subscribed`.
        // `beacon_attestation_` has left it for the same reason, and is covered
        // by `only_the_backbone_attestation_subnets_are_subscribed`; what this
        // still pins is that neither family appears unless a caller asked for
        // it, which is what the empty lists here say.
        let excluded = ["beacon_attestation_", "sync_committee_", "blob_sidecar_"];
        for topic in BeaconTopics::new(MAINNET, &[], &[]).topics {
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
    fn the_digest_reads_back_from_a_topic_name() {
        assert_eq!(
            topic_digest(&topic_name(MAINNET, BEACON_BLOCK)),
            Some(MAINNET)
        );
        assert_eq!(
            topic_digest(&attestation_topic_name([0x0a, 0xbc, 0xde, 0xf0], 3)),
            Some([0x0a, 0xbc, 0xde, 0xf0])
        );
        assert_eq!(topic_digest("/eth2/zz/beacon_block/ssz_snappy"), None);
        assert_eq!(topic_digest("/eth2/8c9f62/beacon_block/ssz_snappy"), None);
        assert_eq!(topic_digest("garbage"), None);
    }

    #[test]
    fn topic_kind_reads_the_name_back() {
        for kind in SUBSCRIBED_TOPIC_KINDS {
            assert_eq!(topic_kind(&topic_name(MAINNET, kind)), Some(kind));
        }
    }

    #[test]
    fn a_column_topic_is_the_family_name_and_its_subnet() {
        assert_eq!(
            data_column_topic_name(MAINNET, 7),
            "/eth2/8c9f62fe/data_column_sidecar_7/ssz_snappy"
        );
    }

    #[test]
    fn a_column_topic_reads_its_subnet_back() {
        assert_eq!(data_column_subnet("data_column_sidecar_42"), Some(42));
        assert_eq!(data_column_subnet("data_column_sidecar_"), None);
        assert_eq!(data_column_subnet("data_column_sidecar_x"), None);
        assert_eq!(data_column_subnet("beacon_block"), None);
    }

    #[test]
    fn only_the_custodied_subnets_are_subscribed() {
        // The narrow set is the point: subscribing to all of them is what
        // makes a supernode, at the whole matrix's bandwidth.
        let topics = BeaconTopics::new(MAINNET, &[3, 9], &[]);
        assert_eq!(topics.topics.len(), SUBSCRIBED_TOPIC_KINDS.len() + 2);
        assert_eq!(topics.column_topics.len(), 2);
        assert!(topics.column_topics.contains_key(&3));
        assert!(topics.column_topics.contains_key(&9));
    }

    #[test]
    fn a_repeated_subnet_id_is_subscribed_once() {
        // Two columns can land on the same subnet on a network where
        // `NUMBER_OF_CUSTODY_GROUPS` and `DATA_COLUMN_SIDECAR_SUBNET_COUNT`
        // differ, so the caller's column-to-subnet reduction can hand this
        // constructor the same id twice. `topics` must not gain a duplicate
        // entry for it: that would mean two `subscribe()` calls, two log
        // lines, and a `topics` count `column_topics.len()` disagrees with.
        let topics = BeaconTopics::new(MAINNET, &[3, 3, 9], &[]);
        assert_eq!(topics.topics.len(), SUBSCRIBED_TOPIC_KINDS.len() + 2);
        assert_eq!(topics.column_topics.len(), 2);
    }

    #[test]
    fn a_beacon_kind_is_its_own_label_and_columns_share_one() {
        assert_eq!(metric_kind(BEACON_BLOCK), Some(BEACON_BLOCK));
        assert_eq!(metric_kind(VOLUNTARY_EXIT), Some(VOLUNTARY_EXIT));
        assert_eq!(
            metric_kind("data_column_sidecar_7"),
            Some(DATA_COLUMN_SIDECAR_KIND)
        );
        // Lean topic kinds get no verdict.
        assert_eq!(metric_kind("block"), None);
    }

    #[test]
    fn attestation_subnets_share_one_label() {
        // Every subnet in the family maps to the same label, the same way
        // every data column subnet maps to `DATA_COLUMN_SIDECAR_KIND`: one
        // metric label value per family, not one per subnet, and every
        // subnet message gets a verdict rather than being invisible to
        // `handle_beacon_gossip`.
        assert_eq!(
            metric_kind("beacon_attestation_3"),
            Some(BEACON_ATTESTATION_KIND)
        );
        assert_eq!(
            metric_kind("beacon_attestation_40"),
            Some(BEACON_ATTESTATION_KIND)
        );
        assert_eq!(metric_kind("beacon_attestation_"), None);
    }

    #[test]
    fn column_topics_are_appended_in_ascending_subnet_order() {
        // `column_topics` is a `BTreeMap` specifically so this holds: it is
        // what lets a reader of `topics` predict the tail's order from the
        // subnet ids alone, the same way `custody_columns` is sorted
        // ascending rather than left in whatever order the walk found them.
        let topics = BeaconTopics::new(MAINNET, &[9, 3], &[]);
        let tail: Vec<String> = topics.topics[SUBSCRIBED_TOPIC_KINDS.len()..]
            .iter()
            .map(|topic| topic.to_string())
            .collect();
        assert_eq!(
            tail,
            vec![
                data_column_topic_name(MAINNET, 3),
                data_column_topic_name(MAINNET, 9),
            ]
        );
    }

    #[test]
    fn an_attestation_topic_is_the_family_name_and_its_subnet() {
        assert_eq!(
            attestation_topic_name(MAINNET, 12),
            "/eth2/8c9f62fe/beacon_attestation_12/ssz_snappy"
        );
    }

    #[test]
    fn an_attestation_topic_reads_its_subnet_back() {
        assert_eq!(attestation_subnet("beacon_attestation_7"), Some(7));
        assert_eq!(attestation_subnet("beacon_attestation_"), None);
        assert_eq!(attestation_subnet("beacon_attestation_x"), None);
        // The global aggregate topic shares no prefix with the family, but the
        // block topic is the one a careless `starts_with` would catch.
        assert_eq!(attestation_subnet("beacon_block"), None);
        assert_eq!(attestation_subnet(BEACON_AGGREGATE_AND_PROOF), None);
    }

    /// The backbone is a narrow slice, not the whole family: subscribing to all
    /// sixty-four is what makes a supernode, at every attester's bandwidth.
    #[test]
    fn only_the_backbone_attestation_subnets_are_subscribed() {
        let topics = BeaconTopics::new(MAINNET, &[], &[12, 40]);
        assert_eq!(topics.topics.len(), SUBSCRIBED_TOPIC_KINDS.len() + 2);
        assert_eq!(topics.attestation_topics.len(), 2);
        assert!(topics.attestation_topics.contains_key(&12));
        assert!(topics.attestation_topics.contains_key(&40));
    }

    /// Both families can be subscribed at once, and each keeps its own count:
    /// the two tails are appended in order, columns then attestations.
    #[test]
    fn both_subnet_families_are_subscribed_together() {
        let topics = BeaconTopics::new(MAINNET, &[3, 9], &[40, 12]);
        assert_eq!(topics.topics.len(), SUBSCRIBED_TOPIC_KINDS.len() + 4);
        let tail: Vec<String> = topics.topics[SUBSCRIBED_TOPIC_KINDS.len()..]
            .iter()
            .map(|topic| topic.to_string())
            .collect();
        assert_eq!(
            tail,
            vec![
                data_column_topic_name(MAINNET, 3),
                data_column_topic_name(MAINNET, 9),
                attestation_topic_name(MAINNET, 12),
                attestation_topic_name(MAINNET, 40),
            ]
        );
    }

    /// A repeated subnet id is subscribed once, for the reason its column
    /// counterpart is: two `subscribe()` calls and a `topics` count that
    /// disagrees with the map beside it.
    #[test]
    fn a_repeated_attestation_subnet_is_subscribed_once() {
        let topics = BeaconTopics::new(MAINNET, &[], &[12, 12, 40]);
        assert_eq!(topics.topics.len(), SUBSCRIBED_TOPIC_KINDS.len() + 2);
        assert_eq!(topics.attestation_topics.len(), 2);
    }
}
