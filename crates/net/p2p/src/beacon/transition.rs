//! Crossing fork-digest boundaries on a running node.
//!
//! [`ForkSchedule`](super::fork_schedule::ForkSchedule) says which digests the
//! node should hold at an epoch; this applies that to the swarm, the wire state
//! and discovery, and works out when to look again. Every fork activation and
//! every blob-parameter-only fork is a boundary, since both move the digest.
//!
//! [`apply`] is idempotent: it computes the target state from the epoch alone
//! and changes only what differs, so the first call at startup (which joins the
//! rest of a window the node started inside) and a call at a live crossing are
//! one code path, and a timer that fires twice does nothing the second time.

use std::time::Duration;

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::constants::MAXIMUM_GOSSIP_CLOCK_DISPARITY;
use ethlambda_types::beacon::preset;
use ethlambda_types::beacon::primitives::{Epoch, ForkDigest};
use ethlambda_types::time::unix_now_ms;
use libp2p::gossipsub::IdentTopic;
use tracing::{error, info};

use super::BeaconWire;
use super::topics::{self, BeaconTopics};
use crate::{P2PServer, Wire, discovery, metrics};

/// How far before a boundary a peer may already be on the next digest and still
/// count as current: clocks disagree by up to the gossip clock disparity.
const BOUNDARY_CLOCK_SKEW: Duration = Duration::from_millis(MAXIMUM_GOSSIP_CLOCK_DISPARITY);

/// The topics [`apply`] joined and left, which it has also handed to the swarm.
/// Returned so the aggregator-subnet handling is observable in tests without a
/// second swarm.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Changes {
    pub(crate) subscribed: Vec<String>,
    pub(crate) unsubscribed: Vec<String>,
}

/// Whether a peer whose `Status` carries `digest` is one to range-sync from.
///
/// Answering a `Status` at any held digest is courtesy; syncing is a choice.
/// After a boundary a peer still on the previous digest has not upgraded, so
/// its chain is not the one being followed. Only the current digest qualifies,
/// or the next one within [`BOUNDARY_CLOCK_SKEW`] of its boundary, for a peer
/// whose clock is slightly ahead of ours.
pub(crate) fn is_syncable_digest(wire: &BeaconWire, digest: ForkDigest, now_ms: u64) -> bool {
    let epoch = epoch_at_ms(&wire.config, wire.genesis_time, now_ms);
    if digest == wire.schedule.digest_at(epoch) {
        return true;
    }
    wire.schedule
        .next_boundary_after(epoch)
        .is_some_and(|next| {
            next.digest == digest
                && delay_until_epoch(
                    &wire.config,
                    wire.genesis_time,
                    next.activation_epoch,
                    now_ms,
                ) <= BOUNDARY_CLOCK_SKEW
        })
}

fn epoch_duration_ms(config: &Config) -> u64 {
    config
        .slot_duration_ms
        .max(1)
        .saturating_mul(preset::SLOTS_PER_EPOCH)
}

/// The epoch the wall clock reads at `now_ms`; epoch 0 before genesis.
pub(crate) fn epoch_at_ms(config: &Config, genesis_time: u64, now_ms: u64) -> Epoch {
    now_ms.saturating_sub(genesis_time.saturating_mul(1000)) / epoch_duration_ms(config)
}

/// How long from `now_ms` until `epoch` begins; zero if it already has.
pub(crate) fn delay_until_epoch(
    config: &Config,
    genesis_time: u64,
    epoch: Epoch,
    now_ms: u64,
) -> Duration {
    let start_ms = genesis_time
        .saturating_mul(1000)
        .saturating_add(epoch.saturating_mul(epoch_duration_ms(config)));
    Duration::from_millis(start_ms.saturating_sub(now_ms))
}

/// Apply the schedule at the current wall-clock epoch, and return how long to
/// wait before the next join, switch or leave. `None` on a lean node or once the
/// schedule has run out.
pub(crate) fn advance(server: &mut P2PServer) -> Option<Duration> {
    let wire = server.wire.beacon()?;
    let now_ms = unix_now_ms();
    let epoch = epoch_at_ms(&wire.config, wire.genesis_time, now_ms);
    let next = wire.schedule.next_change_after(epoch).map(|next| {
        // A timer that fires a hair early would read the same epoch and
        // reschedule itself with no delay, spinning until the boundary; one
        // millisecond floor keeps that to a handful of wakeups.
        delay_until_epoch(&wire.config, wire.genesis_time, next, now_ms)
            .max(Duration::from_millis(1))
    });
    apply(server, epoch);
    next
}

/// Move the node to the state the schedule prescribes at `epoch`.
///
/// 1. Join the topics of every digest the window now covers, including the
///    aggregator-subnet topics already held for the current slot.
/// 2. Leave the topics of every digest the window no longer covers.
/// 3. If the current digest changed, switch what this node publishes and
///    advertises: digest, fork, metadata sequence number, metric, and the
///    `eth2` entry.
/// 4. Point the admission filter at the new entry, admitting every held digest.
pub(crate) fn apply(server: &mut P2PServer, epoch: Epoch) -> Changes {
    let mut changes = Changes::default();
    let Wire::Beacon(wire) = &mut server.wire else {
        return changes;
    };
    let held = wire.schedule.held_at(epoch);
    let current = wire.schedule.current_at(epoch);
    // Checked before anything is joined, so a schedule bug cannot leave topics
    // subscribed but untracked. `held_at` always contains the current digest.
    if !held.iter().any(|entry| entry.digest == current.digest) {
        error!(
            epoch,
            "The fork schedule holds no topics for the current digest"
        );
        return changes;
    }
    let column_subnets = topics::column_subnets(&wire.custody_columns);

    let mut existing = std::mem::take(&mut wire.window_topics);
    existing.push(wire.topics.clone());

    let mut kept: Vec<BeaconTopics> = Vec::with_capacity(held.len());
    for entry in &held {
        if let Some(index) = existing
            .iter()
            .position(|topics| topics.fork_digest == entry.digest)
        {
            kept.push(existing.swap_remove(index));
            continue;
        }
        let joined = BeaconTopics::for_fork(
            entry.fork,
            entry.digest,
            &column_subnets,
            &wire.attestation_subnets,
        );
        for topic in &joined.topics {
            server.swarm_handle.subscribe(topic.clone());
            changes.subscribed.push(topic.to_string());
        }
        for &subnet_id in server.aggregator_subnets.keys() {
            let topic = attestation_topic(entry.digest, subnet_id);
            changes.subscribed.push(topic.to_string());
            server.swarm_handle.subscribe(topic);
        }
        info!(
            fork_digest = %hex::encode(entry.digest),
            fork = entry.fork.as_str(),
            activation_epoch = entry.activation_epoch,
            epoch,
            topics = joined.topics.len(),
            "Joined the topics of an upcoming or live fork digest"
        );
        kept.push(joined);
    }

    for left in existing {
        for topic in &left.topics {
            server.swarm_handle.unsubscribe(topic.clone());
            changes.unsubscribed.push(topic.to_string());
        }
        for &subnet_id in server.aggregator_subnets.keys() {
            let topic = attestation_topic(left.fork_digest, subnet_id);
            changes.unsubscribed.push(topic.to_string());
            server.swarm_handle.unsubscribe(topic);
        }
        info!(
            fork_digest = %hex::encode(left.fork_digest),
            epoch,
            "Left the topics of a past fork digest"
        );
    }

    let index = kept
        .iter()
        .position(|topics| topics.fork_digest == current.digest)
        .expect("`kept` holds one entry per held digest, checked above to include the current");
    wire.topics = kept.remove(index);
    wire.window_topics = kept;

    let switched = wire.fork_digest != current.digest;
    if switched {
        let previous = wire.fork_digest;
        wire.fork_digest = current.digest;
        wire.fork = current.fork;
        wire.metadata_seq_number += 1;
        let digest_hex = hex::encode(current.digest);
        metrics::set_beacon_fork_digest(&digest_hex);
        info!(
            epoch,
            previous_digest = %hex::encode(previous),
            fork_digest = %digest_hex,
            fork = current.fork.as_str(),
            metadata_seq_number = wire.metadata_seq_number,
            "Crossed a fork digest boundary"
        );
    }

    let fork_id = wire.schedule.enr_fork_id(epoch);
    let also_admitted: Vec<ForkDigest> = wire
        .window_topics
        .iter()
        .map(|topics| topics.fork_digest)
        .collect();
    // A beacon wire always runs discovery; `None` is a lean node's, which
    // never reaches a fork boundary.
    if let Some(discovery) = &server.discovery {
        discovery.filter().set_fork_id(fork_id, also_admitted);
    }
    if switched {
        discovery::update_served_enr(&fork_id);
    }
    changes
}

fn attestation_topic(digest: ForkDigest, subnet_id: u64) -> IdentTopic {
    IdentTopic::new(topics::attestation_topic_name(digest, subnet_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::unconnected_beacon_server;
    use ethlambda_types::beacon::fork::ForkName;
    use libssz_types::SszList;

    use ethlambda_types::beacon::config::BlobScheduleEntry;

    const FULU: Epoch = 1_000;
    const BPO: Epoch = 2_000;
    const GLOAS: Epoch = 5_000;

    /// Fulu, one BPO, then gloas, on a chain whose wire the test server builds
    /// with `Root::ZERO` as its genesis validators root.
    fn config() -> Config {
        let mut config = Config::mainnet()
            .with_fork_epoch(ForkName::Altair, 1)
            .with_fork_epoch(ForkName::Bellatrix, 2)
            .with_fork_epoch(ForkName::Capella, 3)
            .with_fork_epoch(ForkName::Deneb, 4)
            .with_fork_epoch(ForkName::Electra, 5)
            .with_fork_epoch(ForkName::Fulu, FULU)
            .with_fork_epoch(ForkName::Gloas, GLOAS);
        config.blob_schedule = SszList::try_from(vec![BlobScheduleEntry {
            epoch: BPO,
            max_blobs_per_block: 15,
        }])
        .expect("within capacity");
        config
    }

    fn digests(server: &P2PServer) -> (ForkDigest, Vec<ForkDigest>) {
        let wire = server.wire.beacon().expect("a beacon wire");
        (
            wire.fork_digest,
            wire.window_topics
                .iter()
                .map(|topics| topics.fork_digest)
                .collect(),
        )
    }

    #[test]
    fn the_epoch_is_read_off_the_slot_duration() {
        let config = Config::mainnet();
        let epoch_ms = config.slot_duration_ms * preset::SLOTS_PER_EPOCH;
        let genesis = 1_000;
        assert_eq!(epoch_at_ms(&config, genesis, 0), 0);
        assert_eq!(
            epoch_at_ms(&config, genesis, genesis * 1000 + epoch_ms - 1),
            0
        );
        assert_eq!(epoch_at_ms(&config, genesis, genesis * 1000 + epoch_ms), 1);
        assert_eq!(
            delay_until_epoch(&config, genesis, 3, genesis * 1000 + epoch_ms),
            Duration::from_millis(2 * epoch_ms)
        );
        assert_eq!(
            delay_until_epoch(&config, genesis, 1, genesis * 1000 + 2 * epoch_ms),
            Duration::ZERO
        );
    }

    #[tokio::test]
    async fn a_live_crossing_joins_switches_and_leaves_in_order() {
        let config = config();
        let mut server = unconnected_beacon_server(config.clone(), 0).await;
        let schedule = server.wire.beacon().expect("beacon").schedule.clone();
        let bpo = schedule.digest_at(BPO);
        let before = schedule.digest_at(BPO - 1);

        // Before the window: only the current digest.
        apply(&mut server, BPO - 2);
        assert_eq!(digests(&server), (before, vec![]));
        let seq_before = server.wire.beacon().unwrap().metadata_seq_number;

        // B-1: the next digest is joined while the old one stays current.
        apply(&mut server, BPO - 1);
        assert_eq!(digests(&server), (before, vec![bpo]));
        assert_eq!(
            server.wire.beacon().unwrap().metadata_seq_number,
            seq_before
        );

        // B: the switch. Publishing and Status move, both digests stay held,
        // and the sequence number is bumped exactly once.
        apply(&mut server, BPO);
        assert_eq!(digests(&server), (bpo, vec![before]));
        let wire = server.wire.beacon().unwrap();
        assert_eq!(wire.metadata_seq_number, seq_before + 1);
        assert!(wire.holds_digest(before) && wire.holds_digest(bpo));

        // Applying again at the same epoch changes nothing.
        apply(&mut server, BPO);
        assert_eq!(digests(&server), (bpo, vec![before]));
        assert_eq!(
            server.wire.beacon().unwrap().metadata_seq_number,
            seq_before + 1
        );

        // B+2: the old topics are left.
        apply(&mut server, BPO + 2);
        assert_eq!(digests(&server), (bpo, vec![]));
        assert!(!server.wire.beacon().unwrap().holds_digest(before));
    }

    #[tokio::test]
    async fn the_gloas_crossing_switches_the_fork_the_node_publishes_in() {
        let config = config();
        let mut server = unconnected_beacon_server(config, 0).await;
        apply(&mut server, GLOAS - 1);
        assert_eq!(server.wire.beacon().unwrap().fork, ForkName::Fulu);
        apply(&mut server, GLOAS);
        assert_eq!(server.wire.beacon().unwrap().fork, ForkName::Gloas);
    }

    #[tokio::test]
    async fn a_node_started_inside_the_window_joins_both_digests() {
        let config = config();
        let mut server = unconnected_beacon_server(config, 0).await;
        let schedule = server.wire.beacon().expect("beacon").schedule.clone();

        // The startup call, at B+1: the node was built on one digest and the
        // window says two.
        apply(&mut server, GLOAS + 1);
        let (current, window) = digests(&server);
        assert_eq!(current, schedule.digest_at(GLOAS));
        assert_eq!(window, vec![schedule.digest_at(GLOAS - 1)]);
    }

    /// While the rollover window holds a fulu and a gloas digest, only the
    /// gloas one carries the two topics gloas adds, whether the gloas digest
    /// is joined ahead of the fork or is current.
    #[tokio::test]
    async fn only_the_gloas_digest_holds_the_gloas_topics() {
        let has_gloas_kinds = |held: &BeaconTopics| {
            topics::GLOAS_TOPIC_KINDS.iter().all(|kind| {
                let name = topics::topic_name(held.fork_digest, kind);
                held.topics.iter().any(|topic| topic.to_string() == name)
            })
        };
        let has_no_gloas_kinds = |held: &BeaconTopics| {
            topics::GLOAS_TOPIC_KINDS.iter().all(|kind| {
                let name = topics::topic_name(held.fork_digest, kind);
                held.topics.iter().all(|topic| topic.to_string() != name)
            })
        };

        let mut server = unconnected_beacon_server(config(), 0).await;
        // Ahead of the fork: fulu is current, gloas is joined in the window.
        apply(&mut server, GLOAS - 1);
        let wire = server.wire.beacon().unwrap();
        assert!(has_no_gloas_kinds(&wire.topics));
        assert!(has_gloas_kinds(&wire.window_topics[0]));

        // After it: gloas is current, fulu is still held.
        apply(&mut server, GLOAS);
        let wire = server.wire.beacon().unwrap();
        assert!(has_gloas_kinds(&wire.topics));
        assert!(has_no_gloas_kinds(&wire.window_topics[0]));
    }

    #[tokio::test]
    async fn a_message_takes_its_fork_from_its_topic() {
        let config = config();
        let mut server = unconnected_beacon_server(config, 0).await;
        apply(&mut server, GLOAS);
        let wire = server.wire.beacon().unwrap();
        // Gloas is current, yet a message on the still-held fulu topic is fulu.
        let fulu = wire.schedule.digest_at(GLOAS - 1);
        let topic = topics::topic_name(fulu, topics::BEACON_BLOCK);
        let digest = topics::topic_digest(&topic).expect("a digest");
        assert_eq!(wire.schedule.fork_for_digest(digest), Some(ForkName::Fulu));
        assert_eq!(wire.fork, ForkName::Gloas);
    }

    fn epoch_start_ms(wire: &BeaconWire, epoch: Epoch) -> u64 {
        wire.genesis_time * 1000 + epoch * epoch_duration_ms(&wire.config)
    }

    #[tokio::test]
    async fn aggregator_subnets_follow_every_held_digest() {
        let mut server = unconnected_beacon_server(config(), 0).await;
        let schedule = server.wire.beacon().expect("beacon").schedule.clone();
        let fulu = schedule.digest_at(GLOAS - 2);
        let gloas = schedule.digest_at(GLOAS);
        server.aggregator_subnets.insert(9, u64::MAX);
        let name = |digest| topics::attestation_topic_name(digest, 9);

        // Settle on the pre-window digest first.
        apply(&mut server, GLOAS - 2);

        // Joining the next digest brings the aggregator subnet along.
        let joined = apply(&mut server, GLOAS - 1);
        assert!(joined.subscribed.contains(&name(gloas)));
        assert!(joined.unsubscribed.is_empty());

        // Leaving the old digest takes it away again.
        let left = apply(&mut server, GLOAS + 2);
        assert!(left.unsubscribed.contains(&name(fulu)));
        assert!(left.subscribed.is_empty());

        // Nothing to do the second time.
        assert_eq!(apply(&mut server, GLOAS + 2), Changes::default());
    }

    #[tokio::test]
    async fn publishing_follows_the_messages_own_slot() {
        let mut server = unconnected_beacon_server(config(), 0).await;
        apply(&mut server, GLOAS - 1);
        let wire = server.wire.beacon().unwrap();
        let first_gloas_slot = GLOAS * preset::SLOTS_PER_EPOCH;
        // Before the switch has run, a slot-B message still names the new digest.
        assert_eq!(wire.fork, ForkName::Fulu);
        assert_eq!(
            wire.digest_for_slot(first_gloas_slot),
            wire.schedule.digest_at(GLOAS)
        );
        assert_eq!(
            wire.digest_for_slot(first_gloas_slot - 1),
            wire.schedule.digest_at(GLOAS - 1)
        );
    }

    #[tokio::test]
    async fn a_digest_that_is_not_held_is_not_published_to() {
        let mut server = unconnected_beacon_server(config(), 0).await;
        apply(&mut server, GLOAS - 2);
        let wire = server.wire.beacon().unwrap();
        let slot_of = |epoch: Epoch| epoch * preset::SLOTS_PER_EPOCH;
        // The current digest, and the next one once its window has opened.
        assert!(wire.publish_digest(slot_of(GLOAS - 2)).is_some());
        assert!(wire.publish_digest(slot_of(GLOAS)).is_none());
        apply(&mut server, GLOAS - 1);
        let wire = server.wire.beacon().unwrap();
        assert!(wire.publish_digest(slot_of(GLOAS)).is_some());
        // A slot long past names a digest that is no longer held.
        assert!(wire.publish_digest(slot_of(FULU)).is_none());
    }

    #[tokio::test]
    async fn sync_starts_only_from_a_peer_on_a_current_digest() {
        let mut server = unconnected_beacon_server(config(), 0).await;
        apply(&mut server, GLOAS);
        let wire = server.wire.beacon().unwrap();
        let old = wire.schedule.digest_at(GLOAS - 1);
        let new = wire.schedule.digest_at(GLOAS);

        // After the boundary: the current digest, not the superseded one, even
        // though the latter is still held (and so still answered).
        let after = epoch_start_ms(wire, GLOAS + 1);
        assert!(wire.holds_digest(old));
        assert!(is_syncable_digest(wire, new, after));
        assert!(!is_syncable_digest(wire, old, after));

        // Just before it, within the skew: a peer whose clock is ahead is fine.
        let skew = BOUNDARY_CLOCK_SKEW.as_millis() as u64;
        let almost = epoch_start_ms(wire, GLOAS) - skew;
        assert!(is_syncable_digest(wire, old, almost));
        assert!(is_syncable_digest(wire, new, almost));

        // Earlier than the skew allows, the next digest is not yet current.
        let early = epoch_start_ms(wire, GLOAS) - skew - 1;
        assert!(!is_syncable_digest(wire, new, early));

        // A digest on no schedule never is.
        assert!(!is_syncable_digest(wire, [0xde, 0xad, 0xbe, 0xef], after));
    }
}
