//! Sync committee subnets and publishing for the beacon wire.
//!
//! Sync subnets are joined on demand only, from a validator client's
//! `sync_committee_subscriptions` request, and advertised in MetaData's
//! `syncnets` (never the ENR, which cannot be replaced at runtime). Nothing
//! here subscribes without a request: validating every subnet permanently
//! would cost every follower up to a committee's worth of BLS verifications
//! per slot.
//!
//! These are the entry points the `RpcToP2P` handlers call, plus the two the
//! 12 s sweep calls. A joined subnet is held in
//! [`BeaconWire::sync_committee_subnets`](super::BeaconWire) with the epoch it
//! is needed until (exclusive), and is subscribed under every digest the wire
//! holds, so a fork boundary's window is covered;
//! [`super::transition::apply`] carries the set across digests.

use ethlambda_state_transition::beacon::sync_committee_pool::RETAINED_SLOTS;
use ethlambda_types::beacon::constants::SYNC_COMMITTEE_SUBNET_COUNT;
use ethlambda_types::beacon::containers::altair::{
    SignedContributionAndProof, SyncCommitteeMessage,
};
use ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;
use ethlambda_types::beacon::primitives::Epoch;
use libp2p::gossipsub::IdentTopic;
use libssz::SszEncode as _;
use tracing::{debug, error, info, warn};

use super::topics;
use crate::gossipsub::compress_message;
use crate::{P2PServer, Wire};

/// Gossip `message` on `sync_committee_{id}` for each of `subnet_ids`, and
/// mark each `(slot, validator, subnet)` seen so a peer's echo is ignored.
///
/// The caller has already checked the message and pooled it; gossip never
/// echoes a node's own messages back, so this only publishes.
pub(crate) fn publish_sync_committee_message(
    server: &mut P2PServer,
    subnet_ids: Vec<u64>,
    message: SyncCommitteeMessage,
) {
    let slot = message.slot;
    let validator = message.validator_index;
    let Some(beacon) = server.wire.beacon() else {
        error!(
            slot,
            validator, "A sync committee message reached a lean node; dropping it"
        );
        return;
    };
    let Some(digest) = beacon.publish_digest(slot) else {
        warn!(
            slot,
            validator,
            "No held fork digest covers this sync committee message's slot; not publishing"
        );
        return;
    };
    let compressed = compress_message(&message.to_ssz());
    for subnet_id in subnet_ids {
        if subnet_id >= SYNC_COMMITTEE_SUBNET_COUNT as u64 {
            error!(
                slot,
                validator, subnet_id, "Sync committee subnet out of range; dropping it"
            );
            continue;
        }
        let topic = IdentTopic::new(topics::sync_committee_topic_name(digest, subnet_id));
        server.swarm_handle.publish(topic, compressed.clone());
        server.seen_sync_messages.record(slot, validator, subnet_id);
        debug!(
            slot,
            validator, subnet_id, "Published sync committee message to gossipsub"
        );
    }
}

/// Gossip `signed` on `sync_committee_contribution_and_proof`, and mark it
/// seen. This node is subscribed to that topic, so it reaches the mesh.
pub(crate) fn publish_sync_committee_contribution(
    server: &mut P2PServer,
    signed: SignedContributionAndProof,
) {
    let contribution = &signed.message.contribution;
    let slot = contribution.slot;
    let subcommittee_index = contribution.subcommittee_index;
    let aggregator = signed.message.aggregator_index;
    let Some(beacon) = server.wire.beacon() else {
        error!(
            slot,
            "A sync committee contribution reached a lean node; dropping it"
        );
        return;
    };
    let Some(digest) = beacon.publish_digest(slot) else {
        warn!(
            slot,
            aggregator, "No held fork digest covers this contribution's slot; not publishing"
        );
        return;
    };
    let topic = IdentTopic::new(topics::topic_name(
        digest,
        topics::SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF,
    ));
    server
        .swarm_handle
        .publish(topic, compress_message(&signed.to_ssz()));
    server.seen_sync_contributions.record(&signed);
    debug!(
        slot,
        subcommittee_index, aggregator, "Published sync committee contribution to gossipsub"
    );
}

/// Join each `(subnet_id, until_epoch)` (exclusive), extending an existing
/// join. Ids past the subnet count are dropped.
pub(crate) fn join_sync_committee_subnets(server: &mut P2PServer, subnets: Vec<(u64, Epoch)>) {
    let subscribed = join(server, subnets);
    if !subscribed.is_empty() {
        info!(topics = subscribed.len(), "Joined sync committee subnets");
    }
}

/// [`join_sync_committee_subnets`], returning the topic names it subscribed.
fn join(server: &mut P2PServer, subnets: Vec<(u64, Epoch)>) -> Vec<String> {
    let Wire::Beacon(wire) = &mut server.wire else {
        return Vec::new();
    };
    let mut joined = Vec::new();
    for (subnet_id, until) in subnets {
        if subnet_id >= SYNC_COMMITTEE_SUBNET_COUNT as u64 {
            continue;
        }
        let held_until = wire
            .sync_committee_subnets
            .entry(subnet_id)
            .or_insert_with(|| {
                joined.push(subnet_id);
                until
            });
        *held_until = (*held_until).max(until);
    }
    // Under every digest the node holds, like the aggregator subnets: while a
    // boundary's window is open, messages are published on either side of it.
    let mut subscribed = Vec::new();
    for &subnet_id in &joined {
        for held in wire.held_topics() {
            let name = topics::sync_committee_topic_name(held.fork_digest, subnet_id);
            server.swarm_handle.subscribe(IdentTopic::new(name.clone()));
            subscribed.push(name);
        }
    }
    if !joined.is_empty() {
        // The advertised `syncnets` changed.
        wire.metadata_seq_number += 1;
    }
    subscribed
}

/// Leave every subnet whose `until_epoch` has been reached.
pub(crate) fn leave_expired_sync_committee_subnets(server: &mut P2PServer) {
    let Some(wire) = server.wire.beacon() else {
        return;
    };
    let epoch = wire.wall_slot() / SLOTS_PER_EPOCH;
    let unsubscribed = leave_expired(server, epoch);
    if !unsubscribed.is_empty() {
        debug!(
            topics = unsubscribed.len(),
            "Left sync committee subnets whose period of need has passed"
        );
    }
}

/// [`leave_expired_sync_committee_subnets`] at a given wall epoch, returning
/// the topic names it unsubscribed.
fn leave_expired(server: &mut P2PServer, epoch: Epoch) -> Vec<String> {
    let Wire::Beacon(wire) = &mut server.wire else {
        return Vec::new();
    };
    let expired: Vec<u64> = wire
        .sync_committee_subnets
        .iter()
        .filter(|&(_, &until)| epoch >= until)
        .map(|(&subnet_id, _)| subnet_id)
        .collect();
    let mut unsubscribed = Vec::new();
    for subnet_id in &expired {
        wire.sync_committee_subnets.remove(subnet_id);
        for held in wire.held_topics() {
            let name = topics::sync_committee_topic_name(held.fork_digest, *subnet_id);
            server
                .swarm_handle
                .unsubscribe(IdentTopic::new(name.clone()));
            unsubscribed.push(name);
        }
    }
    if !expired.is_empty() {
        wire.metadata_seq_number += 1;
    }
    unsubscribed
}

/// Drop pooled messages older than the retained window. Inserts prune as they
/// go; this also runs on the sweep, so a pool nothing is inserted into does not
/// keep stale entries.
pub(crate) fn prune_sync_committee_pool(server: &P2PServer) {
    let Some(wire) = server.wire.beacon() else {
        return;
    };
    let now = wire.wall_slot();
    server
        .sync_committee_pool
        .lock()
        .expect("sync committee pool lock poisoned")
        .prune_before(now.saturating_sub(RETAINED_SLOTS));
}

#[cfg(test)]
mod tests {
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::containers::altair::{
        ContributionAndProof, SyncCommitteeContribution, SyncSubcommitteeBits,
    };
    use ethlambda_types::beacon::fork::ForkName;
    use ethlambda_types::beacon::primitives::Root;

    use super::*;
    use crate::beacon::handler::build_metadata;
    use crate::beacon::messages::BeaconMetaData;
    use crate::beacon::protocols;
    use crate::beacon::transition::apply;
    use crate::test_support::unconnected_beacon_server;

    /// A config whose gloas boundary is 10 epochs after fulu's, so a second
    /// digest can be held.
    fn config_with_boundary() -> (Config, u64) {
        let config = Config::mainnet();
        let gloas = config.fulu_fork_epoch + 10;
        (config.with_fork_epoch(ForkName::Gloas, gloas), gloas)
    }

    fn syncnets_of(server: &P2PServer) -> Vec<bool> {
        let wire = server.wire.beacon().expect("beacon wire");
        let Some(BeaconMetaData::V3(v3)) = build_metadata(wire, protocols::METADATA_V3) else {
            panic!("v3 requested");
        };
        (0..4)
            .map(|id| v3.syncnets.get(id).unwrap_or(false))
            .collect()
    }

    fn seq(server: &P2PServer) -> u64 {
        server
            .wire
            .beacon()
            .expect("beacon wire")
            .metadata_seq_number
    }

    fn one_bit() -> SyncSubcommitteeBits {
        let mut bits = SyncSubcommitteeBits::default();
        bits.set(0, true).expect("position 0 exists");
        bits
    }

    #[tokio::test]
    async fn joining_subscribes_once_per_held_digest_and_extends_until() {
        let (config, gloas) = config_with_boundary();
        let mut server = unconnected_beacon_server(config, 0).await;
        // Open the window so two digests are held.
        apply(&mut server, gloas - 1);
        let wire = server.wire.beacon().expect("beacon wire");
        let digests: Vec<_> = wire.held_topics().map(|held| held.fork_digest).collect();
        assert_eq!(digests.len(), 2);

        let mut got = join(&mut server, vec![(1, 100)]);
        let mut expected: Vec<String> = digests
            .iter()
            .map(|&digest| topics::sync_committee_topic_name(digest, 1))
            .collect();
        expected.sort();
        got.sort();
        assert_eq!(got, expected);

        // A second request for the same subnet subscribes nothing and keeps
        // the later `until`, whichever order they arrive in.
        assert!(join(&mut server, vec![(1, 150)]).is_empty());
        assert!(join(&mut server, vec![(1, 120)]).is_empty());
        let wire = server.wire.beacon().expect("beacon wire");
        assert_eq!(wire.sync_committee_subnets.get(&1), Some(&150));
    }

    #[tokio::test]
    async fn subnet_ids_past_the_count_are_dropped() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let seq_before = seq(&server);
        assert!(join(&mut server, vec![(4, 10), (99, 10)]).is_empty());
        let wire = server.wire.beacon().expect("beacon wire");
        assert!(wire.sync_committee_subnets.is_empty());
        assert_eq!(seq(&server), seq_before);
    }

    #[tokio::test]
    async fn a_subnet_is_left_at_its_until_epoch() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        join(&mut server, vec![(0, 50), (3, 60)]);

        assert!(leave_expired(&mut server, 49).is_empty());
        let left = leave_expired(&mut server, 50);
        assert_eq!(left.len(), 1);
        assert!(left[0].contains("/sync_committee_0/"));
        let wire = server.wire.beacon().expect("beacon wire");
        assert_eq!(
            wire.sync_committee_subnets
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![3]
        );

        let left = leave_expired(&mut server, 1_000);
        assert!(left[0].contains("/sync_committee_3/"));
        let wire = server.wire.beacon().expect("beacon wire");
        assert!(wire.sync_committee_subnets.is_empty());
    }

    #[tokio::test]
    async fn metadata_advertises_the_joined_subnets_and_the_sequence_moves_only_on_change() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let start = seq(&server);
        assert_eq!(syncnets_of(&server), [false; 4]);

        join(&mut server, vec![(1, 100), (2, 100)]);
        assert_eq!(syncnets_of(&server), [false, true, true, false]);
        assert_eq!(seq(&server), start + 1);

        // Neither a repeat nor an extension changes what is advertised.
        join(&mut server, vec![(1, 100)]);
        join(&mut server, vec![(2, 200)]);
        assert_eq!(seq(&server), start + 1);

        join(&mut server, vec![(3, 100)]);
        assert_eq!(seq(&server), start + 2);

        // Nothing expired: no change.
        leave_expired(&mut server, 99);
        assert_eq!(seq(&server), start + 2);
        leave_expired(&mut server, 100);
        assert_eq!(syncnets_of(&server), [false, false, true, false]);
        assert_eq!(seq(&server), start + 3);
    }

    #[tokio::test]
    async fn publishing_a_message_marks_each_subnet_seen() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let slot = server.wire.beacon().expect("beacon wire").wall_slot();
        // The test server's wire carries a placeholder digest; settle on the
        // schedule's so the slot's digest is a held one.
        apply(
            &mut server,
            slot / ethlambda_types::beacon::preset::SLOTS_PER_EPOCH,
        );
        let message = SyncCommitteeMessage {
            slot,
            beacon_block_root: Root::repeat_byte(1),
            validator_index: 9,
            signature: Default::default(),
        };

        publish_sync_committee_message(&mut server, vec![1, 2, 4], message);
        assert!(server.seen_sync_messages.contains(slot, 9, 1));
        assert!(server.seen_sync_messages.contains(slot, 9, 2));
        assert!(!server.seen_sync_messages.contains(slot, 9, 0));
        // An out-of-range subnet is dropped, not recorded.
        assert!(!server.seen_sync_messages.contains(slot, 9, 4));
    }

    #[tokio::test]
    async fn a_message_for_a_slot_no_held_digest_covers_is_not_marked_seen() {
        let (config, gloas) = config_with_boundary();
        let mut server = unconnected_beacon_server(config, 0).await;
        apply(&mut server, gloas - 20);
        // A slot past the boundary names a digest nobody holds yet.
        let slot = (gloas + 5) * ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;
        let message = SyncCommitteeMessage {
            slot,
            beacon_block_root: Root::repeat_byte(1),
            validator_index: 9,
            signature: Default::default(),
        };
        publish_sync_committee_message(&mut server, vec![1], message);
        assert!(!server.seen_sync_messages.contains(slot, 9, 1));
    }

    #[tokio::test]
    async fn publishing_a_contribution_marks_it_seen() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let slot = server.wire.beacon().expect("beacon wire").wall_slot();
        // The test server's wire carries a placeholder digest; settle on the
        // schedule's so the slot's digest is a held one.
        apply(
            &mut server,
            slot / ethlambda_types::beacon::preset::SLOTS_PER_EPOCH,
        );
        let signed = SignedContributionAndProof {
            message: ContributionAndProof {
                aggregator_index: 4,
                contribution: SyncCommitteeContribution {
                    slot,
                    beacon_block_root: Root::repeat_byte(1),
                    subcommittee_index: 2,
                    aggregation_bits: one_bit(),
                    signature: Default::default(),
                },
                selection_proof: Default::default(),
            },
            signature: Default::default(),
        };

        publish_sync_committee_contribution(&mut server, signed.clone());
        // Recording the same contribution again says it was already there.
        assert!(!server.seen_sync_contributions.record(&signed));
    }

    #[tokio::test]
    async fn pruning_drops_slots_outside_the_retained_window() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let wall = server.wire.beacon().expect("beacon wire").wall_slot();
        let old = wall - RETAINED_SLOTS - 10;
        let root = Root::repeat_byte(1);
        let contribution = |slot| SyncCommitteeContribution {
            slot,
            beacon_block_root: root,
            subcommittee_index: 0,
            aggregation_bits: one_bit(),
            signature: Default::default(),
        };
        {
            let mut pool = server.sync_committee_pool.lock().unwrap();
            // Newest first: an insert prunes what trails its own slot.
            pool.insert_contribution(contribution(wall));
            pool.insert_contribution(contribution(old));
        }
        prune_sync_committee_pool(&server);
        let pool = server.sync_committee_pool.lock().unwrap();
        assert!(pool.contribution(old, root, 0).is_none());
        assert!(pool.contribution(wall, root, 0).is_some());
    }
}
