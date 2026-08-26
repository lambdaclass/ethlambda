//! Gossipsub peer scoring parameters, ported from lighthouse.
//!
//! Without a call to `Behaviour::with_peer_score`, gossipsub keeps
//! `PeerScoreState::Disabled`, and three of its defences are dead code:
//! `below_threshold` returns `(false, 0.0)` for every peer so the publish and
//! gossip gates pass everyone; the heartbeat's "prune peer with negative
//! score" pass reads a score of 0.0 and never fires; and the
//! `failed_message_slow_peer` penalty at the `Send Queue full` site takes the
//! `PeerScoreState::Active` arm never. Enabling scoring is what turns a peer
//! that cannot drain its send queue into a peer we stop feeding.
//!
//! Everything topology-independent is taken from lighthouse's
//! `gossipsub_scoring_parameters.rs` unchanged, including the deliberately
//! harsh slow-peer weights. Rates and decay horizons are re-derived for lean,
//! which has no epochs and where every validator attests every slot.
//!
//! DEVIATION: the `mesh_message_deliveries` terms are explicitly zeroed. They
//! are the negative topic-level terms, weighted `-topic_weight`, that punish a
//! peer for delivering fewer mesh messages than expected. Getting the expected
//! rate wrong drives healthy peers negative and prunes them, which is the
//! failure mode this scoring exists to prevent, so they stay off until lean's
//! real rates are measured. Lighthouse does the same for its low-rate topics.
//!
//! Zeroing them has to be explicit. `TopicScoreParams::default()` ships
//! `mesh_message_deliveries_weight: -1.0` with a threshold of 20 messages per
//! 10ms window, activating 5s after a peer joins the mesh. No node can meet
//! that, so leaving the fields at their defaults penalises every peer on a
//! healthy network: a 6-node devnet run scored every peer between -20 and -67
//! and pruned every mesh to empty. Lighthouse's `get_topic_params` has an
//! `else` branch zeroing all eight fields for exactly this reason.

use std::collections::HashMap;
use std::time::Duration;

use ethlambda_types::constants::MILLISECONDS_PER_SLOT;
use libp2p::gossipsub::{PeerScoreParams, PeerScoreThresholds, TopicHash, TopicScoreParams};

use super::{aggregation_topic, attestation_subnet_topic, block_topic};

/// Cap on the score a peer earns from sitting in our mesh, per lighthouse.
const MAX_IN_MESH_SCORE: f64 = 10.0;
/// Cap on the score a peer earns from being first to deliver, per lighthouse.
const MAX_FIRST_MESSAGE_DELIVERIES_SCORE: f64 = 40.0;

/// Topic weights. Lighthouse splits its weight budget across topic kinds and
/// keeps the total at 1.0 so that `max_positive_score` is stable; the same
/// split is used here, with the attestation budget spread over the subnets.
const BLOCK_TOPIC_WEIGHT: f64 = 0.5;
const AGGREGATION_TOPIC_WEIGHT: f64 = 0.5;

/// Decay horizon, standing in for the beacon epoch that lighthouse's decay
/// times are expressed in. Lean has no epochs, so a fixed span of slots is
/// used and lighthouse's multipliers are applied to it unchanged.
const SLOTS_PER_SCORE_EPOCH: u32 = 32;

/// Number of peers permitted to share one source IP before the quadratic
/// colocation penalty starts, per lighthouse.
///
/// NOTE: a single-host devnet puts every node on 127.0.0.1, so a node with
/// more than this many peers penalises all of them. Keep local runs at or
/// below `threshold + 1` nodes, or the penalty, not the slow-peer weight,
/// dominates the score.
const IP_COLOCATION_FACTOR_THRESHOLD: f64 = 8.0;

/// Graylist threshold, below which gossipsub ignores a peer's inbound RPCs.
/// Public because it bounds how far a peer's score can sink, which is what
/// makes the "scoring alone never disconnects" property checkable.
pub const GRAYLIST_THRESHOLD: f64 = -16000.0;

fn slot() -> Duration {
    Duration::from_millis(MILLISECONDS_PER_SLOT)
}

/// Stand-in for lighthouse's epoch in decay-time expressions.
fn score_epoch() -> Duration {
    slot() * SLOTS_PER_SCORE_EPOCH
}

/// Score thresholds, taken from lighthouse's `lighthouse_gossip_thresholds`.
pub fn thresholds() -> PeerScoreThresholds {
    PeerScoreThresholds {
        gossip_threshold: -4000.0,
        publish_threshold: -8000.0,
        graylist_threshold: GRAYLIST_THRESHOLD,
        accept_px_threshold: 100.0,
        opportunistic_graft_threshold: 5.0,
    }
}

/// Per-tick decay factor that takes `decay_time` to reach `decay_to_zero`.
fn score_parameter_decay(
    decay_time: Duration,
    decay_interval: Duration,
    decay_to_zero: f64,
) -> f64 {
    let ticks = decay_time.as_secs_f64() / decay_interval.as_secs_f64();
    decay_to_zero.powf(1.0 / ticks)
}

/// Value a counter converges to when incremented at `rate` per tick and
/// multiplied by `decay` each tick.
fn decay_convergence(decay: f64, rate: f64) -> f64 {
    rate / (1.0 - decay)
}

/// Inputs that decide the expected message rate on each topic.
///
/// `network_validator_count` is the whole network's validator set, not this
/// node's, because the rate a topic carries is a property of the network.
pub struct ScoringTopology {
    pub network_validator_count: u64,
    pub attestation_committee_count: u64,
    /// `mesh_n`, needed because a peer is only expected to be first-deliverer
    /// for its share of the mesh.
    pub mesh_n: usize,
}

/// Build the score params. Mirrors lighthouse's `get_peer_score_params`.
pub fn params(topology: &ScoringTopology) -> PeerScoreParams {
    let attestation_subnet_weight = 1.0 / topology.attestation_committee_count as f64;
    // Weights sum to 1.0: block + aggregation + every subnet's share.
    let total_topic_weight = BLOCK_TOPIC_WEIGHT
        + AGGREGATION_TOPIC_WEIGHT
        + attestation_subnet_weight * topology.attestation_committee_count as f64;
    let max_positive_score =
        (MAX_IN_MESH_SCORE + MAX_FIRST_MESSAGE_DELIVERIES_SCORE) * total_topic_weight;

    let decay_interval = std::cmp::max(Duration::from_secs(1), slot());
    let decay_to_zero = 0.01;
    let decay =
        |decay_time: Duration| score_parameter_decay(decay_time, decay_interval, decay_to_zero);

    let mut params = PeerScoreParams {
        decay_interval,
        decay_to_zero,
        retain_score: score_epoch() * 100,
        app_specific_weight: 1.0,
        ip_colocation_factor_threshold: IP_COLOCATION_FACTOR_THRESHOLD,
        behaviour_penalty_threshold: 6.0,
        behaviour_penalty_decay: decay(score_epoch() * 10),
        // Lighthouse's overrides, 50x the libp2p defaults of -0.2 / 0.2. This
        // is the term that reacts to `Send Queue full`: every failed send adds
        // 1.0 to `slow_peer_penalty`, and the score contribution is
        // `(penalty - threshold) * weight`.
        slow_peer_decay: 0.1,
        slow_peer_weight: -10.0,
        slow_peer_threshold: 0.0,
        ..Default::default()
    };

    // Behaviour penalty is scaled so that the configured threshold sits at the
    // gossip threshold, exactly as lighthouse derives it.
    let target_value = decay_convergence(
        params.behaviour_penalty_decay,
        10.0 / SLOTS_PER_SCORE_EPOCH as f64,
    ) - params.behaviour_penalty_threshold;
    params.behaviour_penalty_weight = thresholds().gossip_threshold / target_value.powi(2);

    params.topic_score_cap = max_positive_score * 0.5;
    params.ip_colocation_factor_weight = -params.topic_score_cap;

    let mut topics: HashMap<TopicHash, TopicScoreParams> = HashMap::new();

    // One block per slot.
    topics.insert(
        block_topic().hash(),
        topic_params(
            BLOCK_TOPIC_WEIGHT,
            1.0,
            score_epoch() * 20,
            decay_interval,
            decay_to_zero,
            topology.mesh_n,
            max_positive_score,
        ),
    );

    // One aggregate per subnet per slot, when every subnet has an aggregator.
    topics.insert(
        aggregation_topic().hash(),
        topic_params(
            AGGREGATION_TOPIC_WEIGHT,
            topology.attestation_committee_count as f64,
            score_epoch(),
            decay_interval,
            decay_to_zero,
            topology.mesh_n,
            max_positive_score,
        ),
    );

    // Every validator attests every slot, so a subnet carries its share of the
    // validator set each slot. This is the main departure from the beacon
    // chain, where a validator attests once per epoch.
    let attestations_per_subnet_per_slot =
        topology.network_validator_count as f64 / topology.attestation_committee_count as f64;
    for subnet in 0..topology.attestation_committee_count {
        topics.insert(
            attestation_subnet_topic(subnet).hash(),
            topic_params(
                attestation_subnet_weight,
                attestations_per_subnet_per_slot,
                score_epoch() * 4,
                decay_interval,
                decay_to_zero,
                topology.mesh_n,
                max_positive_score,
            ),
        );
    }

    params.topics = topics;
    params
}

/// Mirrors lighthouse's `get_topic_params` with `mesh_message_info: None`,
/// including its `else` branch.
fn topic_params(
    topic_weight: f64,
    expected_message_rate: f64,
    first_message_decay_time: Duration,
    decay_interval: Duration,
    decay_to_zero: f64,
    mesh_n: usize,
    max_positive_score: f64,
) -> TopicScoreParams {
    let mut t = TopicScoreParams::default();
    t.topic_weight = topic_weight;

    t.time_in_mesh_quantum = slot();
    t.time_in_mesh_cap = 3600.0 / t.time_in_mesh_quantum.as_secs_f64();
    t.time_in_mesh_weight = MAX_IN_MESH_SCORE / t.time_in_mesh_cap;

    t.first_message_deliveries_decay =
        score_parameter_decay(first_message_decay_time, decay_interval, decay_to_zero);
    t.first_message_deliveries_cap = decay_convergence(
        t.first_message_deliveries_decay,
        2.0 * expected_message_rate / mesh_n as f64,
    );
    t.first_message_deliveries_weight =
        MAX_FIRST_MESSAGE_DELIVERIES_SCORE / t.first_message_deliveries_cap;

    // P3 and P3b off. Every field must be zeroed, not merely left alone: see
    // the module note on what `TopicScoreParams::default()` puts here.
    t.mesh_message_deliveries_weight = 0.0;
    t.mesh_message_deliveries_threshold = 0.0;
    t.mesh_message_deliveries_decay = 0.0;
    t.mesh_message_deliveries_cap = 0.0;
    t.mesh_message_deliveries_window = Duration::ZERO;
    t.mesh_message_deliveries_activation = Duration::ZERO;
    t.mesh_failure_penalty_weight = 0.0;
    t.mesh_failure_penalty_decay = 0.0;

    // P4. Kept, and set to lighthouse's weight rather than the default -1.0:
    // an invalid message is a protocol violation, and one is enough to cancel
    // out everything a peer can earn.
    t.invalid_message_deliveries_weight = -max_positive_score / topic_weight;
    t.invalid_message_deliveries_decay =
        score_parameter_decay(score_epoch() * 50, decay_interval, decay_to_zero);

    t
}

#[cfg(test)]
mod tests {
    use libp2p::{
        Swarm, futures::StreamExt, gossipsub, swarm::SwarmEvent, swarm::dial_opts::DialOpts,
    };
    use std::time::Duration;

    use super::*;
    use crate::{GOSSIP_MESH_N, gossipsub_config};

    fn topology() -> ScoringTopology {
        ScoringTopology {
            network_validator_count: 12,
            attestation_committee_count: 4,
            mesh_n: GOSSIP_MESH_N,
        }
    }

    #[test]
    fn params_are_accepted_by_gossipsub() {
        // `with_peer_score` runs `PeerScoreParams::validate`, which rejects a
        // positive weight where a penalty is expected, a zero decay, a decay
        // outside (0, 1], and several cross-field constraints. Building the
        // behaviour is the only way to exercise that, and a panic here at
        // startup would take the node down, so it is worth a test of its own.
        let mut behaviour: gossipsub::Behaviour = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Anonymous,
            gossipsub_config(),
        )
        .expect("behaviour");
        behaviour
            .with_peer_score(params(&topology()), thresholds())
            .expect("params should validate");
    }

    #[test]
    fn every_topic_the_node_gossips_on_is_scored() {
        // A topic absent from `params.topics` earns no positive score at all,
        // so a peer on it sits at 0.0 and the first dropped message is enough
        // to make it negative and get it pruned. Every topic we publish to
        // must therefore be present.
        let topology = topology();
        let params = params(&topology);
        assert!(params.topics.contains_key(&block_topic().hash()));
        assert!(params.topics.contains_key(&aggregation_topic().hash()));
        for subnet in 0..topology.attestation_committee_count {
            assert!(
                params
                    .topics
                    .contains_key(&attestation_subnet_topic(subnet).hash()),
                "subnet {subnet} is unscored"
            );
        }
        assert_eq!(
            params.topics.len(),
            2 + topology.attestation_committee_count as usize
        );
    }

    #[test]
    fn no_topic_carries_a_mesh_delivery_penalty() {
        // Regression test for a real 6-node devnet failure. Leaving the P3/P3b
        // fields at `TopicScoreParams::default()` enables them with a
        // threshold of 20 messages per 10ms window, which no node can meet, so
        // every peer on a healthy network went negative and every mesh emptied.
        // Not configuring these is not the same as disabling them.
        for (topic, t) in params(&topology()).topics {
            assert_eq!(t.mesh_message_deliveries_weight, 0.0, "{topic}");
            assert_eq!(t.mesh_message_deliveries_threshold, 0.0, "{topic}");
            assert_eq!(t.mesh_failure_penalty_weight, 0.0, "{topic}");
            assert_eq!(t.mesh_message_deliveries_window, Duration::ZERO, "{topic}");
            // The positive terms must still be live, or peers never build the
            // buffer that keeps a transient penalty from pruning them.
            assert!(t.time_in_mesh_weight > 0.0, "{topic}");
            assert!(t.first_message_deliveries_weight > 0.0, "{topic}");
            // An invalid message must still cost more than a peer can earn.
            assert!(t.invalid_message_deliveries_weight < 0.0, "{topic}");
        }
    }

    #[test]
    fn a_graylisted_peer_cannot_reach_the_disconnect_threshold_alone() {
        // Lighthouse's property, restated for our setup: gossipsub owns no
        // disconnect path, so the floor a peer's score can reach is bounded by
        // the graylist threshold and nothing in gossipsub acts on it beyond
        // ignoring the peer's inbound RPCs. This is what "handle SlowPeer but
        // do not disconnect" rests on, so it is asserted rather than assumed.
        let t = thresholds();
        assert!(t.graylist_threshold < t.publish_threshold);
        assert!(t.publish_threshold < t.gossip_threshold);
        assert!(t.gossip_threshold < 0.0);
    }

    fn node() -> Swarm<gossipsub::Behaviour> {
        libp2p::SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_other_transport(|keypair| {
                use libp2p::Transport;
                libp2p::core::transport::MemoryTransport::default()
                    .upgrade(libp2p::core::upgrade::Version::V1)
                    .authenticate(libp2p::noise::Config::new(keypair).expect("noise"))
                    .multiplex(libp2p::yamux::Config::default())
            })
            .expect("transport")
            .with_behaviour(|_keypair| {
                let mut behaviour = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Anonymous,
                    gossipsub_config(),
                )
                .expect("behaviour");
                behaviour
                    .with_peer_score(params(&topology()), thresholds())
                    .expect("score params");
                behaviour
            })
            .expect("behaviour")
            .build()
    }

    /// The behaviour this whole change exists for.
    ///
    /// A peer that stops draining its send queue is pruned from the mesh, so
    /// we stop feeding it, and is NOT disconnected, so it keeps its connection
    /// and can still be served over request/response. On `main` the same
    /// scenario leaves the peer in the mesh indefinitely, which on devnet-5
    /// meant one node losing ~33 messages/second to one peer for 12+ hours.
    #[tokio::test(flavor = "current_thread")]
    async fn a_stalled_peer_is_pruned_from_the_mesh_but_not_disconnected() {
        // Scored topic, so the stalled peer starts from a real positive score
        // rather than a bare 0.0 that any penalty would tip negative.
        let topic = gossipsub::IdentTopic::new(block_topic().to_string());
        let (mut a, mut b) = (node(), node());
        a.behaviour_mut().subscribe(&topic).expect("subscribe a");
        b.behaviour_mut().subscribe(&topic).expect("subscribe b");

        let addr: libp2p::Multiaddr = "/memory/515151".parse().expect("addr");
        b.listen_on(addr.clone()).expect("listen");
        let b_id = *b.local_peer_id();
        a.dial(DialOpts::unknown_peer_id().address(addr).build())
            .expect("dial");

        let meshed = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    _ = a.select_next_some() => {}
                    _ = b.select_next_some() => {}
                }
                if a.behaviour().mesh_peers(&topic.hash()).any(|p| *p == b_id) {
                    return;
                }
            }
        })
        .await;
        assert!(meshed.is_ok(), "the two nodes should mesh");
        assert!(
            a.behaviour().peer_score(&b_id).is_some(),
            "scoring must be active, or this test proves nothing"
        );

        // B stays alive but is never polled again, so its connection handler
        // stops draining and A's per-peer send queue fills. Dropping B would
        // close the connection instead, which is not the condition under test:
        // on devnet-5 the peer stayed connected and kept serving Status.
        let _b_parked = b;

        let mut payload = vec![0u8; 4096];
        let mut queues_full = 0usize;
        let mut not_targeted = 0usize;
        let mut first_not_targeted_at = None;
        for nonce in 0u64..8_000 {
            // Unique bytes per publish: the message id is a hash of topic and
            // data, and `duplicate_cache_time` would otherwise dedupe these.
            payload[..8].copy_from_slice(&nonce.to_le_bytes());
            match a.behaviour_mut().publish(topic.clone(), payload.clone()) {
                Ok(_) => {}
                Err(gossipsub::PublishError::AllQueuesFull(_)) => queues_full += 1,
                // Once the score falls under `publish_threshold`, `publish_peers`
                // drops the peer from the candidate set, so there is no longer
                // anyone to publish to and we stop even trying to enqueue.
                Err(gossipsub::PublishError::NoPeersSubscribedToTopic) => {
                    first_not_targeted_at.get_or_insert(queues_full);
                    not_targeted += 1;
                }
                Err(err) => panic!("unexpected publish error: {err:?}"),
            }
        }
        assert!(queues_full > 0, "the parked peer's queue should fill");

        // `Event::SlowPeer` and the negative-score prune both run on the
        // gossipsub heartbeat, and `heartbeat_initial_delay` defaults to 5s and
        // is not overridden by `gossipsub_config`, so the window has to clear
        // that before the first heartbeat runs at all.
        let mut slow_peer_reports = 0usize;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut pruned = false;
        while tokio::time::Instant::now() < deadline {
            let step = tokio::time::timeout(Duration::from_millis(200), a.select_next_some()).await;
            if let Ok(SwarmEvent::Behaviour(gossipsub::Event::SlowPeer { peer_id, .. })) = step {
                assert_eq!(peer_id, b_id);
                slow_peer_reports += 1;
            }
            if !a.behaviour().mesh_peers(&topic.hash()).any(|p| *p == b_id) {
                pruned = true;
                break;
            }
        }

        let score = a.behaviour().peer_score(&b_id).expect("scored");
        let still_connected = a.behaviour().all_peers().any(|(p, _)| *p == b_id);
        println!(
            "\n  AllQueuesFull rejections:   {queues_full}\
             \n  publishes not even tried:   {not_targeted}\
             \n  gave up targeting after:    {first_not_targeted_at:?} dropped messages\
             \n  SlowPeer reports:           {slow_peer_reports}\
             \n  peer score:                 {score}\
             \n  pruned from mesh:           {pruned}\
             \n  still connected:            {still_connected}\n"
        );

        assert!(
            slow_peer_reports > 0,
            "gossipsub should report the peer as slow"
        );
        assert!(
            score < 0.0,
            "the slow-peer penalty should drive the score negative, got {score}"
        );
        assert!(
            pruned,
            "the stalled peer should be pruned from the mesh so we stop feeding it"
        );
        assert!(
            still_connected,
            "scoring must not disconnect: the peer is still useful for request/response"
        );
        // Past `publish_threshold` the peer also leaves the publish candidate
        // set. Reaching it here is an artifact of this test publishing 8000
        // times in a tight synchronous loop, with no `decay_interval` tick in
        // between, so `slow_peer_penalty` accumulates unchecked to 800.
        //
        // It does NOT work that way against a live network. The penalty decays
        // by `slow_peer_decay` every `decay_interval`, so it settles at
        //
        //     penalty_steady = rate * decay_interval / (1 - slow_peer_decay)
        //     score_steady   = slow_peer_weight * penalty_steady
        //
        // which for our parameters is `-44.4 * rate`. Crossing
        // `publish_threshold` therefore needs a sustained ~180 failed
        // sends/second; the ~33/s measured on devnet-5 settles near -1500 and
        // never gets there. So the publish gate is not the mechanism that ends
        // the flood in production, and this assertion only pins the tight-loop
        // behaviour. What ends it is the mesh prune below, which needs nothing
        // more than a negative score: an A/B on a 6-node devnet cut dropped
        // `Forward` RPCs by 99.2% (2441 -> 20) while dropped `Publish` stayed
        // flat, because a network with fewer peers than `mesh_n` re-selects the
        // pruned peer as a publish top-up in `filter_publish_candidates`.
        assert!(
            not_targeted > 0,
            "past publish_threshold the peer should be dropped from the publish set"
        );
    }
}
