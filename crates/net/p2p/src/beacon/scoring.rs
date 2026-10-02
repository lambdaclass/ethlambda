//! Gossipsub peer scoring on the beacon wire.
//!
//! Lighthouse's parameters (`lighthouse_network/src/service/gossipsub_scoring_parameters.rs`),
//! ported formula for formula. Grandine, Teku and Lodestar run the same
//! constants, so a peer is scored here the way most of mainnet scores it, and
//! the tests pin this port to the numbers lighthouse's formulas give. What is
//! scored:
//!
//! | topic | weight | mesh deliveries (P3) |
//! |---|---|---|
//! | `beacon_block` | 0.5 | scored |
//! | `beacon_aggregate_and_proof` | 0.5 | scored |
//! | `beacon_attestation_{subnet_id}`, every subnet | 1/64 each | scored |
//! | `voluntary_exit`, `proposer_slashing`, `attester_slashing` | 0.05 each | off |
//!
//! Every subnet is given parameters, not only the backbone ones, because an
//! aggregator joins other subnets at runtime and the parameters have to be in
//! place before the mesh forms.
//!
//! Nothing else this node subscribes to has topic parameters, so only the
//! topic-independent terms (IP colocation, broken IWANT promises, slow peers)
//! see that traffic. `data_column_sidecar_{subnet_id}` is left out, as every
//! client but Prysm leaves it out. `sync_committee_contribution_and_proof` and
//! `bls_to_execution_change` are left out because this node has no consumer
//! for either and `Ignore`s every message on them. A delivery is only credited
//! once it is accepted, so mesh-delivery scoring there would starve every mesh
//! peer for a gap that is this node's own.
//!
//! # Where this differs from lighthouse
//!
//! - `mesh_n` is this node's own ([`crate::MESH_N`]) rather than the 5 that
//!   lighthouse's default network load gives. It only enters the
//!   first-message-delivery cap, which is two mesh shares of the expected
//!   traffic.
//! - Mesh-delivery scoring also waits for this node to keep up with the chain:
//!   see [`MeshDeliveryGate`].
//!
//! # Refreshing
//!
//! The expected message rates depend on the active validator count, so the
//! block, aggregate and attestation parameters are rebuilt once per slot
//! ([`refresh`]) from the head's current-epoch shuffling. Until the first
//! refresh they are built for [`PLACEHOLDER_ACTIVE_VALIDATORS`] with P3 off,
//! the same placeholder lighthouse starts from.
//!
//! The topics are named for the one fork digest the node subscribed under at
//! startup. When the digest can change at runtime, the old digest's topics
//! need their weight zeroed and the new digest's topics need parameters, as
//! lighthouse's `remove_topic_weight_except` does.

use std::collections::HashSet;
use std::time::Duration;

use ethlambda_state_transition::beacon::helpers::accessors::committee_count_per_slot;
use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::constants::TARGET_AGGREGATORS_PER_COMMITTEE;
use ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;
use ethlambda_types::beacon::primitives::ForkDigest;
use libp2p::gossipsub::{IdentTopic, PeerScoreParams, PeerScoreThresholds, TopicScoreParams};
use tracing::info;

use crate::beacon::constants::ATTESTATION_SUBNET_COUNT;
use crate::beacon::topics::{
    ATTESTER_SLASHING, BEACON_AGGREGATE_AND_PROOF, BEACON_BLOCK, PROPOSER_SLASHING, VOLUNTARY_EXIT,
    attestation_topic_name, topic_name,
};
use crate::gossipsub::beacon_wall_slot;
use crate::{P2PServer, metrics};

/// The most a topic's time-in-mesh term (P1) contributes, before its weight.
const MAX_IN_MESH_SCORE: f64 = 10.0;
/// The most a topic's first-message-delivery term (P2) contributes, before
/// its weight.
const MAX_FIRST_MESSAGE_DELIVERIES_SCORE: f64 = 40.0;

const BEACON_BLOCK_WEIGHT: f64 = 0.5;
const BEACON_AGGREGATE_PROOF_WEIGHT: f64 = 0.5;
const VOLUNTARY_EXIT_WEIGHT: f64 = 0.05;
const PROPOSER_SLASHING_WEIGHT: f64 = 0.05;
const ATTESTER_SLASHING_WEIGHT: f64 = 0.05;

/// How late after the first delivery a mesh peer's copy still counts towards
/// its mesh deliveries: the time a hostile peer would need to replay a message
/// this node just forwarded to it and be credited for it.
const MESH_MESSAGE_DELIVERIES_WINDOW: Duration = Duration::from_secs(2);

/// A counter decayed below this is treated as zero.
const DECAY_TO_ZERO: f64 = 0.01;

/// Below this score a peer gets no IHAVE/IWANT gossip from this node.
pub const GOSSIP_THRESHOLD: f64 = -4000.0;
/// Below this score a peer is left out of this node's publishes.
pub const PUBLISH_THRESHOLD: f64 = -8000.0;
/// Below this score gossipsub ignores every RPC the peer sends, and
/// [`crate::swarm_adapter`] disconnects it.
pub const GRAYLIST_THRESHOLD: f64 = -16000.0;

/// The active validator count the parameters are built for before the head
/// has named one: lighthouse's `minimum_validator_count`, one per slot.
pub const PLACEHOLDER_ACTIVE_VALIDATORS: u64 = SLOTS_PER_EPOCH;

/// Head lag, in slots, beyond which [`MeshDeliveryGate`] switches mesh-delivery
/// scoring off.
///
/// Two slots behind is already enough to `Ignore` most of what arrives,
/// since current aggregates and attestations vote for a block this node has
/// not imported. The margin is set by how long the delivery counters can go
/// without credit before a penalty starts. The aggregate counter falls from
/// its cap to the threshold in about 19 slots, and the other scored topics
/// take longer, so closing the gate within a few slots of losing the head
/// leaves nothing to penalize. Empty slots count towards the lag as well,
/// which is harmless: those votes are for a block this node has.
pub const MESH_DELIVERY_MAX_HEAD_LAG: u64 = 4;

/// How many slots the head has to stay within [`MESH_DELIVERY_MAX_HEAD_LAG`]
/// before [`MeshDeliveryGate`] switches mesh-delivery scoring back on.
///
/// While the gate was closed the counters kept counting, but a catch-up
/// credits nothing, so they come out of it near zero. Reopening the moment the
/// head catches up would score the whole mesh on that empty history. Every
/// scored topic refills to its threshold within a few slots of accepted
/// traffic, so one epoch leaves ample margin.
pub const MESH_DELIVERY_WARMUP_SLOTS: u64 = SLOTS_PER_EPOCH;

/// The score thresholds, which do not depend on the chain.
pub fn thresholds() -> PeerScoreThresholds {
    PeerScoreThresholds {
        gossip_threshold: GOSSIP_THRESHOLD,
        publish_threshold: PUBLISH_THRESHOLD,
        graylist_threshold: GRAYLIST_THRESHOLD,
        // Above what any peer can reach (the topic score cap), so peer
        // exchange is never accepted, as on lighthouse.
        accept_px_threshold: 100.0,
        opportunistic_graft_threshold: 5.0,
    }
}

/// What the dynamic topic parameters are rebuilt from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScoreInputs {
    /// Active validators in the head's current epoch.
    pub active_validators: u64,
    /// The wall-clock slot. Only matters on a young chain: a topic's
    /// mesh-delivery scoring stays off until the chain is older than that
    /// topic's decay window, as on lighthouse.
    pub current_slot: u64,
    /// [`MeshDeliveryGate`]'s verdict.
    pub mesh_deliveries_scored: bool,
}

impl ScoreInputs {
    /// What the parameters are built from before the first refresh: a
    /// placeholder validator count, and no mesh-delivery scoring.
    pub fn placeholder() -> Self {
        Self {
            active_validators: PLACEHOLDER_ACTIVE_VALIDATORS,
            current_slot: 0,
            mesh_deliveries_scored: false,
        }
    }
}

/// A topic's mesh-delivery (P3) setup: lighthouse's `mesh_message_info`.
struct MeshDeliveries {
    /// How many slots the delivery counter takes to decay to zero.
    decay_slots: u64,
    /// The counter's cap, as a multiple of its threshold.
    cap_factor: f64,
    /// How long a peer is in the mesh before its deficit counts.
    activation: Duration,
}

/// The chain-derived constants every parameter is computed from, fixed for
/// the life of the node.
#[derive(Debug, Clone)]
pub struct ScoreSettings {
    slot: Duration,
    epoch: Duration,
    decay_interval: Duration,
    mesh_n: usize,
    attestation_subnet_weight: f64,
    /// The most every scored topic's P1 and P2 can add up to, the unit the
    /// invalid-message penalty is sized in.
    max_positive_score: f64,
}

impl ScoreSettings {
    pub fn new(config: &Config, mesh_n: usize) -> Self {
        let slot = Duration::from_millis(config.slot_duration_ms);
        let attestation_subnet_weight = 1.0 / ATTESTATION_SUBNET_COUNT as f64;
        let max_positive_score = (MAX_IN_MESH_SCORE + MAX_FIRST_MESSAGE_DELIVERIES_SCORE)
            * (BEACON_BLOCK_WEIGHT
                + BEACON_AGGREGATE_PROOF_WEIGHT
                + attestation_subnet_weight * ATTESTATION_SUBNET_COUNT as f64
                + VOLUNTARY_EXIT_WEIGHT
                + PROPOSER_SLASHING_WEIGHT
                + ATTESTER_SLASHING_WEIGHT);
        Self {
            slot,
            epoch: slot * SLOTS_PER_EPOCH as u32,
            // One decay tick per slot, which is what every expected rate
            // below is stated per.
            decay_interval: slot.max(Duration::from_secs(1)),
            mesh_n,
            attestation_subnet_weight,
            max_positive_score,
        }
    }

    /// The whole parameter set: the global terms, and every scored topic
    /// under `fork_digest`.
    pub fn peer_score_params(
        &self,
        fork_digest: ForkDigest,
        inputs: ScoreInputs,
    ) -> PeerScoreParams {
        let behaviour_penalty_decay = self.decay(self.epoch * 10);
        // The weight puts a peer that keeps earning ten behaviour penalties
        // an epoch exactly at the gossip threshold once its counter settles.
        let behaviour_penalty_threshold = 6.0;
        let settled_excess =
            decay_convergence(behaviour_penalty_decay, 10.0 / SLOTS_PER_EPOCH as f64)
                - behaviour_penalty_threshold;
        let topic_score_cap = self.max_positive_score * 0.5;

        let topics = self
            .fixed_topic_params(fork_digest)
            .into_iter()
            .chain(self.dynamic_topic_params(fork_digest, inputs))
            .map(|(topic, params)| (topic.hash(), params))
            .collect();

        PeerScoreParams {
            topics,
            topic_score_cap,
            // Lighthouse's value. This node never sets an application score,
            // so the term is always zero.
            app_specific_weight: 1.0,
            ip_colocation_factor_weight: -topic_score_cap,
            // Up to eight peers per IP before the penalty starts.
            ip_colocation_factor_threshold: 8.0,
            ip_colocation_factor_whitelist: HashSet::new(),
            behaviour_penalty_weight: GOSSIP_THRESHOLD / settled_excess.powi(2),
            behaviour_penalty_threshold,
            behaviour_penalty_decay,
            decay_interval: self.decay_interval,
            decay_to_zero: DECAY_TO_ZERO,
            retain_score: self.epoch * 100,
            // A peer whose send queue is full, or whose queued messages time
            // out, loses ten a time, mostly gone by the next tick.
            slow_peer_weight: -10.0,
            slow_peer_threshold: 0.0,
            slow_peer_decay: 0.1,
        }
    }

    /// Exits and slashings: rare enough that their rates do not depend on
    /// the validator count, and never mesh-delivery scored.
    fn fixed_topic_params(&self, fork_digest: ForkDigest) -> Vec<(IdentTopic, TopicScoreParams)> {
        let per_slot = |per_epoch: f64| per_epoch / SLOTS_PER_EPOCH as f64;
        [
            (VOLUNTARY_EXIT, VOLUNTARY_EXIT_WEIGHT, per_slot(4.0)),
            (
                ATTESTER_SLASHING,
                ATTESTER_SLASHING_WEIGHT,
                per_slot(1.0 / 5.0),
            ),
            (
                PROPOSER_SLASHING,
                PROPOSER_SLASHING_WEIGHT,
                per_slot(1.0 / 5.0),
            ),
        ]
        .into_iter()
        .map(|(kind, weight, rate)| {
            let topic = IdentTopic::new(topic_name(fork_digest, kind));
            let params = self.topic_params(weight, rate, self.epoch * 100, None, false);
            (topic, params)
        })
        .collect()
    }

    /// Blocks, aggregates and every attestation subnet: the topics whose
    /// expected traffic follows the validator count, and so the ones
    /// [`refresh`] rebuilds.
    pub fn dynamic_topic_params(
        &self,
        fork_digest: ForkDigest,
        inputs: ScoreInputs,
    ) -> Vec<(IdentTopic, TopicScoreParams)> {
        // Zero would leave every rate zero and every first-delivery cap with
        // it, which gossipsub rejects.
        let active = inputs.active_validators.max(PLACEHOLDER_ACTIVE_VALIDATORS);
        let (aggregators_per_slot, committees_per_slot) = expected_aggregators_per_slot(active);
        // Whether each subnet sees more than one committee's burst an epoch,
        // which shortens its decay windows.
        let multiple_bursts_per_subnet_per_epoch =
            committees_per_slot >= 2 * ATTESTATION_SUBNET_COUNT / SLOTS_PER_EPOCH;
        // Lighthouse's young-chain rule and this node's sync gate: P3 needs
        // both a chain older than the topic's decay window and a node that
        // has kept up with it.
        let scored =
            |decay_slots: u64| inputs.mesh_deliveries_scored && inputs.current_slot > decay_slots;

        let block_mesh = MeshDeliveries {
            decay_slots: SLOTS_PER_EPOCH * 5,
            cap_factor: 3.0,
            activation: self.epoch,
        };
        let block = self.topic_params(
            BEACON_BLOCK_WEIGHT,
            1.0,
            self.epoch * 20,
            Some(&block_mesh),
            scored(block_mesh.decay_slots),
        );

        let aggregate_mesh = MeshDeliveries {
            decay_slots: SLOTS_PER_EPOCH * 2,
            cap_factor: 4.0,
            activation: self.epoch,
        };
        let aggregate = self.topic_params(
            BEACON_AGGREGATE_PROOF_WEIGHT,
            aggregators_per_slot,
            self.epoch,
            Some(&aggregate_mesh),
            scored(aggregate_mesh.decay_slots),
        );

        let attestation_mesh = if multiple_bursts_per_subnet_per_epoch {
            MeshDeliveries {
                decay_slots: SLOTS_PER_EPOCH * 4,
                cap_factor: 16.0,
                activation: self.slot * (SLOTS_PER_EPOCH as u32 / 2 + 1),
            }
        } else {
            MeshDeliveries {
                decay_slots: SLOTS_PER_EPOCH * 16,
                cap_factor: 16.0,
                activation: self.epoch * 3,
            }
        };
        let attestation_fmd_decay_time = if multiple_bursts_per_subnet_per_epoch {
            self.epoch
        } else {
            self.epoch * 4
        };
        let attestation = self.topic_params(
            self.attestation_subnet_weight,
            active as f64 / ATTESTATION_SUBNET_COUNT as f64 / SLOTS_PER_EPOCH as f64,
            attestation_fmd_decay_time,
            Some(&attestation_mesh),
            scored(attestation_mesh.decay_slots),
        );

        let mut topics = vec![
            (
                IdentTopic::new(topic_name(fork_digest, BEACON_BLOCK)),
                block,
            ),
            (
                IdentTopic::new(topic_name(fork_digest, BEACON_AGGREGATE_AND_PROOF)),
                aggregate,
            ),
        ];
        topics.extend((0..ATTESTATION_SUBNET_COUNT).map(|subnet_id| {
            let topic = IdentTopic::new(attestation_topic_name(fork_digest, subnet_id));
            (topic, attestation.clone())
        }));
        topics
    }

    /// One topic's parameters: lighthouse's `get_topic_params`.
    ///
    /// `rate` is the topic's expected messages per slot, one decay tick.
    /// With `mesh_scored` false the mesh-delivery threshold and weight are
    /// zero, so no deficit can build and no P3b is charged at prune, but the
    /// cap stays where the threshold would put it: the counters keep
    /// counting to their real ceiling, so switching P3 on later scores the
    /// history that was actually delivered.
    fn topic_params(
        &self,
        topic_weight: f64,
        rate: f64,
        first_message_decay_time: Duration,
        mesh: Option<&MeshDeliveries>,
        mesh_scored: bool,
    ) -> TopicScoreParams {
        let time_in_mesh_cap = 3600.0 / self.slot.as_secs_f64();
        let first_message_deliveries_decay = self.decay(first_message_decay_time);
        // Two mesh shares of the traffic that arrives over one decay window.
        let first_message_deliveries_cap = decay_convergence(
            first_message_deliveries_decay,
            2.0 * rate / self.mesh_n as f64,
        );

        let mut params = TopicScoreParams {
            topic_weight,
            time_in_mesh_weight: MAX_IN_MESH_SCORE / time_in_mesh_cap,
            time_in_mesh_quantum: self.slot,
            time_in_mesh_cap,
            first_message_deliveries_weight: MAX_FIRST_MESSAGE_DELIVERIES_SCORE
                / first_message_deliveries_cap,
            first_message_deliveries_decay,
            first_message_deliveries_cap,
            mesh_message_deliveries_weight: 0.0,
            mesh_message_deliveries_decay: 0.0,
            mesh_message_deliveries_cap: 0.0,
            mesh_message_deliveries_threshold: 0.0,
            mesh_message_deliveries_window: Duration::ZERO,
            mesh_message_deliveries_activation: Duration::ZERO,
            mesh_failure_penalty_weight: 0.0,
            mesh_failure_penalty_decay: 0.0,
            // One invalid message costs a whole `max_positive_score`, on any
            // topic, whatever its weight.
            invalid_message_deliveries_weight: -self.max_positive_score / topic_weight,
            invalid_message_deliveries_decay: self.decay(self.epoch * 50),
        };

        if let Some(mesh) = mesh {
            let decay = self.decay(self.slot * mesh.decay_slots as u32);
            // Two percent of the expected traffic, over the decay window.
            let threshold = decay_convergence(decay, rate / 50.0) * decay;
            params.mesh_message_deliveries_decay = decay;
            params.mesh_message_deliveries_cap = (mesh.cap_factor * threshold).max(2.0);
            params.mesh_message_deliveries_activation = mesh.activation;
            params.mesh_message_deliveries_window = MESH_MESSAGE_DELIVERIES_WINDOW;
            params.mesh_failure_penalty_decay = decay;
            params.mesh_failure_penalty_weight = -topic_weight;
            if mesh_scored {
                params.mesh_message_deliveries_threshold = threshold;
                params.mesh_message_deliveries_weight = -topic_weight;
            }
        }

        params
    }

    /// The per-tick factor that takes a counter from one to
    /// [`DECAY_TO_ZERO`] over `decay_time`.
    fn decay(&self, decay_time: Duration) -> f64 {
        let ticks = decay_time.as_secs_f64() / self.decay_interval.as_secs_f64();
        DECAY_TO_ZERO.powf(1.0 / ticks)
    }
}

/// Where a counter that gains `rate` a tick and decays by `decay` a tick
/// settles.
fn decay_convergence(decay: f64, rate: f64) -> f64 {
    rate / (1.0 - decay)
}

/// Aggregates expected per slot with `active` validators, and the committee
/// count per slot it was derived from.
///
/// Every committee selects `len / max(1, len / TARGET_AGGREGATORS_PER_COMMITTEE)`
/// aggregators in expectation (phase0's `is_aggregator`), and an epoch's
/// committees differ in size by at most one member.
fn expected_aggregators_per_slot(active: u64) -> (f64, u64) {
    let committees_per_slot = committee_count_per_slot(active);
    let committees = committees_per_slot * SLOTS_PER_EPOCH;
    let smaller = active / committees;
    let larger_count = active - smaller * committees;
    let smaller_modulo = (smaller / TARGET_AGGREGATORS_PER_COMMITTEE).max(1);
    let larger_modulo = ((smaller + 1) / TARGET_AGGREGATORS_PER_COMMITTEE).max(1);
    let per_epoch = ((committees - larger_count) * smaller) as f64 / smaller_modulo as f64
        + (larger_count * (smaller + 1)) as f64 / larger_modulo as f64;
    (per_epoch / SLOTS_PER_EPOCH as f64, committees_per_slot)
}

/// Whether mesh-delivery scoring (P3) is safe to switch on: the head has
/// kept up with the wall clock long enough that the delivery counters
/// reflect what mesh peers sent, not what this node was able to accept.
///
/// A delivery is credited only once it is accepted. While this node catches
/// up it `Ignore`s every aggregate and attestation voting for a block it has
/// not imported, so no mesh peer is credited for anything. Aggregate traffic
/// is heavy enough that a mesh peer credited with nothing scores below the
/// graylist. Without the gate, a restart would graylist the whole aggregate
/// mesh because of this node's lag, not anything the peers did.
///
/// Lighthouse avoids the same trap differently: it joins these topics only
/// once it has synced, so it has no mesh while it catches up. This node
/// subscribes at startup. The gate also covers the case lighthouse leaves
/// open, a node that falls behind after it has synced.
#[derive(Debug, Default)]
pub struct MeshDeliveryGate {
    /// The wall-clock slot since which the head has stayed within
    /// [`MESH_DELIVERY_MAX_HEAD_LAG`], or `None` while it lags further.
    keeping_up_since: Option<u64>,
}

impl MeshDeliveryGate {
    /// Record where the head is, and return whether mesh deliveries should
    /// be scored.
    pub fn update(&mut self, wall_slot: u64, head_slot: u64) -> bool {
        if wall_slot.saturating_sub(head_slot) > MESH_DELIVERY_MAX_HEAD_LAG {
            self.keeping_up_since = None;
            return false;
        }
        let since = *self.keeping_up_since.get_or_insert(wall_slot);
        // Saturating: the wall clock can step backwards under an NTP correction.
        wall_slot.saturating_sub(since) >= MESH_DELIVERY_WARMUP_SLOTS
    }
}

/// The scoring state [`P2PServer`] keeps on a beacon wire.
pub(crate) struct PeerScoring {
    settings: ScoreSettings,
    gate: MeshDeliveryGate,
    /// The last active validator count the head named, kept for the ticks
    /// where its shuffling is not built yet.
    active_validators: u64,
    /// The gate's last verdict, so a change is logged once.
    mesh_deliveries_scored: bool,
}

impl PeerScoring {
    pub(crate) fn new(config: &Config) -> Self {
        Self {
            settings: ScoreSettings::new(config, crate::MESH_N),
            gate: MeshDeliveryGate::default(),
            active_validators: PLACEHOLDER_ACTIVE_VALIDATORS,
            mesh_deliveries_scored: false,
        }
    }
}

/// Rebuild the dynamic topic parameters from the head and hand them to the
/// swarm. Beacon only; a no-op on lean, which runs without peer scoring.
pub(crate) fn refresh(server: &mut P2PServer) {
    let (Some(wire), Some(scoring)) = (server.wire.beacon(), server.peer_scoring.as_mut()) else {
        return;
    };
    let wall_slot = beacon_wall_slot(wire);
    let head_slot = server.store.beacon_head().map_or(0, |(slot, _)| slot);
    let mesh_deliveries_scored = scoring.gate.update(wall_slot, head_slot);
    if mesh_deliveries_scored != scoring.mesh_deliveries_scored {
        info!(
            wall_slot,
            head_slot, mesh_deliveries_scored, "Gossipsub mesh-delivery scoring switched"
        );
        scoring.mesh_deliveries_scored = mesh_deliveries_scored;
    }
    metrics::set_gossipsub_mesh_delivery_scoring(mesh_deliveries_scored);

    if let Some(committees) = server.store.committee_cache().head_current_committees() {
        scoring.active_validators = committees.active_validator_count();
    }

    let inputs = ScoreInputs {
        active_validators: scoring.active_validators,
        current_slot: wall_slot,
        mesh_deliveries_scored,
    };
    let topics = scoring
        .settings
        .dynamic_topic_params(wire.fork_digest, inputs);
    server.swarm_handle.set_topic_score_params(topics);
}

/// Which score band a peer falls in, for `lean_gossipsub_peers_by_score`.
///
/// Mutually exclusive, so the bands add up to the peers gossipsub knows.
pub(crate) fn score_band(score: f64) -> &'static str {
    if score >= 0.0 {
        "non_negative"
    } else if score >= GOSSIP_THRESHOLD {
        "negative"
    } else if score >= PUBLISH_THRESHOLD {
        "below_gossip"
    } else if score >= GRAYLIST_THRESHOLD {
        "below_publish"
    } else {
        "below_graylist"
    }
}

/// Every band [`score_band`] can return, so a band that empties is published
/// as zero rather than keeping its last count.
pub(crate) const SCORE_BANDS: [&str; 5] = [
    "non_negative",
    "negative",
    "below_gossip",
    "below_publish",
    "below_graylist",
];

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: ForkDigest = [0x8c, 0x9f, 0x62, 0xfe];

    /// Lighthouse's default network load gives `mesh_n` 5, the value every
    /// number below was computed at on lighthouse v8.2.2's formulas.
    const LIGHTHOUSE_MESH_N: usize = 5;

    fn settings(mesh_n: usize) -> ScoreSettings {
        ScoreSettings::new(&Config::mainnet(), mesh_n)
    }

    fn inputs(active_validators: u64, mesh_deliveries_scored: bool) -> ScoreInputs {
        ScoreInputs {
            active_validators,
            // Far past every topic's decay window, like mainnet.
            current_slot: 12_000_000,
            mesh_deliveries_scored,
        }
    }

    fn assert_close(actual: f64, expected: f64, what: &str) {
        let tolerance = expected.abs() * 1e-3;
        assert!(
            (actual - expected).abs() <= tolerance,
            "{what}: {actual} is not {expected}"
        );
    }

    fn topic<'a>(topics: &'a [(IdentTopic, TopicScoreParams)], kind: &str) -> &'a TopicScoreParams {
        let name = topic_name(DIGEST, kind);
        &topics
            .iter()
            .find(|(topic, _)| topic.to_string() == name)
            .unwrap_or_else(|| panic!("{kind} has parameters"))
            .1
    }

    /// The globals match lighthouse's, which is what makes the thresholds
    /// mean what they mean on every other client.
    #[test]
    fn the_global_terms_are_lighthouses() {
        let params = settings(LIGHTHOUSE_MESH_N).peer_score_params(DIGEST, inputs(1_000_000, true));
        assert_close(params.topic_score_cap, 53.75, "topic_score_cap");
        assert_close(
            params.ip_colocation_factor_weight,
            -53.75,
            "ip colocation weight",
        );
        assert_close(params.behaviour_penalty_decay, 0.985_712, "behaviour decay");
        assert_close(params.behaviour_penalty_weight, -15.879, "behaviour weight");
        assert_eq!(params.decay_interval, Duration::from_secs(12));
        assert_eq!(params.retain_score, Duration::from_secs(38_400));
    }

    /// The per-topic numbers at 1,000,000 active validators match
    /// lighthouse's, computed from its own formulas.
    #[test]
    fn the_topic_terms_are_lighthouses() {
        let topics =
            settings(LIGHTHOUSE_MESH_N).dynamic_topic_params(DIGEST, inputs(1_000_000, true));

        let block = topic(&topics, BEACON_BLOCK);
        assert_close(block.first_message_deliveries_cap, 55.79, "block fmd cap");
        assert_close(
            block.mesh_message_deliveries_threshold,
            0.685,
            "block mmd threshold",
        );
        assert_close(
            block.invalid_message_deliveries_weight,
            -215.0,
            "block imd weight",
        );

        let aggregate = topic(&topics, BEACON_AGGREGATE_AND_PROOF);
        assert_close(
            aggregate.first_message_deliveries_cap,
            3108.6,
            "aggregate fmd cap",
        );
        assert_close(
            aggregate.mesh_message_deliveries_threshold,
            279.24,
            "aggregate threshold",
        );
        assert_close(
            aggregate.mesh_message_deliveries_cap,
            1116.95,
            "aggregate mmd cap",
        );

        let attestation = topic(&topics, "beacon_attestation_0");
        assert_close(
            attestation.first_message_deliveries_cap,
            1457.2,
            "attestation fmd cap",
        );
        assert_close(
            attestation.mesh_message_deliveries_threshold,
            266.58,
            "attestation threshold",
        );
        assert_eq!(
            attestation.mesh_message_deliveries_activation,
            Duration::from_secs(204)
        );
        assert_close(
            attestation.invalid_message_deliveries_weight,
            -6880.0,
            "attestation imd",
        );
    }

    /// Every combination gossipsub can be handed passes its own validation,
    /// including the placeholder the swarm starts on and a registry of zero.
    #[test]
    fn every_parameter_set_is_valid() {
        let settings = settings(crate::MESH_N);
        for active in [
            0,
            1,
            PLACEHOLDER_ACTIVE_VALIDATORS,
            1_000,
            100_000,
            1_000_000,
            2_500_000,
        ] {
            for current_slot in [0, 100, 600, 12_000_000] {
                for mesh_deliveries_scored in [false, true] {
                    let inputs = ScoreInputs {
                        active_validators: active,
                        current_slot,
                        mesh_deliveries_scored,
                    };
                    settings
                        .peer_score_params(DIGEST, inputs)
                        .validate()
                        .unwrap_or_else(|err| panic!("{inputs:?}: {err}"));
                }
            }
        }
        thresholds().validate().expect("valid thresholds");
    }

    /// With the gate closed no deficit can build, but the cap stays at its
    /// real value, so the counters are full when the gate opens again.
    #[test]
    fn a_closed_gate_zeroes_the_deficit_but_keeps_the_cap() {
        let settings = settings(crate::MESH_N);
        let open = settings.dynamic_topic_params(DIGEST, inputs(1_000_000, true));
        let closed = settings.dynamic_topic_params(DIGEST, inputs(1_000_000, false));
        for kind in [
            BEACON_BLOCK,
            BEACON_AGGREGATE_AND_PROOF,
            "beacon_attestation_7",
        ] {
            let (open, closed) = (topic(&open, kind), topic(&closed, kind));
            assert!(
                open.mesh_message_deliveries_weight < 0.0,
                "{kind} scored when open"
            );
            assert_eq!(closed.mesh_message_deliveries_weight, 0.0, "{kind}");
            assert_eq!(closed.mesh_message_deliveries_threshold, 0.0, "{kind}");
            assert_eq!(
                closed.mesh_message_deliveries_cap, open.mesh_message_deliveries_cap,
                "{kind} keeps counting to its real cap"
            );
        }
    }

    /// Lighthouse's young-chain rule survives the port: an open gate still
    /// leaves a topic unscored until the chain outlives its decay window.
    #[test]
    fn a_young_chain_leaves_mesh_deliveries_unscored() {
        let young = ScoreInputs {
            current_slot: SLOTS_PER_EPOCH * 2,
            ..inputs(1_000_000, true)
        };
        let topics = settings(crate::MESH_N).dynamic_topic_params(DIGEST, young);
        assert_eq!(
            topic(&topics, BEACON_BLOCK).mesh_message_deliveries_weight,
            0.0
        );
        assert_eq!(
            topic(&topics, BEACON_AGGREGATE_AND_PROOF).mesh_message_deliveries_weight,
            0.0,
            "the aggregate window is exactly two epochs, and the slot is not past it"
        );
    }

    /// Every attestation subnet has parameters, not only the ones this node
    /// backbones, since an aggregator joins others at runtime.
    #[test]
    fn every_attestation_subnet_is_scored() {
        let params = settings(crate::MESH_N).peer_score_params(DIGEST, inputs(1_000_000, true));
        for subnet_id in 0..ATTESTATION_SUBNET_COUNT {
            let topic = IdentTopic::new(attestation_topic_name(DIGEST, subnet_id));
            assert!(
                params.topics.contains_key(&topic.hash()),
                "subnet {subnet_id}"
            );
        }
        // Block, aggregate, three fixed topics and the 64 subnets.
        assert_eq!(
            params.topics.len(),
            2 + 3 + ATTESTATION_SUBNET_COUNT as usize
        );
    }

    /// Mainnet's committees saturate at `MAX_COMMITTEES_PER_SLOT`, so about
    /// sixteen aggregators each: lighthouse's figure of 1041.67 per slot.
    #[test]
    fn a_million_validators_expect_about_a_thousand_aggregators_a_slot() {
        let (per_slot, committees_per_slot) = expected_aggregators_per_slot(1_000_000);
        assert_eq!(committees_per_slot, 64);
        assert_close(per_slot, 1041.67, "aggregators per slot");
    }

    #[test]
    fn the_gate_opens_only_after_a_warmup_within_the_lag() {
        let mut gate = MeshDeliveryGate::default();
        // Catching up: far behind.
        assert!(!gate.update(1_000, 900));
        // Caught up, but the counters have not refilled yet.
        assert!(!gate.update(1_001, 1_000));
        assert!(!gate.update(
            1_000 + MESH_DELIVERY_WARMUP_SLOTS,
            1_000 + MESH_DELIVERY_WARMUP_SLOTS
        ));
        assert!(gate.update(
            1_001 + MESH_DELIVERY_WARMUP_SLOTS,
            1_000 + MESH_DELIVERY_WARMUP_SLOTS
        ));
        // A lag within the bound, empty slots say, keeps it open.
        let wall = 1_001 + MESH_DELIVERY_WARMUP_SLOTS + MESH_DELIVERY_MAX_HEAD_LAG;
        assert!(gate.update(wall, 1_001 + MESH_DELIVERY_WARMUP_SLOTS));
        // Falling further behind closes it at once, and restarts the warmup.
        assert!(!gate.update(wall + 1, 1_001 + MESH_DELIVERY_WARMUP_SLOTS));
        assert!(!gate.update(wall + 2, wall + 2));
    }

    /// The built beacon swarm scores peers and already has parameters for a
    /// subnet it does not subscribe to; a lean swarm scores nothing.
    #[tokio::test]
    async fn only_the_beacon_swarm_scores_peers() {
        use ethlambda_types::beacon::fork::ForkName;
        use ethlambda_types::beacon::primitives::Root;

        use crate::beacon::swarm::BeaconWireConfig;
        use crate::{LeanWireConfig, SwarmConfig, WireConfig, build_swarm};

        let swarm_config = |wire| SwarmConfig {
            node_key: vec![3u8; 32],
            bootnodes: Vec::new(),
            listening_socket: "127.0.0.1:0".parse().expect("valid socket"),
            target_peers: crate::discovery::DEFAULT_DISCOVERY_TARGET_PEERS,
            wire,
        };

        let beacon = build_swarm(swarm_config(WireConfig::Beacon(Box::new(
            BeaconWireConfig {
                fork_digest: DIGEST,
                fork: ForkName::Fulu,
                config: Config::mainnet(),
                genesis_time: 1_606_824_023,
                genesis_validators_root: Root::ZERO,
                custody_columns: vec![3],
                attestation_subnets: vec![5],
            },
        ))))
        .expect("beacon swarm builds");
        let gossipsub = &beacon.swarm.behaviour().gossipsub;
        assert!(gossipsub.peer_score(&beacon.local_peer_id).is_some());
        let unsubscribed_subnet = IdentTopic::new(attestation_topic_name(DIGEST, 40));
        assert!(gossipsub.get_topic_params(&unsubscribed_subnet).is_some());
        let column = IdentTopic::new(crate::beacon::topics::data_column_topic_name(DIGEST, 3));
        assert!(
            gossipsub.get_topic_params(&column).is_none(),
            "columns are not scored"
        );

        let lean = build_swarm(swarm_config(WireConfig::Lean(LeanWireConfig {
            validator_ids: Vec::new(),
            attestation_committee_count: 1,
            subscription_subnets: HashSet::new(),
            milliseconds_per_slot: 4_000,
        })))
        .expect("lean swarm builds");
        assert!(
            lean.swarm
                .behaviour()
                .gossipsub
                .peer_score(&lean.local_peer_id)
                .is_none()
        );
    }

    #[test]
    fn the_score_bands_are_split_at_the_thresholds() {
        assert_eq!(score_band(10.0), "non_negative");
        assert_eq!(score_band(0.0), "non_negative");
        assert_eq!(score_band(-1.0), "negative");
        assert_eq!(score_band(GOSSIP_THRESHOLD), "negative");
        assert_eq!(score_band(GOSSIP_THRESHOLD - 1.0), "below_gossip");
        assert_eq!(score_band(PUBLISH_THRESHOLD - 1.0), "below_publish");
        assert_eq!(score_band(GRAYLIST_THRESHOLD - 1.0), "below_graylist");
        for score in [10.0, -1.0, -5000.0, -9000.0, -20000.0] {
            assert!(SCORE_BANDS.contains(&score_band(score)));
        }
    }
}
