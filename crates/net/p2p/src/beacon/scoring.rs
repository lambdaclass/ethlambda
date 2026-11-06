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
//! ([`refresh`]) from the head's current-epoch shuffling, under every held
//! fork digest. Until the first refresh they are built for
//! [`PLACEHOLDER_ACTIVE_VALIDATORS`] with P3 off, the same placeholder
//! lighthouse starts from.
//!
//! # Fork digests
//!
//! Around a boundary the node holds two digests' topics (see
//! [`super::fork_schedule`]). Every held digest gets the whole parameter set,
//! scored by its [`DigestRole`]:
//!
//! | role | topic weights | mesh deliveries (P3) |
//! |---|---|---|
//! | upcoming, joined [`SUBSCRIBE_LEAD_EPOCHS`] ahead | as above | off |
//! | current | as above | per [`MeshDeliveryGate`] |
//! | previous, held [`UNSUBSCRIBE_LAG_EPOCHS`] after | 0 | off |
//!
//! [`SUBSCRIBE_LEAD_EPOCHS`]: super::fork_schedule::SUBSCRIBE_LEAD_EPOCHS
//! [`UNSUBSCRIBE_LAG_EPOCHS`]: super::fork_schedule::UNSUBSCRIBE_LAG_EPOCHS
//!
//! - The parameters reach the swarm before the topics are joined
//!   ([`super::transition::apply`]). Gossipsub tracks a mesh peer on a topic
//!   only if the topic had parameters when the peer was grafted: parameters
//!   installed later do not reach a mesh that already exists.
//! - The previous digest's traffic moves away at the boundary, so its delivery
//!   counters drain. Scored at its weight, the aggregate topic alone would put
//!   an honest mesh peer below the graylist before the topic is left, and
//!   leaving it would charge every mesh peer the sticky mesh-failure penalty.
//!   Lighthouse zeroes the same weights (`remove_topic_weight_except`).
//! - A switch restarts the gate's warmup. The new digest's counters start
//!   empty, while its mesh, formed before the boundary, can already be past
//!   the deliveries' activation. Lighthouse joins two slots ahead, so
//!   activation covers the refill there; this node joins whole epochs ahead.

use std::cmp::Ordering;
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
use crate::swarm_adapter::SwarmHandle;
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

/// Where a held fork digest stands against the one this node publishes
/// under, which decides how its topics are scored. See the module
/// documentation's "Fork digests".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestRole {
    /// Left behind by the last boundary and held a while longer. Weighs
    /// nothing, since its traffic has moved to the current digest.
    Previous,
    /// The digest this node publishes under, and the only one whose mesh
    /// deliveries can be scored.
    Current,
    /// Joined ahead of its boundary. Nothing is published under it yet, so
    /// its mesh deliveries are not scored.
    Upcoming,
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
    /// under `fork_digest` as the current digest. The digests a fork schedule
    /// adds later are parametrized by [`PeerScoring::hold`].
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
            .digest_topic_params(fork_digest, DigestRole::Current, inputs)
            .into_iter()
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

    /// Every scored topic under `fork_digest`, for a digest in `role`.
    ///
    /// `inputs.mesh_deliveries_scored` only reaches the current digest. The
    /// rest are built at their real rates, so their caps match the current
    /// digest's, and a previous digest then has its weights zeroed.
    pub fn digest_topic_params(
        &self,
        fork_digest: ForkDigest,
        role: DigestRole,
        inputs: ScoreInputs,
    ) -> Vec<(IdentTopic, TopicScoreParams)> {
        let inputs = ScoreInputs {
            mesh_deliveries_scored: inputs.mesh_deliveries_scored && role == DigestRole::Current,
            ..inputs
        };
        let mut topics = self.fixed_topic_params(fork_digest);
        topics.extend(self.dynamic_topic_params(fork_digest, inputs));
        if role == DigestRole::Previous {
            // Zeroed after the build rather than passed in as the weight:
            // the invalid-message weight divides by it.
            for (_, params) in &mut topics {
                params.topic_weight = 0.0;
            }
        }
        topics
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

    /// Start the warmup over, as if the head had just caught up: the
    /// counters that the verdict reads have been emptied.
    pub fn restart(&mut self) {
        self.keeping_up_since = None;
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
    /// The fork digests whose topics the node holds, in activation order.
    held: Vec<ForkDigest>,
    /// The one among [`Self::held`] this node publishes under.
    current: ForkDigest,
}

impl PeerScoring {
    /// `fork_digest` is the digest the swarm was built on, the only one held
    /// until the fork schedule is first applied.
    pub(crate) fn new(config: &Config, fork_digest: ForkDigest) -> Self {
        Self {
            settings: ScoreSettings::new(config, crate::MESH_N),
            gate: MeshDeliveryGate::default(),
            active_validators: PLACEHOLDER_ACTIVE_VALIDATORS,
            mesh_deliveries_scored: false,
            held: vec![fork_digest],
            current: fork_digest,
        }
    }

    /// Record the digests the node now holds, in activation order, and which
    /// one is current, then hand the swarm every one's parameters.
    ///
    /// Called by [`super::transition::apply`] before it joins any topic, so
    /// a digest is parametrized before its first GRAFT. Both travel the
    /// swarm's one command channel, so sending these first is enough.
    pub(crate) fn hold(
        &mut self,
        held: Vec<ForkDigest>,
        current: ForkDigest,
        wall_slot: u64,
        swarm: &SwarmHandle,
    ) {
        if current != self.current {
            // The new digest's counters are empty and its mesh may already
            // be past the deliveries' activation, so scoring it now would
            // graylist its whole aggregate mesh before the first aggregate.
            self.gate.restart();
            if self.mesh_deliveries_scored {
                info!(
                    fork_digest = %hex::encode(current),
                    "Gossipsub mesh-delivery scoring paused while the new fork digest warms up"
                );
                self.mesh_deliveries_scored = false;
                metrics::set_gossipsub_mesh_delivery_scoring(false);
            }
            self.current = current;
        }
        self.held = held;
        self.install(wall_slot, swarm);
    }

    /// Hand the swarm the parameters of every held digest, each by its role.
    fn install(&self, wall_slot: u64, swarm: &SwarmHandle) {
        let inputs = ScoreInputs {
            active_validators: self.active_validators,
            current_slot: wall_slot,
            mesh_deliveries_scored: self.mesh_deliveries_scored,
        };
        // `apply` checks that the current digest is held before it calls
        // `hold`, so `None` (every digest previous) is never reached.
        let current_index = self.held.iter().position(|&digest| digest == self.current);
        let topics = self
            .held
            .iter()
            .enumerate()
            .flat_map(|(index, &digest)| {
                let role = match current_index.map(|current| index.cmp(&current)) {
                    Some(Ordering::Equal) => DigestRole::Current,
                    Some(Ordering::Greater) => DigestRole::Upcoming,
                    Some(Ordering::Less) | None => DigestRole::Previous,
                };
                self.settings.digest_topic_params(digest, role, inputs)
            })
            .collect();
        swarm.set_topic_score_params(topics);
    }
}

/// Rebuild every held digest's topic parameters from the head and hand them
/// to the swarm. Beacon only; a no-op on lean, which runs without peer
/// scoring.
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

    scoring.install(wall_slot, &server.swarm_handle);
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

    use std::collections::HashMap;

    use ethlambda_types::beacon::config::BlobScheduleEntry;
    use ethlambda_types::beacon::fork::ForkName;
    use ethlambda_types::beacon::primitives::Root;
    use futures::StreamExt;
    use libp2p::gossipsub::TopicHash;
    use libp2p::swarm::SwarmEvent;
    use libssz_types::SszList;
    use tokio::sync::mpsc::UnboundedReceiver;

    use crate::beacon::fork_schedule::{ForkSchedule, UNSUBSCRIBE_LAG_EPOCHS};
    use crate::beacon::swarm::BeaconWireConfig;
    use crate::beacon::transition::apply;
    use crate::swarm_adapter::{SwarmCommand, execute_command};
    use crate::test_support::unconnected_beacon_server;
    use crate::{BuiltSwarm, LeanWireConfig, SwarmConfig, WireConfig, build_swarm};

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
    /// including the placeholder the swarm starts on, a registry of zero, and
    /// every digest role's topics.
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
                    for role in [DigestRole::Previous, DigestRole::Upcoming] {
                        for (topic, params) in settings.digest_topic_params(DIGEST, role, inputs) {
                            params
                                .validate()
                                .unwrap_or_else(|err| panic!("{role:?} {topic} {inputs:?}: {err}"));
                        }
                    }
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

    /// A restart, which a fork digest switch triggers, closes an open gate
    /// for a whole warmup even though the head never fell behind.
    #[test]
    fn a_restarted_gate_warms_up_again() {
        let mut gate = MeshDeliveryGate::default();
        assert!(!gate.update(1_000, 1_000));
        let open = 1_000 + MESH_DELIVERY_WARMUP_SLOTS;
        assert!(gate.update(open, open));

        gate.restart();
        assert!(!gate.update(open + 1, open + 1));
        let warm = open + 1 + MESH_DELIVERY_WARMUP_SLOTS;
        assert!(!gate.update(warm - 1, warm - 1));
        assert!(gate.update(warm, warm));
    }

    /// Only the current digest's mesh deliveries are scored, whatever the
    /// gate says; a previous digest weighs nothing; and every role carries
    /// the whole topic set, exits and slashings included.
    #[test]
    fn each_digest_role_is_scored_as_its_traffic_allows() {
        let settings = settings(crate::MESH_N);
        let inputs = inputs(1_000_000, true);
        let current = settings.digest_topic_params(DIGEST, DigestRole::Current, inputs);
        let upcoming = settings.digest_topic_params(DIGEST, DigestRole::Upcoming, inputs);
        let previous = settings.digest_topic_params(DIGEST, DigestRole::Previous, inputs);

        for topics in [&current, &upcoming, &previous] {
            assert_eq!(topics.len(), 2 + 3 + ATTESTATION_SUBNET_COUNT as usize);
            for kind in [VOLUNTARY_EXIT, PROPOSER_SLASHING, ATTESTER_SLASHING] {
                topic(topics, kind);
            }
        }
        for kind in [
            BEACON_BLOCK,
            BEACON_AGGREGATE_AND_PROOF,
            "beacon_attestation_7",
        ] {
            let current = topic(&current, kind);
            assert!(current.mesh_message_deliveries_weight < 0.0, "{kind}");
            let others = [
                ("upcoming", topic(&upcoming, kind)),
                ("previous", topic(&previous, kind)),
            ];
            for (role, params) in others {
                assert_eq!(params.mesh_message_deliveries_weight, 0.0, "{role} {kind}");
                assert_eq!(
                    params.mesh_message_deliveries_threshold, 0.0,
                    "{role} {kind}"
                );
                // The same caps, so a change of role trims no counter.
                assert_eq!(
                    params.mesh_message_deliveries_cap, current.mesh_message_deliveries_cap,
                    "{role} {kind}"
                );
                assert_eq!(
                    params.first_message_deliveries_cap, current.first_message_deliveries_cap,
                    "{role} {kind}"
                );
            }
            assert_eq!(topic(&upcoming, kind).topic_weight, current.topic_weight);
        }
        assert!(
            previous
                .iter()
                .all(|(_, params)| params.topic_weight == 0.0)
        );
    }

    /// One honest mesh peer on a topic whose traffic stopped at a boundary,
    /// scored tick by tick the way the pinned gossipsub scores mesh
    /// deliveries (`peer_score.rs`): the counter starts at its cap and only
    /// decays. Returns the weighted P3 at every tick of the epochs the topic
    /// is still held, and the P3b that leaving the topic then charges.
    fn silent_mesh_penalties(params: &TopicScoreParams) -> (Vec<f64>, f64) {
        let deficit =
            |deliveries: f64| (params.mesh_message_deliveries_threshold - deliveries).max(0.0);
        let mut deliveries = params.mesh_message_deliveries_cap;
        let p3 = (0..UNSUBSCRIBE_LAG_EPOCHS * SLOTS_PER_EPOCH)
            .map(|_| {
                deliveries *= params.mesh_message_deliveries_decay;
                if deliveries < DECAY_TO_ZERO {
                    deliveries = 0.0;
                }
                deficit(deliveries).powi(2)
                    * params.mesh_message_deliveries_weight
                    * params.topic_weight
            })
            .collect();
        let p3b =
            deficit(deliveries).powi(2) * params.mesh_failure_penalty_weight * params.topic_weight;
        (p3, p3b)
    }

    /// The aggregate topic of the digest a boundary just left. Still scored
    /// as current, an honest mesh peer's P3 alone crosses the graylist 53
    /// slots in, before the topic is left; as a previous digest, no topic
    /// costs it anything while held or when left.
    #[test]
    fn a_previous_digest_never_graylists_its_silent_mesh() {
        let settings = settings(crate::MESH_N);
        let inputs = inputs(1_000_000, true);

        let as_current = settings.digest_topic_params(DIGEST, DigestRole::Current, inputs);
        let (p3, _) = silent_mesh_penalties(topic(&as_current, BEACON_AGGREGATE_AND_PROOF));
        let graylisted_at = p3
            .iter()
            .position(|&penalty| penalty < GRAYLIST_THRESHOLD)
            .map(|tick| tick + 1);
        assert_eq!(graylisted_at, Some(53));

        let as_previous = settings.digest_topic_params(DIGEST, DigestRole::Previous, inputs);
        for (topic, params) in &as_previous {
            let (p3, p3b) = silent_mesh_penalties(params);
            assert!(p3.iter().all(|&penalty| penalty == 0.0), "{topic}");
            assert_eq!(p3b, 0.0, "{topic}");
        }
    }

    const FULU: u64 = 1_000;
    const BPO: u64 = 2_000;

    /// Fulu, then one blob-parameter-only fork: a single digest boundary.
    fn rollover_config() -> Config {
        let mut config = Config::mainnet()
            .with_fork_epoch(ForkName::Altair, 1)
            .with_fork_epoch(ForkName::Bellatrix, 2)
            .with_fork_epoch(ForkName::Capella, 3)
            .with_fork_epoch(ForkName::Deneb, 4)
            .with_fork_epoch(ForkName::Electra, 5)
            .with_fork_epoch(ForkName::Fulu, FULU);
        config.blob_schedule = SszList::try_from(vec![BlobScheduleEntry {
            epoch: BPO,
            max_blobs_per_block: 15,
        }])
        .expect("within capacity");
        config
    }

    /// A beacon `P2PServer` whose swarm commands land in the returned
    /// receiver, scoring peers the way `P2P::spawn` sets it up.
    async fn capturing_server(config: &Config) -> (P2PServer, UnboundedReceiver<SwarmCommand>) {
        let mut server = unconnected_beacon_server(config.clone(), 0).await;
        let (swarm_handle, commands) = SwarmHandle::capturing();
        server.swarm_handle = swarm_handle;
        // The digest `unconnected_beacon_server` builds its swarm on.
        server.peer_scoring = Some(PeerScoring::new(config, [0; 4]));
        (server, commands)
    }

    /// Plays captured swarm commands into what gossipsub would hold: the
    /// installed parameters, plus the topics joined and left. Every scored
    /// topic joined must have had its parameters installed by then.
    fn replay(
        commands: &mut UnboundedReceiver<SwarmCommand>,
        installed: &mut HashMap<TopicHash, TopicScoreParams>,
        scored: &HashSet<TopicHash>,
    ) -> (HashSet<TopicHash>, HashSet<TopicHash>) {
        let (mut joined, mut left) = (HashSet::new(), HashSet::new());
        while let Ok(command) = commands.try_recv() {
            match command {
                SwarmCommand::SetTopicScoreParams(topics) => installed.extend(
                    topics
                        .into_iter()
                        .map(|(topic, params)| (topic.hash(), params)),
                ),
                SwarmCommand::Subscribe(topic) => {
                    let hash = topic.hash();
                    assert!(
                        !scored.contains(&hash) || installed.contains_key(&hash),
                        "{topic} joined before it had parameters"
                    );
                    joined.insert(hash);
                }
                SwarmCommand::Unsubscribe(topic) => {
                    left.insert(topic.hash());
                }
                _ => {}
            }
        }
        (joined, left)
    }

    /// A live rollover through [`apply`], with the swarm's commands read in
    /// order: each digest is parametrized whole before any of its topics is
    /// joined, the digest left behind stops weighing at the switch and is
    /// left that way, and the switch restarts the mesh-delivery warmup.
    #[tokio::test]
    async fn a_rollover_parametrizes_each_digest_before_joining_it() {
        let config = rollover_config();
        let (mut server, mut commands) = capturing_server(&config).await;
        let schedule = server.wire.beacon().expect("beacon").schedule.clone();
        let (before, after) = (schedule.digest_at(BPO - 1), schedule.digest_at(BPO));

        let settings = ScoreSettings::new(&config, crate::MESH_N);
        let scored_under = |digest| -> HashSet<TopicHash> {
            settings
                .digest_topic_params(digest, DigestRole::Current, ScoreInputs::placeholder())
                .into_iter()
                .map(|(topic, _)| topic.hash())
                .collect()
        };
        let scored: HashSet<TopicHash> = scored_under(before)
            .union(&scored_under(after))
            .cloned()
            .collect();
        // What is joined and left of them: the attestation subnets only when
        // backboned, which this server has none of.
        let global_scored_under = |digest| -> HashSet<TopicHash> {
            [
                BEACON_BLOCK,
                BEACON_AGGREGATE_AND_PROOF,
                VOLUNTARY_EXIT,
                PROPOSER_SLASHING,
                ATTESTER_SLASHING,
            ]
            .into_iter()
            .map(|kind| IdentTopic::new(topic_name(digest, kind)).hash())
            .collect()
        };
        let mut installed = HashMap::new();
        let params = |installed: &HashMap<TopicHash, TopicScoreParams>, digest, kind| {
            installed[&IdentTopic::new(topic_name(digest, kind)).hash()].clone()
        };
        let dynamic_kinds = [
            BEACON_BLOCK,
            BEACON_AGGREGATE_AND_PROOF,
            "beacon_attestation_0",
        ];

        apply(&mut server, BPO - 2);
        replay(&mut commands, &mut installed, &scored);
        // As if the head had kept up for a warmup already.
        let scoring = server.peer_scoring.as_mut().unwrap();
        scoring.gate.keeping_up_since = Some(0);
        scoring.mesh_deliveries_scored = true;

        // The epoch before: the next digest is joined, every topic of it
        // parametrized, none of them scored for deliveries.
        apply(&mut server, BPO - 1);
        let (joined, _) = replay(&mut commands, &mut installed, &scored);
        assert!(global_scored_under(after).is_subset(&joined));
        for kind in dynamic_kinds {
            assert!(params(&installed, before, kind).mesh_message_deliveries_weight < 0.0);
            let upcoming = params(&installed, after, kind);
            assert_eq!(upcoming.mesh_message_deliveries_weight, 0.0, "{kind}");
            assert!(upcoming.topic_weight > 0.0, "{kind}");
        }

        // The switch: the digest left behind weighs nothing, and the new one
        // waits out a warmup before its deliveries are scored.
        apply(&mut server, BPO);
        replay(&mut commands, &mut installed, &scored);
        for hash in scored_under(before) {
            assert_eq!(installed[&hash].topic_weight, 0.0);
            assert_eq!(installed[&hash].mesh_message_deliveries_weight, 0.0);
        }
        for kind in dynamic_kinds {
            let current = params(&installed, after, kind);
            assert_eq!(current.mesh_message_deliveries_weight, 0.0, "{kind}");
        }
        let scoring = server.peer_scoring.as_ref().unwrap();
        assert!(!scoring.mesh_deliveries_scored);
        assert!(scoring.gate.keeping_up_since.is_none());

        // Warm again: the new digest is scored as the old one was.
        server.peer_scoring.as_mut().unwrap().mesh_deliveries_scored = true;
        apply(&mut server, BPO + 1);
        replay(&mut commands, &mut installed, &scored);
        for kind in dynamic_kinds {
            assert!(params(&installed, after, kind).mesh_message_deliveries_weight < 0.0);
            assert_eq!(params(&installed, before, kind).topic_weight, 0.0);
        }

        // Two epochs on, the old digest is left still weighing nothing, so
        // leaving it charges its mesh no mesh-failure penalty.
        apply(&mut server, BPO + 2);
        let (_, left) = replay(&mut commands, &mut installed, &scored);
        assert!(global_scored_under(before).is_subset(&left));
        assert!(
            scored_under(before)
                .iter()
                .all(|hash| installed[hash].topic_weight == 0.0)
        );
    }

    /// Polls both swarms until `done` holds of `node`'s gossipsub, for at
    /// most `limit`, and returns whether it did.
    async fn poll_until(
        node: &mut BuiltSwarm,
        peer: &mut BuiltSwarm,
        limit: Duration,
        done: impl Fn(&crate::Gossipsub) -> bool,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + limit;
        while tokio::time::Instant::now() < deadline {
            if done(&node.swarm.behaviour().gossipsub) {
                return true;
            }
            tokio::select! {
                _ = node.swarm.select_next_some() => {}
                _ = peer.swarm.select_next_some() => {}
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
        }
        done(&node.swarm.behaviour().gossipsub)
    }

    /// The same rollover on two real swarms. A mesh grafted on the next
    /// digest's topics in the epoch before its fork is scored from that GRAFT
    /// on, because [`apply`] installs the parameters before it joins. The
    /// control is the order this replaces: a topic joined before it had
    /// parameters keeps its mesh unscored even after they arrive.
    #[tokio::test]
    async fn a_mesh_grafted_ahead_of_its_fork_is_scored() {
        // One-second slots: gossipsub refreshes its scores once a slot.
        let mut config = rollover_config();
        config.slot_duration_ms = 1_000;
        let schedule = ForkSchedule::new(&config, Root::ZERO);
        let build = |node_key_byte: u8, fork_digest: ForkDigest| {
            build_swarm(SwarmConfig {
                node_key: vec![node_key_byte; 32],
                bootnodes: Vec::new(),
                listening_socket: "127.0.0.1:0".parse().expect("valid socket"),
                target_peers: crate::discovery::DEFAULT_DISCOVERY_TARGET_PEERS,
                agent_version: "ethlambda/test",
                wire: WireConfig::Beacon(Box::new(BeaconWireConfig {
                    fork_digest,
                    fork: ForkName::Fulu,
                    config: config.clone(),
                    genesis_time: config.genesis_time,
                    genesis_validators_root: Root::ZERO,
                    custody_columns: Vec::new(),
                    attestation_subnets: Vec::new(),
                })),
            })
            .expect("beacon swarm builds")
        };
        // `node` is the one scoring. `peer` was built on a digest of its own,
        // so the two share only the topics subscribed below.
        let mut node = build(1, schedule.digest_at(BPO - 1));
        let mut peer = build(2, [0xEE; 4]);
        let peer_id = peer.local_peer_id;

        let node_addr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = node.swarm.select_next_some().await {
                break address
                    .with_p2p(node.local_peer_id)
                    .expect("failed to add peer ID to multiaddr");
            }
        };
        peer.swarm.dial(node_addr).expect("dial is accepted");

        let control = IdentTopic::new(topic_name([0xAB; 4], BEACON_BLOCK));
        let upcoming = IdentTopic::new(topic_name(schedule.digest_at(BPO), BEACON_BLOCK));
        for topic in [&control, &upcoming] {
            let gossipsub = &mut peer.swarm.behaviour_mut().gossipsub;
            gossipsub.subscribe(topic).expect("peer subscribes");
        }
        let peer_on_both = |gossipsub: &crate::Gossipsub| {
            gossipsub.all_peers().any(|(id, topics)| {
                *id == peer_id
                    && topics.contains(&&control.hash())
                    && topics.contains(&&upcoming.hash())
            })
        };
        let announced =
            poll_until(&mut node, &mut peer, Duration::from_secs(10), peer_on_both).await;
        assert!(announced, "the peer's subscriptions reach the node");
        let in_mesh = |gossipsub: &crate::Gossipsub, topic: &IdentTopic| {
            gossipsub.mesh_peers(&topic.hash()).any(|id| *id == peer_id)
        };

        // The control: joined first, so the join grafts the peer before the
        // topic has parameters.
        let settings = ScoreSettings::new(&config, crate::MESH_N);
        let control_params = settings
            .digest_topic_params([0xAB; 4], DigestRole::Upcoming, ScoreInputs::placeholder())
            .into_iter()
            .find(|(topic, _)| topic.hash() == control.hash())
            .expect("the block topic is scored")
            .1;
        let gossipsub = &mut node.swarm.behaviour_mut().gossipsub;
        gossipsub.subscribe(&control).expect("node subscribes");
        gossipsub
            .set_topic_params(control.clone(), control_params)
            .expect("the beacon swarm scores peers");
        assert!(in_mesh(&node.swarm.behaviour().gossipsub, &control));
        // Long enough for two score refreshes.
        poll_until(&mut node, &mut peer, Duration::from_millis(2_500), |_| {
            false
        })
        .await;
        let gossipsub = &node.swarm.behaviour().gossipsub;
        assert_eq!(gossipsub.peer_score(&peer_id), Some(0.0));

        // The rollover's own order, at the epoch before the fork.
        let (mut server, mut commands) = capturing_server(&config).await;
        apply(&mut server, BPO - 1);
        while let Ok(command) = commands.try_recv() {
            execute_command(&mut node.swarm, command);
        }
        assert!(in_mesh(&node.swarm.behaviour().gossipsub, &upcoming));
        let scored = poll_until(&mut node, &mut peer, Duration::from_secs(10), |gossipsub| {
            gossipsub
                .peer_score(&peer_id)
                .is_some_and(|score| score > 0.0)
        })
        .await;
        assert!(
            scored,
            "the mesh grafted ahead of the fork earns time in mesh"
        );
    }

    /// The built beacon swarm scores peers and already has parameters for a
    /// subnet it does not subscribe to; a lean swarm scores nothing.
    #[tokio::test]
    async fn only_the_beacon_swarm_scores_peers() {
        let swarm_config = |wire| SwarmConfig {
            node_key: vec![3u8; 32],
            bootnodes: Vec::new(),
            listening_socket: "127.0.0.1:0".parse().expect("valid socket"),
            target_peers: crate::discovery::DEFAULT_DISCOVERY_TARGET_PEERS,
            agent_version: "ethlambda/test",
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
