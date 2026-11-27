//! PQ aggregates over Waggle (the "Fast leanVM Proof Broadcast" draft EIP), as
//! Lighthouse's `pq-devnet-0-waggle` image broadcasts them.
//!
//! Every held PQ fork digest gets a Waggle subscription to its
//! `beacon_aggregate_and_proof` topic, under the same name gossipsub gives that
//! topic, and an [`AggregateDisseminationService`] that disseminates the
//! aggregates on it ([`sync`] keeps the two in step with the digests the fork
//! schedule holds). The gossipsub topic stays subscribed alongside: peers that
//! publish aggregates there are still heard, and a Waggle aggregate and a
//! gossipsub one share the seen cache, so neither is applied twice.
//!
//! [`NodeHost`] is how a service reaches the node. A header is checked on a
//! blocking thread straight off the [`Store`] (`aggregate_header_checks`),
//! drawing from the attestation permit pool gossip aggregates use. A complete
//! aggregate goes to the P2P actor, which owns the seen cache: it reassembles
//! the proof, checks it on a blocking thread (`aggregate_proof_checks`),
//! records the aggregate as seen and hands it on as an accepted gossip
//! aggregate is, to the aggregate pool and the chain actor. Nothing is reported
//! to gossipsub: the aggregate never travelled through it.

use std::collections::HashMap;
use std::ops::RangeInclusive;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant as StdInstant};

use ethlambda_network_api::AggregateArrival;
use ethlambda_state_transition::beacon::gossip::pq::{
    CheckedHeader, aggregate_header_checks, aggregate_proof_checks, aggregators_at_slot,
};
use ethlambda_state_transition::beacon::gossip::{IgnoreReason, Outcome};
use ethlambda_storage::{Store, pools::PooledPqAggregate};
use ethlambda_types::beacon::constants::MAXIMUM_GOSSIP_CLOCK_DISPARITY;
use ethlambda_types::beacon::containers::pq::{AttestationProof, SignedAggregateHeader};
use ethlambda_types::beacon::containers::proof_chunks::{
    AggregateId, AggregatePiece, ProofChunk, proof_from_chunks,
};
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::preset;
use ethlambda_types::beacon::primitives::{ForkDigest, Slot, ValidatorIndex};
use ethlambda_types::time::unix_now_ms;
use libp2p::PeerId;
use libp2p::swarm::ConnectionId;
use spawned_concurrency::message::Message;
use spawned_concurrency::tasks::{ActorRef, Context, Handler};
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio::time::Instant;
use tracing::{debug, info, warn};

use super::fork_schedule::ForkSchedule;
use super::topics::{BEACON_AGGREGATE_AND_PROOF, topic_name};
use super::verdict::guarded;
use super::waggle_aggregates::{
    AggregateDisseminationMessage, AggregateDisseminationService, AggregateOutcome,
    HeaderRejection, Host, HostError, PeerPenalties, Penalty, time_to_next_tracking_window,
    tracked_slots,
};
use crate::swarm_adapter::SwarmHandle;
use crate::waggle::{self as transport, PieceSender};
use crate::{P2PServer, Wire};

/// How many messages a service's mailbox holds: peer subscriptions and check
/// results. A full mailbox drops the message, as Lighthouse's does.
const SERVICE_MAILBOX: usize = 1024;

/// How many slots of aggregators [`NodeHost`] remembers.
const AGGREGATOR_CACHE_SLOTS: usize = 4;

/// The Waggle topic of `digest`'s aggregates: gossipsub's topic name.
pub(crate) fn topic_id(digest: ForkDigest) -> Vec<u8> {
    topic_name(digest, BEACON_AGGREGATE_AND_PROOF).into_bytes()
}

/// The transport's configuration on the beacon wire: messages as long as the
/// largest piece compresses to at worst, with room for the id and metadata,
/// and only the aggregate topics of `schedule`'s PQ digests accepted.
pub(crate) fn transport_config(schedule: Option<&ForkSchedule>) -> transport::Config {
    let max_piece = snap::raw::max_compress_len(AggregatePiece::max_ssz_len());
    let whitelist = schedule
        .map(|schedule| {
            schedule
                .entries()
                .iter()
                .filter(|entry| entry.fork == ForkName::Pq)
                .map(|entry| topic_id(entry.digest))
                .collect()
        })
        .unwrap_or_default();
    transport::Config::default()
        .set_max_protobuf_size(max_piece + 1024)
        .set_topic_whitelist(Some(whitelist))
}

/// The services of the held PQ digests, and the peers that subscribed to a
/// topic before its service started.
#[derive(Default)]
pub(crate) struct WaggleTopics {
    services: HashMap<ForkDigest, Service>,
    early: HashMap<Vec<u8>, HashMap<PeerId, (ConnectionId, PieceSender)>>,
    penalties: Arc<Mutex<PeerPenalties>>,
}

struct Service {
    messages: mpsc::Sender<AggregateDisseminationMessage>,
    /// Dropping it stops the service, which unsubscribes from the topic.
    _stop: oneshot::Sender<()>,
}

/// Start a service for every held PQ digest that has none, and stop the
/// services of the digests no longer held. Idempotent, so it runs after every
/// fork-schedule advance, the first of which is at startup.
pub(crate) fn sync(server: &mut P2PServer, ctx: &Context<P2PServer>) {
    let Wire::Beacon(wire) = &server.wire else {
        return;
    };
    let held: Vec<ForkDigest> = wire
        .held_topics()
        .filter(|topics| topics.pq)
        .map(|topics| topics.fork_digest)
        .collect();
    let schedule = wire.schedule.clone();
    let (slot_duration_ms, genesis_time) = (wire.config.slot_duration_ms, wire.genesis_time);

    server.waggle.services.retain(|digest, _| {
        let keep = held.contains(digest);
        if !keep {
            info!(fork_digest = %hex::encode(digest), "Stopped disseminating aggregates over Waggle");
        }
        keep
    });
    for digest in held {
        if server.waggle.services.contains_key(&digest) {
            continue;
        }
        let topic = topic_id(digest);
        let (messages, mailbox) = mpsc::channel(SERVICE_MAILBOX);
        let (stop, stopped) = oneshot::channel();
        let early = server.waggle.early.remove(&topic).unwrap_or_default();
        let host = NodeHost {
            store: server.store.clone(),
            schedule: schedule.clone(),
            slot_duration: Duration::from_millis(slot_duration_ms.max(1)),
            genesis_time,
            messages: messages.clone(),
            permits: server.attestation_validation_permits.clone(),
            actor: ctx.actor_ref(),
            swarm: server.swarm_handle.clone(),
            penalties: server.waggle.penalties.clone(),
            aggregators: Mutex::default(),
        };
        let (reply, subscription) = oneshot::channel();
        server.swarm_handle.waggle_subscribe(topic, reply);
        tokio::spawn(async move {
            match subscription.await {
                Ok(Some(events)) => AggregateDisseminationService::spawn(
                    digest, mailbox, events, stopped, early, host,
                ),
                _ => {
                    warn!(fork_digest = %hex::encode(digest), "Could not subscribe to the Waggle aggregate topic")
                }
            }
        });
        info!(fork_digest = %hex::encode(digest), "Disseminating aggregates over Waggle");
        server.waggle.services.insert(
            digest,
            Service {
                messages,
                _stop: stop,
            },
        );
    }
}

/// Hand a Waggle behaviour event to its topic's service: a peer that
/// subscribed to us is one the service can send to. A subscription that ended
/// needs no message, as the service sees its sender close.
pub(crate) fn on_event(server: &mut P2PServer, event: transport::Event) {
    match event {
        transport::Event::Subscribed {
            peer_id,
            connection_id,
            topic_id,
            sender,
        } => {
            let service = server
                .waggle
                .services
                .iter()
                .find(|(digest, _)| self::topic_id(**digest) == topic_id);
            match service {
                Some((_, service)) => {
                    let message = AggregateDisseminationMessage::PeerSubscribed {
                        peer_id,
                        connection_id,
                        sender,
                    };
                    let _ = service
                        .messages
                        .try_send(message)
                        .inspect_err(|err| debug!(%err, %peer_id, "Waggle service mailbox full"));
                }
                None => {
                    server
                        .waggle
                        .early
                        .entry(topic_id)
                        .or_default()
                        .insert(peer_id, (connection_id, sender));
                }
            }
        }
        transport::Event::Unsubscribed {
            peer_id,
            connection_id,
            topic_id,
        } => {
            if let Some(peers) = server.waggle.early.get_mut(&topic_id)
                && peers
                    .get(&peer_id)
                    .is_some_and(|(connection, _)| *connection == connection_id)
            {
                peers.remove(&peer_id);
            }
        }
    }
}

/// [`Host`] for a running node.
pub(crate) struct NodeHost {
    store: Store,
    schedule: ForkSchedule,
    slot_duration: Duration,
    genesis_time: u64,
    /// The service's own mailbox, for the results of the checks it asks for.
    messages: mpsc::Sender<AggregateDisseminationMessage>,
    /// The attestation pool's permits, which gossip aggregates draw from too.
    permits: Arc<Semaphore>,
    actor: ActorRef<P2PServer>,
    swarm: SwarmHandle,
    penalties: Arc<Mutex<PeerPenalties>>,
    /// The aggregators of the last few slots asked about, as reading them
    /// takes the head state.
    aggregators: Mutex<Vec<(Slot, Option<Vec<ValidatorIndex>>)>>,
}

impl NodeHost {
    /// The time since genesis, if the clock is past it.
    fn since_genesis(&self) -> Option<Duration> {
        let now = Duration::from_millis(unix_now_ms());
        now.checked_sub(Duration::from_secs(self.genesis_time))
    }

    fn disparity() -> Duration {
        Duration::from_millis(MAXIMUM_GOSSIP_CLOCK_DISPARITY)
    }
}

impl Host for NodeHost {
    fn fork_digest_at(&self, slot: Slot) -> ForkDigest {
        self.schedule.digest_at(slot / preset::slots_per_epoch())
    }

    fn aggregators_at(&self, slot: Slot) -> Option<Vec<ValidatorIndex>> {
        let mut cache = self.aggregators.lock().expect("aggregator cache poisoned");
        if let Some((_, aggregators)) = cache.iter().find(|(cached, _)| *cached == slot) {
            return aggregators.clone();
        }
        let aggregators = aggregators_at_slot(&self.store, slot);
        // A miss is not cached: the head may reach the slot shortly.
        if aggregators.is_some() {
            if cache.len() >= AGGREGATOR_CACHE_SLOTS {
                cache.remove(0);
            }
            cache.push((slot, aggregators.clone()));
        }
        aggregators
    }

    fn tracked_slots(&self) -> Option<RangeInclusive<Slot>> {
        tracked_slots(self.since_genesis()?, self.slot_duration, Self::disparity())
    }

    fn time_to_next_tracking_window(&self) -> Duration {
        match self.since_genesis() {
            Some(now) => time_to_next_tracking_window(now, self.slot_duration, Self::disparity()),
            None => self.slot_duration,
        }
    }

    fn check_header(
        &self,
        id: AggregateId,
        peer_id: PeerId,
        signed_header: Arc<SignedAggregateHeader>,
    ) -> Result<(), HostError> {
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| HostError::Overloaded)?;
        let store = self.store.clone();
        let messages = self.messages.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut checked = None;
            let outcome =
                guarded(
                    || match aggregate_header_checks(&store, &signed_header, unix_now_ms()) {
                        Ok(header) => {
                            checked = Some(header);
                            Outcome::Accept
                        }
                        Err(outcome) => outcome,
                    },
                );
            let result = match (outcome, checked) {
                (Outcome::Accept, Some(header)) => Ok(Arc::new(header)),
                (Outcome::Reject(reason), _) => {
                    debug!(
                        slot = id.slot,
                        aggregator_index = id.aggregator_index,
                        ?reason,
                        "Invalid aggregate header"
                    );
                    Err(HeaderRejection::Invalid)
                }
                (outcome, _) => {
                    debug!(
                        slot = id.slot,
                        aggregator_index = id.aggregator_index,
                        ?outcome,
                        "Aggregate header not checked"
                    );
                    Err(HeaderRejection::Ignored)
                }
            };
            let message = AggregateDisseminationMessage::HeaderVerified {
                id,
                peer_id,
                result,
            };
            let _ = messages.blocking_send(message);
        });
        Ok(())
    }

    fn check_aggregate(
        &self,
        header: Arc<CheckedHeader>,
        chunks: Vec<Arc<ProofChunk>>,
        peer_id: PeerId,
    ) -> Result<(), HostError> {
        let complete = WaggleAggregateComplete {
            header,
            chunks,
            peer_id,
            reply: self.messages.clone(),
            received_at: StdInstant::now(),
        };
        self.actor
            .send(complete)
            .map_err(|_| HostError::ShuttingDown)
    }

    fn report_peer(&self, peer_id: PeerId, penalty: Penalty, reason: &'static str) {
        debug!(%peer_id, ?penalty, reason, "Penalizing a peer for its Waggle messages");
        let disconnect = self.penalties.lock().expect("penalties poisoned").add(
            peer_id,
            penalty,
            Instant::now(),
        );
        if disconnect {
            info!(%peer_id, reason, "Disconnecting a peer for misbehaving on Waggle");
            self.swarm.disconnect(peer_id);
        }
    }
}

/// An aggregate whose every chunk a service holds, for the P2P actor to check
/// against the seen cache and the proof, and hand on.
pub(crate) struct WaggleAggregateComplete {
    header: Arc<CheckedHeader>,
    chunks: Vec<Arc<ProofChunk>>,
    peer_id: PeerId,
    /// The service's mailbox, for the outcome.
    reply: mpsc::Sender<AggregateDisseminationMessage>,
    received_at: StdInstant,
}

impl Message for WaggleAggregateComplete {
    type Result = ();
}

/// A complete aggregate's proof, checked on a blocking thread.
pub(crate) struct WaggleAggregateChecked {
    header: Arc<CheckedHeader>,
    proof: AttestationProof,
    outcome: Outcome,
    reply: mpsc::Sender<AggregateDisseminationMessage>,
    received_at: StdInstant,
}

impl Message for WaggleAggregateChecked {
    type Result = ();
}

impl Handler<WaggleAggregateComplete> for P2PServer {
    async fn handle(&mut self, msg: WaggleAggregateComplete, ctx: &Context<Self>) {
        let WaggleAggregateComplete {
            header,
            chunks,
            peer_id,
            reply,
            received_at,
        } = msg;
        let id = AggregateId::of(&header.signed_header.message);
        let proof = match proof_from_chunks(chunks.iter().map(|chunk| &chunk.chunk)) {
            Ok(proof) => proof,
            Err(err) => {
                debug!(%err, %peer_id, "A complete aggregate's chunks do not reassemble");
                send_outcome(&reply, id, AggregateOutcome::Invalid);
                return;
            }
        };
        // The seen cache's two rules, before the proof is checked.
        if let Err(outcome) = header.seen_check(&self.seen_aggregates) {
            debug!(
                ?outcome,
                slot = id.slot,
                aggregator_index = id.aggregator_index,
                "Complete aggregate already seen"
            );
            send_outcome(&reply, id, AggregateOutcome::Ignored);
            return;
        }
        let Ok(permit) = self
            .attestation_validation_permits
            .clone()
            .try_acquire_owned()
        else {
            send_outcome(&reply, id, AggregateOutcome::Ignored);
            return;
        };
        let actor = ctx.actor_ref();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let outcome = guarded(|| aggregate_proof_checks(&header, &proof));
            let checked = WaggleAggregateChecked {
                header,
                proof,
                outcome,
                reply,
                received_at,
            };
            let _ = actor
                .send(checked)
                .inspect_err(|_| warn!("P2P actor stopped before a Waggle aggregate was checked"));
        });
    }
}

impl Handler<WaggleAggregateChecked> for P2PServer {
    async fn handle(&mut self, msg: WaggleAggregateChecked, _ctx: &Context<Self>) {
        let WaggleAggregateChecked {
            header,
            proof,
            outcome,
            reply,
            received_at,
        } = msg;
        let id = AggregateId::of(&header.signed_header.message);
        // First valid one wins, as for gossip: another copy may have been
        // accepted while this one's proof was checked.
        let bits = header.aggregation_bits();
        let outcome = if outcome == Outcome::Accept
            && !self.seen_aggregates.record_parts(&header.seen_key(), &bits)
        {
            Outcome::Ignore(IgnoreReason::AlreadySeen)
        } else {
            outcome
        };
        let (label, reason) = outcome.labels();
        crate::metrics::observe_beacon_gossip_verdict(
            "waggle_aggregate",
            label,
            reason,
            received_at.elapsed(),
        );
        let result = match outcome {
            Outcome::Accept => {
                hand_on(self, &header, proof, received_at);
                AggregateOutcome::Valid
            }
            Outcome::Reject(_) => AggregateOutcome::Invalid,
            Outcome::Ignore(_) | Outcome::Queue(_) => AggregateOutcome::Ignored,
        };
        send_outcome(&reply, id, result);
    }
}

fn send_outcome(
    reply: &mpsc::Sender<AggregateDisseminationMessage>,
    id: AggregateId,
    outcome: AggregateOutcome,
) {
    let message = AggregateDisseminationMessage::AggregateVerified { id, outcome };
    let _ = reply
        .try_send(message)
        .inspect_err(|err| debug!(%err, "Waggle service mailbox full"));
}

/// Hand an accepted aggregate on as an accepted gossip aggregate is: to the
/// pool block production merges proofs from, and its vote to the chain actor.
fn hand_on(
    server: &P2PServer,
    header: &CheckedHeader,
    proof: AttestationProof,
    received_at: StdInstant,
) {
    let aggregate = header.aggregate();
    server.store.pq_aggregate_pool().insert(PooledPqAggregate {
        attestation: aggregate.clone(),
        committee_index: header.committee_index,
        attesting_indices: header.attesting_indices.clone(),
        proof,
    });
    let Some(blockchain) = &server.blockchain else {
        return;
    };
    let arrival = AggregateArrival {
        decode_start: received_at,
        handed_off: StdInstant::now(),
    };
    let _ = blockchain
        .new_pq_aggregate(aggregate.data, header.attesting_indices.clone(), arrival)
        .inspect_err(|err| warn!(%err, "Failed to forward a Waggle aggregate"));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lighthouse whitelists, and names, the topic exactly as gossipsub does.
    #[test]
    fn the_topic_is_gossipsubs_aggregate_topic() {
        let digest = [0xab, 0xcd, 0x01, 0x02];
        assert_eq!(
            topic_id(digest),
            b"/eth2/abcd0102/beacon_aggregate_and_proof/ssz_snappy".to_vec()
        );
    }

    /// The largest piece fits a message, as Lighthouse sizes it.
    #[test]
    fn a_message_holds_the_largest_piece() {
        let config = transport_config(None);
        assert!(config.max_protobuf_size() > AggregatePiece::max_ssz_len());
        assert_eq!(config.topic_whitelist().map(|w| w.len()), Some(0));
    }
}
