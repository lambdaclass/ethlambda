//! Gossip on a PQ fork digest's topics whose container the fork reshapes:
//! decode by the topic's digest, the cheap rules inline, and the stateful ones
//! on a blocking thread. The rules are
//! `ethlambda_state_transition::beacon::gossip::pq`'s, and the bid and
//! preference rules gloas's own through their fork traits.
//!
//! An accepted message is relayed and recorded in the seen caches the other
//! forks' messages share (and its bid or preferences in the PQ builder
//! market). The chain actor then takes what fork choice reads: an aggregate's
//! vote and attesting indices, a payload attestation message, and an envelope
//! (queued ones too, as for gloas). Blocks and data column sidecars take the
//! shared path.

use std::time::Instant;

use std::time::Instant as StdInstant;

use ethlambda_network_api::{AggregateArrival, BlockArrival};
use ethlambda_state_transition::beacon::builder_market::SharedPqBuilderMarket;
use ethlambda_state_transition::beacon::gossip::{self, IgnoreReason, Outcome};
use ethlambda_state_transition::beacon::helpers::pq::get_committee_indices;
use ethlambda_storage::{Store, pools::PooledPqAggregate};
use ethlambda_types::beacon::containers::{SignedExecutionPayloadEnvelope, pq};
use ethlambda_types::beacon::primitives::ValidatorIndex;
use ethlambda_types::time::unix_now_ms;
use tracing::{debug, trace, warn};

use crate::beacon::builder_market::wall_slot;
use crate::beacon::decode::{self as beacon_decode, PqGossip};
use crate::beacon::topics as beacon_topics;
use crate::beacon::verdict::{Dispatch, Validated};
use crate::{P2PServer, metrics};

/// A PQ message whose stateful checks run on a blocking thread. The one
/// [`Validated`] variant for every PQ topic, so the shared variants, which
/// the chain actor, the pools and the event stream read, carry no PQ shape.
pub(crate) enum PqValidated {
    Aggregate {
        signed: Box<pq::SignedAggregateAndProof>,
        /// Filled in by [`Self::stateful_checks`] on `Accept`.
        attesting_indices: Vec<ValidatorIndex>,
    },
    Attestation {
        attestation: Box<pq::SingleAttestation>,
        subnet_id: u64,
    },
    ProposerSlashing(Box<pq::ProposerSlashing>),
    AttesterSlashing(Box<pq::AttesterSlashing>),
    PayloadAttestation(Box<pq::PayloadAttestationMessage>),
    /// Carries the market because the stateful checks receive only the store.
    ExecutionPayloadBid {
        bid: Box<pq::SignedExecutionPayloadBid>,
        market: SharedPqBuilderMarket,
    },
    ProposerPreferences(Box<pq::SignedProposerPreferences>),
    Envelope(Box<pq::SignedExecutionPayloadEnvelope>),
}

impl PqValidated {
    pub(crate) fn stateful_checks(&mut self, store: &Store) -> Outcome {
        match self {
            Self::Aggregate {
                signed,
                attesting_indices,
            } => match gossip::pq::aggregate_stateful_checks(store, signed) {
                Ok(indices) => {
                    *attesting_indices = indices;
                    Outcome::Accept
                }
                Err(outcome) => outcome,
            },
            Self::Attestation {
                attestation,
                subnet_id,
            } => gossip::pq::attestation_stateful_checks(store, attestation, *subnet_id),
            Self::ProposerSlashing(slashing) => {
                gossip::pq::proposer_slashing_stateful_checks(store, slashing)
            }
            Self::AttesterSlashing(slashing) => {
                gossip::pq::attester_slashing_stateful_checks(store, slashing)
            }
            Self::PayloadAttestation(message) => {
                gossip::pq::payload_attestation_stateful_checks(store, message)
            }
            Self::ExecutionPayloadBid { bid, market } => {
                gossip::execution_payload_bid::stateful_checks(store, &**market, &**bid)
            }
            Self::ProposerPreferences(preferences) => {
                gossip::proposer_preferences::stateful_checks(store, &**preferences)
            }
            Self::Envelope(envelope) => gossip::pq::envelope_stateful_checks(store, envelope),
        }
    }

    /// Record this message as the first valid one for its key, in the seen
    /// caches the other forks' messages of its topic share. `false` when
    /// another verdict recorded one first.
    pub(crate) fn record_seen(&self, server: &mut P2PServer) -> bool {
        match self {
            Self::Aggregate { signed, .. } => {
                let Some(key) = gossip::pq::aggregate_key(signed) else {
                    return false;
                };
                let bits = gossip::pq::aggregation_bits(signed);
                server.seen_aggregates.record_parts(&key, &bits)
            }
            Self::Attestation { attestation, .. } => server
                .seen_attestations
                .record_key(attestation.data.target.epoch, attestation.attester_index),
            Self::ProposerSlashing(slashing) => server
                .seen_operations
                .record_proposer_slashing(slashing.signed_header_1.message.proposer_index),
            Self::AttesterSlashing(slashing) => server
                .seen_operations
                .record_attester_slashing(&gossip::pq::slashed_indices(slashing)),
            Self::PayloadAttestation(message) => server
                .seen_payload_attestations
                .record(message.data.slot, message.validator_index),
            Self::ExecutionPayloadBid { bid, .. } => {
                server.pq_builder_market.record_bid((**bid).clone())
            }
            Self::ProposerPreferences(preferences) => server
                .pq_builder_market
                .record_preferences((**preferences).clone(), wall_slot(server)),
            Self::Envelope(envelope) => {
                let recorded = server.seen_envelopes.record(
                    envelope.message.beacon_block_root,
                    envelope.message.builder_index,
                );
                if recorded {
                    // A PQ bid's parent payload is known once its envelope
                    // passed gossip, as a gloas bid's is.
                    server
                        .pq_builder_market
                        .record_pq_execution_payload(&envelope.message);
                }
                recorded
            }
        }
    }

    /// Hand the parts fork choice reads to the chain actor, given the gossip
    /// `outcome`: an aggregate's vote and a payload attestation only when
    /// accepted, an envelope also when queued (the actor holds one whose block
    /// it has not imported). Subnet attestations, slashings, bids and
    /// preferences stop at relay, as gloas's do.
    pub(crate) fn forward(self, server: &P2PServer, received_at: StdInstant, outcome: Outcome) {
        if let Self::Aggregate {
            signed,
            attesting_indices,
        } = &self
            && outcome == Outcome::Accept
        {
            pool_aggregate(&server.store, signed, attesting_indices);
        }
        if let Self::Attestation { attestation, .. } = &self
            && outcome == Outcome::Accept
            && let Some(wire) = server.wire.beacon()
        {
            let now = crate::gossipsub::beacon_wall_slot(wire);
            server.store.pq_signature_pool().insert(now, attestation);
        }
        let Some(blockchain) = &server.blockchain else {
            return;
        };
        match self {
            Self::Aggregate {
                signed,
                attesting_indices,
            } if outcome == Outcome::Accept => {
                let arrival = AggregateArrival {
                    decode_start: received_at,
                    handed_off: StdInstant::now(),
                };
                let data = signed.message.aggregate.data;
                let _ = blockchain
                    .new_pq_aggregate(data, attesting_indices, arrival)
                    .inspect_err(|err| warn!(%err, "Failed to forward a PQ aggregate"));
            }
            Self::PayloadAttestation(message) if outcome == Outcome::Accept => {
                let arrival = BlockArrival {
                    decode_start: Some(received_at),
                    handed_off: StdInstant::now(),
                    deferred_from: None,
                };
                let _ = blockchain
                    .new_pq_payload_attestation_message(message, arrival)
                    .inspect_err(|err| warn!(%err, "Failed to forward a PQ payload attestation"));
            }
            Self::Envelope(envelope) if matches!(outcome, Outcome::Accept | Outcome::Queue(_)) => {
                let arrival = BlockArrival {
                    decode_start: Some(received_at),
                    handed_off: StdInstant::now(),
                    deferred_from: None,
                };
                let envelope = Box::new(SignedExecutionPayloadEnvelope::Pq(envelope));
                let _ = blockchain
                    .new_execution_payload_envelope(envelope, arrival)
                    .inspect_err(|err| warn!(%err, "Failed to forward a PQ envelope"));
            }
            _ => {}
        }
    }

    /// The permit pool its stateful checks draw from, as the matching gloas
    /// object's does.
    pub(crate) fn pool(&self) -> &'static str {
        match self {
            Self::Envelope(_) => "gossip",
            Self::Aggregate { .. }
            | Self::Attestation { .. }
            | Self::PayloadAttestation(_)
            | Self::ProposerSlashing(_)
            | Self::AttesterSlashing(_) => "attestation",
            Self::ExecutionPayloadBid { .. } | Self::ProposerPreferences(_) => "builder",
        }
    }
}

/// Hold an accepted aggregate for block production, which merges the proofs
/// of the ones it packs (PQ `validator.md`, "Proof").
fn pool_aggregate(
    store: &Store,
    signed: &pq::SignedAggregateAndProof,
    attesting_indices: &[ValidatorIndex],
) {
    let aggregate = &signed.message.aggregate;
    let committees = get_committee_indices(&aggregate.committee_bits);
    // Gossip validation accepts single-committee aggregates only.
    let [committee_index] = committees[..] else {
        return;
    };
    store.pq_aggregate_pool().insert(PooledPqAggregate {
        attestation: aggregate.clone(),
        committee_index,
        attesting_indices: attesting_indices.to_vec(),
        proof: signed.message.proof.clone(),
    });
}

/// Decode a message from a PQ digest's topic `kind` and run its cheap rules,
/// or `None` when `kind` is not one whose container PQ reshapes (a block or a
/// data column sidecar), which the shared path takes.
///
/// A message that does not decode is ignored rather than rejected, as on
/// every topic of a fork this node does not follow: its containers are
/// modelled from a moving specification branch, and a peer must not be
/// scored down for this build's gap.
pub(crate) fn triage(
    server: &P2PServer,
    kind: &str,
    payload: &[u8],
    received_at: Instant,
) -> Option<Dispatch> {
    if !beacon_decode::is_pq_reshaped(kind) {
        return None;
    }
    let metric_kind = beacon_topics::metric_kind(kind).unwrap_or(kind);
    let decoded = match beacon_decode::decode_pq_gossip(kind, payload) {
        Ok(decoded) => decoded,
        Err(err) => {
            metrics::inc_beacon_gossip(metric_kind, "unsupported_fork");
            debug!(kind, %err, bytes = payload.len(), "PQ gossip decode failed");
            return Some(Dispatch::Report(Outcome::Ignore(
                IgnoreReason::UnsupportedFork,
            )));
        }
    };
    metrics::inc_beacon_gossip(metric_kind, "decoded");
    trace!(
        kind,
        bytes = payload.len(),
        elapsed_ms = received_at.elapsed().as_millis() as u64,
        "PQ gossip decoded"
    );
    let now_ms = unix_now_ms();
    let store = &server.store;
    let cheap = match &decoded {
        PqGossip::Aggregate(signed) => {
            gossip::pq::aggregate_cheap_checks(&server.seen_aggregates, store, signed, now_ms)
        }
        PqGossip::Attestation(attestation) => gossip::pq::attestation_cheap_checks(
            &server.seen_attestations,
            store,
            attestation,
            now_ms,
        ),
        PqGossip::ProposerSlashing(slashing) => {
            gossip::pq::proposer_slashing_cheap_checks(&server.seen_operations, slashing)
        }
        PqGossip::AttesterSlashing(slashing) => {
            gossip::pq::attester_slashing_cheap_checks(&server.seen_operations, slashing)
        }
        PqGossip::PayloadAttestation(message) => gossip::pq::payload_attestation_cheap_checks(
            &server.seen_payload_attestations,
            store,
            message,
            now_ms,
        ),
        PqGossip::ExecutionPayloadBid(bid) => gossip::execution_payload_bid::cheap_checks(
            &*server.pq_builder_market,
            store,
            &**bid,
            now_ms,
        ),
        PqGossip::ProposerPreferences(preferences) => gossip::proposer_preferences::cheap_checks(
            &*server.pq_builder_market,
            store,
            &**preferences,
            now_ms,
        ),
        PqGossip::Envelope(envelope) => {
            gossip::pq::envelope_cheap_checks(&server.seen_envelopes, store, envelope)
        }
    };
    if let Err(outcome) = cheap {
        return Some(Dispatch::Report(outcome));
    }
    let object = match decoded {
        PqGossip::Aggregate(signed) => PqValidated::Aggregate {
            signed,
            attesting_indices: Vec::new(),
        },
        PqGossip::Attestation(attestation) => {
            let subnet_id = beacon_topics::attestation_subnet(kind)
                .expect("decode_pq_gossip decodes an attestation only off a subnet topic");
            PqValidated::Attestation {
                attestation,
                subnet_id,
            }
        }
        PqGossip::ProposerSlashing(slashing) => PqValidated::ProposerSlashing(slashing),
        PqGossip::AttesterSlashing(slashing) => PqValidated::AttesterSlashing(slashing),
        PqGossip::PayloadAttestation(message) => PqValidated::PayloadAttestation(message),
        PqGossip::ExecutionPayloadBid(bid) => PqValidated::ExecutionPayloadBid {
            bid,
            market: server.pq_builder_market.clone(),
        },
        PqGossip::ProposerPreferences(preferences) => PqValidated::ProposerPreferences(preferences),
        PqGossip::Envelope(envelope) => PqValidated::Envelope(envelope),
    };
    Some(Dispatch::Validate(Validated::Pq(Box::new(object))))
}

/// Gossip one of a validator client's PQ messages, which the Beacon API
/// validated with PQ's gossip rules, on its topic under the digest of its
/// slot, record it in the seen caches gossip validation reads, and hand the
/// chain actor what fork choice takes: gossip never delivers a node its own
/// messages.
pub(crate) fn publish_pq_gossip(
    server: &mut P2PServer,
    object: ethlambda_network_api::PqGossipObject,
) {
    use ethlambda_network_api::PqGossipObject;
    use libp2p::gossipsub::IdentTopic;
    use libssz::SszEncode as _;

    let slot = match &object {
        PqGossipObject::Attestation { attestation, .. } => attestation.data.slot,
        PqGossipObject::Aggregate { aggregate, .. } => aggregate.message.aggregate.data.slot,
        PqGossipObject::PayloadAttestation(message) => message.data.slot,
    };
    let Some(beacon) = server.wire.beacon() else {
        warn!(slot, "A PQ message reached a lean node; dropping it");
        return;
    };
    let Some(digest) = beacon.publish_digest(slot) else {
        warn!(
            slot,
            "No held fork digest covers this PQ message's slot; not publishing"
        );
        return;
    };
    let (topic, bytes) = match &object {
        PqGossipObject::Attestation {
            subnet_id,
            attestation,
        } => {
            server
                .seen_attestations
                .record_key(attestation.data.target.epoch, attestation.attester_index);
            (
                beacon_topics::attestation_topic_name(digest, *subnet_id),
                attestation.to_ssz(),
            )
        }
        PqGossipObject::Aggregate {
            aggregate,
            attesting_indices,
        } => {
            // Gossip never hands a node its own aggregate back.
            pool_aggregate(&server.store, aggregate, attesting_indices);
            if let Some(key) = gossip::pq::aggregate_key(aggregate) {
                let bits = gossip::pq::aggregation_bits(aggregate);
                server.seen_aggregates.record_parts(&key, &bits);
            }
            (
                beacon_topics::topic_name(digest, beacon_topics::BEACON_AGGREGATE_AND_PROOF),
                aggregate.to_ssz(),
            )
        }
        PqGossipObject::PayloadAttestation(message) => {
            server
                .seen_payload_attestations
                .record(message.data.slot, message.validator_index);
            (
                beacon_topics::topic_name(digest, beacon_topics::PAYLOAD_ATTESTATION_MESSAGE),
                message.to_ssz(),
            )
        }
    };
    server.swarm_handle.publish(
        IdentTopic::new(topic),
        crate::gossipsub::compress_message(&bytes),
    );
    debug!(slot, "Published a validator client's PQ message");

    let Some(blockchain) = server.blockchain.clone() else {
        return;
    };
    match object {
        PqGossipObject::Attestation { .. } => {}
        PqGossipObject::Aggregate {
            aggregate,
            attesting_indices,
        } => {
            let arrival = AggregateArrival {
                decode_start: StdInstant::now(),
                handed_off: StdInstant::now(),
            };
            let _ = blockchain
                .new_pq_aggregate(aggregate.message.aggregate.data, attesting_indices, arrival)
                .inspect_err(|err| warn!(%err, "Failed to hand over a published PQ aggregate"));
        }
        PqGossipObject::PayloadAttestation(message) => {
            let _ = blockchain
                .new_pq_payload_attestation_message(message, BlockArrival::now())
                .inspect_err(
                    |err| warn!(%err, "Failed to hand over a published PQ payload attestation"),
                );
        }
    }
}

#[cfg(test)]
mod tests {
    use ethlambda_state_transition::beacon::gossip::RejectReason;
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::containers::shared::BeaconBlockHeader;
    use ethlambda_types::beacon::fork::ForkName;
    use libssz::SszEncode as _;

    use super::*;
    use crate::test_support::unconnected_beacon_server;

    fn config() -> Config {
        Config::mainnet()
            .with_fork_epoch(ForkName::Gloas, 0)
            .with_fork_epoch(ForkName::Eip8483, 0)
            .with_fork_epoch(ForkName::Pq, 0)
    }

    fn triage_now(server: &P2PServer, kind: &str, payload: &[u8]) -> Option<Dispatch> {
        triage(server, kind, payload, Instant::now())
    }

    /// A message this build cannot decode under a PQ digest is this build's
    /// gap, as on every topic of a fork the node does not follow: ignored,
    /// so no peer is scored down for it.
    #[tokio::test]
    async fn an_undecodable_pq_message_is_ignored_not_rejected() {
        let server = unconnected_beacon_server(config(), 0).await;
        let dispatch = triage_now(
            &server,
            beacon_topics::BEACON_AGGREGATE_AND_PROOF,
            &[0xff; 9],
        );
        assert!(matches!(
            dispatch,
            Some(Dispatch::Report(Outcome::Ignore(
                IgnoreReason::UnsupportedFork
            )))
        ));
    }

    /// A block or a column takes the shared path under a PQ digest too.
    #[tokio::test]
    async fn a_pq_digests_block_topic_is_not_triaged_here() {
        let server = unconnected_beacon_server(config(), 0).await;
        assert!(triage_now(&server, beacon_topics::BEACON_BLOCK, &[]).is_none());
    }

    /// A slashing that passes the cheap rules goes on to the stateful ones as
    /// a PQ object; one whose headers do not match is rejected inline.
    #[tokio::test]
    async fn a_pq_proposer_slashing_is_judged_as_pq() {
        let server = unconnected_beacon_server(config(), 0).await;
        let header = |state_root| pq::SignedBeaconBlockHeader {
            message: BeaconBlockHeader {
                slot: 5,
                proposer_index: 2,
                state_root,
                ..Default::default()
            },
            signature: Default::default(),
        };
        let slashing = pq::ProposerSlashing {
            signed_header_1: header(ethlambda_types::beacon::primitives::Root::repeat_byte(1)),
            signed_header_2: header(ethlambda_types::beacon::primitives::Root::repeat_byte(2)),
        };
        let dispatch = triage_now(
            &server,
            beacon_topics::PROPOSER_SLASHING,
            &slashing.to_ssz(),
        );
        assert!(matches!(
            dispatch,
            Some(Dispatch::Validate(Validated::Pq(ref object)))
                if matches!(**object, PqValidated::ProposerSlashing(_))
        ));

        let same = pq::ProposerSlashing {
            signed_header_1: slashing.signed_header_1.clone(),
            signed_header_2: slashing.signed_header_1,
        };
        assert!(matches!(
            triage_now(&server, beacon_topics::PROPOSER_SLASHING, &same.to_ssz()),
            Some(Dispatch::Report(Outcome::Reject(
                RejectReason::InvalidOperation
            )))
        ));
    }

    /// The PQ node does not follow PQ, so its head state is not a PQ one: a
    /// slashing that reaches the stateful rules is ignored.
    #[tokio::test]
    async fn a_pq_slashing_against_a_non_pq_head_is_ignored() {
        let server = unconnected_beacon_server(config(), 0).await;
        let mut object = PqValidated::ProposerSlashing(Box::default());
        assert_eq!(
            object.stateful_checks(&server.store),
            Outcome::Ignore(IgnoreReason::StateUnavailable)
        );
    }
}
