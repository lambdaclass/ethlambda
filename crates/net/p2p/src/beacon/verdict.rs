//! The verdict plumbing between gossipsub and the beacon gossip rules.
//!
//! The rules live in `ethlambda_state_transition::beacon::gossip`; this module
//! decides where each half runs and what happens to the result. Cheap checks
//! run inline in the p2p actor. Stateful checks run on a `spawn_blocking`
//! thread, bounded by one of two pools depending on the kind: a block or a
//! column draws from [`P2PServer::gossip_validation_permits`], an aggregate or
//! a subnet attestation from [`P2PServer::attestation_validation_permits`] (see
//! that field's own documentation for why they must not share one). Either way
//! the blocking task sends a [`GossipVerdict`] back to the actor. Every beacon
//! gossip message ends in exactly one [`report`]: gossipsub holds each one
//! until then.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;

use ethlambda_network_api::{AggregateArrival, BlockAnnouncement, BlockArrival, BlockSource};
use ethlambda_state_transition::beacon::gossip::{self, IgnoreReason, Outcome};
use ethlambda_state_transition::beacon::helpers::accessors::CommitteeCacheExt as _;
use ethlambda_storage::{CacheKey, Store};
use ethlambda_types::beacon::containers::electra::{self, SingleAttestation};
use ethlambda_types::beacon::containers::gloas::{
    PayloadAttestationMessage, SignedExecutionPayloadEnvelope,
};
use ethlambda_types::beacon::containers::{
    DataColumnSidecar, SignedAggregateAndProof, SignedBeaconBlock,
};
use ethlambda_types::beacon::operation::BeaconOperation;
use ethlambda_types::beacon::primitives::{Root, ValidatorIndex};
use libp2p::PeerId;
use libp2p::gossipsub::{MessageAcceptance, MessageId};
use spawned_concurrency::message::Message;
use spawned_concurrency::tasks::{Context, Handler};
use tracing::{debug, error, warn};

use crate::beacon::column_checks;
use crate::gossipsub::operation_kind;
use crate::{P2PServer, metrics};

/// Which gossip message a verdict is for.
pub(crate) struct GossipId {
    pub(crate) message_id: MessageId,
    pub(crate) propagation_source: PeerId,
    /// The payload came off the wire, before decompression.
    pub(crate) received_at: Instant,
    /// The topic kind, as a metric label. See [`crate::beacon::topics::metric_kind`].
    pub(crate) kind: &'static str,
}

/// An object whose stateful checks run on a blocking thread.
pub(crate) enum Validated {
    Block {
        // Boxed for the reason `BeaconGossip::Block` is (see `beacon::decode`):
        // unboxed, a `SignedBeaconBlock` would set the size of every `Validated`
        // this module moves through a channel and a `spawn_blocking` closure.
        block: Box<SignedBeaconBlock>,
        block_root: Root,
    },
    // Boxed for the same reason `block` is: `DataColumnSidecar` carries a KZG
    // commitment and proof list plus a full cell, wide enough on its own to
    // set the enum's size.
    Column(Box<DataColumnSidecar>),
    /// A `beacon_aggregate_and_proof`.
    Aggregate {
        aggregate: Box<SignedAggregateAndProof>,
        /// The attesting indices its aggregate signature verified. Empty
        /// until [`Validated::stateful_checks`] fills it in on `Accept`;
        /// [`Validated::forward`] is what reads it, and only ever on that
        /// outcome, so an empty value here is never mistaken for a verified
        /// one.
        attesting_indices: Vec<ValidatorIndex>,
    },
    /// A `beacon_attestation_{subnet_id}`. Never forwarded to the chain actor
    /// (see [`Validated::forward`]'s doc comment), so nothing beyond the
    /// verdict and the seen cache is kept once its checks have run.
    Attestation {
        attestation: Box<SingleAttestation>,
        subnet_id: u64,
    },
    /// A gloas `execution_payload`. Boxed for the reason `Block` is: it
    /// carries a whole execution payload.
    Envelope(Box<SignedExecutionPayloadEnvelope>),
    /// A gloas `payload_attestation_message`.
    PayloadAttestation(PayloadAttestationMessage),
    /// One of the four operation topics. Boxed like the other wide payloads.
    Operation(Box<BeaconOperation>),
}

impl Validated {
    /// Run this object's stateful checks. `&mut self` rather than `&self`:
    /// [`Self::Aggregate`]'s `attesting_indices` starts empty and is filled in
    /// here on `Accept`, the one place its aggregate signature is checked and
    /// its attesting indices resolved, so [`Validated::forward`] finds them
    /// already in hand rather than having to re-verify the aggregate to learn
    /// them.
    fn stateful_checks(&mut self, store: &Store) -> Outcome {
        match self {
            Self::Block { block, block_root } => {
                gossip::block::stateful_checks(store, block, *block_root)
            }
            Self::Column(sidecar) => match &**sidecar {
                DataColumnSidecar::Fulu(sidecar) => gossip::column::stateful_checks(store, sidecar),
                DataColumnSidecar::Gloas(sidecar) => {
                    gossip::column::stateful_checks_gloas(store, sidecar)
                }
            },
            Self::Aggregate {
                aggregate,
                attesting_indices,
            } => match gossip::aggregate::stateful_checks(store, aggregate) {
                Ok(indices) => {
                    *attesting_indices = indices;
                    Outcome::Accept
                }
                Err(outcome) => outcome,
            },
            Self::Attestation {
                attestation,
                subnet_id,
            } => gossip::attestation::stateful_checks(store, attestation, *subnet_id),
            Self::Envelope(envelope) => gossip::envelope::stateful_checks(store, envelope),
            Self::PayloadAttestation(message) => {
                gossip::payload_attestation::stateful_checks(store, message)
            }
            Self::Operation(operation) => gossip::operations::stateful_checks(store, operation),
        }
    }

    /// Record this object as the first valid one for its key. `false` when
    /// another verdict recorded one first.
    fn record_seen(&self, server: &mut P2PServer) -> bool {
        match self {
            Self::Block { block, block_root } => {
                server
                    .seen_blocks
                    .record(block.slot(), block.proposer_index(), *block_root)
            }
            Self::Column(sidecar) => match &**sidecar {
                DataColumnSidecar::Fulu(sidecar) => {
                    let header = &sidecar.signed_block_header.message;
                    server
                        .seen_columns
                        .record(header.slot, header.proposer_index, sidecar.index)
                }
                DataColumnSidecar::Gloas(sidecar) => server
                    .seen_block_columns
                    .record(sidecar.beacon_block_root, sidecar.index),
            },
            Self::Aggregate { aggregate, .. } => server.seen_aggregates.record(aggregate),
            Self::Attestation { attestation, .. } => server.seen_attestations.record(attestation),
            Self::Envelope(envelope) => server.seen_envelopes.record(
                envelope.message.beacon_block_root,
                envelope.message.builder_index,
            ),
            Self::PayloadAttestation(message) => server
                .seen_payload_attestations
                .record(message.data.slot, message.validator_index),
            Self::Operation(operation) => server.seen_operations.record(operation),
        }
    }

    /// Hand this object on towards the chain actor, given its gossip
    /// `outcome`.
    ///
    /// A block goes straight to the chain actor whatever the outcome, since
    /// its import runs the state transition, which judges it again. A column
    /// goes straight there only on `Accept`: the chain actor keeps a column
    /// without checking it, so one gossip did not finish judging goes through
    /// [`column_checks`] first. An aggregate goes on only on `Accept`, and
    /// carries the attesting indices [`Self::stateful_checks`] resolved: the
    /// chain actor no longer verifies anything on this topic (see reviewer
    /// finding #1 on PR #19), so an aggregate that never got a real `Accept`
    /// (`Overloaded`, `Ignore`, `Reject`) must never reach it. A subnet
    /// attestation is never forwarded at all, on any outcome: nothing on the
    /// chain actor consumes one, matching a lighthouse follower with no
    /// validators, which verifies and relays its own backbone subnets but
    /// never calls `apply_attestation_to_fork_choice` for them either.
    ///
    /// An envelope goes on when accepted, and also when queued: the chain
    /// actor holds an envelope whose block it has not imported yet, which is
    /// exactly what `Queue` means, and its own checks judge it again once the
    /// block is there; a queued one has not had its signature checked, so the
    /// actor checks it before it parks one. Any other outcome keeps it away. A
    /// payload attestation goes on only when accepted: it is only valid within
    /// its own slot, and the specification makes queueing one optional.
    ///
    /// What an accepted subnet attestation does feed is the attestation pool,
    /// when its subnet is one a validator client's aggregator had this node
    /// join: that aggregator will ask for exactly these votes. See
    /// [`pool_aggregator_attestation`]. An accepted aggregate goes into the
    /// pool too, whatever else happens to it, so block production can pack
    /// other nodes' votes; see [`pool_gossip_aggregate`].
    ///
    /// Every accepted aggregate or subnet attestation also marks the
    /// validators it names as live for its target epoch; see
    /// [`record_liveness`].
    fn forward(self, server: &P2PServer, received_at: Instant, outcome: Outcome) {
        if outcome == Outcome::Accept {
            record_liveness(server, &self);
        }
        if let Self::Aggregate { aggregate, .. } = &self
            && outcome == Outcome::Accept
        {
            pool_gossip_aggregate(server, aggregate);
        }
        if let Self::Attestation {
            attestation,
            subnet_id,
        } = &self
            && outcome == Outcome::Accept
            && server.aggregator_subnets.contains_key(subnet_id)
        {
            pool_aggregator_attestation(server, attestation);
        }
        if let Self::Operation(operation) = &self {
            // Only an accepted operation is pooled; the chain actor consumes
            // nothing on these topics, so nothing is forwarded to it.
            if outcome == Outcome::Accept {
                let kind = operation_kind(operation);
                let inserted = server.store.operation_pool().insert((**operation).clone());
                debug!(kind, inserted, "Pooled a gossip operation");
            }
            return;
        }
        if let Self::PayloadAttestation(message) = &self
            && outcome == Outcome::Accept
        {
            // Block production packs these, and a node with no chain actor
            // attached still serves `GET .../pool/payload_attestations`.
            server
                .payload_attestation_pool
                .lock()
                .expect("payload attestation pool lock")
                .insert(message.clone());
        }
        let Some(blockchain) = &server.blockchain else {
            return;
        };
        match self {
            Self::Block { block, .. } => {
                // `decode_start` is the wire arrival, so the import's decode
                // section spans the decode and gossip validation.
                let arrival = BlockArrival {
                    decode_start: Some(received_at),
                    handed_off: Instant::now(),
                    deferred_from: None,
                };
                // Only a block that passed validation is announced: one
                // forwarded on `Queue` or `Ignore(Overloaded)` still imports,
                // but `block_gossip` names blocks that passed the topic's
                // rules.
                let announcement = if outcome == Outcome::Accept {
                    BlockAnnouncement::Announce
                } else {
                    BlockAnnouncement::Silent
                };
                let _ = blockchain
                    .new_block(*block, BlockSource::Gossip, arrival, announcement)
                    .inspect_err(|err| warn!(%err, "Failed to forward a gossip block"));
            }
            Self::Column(sidecar) if outcome == Outcome::Accept => {
                let _ = blockchain
                    .new_data_column_sidecars(vec![*sidecar])
                    .inspect_err(|err| warn!(%err, "Failed to forward a data column sidecar"));
            }
            Self::Column(sidecar) => column_checks::check_and_forward(server, vec![*sidecar]),
            Self::Aggregate {
                aggregate,
                attesting_indices,
            } if outcome == Outcome::Accept => {
                let arrival = AggregateArrival {
                    decode_start: received_at,
                    handed_off: Instant::now(),
                };
                let _ = blockchain
                    .new_beacon_aggregate(aggregate, attesting_indices, arrival)
                    .inspect_err(|err| warn!(%err, "Failed to forward a gossip aggregate"));
            }
            Self::Envelope(envelope) if matches!(outcome, Outcome::Accept | Outcome::Queue(_)) => {
                let arrival = BlockArrival {
                    decode_start: Some(received_at),
                    handed_off: Instant::now(),
                    deferred_from: None,
                };
                let _ = blockchain
                    .new_execution_payload_envelope(envelope, arrival)
                    .inspect_err(|err| warn!(%err, "Failed to forward a gossip envelope"));
            }
            Self::PayloadAttestation(message) if outcome == Outcome::Accept => {
                let arrival = BlockArrival {
                    decode_start: Some(received_at),
                    handed_off: Instant::now(),
                    deferred_from: None,
                };
                let _ = blockchain
                    .new_payload_attestation_message(message, arrival)
                    .inspect_err(|err| warn!(%err, "Failed to forward a payload attestation"));
            }
            Self::Aggregate { .. }
            | Self::Attestation { .. }
            | Self::Envelope(_)
            | Self::PayloadAttestation(_)
            | Self::Operation(_) => {}
        }
    }
}

/// Mark the validators an accepted aggregate or subnet attestation names as
/// live for its target epoch, for `/eth/v1/validator/liveness`.
///
/// An aggregate names its aggregator and every attester its aggregate
/// signature verified, which is what makes an aggregate worth more here than
/// the attestation subnets alone: this node joins only a few of those. A
/// block's proposer is recorded where the chain actor imports it instead, so
/// a block that reached it by range sync or through this node's own API
/// counts too.
fn record_liveness(server: &P2PServer, object: &Validated) {
    let observed = server.store.observed_liveness();
    match object {
        Validated::Aggregate {
            aggregate,
            attesting_indices,
        } => {
            let (epoch, _root) = aggregate.target();
            let aggregator = std::iter::once(aggregate.aggregator_index());
            observed.record_all(epoch, aggregator.chain(attesting_indices.iter().copied()));
        }
        Validated::Attestation { attestation, .. } => {
            observed.record(attestation.data.target.epoch, attestation.attester_index);
        }
        Validated::Block { .. }
        | Validated::Column(_)
        | Validated::Envelope(_)
        | Validated::PayloadAttestation(_)
        | Validated::Operation(_) => {}
    }
}

/// Pool an accepted gossip aggregate for block production to pack.
///
/// Pooled here, on `Accept`, because this is where all three of its
/// signatures have just been verified, and one unverified attestation in a
/// block fails the whole block. Pooling on arrival also means a slot's
/// aggregates, published two thirds of the way through it, are in the pool
/// when the next slot's block is asked for at its start, rather than
/// waiting for the chain actor's next tick. The pool holds electra's shape, so
/// a gloas aggregate is converted to it first.
fn pool_gossip_aggregate(server: &P2PServer, aggregate: &SignedAggregateAndProof) {
    let pooled = match aggregate {
        SignedAggregateAndProof::Electra(signed) => signed.message.aggregate.clone(),
        // Gloas's aggregate converts to the pool's electra shape; the bits
        // only fail to fit electra's bound for a size no committee reaches.
        SignedAggregateAndProof::Gloas(signed) => {
            let Ok(converted) = electra::Attestation::try_from(&signed.message.aggregate) else {
                return;
            };
            converted
        }
        SignedAggregateAndProof::Phase0(_) => return,
    };
    server.store.attestation_pool().insert_aggregate(pooled);
}

/// Pool an accepted subnet attestation for a validator client's aggregator.
///
/// The pool keys a vote by its position in its committee, which the gossip
/// checks resolved but do not return; it is read back from the same place
/// they read it, the voted block's cached post-state and the shared committee
/// cache, so nothing is derived twice.
fn pool_aggregator_attestation(server: &P2PServer, attestation: &SingleAttestation) {
    let data = &attestation.data;
    let Some(state) = server
        .store
        .cached_state(CacheKey::BlockState(data.beacon_block_root))
    else {
        return;
    };
    let committees = server
        .store
        .committee_cache()
        .committees(&state, data.target.epoch);
    let Ok(committee) = committees.committee(data.slot, attestation.committee_index) else {
        return;
    };
    let Some(position) = committee
        .iter()
        .position(|&member| member == attestation.attester_index)
    else {
        return;
    };
    server
        .store
        .attestation_pool()
        .insert(attestation, position, committee.len());
}

/// What to do with a beacon gossip message once the checks that read only the
/// message, the clock and the store's metadata (the `triage_*` functions in
/// [`crate::gossipsub::handler`]) have run.
///
/// Splits the decision from the action: a `triage_*` function decides and
/// returns one of these, and [`crate::gossipsub::handler::handle_beacon_gossip`]
/// is the single place that acts on it, reporting or spawning. That split is
/// what makes `triage_*` unit-testable with no actor in sight: a
/// `Context<P2PServer>` only exists once the actor has started, and deciding a
/// verdict needs no context at all.
pub(crate) enum Dispatch {
    /// A verdict is already known; nothing further to check.
    ///
    /// No cheap check ever answers `Queue`: a `Queue` verdict means "hold the
    /// object until its dependency arrives", which is a stateful check's call
    /// to make on the decoded object, not a cheap one's. `handle_beacon_gossip`'s
    /// `debug_assert!` enforces this invariant in debug builds rather than
    /// widening this variant to carry an object for a case that cannot happen;
    /// in release, a `Queue` reaching here would still be reported as IGNORE,
    /// with nothing forwarded, since this variant carries no object to
    /// forward it with.
    Report(Outcome),
    /// The object passed the cheap checks; its stateful checks decide.
    Validate(Validated),
}

/// A blocking task's verdict, sent back to the p2p actor.
pub(crate) struct GossipVerdict {
    id: GossipId,
    outcome: Outcome,
    object: Validated,
}

impl Message for GossipVerdict {
    type Result = ();
}

/// Re-check the seen cache at verdict time: two copies of one key can be in
/// validation on separate blocking threads at once, and only the first
/// `Accept` to reach the actor stands, which is the specification's "first
/// valid". Any other outcome passes through unrecorded, since only an Accept
/// is a candidate for the seen cache in the first place.
fn settle(server: &mut P2PServer, outcome: Outcome, object: &Validated) -> Outcome {
    if outcome == Outcome::Accept && !object.record_seen(server) {
        Outcome::Ignore(IgnoreReason::AlreadySeen)
    } else {
        outcome
    }
}

impl Handler<GossipVerdict> for P2PServer {
    async fn handle(&mut self, msg: GossipVerdict, _ctx: &Context<Self>) {
        let GossipVerdict {
            id,
            outcome,
            object,
        } = msg;
        let outcome = settle(self, outcome, &object);
        let received_at = id.received_at;
        if report(self, id, outcome) {
            object.forward(self, received_at, outcome);
        }
    }
}

/// How an outcome maps onto gossipsub, and whether the object still goes on
/// towards the chain actor (see [`Validated::forward`] for the route).
pub(crate) fn disposition(outcome: Outcome) -> (MessageAcceptance, bool) {
    match outcome {
        Outcome::Accept => (MessageAcceptance::Accept, true),
        Outcome::Queue(_) => (MessageAcceptance::Ignore, true),
        Outcome::Ignore(_) => (MessageAcceptance::Ignore, false),
        Outcome::Reject(_) => (MessageAcceptance::Reject, false),
    }
}

/// Report `outcome` for `id` to gossipsub and the metrics. Returns whether
/// the object goes on towards the chain actor.
pub(crate) fn report(server: &P2PServer, id: GossipId, outcome: Outcome) -> bool {
    let (acceptance, forward) = disposition(outcome);
    let (outcome_label, reason) = outcome.labels();
    metrics::observe_beacon_gossip_verdict(
        id.kind,
        outcome_label,
        reason,
        id.received_at.elapsed(),
    );
    server.swarm_handle.report_validation(
        id.message_id,
        id.propagation_source,
        acceptance,
        id.kind,
    );
    forward
}

/// The permit pool `object`'s stateful checks draw from: blocks, columns and
/// envelopes from the gossip pool, everything the attesters send (and the
/// operation topics) from the attestation pool, so neither burst starves the
/// other.
fn permits_for<'a>(
    server: &'a P2PServer,
    object: &Validated,
) -> &'a std::sync::Arc<tokio::sync::Semaphore> {
    match object {
        Validated::Block { .. } | Validated::Column(_) | Validated::Envelope(_) => {
            &server.gossip_validation_permits
        }
        Validated::Aggregate { .. }
        | Validated::Attestation { .. }
        | Validated::PayloadAttestation(_)
        | Validated::Operation(_) => &server.attestation_validation_permits,
    }
}

/// Run `object`'s stateful checks on a blocking thread. The verdict comes back
/// to the actor as a [`GossipVerdict`].
///
/// A block or a column draws its permit from
/// [`P2PServer::gossip_validation_permits`]; an aggregate or a subnet
/// attestation from [`P2PServer::attestation_validation_permits`], a pool of
/// its own so neither topic's per-slot burst can starve the other (see that
/// field's documentation).
///
/// With every permit taken, the object is reported `Ignore(Overloaded)`
/// instead of queued: queueing it would only make its verdict later than
/// gossipsub's cache can wait for, so it never propagates unvalidated. A block
/// still goes on towards the chain actor regardless: its import runs the
/// state transition, which judges it again. A column goes through
/// [`column_checks`] instead (see [`Validated::forward`]); dropping either
/// here would leave the actor to learn of it only through a child's by-root
/// fetch or range sync, both far slower than gossip. An aggregate or a subnet
/// attestation is not forwarded on this outcome at all: see
/// [`Validated::forward`]'s own documentation for why.
pub(crate) fn spawn_stateful_checks(
    server: &P2PServer,
    ctx: &Context<P2PServer>,
    id: GossipId,
    object: Validated,
) {
    let Ok(permit) = permits_for(server, &object).clone().try_acquire_owned() else {
        let received_at = id.received_at;
        let outcome = Outcome::Ignore(IgnoreReason::Overloaded);
        report(server, id, outcome);
        object.forward(server, received_at, outcome);
        return;
    };
    let store = server.store.clone();
    let actor = ctx.actor_ref();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut object = object;
        let outcome = guarded(|| object.stateful_checks(&store));
        let _ = actor
            .send(GossipVerdict {
                id,
                outcome,
                object,
            })
            .inspect_err(|_| warn!("P2P actor stopped before a gossip verdict arrived"));
    });
}

/// `checks()`, with a panic turned into `Ignore(Internal)`.
///
/// A panic inside validation (a `Store` read's `.expect()` on a DB error, say)
/// must still produce a verdict, or gossipsub would hold the message until its
/// cache evicts it. The blocking thread's permit is unaffected either way: it
/// drops on unwind exactly as it would on a normal return.
pub(crate) fn guarded(checks: impl FnOnce() -> Outcome) -> Outcome {
    catch_unwind(AssertUnwindSafe(checks)).unwrap_or_else(|payload| {
        let panic_message = payload
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
            .unwrap_or("<non-string panic payload>");
        error!(
            panic_message,
            "Beacon gossip validation panicked; reporting Ignore(Internal)"
        );
        Outcome::Ignore(IgnoreReason::Internal)
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ethlambda_network_api::P2PToBlockChain;
    use ethlambda_state_transition::beacon::gossip::{QueueReason, RejectReason};
    use ethlambda_types::attestation::{SignedAggregatedAttestation, SignedAttestation};
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::containers::{
        AttestationData, Checkpoint, electra, gloas, phase0,
    };
    use spawned_concurrency::error::ActorError;

    use super::*;
    use crate::test_support::{
        RecordingChain, envelope, unconnected_beacon_server, valid_shaped_sidecar,
    };

    /// A minimal fulu block for a given `(slot, proposer)`: `settle` and
    /// `record_seen` only ever read those two fields plus the root passed
    /// alongside, so nothing else about the block's shape matters here.
    fn fulu_block(slot: u64, proposer: u64) -> SignedBeaconBlock {
        SignedBeaconBlock::Fulu(electra::SignedBeaconBlock {
            message: electra::BeaconBlock {
                slot,
                proposer_index: proposer,
                parent_root: Root::ZERO,
                state_root: Root::ZERO,
                body: electra::BeaconBlockBody::empty(),
            },
            signature: Default::default(),
        })
    }

    /// A minimal phase0 aggregate at `(slot, aggregator)`: only what
    /// `settle`/`record_seen` and `forward` read is meaningful, nothing here
    /// is signature-valid. Mirrors `beacon_aggregates`'s own test helper in
    /// `ethlambda-blockchain`.
    fn phase0_aggregate(slot: u64, aggregator: u64) -> SignedAggregateAndProof {
        SignedAggregateAndProof::Phase0(phase0::SignedAggregateAndProof {
            message: phase0::AggregateAndProof {
                aggregator_index: aggregator,
                aggregate: phase0::Attestation {
                    aggregation_bits: phase0::AggregationBits::with_length(1).unwrap(),
                    data: AttestationData {
                        slot,
                        index: 0,
                        beacon_block_root: Root::ZERO,
                        source: Checkpoint::default(),
                        target: Checkpoint {
                            epoch: slot / 32,
                            root: Root::ZERO,
                        },
                    },
                    signature: Default::default(),
                },
                selection_proof: Default::default(),
            },
            signature: Default::default(),
        })
    }

    /// A one-member electra aggregate at `(slot, aggregator)`, from committee
    /// 0. Same reasoning as [`phase0_aggregate`]: `forward` runs after the
    /// stateful checks, so nothing here needs to be signature-valid.
    fn electra_aggregate(slot: u64, aggregator: u64) -> SignedAggregateAndProof {
        let mut aggregation_bits = electra::AggregationBits::with_length(1).unwrap();
        aggregation_bits.set(0, true).unwrap();
        let mut committee_bits = electra::CommitteeBits::default();
        committee_bits.set(0, true).unwrap();
        SignedAggregateAndProof::Electra(electra::SignedAggregateAndProof {
            message: electra::AggregateAndProof {
                aggregator_index: aggregator,
                aggregate: electra::Attestation {
                    aggregation_bits,
                    data: AttestationData {
                        slot,
                        index: 0,
                        beacon_block_root: Root::ZERO,
                        source: Checkpoint::default(),
                        target: Checkpoint {
                            epoch: slot / 32,
                            root: Root::ZERO,
                        },
                    },
                    signature: Default::default(),
                    committee_bits,
                },
                selection_proof: Default::default(),
            },
            signature: Default::default(),
        })
    }

    /// A minimal electra `SingleAttestation` at `(slot, attester)`. Same
    /// reasoning as [`phase0_aggregate`].
    fn electra_attestation(slot: u64, attester: u64) -> SingleAttestation {
        SingleAttestation {
            committee_index: 0,
            attester_index: attester,
            data: AttestationData {
                slot,
                index: 0,
                beacon_block_root: Root::ZERO,
                source: Checkpoint::default(),
                target: Checkpoint {
                    epoch: slot / 32,
                    root: Root::ZERO,
                },
            },
            signature: Default::default(),
        }
    }

    #[tokio::test]
    async fn the_first_accept_for_a_block_key_stands_and_the_second_is_marked_seen() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let object = Validated::Block {
            block: Box::new(fulu_block(5, 1)),
            block_root: Root::repeat_byte(1),
        };

        assert_eq!(
            settle(&mut server, Outcome::Accept, &object),
            Outcome::Accept
        );
        assert_eq!(
            settle(&mut server, Outcome::Accept, &object),
            Outcome::Ignore(IgnoreReason::AlreadySeen)
        );
    }

    #[tokio::test]
    async fn a_queued_or_rejected_block_records_nothing() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let object = Validated::Block {
            block: Box::new(fulu_block(5, 1)),
            block_root: Root::repeat_byte(1),
        };

        assert_eq!(
            settle(
                &mut server,
                Outcome::Queue(QueueReason::ParentUnknown),
                &object
            ),
            Outcome::Queue(QueueReason::ParentUnknown)
        );
        assert_eq!(
            settle(
                &mut server,
                Outcome::Reject(RejectReason::BadSignature),
                &object
            ),
            Outcome::Reject(RejectReason::BadSignature)
        );
        // Neither the queue nor the reject recorded the key, so a later
        // Accept for it still stands.
        assert_eq!(
            settle(&mut server, Outcome::Accept, &object),
            Outcome::Accept
        );
    }

    #[tokio::test]
    async fn the_first_accept_for_a_column_key_stands_and_the_second_is_marked_seen() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let object = Validated::Column(Box::new(DataColumnSidecar::Fulu(valid_shaped_sidecar(
            5, 0,
        ))));

        assert_eq!(
            settle(&mut server, Outcome::Accept, &object),
            Outcome::Accept
        );
        assert_eq!(
            settle(&mut server, Outcome::Accept, &object),
            Outcome::Ignore(IgnoreReason::AlreadySeen)
        );
    }

    #[tokio::test]
    async fn the_first_accept_for_an_aggregate_key_stands_and_the_second_is_marked_seen() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let object = Validated::Aggregate {
            aggregate: Box::new(phase0_aggregate(5, 1)),
            attesting_indices: Vec::new(),
        };

        assert_eq!(
            settle(&mut server, Outcome::Accept, &object),
            Outcome::Accept
        );
        assert_eq!(
            settle(&mut server, Outcome::Accept, &object),
            Outcome::Ignore(IgnoreReason::AlreadySeen)
        );
    }

    #[tokio::test]
    async fn the_first_accept_for_an_attestation_key_stands_and_the_second_is_marked_seen() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let object = Validated::Attestation {
            attestation: Box::new(electra_attestation(5, 1)),
            subnet_id: 0,
        };

        assert_eq!(
            settle(&mut server, Outcome::Accept, &object),
            Outcome::Accept
        );
        assert_eq!(
            settle(&mut server, Outcome::Accept, &object),
            Outcome::Ignore(IgnoreReason::AlreadySeen)
        );
    }

    /// The condition reviewer finding #1 on PR #19 was about: an aggregate
    /// that never got a real `Accept` (here, `Overloaded`, standing in for
    /// `Ignore`/`Reject` too, since `forward`'s guard is the same `if let ...
    /// if outcome == Outcome::Accept` for all three) must never reach the
    /// chain actor.
    /// `block_gossip` names blocks that passed validation, so a block
    /// forwarded on any other verdict still imports but is not announced.
    #[tokio::test]
    async fn only_an_accepted_gossip_block_is_announced() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let chain = Arc::new(RecordingChain::default());
        server.blockchain = Some(chain.clone());
        let block = || Validated::Block {
            block: Box::new(fulu_block(5, 1)),
            block_root: Root::repeat_byte(1),
        };

        block().forward(&server, Instant::now(), Outcome::Accept);
        block().forward(
            &server,
            Instant::now(),
            Outcome::Queue(QueueReason::ParentUnknown),
        );
        block().forward(
            &server,
            Instant::now(),
            Outcome::Ignore(IgnoreReason::Overloaded),
        );

        assert_eq!(
            *chain.announcements.lock().unwrap(),
            [
                BlockAnnouncement::Announce,
                BlockAnnouncement::Silent,
                BlockAnnouncement::Silent
            ]
        );
    }

    #[tokio::test]
    async fn an_overloaded_aggregate_is_not_forwarded() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let chain = Arc::new(RecordingChain::default());
        server.blockchain = Some(chain.clone());
        let object = Validated::Aggregate {
            aggregate: Box::new(phase0_aggregate(5, 1)),
            attesting_indices: Vec::new(),
        };

        object.forward(
            &server,
            Instant::now(),
            Outcome::Ignore(IgnoreReason::Overloaded),
        );

        assert!(chain.aggregates.lock().unwrap().is_empty());
    }

    /// An accepted electra aggregate is what block production packs other
    /// nodes' votes from, so `forward` has to put it in the pool; a phase0 one
    /// has no place there, since the pool holds electra attestations.
    #[tokio::test]
    async fn an_accepted_electra_aggregate_is_pooled_and_a_phase0_one_is_not() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let forward_accepted = |aggregate| {
            Validated::Aggregate {
                aggregate: Box::new(aggregate),
                attesting_indices: Vec::new(),
            }
            .forward(&server, Instant::now(), Outcome::Accept)
        };

        forward_accepted(phase0_aggregate(5, 1));
        assert!(
            server
                .store
                .attestation_pool()
                .block_candidates()
                .is_empty()
        );

        forward_accepted(electra_aggregate(5, 1));
        let SignedAggregateAndProof::Electra(expected) = electra_aggregate(5, 1) else {
            unreachable!("built as electra")
        };
        assert_eq!(
            server.store.attestation_pool().block_candidates(),
            vec![expected.message.aggregate]
        );
    }

    /// An accepted aggregate names its aggregator and every attester its
    /// signature verified; all of them count as live for its target epoch.
    #[tokio::test]
    async fn an_accepted_aggregate_marks_its_aggregator_and_attesters_live() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let slot = 40;
        Validated::Aggregate {
            aggregate: Box::new(electra_aggregate(slot, 7)),
            attesting_indices: vec![11, 12],
        }
        .forward(&server, Instant::now(), Outcome::Accept);

        let observed = server.store.observed_liveness();
        let epoch = slot / 32;
        for validator in [7, 11, 12] {
            assert!(observed.is_live(epoch, validator), "{validator}");
        }
        assert!(!observed.is_live(epoch, 13));
    }

    #[tokio::test]
    async fn an_accepted_subnet_attestation_marks_its_attester_live() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;
        Validated::Attestation {
            attestation: Box::new(electra_attestation(40, 5)),
            subnet_id: 0,
        }
        .forward(&server, Instant::now(), Outcome::Accept);
        assert!(server.store.observed_liveness().is_live(40 / 32, 5));
    }

    /// Liveness rests on the same verdict the pool does: an object that was
    /// not accepted proves nothing about the validators it names.
    #[tokio::test]
    async fn an_object_that_was_not_accepted_marks_nobody_live() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;
        Validated::Aggregate {
            aggregate: Box::new(electra_aggregate(40, 7)),
            attesting_indices: vec![11],
        }
        .forward(
            &server,
            Instant::now(),
            Outcome::Ignore(IgnoreReason::Overloaded),
        );
        let observed = server.store.observed_liveness();
        assert!(!observed.is_live(1, 7));
        assert!(!observed.is_live(1, 11));
    }

    /// A gloas aggregate is pooled as the electra-shaped aggregate it converts
    /// to, since the pool holds electra's shape.
    #[tokio::test]
    async fn an_accepted_gloas_aggregate_is_pooled_in_the_pools_shape() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let SignedAggregateAndProof::Electra(electra_signed) = electra_aggregate(5, 1) else {
            unreachable!("built as electra")
        };
        let expected = electra_signed.message.aggregate;
        let gloas_signed = gloas::SignedAggregateAndProof {
            message: gloas::AggregateAndProof {
                aggregator_index: 1,
                aggregate: gloas::Attestation::from(&expected),
                selection_proof: Default::default(),
            },
            signature: Default::default(),
        };
        Validated::Aggregate {
            aggregate: Box::new(SignedAggregateAndProof::Gloas(gloas_signed)),
            attesting_indices: Vec::new(),
        }
        .forward(&server, Instant::now(), Outcome::Accept);
        assert_eq!(
            server.store.attestation_pool().block_candidates(),
            vec![expected]
        );
    }

    /// Only `Accept` means the signatures were verified; anything else must
    /// stay out of the pool, since one unverified attestation fails the
    /// whole block it is packed into.
    #[tokio::test]
    async fn an_aggregate_that_was_not_accepted_is_not_pooled() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;
        Validated::Aggregate {
            aggregate: Box::new(electra_aggregate(5, 1)),
            attesting_indices: Vec::new(),
        }
        .forward(
            &server,
            Instant::now(),
            Outcome::Ignore(IgnoreReason::Overloaded),
        );
        assert!(
            server
                .store
                .attestation_pool()
                .block_candidates()
                .is_empty()
        );
    }

    /// A subnet attestation is never forwarded, on any outcome, `Accept`
    /// included: see `Validated::forward`'s own documentation for why.
    #[tokio::test]
    async fn a_subnet_attestation_is_never_forwarded_even_on_accept() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let chain = Arc::new(RecordingChain::default());
        server.blockchain = Some(chain.clone());
        let object = Validated::Attestation {
            attestation: Box::new(electra_attestation(5, 1)),
            subnet_id: 0,
        };

        object.forward(&server, Instant::now(), Outcome::Accept);

        assert!(chain.aggregates.lock().unwrap().is_empty());
    }

    /// What `forward` handed the chain actor, by method.
    #[derive(Debug, PartialEq)]
    enum Sent {
        Envelope,
        PayloadAttestation,
    }

    /// A chain actor stand-in that reports only the two gloas deliveries.
    struct GloasRecorder(tokio::sync::mpsc::UnboundedSender<Sent>);

    impl P2PToBlockChain for GloasRecorder {
        fn new_block(
            &self,
            _block: SignedBeaconBlock,
            _source: BlockSource,
            _arrival: BlockArrival,
            _announcement: BlockAnnouncement,
        ) -> Result<(), ActorError> {
            Ok(())
        }
        fn new_attestation(&self, _attestation: SignedAttestation) -> Result<(), ActorError> {
            Ok(())
        }
        fn new_aggregated_attestation(
            &self,
            _attestation: SignedAggregatedAttestation,
        ) -> Result<(), ActorError> {
            Ok(())
        }
        fn new_data_column_sidecars(
            &self,
            _sidecars: Vec<DataColumnSidecar>,
        ) -> Result<(), ActorError> {
            Ok(())
        }
        fn data_column_sidecars_awaiting_parent(
            &self,
            _sidecars: Vec<DataColumnSidecar>,
        ) -> Result<(), ActorError> {
            Ok(())
        }
        fn new_beacon_aggregate(
            &self,
            _aggregate: Box<SignedAggregateAndProof>,
            _attesting_indices: Vec<ValidatorIndex>,
            _arrival: AggregateArrival,
        ) -> Result<(), ActorError> {
            Ok(())
        }
        fn new_execution_payload_envelope(
            &self,
            _envelope: Box<SignedExecutionPayloadEnvelope>,
            _arrival: BlockArrival,
        ) -> Result<(), ActorError> {
            let _ = self.0.send(Sent::Envelope);
            Ok(())
        }
        fn new_payload_attestation_message(
            &self,
            _message: PayloadAttestationMessage,
            _arrival: BlockArrival,
        ) -> Result<(), ActorError> {
            let _ = self.0.send(Sent::PayloadAttestation);
            Ok(())
        }
    }

    pub(crate) fn payload_attestation(slot: u64, validator: u64) -> PayloadAttestationMessage {
        let mut message = PayloadAttestationMessage {
            validator_index: validator,
            data: Default::default(),
            signature: Default::default(),
        };
        message.data.slot = slot;
        message
    }

    #[tokio::test]
    async fn the_first_accept_for_an_envelope_key_stands_and_the_second_is_marked_seen() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let object = Validated::Envelope(Box::new(envelope(1, 3)));

        assert_eq!(
            settle(&mut server, Outcome::Accept, &object),
            Outcome::Accept
        );
        assert_eq!(
            settle(&mut server, Outcome::Accept, &object),
            Outcome::Ignore(IgnoreReason::AlreadySeen)
        );
        // A queued envelope records nothing, so a later accept still stands.
        let other = Validated::Envelope(Box::new(envelope(2, 3)));
        assert_eq!(
            settle(
                &mut server,
                Outcome::Queue(QueueReason::BlockUnknown),
                &other
            ),
            Outcome::Queue(QueueReason::BlockUnknown)
        );
        assert_eq!(
            settle(&mut server, Outcome::Accept, &other),
            Outcome::Accept
        );
    }

    #[tokio::test]
    async fn the_first_accept_for_a_payload_attestation_key_stands_and_the_second_is_marked_seen() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let object = Validated::PayloadAttestation(payload_attestation(5, 1));

        assert_eq!(
            settle(&mut server, Outcome::Accept, &object),
            Outcome::Accept
        );
        assert_eq!(
            settle(&mut server, Outcome::Accept, &object),
            Outcome::Ignore(IgnoreReason::AlreadySeen)
        );
    }

    /// An envelope reaches the chain actor on `Accept` and on `Queue` (the
    /// actor holds it for its block), and on nothing else.
    #[tokio::test]
    async fn an_envelope_is_forwarded_on_accept_and_queue_only() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let (sender, mut received) = tokio::sync::mpsc::unbounded_channel();
        server.blockchain = Some(Arc::new(GloasRecorder(sender)));

        let forward = |outcome| {
            Validated::Envelope(Box::new(envelope(1, 3))).forward(&server, Instant::now(), outcome)
        };
        forward(Outcome::Accept);
        assert_eq!(received.try_recv(), Ok(Sent::Envelope));
        forward(Outcome::Queue(QueueReason::BlockUnknown));
        assert_eq!(received.try_recv(), Ok(Sent::Envelope));
        forward(Outcome::Ignore(IgnoreReason::Overloaded));
        forward(Outcome::Reject(RejectReason::BadSignature));
        assert!(received.try_recv().is_err());
    }

    /// A payload attestation reaches the chain actor on `Accept` alone.
    #[tokio::test]
    async fn a_payload_attestation_is_forwarded_on_accept_only() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let (sender, mut received) = tokio::sync::mpsc::unbounded_channel();
        server.blockchain = Some(Arc::new(GloasRecorder(sender)));

        let forward = |outcome| {
            Validated::PayloadAttestation(payload_attestation(5, 1)).forward(
                &server,
                Instant::now(),
                outcome,
            )
        };
        forward(Outcome::Ignore(IgnoreReason::UnknownBlock));
        forward(Outcome::Ignore(IgnoreReason::Overloaded));
        forward(Outcome::Reject(RejectReason::NotInPtc));
        assert!(received.try_recv().is_err());
        forward(Outcome::Accept);
        assert_eq!(received.try_recv(), Ok(Sent::PayloadAttestation));
    }

    /// An accepted payload attestation is pooled for block production, with
    /// or without a chain actor attached; any other outcome stays out, since
    /// one unverified share fails the aggregate it is packed into.
    #[tokio::test]
    async fn an_accepted_payload_attestation_is_pooled_and_others_are_not() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let forward = |outcome| {
            Validated::PayloadAttestation(payload_attestation(5, 1)).forward(
                &server,
                Instant::now(),
                outcome,
            )
        };
        forward(Outcome::Ignore(IgnoreReason::Overloaded));
        forward(Outcome::Reject(RejectReason::NotInPtc));
        assert!(
            server
                .payload_attestation_pool
                .lock()
                .unwrap()
                .all(None)
                .is_empty()
        );
        forward(Outcome::Accept);
        assert_eq!(
            server.payload_attestation_pool.lock().unwrap().all(None),
            vec![payload_attestation(5, 1)]
        );
    }

    /// The pool an aggregate or a subnet attestation draws its stateful-check
    /// permit from is not the pool a block or a column draws from: exhausting
    /// one must leave the other untouched, or a burst on this topic could
    /// make a block or a column answer `Ignore(Overloaded)` too.
    ///
    /// An envelope shares the block pool and a payload attestation the
    /// attestation pool, for the same reason: a slot's committee votes arrive
    /// in a burst that must not starve block validation.
    #[tokio::test]
    async fn the_block_column_and_attestation_permit_pools_are_independent() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let attestation_permits_before = server.attestation_validation_permits.available_permits();

        let same_pool = |a: &std::sync::Arc<tokio::sync::Semaphore>, b: &std::sync::Arc<_>| {
            std::sync::Arc::ptr_eq(a, b)
        };
        let envelope = Validated::Envelope(Box::new(envelope(1, 3)));
        let vote = Validated::PayloadAttestation(payload_attestation(5, 1));
        assert!(same_pool(
            permits_for(&server, &envelope),
            &server.gossip_validation_permits
        ));
        assert!(same_pool(
            permits_for(&server, &vote),
            &server.attestation_validation_permits
        ));

        let mut held = Vec::new();
        while let Ok(permit) = server.gossip_validation_permits.clone().try_acquire_owned() {
            held.push(permit);
        }
        assert_eq!(server.gossip_validation_permits.available_permits(), 0);

        assert_eq!(
            server.attestation_validation_permits.available_permits(),
            attestation_permits_before
        );
        assert!(server.attestation_validation_permits.try_acquire().is_ok());
    }

    #[test]
    fn only_accept_propagates_and_only_accept_or_queue_reaches_the_chain() {
        assert!(matches!(
            disposition(Outcome::Accept),
            (MessageAcceptance::Accept, true)
        ));
        assert!(matches!(
            disposition(Outcome::Queue(QueueReason::ParentUnknown)),
            (MessageAcceptance::Ignore, true)
        ));
        assert!(matches!(
            disposition(Outcome::Ignore(IgnoreReason::FutureSlot)),
            (MessageAcceptance::Ignore, false)
        ));
        assert!(matches!(
            disposition(Outcome::Reject(RejectReason::BadSignature)),
            (MessageAcceptance::Reject, false)
        ));
    }

    #[test]
    fn a_panicking_check_is_ignored_rather_than_propagated() {
        assert_eq!(
            guarded(|| panic!("a DB read failed")),
            Outcome::Ignore(IgnoreReason::Internal)
        );
        assert_eq!(guarded(|| Outcome::Accept), Outcome::Accept);
    }
}
