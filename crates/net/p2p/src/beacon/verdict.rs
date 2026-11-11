//! The verdict plumbing between gossipsub and the beacon gossip rules.
//!
//! The rules live in `ethlambda_state_transition::beacon::gossip`; this module
//! decides where each half runs and what happens to the result. Cheap checks
//! run inline in the p2p actor. Stateful checks run off it as a job owned by
//! the actor, bounded by one of three pools depending on the kind: a block or a
//! column draws from [`P2PServer::gossip_validation_permits`], an aggregate or
//! a subnet attestation from [`P2PServer::attestation_validation_permits`] (see
//! that field's own documentation for why they must not share one), a sync
//! committee message or contribution from
//! [`P2PServer::sync_validation_permits`]. Either way
//! the job delivers one [`GossipVerdict`] back to the actor. Every beacon
//! gossip message ends in exactly one [`report`]: gossipsub holds each one
//! until then.

use std::time::{Duration, Instant};

use ethlambda_network_api::{AggregateArrival, BlockAnnouncement, BlockArrival, BlockSource};
use ethlambda_state_transition::beacon::builder_market::SharedBuilderMarket;
use ethlambda_state_transition::beacon::gossip::{self, IgnoreReason, Outcome};
use ethlambda_state_transition::beacon::helpers::accessors::CommitteeCacheExt as _;
use ethlambda_storage::{CacheKey, Store};
use ethlambda_types::beacon::containers::altair::{
    SignedContributionAndProof, SyncCommitteeMessage,
};
use ethlambda_types::beacon::containers::electra::{self, SingleAttestation};
use ethlambda_types::beacon::containers::gloas::{
    PayloadAttestationMessage, SignedExecutionPayloadBid, SignedExecutionPayloadEnvelope,
    SignedProposerPreferences,
};
use ethlambda_types::beacon::containers::{
    DataColumnSidecar, SignedAggregateAndProof, SignedBeaconBlock,
};
use ethlambda_types::beacon::operation::BeaconOperation;
use ethlambda_types::beacon::primitives::{Root, ValidatorIndex};
use libp2p::PeerId;
use libp2p::gossipsub::{MessageAcceptance, MessageId};
use spawned_concurrency::message::Message;
use spawned_concurrency::tasks::{
    Context, Handler, JobError, JobOptions, JobOutcome, PendingReply,
};
use tracing::{debug, error, warn};

use crate::beacon::{builder_market, column_checks};
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
    /// A gloas `execution_payload_bid`. Carries the market because
    /// `stateful_checks` receives only the store.
    ExecutionPayloadBid {
        bid: Box<SignedExecutionPayloadBid>,
        market: SharedBuilderMarket,
    },
    /// A gloas `proposer_preferences`.
    ProposerPreferences(Box<SignedProposerPreferences>),
    /// A gloas `payload_attestation_message`.
    PayloadAttestation(PayloadAttestationMessage),
    /// One of the four operation topics. Boxed like the other wide payloads.
    Operation(Box<BeaconOperation>),
    /// A `sync_committee_{subnet_id}` message.
    SyncCommitteeMessage {
        message: SyncCommitteeMessage,
        subnet_id: u64,
        /// The `(subcommittee, position)` seats its signature verified for.
        /// Empty until [`Validated::stateful_checks`] fills it in on `Accept`,
        /// like [`Self::Aggregate`]'s `attesting_indices`.
        seats: Vec<(u64, usize)>,
    },
    /// A `sync_committee_contribution_and_proof`.
    SyncContribution(Box<SignedContributionAndProof>),
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
            Self::ExecutionPayloadBid { bid, market } => {
                gossip::execution_payload_bid::stateful_checks(store, market, bid)
            }
            Self::ProposerPreferences(preferences) => {
                gossip::proposer_preferences::stateful_checks(store, preferences)
            }
            Self::PayloadAttestation(message) => {
                gossip::payload_attestation::stateful_checks(store, message)
            }
            Self::Operation(operation) => gossip::operations::stateful_checks(store, operation),
            Self::SyncCommitteeMessage {
                message,
                subnet_id,
                seats,
            } => {
                match gossip::sync_committee::message_stateful_checks(store, message, *subnet_id) {
                    Ok(resolved) => {
                        *seats = resolved;
                        Outcome::Accept
                    }
                    Err(outcome) => outcome,
                }
            }
            Self::SyncContribution(signed) => {
                gossip::sync_committee::contribution_stateful_checks(store, signed)
            }
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
            Self::Envelope(envelope) => {
                let recorded = server.seen_envelopes.record(
                    envelope.message.beacon_block_root,
                    envelope.message.builder_index,
                );
                if recorded {
                    // A bid's parent payload is known once its envelope passed
                    // gossip; the builder market judges bids against this.
                    server
                        .builder_market
                        .record_execution_payload(&envelope.message);
                }
                recorded
            }
            Self::ExecutionPayloadBid { bid, .. } => {
                server.builder_market.record_bid((**bid).clone())
            }
            Self::ProposerPreferences(preferences) => server
                .builder_market
                .record_preferences((**preferences).clone(), builder_market::wall_slot(server)),
            Self::PayloadAttestation(message) => server
                .seen_payload_attestations
                .record(message.data.slot, message.validator_index),
            Self::Operation(operation) => server.seen_operations.record(operation),
            Self::SyncCommitteeMessage {
                message, subnet_id, ..
            } => {
                server
                    .seen_sync_messages
                    .record(message.slot, message.validator_index, *subnet_id)
            }
            Self::SyncContribution(signed) => server.seen_sync_contributions.record(signed),
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
        if let Self::SyncCommitteeMessage { message, seats, .. } = &self
            && outcome == Outcome::Accept
        {
            // Block production packs these through the pool; nothing on the
            // chain actor consumes a sync message, so it never goes further.
            server
                .sync_committee_pool
                .lock()
                .expect("sync committee pool lock poisoned")
                .insert_message(message, seats);
        }
        if let Self::SyncContribution(signed) = &self
            && outcome == Outcome::Accept
        {
            server
                .sync_committee_pool
                .lock()
                .expect("sync committee pool lock poisoned")
                .insert_contribution(signed.message.contribution.clone());
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
            // The SSE `execution_payload_bid` and `proposer_preferences` events
            // hook in here once the events endpoint lands.
            | Self::ExecutionPayloadBid { .. }
            | Self::ProposerPreferences(_)
            | Self::PayloadAttestation(_)
            | Self::Operation(_)
            | Self::SyncCommitteeMessage { .. }
            | Self::SyncContribution(_) => {}
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
        | Validated::ExecutionPayloadBid { .. }
        | Validated::ProposerPreferences(_)
        | Validated::Operation(_)
        | Validated::SyncCommitteeMessage { .. }
        | Validated::SyncContribution(_) => {}
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

/// A stateful check's job ended: the terminal message of the job
/// [`spawn_stateful_checks`] starts, so it arrives exactly once per object,
/// whether the check returned, panicked or overran
/// [`STATEFUL_CHECK_DEADLINE`].
pub(crate) struct GossipVerdict {
    id: GossipId,
    checked: JobOutcome<(Outcome, Validated)>,
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
    async fn handle(
        &mut self,
        msg: GossipVerdict,
        _reply: PendingReply<'_, ()>,
        _ctx: &Context<Self>,
    ) {
        let GossipVerdict { id, checked } = msg;
        let (outcome, object) = match checked {
            JobOutcome::Ok((outcome, object)) => (settle(self, outcome, &object), Some(object)),
            // A panic inside validation (a `Store` read's `.expect()` on a DB
            // error, say) must still produce a verdict, or gossipsub would hold
            // the message until its cache evicts it.
            JobOutcome::Err(JobError::Panicked(panic_message)) => {
                error!(
                    panic_message,
                    "Beacon gossip validation panicked; reporting Ignore(Internal)"
                );
                (Outcome::Ignore(IgnoreReason::Internal), None)
            }
            // The check still runs, holding its permit; its result is dropped.
            JobOutcome::Err(JobError::DeadlineExceeded) => {
                warn!(
                    kind = id.kind,
                    deadline_secs = STATEFUL_CHECK_DEADLINE.as_secs(),
                    "Beacon gossip validation overran its deadline; reporting Ignore"
                );
                (Outcome::Ignore(IgnoreReason::ValidationTimeout), None)
            }
            // `JobOutcome` and `JobError` are `#[non_exhaustive]`: a way of
            // ending spawned adds later still yields the one verdict.
            _ => {
                error!(
                    kind = id.kind,
                    "Beacon gossip validation ended without a result; reporting Ignore(Internal)"
                );
                (Outcome::Ignore(IgnoreReason::Internal), None)
            }
        };
        let received_at = id.received_at;
        // Only an Accept or a Queue forwards, and both come with the object.
        if report(self, id, outcome)
            && let Some(object) = object
        {
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
/// operation topics) from the attestation pool, and the sync committee's
/// messages and contributions from a pool of their own, so no burst starves
/// another.
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
        Validated::ExecutionPayloadBid { .. } | Validated::ProposerPreferences(_) => {
            &server.builder_validation_permits
        }
        Validated::SyncCommitteeMessage { .. } | Validated::SyncContribution(_) => {
            &server.sync_validation_permits
        }
    }
}

/// How long an object's stateful checks may run before it is reported
/// `Ignore(ValidationTimeout)` anyway. One mainnet slot: a check that has not
/// finished by then is hung, and gossipsub would otherwise hold its message
/// until the cache evicts it.
pub(crate) const STATEFUL_CHECK_DEADLINE: Duration = Duration::from_secs(12);

/// Run `object`'s stateful checks off the actor, as a job owned by the p2p
/// actor. The verdict comes back as one [`GossipVerdict`], also when the check
/// panics or overruns [`STATEFUL_CHECK_DEADLINE`], and never after the actor
/// began to stop (the job is cancelled with it).
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
///
/// The check itself runs on Tokio's blocking pool, awaited by an async job
/// (`pipe_with`), not as a native job (`pipe_blocking_with`): spawned 0.8 runs
/// each native job on a freshly spawned OS thread, under a per-actor budget
/// (`MAX_NATIVE_JOBS`, at most 4 by default) that `#[actor]` cannot raise,
/// while these pools admit up to 352 checks at once.
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
    pipe_checks(server, ctx, id, STATEFUL_CHECK_DEADLINE, move || {
        let _permit = permit;
        let mut object = object;
        let outcome = object.stateful_checks(&store);
        (outcome, object)
    });
}

/// Run `checks` on Tokio's blocking pool as a job owned by the p2p actor,
/// with a `deadline`, and deliver its one [`GossipVerdict`].
fn pipe_checks(
    server: &P2PServer,
    ctx: &Context<P2PServer>,
    id: GossipId,
    deadline: Duration,
    checks: impl FnOnce() -> (Outcome, Validated) + Send + 'static,
) {
    // `pipe_with` drops `work` and `done` when it cannot start the job; keep
    // what the verdict for that case needs.
    let fallback = GossipId {
        message_id: id.message_id.clone(),
        propagation_source: id.propagation_source,
        received_at: id.received_at,
        kind: id.kind,
    };
    let opts = JobOptions {
        // `spawned_rt::time::Instant` is `std::time::Instant` outside simulation.
        deadline: Some(Instant::now() + deadline),
        ..JobOptions::default()
    };
    let work = async move {
        match tokio::task::spawn_blocking(checks).await {
            Ok(checked) => checked,
            // Re-raise the check's panic so the job reports it as
            // `JobError::Panicked`.
            Err(err) => match err.try_into_panic() {
                Ok(panic) => std::panic::resume_unwind(panic),
                Err(err) => panic!("stateful checks did not finish: {err}"),
            },
        }
    };
    let started = ctx.pipe_with(opts, work, move |checked| GossipVerdict { id, checked });
    if let Err(err) = started {
        // Only when the actor is stopping (`OwnerStopping`), or at its 1024
        // deferred credits, far above the 352 permits. The object went with
        // the refused job, so it is not forwarded.
        warn!(%err, "Could not start a gossip check");
        report(server, fallback, Outcome::Ignore(IgnoreReason::Overloaded));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ethlambda_network_api::ToP2PToBlockChainRef as _;
    use ethlambda_network_api::p2p_to_block_chain::{
        NewBlock, NewExecutionPayloadEnvelope, NewPayloadAttestationMessage,
    };
    use ethlambda_state_transition::beacon::gossip::{QueueReason, RejectReason};
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::containers::{
        AttestationData, Checkpoint, electra, gloas, phase0,
    };
    use spawned_test::tasks::{Mock, MockRef};

    use super::*;
    use crate::test_support::{envelope, unconnected_beacon_server, valid_shaped_sidecar};

    /// A chain actor stand-in that takes every send and logs it.
    fn recording_chain(server: &mut P2PServer) -> MockRef {
        let chain = Mock::new().allow_sends().start();
        server.blockchain = Some(chain.to_p2p_to_block_chain_ref());
        chain
    }

    /// A chain actor stand-in that fails the test on any message at all.
    fn silent_chain(server: &mut P2PServer) -> MockRef {
        let chain = Mock::new().start();
        server.blockchain = Some(chain.to_p2p_to_block_chain_ref());
        chain
    }

    /// Assert the chain actor was sent nothing. `forward` sends synchronously,
    /// so once the mock has handled what was sent before, the log is complete.
    async fn assert_nothing_sent(chain: &MockRef) {
        chain.settle().await;
        assert_eq!(chain.received(), []);
    }

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
        let chain = recording_chain(&mut server);
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

        chain.settle().await;
        let announcements: Vec<_> = chain
            .take_all::<NewBlock>()
            .into_iter()
            .map(|sent| sent.announcement)
            .collect();
        assert_eq!(
            announcements,
            [
                BlockAnnouncement::Announce,
                BlockAnnouncement::Silent,
                BlockAnnouncement::Silent
            ]
        );
        chain.assert_no_unexpected();
    }

    #[tokio::test]
    async fn an_overloaded_aggregate_is_not_forwarded() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let chain = silent_chain(&mut server);
        let object = Validated::Aggregate {
            aggregate: Box::new(phase0_aggregate(5, 1)),
            attesting_indices: Vec::new(),
        };

        object.forward(
            &server,
            Instant::now(),
            Outcome::Ignore(IgnoreReason::Overloaded),
        );

        assert_nothing_sent(&chain).await;
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
        let chain = silent_chain(&mut server);
        let object = Validated::Attestation {
            attestation: Box::new(electra_attestation(5, 1)),
            subnet_id: 0,
        };

        object.forward(&server, Instant::now(), Outcome::Accept);

        assert_nothing_sent(&chain).await;
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
        let chain = recording_chain(&mut server);

        let forward = |outcome| {
            Validated::Envelope(Box::new(envelope(1, 3))).forward(&server, Instant::now(), outcome)
        };
        forward(Outcome::Accept);
        forward(Outcome::Queue(QueueReason::BlockUnknown));
        forward(Outcome::Ignore(IgnoreReason::Overloaded));
        forward(Outcome::Reject(RejectReason::BadSignature));
        chain.settle().await;
        assert_eq!(chain.count::<NewExecutionPayloadEnvelope>(), 2);
        assert_eq!(chain.received().len(), 2);
    }

    /// A payload attestation reaches the chain actor on `Accept` alone.
    #[tokio::test]
    async fn a_payload_attestation_is_forwarded_on_accept_only() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let chain = recording_chain(&mut server);

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
        forward(Outcome::Accept);
        chain.settle().await;
        assert_eq!(chain.count::<NewPayloadAttestationMessage>(), 1);
        assert_eq!(chain.received().len(), 1);
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

    fn bid(slot: u64, builder_index: u64, value: u64) -> SignedExecutionPayloadBid {
        let mut bid = SignedExecutionPayloadBid::default();
        bid.message.slot = slot;
        bid.message.builder_index = builder_index;
        bid.message.value = value;
        bid
    }

    fn preferences(proposal_slot: u64, validator: u64) -> SignedProposerPreferences {
        let mut preferences = SignedProposerPreferences::default();
        preferences.message.proposal_slot = proposal_slot;
        preferences.message.validator_index = validator;
        preferences
    }

    fn bid_object(server: &P2PServer, bid: SignedExecutionPayloadBid) -> Validated {
        Validated::ExecutionPayloadBid {
            bid: Box::new(bid),
            market: server.builder_market.clone(),
        }
    }

    /// Needs the real market (Agent A): its stub never records.
    #[tokio::test]
    async fn the_first_accept_for_a_bid_key_stands_and_the_second_is_marked_seen() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let object = bid_object(&server, bid(5, 3, 10));

        assert_eq!(
            settle(&mut server, Outcome::Accept, &object),
            Outcome::Accept
        );
        assert_eq!(
            settle(&mut server, Outcome::Accept, &object),
            Outcome::Ignore(IgnoreReason::AlreadySeen)
        );
        // Anything but an accept records nothing. The value must beat the
        // best one recorded for the same (slot, parent), or the spec's
        // highest-bid rule would ignore it on its own account.
        let other = bid_object(&server, bid(5, 4, 11));
        assert_eq!(
            settle(
                &mut server,
                Outcome::Ignore(IgnoreReason::StateUnavailable),
                &other
            ),
            Outcome::Ignore(IgnoreReason::StateUnavailable)
        );
        assert_eq!(
            settle(&mut server, Outcome::Accept, &other),
            Outcome::Accept
        );
    }

    /// An accepted bid is pooled in the market the API and `produceBlockV4`
    /// read. Needs the real market (Agent A).
    #[tokio::test]
    async fn an_accepted_bid_is_pooled_in_the_shared_market() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let signed = bid(5, 3, 10);
        let object = bid_object(&server, signed.clone());
        assert!(!server.builder_market.contains_bid(&signed));

        assert_eq!(
            settle(&mut server, Outcome::Accept, &object),
            Outcome::Accept
        );
        assert!(server.builder_market.contains_bid(&signed));
        assert_eq!(
            server.builder_market.bids_for(
                5,
                signed.message.parent_block_root,
                signed.message.parent_block_hash
            ),
            vec![signed]
        );
    }

    /// Needs the real market (Agent A).
    #[tokio::test]
    async fn the_first_accept_for_a_preferences_key_stands_and_the_second_is_marked_seen() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let object = Validated::ProposerPreferences(Box::new(preferences(40, 5)));

        assert_eq!(
            settle(&mut server, Outcome::Accept, &object),
            Outcome::Accept
        );
        assert_eq!(
            settle(&mut server, Outcome::Accept, &object),
            Outcome::Ignore(IgnoreReason::AlreadySeen)
        );
        assert!(server.builder_market.preferences(40, Root::ZERO).is_some());
    }

    /// Neither builder market type has a consumer on the chain actor, on any
    /// outcome.
    #[tokio::test]
    async fn bids_and_preferences_never_reach_the_chain_actor() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let chain = silent_chain(&mut server);

        for outcome in [
            Outcome::Accept,
            Outcome::Queue(QueueReason::BlockUnknown),
            Outcome::Ignore(IgnoreReason::Overloaded),
        ] {
            bid_object(&server, bid(5, 3, 10)).forward(&server, Instant::now(), outcome);
            Validated::ProposerPreferences(Box::new(preferences(40, 5))).forward(
                &server,
                Instant::now(),
                outcome,
            );
        }

        assert_nothing_sent(&chain).await;
    }

    /// Bids and preferences draw from a pool of their own, so a burst of them
    /// cannot starve blocks, columns or attestations, and the reverse.
    #[tokio::test]
    async fn the_builder_permit_pool_is_independent_of_the_others() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let bid = bid_object(&server, bid(5, 3, 10));
        let preferences = Validated::ProposerPreferences(Box::new(preferences(40, 5)));
        for object in [&bid, &preferences] {
            assert!(Arc::ptr_eq(
                permits_for(&server, object),
                &server.builder_validation_permits
            ));
        }

        let gossip_before = server.gossip_validation_permits.available_permits();
        let attestation_before = server.attestation_validation_permits.available_permits();
        let mut held = Vec::new();
        while let Ok(permit) = server
            .builder_validation_permits
            .clone()
            .try_acquire_owned()
        {
            held.push(permit);
        }
        // Exhausted: a bid's stateful checks would answer `Ignore(Overloaded)`.
        assert_eq!(server.builder_validation_permits.available_permits(), 0);
        assert!(
            permits_for(&server, &bid)
                .clone()
                .try_acquire_owned()
                .is_err()
        );
        assert_eq!(
            server.gossip_validation_permits.available_permits(),
            gossip_before
        );
        assert_eq!(
            server.attestation_validation_permits.available_permits(),
            attestation_before
        );
    }

    /// An accepted envelope is a known payload for bid validation. Needs the
    /// real market (Agent A).
    #[tokio::test]
    async fn an_accepted_envelope_becomes_a_known_payload() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let signed = envelope(1, 3);
        let hash = signed.message.payload.block_hash;
        assert!(server.builder_market.known_payload(hash).is_none());
        let object = Validated::Envelope(Box::new(signed));

        // A queued envelope has not been judged, so it is not known.
        settle(
            &mut server,
            Outcome::Queue(QueueReason::BlockUnknown),
            &object,
        );
        assert!(server.builder_market.known_payload(hash).is_none());

        settle(&mut server, Outcome::Accept, &object);
        assert!(server.builder_market.known_payload(hash).is_some());
    }

    /// The node's own envelope is known too, since gossip never echoes it.
    /// Needs the real market (Agent A).
    #[tokio::test]
    async fn a_published_envelope_becomes_a_known_payload() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let signed = envelope(2, 3);
        let hash = signed.message.payload.block_hash;
        assert!(server.builder_market.known_payload(hash).is_none());

        crate::gossipsub::publish_execution_payload_envelope(&mut server, signed, Vec::new()).await;

        assert!(server.builder_market.known_payload(hash).is_some());
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

    /// The compressed BLS12-381 G2 generator: a signature that decodes and
    /// combines, standing in for a verified one where the test is about
    /// pooling and not about verification.
    fn valid_looking_signature() -> ethlambda_types::beacon::primitives::BlsSignature {
        let bytes = hex::decode(
            "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049\
             334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051\
             c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
        )
        .expect("valid hex");
        ethlambda_types::beacon::primitives::BlsSignature(bytes.try_into().expect("96 bytes"))
    }

    fn sync_message(slot: u64, validator: u64) -> SyncCommitteeMessage {
        SyncCommitteeMessage {
            slot,
            beacon_block_root: Root::repeat_byte(7),
            validator_index: validator,
            signature: valid_looking_signature(),
        }
    }

    fn sync_message_object(
        slot: u64,
        validator: u64,
        subnet_id: u64,
        seats: Vec<(u64, usize)>,
    ) -> Validated {
        Validated::SyncCommitteeMessage {
            message: sync_message(slot, validator),
            subnet_id,
            seats,
        }
    }

    fn sync_contribution(
        slot: u64,
        aggregator: u64,
        subcommittee: u64,
    ) -> SignedContributionAndProof {
        let mut aggregation_bits =
            ethlambda_types::beacon::containers::altair::SyncSubcommitteeBits::default();
        aggregation_bits.set(0, true).expect("position 0 exists");
        SignedContributionAndProof {
            message: ethlambda_types::beacon::containers::altair::ContributionAndProof {
                aggregator_index: aggregator,
                contribution:
                    ethlambda_types::beacon::containers::altair::SyncCommitteeContribution {
                        slot,
                        beacon_block_root: Root::repeat_byte(7),
                        subcommittee_index: subcommittee,
                        aggregation_bits,
                        signature: valid_looking_signature(),
                    },
                selection_proof: Default::default(),
            },
            signature: Default::default(),
        }
    }

    #[tokio::test]
    async fn the_first_accept_for_a_sync_message_key_stands_and_the_second_is_marked_seen() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let object = sync_message_object(5, 11, 1, vec![(1, 0)]);

        assert_eq!(
            settle(&mut server, Outcome::Accept, &object),
            Outcome::Accept
        );
        assert_eq!(
            settle(&mut server, Outcome::Accept, &object),
            Outcome::Ignore(IgnoreReason::AlreadySeen)
        );
        // The same validator on another subnet is another key.
        let other_subnet = sync_message_object(5, 11, 2, vec![(2, 0)]);
        assert_eq!(
            settle(&mut server, Outcome::Accept, &other_subnet),
            Outcome::Accept
        );
        // So is the same subnet in another slot.
        let other_slot = sync_message_object(6, 11, 1, vec![(1, 0)]);
        assert_eq!(
            settle(&mut server, Outcome::Accept, &other_slot),
            Outcome::Accept
        );
    }

    #[tokio::test]
    async fn the_first_accept_for_a_sync_contribution_stands_and_the_second_is_marked_seen() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let object = Validated::SyncContribution(Box::new(sync_contribution(5, 3, 1)));

        assert_eq!(
            settle(&mut server, Outcome::Accept, &object),
            Outcome::Accept
        );
        assert_eq!(
            settle(&mut server, Outcome::Accept, &object),
            Outcome::Ignore(IgnoreReason::AlreadySeen)
        );
        // Anything but an accept records nothing.
        let other = Validated::SyncContribution(Box::new(sync_contribution(5, 4, 2)));
        assert_eq!(
            settle(
                &mut server,
                Outcome::Reject(RejectReason::BadSignature),
                &other
            ),
            Outcome::Reject(RejectReason::BadSignature)
        );
        assert_eq!(
            settle(&mut server, Outcome::Accept, &other),
            Outcome::Accept
        );
    }

    /// An accepted sync message lands in the pool at the seats its checks
    /// resolved; any other outcome stays out, since one unverified signature
    /// fails the aggregate it is packed into.
    #[tokio::test]
    async fn an_accepted_sync_message_is_pooled_and_others_are_not() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let root = Root::repeat_byte(7);
        let pooled = || {
            server
                .sync_committee_pool
                .lock()
                .unwrap()
                .contribution(5, root, 1)
        };
        let forward = |outcome| {
            sync_message_object(5, 11, 1, vec![(1, 3)]).forward(&server, Instant::now(), outcome)
        };
        forward(Outcome::Ignore(IgnoreReason::Overloaded));
        forward(Outcome::Reject(RejectReason::BadSignature));
        forward(Outcome::Queue(QueueReason::BlockUnknown));
        assert!(pooled().is_none());
        forward(Outcome::Accept);
        let contribution = pooled().expect("pooled on accept");
        assert!(contribution.aggregation_bits.get(3).unwrap());
        assert!(!contribution.aggregation_bits.get(0).unwrap());
    }

    #[tokio::test]
    async fn an_accepted_sync_contribution_is_pooled_and_others_are_not() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let root = Root::repeat_byte(7);
        let pooled = || {
            server
                .sync_committee_pool
                .lock()
                .unwrap()
                .contribution(5, root, 2)
        };
        let forward = |outcome| {
            Validated::SyncContribution(Box::new(sync_contribution(5, 3, 2))).forward(
                &server,
                Instant::now(),
                outcome,
            )
        };
        forward(Outcome::Ignore(IgnoreReason::Overloaded));
        forward(Outcome::Reject(RejectReason::AggregateSignature));
        assert!(pooled().is_none());
        forward(Outcome::Accept);
        assert_eq!(
            pooled().expect("pooled on accept"),
            sync_contribution(5, 3, 2).message.contribution
        );
    }

    /// Sync messages and contributions have no fork-choice effect, so nothing
    /// is handed to the chain actor on any outcome.
    #[tokio::test]
    async fn sync_committee_gossip_never_reaches_the_chain_actor() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let chain = silent_chain(&mut server);
        for outcome in [
            Outcome::Accept,
            Outcome::Queue(QueueReason::BlockUnknown),
            Outcome::Ignore(IgnoreReason::Overloaded),
            Outcome::Reject(RejectReason::BadSignature),
        ] {
            sync_message_object(5, 11, 1, vec![(1, 3)]).forward(&server, Instant::now(), outcome);
            Validated::SyncContribution(Box::new(sync_contribution(5, 3, 2))).forward(
                &server,
                Instant::now(),
                outcome,
            );
        }
        assert_nothing_sent(&chain).await;
    }

    /// The sync pool is its own: exhausting it must not starve the block and
    /// column pool or the attestation pool, nor the other way round.
    #[tokio::test]
    async fn the_sync_permit_pool_is_independent_of_the_others() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let message = sync_message_object(5, 11, 1, Vec::new());
        let contribution = Validated::SyncContribution(Box::new(sync_contribution(5, 3, 1)));
        let sync = &server.sync_validation_permits;
        for object in [&message, &contribution] {
            assert!(std::sync::Arc::ptr_eq(permits_for(&server, object), sync));
        }
        assert!(!std::sync::Arc::ptr_eq(
            sync,
            &server.gossip_validation_permits
        ));
        assert!(!std::sync::Arc::ptr_eq(
            sync,
            &server.attestation_validation_permits
        ));

        // Draining the sync pool leaves the other two untouched.
        let gossip_before = server.gossip_validation_permits.available_permits();
        let attestation_before = server.attestation_validation_permits.available_permits();
        let held = sync
            .clone()
            .acquire_many_owned(sync.available_permits() as u32)
            .await
            .expect("the pool is open");
        assert!(sync.clone().try_acquire_owned().is_err());
        assert_eq!(
            server.gossip_validation_permits.available_permits(),
            gossip_before
        );
        assert_eq!(
            server.attestation_validation_permits.available_permits(),
            attestation_before
        );
        drop(held);
    }

    // ---- The job that carries a stateful check (spawned 0.8 `pipe_with`) ----

    /// Run `f` in one of the p2p actor's turns, to reach its `Context`.
    type InTurn = Box<dyn FnOnce(&mut P2PServer, &Context<P2PServer>) + Send>;
    struct InActor(InTurn);
    impl Message for InActor {
        type Result = ();
    }
    impl Handler<InActor> for P2PServer {
        async fn handle(
            &mut self,
            msg: InActor,
            _reply: PendingReply<'_, ()>,
            ctx: &Context<Self>,
        ) {
            (msg.0)(self, ctx);
        }
    }

    /// A gossip id under a metric `kind` of the test's own, so the global
    /// verdict counters tell its verdicts apart from every other test's.
    fn test_id(kind: &'static str) -> GossipId {
        GossipId {
            message_id: MessageId::new(kind.as_bytes()),
            propagation_source: PeerId::random(),
            received_at: Instant::now(),
            kind,
        }
    }

    /// Start `checks` on a running p2p actor under `kind`, with `deadline`.
    async fn run_checks(
        kind: &'static str,
        deadline: Duration,
        checks: impl FnOnce() -> (Outcome, Validated) + Send + 'static,
    ) -> spawned_concurrency::tasks::ActorRef<P2PServer> {
        use spawned_concurrency::tasks::ActorStart as _;
        let server = unconnected_beacon_server(Config::mainnet(), 0)
            .await
            .start();
        server
            .send(InActor(Box::new(move |server, ctx| {
                pipe_checks(server, ctx, test_id(kind), deadline, checks)
            })))
            .expect("the p2p actor runs");
        server
    }

    /// Wait (up to 5 s) until `kind` has at least `n` verdicts.
    async fn verdicts_reach(kind: &'static str, n: u64) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while metrics::beacon_gossip_verdicts(kind, "", "").0 < n {
            assert!(Instant::now() < deadline, "{kind}: fewer than {n} verdicts");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_panicking_check_still_yields_exactly_one_verdict() {
        const KIND: &str = "test_panicking_check";
        let server = run_checks(KIND, Duration::from_secs(5), || panic!("a DB read failed")).await;
        verdicts_reach(KIND, 1).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            metrics::beacon_gossip_verdicts(KIND, "ignore", "internal"),
            (1, 1)
        );
        server.child_handle().stop();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_hung_check_is_reported_at_its_deadline_and_its_late_result_dropped() {
        const KIND: &str = "test_hung_check";
        let server = run_checks(KIND, Duration::from_millis(50), || {
            std::thread::sleep(Duration::from_millis(500));
            (Outcome::Accept, sync_message_object(5, 11, 1, vec![(1, 0)]))
        })
        .await;
        verdicts_reach(KIND, 1).await;
        assert_eq!(
            metrics::beacon_gossip_verdicts(KIND, "ignore", "validation_timeout"),
            (1, 1)
        );
        // The check returns Accept long after: no second verdict.
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert_eq!(metrics::beacon_gossip_verdicts(KIND, "", "").0, 1);
        server.child_handle().stop();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_verdict_reaches_an_actor_that_stopped_during_the_check() {
        const KIND: &str = "test_check_during_stop";
        let server = run_checks(KIND, Duration::from_secs(5), || {
            std::thread::sleep(Duration::from_millis(300));
            (Outcome::Accept, sync_message_object(5, 11, 1, vec![(1, 0)]))
        })
        .await;
        // Let the job start, then stop the actor while the check still runs.
        tokio::time::sleep(Duration::from_millis(50)).await;
        server.child_handle().stop();
        server.join().await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(metrics::beacon_gossip_verdicts(KIND, "", "").0, 0);
    }
}
