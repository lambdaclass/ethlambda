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

use ethlambda_network_api::{AggregateArrival, BlockArrival, BlockSource};
use ethlambda_state_transition::beacon::gossip::{self, IgnoreReason, Outcome};
use ethlambda_storage::Store;
use ethlambda_types::beacon::containers::electra::SingleAttestation;
use ethlambda_types::beacon::containers::{
    SignedAggregateAndProof, SignedBeaconBlock, fulu::DataColumnSidecar,
};
use ethlambda_types::beacon::primitives::{Root, ValidatorIndex};
use libp2p::PeerId;
use libp2p::gossipsub::{MessageAcceptance, MessageId};
use spawned_concurrency::message::Message;
use spawned_concurrency::tasks::{Context, Handler};
use tracing::{error, warn};

use crate::beacon::column_checks;
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
            Self::Column(sidecar) => gossip::column::stateful_checks(store, sidecar),
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
            Self::Column(sidecar) => {
                let header = &sidecar.signed_block_header.message;
                server
                    .seen_columns
                    .record(header.slot, header.proposer_index, sidecar.index)
            }
            Self::Aggregate { aggregate, .. } => server.seen_aggregates.record(aggregate),
            Self::Attestation { attestation, .. } => server.seen_attestations.record(attestation),
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
    fn forward(self, server: &P2PServer, received_at: Instant, outcome: Outcome) {
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
                let _ = blockchain
                    .new_block(*block, BlockSource::Gossip, arrival)
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
            Self::Aggregate { .. } | Self::Attestation { .. } => {}
        }
    }
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
    let permits = match &object {
        Validated::Block { .. } | Validated::Column(_) => &server.gossip_validation_permits,
        Validated::Aggregate { .. } | Validated::Attestation { .. } => {
            &server.attestation_validation_permits
        }
    };
    let Ok(permit) = permits.clone().try_acquire_owned() else {
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
    use std::sync::atomic::{AtomicBool, Ordering};

    use ethlambda_network_api::P2PToBlockChain;
    use ethlambda_state_transition::beacon::gossip::{QueueReason, RejectReason};
    use ethlambda_types::attestation::{SignedAggregatedAttestation, SignedAttestation};
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::containers::{AttestationData, Checkpoint, electra, phase0};
    use spawned_concurrency::error::ActorError;

    use super::*;
    use crate::test_support::{unconnected_beacon_server, valid_shaped_sidecar};

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

    /// A [`P2PToBlockChain`] stand-in that only records whether
    /// `new_beacon_aggregate` was called, for the tests that check `forward`
    /// keeps an aggregate off the chain actor on every outcome but `Accept`.
    struct RecordingChain(AtomicBool);

    impl P2PToBlockChain for RecordingChain {
        fn new_block(
            &self,
            _block: SignedBeaconBlock,
            _source: BlockSource,
            _arrival: BlockArrival,
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
            self.0.store(true, Ordering::SeqCst);
            Ok(())
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
        let object = Validated::Column(Box::new(valid_shaped_sidecar(5, 0)));

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
    #[tokio::test]
    async fn an_overloaded_aggregate_is_not_forwarded() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let chain = Arc::new(RecordingChain(AtomicBool::new(false)));
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

        assert!(!chain.0.load(Ordering::SeqCst));
    }

    /// A subnet attestation is never forwarded, on any outcome, `Accept`
    /// included: see `Validated::forward`'s own documentation for why.
    #[tokio::test]
    async fn a_subnet_attestation_is_never_forwarded_even_on_accept() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let chain = Arc::new(RecordingChain(AtomicBool::new(false)));
        server.blockchain = Some(chain.clone());
        let object = Validated::Attestation {
            attestation: Box::new(electra_attestation(5, 1)),
            subnet_id: 0,
        };

        object.forward(&server, Instant::now(), Outcome::Accept);

        assert!(!chain.0.load(Ordering::SeqCst));
    }

    /// The pool an aggregate or a subnet attestation draws its stateful-check
    /// permit from is not the pool a block or a column draws from: exhausting
    /// one must leave the other untouched, or a burst on this topic could
    /// make a block or a column answer `Ignore(Overloaded)` too.
    #[tokio::test]
    async fn the_block_column_and_attestation_permit_pools_are_independent() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let attestation_permits_before = server.attestation_validation_permits.available_permits();

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
