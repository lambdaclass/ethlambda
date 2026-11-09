//! The gossip rules for an execution payload envelope, run on every envelope a
//! peer sent in answer to a request, before the chain actor gets it.
//!
//! The specification treats an envelope obtained by any other means as if it
//! had arrived on gossip, so a fetched one passes the same rules
//! (`gossip::envelope::{cheap_checks, stateful_checks}`) minus the seen cache,
//! which only means something on a topic: the chain actor already drops an
//! envelope for a block it holds one for. Verdicts map onto the actor like so:
//!
//! - `Accept`: forwarded.
//! - `Queue`: forwarded too. The envelope's block (or its post-state) is not
//!   here yet, so the actor keeps it, but only briefly and in small numbers
//!   (`ENVELOPE_AWAITING_BLOCK_TTL_SLOTS` by arrival slot, at most
//!   `MAX_ENVELOPES_AWAITING_BLOCK_PER_SLOT` of them per slot), and the rest
//!   are dropped. A range answer is therefore only safe to deliver while the
//!   blocks it belongs to are imported in order, which is why range pacing
//!   waits on it: see [`check_and_forward_then`].
//! - `Ignore` and `Reject`: dropped.
//!
//! Envelopes go to the actor in the order given. The caller sorts them by
//! slot, and the checks run concurrently but are awaited in order, so a slower
//! signature check does not reorder the batch.

use std::num::NonZeroUsize;

use ethlambda_network_api::BlockArrival;
use ethlambda_state_transition::beacon::gossip::Outcome;
use ethlambda_state_transition::beacon::gossip::envelope::{
    SeenEnvelopes, cheap_checks, stateful_checks,
};
use ethlambda_storage::Store;
use ethlambda_types::beacon::containers::gloas::SignedExecutionPayloadEnvelope;
use tracing::{debug, error, warn};

use crate::P2PServer;

/// Whether a fetched envelope goes to the chain actor.
pub(crate) fn forwards(outcome: &Outcome) -> bool {
    match outcome {
        Outcome::Accept | Outcome::Queue(_) => true,
        Outcome::Ignore(_) | Outcome::Reject(_) => false,
    }
}

/// Both halves of the gossip rule for one envelope. Blocking: the second half
/// verifies a signature against the block's post-state.
fn judge(store: &Store, envelope: &SignedExecutionPayloadEnvelope) -> Outcome {
    // A fresh, empty cache: a fetched envelope is not a gossip duplicate of
    // anything, so the cache's one rule never fires.
    let seen = SeenEnvelopes::new(NonZeroUsize::MIN);
    match cheap_checks(&seen, store, envelope) {
        Ok(()) => stateful_checks(store, envelope),
        Err(outcome) => outcome,
    }
}

/// Run the gossip rules on `envelopes` and send the chain actor the ones that
/// pass, in order.
///
/// Returns at once: the checks run on a task of their own, bounded by
/// [`P2PServer::column_check_permits`] like the column checks are, since a
/// range answer can carry a full request's worth of signatures.
pub(crate) fn check_and_forward(
    server: &P2PServer,
    envelopes: Vec<SignedExecutionPayloadEnvelope>,
) {
    check_and_forward_then(server, envelopes, None);
}

/// A completion callback: runs once every envelope that passed has been handed
/// to the chain actor.
pub(crate) type Done = Box<dyn FnOnce() + Send>;

/// [`check_and_forward`], then `done` once the last passing envelope has been
/// sent, or at once when there is nothing to check.
///
/// This is how range sync paces itself on a gloas batch: the next batch's
/// blocks are requested only after `done`, so the actor never sees them ahead
/// of this batch's envelopes. All of the batch's envelopes are sent by one
/// task, in the order given, with nothing from another batch between them.
pub(crate) fn check_and_forward_then(
    server: &P2PServer,
    envelopes: Vec<SignedExecutionPayloadEnvelope>,
    done: Option<Done>,
) {
    let run_done = |done: Option<Done>| {
        if let Some(done) = done {
            done();
        }
    };
    if envelopes.is_empty() {
        run_done(done);
        return;
    }
    let Some(blockchain) = server.blockchain.clone() else {
        run_done(done);
        return;
    };
    let store = server.store.clone();
    let permits = server.column_check_permits.clone();
    tokio::spawn(async move {
        let mut checks = Vec::with_capacity(envelopes.len());
        for envelope in envelopes {
            // The semaphore is never closed, so this only returns once a
            // permit is free.
            let Ok(permit) = permits.clone().acquire_owned().await else {
                if let Some(done) = done {
                    done();
                }
                return;
            };
            let store = store.clone();
            checks.push(tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let outcome = judge(&store, &envelope);
                (envelope, outcome)
            }));
        }

        for check in checks {
            let (envelope, outcome) = match check.await {
                Ok(checked) => checked,
                Err(err) => {
                    error!(%err, "An envelope check panicked; dropping the envelope");
                    continue;
                }
            };
            if !forwards(&outcome) {
                let block_root = envelope.message.beacon_block_root;
                let (_, reason) = outcome.labels();
                debug!(
                    block_root = %ethlambda_types::ShortRoot(&block_root.0),
                    reason,
                    "Dropping a fetched execution payload envelope"
                );
                continue;
            }
            let _ = blockchain
                .new_execution_payload_envelope(Box::new(envelope), BlockArrival::now())
                .inspect_err(|err| warn!(%err, "Failed to forward a fetched envelope"));
        }
        if let Some(done) = done {
            done();
        }
    });
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Duration;

    use ethlambda_network_api::ToP2PToBlockChainRef as _;
    use ethlambda_network_api::p2p_to_block_chain::NewExecutionPayloadEnvelope;
    use ethlambda_state_transition::beacon::gossip::{IgnoreReason, QueueReason, RejectReason};
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::primitives::H256;
    use spawned_test::tasks::Mock;

    use super::*;
    use crate::test_support::unconnected_beacon_server;

    /// Long enough for the checks' blocking tasks on a loaded test machine.
    pub(crate) const FORWARDED: Duration = Duration::from_secs(10);

    pub(crate) fn envelope(slot: u64, byte: u8) -> SignedExecutionPayloadEnvelope {
        crate::beacon::encoding::test_support::envelope(H256::repeat_byte(byte), slot, H256::ZERO)
    }

    /// The `(block root, slot)` an envelope the chain actor was sent names.
    pub(crate) fn sent(message: &NewExecutionPayloadEnvelope) -> (H256, u64) {
        (
            message.envelope.message.beacon_block_root,
            message.envelope.message.payload.slot_number,
        )
    }

    #[test]
    fn only_accept_and_queue_reach_the_chain_actor() {
        assert!(forwards(&Outcome::Accept));
        assert!(forwards(&Outcome::Queue(QueueReason::BlockUnknown)));
        assert!(forwards(&Outcome::Queue(QueueReason::StateNotCached)));
        assert!(!forwards(&Outcome::Ignore(IgnoreReason::Finalized)));
        assert!(!forwards(&Outcome::Reject(RejectReason::BadSignature)));
    }

    /// An envelope whose block this node has not seen is queued, so it reaches
    /// the actor, and a batch keeps the order it was given.
    #[tokio::test]
    async fn envelopes_for_unknown_blocks_are_forwarded_in_order() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let chain = Mock::new().allow_sends().start();
        server.blockchain = Some(chain.to_p2p_to_block_chain_ref());

        check_and_forward(
            &server,
            vec![envelope(7, 1), envelope(8, 2), envelope(9, 3)],
        );

        for (slot, byte) in [(7, 1), (8, 2), (9, 3)] {
            let forwarded: NewExecutionPayloadEnvelope = chain.expect(FORWARDED).await;
            assert_eq!(sent(&forwarded), (H256::repeat_byte(byte), slot));
        }
        // The last of the batch is the task's last send.
        assert_eq!(chain.received().len(), 3);
        chain.assert_no_unexpected();
    }
}
