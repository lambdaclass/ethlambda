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
//!   here yet, and the actor holds such an envelope until the block imports,
//!   which is exactly what a range answer needs, since its envelopes arrive
//!   while the blocks they belong to are still queued in the actor's mailbox.
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
    if envelopes.is_empty() {
        return;
    }
    let Some(blockchain) = server.blockchain.clone() else {
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
    });
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    use ethlambda_network_api::{AggregateArrival, BlockSource, P2PToBlockChain};
    use ethlambda_state_transition::beacon::gossip::{IgnoreReason, QueueReason, RejectReason};
    use ethlambda_types::attestation::{SignedAggregatedAttestation, SignedAttestation};
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::containers::{
        DataColumnSidecar, SignedAggregateAndProof, SignedBeaconBlock,
    };
    use ethlambda_types::beacon::primitives::ValidatorIndex;
    use ethlambda_types::primitives::H256;
    use spawned_concurrency::error::ActorError;
    use tokio::sync::mpsc;

    use super::*;
    use crate::test_support::unconnected_beacon_server;

    /// What a [`Recorder`] saw the chain actor be sent, in order.
    #[derive(Debug, PartialEq)]
    pub(crate) enum Seen {
        Block(u64),
        Envelope(H256, u64),
    }

    /// A chain actor stand-in that reports every block and envelope it gets,
    /// in one stream so their relative order is observable.
    pub(crate) struct Recorder(pub mpsc::UnboundedSender<Seen>);

    impl P2PToBlockChain for Recorder {
        fn new_block(
            &self,
            block: SignedBeaconBlock,
            _: BlockSource,
            _: BlockArrival,
        ) -> Result<(), ActorError> {
            let _ = self.0.send(Seen::Block(block.slot()));
            Ok(())
        }
        fn new_attestation(&self, _: SignedAttestation) -> Result<(), ActorError> {
            Ok(())
        }
        fn new_aggregated_attestation(
            &self,
            _: SignedAggregatedAttestation,
        ) -> Result<(), ActorError> {
            Ok(())
        }
        fn new_data_column_sidecars(&self, _: Vec<DataColumnSidecar>) -> Result<(), ActorError> {
            Ok(())
        }
        fn data_column_sidecars_awaiting_parent(
            &self,
            _: Vec<DataColumnSidecar>,
        ) -> Result<(), ActorError> {
            Ok(())
        }
        fn new_beacon_aggregate(
            &self,
            _: Box<SignedAggregateAndProof>,
            _: Vec<ValidatorIndex>,
            _: AggregateArrival,
        ) -> Result<(), ActorError> {
            Ok(())
        }
        fn new_execution_payload_envelope(
            &self,
            envelope: Box<SignedExecutionPayloadEnvelope>,
            _: BlockArrival,
        ) -> Result<(), ActorError> {
            let _ = self.0.send(Seen::Envelope(
                envelope.message.beacon_block_root,
                envelope.message.payload.slot_number,
            ));
            Ok(())
        }
    }

    pub(crate) fn envelope(slot: u64, byte: u8) -> SignedExecutionPayloadEnvelope {
        crate::beacon::encoding::test_support::envelope(H256::repeat_byte(byte), slot, H256::ZERO)
    }

    #[test]
    fn only_accept_and_queue_reach_the_chain_actor() {
        assert!(forwards(&Outcome::Accept));
        assert!(forwards(&Outcome::Queue(QueueReason::BlockUnknown)));
        assert!(!forwards(&Outcome::Ignore(IgnoreReason::Finalized)));
        assert!(!forwards(&Outcome::Reject(RejectReason::BadSignature)));
    }

    /// An envelope whose block this node has not seen is queued, so it reaches
    /// the actor, and a batch keeps the order it was given.
    #[tokio::test]
    async fn envelopes_for_unknown_blocks_are_forwarded_in_order() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let (sender, mut received) = mpsc::unbounded_channel();
        server.blockchain = Some(Arc::new(Recorder(sender)));

        check_and_forward(
            &server,
            vec![envelope(7, 1), envelope(8, 2), envelope(9, 3)],
        );

        for (slot, byte) in [(7, 1), (8, 2), (9, 3)] {
            assert_eq!(
                received.recv().await,
                Some(Seen::Envelope(H256::repeat_byte(byte), slot))
            );
        }
        drop(server);
        assert_eq!(received.recv().await, None);
    }
}
