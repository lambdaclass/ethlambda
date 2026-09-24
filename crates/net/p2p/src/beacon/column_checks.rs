//! The chain checks, run on every data column sidecar gossip did not accept,
//! before the chain actor gets it.
//!
//! The chain actor keeps a sidecar without checking it (only debug builds
//! check again), so a sidecar reaches it by one of two routes: gossip accepted
//! it, having run every rule already, or it came through here. What comes
//! through here:
//!
//! - a gossiped sidecar reported `Queue` or `Ignore(Overloaded)`, whose
//!   stateful checks stopped early or never ran;
//! - every `DataColumnsByRoot` and `DataColumnsByRange` answer;
//! - sidecars the chain actor had parked, handed back once their parent
//!   imported (`BlockChainToP2P::check_data_column_sidecars`).
//!
//! Each sidecar is checked on a blocking thread, bounded by
//! [`P2PServer::column_check_permits`]. Unlike a gossip verdict, nothing here
//! has a deadline, so a sidecar with no free permit waits for one rather than
//! being dropped.

use ethlambda_state_transition::beacon::gossip::column::{self, ChainVerdict};
use ethlambda_state_transition::beacon::gossip::{IgnoreReason, Outcome};
use ethlambda_types::beacon::containers::fulu::DataColumnSidecar;
use ethlambda_types::time::unix_now_ms;
use tracing::{error, warn};

use crate::{P2PServer, metrics};

/// Run the chain checks on `sidecars`, then send the chain actor the ones that
/// passed as one batch and the ones waiting on a parent as another.
///
/// Returns at once: the checks run on a task of their own, so the p2p actor
/// goes on handling swarm events while a range batch's KZG proofs are
/// verified.
pub(crate) fn check_and_forward(server: &P2PServer, sidecars: Vec<DataColumnSidecar>) {
    if sidecars.is_empty() {
        return;
    }
    let Some(blockchain) = server.blockchain.clone() else {
        return;
    };
    let store = server.store.clone();
    let permits = server.column_check_permits.clone();
    tokio::spawn(async move {
        let mut checks = Vec::with_capacity(sidecars.len());
        for sidecar in sidecars {
            // The semaphore is never closed, so this only returns once a
            // permit is free.
            let Ok(permit) = permits.clone().acquire_owned().await else {
                return;
            };
            let store = store.clone();
            checks.push(tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let verdict = column::chain_checks(&store, &sidecar, unix_now_ms());
                (sidecar, verdict)
            }));
        }

        let mut keep = Vec::new();
        let mut awaiting_parent = Vec::new();
        for check in checks {
            // A panic inside the checks (a `Store` read's `.expect()` on a DB
            // error, say) costs that one sidecar, which is what dropping it
            // would have done anyway. Tokio has already caught it.
            let (sidecar, verdict) = match check.await {
                Ok(checked) => checked,
                Err(err) => {
                    error!(%err, "A data column check panicked; dropping the sidecar");
                    continue;
                }
            };
            match verdict {
                ChainVerdict::Keep => keep.push(sidecar),
                ChainVerdict::AwaitParent => awaiting_parent.push(sidecar),
                ChainVerdict::Drop(outcome) => count_drop(outcome),
            }
        }

        if !keep.is_empty() {
            let _ = blockchain
                .new_data_column_sidecars(keep)
                .inspect_err(|err| warn!(%err, "Failed to forward checked data column sidecars"));
        }
        if !awaiting_parent.is_empty() {
            let _ = blockchain
                .data_column_sidecars_awaiting_parent(awaiting_parent)
                .inspect_err(
                    |err| warn!(%err, "Failed to forward data column sidecars awaiting a parent"),
                );
        }
    });
}

/// Count a dropped sidecar under its reason.
///
/// An already stored one is not counted: consecutive range batches ask for
/// overlapping spans of columns, so re-deliveries are routine, and they are
/// duplicates rather than rejections.
fn count_drop(outcome: Outcome) {
    if outcome == Outcome::Ignore(IgnoreReason::AlreadyStored) {
        return;
    }
    let (_, reason) = outcome.labels();
    metrics::inc_data_column_rejected(reason);
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ethlambda_network_api::{BlockArrival, BlockSource, P2PToBlockChain};
    use ethlambda_types::attestation::{SignedAggregatedAttestation, SignedAttestation};
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::containers::SignedBeaconBlock;
    use spawned_concurrency::error::ActorError;
    use tokio::sync::mpsc;

    use super::*;
    use crate::test_support::{unconnected_beacon_server, valid_shaped_sidecar};

    /// What [`check_and_forward`] sent the chain actor.
    #[derive(Debug, PartialEq)]
    enum Forwarded {
        Checked(Vec<DataColumnSidecar>),
        AwaitingParent(Vec<DataColumnSidecar>),
    }

    /// A chain actor stand-in that reports every sidecar batch it receives.
    struct RecordingChain(mpsc::UnboundedSender<Forwarded>);

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
            sidecars: Vec<DataColumnSidecar>,
        ) -> Result<(), ActorError> {
            let _ = self.0.send(Forwarded::Checked(sidecars));
            Ok(())
        }
        fn data_column_sidecars_awaiting_parent(
            &self,
            sidecars: Vec<DataColumnSidecar>,
        ) -> Result<(), ActorError> {
            let _ = self.0.send(Forwarded::AwaitingParent(sidecars));
            Ok(())
        }
    }

    /// A sidecar the checks cannot judge yet goes back to the chain actor to
    /// be parked, and one they refuse goes nowhere: neither reaches the batch
    /// the chain actor stores unchecked.
    #[tokio::test]
    async fn only_what_passes_is_forwarded_as_checked() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let (sender, mut received) = mpsc::unbounded_channel();
        server.blockchain = Some(Arc::new(RecordingChain(sender)));

        // Nothing in the store is its parent.
        let orphan = valid_shaped_sidecar(5, 0);
        let mut malformed = valid_shaped_sidecar(5, 1);
        malformed.kzg_commitments = Default::default();

        check_and_forward(&server, vec![orphan.clone(), malformed]);

        assert_eq!(
            received.recv().await,
            Some(Forwarded::AwaitingParent(vec![orphan]))
        );
        // The task sends at most one message per kind and has now finished,
        // so the channel closes with nothing else in it.
        drop(server);
        assert_eq!(received.recv().await, None);
    }
}
