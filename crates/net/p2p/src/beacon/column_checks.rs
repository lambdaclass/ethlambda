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
//! - sidecars the chain actor had parked, handed back once the block they
//!   wait on imported (`BlockChainToP2P::check_data_column_sidecars`): a fulu
//!   sidecar's parent, a gloas sidecar's own block.
//!
//! Each sidecar is checked on a blocking thread, bounded by
//! [`P2PServer::column_check_permits`]. Unlike a gossip verdict, nothing here
//! has a deadline, so a sidecar with no free permit waits for one rather than
//! being dropped.

use ethlambda_state_transition::beacon::gossip::column::{self, ChainVerdict};
use ethlambda_state_transition::beacon::gossip::{IgnoreReason, Outcome};
use ethlambda_types::beacon::containers::DataColumnSidecar;
use ethlambda_types::time::unix_now_ms;
use tracing::{error, warn};

use crate::{P2PServer, metrics};

/// What the checks made of one fetched sidecar, as the lookup that asked for
/// it needs to know: whether its column is now here, and whether the peer that
/// sent it is to blame if not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ColumnVerdict {
    /// Passed and went to the chain actor, or was already stored: the column
    /// is here.
    Delivered,
    /// Not judged, through no fault of the sender: parked until its block can
    /// judge it, dropped for a reason that is not the sender's (an `Ignore`),
    /// or never checked, because this node had no chain actor to check it for
    /// or its check panicked.
    Undecided,
    /// Refused as invalid: the sender sent something it should not have.
    Rejected,
}

impl From<&ChainVerdict> for ColumnVerdict {
    fn from(verdict: &ChainVerdict) -> Self {
        match verdict {
            ChainVerdict::Keep
            | ChainVerdict::Drop(Outcome::Ignore(IgnoreReason::AlreadyStored)) => Self::Delivered,
            ChainVerdict::Drop(Outcome::Reject(_)) => Self::Rejected,
            ChainVerdict::AwaitParent | ChainVerdict::Drop(_) => Self::Undecided,
        }
    }
}

/// A completion callback: each sidecar's column index with its
/// [`ColumnVerdict`].
pub(crate) type Done = Box<dyn FnOnce(Vec<(u64, ColumnVerdict)>) + Send>;

/// Run the chain checks on `sidecars`, then send the chain actor the ones that
/// passed as one batch and the ones waiting on a block as another.
///
/// Returns at once: the checks run on a task of their own, so the p2p actor
/// goes on handling swarm events while a range batch's KZG proofs are
/// verified.
pub(crate) fn check_and_forward(server: &P2PServer, sidecars: Vec<DataColumnSidecar>) {
    check_and_forward_then(server, sidecars, None);
}

/// [`check_and_forward`], then `done` with every sidecar's verdict, once the
/// ones that passed have been handed to the chain actor.
///
/// This is how a `DataColumnsByRoot` lookup settles on what passed rather than
/// on what a peer sent: a sidecar with the right root and index can still
/// carry bad cells or proofs, and a gloas one carries no signature at all.
/// `done` runs on every path, with a sidecar that was never judged reported as
/// [`ColumnVerdict::Undecided`]: a lookup left waiting on a verdict that never
/// comes would keep its columns covered until the lookup goes stale.
pub(crate) fn check_and_forward_then(
    server: &P2PServer,
    sidecars: Vec<DataColumnSidecar>,
    done: Option<Done>,
) {
    let run_done = |done: Option<Done>, verdicts: Vec<(u64, ColumnVerdict)>| {
        if let Some(done) = done {
            done(verdicts);
        }
    };
    let blockchain = match server.blockchain.clone() {
        Some(blockchain) if !sidecars.is_empty() => blockchain,
        _ => {
            run_done(done, undecided(&sidecars));
            return;
        }
    };
    let store = server.store.clone();
    let permits = server.column_check_permits.clone();
    tokio::spawn(async move {
        let mut checks = Vec::with_capacity(sidecars.len());
        let mut verdicts = Vec::with_capacity(sidecars.len());
        let mut sidecars = sidecars.into_iter();
        while let Some(sidecar) = sidecars.next() {
            // The semaphore is never closed, so this only returns once a
            // permit is free.
            let Ok(permit) = permits.clone().acquire_owned().await else {
                verdicts.push((sidecar.index(), ColumnVerdict::Undecided));
                verdicts.extend(undecided(sidecars.as_slice()));
                break;
            };
            let store = store.clone();
            let index = sidecar.index();
            let check = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let verdict = column::chain_checks_for(&store, &sidecar, unix_now_ms());
                (sidecar, verdict)
            });
            checks.push((index, check));
        }

        let mut keep = Vec::new();
        let mut awaiting_parent = Vec::new();
        for (index, check) in checks {
            // A panic inside the checks (a `Store` read's `.expect()` on a DB
            // error, say) costs that one sidecar, which is what dropping it
            // would have done anyway. Tokio has already caught it.
            let (sidecar, verdict) = match check.await {
                Ok(checked) => checked,
                Err(err) => {
                    error!(%err, "A data column check panicked; dropping the sidecar");
                    verdicts.push((index, ColumnVerdict::Undecided));
                    continue;
                }
            };
            verdicts.push((index, ColumnVerdict::from(&verdict)));
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
        run_done(done, verdicts);
    });
}

/// Every sidecar of `sidecars` as [`ColumnVerdict::Undecided`].
fn undecided(sidecars: &[DataColumnSidecar]) -> Vec<(u64, ColumnVerdict)> {
    sidecars
        .iter()
        .map(|sidecar| (sidecar.index(), ColumnVerdict::Undecided))
        .collect()
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
pub(crate) mod tests {
    use std::sync::Arc;

    use ethlambda_network_api::{
        AggregateArrival, BlockAnnouncement, BlockArrival, BlockSource, P2PToBlockChain,
    };
    use ethlambda_types::attestation::{SignedAggregatedAttestation, SignedAttestation};
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::containers::{SignedAggregateAndProof, SignedBeaconBlock, gloas};
    use ethlambda_types::beacon::primitives::{Root, ValidatorIndex};
    use spawned_concurrency::error::ActorError;
    use tokio::sync::mpsc;

    use super::*;
    use crate::test_support::{unconnected_beacon_server, valid_shaped_sidecar};

    /// What [`check_and_forward`] sent the chain actor.
    #[derive(Debug, PartialEq)]
    pub(crate) enum Forwarded {
        Checked(Vec<DataColumnSidecar>),
        AwaitingParent(Vec<DataColumnSidecar>),
    }

    /// A chain actor stand-in that reports every sidecar batch it receives.
    pub(crate) struct RecordingChain(pub(crate) mpsc::UnboundedSender<Forwarded>);

    impl P2PToBlockChain for RecordingChain {
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
            _envelope: Box<
                ethlambda_types::beacon::containers::gloas::SignedExecutionPayloadEnvelope,
            >,
            _arrival: BlockArrival,
        ) -> Result<(), ActorError> {
            Ok(())
        }
        fn new_payload_attestation_message(
            &self,
            _message: ethlambda_types::beacon::containers::gloas::PayloadAttestationMessage,
            _arrival: BlockArrival,
        ) -> Result<(), ActorError> {
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

        check_and_forward(
            &server,
            vec![
                DataColumnSidecar::Fulu(orphan.clone()),
                DataColumnSidecar::Fulu(malformed),
            ],
        );

        assert_eq!(
            received.recv().await,
            Some(Forwarded::AwaitingParent(vec![DataColumnSidecar::Fulu(
                orphan
            )]))
        );
        // The task sends at most one message per kind and has now finished,
        // so the channel closes with nothing else in it.
        drop(server);
        assert_eq!(received.recv().await, None);
    }

    /// A gloas sidecar is judged against its own block, not a parent: one
    /// whose block this node has not seen goes back to the chain actor to be
    /// parked, and one from a slot that has not started is dropped, so neither
    /// reaches the batch the chain actor stores unchecked.
    #[tokio::test]
    async fn a_gloas_sidecar_for_an_unknown_block_is_parked_and_a_future_one_dropped() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let (sender, mut received) = mpsc::unbounded_channel();
        server.blockchain = Some(Arc::new(RecordingChain(sender)));

        let unknown_block = DataColumnSidecar::Gloas(gloas::DataColumnSidecar {
            index: 0,
            slot: 5,
            beacon_block_root: Root::repeat_byte(9),
            ..Default::default()
        });
        let future = DataColumnSidecar::Gloas(gloas::DataColumnSidecar {
            index: 1,
            slot: u64::MAX / 2,
            beacon_block_root: Root::repeat_byte(9),
            ..Default::default()
        });

        check_and_forward(&server, vec![unknown_block.clone(), future]);

        assert_eq!(
            received.recv().await,
            Some(Forwarded::AwaitingParent(vec![unknown_block]))
        );
        drop(server);
        assert_eq!(received.recv().await, None);
    }

    /// The completion callback hears every sidecar's verdict: one already
    /// stored is here, a malformed one is its sender's fault, and one waiting
    /// on its parent is neither.
    #[tokio::test]
    async fn the_callback_reports_what_the_checks_made_of_each_sidecar() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let (sender, _received) = mpsc::unbounded_channel();
        server.blockchain = Some(Arc::new(RecordingChain(sender)));

        let stored = DataColumnSidecar::Fulu(valid_shaped_sidecar(5, 0));
        server.store.put_data_column(&stored).expect("stored");
        let mut malformed = valid_shaped_sidecar(5, 1);
        malformed.kzg_commitments = Default::default();
        let orphan = valid_shaped_sidecar(5, 2);

        let (verdicts, mut reported) = mpsc::unbounded_channel();
        let done: Done = Box::new(move |checked| {
            let _ = verdicts.send(checked);
        });
        let sidecars = vec![
            stored,
            DataColumnSidecar::Fulu(malformed),
            DataColumnSidecar::Fulu(orphan),
        ];
        check_and_forward_then(&server, sidecars, Some(done));

        assert_eq!(
            reported.recv().await,
            Some(vec![
                (0, ColumnVerdict::Delivered),
                (1, ColumnVerdict::Rejected),
                (2, ColumnVerdict::Undecided),
            ])
        );
    }

    /// With no chain actor to check for, the callback still runs, so a lookup
    /// waiting on it is not left with its columns on the wire.
    #[tokio::test]
    async fn the_callback_runs_when_nothing_can_be_checked() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let (verdicts, mut reported) = mpsc::unbounded_channel();
        let done: Done = Box::new(move |checked| {
            let _ = verdicts.send(checked);
        });

        let sidecar = DataColumnSidecar::Fulu(valid_shaped_sidecar(5, 3));
        check_and_forward_then(&server, vec![sidecar], Some(done));

        assert_eq!(
            reported.recv().await,
            Some(vec![(3, ColumnVerdict::Undecided)])
        );
    }
}
