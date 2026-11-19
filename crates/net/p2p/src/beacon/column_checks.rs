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
    /// Passed and was handed to the chain actor, or was already stored: the
    /// column is here.
    Delivered,
    /// Not judged, through no fault of the sender: parked until its block can
    /// judge it, dropped for a reason that is not the sender's (an `Ignore`),
    /// or never checked or never handed over, because this node had no chain
    /// actor to check it for or reach, its check panicked, or its task ended
    /// first.
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
/// [`ColumnVerdict`], in no particular order.
pub(crate) type Done = Box<dyn FnOnce(Vec<(u64, ColumnVerdict)>) + Send>;

/// The verdicts of one batch, handed to its [`Done`] when dropped: those
/// recorded, and every other sidecar of the batch as
/// [`ColumnVerdict::Undecided`].
///
/// Reported on drop rather than by a call at the end of the checks, so every
/// way out reports, a panic or a task ended early included: a lookup that
/// never hears back keeps its columns on the wire until it goes stale.
struct Verdicts {
    done: Option<Done>,
    /// Column indices of the batch with no verdict recorded yet.
    unjudged: Vec<u64>,
    recorded: Vec<(u64, ColumnVerdict)>,
}

impl Verdicts {
    fn new(done: Option<Done>, sidecars: &[DataColumnSidecar]) -> Self {
        let unjudged = sidecars.iter().map(DataColumnSidecar::index).collect();
        Self {
            done,
            unjudged,
            recorded: Vec::new(),
        }
    }

    fn record(&mut self, index: u64, verdict: ColumnVerdict) {
        if let Some(position) = self.unjudged.iter().position(|&left| left == index) {
            self.unjudged.swap_remove(position);
        }
        self.recorded.push((index, verdict));
    }

    /// Take back `indices`' delivery: the chain actor never got them.
    fn not_delivered(&mut self, indices: &[u64]) {
        for (index, verdict) in &mut self.recorded {
            if *verdict == ColumnVerdict::Delivered && indices.contains(index) {
                *verdict = ColumnVerdict::Undecided;
            }
        }
    }
}

impl Drop for Verdicts {
    fn drop(&mut self) {
        let Some(done) = self.done.take() else {
            return;
        };
        let mut verdicts = std::mem::take(&mut self.recorded);
        let unjudged = self.unjudged.drain(..);
        verdicts.extend(unjudged.map(|index| (index, ColumnVerdict::Undecided)));
        done(verdicts);
    }
}

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
/// `done` runs on every path ([`Verdicts`] reports when dropped), with a
/// sidecar that was never judged, or that passed but could not be handed to
/// the chain actor, reported as [`ColumnVerdict::Undecided`].
pub(crate) fn check_and_forward_then(
    server: &P2PServer,
    sidecars: Vec<DataColumnSidecar>,
    done: Option<Done>,
) {
    let mut verdicts = Verdicts::new(done, &sidecars);
    let Some(blockchain) = server.blockchain.clone().filter(|_| !sidecars.is_empty()) else {
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
                break;
            };
            let store = store.clone();
            let check = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let verdict = column::chain_checks_for(&store, &sidecar, unix_now_ms());
                (sidecar, verdict)
            });
            checks.push(check);
        }

        let mut keep = Vec::new();
        let mut kept = Vec::new();
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
            verdicts.record(sidecar.index(), ColumnVerdict::from(&verdict));
            match verdict {
                ChainVerdict::Keep => {
                    kept.push(sidecar.index());
                    keep.push(sidecar);
                }
                ChainVerdict::AwaitParent => awaiting_parent.push(sidecar),
                ChainVerdict::Drop(outcome) => count_drop(outcome),
            }
        }

        if !keep.is_empty() {
            let _ = blockchain
                .new_data_column_sidecars(keep)
                .inspect_err(|err| {
                    warn!(%err, "Failed to forward checked data column sidecars");
                    verdicts.not_delivered(&kept);
                });
        }
        if !awaiting_parent.is_empty() {
            let _ = blockchain
                .data_column_sidecars_awaiting_parent(awaiting_parent)
                .inspect_err(
                    |err| warn!(%err, "Failed to forward data column sidecars awaiting a parent"),
                );
        }
        // `verdicts` reports as it drops here.
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

    /// Verdicts reported through `done`, for the guard tests below.
    fn reporting() -> (
        Option<Done>,
        mpsc::UnboundedReceiver<Vec<(u64, ColumnVerdict)>>,
    ) {
        let (sender, received) = mpsc::unbounded_channel();
        let done: Done = Box::new(move |verdicts| {
            let _ = sender.send(verdicts);
        });
        (Some(done), received)
    }

    /// A task that ends before judging every sidecar (a panic outside the
    /// blocking checks, or a runtime shutting down) still settles the lookup,
    /// with what it did not judge as undecided.
    #[test]
    fn verdicts_dropped_early_report_the_rest_as_undecided() {
        let (done, mut reported) = reporting();
        let batch = [
            DataColumnSidecar::Fulu(valid_shaped_sidecar(5, 3)),
            DataColumnSidecar::Fulu(valid_shaped_sidecar(5, 4)),
        ];
        let mut verdicts = Verdicts::new(done, &batch);
        verdicts.record(3, ColumnVerdict::Delivered);
        drop(verdicts);

        assert_eq!(
            reported.try_recv().ok(),
            Some(vec![
                (3, ColumnVerdict::Delivered),
                (4, ColumnVerdict::Undecided)
            ])
        );
    }

    /// A sidecar that passed but never reached the chain actor (its mailbox
    /// closed) is not delivered: the lookup asks for it again.
    #[test]
    fn a_kept_sidecar_the_chain_never_got_is_not_delivered() {
        let (done, mut reported) = reporting();
        let batch = [
            DataColumnSidecar::Fulu(valid_shaped_sidecar(5, 5)),
            DataColumnSidecar::Fulu(valid_shaped_sidecar(5, 6)),
        ];
        let mut verdicts = Verdicts::new(done, &batch);
        verdicts.record(5, ColumnVerdict::Delivered);
        verdicts.record(6, ColumnVerdict::Delivered);
        verdicts.not_delivered(&[5]);
        drop(verdicts);

        assert_eq!(
            reported.try_recv().ok(),
            Some(vec![
                (5, ColumnVerdict::Undecided),
                (6, ColumnVerdict::Delivered)
            ])
        );
    }
}
