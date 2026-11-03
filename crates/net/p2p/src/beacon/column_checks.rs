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
//! - sidecars the chain actor was told to hold, handed back once the block
//!   they wait on imported (`BlockChainToP2P::check_data_column_sidecars`): a
//!   fulu sidecar's parent, a gloas sidecar's own block.
//!
//! The sidecars are grouped by the block they belong to, and each group is
//! checked on one blocking thread, bounded by
//! [`P2PServer::column_check_permits`]. Unlike a gossip verdict, nothing here
//! has a deadline, so a group with no free permit waits for one rather than
//! being dropped.
//!
//! A group takes one permit, not one per sidecar, because the KZG proofs of
//! all its sidecars are verified in one batch: the batch is one unit of work
//! on one thread, so a permit per sidecar would count permits the group does
//! not use at the same time. The pool still bounds the blocking threads this
//! module occupies, at one per block in flight. A group's verdicts are
//! forwarded as soon as it finishes, so the chain actor can count a block's
//! columns toward availability without waiting for the rest of a range batch.

use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;

use ethlambda_network_api::P2PToBlockChainRef;
use ethlambda_state_transition::beacon::gossip::column::{
    self, ChainPrecheck, ChainVerdict, PendingKzg, SignatureMemo,
};
use ethlambda_state_transition::beacon::gossip::{IgnoreReason, Outcome};
use ethlambda_storage::Store;
use ethlambda_telemetry::BlockEvent;
use ethlambda_types::beacon::containers::DataColumnSidecar;
use ethlambda_types::beacon::primitives::{HashTreeRoot as _, Root};
use ethlambda_types::time::unix_now_ms;
use tracing::{error, warn};

use crate::{P2PServer, metrics};

/// How a batch of sidecars reached [`check_and_forward`], for the telemetry
/// rows (`docs/telemetry.md`).
#[derive(Debug, Clone, Copy)]
pub(crate) enum ColumnArrival {
    /// Sidecars that just reached this node.
    Received {
        /// The rows' `source`: how they reached this node.
        source: &'static str,
        /// When they arrived. For a by-root or by-range answer this is when
        /// the whole answer was delivered to the handler, so every sidecar in
        /// it shares one instant.
        at: Instant,
    },
    /// Sidecars judged to wait for their block, handed back once it imports:
    /// their arrival was written then, so only their validation is new.
    Recheck,
}

impl ColumnArrival {
    pub(crate) fn received(source: &'static str, at: Instant) -> Self {
        Self::Received { source, at }
    }

    fn source(self) -> &'static str {
        match self {
            Self::Received { source, .. } => source,
            Self::Recheck => "recheck",
        }
    }
}

/// One `block_events` row for `sidecar`: the one place its fields are named,
/// so the root (a header hash for a fulu sidecar) is computed per row built.
fn column_event(
    stage: &'static str,
    sidecar: &DataColumnSidecar,
    source: &'static str,
    at: Instant,
) -> BlockEvent {
    BlockEvent {
        stage,
        at,
        slot: sidecar.slot(),
        block_root: sidecar.block_root().0,
        source,
        verdict: None,
        column_index: Some(sidecar.index()),
    }
}

/// The rows of a sidecar that passed validation at `validated_at`: its arrival
/// (unless it is a re-check) and its validation. Gossip-accepted columns and
/// this node's own columns call this directly, as they need no check of their
/// own.
pub(crate) fn passed_rows(
    sidecar: &DataColumnSidecar,
    arrival: ColumnArrival,
    validated_at: Instant,
) -> Vec<BlockEvent> {
    let validated = column_event("column_validated", sidecar, arrival.source(), validated_at);
    match arrival {
        ColumnArrival::Received { at, .. } => vec![
            BlockEvent {
                stage: "column_recv",
                at,
                ..validated
            },
            validated,
        ],
        ColumnArrival::Recheck => vec![validated],
    }
}

/// The rows one checked sidecar writes (see [`check_and_forward`]): its
/// arrival unless already written, and its validation once kept. A dropped
/// sidecar writes none, as Silver records a column only once it passed
/// validation.
pub(crate) fn column_rows(
    sidecar: &DataColumnSidecar,
    arrival: ColumnArrival,
    verdict: ChainVerdict,
    checked_at: Instant,
) -> Vec<BlockEvent> {
    match verdict {
        ChainVerdict::Keep => passed_rows(sidecar, arrival, checked_at),
        ChainVerdict::AwaitParent => match arrival {
            ColumnArrival::Received { source, at } => {
                vec![column_event("column_recv", sidecar, source, at)]
            }
            ColumnArrival::Recheck => Vec::new(),
        },
        ChainVerdict::Drop(_) => Vec::new(),
    }
}

/// What one block's sidecars came to: the ones to store, the ones to park, and
/// the reason for each one dropped.
#[derive(Default)]
struct GroupVerdicts {
    keep: Vec<DataColumnSidecar>,
    awaiting_parent: Vec<DataColumnSidecar>,
    dropped: Vec<Outcome>,
}

impl GroupVerdicts {
    /// File `sidecar` under `verdict`, writing its `block_events` rows (see
    /// [`column_rows`]) at the moment its verdict is known: after its own
    /// checks for one settled early, after the group's KZG batch otherwise.
    fn record(
        &mut self,
        sidecar: DataColumnSidecar,
        verdict: ChainVerdict,
        arrival: ColumnArrival,
    ) {
        let checked_at = Instant::now();
        ethlambda_telemetry::emit(|| column_rows(&sidecar, arrival, verdict, checked_at));
        match verdict {
            ChainVerdict::Keep => self.keep.push(sidecar),
            ChainVerdict::AwaitParent => self.awaiting_parent.push(sidecar),
            ChainVerdict::Drop(outcome) => self.dropped.push(outcome),
        }
    }
}

/// The block a sidecar belongs to: a fulu sidecar's signed header's root, a
/// gloas sidecar's `beacon_block_root`.
fn block_of(sidecar: &DataColumnSidecar) -> Root {
    match sidecar {
        DataColumnSidecar::Fulu(sidecar) => sidecar.signed_block_header.message.hash_tree_root(),
        DataColumnSidecar::Gloas(sidecar) => sidecar.beacon_block_root,
    }
}

/// Group `sidecars` by block, in the order each block first appears.
fn group_by_block(sidecars: Vec<DataColumnSidecar>) -> Vec<Vec<DataColumnSidecar>> {
    let mut positions: HashMap<Root, usize> = HashMap::new();
    let mut groups: Vec<Vec<DataColumnSidecar>> = Vec::new();
    for sidecar in sidecars {
        let position = *positions.entry(block_of(&sidecar)).or_insert_with(|| {
            groups.push(Vec::new());
            groups.len() - 1
        });
        groups[position].push(sidecar);
    }
    groups
}

/// Judge every sidecar of one block: each one's checks that do not read the
/// cells, then the KZG proofs of the ones still standing, in one batch.
///
/// Each sidecar gets the verdict [`column::chain_checks_for`] would give it:
/// the proofs are the last rule on the chain path, so running the other rules
/// first and the proofs together changes nothing but how the proofs are paid
/// for, and a failed batch is re-run sidecar by sidecar.
fn judge_group(
    store: &Store,
    sidecars: Vec<DataColumnSidecar>,
    now_ms: u64,
    arrival: ColumnArrival,
) -> GroupVerdicts {
    let mut verdicts = GroupVerdicts::default();
    let mut pending: Vec<(DataColumnSidecar, PendingKzg)> = Vec::new();
    // The block's sidecars share a header, so its signature is verified once.
    let mut memo = SignatureMemo::default();
    for sidecar in sidecars {
        // A panic inside the checks (a `Store` read's `.expect()` on a DB
        // error, say) costs that one sidecar, which is what dropping it
        // would have done anyway.
        let precheck = catch_unwind(AssertUnwindSafe(|| {
            column::chain_precheck_for_with(store, &sidecar, now_ms, &mut memo)
        }));
        match precheck {
            Ok(ChainPrecheck::Settled(verdict)) => verdicts.record(sidecar, verdict, arrival),
            Ok(ChainPrecheck::Pending(kzg)) => pending.push((sidecar, kzg)),
            Err(_) => error!("A data column check panicked; dropping the sidecar"),
        }
    }
    if pending.is_empty() {
        return verdicts;
    }
    let items: Vec<_> = pending
        .iter()
        .map(|(sidecar, kzg)| (sidecar, kzg))
        .collect();
    let kzg_verdicts = column::kzg_verdicts(&items);
    for ((sidecar, _), verdict) in pending.into_iter().zip(kzg_verdicts) {
        verdicts.record(sidecar, verdict, arrival);
    }
    verdicts
}

/// Send the chain actor one group's results: the sidecars to store as one
/// batch, and the ones waiting on a block as another.
fn forward(blockchain: &P2PToBlockChainRef, verdicts: GroupVerdicts) {
    for outcome in verdicts.dropped {
        count_drop(outcome);
    }
    if !verdicts.keep.is_empty() {
        let _ = blockchain
            .new_data_column_sidecars(verdicts.keep)
            .inspect_err(|err| warn!(%err, "Failed to forward checked data column sidecars"));
    }
    if !verdicts.awaiting_parent.is_empty() {
        let _ = blockchain
            .data_column_sidecars_awaiting_parent(verdicts.awaiting_parent)
            .inspect_err(
                |err| warn!(%err, "Failed to forward data column sidecars awaiting a parent"),
            );
    }
}

/// Run the chain checks on `sidecars`, then send the chain actor the ones that
/// passed as one batch per block and the ones waiting on a block as another.
///
/// Returns at once: the checks run on tasks of their own, so the p2p actor
/// goes on handling swarm events while a range batch's KZG proofs are
/// verified. A block's sidecars are forwarded when that block's group
/// finishes, not when every group of the call has.
///
/// Each sidecar's `block_events` rows are written once its check is done, by
/// [`column_rows`]: after the check, so an already stored re-delivery writes
/// none, and off the p2p actor. A column delivered again while it waits for
/// its block, or two copies passing at once, write rows each, so rows are at
/// least once per column and stage: a reader takes the earliest.
pub(crate) fn check_and_forward(
    server: &P2PServer,
    sidecars: Vec<DataColumnSidecar>,
    arrival: ColumnArrival,
) {
    if sidecars.is_empty() {
        return;
    }
    let Some(blockchain) = server.blockchain.clone() else {
        return;
    };
    let store = server.store.clone();
    let permits = server.column_check_permits.clone();
    tokio::spawn(async move {
        for group in group_by_block(sidecars) {
            // The semaphore is never closed, so this only returns once a
            // permit is free.
            let waiting_since = std::time::Instant::now();
            let Ok(permit) = permits.clone().acquire_owned().await else {
                return;
            };
            metrics::observe_column_check_permit_wait("column_check", waiting_since.elapsed());
            let in_use = metrics::PoolInUse::new("column_check");
            let task = metrics::BlockingTask::new("column_check");
            let store = store.clone();
            let blockchain = blockchain.clone();
            tokio::spawn(async move {
                let checked = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    let _in_use = in_use;
                    let _run = task.start();
                    judge_group(&store, group, unix_now_ms(), arrival)
                })
                .await;
                match checked {
                    Ok(verdicts) => forward(&blockchain, verdicts),
                    // Tokio has already caught the panic; what the group
                    // held is lost, which is what dropping it would have
                    // done anyway.
                    Err(err) => error!(%err, "A data column check panicked; dropping the group"),
                }
            });
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
    use std::time::Duration;

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
    /// be held for its block, and one they refuse goes nowhere: neither reaches the batch
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
            ColumnArrival::Recheck,
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
    /// held for it, and one from a slot that has not started is dropped, so
    /// neither reaches the batch the chain actor stores unchecked.
    #[tokio::test]
    async fn a_gloas_sidecar_for_an_unknown_block_is_held_and_a_future_one_dropped() {
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

        check_and_forward(
            &server,
            vec![unknown_block.clone(), future],
            ColumnArrival::Recheck,
        );

        assert_eq!(
            received.recv().await,
            Some(Forwarded::AwaitingParent(vec![unknown_block]))
        );
        drop(server);
        assert_eq!(received.recv().await, None);
    }

    /// A call mixing blocks forwards each block's sidecars on their own: the
    /// chain actor hears about a block as soon as that block's group is done,
    /// and a block's sidecars arrive together.
    #[tokio::test]
    async fn each_block_of_a_mixed_call_is_forwarded_on_its_own() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let (sender, mut received) = mpsc::unbounded_channel();
        server.blockchain = Some(Arc::new(RecordingChain(sender)));

        // Two columns of one block (slot 5) and one of another (slot 6), all
        // with a parent the store has never seen, interleaved. A third block
        // (slot 7) is malformed and goes nowhere.
        let a0 = DataColumnSidecar::Fulu(valid_shaped_sidecar(5, 0));
        let b0 = DataColumnSidecar::Fulu(valid_shaped_sidecar(6, 0));
        let a1 = DataColumnSidecar::Fulu(valid_shaped_sidecar(5, 1));
        let mut malformed = valid_shaped_sidecar(7, 0);
        malformed.kzg_commitments = Default::default();

        check_and_forward(
            &server,
            vec![
                a0.clone(),
                b0.clone(),
                a1.clone(),
                DataColumnSidecar::Fulu(malformed),
            ],
            ColumnArrival::Recheck,
        );

        let mut batches = Vec::new();
        for _ in 0..2 {
            let Some(Forwarded::AwaitingParent(batch)) = received.recv().await else {
                panic!("expected a batch awaiting its parent");
            };
            batches.push(batch);
        }
        batches.sort_by_key(|batch| batch.len());
        assert_eq!(batches, vec![vec![b0], vec![a0, a1]]);
        drop(server);
        assert_eq!(received.recv().await, None);
    }

    #[test]
    fn sidecars_are_grouped_by_block_in_first_seen_order() {
        let a0 = DataColumnSidecar::Fulu(valid_shaped_sidecar(5, 0));
        let b0 = DataColumnSidecar::Fulu(valid_shaped_sidecar(6, 0));
        let a1 = DataColumnSidecar::Fulu(valid_shaped_sidecar(5, 1));
        let gloas_of = |byte| {
            DataColumnSidecar::Gloas(gloas::DataColumnSidecar {
                beacon_block_root: Root::repeat_byte(byte),
                ..Default::default()
            })
        };
        let (g1, g2, g1_again) = (gloas_of(1), gloas_of(2), gloas_of(1));

        let groups = group_by_block(vec![
            a0.clone(),
            b0.clone(),
            a1.clone(),
            g1.clone(),
            g2.clone(),
            g1_again.clone(),
        ]);

        assert_eq!(
            groups,
            vec![vec![a0, a1], vec![b0], vec![g1, g1_again], vec![g2]]
        );
    }

    fn sidecar_48() -> DataColumnSidecar {
        DataColumnSidecar::Gloas(gloas::DataColumnSidecar {
            index: 48,
            slot: 5,
            beacon_block_root: Root::repeat_byte(9),
            ..Default::default()
        })
    }

    /// Silver records a column only once it passed validation: one judged to
    /// wait for its block writes its arrival now and its validation when the
    /// recheck keeps it, and a dropped one (an already stored re-delivery
    /// included) writes none.
    #[test]
    fn a_column_writes_rows_only_once_judged_and_validation_only_once_it_passes() {
        let sidecar = sidecar_48();
        let arrived = Instant::now();
        let checked = arrived + Duration::from_millis(3);
        let fresh = ColumnArrival::received("by_root", arrived);
        let rows = |rows: Vec<BlockEvent>| {
            rows.into_iter()
                .map(|row| (row.stage, row.at))
                .collect::<Vec<_>>()
        };

        assert_eq!(
            rows(column_rows(&sidecar, fresh, ChainVerdict::Keep, checked)),
            [("column_recv", arrived), ("column_validated", checked)]
        );
        let awaiting = column_rows(&sidecar, fresh, ChainVerdict::AwaitParent, checked);
        assert_eq!(
            awaiting,
            [BlockEvent {
                stage: "column_recv",
                at: arrived,
                slot: 5,
                block_root: [9; 32],
                source: "by_root",
                verdict: None,
                column_index: Some(48),
            }]
        );
        let stored = ChainVerdict::Drop(Outcome::Ignore(IgnoreReason::AlreadyStored));
        assert!(column_rows(&sidecar, fresh, stored, checked).is_empty());
        assert_eq!(
            rows(column_rows(
                &sidecar,
                ColumnArrival::Recheck,
                ChainVerdict::Keep,
                checked
            )),
            [("column_validated", checked)]
        );
    }

    /// A fulu sidecar names its block by its header's root, which the row
    /// must carry.
    #[test]
    fn a_fulu_column_row_names_its_header_root() {
        use ethlambda_types::beacon::primitives::HashTreeRoot as _;

        let fulu = valid_shaped_sidecar(5, 3);
        let expected = fulu.signed_block_header.message.hash_tree_root();
        let sidecar = DataColumnSidecar::Fulu(fulu);

        let arrival = ColumnArrival::received("gossip", Instant::now());
        let event = passed_rows(&sidecar, arrival, Instant::now()).remove(0);
        assert_eq!(event.block_root, expected.0);
        assert_eq!(event.slot, 5);
        assert_eq!(event.column_index, Some(3));
    }

    #[test]
    fn a_column_row_names_its_block_slot_and_index() {
        let sidecar = sidecar_48();
        let at = Instant::now();

        let rows = passed_rows(&sidecar, ColumnArrival::received("by_root", at), at);
        let event = rows[0];
        assert_eq!(event.stage, "column_recv");
        assert_eq!(event.slot, 5);
        assert_eq!(event.block_root, [9; 32]);
        assert_eq!(event.column_index, Some(48));
        assert_eq!(event.source, "by_root");
        assert_eq!(event.at, at);
        assert_eq!(event.verdict, None);
    }
}
