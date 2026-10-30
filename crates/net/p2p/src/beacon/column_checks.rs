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

use ethlambda_network_api::P2PToBlockChainRef;
use ethlambda_state_transition::beacon::gossip::column::{
    self, ChainPrecheck, ChainVerdict, PendingKzg,
};
use ethlambda_state_transition::beacon::gossip::{IgnoreReason, Outcome};
use ethlambda_storage::Store;
use ethlambda_types::beacon::containers::DataColumnSidecar;
use ethlambda_types::beacon::primitives::{HashTreeRoot as _, Root};
use ethlambda_types::time::unix_now_ms;
use tracing::{error, warn};

use crate::{P2PServer, metrics};

/// What one block's sidecars came to: the ones to store, the ones to park, and
/// the reason for each one dropped.
#[derive(Default)]
struct GroupVerdicts {
    keep: Vec<DataColumnSidecar>,
    awaiting_parent: Vec<DataColumnSidecar>,
    dropped: Vec<Outcome>,
}

impl GroupVerdicts {
    fn record(&mut self, sidecar: DataColumnSidecar, verdict: ChainVerdict) {
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
fn judge_group(store: &Store, sidecars: Vec<DataColumnSidecar>, now_ms: u64) -> GroupVerdicts {
    let mut verdicts = GroupVerdicts::default();
    let mut pending: Vec<(DataColumnSidecar, PendingKzg)> = Vec::new();
    for sidecar in sidecars {
        // A panic inside the checks (a `Store` read's `.expect()` on a DB
        // error, say) costs that one sidecar, which is what dropping it
        // would have done anyway.
        let precheck = catch_unwind(AssertUnwindSafe(|| {
            column::chain_precheck_for(store, &sidecar, now_ms)
        }));
        match precheck {
            Ok(ChainPrecheck::Settled(verdict)) => verdicts.record(sidecar, verdict),
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
        verdicts.record(sidecar, verdict);
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
        for group in group_by_block(sidecars) {
            // The semaphore is never closed, so this only returns once a
            // permit is free.
            let Ok(permit) = permits.clone().acquire_owned().await else {
                return;
            };
            let store = store.clone();
            let blockchain = blockchain.clone();
            tokio::spawn(async move {
                let checked = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    judge_group(&store, group, unix_now_ms())
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
}
