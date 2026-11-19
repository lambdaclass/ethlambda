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
//! The sidecars of one call are grouped by the block they belong to, each
//! `(block, index)` once ([`group_by_block`]), and each group is checked in
//! two stages on blocking threads, bounded by
//! [`P2PServer::column_check_permits`]:
//!
//! 1. Every rule before the KZG proofs, sidecar by sidecar on one thread,
//!    through one [`ChainPrechecks`], so the rules that read only what the
//!    block's sidecars share (the signed header's, or the gloas block lookup)
//!    run once for the group. The sidecars this settles, parked or dropped,
//!    are forwarded as soon as it finishes.
//! 2. The KZG proofs of the sidecars still standing, in sub-batches of at most
//!    [`KZG_BATCH_COLUMNS`] columns, each one `verify_cell_kzg_proof_batch`
//!    call on a thread of its own. The first runs on the permit the group's
//!    prechecks held; each further one waits for a permit of its own, so a
//!    block with many columns spreads over the free permits rather than
//!    queueing on one thread. Once every sub-batch is back, the sidecars kept
//!    go to the chain actor as one batch, so it can count a block's columns
//!    toward availability without waiting for the rest of a range answer.
//!
//! A permit is held for one group's prechecks and first sub-batch, or for
//! one further sub-batch. The proofs' share of a hold is bounded by
//! [`KZG_BATCH_COLUMNS`], not by how many columns the block has. The
//! prechecks' share is not bounded that way: they take the group's sidecars in
//! turn, one header judgment (a state read, and past the lookahead a state
//! advance) plus a check per sidecar, and how long that holds a permit on a
//! live node is unmeasured. Nothing awaits a permit while it holds one, so
//! groups and sub-batches cannot deadlock the pool between them. The pool is
//! shared with the envelope checks (`envelope_checks.rs`, one permit per
//! envelope), and tokio serves waiting requests in arrival order, so an
//! envelope waits behind only the requests queued before it.
//!
//! Unlike a gossip verdict, nothing here has a deadline, so a group or
//! sub-batch with no free permit waits for one rather than being dropped.
//! Each call runs on one task, which takes a permit per group in turn, and
//! each group on a task of its own until its last sub-batch is back. A group
//! task waiting for a sub-batch permit holds none, so the group tasks alive at
//! once are bounded by the groups of the calls in flight, whose sidecars are
//! in memory already, rather than by the pool.

use std::collections::{HashMap, HashSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use ethlambda_network_api::P2PToBlockChainRef;
use ethlambda_state_transition::beacon::gossip::column::{
    self, ChainPrechecks, ChainVerdict, PendingKzg,
};
use ethlambda_state_transition::beacon::gossip::{IgnoreReason, Outcome};
use ethlambda_storage::Store;
use ethlambda_types::beacon::containers::DataColumnSidecar;
use ethlambda_types::beacon::primitives::Root;
use ethlambda_types::time::unix_now_ms;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{debug, error, warn};

use crate::{P2PServer, metrics};

/// The most columns one KZG batch verifies. A block's columns past this are
/// split into near-equal sub-batches, each on a permit of its own.
///
/// One batch costs about 3 ms plus 0.55 ms per column (9 blobs,
/// `bench_kzg_batch_against_separate_calls`: one column 3.2 ms, 8 columns
/// 7.9 ms, 16 columns 12.6 ms, 128 columns 73 ms, on one core). Computed from
/// those, at 16: the 8 columns a node samples are one batch, a third of the CPU
/// of eight separate checks; a supernode's 128 are 8 batches, about 13 ms of
/// wall-clock with 8 permits free where one batch takes 73 ms; and a failed
/// batch's one-by-one re-check covers 16 columns at most.
const KZG_BATCH_COLUMNS: usize = 16;

/// A sidecar every rule before the KZG proofs passed, with what its proofs
/// are checked against.
type Pending = (DataColumnSidecar, PendingKzg);

/// What some of one block's sidecars came to: the ones to store, the ones to
/// park, and the reason for each one dropped.
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

    fn merge(&mut self, other: GroupVerdicts) {
        self.keep.extend(other.keep);
        self.awaiting_parent.extend(other.awaiting_parent);
        self.dropped.extend(other.dropped);
    }
}

/// Group `sidecars` by block, in the order each block first appears, keeping
/// only the first sidecar of each `(block, index)`. Returns the groups and how
/// many repeats were left out.
///
/// The repeats are what bound a group: a block has `NUMBER_OF_COLUMNS`
/// columns, and the checks refuse an index past that before the KZG stage, so
/// no group sends more than `NUMBER_OF_COLUMNS` sidecars to it, however many
/// copies a peer's answer carries (a range answer may hold 16,384). Nothing
/// else would catch a repeat within one call: the answer filters match on
/// block and index, not on repeats of them, and `AlreadyStored` cannot fire
/// before the group is done. The first copy is the one kept, as the chain
/// actor's own parking keeps the first (`queue_sidecar_awaiting_parent`), and
/// the repeats are not judged even when the first copy fails its checks and a
/// later one would pass: an honest answer never repeats a column, and judging
/// copies in turn until one passes is the cost this bounds. Every caller hands
/// over one source's sidecars (one peer's answer, one gossip message, the
/// parked set of one block, this node's own), so a repeat is that source's.
fn group_by_block(sidecars: Vec<DataColumnSidecar>) -> (Vec<Vec<DataColumnSidecar>>, usize) {
    let mut positions: HashMap<Root, usize> = HashMap::new();
    let mut seen: HashSet<(Root, u64)> = HashSet::new();
    let mut groups: Vec<Vec<DataColumnSidecar>> = Vec::new();
    let mut repeats = 0;
    for sidecar in sidecars {
        let block = sidecar.block_root();
        if !seen.insert((block, sidecar.index())) {
            repeats += 1;
            continue;
        }
        let position = *positions.entry(block).or_insert_with(|| {
            groups.push(Vec::new());
            groups.len() - 1
        });
        groups[position].push(sidecar);
    }
    (groups, repeats)
}

/// Split `items` into the fewest sub-batches of at most [`KZG_BATCH_COLUMNS`],
/// in order, no two differing in size by more than one.
fn sub_batches<T>(items: Vec<T>) -> Vec<Vec<T>> {
    let count = items.len().div_ceil(KZG_BATCH_COLUMNS);
    if count == 0 {
        return Vec::new();
    }
    // The first `longer` sub-batches take one item more than the rest.
    let (base, longer) = (items.len() / count, items.len() % count);
    let mut items = items.into_iter();
    (0..count)
        .map(|batch| {
            let size = base + usize::from(batch < longer);
            items.by_ref().take(size).collect()
        })
        .collect()
}

/// The first stage: every rule of one block's sidecars that does not read the
/// cells. Returns what those rules settled and the sidecars whose KZG proofs
/// decide.
///
/// Each sidecar gets the verdict [`column::chain_checks_for`] would give it:
/// the proofs are the last rule on the chain path, so running the other rules
/// first and the proofs afterwards, batched, changes nothing but how the
/// proofs are paid for.
fn precheck_group(
    store: &Store,
    sidecars: Vec<DataColumnSidecar>,
    now_ms: u64,
) -> (GroupVerdicts, Vec<Pending>) {
    let mut settled = GroupVerdicts::default();
    let mut pending = Vec::new();
    let mut prechecks = ChainPrechecks::new(store, now_ms);
    for sidecar in sidecars {
        // A panic inside the checks (one of the `Store` reads that still
        // `.expect()` on a DB error, say) costs that one sidecar, dropped and
        // counted as `internal`. `ChainPrechecks` keeps an answer only once it
        // is complete, so the next sidecar works it out again. The
        // parent-state read returns its error instead, and the checks drop the
        // sidecar for it as `internal` without unwinding, remembering nothing
        // either.
        let precheck = catch_unwind(AssertUnwindSafe(|| prechecks.check(&sidecar)));
        match precheck {
            Ok(Ok(kzg)) => pending.push((sidecar, kzg)),
            Ok(Err(verdict)) => settled.record(sidecar, verdict),
            Err(_) => {
                error!("A data column check panicked; dropping the sidecar");
                let internal = ChainVerdict::Drop(Outcome::Ignore(IgnoreReason::Internal));
                settled.record(sidecar, internal);
            }
        }
    }
    (settled, pending)
}

/// The second stage, for one sub-batch: its sidecars' KZG proofs in one
/// batch, each re-verified alone if the batch fails ([`column::kzg_verdicts`]).
fn verify_batch(batch: Vec<Pending>) -> GroupVerdicts {
    let items: Vec<_> = batch.iter().map(|(sidecar, kzg)| (sidecar, kzg)).collect();
    let kzg_verdicts = column::kzg_verdicts(&items);
    let mut verdicts = GroupVerdicts::default();
    for ((sidecar, _), verdict) in batch.into_iter().zip(kzg_verdicts) {
        verdicts.record(sidecar, verdict);
    }
    verdicts
}

/// Check one block's sidecars, `permit` already taken for them, and forward
/// what they come to: the parked and the dropped once the prechecks are done,
/// the kept once every sub-batch is.
async fn check_group(
    store: Store,
    blockchain: P2PToBlockChainRef,
    permits: Arc<Semaphore>,
    group: Vec<DataColumnSidecar>,
    permit: OwnedSemaphorePermit,
) {
    let group_size = group.len();
    let prechecked =
        tokio::task::spawn_blocking(move || precheck_group(&store, group, unix_now_ms())).await;
    let (settled, pending) = match prechecked {
        Ok(prechecked) => prechecked,
        // Tokio has already caught the panic. A sidecar's own checks catch
        // theirs, so this one came from outside them, and the whole group is
        // lost: none of it is forwarded, and all of it is counted as
        // `internal`.
        Err(err) => {
            error!(%err, lost = group_size, "A data column precheck panicked; dropping the group");
            count_drops(Outcome::Ignore(IgnoreReason::Internal), group_size);
            return;
        }
    };
    // Nothing the proofs say changes these, so they go now: a panic in a KZG
    // batch below cannot cost them.
    forward(&blockchain, settled);

    let mut own_permit = Some(permit);
    let mut batches = Vec::new();
    let mut remaining = sub_batches(pending).into_iter();
    while let Some(batch) = remaining.next() {
        // The group's own permit carries the first sub-batch. Each further one
        // waits for a permit of its own, and the group holds none while it
        // waits, the first having moved into its batch.
        let permit = match own_permit.take() {
            Some(permit) => permit,
            None => match permits.clone().acquire_owned().await {
                Ok(permit) => permit,
                // The semaphore is never closed, so this does not happen
                // today. Should it ever, the sidecars not yet sent to a batch
                // are lost, and say so rather than vanish.
                Err(_) => {
                    let lost =
                        batch.len() + remaining.by_ref().map(|rest| rest.len()).sum::<usize>();
                    error!(
                        lost,
                        "The column check permits are closed; dropping a block's unverified sidecars"
                    );
                    count_drops(Outcome::Ignore(IgnoreReason::Internal), lost);
                    break;
                }
            },
        };
        let size = batch.len();
        let verified = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            verify_batch(batch)
        });
        batches.push((size, verified));
    }
    let mut verdicts = GroupVerdicts::default();
    for (size, batch) in batches {
        match batch.await {
            Ok(batch) => verdicts.merge(batch),
            // Tokio has already caught the panic. That sub-batch's sidecars
            // are lost, not forwarded and counted as `internal`; the group's
            // other sub-batches and everything settled above are not.
            Err(err) => {
                error!(%err, lost = size, "A data column KZG batch panicked; dropping its sidecars");
                count_drops(Outcome::Ignore(IgnoreReason::Internal), size);
            }
        }
    }
    forward(&blockchain, verdicts);
}

/// Send the chain actor some of one block's verdicts: the sidecars to store as
/// one batch, and the ones waiting on a block as another, and count the drops.
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

/// Run the chain checks on `sidecars`, then send the chain actor, per block,
/// the ones waiting on a block as one batch and the ones that passed as
/// another.
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
        let (groups, repeats) = group_by_block(sidecars);
        if repeats > 0 {
            debug!(
                repeats,
                "Dropping data column sidecars that repeat a block and index of the same call"
            );
            count_drops(Outcome::Ignore(IgnoreReason::AlreadySeen), repeats);
        }
        for group in groups {
            // The semaphore is never closed, so this only returns once a
            // permit is free.
            let Ok(permit) = permits.clone().acquire_owned().await else {
                return;
            };
            tokio::spawn(check_group(
                store.clone(),
                blockchain.clone(),
                permits.clone(),
                group,
                permit,
            ));
        }
    });
}

/// Count a dropped sidecar under its reason.
fn count_drop(outcome: Outcome) {
    count_drops(outcome, 1);
}

/// Count `count` sidecars dropped for the same reason, in one increment.
///
/// An already stored one is not counted: consecutive range batches ask for
/// overlapping spans of columns, so re-deliveries are routine, and they are
/// duplicates rather than rejections. A repeat within one call is counted
/// (`already_seen`): an honest peer never sends one. So is every sidecar a
/// panic in the checks, or a closed permit pool, cost (`internal`).
fn count_drops(outcome: Outcome, count: usize) {
    if count == 0 || outcome == Outcome::Ignore(IgnoreReason::AlreadyStored) {
        return;
    }
    let (_, reason) = outcome.labels();
    metrics::inc_data_column_rejected(reason, count as u64);
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
        let gloas_of = |byte, index| {
            DataColumnSidecar::Gloas(gloas::DataColumnSidecar {
                index,
                beacon_block_root: Root::repeat_byte(byte),
                ..Default::default()
            })
        };
        let (g1, g2, g1_next) = (gloas_of(1, 0), gloas_of(2, 0), gloas_of(1, 1));

        let (groups, repeats) = group_by_block(vec![
            a0.clone(),
            b0.clone(),
            a1.clone(),
            g1.clone(),
            g2.clone(),
            g1_next.clone(),
        ]);

        assert_eq!(
            groups,
            vec![vec![a0, a1], vec![b0], vec![g1, g1_next], vec![g2]]
        );
        assert_eq!(repeats, 0);
    }

    /// A `(block, index)` an answer carries more than once is judged once,
    /// on its first copy, however many copies follow: what keeps a group, and
    /// so the KZG stage, at one sidecar per column.
    #[test]
    fn a_repeated_block_and_index_is_kept_once() {
        let first = valid_shaped_sidecar(5, 0);
        let mut other_cells = first.clone();
        other_cells.column[0] = vec![1u8; ethlambda_types::beacon::preset::BYTES_PER_CELL]
            .try_into()
            .expect("exact cell size");
        let next = valid_shaped_sidecar(5, 1);
        let mut sidecars = vec![DataColumnSidecar::Fulu(first.clone())];
        sidecars.extend(std::iter::repeat_n(
            DataColumnSidecar::Fulu(other_cells),
            1000,
        ));
        sidecars.push(DataColumnSidecar::Fulu(next.clone()));
        sidecars.push(DataColumnSidecar::Fulu(first.clone()));

        let (groups, repeats) = group_by_block(sidecars);

        assert_eq!(
            groups,
            vec![vec![
                DataColumnSidecar::Fulu(first),
                DataColumnSidecar::Fulu(next)
            ]]
        );
        assert_eq!(repeats, 1001);
    }

    /// Sub-batches hold at most [`KZG_BATCH_COLUMNS`] each, as few as that
    /// allows, no two differing by more than one, and in order. 100 columns
    /// are seven sub-batches of 15 and 14, not six of 15 and a short one of 10.
    #[test]
    fn sub_batches_are_bounded_near_equal_and_in_order() {
        let sizes = |count: usize| -> Vec<usize> {
            sub_batches((0..count).collect::<Vec<_>>())
                .iter()
                .map(Vec::len)
                .collect()
        };
        assert_eq!(sizes(0), Vec::<usize>::new());
        assert_eq!(sizes(1), vec![1]);
        assert_eq!(sizes(8), vec![8]);
        assert_eq!(sizes(KZG_BATCH_COLUMNS), vec![KZG_BATCH_COLUMNS]);
        assert_eq!(sizes(KZG_BATCH_COLUMNS + 1), vec![9, 8]);
        assert_eq!(sizes(128), vec![16; 8]);
        assert_eq!(sizes(100), vec![15, 15, 14, 14, 14, 14, 14]);
        let flattened: Vec<usize> = sub_batches((0..100).collect()).concat();
        assert_eq!(flattened, (0..100).collect::<Vec<_>>());
    }

    /// A blob of canonical field elements derived from `seed`: the top byte of
    /// each 32-byte element is zero, which keeps it below the modulus.
    fn blob(seed: u8) -> Vec<u8> {
        (0..ethlambda_types::beacon::preset::BYTES_PER_BLOB)
            .map(|i| {
                if i % 32 == 0 {
                    0
                } else {
                    (i as u8).wrapping_mul(31).wrapping_add(seed)
                }
            })
            .collect()
    }

    /// A gloas block at `slot` whose bid commits to two real blobs, stored
    /// under `root` with a post-state, and its sidecars at every column in
    /// `columns`, carrying the real cells and proofs: sidecars every chain
    /// rule passes.
    fn stored_gloas_block_and_sidecars(
        store: &mut Store,
        slot: u64,
        root: Root,
        columns: &[u64],
    ) -> Vec<gloas::DataColumnSidecar> {
        use ethlambda_state_transition::beacon::kzg;
        let blobs = [blob(1), blob(2)];
        let commitments: Vec<_> = blobs
            .iter()
            .map(|blob| kzg::blob_to_kzg_commitment(blob).expect("commit"))
            .collect();
        let cells_and_proofs: Vec<_> = blobs
            .iter()
            .map(|blob| kzg::compute_cells_and_kzg_proofs(blob).expect("cells"))
            .collect();
        let mut block = gloas::SignedBeaconBlock {
            message: gloas::BeaconBlock {
                slot,
                proposer_index: 0,
                parent_root: Root::ZERO,
                state_root: Root::ZERO,
                body: Default::default(),
            },
            signature: Default::default(),
        };
        block
            .message
            .body
            .signed_execution_payload_bid
            .message
            .blob_kzg_commitments = commitments.into();
        store
            .insert_pending_block(root, SignedBeaconBlock::Gloas(block))
            .expect("insert the block");
        let state = ethlambda_state_transition::beacon::helpers::test_state::with_validators_at(
            ethlambda_types::beacon::fork::ForkName::Gloas,
            1,
        );
        store
            .insert_state(root, state)
            .expect("insert a post-state");
        columns
            .iter()
            .map(|&index| {
                let column: Vec<ethlambda_types::beacon::containers::fulu::Cell> = cells_and_proofs
                    .iter()
                    .map(|(cells, _)| {
                        cells[index as usize]
                            .to_bytes()
                            .to_vec()
                            .try_into()
                            .expect("exact cell size")
                    })
                    .collect();
                let proofs: Vec<_> = cells_and_proofs
                    .iter()
                    .map(|(_, proofs)| proofs[index as usize])
                    .collect();
                gloas::DataColumnSidecar {
                    index,
                    slot,
                    beacon_block_root: root,
                    column: column.into(),
                    kzg_proofs: proofs.into(),
                }
            })
            .collect()
    }

    /// A block with more columns than one KZG batch takes is verified in
    /// sub-batches on permits of their own, and what passes comes back to
    /// the chain actor as one batch, in order: here every column but the one
    /// forged in the second sub-batch, which goes nowhere.
    #[tokio::test]
    async fn a_blocks_columns_that_verify_are_forwarded_together_across_sub_batches() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let (sender, mut received) = mpsc::unbounded_channel();
        server.blockchain = Some(Arc::new(RecordingChain(sender)));

        let all: Vec<u64> = (0..KZG_BATCH_COLUMNS as u64 + 2).collect();
        let mut sidecars =
            stored_gloas_block_and_sidecars(&mut server.store, 5, Root::repeat_byte(0x5a), &all);
        let forged = KZG_BATCH_COLUMNS - 1;
        let mut cell = sidecars[forged].column[0].to_vec();
        cell[31] ^= 1;
        sidecars[forged].column[0] = cell.try_into().expect("exact cell size");
        let sidecars: Vec<DataColumnSidecar> =
            sidecars.into_iter().map(DataColumnSidecar::Gloas).collect();
        let mut expected = sidecars.clone();
        expected.remove(forged);

        check_and_forward(&server, sidecars);

        assert_eq!(received.recv().await, Some(Forwarded::Checked(expected)));
        drop(server);
        assert_eq!(received.recv().await, None);
    }
}
