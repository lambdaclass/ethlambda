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
//! advance) plus a check per sidecar. Both stages' blocking tasks are timed as
//! `kind="column_check"` (`lean_beacon_validation_run_seconds`), so the
//! prechecks' hold is measured only together with the KZG sub-batches', not on
//! its own. Nothing awaits a permit while it holds one, so groups and
//! sub-batches cannot deadlock the pool between them. The pool is
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
//!
//! A `DataColumnsByRoot` lookup also hears what became of each sidecar it
//! asked for ([`check_and_forward_then`]): the call's tasks share one
//! [`Verdicts`], which reports once the last of them is done.

use std::collections::{HashMap, HashSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use ethlambda_network_api::P2PToBlockChainRef;
use ethlambda_state_transition::beacon::gossip::column::{
    self, ChainPrechecks, ChainVerdict, PendingKzg,
};
use ethlambda_state_transition::beacon::gossip::{IgnoreReason, Outcome};
use ethlambda_storage::Store;
use ethlambda_telemetry::BlockEvent;
use ethlambda_types::beacon::containers::DataColumnSidecar;
use ethlambda_types::beacon::primitives::Root;
use ethlambda_types::time::unix_now_ms;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{debug, error, warn};

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

/// One `block_events` row for `sidecar` of the block `block_root`: the one
/// place its fields are named.
fn column_event(
    stage: &'static str,
    sidecar: &DataColumnSidecar,
    block_root: [u8; 32],
    source: &'static str,
    at: Instant,
) -> BlockEvent {
    BlockEvent {
        stage,
        at,
        slot: sidecar.slot(),
        block_root,
        source,
        verdict: None,
        column_index: Some(sidecar.index()),
    }
}

/// The rows of a sidecar that passed validation at `validated_at`: its arrival
/// (unless it is a re-check) and its validation. Gossip-accepted columns and
/// this node's own columns call this directly, as they need no check of their
/// own.
///
/// Computes the sidecar's block root (a header hash for fulu); a caller that
/// already knows it, or writes many columns of one block, uses
/// [`passed_rows_under`].
pub(crate) fn passed_rows(
    sidecar: &DataColumnSidecar,
    arrival: ColumnArrival,
    validated_at: Instant,
) -> Vec<BlockEvent> {
    passed_rows_under(sidecar, sidecar.block_root().0, arrival, validated_at)
}

/// [`passed_rows`] for a sidecar whose block root is already known.
pub(crate) fn passed_rows_under(
    sidecar: &DataColumnSidecar,
    block_root: [u8; 32],
    arrival: ColumnArrival,
    validated_at: Instant,
) -> Vec<BlockEvent> {
    let validated = column_event(
        "column_validated",
        sidecar,
        block_root,
        arrival.source(),
        validated_at,
    );
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
                let root = sidecar.block_root().0;
                vec![column_event("column_recv", sidecar, root, source, at)]
            }
            ColumnArrival::Recheck => Vec::new(),
        },
        ChainVerdict::Drop(_) => Vec::new(),
    }
}

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
/// [`ColumnVerdict`], once per index, in no particular order.
pub(crate) type Done = Box<dyn FnOnce(Vec<(u64, ColumnVerdict)>) + Send>;

/// The verdicts of one call, handed to its [`Done`] when dropped: those
/// recorded, and every other column of the call as
/// [`ColumnVerdict::Undecided`].
///
/// Reported on drop rather than by a call at the end of the checks, so every
/// way out reports, a panic or a task ended early included: a lookup that
/// never hears back keeps its columns on the wire until it goes stale. The
/// call's tasks share it ([`SharedVerdicts`]), so it reports once the last of
/// them lets go of it.
struct Verdicts {
    done: Option<Done>,
    /// Column indices of the call with no verdict recorded yet, each once: a
    /// repeat within the call is dropped unjudged ([`group_by_block`]), and the
    /// first copy's verdict answers for its index.
    unjudged: Vec<u64>,
    recorded: Vec<(u64, ColumnVerdict)>,
}

impl Verdicts {
    fn new(done: Done, sidecars: &[DataColumnSidecar]) -> Self {
        let mut unjudged: Vec<u64> = sidecars.iter().map(DataColumnSidecar::index).collect();
        unjudged.sort_unstable();
        unjudged.dedup();
        Self {
            done: Some(done),
            unjudged,
            recorded: Vec::new(),
        }
    }

    fn record(&mut self, index: u64, verdict: ColumnVerdict) {
        let Some(position) = self.unjudged.iter().position(|&left| left == index) else {
            return;
        };
        self.unjudged.swap_remove(position);
        self.recorded.push((index, verdict));
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

/// One call's [`Verdicts`], shared by its tasks, or `None` when nobody waits
/// on them (every call through [`check_and_forward`]).
type SharedVerdicts = Option<Arc<Mutex<Verdicts>>>;

/// Record `verdicts` in `shared`, if anyone waits on them.
fn report(shared: &SharedVerdicts, verdicts: impl IntoIterator<Item = (u64, ColumnVerdict)>) {
    let Some(shared) = shared else {
        return;
    };
    // Nothing panics while holding the lock, but a poisoned one still holds
    // what was recorded, and the lookup is better off hearing it.
    let mut recorded = shared.lock().unwrap_or_else(PoisonError::into_inner);
    for (index, verdict) in verdicts {
        recorded.record(index, verdict);
    }
}

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

/// A [`P2PServer::column_check_permits`] permit, counted in
/// `lean_beacon_validation_permits_in_use{pool="column_check"}` for as long as
/// it is held. One value, so the gauge falls wherever the permit is released:
/// at the end of the sub-batch it moved into, or with the group task holding
/// it when nothing was left to verify or a precheck panic cut the group short.
struct HeldPermit {
    _permit: OwnedSemaphorePermit,
    _in_use: metrics::PoolInUse,
}

/// Wait for a [`P2PServer::column_check_permits`] permit, the wait observed
/// under `lean_beacon_column_check_permit_wait_seconds{kind="column_check"}`.
/// Both a group (its prechecks and first KZG sub-batch) and each further
/// sub-batch take theirs here. `None` only once the semaphore is closed, which
/// it never is.
async fn acquire_permit(permits: &Arc<Semaphore>) -> Option<HeldPermit> {
    let waiting_since = Instant::now();
    let permit = permits.clone().acquire_owned().await.ok()?;
    metrics::observe_column_check_permit_wait("column_check", waiting_since.elapsed());
    Some(HeldPermit {
        _permit: permit,
        _in_use: metrics::PoolInUse::new("column_check"),
    })
}

/// What some of one block's sidecars came to: the ones to store, the ones to
/// park, and the reason for each one dropped.
#[derive(Default)]
struct GroupVerdicts {
    keep: Vec<DataColumnSidecar>,
    awaiting_parent: Vec<DataColumnSidecar>,
    dropped: Vec<Outcome>,
    /// The [`ColumnVerdict`] of every sidecar here but the kept ones, which
    /// count as delivered only once the chain actor has them ([`forward`]).
    judged: Vec<(u64, ColumnVerdict)>,
}

impl GroupVerdicts {
    fn record(&mut self, sidecar: DataColumnSidecar, verdict: ChainVerdict) {
        if verdict != ChainVerdict::Keep {
            self.judged
                .push((sidecar.index(), ColumnVerdict::from(&verdict)));
        }
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
        self.judged.extend(other.judged);
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
///
/// Writes the `block_events` rows of each sidecar this settles
/// ([`column_rows`]) as soon as it is judged.
fn precheck_group(
    store: &Store,
    sidecars: Vec<DataColumnSidecar>,
    now_ms: u64,
    arrival: ColumnArrival,
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
        let verdict = match precheck {
            Ok(Ok(kzg)) => {
                pending.push((sidecar, kzg));
                continue;
            }
            Ok(Err(verdict)) => verdict,
            Err(_) => {
                error!("A data column check panicked; dropping the sidecar");
                ChainVerdict::Drop(Outcome::Ignore(IgnoreReason::Internal))
            }
        };
        let checked_at = Instant::now();
        ethlambda_telemetry::emit(|| column_rows(&sidecar, arrival, verdict, checked_at));
        settled.record(sidecar, verdict);
    }
    (settled, pending)
}

/// The second stage, for one sub-batch: its sidecars' KZG proofs in one
/// batch, each re-verified alone if the batch fails ([`column::kzg_verdicts`]).
///
/// Writes each sidecar's `block_events` rows ([`column_rows`]), stamped with
/// the moment the sub-batch's verdicts were in: a kept sidecar's
/// `column_validated` is when its sub-batch finished, not when the block's
/// last one did.
fn verify_batch(batch: Vec<Pending>, arrival: ColumnArrival) -> GroupVerdicts {
    let items: Vec<_> = batch.iter().map(|(sidecar, kzg)| (sidecar, kzg)).collect();
    let kzg_verdicts = column::kzg_verdicts(&items);
    let checked_at = Instant::now();
    let mut verdicts = GroupVerdicts::default();
    for ((sidecar, _), verdict) in batch.into_iter().zip(kzg_verdicts) {
        ethlambda_telemetry::emit(|| column_rows(&sidecar, arrival, verdict, checked_at));
        verdicts.record(sidecar, verdict);
    }
    verdicts
}

/// Check one block's sidecars, `permit` already taken for them, and forward
/// what they come to: the parked and the dropped once the prechecks are done,
/// the kept once every sub-batch is. Whatever a panic costs here stays
/// unjudged in `shared`, so the lookup hears it as undecided.
async fn check_group(
    store: Store,
    blockchain: P2PToBlockChainRef,
    permits: Arc<Semaphore>,
    group: Vec<DataColumnSidecar>,
    permit: HeldPermit,
    arrival: ColumnArrival,
    shared: SharedVerdicts,
) {
    let group_size = group.len();
    let task = metrics::BlockingTask::new("column_check");
    let prechecked = tokio::task::spawn_blocking(move || {
        let _run = task.start();
        precheck_group(&store, group, unix_now_ms(), arrival)
    })
    .await;
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
    forward(&blockchain, settled, &shared);

    let mut own_permit = Some(permit);
    let mut batches = Vec::new();
    let mut remaining = sub_batches(pending).into_iter();
    while let Some(batch) = remaining.next() {
        // The group's own permit carries the first sub-batch. Each further one
        // waits for a permit of its own, and the group holds none while it
        // waits, the first having moved into its batch.
        let permit = match own_permit.take() {
            Some(permit) => permit,
            None => match acquire_permit(&permits).await {
                Some(permit) => permit,
                // The semaphore is never closed, so this does not happen
                // today. Should it ever, the sidecars not yet sent to a batch
                // are lost, and say so rather than vanish.
                None => {
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
        let task = metrics::BlockingTask::new("column_check");
        let verified = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _run = task.start();
            verify_batch(batch, arrival)
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
    forward(&blockchain, verdicts, &shared);
}

/// Send the chain actor some of one block's verdicts: the sidecars to store as
/// one batch, and the ones waiting on a block as another, and count the drops.
/// The kept sidecars are recorded as delivered in `shared` only once the chain
/// actor has taken them.
fn forward(blockchain: &P2PToBlockChainRef, verdicts: GroupVerdicts, shared: &SharedVerdicts) {
    for outcome in verdicts.dropped {
        count_drop(outcome);
    }
    report(shared, verdicts.judged);
    if !verdicts.keep.is_empty() {
        let kept: Vec<u64> = verdicts.keep.iter().map(DataColumnSidecar::index).collect();
        let delivered = kept
            .into_iter()
            .map(|index| (index, ColumnVerdict::Delivered));
        let _ = blockchain
            .new_data_column_sidecars(verdicts.keep)
            .inspect(|()| report(shared, delivered))
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
///
/// Each sidecar's `block_events` rows are written once its check is done, by
/// [`column_rows`]: as the prechecks settle it, or as its KZG sub-batch
/// finishes. After the check, so an already stored re-delivery writes none,
/// and off the p2p actor. A sidecar repeating a `(block, index)` of the same
/// call is dropped unjudged and writes none. A column delivered again in
/// another call while it waits for its block, or two copies passing at once
/// in two calls, write rows each, so rows are at least once per column and
/// stage: a reader takes the earliest.
pub(crate) fn check_and_forward(
    server: &P2PServer,
    sidecars: Vec<DataColumnSidecar>,
    arrival: ColumnArrival,
) {
    check_and_forward_then(server, sidecars, arrival, None);
}

/// [`check_and_forward`], then `done` with every sidecar's verdict, once every
/// block's group is done and the ones that passed have been handed to the
/// chain actor.
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
    arrival: ColumnArrival,
    done: Option<Done>,
) {
    let shared: SharedVerdicts =
        done.map(|done| Arc::new(Mutex::new(Verdicts::new(done, &sidecars))));
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
            let Some(permit) = acquire_permit(&permits).await else {
                return;
            };
            tokio::spawn(check_group(
                store.clone(),
                blockchain.clone(),
                permits.clone(),
                group,
                permit,
                arrival,
                shared.clone(),
            ));
        }
        // This task's share of the verdicts goes here; they report once the
        // last group's task lets go of its own.
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
pub(crate) mod tests {
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
    pub(crate) enum Forwarded {
        Checked(Vec<DataColumnSidecar>),
        AwaitingParent(Vec<DataColumnSidecar>),
    }

    /// A chain actor stand-in that reports every sidecar batch it receives.
    ///
    /// Taking a batch fails once the receiver is gone, as a stopped actor's
    /// mailbox does.
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
            self.0
                .send(Forwarded::Checked(sidecars))
                .map_err(|_| ActorError::NoProc)
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
        fn new_proposer_preferences(&self, _proposal_slot: u64) -> Result<(), ActorError> {
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

        check_and_forward(&server, sidecars, ColumnArrival::Recheck);

        assert_eq!(received.recv().await, Some(Forwarded::Checked(expected)));
        drop(server);
        assert_eq!(received.recv().await, None);
    }

    /// The verdicts `done` reports, sorted by column so a test can compare
    /// them whatever order the groups finished in.
    async fn verdicts_of(
        received: &mut mpsc::UnboundedReceiver<Vec<(u64, ColumnVerdict)>>,
    ) -> Option<Vec<(u64, ColumnVerdict)>> {
        let mut verdicts = received.recv().await?;
        verdicts.sort_by_key(|(index, _)| *index);
        Some(verdicts)
    }

    /// A completion callback that reports into a channel.
    fn reporting() -> (Done, mpsc::UnboundedReceiver<Vec<(u64, ColumnVerdict)>>) {
        let (sender, received) = mpsc::unbounded_channel();
        let done: Done = Box::new(move |verdicts| {
            let _ = sender.send(verdicts);
        });
        (done, received)
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

        let (done, mut reported) = reporting();
        let sidecars = vec![
            stored,
            DataColumnSidecar::Fulu(malformed),
            DataColumnSidecar::Fulu(orphan),
        ];
        check_and_forward_then(&server, sidecars, ColumnArrival::Recheck, Some(done));

        assert_eq!(
            verdicts_of(&mut reported).await,
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
        let (done, mut reported) = reporting();

        let sidecar = DataColumnSidecar::Fulu(valid_shaped_sidecar(5, 3));
        check_and_forward_then(&server, vec![sidecar], ColumnArrival::Recheck, Some(done));

        assert_eq!(
            verdicts_of(&mut reported).await,
            Some(vec![(3, ColumnVerdict::Undecided)])
        );
    }

    /// A column an answer carries twice is judged once, and reported once.
    #[tokio::test]
    async fn a_repeated_column_is_reported_once() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let (sender, _received) = mpsc::unbounded_channel();
        server.blockchain = Some(Arc::new(RecordingChain(sender)));
        let (done, mut reported) = reporting();

        let orphan = DataColumnSidecar::Fulu(valid_shaped_sidecar(5, 4));
        check_and_forward_then(
            &server,
            vec![orphan.clone(), orphan],
            ColumnArrival::Recheck,
            Some(done),
        );

        assert_eq!(
            verdicts_of(&mut reported).await,
            Some(vec![(4, ColumnVerdict::Undecided)])
        );
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

    /// Sidecars the checks keep are delivered once the chain actor takes
    /// them, and undecided when it cannot (its mailbox closed): the lookup
    /// then asks for them again rather than retiring.
    #[tokio::test]
    async fn a_kept_sidecar_is_delivered_only_once_the_chain_has_it() {
        for chain_alive in [true, false] {
            let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
            let (sender, received) = mpsc::unbounded_channel();
            server.blockchain = Some(Arc::new(RecordingChain(sender)));
            let _received = chain_alive.then_some(received);
            let sidecars = stored_gloas_block_and_sidecars(
                &mut server.store,
                5,
                Root::repeat_byte(0x5b),
                &[0, 1],
            );
            let sidecars = sidecars.into_iter().map(DataColumnSidecar::Gloas).collect();
            let (done, mut reported) = reporting();

            check_and_forward_then(&server, sidecars, ColumnArrival::Recheck, Some(done));

            let expected = if chain_alive {
                ColumnVerdict::Delivered
            } else {
                ColumnVerdict::Undecided
            };
            assert_eq!(
                verdicts_of(&mut reported).await,
                Some(vec![(0, expected), (1, expected)]),
                "chain alive: {chain_alive}"
            );
        }
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
