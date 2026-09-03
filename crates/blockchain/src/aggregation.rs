//! Committee-signature aggregation: the always-on off-thread worker and the
//! pure functions it runs.
//!
//! One worker thread is spawned when the blockchain actor starts and lives as
//! long as it does. It holds its own [`Store`] handle (a clone sharing the same
//! backend and in-memory buffers), so it re-reads the pool itself instead of
//! being handed a per-slot snapshot: pick the single best job available right
//! now, run its expensive XMSS proof, hand the result to the actor as an
//! [`AggregateProduced`] message, pick again. With nothing eligible it polls
//! every [`WORKER_IDLE_POLL`].
//!
//! It is a plain `std::thread`, not a `spawn_blocking` task. The thread runs
//! for the process's life and spends it in leanVM proofs, so handing it to the
//! runtime's blocking pool would park one of those threads permanently while
//! buying nothing: the loop awaits nothing, and it reaches the actor through an
//! unbounded channel that needs no reactor.
//!
//! The actor applies each aggregate to the store on arrival but holds the
//! gossip publication until the vote-aggregation interval, so proving is free
//! to run whenever while publication stays on the interval grid.
//!
//! [`select_best_job`] builds the candidate pool with the same tiered scoring
//! as `block_builder::select_attestations`: a store pass resolves every
//! candidate `AttestationData`'s aggregation material once (raw-first + trim,
//! see [`resolve_job`]), then a pure in-memory pass ranks candidates by
//! consensus value (current-slot before stale, then Finalize > Justify >
//! Build) and returns the winner.
//!
//! What the worker may pick up depends on where the slot is: see
//! [`JobPolicy`]. In short, a current-slot group needs two thirds of the
//! signatures this node expects before the vote-aggregation boundary, and
//! inside the early window ahead of that boundary the worker takes nothing
//! else — it would rather idle than start a recursive merge that runs into the
//! slot's committee aggregation.
//!
//! The actor can also park the worker outright: it raises the pause flag
//! around its own block build, so the prover is not shared with it (see
//! [`AggregationWorker::pause`]).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ethlambda_crypto::aggregate_mixed;
use ethlambda_crypto::signature::{ValidatorPublicKey, ValidatorSignature};
use ethlambda_storage::Store;
use ethlambda_types::{
    ShortRoot,
    aggregator::AggregatorController,
    attestation::{AggregationBits, AttestationData, HashedAttestationData},
    block::{ByteList512KiB, SingleMessageAggregate},
    chain_config::ChainConfig,
    constants::{INTERVALS_PER_SLOT, MIN_MILLISECONDS_PER_SLOT},
    primitives::H256,
    state::Validator,
};
use spawned_concurrency::message::Message;
use spawned_concurrency::tasks::ActorRef;
use tokio_util::sync::CancellationToken;
use tracing::{info, trace, warn};

use crate::block_builder::{self, EntryScore};
use crate::{SlotInterval, metrics};

/// How long the worker waits before re-reading the pool when it found nothing
/// to do — no eligible job, the pause flag raised, or no aggregation duty.
/// Short enough that a signature arriving mid-interval is picked up promptly,
/// long enough that an idle node is not re-scanning the pool in a spin loop.
pub(crate) const WORKER_IDLE_POLL: Duration = Duration::from_millis(100);

/// Upper bound we wait for the worker to exit on shutdown. Reached only when a
/// proof is mid-flight (`aggregate_mixed` cannot be interrupted); we warn
/// before giving up on the join.
pub(crate) const WORKER_JOIN_TIMEOUT: Duration = Duration::from_secs(2);

/// How often shutdown checks whether the worker thread has exited. Joining a
/// thread blocks, and the actor's `stopped()` hook runs on the runtime, so the
/// wait polls instead of blocking a runtime thread on a proof that may still
/// have a second to run.
const WORKER_SHUTDOWN_POLL: Duration = Duration::from_millis(20);

/// Offset within the slot at which the vote-propagation gate lifts: the start
/// of the vote-aggregation interval. Before it, a current-slot group needs
/// [`min_current_slot_group_sigs`] signatures to be worth a proof; from it on,
/// whatever the group holds is aggregated.
///
/// Derived from the configured slot duration, like every other interval
/// boundary.
fn vote_aggregation_offset_ms(config: &ChainConfig) -> u64 {
    // Slot 0 reduces `to_ms_since_genesis` to the offset within a slot.
    SlotInterval::Aggregation.to_ms_since_genesis(0, config)
}

/// How long before the vote-aggregation boundary the worker stops taking
/// anything but the slot's committee signatures.
///
/// A backlog job is a recursive proof merge that can run well past the
/// boundary, and the prover is single-threaded: starting one here would delay
/// the aggregate the whole slot is waiting on. Idling instead costs little,
/// since the backlog is not going anywhere, and this window is where the
/// committee's signatures typically cross the two-thirds mark.
///
/// Fixed rather than scaled with the slot duration. What the window protects
/// is wall time for one leanVM proof, and a proof costs the same however long
/// the network's slot is.
pub(crate) const EARLY_AGGREGATION_WINDOW: Duration = Duration::from_millis(600);

// The window must not reach past the start of the slot, so `job_policy`'s
// subtraction cannot underflow into the previous one. The slot duration is
// configurable, so the binding case is the narrowest grid a config file can
// ask for. Keep the invariant self-enforcing so a future bump to the window,
// or a lowered floor, can't silently underflow that subtraction.
const _: () = assert!(
    EARLY_AGGREGATION_WINDOW.as_millis()
        <= (2 * MIN_MILLISECONDS_PER_SLOT / INTERVALS_PER_SLOT) as u128,
    "EARLY_AGGREGATION_WINDOW must not reach past the slot boundary at the shortest cadence"
);

/// A single pre-prepared aggregation group.
///
/// Built on the actor thread from a store snapshot; consumed by an off-thread
/// worker that only needs to run the expensive `aggregate_mixed` call. Holding
/// this struct requires no store access.
pub struct AggregationJob {
    pub(crate) hashed: HashedAttestationData,
    pub(crate) slot: u64,
    /// Pre-resolved `(participant_pubkeys, proof_data)` pairs for children
    /// selected via greedy coverage.
    pub(crate) children: Vec<(Vec<ValidatorPublicKey>, ByteList512KiB)>,
    pub(crate) accepted_child_ids: Vec<u64>,
    pub(crate) raw_pubkeys: Vec<ValidatorPublicKey>,
    pub(crate) raw_sigs: Vec<ValidatorSignature>,
    pub(crate) raw_ids: Vec<u64>,
    /// Gossip-signature keys to delete on successful aggregation.
    pub(crate) keys_to_delete: Vec<(u64, H256)>,
}

impl AggregationJob {
    /// Realized coverage (`raw_ids ∪ accepted_child_ids`): the exact validator
    /// set the produced proof will attest to. Used for scoring during
    /// selection so scores stay consistent with the job actually emitted,
    /// instead of the full union of every proof considered. Derived on demand:
    /// the fields it unions are already carried by the job.
    fn coverage(&self) -> HashSet<u64> {
        self.raw_ids
            .iter()
            .copied()
            .chain(self.accepted_child_ids.iter().copied())
            .collect()
    }
}

/// Result of one successful aggregation group. Carried back to the actor thread
/// as a message payload so the store can be updated and gossip publish fired.
pub struct AggregatedGroupOutput {
    pub(crate) hashed: HashedAttestationData,
    pub(crate) proof: SingleMessageAggregate,
    pub(crate) participants: Vec<u64>,
    pub(crate) keys_to_delete: Vec<(u64, H256)>,
}

/// Handle to the always-on aggregation worker, held by the actor for the
/// actor's whole lifetime.
pub(crate) struct AggregationWorker {
    /// Cancelled by the actor's `stopped()` hook; the worker breaks out of its
    /// loop at the next job boundary.
    cancel: CancellationToken,
    /// Raised while the actor needs the prover to itself; see [`Self::pause`].
    paused: Arc<AtomicBool>,
    /// Handle to the worker thread, held so shutdown can join it.
    handle: std::thread::JoinHandle<()>,
}

impl AggregationWorker {
    /// Stop handing the worker new jobs for as long as the returned guard
    /// lives. A proof already in flight is not interrupted (`aggregate_mixed`
    /// cannot be), so this bounds contention rather than eliminating it.
    pub(crate) fn pause(&self) -> PauseGuard {
        self.paused.store(true, Ordering::Release);
        PauseGuard(self.paused.clone())
    }

    /// Cancel the worker and wait up to [`WORKER_JOIN_TIMEOUT`] for it to exit.
    ///
    /// Polls rather than joining straight away: the thread only notices
    /// cancellation between jobs, so a join here would block a runtime thread
    /// for as long as the proof in flight takes. Past the timeout the thread is
    /// left detached — it exits on its own once the current proof returns, and
    /// the process is on its way out regardless.
    pub(crate) async fn shutdown(self) {
        self.cancel.cancel();

        let deadline = Instant::now() + WORKER_JOIN_TIMEOUT;
        while !self.handle.is_finished() && Instant::now() < deadline {
            tokio::time::sleep(WORKER_SHUTDOWN_POLL).await;
        }

        if !self.handle.is_finished() {
            warn!(
                timeout_secs = WORKER_JOIN_TIMEOUT.as_secs(),
                "Aggregation worker still proving at shutdown; leaving it detached"
            );
            return;
        }
        match self.handle.join() {
            Ok(()) => info!("Aggregation worker joined on shutdown"),
            Err(_) => warn!("Aggregation worker panicked"),
        }
    }
}

/// Lowers the worker's pause flag on drop, so an early return on the paused
/// code path cannot leave the worker parked forever.
pub(crate) struct PauseGuard(Arc<AtomicBool>);

impl Drop for PauseGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Startup-fixed inputs the worker's vote-propagation gate needs. Both come
/// from the CLI and never change at runtime, so the worker owns a copy instead
/// of reaching back into the actor.
#[derive(Clone)]
pub(crate) struct WorkerConfig {
    /// Number of attestation committees (= subnet count).
    pub(crate) attestation_committee_count: u64,
    /// Attestation subnets this node subscribes to.
    pub(crate) subscribed_subnets: HashSet<u64>,
}

/// One successful aggregate streamed back from the worker.
pub(crate) struct AggregateProduced {
    pub(crate) output: AggregatedGroupOutput,
    /// Wall time the proof itself took, observed on the worker thread.
    pub(crate) elapsed: Duration,
}
impl Message for AggregateProduced {
    type Result = ();
}

/// Validator ids this worker has already produced a proof for, keyed by
/// attestation data root, for the slot in [`Self::slot`].
///
/// The actor applies an aggregate (which deletes the group's gossip
/// signatures) only once the message reaches it, so between sending and that
/// apply the store still shows the job as pending and the very next selection
/// round would prove it a second time. Remembering what we emitted closes that
/// window without making the worker a store writer.
#[derive(Default)]
struct EmittedCoverage {
    slot: u64,
    by_data_root: HashMap<H256, HashSet<u64>>,
}

impl EmittedCoverage {
    /// Drop everything remembered for an earlier slot. Entries only exist to
    /// cover the send-to-apply window, so a slot's worth is always stale by
    /// the time the next one starts.
    fn roll_to(&mut self, slot: u64) {
        if self.slot != slot {
            self.slot = slot;
            self.by_data_root.clear();
        }
    }

    fn record(&mut self, data_root: H256, participants: &[u64]) {
        self.by_data_root
            .entry(data_root)
            .or_default()
            .extend(participants);
    }

    /// Whether a candidate would only re-prove validators we already covered.
    fn covers(&self, data_root: &H256, coverage: &HashSet<u64>) -> bool {
        self.by_data_root
            .get(data_root)
            .is_some_and(|emitted| coverage.is_subset(emitted))
    }
}

/// What the worker is allowed to pick up, given where the slot is.
///
/// The prover is single-threaded and the slot's committee aggregate is the one
/// piece of work with a deadline, so the policy tightens as that deadline
/// approaches and opens up once it has passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JobPolicy {
    /// Early in the slot: backlog work is welcome — stale groups, merges of
    /// proofs already held — and a current-slot group is eligible once it
    /// holds `min_sigs` signatures.
    Backlog { min_sigs: usize },
    /// Inside [`EARLY_AGGREGATION_WINDOW`]: only a current-slot group that
    /// already holds `min_sigs`. Anything else would occupy the prover across
    /// the boundary and delay the aggregate the slot is waiting on, so the
    /// worker idles until either the threshold is met or the boundary arrives.
    CommitteeOnly { min_sigs: usize },
    /// From the vote-aggregation boundary on: everything is eligible, however
    /// few signatures back it.
    Open,
}

impl JobPolicy {
    /// Whether a current-slot gossip group holding `sigs` signatures may be
    /// proved now.
    fn admits_current_slot(self, sigs: usize) -> bool {
        match self {
            Self::Open => true,
            Self::Backlog { min_sigs } | Self::CommitteeOnly { min_sigs } => sigs >= min_sigs,
        }
    }

    /// Whether work other than the current slot's committee signatures may be
    /// started now: a stale group, or a merge of proofs already in the pool.
    fn admits_backlog(self) -> bool {
        !matches!(self, Self::CommitteeOnly { .. })
    }
}

/// Pick the single most valuable aggregation job available right now, or
/// `None` when nothing is worth proving. Touches the store, does no heavy
/// cryptography.
///
/// A tiered selector modeled on `block_builder::select_attestations`:
///
/// 1. **Store pass**: resolves every candidate `AttestationData` into a
///    store-free [`AggregationJob`] via [`resolve_job`] (raw-first, then
///    trim). Candidates come from gossip groups
///    (`store.iter_gossip_signatures()`) and payload-only groups
///    (`store.new_payload_keys()` not already a gossip candidate, requiring
///    at least two existing proofs to merge), each admitted or held back by
///    `policy`.
/// 2. **Ranking**: scores every candidate against the head state and keeps the
///    lowest ordering key (current-slot before stale, then Finalize > Justify
///    > Build, mirroring the block builder).
fn select_best_job(
    store: &Store,
    current_slot: u64,
    policy: JobPolicy,
    emitted: &EmittedCoverage,
) -> Option<AggregationJob> {
    let gossip_groups = store.iter_gossip_signatures();
    let new_payload_keys = if policy.admits_backlog() {
        store.new_payload_keys()
    } else {
        // A payload-only candidate is a pure proof merge: the most expensive
        // job there is, and the one with the least claim on the prover right
        // before the boundary.
        Vec::new()
    };

    if gossip_groups.is_empty() && new_payload_keys.is_empty() {
        return None;
    }

    let head_state = store.head_state();
    let validators = &head_state.validators;

    let mut candidates: HashMap<H256, AggregationJob> = HashMap::new();

    for (hashed, validator_sigs) in &gossip_groups {
        let data_root = hashed.root();
        let admitted = if hashed.data().slot == current_slot {
            // A current-slot group still collecting signatures is worth more as
            // one wide proof after the boundary than as several thin ones
            // before it.
            policy.admits_current_slot(validator_sigs.len())
        } else {
            // Stale groups are backlog: no further signature is coming for
            // them, so they are only held back to keep the prover free.
            policy.admits_backlog()
        };
        if !admitted {
            trace!(
                ?policy,
                sigs = validator_sigs.len(),
                group_slot = hashed.data().slot,
                data_root = %ShortRoot(&data_root.0),
                "holding aggregation candidate back"
            );
            continue;
        }
        let (new_proofs, known_proofs) = store.existing_proofs_for_data(&data_root);
        if let Some(job) = resolve_job(
            hashed.clone(),
            validator_sigs,
            &new_proofs,
            &known_proofs,
            validators,
        ) {
            candidates.insert(data_root, job);
        }
    }

    for (data_root, att_data) in &new_payload_keys {
        if candidates.contains_key(data_root) {
            continue;
        }
        // Cheap pre-check to skip the expensive `existing_proofs_for_data` clone when
        // fewer than 2 proofs are present (a payload-only merge needs at least 2).
        if store.proof_count_for_data(data_root) < 2 {
            continue;
        }
        let (new_proofs, known_proofs) = store.existing_proofs_for_data(data_root);
        let hashed = HashedAttestationData::new(att_data.clone());
        if let Some(job) = resolve_job(hashed, &[], &new_proofs, &known_proofs, validators) {
            candidates.insert(*data_root, job);
        }
    }

    // Drop candidates that would only re-prove coverage already in flight.
    candidates.retain(|data_root, job| !emitted.covers(data_root, &job.coverage()));

    if candidates.is_empty() {
        return None;
    }
    let validator_count = validators.len();

    // Chain view covering [0, head_slot]. A state's `historical_block_hashes`
    // only covers [0, head_slot - 1]: `process_block_header` pushes the
    // *parent* root, never the block's own root, so the head root at index
    // head_slot is absent. We push `store.head()` (the canonical tip, i.e.
    // the block `head_state` is the state of) to land it at head_slot, so
    // votes for the current head pass `attestation_data_matches_chain`.
    //
    // Unlike the block builder, which extends by parent_root + empty slots to
    // model a *future* candidate block it is about to propose, we validate
    // against the current chain: aggregated attestations only reference
    // existing blocks (head.slot / target.slot <= head_slot), so no
    // empty-slot padding beyond the tip is needed.
    let known_block_roots = store.get_block_roots().expect("block roots read works");
    let mut extended_historical_block_hashes: Vec<H256> =
        head_state.historical_block_hashes.iter().copied().collect();
    extended_historical_block_hashes.push(store.head().expect("head read works"));

    let projected = block_builder::ProjectedState::from_head_state(&head_state);

    // One round: the store is re-read before the next job, so a same-target
    // candidate re-tiers against the aggregate this one produced (once
    // applied) rather than against an in-memory projection of it.
    let (data_root, score) = pick_best_candidate(
        &candidates,
        &projected,
        &known_block_roots,
        &extended_historical_block_hashes,
        current_slot,
        validator_count,
    )
    .or_else(|| {
        trace!("aggregation selection converged: no scoring candidates");
        None
    })?;

    let job = candidates
        .remove(&data_root)
        .expect("picked candidate exists in pool");
    let att_data = job.hashed.data();

    trace!(
        tier = ?score.tier,
        new_voters = score.new_voters,
        target_slot = att_data.target.slot,
        target_root = %ShortRoot(&att_data.target.root.0),
        data_root = %ShortRoot(&data_root.0),
        "selected aggregation job"
    );

    Some(job)
}

/// Minimum gossip signatures a current-slot group must hold for the worker to
/// prove it before the vote-aggregation boundary: two thirds of the votes this
/// node expects to collect, rounded up.
///
/// Groups are keyed by attestation data (not by subnet), so one group gathers
/// signatures from every subnet we subscribe to; the expected count is
/// therefore the number of network validators whose committee subnet is one of
/// ours, not a single committee's worth. With `N` validators across `C`
/// committees, subnet `s` holds `N / C` validators, plus one more when
/// `s < N % C`.
///
/// Returns `None` when no such validator exists (no subscribed subnet is in
/// range, or the chain has no committees), which no group can ever clear: the
/// caller treats that as "wait for the boundary".
fn min_current_slot_group_sigs(
    validator_count: u64,
    committee_count: u64,
    subscribed_subnets: &HashSet<u64>,
) -> Option<usize> {
    if committee_count == 0 {
        return None;
    }
    let expected_votes: u64 = subscribed_subnets
        .iter()
        .filter(|&&subnet| subnet < committee_count)
        .map(|&subnet| {
            validator_count / committee_count
                + u64::from(subnet < validator_count % committee_count)
        })
        .sum();
    let min_sigs = (2 * expected_votes).div_ceil(3) as usize;
    (min_sigs > 0).then_some(min_sigs)
}

/// The policy in force `ms_into_slot` into the slot.
fn job_policy(
    ms_into_slot: u64,
    time_config: &ChainConfig,
    store: &Store,
    config: &WorkerConfig,
) -> JobPolicy {
    let vote_aggregation_offset_ms = vote_aggregation_offset_ms(time_config);
    if ms_into_slot >= vote_aggregation_offset_ms {
        return JobPolicy::Open;
    }

    let validator_count = store.head_state().validators.len() as u64;
    // With no votes expected there is no quorum to wait for, so nothing
    // justifies proving a current-slot group early: an unreachable floor holds
    // every one of them to the boundary.
    let min_sigs = min_current_slot_group_sigs(
        validator_count,
        config.attestation_committee_count,
        &config.subscribed_subnets,
    )
    .unwrap_or(usize::MAX);

    let window_opens_at = vote_aggregation_offset_ms - EARLY_AGGREGATION_WINDOW.as_millis() as u64;
    if ms_into_slot >= window_opens_at {
        JobPolicy::CommitteeOnly { min_sigs }
    } else {
        JobPolicy::Backlog { min_sigs }
    }
}

/// Scan the candidate pool and pick the best-scoring, not-yet-selected entry.
///
/// Mirrors `block_builder::pick_best_candidate`: skips entries failing
/// `entry_passes_filters` (logging the reason) and those scoring zero new
/// voters (relative to the candidate's realized [`AggregationJob::coverage`],
/// not the full proof union — see [`resolve_job`]). Among the rest, returns
/// `(data_root, score)` for the entry with the lowest composite key:
/// current-slot groups precede stale ones, then `EntryScore::ordering_key`
/// (tier, then tier-dependent dims, then `data_root`) decides.
fn pick_best_candidate(
    candidates: &HashMap<H256, AggregationJob>,
    projected: &block_builder::ProjectedState,
    known_block_roots: &HashSet<H256>,
    extended_historical_block_hashes: &[H256],
    current_slot: u64,
    validator_count: usize,
) -> Option<(H256, EntryScore)> {
    let mut best: Option<(H256, EntryScore)> = None;
    let mut best_key: Option<(u8, block_builder::OrderingKey)> = None;

    for (data_root, candidate) in candidates {
        let att_data = candidate.hashed.data();
        if let Err(reason) = projected.entry_passes_filters(
            att_data,
            known_block_roots,
            extended_historical_block_hashes,
        ) {
            trace_skipped_candidate(reason, att_data, data_root);
            continue;
        }

        let Some((score, _new_voters)) =
            projected.score_entry(att_data, &candidate.coverage(), validator_count)
        else {
            trace_skipped_candidate("zero_new_voters", att_data, data_root);
            continue;
        };

        // Current-slot groups always precede stale ones (goal: consider
        // current-slot signatures first); within a bucket, `EntryScore`
        // decides.
        let slot_bucket: u8 = if att_data.slot == current_slot { 0 } else { 1 };
        let candidate_key = candidate_ordering_key(slot_bucket, &score, *data_root);
        if best_key.as_ref().is_none_or(|k| candidate_key < *k) {
            best = Some((*data_root, score));
            best_key = Some(candidate_key);
        }
    }

    best
}

/// Composite ordering key (lower is better): current-slot groups (`0`)
/// precede stale ones (`1`); within a bucket, `EntryScore::ordering_key`
/// (tier, then tier-dependent dims, then `data_root`) decides.
fn candidate_ordering_key(
    slot_bucket: u8,
    score: &EntryScore,
    data_root: H256,
) -> (u8, block_builder::OrderingKey) {
    (slot_bucket, score.ordering_key(data_root))
}

fn trace_skipped_candidate(reason: &'static str, att_data: &AttestationData, data_root: &H256) {
    trace!(
        reason,
        attestation_slot = att_data.slot,
        target_slot = att_data.target.slot,
        target_root = %ShortRoot(&att_data.target.root.0),
        data_root = %ShortRoot(&data_root.0),
        "skipped aggregation candidate"
    );
}

/// Resolve one candidate's aggregation material, raw-first + trim. No store
/// access: the caller passes pre-resolved `(new_proofs, known_proofs)`.
///
/// 1. Resolves every gossip sig to `(id, pubkey, sig)`; seeds `covered` with
///    their validator ids.
/// 2. Runs [`select_proofs_greedily`] seeded with that `covered` set so a
///    chosen child only adds coverage beyond the raw sigs; capped at
///    [`MAX_AGGREGATION_CHILDREN`].
/// 3. Trims any raw sig whose validator id ended up in the chosen children's
///    participant union. This is not just an efficiency win: `aggregate_mixed`
///    must never receive a validator both as a raw participant and inside a
///    child (double inclusion corrupts the aggregate), and going raw-first
///    (instead of selecting children first) re-introduces that possibility.
///
/// Returns `None` when the resulting material is non-viable: no raw sigs and
/// fewer than two children, or a lone raw sig with no children.
fn resolve_job(
    hashed: HashedAttestationData,
    validator_sigs: &[(u64, ValidatorSignature)],
    new_proofs: &[SingleMessageAggregate],
    known_proofs: &[SingleMessageAggregate],
    validators: &[Validator],
) -> Option<AggregationJob> {
    let data_root = hashed.root();
    let mut raw_by_id: HashMap<u64, (ValidatorPublicKey, ValidatorSignature)> = HashMap::new();
    for (vid, sig) in validator_sigs {
        let Some(validator) = validators.get(*vid as usize) else {
            continue;
        };
        let Ok(pubkey) = ValidatorPublicKey::from_bytes(&validator.attestation_pubkey) else {
            continue;
        };
        raw_by_id.insert(*vid, (pubkey, sig.clone()));
    }
    let seed_covered: HashSet<u64> = raw_by_id.keys().copied().collect();

    let (child_proofs, _) = select_proofs_greedily(new_proofs, known_proofs, seed_covered);
    let (children, accepted_child_ids) = resolve_child_pubkeys(&child_proofs, validators);
    let child_id_set: HashSet<u64> = accepted_child_ids.iter().copied().collect();

    let mut raw_pubkeys = Vec::new();
    let mut raw_sigs = Vec::new();
    let mut raw_ids = Vec::new();
    for (vid, (pubkey, sig)) in &raw_by_id {
        if child_id_set.contains(vid) {
            continue;
        }
        raw_pubkeys.push(pubkey.clone());
        raw_sigs.push(sig.clone());
        raw_ids.push(*vid);
    }

    // Skip aggregation when there's nothing to aggregate.
    if raw_ids.is_empty() && children.len() < 2 {
        return None;
    }
    // Skip aggregation when there's only a single raw signature to aggregate.
    if children.is_empty() && raw_ids.len() <= 1 {
        return None;
    }

    // Consume the whole group's gossip signatures on successful aggregation,
    // including any trimmed in step 3: their vote is now represented via the
    // child that covers them.
    let keys_to_delete: Vec<(u64, H256)> = validator_sigs
        .iter()
        .map(|(vid, _)| (*vid, data_root))
        .collect();

    let slot = hashed.data().slot;
    Some(AggregationJob {
        hashed,
        slot,
        children,
        accepted_child_ids,
        raw_pubkeys,
        raw_sigs,
        raw_ids,
        keys_to_delete,
    })
}

/// Resolve each child's participant pubkeys. Drops any child whose pubkeys
/// can't be fully resolved (passing fewer pubkeys than the proof expects would
/// produce an invalid aggregate).
fn resolve_child_pubkeys(
    child_proofs: &[SingleMessageAggregate],
    validators: &[Validator],
) -> (Vec<(Vec<ValidatorPublicKey>, ByteList512KiB)>, Vec<u64>) {
    let mut children = Vec::with_capacity(child_proofs.len());
    let mut accepted_child_ids: Vec<u64> = Vec::new();

    for proof in child_proofs {
        let participant_ids: Vec<u64> = proof.participant_indices().collect();
        let child_pubkeys: Vec<ValidatorPublicKey> = participant_ids
            .iter()
            .filter_map(|&vid| {
                let v = validators.get(vid as usize)?;
                ValidatorPublicKey::from_bytes(&v.attestation_pubkey).ok()
            })
            .collect();
        if child_pubkeys.len() != participant_ids.len() {
            warn!(
                expected = participant_ids.len(),
                resolved = child_pubkeys.len(),
                "Skipping child proof: could not resolve all participant pubkeys"
            );
            continue;
        }
        accepted_child_ids.extend(&participant_ids);
        children.push((child_pubkeys, proof.proof.clone()));
    }

    (children, accepted_child_ids)
}

/// Run the expensive `aggregate_mixed` call for a single prepared job.
///
/// Pure function — no store access, safe to call from a `tokio::task::spawn_blocking`
/// worker. Returns `None` on cryptographic failure.
pub fn aggregate_job(job: AggregationJob) -> Option<AggregatedGroupOutput> {
    if job.raw_ids.is_empty() && job.children.len() < 2 {
        return None;
    }

    let slot_u32: u32 = job.slot.try_into().expect("slot exceeds u32");
    let data_root = job.hashed.root();

    let proof_data = {
        let _timing = metrics::time_pq_sig_aggregated_signatures_building();
        aggregate_mixed(
            job.children,
            job.raw_pubkeys,
            job.raw_sigs,
            &data_root,
            slot_u32,
        )
    }
    .inspect_err(|err| warn!(%err, "Failed to aggregate committee signatures"))
    .ok()?;

    let mut participants: Vec<u64> = job.raw_ids;
    participants.extend(&job.accepted_child_ids);
    participants.sort_unstable();
    participants.dedup();

    let aggregation_bits = aggregation_bits_from_validator_indices(&participants);
    let proof = SingleMessageAggregate::new(aggregation_bits, proof_data);
    metrics::observe_aggregated_proof_size(proof.proof.len());

    Some(AggregatedGroupOutput {
        hashed: job.hashed,
        proof,
        participants,
        keys_to_delete: job.keys_to_delete,
    })
}

/// Apply a worker-produced aggregate to the store. Called per message on the
/// actor thread; gauge metrics that depend on total counts are batched into
/// `finalize_aggregation_session` so we pay one lock per session instead of
/// one per aggregate. Idempotent wrt the gossip delete.
pub fn apply_aggregated_group(store: &mut Store, output: &AggregatedGroupOutput) {
    store.insert_new_aggregated_payload(output.hashed.clone(), output.proof.clone());
    store.delete_gossip_signatures(&output.keys_to_delete);

    metrics::inc_pq_sig_aggregated_signatures();
    metrics::inc_pq_sig_attestations_in_aggregated_signatures(output.participants.len() as u64);
}

/// Refresh the pool-size gauges. Called from the vote-aggregation tick, once
/// the slot's buffered aggregates have gone out, so
/// `lean_latest_new_aggregated_payloads` and `lean_gossip_signatures` settle
/// on a per-slot reading instead of being churned per aggregate.
pub fn refresh_pool_gauges(store: &Store) {
    metrics::update_latest_new_aggregated_payloads(store.new_aggregated_payloads_count());
    metrics::update_gossip_signatures(store.gossip_signatures_count());
}

/// Maximum number of existing proofs reused as children in a single
/// aggregation job. Recursive aggregation is costly, so we limit the
/// number of children to avoid unbounded aggregation times.
const MAX_AGGREGATION_CHILDREN: usize = 2;

/// Greedy set-cover selection of proofs to maximize validator coverage.
///
/// Processes proof sets in priority order (new before known). Within each set,
/// repeatedly picks the proof covering the most uncovered validators until no
/// proof adds new coverage. `seed_covered` primes the coverage set before
/// selection starts — [`resolve_job`] seeds it with raw-signature validator
/// ids so a chosen proof is only picked for coverage beyond what raw sigs
/// already provide.
///
/// Caps the number of proofs selected at [`MAX_AGGREGATION_CHILDREN`].
fn select_proofs_greedily(
    new_proofs: &[SingleMessageAggregate],
    known_proofs: &[SingleMessageAggregate],
    seed_covered: HashSet<u64>,
) -> (Vec<SingleMessageAggregate>, HashSet<u64>) {
    let mut selected: Vec<SingleMessageAggregate> = Vec::new();
    let mut covered: HashSet<u64> = seed_covered;

    for proof_set in [new_proofs, known_proofs] {
        let mut remaining: Vec<&SingleMessageAggregate> = proof_set.iter().collect();

        while selected.len() < MAX_AGGREGATION_CHILDREN && !remaining.is_empty() {
            let best_idx = remaining
                .iter()
                .enumerate()
                .max_by_key(|(_, p)| {
                    p.participant_indices()
                        .filter(|vid| !covered.contains(vid))
                        .count()
                })
                .map(|(i, _)| i)
                .expect("remaining is non-empty");

            let new_coverage: HashSet<u64> = remaining[best_idx]
                .participant_indices()
                .filter(|vid| !covered.contains(vid))
                .collect();

            if new_coverage.is_empty() {
                break;
            }

            selected.push(remaining.swap_remove(best_idx).clone());
            covered.extend(new_coverage);
        }

        if selected.len() >= MAX_AGGREGATION_CHILDREN {
            break;
        }
    }

    (selected, covered)
}

/// Build an AggregationBits bitfield from a list of validator indices.
pub(crate) fn aggregation_bits_from_validator_indices(bits: &[u64]) -> AggregationBits {
    if bits.is_empty() {
        return AggregationBits::with_length(0).unwrap();
    }
    let max_id = bits
        .iter()
        .copied()
        .max()
        .expect("already checked it's non-empty") as usize;
    let mut aggregation_bits =
        AggregationBits::with_length(max_id + 1).expect("validator count exceeds limit");

    for &vid in bits {
        aggregation_bits
            .set(vid as usize, true)
            .expect("capacity support highest validator id");
    }
    aggregation_bits
}

/// Spawn the always-on aggregation worker on its own thread.
///
/// The worker owns a [`Store`] clone — same backend, same in-memory buffers —
/// the shared aggregator-role flag (so a runtime toggle reaches it without a
/// restart), and the startup-fixed gate inputs. It runs until the returned
/// handle's [`AggregationWorker::shutdown`] cancels it.
pub(crate) fn spawn_aggregation_worker(
    store: Store,
    actor: ActorRef<crate::BlockChainServer>,
    aggregator: AggregatorController,
    config: WorkerConfig,
) -> AggregationWorker {
    let cancel = CancellationToken::new();
    let paused = Arc::new(AtomicBool::new(false));
    let handle = {
        let cancel = cancel.clone();
        let paused = paused.clone();
        std::thread::Builder::new()
            .name("aggregation-worker".to_owned())
            .spawn(move || run_aggregation_worker(store, actor, aggregator, config, cancel, paused))
            .expect("spawning the aggregation worker thread")
    };

    AggregationWorker {
        cancel,
        paused,
        handle,
    }
}

/// Worker loop — runs on its own thread for the actor's lifetime.
///
/// Each round re-reads the pool through the store handle, picks the best job
/// ([`select_best_job`]), proves it, and hands the result to the actor as an
/// [`AggregateProduced`] message. With nothing to do — nothing eligible,
/// paused for a block build, or no aggregation duty — it sleeps
/// [`WORKER_IDLE_POLL`] and looks again.
///
/// `aggregate_mixed` cannot be interrupted, so both cancellation and the pause
/// flag are only observed between jobs.
fn run_aggregation_worker(
    store: Store,
    actor: ActorRef<crate::BlockChainServer>,
    aggregator: AggregatorController,
    config: WorkerConfig,
    cancel: CancellationToken,
    paused: Arc<AtomicBool>,
) {
    info!("Aggregation worker started");

    // The chain's time grid never changes at runtime, so one read covers the
    // worker's whole life.
    let time_config = *store.config();
    let mut emitted = EmittedCoverage::default();

    while !cancel.is_cancelled() {
        let Some(job) = next_job(
            &store,
            &time_config,
            &aggregator,
            &paused,
            &config,
            &mut emitted,
        ) else {
            std::thread::sleep(WORKER_IDLE_POLL);
            continue;
        };

        let slot = job.slot;
        let raw_sigs = job.raw_ids.len();
        let children = job.children.len();
        let data_root = job.hashed.root();
        // Recorded whether or not the proof succeeds: a failed job re-reads
        // identically, so without this the loop would retry it at full prover
        // cost until a new signature arrives.
        let attempted: Vec<u64> = job.coverage().into_iter().collect();

        let job_start = Instant::now();
        let output = aggregate_job(job);
        let elapsed = job_start.elapsed();
        emitted.record(data_root, &attempted);

        let Some(output) = output else {
            warn!(
                slot,
                raw_sigs,
                children,
                ?elapsed,
                "Committee signature aggregation failed"
            );
            metrics::inc_aggregator_skipped_other(1);
            continue;
        };

        info!(
            slot,
            raw_sigs,
            children,
            participants = output.participants.len(),
            ?elapsed,
            "Committee signature aggregated"
        );

        if actor.send(AggregateProduced { output, elapsed }).is_err() {
            // Actor is gone; nothing would consume further aggregates.
            break;
        }
    }

    info!("Aggregation worker stopped");
}

/// One round of job selection: honor the role flag and the pause flag, derive
/// the slot and the [`JobPolicy`] from the wall clock, then ask
/// [`select_best_job`] for the winner. `None` means "nothing to do right now",
/// which inside the early window is a deliberate answer rather than an idle
/// one.
fn next_job(
    store: &Store,
    time_config: &ChainConfig,
    aggregator: &AggregatorController,
    paused: &AtomicBool,
    config: &WorkerConfig,
    emitted: &mut EmittedCoverage,
) -> Option<AggregationJob> {
    if !aggregator.is_enabled() || paused.load(Ordering::Acquire) {
        return None;
    }

    // Before genesis there is no slot to aggregate for.
    let ms_since_genesis = crate::unix_now_ms().checked_sub(time_config.genesis_time_ms())?;
    let slot = ms_since_genesis / time_config.milliseconds_per_slot;
    let ms_into_slot = ms_since_genesis % time_config.milliseconds_per_slot;

    emitted.roll_to(slot);
    let policy = job_policy(ms_into_slot, time_config, store, config);

    select_best_job(store, slot, policy, emitted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_storage::backend::InMemoryBackend;
    use ethlambda_types::constants::DEFAULT_MILLISECONDS_PER_SLOT;
    use ethlambda_types::{
        block::{Block, BlockBody, BlockHeader, MultiMessageAggregate, SignedBlock},
        checkpoint::Checkpoint,
        state::{JustificationValidators, JustifiedSlots, State, StateConfig},
    };
    use libssz_types::SszList;
    use std::sync::Arc;

    fn make_bits(indices: &[usize]) -> AggregationBits {
        let max = indices.iter().copied().max().unwrap_or(0);
        let mut bits = AggregationBits::with_length(max + 1).unwrap();
        for &i in indices {
            bits.set(i, true).unwrap();
        }
        bits
    }

    fn make_validators(n: usize) -> Vec<Validator> {
        (0..n)
            .map(|i| Validator {
                attestation_pubkey: [i as u8; 52],
                proposal_pubkey: [i as u8; 52],
                index: i as u64,
            })
            .collect()
    }

    /// A cheap-but-real XMSS signature (tiny lifetime, cached) for tests that
    /// only need `ValidatorSignature::from_bytes` to succeed. `resolve_job`
    /// never checks signature validity, only that it clones and carries a
    /// resolvable id — mirrors `ethlambda_storage::store::tests::make_dummy_sig`.
    fn dummy_sig() -> ValidatorSignature {
        use ethlambda_crypto::signature::LeanSignatureScheme;
        use leansig::{serialization::Serializable, signature::SignatureScheme};
        use rand::{SeedableRng, rngs::StdRng};

        static CACHED_SIG: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| {
            let mut rng = StdRng::seed_from_u64(42);
            let lifetime = 1 << 5; // small for speed
            let (_pk, sk) = LeanSignatureScheme::key_gen(&mut rng, 0, lifetime);
            let sig = LeanSignatureScheme::sign(&sk, 0, &[0u8; 32]).unwrap();
            sig.to_bytes()
        });

        ValidatorSignature::from_bytes(&CACHED_SIG).expect("cached test signature")
    }

    /// A `HashedAttestationData` over default (all-zero) data for `resolve_job`
    /// tests, which never inspect the attestation data itself — only the raw
    /// sigs / children / coverage the resulting job carries.
    fn dummy_hashed() -> HashedAttestationData {
        HashedAttestationData::new(AttestationData {
            slot: 0,
            head: Checkpoint::default(),
            target: Checkpoint::default(),
            source: Checkpoint::default(),
        })
    }

    fn make_head_state(head_slot: u64, num_validators: usize, hashes: &[H256]) -> State {
        let head_header = BlockHeader {
            slot: head_slot,
            proposer_index: 0,
            parent_root: H256::ZERO,
            state_root: H256::ZERO,
            body_root: H256::ZERO,
        };
        State {
            config: StateConfig { genesis_time: 1000 },
            slot: head_slot,
            latest_block_header: head_header,
            latest_justified: Checkpoint::default(),
            latest_finalized: Checkpoint::default(),
            historical_block_hashes: SszList::try_from(hashes.to_vec()).unwrap(),
            justified_slots: JustifiedSlots::new(),
            validators: SszList::try_from(make_validators(num_validators)).unwrap(),
            justifications_roots: Default::default(),
            justifications_validators: JustificationValidators::new(),
        }
    }

    fn new_test_store(head_state: State) -> Store {
        let backend: Arc<dyn ethlambda_storage::StorageBackend> = Arc::new(InMemoryBackend::new());
        Store::from_anchor_state(backend, head_state, DEFAULT_MILLISECONDS_PER_SLOT)
    }

    /// Insert a header-only block at `root` so it shows up in
    /// `store.get_block_roots()`. Mirrors the pattern used throughout the
    /// blockchain crate's own store tests.
    fn insert_test_block(store: &mut Store, root: H256, slot: u64, parent_root: H256) {
        let signed_block = SignedBlock {
            message: Block {
                slot,
                proposer_index: 0,
                parent_root,
                state_root: H256::ZERO,
                body: BlockBody::default(),
            },
            proof: MultiMessageAggregate::default(),
        };
        store
            .insert_signed_block(root, signed_block)
            .expect("insert test block should succeed");
    }

    // ---- resolve_job ----

    /// Given gossip sigs for {a,b} and a proof covering {c}, `resolve_job`
    /// keeps {a,b} raw and reuses the proof for {c} as a child (c is not
    /// covered by any raw sig, so nothing is trimmed).
    #[test]
    fn resolve_job_prefers_raw_then_fills_missing_coverage() {
        let validators = make_validators(5);
        let sig = dummy_sig();
        let validator_sigs = vec![(0u64, sig.clone()), (1u64, sig)];
        let proof_c = SingleMessageAggregate::empty(make_bits(&[2]));

        let resolved = resolve_job(
            dummy_hashed(),
            &validator_sigs,
            &[proof_c],
            &[],
            &validators,
        )
        .expect("raw {0,1} plus a filling child for {2} should be viable");

        let raw_id_set: HashSet<u64> = resolved.raw_ids.iter().copied().collect();
        assert_eq!(raw_id_set, HashSet::from([0, 1]), "both raw sigs kept");
        assert_eq!(
            resolved.children.len(),
            1,
            "the proof for {{c}} is reused as a child"
        );
        assert_eq!(resolved.accepted_child_ids, vec![2]);
        assert_eq!(resolved.coverage(), HashSet::from([0, 1, 2]));
    }

    /// Given gossip sigs for {a,b,c} and a proof covering {c,d,e} (chosen for
    /// its new coverage {d,e}), `resolve_job` trims the now-redundant raw sig
    /// for c: `aggregate_mixed` must never see a validator both raw and
    /// inside a child. Realized coverage still includes c via the child.
    #[test]
    fn resolve_job_trims_raw_covered_by_chosen_child() {
        let validators = make_validators(5);
        let sig = dummy_sig();
        let validator_sigs = vec![(0u64, sig.clone()), (1u64, sig.clone()), (2u64, sig)];
        let proof_cde = SingleMessageAggregate::empty(make_bits(&[2, 3, 4]));

        let resolved = resolve_job(
            dummy_hashed(),
            &validator_sigs,
            &[proof_cde],
            &[],
            &validators,
        )
        .expect("raw {0,1,2} plus a child for {2,3,4} should be viable");

        let raw_id_set: HashSet<u64> = resolved.raw_ids.iter().copied().collect();
        assert_eq!(
            raw_id_set,
            HashSet::from([0, 1]),
            "id 2 is trimmed: it is covered by the chosen child"
        );
        assert_eq!(resolved.children.len(), 1);
        assert_eq!(resolved.coverage(), HashSet::from([0, 1, 2, 3, 4]));
        // The whole gossip group (including the trimmed raw sig) is consumed.
        assert_eq!(resolved.keys_to_delete.len(), 3);
    }

    /// A lone raw signature with no children to merge is not a viable job:
    /// aggregating a single signature carries no benefit over gossiping it.
    #[test]
    fn resolve_job_rejects_lone_raw_signature_with_no_children() {
        let validators = make_validators(5);
        let validator_sigs = vec![(0u64, dummy_sig())];
        let resolved = resolve_job(dummy_hashed(), &validator_sigs, &[], &[], &validators);
        assert!(resolved.is_none());
    }

    /// Payload-only candidates (no raw gossip sigs) are viable once at least
    /// two existing proofs can be merged.
    #[test]
    fn resolve_job_allows_payload_only_merge_with_two_children() {
        let validators = make_validators(5);
        let proof_a = SingleMessageAggregate::empty(make_bits(&[0]));
        let proof_b = SingleMessageAggregate::empty(make_bits(&[1]));

        let resolved = resolve_job(dummy_hashed(), &[], &[proof_a, proof_b], &[], &validators)
            .expect("two children with no raw sigs should be viable");

        assert!(resolved.raw_ids.is_empty());
        assert_eq!(resolved.children.len(), 2);
        assert_eq!(resolved.coverage(), HashSet::from([0, 1]));
        assert!(
            resolved.keys_to_delete.is_empty(),
            "nothing to delete from gossip: this candidate has no gossip sigs"
        );
    }

    // ---- ordering ----

    /// The slot bucket dominates the within-bucket score: a current-slot
    /// candidate is picked ahead of a stale candidate that has *more* new
    /// voters (which, absent the bucket, would win the Build-tier
    /// `new_voters` dimension). Exercises `candidate_ordering_key` through the
    /// real `pick_best_candidate` path rather than constructing an
    /// `EntryScore` directly.
    #[test]
    fn pick_best_candidate_prefers_current_slot_over_higher_stale_score() {
        const NUM_VALIDATORS: usize = 100;
        const CURRENT_SLOT: u64 = 3;

        let genesis_root = H256([1u8; 32]);
        let target_root = H256([7u8; 32]);
        let source = Checkpoint {
            root: genesis_root,
            slot: 0,
        };
        let target = Checkpoint {
            root: target_root,
            slot: 3,
        };
        let head = Checkpoint {
            root: genesis_root,
            slot: 0,
        };

        // Current-slot candidate: only 1 new voter.
        let att_current = AttestationData {
            slot: CURRENT_SLOT,
            head,
            target,
            source,
        };
        // Stale candidate (different target root so their voter buckets are
        // independent): 5 new voters — a strictly better within-Build score.
        let stale_target_root = H256([9u8; 32]);
        let att_stale = AttestationData {
            slot: CURRENT_SLOT - 1,
            head,
            target: Checkpoint {
                root: stale_target_root,
                slot: 2,
            },
            source,
        };

        let hashed_current = HashedAttestationData::new(att_current);
        let hashed_stale = HashedAttestationData::new(att_stale);
        let root_current = hashed_current.root();
        let root_stale = hashed_stale.root();

        let make_job = |hashed: HashedAttestationData, coverage: HashSet<u64>| {
            let slot = hashed.data().slot;
            AggregationJob {
                hashed,
                slot,
                children: Vec::new(),
                accepted_child_ids: Vec::new(),
                raw_pubkeys: Vec::new(),
                raw_sigs: Vec::new(),
                raw_ids: coverage.into_iter().collect(),
                keys_to_delete: Vec::new(),
            }
        };

        let mut candidates: HashMap<H256, AggregationJob> = HashMap::new();
        candidates.insert(root_current, make_job(hashed_current, HashSet::from([0])));
        candidates.insert(
            root_stale,
            make_job(hashed_stale, HashSet::from([1, 2, 3, 4, 5])),
        );

        let known_block_roots: HashSet<H256> = HashSet::from([genesis_root]);
        // Index 0 = genesis (head/source), 2 = stale target, 3 = current target.
        let historical_block_hashes =
            vec![genesis_root, H256::ZERO, stale_target_root, target_root];

        let projected = block_builder::ProjectedState {
            justified_slots: JustifiedSlots::new(),
            finalized_slot: 0,
            current_votes: HashMap::new(),
        };

        let (picked_root, score) = pick_best_candidate(
            &candidates,
            &projected,
            &known_block_roots,
            &historical_block_hashes,
            CURRENT_SLOT,
            NUM_VALIDATORS,
        )
        .expect("both candidates are viable Build-tier entries");

        assert_eq!(score.tier, block_builder::Tier::Build);
        assert_eq!(
            picked_root, root_current,
            "the current-slot group must be picked ahead of a stale group with more new voters"
        );
    }

    // ---- projection ----

    /// Two candidates targeting the same root accumulate coverage: the
    /// second is re-tiered upward once the first candidate's realized
    /// coverage is folded into `current_votes` for that target.
    #[test]
    fn pick_best_candidate_re_tiers_same_target_after_first_selection() {
        const NUM_VALIDATORS: usize = 10;

        let genesis_root = H256([1u8; 32]);
        let target_root = H256([7u8; 32]);
        let source = Checkpoint {
            root: genesis_root,
            slot: 0,
        };
        let target = Checkpoint {
            root: target_root,
            slot: 3,
        };
        let head = Checkpoint {
            root: genesis_root,
            slot: 0,
        };

        // A covers 6 validators (Build tier alone: 6*3=18 < 2*10=20).
        let att_a = AttestationData {
            slot: 1,
            head,
            target,
            source,
        };
        // B covers 2 more validators on the SAME target.
        let att_b = AttestationData {
            slot: 2,
            head,
            target,
            source,
        };

        let hashed_a = HashedAttestationData::new(att_a);
        let hashed_b = HashedAttestationData::new(att_b);
        let root_a = hashed_a.root();
        let root_b = hashed_b.root();

        let make_job = |hashed: HashedAttestationData, coverage: HashSet<u64>| {
            let slot = hashed.data().slot;
            AggregationJob {
                hashed,
                slot,
                children: Vec::new(),
                accepted_child_ids: Vec::new(),
                raw_pubkeys: Vec::new(),
                raw_sigs: Vec::new(),
                raw_ids: coverage.into_iter().collect(),
                keys_to_delete: Vec::new(),
            }
        };

        let mut candidates: HashMap<H256, AggregationJob> = HashMap::new();
        candidates.insert(
            root_a,
            make_job(hashed_a, HashSet::from([0, 1, 2, 3, 4, 5])),
        );
        candidates.insert(root_b, make_job(hashed_b, HashSet::from([6, 7])));

        let known_block_roots: HashSet<H256> = HashSet::from([genesis_root]);
        // Index 0 = genesis (head/source), index 3 = target.
        let historical_block_hashes = vec![genesis_root, H256::ZERO, H256::ZERO, target_root];

        let mut projected = block_builder::ProjectedState {
            justified_slots: JustifiedSlots::new(),
            finalized_slot: 0,
            current_votes: HashMap::new(),
        };

        // Round 1: A (6 new voters) outranks B (2 new voters); both Build tier.
        let (picked_root, score) = pick_best_candidate(
            &candidates,
            &projected,
            &known_block_roots,
            &historical_block_hashes,
            999,
            NUM_VALIDATORS,
        )
        .expect("round 1 should find a candidate");
        assert_eq!(picked_root, root_a);
        assert_eq!(score.tier, block_builder::Tier::Build);

        // Fold the winner into the projection, standing in for the store
        // update the actor applies before the worker's next round.
        let winner = candidates.remove(&picked_root).expect("A is in the pool");
        projected
            .current_votes
            .entry(target_root)
            .or_default()
            .extend(winner.coverage());

        // Round 2: only B remains. Combined with A's now-recorded 6 voters,
        // B's 2 new voters cross 2/3 of 10 — B is re-tiered from what would
        // have been Build in isolation to Justify.
        let (picked_root, score) = pick_best_candidate(
            &candidates,
            &projected,
            &known_block_roots,
            &historical_block_hashes,
            999,
            NUM_VALIDATORS,
        )
        .expect("round 2 should find B");
        assert_eq!(picked_root, root_b);
        assert_eq!(
            score.tier,
            block_builder::Tier::Justify,
            "B alone doesn't cross 2/3, but combined with A's prior coverage it does"
        );
    }

    // ---- select_best_job (full pipeline) ----

    /// An empty store (no gossip signatures, no pending payloads) has nothing
    /// to aggregate.
    #[test]
    fn select_returns_none_for_empty_store() {
        let hashes = vec![H256([1u8; 32])];
        let store = new_test_store(make_head_state(0, 4, &hashes));
        assert!(select_best_job(&store, 0, JobPolicy::Open, &EmittedCoverage::default()).is_none());
    }

    /// A single gossip signature with no other material to merge is dropped
    /// as non-viable up front, leaving zero candidates.
    #[test]
    fn select_returns_none_for_lone_raw_signature() {
        let hashes = vec![H256([1u8; 32])];
        let mut store = new_test_store(make_head_state(0, 4, &hashes));
        insert_test_block(&mut store, hashes[0], 0, H256::ZERO);

        let att_data = AttestationData {
            slot: 0,
            head: Checkpoint {
                root: hashes[0],
                slot: 0,
            },
            target: Checkpoint {
                root: hashes[0],
                slot: 0,
            },
            source: Checkpoint {
                root: hashes[0],
                slot: 0,
            },
        };
        let hashed = HashedAttestationData::new(att_data);
        store.insert_gossip_signature(hashed, 0, dummy_sig());

        assert!(select_best_job(&store, 0, JobPolicy::Open, &EmittedCoverage::default()).is_none());
    }

    /// A group whose target is already justified (here: at or behind the
    /// finalized boundary) can never justify or finalize anything further and
    /// must never become a job, even with enough raw sigs to otherwise be
    /// viable.
    #[test]
    fn select_skips_group_whose_target_is_already_justified() {
        const NUM_VALIDATORS: usize = 10;
        const HEAD_SLOT: u64 = 20;
        const FINALIZED_SLOT: u64 = 10;
        const TARGET_SLOT: u64 = 5; // <= FINALIZED_SLOT: implicitly justified

        let hashes: Vec<H256> = (0..HEAD_SLOT).map(|i| H256([(i + 1) as u8; 32])).collect();
        let mut head_state = make_head_state(HEAD_SLOT, NUM_VALIDATORS, &hashes);
        head_state.latest_finalized = Checkpoint {
            root: hashes[FINALIZED_SLOT as usize],
            slot: FINALIZED_SLOT,
        };
        let mut store = new_test_store(head_state);
        insert_test_block(&mut store, hashes[0], 0, H256::ZERO);

        let att_data = AttestationData {
            slot: TARGET_SLOT,
            head: Checkpoint {
                root: hashes[0],
                slot: 0,
            },
            target: Checkpoint {
                root: hashes[TARGET_SLOT as usize],
                slot: TARGET_SLOT,
            },
            source: Checkpoint {
                root: hashes[0],
                slot: 0,
            },
        };
        let hashed = HashedAttestationData::new(att_data);
        store.insert_gossip_signature(hashed.clone(), 0, dummy_sig());
        store.insert_gossip_signature(hashed, 1, dummy_sig());

        assert!(
            select_best_job(&store, 999, JobPolicy::Open, &EmittedCoverage::default()).is_none(),
            "a group targeting an already-justified slot must never become a job"
        );
    }

    /// Regression: a vote for the *current head* (head.slot == target.slot ==
    /// head_slot) must pass the chain-match filter and become a job.
    ///
    /// A state's `historical_block_hashes` only covers [0, head_slot - 1]
    /// (`process_block_header` pushes the parent root, never the block's own
    /// root), so the chain view must be extended by `store.head()` to cover
    /// the tip at index head_slot. Without that extension,
    /// `attestation_data_matches_chain` rejects any vote whose head/target is
    /// the current head (head_slot >= historical_block_hashes.len()), which on
    /// a non-genesis chain is nearly every fresh vote: every candidate is
    /// filtered as `chain_mismatch` and aggregation produces nothing.
    ///
    /// This test FAILS against the unextended (buggy) chain view and PASSES
    /// after the `store.head()` extension.
    #[test]
    fn select_aggregates_vote_for_current_head_on_non_genesis_chain() {
        const NUM_VALIDATORS: usize = 10;
        const HEAD_SLOT: u64 = 4;

        // On-chain roots for slots [0, HEAD_SLOT - 1]; the head block's own
        // root at HEAD_SLOT is NOT here (it is `store.head()`), mirroring how
        // `process_block_header` builds the list.
        let hashes: Vec<H256> = (0..HEAD_SLOT).map(|i| H256([(i + 1) as u8; 32])).collect();
        let mut store = new_test_store(make_head_state(HEAD_SLOT, NUM_VALIDATORS, &hashes));

        // The canonical tip: `head_state` is the state at this block, and it
        // sits at index HEAD_SLOT once the chain view is extended.
        let head_root = store.head().expect("head read works");

        // Vote whose head AND target are the current head at HEAD_SLOT, with a
        // genesis (implicitly justified) source. Justifiable: delta 4 <= 5.
        let att_data = AttestationData {
            slot: HEAD_SLOT,
            head: Checkpoint {
                root: head_root,
                slot: HEAD_SLOT,
            },
            target: Checkpoint {
                root: head_root,
                slot: HEAD_SLOT,
            },
            source: Checkpoint {
                root: hashes[0],
                slot: 0,
            },
        };
        let hashed = HashedAttestationData::new(att_data);
        // Two raw sigs so the group is viable (a lone raw sig is dropped).
        store.insert_gossip_signature(hashed.clone(), 0, dummy_sig());
        store.insert_gossip_signature(hashed, 1, dummy_sig());

        let job = select_best_job(
            &store,
            HEAD_SLOT,
            JobPolicy::Open,
            &EmittedCoverage::default(),
        )
        .expect("a vote for the current head must produce a job (chain view covers the tip)");
        assert_eq!(
            job.hashed.data().target.slot,
            HEAD_SLOT,
            "the job aggregates the vote targeting the current head"
        );
    }

    /// Number of competing candidates built by
    /// [`store_with_competing_build_tier_groups`]; more than either job cap so
    /// both cap tests actually bind.
    const NUM_GROUPS: usize = 5;

    /// Store holding `NUM_GROUPS` competing Build-tier candidates (2 raw sigs
    /// each, well under the 2/3 threshold) that differ only by `target_slot`
    /// (`1..=NUM_GROUPS`, all justifiable at delta <= 5). Build-tier ordering
    /// prefers larger `target_slot` on a new_voters tie, so selection takes
    /// them highest-slot-first.
    fn store_with_competing_build_tier_groups() -> Store {
        const NUM_VALIDATORS: usize = 10;
        const HEAD_SLOT: u64 = 10;

        let hashes: Vec<H256> = (0..HEAD_SLOT).map(|i| H256([(i + 1) as u8; 32])).collect();
        let mut store = new_test_store(make_head_state(HEAD_SLOT, NUM_VALIDATORS, &hashes));
        insert_test_block(&mut store, hashes[0], 0, H256::ZERO);

        for i in 0..NUM_GROUPS {
            let target_slot = i as u64 + 1;
            let att_data = AttestationData {
                slot: target_slot,
                head: Checkpoint {
                    root: hashes[0],
                    slot: 0,
                },
                target: Checkpoint {
                    root: hashes[target_slot as usize],
                    slot: target_slot,
                },
                source: Checkpoint {
                    root: hashes[0],
                    slot: 0,
                },
            };
            let hashed = HashedAttestationData::new(att_data);
            // Distinct validator pair per group so groups don't interact.
            store.insert_gossip_signature(hashed.clone(), (2 * i) as u64, dummy_sig());
            store.insert_gossip_signature(hashed, (2 * i + 1) as u64, dummy_sig());
        }

        store
    }

    /// From a pool of competing candidates the selector emits the single
    /// best-scoring one — here the highest `target_slot`, which wins the
    /// Build-tier `new_voters` tie.
    #[test]
    fn select_picks_the_best_scoring_candidate() {
        let store = store_with_competing_build_tier_groups();

        let job = select_best_job(&store, 999, JobPolicy::Open, &EmittedCoverage::default())
            .expect("should produce a job");
        assert_eq!(job.hashed.data().target.slot, NUM_GROUPS as u64);
    }

    /// A candidate whose whole coverage is already in flight (proved, message
    /// not yet applied by the actor) is skipped, so the worker moves on to the
    /// next-best group instead of re-proving the same one.
    #[test]
    fn select_skips_coverage_already_emitted() {
        let store = store_with_competing_build_tier_groups();

        let mut emitted = EmittedCoverage::default();
        let first = select_best_job(&store, 999, JobPolicy::Open, &emitted).expect("first job");
        let first_target = first.hashed.data().target.slot;
        let covered: Vec<u64> = first.coverage().into_iter().collect();
        emitted.record(first.hashed.root(), &covered);

        let second = select_best_job(&store, 999, JobPolicy::Open, &emitted).expect("second job");
        assert_eq!(
            second.hashed.data().target.slot,
            first_target - 1,
            "the in-flight group is skipped for the next-best one"
        );
    }

    /// Early in the slot a current-slot group short of the signature floor is
    /// held back, but stale groups in the same pool are still fair game: the
    /// worker keeps busy on the backlog.
    #[test]
    fn select_holds_current_slot_group_below_the_floor() {
        let store = store_with_competing_build_tier_groups();

        // Groups carry two signatures each and are keyed by `target_slot`,
        // which doubles as their attestation slot in this fixture.
        let job = select_best_job(
            &store,
            NUM_GROUPS as u64,
            JobPolicy::Backlog { min_sigs: 3 },
            &EmittedCoverage::default(),
        )
        .expect("stale groups stay eligible");
        assert_eq!(
            job.hashed.data().target.slot,
            NUM_GROUPS as u64 - 1,
            "the current-slot group is held; the best stale one is taken instead"
        );
    }

    /// Inside the early window the backlog is held back too: with no
    /// current-slot group at the floor there is nothing to do, and idling is
    /// the point — a recursive merge started here would run into the slot's
    /// committee aggregation.
    #[test]
    fn select_holds_the_backlog_inside_the_early_window() {
        let store = store_with_competing_build_tier_groups();

        assert!(
            select_best_job(
                &store,
                NUM_GROUPS as u64,
                JobPolicy::CommitteeOnly { min_sigs: 3 },
                &EmittedCoverage::default(),
            )
            .is_none(),
            "no current-slot group meets the floor, so the worker waits"
        );
    }

    /// The current-slot group is taken inside the window as soon as it meets
    /// the floor: that is the work the window is kept free for.
    #[test]
    fn select_takes_the_current_slot_group_at_the_floor() {
        let store = store_with_competing_build_tier_groups();

        let job = select_best_job(
            &store,
            NUM_GROUPS as u64,
            JobPolicy::CommitteeOnly { min_sigs: 2 },
            &EmittedCoverage::default(),
        )
        .expect("the current-slot group meets the floor");
        assert_eq!(job.hashed.data().target.slot, NUM_GROUPS as u64);
    }

    /// The same group the floor held back is taken once the boundary opens the
    /// policy, however few signatures it holds.
    #[test]
    fn select_takes_current_slot_group_once_the_policy_opens() {
        let store = store_with_competing_build_tier_groups();

        let job = select_best_job(
            &store,
            NUM_GROUPS as u64,
            JobPolicy::Open,
            &EmittedCoverage::default(),
        )
        .expect("should produce a job");
        assert_eq!(job.hashed.data().target.slot, NUM_GROUPS as u64);
    }

    /// The floor is two thirds of the votes the node's own subnets are
    /// expected to carry, not two thirds of the validator set: with 10
    /// validators over 4 committees, subnets 0 and 1 hold 3 each, so a group
    /// gathering both needs 4 of those 6.
    #[test]
    fn min_current_slot_group_sigs_counts_subscribed_subnets_only() {
        let subscribed = HashSet::from([0, 1]);
        assert_eq!(
            min_current_slot_group_sigs(10, 4, &subscribed),
            Some(4),
            "ceil(2/3 * (3 + 3))"
        );

        // A subnet past the committee count carries no validators.
        assert_eq!(
            min_current_slot_group_sigs(10, 4, &HashSet::from([9])),
            None
        );
        // No committees at all: nothing to expect.
        assert_eq!(min_current_slot_group_sigs(10, 0, &subscribed), None);
    }

    /// The policy is purely a function of where in the slot we are: backlog
    /// work early, committee signatures only inside the early window, and
    /// everything from the vote-aggregation boundary to the slot's end. The
    /// boundaries follow the configured slot duration; the window ahead of
    /// them does not, since it is sized against one leanVM proof.
    #[test]
    fn job_policy_tightens_into_the_window_and_opens_at_the_boundary() {
        let hashes = vec![H256([1u8; 32])];
        let store = new_test_store(make_head_state(0, 10, &hashes));
        let config = WorkerConfig {
            attestation_committee_count: 4,
            subscribed_subnets: HashSet::from([0, 1]),
        };
        // 10 validators over 4 committees: subnets 0 and 1 hold 3 each, so a
        // group gathering both needs 4 of those 6.
        let min_sigs = 4;

        for milliseconds_per_slot in [DEFAULT_MILLISECONDS_PER_SLOT, 8_000] {
            let time_config = ChainConfig::new(1_000, milliseconds_per_slot);
            let boundary = vote_aggregation_offset_ms(&time_config);
            assert_eq!(boundary, 2 * milliseconds_per_slot / INTERVALS_PER_SLOT);
            let window_opens_at = boundary - EARLY_AGGREGATION_WINDOW.as_millis() as u64;

            assert_eq!(
                job_policy(0, &time_config, &store, &config),
                JobPolicy::Backlog { min_sigs }
            );
            assert_eq!(
                job_policy(window_opens_at - 1, &time_config, &store, &config),
                JobPolicy::Backlog { min_sigs }
            );
            assert_eq!(
                job_policy(window_opens_at, &time_config, &store, &config),
                JobPolicy::CommitteeOnly { min_sigs }
            );
            assert_eq!(
                job_policy(boundary - 1, &time_config, &store, &config),
                JobPolicy::CommitteeOnly { min_sigs }
            );
            assert_eq!(
                job_policy(boundary, &time_config, &store, &config),
                JobPolicy::Open
            );
            assert_eq!(
                job_policy(milliseconds_per_slot - 1, &time_config, &store, &config),
                JobPolicy::Open
            );
        }
    }
}
