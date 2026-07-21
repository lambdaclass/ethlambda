//! Committee-signature aggregation: off-thread worker orchestration and the
//! pure functions it runs.
//!
//! The blockchain actor fires one aggregation session per slot — at interval 2,
//! or up to [`EARLY_AGGREGATION_WINDOW`] early when the 2/3 signature
//! threshold is met — via
//! [`run_aggregation_worker`]. The actor stays on its message loop; the worker
//! runs the expensive XMSS proofs on a `spawn_blocking` thread and streams
//! results back as [`AggregateProduced`] / [`AggregationDone`] messages.
//!
//! [`snapshot_aggregation_inputs`] builds the session's job list with a tiered
//! greedy selector modeled on `block_builder::select_attestations`: an
//! up-front store pass resolves every candidate `AttestationData`'s
//! aggregation material once (raw-first + trim, see [`resolve_job`]), then a
//! pure in-memory loop scores and orders candidates by consensus value
//! (current-slot before stale, then Finalize > Justify > Build), emitting at
//! most [`MAX_AGGREGATION_JOBS`] jobs.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime};

use ethlambda_crypto::aggregate_mixed;
use ethlambda_storage::Store;
use ethlambda_types::{
    ShortRoot,
    attestation::{AggregationBits, AttestationData, HashedAttestationData},
    block::{ByteList512KiB, SingleMessageAggregate},
    primitives::H256,
    signature::{ValidatorPublicKey, ValidatorSignature},
    state::Validator,
};
use spawned_concurrency::message::Message;
use spawned_concurrency::tasks::{ActorRef, Context, send_after};
use tokio_util::sync::CancellationToken;
use tracing::{info, trace, warn};

use crate::block_builder::{self, EntryScore};
use crate::{MILLISECONDS_PER_INTERVAL, metrics};

/// Soft deadline for committee-signature aggregation measured from session
/// start. After this much wall time elapses, the actor signals the worker to
/// stop via its cancellation token. A session started exactly at interval 2
/// gets the full interval (interval 3 is one interval later); a session
/// started early (see `maybe_start_early_aggregation`) ends correspondingly
/// earlier. The deadline only stops new jobs from starting — a job mid-proof
/// finishes and publishes right after.
pub(crate) const AGGREGATION_DEADLINE: Duration = Duration::from_millis(800);
/// Upper bound we wait for a prior worker to exit if it is still running when
/// the next session is about to start. Reached only in pathological cases
/// (mismatched timers, stuck proofs); we warn before blocking.
pub(crate) const PRIOR_WORKER_JOIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Width of the early-aggregation window: a session may start at most this
/// long before the interval-2 boundary, provided the signature threshold is
/// met (see the check in `maybe_start_early_aggregation`).
pub(crate) const EARLY_AGGREGATION_WINDOW: Duration = Duration::from_millis(600);

// The window must fit within one interval: `maybe_start_early_aggregation`
// subtracts it from the interval-2 offset, and the interval-1 tick schedules
// the check at `MILLISECONDS_PER_INTERVAL - EARLY_AGGREGATION_WINDOW`. Keep
// this invariant self-enforcing so a future bump to the window can't silently
// underflow either subtraction.
const _: () = assert!(
    EARLY_AGGREGATION_WINDOW.as_millis() <= MILLISECONDS_PER_INTERVAL as u128,
    "EARLY_AGGREGATION_WINDOW must not exceed one interval"
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

/// All input needed to run a session of committee-signature aggregation off-thread.
pub struct AggregationSnapshot {
    pub(crate) jobs: Vec<AggregationJob>,
    pub(crate) groups_considered: usize,
}

/// Result of one successful aggregation group. Carried back to the actor thread
/// as a message payload so the store can be updated and gossip publish fired.
pub struct AggregatedGroupOutput {
    pub(crate) hashed: HashedAttestationData,
    pub(crate) proof: SingleMessageAggregate,
    pub(crate) participants: Vec<u64>,
    pub(crate) keys_to_delete: Vec<(u64, H256)>,
}

/// Tracks an in-flight off-thread aggregation worker so the actor can cancel,
/// join, and correlate incoming result messages with the right session.
pub(crate) struct AggregationSession {
    /// Slot at which this session was started; used as a fencing id so we can
    /// drop late-arriving messages from a prior session.
    pub(crate) session_id: u64,
    /// Whether the session started before the slot's interval-2 boundary via
    /// the early-aggregation trigger.
    pub(crate) early: bool,
    /// Child of the actor cancellation token; fires either at the deadline or
    /// when the actor itself is stopping.
    pub(crate) cancel: CancellationToken,
    /// Handle to the `spawn_blocking` worker. Held so `stopped()` / new-session
    /// start can await completion.
    pub(crate) worker: tokio::task::JoinHandle<()>,
}

/// One successful aggregate streamed back from the worker.
pub(crate) struct AggregateProduced {
    pub(crate) session_id: u64,
    pub(crate) output: AggregatedGroupOutput,
}
impl Message for AggregateProduced {
    type Result = ();
}

/// Emitted by the worker after its loop exits (completion or cancellation).
pub(crate) struct AggregationDone {
    pub(crate) session_id: u64,
    pub(crate) groups_considered: usize,
    pub(crate) groups_aggregated: usize,
    pub(crate) total_raw_sigs: usize,
    pub(crate) total_children: usize,
    pub(crate) total_elapsed: Duration,
    pub(crate) cancelled: bool,
}
impl Message for AggregationDone {
    type Result = ();
}

/// Self-message scheduled via `send_after` at session start. Cancels the
/// session's token so the worker stops starting new aggregations.
pub(crate) struct AggregationDeadline {
    pub(crate) session_id: u64,
}
impl Message for AggregationDeadline {
    type Result = ();
}

/// One-shot self-message scheduled at the interval-1 tick; fires when the
/// early-aggregation window opens (T2 - EARLY_AGGREGATION_WINDOW) to run
/// the threshold check for signatures that all arrived before the window.
/// Arrivals inside the window are checked per insert instead.
pub(crate) struct EarlyAggregationCheck;
impl Message for EarlyAggregationCheck {
    type Result = ();
}

/// Maximum number of aggregation jobs selected per interval-2 session. Caps
/// leanVM prover work against [`AGGREGATION_DEADLINE`]: the greedy loop in
/// [`snapshot_aggregation_inputs`] stops after this many rounds even if
/// scoring candidates remain.
const MAX_AGGREGATION_JOBS: usize = 3;

/// Build a snapshot of everything needed to aggregate. Runs on the actor
/// thread, touches the store, does no heavy cryptography. Returns `None` when
/// there is nothing to aggregate so callers can avoid spawning an empty worker.
///
/// A tiered greedy selector modeled on `block_builder::select_attestations`:
///
/// 1. **Up-front store pass**: resolves every candidate `AttestationData`
///    into a store-free [`AggregationJob`] once via [`resolve_job`]
///    (raw-first, then trim). Candidates come from gossip groups
///    (`store.iter_gossip_signatures()`) and payload-only groups
///    (`store.new_payload_keys()` not already a gossip candidate, requiring
///    at least two existing proofs to merge).
/// 2. **Greedy loop**, at most [`MAX_AGGREGATION_JOBS`] rounds: each round
///    scores every unselected candidate against the projected state and
///    keeps the lowest ordering key (current-slot before stale, then
///    Finalize > Justify > Build, mirroring the block builder). The winning
///    [`AggregationJob`] is emitted as-is; the projection is updated with its
///    realized coverage.
///
/// Stops early when no remaining candidate scores (converged).
pub fn snapshot_aggregation_inputs(
    store: &Store,
    current_slot: u64,
) -> Option<AggregationSnapshot> {
    let gossip_groups = store.iter_gossip_signatures();
    let new_payload_keys = store.new_payload_keys();

    if gossip_groups.is_empty() && new_payload_keys.is_empty() {
        return None;
    }

    let head_state = store.head_state();
    let validators = &head_state.validators;

    let mut candidates: HashMap<H256, AggregationJob> = HashMap::new();

    for (hashed, validator_sigs) in &gossip_groups {
        let data_root = hashed.root();
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

    if candidates.is_empty() {
        return None;
    }
    let groups_considered = candidates.len();
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

    let mut projected = block_builder::ProjectedState::from_head_state(&head_state);

    let mut jobs: Vec<AggregationJob> =
        Vec::with_capacity(MAX_AGGREGATION_JOBS.min(groups_considered));
    for _round in 0..MAX_AGGREGATION_JOBS {
        let Some((data_root, score)) = pick_best_candidate(
            &candidates,
            &projected,
            &known_block_roots,
            &extended_historical_block_hashes,
            current_slot,
            validator_count,
        ) else {
            trace!(
                jobs_selected = jobs.len(),
                "aggregation selection converged: no scoring candidates"
            );
            break;
        };

        let job = candidates
            .remove(&data_root)
            .expect("picked candidate exists in pool");
        let coverage = job.coverage();
        let att_data = job.hashed.data();
        let target_root = att_data.target.root;
        let target_slot = att_data.target.slot;

        trace!(
            tier = ?score.tier,
            new_voters = score.new_voters,
            target_slot,
            target_root = %ShortRoot(&target_root.0),
            data_root = %ShortRoot(&data_root.0),
            "selected aggregation job"
        );

        // Fold the job's realized coverage into the shared projection so
        // same-target candidates re-tier across rounds exactly as the block
        // builder's post-state would.
        projected.advance(score.tier, att_data, coverage.iter().copied());

        jobs.push(job);
    }

    if jobs.is_empty() {
        return None;
    }

    Some(AggregationSnapshot {
        jobs,
        groups_considered,
    })
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
        let Ok(pubkey) = validator.get_attestation_pubkey() else {
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
            .filter_map(|&vid| validators.get(vid as usize)?.get_attestation_pubkey().ok())
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

/// End-of-session gauge refresh. Called once after the worker finishes so the
/// `lean_latest_new_aggregated_payloads` and `lean_gossip_signatures` gauges
/// settle on the final counts instead of being churned per aggregate.
pub fn finalize_aggregation_session(store: &Store) {
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

/// Worker loop — runs on a `spawn_blocking` thread, no store access.
///
/// Pulls jobs from the snapshot, runs [`aggregate_job`] for each, and streams
/// successful aggregates back to the actor as [`AggregateProduced`] messages.
/// Emits [`AggregationDone`] when the loop exits (completion or cancellation).
///
/// Publish alignment: aggregates must not reach the actor (and thus gossip)
/// before the interval-2 boundary. `publish_at` is that boundary as a wall-clock
/// instant; a produced aggregate still ahead of it is delivered via
/// [`send_after`] timed to land at the boundary, otherwise it is sent
/// immediately. A normal interval-2 session starts at the boundary, so its
/// aggregates are always past it and sent without delay.
pub(crate) fn run_aggregation_worker(
    snapshot: AggregationSnapshot,
    actor: ActorRef<crate::BlockChainServer>,
    cancel: CancellationToken,
    session_id: u64,
    publish_at: SystemTime,
) {
    let start = Instant::now();
    let groups_considered = snapshot.groups_considered;
    let mut groups_aggregated = 0usize;
    let mut total_raw_sigs = 0usize;
    let mut total_children = 0usize;
    let jobs_total = snapshot.jobs.len();
    let mut jobs_attempted = 0usize;

    for job in snapshot.jobs {
        if cancel.is_cancelled() {
            break;
        }
        jobs_attempted += 1;

        let slot = job.slot;
        let raw_sigs = job.raw_ids.len();
        let children = job.children.len();

        let group_start = Instant::now();
        let Some(output) = aggregate_job(job) else {
            let elapsed = group_start.elapsed();
            warn!(
                session_id,
                slot,
                raw_sigs,
                children,
                ?elapsed,
                "Committee signature aggregation failed"
            );
            continue;
        };
        let elapsed = group_start.elapsed();
        info!(
            session_id,
            slot,
            raw_sigs,
            children,
            participants = output.participants.len(),
            ?elapsed,
            "Committee signature aggregated"
        );

        groups_aggregated += 1;
        total_raw_sigs += raw_sigs;
        total_children += children;

        // Hold the aggregate until the interval-2 boundary (early session), or
        // send now if already at/past it. `send_after` is fire-and-forget: it
        // spawns a timer that delivers the message and is cancelled only if the
        // actor stops, so the produced aggregate is not lost when the worker's
        // own loop ends. `duration_since` errs once the boundary has passed,
        // which collapses to a zero delay here.
        let delay = publish_at
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO);
        if delay.is_zero() {
            if actor
                .send(AggregateProduced { session_id, output })
                .is_err()
            {
                // Actor is gone; no point producing more.
                break;
            }
        } else {
            send_after(
                delay,
                Context::from_ref(&actor),
                AggregateProduced { session_id, output },
            );
        }
    }

    // Jobs the loop never reached (deadline cancellation or actor gone) are
    // skipped aggregation submissions per leanMetrics.
    let jobs_dropped = jobs_total - jobs_attempted;
    if jobs_dropped > 0 {
        metrics::inc_aggregator_skipped_other(jobs_dropped as u64);
    }

    let _ = actor.send(AggregationDone {
        session_id,
        groups_considered,
        groups_aggregated,
        total_raw_sigs,
        total_children,
        total_elapsed: start.elapsed(),
        cancelled: cancel.is_cancelled(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_storage::backend::InMemoryBackend;
    use ethlambda_types::{
        block::{Block, BlockBody, BlockHeader, MultiMessageAggregate, SignedBlock},
        checkpoint::Checkpoint,
        state::{ChainConfig, JustificationValidators, JustifiedSlots, State},
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
        use ethlambda_types::signature::LeanSignatureScheme;
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
            config: ChainConfig { genesis_time: 1000 },
            slot: head_slot,
            latest_block_header: head_header,
            latest_justified: Checkpoint::default(),
            latest_finalized: Checkpoint::default(),
            historical_block_hashes: SszList::try_from(hashes.to_vec()).unwrap(),
            justified_slots: JustifiedSlots::new(),
            validators: SszList::try_from(make_validators(num_validators)).unwrap(),
            justifications_roots: Default::default(),
            justifications_validators: JustificationValidators::new(),
            latest_execution_payload_header: Default::default(),
        }
    }

    fn new_test_store(head_state: State) -> Store {
        let backend: Arc<dyn ethlambda_storage::StorageBackend> = Arc::new(InMemoryBackend::new());
        Store::from_anchor_state(backend, head_state)
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

        // Apply the selection to the projection, as `snapshot_aggregation_inputs` would.
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

    // ---- snapshot_aggregation_inputs (full pipeline) ----

    /// An empty store (no gossip signatures, no pending payloads) has nothing
    /// to aggregate.
    #[test]
    fn snapshot_returns_none_for_empty_store() {
        let hashes = vec![H256([1u8; 32])];
        let store = new_test_store(make_head_state(0, 4, &hashes));
        assert!(snapshot_aggregation_inputs(&store, 0).is_none());
    }

    /// A single gossip signature with no other material to merge is dropped
    /// as non-viable up front, leaving zero candidates.
    #[test]
    fn snapshot_returns_none_for_lone_raw_signature() {
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

        assert!(snapshot_aggregation_inputs(&store, 0).is_none());
    }

    /// A group whose target is already justified (here: at or behind the
    /// finalized boundary) can never justify or finalize anything further and
    /// must never become a job, even with enough raw sigs to otherwise be
    /// viable.
    #[test]
    fn snapshot_skips_group_whose_target_is_already_justified() {
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
            snapshot_aggregation_inputs(&store, 999).is_none(),
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
    fn snapshot_aggregates_vote_for_current_head_on_non_genesis_chain() {
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

        let snapshot = snapshot_aggregation_inputs(&store, HEAD_SLOT)
            .expect("a vote for the current head must produce a job (chain view covers the tip)");
        assert_eq!(snapshot.jobs.len(), 1);
        assert_eq!(
            snapshot.jobs[0].hashed.data().target.slot,
            HEAD_SLOT,
            "the job aggregates the vote targeting the current head"
        );
    }

    /// With more scoring candidates than `MAX_AGGREGATION_JOBS`, exactly that
    /// many jobs are produced — the best `MAX_AGGREGATION_JOBS` by ordering
    /// key. Five Build-tier candidates (2 raw sigs each, well under the 2/3
    /// threshold) differ only by `target_slot`; Build-tier ordering prefers
    /// larger `target_slot` on a new_voters tie, so the top three by slot win.
    #[test]
    fn snapshot_caps_jobs_at_max_aggregation_jobs() {
        const NUM_VALIDATORS: usize = 10;
        const HEAD_SLOT: u64 = 10;
        const NUM_GROUPS: usize = 5;

        let hashes: Vec<H256> = (0..HEAD_SLOT).map(|i| H256([(i + 1) as u8; 32])).collect();
        let mut store = new_test_store(make_head_state(HEAD_SLOT, NUM_VALIDATORS, &hashes));
        insert_test_block(&mut store, hashes[0], 0, H256::ZERO);

        for i in 0..NUM_GROUPS {
            let target_slot = i as u64 + 1; // 1..=5, all justifiable (delta <= 5)
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

        let snapshot = snapshot_aggregation_inputs(&store, 999).expect("should produce jobs");
        assert_eq!(snapshot.groups_considered, NUM_GROUPS);
        assert_eq!(snapshot.jobs.len(), MAX_AGGREGATION_JOBS);

        let selected_targets: HashSet<u64> = snapshot
            .jobs
            .iter()
            .map(|job| job.hashed.data().target.slot)
            .collect();
        assert_eq!(
            selected_targets,
            HashSet::from([3, 4, 5]),
            "the three highest target_slot groups win the new_voters tie"
        );
    }
}
