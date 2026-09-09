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
//! most `max_jobs` jobs — [`MAX_AGGREGATION_JOBS`] normally, dropping to a
//! single job in the slot before one of our validators proposes.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime};

use ethlambda_crypto::aggregate_mixed;
use ethlambda_crypto::signature::{ValidatorPublicKey, ValidatorSignature};
use ethlambda_storage::Store;
use ethlambda_types::{
    ShortRoot,
    attestation::{AggregationBits, AttestationData, HashedAttestationData, validator_indices},
    block::{ByteList512KiB, SingleMessageAggregate},
    constants::{INTERVALS_PER_SLOT, MIN_MILLISECONDS_PER_SLOT},
    primitives::H256,
    state::Validator,
};
use spawned_concurrency::message::Message;
use spawned_concurrency::tasks::{ActorRef, Context, send_after};
use tokio_util::sync::CancellationToken;
use tracing::{info, trace, warn};

use crate::block_builder::{self, EntryScore};
use crate::metrics;

/// Soft deadline for committee-signature aggregation measured from session
/// start: one full interval. After this much wall time elapses, the actor
/// signals the worker to stop via its cancellation token. A session started
/// exactly at interval 2 therefore runs until interval 3; a session started
/// early (see `maybe_start_early_aggregation`) ends correspondingly earlier.
/// The deadline only stops new jobs from starting — a job mid-proof finishes
/// and publishes right after.
pub(crate) fn aggregation_deadline(milliseconds_per_interval: u64) -> Duration {
    Duration::from_millis(milliseconds_per_interval)
}

/// Upper bound we wait for a prior worker to exit if it is still running when
/// the next session is about to start. Reached only in pathological cases
/// (mismatched timers, stuck proofs); we warn before blocking.
pub(crate) const PRIOR_WORKER_JOIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Width of the early-aggregation window: a session may start at most this
/// long before the interval-2 boundary, provided the signature threshold is
/// met (see the check in `maybe_start_early_aggregation`).
///
/// Fixed rather than scaled with the slot duration. What the window buys is
/// wall time for the leanVM proof to land before the block that carries it,
/// and a proof costs the same however long the network's slot is.
pub(crate) const EARLY_AGGREGATION_WINDOW: Duration = Duration::from_millis(600);

// The window must fit within one interval: `maybe_start_early_aggregation`
// subtracts it from the interval-2 offset, and the interval-1 tick schedules
// the check at `milliseconds_per_interval - EARLY_AGGREGATION_WINDOW`. The
// slot duration is configurable, so the binding case is the narrowest interval
// a config file can ask for. Keep this invariant self-enforcing so a future
// bump to the window, or a lowered floor, can't silently underflow either
// subtraction.
const _: () = assert!(
    EARLY_AGGREGATION_WINDOW.as_millis()
        <= (MIN_MILLISECONDS_PER_SLOT / INTERVALS_PER_SLOT) as u128,
    "EARLY_AGGREGATION_WINDOW must not exceed the shortest configurable interval"
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
/// early-aggregation window opens (T2 - [`EARLY_AGGREGATION_WINDOW`]) to run
/// the threshold check for signatures that all arrived before the window.
/// Arrivals inside the window are checked per insert instead.
pub(crate) struct EarlyAggregationCheck;
impl Message for EarlyAggregationCheck {
    type Result = ();
}

/// The aggregator's subnet-window duty, as read by
/// [`snapshot_aggregation_inputs`].
///
/// Grouped rather than passed as three loose arguments, matching
/// `BlockChainConfig` and `ProposerConfig`.
#[derive(Clone, Copy, Debug)]
pub struct AggregationWindowConfig {
    /// The subnet this aggregator is responsible for: the first value of
    /// `--aggregate-subnet-ids`.
    pub duty_subnet: u64,
    /// Number of attestation committees, i.e. the subnet count.
    pub committee_count: u64,
    /// Whether to narrow to the widest level this duty subnet owns in the
    /// slot, trading coverage overlap for less duplicated prover work. See
    /// [`effective_width`].
    pub skip_redundant: bool,
}

/// Maximum number of aggregation jobs selected per interval-2 session. Caps
/// leanVM prover work against [`aggregation_deadline`]: the greedy loop in
/// [`snapshot_aggregation_inputs`] stops after this many rounds even if
/// scoring candidates remain.
pub(crate) const MAX_AGGREGATION_JOBS: usize = 2;

/// The window derived for one candidate, and whether the redundancy-skipping
/// rotation narrowed it below what the candidate's pool alone allowed.
struct CandidateWindow {
    window: SubnetWindow,
    narrowed: bool,
}

/// The window this aggregator uses for one candidate `AttestationData`.
///
/// The width is taken over the candidate's whole pool rather than the part
/// inside any window, so it does not depend on which subnets this aggregator
/// owns: two aggregators holding the same pool derive the same width, and the
/// reduction tree stays in step. Narrowing the reach to a window would make
/// the width self-referential and desynchronize it across the network.
fn window_for_candidate(
    new_proofs: &[SingleMessageAggregate],
    known_proofs: &[SingleMessageAggregate],
    current_slot: u64,
    config: AggregationWindowConfig,
) -> CandidateWindow {
    // Reduce before the rotation, not just inside `SubnetWindow::new`: at a
    // width that does not divide the committee count, an out-of-range duty
    // subnet would otherwise rotate on different slots from its reduced twin.
    let duty_subnet = if config.committee_count == 0 {
        0
    } else {
        config.duty_subnet % config.committee_count
    };
    let max_reach = new_proofs
        .iter()
        .chain(known_proofs.iter())
        .map(|proof| subnet_reach(&proof.participants, config.committee_count))
        .max()
        .unwrap_or(0);
    let base_width = window_width(max_reach, config.committee_count);
    let width = effective_width(base_width, duty_subnet, current_slot, config.skip_redundant);
    CandidateWindow {
        window: SubnetWindow::new(duty_subnet, width, config.committee_count),
        narrowed: width < base_width,
    }
}

/// Report one candidate's derived window. Kept out of `window_for_candidate`
/// so the derivation stays pure and unit-testable without a metrics registry.
fn record_window_metrics(derived: &CandidateWindow) {
    metrics::observe_aggregation_window_width(derived.window.width());
    if derived.narrowed {
        metrics::inc_aggregation_narrowed();
    }
}

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
///    Each candidate's window is derived from the best reach in its own proof
///    pool (see [`window_for_candidate`]) and scores child selection.
/// 2. **Greedy loop**, at most `max_jobs` rounds: each round
///    scores every unselected candidate against the projected state and
///    keeps the lowest ordering key (current-slot before stale, then
///    Finalize > Justify > Build, mirroring the block builder). The winning
///    [`AggregationJob`] is emitted as-is; the projection is updated with its
///    realized coverage.
///
/// Stops early when no remaining candidate scores (converged).
///
/// `max_jobs` is [`MAX_AGGREGATION_JOBS`] for an ordinary session and `1` when
/// the caller is about to build a block at interval 4 (see
/// `BlockChainServer::start_aggregation_session`).
pub fn snapshot_aggregation_inputs(
    store: &Store,
    current_slot: u64,
    max_jobs: usize,
    window_config: AggregationWindowConfig,
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
        let derived = window_for_candidate(&new_proofs, &known_proofs, current_slot, window_config);
        record_window_metrics(&derived);
        if let Some(job) = resolve_job(
            hashed.clone(),
            validator_sigs,
            &new_proofs,
            &known_proofs,
            validators,
            &derived.window,
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
        let derived = window_for_candidate(&new_proofs, &known_proofs, current_slot, window_config);
        record_window_metrics(&derived);
        let hashed = HashedAttestationData::new(att_data.clone());
        if let Some(job) = resolve_job(
            hashed,
            &[],
            &new_proofs,
            &known_proofs,
            validators,
            &derived.window,
        ) {
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

    let mut jobs: Vec<AggregationJob> = Vec::with_capacity(max_jobs.min(groups_considered));
    for _round in 0..max_jobs {
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
///    Selection is scored through `window`, so a child is valued by the
///    in-window validators it adds; see [`select_proofs_greedily`].
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
    window: &SubnetWindow,
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

    let (child_proofs, _) = select_proofs_greedily(new_proofs, known_proofs, seed_covered, window);
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

/// End-of-session gauge refresh. Called once after the worker finishes so the
/// `lean_latest_new_aggregated_payloads` and `lean_gossip_signatures` gauges
/// settle on the final counts instead of being churned per aggregate.
pub fn finalize_aggregation_session(store: &Store) {
    metrics::update_latest_new_aggregated_payloads(store.new_aggregated_payloads_count());
    metrics::update_gossip_signatures(store.gossip_signatures_count());
}

/// The contiguous cyclic run of subnets an aggregator is currently
/// responsible for, starting at its duty subnet.
///
/// Used as a scoring lens rather than an admission filter: a proof reaching
/// outside the window earns no credit for the part that falls outside. That
/// keeps a proof straddling the boundary usable for its in-window half.
///
/// Windows belonging to different duty subnets overlap at the same width
/// (`{0,1}` and `{1,2}` share subnet 1). That is deliberate: every aggregator
/// stays busy, and `--skip-redundant-aggregation` is what trades the overlap
/// away.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SubnetWindow {
    start: u64,
    width: u64,
    committee_count: u64,
}

impl SubnetWindow {
    /// Build a window of `width` subnets starting at `start`.
    ///
    /// A `committee_count` of 0 is not a real configuration (the CLI parser
    /// enforces `>= 1`), but is treated as "no subnet structure" so nothing
    /// downstream has to guard against a division by zero. `width` is clamped
    /// to `committee_count` so the stored representation is canonical: two
    /// windows covering the same subnets always compare equal.
    pub(crate) fn new(start: u64, width: u64, committee_count: u64) -> Self {
        let start = if committee_count == 0 {
            0
        } else {
            start % committee_count
        };
        let width = if committee_count == 0 {
            width
        } else {
            width.min(committee_count)
        };
        Self {
            start,
            width,
            committee_count,
        }
    }

    /// Whether `subnet` falls inside the window, wrapping past the top.
    pub(crate) fn contains_subnet(&self, subnet: u64) -> bool {
        if self.committee_count == 0 {
            return true;
        }
        let subnet = subnet % self.committee_count;
        let offset = if subnet >= self.start {
            subnet - self.start
        } else {
            self.committee_count - self.start + subnet
        };
        offset < self.width
    }

    /// Whether `vid`'s subnet falls inside the window.
    pub(crate) fn contains_validator(&self, vid: u64) -> bool {
        if self.committee_count == 0 {
            return true;
        }
        self.contains_subnet(vid % self.committee_count)
    }

    /// The window's width in subnets, for metrics reporting.
    pub(crate) fn width(&self) -> u64 {
        self.width
    }
}

/// The number of distinct subnets `bits` reaches into.
///
/// A proof's reach is how far up the reduction tree it has climbed: raw
/// per-subnet aggregates have reach 1, a merge of two of them has reach 2.
pub(crate) fn subnet_reach(bits: &AggregationBits, committee_count: u64) -> u64 {
    if committee_count == 0 {
        return 0;
    }
    // Stop as soon as every subnet has been seen rather than scanning the rest
    // of a wide proof's set bits: `committee_count` is CLI-supplied with no
    // upper bound, so a `Vec<bool>` presence table sized by it is not safe,
    // but the early exit alone turns a saturated pool from a full scan into a
    // handful of insertions.
    let mut seen: HashSet<u64> = HashSet::new();
    for vid in validator_indices(bits) {
        seen.insert(vid % committee_count);
        if seen.len() as u64 == committee_count {
            break;
        }
    }
    seen.len() as u64
}

/// The window width for a pool whose best proof has reach `max_reach`.
///
/// Wide enough to hold two proofs at the current level, capped at the
/// committee count, so the window only widens after the pool has actually
/// climbed. An empty pool has nothing to merge, so it sits at the narrowest
/// width and the aggregator falls back to its own raw signatures.
///
/// Deriving the width instead of choosing it is what makes the scheme work:
/// windows nest, so "use the widest window that yields a viable job" would
/// collapse to the full committee set for every aggregator on the first round.
pub(crate) fn window_width(max_reach: u64, committee_count: u64) -> u64 {
    if committee_count == 0 || max_reach == 0 {
        return 1;
    }
    max_reach.saturating_mul(2).min(committee_count)
}

/// Narrow `width` to the widest level this duty subnet owns in `slot`, when
/// `--skip-redundant-aggregation` is on.
///
/// At width `w` the non-overlapping tiling of the committee set starts at
/// multiples of `w`, rotated by `slot % w`, so the owner test is
/// `duty_subnet % w == slot % w`. An aggregator that does not own the derived
/// width halves down until it owns one. Width 1 is owned by everyone, so the
/// raw-signature path is never skipped and only the recursive levels rotate.
///
/// When `w` does not divide the committee count the tiling is ragged at the
/// wrap: a slot can leave a subnet uncovered at the widest level, or hand two
/// duty subnets overlapping windows. Neither costs correctness, only a round
/// of climbing or a round of duplicated work. `w` is also not necessarily a
/// power of two, since `window_width` caps at the committee count, so the
/// ladder truncates: 7 narrows to 3, then to 1. Each level is still an
/// exclusive partition by residue, so ownership stays exclusive throughout.
pub(crate) fn effective_width(
    width: u64,
    duty_subnet: u64,
    slot: u64,
    skip_redundant: bool,
) -> u64 {
    // Floor at the narrowest window rather than trusting the caller: a width
    // of 0 would idle the raw-signature path, which no configuration should
    // be able to ask for.
    let width = width.max(1);
    if !skip_redundant {
        return width;
    }
    let mut w = width;
    while w > 1 && duty_subnet % w != slot % w {
        w /= 2;
    }
    w
}

/// Maximum number of existing proofs reused as children in a single
/// aggregation job. Recursive aggregation is costly, so we limit the
/// number of children to avoid unbounded aggregation times.
const MAX_AGGREGATION_CHILDREN: usize = 2;

/// Greedy set-cover selection of proofs, scored through the aggregator's
/// subnet window.
///
/// Processes proof sets in priority order (new before known). Within each set,
/// repeatedly picks the proof adding the most *in-window* new coverage until
/// no proof adds any. `seed_covered` primes the coverage set before selection
/// starts: [`resolve_job`] seeds it with raw-signature validator ids so a
/// chosen proof is only picked for coverage beyond what raw sigs already
/// provide.
///
/// The window scores, it does not filter. A proof reaching outside the window
/// stays selectable and is judged on its in-window part alone; one lying
/// wholly outside scores zero and is skipped. Either way, a selected proof
/// contributes **all** of its participants to `covered`, in-window or not.
/// That keeps the marginal-coverage score honest across rounds: the aggregate
/// binds every participant of a chosen child, so a later round must not be
/// paid again for coverage an earlier one already secured, whichever side of
/// the window it sits on.
///
/// Caps the number of proofs selected at [`MAX_AGGREGATION_CHILDREN`].
fn select_proofs_greedily(
    new_proofs: &[SingleMessageAggregate],
    known_proofs: &[SingleMessageAggregate],
    seed_covered: HashSet<u64>,
    window: &SubnetWindow,
) -> (Vec<SingleMessageAggregate>, HashSet<u64>) {
    let mut selected: Vec<SingleMessageAggregate> = Vec::new();
    let mut covered: HashSet<u64> = seed_covered;

    for proof_set in [new_proofs, known_proofs] {
        let mut remaining: Vec<&SingleMessageAggregate> = proof_set.iter().collect();

        while selected.len() < MAX_AGGREGATION_CHILDREN && !remaining.is_empty() {
            // A zero-scoring best means nothing left in this set adds
            // in-window coverage, so the set is exhausted.
            let Some((best_idx, _)) = remaining
                .iter()
                .enumerate()
                .map(|(i, p)| (i, in_window_new_coverage(p, &covered, window)))
                .max_by_key(|&(_, score)| score)
                .filter(|&(_, score)| score > 0)
            else {
                break;
            };

            // Record every newly covered participant, not just the in-window
            // ones: the aggregate binds all of them, so a later round must not
            // score them as new.
            let new_coverage: HashSet<u64> = remaining[best_idx]
                .participant_indices()
                .filter(|vid| !covered.contains(vid))
                .collect();

            selected.push(remaining.swap_remove(best_idx).clone());
            covered.extend(new_coverage);
        }

        if selected.len() >= MAX_AGGREGATION_CHILDREN {
            break;
        }
    }

    (selected, covered)
}

/// How many validators `proof` would newly cover whose subnet is inside
/// `window`. The greedy selection score.
fn in_window_new_coverage(
    proof: &SingleMessageAggregate,
    covered: &HashSet<u64>,
    window: &SubnetWindow,
) -> usize {
    proof
        .participant_indices()
        .filter(|vid| !covered.contains(vid) && window.contains_validator(*vid))
        .count()
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

    /// A single-committee config, for tests that predate the subnet window
    /// and want it to stay out of the way: with `committee_count` 1 every
    /// validator shares one subnet, so the derived window always covers the
    /// whole pool regardless of duty subnet.
    fn vacuous_window_config() -> AggregationWindowConfig {
        AggregationWindowConfig {
            duty_subnet: 0,
            committee_count: 1,
            skip_redundant: false,
        }
    }

    // ---- subnet windows ----

    /// Reach counts distinct subnets, not validators: two validators in the
    /// same subnet contribute one.
    #[test]
    fn reach_counts_distinct_subnets() {
        // C = 4, so subnet(vid) = vid % 4.
        assert_eq!(
            subnet_reach(&make_bits(&[0, 4, 8]), 4),
            1,
            "all in subnet 0"
        );
        assert_eq!(subnet_reach(&make_bits(&[0, 1]), 4), 2);
        assert_eq!(subnet_reach(&make_bits(&[0, 1, 2, 3]), 4), 4);
        assert_eq!(
            subnet_reach(&make_bits(&[3, 4]), 4),
            2,
            "wraps across the top"
        );
    }

    /// With a single committee every validator is in subnet 0, so every proof
    /// has reach 1.
    #[test]
    fn reach_is_one_for_a_single_committee() {
        assert_eq!(subnet_reach(&make_bits(&[0, 1, 2, 3]), 1), 1);
    }

    /// Width is just wide enough to hold two proofs of the pool's current best
    /// reach, capped at the committee count. An empty pool starts at 1.
    #[test]
    fn window_width_doubles_the_pools_best_reach() {
        assert_eq!(window_width(0, 4), 1, "empty pool");
        assert_eq!(window_width(1, 4), 2);
        assert_eq!(window_width(2, 4), 4);
        assert_eq!(window_width(4, 4), 4, "capped at the committee count");

        // Non-power-of-two committee counts need no special handling.
        assert_eq!(window_width(1, 6), 2);
        assert_eq!(window_width(2, 6), 4);
        assert_eq!(window_width(4, 6), 6);
        assert_eq!(window_width(2, 7), 4);
        assert_eq!(window_width(4, 7), 7);

        // A single committee pins the width at 1, which is also the whole set.
        assert_eq!(window_width(0, 1), 1);
        assert_eq!(window_width(1, 1), 1);
    }

    /// The derived width does not depend on which subnets an aggregator owns.
    /// Two aggregators holding the same pool must agree on it, or the
    /// reduction tree desynchronizes across the network.
    #[test]
    fn window_width_is_independent_of_the_duty_subnet() {
        let pool = [
            SingleMessageAggregate::empty(make_bits(&[0, 4])),
            SingleMessageAggregate::empty(make_bits(&[1, 5])),
        ];

        let widths: Vec<u64> = (0..4)
            .map(|duty_subnet| {
                let config = AggregationWindowConfig {
                    duty_subnet,
                    committee_count: 4,
                    skip_redundant: false,
                };
                window_for_candidate(&pool, &[], WINDOW_TEST_SLOT, config)
                    .window
                    .width()
            })
            .collect();

        assert_eq!(
            widths,
            vec![2, 2, 2, 2],
            "reach-1 pool gives width 2 for every duty subnet"
        );
    }

    /// A duty subnet at or above the committee count is reduced before it
    /// reaches the rotation, so it behaves as its in-range twin. Nothing
    /// validates the flag's upper bound, so this is reachable from the CLI.
    #[test]
    fn window_for_candidate_reduces_an_out_of_range_duty_subnet() {
        let pool = [SingleMessageAggregate::empty(make_bits(&[0, 4]))];
        let derived = |duty_subnet: u64| {
            let config = AggregationWindowConfig {
                duty_subnet,
                committee_count: 4,
                skip_redundant: true,
            };
            window_for_candidate(&pool, &[], WINDOW_TEST_SLOT, config).window
        };

        assert_eq!(
            derived(6),
            derived(2),
            "6 reduces to 2 at committee count 4"
        );
    }

    /// The window is a contiguous cyclic run of subnets starting at the duty
    /// subnet.
    #[test]
    fn subnet_window_wraps_around_the_committee_count() {
        let w = SubnetWindow::new(3, 2, 4);
        assert!(w.contains_subnet(3));
        assert!(w.contains_subnet(0), "wraps past the top");
        assert!(!w.contains_subnet(1));
        assert!(!w.contains_subnet(2));
    }

    /// A window as wide as the committee count contains everything, whatever
    /// its start.
    #[test]
    fn subnet_window_at_full_width_contains_every_subnet() {
        let w = SubnetWindow::new(2, 4, 4);
        for subnet in 0..4 {
            assert!(w.contains_subnet(subnet));
        }
    }

    /// Validators are mapped to subnets by `vid % C` before the membership
    /// test.
    #[test]
    fn subnet_window_maps_validators_through_their_subnet() {
        let w = SubnetWindow::new(0, 2, 4);
        assert!(w.contains_validator(0), "subnet 0");
        assert!(w.contains_validator(5), "subnet 1");
        assert!(!w.contains_validator(6), "subnet 2");
        assert!(w.contains_validator(4), "subnet 0 again");
    }

    /// With one committee the window is the whole validator set, so the lens
    /// is vacuous.
    #[test]
    fn subnet_window_is_vacuous_for_a_single_committee() {
        let w = SubnetWindow::new(0, 1, 1);
        for vid in 0..10 {
            assert!(w.contains_validator(vid));
        }
    }

    /// A committee count of 0 cannot come from the CLI, but every primitive
    /// still has to answer without dividing by zero. The agreed answers are
    /// "no subnet structure": the window admits everything, nothing has any
    /// reach, and the width sits at its floor.
    #[test]
    fn zero_committee_count_disables_the_subnet_scheme() {
        let w = SubnetWindow::new(7, 3, 0);
        assert!(w.contains_subnet(0));
        assert!(w.contains_subnet(u64::MAX));
        assert!(w.contains_validator(0));
        assert!(w.contains_validator(u64::MAX));

        assert_eq!(subnet_reach(&make_bits(&[0, 1, 2]), 0), 0);
        assert_eq!(window_width(0, 0), 1);
        assert_eq!(window_width(5, 0), 1);
    }

    /// A start at or past the committee count is folded back into range, so
    /// the duty subnet never has to be pre-reduced by the caller.
    #[test]
    fn subnet_window_folds_an_out_of_range_start() {
        assert_eq!(SubnetWindow::new(6, 2, 4), SubnetWindow::new(2, 2, 4));
        let w = SubnetWindow::new(6, 2, 4);
        assert!(w.contains_subnet(2));
        assert!(w.contains_subnet(3));
        assert!(!w.contains_subnet(0));
        assert!(!w.contains_subnet(1));
    }

    /// A zero-width window admits nothing.
    #[test]
    fn subnet_window_of_zero_width_contains_nothing() {
        let w = SubnetWindow::new(1, 0, 4);
        for subnet in 0..4 {
            assert!(!w.contains_subnet(subnet));
        }
    }

    // ---- window-scored child selection ----

    /// A window covering every subnet reproduces the pre-window selection:
    /// greedy picks by total new coverage.
    #[test]
    fn select_proofs_greedily_full_window_picks_by_total_coverage() {
        let small = SingleMessageAggregate::empty(make_bits(&[0]));
        let large = SingleMessageAggregate::empty(make_bits(&[1, 2, 3]));
        let window = SubnetWindow::new(0, 4, 4);

        let (selected, covered) =
            select_proofs_greedily(&[small, large], &[], HashSet::new(), &window);

        assert_eq!(selected.len(), 2);
        assert_eq!(
            selected[0].participant_indices().collect::<HashSet<_>>(),
            HashSet::from([1, 2, 3]),
            "the larger proof is picked first"
        );
        assert_eq!(covered, HashSet::from([0, 1, 2, 3]));
    }

    /// A proof whose participants all sit outside the window scores zero and
    /// is never selected, even when it is the only thing on offer.
    #[test]
    fn select_proofs_greedily_skips_proofs_wholly_outside_the_window() {
        // C = 4, window {0,1}. Validators 2 and 6 are both in subnet 2.
        let outside = SingleMessageAggregate::empty(make_bits(&[2, 6]));
        let window = SubnetWindow::new(0, 2, 4);

        let (selected, covered) = select_proofs_greedily(&[outside], &[], HashSet::new(), &window);

        assert!(selected.is_empty(), "nothing in the window to gain");
        assert!(covered.is_empty());
    }

    /// A proof straddling the window boundary is selected for its in-window
    /// contribution, and its out-of-window participants still land in
    /// `covered`: the produced aggregate genuinely binds them, so a later raw
    /// signature for one of them must be trimmed.
    #[test]
    fn select_proofs_greedily_covers_out_of_window_participants_of_a_chosen_proof() {
        // C = 4, window {0,1}. Validator 1 is in subnet 1 (inside),
        // validator 2 is in subnet 2 (outside).
        let straddling = SingleMessageAggregate::empty(make_bits(&[1, 2]));
        let window = SubnetWindow::new(0, 2, 4);

        let (selected, covered) =
            select_proofs_greedily(&[straddling], &[], HashSet::new(), &window);

        assert_eq!(selected.len(), 1, "picked for its in-window half");
        assert_eq!(
            covered,
            HashSet::from([1, 2]),
            "the out-of-window participant is covered too"
        );
    }

    /// In-window coverage beats total coverage: a proof with fewer validators
    /// overall wins when more of them fall inside the window.
    #[test]
    fn select_proofs_greedily_prefers_in_window_coverage_over_total() {
        // C = 4, window {0,1}.
        // `wide` covers 3 validators but only validator 0 is in the window.
        // `narrow` covers 2 validators, both in the window.
        let wide = SingleMessageAggregate::empty(make_bits(&[0, 2, 6]));
        let narrow = SingleMessageAggregate::empty(make_bits(&[4, 5]));
        let window = SubnetWindow::new(0, 2, 4);

        let (selected, _covered) =
            select_proofs_greedily(&[wide, narrow], &[], HashSet::new(), &window);

        assert_eq!(
            selected.len(),
            2,
            "the wide proof is still taken, second, for its one in-window validator"
        );
        assert_eq!(
            selected[0].participant_indices().collect::<HashSet<_>>(),
            HashSet::from([4, 5]),
            "two in-window validators beat one in-window plus two outside"
        );
    }

    /// The seed set still suppresses proofs that add nothing new, and it does
    /// so through the window: a proof whose only in-window validators are
    /// already covered scores zero.
    #[test]
    fn select_proofs_greedily_respects_the_seed_within_the_window() {
        // C = 4, window {0,1}. Validator 0 (subnet 0) is already covered by a
        // raw signature; validator 2 (subnet 2) is outside the window.
        let proof = SingleMessageAggregate::empty(make_bits(&[0, 2]));
        let window = SubnetWindow::new(0, 2, 4);

        let (selected, _covered) =
            select_proofs_greedily(&[proof], &[], HashSet::from([0]), &window);

        assert!(selected.is_empty());
    }

    /// Exhausting the new-proof set on in-window score does not end
    /// selection: the known set is still consulted, and a known proof with
    /// in-window coverage is taken.
    #[test]
    fn select_proofs_greedily_falls_through_to_known_proofs_within_the_window() {
        // C = 4, window {0,1}. The only new proof sits in subnet 2, so it
        // scores zero and the new set is exhausted immediately.
        let new_outside = SingleMessageAggregate::empty(make_bits(&[2, 6]));
        let known_inside = SingleMessageAggregate::empty(make_bits(&[0, 1]));
        let window = SubnetWindow::new(0, 2, 4);

        let (selected, covered) =
            select_proofs_greedily(&[new_outside], &[known_inside], HashSet::new(), &window);

        assert_eq!(selected.len(), 1);
        assert_eq!(
            covered,
            HashSet::from([0, 1]),
            "only the known proof is taken"
        );
    }

    // ---- effective width and the ownership rotation ----

    /// Without the flag, the derived width is used as-is.
    #[test]
    fn effective_width_is_the_base_width_when_not_skipping() {
        for duty_subnet in 0..4 {
            for slot in 0..4 {
                assert_eq!(effective_width(4, duty_subnet, slot, false), 4);
            }
        }
    }

    /// With the flag, an aggregator works at the derived width only when it
    /// owns the phase for that width, and otherwise halves down until it does.
    /// Width 1 is always owned, so raw-signature aggregation is never skipped.
    /// Widening to eight duty subnets puts two owners in each slot, spaced a
    /// full width apart, so the test can tell the tiling apart from "exactly
    /// one owner".
    #[test]
    fn effective_width_rotates_which_aggregator_works_widest() {
        let row = |slot: u64| {
            (0..8)
                .map(|duty_subnet| effective_width(4, duty_subnet, slot, true))
                .collect::<Vec<_>>()
        };

        // Two owners per slot, spaced a full width apart, so their windows
        // are disjoint.
        assert_eq!(row(0), vec![4, 1, 2, 1, 4, 1, 2, 1]);
        assert_eq!(row(1), vec![1, 4, 1, 2, 1, 4, 1, 2]);
        assert_eq!(row(2), vec![2, 1, 4, 1, 2, 1, 4, 1]);
        assert_eq!(row(3), vec![1, 2, 1, 4, 1, 2, 1, 4]);
    }

    /// Every duty subnet gets the widest slot in turn: over C slots each one
    /// reaches the full width exactly once.
    #[test]
    fn effective_width_gives_every_aggregator_a_turn() {
        for duty_subnet in 0..4u64 {
            let widest_slots: Vec<u64> = (0..4)
                .filter(|&slot| effective_width(4, duty_subnet, slot, true) == 4)
                .collect();
            assert_eq!(widest_slots, vec![duty_subnet]);
        }
    }

    /// Narrowing bottoms out at 1: width 1 is owned by every aggregator in
    /// every slot, and a degenerate 0 floors to 1 rather than idling the
    /// raw-signature path.
    #[test]
    fn effective_width_never_narrows_below_one() {
        for duty_subnet in 0..4 {
            for slot in 0..8 {
                assert_eq!(effective_width(1, duty_subnet, slot, true), 1);
                assert_eq!(effective_width(0, duty_subnet, slot, true), 1);
                assert_eq!(effective_width(0, duty_subnet, slot, false), 1);
            }
        }
    }

    /// Widths capped at an odd committee count truncate as they halve, and
    /// every level is still an exclusive partition by residue.
    #[test]
    fn effective_width_halves_through_non_power_of_two_widths() {
        for slot in 0..7u64 {
            let widths: Vec<u64> = (0..7)
                .map(|duty_subnet| effective_width(7, duty_subnet, slot, true))
                .collect();
            assert_eq!(widths.iter().filter(|&&w| w == 7).count(), 1);
            assert!(widths.iter().all(|&w| [1, 3, 7].contains(&w)));
        }
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
            &SubnetWindow::new(0, 1, 1),
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
            &SubnetWindow::new(0, 1, 1),
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
        let resolved = resolve_job(
            dummy_hashed(),
            &validator_sigs,
            &[],
            &[],
            &validators,
            &SubnetWindow::new(0, 1, 1),
        );
        assert!(resolved.is_none());
    }

    /// Payload-only candidates (no raw gossip sigs) are viable once at least
    /// two existing proofs can be merged.
    #[test]
    fn resolve_job_allows_payload_only_merge_with_two_children() {
        let validators = make_validators(5);
        let proof_a = SingleMessageAggregate::empty(make_bits(&[0]));
        let proof_b = SingleMessageAggregate::empty(make_bits(&[1]));

        let resolved = resolve_job(
            dummy_hashed(),
            &[],
            &[proof_a, proof_b],
            &[],
            &validators,
            &SubnetWindow::new(0, 1, 1),
        )
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
        assert!(
            snapshot_aggregation_inputs(&store, 0, MAX_AGGREGATION_JOBS, vacuous_window_config())
                .is_none()
        );
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

        assert!(
            snapshot_aggregation_inputs(&store, 0, MAX_AGGREGATION_JOBS, vacuous_window_config())
                .is_none()
        );
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
            snapshot_aggregation_inputs(&store, 999, MAX_AGGREGATION_JOBS, vacuous_window_config())
                .is_none(),
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

        let snapshot = snapshot_aggregation_inputs(
            &store,
            HEAD_SLOT,
            MAX_AGGREGATION_JOBS,
            vacuous_window_config(),
        )
        .expect("a vote for the current head must produce a job (chain view covers the tip)");
        assert_eq!(snapshot.jobs.len(), 1);
        assert_eq!(
            snapshot.jobs[0].hashed.data().target.slot,
            HEAD_SLOT,
            "the job aggregates the vote targeting the current head"
        );
    }

    /// Head slot used by the subnet-window tests.
    const WINDOW_TEST_SLOT: u64 = 4;

    /// Validator count for the subnet-window tests: eight, so with four
    /// committees each subnet holds exactly two (validator `v` in subnet
    /// `v % 4`).
    const WINDOW_TEST_VALIDATORS: usize = 8;

    /// A store whose `new_payloads` buffer holds one proof per entry in
    /// `participant_sets`, all bound to the same `AttestationData`, so
    /// `snapshot_aggregation_inputs` sees a single candidate whose pool is
    /// exactly those proofs.
    ///
    /// Deliberately carries no gossip signatures: a payload-only candidate
    /// isolates child selection from the raw-signature path, which is what the
    /// window changes. Each proof carries empty proof bytes (`empty`), so the
    /// resulting store can drive selection but never a real merge; a future
    /// end-to-end test reusing this helper needs its own real proofs.
    fn store_with_payload_only_proofs(participant_sets: &[AggregationBits]) -> Store {
        let hashes: Vec<H256> = (0..WINDOW_TEST_SLOT)
            .map(|i| H256([(i + 1) as u8; 32]))
            .collect();
        let mut store = new_test_store(make_head_state(
            WINDOW_TEST_SLOT,
            WINDOW_TEST_VALIDATORS,
            &hashes,
        ));
        let head_root = store.head().expect("head read works");

        let head = Checkpoint {
            root: head_root,
            slot: WINDOW_TEST_SLOT,
        };
        let att_data = AttestationData {
            slot: WINDOW_TEST_SLOT,
            head,
            target: head,
            source: Checkpoint {
                root: hashes[0],
                slot: 0,
            },
        };
        let hashed = HashedAttestationData::new(att_data);

        for bits in participant_sets {
            store.insert_new_aggregated_payload(
                hashed.clone(),
                SingleMessageAggregate::empty(bits.clone()),
            );
        }
        store
    }

    /// Two aggregators on different duty subnets, given the same pool of
    /// per-subnet proofs, select different children: the whole point of the
    /// window. Drives the real `snapshot_aggregation_inputs` path.
    #[test]
    fn snapshot_gives_different_duty_subnets_different_children() {
        // Four reach-1 proofs (one per subnet), so the derived width is 2 and
        // duty subnet s covers {s, s+1}.
        let store = store_with_payload_only_proofs(&[
            make_bits(&[0, 4]),
            make_bits(&[1, 5]),
            make_bits(&[2, 6]),
            make_bits(&[3, 7]),
        ]);

        let for_subnet = |duty_subnet: u64| {
            let config = AggregationWindowConfig {
                duty_subnet,
                committee_count: 4,
                skip_redundant: false,
            };
            let snapshot = snapshot_aggregation_inputs(&store, WINDOW_TEST_SLOT, 1, config)
                .expect("a payload-only merge is viable");
            snapshot.jobs[0]
                .accepted_child_ids
                .iter()
                .copied()
                .collect::<HashSet<u64>>()
        };

        assert_eq!(for_subnet(0), HashSet::from([0, 4, 1, 5]));
        assert_eq!(for_subnet(2), HashSet::from([2, 6, 3, 7]));
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

    /// With more scoring candidates than `MAX_AGGREGATION_JOBS`, exactly that
    /// many jobs are produced — the best `MAX_AGGREGATION_JOBS` by ordering
    /// key, i.e. the top two by `target_slot`.
    #[test]
    fn snapshot_caps_jobs_at_max_aggregation_jobs() {
        let store = store_with_competing_build_tier_groups();

        let snapshot =
            snapshot_aggregation_inputs(&store, 999, MAX_AGGREGATION_JOBS, vacuous_window_config())
                .expect("should produce jobs");
        assert_eq!(snapshot.groups_considered, NUM_GROUPS);
        assert_eq!(snapshot.jobs.len(), MAX_AGGREGATION_JOBS);

        let selected_targets: HashSet<u64> = snapshot
            .jobs
            .iter()
            .map(|job| job.hashed.data().target.slot)
            .collect();
        assert_eq!(
            selected_targets,
            HashSet::from([4, 5]),
            "the two highest target_slot groups win the new_voters tie"
        );
    }

    /// The proposer cap (`max_jobs = 1`) yields exactly one job from the same
    /// pool, and it is the single best-scoring candidate — the one the uncapped
    /// selection also picks first (highest `target_slot`). Every other candidate
    /// is still counted in `groups_considered`, so the cap is visibly a
    /// selection bound rather than a narrower candidate pool.
    #[test]
    fn snapshot_caps_jobs_at_one_for_proposer() {
        let store = store_with_competing_build_tier_groups();

        let snapshot = snapshot_aggregation_inputs(&store, 999, 1, vacuous_window_config())
            .expect("should produce a job");
        assert_eq!(snapshot.groups_considered, NUM_GROUPS);
        assert_eq!(snapshot.jobs.len(), 1);
        assert_eq!(
            snapshot.jobs[0].hashed.data().target.slot,
            NUM_GROUPS as u64,
            "the single job is the best-scoring candidate, not an arbitrary one"
        );
    }
}
