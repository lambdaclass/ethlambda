//! Committee-signature aggregation: off-thread worker orchestration and the
//! pure functions it runs.
//!
//! The blockchain actor fires one aggregation session per interval 2 via
//! [`run_aggregation_worker`]. The actor stays on its message loop; the worker
//! runs the expensive XMSS proofs on a `spawn_blocking` thread and streams
//! results back as [`AggregateProduced`] / [`AggregationDone`] messages.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use ethlambda_crypto::aggregate_mixed;
use ethlambda_storage::Store;
use ethlambda_types::{
    attestation::{AggregationBits, HashedAttestationData},
    block::{AggregatedSignatureProof, ByteListMiB},
    primitives::H256,
    signature::{ValidatorPublicKey, ValidatorSignature},
    state::Validator,
};
use spawned_concurrency::message::Message;
use spawned_concurrency::tasks::ActorRef;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::metrics;

/// Soft deadline for committee-signature aggregation measured from the
/// interval-2 tick. After this much wall time elapses, the actor signals the
/// worker to stop via its cancellation token. The 50 ms budget before the next
/// interval (interval 3 at +800 ms) is reserved for publishing any late-arriving
/// aggregates and for gossip propagation margin.
pub(crate) const AGGREGATION_DEADLINE: Duration = Duration::from_millis(750);
/// Upper bound we wait for a prior worker to exit if it is still running when
/// the next session is about to start. Reached only in pathological cases
/// (mismatched timers, stuck proofs); we warn before blocking.
pub(crate) const PRIOR_WORKER_JOIN_TIMEOUT: Duration = Duration::from_secs(2);

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
    pub(crate) children: Vec<(Vec<ValidatorPublicKey>, ByteListMiB)>,
    pub(crate) accepted_child_ids: Vec<u64>,
    pub(crate) raw_pubkeys: Vec<ValidatorPublicKey>,
    pub(crate) raw_sigs: Vec<ValidatorSignature>,
    pub(crate) raw_ids: Vec<u64>,
    /// Gossip-signature keys to delete on successful aggregation.
    pub(crate) keys_to_delete: Vec<(u64, H256)>,
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
    pub(crate) proof: AggregatedSignatureProof,
    pub(crate) participants: Vec<u64>,
    pub(crate) keys_to_delete: Vec<(u64, H256)>,
}

/// Tracks an in-flight off-thread aggregation worker so the actor can cancel,
/// join, and correlate incoming result messages with the right session.
pub(crate) struct AggregationSession {
    /// Slot at which this session was started; used as a fencing id so we can
    /// drop late-arriving messages from a prior session.
    pub(crate) session_id: u64,
    /// Child of the actor cancellation token; fires either at the deadline or
    /// when the actor itself is stopping.
    pub(crate) cancel: CancellationToken,
    /// Handle to the `spawn_blocking` worker. Held so `stopped()` / new-session
    /// start can await completion.
    pub(crate) worker: tokio::task::JoinHandle<()>,
    /// Kept alive so the timer is implicitly cancelled when the field is
    /// replaced or the actor stops (see `spawned_concurrency::tasks::time`).
    pub(crate) _deadline_timer: spawned_concurrency::tasks::TimerHandle,
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

/// Self-message scheduled via `send_after` at interval-2 start. Cancels the
/// session's token so the worker stops starting new aggregations.
pub(crate) struct AggregationDeadline {
    pub(crate) session_id: u64,
}
impl Message for AggregationDeadline {
    type Result = ();
}

/// Build a snapshot of everything needed to aggregate. Runs on the actor
/// thread, touches the store, does no heavy cryptography. Returns `None` when
/// there is nothing to aggregate so callers can avoid spawning an empty worker.
pub fn snapshot_aggregation_inputs(store: &Store) -> Option<AggregationSnapshot> {
    let gossip_groups = store.iter_gossip_signatures();
    let new_payload_keys = store.new_payload_keys();

    if gossip_groups.is_empty() && new_payload_keys.is_empty() {
        return None;
    }

    let head_state = store.head_state();
    let validators = &head_state.validators;

    let gossip_roots: HashSet<H256> = gossip_groups
        .iter()
        .map(|(hashed, _)| hashed.root())
        .collect();

    let groups_considered = gossip_groups.len()
        + new_payload_keys
            .iter()
            .filter(|(root, _)| !gossip_roots.contains(root))
            .count();

    let mut jobs = Vec::with_capacity(groups_considered);

    // Pass 1: attestation data with gossip signatures (may also reuse existing proofs as children).
    for (hashed, validator_sigs) in &gossip_groups {
        if let Some(job) = build_job(store, validators, hashed.clone(), Some(validator_sigs)) {
            jobs.push(job);
        }
    }

    // Pass 2: attestation data with pending proofs but no gossip signatures — pure recursive merge.
    for (data_root, att_data) in &new_payload_keys {
        if gossip_roots.contains(data_root) {
            continue;
        }
        // Cheap pre-check to skip the expensive `existing_proofs_for_data` clone when
        // fewer than 2 proofs are present (merge needs at least 2).
        if store.proof_count_for_data(data_root) < 2 {
            continue;
        }
        let hashed = HashedAttestationData::new(att_data.clone());
        if let Some(job) = build_job(store, validators, hashed, None) {
            jobs.push(job);
        }
    }

    Some(AggregationSnapshot {
        jobs,
        groups_considered,
    })
}

/// Build one `AggregationJob` for a given attestation data. Returns `None` when
/// there is not enough material for a viable aggregation (no raw sigs and fewer
/// than two children). `validator_sigs` is `None` for Pass 2 (payload-only).
fn build_job(
    store: &Store,
    validators: &[Validator],
    hashed: HashedAttestationData,
    validator_sigs: Option<&[(u64, ValidatorSignature)]>,
) -> Option<AggregationJob> {
    let data_root = hashed.root();
    let (new_proofs, known_proofs) = store.existing_proofs_for_data(&data_root);
    let (child_proofs, covered) = select_proofs_greedily(&new_proofs, &known_proofs);

    let mut raw_sigs = Vec::new();
    let mut raw_pubkeys = Vec::new();
    let mut raw_ids = Vec::new();
    for (vid, sig) in validator_sigs.into_iter().flatten() {
        if covered.contains(vid) {
            continue;
        }
        let Some(validator) = validators.get(*vid as usize) else {
            continue;
        };
        let Ok(pubkey) = validator.get_attestation_pubkey() else {
            continue;
        };
        raw_sigs.push(sig.clone());
        raw_pubkeys.push(pubkey);
        raw_ids.push(*vid);
    }

    let (children, accepted_child_ids) = resolve_child_pubkeys(&child_proofs, validators);

    if raw_ids.is_empty() && children.len() < 2 {
        return None;
    }

    let keys_to_delete: Vec<(u64, H256)> = validator_sigs
        .into_iter()
        .flatten()
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
    child_proofs: &[AggregatedSignatureProof],
    validators: &[Validator],
) -> (Vec<(Vec<ValidatorPublicKey>, ByteListMiB)>, Vec<u64>) {
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
        children.push((child_pubkeys, proof.proof_data.clone()));
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

    Some(AggregatedGroupOutput {
        hashed: job.hashed,
        proof: AggregatedSignatureProof::new(aggregation_bits, proof_data),
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

/// Greedy set-cover selection of proofs to maximize validator coverage.
///
/// Processes proof sets in priority order (new before known). Within each set,
/// repeatedly picks the proof covering the most uncovered validators until
/// no proof adds new coverage. This keeps the number of children minimal
/// while maximizing the validators we can skip re-aggregating from scratch.
fn select_proofs_greedily(
    new_proofs: &[AggregatedSignatureProof],
    known_proofs: &[AggregatedSignatureProof],
) -> (Vec<AggregatedSignatureProof>, HashSet<u64>) {
    let mut selected: Vec<AggregatedSignatureProof> = Vec::new();
    let mut covered: HashSet<u64> = HashSet::new();

    for proof_set in [new_proofs, known_proofs] {
        let mut remaining: Vec<&AggregatedSignatureProof> = proof_set.iter().collect();

        while !remaining.is_empty() {
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
pub(crate) fn run_aggregation_worker(
    snapshot: AggregationSnapshot,
    actor: ActorRef<crate::BlockChainServer>,
    cancel: CancellationToken,
    session_id: u64,
) {
    let start = Instant::now();
    let groups_considered = snapshot.groups_considered;
    let mut groups_aggregated = 0usize;
    let mut total_raw_sigs = 0usize;
    let mut total_children = 0usize;

    for job in snapshot.jobs {
        if cancel.is_cancelled() {
            break;
        }

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

        if actor
            .send(AggregateProduced { session_id, output })
            .is_err()
        {
            // Actor is gone; no point producing more.
            break;
        }
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
