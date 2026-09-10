//! Committee-signature aggregation: the always-on off-thread worker and the
//! pure functions it runs.
//!
//! One worker thread is spawned when the blockchain actor starts and lives as
//! long as it does. It holds its own [`Store`] handle (a clone sharing the same
//! backend and in-memory buffers), so it both re-reads the pool itself instead
//! of being handed a per-slot snapshot and writes what it produces straight
//! back: pick the single best job available right now, run its expensive XMSS
//! proof, [`store_aggregate`] it, tell the actor with an [`AggregateProduced`]
//! message, pick again. With nothing eligible it polls every
//! [`WORKER_IDLE_POLL`].
//!
//! It is a plain `std::thread`, not a `spawn_blocking` task. The thread runs
//! for the process's life and spends it in leanVM proofs, so handing it to the
//! runtime's blocking pool would park one of those threads permanently while
//! buying nothing: the loop awaits nothing, and it reaches the actor through an
//! unbounded channel that needs no reactor.
//!
//! Storing on the worker keeps the proof off the actor's mailbox: the message
//! carries only the attestation data and the participant set naming the proof,
//! and the actor reads the bytes back out of the pool when it publishes. That
//! publication is what stays on the interval grid, held to the
//! vote-aggregation interval unless the aggregate finishes inside the window
//! (see `SlotInterval::publishes_aggregates_on_arrival`), so proving is free to
//! run whenever.
//!
//! It also means the worker needs no memory of what it has already proved: the
//! pool its next selection round re-reads already accounts for it. A failed
//! proof is the exception, since it leaves the pool untouched and gets picked
//! again; that path sleeps [`WORKER_IDLE_POLL`] so a proof failing cheaply,
//! before the prover even runs, cannot spin the thread.
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
//! The actor parks the worker outright for as long as it needs the prover to
//! itself, or the node has no business aggregating: around its own proposal,
//! and while the sync gate suppresses duties, so a node that is behind spends
//! the prover on the block import that closes the gap rather than on a backlog
//! the network has stopped waiting for. Both are [`PauseReason`]s (see
//! [`AggregationWorker::pause`] and [`AggregationWorker::set_paused`]).
//!
//! During the head-update interval the worker has one further duty: build the
//! candidate [`BlockBodyProof`] for the upcoming slot (see
//! [`body_proof::build_body_proof`]) and hand it to the actor, which gossips it
//! for that slot's proposer to adopt. It takes priority over aggregation there,
//! since it is the one job with a deadline.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use ethlambda_crypto::aggregate_mixed;
use ethlambda_crypto::signature::{ValidatorPublicKey, ValidatorSignature};
use ethlambda_storage::Store;
use ethlambda_types::{
    ShortRoot,
    aggregator::AggregatorController,
    attestation::{AggregationBits, AttestationData, HashedAttestationData, validator_indices},
    block::{BlockBodyProof, ByteList512KiB, SingleMessageAggregate},
    chain_config::ChainConfig,
    constants::{INTERVALS_PER_SLOT, MIN_MILLISECONDS_PER_SLOT},
    primitives::H256,
    state::Validator,
};
use spawned_concurrency::message::Message;
use spawned_concurrency::tasks::ActorRef;
use tokio_util::sync::CancellationToken;
use tracing::{info, trace, warn};

use crate::block_builder::{self, EntryScore, ProposerConfig};
use crate::body_proof;
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

/// How far into `slot` the wall clock is, in milliseconds.
///
/// The store clock decides which slot the worker is in, but it counts whole
/// intervals and [`EARLY_AGGREGATION_WINDOW`] is finer than one, so the
/// position *inside* the slot still comes from the wall clock. It is measured
/// from `slot`'s own start and clamped to that slot, so when the two clocks
/// disagree the answer degrades to an edge of the slot the store says we are
/// in: short of it the permissive [`JobPolicy::Backlog`] end, past it
/// [`JobPolicy::Open`]. It never describes a position inside some other slot.
fn ms_into_slot(now_ms: u64, slot: u64, config: &ChainConfig) -> u64 {
    let slot_start_ms = config.genesis_time_ms() + slot * config.milliseconds_per_slot;
    now_ms
        .saturating_sub(slot_start_ms)
        .min(config.milliseconds_per_slot)
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

/// Offset within the slot at which the head-update interval — the slot's last
/// — begins. From here the worker's first duty is the next slot's candidate
/// body proof.
///
/// Derived from the configured slot duration, like
/// [`vote_aggregation_offset_ms`].
fn head_update_offset_ms(config: &ChainConfig) -> u64 {
    // Slot 0 reduces `to_ms_since_genesis` to the offset within a slot.
    SlotInterval::EndOfSlot.to_ms_since_genesis(0, config)
}

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

/// Why the worker is parked. The actor owns every reason and sets them
/// independently; the worker takes no new job while any is set.
///
/// A bitset rather than a single flag or a depth counter: each reason has
/// exactly one owner, so setting one twice is idempotent, clearing one cannot
/// clear another's, and nothing is left to leak when an owner is level-driven
/// rather than scoped. Values are distinct bits of the `AtomicU8` in
/// [`AggregationWorker`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum PauseReason {
    /// The actor is building a block. Both it and the worker run leanVM
    /// proofs on the same single-threaded prover, and the block is the one
    /// with a deadline. Scoped to the build, so it is taken as a
    /// [`PauseGuard`].
    BlockBuild = 1 << 0,
    /// The sync gate is suppressing this node's duties. A node that is behind
    /// would otherwise prove a backlog the network has moved past, against
    /// the same prover its block import needs to close the gap. Level-driven
    /// from the actor's tick, so it is set through
    /// [`AggregationWorker::set_paused`] rather than held as a guard.
    Syncing = 1 << 1,
}

/// Handle to the always-on aggregation worker, held by the actor for the
/// actor's whole lifetime.
pub(crate) struct AggregationWorker {
    /// Cancelled by the actor's `stopped()` hook; the worker breaks out of its
    /// loop at the next job boundary.
    cancel: CancellationToken,
    /// Set of [`PauseReason`]s currently holding the worker back, as a bitset.
    /// Non-zero means "take no new job"; see [`Self::pause`].
    paused: Arc<AtomicU8>,
    /// Handle to the worker thread, held so shutdown can join it.
    handle: std::thread::JoinHandle<()>,
}

/// Set or clear one reason's bit. Read-modify-write, so reasons are
/// independent: an owner only ever touches its own bit.
fn set_pause_reason(paused: &AtomicU8, reason: PauseReason, on: bool) {
    if on {
        paused.fetch_or(reason as u8, Ordering::Release);
    } else {
        paused.fetch_and(!(reason as u8), Ordering::Release);
    }
}

impl AggregationWorker {
    /// Stop handing the worker new jobs for `reason` for as long as the
    /// returned guard lives. A proof already in flight is not interrupted
    /// (`aggregate_mixed` cannot be), so this bounds contention rather than
    /// eliminating it.
    ///
    /// For a reason whose lifetime is a scope. A reason the actor tracks as
    /// state instead, recomputing it each tick, belongs in
    /// [`Self::set_paused`]. Either way one reason has one owner: two live
    /// guards for the same reason would release it when the first drops.
    pub(crate) fn pause(&self, reason: PauseReason) -> PauseGuard {
        set_pause_reason(&self.paused, reason, true);
        PauseGuard {
            paused: self.paused.clone(),
            reason,
        }
    }

    /// Level-triggered form of [`Self::pause`]: bring `reason` in line with
    /// `paused`, whatever it was before. Idempotent, so the actor can drive it
    /// straight off a predicate it recomputes every tick without tracking
    /// whether it already set it.
    pub(crate) fn set_paused(&self, reason: PauseReason, paused: bool) {
        set_pause_reason(&self.paused, reason, paused);
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

/// Clears its own [`PauseReason`] on drop, so an early return on the paused
/// code path cannot leave the worker parked forever. Touches no other
/// reason's bit; see [`AggregationWorker::pause`].
pub(crate) struct PauseGuard {
    paused: Arc<AtomicU8>,
    reason: PauseReason,
}

impl Drop for PauseGuard {
    fn drop(&mut self) {
        set_pause_reason(&self.paused, self.reason, false);
    }
}

/// Startup-fixed inputs the worker needs. All come from the CLI and never
/// change at runtime, so the worker owns a copy instead of reaching back into
/// the actor.
#[derive(Clone)]
pub(crate) struct WorkerConfig {
    /// Number of attestation committees (= subnet count).
    pub(crate) attestation_committee_count: u64,
    /// Attestation subnets this node subscribes to.
    pub(crate) subscribed_subnets: HashSet<u64>,
    /// The subnet this aggregator is responsible for when scoring recursive
    /// aggregation: the first value of `--aggregate-subnet-ids`.
    pub(crate) aggregation_duty_subnet: u64,
    /// Whether to sit out candidates whose level another duty subnet owns
    /// this slot. See [`owns_width`].
    pub(crate) skip_redundant_aggregation: bool,
    /// Body-packing policy, shared with the proposer path.
    pub(crate) proposer_config: ProposerConfig,
}

/// One successful aggregate announced to the actor, after the worker has
/// already stored it.
///
/// Carries no proof: [`store_aggregate`] put it in the pending payload pool,
/// and `participants` names it there for `Store::proof_for_participants`. A
/// proof is up to [`ByteList512KiB`], so keeping it out of the mailbox keeps
/// the actor's queue small however far behind publication falls.
pub(crate) struct AggregateProduced {
    pub(crate) hashed: HashedAttestationData,
    /// Participant set of the stored proof, which is both what names it in the
    /// pool and what the actor buffers until publication.
    pub(crate) participants: AggregationBits,
    /// Wall time the proof itself took, observed on the worker thread.
    pub(crate) elapsed: Duration,
}
impl Message for AggregateProduced {
    type Result = ();
}

/// A candidate body proof the worker built for `slot`.
pub(crate) struct BodyProofProduced {
    /// Slot the body was packed for: the one whose proposer may adopt it.
    pub(crate) slot: u64,
    pub(crate) body_proof: BlockBodyProof,
    /// Wall time the merge took, observed on the worker thread.
    pub(crate) elapsed: Duration,
}
impl Message for BodyProofProduced {
    type Result = ();
}

/// What the worker does with a turn of its loop.
enum WorkerJob {
    /// Prove one aggregation group. Boxed: a job carries its whole aggregation
    /// material, which dwarfs the other variant.
    Aggregate(Box<AggregationJob>),
    /// Build the candidate body proof for `slot`.
    BodyProof { slot: u64 },
}

/// The aggregator's subnet-window duty, as read by [`select_best_job`].
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
    /// Whether to sit out candidates whose level another duty subnet owns
    /// this slot, trading coverage overlap for less duplicated prover work.
    /// See [`owns_width`].
    pub skip_redundant: bool,
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

/// The window this aggregator uses for one candidate `AttestationData`, or
/// `None` when `--skip-redundant-aggregation` is on and another duty subnet
/// owns this candidate's level in this slot.
///
/// The width comes from the *anchor*: the largest-coverage pool proof that
/// touches the duty subnet (see [`anchor_reach`]). Anchoring on a proof that
/// covers our own subnet keeps the window tied to work we can contribute to,
/// and it gives the raw-signature path a floor. A pool holding nothing on our
/// subnet yields no anchor, hence the narrowest window, hence a job built
/// from our own raw signatures instead of a merge of other aggregators'
/// proofs, which is exactly the case where nobody else can do the work for
/// us.
///
/// The width is therefore *not* uniform across the network: two aggregators
/// on different duty subnets can derive different widths from one lopsided
/// pool. That costs tiling precision (windows at different widths nest rather
/// than tile) but no correctness, and it buys immunity to a single sparse
/// wide proof, one validator in each of many subnets, collapsing every
/// aggregator's window to the full committee set.
///
/// The current slot's own candidate normally has an empty pool, since the
/// worker publishes what it produces and nothing for this slot has come back
/// yet, so it derives the narrowest width and is never skipped. The pool only
/// has something to reach into once a data root has stayed live past its own
/// slot.
fn window_for_candidate(
    new_proofs: &[SingleMessageAggregate],
    known_proofs: &[SingleMessageAggregate],
    current_slot: u64,
    config: AggregationWindowConfig,
) -> Option<SubnetWindow> {
    // Reduce before both the anchor search and the ownership test, not just
    // inside `SubnetWindow::new`: an out-of-range duty subnet matches no
    // validator's subnet, so it would find no anchor at all, and at a width
    // that does not divide the committee count it would rotate on different
    // slots from its reduced twin.
    let duty_subnet = if config.committee_count == 0 {
        0
    } else {
        config.duty_subnet % config.committee_count
    };
    let reach = anchor_reach(
        new_proofs,
        known_proofs,
        duty_subnet,
        config.committee_count,
    );
    let width = window_width(reach, config.committee_count);
    if config.skip_redundant && !owns_width(duty_subnet, current_slot, width) {
        return None;
    }
    Some(SubnetWindow::new(
        duty_subnet,
        width,
        config.committee_count,
    ))
}

/// [`window_for_candidate`] plus the metrics for its outcome. Kept apart from
/// the derivation so that stays pure and unit-testable without a metrics
/// registry.
fn metered_window_for_candidate(
    new_proofs: &[SingleMessageAggregate],
    known_proofs: &[SingleMessageAggregate],
    current_slot: u64,
    config: AggregationWindowConfig,
) -> Option<SubnetWindow> {
    let window = window_for_candidate(new_proofs, known_proofs, current_slot, config);
    match &window {
        Some(window) => metrics::observe_aggregation_window_width(window.width()),
        None => metrics::inc_aggregation_skipped_redundant(),
    }
    window
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
///    Each candidate's window is derived from the best proof in its own pool
///    that touches this aggregator's duty subnet (see
///    [`window_for_candidate`]) and scores child selection; under
///    `--skip-redundant-aggregation` a candidate whose level another duty
///    subnet owns this slot is dropped here, so the ranking below falls
///    through to the next-best `AttestationData`.
/// 2. **Ranking**: scores every candidate against the head state and keeps the
///    lowest ordering key (current-slot before stale, then Finalize > Justify
///    > Build, mirroring the block builder).
fn select_best_job(
    store: &Store,
    current_slot: u64,
    policy: JobPolicy,
    window_config: AggregationWindowConfig,
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
        let Some(window) =
            metered_window_for_candidate(&new_proofs, &known_proofs, current_slot, window_config)
        else {
            continue;
        };
        if let Some(job) = resolve_job_with_window_fallback(
            hashed.clone(),
            validator_sigs,
            &new_proofs,
            &known_proofs,
            validators,
            &window,
            window_config,
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
        let Some(window) =
            metered_window_for_candidate(&new_proofs, &known_proofs, current_slot, window_config)
        else {
            continue;
        };
        let hashed = HashedAttestationData::new(att_data.clone());
        if let Some(job) = resolve_job_with_window_fallback(
            hashed,
            &[],
            &new_proofs,
            &known_proofs,
            validators,
            &window,
            window_config,
        ) {
            candidates.insert(*data_root, job);
        }
    }

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

/// A window can decline a merge the unwindowed pool would have allowed: the
/// window is a contiguous run of subnets, but the pool need not be contiguous
/// in subnet space, so a sparse aggregator placement can leave a window
/// holding a single proof. Falling back to the full committee set means the
/// window can only ever improve on the unwindowed selection, never lose
/// coverage relative to it.
///
/// Skipped entirely under `--skip-redundant-aggregation`. That flag is a
/// request to do strictly less prover work, and every width below the
/// committee count has several owners, so a fallback would have all of them
/// retry at full width and rebuild the duplication the flag buys away.
///
/// `resolve_job` is store-free, so trying it twice is cheap.
fn resolve_job_with_window_fallback(
    hashed: HashedAttestationData,
    validator_sigs: &[(u64, ValidatorSignature)],
    new_proofs: &[SingleMessageAggregate],
    known_proofs: &[SingleMessageAggregate],
    validators: &[Validator],
    window: &SubnetWindow,
    config: AggregationWindowConfig,
) -> Option<AggregationJob> {
    let primary = resolve_job(
        hashed.clone(),
        validator_sigs,
        new_proofs,
        known_proofs,
        validators,
        window,
    );
    if primary.is_some() || config.skip_redundant {
        return primary;
    }
    metrics::inc_aggregation_window_fallback();
    let committee_count = config.committee_count;
    let full = SubnetWindow::new(0, committee_count.max(1), committee_count);
    resolve_job(
        hashed,
        validator_sigs,
        new_proofs,
        known_proofs,
        validators,
        &full,
    )
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

/// Store one aggregate the worker just produced and build the announcement
/// for the actor: the proof into the pending payload pool, and the gossip
/// signatures it consumed out of the pool.
///
/// Runs on the worker thread through its own `Store` handle. `Store`'s `&mut
/// self` does not mean exclusive access (its buffers are behind `Arc<Mutex<_>>`
/// and the actor holds a handle of its own), so this interleaves with the
/// actor, and both writes are safe under that:
///
/// - `insert_new_aggregated_payload` records the fork-choice votes before it
///   pushes the payload, and it records them with a max-merge
///   (`should_replace_vote`) that gives the same map whatever order concurrent
///   writers arrive in. A promote landing in the middle moves votes from `new`
///   to `known` rather than dropping them, so the worst interleaving leaves the
///   vote or the payload to be promoted one tick later. Neither is lost.
/// - `delete_gossip_signatures` removes keys this proof consumed. A signature
///   arriving concurrently for one of them is the same validator's signature
///   over the same attestation data, i.e. a duplicate of a vote the proof
///   already binds, so deleting it loses nothing.
///
/// Gauge metrics that depend on total counts are batched into
/// [`refresh_pool_gauges`] instead, so we pay one lock per slot rather than one
/// per aggregate. Idempotent wrt the gossip delete.
fn store_aggregate(
    store: &mut Store,
    output: AggregatedGroupOutput,
    elapsed: Duration,
) -> AggregateProduced {
    let AggregatedGroupOutput {
        hashed,
        proof,
        participants,
        keys_to_delete,
    } = output;
    // Named before the proof moves into the pool; the bitfield is a few
    // hundred bytes against the proof's up-to-512 KiB.
    let bits = proof.participants.clone();

    store.insert_new_aggregated_payload(hashed.clone(), proof);
    store.delete_gossip_signatures(&keys_to_delete);

    metrics::inc_pq_sig_aggregated_signatures();
    metrics::inc_pq_sig_attestations_in_aggregated_signatures(participants.len() as u64);

    AggregateProduced {
        hashed,
        participants: bits,
        elapsed,
    }
}

/// Refresh the pool-size gauges. Called from the vote-aggregation tick, once
/// the slot's buffered aggregates have gone out, so
/// `lean_latest_new_aggregated_payloads` and `lean_gossip_signatures` settle
/// on a per-slot reading instead of being churned per aggregate.
pub fn refresh_pool_gauges(store: &Store) {
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

/// The window width for an anchor proof of reach `anchor_reach`.
///
/// Wide enough to hold two proofs at the anchor's level, capped at the
/// committee count, so the window only widens after the pool has actually
/// climbed. A reach of 0 means no anchor was found, so there is nothing to
/// merge on our subnet and the window sits at its narrowest, leaving the
/// aggregator to its own raw signatures. The current slot's own candidate is
/// the common case of this, since nothing has been published for it yet (see
/// [`window_for_candidate`]).
///
/// Deriving the width instead of choosing it is what makes the scheme work:
/// windows nest, so "use the widest window that yields a viable job" would
/// collapse to the full committee set for every aggregator the first time a
/// data root is aggregated.
pub(crate) fn window_width(anchor_reach: u64, committee_count: u64) -> u64 {
    if committee_count == 0 || anchor_reach == 0 {
        return 1;
    }
    anchor_reach.saturating_mul(2).min(committee_count)
}

/// The reach of the proof this aggregator anchors its window on: the
/// largest-coverage proof in the pool that touches `duty_subnet`. Zero when
/// the pool holds nothing on that subnet.
///
/// Anchoring on a proof that covers our own subnet, rather than on the
/// widest proof anywhere in the pool, does two things. It ties the window to
/// a level we can actually contribute to, and it makes "no anchor" mean "no
/// peer has covered my subnet", which is precisely when this aggregator's
/// raw signatures are irreplaceable and it should be aggregating them rather
/// than merging other aggregators' proofs.
///
/// Coverage rather than reach picks the anchor, so a sparse proof spanning
/// many subnets with a single validator in each no longer sets the width. A
/// coverage tie falls to the larger reach, which keeps the derived width
/// independent of the pool's iteration order.
fn anchor_reach(
    new_proofs: &[SingleMessageAggregate],
    known_proofs: &[SingleMessageAggregate],
    duty_subnet: u64,
    committee_count: u64,
) -> u64 {
    new_proofs
        .iter()
        .chain(known_proofs.iter())
        .filter_map(|proof| anchor_key(&proof.participants, duty_subnet, committee_count))
        .max()
        .map_or(0, |(_coverage, reach)| reach)
}

/// `(coverage, reach)` for a proof that touches `duty_subnet`, or `None` when
/// it does not. The ordering of this pair is the anchor ranking.
///
/// A committee count of 0 means no subnet structure, so every non-empty proof
/// is an anchor and reach is 0 throughout; [`window_width`] floors the width
/// either way.
fn anchor_key(
    bits: &AggregationBits,
    duty_subnet: u64,
    committee_count: u64,
) -> Option<(usize, u64)> {
    let mut coverage = 0usize;
    let mut touches_duty = false;
    for vid in validator_indices(bits) {
        coverage += 1;
        if committee_count == 0 || vid % committee_count == duty_subnet {
            touches_duty = true;
        }
    }
    // `subnet_reach` walks the bits a second time, but only for the proofs
    // that are anchor candidates at all.
    touches_duty.then(|| (coverage, subnet_reach(bits, committee_count)))
}

/// Whether `duty_subnet` owns the width-`width` tiling of the committee set
/// in `slot`. Consulted only under `--skip-redundant-aggregation`, where a
/// duty subnet that does not own a candidate's width sits that candidate out
/// so its job budget goes to the next-best `AttestationData` instead.
///
/// At width `w` the non-overlapping tiling starts at multiples of `w`,
/// rotated by `slot % w`, so the test is `duty_subnet % w == slot % w`. The
/// rotation walks with the slot, so no duty subnet is permanently the one
/// sitting out. Width 1 is owned by everyone, which is what keeps a candidate
/// with no anchor on our subnet, the raw-signature case, from ever being
/// skipped.
///
/// When `w` does not divide the committee count the tiling is ragged at the
/// wrap: a slot can leave a subnet uncovered at the widest level, or hand two
/// duty subnets overlapping windows. Neither costs correctness, only a round
/// of climbing or a round of duplicated work.
pub(crate) fn owns_width(duty_subnet: u64, slot: u64, width: u64) -> bool {
    // Floor at the narrowest window rather than trusting the caller: a width
    // of 0 would divide by zero, and no configuration should be able to idle
    // the raw-signature path.
    let width = width.max(1);
    duty_subnet % width == slot % width
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

/// Spawn the always-on aggregation worker on its own thread.
///
/// The worker owns a [`Store`] clone — same backend, same in-memory buffers —
/// the shared aggregator-role flag (so a runtime toggle from the RPC thread
/// reaches it without a restart), and the startup-fixed gate inputs. State the
/// actor owns rather than shares, such as the sync verdict, reaches it as a
/// [`PauseReason`] instead. It runs until the returned handle's
/// [`AggregationWorker::shutdown`] cancels it.
pub(crate) fn spawn_aggregation_worker(
    store: Store,
    actor: ActorRef<crate::BlockChainServer>,
    aggregator: AggregatorController,
    config: WorkerConfig,
) -> AggregationWorker {
    let cancel = CancellationToken::new();
    let paused = Arc::new(AtomicU8::new(0));
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
/// Each round re-reads the pool through the store handle, takes the job worth
/// doing right now ([`next_job`]), and hands the result to the actor: an
/// [`AggregateProduced`] for a proved group, a [`BodyProofProduced`] for the
/// upcoming slot's candidate body. With nothing to do — nothing eligible,
/// parked for some [`PauseReason`], or no aggregation duty — it sleeps
/// [`WORKER_IDLE_POLL`] and looks again.
///
/// leanVM proofs cannot be interrupted, so both cancellation and the pause
/// reasons are only observed between jobs.
fn run_aggregation_worker(
    mut store: Store,
    actor: ActorRef<crate::BlockChainServer>,
    aggregator: AggregatorController,
    config: WorkerConfig,
    cancel: CancellationToken,
    paused: Arc<AtomicU8>,
) {
    info!("Aggregation worker started");

    // The chain's time grid never changes at runtime, so one read covers the
    // worker's whole life.
    let time_config = *store.config();
    // Slot the last candidate body proof was packed for, so the head-update
    // interval produces one candidate rather than a stream of them.
    let mut body_proof_slot: Option<u64> = None;

    while !cancel.is_cancelled() {
        let Some(job) = next_job(
            &store,
            &time_config,
            &aggregator,
            &paused,
            &config,
            body_proof_slot,
        ) else {
            std::thread::sleep(WORKER_IDLE_POLL);
            continue;
        };

        let delivered = match job {
            WorkerJob::Aggregate(job) => run_aggregate_job(*job, &mut store, &actor),
            WorkerJob::BodyProof { slot } => {
                // Marked before the build, not after: a failed or empty build
                // would otherwise be retried for the rest of the interval.
                body_proof_slot = Some(slot);
                run_body_proof_job(slot, &store, &config, &actor)
            }
        };

        if !delivered {
            // Actor is gone; nothing would consume further work.
            break;
        }
    }

    info!("Aggregation worker stopped");
}

/// Prove one aggregation group, store it, and announce it to the actor.
/// Returns false when the actor is gone.
fn run_aggregate_job(
    job: AggregationJob,
    store: &mut Store,
    actor: &ActorRef<crate::BlockChainServer>,
) -> bool {
    let slot = job.slot;
    let raw_sigs = job.raw_ids.len();
    let children = job.children.len();

    let job_start = Instant::now();
    let output = aggregate_job(job);
    let elapsed = job_start.elapsed();

    let Some(output) = output else {
        warn!(
            slot,
            raw_sigs,
            children,
            ?elapsed,
            "Committee signature aggregation failed"
        );
        metrics::inc_aggregator_skipped_other(1);
        // A failure leaves the store exactly as it found it, so the next round
        // re-reads the same pool and picks the same job. Sleep before looping:
        // a proof that fails cheaply, before the prover runs, would otherwise
        // spin this thread at full speed.
        std::thread::sleep(WORKER_IDLE_POLL);
        return true;
    };

    info!(
        slot,
        raw_sigs,
        children,
        participants = output.participants.len(),
        ?elapsed,
        "Committee signature aggregated"
    );

    // Store before announcing, so the pool the actor reads to publish, and the
    // one the next selection round re-reads, both already account for this
    // aggregate.
    let produced = store_aggregate(store, output, elapsed);
    actor.send(produced).is_ok()
}

/// Build the candidate body proof for `slot` and send it to the actor. Returns
/// false when the actor is gone.
fn run_body_proof_job(
    slot: u64,
    store: &Store,
    config: &WorkerConfig,
    actor: &ActorRef<crate::BlockChainServer>,
) -> bool {
    let job_start = Instant::now();
    let Some(body_proof) = body_proof::build_body_proof(store, slot, config.proposer_config) else {
        return true;
    };
    let elapsed = job_start.elapsed();

    info!(
        %slot,
        attestation_count = body_proof.block_body.attestations.len(),
        proof_bytes = body_proof.proof.proof.len(),
        ?elapsed,
        "Block body proof built"
    );
    metrics::observe_body_proof_building(elapsed);

    actor
        .send(BodyProofProduced {
            slot,
            body_proof,
            elapsed,
        })
        .is_ok()
}

/// One round of job selection: honor the role flag and the pause reasons, take
/// the slot from the store clock and the position inside it from the wall
/// clock, then decide what is worth doing.
///
/// In the head-update interval the next slot's candidate body proof comes
/// first, unless one was already built for that slot: it is the job with a
/// deadline (the proposer assembles before the slot boundary), while
/// aggregation work keeps just as well for the next round. Otherwise the best
/// aggregation job the [`JobPolicy`] admits wins ([`select_best_job`]). `None`
/// means "nothing to do right now", which inside the early window is a
/// deliberate answer rather than an idle one.
fn next_job(
    store: &Store,
    time_config: &ChainConfig,
    aggregator: &AggregatorController,
    paused: &AtomicU8,
    config: &WorkerConfig,
    body_proof_slot: Option<u64>,
) -> Option<WorkerJob> {
    // The role flag is read here because the RPC thread writes it. Everything
    // the actor itself owns, the sync verdict included, reaches us as a
    // [`PauseReason`] instead of being re-derived from shared state.
    if !aggregator.is_enabled() || paused.load(Ordering::Acquire) != 0 {
        return None;
    }

    let now_ms = crate::unix_now_ms();
    // Before genesis there is no slot to aggregate for. A "has the chain
    // started" test only; which slot we are in comes from the store clock.
    if now_ms < time_config.genesis_time_ms() {
        return None;
    }

    // The slot comes from the store clock, the one authority the actor drives
    // the interval grid off (`on_tick`'s idempotency guard keys on it).
    // Derived independently from the wall clock the two could disagree — the
    // wall clock drifts behind the monotonic tick cadence inside VMs, and a
    // long block build leaves the store clock ahead of it — and
    // `select_best_job` would then bucket the slot's real group as stale,
    // proving it thin below `min_sigs`, or bucket a stale group as current and
    // hold it back to a boundary that has already passed.
    let slot = store.current_slot();
    let ms_into_slot = ms_into_slot(now_ms, slot, time_config);

    if ms_into_slot >= head_update_offset_ms(time_config) && body_proof_slot != Some(slot + 1) {
        return Some(WorkerJob::BodyProof { slot: slot + 1 });
    }

    let policy = job_policy(ms_into_slot, time_config, store, config);
    let window_config = AggregationWindowConfig {
        duty_subnet: config.aggregation_duty_subnet,
        committee_count: config.attestation_committee_count,
        skip_redundant: config.skip_redundant_aggregation,
    };

    select_best_job(store, slot, policy, window_config)
        .map(Box::new)
        .map(WorkerJob::Aggregate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_storage::backend::InMemoryBackend;
    use ethlambda_types::constants::DEFAULT_MILLISECONDS_PER_SLOT;
    use ethlambda_types::{
        block::{Block, BlockBody, BlockHeader, BlockProof, SignedBlock},
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
                attestation_pubkey: [i as u8; 32],
                proposal_pubkey: [i as u8; 32],
                index: i as u64,
            })
            .collect()
    }

    /// A structurally valid XMSS signature for tests that only need
    /// `ValidatorSignature::from_bytes` to succeed. `resolve_job` never checks
    /// signature validity, only that it clones and carries a resolvable id —
    /// mirrors `ethlambda_storage::store::tests::make_dummy_sig`. An all-zero
    /// blob decodes as a valid (unverifiable) signature.
    fn dummy_sig() -> ValidatorSignature {
        use ethlambda_types::attestation::SIGNATURE_SIZE;
        ValidatorSignature::from_bytes(&vec![0u8; SIGNATURE_SIZE])
            .expect("all-zero test signature decodes")
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
            proof: BlockProof::default(),
        };
        store
            .insert_signed_block(root, signed_block)
            .expect("insert test block should succeed");
    }

    /// Head slot used by the subnet-window tests.
    const WINDOW_TEST_SLOT: u64 = 4;

    /// Validator count for the subnet-window tests: eight, so with four
    /// committees each subnet holds exactly two (validator `v` in subnet
    /// `v % 4`).
    const WINDOW_TEST_VALIDATORS: usize = 8;

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

    /// The window matching [`vacuous_window_config`], for `resolve_job` tests
    /// that predate the window and want it to admit everything.
    fn vacuous_window() -> SubnetWindow {
        SubnetWindow::new(0, 1, 1)
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

    /// The anchor is the largest-coverage proof touching the duty subnet, so
    /// a duty subnet the pool does not reach gets no anchor and therefore the
    /// narrowest window: the aggregator is left to its own raw signatures
    /// rather than merging proofs it has no stake in.
    #[test]
    fn window_width_follows_the_anchor_on_the_duty_subnet() {
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
                    .expect("no rotation without the flag")
                    .width()
            })
            .collect();

        assert_eq!(
            widths,
            vec![2, 2, 1, 1],
            "subnets 0 and 1 have a reach-1 anchor; 2 and 3 have none"
        );
    }

    /// Coverage, not reach, picks the anchor. A sparse proof spanning every
    /// subnet with one validator each would otherwise set the width to the
    /// committee count for every aggregator and switch the window off
    /// network-wide.
    #[test]
    fn a_sparse_wide_proof_does_not_set_the_width() {
        let pool = [
            // Reach 4, coverage 4: one validator in each subnet.
            SingleMessageAggregate::empty(make_bits(&[0, 1, 2, 3])),
            // Reach 1, coverage 6: subnet 0 only, but far more of it.
            SingleMessageAggregate::empty(make_bits(&[0, 4, 8, 12, 16, 20])),
        ];

        assert_eq!(
            anchor_reach(&pool, &[], 0, 4),
            1,
            "the denser proof anchors"
        );
        assert_eq!(window_width(anchor_reach(&pool, &[], 0, 4), 4), 2);

        // Subnet 1 is only in the sparse proof, so there it does set the width.
        assert_eq!(anchor_reach(&pool, &[], 1, 4), 4);
    }

    /// A pool with nothing on the duty subnet has no anchor at all.
    #[test]
    fn anchor_reach_is_zero_without_a_proof_on_the_duty_subnet() {
        let pool = [
            SingleMessageAggregate::empty(make_bits(&[0, 4])),
            SingleMessageAggregate::empty(make_bits(&[1, 5])),
        ];
        assert_eq!(anchor_reach(&pool, &[], 2, 4), 0);
        assert_eq!(window_width(0, 4), 1, "which floors the window");
    }

    /// A coverage tie falls to the larger reach, so the width does not depend
    /// on which order the pool happens to be iterated in.
    #[test]
    fn anchor_reach_breaks_a_coverage_tie_on_reach() {
        let narrow = SingleMessageAggregate::empty(make_bits(&[0, 4]));
        let wide = SingleMessageAggregate::empty(make_bits(&[0, 1]));

        assert_eq!(anchor_reach(&[narrow.clone(), wide.clone()], &[], 0, 4), 2);
        assert_eq!(anchor_reach(&[wide, narrow], &[], 0, 4), 2);
    }

    /// The known set is searched for an anchor alongside the new set.
    #[test]
    fn anchor_reach_spans_both_proof_sets() {
        let new = [SingleMessageAggregate::empty(make_bits(&[1, 5]))];
        let known = [SingleMessageAggregate::empty(make_bits(&[0, 1]))];
        assert_eq!(
            anchor_reach(&new, &known, 0, 4),
            2,
            "only `known` reaches 0"
        );
    }

    /// A duty subnet at or above the committee count is reduced *before* the
    /// width rotation, not merely inside `SubnetWindow::new`. Nothing
    /// validates the upper bound of `--aggregate-subnet-ids`, so this is
    /// reachable from the CLI.
    ///
    /// Reduction is load-bearing twice over. Unreduced, duty subnet 4 matches
    /// no validator's subnet at committee count 3, so it would find no anchor
    /// and sit at width 1; and at a width that does not divide the committee
    /// count it would rotate on different slots from its reduced twin. Slot 1
    /// separates both from the reduced answer: subnet 1 anchors at reach 1,
    /// so width 2, which it owns at slot 1 but not at slot 0.
    #[test]
    fn window_for_candidate_reduces_an_out_of_range_duty_subnet() {
        let pool = [
            SingleMessageAggregate::empty(make_bits(&[0])),
            SingleMessageAggregate::empty(make_bits(&[1])),
        ];
        let derived = |slot: u64, duty_subnet: u64| {
            let config = AggregationWindowConfig {
                duty_subnet,
                committee_count: 3,
                skip_redundant: true,
            };
            window_for_candidate(&pool, &[], slot, config)
        };

        assert_eq!(derived(0, 4), derived(0, 1), "4 reduces to 1 at slot 0");
        assert_eq!(
            derived(0, 1),
            None,
            "subnet 1 does not own width 2 at slot 0"
        );

        assert_eq!(derived(1, 4), derived(1, 1), "4 reduces to 1 at slot 1");
        assert_eq!(
            derived(1, 1),
            Some(SubnetWindow::new(1, 2, 3)),
            "unreduced, 4 would find no anchor and sit at width 1 instead"
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

    // ---- the ownership rotation ----

    /// At a given width the owners tile the committee set: they are spaced a
    /// full width apart, so their windows are disjoint. Eight duty subnets at
    /// width 4 put two owners in each slot, which tells a tiling apart from
    /// "exactly one owner".
    #[test]
    fn owners_tile_the_committee_set_at_a_given_width() {
        let owners = |slot: u64| {
            (0..8)
                .filter(|&duty_subnet| owns_width(duty_subnet, slot, 4))
                .collect::<Vec<u64>>()
        };

        assert_eq!(owners(0), vec![0, 4]);
        assert_eq!(owners(1), vec![1, 5]);
        assert_eq!(owners(2), vec![2, 6]);
        assert_eq!(owners(3), vec![3, 7]);
    }

    /// Every duty subnet gets its turn: over `width` slots each one owns the
    /// level exactly once, so none is permanently the one sitting out.
    #[test]
    fn ownership_gives_every_aggregator_a_turn() {
        for duty_subnet in 0..4u64 {
            let owned_slots: Vec<u64> = (0..4)
                .filter(|&slot| owns_width(duty_subnet, slot, 4))
                .collect();
            assert_eq!(owned_slots, vec![duty_subnet]);
        }
    }

    /// Width 1 is owned by every aggregator in every slot, so a candidate
    /// with no anchor on our subnet, which is the raw-signature case, is
    /// never skipped. A degenerate 0 floors to 1 rather than dividing by
    /// zero.
    #[test]
    fn the_narrowest_width_is_owned_by_everyone() {
        for duty_subnet in 0..4 {
            for slot in 0..8 {
                assert!(owns_width(duty_subnet, slot, 1));
                assert!(owns_width(duty_subnet, slot, 0));
            }
        }
    }

    /// A width that does not divide the committee count still partitions the
    /// duty subnets by residue, so every one of them owns the level exactly
    /// once per `width` slots. The tiling is only ragged in how many owners a
    /// slot has: at committee count 7 and width 4 the residue class `{3}` has
    /// a single member below 7 while the others have two.
    #[test]
    fn ownership_is_exclusive_at_a_non_dividing_width() {
        const COMMITTEE_COUNT: u64 = 7;
        const WIDTH: u64 = 4;

        for duty_subnet in 0..COMMITTEE_COUNT {
            let owned = (0..WIDTH)
                .filter(|&slot| owns_width(duty_subnet, slot, WIDTH))
                .count();
            assert_eq!(owned, 1, "duty subnet {duty_subnet} owns one slot in four");
        }

        let owners_per_slot: Vec<usize> = (0..WIDTH)
            .map(|slot| {
                (0..COMMITTEE_COUNT)
                    .filter(|&d| owns_width(d, slot, WIDTH))
                    .count()
            })
            .collect();
        assert_eq!(owners_per_slot, vec![2, 2, 2, 1], "ragged at the wrap");
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
            &vacuous_window(),
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
            &vacuous_window(),
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
            &vacuous_window(),
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
            &vacuous_window(),
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
        assert!(select_best_job(&store, 0, JobPolicy::Open, vacuous_window_config()).is_none());
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

        assert!(select_best_job(&store, 0, JobPolicy::Open, vacuous_window_config()).is_none());
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
            select_best_job(&store, 999, JobPolicy::Open, vacuous_window_config()).is_none(),
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

        let job = select_best_job(&store, HEAD_SLOT, JobPolicy::Open, vacuous_window_config())
            .expect("a vote for the current head must produce a job (chain view covers the tip)");
        assert_eq!(
            job.hashed.data().target.slot,
            HEAD_SLOT,
            "the job aggregates the vote targeting the current head"
        );
    }

    /// A store whose `new_payloads` buffer holds one proof per entry in
    /// `participant_sets`, all bound to the same `AttestationData`, so
    /// `select_best_job` sees a single candidate whose pool is
    /// exactly those proofs.
    ///
    /// Deliberately carries no gossip signatures: a payload-only candidate
    /// isolates child selection from the raw-signature path, which is what the
    /// window changes. Each proof carries empty proof bytes (`empty`), so the
    /// resulting store can drive selection but never a real merge; a future
    /// end-to-end test reusing this helper needs its own real proofs.
    ///
    /// `validator_count` is a parameter rather than always `WINDOW_TEST_VALIDATORS`
    /// so a wider-committee test (more subnets than the default four) can size
    /// its own validator set.
    fn store_with_payload_only_proofs(
        validator_count: usize,
        participant_sets: &[AggregationBits],
    ) -> Store {
        let (mut store, hashes) = window_test_store(validator_count);
        let att_data = window_test_att_data(&store, WINDOW_TEST_SLOT, &hashes);
        insert_payload_only_candidate(&mut store, att_data, participant_sets);
        store
    }

    /// The chain the subnet-window tests run against: head at
    /// [`WINDOW_TEST_SLOT`], with `hashes[i]` the block root at slot `i`.
    fn window_test_store(validator_count: usize) -> (Store, Vec<H256>) {
        let hashes: Vec<H256> = (0..WINDOW_TEST_SLOT)
            .map(|i| H256([(i + 1) as u8; 32]))
            .collect();
        let store = new_test_store(make_head_state(WINDOW_TEST_SLOT, validator_count, &hashes));
        (store, hashes)
    }

    /// A vote for the canonical block at `slot`, sourced at genesis. Distinct
    /// slots give distinct data roots, so a test can put more than one
    /// candidate in front of `select_best_job`.
    fn window_test_att_data(store: &Store, slot: u64, hashes: &[H256]) -> AttestationData {
        let root = if slot == WINDOW_TEST_SLOT {
            store.head().expect("head read works")
        } else {
            hashes[slot as usize]
        };
        let checkpoint = Checkpoint { root, slot };
        AttestationData {
            slot,
            head: checkpoint,
            target: checkpoint,
            source: Checkpoint {
                root: hashes[0],
                slot: 0,
            },
        }
    }

    /// Bind `participant_sets` to `att_data` as payload-only proofs, making
    /// one aggregation candidate whose pool is exactly those proofs.
    fn insert_payload_only_candidate(
        store: &mut Store,
        att_data: AttestationData,
        participant_sets: &[AggregationBits],
    ) {
        let hashed = HashedAttestationData::new(att_data);
        for bits in participant_sets {
            store.insert_new_aggregated_payload(
                hashed.clone(),
                SingleMessageAggregate::empty(bits.clone()),
            );
        }
    }

    /// Two aggregators on different duty subnets, given the same pool of
    /// per-subnet proofs, select different children: the whole point of the
    /// window. Drives the real `select_best_job` path.
    ///
    /// A two-subnet smoke case; the full four-subnet climb (and its second
    /// round) is pinned by `four_aggregators_climb_from_per_subnet_proofs_to_full_coverage`,
    /// so keep both.
    #[test]
    fn snapshot_gives_different_duty_subnets_different_children() {
        // Four reach-1 proofs (one per subnet), so the derived width is 2 and
        // duty subnet s covers {s, s+1}.
        let store = store_with_payload_only_proofs(
            WINDOW_TEST_VALIDATORS,
            &[
                make_bits(&[0, 4]),
                make_bits(&[1, 5]),
                make_bits(&[2, 6]),
                make_bits(&[3, 7]),
            ],
        );

        let for_subnet = |duty_subnet: u64| {
            let config = AggregationWindowConfig {
                duty_subnet,
                committee_count: 4,
                skip_redundant: false,
            };
            select_best_job(&store, WINDOW_TEST_SLOT, JobPolicy::Open, config)
                .expect("a payload-only merge is viable")
                .accepted_child_ids
                .iter()
                .copied()
                .collect::<HashSet<u64>>()
        };

        assert_eq!(for_subnet(0), HashSet::from([0, 4, 1, 5]));
        assert_eq!(for_subnet(2), HashSet::from([2, 6, 3, 7]));
    }

    /// The reduction tree the whole feature exists to produce. Four
    /// aggregators on four duty subnets, one AttestationData, eight validators
    /// (validator v in subnet v % 4).
    ///
    /// Round 1's pool holds reach-1 proofs, so the width is 2 and each
    /// aggregator merges its own subnet with the next. Round 2's pool holds
    /// what round 1 published, all reach 2, so the width is 4 and every
    /// aggregator reaches the full validator set.
    ///
    /// The two rounds are constructed here as two separate stores, not
    /// observed from one session: only one session runs per slot, so in
    /// production these would be two successive slots' sessions for a data
    /// root that stays live, not two rounds back to back within one session.
    #[test]
    fn four_aggregators_climb_from_per_subnet_proofs_to_full_coverage() {
        const COMMITTEE_COUNT: u64 = 4;

        let coverage_for = |store: &Store, duty_subnet: u64| -> HashSet<u64> {
            let config = AggregationWindowConfig {
                duty_subnet,
                committee_count: COMMITTEE_COUNT,
                skip_redundant: false,
            };
            select_best_job(store, WINDOW_TEST_SLOT, JobPolicy::Open, config)
                .expect("a payload-only merge is viable")
                .coverage()
        };

        let round_1 = store_with_payload_only_proofs(
            WINDOW_TEST_VALIDATORS,
            &[
                make_bits(&[0, 4]),
                make_bits(&[1, 5]),
                make_bits(&[2, 6]),
                make_bits(&[3, 7]),
            ],
        );

        assert_eq!(coverage_for(&round_1, 0), HashSet::from([0, 4, 1, 5]));
        assert_eq!(coverage_for(&round_1, 1), HashSet::from([1, 5, 2, 6]));
        assert_eq!(coverage_for(&round_1, 2), HashSet::from([2, 6, 3, 7]));
        assert_eq!(coverage_for(&round_1, 3), HashSet::from([3, 7, 0, 4]));

        // The pool now holds what round 1 published.
        let round_2 = store_with_payload_only_proofs(
            WINDOW_TEST_VALIDATORS,
            &[
                make_bits(&[0, 4, 1, 5]),
                make_bits(&[1, 5, 2, 6]),
                make_bits(&[2, 6, 3, 7]),
                make_bits(&[3, 7, 0, 4]),
            ],
        );

        let all_validators: HashSet<u64> = (0..WINDOW_TEST_VALIDATORS as u64).collect();
        for duty_subnet in 0..COMMITTEE_COUNT {
            assert_eq!(
                coverage_for(&round_2, duty_subnet),
                all_validators,
                "duty subnet {duty_subnet} reaches every validator once the width is 4"
            );
        }
    }

    /// A genuine mid-climb widening: the window grows but stays a proper
    /// subset of the committee set, wide enough to change which children get
    /// picked. Unreachable at four committees (there the only states are
    /// width 2 and width 4, i.e. full), so this uses eight committees and
    /// sixteen validators: a reach-2 pool derives width 4, half the committee.
    ///
    /// Each proof merges a disjoint pair of adjacent subnets, so within any
    /// width-4 window exactly two proofs score (the other two lie wholly
    /// outside and are skipped), leaving no tie to break. Duty subnets four
    /// apart get non-overlapping windows and therefore disjoint children.
    #[test]
    fn wider_window_at_eight_committees_selects_disjoint_halves() {
        const COMMITTEE_COUNT: u64 = 8;
        const VALIDATOR_COUNT: usize = 16;

        // Reach-2 proofs, one per disjoint subnet pair: {0,1}, {2,3}, {4,5}, {6,7}.
        let store = store_with_payload_only_proofs(
            VALIDATOR_COUNT,
            &[
                make_bits(&[0, 8, 1, 9]),
                make_bits(&[2, 10, 3, 11]),
                make_bits(&[4, 12, 5, 13]),
                make_bits(&[6, 14, 7, 15]),
            ],
        );

        let coverage_for = |duty_subnet: u64| -> HashSet<u64> {
            let config = AggregationWindowConfig {
                duty_subnet,
                committee_count: COMMITTEE_COUNT,
                skip_redundant: false,
            };
            select_best_job(&store, WINDOW_TEST_SLOT, JobPolicy::Open, config)
                .expect("a payload-only merge is viable")
                .coverage()
        };

        assert_eq!(
            coverage_for(0),
            HashSet::from([0, 8, 1, 9, 2, 10, 3, 11]),
            "duty 0's width-4 window {{0,1,2,3}} covers the first two pairs"
        );
        assert_eq!(
            coverage_for(4),
            HashSet::from([4, 12, 5, 13, 6, 14, 7, 15]),
            "duty 4's window {{4,5,6,7}} covers the other two pairs, disjoint from duty 0's"
        );
    }

    /// A skipped candidate hands its job budget to the next-best
    /// `AttestationData` rather than being downgraded to a narrower merge of
    /// its own. Two candidates, one job:
    ///
    /// - the current-slot candidate's pool is reach-2, so width 4, which at
    ///   [`WINDOW_TEST_SLOT`] only duty subnet 0 owns;
    /// - the stale candidate's pool is reach-1, so width 2, which duty
    ///   subnets 0 and 2 own at that slot.
    ///
    /// Duty subnet 2 therefore skips the current-slot candidate that
    /// outranks everything (current-slot groups always precede stale ones)
    /// and spends its one job on the stale candidate instead.
    #[test]
    fn a_skipped_candidate_hands_its_budget_to_the_next_best() {
        const STALE_SLOT: u64 = WINDOW_TEST_SLOT - 1;

        let (mut store, hashes) = window_test_store(WINDOW_TEST_VALIDATORS);
        // The stale candidate votes for a block below the tip, which
        // `entry_passes_filters` looks up in `get_block_roots` rather than in
        // the state's `historical_block_hashes`.
        insert_test_block(
            &mut store,
            hashes[STALE_SLOT as usize],
            STALE_SLOT,
            hashes[STALE_SLOT as usize - 1],
        );
        let current = window_test_att_data(&store, WINDOW_TEST_SLOT, &hashes);
        let stale = window_test_att_data(&store, STALE_SLOT, &hashes);
        let current_pool = [make_bits(&[0, 4, 1, 5]), make_bits(&[2, 6, 3, 7])];
        let stale_pool = [
            make_bits(&[0, 4]),
            make_bits(&[1, 5]),
            make_bits(&[2, 6]),
            make_bits(&[3, 7]),
        ];
        insert_payload_only_candidate(&mut store, current, &current_pool);
        insert_payload_only_candidate(&mut store, stale, &stale_pool);

        let job_slot = |duty_subnet: u64, skip_redundant: bool| -> Option<u64> {
            let config = AggregationWindowConfig {
                duty_subnet,
                committee_count: 4,
                skip_redundant,
            };
            select_best_job(&store, WINDOW_TEST_SLOT, JobPolicy::Open, config)
                .map(|job| job.hashed.data().slot)
        };

        assert_eq!(
            job_slot(2, false),
            Some(WINDOW_TEST_SLOT),
            "without the flag the current-slot candidate always wins the budget"
        );
        assert_eq!(
            job_slot(2, true),
            Some(STALE_SLOT),
            "duty 2 does not own width 4, so its budget moves to the next best"
        );
        assert_eq!(
            job_slot(0, true),
            Some(WINDOW_TEST_SLOT),
            "duty 0 owns width 4 at this slot and keeps the better candidate"
        );
    }

    /// With the redundancy-skipping rotation on, a duty subnet that does not
    /// own the derived width sits the candidate out so its job budget can go
    /// to the next-best `AttestationData`. Here that candidate is the only
    /// one, so the session is simply empty for those aggregators; in
    /// production the budget lands on the current slot's own candidate, whose
    /// empty pool gives it no anchor and therefore width 1, which everybody
    /// owns.
    #[test]
    fn skip_redundant_leaves_unowned_duty_subnets_without_a_job() {
        let pool = [
            make_bits(&[0, 4]),
            make_bits(&[1, 5]),
            make_bits(&[2, 6]),
            make_bits(&[3, 7]),
        ];
        let snapshot_for = |duty_subnet: u64| {
            let store = store_with_payload_only_proofs(WINDOW_TEST_VALIDATORS, &pool);
            let config = AggregationWindowConfig {
                duty_subnet,
                committee_count: 4,
                skip_redundant: true,
            };
            select_best_job(&store, WINDOW_TEST_SLOT, JobPolicy::Open, config)
        };

        assert!(
            snapshot_for(0).is_some(),
            "duty 0 owns width 2 at this slot"
        );
        assert!(
            snapshot_for(2).is_some(),
            "duty 2 owns width 2 at this slot"
        );
        assert!(
            snapshot_for(1).is_none(),
            "duty 1 does not own width 2 at this slot"
        );
        assert!(
            snapshot_for(3).is_none(),
            "duty 3 does not own width 2 at this slot"
        );
    }

    /// Regression: a strided aggregator placement (this project's devnets
    /// place single-subnet aggregators this way) can leave a window holding
    /// only one proof, where the pre-window (unwindowed) selection would have
    /// merged two. Committee count 8, sixteen validators (two per subnet, so
    /// a single-subnet aggregator's proof has reach 1), proofs on subnets 0,
    /// 3, 5 and 7 only. Duty subnet 0 derives width 2 (max_reach 1), so its
    /// window is {0,1}: only the subnet-0 proof scores, the other three lie
    /// wholly outside and are skipped, leaving one child. That is not viable
    /// on its own (`resolve_job`'s viability guard needs at least two
    /// children when there are no raw sigs), so without the fallback this
    /// candidate would be dropped entirely.
    ///
    /// The expected coverage is derived from the unwindowed (full-width)
    /// greedy selection by hand, not asserted against the windowed run: with
    /// every proof the same size (2 validators), `select_proofs_greedily`'s
    /// `max_by_key` ties break toward the *last* candidate in pool order
    /// (std's documented tie-breaking), so a full window picks subnet 7's
    /// proof first, then subnet 5's, capping at `MAX_AGGREGATION_CHILDREN`
    /// before subnets 0 or 3 are ever reached.
    #[test]
    fn window_fallback_recovers_a_merge_a_strided_placement_would_drop() {
        const COMMITTEE_COUNT: u64 = 8;
        const VALIDATOR_COUNT: usize = 16;

        let pool = [
            make_bits(&[0, 8]),
            make_bits(&[3, 11]),
            make_bits(&[5, 13]),
            make_bits(&[7, 15]),
        ];
        let store = store_with_payload_only_proofs(VALIDATOR_COUNT, &pool);
        let config = AggregationWindowConfig {
            duty_subnet: 0,
            committee_count: COMMITTEE_COUNT,
            skip_redundant: false,
        };

        let job = select_best_job(&store, WINDOW_TEST_SLOT, JobPolicy::Open, config).expect(
            "the full-width fallback recovers a viable job the windowed selection alone drops",
        );

        assert_eq!(
            job.coverage(),
            HashSet::from([5, 7, 13, 15]),
            "coverage matches the unwindowed selection's last-two-by-pool-order tie-break"
        );
    }

    /// Guards `vacuous_window_config`: at a committee count of 1 the window
    /// covers everything whatever the duty subnet, so the pre-window tests
    /// that use it keep testing what they used to. Uses an out-of-range duty
    /// subnet to pin that the fold happens before any window arithmetic.
    #[test]
    fn a_single_committee_ignores_the_duty_subnet() {
        let store = store_with_payload_only_proofs(
            WINDOW_TEST_VALIDATORS,
            &[make_bits(&[0, 1]), make_bits(&[2, 3])],
        );

        let coverage_for = |duty_subnet: u64| -> HashSet<u64> {
            let config = AggregationWindowConfig {
                duty_subnet,
                committee_count: 1,
                skip_redundant: false,
            };
            select_best_job(&store, WINDOW_TEST_SLOT, JobPolicy::Open, config)
                .expect("a payload-only merge is viable")
                .coverage()
        };

        assert_eq!(coverage_for(0), HashSet::from([0, 1, 2, 3]));
        assert_eq!(
            coverage_for(3),
            HashSet::from([0, 1, 2, 3]),
            "duty subnet 3 is out of range at committee count 1 and folds to 0"
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

        let job = select_best_job(&store, 999, JobPolicy::Open, vacuous_window_config())
            .expect("should produce a job");
        assert_eq!(job.hashed.data().target.slot, NUM_GROUPS as u64);
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
            vacuous_window_config(),
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
                vacuous_window_config(),
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
            vacuous_window_config(),
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
            vacuous_window_config(),
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
            aggregation_duty_subnet: 0,
            skip_redundant_aggregation: false,
            proposer_config: ProposerConfig {
                enable_proposer_aggregation: false,
                max_attestations_per_block: 1,
            },
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

    /// The point of a bitset over a single flag: reasons are independent, so
    /// setting one twice is idempotent (the level-driven owner sets its reason
    /// on every tick) and releasing one leaves the others holding the worker.
    #[test]
    fn pause_reasons_are_independent() {
        let paused = AtomicU8::new(0);

        set_pause_reason(&paused, PauseReason::Syncing, true);
        set_pause_reason(&paused, PauseReason::BlockBuild, true);
        set_pause_reason(&paused, PauseReason::Syncing, true);

        // The build finishing leaves the sync gate still holding the worker.
        set_pause_reason(&paused, PauseReason::BlockBuild, false);
        assert_eq!(paused.load(Ordering::Acquire), PauseReason::Syncing as u8);

        set_pause_reason(&paused, PauseReason::Syncing, false);
        assert_eq!(paused.load(Ordering::Acquire), 0);
    }

    /// A guard clears its own reason and nothing else. Under the plain bool
    /// this replaced, dropping the block-build guard released every reason.
    #[test]
    fn pause_guard_drop_releases_only_its_own_reason() {
        let paused = Arc::new(AtomicU8::new(0));
        set_pause_reason(&paused, PauseReason::Syncing, true);

        {
            set_pause_reason(&paused, PauseReason::BlockBuild, true);
            let _guard = PauseGuard {
                paused: paused.clone(),
                reason: PauseReason::BlockBuild,
            };
        }

        assert_eq!(paused.load(Ordering::Acquire), PauseReason::Syncing as u8);
    }

    /// The store clock owns which slot the worker is in, so the wall-clock
    /// offset is always measured against *that* slot and clamped to it. A wall
    /// clock lagging the store reads as the start of the store's slot, one
    /// running ahead as its end; neither can describe a position inside a
    /// different slot, which is what would mis-bucket the slot's own group.
    #[test]
    fn ms_into_slot_is_measured_against_the_store_slot() {
        let time_config = ChainConfig::new(1_000, DEFAULT_MILLISECONDS_PER_SLOT);
        let genesis_ms = time_config.genesis_time_ms();
        let slot = 7;
        let slot_start_ms = genesis_ms + slot * DEFAULT_MILLISECONDS_PER_SLOT;

        assert_eq!(ms_into_slot(slot_start_ms, slot, &time_config), 0);
        assert_eq!(
            ms_into_slot(slot_start_ms + 1_234, slot, &time_config),
            1_234
        );

        // Wall clock a slot and a half behind the store: clamped to the start
        // of the store's slot, the permissive `Backlog` end.
        let behind = slot_start_ms - DEFAULT_MILLISECONDS_PER_SLOT / 2;
        assert_eq!(ms_into_slot(behind, slot, &time_config), 0);
        assert_eq!(ms_into_slot(genesis_ms, slot, &time_config), 0);

        // Wall clock past the end of the store's slot: clamped to the slot's
        // width, which is at or past the vote-aggregation boundary, so `Open`.
        let ahead = slot_start_ms + 3 * DEFAULT_MILLISECONDS_PER_SLOT;
        assert_eq!(
            ms_into_slot(ahead, slot, &time_config),
            DEFAULT_MILLISECONDS_PER_SLOT
        );
        assert!(
            ms_into_slot(ahead, slot, &time_config) >= vote_aggregation_offset_ms(&time_config)
        );

        // Before genesis at all: still the start of slot 0, no underflow.
        assert_eq!(ms_into_slot(0, 0, &time_config), 0);
    }
}
