use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant, SystemTime};

use ethlambda_network_api::{BlockChainToP2PRef, InitP2P};
use ethlambda_state_transition::is_proposer;
use ethlambda_storage::{ALL_TABLES, Store};
use ethlambda_types::{
    ShortRoot,
    aggregator::AggregatorController,
    attestation::{SignedAggregatedAttestation, SignedAttestation},
    block::{ByteList512KiB, MultiMessageAggregate, SignedBlock},
    primitives::{H256, HashTreeRoot as _},
    signature::{ValidatorPublicKey, ValidatorSignature},
};

use crate::aggregation::{
    AGGREGATION_DEADLINE, AggregateProduced, AggregationDeadline, AggregationDone,
    AggregationSession, EARLY_AGGREGATION_WINDOW_MS, EarlyAggregationCheck,
    PRIOR_WORKER_JOIN_TIMEOUT, run_aggregation_worker,
};
use crate::key_manager::ValidatorKeyPair;
use crate::sync_status::SyncStatusTracker;
use spawned_concurrency::actor;
use spawned_concurrency::error::ActorError;
use spawned_concurrency::protocol;
use spawned_concurrency::tasks::{Actor, ActorRef, ActorStart, Context, Handler, send_after};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use crate::block_builder::ProposerConfig;
use crate::store::StoreError;

pub mod aggregation;
pub mod block_builder;
pub(crate) mod coverage;
pub(crate) mod fork_choice_tree;
pub mod key_manager;
pub mod metrics;
pub mod reaggregate;
pub mod store;
mod sync_status;

pub struct BlockChain {
    handle: ActorRef<BlockChainServer>,
}

/// Milliseconds per interval (800ms ticks).
pub const MILLISECONDS_PER_INTERVAL: u64 = 800;
/// Number of intervals per slot (5 intervals of 800ms = 4 seconds).
pub const INTERVALS_PER_SLOT: u64 = 5;
/// Milliseconds in a slot (derived from interval duration and count).
pub const MILLISECONDS_PER_SLOT: u64 = MILLISECONDS_PER_INTERVAL * INTERVALS_PER_SLOT;
pub use ethlambda_types::block::MAX_ATTESTATIONS_DATA;
/// Future-slot tolerance for gossip attestations, expressed in intervals.
///
/// Bounds the clock skew the time check is willing to absorb when admitting a
/// vote whose slot has not yet started locally. One interval is roughly 800 ms,
/// the lean analogue of mainnet's `MAXIMUM_GOSSIP_CLOCK_DISPARITY`.
///
/// See: leanSpec PR #682.
pub const GOSSIP_DISPARITY_INTERVALS: u64 = 1;

/// Milliseconds until the next interval boundary, measured relative to genesis.
fn ms_until_next_interval(now_ms: u64, genesis_time_ms: u64) -> u64 {
    // Before genesis: wait until genesis itself.
    let Some(ms_since_genesis) = now_ms.checked_sub(genesis_time_ms) else {
        return genesis_time_ms - now_ms;
    };
    MILLISECONDS_PER_INTERVAL - (ms_since_genesis % MILLISECONDS_PER_INTERVAL)
}

/// Current UNIX timestamp in milliseconds.
fn unix_now_ms() -> u64 {
    SystemTime::UNIX_EPOCH
        .elapsed()
        .expect("already past the unix epoch")
        .as_millis() as u64
}

impl BlockChain {
    pub fn spawn(
        store: Store,
        validator_keys: HashMap<u64, ValidatorKeyPair>,
        aggregator: AggregatorController,
        attestation_committee_count: u64,
        gate_duties: bool,
        proposer_config: ProposerConfig,
    ) -> BlockChain {
        metrics::set_is_aggregator(aggregator.is_enabled());
        metrics::set_node_sync_status(metrics::SyncStatus::Idle);
        let genesis_time = store.config().genesis_time;
        let mut key_manager = key_manager::KeyManager::new(validator_keys);

        // Catch XMSS keys up to the current slot before the first tick
        // store.time() doesn't work here: after an offline gap it lags wall-clock by
        // exactly the gap we need to catch up through
        let now_ms = unix_now_ms();
        let current_slot =
            (now_ms.saturating_sub(genesis_time * 1000) / MILLISECONDS_PER_SLOT) as u32;
        key_manager.advance_keys_to(current_slot);

        let handle = BlockChainServer {
            store,
            p2p: None,
            key_manager,
            pending_blocks: HashMap::new(),
            aggregator,
            pending_block_parents: HashMap::new(),
            current_aggregation: None,
            last_tick_instant: None,
            attestation_committee_count,
            proposer_config,
            pre_merge_coverage: None,
            sync_status: SyncStatusTracker::new(gate_duties),
        }
        .start();
        let time_until_genesis = (SystemTime::UNIX_EPOCH + Duration::from_secs(genesis_time))
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        send_after(
            time_until_genesis,
            handle.context(),
            block_chain_protocol::Tick,
        );
        BlockChain { handle }
    }

    pub fn actor_ref(&self) -> &ActorRef<BlockChainServer> {
        &self.handle
    }
}

/// GenServer that sequences all blockchain updates.
///
/// Any head or finalization updates are done by this server.
/// Right now it also handles block processing, but in the future
/// those updates might be done in parallel with only writes being
/// processed by this server.
pub struct BlockChainServer {
    store: Store,

    // P2P protocol ref (set via InitP2P message)
    p2p: Option<BlockChainToP2PRef>,

    key_manager: key_manager::KeyManager,

    // Pending block roots waiting for their parent (block data stored in DB)
    pending_blocks: HashMap<H256, HashSet<H256>>,
    // Maps pending block_root → its cached missing ancestor. Resolved by walking the
    // chain at lookup time, since a cached ancestor may itself have become pending with
    // a deeper missing parent after the entry was created.
    pending_block_parents: HashMap<H256, H256>,

    /// Whether this node acts as a committee aggregator.
    ///
    /// Read fresh on every tick and gossip event so runtime toggles via the
    /// admin API take effect without a restart. Seeded from the CLI
    /// `--is-aggregator` flag at spawn.
    aggregator: AggregatorController,

    /// The slot's one committee-signature aggregation session (started at
    /// interval 2, or early via the 2/3 trigger). Deliberately persists after
    /// the worker finishes — that persistence is the once-per-slot latch the
    /// early trigger and the interval-2 skip both check — until the next
    /// session start replaces it.
    current_aggregation: Option<AggregationSession>,

    /// Last tick instant for measuring interval duration.
    last_tick_instant: Option<Instant>,

    /// Number of attestation committees (= subnet count). Used by the
    /// attestation aggregate coverage emission and the early-aggregation
    /// threshold.
    attestation_committee_count: u64,

    /// Proposer-side block-building policy
    proposer_config: ProposerConfig,

    /// Pre-merge `new_payloads` snapshot for the attestation aggregate coverage
    /// report. Captured at the end-of-slot promote (interval 4), read at the
    /// next slot boundary. Owned solely by the actor and only touched from the
    /// single-threaded message loop, so no synchronization is needed.
    /// Observability-only.
    pre_merge_coverage: Option<coverage::CoverageSnapshot>,

    /// Stateful sync heuristic used by `lean_node_sync_status`. Also gates
    /// validator duties while syncing, unless that gating was disabled at
    /// startup via `--disable-duty-sync-gate` (then it is metric-only).
    sync_status: SyncStatusTracker,
}

impl BlockChainServer {
    async fn on_tick(&mut self, timestamp_ms: u64, ctx: &Context<Self>) {
        let genesis_time_ms = self.store.config().genesis_time * 1000;

        // Calculate current slot and interval from milliseconds
        let time_since_genesis_ms = timestamp_ms.saturating_sub(genesis_time_ms);
        let slot = time_since_genesis_ms / MILLISECONDS_PER_SLOT;
        let interval = (time_since_genesis_ms % MILLISECONDS_PER_SLOT) / MILLISECONDS_PER_INTERVAL;

        // Idempotency guard
        //
        // `slot`/`interval` come from the wall clock, but the tick cadence is driven
        // by the monotonic clock (`tokio::sleep`). The wall clock can drift behind it
        // inside VMs, so a tick scheduled for the next interval boundary can fire
        // while the wall clock still reads the previous interval.
        let tick_interval = time_since_genesis_ms / MILLISECONDS_PER_INTERVAL;
        let store_time = self.store.time();

        if store_time > 0 && tick_interval <= store_time {
            debug!(
                %slot,
                %interval,
                tick_interval,
                store_time,
                "Skipping already-processed tick"
            );
            return;
        }

        // Fail fast: a state with zero validators is invalid and would cause
        // panics in proposer selection and attestation processing.
        if self.store.head_state().validators.is_empty() {
            error!("Head state has no validators, skipping tick");
            return;
        }

        // Observe tick interval duration. Done after the idempotency guard so a
        // skipped duplicate tick doesn't shorten the next real tick's sample.
        if let Some(prev_instant) = self.last_tick_instant {
            metrics::observe_tick_interval_duration(prev_instant.elapsed());
        }
        self.last_tick_instant = Some(Instant::now());

        // Update current slot metric
        metrics::update_current_slot(slot);
        self.update_sync_status(slot);

        // Snapshot the aggregator flag once per tick so all read sites within
        // the tick see a consistent value even if the admin API toggles it
        // mid-tick. Mirror it to the gauge from the actor side so
        // `lean_is_aggregator` reflects the value the actor is acting on.
        let is_aggregator = self.aggregator.is_enabled();
        metrics::set_is_aggregator(is_aggregator);

        // ==== interval 4 (pre-tick) ====

        // Snapshot the pre-merge `new_payloads` set at the end-of-slot promote
        // (interval 4), so the post-block report for this round sees its
        // "timely" cohort just before it is promoted out of `new_payloads`.
        //
        // Only interval 4 — not the proposer's interval-0 promote. By interval 0
        // the round's votes have already been promoted at the previous slot's
        // interval 4; `new_payloads` then holds only stragglers, and snapshotting
        // them here would overwrite the good interval-4 snapshot the report still
        // needs (those stragglers surface in the `late` section instead). Skip
        // empty snapshots so a missed round keeps the last set we saw. Pure
        // observability.
        if interval == 4
            && let Some(snapshot) = coverage::snapshot_new_payloads(&self.store)
        {
            self.pre_merge_coverage = Some(snapshot);
        }

        // Whether one of our validators proposes this slot. Drives the store's
        // interval-0 attestation acceptance.
        let is_proposer = (interval == 0 && slot > 0)
            .then(|| self.get_our_proposer(slot))
            .flatten()
            .is_some();

        // Tick the store first - this accepts attestations at interval 0 if we have a proposal
        store::on_tick(&mut self.store, timestamp_ms, is_proposer);

        // Per-interval duties for this tick. Intervals 0 (block publish) and 3
        // (safe-target update) are driven inside `store::on_tick` above, so they
        // carry only a note below.
        match interval {
            // ==== interval 0 ====
            //
            // No actor work at interval 0. The block is published here
            // conceptually (at the slot boundary), but the build+publish code
            // path runs at interval 4 of the previous slot — where it also
            // advances the store to this slot's interval 0 before building (see
            // `propose_block`). The real interval-0 tick is then skipped by the
            // idempotency guard above, since the store clock is already here.
            0 => {}

            // ==== interval 1 ====
            //
            // Produce attestations at interval 1 (all validators including
            // proposer). Reuse the same snapshot so self-delivery decisions
            // match the rest of the tick.
            1 => {
                // Emit the post-block coverage report for the previous slot.
                // Fired at interval 1 (not 0) so the block carrying `slot - 1`'s
                // votes — proposed at interval 0 of this slot — has typically
                // been received and processed, letting the `block` section see
                // the same round.
                if slot > 0 {
                    coverage::emit_post_block_coverage(
                        &self.store,
                        self.pre_merge_coverage.as_ref(),
                        self.attestation_committee_count,
                        slot - 1,
                    );
                }
                if self.sync_status.duties_allowed() {
                    self.produce_attestations(slot, is_aggregator);
                } else if !self.key_manager.validator_ids().is_empty() {
                    info!(%slot, "Skipping attestations while syncing");
                }

                // Schedule the early-aggregation window check. This tick is
                // one interval before T2, so the timer fires right as the
                // window opens at T2 - EARLY_AGGREGATION_WINDOW_MS.
                if is_aggregator {
                    send_after(
                        Duration::from_millis(
                            MILLISECONDS_PER_INTERVAL - EARLY_AGGREGATION_WINDOW_MS,
                        ),
                        ctx.clone(),
                        EarlyAggregationCheck,
                    );
                }
            }

            // ==== interval 2 ====
            2 => {
                if is_aggregator {
                    // The early trigger may have already started this slot's
                    // session (running or finished) — it IS the slot's session,
                    // so don't start a second one.
                    let already_started = self
                        .current_aggregation
                        .as_ref()
                        .is_some_and(|session| session.session_id == slot);
                    if !already_started {
                        self.start_aggregation_session(slot, ctx).await;
                    }
                } else {
                    metrics::inc_aggregator_skipped_not_aggregator();
                }
            }

            // ==== interval 3 ====
            //
            // Safe-target update is handled inside `store::on_tick`.
            3 => {}

            // ==== interval 4 ====
            //
            // Build and publish the NEXT slot's block here, one interval early,
            // so the heavy leanVM work happens during this otherwise-idle
            // interval. `propose_block` blocks the actor for the build and aligns
            // publication to the slot boundary. Doing the whole proposal here —
            // rather than stashing it for the interval-0 tick — keeps it robust:
            // `on_tick` skips the interval-0 tick whenever this build overruns
            // its interval.
            4 => {
                let next_slot = slot + 1;
                let next_proposer = self
                    .get_our_proposer(next_slot)
                    .filter(|_| self.sync_status.duties_allowed());

                if let Some(validator_id) = next_proposer {
                    self.propose_block(next_slot, validator_id).await;
                }
            }

            _ => {}
        }

        // Update safe target slot metric (updated by store.on_tick at interval 3)
        metrics::update_safe_target_slot(self.store.safe_target_slot());
        // Update head slot metric (head may change when attestations are promoted at intervals 0/4)
        metrics::update_head_slot(self.store.head_slot());

        // Advance XMSS keys for next slot so the signing paths don't have to
        self.key_manager.advance_keys_to((slot + 1) as u32);
    }

    /// Kick off a committee-signature aggregation session:
    /// 1. If a prior session is still running (pathological), warn and join it.
    /// 2. Snapshot the aggregation inputs from the store.
    /// 3. Spawn a `spawn_blocking` worker that streams results back as messages.
    /// 4. Schedule the `AggregationDeadline` self-message at +`AGGREGATION_DEADLINE`.
    async fn start_aggregation_session(&mut self, slot: u64, ctx: &Context<Self>) {
        if let Some(prior) = self.current_aggregation.take() {
            prior.cancel.cancel();
            if !prior.worker.is_finished() {
                warn!(
                    prior_session_id = prior.session_id,
                    new_session_id = slot,
                    "Prior aggregation worker still running at next session start; joining before proceeding"
                );
            }
            match tokio::time::timeout(PRIOR_WORKER_JOIN_TIMEOUT, prior.worker).await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => warn!(?err, "Prior aggregation worker task ended abnormally"),
                Err(_) => warn!(
                    timeout_secs = PRIOR_WORKER_JOIN_TIMEOUT.as_secs(),
                    "Timed out joining prior aggregation worker"
                ),
            }
        }

        coverage::emit_agg_start_new_coverage(&self.store, self.attestation_committee_count);

        let Some(snapshot) =
            aggregation::snapshot_current_slot_aggregation_inputs(&self.store, slot)
        else {
            // No current-slot gossip sigs — nothing to aggregate this slot.
            return;
        };

        let session_id = slot;
        let genesis_time_ms = self.store.config().genesis_time * 1000;
        let t2_ms = aggregation::interval2_boundary_ms(genesis_time_ms, slot);
        let now_ms = unix_now_ms();
        let early = now_ms < t2_ms;
        if early {
            // Publish alignment lives in the worker: it holds each produced
            // aggregate until `t2_ms` (the interval-2 boundary) before sending
            // it back, so nothing reaches gossip early.
            let lead = Duration::from_millis(t2_ms - now_ms);
            metrics::inc_aggregation_early_starts();
            metrics::observe_aggregation_early_start_lead(lead);
            info!(
                %slot,
                lead_ms = lead.as_millis() as u64,
                "Starting aggregation session early"
            );
        }

        // Independent token per session. Shutdown propagates via our
        // #[stopped] hook which cancels any current session; the deadline
        // timer cancels this specific session at +AGGREGATION_DEADLINE.
        let cancel = CancellationToken::new();
        let actor_ref = ctx.actor_ref();

        let worker_cancel = cancel.clone();
        let worker_actor = actor_ref.clone();
        let worker = tokio::task::spawn_blocking(move || {
            run_aggregation_worker(snapshot, worker_actor, worker_cancel, session_id, t2_ms);
        });

        let _deadline_timer = send_after(
            AGGREGATION_DEADLINE,
            ctx.clone(),
            AggregationDeadline { session_id },
        );

        self.current_aggregation = Some(AggregationSession {
            session_id,
            early,
            cancel,
            worker,
        });
    }

    /// Early-aggregation trigger: start the slot's session ahead of the
    /// interval-2 tick when, inside the window `[T2 - EARLY_AGGREGATION_WINDOW_MS, T2)`,
    /// a single attestation-data group already holds 2/3 of the signatures
    /// expected from this node's aggregation subnets. Called after every
    /// stored gossip signature and once at the window opening via
    /// [`EarlyAggregationCheck`]. Fires at most once per slot: the started
    /// session stays in `current_aggregation` (running or finished) until the
    /// next session replaces it. The latch has one hole: if the snapshot
    /// yields no jobs (possible only when no signer's pubkey resolves, i.e. a
    /// corrupted validator registry), no session is installed and the check
    /// retries on later inserts — each retry is a no-op session attempt.
    async fn maybe_start_early_aggregation(&mut self, ctx: &Context<Self>) {
        if !self.aggregator.is_enabled() {
            return;
        }
        let genesis_time_ms = self.store.config().genesis_time * 1000;
        let Some(slot) = aggregation::early_aggregation_slot(unix_now_ms(), genesis_time_ms) else {
            return;
        };
        if self
            .current_aggregation
            .as_ref()
            .is_some_and(|session| session.session_id == slot)
        {
            return;
        }
        let max_group = self.store.max_gossip_group_count_for_slot(slot);
        let min_group_sigs = self.early_aggregation_min_group_sigs();
        if !aggregation::early_threshold_met(max_group, min_group_sigs) {
            return;
        }
        info!(
            %slot,
            max_group,
            min_group_sigs,
            "Early-aggregation threshold met"
        );
        self.start_aggregation_session(slot, ctx).await;
    }

    /// Minimum signatures in one attestation-data group that trigger early
    /// aggregation: two-thirds of one committee's expected votes,
    /// `2 * validator_count / (3 * committee_count)`. Computed on demand rather
    /// than cached; only reached inside the early-aggregation window and only
    /// until a session starts, so the `head_state` read (memoized on the
    /// stable head root) runs a handful of times per slot at most.
    fn early_aggregation_min_group_sigs(&self) -> usize {
        if self.attestation_committee_count == 0 {
            return 0;
        }
        let validator_count = self.store.head_state().validators.len() as u64;
        (2 * validator_count / (3 * self.attestation_committee_count)) as usize
    }

    /// Returns the validator ID if any of our validators is the proposer for this slot.
    fn get_our_proposer(&self, slot: u64) -> Option<u64> {
        let head_state = self.store.head_state();
        let num_validators = head_state.validators.len() as u64;

        self.key_manager
            .validator_ids()
            .into_iter()
            .find(|&vid| is_proposer(vid, slot, num_validators))
    }

    fn produce_attestations(&mut self, slot: u64, is_aggregator: bool) {
        let _timing = metrics::time_attestations_production();

        // Produce attestation data once for all validators
        let attestation_data = store::produce_attestation_data(&self.store, slot);

        // For each registered validator, produce and publish attestation
        for validator_id in self.key_manager.validator_ids() {
            // Sign the attestation
            let Ok(signature) = self
                .key_manager
                .sign_attestation(validator_id, &attestation_data)
                .inspect_err(
                    |err| error!(%slot, %validator_id, %err, "Failed to sign attestation"),
                )
            else {
                continue;
            };

            // Create signed attestation
            let signed_attestation = SignedAttestation {
                validator_id,
                data: attestation_data.clone(),
                signature,
            };

            // Self-deliver: store our own attestation locally for aggregation.
            // Gossipsub does not deliver messages back to the sender, so without
            // this the aggregator never sees its own validator's signature in
            // gossip_signatures and it is excluded from aggregated proofs.
            if is_aggregator {
                let _ = store::on_gossip_attestation(&mut self.store, &signed_attestation, true)
                    .inspect_err(|err| {
                        warn!(%slot, %validator_id, %err, "Self-delivery of attestation failed")
                    });
            }

            // Publish to gossip network
            if let Some(ref p2p) = self.p2p {
                let _ = p2p.publish_attestation(signed_attestation).inspect_err(
                    |err| error!(%slot, %validator_id, %err, "Failed to publish attestation"),
                );
                info!(%slot, %validator_id, "Published attestation");
            }
        }
    }

    /// Build the target slot's block and publish it, one interval early.
    ///
    /// Runs at the previous slot's interval 4, blocking the actor for the build
    /// (the expensive part is the leanVM single-message → multi-message
    /// aggregate merge). It first
    /// advances the store to the target slot's interval 0 (accepting
    /// attestations) so the block is built on exactly the interval-0 state a
    /// non-prebuilding proposer would see, then builds and publishes — aligned
    /// to the slot boundary: if the build finishes before the slot opens we wait
    /// out the remainder so the block is not published early; if it overran (the
    /// common case under load) we publish at once. The whole proposal is
    /// self-contained here, so it never depends on the interval-0 tick — which
    /// `handle_tick` skips whenever this build overruns its interval.
    async fn propose_block(&mut self, slot: u64, validator_id: u64) {
        info!(%slot, %validator_id, "We are the proposer for this slot");

        let genesis_time_ms = self.store.config().genesis_time * 1000;
        let slot_start_ms = genesis_time_ms + slot * MILLISECONDS_PER_SLOT;

        // Build the block. `produce_block_with_signatures` advances the store to
        // this slot's interval 0 (accepting attestations) before building — one
        // interval ahead of the interval-4 tick we are running in — so the block
        // is built on the interval-0 state rather than the previous slot's end
        // state. Building early is safe because we publish below (nothing is
        // stashed for a later tick), and the real interval-0 tick is then skipped
        // by the idempotency guard in `on_tick`, since the store clock is already
        // here.
        let timing = metrics::time_block_building();
        let Ok((block, single_message_aggregates, _post_checkpoints)) =
            store::produce_block_with_signatures(
                &mut self.store,
                slot,
                validator_id,
                self.proposer_config,
            )
            .inspect_err(|err| error!(%slot, %validator_id, %err, "Failed to build block"))
        else {
            metrics::inc_block_building_failures();
            return;
        };

        coverage::emit_proposal_coverage(
            &self.store,
            self.attestation_committee_count,
            block.body.attestations.iter(),
        );

        // Sign the block root with the proposal key
        let block_root = block.hash_tree_root();
        let Ok(proposer_signature) = self
            .key_manager
            .sign_block_root(validator_id, slot as u32, &block_root)
            .inspect_err(|err| error!(%slot, %validator_id, %err, "Failed to sign block root"))
        else {
            metrics::inc_block_building_failures();
            return;
        };

        // Wrap the proposer's raw XMSS signature into a singleton
        // single-message aggregate SNARK, then merge it with every attestation
        // single-message aggregate into the single multi-message aggregate.
        let head_state = self.store.head_state();
        let validators = &head_state.validators;
        let Some(proposer_validator) = validators.get(validator_id as usize) else {
            error!(%slot, %validator_id, "Proposer index out of range when assembling block");
            metrics::inc_block_building_failures();
            return;
        };

        // Decode the proposer's proposal pubkey once and reuse it both for the
        // singleton single-message aggregate wrap and for the multi-message
        // aggregate merge inputs.
        let Ok(proposer_pubkey) = proposer_validator.get_proposal_pubkey().inspect_err(
            |err| error!(%slot, %validator_id, %err, "Failed to decode proposer proposal pubkey"),
        ) else {
            metrics::inc_block_building_failures();
            return;
        };

        let Ok(proposer_validator_signature) =
            ValidatorSignature::from_bytes(&proposer_signature).inspect_err(|err| {
                error!(%slot, %validator_id, %err, "Failed to decode proposer signature bytes")
            })
        else {
            metrics::inc_block_building_failures();
            return;
        };
        let Ok(proposer_proof_bytes) = ethlambda_crypto::aggregate_signatures(
            vec![proposer_pubkey.clone()],
            vec![proposer_validator_signature],
            &block_root,
            slot as u32,
        )
        .inspect_err(
            |err| error!(%slot, %validator_id, %err, "Failed to wrap proposer signature as single-message aggregate"),
        ) else {
            metrics::inc_block_building_failures();
            return;
        };

        let mut merge_inputs: Vec<(Vec<ValidatorPublicKey>, ByteList512KiB)> =
            Vec::with_capacity(single_message_aggregates.len() + 1);
        let mut resolve_failed = false;
        for sma in &single_message_aggregates {
            let mut pubkeys = Vec::new();
            for vid in sma.participant_indices() {
                let Some(validator) = validators.get(vid as usize) else {
                    error!(%slot, %validator_id, vid, "Participant out of range while resolving pubkeys");
                    resolve_failed = true;
                    break;
                };
                match validator.get_attestation_pubkey() {
                    Ok(pk) => pubkeys.push(pk),
                    Err(err) => {
                        error!(%slot, %validator_id, vid, %err, "Failed to decode attestation pubkey");
                        resolve_failed = true;
                        break;
                    }
                }
            }
            if resolve_failed {
                break;
            }
            merge_inputs.push((pubkeys, sma.proof.clone()));
        }
        if resolve_failed {
            metrics::inc_block_building_failures();
            return;
        }
        merge_inputs.push((vec![proposer_pubkey], proposer_proof_bytes));

        // Merge yields raw lean-multisig type-2 bytes. Per-component
        // participants are rederived at verify time from
        // `block.body.attestations[i].aggregation_bits` plus
        // `block.proposer_index`, so nothing else needs persisting.
        let merged_bytes = match ethlambda_crypto::merge_type_1s_into_type_2(merge_inputs) {
            Ok(bytes) => bytes,
            Err(err) => {
                error!(%slot, %validator_id, %err, "Failed to merge Type-1s into Type-2");
                metrics::inc_block_building_failures();
                return;
            }
        };
        let proof = match MultiMessageAggregate::from_bytes(merged_bytes.iter().as_slice()) {
            Ok(p) => p,
            Err(err) => {
                error!(%slot, %validator_id, %err, "Failed to build multi-message aggregate");
                metrics::inc_block_building_failures();
                return;
            }
        };
        let signed_block = SignedBlock {
            message: block,
            proof,
        };

        // Stop timing here: the build is done, and the alignment wait below must
        // not count toward the block-building metric.
        drop(timing);

        info!(%slot, %validator_id, "Finished building block");

        let now_ms = unix_now_ms();

        // Align publication to the slot boundary. If the build finished before
        // the slot opened, wait out the remainder so the block is not published
        // early; if it overran, publish immediately.
        if now_ms < genesis_time_ms + slot * crate::MILLISECONDS_PER_SLOT {
            let wait_ms = slot_start_ms.saturating_sub(now_ms);
            tokio::time::sleep(Duration::from_millis(wait_ms)).await;
        }

        self.process_and_publish_block(slot, validator_id, signed_block);
    }

    /// Import a freshly built block locally, then publish it to gossip. On
    /// import failure, logs and counts it, and returns without publishing.
    fn process_and_publish_block(
        &mut self,
        slot: u64,
        validator_id: u64,
        signed_block: SignedBlock,
    ) {
        if let Err(err) = self.process_block(signed_block.clone()) {
            error!(%slot, %validator_id, %err, "Failed to process built block");
            metrics::inc_block_building_failures();
            return;
        }

        metrics::inc_block_building_success();

        if let Some(ref p2p) = self.p2p {
            let _ = p2p
                .publish_block(signed_block)
                .inspect_err(|err| error!(%slot, %validator_id, %err, "Failed to publish block"));
        }

        info!(%slot, %validator_id, "Published block");
    }

    /// Run block import and refresh metrics.
    fn process_block(&mut self, signed_block: SignedBlock) -> Result<(), StoreError> {
        store::on_block(&mut self.store, signed_block)?;
        metrics::update_head_slot(self.store.head_slot());
        metrics::update_latest_justified_slot(self.store.latest_justified().slot);
        metrics::update_latest_finalized_slot(self.store.latest_finalized().slot);
        metrics::update_validators_count(self.key_manager.validator_ids().len() as u64);

        for table in ALL_TABLES {
            metrics::update_table_bytes(table.name(), self.store.estimate_table_bytes(table));
        }
        Ok(())
    }

    /// Process a newly received block.
    fn on_block(&mut self, signed_block: SignedBlock) {
        let mut queue = VecDeque::new();
        queue.push_back(signed_block);

        // A new block can trigger a cascade of pending blocks becoming processable.
        // Here we process blocks iteratively, to avoid recursive calls that could
        // cause a stack overflow.
        while let Some(block) = queue.pop_front() {
            self.process_or_pend_block(block, &mut queue);
        }

        // Prune old states and blocks AFTER the entire cascade completes.
        // Running this mid-cascade would delete states that pending children
        // still need, causing re-processing loops when fallback pruning is active.
        self.store.prune_old_data();
    }

    /// Try to process a single block. If its parent state is missing, store it
    /// as pending. On success, collect any unblocked children into `queue` for
    /// the caller to process next (iteratively, avoiding deep recursion).
    fn process_or_pend_block(
        &mut self,
        signed_block: SignedBlock,
        queue: &mut VecDeque<SignedBlock>,
    ) {
        let slot = signed_block.message.slot;
        let block_root = signed_block.message.hash_tree_root();
        let parent_root = signed_block.message.parent_root;
        let proposer = signed_block.message.proposer_index;

        // Never process blocks at or below the finalized slot — they are
        // already part of the canonical chain and cannot affect fork choice.
        // Discard any pending children: since we won't process this block,
        // children referencing it as parent would remain stuck indefinitely.
        if slot <= self.store.latest_finalized().slot {
            self.discard_pending_subtree(block_root);
            return;
        }

        // Reject blocks whose slot has not started locally, mirroring the
        // attestation time check in `validate_attestation_data`. The disparity
        // bound is in intervals, not slots: a whole-slot margin would let an
        // adversary pre-publish next-slot blocks ahead of any honest proposer.
        // Catching this early also avoids persisting bogus future blocks to
        // RocksDB and triggering BlocksByRoot fan-out for fabricated parents.
        let block_start_interval = slot.saturating_mul(INTERVALS_PER_SLOT);
        let store_time = self.store.time();
        if block_start_interval > store_time + GOSSIP_DISPARITY_INTERVALS {
            warn!(
                %slot,
                store_time,
                proposer,
                block_root = %ShortRoot(&block_root.0),
                parent_root = %ShortRoot(&parent_root.0),
                "Rejecting block: slot is too far in future"
            );
            self.discard_pending_subtree(block_root);
            return;
        }

        // Check if parent state exists before attempting to process
        if !self.store.has_state(&parent_root) {
            info!(%slot, %parent_root, %block_root, "Block parent missing, storing as pending");

            // Resolve the actual missing ancestor by walking the chain. A stale entry
            // can occur when a cached ancestor was itself received and became pending
            // with its own missing parent — the children still point to the old value.
            let mut missing_root = parent_root;
            while let Some(&ancestor) = self.pending_block_parents.get(&missing_root) {
                missing_root = ancestor;
            }

            self.pending_block_parents.insert(block_root, missing_root);

            // Persist block data to DB (no LiveChain entry — invisible to fork choice)
            self.store
                .insert_pending_block(block_root, signed_block)
                .expect("DB insert should succeed");

            // Store only the H256 reference in memory
            self.pending_blocks
                .entry(parent_root)
                .or_default()
                .insert(block_root);

            // Walk up through DB: if missing_root is already stored from a previous
            // session, the actual missing block is further up the chain.
            // Note: this loop always terminates — blocks reference parents by hash,
            // so a cycle would require a hash collision.
            while let Some(header) = self.store.get_block_header(&missing_root) {
                if self.store.has_state(&header.parent_root) {
                    // Parent state available — enqueue for processing, cascade
                    // handles the rest via the outer loop.
                    let block = self
                        .store
                        .get_signed_block(&missing_root)
                        .expect("header and parent state exist, so the full signed block must too");
                    queue.push_back(block);
                    return;
                }
                // Block exists but parent doesn't have state — register as pending
                // so the cascade works when the true ancestor arrives
                self.pending_blocks
                    .entry(header.parent_root)
                    .or_default()
                    .insert(missing_root);
                self.pending_block_parents
                    .insert(missing_root, header.parent_root);
                missing_root = header.parent_root;
            }

            // Request the actual missing block from network
            self.request_missing_block(missing_root);
            return;
        }

        // Parent exists, proceed with processing. Clone the block so we
        // can run post-import reaggregation against its merged proof —
        // `process_block` consumes the original for the storage layer.
        let block_for_reaggregate = signed_block.clone();
        match self.process_block(signed_block) {
            Ok(()) => {
                info!(
                    %slot,
                    proposer,
                    block_root = %ShortRoot(&block_root.0),
                    parent_root = %ShortRoot(&parent_root.0),
                    "Block imported successfully"
                );

                // Recover per-attestation single-message aggregates from the
                // block's merged multi-message aggregate and fold them into the
                // local pool. Only
                // run when the chain is in sync — backfilling nodes must
                // not spam gossip with rederived aggregates.
                if self.sync_status.duties_allowed() {
                    self.run_reaggregate_from_block(&block_for_reaggregate);
                }

                // Enqueue any pending blocks that were waiting for this parent
                self.collect_pending_children(block_root, queue);
            }
            Err(err) => {
                warn!(
                    %slot,
                    proposer,
                    block_root = %ShortRoot(&block_root.0),
                    parent_root = %ShortRoot(&parent_root.0),
                    %err,
                    "Failed to process block"
                );
            }
        }
    }

    /// Run the post-import reaggregation pass and publish the resulting
    /// aggregates when this node is in the aggregator role.
    fn run_reaggregate_from_block(&mut self, signed_block: &SignedBlock) {
        let aggregates = reaggregate::reaggregate_from_block(&mut self.store, signed_block);
        if aggregates.is_empty() {
            return;
        }
        let count = aggregates.len();
        let is_aggregator = self.aggregator.is_enabled();
        info!(
            count,
            is_aggregator, "Reaggregated block-borne attestations"
        );
        if !is_aggregator {
            return;
        }
        let Some(ref p2p) = self.p2p else {
            return;
        };
        for aggregate in aggregates {
            let _ = p2p
                .publish_aggregated_attestation(aggregate)
                .inspect_err(|err| warn!(%err, "Failed to publish reaggregated attestation"));
        }
    }

    fn request_missing_block(&mut self, block_root: H256) {
        // Send request to P2P layer (deduplication handled by P2P module)
        if let Some(ref p2p) = self.p2p {
            let _ = p2p
                .fetch_block(block_root)
                .inspect(|_| info!(%block_root, "Requested missing block from network"))
                .inspect_err(
                    |err| error!(%block_root, %err, "Failed to send FetchBlock message to P2P"),
                );
        }
    }

    /// Move pending children of `parent_root` into the work queue for iterative
    /// processing. This replaces the old recursive `process_pending_children`.
    fn collect_pending_children(&mut self, parent_root: H256, queue: &mut VecDeque<SignedBlock>) {
        let Some(child_roots) = self.pending_blocks.remove(&parent_root) else {
            return;
        };

        info!(%parent_root, num_children=%child_roots.len(),
              "Processing pending blocks after parent arrival");

        for block_root in child_roots {
            // Clean up lineage tracking
            self.pending_block_parents.remove(&block_root);

            // Load block data from DB
            let Some(child_block) = self.store.get_signed_block(&block_root) else {
                warn!(
                    block_root = %ShortRoot(&block_root.0),
                    "Pending block missing from DB, skipping"
                );
                continue;
            };

            let slot = child_block.message.slot;
            trace!(%parent_root, %slot, "Processing pending child block");

            queue.push_back(child_block);
        }
    }

    /// Recursively discard a block and all its pending descendants.
    ///
    /// Used when a block is rejected (e.g., at/below finalized slot) to clean up
    /// children that would otherwise remain stuck in the pending maps indefinitely.
    fn discard_pending_subtree(&mut self, block_root: H256) {
        let Some(child_roots) = self.pending_blocks.remove(&block_root) else {
            return;
        };
        for child_root in child_roots {
            self.pending_block_parents.remove(&child_root);
            self.discard_pending_subtree(child_root);
        }
    }

    /// Publish an aggregated attestation to the aggregation gossip topic.
    fn publish_aggregate(&self, aggregate: SignedAggregatedAttestation) {
        if let Some(ref p2p) = self.p2p {
            let _ = p2p
                .publish_aggregated_attestation(aggregate)
                .inspect_err(|err| error!(%err, "Failed to publish aggregated attestation"));
        }
    }

    fn on_gossip_attestation(&mut self, attestation: &SignedAttestation) {
        // Read fresh here too: a gossip event can arrive between ticks, and
        // if the admin API just toggled, the first gossip after the toggle
        // should already use the new value.
        let is_aggregator = self.aggregator.is_enabled();
        let _ = store::on_gossip_attestation(&mut self.store, attestation, is_aggregator)
            .inspect_err(|err| warn!(%err, "Failed to process gossiped attestation"));
    }

    fn on_gossip_aggregated_attestation(&mut self, attestation: SignedAggregatedAttestation) {
        let _ = store::on_gossip_aggregated_attestation(&mut self.store, attestation)
            .inspect_err(|err| warn!(%err, "Failed to process gossiped aggregated attestation"));
    }

    fn update_sync_status(&mut self, current_slot: u64) {
        let head_slot = self.store.head_slot();
        let max_seen_slot = self.store.max_live_chain_slot().unwrap_or(head_slot);
        let status = self
            .sync_status
            .update(current_slot, head_slot, max_seen_slot);
        metrics::set_node_sync_status(status);
    }
}

// Protocol trait for internal messages only (tick scheduling).
// Network-api messages are handled via manual Handler impls to allow
// Recipient<M> to work across actor boundaries.
#[protocol]
pub(crate) trait BlockChainProtocol: Send + Sync {
    #[allow(dead_code)] // invoked via send_after(Tick), not called directly
    fn tick(&self) -> Result<(), ActorError>;
}

#[actor(protocol = BlockChainProtocol)]
impl BlockChainServer {
    #[send_handler]
    async fn handle_tick(&mut self, _msg: block_chain_protocol::Tick, ctx: &Context<Self>) {
        let now_ms = unix_now_ms();
        self.on_tick(now_ms, ctx).await;

        let genesis_time_ms = self.store.config().genesis_time * 1000;
        let remaining_at_entry = ms_until_next_interval(now_ms, genesis_time_ms);
        let now_after_tick = unix_now_ms();
        let elapsed = now_after_tick.saturating_sub(now_ms);

        // If on_tick ran past the next interval boundary, tick again
        // immediately so that interval's duty still runs (issue #413).
        let ms_to_next_interval = if elapsed >= remaining_at_entry {
            0
        } else {
            // Schedule the next tick at the next interval boundary
            ms_until_next_interval(now_after_tick, genesis_time_ms)
        };
        send_after(
            Duration::from_millis(ms_to_next_interval),
            ctx.clone(),
            block_chain_protocol::Tick,
        );
    }

    /// Actor lifecycle hook: wait for any in-flight aggregation worker to exit
    /// before the actor is fully stopped. We cancel the session's token and
    /// wait up to PRIOR_WORKER_JOIN_TIMEOUT for the worker's current
    /// `aggregate_job` call to finish (the proof itself cannot be interrupted).
    #[stopped]
    async fn on_stopped(&mut self, _ctx: &Context<Self>) {
        let Some(session) = self.current_aggregation.take() else {
            return;
        };
        session.cancel.cancel();
        match tokio::time::timeout(PRIOR_WORKER_JOIN_TIMEOUT, session.worker).await {
            Ok(Ok(())) => {
                info!(
                    session_id = session.session_id,
                    "Aggregation worker joined on shutdown"
                );
            }
            Ok(Err(err)) => warn!(?err, "Aggregation worker task ended abnormally on shutdown"),
            Err(_) => warn!(
                timeout_secs = PRIOR_WORKER_JOIN_TIMEOUT.as_secs(),
                "Timed out joining aggregation worker on shutdown"
            ),
        }
    }
}

// --- Manual Handler impls for network-api messages ---

use ethlambda_network_api::p2p_to_block_chain::{
    NewAggregatedAttestation, NewAttestation, NewBlock,
};

impl Handler<InitP2P> for BlockChainServer {
    async fn handle(&mut self, msg: InitP2P, _ctx: &Context<Self>) {
        self.p2p = Some(msg.p2p);
        info!("P2P protocol ref initialized");
    }
}

impl Handler<NewBlock> for BlockChainServer {
    async fn handle(&mut self, msg: NewBlock, _ctx: &Context<Self>) {
        self.on_block(msg.block);
    }
}

impl Handler<NewAttestation> for BlockChainServer {
    async fn handle(&mut self, msg: NewAttestation, ctx: &Context<Self>) {
        self.on_gossip_attestation(&msg.attestation);
        self.maybe_start_early_aggregation(ctx).await;
    }
}

impl Handler<NewAggregatedAttestation> for BlockChainServer {
    async fn handle(&mut self, msg: NewAggregatedAttestation, _ctx: &Context<Self>) {
        self.on_gossip_aggregated_attestation(msg.attestation);
    }
}

// -------------------------------------------------------------------------
// Aggregation message handlers (worker → actor, actor → self for deadline)
// -------------------------------------------------------------------------

impl Handler<AggregateProduced> for BlockChainServer {
    async fn handle(&mut self, msg: AggregateProduced, _ctx: &Context<Self>) {
        // Drop results from a prior session (or from an unexpected late worker).
        // Current session may be None if the actor already cleaned it up; accept
        // the message only when ids match.
        let current = self.current_aggregation.as_ref().map(|s| s.session_id);
        if current != Some(msg.session_id) {
            trace!(
                incoming_session_id = msg.session_id,
                current_session_id = ?current,
                "Dropping stale aggregate produced for non-current session"
            );
            return;
        }

        // Publish alignment is enforced upstream: the worker delays delivery of
        // this message until the interval-2 boundary, so by the time it lands
        // the aggregate is safe to apply and gossip immediately.
        aggregation::apply_aggregated_group(&mut self.store, &msg.output);

        let aggregate = SignedAggregatedAttestation {
            data: msg.output.hashed.data().clone(),
            proof: msg.output.proof,
        };
        self.publish_aggregate(aggregate);
    }
}

impl Handler<EarlyAggregationCheck> for BlockChainServer {
    async fn handle(&mut self, _msg: EarlyAggregationCheck, ctx: &Context<Self>) {
        self.maybe_start_early_aggregation(ctx).await;
    }
}

impl Handler<AggregationDone> for BlockChainServer {
    async fn handle(&mut self, msg: AggregationDone, _ctx: &Context<Self>) {
        aggregation::finalize_aggregation_session(&self.store);
        metrics::observe_committee_signatures_aggregation(msg.total_elapsed);

        let aggregation_elapsed = msg.total_elapsed;
        let early = self
            .current_aggregation
            .as_ref()
            .is_some_and(|s| s.session_id == msg.session_id && s.early);
        info!(
            ?aggregation_elapsed,
            session_id = msg.session_id,
            groups_considered = msg.groups_considered,
            groups_aggregated = msg.groups_aggregated,
            total_raw_sigs = msg.total_raw_sigs,
            total_children = msg.total_children,
            cancelled = msg.cancelled,
            early,
            aggregation_deadline_ms = AGGREGATION_DEADLINE.as_millis() as u64,
            "Committee signatures aggregated"
        );
    }
}

impl Handler<AggregationDeadline> for BlockChainServer {
    async fn handle(&mut self, msg: AggregationDeadline, _ctx: &Context<Self>) {
        if let Some(session) = &self.current_aggregation
            && session.session_id == msg.session_id
        {
            session.cancel.cancel();
        }
    }
}
