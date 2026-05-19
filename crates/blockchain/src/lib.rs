use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant, SystemTime};

use ethlambda_ethrex_client::{
    EngineClient, ForkChoiceState, PayloadAttributesV3, PayloadId, PayloadStatusKind,
};
use ethlambda_network_api::{BlockChainToP2PRef, InitP2P};
use ethlambda_state_transition::{SECONDS_PER_SLOT, is_proposer};
use ethlambda_storage::{ALL_TABLES, Store};
use ethlambda_types::{
    ShortRoot,
    aggregator::AggregatorController,
    attestation::{SignedAggregatedAttestation, SignedAttestation},
    block::{BlockSignatures, SignedBlock},
    execution_payload::ExecutionPayloadV3,
    primitives::{H256, HashTreeRoot as _},
};

use crate::aggregation::{
    AGGREGATION_DEADLINE, AggregateProduced, AggregationDeadline, AggregationDone,
    AggregationSession, PRIOR_WORKER_JOIN_TIMEOUT, run_aggregation_worker,
};
use crate::key_manager::ValidatorKeyPair;
use spawned_concurrency::actor;
use spawned_concurrency::error::ActorError;
use spawned_concurrency::protocol;
use spawned_concurrency::tasks::{Actor, ActorRef, ActorStart, Context, Handler, send_after};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, trace, warn};

use crate::store::StoreError;

pub mod aggregation;
pub(crate) mod fork_choice_tree;
pub mod key_manager;
pub mod metrics;
pub mod store;

pub struct BlockChain {
    handle: ActorRef<BlockChainServer>,
}

/// Milliseconds per interval (800ms ticks).
pub const MILLISECONDS_PER_INTERVAL: u64 = 800;
/// Number of intervals per slot (5 intervals of 800ms = 4 seconds).
pub const INTERVALS_PER_SLOT: u64 = 5;
/// Milliseconds in a slot (derived from interval duration and count).
pub const MILLISECONDS_PER_SLOT: u64 = MILLISECONDS_PER_INTERVAL * INTERVALS_PER_SLOT;
/// Maximum number of distinct AttestationData entries per block.
///
/// See: leanSpec commit 0c9528a (PR #536).
pub const MAX_ATTESTATIONS_DATA: usize = 16;
/// Future-slot tolerance for gossip attestations, expressed in intervals.
///
/// Bounds the clock skew the time check is willing to absorb when admitting a
/// vote whose slot has not yet started locally. One interval is roughly 800 ms,
/// the lean analogue of mainnet's `MAXIMUM_GOSSIP_CLOCK_DISPARITY`.
///
/// See: leanSpec PR #682.
pub const GOSSIP_DISPARITY_INTERVALS: u64 = 1;

impl BlockChain {
    pub fn spawn(
        store: Store,
        validator_keys: HashMap<u64, ValidatorKeyPair>,
        aggregator: AggregatorController,
        execution_client: Option<EngineClient>,
    ) -> BlockChain {
        metrics::set_is_aggregator(aggregator.is_enabled());
        metrics::set_node_sync_status(metrics::SyncStatus::Idle);
        let genesis_time = store.config().genesis_time;
        let key_manager = key_manager::KeyManager::new(validator_keys);
        let handle = BlockChainServer {
            store,
            p2p: None,
            key_manager,
            pending_blocks: HashMap::new(),
            aggregator,
            pending_block_parents: HashMap::new(),
            current_aggregation: None,
            last_tick_instant: None,
            execution_client,
            pending_payload_id: None,
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

    /// In-flight committee-signature aggregation, if any. Present only while a
    /// worker started at the most recent interval 2 is still running or until
    /// the next interval 2 takes over.
    current_aggregation: Option<AggregationSession>,

    /// Last tick instant for measuring interval duration.
    last_tick_instant: Option<Instant>,

    /// Optional Engine API client to the execution layer (e.g. ethrex).
    ///
    /// Present only when ethlambda was started with `--execution-endpoint`
    /// and `--execution-jwt-secret`. When set, the actor fires
    /// `engine_forkchoiceUpdatedV3` at the start of each slot to keep the EL
    /// informed of our head/justified/finalized. The schema is currently
    /// scaffolding only — Lean blocks do not yet carry execution payloads,
    /// so the EL responds `SYNCING` against zeros until a real payload
    /// pipeline is wired (see docs/plans/engine-api-integration.md).
    execution_client: Option<EngineClient>,

    /// `(target_slot, payload_id)` returned by the EL after a build-mode
    /// FCU at interval 4 of the previous slot. Consumed at interval 0 by
    /// `take_prepared_payload`. Absent when no EL is configured, when we
    /// didn't queue a build for this slot, or when the EL was syncing and
    /// returned `payload_id = None`.
    pending_payload_id: Option<(u64, PayloadId)>,
}

impl BlockChainServer {
    async fn on_tick(&mut self, timestamp_ms: u64, ctx: &Context<Self>) {
        // Observe tick interval duration before any processing
        if let Some(prev_instant) = self.last_tick_instant {
            metrics::observe_tick_interval_duration(prev_instant.elapsed());
        }
        self.last_tick_instant = Some(Instant::now());

        let genesis_time_ms = self.store.config().genesis_time * 1000;

        // Calculate current slot and interval from milliseconds
        let time_since_genesis_ms = timestamp_ms.saturating_sub(genesis_time_ms);
        let slot = time_since_genesis_ms / MILLISECONDS_PER_SLOT;
        let interval = (time_since_genesis_ms % MILLISECONDS_PER_SLOT) / MILLISECONDS_PER_INTERVAL;

        // Fail fast: a state with zero validators is invalid and would cause
        // panics in proposer selection and attestation processing.
        if self.store.head_state().validators.is_empty() {
            error!("Head state has no validators, skipping tick");
            return;
        }

        // Update current slot metric
        metrics::update_current_slot(slot);

        // Snapshot the aggregator flag once per tick so all read sites within
        // the tick see a consistent value even if the admin API toggles it
        // mid-tick. Mirror it to the gauge from the actor side so
        // `lean_is_aggregator` reflects the value the actor is acting on.
        let is_aggregator = self.aggregator.is_enabled();
        metrics::set_is_aggregator(is_aggregator);

        // At interval 0, check if we will propose (but don't build the block yet).
        // Tick forkchoice first to accept attestations, then build the block
        // using the freshly-accepted attestations.
        let proposer_validator_id = (interval == 0 && slot > 0)
            .then(|| self.get_our_proposer(slot))
            .flatten();

        // Tick the store first - this accepts attestations at interval 0 if we have a proposal
        store::on_tick(
            &mut self.store,
            timestamp_ms,
            proposer_validator_id.is_some(),
        );

        if interval == 2 && is_aggregator {
            self.start_aggregation_session(slot, ctx).await;
        }

        // Now build and publish the block (after attestations have been accepted)
        if let Some(validator_id) = proposer_validator_id {
            // Phase 4 (M6): try to pick up a payload the EL has been building
            // since interval 4 of the previous slot. None when no EL is
            // configured, when no build was queued, or when the EL was
            // syncing. `build_block` falls back to `synthetic_payload`.
            let payload = self.take_prepared_payload(slot).await;
            self.propose_block(slot, validator_id, payload);
        }

        // Produce attestations at interval 1 (all validators including proposer).
        // Reuse the same snapshot so self-delivery decisions match the rest
        // of the tick.
        if interval == 1 {
            self.produce_attestations(slot, is_aggregator);
        }

        // Phase 4 (M6): at the end of this slot, if any of our validators
        // is the next-slot proposer, ask the EL to start building a payload
        // we'll fetch at interval 0 of slot+1.
        if interval == 4 {
            self.request_payload_id_for_next_slot(slot).await;
        }

        // Update safe target slot metric (updated by store.on_tick at interval 3)
        metrics::update_safe_target_slot(self.store.safe_target_slot());
        // Update head slot metric (head may change when attestations are promoted at intervals 0/4)
        metrics::update_head_slot(self.store.head_slot());

        // Notify the execution layer once per slot (interval 0). Fire and
        // forget: the EL is informational here, never on the consensus
        // critical path. The hashes carried are `block_hash` fields read
        // off the head/safe/finalized Lean blocks' `execution_payload`s
        // (Phase 5 of M6), so the EL can chain forward off blocks it has
        // actually seen via `engine_newPayloadV4`.
        if interval == 0 && self.execution_client.is_some() {
            self.notify_execution_layer();
        }
    }

    /// Send a forkchoice update to the execution layer via
    /// `engine_forkchoiceUpdatedV3` carrying the current head/safe/finalized
    /// EL block hashes (read from the corresponding Lean blocks'
    /// `execution_payload.block_hash`). Errors are logged but never
    /// propagated — the consensus loop must continue regardless of EL state.
    ///
    /// At genesis every triplet entry is `H256::ZERO` because the genesis
    /// `BlockBody::default()` carries an `ExecutionPayloadV3::default()`
    /// whose `block_hash` is zero. Subsequent slots advance once a real
    /// payload (from `engine_getPayloadV3`) has been imported.
    fn notify_execution_layer(&self) {
        let Some(client) = self.execution_client.as_ref() else {
            return;
        };
        let state = self.current_el_forkchoice_state();
        let client = client.clone();
        tokio::spawn(async move {
            match client.forkchoice_updated_v3(state, None).await {
                Ok(resp) => trace!(
                    status = ?resp.payload_status.status,
                    "engine_forkchoiceUpdatedV3 ok"
                ),
                Err(err) => warn!(%err, "engine_forkchoiceUpdatedV3 failed"),
            }
        });
    }

    /// Compute the `ForkChoiceState` the EL should see right now: head/safe/
    /// finalized resolved from Lean roots to the corresponding execution
    /// payload `block_hash`es via `el_hash_at`. Shared by the per-slot
    /// notification (`notify_execution_layer`) and the build-mode
    /// `request_payload_id_for_next_slot`, so the EL sees the same view
    /// regardless of which call hits first.
    fn current_el_forkchoice_state(&self) -> ForkChoiceState {
        ForkChoiceState {
            head_block_hash: self.el_hash_at(self.store.head()),
            safe_block_hash: self.el_hash_at(self.store.safe_target()),
            finalized_block_hash: self.el_hash_at(self.store.latest_finalized().root),
        }
    }

    /// Resolve a Lean block root to its execution payload's `block_hash`.
    ///
    /// `H256::ZERO` fallback applies when:
    ///   * `lean_root` is itself zero (uninitialized head)
    ///   * the block is missing from storage (defensive — head/safe/
    ///     finalized are always present, but a torn write or pruning bug
    ///     shouldn't crash the EL notifier)
    ///
    /// At genesis the payload is `ExecutionPayloadV3::default()`, so its
    /// `block_hash` is `H256::ZERO` and the result naturally rolls back
    /// to the same sentinel.
    fn el_hash_at(&self, lean_root: H256) -> H256 {
        if lean_root.is_zero() {
            return H256::ZERO;
        }
        self.store
            .get_block(&lean_root)
            .map(|block| block.body.execution_payload.block_hash)
            .unwrap_or(H256::ZERO)
    }

    /// At interval 4 of slot N-1, ask the EL to start building a payload
    /// for slot N if any of our validators is the slot-N proposer.
    ///
    /// Fires a build-mode `engine_forkchoiceUpdatedV3` carrying the same
    /// real head/safe/finalized triplet `notify_execution_layer` uses,
    /// plus `PayloadAttributesV3` with the correct slot timestamp. If the
    /// EL returns a `payload_id`, we stash it for `take_prepared_payload`
    /// to consume at interval 0 of slot N. When the EL is syncing it
    /// returns `payload_id = None` and we silently fall back to the
    /// synthetic payload path.
    ///
    /// `suggested_fee_recipient` and `prev_randao` are zero for now; refine
    /// when CLI / config support lands.
    async fn request_payload_id_for_next_slot(&mut self, current_slot: u64) {
        let Some(client) = self.execution_client.as_ref() else {
            return;
        };
        let next_slot = current_slot + 1;
        if self.get_our_proposer(next_slot).is_none() {
            return;
        }

        let state = self.current_el_forkchoice_state();
        let attrs = PayloadAttributesV3 {
            timestamp: self.store.config().genesis_time + next_slot * SECONDS_PER_SLOT,
            prev_randao: H256::ZERO,
            suggested_fee_recipient: [0u8; 20],
            withdrawals: vec![],
            parent_beacon_block_root: H256::ZERO,
        };
        let client = client.clone();
        match client.forkchoice_updated_v3(state, Some(attrs)).await {
            Ok(resp) => {
                if let Some(id) = resp.payload_id {
                    self.pending_payload_id = Some((next_slot, id));
                    trace!(
                        slot = next_slot,
                        status = ?resp.payload_status.status,
                        "Queued EL payload build for next slot",
                    );
                } else {
                    trace!(
                        slot = next_slot,
                        status = ?resp.payload_status.status,
                        "EL declined to start build (syncing or unknown head)",
                    );
                }
            }
            Err(err) => {
                warn!(slot = next_slot, %err, "engine_forkchoiceUpdatedV3 (build mode) failed");
            }
        }
    }

    /// At interval 0 of slot N, consume the `payload_id` stashed by
    /// `request_payload_id_for_next_slot` and fetch the now-built payload.
    ///
    /// Returns `None` (caller falls back to synthetic) on any of:
    ///   * no EL configured
    ///   * no stashed id (we weren't expecting to propose this slot, or
    ///     the build request was rejected at interval 4)
    ///   * stashed id is for a different slot (we missed a tick)
    ///   * the `engine_getPayloadV3` roundtrip failed
    async fn take_prepared_payload(&mut self, slot: u64) -> Option<ExecutionPayloadV3> {
        let client = self.execution_client.as_ref()?.clone();
        let (stashed_slot, payload_id) = self.pending_payload_id.take()?;
        if stashed_slot != slot {
            warn!(
                stashed_slot,
                slot, "Stashed payload_id doesn't match this slot; discarding"
            );
            return None;
        }
        match client.get_payload_v3(payload_id).await {
            Ok(payload) => {
                trace!(slot, "Fetched execution payload from EL");
                Some(payload)
            }
            Err(err) => {
                warn!(slot, %err, "engine_getPayloadV3 failed; falling back to synthetic payload");
                None
            }
        }
    }

    /// Submit a received block's execution payload to the EL for validation.
    ///
    /// Returns `true` when the block should proceed to fork-choice insertion
    /// (no EL configured, EL says VALID/SYNCING/ACCEPTED, or the EL roundtrip
    /// itself failed). Returns `false` only on the explicit `INVALID` /
    /// `INVALID_BLOCK_HASH` verdicts — those mean the EL claims the payload
    /// is unexecutable on its own chain, so importing the block would be
    /// pointless.
    ///
    /// Network errors and unparseable responses are permissive — same policy
    /// as `notify_execution_layer`: consensus must keep running regardless
    /// of EL state. Operators are expected to monitor the warn logs.
    async fn validate_payload_with_el(&self, payload: &ExecutionPayloadV3) -> bool {
        let Some(client) = self.execution_client.as_ref() else {
            return true;
        };
        // Prague-era V4: same payload shape as V3 plus an
        // `executionRequests` parameter for EIP-7685 system contract
        // operations. Lean blocks don't produce system requests yet, blob
        // transactions, or beacon parent roots, so all three trailing args
        // are empty/zero placeholders. Refine when those land.
        let result = client
            .new_payload_v4(payload.clone(), vec![], H256::ZERO, vec![])
            .await;
        match result {
            Ok(status) => match status.status {
                PayloadStatusKind::Valid
                | PayloadStatusKind::Syncing
                | PayloadStatusKind::Accepted => {
                    trace!(status = ?status.status, "engine_newPayloadV4 ok");
                    true
                }
                PayloadStatusKind::Invalid | PayloadStatusKind::InvalidBlockHash => {
                    warn!(
                        status = ?status.status,
                        error = ?status.validation_error,
                        "engine_newPayloadV4 rejected payload; dropping block"
                    );
                    false
                }
            },
            Err(err) => {
                warn!(%err, "engine_newPayloadV4 transport failure; accepting block");
                true
            }
        }
    }

    /// Kick off a committee-signature aggregation session:
    /// 1. If a prior session is still running (pathological), warn and join it.
    /// 2. Snapshot the aggregation inputs from the store.
    /// 3. Spawn a `spawn_blocking` worker that streams results back as messages.
    /// 4. Schedule the `AggregationDeadline` self-message at +750 ms.
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

        let Some(snapshot) = aggregation::snapshot_aggregation_inputs(&self.store) else {
            // No gossip sigs and no pending payloads — nothing to aggregate this slot.
            return;
        };

        let session_id = slot;
        // Independent token per session. Shutdown propagates via our
        // #[stopped] hook which cancels any current session; the deadline
        // timer cancels this specific session at +AGGREGATION_DEADLINE.
        let cancel = CancellationToken::new();
        let actor_ref = ctx.actor_ref();

        let worker_cancel = cancel.clone();
        let worker_actor = actor_ref.clone();
        let worker = tokio::task::spawn_blocking(move || {
            run_aggregation_worker(snapshot, worker_actor, worker_cancel, session_id);
        });

        let _deadline_timer = send_after(
            AGGREGATION_DEADLINE,
            ctx.clone(),
            AggregationDeadline { session_id },
        );

        self.current_aggregation = Some(AggregationSession {
            session_id,
            cancel,
            worker,
        });
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

    /// Build and publish a block for the given slot and validator.
    fn propose_block(
        &mut self,
        slot: u64,
        validator_id: u64,
        execution_payload: Option<ExecutionPayloadV3>,
    ) {
        info!(%slot, %validator_id, "We are the proposer for this slot");

        let _timing = metrics::time_block_building();

        // Build the block with attestation signatures
        let Ok((block, attestation_signatures, _post_checkpoints)) =
            store::produce_block_with_signatures(
                &mut self.store,
                slot,
                validator_id,
                execution_payload,
            )
            .inspect_err(|err| error!(%slot, %validator_id, %err, "Failed to build block"))
        else {
            metrics::inc_block_building_failures();
            return;
        };

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

        // Assemble SignedBlock
        let signed_block = SignedBlock {
            message: block,
            signature: BlockSignatures {
                proposer_signature,
                attestation_signatures: attestation_signatures
                    .try_into()
                    .expect("attestation signatures within limit"),
            },
        };

        // Process the block locally before publishing
        if let Err(err) = self.process_block(signed_block.clone()) {
            error!(%slot, %validator_id, %err, "Failed to process built block");
            metrics::inc_block_building_failures();
            return;
        };

        metrics::inc_block_building_success();

        // Inform the EL of our own freshly-built block (M6 phase 5 follow-up).
        //
        // `engine_getPayloadV3` produced the embedded payload as a *candidate*;
        // the EL doesn't promote it to a real imported block until something
        // calls `engine_newPayloadV4`. For received blocks that's the import
        // pre-check in `Handler<NewBlock>`, but for our own builds nobody
        // gossips it back to us — without this call the EL stays at genesis
        // and rejects every subsequent FCU `head_block_hash`.
        //
        // Fire-and-forget; the EL roundtrip is ~ms but the next FCU is 4s
        // away. If the EL says INVALID we log it but don't reverse — process_block
        // already accepted into the store and the block is on its way to gossip.
        if let Some(client) = self.execution_client.as_ref() {
            let payload = signed_block.message.body.execution_payload.clone();
            let client = client.clone();
            tokio::spawn(async move {
                match client
                    .new_payload_v4(payload, vec![], H256::ZERO, vec![])
                    .await
                {
                    Ok(status) => trace!(
                        status = ?status.status,
                        "engine_newPayloadV4 on own-built block"
                    ),
                    Err(err) => warn!(%err, "engine_newPayloadV4 on own-built block failed"),
                }
            });
        }

        // Publish to gossip network
        if let Some(ref p2p) = self.p2p {
            let _ = p2p
                .publish_block(signed_block)
                .inspect_err(|err| error!(%slot, %validator_id, %err, "Failed to publish block"));
        }

        info!(%slot, %validator_id, "Published block");
    }

    fn process_block(&mut self, signed_block: SignedBlock) -> Result<(), StoreError> {
        store::on_block(&mut self.store, signed_block)?;
        let head_slot = self.store.head_slot();
        metrics::update_head_slot(head_slot);
        metrics::update_latest_justified_slot(self.store.latest_justified().slot);
        metrics::update_latest_finalized_slot(self.store.latest_finalized().slot);
        metrics::update_validators_count(self.key_manager.validator_ids().len() as u64);

        // Update sync status based on head slot vs wall clock slot
        let current_slot = self.store.time() / INTERVALS_PER_SLOT;
        let status = if head_slot >= current_slot {
            metrics::SyncStatus::Synced
        } else {
            metrics::SyncStatus::Syncing
        };
        metrics::set_node_sync_status(status);

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
            self.store.insert_pending_block(block_root, signed_block);

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

        // Parent exists, proceed with processing
        match self.process_block(signed_block) {
            Ok(_) => {
                info!(
                    %slot,
                    proposer,
                    block_root = %ShortRoot(&block_root.0),
                    parent_root = %ShortRoot(&parent_root.0),
                    "Block imported successfully"
                );

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
        let timestamp = SystemTime::UNIX_EPOCH
            .elapsed()
            .expect("already past the unix epoch");
        self.on_tick(timestamp.as_millis() as u64, ctx).await;
        // Schedule the next tick at the next 800ms interval boundary
        let ms_since_epoch = timestamp.as_millis() as u64;
        let ms_to_next_interval =
            MILLISECONDS_PER_INTERVAL - (ms_since_epoch % MILLISECONDS_PER_INTERVAL);
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
        // EL pre-check (Phase 3 of M6). When `--execution-endpoint` is
        // unset this is a no-op. INVALID verdict drops the block before it
        // touches the store; pending children referencing it as parent are
        // not enqueued because we never call `on_block`. They will be
        // pruned by the standard slot-bound timeout.
        let payload = &msg.block.message.body.execution_payload;
        if !self.validate_payload_with_el(payload).await {
            return;
        }
        self.on_block(msg.block);
    }
}

impl Handler<NewAttestation> for BlockChainServer {
    async fn handle(&mut self, msg: NewAttestation, _ctx: &Context<Self>) {
        self.on_gossip_attestation(&msg.attestation);
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

        aggregation::apply_aggregated_group(&mut self.store, &msg.output);

        if let Some(ref p2p) = self.p2p {
            let aggregate = SignedAggregatedAttestation {
                data: msg.output.hashed.data().clone(),
                proof: msg.output.proof,
            };
            let _ = p2p
                .publish_aggregated_attestation(aggregate)
                .inspect_err(|err| error!(%err, "Failed to publish aggregated attestation"));
        }
    }
}

impl Handler<AggregationDone> for BlockChainServer {
    async fn handle(&mut self, msg: AggregationDone, _ctx: &Context<Self>) {
        aggregation::finalize_aggregation_session(&self.store);
        metrics::observe_committee_signatures_aggregation(msg.total_elapsed);

        let aggregation_elapsed = msg.total_elapsed;
        info!(
            ?aggregation_elapsed,
            session_id = msg.session_id,
            groups_considered = msg.groups_considered,
            groups_aggregated = msg.groups_aggregated,
            total_raw_sigs = msg.total_raw_sigs,
            total_children = msg.total_children,
            cancelled = msg.cancelled,
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
