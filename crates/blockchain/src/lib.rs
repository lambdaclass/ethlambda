use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant, SystemTime};

use ethlambda_network_api::{BlockChainToP2PRef, InitP2P};
use ethlambda_state_transition::is_proposer;
use ethlambda_storage::{ALL_TABLES, Store};
use ethlambda_types::{
    ShortRoot,
    attestation::{SignedAggregatedAttestation, SignedAttestation},
    block::{BlockSignatures, SignedBlock},
    primitives::{H256, HashTreeRoot as _},
};

use crate::key_manager::ValidatorKeyPair;
use crate::store::{AggregatedGroupOutput, AggregationSnapshot};
use spawned_concurrency::actor;
use spawned_concurrency::error::ActorError;
use spawned_concurrency::message::Message;
use spawned_concurrency::protocol;
use spawned_concurrency::tasks::{Actor, ActorRef, ActorStart, Context, Handler, send_after};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, trace, warn};

use crate::store::StoreError;

/// Soft deadline for committee-signature aggregation measured from the
/// interval-2 tick. After this much wall time elapses, the actor signals the
/// worker to stop via its cancellation token. The 50 ms budget before the next
/// interval (interval 3 at +800 ms) is reserved for publishing any late-arriving
/// aggregates and for gossip propagation margin.
const AGGREGATION_DEADLINE: Duration = Duration::from_millis(750);
/// Upper bound we wait for a prior worker to exit if it is still running when
/// the next session is about to start. Reached only in pathological cases
/// (mismatched timers, stuck proofs); we warn before blocking.
const PRIOR_WORKER_JOIN_TIMEOUT: Duration = Duration::from_secs(2);

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

impl BlockChain {
    pub fn spawn(
        store: Store,
        validator_keys: HashMap<u64, ValidatorKeyPair>,
        is_aggregator: bool,
    ) -> BlockChain {
        metrics::set_is_aggregator(is_aggregator);
        metrics::set_node_sync_status(metrics::SyncStatus::Idle);
        let genesis_time = store.config().genesis_time;
        let key_manager = key_manager::KeyManager::new(validator_keys);
        let handle = BlockChainServer {
            store,
            p2p: None,
            key_manager,
            pending_blocks: HashMap::new(),
            is_aggregator,
            pending_block_parents: HashMap::new(),
            current_aggregation: None,
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
    is_aggregator: bool,

    /// In-flight committee-signature aggregation, if any. Present only while a
    /// worker started at the most recent interval 2 is still running or until
    /// the next interval 2 takes over.
    current_aggregation: Option<AggregationSession>,
}

/// Tracks an in-flight off-thread aggregation worker so the actor can cancel,
/// join, and correlate incoming result messages with the right session.
struct AggregationSession {
    /// Slot at which this session was started; used as a fencing id so we can
    /// drop late-arriving messages from a prior session.
    session_id: u64,
    /// Child of the actor cancellation token; fires either at the deadline or
    /// when the actor itself is stopping.
    cancel: CancellationToken,
    /// Handle to the `spawn_blocking` worker. Held so `stopped()` / new-session
    /// start can await completion.
    worker: tokio::task::JoinHandle<()>,
    /// Kept alive so the timer is implicitly cancelled when the field is
    /// replaced or the actor stops (see `spawned_concurrency::tasks::time`).
    _deadline_timer: spawned_concurrency::tasks::TimerHandle,
}

/// One successful aggregate streamed back from the worker.
pub(crate) struct AggregateProduced {
    session_id: u64,
    output: AggregatedGroupOutput,
}
impl Message for AggregateProduced {
    type Result = ();
}

/// Emitted by the worker after its loop exits (completion or cancellation).
pub(crate) struct AggregationDone {
    session_id: u64,
    groups_considered: usize,
    groups_aggregated: usize,
    total_raw_sigs: usize,
    total_children: usize,
    total_elapsed: Duration,
    cancelled: bool,
}
impl Message for AggregationDone {
    type Result = ();
}

/// Self-message scheduled via `send_after` at interval-2 start. Cancels the
/// session's token so the worker stops starting new aggregations.
pub(crate) struct AggregationDeadline {
    session_id: u64,
}
impl Message for AggregationDeadline {
    type Result = ();
}

impl BlockChainServer {
    async fn on_tick(&mut self, timestamp_ms: u64, ctx: &Context<Self>) {
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

        if interval == 2 && self.is_aggregator {
            self.start_aggregation_session(slot, ctx).await;
        }

        // Now build and publish the block (after attestations have been accepted)
        if let Some(validator_id) = proposer_validator_id {
            self.propose_block(slot, validator_id);
        }

        // Produce attestations at interval 1 (all validators including proposer)
        if interval == 1 {
            self.produce_attestations(slot);
        }

        // Update safe target slot metric (updated by store.on_tick at interval 3)
        metrics::update_safe_target_slot(self.store.safe_target_slot());
        // Update head slot metric (head may change when attestations are promoted at intervals 0/4)
        metrics::update_head_slot(self.store.head_slot());
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

        let Some(snapshot) = store::snapshot_aggregation_inputs(&self.store) else {
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

        let deadline_timer = send_after(
            AGGREGATION_DEADLINE,
            ctx.clone(),
            AggregationDeadline { session_id },
        );

        self.current_aggregation = Some(AggregationSession {
            session_id,
            cancel,
            worker,
            _deadline_timer: deadline_timer,
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

    fn produce_attestations(&mut self, slot: u64) {
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
            if self.is_aggregator {
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
    fn propose_block(&mut self, slot: u64, validator_id: u64) {
        info!(%slot, %validator_id, "We are the proposer for this slot");

        let _timing = metrics::time_block_building();

        // Build the block with attestation signatures
        let Ok((block, attestation_signatures, _post_checkpoints)) =
            store::produce_block_with_signatures(&mut self.store, slot, validator_id)
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
        let _ = store::on_gossip_attestation(&mut self.store, attestation, self.is_aggregator)
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

        store::apply_aggregated_group(&mut self.store, &msg.output);

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
        store::finalize_aggregation_session(&self.store);
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

// -------------------------------------------------------------------------
// Worker loop — runs on a `spawn_blocking` thread, no store access.
// -------------------------------------------------------------------------

fn run_aggregation_worker(
    snapshot: AggregationSnapshot,
    actor: ActorRef<BlockChainServer>,
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

        let job_raw_sigs = job.raw_ids.len();
        let job_children = job.children.len();

        let Some(output) = store::aggregate_job(job) else {
            continue;
        };

        groups_aggregated += 1;
        total_raw_sigs += job_raw_sigs;
        total_children += job_children;

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
