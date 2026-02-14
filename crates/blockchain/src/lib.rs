use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, SystemTime};

use ethlambda_state_transition::is_proposer;
use ethlambda_storage::Store;
use ethlambda_types::{
    ShortRoot,
    attestation::{Attestation, AttestationData, SignedAggregatedAttestation, SignedAttestation},
    block::{BlockSignatures, BlockWithAttestation, SignedBlockWithAttestation},
    primitives::{H256, ssz::TreeHash},
    signature::ValidatorSecretKey,
    state::Checkpoint,
};
use spawned_concurrency::tasks::{
    CallResponse, CastResponse, GenServer, GenServerHandle, send_after,
};
use tokio::sync::mpsc;
use tracing::{error, info, trace, warn};

use crate::store::StoreError;

pub mod key_manager;
pub mod metrics;
pub mod store;

/// Messages sent from the blockchain to the P2P layer.
#[derive(Clone, Debug)]
pub enum P2PMessage {
    /// Publish an attestation to the gossip network.
    PublishAttestation(SignedAttestation),
    /// Publish a block to the gossip network.
    PublishBlock(SignedBlockWithAttestation),
    /// Publish an aggregated attestation to the gossip network.
    PublishAggregatedAttestation(SignedAggregatedAttestation),
    /// Fetch a block by its root hash.
    FetchBlock(H256),
}

pub struct BlockChain {
    handle: GenServerHandle<BlockChainServer>,
}

/// Seconds in a slot.
pub const SECONDS_PER_SLOT: u64 = 4;
/// Milliseconds in a slot.
pub const MILLISECONDS_PER_SLOT: u64 = 4_000;
/// Milliseconds per interval (800ms ticks).
pub const MILLISECONDS_PER_INTERVAL: u64 = 800;
/// Number of intervals per slot (5 intervals of 800ms = 4 seconds).
pub const INTERVALS_PER_SLOT: u64 = 5;
/// Number of attestation committees per slot.
pub const ATTESTATION_COMMITTEE_COUNT: u64 = 1;

impl BlockChain {
    pub fn spawn(
        store: Store,
        p2p_tx: mpsc::UnboundedSender<P2PMessage>,
        validator_keys: HashMap<u64, ValidatorSecretKey>,
        is_aggregator: bool,
    ) -> BlockChain {
        let genesis_time = store.config().genesis_time;
        let key_manager = key_manager::KeyManager::new(validator_keys);
        let handle = BlockChainServer {
            store,
            p2p_tx,
            key_manager,
            pending_blocks: HashMap::new(),
            is_aggregator,
            pending_block_parents: HashMap::new(),
        }
        .start();
        let time_until_genesis = (SystemTime::UNIX_EPOCH + Duration::from_secs(genesis_time))
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        send_after(time_until_genesis, handle.clone(), CastMessage::Tick);
        BlockChain { handle }
    }

    /// Sends a block to the BlockChain for processing.
    ///
    /// Note that this is *NOT* `async`, since the internal [`GenServerHandle::cast`] is non-blocking.
    pub async fn notify_new_block(&mut self, block: SignedBlockWithAttestation) {
        let _ = self
            .handle
            .cast(CastMessage::NewBlock(block))
            .await
            .inspect_err(|err| error!(%err, "Failed to notify BlockChain of new block"));
    }

    /// Sends an attestation to the BlockChain for processing.
    ///
    /// Note that this is *NOT* `async`, since the internal [`GenServerHandle::cast`] is non-blocking.
    pub async fn notify_new_attestation(&mut self, attestation: SignedAttestation) {
        let _ = self
            .handle
            .cast(CastMessage::NewAttestation(attestation))
            .await
            .inspect_err(|err| error!(%err, "Failed to notify BlockChain of new attestation"));
    }

    /// Sends an aggregated attestation to the BlockChain for processing.
    pub async fn notify_new_aggregated_attestation(
        &mut self,
        attestation: SignedAggregatedAttestation,
    ) {
        let _ = self
            .handle
            .cast(CastMessage::NewAggregatedAttestation(attestation))
            .await
            .inspect_err(
                |err| error!(%err, "Failed to notify BlockChain of new aggregated attestation"),
            );
    }
}

/// GenServer that sequences all blockchain updates.
///
/// Any head or finalization updates are done by this server.
/// Right now it also handles block processing, but in the future
/// those updates might be done in parallel with only writes being
/// processed by this server.
struct BlockChainServer {
    store: Store,
    p2p_tx: mpsc::UnboundedSender<P2PMessage>,
    key_manager: key_manager::KeyManager,

    // Pending block roots waiting for their parent (block data stored in DB)
    pending_blocks: HashMap<H256, HashSet<H256>>,
    // Maps pending block_root → its cached missing ancestor. Resolved by walking the
    // chain at lookup time, since a cached ancestor may itself have become pending with
    // a deeper missing parent after the entry was created.
    pending_block_parents: HashMap<H256, H256>,

    /// Whether this node acts as a committee aggregator.
    is_aggregator: bool,
}

impl BlockChainServer {
    fn on_tick(&mut self, timestamp_ms: u64) {
        let genesis_time_ms = self.store.config().genesis_time * 1000;

        // Calculate current slot and interval from milliseconds
        let time_since_genesis_ms = timestamp_ms.saturating_sub(genesis_time_ms);
        let slot = time_since_genesis_ms / MILLISECONDS_PER_SLOT;
        let interval = (time_since_genesis_ms % MILLISECONDS_PER_SLOT) / MILLISECONDS_PER_INTERVAL;

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
            self.is_aggregator,
        );

        // Now build and publish the block (after attestations have been accepted)
        if let Some(validator_id) = proposer_validator_id {
            self.propose_block(slot, validator_id);
        }

        // Produce attestations at interval 1 (proposer already attested in block)
        if interval == 1 {
            self.produce_attestations(slot);
        }

        // Update safe target slot metric (updated by store.on_tick at interval 3)
        metrics::update_safe_target_slot(self.store.safe_target_slot());
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
        // Get the head state to determine number of validators
        let head_state = self.store.head_state();

        let num_validators = head_state.validators.len() as u64;

        // Produce attestation data once for all validators
        let attestation_data = store::produce_attestation_data(&self.store, slot);

        // For each registered validator, produce and publish attestation
        for validator_id in self.key_manager.validator_ids() {
            // Skip if this validator is the slot proposer
            if is_proposer(validator_id, slot, num_validators) {
                info!(%slot, %validator_id, "Skipping attestation for proposer");
                continue;
            }

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
                message: attestation_data.clone(),
                signature,
            };

            // Publish to gossip network
            let Ok(_) = self
                .p2p_tx
                .send(P2PMessage::PublishAttestation(signed_attestation))
                .inspect_err(
                    |err| error!(%slot, %validator_id, %err, "Failed to publish attestation"),
                )
            else {
                continue;
            };
            info!(%slot, %validator_id, "Published attestation");
        }
    }

    /// Build and publish a block for the given slot and validator.
    fn propose_block(&mut self, slot: u64, validator_id: u64) {
        info!(%slot, %validator_id, "We are the proposer for this slot");

        // Build the block with attestation signatures
        let Ok((block, attestation_signatures)) =
            store::produce_block_with_signatures(&mut self.store, slot, validator_id)
                .inspect_err(|err| error!(%slot, %validator_id, %err, "Failed to build block"))
        else {
            return;
        };

        // Create proposer's attestation (attests to the new block)
        let proposer_attestation = Attestation {
            validator_id,
            data: AttestationData {
                slot,
                head: Checkpoint {
                    root: block.tree_hash_root(),
                    slot: block.slot,
                },
                target: store::get_attestation_target(&self.store),
                source: self.store.latest_justified(),
            },
        };

        // Sign the proposer's attestation
        let Ok(proposer_signature) = self
            .key_manager
            .sign_attestation(validator_id, &proposer_attestation.data)
            .inspect_err(
                |err| error!(%slot, %validator_id, %err, "Failed to sign proposer attestation"),
            )
        else {
            return;
        };

        // Assemble SignedBlockWithAttestation
        let signed_block = SignedBlockWithAttestation {
            message: BlockWithAttestation {
                block,
                proposer_attestation,
            },
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
            return;
        };

        // Publish to gossip network
        let Ok(()) = self
            .p2p_tx
            .send(P2PMessage::PublishBlock(signed_block))
            .inspect_err(|err| error!(%slot, %validator_id, %err, "Failed to publish block"))
        else {
            return;
        };

        info!(%slot, %validator_id, "Published block");
    }

    fn process_block(
        &mut self,
        signed_block: SignedBlockWithAttestation,
    ) -> Result<(), StoreError> {
        let slot = signed_block.message.block.slot;
        store::on_block(&mut self.store, signed_block)?;
        metrics::update_head_slot(slot);
        metrics::update_latest_justified_slot(self.store.latest_justified().slot);
        metrics::update_latest_finalized_slot(self.store.latest_finalized().slot);
        metrics::update_validators_count(self.key_manager.validator_ids().len() as u64);
        Ok(())
    }

    /// Process a newly received block.
    fn on_block(&mut self, signed_block: SignedBlockWithAttestation) {
        let mut queue = VecDeque::new();
        queue.push_back(signed_block);

        // A new block can trigger a cascade of pending blocks becoming processable.
        // Here we process blocks iteratively, to avoid recursive calls that could
        // cause a stack overflow.
        while let Some(block) = queue.pop_front() {
            self.process_or_pend_block(block, &mut queue);
        }
    }

    /// Try to process a single block. If its parent state is missing, store it
    /// as pending. On success, collect any unblocked children into `queue` for
    /// the caller to process next (iteratively, avoiding deep recursion).
    fn process_or_pend_block(
        &mut self,
        signed_block: SignedBlockWithAttestation,
        queue: &mut VecDeque<SignedBlockWithAttestation>,
    ) {
        let slot = signed_block.message.block.slot;
        let block_root = signed_block.message.block.tree_hash_root();
        let parent_root = signed_block.message.block.parent_root;
        let proposer = signed_block.message.block.proposer_index;

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
        let _ = self
            .p2p_tx
            .send(P2PMessage::FetchBlock(block_root))
            .inspect(|_| info!(%block_root, "Requested missing block from network"))
            .inspect_err(
                |err| error!(%block_root, %err, "Failed to send FetchBlock message to P2P"),
            );
    }

    /// Move pending children of `parent_root` into the work queue for iterative
    /// processing. This replaces the old recursive `process_pending_children`.
    fn collect_pending_children(
        &mut self,
        parent_root: H256,
        queue: &mut VecDeque<SignedBlockWithAttestation>,
    ) {
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

            let slot = child_block.message.block.slot;
            trace!(%parent_root, %slot, "Processing pending child block");

            queue.push_back(child_block);
        }
    }

    fn on_gossip_attestation(&mut self, attestation: SignedAttestation) {
        let _ = store::on_gossip_attestation(&mut self.store, attestation, self.is_aggregator)
            .inspect_err(|err| warn!(%err, "Failed to process gossiped attestation"));
    }

    fn on_gossip_aggregated_attestation(&mut self, attestation: SignedAggregatedAttestation) {
        let _ = store::on_gossip_aggregated_attestation(&mut self.store, attestation)
            .inspect_err(|err| warn!(%err, "Failed to process gossiped aggregated attestation"));
    }
}

#[derive(Clone, Debug)]
enum CastMessage {
    NewBlock(SignedBlockWithAttestation),
    NewAttestation(SignedAttestation),
    NewAggregatedAttestation(SignedAggregatedAttestation),
    Tick,
}

impl GenServer for BlockChainServer {
    type CallMsg = ();

    type CastMsg = CastMessage;

    type OutMsg = ();

    type Error = ();

    async fn handle_call(
        &mut self,
        _message: Self::CallMsg,
        _handle: &GenServerHandle<Self>,
    ) -> CallResponse<Self> {
        CallResponse::Unused
    }

    async fn handle_cast(
        &mut self,
        message: Self::CastMsg,
        handle: &GenServerHandle<Self>,
    ) -> CastResponse {
        match message {
            CastMessage::Tick => {
                let timestamp = SystemTime::UNIX_EPOCH
                    .elapsed()
                    .expect("already past the unix epoch");
                self.on_tick(timestamp.as_millis() as u64);
                // Schedule the next tick at the next 800ms interval boundary
                let ms_since_epoch = timestamp.as_millis() as u64;
                let ms_to_next_interval =
                    MILLISECONDS_PER_INTERVAL - (ms_since_epoch % MILLISECONDS_PER_INTERVAL);
                send_after(
                    Duration::from_millis(ms_to_next_interval),
                    handle.clone(),
                    message,
                );
            }
            CastMessage::NewBlock(signed_block) => {
                self.on_block(signed_block);
            }
            CastMessage::NewAttestation(attestation) => self.on_gossip_attestation(attestation),
            CastMessage::NewAggregatedAttestation(attestation) => {
                self.on_gossip_aggregated_attestation(attestation);
            }
        }
        CastResponse::NoReply
    }
}
