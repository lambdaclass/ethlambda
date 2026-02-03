use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime};

use ethlambda_state_transition::is_proposer;
use ethlambda_storage::Store;
use ethlambda_types::{
    ShortRoot,
    attestation::{Attestation, AttestationData, SignedAttestation},
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
    /// Fetch a block by its root hash.
    FetchBlock(H256),
}

pub struct BlockChain {
    handle: GenServerHandle<BlockChainServer>,
}

/// Seconds in a slot. Each slot has 4 intervals of 1 second each.
pub const SECONDS_PER_SLOT: u64 = 4;

// Pending attestation limits (tighter to reduce DoS surface)
const MAX_PENDING_ATTESTATIONS_PER_BLOCK: usize = 32; // Per unknown block
const MAX_TOTAL_PENDING_ATTESTATIONS: usize = 512; // Global cap
const PENDING_ATTESTATION_TTL_SLOTS: u64 = 4; // 16 seconds

/// Attestation pending on one or more unknown blocks.
struct PendingAttestation {
    /// Full signed attestation (need signature for re-verification)
    signed_attestation: SignedAttestation,
    /// Block roots we're waiting for
    waiting_for: HashSet<H256>,
    /// Slot when attestation was received (for TTL tracking)
    received_slot: u64,
}

/// Storage for pending attestations.
struct PendingAttestations {
    /// Index from block root to attestation indices waiting for that block
    by_block: HashMap<H256, Vec<usize>>,
    /// All pending attestations (indices used by by_block)
    attestations: Vec<Option<PendingAttestation>>,
    /// Free list for slot reuse
    free_slots: Vec<usize>,
    /// Total active count
    active_count: usize,
}

impl PendingAttestations {
    fn new() -> Self {
        Self {
            by_block: HashMap::new(),
            attestations: Vec::new(),
            free_slots: Vec::new(),
            active_count: 0,
        }
    }
}

impl BlockChain {
    pub fn spawn(
        store: Store,
        p2p_tx: mpsc::UnboundedSender<P2PMessage>,
        validator_keys: HashMap<u64, ValidatorSecretKey>,
    ) -> BlockChain {
        let genesis_time = store.config().genesis_time;
        let key_manager = key_manager::KeyManager::new(validator_keys);
        let handle = BlockChainServer {
            store,
            p2p_tx,
            key_manager,
            pending_blocks: HashMap::new(),
            pending_attestations: PendingAttestations::new(),
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
}

struct BlockChainServer {
    store: Store,
    p2p_tx: mpsc::UnboundedSender<P2PMessage>,
    key_manager: key_manager::KeyManager,

    // Pending blocks waiting for their parent
    pending_blocks: HashMap<H256, Vec<SignedBlockWithAttestation>>,
    // Pending attestations waiting for missing blocks
    pending_attestations: PendingAttestations,
}

impl BlockChainServer {
    fn on_tick(&mut self, timestamp: u64) {
        let genesis_time = self.store.config().genesis_time;

        // Calculate current slot and interval
        let time_since_genesis = timestamp.saturating_sub(genesis_time);
        let slot = time_since_genesis / SECONDS_PER_SLOT;
        let interval = time_since_genesis % SECONDS_PER_SLOT;

        // Update current slot metric
        metrics::update_current_slot(slot);

        // At interval 0, check if we will propose (but don't build the block yet).
        // Tick forkchoice first to accept attestations, then build the block
        // using the freshly-accepted attestations.
        let proposer_validator_id = (interval == 0 && slot > 0)
            .then(|| self.get_our_proposer(slot))
            .flatten();

        // Tick the store first - this accepts attestations at interval 0 if we have a proposal
        store::on_tick(&mut self.store, timestamp, proposer_validator_id.is_some());

        // Now build and publish the block (after attestations have been accepted)
        if let Some(validator_id) = proposer_validator_id {
            self.propose_block(slot, validator_id);
        }

        // Produce attestations at interval 1 (proposer already attested in block)
        if interval == 1 {
            self.produce_attestations(slot);
        }

        // Update safe target slot metric (updated by store.on_tick at interval 2)
        metrics::update_safe_target_slot(self.store.safe_target_slot());

        // Clean up expired pending attestations at interval 2
        // (avoids conflict with attestation promotion at intervals 0 and 3)
        if interval == 2 {
            self.cleanup_expired_pending_attestations(slot);
        }
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
        let old_finalized_slot = self.store.latest_finalized().slot;

        store::on_block(&mut self.store, signed_block)?;

        let new_finalized_slot = self.store.latest_finalized().slot;

        metrics::update_head_slot(slot);
        metrics::update_latest_justified_slot(self.store.latest_justified().slot);
        metrics::update_latest_finalized_slot(new_finalized_slot);
        metrics::update_validators_count(self.key_manager.validator_ids().len() as u64);

        // Clean up pending attestations if finalization advanced
        if new_finalized_slot > old_finalized_slot {
            self.cleanup_finalized_pending_attestations(new_finalized_slot);
        }

        Ok(())
    }

    fn on_block(&mut self, signed_block: SignedBlockWithAttestation) {
        let slot = signed_block.message.block.slot;
        let block_root = signed_block.message.block.tree_hash_root();
        let parent_root = signed_block.message.block.parent_root;
        let proposer = signed_block.message.block.proposer_index;

        // Check if parent block exists before attempting to process
        if !self.store.contains_block(&parent_root) {
            info!(%slot, %parent_root, %block_root, "Block parent missing, storing as pending");

            // Store block for later processing
            self.pending_blocks
                .entry(parent_root)
                .or_default()
                .push(signed_block);

            // Request missing parent from network
            self.request_missing_block(parent_root);
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

                // Check if any pending blocks can now be processed
                self.process_pending_children(block_root);

                // Process pending attestations waiting for this block
                self.process_pending_attestations(block_root);
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
        if let Err(err) = self.p2p_tx.send(P2PMessage::FetchBlock(block_root)) {
            error!(%block_root, %err, "Failed to send FetchBlock message to P2P");
        } else {
            info!(%block_root, "Requested missing block from network");
        }
    }

    fn process_pending_children(&mut self, parent_root: H256) {
        // Remove and process all blocks that were waiting for this parent
        if let Some(children) = self.pending_blocks.remove(&parent_root) {
            info!(%parent_root, num_children=%children.len(),
                  "Processing pending blocks after parent arrival");

            for child_block in children {
                let slot = child_block.message.block.slot;
                trace!(%parent_root, %slot, "Processing pending child block");

                // Process recursively - might unblock more descendants
                self.on_block(child_block);
            }
        }
    }

    fn on_gossip_attestation(&mut self, attestation: SignedAttestation) {
        // First, check which blocks are unknown
        let data = &attestation.message;
        let mut unknown_blocks = Vec::new();

        // Source check happens first in validate_attestation
        if !self.store.contains_block(&data.source.root) {
            // Source unknown = reject (not recoverable)
            warn!(
                source_root = %ShortRoot(&data.source.root.0),
                validator = attestation.validator_id,
                "Attestation has unknown source block"
            );
            return;
        }
        if !self.store.contains_block(&data.target.root) {
            unknown_blocks.push(data.target.root);
        }
        if !self.store.contains_block(&data.head.root) {
            unknown_blocks.push(data.head.root);
        }

        if !unknown_blocks.is_empty() {
            // Pre-validate before queuing
            if !self.can_queue_pending_attestation(&attestation) {
                trace!(
                    validator = attestation.validator_id,
                    "Rejecting pending attestation: failed pre-validation"
                );
                return;
            }
            self.store_pending_attestation(attestation, unknown_blocks);
            return;
        }

        // All blocks known, process normally
        if let Err(err) = store::on_gossip_attestation(&mut self.store, attestation) {
            warn!(%err, "Failed to process gossiped attestation");
        }
    }

    /// Get the current slot based on system time
    fn current_slot(&self) -> u64 {
        let genesis_time = self.store.config().genesis_time;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(genesis_time) / SECONDS_PER_SLOT
    }

    /// Pre-validate attestation before queuing (cheap checks to filter garbage)
    fn can_queue_pending_attestation(&self, attestation: &SignedAttestation) -> bool {
        let current_slot = self.current_slot();
        let data = &attestation.message;

        // 1. Slot sanity: not too old, not too far in future
        if data.slot + PENDING_ATTESTATION_TTL_SLOTS < current_slot {
            return false; // Too old
        }
        if data.slot > current_slot + 1 {
            return false; // Future attestation
        }

        // 2. Source must be known (required by spec, not recoverable)
        if !self.store.contains_block(&data.source.root) {
            return false;
        }

        // 3. Target not already finalized (would be useless)
        if data.target.slot <= self.store.latest_finalized().slot {
            return false;
        }

        // 4. Validator ID must be plausible
        let head_state = self.store.head_state();
        if attestation.validator_id >= head_state.validators.len() as u64 {
            return false;
        }

        true
    }

    /// Store a pending attestation waiting for one or more unknown blocks
    fn store_pending_attestation(
        &mut self,
        attestation: SignedAttestation,
        unknown_blocks: Vec<H256>,
    ) {
        let current_slot = self.current_slot();
        let validator_id = attestation.validator_id;

        // Enforce global limit
        if self.pending_attestations.active_count >= MAX_TOTAL_PENDING_ATTESTATIONS {
            self.evict_oldest_pending_attestation();
        }

        // Enforce per-block limits (check all unknown blocks)
        for root in &unknown_blocks {
            if let Some(indices) = self.pending_attestations.by_block.get(root)
                && indices.len() >= MAX_PENDING_ATTESTATIONS_PER_BLOCK
            {
                trace!(
                    root = %ShortRoot(&root.0),
                    %validator_id,
                    "Per-block pending limit reached"
                );
                return;
            }
        }

        // Create the pending attestation
        let waiting_for: HashSet<H256> = unknown_blocks.iter().copied().collect();
        let pending = PendingAttestation {
            signed_attestation: attestation,
            waiting_for: waiting_for.clone(),
            received_slot: current_slot,
        };

        // Allocate slot
        let idx = if let Some(free_idx) = self.pending_attestations.free_slots.pop() {
            self.pending_attestations.attestations[free_idx] = Some(pending);
            free_idx
        } else {
            let idx = self.pending_attestations.attestations.len();
            self.pending_attestations.attestations.push(Some(pending));
            idx
        };

        // Add to indices for each unknown block
        for root in &unknown_blocks {
            self.pending_attestations
                .by_block
                .entry(*root)
                .or_default()
                .push(idx);
        }

        self.pending_attestations.active_count += 1;

        info!(
            %validator_id,
            num_unknown = unknown_blocks.len(),
            pending_count = self.pending_attestations.active_count,
            "Stored attestation pending on missing blocks"
        );

        // Request ALL unknown blocks
        for root in unknown_blocks {
            self.request_missing_block(root);
        }
    }

    /// Evict the oldest pending attestation to make room for new ones
    fn evict_oldest_pending_attestation(&mut self) {
        // Find the oldest attestation by received_slot
        let mut oldest_idx = None;
        let mut oldest_slot = u64::MAX;

        for (idx, pending_opt) in self.pending_attestations.attestations.iter().enumerate() {
            if let Some(pending) = pending_opt
                && pending.received_slot < oldest_slot
            {
                oldest_slot = pending.received_slot;
                oldest_idx = Some(idx);
            }
        }

        if let Some(idx) = oldest_idx
            && let Some(pending) = self.pending_attestations.attestations[idx].take()
        {
            // Remove from all by_block indices
            for root in &pending.waiting_for {
                if let Some(indices) = self.pending_attestations.by_block.get_mut(root) {
                    indices.retain(|&i| i != idx);
                }
            }
            // Clear the slot and add to free list
            self.pending_attestations.free_slots.push(idx);
            self.pending_attestations.active_count -= 1;
        }
    }

    /// Process pending attestations after a block arrives
    fn process_pending_attestations(&mut self, arrived_block: H256) {
        // Get indices waiting for this block
        let Some(indices) = self.pending_attestations.by_block.remove(&arrived_block) else {
            return;
        };

        let mut processed = 0;
        let mut still_waiting = 0;
        let mut failed = 0;

        for idx in indices {
            let Some(pending) = self.pending_attestations.attestations[idx].as_mut() else {
                continue; // Already processed
            };

            // Remove this block from waiting set
            pending.waiting_for.remove(&arrived_block);

            // If still waiting for other blocks, keep pending
            if !pending.waiting_for.is_empty() {
                still_waiting += 1;
                continue;
            }

            // All blocks now available - process
            let attestation = self.pending_attestations.attestations[idx]
                .take()
                .unwrap()
                .signed_attestation;

            // Return slot to free list
            self.pending_attestations.free_slots.push(idx);
            self.pending_attestations.active_count -= 1;

            // Process through FULL on_gossip_attestation flow (includes signature verification)
            match store::on_gossip_attestation(&mut self.store, attestation) {
                Ok(()) => {
                    processed += 1;
                }
                Err(err) => {
                    failed += 1;
                    trace!(
                        arrived_block = %ShortRoot(&arrived_block.0),
                        %err,
                        "Pending attestation still invalid after block arrival"
                    );
                }
            }
        }

        if processed > 0 || failed > 0 {
            info!(
                arrived_block = %ShortRoot(&arrived_block.0),
                processed,
                still_waiting,
                failed,
                "Processed pending attestations after block arrival"
            );
        }
    }

    /// Clean up expired pending attestations (TTL-based)
    fn cleanup_expired_pending_attestations(&mut self, current_slot: u64) {
        let cutoff_slot = current_slot.saturating_sub(PENDING_ATTESTATION_TTL_SLOTS);
        let mut removed_count = 0;

        for idx in 0..self.pending_attestations.attestations.len() {
            if let Some(pending) = &self.pending_attestations.attestations[idx]
                && pending.received_slot < cutoff_slot
            {
                // Remove from all by_block indices
                for root in &pending.waiting_for {
                    if let Some(indices) = self.pending_attestations.by_block.get_mut(root) {
                        indices.retain(|&i| i != idx);
                    }
                }
                // Clear the slot
                self.pending_attestations.attestations[idx] = None;
                self.pending_attestations.free_slots.push(idx);
                self.pending_attestations.active_count -= 1;
                removed_count += 1;
            }
        }

        // Clean up empty by_block entries
        self.pending_attestations
            .by_block
            .retain(|_, indices| !indices.is_empty());

        if removed_count > 0 {
            info!(
                current_slot,
                removed_count,
                remaining = self.pending_attestations.active_count,
                "Cleaned up expired pending attestations"
            );
        }
    }

    /// Clean up pending attestations whose target is now finalized
    fn cleanup_finalized_pending_attestations(&mut self, finalized_slot: u64) {
        let mut removed_count = 0;

        for idx in 0..self.pending_attestations.attestations.len() {
            if let Some(pending) = &self.pending_attestations.attestations[idx]
                && pending.signed_attestation.message.target.slot <= finalized_slot
            {
                // Remove from all by_block indices
                for root in &pending.waiting_for {
                    if let Some(indices) = self.pending_attestations.by_block.get_mut(root) {
                        indices.retain(|&i| i != idx);
                    }
                }
                // Clear the slot
                self.pending_attestations.attestations[idx] = None;
                self.pending_attestations.free_slots.push(idx);
                self.pending_attestations.active_count -= 1;
                removed_count += 1;
            }
        }

        // Clean up empty by_block entries
        self.pending_attestations
            .by_block
            .retain(|_, indices| !indices.is_empty());

        if removed_count > 0 {
            info!(
                finalized_slot,
                removed_count,
                remaining = self.pending_attestations.active_count,
                "Cleaned up finalized pending attestations"
            );
        }
    }
}

#[derive(Clone, Debug)]
enum CastMessage {
    NewBlock(SignedBlockWithAttestation),
    NewAttestation(SignedAttestation),
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
                self.on_tick(timestamp.as_secs());
                // Schedule the next tick at the start of the next second
                let millis_to_next_sec =
                    ((timestamp.as_secs() as u128 + 1) * 1000 - timestamp.as_millis()) as u64;
                send_after(
                    Duration::from_millis(millis_to_next_sec),
                    handle.clone(),
                    message,
                );
            }
            CastMessage::NewBlock(signed_block) => {
                self.on_block(signed_block);
            }
            CastMessage::NewAttestation(attestation) => self.on_gossip_attestation(attestation),
        }
        CastResponse::NoReply
    }
}
