use std::collections::HashMap;
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

        // Pre-check signatures for external blocks before processing
        if let Err(err) = store::precheck_block_signatures(&self.store, &signed_block) {
            warn!(%slot, %err, "Block signature verification failed");
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
        let _ = store::on_gossip_attestation(&mut self.store, attestation)
            .inspect_err(|err| warn!(%err, "Failed to process gossiped attestation"));
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
