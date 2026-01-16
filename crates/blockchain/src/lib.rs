use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use ethlambda_state_transition::is_proposer;
use ethlambda_types::{
    attestation::SignedAttestation, block::SignedBlockWithAttestation, primitives::TreeHash,
    signature::ValidatorSecretKey, state::State,
};
use spawned_concurrency::tasks::{
    CallResponse, CastResponse, GenServer, GenServerHandle, send_after,
};
use store::Store;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

pub mod key_manager;
pub mod store;

/// Messages sent from the blockchain to the P2P layer for publishing.
#[derive(Clone, Debug)]
pub enum OutboundGossip {
    /// Publish an attestation to the gossip network.
    PublishAttestation(SignedAttestation),
}

pub struct BlockChain {
    handle: GenServerHandle<BlockChainServer>,
}

/// Seconds in a slot. Each slot has 4 intervals of 1 second each.
pub const SECONDS_PER_SLOT: u64 = 4;

impl BlockChain {
    pub fn spawn(
        genesis_state: State,
        p2p_tx: mpsc::UnboundedSender<OutboundGossip>,
        validator_keys: HashMap<u64, ValidatorSecretKey>,
    ) -> BlockChain {
        let genesis_time = genesis_state.config.genesis_time;
        let store = Store::from_genesis(genesis_state);
        let key_manager = key_manager::KeyManager::new(validator_keys);
        let handle = BlockChainServer {
            store,
            p2p_tx,
            key_manager,
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
    p2p_tx: mpsc::UnboundedSender<OutboundGossip>,
    key_manager: key_manager::KeyManager,
}

impl BlockChainServer {
    fn on_tick(&mut self, timestamp: u64) {
        let genesis_time = self.store.config().genesis_time;

        // Calculate current slot and interval
        let time_since_genesis = timestamp.saturating_sub(genesis_time);
        let slot = time_since_genesis / SECONDS_PER_SLOT;
        let interval = time_since_genesis % SECONDS_PER_SLOT;

        // Produce attestations at interval 1
        if interval == 1 {
            self.produce_attestations(slot);
        }

        // TODO: check if we are proposing
        let has_proposal = false;

        self.store.on_tick(timestamp, has_proposal);
    }

    fn produce_attestations(&mut self, slot: u64) {
        // Get the head state to determine number of validators
        let head_state = match self.store.head_state() {
            Some(state) => state,
            None => {
                warn!(%slot, "Cannot produce attestations: no head state");
                return;
            }
        };

        let num_validators = head_state.validators.len() as u64;

        // Produce attestation data once for all validators
        let attestation_data = self.store.produce_attestation_data(slot);

        // Hash the attestation data for signing
        let message_hash = attestation_data.tree_hash_root();

        // Epoch for signing (slot as u32 per Zeam's implementation)
        let epoch = slot as u32;

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
                .sign_attestation(validator_id, epoch, &message_hash)
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
            if let Err(err) = self
                .p2p_tx
                .send(OutboundGossip::PublishAttestation(signed_attestation))
            {
                error!(%slot, %validator_id, %err, "Failed to publish attestation");
            } else {
                info!(%slot, %validator_id, "Published attestation");
            }
        }
    }

    fn on_block(&mut self, signed_block: SignedBlockWithAttestation) {
        let slot = signed_block.message.block.slot;
        if let Err(err) = self.store.on_block(signed_block) {
            warn!(%slot, %err, "Failed to process block");
            return;
        }
        update_head_slot(slot);
    }

    fn on_gossip_attestation(&mut self, attestation: SignedAttestation) {
        if let Err(err) = self.store.on_gossip_attestation(attestation) {
            warn!(%err, "Failed to process gossiped attestation");
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

fn update_head_slot(slot: u64) {
    static LEAN_HEAD_SLOT: std::sync::LazyLock<prometheus::IntGauge> =
        std::sync::LazyLock::new(|| {
            prometheus::register_int_gauge!("lean_head_slot", "Latest slot of the lean chain")
                .unwrap()
        });
    LEAN_HEAD_SLOT.set(slot.try_into().unwrap());
}
