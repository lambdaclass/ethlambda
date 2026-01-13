use std::time::{Duration, SystemTime};

use ethlambda_storage::Store;
use ethlambda_types::{
    attestation::SignedAttestation, block::SignedBlockWithAttestation, primitives::TreeHash,
};
use spawned_concurrency::tasks::{
    CallResponse, CastResponse, GenServer, GenServerHandle, send_after,
};
use tracing::{error, info, trace, warn};

pub struct BlockChain {
    handle: GenServerHandle<BlockChainServer>,
}

impl BlockChain {
    pub fn spawn(store: Store) -> BlockChain {
        let genesis_time = store.get_genesis_time();
        let handle = BlockChainServer { store }.start();
        let time_until_genesis = (SystemTime::UNIX_EPOCH + Duration::from_secs(genesis_time))
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::default());
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
}

impl BlockChainServer {
    fn on_tick(&mut self, timestamp: u64) {
        let time = timestamp - self.store.get_genesis_time();
        // TODO: check if we are proposing
        let has_proposal = false;
        let slot = time / 4;
        let interval = time - slot * 4;
        trace!(%slot, %interval, "processing tick");
    }

    fn on_block(&mut self, signed_block: SignedBlockWithAttestation) {
        let slot = signed_block.message.block.slot;

        let block = signed_block.message.block;
        let proposer_attestation = signed_block.message.proposer_attestation;
        let signatures = signed_block.signature;

        let block_root = block.tree_hash_root();

        if self.store.has_state(&block_root) {
            return;
        }

        let Some(mut pre_state) = self.store.get_state(&block.parent_root) else {
            // TODO: backfill missing blocks
            warn!(%slot, %block_root, parent=%block.parent_root, "Missing pre-state for new block");
            return;
        };

        // TODO: validate block signatures

        if let Err(err) = ethlambda_state_transition::state_transition(&mut pre_state, &block) {
            warn!(%slot, %block_root, %err, "State transition failed for new block");
            return;
        }
        // Cache the state root in the latest block header
        let state_root = block.state_root;
        pre_state.latest_block_header.state_root = state_root;

        let post_state = pre_state;

        self.store.add_block(block, post_state);

        info!(%slot, %block_root, %state_root, "Processed new block");
        update_head_slot(slot);
    }

    fn on_attestation(&mut self, attestation: SignedAttestation) {}
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
            CastMessage::NewAttestation(attestation) => self.on_attestation(attestation),
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
