use std::time::{Duration, SystemTime};

use ethlambda_types::{
    attestation::SignedAttestation, block::SignedBlockWithAttestation, state::State,
};
use spawned_concurrency::tasks::{
    CallResponse, CastResponse, GenServer, GenServerHandle, send_after,
};
use store::Store;
use tracing::{error, warn};

pub mod store;

pub struct BlockChain {
    handle: GenServerHandle<BlockChainServer>,
}

/// Seconds in a slot. Each slot has 4 intervals of 1 second each.
const SECONDS_PER_SLOT: u64 = 4;

impl BlockChain {
    pub fn spawn(genesis_state: State) -> BlockChain {
        let genesis_time = genesis_state.config.genesis_time;
        let store = Store::from_genesis(genesis_state);
        let handle = BlockChainServer { store }.start();
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
}

impl BlockChainServer {
    fn on_tick(&mut self, timestamp: u64) {
        // TODO: check if we are proposing
        let has_proposal = false;

        self.store.on_tick(timestamp, has_proposal);
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
