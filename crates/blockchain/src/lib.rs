use ethlambda_storage::Store;
use ethlambda_types::{block::SignedBlockWithAttestation, primitives::TreeHash};
use spawned_concurrency::tasks::{CallResponse, CastResponse, GenServer, GenServerHandle};
use tracing::{error, warn};

pub struct BlockChain {
    handle: GenServerHandle<BlockChainServer>,
}

impl BlockChain {
    pub fn spawn(store: Store) -> BlockChain {
        BlockChain {
            handle: BlockChainServer { store }.start(),
        }
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
}

struct BlockChainServer {
    store: Store,
}

impl BlockChainServer {
    fn on_block(&mut self, signed_block: SignedBlockWithAttestation) {
        let slot = signed_block.message.block.slot;
        update_head_slot(slot);

        let block = signed_block.message.block;
        let proposer_attestation = signed_block.message.proposer_attestation;
        let signatures = signed_block.signature;

        let block_root = block.tree_hash_root();

        if self.store.has_state(&block_root) {
            return;
        }

        if !self.store.has_state(&block.parent_root) {
            // TODO: backfill missing blocks
            warn!(%slot, %block_root, parent=%block.parent_root, "Missing pre-state for new block");
            return;
        }

        // TODO: validate block signatures

        // TODO: execute block and obtain new state
    }
}

#[derive(Clone, Debug)]
enum CastMessage {
    NewBlock(SignedBlockWithAttestation),
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
        _handle: &GenServerHandle<Self>,
    ) -> CastResponse {
        match message {
            CastMessage::NewBlock(signed_block) => {
                self.on_block(signed_block);
            }
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
