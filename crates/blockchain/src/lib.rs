use ethlambda_storage::Store;
use ethlambda_types::block::SignedBlockWithAttestation;
use spawned_concurrency::tasks::{CallResponse, CastResponse, GenServer, GenServerHandle};
use tracing::error;

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
            CastMessage::NewBlock(block) => {
                update_head_slot(block.message.block.slot);
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
