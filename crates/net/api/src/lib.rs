use ethlambda_types::{
    attestation::{SignedAggregatedAttestation, SignedAttestation},
    block::SignedBlockWithAttestation,
    primitives::H256,
};
use spawned_concurrency::tasks::Recipient;

// --- Messages: BlockChain -> P2P ---

spawned_concurrency::send_messages! {
    PublishBlock { block: SignedBlockWithAttestation };
    PublishAttestation { attestation: SignedAttestation };
    PublishAggregatedAttestation { attestation: SignedAggregatedAttestation };
    FetchBlock { root: H256 }
}

// --- Messages: P2P -> BlockChain ---

spawned_concurrency::send_messages! {
    NewBlock { block: SignedBlockWithAttestation };
    NewAttestation { attestation: SignedAttestation };
    NewAggregatedAttestation { attestation: SignedAggregatedAttestation }
}

// --- Init messages ---
// Defined manually because #[protocol] requires Clone, and send_messages!
// doesn't derive it.

use spawned_concurrency::message::Message;

#[derive(Clone)]
pub struct InitP2P {
    pub publish_block: Recipient<PublishBlock>,
    pub publish_attestation: Recipient<PublishAttestation>,
    pub publish_aggregated: Recipient<PublishAggregatedAttestation>,
    pub fetch_block: Recipient<FetchBlock>,
}
impl Message for InitP2P {
    type Result = ();
}

#[derive(Clone)]
pub struct InitBlockChain {
    pub new_block: Recipient<NewBlock>,
    pub new_attestation: Recipient<NewAttestation>,
    pub new_aggregated: Recipient<NewAggregatedAttestation>,
}
impl Message for InitBlockChain {
    type Result = ();
}
