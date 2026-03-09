use ethlambda_types::{
    attestation::{SignedAggregatedAttestation, SignedAttestation},
    block::SignedBlockWithAttestation,
    primitives::H256,
};
use spawned_concurrency::message::Message;
use spawned_concurrency::tasks::Recipient;

// --- Messages: BlockChain -> P2P ---

pub struct PublishBlock {
    pub block: SignedBlockWithAttestation,
}
impl Message for PublishBlock {
    type Result = ();
}

pub struct PublishAttestation {
    pub attestation: SignedAttestation,
}
impl Message for PublishAttestation {
    type Result = ();
}

pub struct PublishAggregatedAttestation {
    pub attestation: SignedAggregatedAttestation,
}
impl Message for PublishAggregatedAttestation {
    type Result = ();
}

pub struct FetchBlock {
    pub root: H256,
}
impl Message for FetchBlock {
    type Result = ();
}

// --- Messages: P2P -> BlockChain ---

pub struct NewBlock {
    pub block: SignedBlockWithAttestation,
}
impl Message for NewBlock {
    type Result = ();
}

pub struct NewAttestation {
    pub attestation: SignedAttestation,
}
impl Message for NewAttestation {
    type Result = ();
}

pub struct NewAggregatedAttestation {
    pub attestation: SignedAggregatedAttestation,
}
impl Message for NewAggregatedAttestation {
    type Result = ();
}

// --- Init messages ---

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
