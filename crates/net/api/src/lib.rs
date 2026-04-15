use ethlambda_types::{
    attestation::{SignedAggregatedAttestation, SignedAttestation},
    block::SignedBlock,
    primitives::H256,
};
use spawned_concurrency::error::ActorError;
use spawned_concurrency::message::Message;
use spawned_concurrency::protocol;

// --- Protocol: BlockChain -> P2P ---

#[protocol]
pub trait BlockChainToP2P: Send + Sync {
    fn publish_block(&self, block: SignedBlock) -> Result<(), ActorError>;
    fn publish_attestation(&self, attestation: SignedAttestation) -> Result<(), ActorError>;
    fn publish_aggregated_attestation(
        &self,
        attestation: SignedAggregatedAttestation,
    ) -> Result<(), ActorError>;
    fn fetch_block(&self, root: H256) -> Result<(), ActorError>;
}

// --- Protocol: P2P -> BlockChain ---

#[protocol]
pub trait P2PToBlockChain: Send + Sync {
    fn new_block(&self, block: SignedBlock) -> Result<(), ActorError>;
    fn new_attestation(&self, attestation: SignedAttestation) -> Result<(), ActorError>;
    fn new_aggregated_attestation(
        &self,
        attestation: SignedAggregatedAttestation,
    ) -> Result<(), ActorError>;
}

// --- Init messages ---
// Used to wire actors together after spawn.

#[derive(Clone)]
pub struct InitP2P {
    pub p2p: BlockChainToP2PRef,
}
impl Message for InitP2P {
    type Result = ();
}

#[derive(Clone)]
pub struct InitBlockChain {
    pub blockchain: P2PToBlockChainRef,
}
impl Message for InitBlockChain {
    type Result = ();
}
