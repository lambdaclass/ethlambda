use ethlambda_types::{
    attestation::{SignedAggregatedAttestation, SignedAttestation},
    beacon::containers::SignedBeaconBlock,
    beacon::primitives::Root as BeaconRoot,
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
    /// Fetch a beacon block by root over `beacon_blocks_by_root/2`.
    ///
    /// Separate from [`BlockChainToP2P::fetch_block`] because the two chains'
    /// roots are different types over the same 32 bytes: lean's
    /// `ethlambda_types::primitives::H256` and the beacon `Root`, which is
    /// `ethereum_types::H256`. Converting at this boundary would leave the two
    /// one typo apart at every call site.
    fn fetch_beacon_block(&self, root: BeaconRoot) -> Result<(), ActorError>;
}

/// How a block reached this node.
///
/// Distinguishes blocks announced on gossip from blocks pulled by req/resp
/// during sync: the two have very different arrival-time characteristics, so
/// consumers that care about timeliness must be able to tell them apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockSource {
    /// Received on the block gossip topic.
    Gossip,
    /// Fetched via req/resp (`BlocksByRoot` / `BlocksByRange`).
    Sync,
}

// --- Protocol: P2P -> BlockChain ---

#[protocol]
pub trait P2PToBlockChain: Send + Sync {
    fn new_block(&self, block: SignedBlock, source: BlockSource) -> Result<(), ActorError>;
    fn new_attestation(&self, attestation: SignedAttestation) -> Result<(), ActorError>;
    fn new_aggregated_attestation(
        &self,
        attestation: SignedAggregatedAttestation,
    ) -> Result<(), ActorError>;
    /// A decoded beacon block, from gossip or from a req/resp fetch.
    ///
    /// The beacon sibling of [`P2PToBlockChain::new_block`]: the two chains'
    /// block types are unrelated, and a widened `new_block` would mean an enum
    /// every lean call site has to construct. `source` is what keeps the
    /// range-fetch counter honest, since a counter that also moved on gossip
    /// could not distinguish a closed gap from a tip-tracking node.
    fn new_beacon_block(
        &self,
        block: SignedBeaconBlock,
        source: BlockSource,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Each chain's root type reaches the P2P actor unconverted. Lean's
    /// `fetch_block` takes lean's `H256`; the beacon sibling takes the beacon
    /// `Root`, which is a different type carrying the same bytes. Converting at
    /// the actor boundary instead would put the two roots one typo apart.
    #[test]
    fn the_two_fetch_messages_carry_different_root_types() {
        let lean = H256([0u8; 32]);
        let beacon = BeaconRoot::zero();

        let lean_message = block_chain_to_p2p::FetchBlock { root: lean };
        let beacon_message = block_chain_to_p2p::FetchBeaconBlock { root: beacon };

        assert_eq!(lean_message.root, lean);
        assert_eq!(beacon_message.root, beacon);
    }

    /// The beacon ingress message exists and carries a `BlockSource`, which is
    /// what lets `lean_sync_range_blocks_total` count only fetched blocks: a
    /// counter that also moved on gossip could not tell a closed gap from a
    /// node happily tracking a tip it cannot evaluate.
    #[test]
    fn a_beacon_block_reaches_the_chain_actor_with_its_source() {
        use ethlambda_types::beacon::containers::phase0;
        let block = SignedBeaconBlock::Phase0(phase0::SignedBeaconBlock {
            message: phase0::BeaconBlock {
                slot: 7,
                proposer_index: 0,
                parent_root: Default::default(),
                state_root: Default::default(),
                body: phase0::BeaconBlockBody {
                    randao_reveal: Default::default(),
                    eth1_data: Default::default(),
                    graffiti: Default::default(),
                    proposer_slashings: Default::default(),
                    attester_slashings: Default::default(),
                    attestations: Default::default(),
                    deposits: Default::default(),
                    voluntary_exits: Default::default(),
                },
            },
            signature: Default::default(),
        });

        let message = p2p_to_block_chain::NewBeaconBlock {
            block,
            source: BlockSource::Sync,
        };

        assert_eq!(message.source, BlockSource::Sync);
    }
}
