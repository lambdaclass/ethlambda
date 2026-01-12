use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use ethlambda_types::{
    attestation::SignedAttestation,
    block::Block,
    primitives::{H256, TreeHash},
    state::{ChainConfig, Checkpoint, State},
};

pub struct Store(Arc<Mutex<StoreInner>>);

/// Forkchoice store tracking chain state and validator attestations.
///
/// This is the "local view" that a node uses to run LMD GHOST. It contains:
///
/// - which blocks and states are known,
/// - which checkpoints are justified and finalized,
/// - which block is currently considered the head,
/// - and, for each validator, their latest attestation that should influence fork choice.
///
/// The `Store` is updated whenever:
/// - a new block is processed,
/// - an attestation is received (via a block or gossip),
/// - an interval tick occurs (activating new attestations),
/// - or when the head is recomputed.
#[derive(Clone)]
struct StoreInner {
    /// Current time in intervals since genesis.
    time: u64,

    /// Chain configuration parameters.
    config: ChainConfig,

    /// Root of the current canonical chain head block.
    ///
    /// This is the result of running the fork choice algorithm on the current contents of the `Store`.
    head: H256,

    /// Root of the current safe target for attestation.
    ///
    /// This can be used by higher-level logic to restrict which blocks are
    /// considered safe to attest to, based on additional safety conditions.
    ///
    safe_target: H256,

    /// Highest slot justified checkpoint known to the store.
    ///
    /// LMD GHOST starts from this checkpoint when computing the head.
    ///
    /// Only descendants of this checkpoint are considered viable.
    latest_justified: Checkpoint,

    /// Highest slot finalized checkpoint known to the store.
    ///
    /// Everything strictly before this checkpoint can be considered immutable.
    ///
    /// Fork choice will never revert finalized history.
    latest_finalized: Checkpoint,

    /// Mapping from block root to Block objects.
    ///
    /// This is the set of blocks that the node currently knows about.
    ///
    /// Every block that might participate in fork choice must appear here.
    blocks: HashMap<H256, Block>,

    /// Mapping from block root to State objects.
    ///
    /// For each known block, we keep its post-state.
    ///
    /// These states carry justified and finalized checkpoints that we use to update the
    /// `Store`'s latest justified and latest finalized checkpoints.
    states: HashMap<H256, State>,

    /// Latest signed attestations by validator that have been processed.
    ///
    /// - These attestations are "known" and contribute to fork choice weights.
    /// - Keyed by validator index to enforce one attestation per validator.
    latest_known_attestations: HashMap<u64, SignedAttestation>,

    /// Latest signed attestations by validator that are pending processing.
    ///
    /// - These attestations are "new" and do not yet contribute to fork choice.
    /// - They migrate to `latest_known_attestations` via interval ticks.
    /// - Keyed by validator index to enforce one attestation per validator.
    latest_new_attestations: HashMap<u64, SignedAttestation>,
}

impl Store {
    pub fn from_genesis(genesis_state: State) -> Self {
        let genesis_state_root = genesis_state.tree_hash_root();
        let genesis_block = Block {
            slot: 0,
            proposer_index: 0,
            parent_root: H256::ZERO,
            state_root: genesis_state_root,
            body: Default::default(),
        };
        Self::get_forkchoice_store(genesis_state, genesis_block)
    }

    pub fn get_forkchoice_store(anchor_state: State, anchor_block: Block) -> Self {
        let anchor_state_root = anchor_state.tree_hash_root();
        let anchor_block_root = anchor_block.tree_hash_root();

        let mut blocks = HashMap::new();
        blocks.insert(anchor_block_root, anchor_block.clone());

        let mut states = HashMap::new();
        states.insert(anchor_state_root, anchor_state.clone());

        let anchor_checkpoint = Checkpoint {
            root: anchor_block_root,
            slot: 0,
        };

        Self(Arc::new(Mutex::new(StoreInner {
            time: 0,
            config: anchor_state.config.clone(),
            head: anchor_block_root,
            safe_target: anchor_block_root,
            latest_justified: anchor_checkpoint,
            latest_finalized: anchor_checkpoint,
            blocks,
            states,
            latest_known_attestations: HashMap::new(),
            latest_new_attestations: HashMap::new(),
        })))
    }

    pub fn has_state(&self, block_root: &H256) -> bool {
        self.0.lock().unwrap().states.contains_key(block_root)
    }

    pub fn get_state(&self, block_root: &H256) -> Option<State> {
        self.0.lock().unwrap().states.get(block_root).cloned()
    }

    pub fn add_block(&self, block: Block, state: State) {
        let block_root = block.tree_hash_root();
        let mut inner = self.0.lock().unwrap();
        inner.blocks.insert(block_root, block);
        inner.states.insert(block_root, state);
    }
}
