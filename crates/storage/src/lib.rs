use std::collections::HashMap;

use ethlambda_types::{
    attestation::SignedAttestation,
    block::Block,
    primitives::H256,
    state::{Checkpoint, State},
};

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
pub struct Store {
    /// Current time in intervals since genesis.
    time: u64,

    /// Chain configuration parameters.
    // config: Config,

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

    /// Mapping from state root to State objects.
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
