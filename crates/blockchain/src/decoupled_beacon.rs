//! The beacon chain actor's side of the `decoupled` fork.
//!
//! From the fork on, the head is the decoupled engine's, not LMD-GHOST's, and
//! the execution client hears the engine's confirmed (locked) and finalized
//! blocks as `safe` and `finalized`. The legacy FFG checkpoints of the store stay where
//! the fork left them: nothing epoch-based may prune or gate on a finalized
//! block the decoupled protocol chose at an arbitrary slot (see
//! `docs/decoupled_consensus.md`).
//!
//! The engine itself lives in a [`SharedDecoupledNode`], shared with the
//! Beacon API (duties, submissions, block production) and the p2p layer
//! (gossip). This actor ticks it on the `Δ` grid and imports every decoupled
//! block the beacon state transition accepted.

use ethlambda_state_transition::beacon::decoupled::block_input;
use ethlambda_state_transition::beacon::decoupled_node::SharedDecoupledNode;
use ethlambda_storage::{CommitteeCache, ForkCheckpoints};
use ethlambda_types::ShortRoot;
use ethlambda_types::beacon::containers::{BeaconState, SignedBeaconBlock};
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::signing::compute_epoch_at_slot;
use ethlambda_types::primitives::H256;
use tracing::{debug, info, warn};

use crate::BlockChainServer;

impl BlockChainServer {
    /// Whether the decoupled fork rules the current slot.
    pub(crate) fn decoupled_active(&self) -> bool {
        if self.decoupled.is_none() {
            return false;
        }
        let config = self.store.config();
        let slot = self.wall_clock_slot();
        config.fork_at_epoch(compute_epoch_at_slot(slot)) == ForkName::Decoupled
    }

    /// Run the engine's ticks up to now. `true` when any ran.
    pub(crate) fn decoupled_tick(&mut self) -> bool {
        let Some(node) = &self.decoupled else {
            return false;
        };
        node.lock().expect("decoupled node lock poisoned").sync()
    }

    /// Import a decoupled block that `fork_choice::on_block` just accepted.
    /// `post_state` is its post-state, whose shuffling covers the previous
    /// slot's committee its votes are counted against.
    pub(crate) fn decoupled_import(
        &mut self,
        block: &SignedBeaconBlock,
        post_state: &BeaconState,
        committees: &CommitteeCache,
    ) {
        let Some(node) = &self.decoupled else {
            return;
        };
        let SignedBeaconBlock::Decoupled(decoupled) = block else {
            return;
        };
        let config = self.store.config();
        let input = match block_input(post_state, decoupled, committees, &config) {
            Ok(input) => input,
            Err(err) => {
                warn!(slot = block.slot(), %err, "Cannot read a decoupled block's votes");
                return;
            }
        };
        let root = input.root;
        let attestations: Vec<_> = decoupled
            .message
            .body
            .combined_attestations
            .iter()
            .cloned()
            .collect();
        let result = node
            .lock()
            .expect("decoupled node lock poisoned")
            .import_block(&input, &attestations);
        match result {
            Ok(()) => debug!(
                slot = input.slot,
                block_root = %ShortRoot(&root.0),
                votes = input.votes.len(),
                attestations = input.attestations.len(),
                "Decoupled engine imported block"
            ),
            Err(err) => warn!(
                slot = input.slot,
                block_root = %ShortRoot(&root.0),
                %err,
                "Decoupled engine refused a block the state transition accepted"
            ),
        }
    }

    /// Make the engine's head the store's head. Returns the head root.
    pub(crate) fn decoupled_update_head(&mut self) -> Option<H256> {
        let node = self.decoupled.as_ref()?;
        let (head, status) = {
            let node = node.lock().expect("decoupled node lock poisoned");
            (node.head(), node.status())
        };
        if !self.store.has_state(&head).unwrap_or(false) {
            // The engine's anchor before the store has it as a block, or a
            // block whose state is still being written: keep the old head.
            return None;
        }
        let previous = self.store.beacon_head().map(|(_, root)| root);
        if previous != Some(head) {
            let _ = self
                .store
                .update_checkpoints(ForkCheckpoints::head_only(head))
                .inspect_err(|err| warn!(%err, "Failed to record the decoupled head"));
            info!(
                head_slot = status.head.slot,
                head_root = %ShortRoot(&head.0),
                confirmed_slot = status.confirmed.slot,
                fg_confirmed_slot = status.fg_confirmed.map(|block| block.slot),
                locks = status.locks.len(),
                finalized_slot = status.finalized.slot,
                finalized_height = status.finalized_height,
                justified_slot = status.justified.slot,
                justified_height = status.justified_height,
                "Decoupled head"
            );
        }
        if let Some((head_slot, _)) = self.store.beacon_head() {
            crate::metrics::update_head_slot(head_slot);
        }
        Some(head)
    }

    /// The `safe` and `finalized` blocks for `forkchoiceUpdated`: the engine's
    /// confirmed (locked) and finalized tips. A lock survives bounded
    /// asynchrony, which is what `safe` promises.
    pub(crate) fn decoupled_safe_and_finalized(&self) -> Option<(H256, H256)> {
        let node = self.decoupled.as_ref()?;
        let node = node.lock().expect("decoupled node lock poisoned");
        let engine = node.engine();
        Some((engine.confirmed().root, engine.finalized().root))
    }
}

/// Rebuild a fresh engine from the blocks a previous run stored.
///
/// The legacy FFG finality never advances in the decoupled fork, so
/// `LiveChain` still holds every block since genesis; they are imported in
/// slot order, each with its own post-state for the committee lookup. The
/// rebuilt node is a node that joins: every block is stamped now, and it holds
/// no locks until its first confirmation updates.
pub fn replay(store: &ethlambda_storage::Store, node: &SharedDecoupledNode) -> usize {
    let mut blocks: Vec<(u64, H256)> = store
        .block_index()
        .into_iter()
        .map(|(root, (slot, _parent))| (slot, root))
        .filter(|(slot, _)| *slot > 0)
        .collect();
    blocks.sort();
    let config = store.config();
    let committees = store.committee_cache();
    let mut node = node.lock().expect("decoupled node lock poisoned");
    node.sync();
    let mut imported = 0;
    for (slot, root) in blocks {
        let Ok(Some(block)) = store.get_signed_block(&root) else {
            continue;
        };
        let SignedBeaconBlock::Decoupled(decoupled) = &block else {
            continue;
        };
        let Ok(Some(state)) = store.get_state(&root) else {
            warn!(slot, block_root = %ShortRoot(&root.0), "No post-state to replay a decoupled block with");
            continue;
        };
        let Ok(input) = block_input(&state, decoupled, &committees, &config) else {
            continue;
        };
        let attestations: Vec<_> = decoupled
            .message
            .body
            .combined_attestations
            .iter()
            .cloned()
            .collect();
        if node.import_block(&input, &attestations).is_ok() {
            imported += 1;
        }
    }
    imported
}

/// Re-export for `main.rs`.
pub use ethlambda_state_transition::beacon::decoupled_node::DecoupledNode;

/// The node's handle type.
pub type Shared = SharedDecoupledNode;
