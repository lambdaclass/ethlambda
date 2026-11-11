//! Invalidating an execution payload the host first accepted.
//!
//! fork-choice.md has no handler for it: `on_execution_payload_envelope`
//! records a payload once the execution engine has not refused it, and an
//! optimistic answer (`SYNCING`, `ACCEPTED`) lets it in before the engine has
//! executed it. When the engine later answers `INVALID` (a later call about
//! the same payload, or a descendant's `latestValidHash`), optimistic sync's
//! rule applies (`sync/optimistic.md`): an invalidated payload and everything
//! built on it is no longer viable, and its weight counts for nothing.
//!
//! In the engine's terms, [`Store::invalidate_payload`] takes the block's
//! `Full` node out of the tree (the payload is no longer verified, and never
//! will be again) and removes every block built on it, directly or through a
//! descendant. Every walk, view and confirmation then reads a tree without
//! them, the way it already reads a tree without pruned branches:
//!
//! * `get_node_children` no longer offers the `Full` node, so the frame's
//!   tree, its viable heads, `get_head`, `get_ac_vote_head`,
//!   `get_ac_proposal`, the confirmation walk and the FG source (the
//!   fast-confirmed path filtered by the viable subtree) never reach it or
//!   anything under it;
//! * a vote for the `Full` node or for a removed block no longer resolves, so
//!   it supports nothing (it still counts as participation, as a vote for an
//!   unknown block does);
//! * `is_fg_contest` and `has_viable_descendant` no longer see the removed
//!   blocks;
//! * the block itself stays, with its `Empty` branch.
//!
//! What the store keeps by node is moved to the deepest node left above it,
//! the block's `Pending` node: a live lock keeps its deadline there (as
//! `unlock` moves a lock to an ancestor), and `latest_confirmed` and the saved
//! confirmations move with it. The fast-confirmed path drops the nodes.
//!
//! The one thing it does not touch is what the finality gadget has committed
//! to: when the justified or the finalized block builds on the payload, the
//! frame itself would go, and optimistic sync's answer to an invalidated
//! justified or finalized block is an operator's, not the protocol's. That
//! case is reported ([`PayloadInvalidation::Committed`]) and nothing changes.

use std::collections::HashSet;

use ethlambda_types::primitives::H256;

use crate::store::Store;
use crate::types::{ForkChoiceNode, HeightCheckpoint, PayloadStatus};

/// What [`Store::invalidate_payload`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadInvalidation {
    /// The payload is invalid from now on: its `Full` node left the tree, and
    /// the blocks built on it (listed, `root`'s `Full` children and their
    /// subtrees) were removed.
    Invalidated { removed_blocks: Vec<H256> },
    /// The payload, or the block itself (built on an invalidated payload),
    /// was invalidated before.
    AlreadyInvalidated,
    /// The finality gadget's justified or finalized block (`checkpoint`)
    /// builds on the payload. Nothing changed: invalidating it would take the
    /// gadget's frame with it.
    Committed { checkpoint: HeightCheckpoint },
    /// The block is not held: unknown, pruned off a branch that conflicts with
    /// the finalized block, or an ancestor of the finalized block whose `Full`
    /// branch the finalized chain does not take. Nothing to do.
    NotHeld,
}

impl Store {
    /// Whether the host invalidated `root`'s payload.
    pub fn is_payload_invalidated(&self, root: &H256) -> bool {
        self.invalid_payloads.contains_key(root)
    }

    /// Whether `root` was removed because its chain builds on an invalidated
    /// payload.
    pub fn is_block_invalidated(&self, root: &H256) -> bool {
        self.invalid_blocks.contains_key(root)
    }

    /// The execution engine found `root`'s payload invalid: drop its `Full`
    /// node and every block built on it, unless the finality gadget's
    /// justified or finalized block builds on it (see the module
    /// documentation).
    ///
    /// The payload need not have been verified: a payload refused before it
    /// was ever recorded is remembered too, so its envelope and the blocks
    /// built on it are refused when they arrive.
    pub fn invalidate_payload(&mut self, root: &H256) -> PayloadInvalidation {
        if self.is_payload_invalidated(root) || self.is_block_invalidated(root) {
            return PayloadInvalidation::AlreadyInvalidated;
        }
        let Some(slot) = self.block_slot(root) else {
            if self.finalized_ancestors.get(root) == Some(&PayloadStatus::Full) {
                return PayloadInvalidation::Committed {
                    checkpoint: self.finalized_checkpoint,
                };
            }
            return PayloadInvalidation::NotHeld;
        };
        let full = ForkChoiceNode::full(*root);
        for checkpoint in [self.finalized_checkpoint, self.justified_checkpoint] {
            if self.is_ancestor(&ForkChoiceNode::pending(checkpoint.root), &full) {
                return PayloadInvalidation::Committed { checkpoint };
            }
        }

        self.payloads.remove(root);
        self.invalid_payloads.insert(*root, slot);

        let full_children: Vec<H256> = self
            .block(root)
            .map(|block| block.children.clone())
            .unwrap_or_default()
            .into_iter()
            .filter(|child| {
                self.block(child)
                    .is_some_and(|child| child.parent_payload_status == PayloadStatus::Full)
            })
            .collect();
        let removed_blocks: Vec<H256> = full_children
            .iter()
            .flat_map(|child| self.block_subtree(child))
            .collect();
        let removed: HashSet<H256> = removed_blocks.iter().copied().collect();

        // What the store keeps by node moves up to the block's `Pending` node,
        // the deepest node left above everything that goes.
        let is_gone = |node: &ForkChoiceNode| *node == full || removed.contains(&node.root);
        let fallback = ForkChoiceNode::pending(*root);
        for lock in self.locks.values_mut() {
            if is_gone(lock) {
                *lock = fallback;
            }
        }
        for confirmation in self.saved_confirmations.values_mut() {
            if is_gone(confirmation) {
                *confirmation = fallback;
            }
        }
        if is_gone(&self.latest_confirmed) {
            self.latest_confirmed = fallback;
        }
        self.fast_confirmed_path.retain(|node| !is_gone(node));

        for removed_root in &removed_blocks {
            self.payloads.remove(removed_root);
            let Some(block) = self.blocks.remove(removed_root) else {
                continue;
            };
            self.invalid_blocks.insert(*removed_root, block.slot);
            if let Some(roots) = self.blocks_by_slot.get_mut(&block.slot) {
                roots.retain(|other| other != removed_root);
            }
        }
        self.blocks_by_slot.retain(|_, roots| !roots.is_empty());
        // Every removed block's parent is `root` or another removed block.
        if let Some(block) = self.blocks.get_mut(root) {
            block.children.retain(|child| !removed.contains(child));
        }
        PayloadInvalidation::Invalidated { removed_blocks }
    }
}
