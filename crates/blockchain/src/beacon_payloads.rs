//! Execution-layer bookkeeping for gloas payloads.
//!
//! Before gloas a block carries its payload, so the execution client's verdict
//! on it is the block's and the optimistic-sync machinery in
//! `ethlambda_state_transition::beacon::fork_choice` works on blocks. In gloas
//! the payload arrives later, in an envelope, and fork choice weighs a FULL and
//! an EMPTY node per block. A payload the execution client rejects must take
//! only its FULL node (and whatever builds on it) with it; the block and its
//! EMPTY branch stay viable. This module is that second granularity:
//!
//! ```text
//! envelope ──► newPayloadV5 ──► VALID    apply, status Valid
//!                           ├─► SYNCING  apply, status Syncing (NOT_VALIDATED)
//!                           └─► INVALID  do not apply, status Invalid,
//!                                        drop children built on the FULL node
//!
//! forkchoiceUpdated(V4) ──► VALID    Syncing payloads on the head's ancestry -> Valid
//!                       └─► INVALID  first invalid payload after latestValidHash:
//!                                    unverify it, drop its FULL children
//! ```
//!
//! # Which hash names what
//!
//! A gloas block's EL hash depends on the node: its FULL node is the payload
//! the envelope revealed (the bid's `block_hash`); its EMPTY node is the last
//! payload before it (the bid's `parent_block_hash`). `SignedBeaconBlock::
//! execution_block_hash` is `None` for gloas on purpose, so the helpers here
//! read the bid.

use std::collections::HashMap;

use ethlambda_engine::ForkchoiceStateV1;
use ethlambda_state_transition::beacon::fork_choice::{
    self, PayloadStatus, PayloadStatusEnum, PayloadValidity,
};
use ethlambda_storage::Store;
use ethlambda_types::ShortRoot;
use ethlambda_types::beacon::containers::{SignedBeaconBlock, gloas};
use ethlambda_types::beacon::primitives::ExecutionBlockHash;
use ethlambda_types::beacon::signing::compute_start_slot_at_epoch;
use ethlambda_types::primitives::H256;
use tracing::{error, warn};

use crate::BlockChainServer;

/// The bid a gloas block carries, or `None` for any other fork.
pub(crate) fn bid_of(block: &SignedBeaconBlock) -> Option<&gloas::ExecutionPayloadBid> {
    match block {
        SignedBeaconBlock::Gloas(inner) => {
            Some(&inner.message.body.signed_execution_payload_bid.message)
        }
        SignedBeaconBlock::Phase0(_)
        | SignedBeaconBlock::Altair(_)
        | SignedBeaconBlock::Bellatrix(_)
        | SignedBeaconBlock::Capella(_)
        | SignedBeaconBlock::Deneb(_)
        | SignedBeaconBlock::Electra(_)
        | SignedBeaconBlock::Fulu(_)
        | SignedBeaconBlock::Lean(_) => None,
    }
}

/// The execution hash of the payload `root` carries on the chain, or `None` if
/// it carries none: a pre-gloas block's own payload (cached at import), or a
/// gloas block's verified payload (cached when the envelope is applied, and
/// read back off the bid for a payload verified before a restart emptied the
/// cache).
pub(crate) fn payload_hash_of(store: &Store, root: H256) -> Option<ExecutionBlockHash> {
    if let Some(hash) = store.beacon_el_block_hash(root) {
        return Some(hash);
    }
    if !store.has_verified_payload(&root) {
        return None;
    }
    let block = store.get_signed_block(&root).ok().flatten()?;
    bid_of(&block).map(|bid| bid.block_hash)
}

/// The execution hash a checkpoint root stands for in `forkchoiceUpdated`.
///
/// A gloas block is `bid.parent_block_hash` (gloas `fork-choice.md`, "Modified
/// `notify_forkchoice_updated`": the payload a checkpoint block builds on is
/// the one a node can know to be final, since the block's own payload may
/// never be revealed). A pre-gloas block keeps its own payload's hash.
fn checkpoint_hash(store: &Store, root: H256) -> ExecutionBlockHash {
    if let Some(block) = store.get_signed_block(&root).ok().flatten()
        && let Some(bid) = bid_of(&block)
    {
        return bid.parent_block_hash;
    }
    store.beacon_el_block_hash(root).unwrap_or(H256::ZERO)
}

/// What `forkchoiceUpdated` should carry for the current head, or `None` when
/// there is nothing to say yet.
pub(crate) struct ForkchoicePlan {
    pub(crate) state: ForkchoiceStateV1,
    /// Whether the head block is gloas or later, which selects
    /// `engine_forkchoiceUpdatedV4` (with custody columns) over V3.
    pub(crate) gloas: bool,
}

/// Builds the `forkchoiceUpdated` payload for `head_root`.
///
/// Head: a gloas head's FULL node is the payload its envelope revealed
/// (`bid.block_hash`), its EMPTY node the payload before it
/// (`bid.parent_block_hash`). `None` while the head's payload status has not
/// been computed (a gloas head is ambiguous without it), and while the head
/// hash is zero, as before.
///
/// Finalized: the finalized block's `bid.parent_block_hash` (spec). Safe: the
/// spec's `get_safe_execution_block_hash` is fast-confirmation based, which
/// this follower does not run, so the justified checkpoint block's
/// `bid.parent_block_hash` stands in (see `docs/spec_deviations.md`). A
/// pre-gloas checkpoint block, including one under a gloas head, uses its own
/// payload hash.
pub(crate) fn forkchoice_plan(store: &Store, head_root: H256) -> Option<ForkchoicePlan> {
    let head_block = store.get_signed_block(&head_root).ok().flatten();
    let head_bid = head_block.as_ref().and_then(bid_of);
    let head_block_hash = match head_bid {
        Some(bid) => match store.head_payload_status()? {
            PayloadStatus::Full => bid.block_hash,
            PayloadStatus::Empty | PayloadStatus::Pending => bid.parent_block_hash,
        },
        None => store.beacon_el_block_hash(head_root).unwrap_or(H256::ZERO),
    };
    if head_block_hash.is_zero() {
        return None;
    }
    let state = ForkchoiceStateV1 {
        head_block_hash,
        safe_block_hash: checkpoint_hash(store, store.beacon_justified_checkpoint().root),
        finalized_block_hash: checkpoint_hash(store, store.beacon_finalized_checkpoint().root),
    };
    Some(ForkchoicePlan {
        state,
        gloas: head_bid.is_some(),
    })
}

/// The nearest ancestor-or-self of `from` whose payload hash is `hash`: the
/// block a `forkchoiceUpdated` verdict about `hash` is about.
pub(crate) fn payload_holder(
    store: &Store,
    index: &HashMap<H256, (u64, H256)>,
    from: H256,
    hash: ExecutionBlockHash,
) -> Option<H256> {
    let mut cursor = from;
    loop {
        if payload_hash_of(store, cursor) == Some(hash) {
            return Some(cursor);
        }
        cursor = index.get(&cursor)?.1;
    }
}

/// The block whose payload is the first invalid one on `holder`'s chain, per
/// `optimistic-sync.md`'s `latestValidHash` table, reading payloads rather
/// than blocks.
///
/// [`fork_choice::resolve_invalid_block`] walks parents while each carries a
/// cached payload hash, which stops at the first gloas block whose payload was
/// never revealed. Here a root with no payload is skipped, since an EMPTY node
/// inherits its parent's payload and a payload built on a FULL ancestor
/// descends from it in the execution layer whatever sits between.
///
/// | `latest_valid_hash` | result |
/// |---|---|
/// | a payload hash found on this chain | the next payload-carrying block after it |
/// | all zeroes | the earliest payload-carrying ancestor |
/// | `None`, or a hash not on this chain | `holder` itself |
pub(crate) fn resolve_invalid_payload(
    store: &Store,
    index: &HashMap<H256, (u64, H256)>,
    holder: H256,
    latest_valid_hash: Option<ExecutionBlockHash>,
) -> H256 {
    let Some(latest_valid_hash) = latest_valid_hash else {
        return holder;
    };
    let mut condemned = holder;
    let mut cursor = holder;
    while let Some(&(_slot, parent)) = index.get(&cursor) {
        cursor = parent;
        match payload_hash_of(store, cursor) {
            Some(hash) if hash == latest_valid_hash => return condemned,
            Some(_) => condemned = cursor,
            None => {}
        }
    }
    if latest_valid_hash.is_zero() {
        condemned
    } else {
        // Ran off the top of what this store indexes without finding it:
        // `optimistic-sync.md` says to treat it as `null`.
        holder
    }
}

/// Moves `root` and every optimistic ancestor to validated: pre-gloas blocks
/// leave `optimistic_roots`, gloas payloads recorded `NOT_VALIDATED` become
/// `VALID`. `optimistic-sync.md`: a block's ancestors transition with it.
///
/// A single walk of the whole ancestry rather than
/// [`fork_choice::mark_validated`]'s stop at the first non-optimistic parent,
/// since a gloas block with a settled payload can sit between two optimistic
/// ones. Skipped entirely, with no `block_index` scan, when nothing is
/// optimistic.
pub(crate) fn mark_payloads_validated(store: &mut Store, root: H256) {
    fork_choice::mark_validated(store, root);
    if !store.has_unvalidated_block_payloads() && !store.has_beacon_optimistic_roots() {
        return;
    }
    let index = store.block_index();
    let mut cursor = root;
    while let Some(&(slot, parent)) = index.get(&cursor) {
        store.remove_beacon_optimistic_root(cursor);
        if store.has_verified_payload(&cursor)
            && store.beacon_block_payload_status(cursor).is_not_validated()
        {
            store.insert_beacon_block_payload_status(cursor, slot, PayloadStatusEnum::Valid);
        }
        cursor = parent;
    }
}

impl BlockChainServer {
    /// [`Self::apply_forkchoice_verdict`] for a gloas head, whose `head_hash`
    /// names a payload.
    ///
    /// `VALID` promotes every optimistic payload on the holder's ancestry;
    /// `INVALID` condemns from the first payload after `latestValidHash`.
    /// `SYNCING` and `ACCEPTED` change nothing.
    pub(crate) fn apply_gloas_forkchoice_verdict(
        &mut self,
        head_root: H256,
        head_hash: ExecutionBlockHash,
        status: &ethlambda_engine::PayloadStatusV1,
    ) {
        let verdict = crate::beacon_engine::verdict(status);
        let (PayloadValidity::Validated | PayloadValidity::Invalidated { .. }) = verdict else {
            return;
        };
        let index = self.store.block_index();
        let Some(holder) = payload_holder(&self.store, &index, head_root, head_hash) else {
            warn!(
                head_root = %ShortRoot(&head_root.0),
                "No block on the head's chain carries the payload forkchoiceUpdated named"
            );
            return;
        };
        match verdict {
            PayloadValidity::Validated => mark_payloads_validated(&mut self.store, holder),
            PayloadValidity::Invalidated { latest_valid_hash } => {
                if self.condemn_payload_chain(holder, latest_valid_hash) {
                    // Not `recompute_beacon_head`: this runs inside
                    // `forkchoiceUpdated`'s own response handling.
                    self.update_head_from_fork_choice();
                }
            }
            PayloadValidity::Optimistic | PayloadValidity::NotRequired => {}
        }
    }

    /// Applies an `INVALID` verdict about the payload of `holder` (an imported
    /// block, or a gloas block whose envelope was just refused).
    ///
    /// Resolves how far the verdict reaches ([`resolve_invalid_payload`]) and
    /// condemns that block's payload: a pre-gloas block is removed with its
    /// subtree, as `forkchoiceUpdated` always did; a gloas payload loses its
    /// FULL node and every child built on it, and the block itself stays with
    /// its EMPTY branch. Returns whether anything left fork choice.
    pub(crate) fn condemn_payload_chain(
        &mut self,
        holder: H256,
        latest_valid_hash: Option<ExecutionBlockHash>,
    ) -> bool {
        let index = self.store.block_index();
        let condemned = resolve_invalid_payload(&self.store, &index, holder, latest_valid_hash);
        let mut removed = self.condemn_gloas_payload(condemned, &index);
        // The holder's own payload is invalid whichever ancestor the verdict
        // reached; when it is a gloas payload it must not stay FULL.
        if condemned != holder {
            let index = self.store.block_index();
            removed |= self.condemn_gloas_payload(holder, &index);
        }
        removed
    }

    /// Records `root`'s payload as `INVALID`, removes its FULL node, and drops
    /// every child built on it, held or imported.
    ///
    /// A pre-gloas `root` takes the block-level path instead: its payload is
    /// the block's, so the whole subtree goes. Refuses a block at or below
    /// finality, like [`fork_choice::invalidate_subtree`].
    fn condemn_gloas_payload(&mut self, root: H256, index: &HashMap<H256, (u64, H256)>) -> bool {
        let Some(block) = self.store.get_signed_block(&root).ok().flatten() else {
            return false;
        };
        let Some(bid) = bid_of(&block) else {
            return fork_choice::invalidate_subtree(&mut self.store, root) > 0;
        };
        let hash = bid.block_hash;
        let slot = block.slot();
        let finalized = self.store.beacon_finalized_checkpoint();
        if root == finalized.root || slot <= compute_start_slot_at_epoch(finalized.epoch) {
            error!(
                condemned = %ShortRoot(&root.0),
                "The execution client condemned a finalized payload; refusing to invalidate. \
                 The execution and consensus layers disagree about finalized history and \
                 this node needs operator attention"
            );
            return false;
        }

        warn!(
            %slot,
            block_root = %ShortRoot(&root.0),
            payload_hash = %ShortRoot(&hash.0),
            "Execution client found a payload invalid; dropping its FULL node"
        );
        self.store
            .insert_beacon_block_payload_status(root, slot, PayloadStatusEnum::Invalid);
        let mut removed = self.store.remove_verified_payload(&root);

        // Children held for this payload build on it by construction.
        if let Some(held) = self.envelopes.blocks_awaiting_parent_payload.remove(&root) {
            for (child_root, _slot) in held {
                self.discard_pending_subtree(child_root);
            }
            self.publish_envelope_queues();
        }

        // Imported children whose bid names this payload as their parent's.
        let full_children: Vec<H256> = index
            .iter()
            .filter(|(_, (_, parent))| *parent == root)
            .map(|(child, _)| *child)
            .filter(|child| {
                self.store
                    .get_signed_block(child)
                    .ok()
                    .flatten()
                    .and_then(|block| bid_of(&block).map(|bid| bid.parent_block_hash == hash))
                    .unwrap_or(false)
            })
            .collect();
        for child in full_children {
            removed |= fork_choice::invalidate_subtree(&mut self.store, child) > 0;
        }
        removed
    }
}
