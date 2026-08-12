//! Beacon blocks waiting on a parent the store does not have yet.
//!
//! Checkpoint sync anchors two epochs behind the head, so the first gossiped
//! blocks all descend from blocks in the unfetched gap. Dropping them would
//! work — the range fetch reaches those slots eventually — but it wastes the
//! freshest blocks on the network and leaves a window where nothing at the head
//! can ever be imported. Holding them by parent root and releasing them when
//! that parent lands closes the gap from both ends.
//!
//! The same shape as lean's `pending_blocks` / `pending_block_parents` pair on
//! `BlockChainServer`, as a type of its own: the ordering guarantee here is the
//! thing that separates a follower that backfills from one that only tracks the
//! tip, and it deserves tests that need neither an actor nor a store.

use std::collections::{HashMap, HashSet};

use ethlambda_types::beacon::containers::SignedBeaconBlock;
use ethlambda_types::beacon::primitives::{Root, Slot};

/// Most blocks held at once, across every parent.
///
/// Two epochs of gap is 64 blocks, and forks add a few more; 1024 is far above
/// anything a healthy run reaches, and low enough that a peer feeding
/// fabricated parents cannot grow this without bound. A gossiped block is a few
/// hundred kilobytes at most, so the ceiling is well under a gigabyte.
pub(crate) const MAX_PENDING_BEACON_BLOCKS: usize = 1024;

/// What happened to a block handed to [`PendingBeaconBlocks::insert`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Pending {
    /// Held. The root carried is the deepest ancestor this buffer knows nothing
    /// about: the one worth asking a peer for, since fetching the immediate
    /// parent would only reveal another block already buffered here.
    Buffered(Root),
    /// The buffer is at [`MAX_PENDING_BEACON_BLOCKS`] and the block was dropped.
    Full,
}

/// Blocks held by the parent root they are waiting on.
#[derive(Default)]
pub(crate) struct PendingBeaconBlocks {
    /// Held blocks, keyed by the parent root each is waiting on, paired with
    /// their own root so neither draining nor pruning has to merkleize again.
    by_parent: HashMap<Root, Vec<(Root, SignedBeaconBlock)>>,
    /// Every held block's own root mapped to the parent it waits on, so a newly
    /// arriving block can walk up to the deepest root nothing knows about.
    parent_of: HashMap<Root, Root>,
    len: usize,
}

impl PendingBeaconBlocks {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Hold `block` until its parent imports.
    pub(crate) fn insert(&mut self, block: SignedBeaconBlock) -> Pending {
        let root = block.message_hash_tree_root();
        let parent = block.parent_root();

        if self.parent_of.contains_key(&root) {
            // A duplicate on the gossip mesh. Report the same ancestor without
            // counting the block twice.
            return Pending::Buffered(self.deepest_missing(parent));
        }
        if self.len >= MAX_PENDING_BEACON_BLOCKS {
            return Pending::Full;
        }

        self.parent_of.insert(root, parent);
        self.by_parent
            .entry(parent)
            .or_default()
            .push((root, block));
        self.len += 1;
        Pending::Buffered(self.deepest_missing(parent))
    }

    /// The deepest root this buffer knows nothing about, walking up from `root`.
    ///
    /// Terminates: blocks name their parents by hash, so a cycle would need a
    /// hash collision.
    fn deepest_missing(&self, root: Root) -> Root {
        let mut current = root;
        while let Some(&parent) = self.parent_of.get(&current) {
            current = parent;
        }
        current
    }

    /// Release every block waiting on `parent`, in ascending slot order.
    ///
    /// Slot order matters when a parent has more than one child: fork choice
    /// must see the earlier slot first, or a later sibling's import can move
    /// the head to a block whose own sibling has not been considered yet.
    pub(crate) fn take_children(&mut self, parent: Root) -> Vec<SignedBeaconBlock> {
        let Some(mut children) = self.by_parent.remove(&parent) else {
            return Vec::new();
        };
        children.sort_by_key(|(_, block)| block.slot());
        self.len -= children.len();
        children
            .into_iter()
            .map(|(root, block)| {
                self.parent_of.remove(&root);
                block
            })
            .collect()
    }

    /// Drop every held block at or below `slot`, returning how many went.
    ///
    /// Called when finalization advances: a block at or below the finalized
    /// slot can never become importable, so holding it only wastes the budget
    /// that a live fork needs.
    pub(crate) fn prune_below(&mut self, slot: Slot) -> usize {
        let mut removed = 0usize;
        self.by_parent.retain(|_, children| {
            children.retain(|(_, block)| {
                let keep = block.slot() > slot;
                if !keep {
                    removed += 1;
                }
                keep
            });
            !children.is_empty()
        });
        let surviving: HashSet<Root> = self
            .by_parent
            .values()
            .flatten()
            .map(|(root, _)| *root)
            .collect();
        self.parent_of.retain(|root, _| surviving.contains(root));
        self.len -= removed;
        removed
    }

    /// Held blocks, across every parent.
    ///
    /// Exported as `lean_sync_pending_blocks`, the series the operator
    /// procedure reads to tell a stalled fetch from a healthy one.
    pub(crate) fn len(&self) -> usize {
        self.len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::beacon::containers::phase0;

    /// A block with an empty body, for tests that care only about its slot and
    /// its place in the chain. Phase0-shaped: nothing here reads a
    /// fork-specific field.
    fn block(slot: Slot, parent_root: Root) -> SignedBeaconBlock {
        SignedBeaconBlock::Phase0(phase0::SignedBeaconBlock {
            message: phase0::BeaconBlock {
                slot,
                proposer_index: 0,
                parent_root,
                state_root: Root::zero(),
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
        })
    }

    /// A chain where slot `s` has parent slot `s - 1`. Returns the blocks
    /// keyed by slot together with their roots, so a test can name any link.
    fn chain(from: Slot, to: Slot, anchor_root: Root) -> Vec<(Slot, Root, SignedBeaconBlock)> {
        let mut built = Vec::new();
        let mut parent = anchor_root;
        for slot in from..=to {
            let signed = block(slot, parent);
            let root = signed.message_hash_tree_root();
            built.push((slot, root, signed));
            parent = root;
        }
        built
    }

    /// Drive the buffer the way the block handler does: import a block, release
    /// its children, import each of those, and so on. Returns the slots in the
    /// order they became importable.
    fn drain_cascade(pending: &mut PendingBeaconBlocks, imported_root: Root) -> Vec<Slot> {
        let mut order = Vec::new();
        let mut queue = std::collections::VecDeque::from(pending.take_children(imported_root));
        while let Some(block) = queue.pop_front() {
            order.push(block.slot());
            for child in pending.take_children(block.message_hash_tree_root()) {
                queue.push_back(child);
            }
        }
        order
    }

    /// The failure this whole plan exists to prevent.
    ///
    /// A follower that tracks the tip without backfilling accepts gossip blocks
    /// whose parents it has never seen. Its head climbs while justification and
    /// finalization stay frozen, because nothing it imported is actually on a
    /// chain it can evaluate. Two properties separate that behaviour from a
    /// correct one, and this test asserts both:
    ///
    ///   1. While the gap is unfilled, no block at the tip is importable. A
    ///      tip-only follower has them all importable immediately.
    ///   2. Once the gap is walked forward from the anchor, every held block
    ///      comes out exactly once, contiguously, in ascending slot order. A
    ///      tip-only follower has nothing left to release here, so the drained
    ///      order is empty.
    #[test]
    fn tip_blocks_are_not_importable_until_the_gap_is_filled() {
        let anchor = Root::repeat_byte(0xa0);
        // The anchor is at slot 64; the live head is at 128. Slots 65..=119 are
        // the gap the range fetch will bring; 120..=128 arrive on gossip first.
        let full = chain(65, 128, anchor);
        let mut pending = PendingBeaconBlocks::new();

        // --- The tip arrives first, out of a chain the node cannot evaluate.
        for (slot, _, signed) in &full {
            if *slot >= 120 {
                assert_eq!(
                    pending.insert(signed.clone()),
                    Pending::Buffered(full[(119 - 65) as usize].1),
                    "every tip block must point at the same unknown ancestor, \
                     the last block of the gap"
                );
            }
        }
        assert_eq!(pending.len(), 9, "slots 120 through 128 are held");

        // Property 1: with the gap unfilled, nothing at the tip is importable.
        // The anchor's children are not here, and neither is anything else the
        // node currently has a state for.
        assert!(
            drain_cascade(&mut pending, anchor).is_empty(),
            "a tip block must not become importable just because it arrived"
        );
        assert_eq!(pending.len(), 9, "and nothing may be silently dropped");

        // --- The range fetch walks the gap forward from the anchor.
        let mut applied = Vec::new();
        for (slot, root, _) in full.iter().filter(|(slot, _, _)| *slot < 120) {
            applied.push(*slot);
            applied.extend(drain_cascade(&mut pending, *root));
        }

        // Property 2: the held tip blocks came out, once each, in slot order,
        // and the whole chain is contiguous from the anchor to the head.
        let expected: Vec<Slot> = (65..=128).collect();
        assert_eq!(
            applied, expected,
            "the chain must be applied contiguously from the anchor to the head"
        );
        assert_eq!(pending.len(), 0, "the buffer must be empty afterwards");
    }

    #[test]
    fn an_orphan_reports_its_own_parent_as_the_root_to_fetch() {
        let mut pending = PendingBeaconBlocks::new();
        let parent = Root::repeat_byte(9);

        let outcome = pending.insert(block(100, parent));

        assert_eq!(outcome, Pending::Buffered(parent));
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn a_chain_of_orphans_reports_the_deepest_one() {
        // Fetching the immediate parent of the newest block would return a
        // block already held here, costing a round trip and learning nothing.
        let mut pending = PendingBeaconBlocks::new();
        let anchor = Root::repeat_byte(9);
        let built = chain(100, 104, anchor);

        for (_, _, signed) in &built {
            assert_eq!(pending.insert(signed.clone()), Pending::Buffered(anchor));
        }

        assert_eq!(pending.len(), 5);
    }

    #[test]
    fn a_duplicate_is_not_counted_twice() {
        let mut pending = PendingBeaconBlocks::new();
        let parent = Root::repeat_byte(9);

        pending.insert(block(100, parent));
        pending.insert(block(100, parent));

        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn the_buffer_refuses_rather_than_growing_without_bound() {
        // A peer feeding fabricated parents must not be able to grow this.
        let mut pending = PendingBeaconBlocks::new();
        for slot in 0..MAX_PENDING_BEACON_BLOCKS as u64 {
            let parent = Root::from_low_u64_be(slot + 1_000_000);
            assert!(matches!(
                pending.insert(block(slot, parent)),
                Pending::Buffered(_)
            ));
        }

        let overflow = pending.insert(block(9_999, Root::repeat_byte(7)));

        assert_eq!(overflow, Pending::Full);
        assert_eq!(pending.len(), MAX_PENDING_BEACON_BLOCKS);
    }

    #[test]
    fn children_come_out_in_slot_order_and_only_once() {
        let mut pending = PendingBeaconBlocks::new();
        let parent = Root::repeat_byte(9);
        pending.insert(block(103, parent));
        pending.insert(block(101, parent));
        pending.insert(block(102, parent));

        let released = pending.take_children(parent);

        let slots: Vec<Slot> = released.iter().map(|b| b.slot()).collect();
        assert_eq!(slots, vec![101, 102, 103]);
        assert_eq!(pending.len(), 0);
        assert!(pending.take_children(parent).is_empty());
    }

    #[test]
    fn a_root_with_no_children_releases_nothing() {
        let mut pending = PendingBeaconBlocks::new();
        pending.insert(block(100, Root::repeat_byte(9)));

        assert!(pending.take_children(Root::repeat_byte(1)).is_empty());
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn finalization_drops_what_can_never_import() {
        let mut pending = PendingBeaconBlocks::new();
        let anchor = Root::repeat_byte(9);
        for (_, _, signed) in chain(100, 109, anchor) {
            pending.insert(signed);
        }

        let dropped = pending.prune_below(104);

        assert_eq!(dropped, 5, "slots 100 through 104");
        assert_eq!(pending.len(), 5);
        // The surviving blocks still resolve their ancestry, so the walk did
        // not leave a dangling entry behind in `parent_of`.
        let survivor_parent = Root::repeat_byte(0xff);
        assert_eq!(
            pending.insert(block(110, survivor_parent)),
            Pending::Buffered(survivor_parent)
        );
    }
}
