//! The `execution_optimistic` flag a Beacon API response carries.
//!
//! Before gloas a block's payload ran inside the block, so the flag is whether
//! that block sits in the store's optimistic set. From gloas on the payload
//! travels in a separate envelope that may arrive late or never, so two
//! different questions share the flag:
//!
//! - an envelope response is optimistic iff that payload's verdict is not
//!   `VALID` ([`envelope_is_optimistic`]);
//! - a block, state or header response is optimistic iff the latest FULL
//!   payload the block builds on is not `VALID` ([`block_is_optimistic`]).
//!   The block's own payload does not count: the block itself was imported
//!   without it, and a withheld payload must not make the chain look
//!   unverified.

use ethlambda_state_transition::beacon::fork_choice::{self, PayloadStatus, PayloadStatusEnum};
use ethlambda_storage::Store;
use ethlambda_types::primitives::H256;

/// Whether the payload of the block at `root` is not yet vouched for by the
/// execution layer.
///
/// An unrecorded gloas verdict reads as `NOT_VALIDATED`, so an envelope the
/// store holds but has no verdict for is optimistic.
pub(crate) fn envelope_is_optimistic(store: &Store, root: H256) -> bool {
    fork_choice::block_payload_status(store, root) != PayloadStatusEnum::Valid
}

/// Whether the block at `root` rests on a payload that is not `VALID`.
///
/// Walks back from `root` through the blocks whose payload branch the child
/// skipped (`Empty`) until it reaches the FULL payload the chain actually
/// builds on, then reads that payload's verdict. A pre-gloas block is its own
/// payload, so it reads the optimistic set as before. A chain that runs out
/// (an anchor whose parent is below the retained window) has nothing left to
/// doubt, so it is not optimistic.
///
/// A link that cannot be derived is reported optimistic: this flag gates
/// signing, so the answer for an unknown is the cautious one.
pub(crate) fn block_is_optimistic(store: &Store, root: H256) -> bool {
    let mut current = root;
    loop {
        if fork_choice::ensure_payload_link(store, current).is_err() {
            return true;
        }
        let Some(link) = store.payload_link(&current) else {
            // The block is not in the store, so there is no payload to doubt.
            return false;
        };
        if !link.is_gloas() {
            return store.is_beacon_optimistic(current);
        }
        let Ok(Some(block)) = store.get_signed_block(&current) else {
            return false;
        };
        let parent = block.parent_root();
        match link.parent_status() {
            Some(PayloadStatus::Full) => {
                return fork_choice::block_payload_status(store, parent)
                    != PayloadStatusEnum::Valid;
            }
            Some(PayloadStatus::Empty) => current = parent,
            // A pending parent status never comes out of a block's own bid.
            Some(PayloadStatus::Pending) | None => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{beacon_fixture, gloas_fixture};

    #[test]
    fn a_pre_gloas_block_reads_the_optimistic_set() {
        let mut fixture = beacon_fixture(64);
        let root = fixture.head_root;
        assert!(!block_is_optimistic(&fixture.store, root));

        fixture
            .store
            .insert_beacon_optimistic_root(root, fixture.head_slot);
        assert!(block_is_optimistic(&fixture.store, root));
    }

    #[test]
    fn a_gloas_block_is_optimistic_iff_the_payload_it_builds_on_is_not_valid() {
        let mut fixture = gloas_fixture();
        let (g1, g1_slot) = fixture.g1;
        let (g2, _) = fixture.g2;
        let (g3, _) = fixture.g3;

        // g1 builds on its pre-gloas parent, which is not optimistic.
        assert!(!block_is_optimistic(&fixture.store, g1));
        // g2 builds on g1's payload, which has no verdict yet.
        assert!(block_is_optimistic(&fixture.store, g2));
        // g3 skipped g2's payload, so it too rests on g1's.
        assert!(block_is_optimistic(&fixture.store, g3));

        fixture
            .store
            .insert_beacon_block_payload_status(g1, g1_slot, PayloadStatusEnum::Valid);
        assert!(!block_is_optimistic(&fixture.store, g2));
        assert!(!block_is_optimistic(&fixture.store, g3));

        // g1's own payload being doubtful does not make g1 optimistic.
        fixture
            .store
            .insert_beacon_block_payload_status(g1, g1_slot, PayloadStatusEnum::Syncing);
        assert!(!block_is_optimistic(&fixture.store, g1));
        assert!(block_is_optimistic(&fixture.store, g2));
    }

    #[test]
    fn a_gloas_block_on_an_optimistic_pre_gloas_parent_is_optimistic() {
        let mut fixture = gloas_fixture();
        let head = fixture.head_root;
        fixture.store.insert_beacon_optimistic_root(head, 65);
        assert!(block_is_optimistic(&fixture.store, fixture.g1.0));
    }
}
