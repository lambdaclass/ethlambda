//! The `execution_optimistic` flag a Beacon API response carries.
//!
//! The rule lives on [`Store`] (`ethlambda_storage`'s `execution_optimistic`
//! module), since the chain actor's event stream answers the same question
//! and cannot depend on this crate. These are its names here, and the tests
//! below pin it against the API's own fixtures.

use ethlambda_storage::Store;
use ethlambda_types::primitives::H256;

/// Whether the payload of the block at `root` is not yet vouched for by the
/// execution layer: an envelope response's flag. See
/// [`Store::is_beacon_payload_optimistic`].
pub(crate) fn envelope_is_optimistic(store: &Store, root: H256) -> bool {
    store.is_beacon_payload_optimistic(root)
}

/// Whether the block at `root` rests on a payload that is not `VALID`: a
/// block, state or header response's flag. See
/// [`Store::is_beacon_block_optimistic`].
pub(crate) fn block_is_optimistic(store: &Store, root: H256) -> bool {
    store.is_beacon_block_optimistic(root)
}

#[cfg(test)]
mod tests {
    use ethlambda_types::beacon::fork_choice::PayloadStatusEnum;

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

    #[test]
    fn a_block_the_store_cannot_produce_is_optimistic() {
        let fixture = gloas_fixture();
        let unknown = H256::from([0xee; 32]);
        assert!(block_is_optimistic(&fixture.store, unknown));
        assert!(envelope_is_optimistic(&fixture.store, unknown));
    }

    #[test]
    fn a_gloas_anchor_with_an_unknown_parent_is_not_optimistic() {
        let mut fixture = gloas_fixture();
        let block = crate::test_utils::gloas_beacon_block(
            500,
            H256::from([0xab; 32]),
            H256::ZERO,
            H256::ZERO,
        );
        let root = block.message_hash_tree_root();
        fixture
            .store
            .insert_signed_block(root, block)
            .expect("insert");

        assert!(!block_is_optimistic(&fixture.store, root));
    }

    #[test]
    fn judging_a_block_records_nothing_in_the_store() {
        let fixture = gloas_fixture();
        let (g2, _) = fixture.g2;
        // Drop whatever import recorded, so the helper has to derive.
        let before = fixture.store.payload_link(&g2);
        block_is_optimistic(&fixture.store, g2);
        assert_eq!(fixture.store.payload_link(&g2), before);
    }
}
