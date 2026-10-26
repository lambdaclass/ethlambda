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
//!
//! Everything here only reads the store, and an answer that cannot be worked
//! out is optimistic: this flag gates signing, so an unknown gets the cautious
//! reading. The payload links are therefore looked up or derived here instead
//! of through fork choice, whose `ensure_payload_link` records what it derives
//! and panics on a failed read.

use ethlambda_storage::Store;
use ethlambda_types::{
    beacon::{
        containers::SignedBeaconBlock,
        fork_choice::{BlockPayloadLink, PayloadStatus, PayloadStatusEnum},
    },
    primitives::H256,
};

/// `root`'s payload link: the one fork choice recorded, or one derived from the
/// stored blocks without recording it. `None` when it cannot be worked out.
///
/// The derivation is `derive_payload_link`'s: a gloas block's parent status is
/// FULL when its bid names the parent's block hash (or the parent is
/// pre-gloas), and unknown when the parent is not stored, which is the anchor.
fn payload_link(store: &Store, root: H256) -> Option<BlockPayloadLink> {
    if let Some(link) = store.payload_link(&root) {
        return Some(link);
    }
    match store.get_signed_block(&root).ok()?? {
        SignedBeaconBlock::Phase0(_)
        | SignedBeaconBlock::Altair(_)
        | SignedBeaconBlock::Bellatrix(_)
        | SignedBeaconBlock::Capella(_)
        | SignedBeaconBlock::Deneb(_)
        | SignedBeaconBlock::Electra(_)
        | SignedBeaconBlock::Fulu(_) => Some(BlockPayloadLink::PreGloas),
        SignedBeaconBlock::Gloas(block) => {
            let parent_status = match store.get_signed_block(&block.message.parent_root).ok()? {
                None => None,
                Some(SignedBeaconBlock::Gloas(parent)) => {
                    let wanted = block
                        .message
                        .body
                        .signed_execution_payload_bid
                        .message
                        .parent_block_hash;
                    let held = parent
                        .message
                        .body
                        .signed_execution_payload_bid
                        .message
                        .block_hash;
                    Some(if wanted == held {
                        PayloadStatus::Full
                    } else {
                        PayloadStatus::Empty
                    })
                }
                Some(_) => Some(PayloadStatus::Full),
            };
            Some(BlockPayloadLink::Gloas { parent_status })
        }
        // A lean block is never in a beacon store.
        SignedBeaconBlock::Lean(_) => None,
    }
}

/// Whether the payload of the block at `root` is not (known to be) `VALID`.
///
/// A pre-gloas block's payload is its own, so it reads the optimistic set; a
/// gloas root reads its recorded verdict, where none recorded is
/// `NOT_VALIDATED`. Unknown links are not valid.
fn payload_is_not_valid(store: &Store, root: H256) -> bool {
    match payload_link(store, root) {
        Some(BlockPayloadLink::PreGloas) => store.is_beacon_optimistic(root),
        Some(BlockPayloadLink::Gloas { .. }) => {
            store.beacon_block_payload_status(root) != PayloadStatusEnum::Valid
        }
        None => true,
    }
}

/// Whether the payload of the block at `root` is not yet vouched for by the
/// execution layer.
///
/// An unrecorded gloas verdict reads as `NOT_VALIDATED`, so an envelope the
/// store holds but has no verdict for is optimistic.
pub(crate) fn envelope_is_optimistic(store: &Store, root: H256) -> bool {
    payload_is_not_valid(store, root)
}

/// Whether the block at `root` rests on a payload that is not `VALID`.
///
/// Walks back from `root` through the blocks whose payload branch the child
/// skipped (`Empty`) until it reaches the FULL payload the chain actually
/// builds on, then reads that payload's verdict. A pre-gloas block is its own
/// payload, so it reads the optimistic set as before. A chain that runs out
/// (an anchor whose parent is below the retained window) has nothing left to
/// doubt, so it is not optimistic. A block or link that cannot be read is
/// optimistic.
pub(crate) fn block_is_optimistic(store: &Store, root: H256) -> bool {
    let mut current = root;
    loop {
        let Some(link) = payload_link(store, current) else {
            return true;
        };
        if !link.is_gloas() {
            return store.is_beacon_optimistic(current);
        }
        let parent = match store.get_signed_block(&current) {
            Ok(Some(block)) => block.parent_root(),
            Ok(None) | Err(_) => return true,
        };
        match link.parent_status() {
            Some(PayloadStatus::Full) => return payload_is_not_valid(store, parent),
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
