//! Beacon Chain support on the DB-backed [`Store`].
//!
//! Split out of `store.rs` for size rather than for layering: these are `impl
//! Store` blocks like the ones there, over the same backend and the same tables.
//!
//! # What lives where
//!
//! | Fork choice needs | Table | Key | Value |
//! |---|---|---|---|
//! | the block itself, for the state transition | `BlockBodies` | root | fork selector, then `SignedBeaconBlock` SSZ |
//! | `slot` and `parent_root`, for tree walks | `BlockHeaders` | root | [`BeaconBlockEntry`] SSZ |
//! | the children of a root | `LiveChain` | slot ‖ root | parent root |
//! | a finalized anchor state | `States` | root | fork selector, then `BeaconState` SSZ |
//! | the unrealized justification of a block | `BeaconForkChoice` | root | beacon `Checkpoint` SSZ |
//!
//! `BlockRoots` is not written on this path. Nothing serves canonical-by-slot
//! beacon queries until sub-project E, and an index nothing reads is an
//! invariant nothing checks.
//!
//! # These accessors do not return `Result`
//!
//! Deliberately, and matching what `store.rs` already does: every lean accessor
//! there `expect`s on backend I/O internally and returns `Result` only for
//! conditions a caller can act on. `ethlambda_beacon::fork_choice` reaches these
//! from ~130 sites whose own error type lives in `ethlambda-types` and therefore
//! cannot carry a storage error, so returning one here would buy a
//! `.map_err(|err| Error::Storage(err.to_string()))` at each of them and nothing
//! else.

use std::collections::HashMap;

use ethlambda_types::beacon::containers::SignedBeaconBlock;
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::primitives::{Root, Slot};
use libssz::{SszDecode, SszEncode};
use libssz_derive::{SszDecode as SszDecodeDerive, SszEncode as SszEncodeDerive};

use crate::api::Table;
use crate::store::Store;

/// Every block in the beacon fork-choice window, as `root -> (slot, parent_root)`.
///
/// Built once per tree walk and passed down, rather than re-read per hop:
/// `get_weight` calls `get_ancestor` once per active validator, so a point
/// lookup per hop would multiply a scan the specification already writes as
/// naive by a backend round trip.
pub type BeaconBlockIndex = HashMap<Root, (Slot, Root)>;

/// What fork choice reads off a block without decoding its body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SszEncodeDerive, SszDecodeDerive)]
struct BeaconBlockEntry {
    slot: Slot,
    parent_root: Root,
}

/// A `BlockHeaders`/`BlockBodies`/`States` key: the block root's 32 bytes.
///
/// Raw bytes rather than `to_ssz()`, deliberately: a beacon `Root` and a lean
/// `H256` are different Rust types over the same 32 bytes, and writing the key
/// out this way makes it plain that the two layouts agree even though the two
/// chains never share a directory.
fn beacon_root_key(root: Root) -> Vec<u8> {
    root.0.to_vec()
}

/// A `LiveChain` key: slot big-endian, then the root, so lexicographic order is
/// slot order. Mirrors `store.rs`'s own `encode_slot_root_key`.
fn beacon_slot_root_key(slot: Slot, root: Root) -> Vec<u8> {
    let mut key = slot.to_be_bytes().to_vec();
    key.extend_from_slice(&root.0);
    key
}

/// The inverse of [`beacon_slot_root_key`].
fn decode_beacon_slot_root_key(bytes: &[u8]) -> (Slot, Root) {
    let slot = u64::from_be_bytes(bytes[..8].try_into().expect("valid slot bytes"));
    (slot, Root::from_slice(&bytes[8..]))
}

/// Encodes a `BlockBodies` value: the block's fork selector, then its SSZ.
fn encode_beacon_block_value(block: &SignedBeaconBlock) -> Vec<u8> {
    let mut bytes = vec![block.fork_name().selector()];
    bytes.extend_from_slice(&block.to_ssz());
    bytes
}

/// The inverse of [`encode_beacon_block_value`].
fn decode_beacon_block_value(bytes: &[u8]) -> SignedBeaconBlock {
    let (tag, ssz) = bytes.split_first().expect("block value is never empty");
    let fork = ForkName::from_selector(*tag).expect("block value carries a known fork selector");
    SignedBeaconBlock::from_ssz(fork, ssz).expect("valid signed beacon block")
}

impl Store {
    /// Records `block` under `root`, which must be the root of its unsigned
    /// message (`SignedBeaconBlock::message_hash_tree_root`).
    ///
    /// Writes all three rows in one batch: a half-written block would be visible
    /// to the children scan without being decodable.
    pub fn insert_beacon_block(&mut self, root: Root, block: &SignedBeaconBlock) {
        let entry = BeaconBlockEntry {
            slot: block.slot(),
            parent_root: block.parent_root(),
        };
        let key = beacon_root_key(root);

        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .put_batch(Table::BlockHeaders, vec![(key.clone(), entry.to_ssz())])
            .expect("put beacon block entry");
        batch
            .put_batch(
                Table::BlockBodies,
                vec![(key, encode_beacon_block_value(block))],
            )
            .expect("put beacon block");
        batch
            .put_batch(
                Table::LiveChain,
                vec![(
                    beacon_slot_root_key(entry.slot, root),
                    entry.parent_root.0.to_vec(),
                )],
            )
            .expect("put beacon live chain index");
        batch.commit().expect("commit");
    }

    /// The block stored under `root`, body and all.
    pub fn beacon_block(&self, root: Root) -> Option<SignedBeaconBlock> {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::BlockBodies, &beacon_root_key(root))
            .expect("get")
            .map(|bytes| decode_beacon_block_value(&bytes))
    }

    /// `root`'s slot and parent root, without decoding its body.
    pub fn beacon_block_entry(&self, root: Root) -> Option<(Slot, Root)> {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::BlockHeaders, &beacon_root_key(root))
            .expect("get")
            .map(|bytes| {
                let entry = BeaconBlockEntry::from_ssz_bytes(&bytes).expect("valid block entry");
                (entry.slot, entry.parent_root)
            })
    }

    /// Whether a block is stored under `root`.
    pub fn has_beacon_block(&self, root: Root) -> bool {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::BlockHeaders, &beacon_root_key(root))
            .expect("get")
            .is_some()
    }

    /// Every stored block as `root -> (slot, parent_root)`. See
    /// [`BeaconBlockIndex`] for why a tree walk takes this rather than reading
    /// per hop.
    pub fn beacon_block_index(&self) -> BeaconBlockIndex {
        let view = self.backend.begin_read().expect("read view");
        view.prefix_iterator(Table::LiveChain, &[])
            .expect("iterator")
            .filter_map(Result::ok)
            .map(|(key, value)| {
                let (slot, root) = decode_beacon_slot_root_key(&key);
                (root, (slot, Root::from_slice(&value)))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ethlambda_types::beacon::containers::phase0;

    use super::*;
    use crate::backend::InMemoryBackend;

    /// A signed block with an empty body and a zero signature. Phase0-shaped
    /// because nothing under test here reads a fork-specific field, matching
    /// the helper `fork_choice.rs`'s own unit tests use.
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
                    graffiti: Root::zero(),
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

    /// An empty beacon store on an in-memory backend.
    fn beacon_store() -> Store {
        Store::init_beacon(Arc::new(InMemoryBackend::new()), 0)
    }

    #[test]
    fn a_beacon_block_round_trips_through_the_store() {
        let mut store = beacon_store();
        let signed = block(3, Root::repeat_byte(1));
        let root = signed.message_hash_tree_root();

        store.insert_beacon_block(root, &signed);

        assert!(store.has_beacon_block(root));
        assert_eq!(store.beacon_block(root), Some(signed));
        assert_eq!(
            store.beacon_block_entry(root),
            Some((3, Root::repeat_byte(1)))
        );
    }

    #[test]
    fn an_unknown_root_has_no_block() {
        let store = beacon_store();
        assert!(!store.has_beacon_block(Root::repeat_byte(9)));
        assert_eq!(store.beacon_block(Root::repeat_byte(9)), None);
        assert_eq!(store.beacon_block_entry(Root::repeat_byte(9)), None);
    }

    #[test]
    fn the_block_index_carries_every_parent_link() {
        let mut store = beacon_store();
        let genesis = block(0, Root::zero());
        let genesis_root = genesis.message_hash_tree_root();
        let child = block(1, genesis_root);
        let child_root = child.message_hash_tree_root();
        // A sibling at the same slot, so the index has to key on root rather
        // than on slot.
        let sibling = block(1, Root::repeat_byte(7));
        let sibling_root = sibling.message_hash_tree_root();

        store.insert_beacon_block(genesis_root, &genesis);
        store.insert_beacon_block(child_root, &child);
        store.insert_beacon_block(sibling_root, &sibling);

        let index = store.beacon_block_index();
        assert_eq!(index.len(), 3);
        assert_eq!(index[&genesis_root], (0, Root::zero()));
        assert_eq!(index[&child_root], (1, genesis_root));
        assert_eq!(index[&sibling_root], (1, Root::repeat_byte(7)));
    }
}
