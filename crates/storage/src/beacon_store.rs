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
use std::sync::Arc;

use ethlambda_types::beacon::containers::{BeaconState, Checkpoint, SignedBeaconBlock};
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::primitives::{Root, Slot};
use libssz::{SszDecode, SszEncode};
use libssz_derive::{SszDecode as SszDecodeDerive, SszEncode as SszEncodeDerive};

use crate::api::Table;
use crate::store::{
    BEACON_ANCHORS_KEPT, KEY_BEACON_ANCHORS, Store, decode_state_value, encode_state_value,
};

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

    /// The full-state snapshot stored under `root`, if it is one of the
    /// finalized anchors.
    ///
    /// `None` for every state above finalization: those are not written at all.
    /// Reconstructing one is `ethlambda_beacon::fork_choice::block_state`'s job,
    /// since it needs `stf::state_transition`, which this crate cannot call.
    pub fn beacon_state_snapshot(&self, root: Root) -> Option<BeaconState> {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::States, &beacon_root_key(root))
            .expect("get")
            .map(|bytes| decode_state_value(&bytes))
    }

    /// Writes `state` as the snapshot for `root`, without touching the anchor
    /// list. [`Store::promote_beacon_anchor`] is what a finalization advance
    /// should call; this is for the bootstrap anchor, which has no predecessor
    /// to prune against.
    pub fn insert_beacon_state_snapshot(&mut self, root: Root, state: &BeaconState) {
        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .put_batch(
                Table::States,
                vec![(beacon_root_key(root), encode_state_value(state))],
            )
            .expect("put beacon state snapshot");
        batch.commit().expect("commit");
        self.push_beacon_anchor(root);
    }

    /// The memoized post-state for `root`, if it is still resident.
    ///
    /// A miss is not an error; see `BeaconCaches`. Returns an `Arc` rather
    /// than a clone because `get_weight` reads the justified checkpoint's state
    /// once per call and a mainnet state is ~350 MB.
    pub fn cached_beacon_state(&self, root: Root) -> Option<Arc<BeaconState>> {
        self.beacon_cache.lock().unwrap().states.get(&root).cloned()
    }

    /// Memoizes `state` as `root`'s post-state.
    ///
    /// Takes `&self`, not `&mut self`: `get_weight` and the rest of the
    /// read-only helpers derive on a miss and must be able to record the result.
    pub fn cache_beacon_state(&self, root: Root, state: Arc<BeaconState>) {
        self.beacon_cache.lock().unwrap().states.put(root, state);
    }

    /// The memoized state at `checkpoint`'s epoch boundary, if it is still
    /// resident. See [`Store::cached_beacon_state`].
    pub fn cached_checkpoint_state(&self, checkpoint: &Checkpoint) -> Option<Arc<BeaconState>> {
        self.beacon_cache
            .lock()
            .unwrap()
            .checkpoint_states
            .get(&(checkpoint.epoch, checkpoint.root))
            .cloned()
    }

    /// Memoizes `state` as the state at `checkpoint`'s epoch boundary.
    pub fn cache_checkpoint_state(&self, checkpoint: Checkpoint, state: Arc<BeaconState>) {
        self.beacon_cache
            .lock()
            .unwrap()
            .checkpoint_states
            .put((checkpoint.epoch, checkpoint.root), state);
    }

    /// The roots of the finalized anchor states held in `States`, oldest first.
    pub fn beacon_anchors(&self) -> Vec<Root> {
        let view = self.backend.begin_read().expect("read view");
        let bytes = view
            .get(Table::Metadata, KEY_BEACON_ANCHORS)
            .expect("get")
            .expect("a beacon store always has an anchor list");
        bytes.chunks_exact(32).map(Root::from_slice).collect()
    }

    /// Records `root` as the newest finalized anchor, writing `state` as its
    /// snapshot and dropping everything the two-anchor rule no longer keeps.
    ///
    /// Three things happen together, and they have to: the new snapshot is
    /// written, any anchor beyond [`BEACON_ANCHORS_KEPT`] has its snapshot
    /// deleted, and `LiveChain` is pruned below the oldest anchor still kept.
    ///
    /// That last bound is what makes the pruning safe rather than merely
    /// bounded. Fork choice never walks below its own finalized checkpoint, and
    /// the finalized checkpoint is at or after the newest anchor, which is at or
    /// after the oldest kept one. So every ancestry walk and every replay
    /// terminates inside the retained window by construction.
    pub fn promote_beacon_anchor(&mut self, root: Root, state: &BeaconState) {
        if self.beacon_anchors().last() == Some(&root) {
            return;
        }
        self.insert_beacon_state_snapshot(root, state);

        let anchors = self.beacon_anchors();
        let oldest = *anchors.first().expect("just pushed at least one anchor");
        let (prune_below, _parent_root) = self
            .beacon_block_entry(oldest)
            .expect("an anchor's own block is always stored");

        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .delete_range(
                Table::LiveChain,
                &0u64.to_be_bytes(),
                &prune_below.to_be_bytes(),
            )
            .expect("prune beacon live chain index");
        batch.commit().expect("commit");
    }

    /// Appends `root` to the anchor list, deleting the snapshot of anything
    /// that falls out of [`BEACON_ANCHORS_KEPT`].
    fn push_beacon_anchor(&mut self, root: Root) {
        let mut anchors = self.beacon_anchors();
        if anchors.contains(&root) {
            return;
        }
        anchors.push(root);

        let mut dropped = Vec::new();
        while anchors.len() > BEACON_ANCHORS_KEPT {
            dropped.push(beacon_root_key(anchors.remove(0)));
        }

        let encoded: Vec<u8> = anchors.iter().flat_map(|root| root.0).collect();
        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .put_batch(
                Table::Metadata,
                vec![(KEY_BEACON_ANCHORS.to_vec(), encoded)],
            )
            .expect("put beacon anchors");
        batch
            .delete_batch(Table::States, dropped)
            .expect("delete superseded anchor snapshots");
        batch.commit().expect("commit");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ethlambda_types::beacon::containers::BeaconState;
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

    /// A `BeaconState` whose shape is irrelevant to the test: these exercise
    /// the snapshot, cache, and anchor machinery, none of which reads a state
    /// field. `BeaconState::Lean` is the one variant this crate can build
    /// without `ethlambda-beacon`'s helpers, and `encode_state_value` handles
    /// it explicitly for exactly that reason.
    fn state(genesis_time: u64) -> BeaconState {
        BeaconState::Lean(ethlambda_types::state::State::from_genesis(
            genesis_time,
            Vec::new(),
        ))
    }

    #[test]
    fn a_state_snapshot_round_trips_through_the_states_table() {
        let mut store = beacon_store();
        let root = Root::repeat_byte(1);

        assert_eq!(store.beacon_state_snapshot(root), None);
        store.insert_beacon_state_snapshot(root, &state(42));
        assert_eq!(store.beacon_state_snapshot(root), Some(state(42)));
    }

    #[test]
    fn the_state_cache_is_shared_across_store_clones() {
        // `Store` is cloned into the RPC and P2P layers, so a cache that was
        // not shared would silently double the resident state count.
        let store = beacon_store();
        let clone = store.clone();
        let root = Root::repeat_byte(2);

        store.cache_beacon_state(root, Arc::new(state(42)));

        assert_eq!(
            clone.cached_beacon_state(root).map(|s| (*s).clone()),
            Some(state(42))
        );
    }

    #[test]
    fn promoting_a_third_anchor_drops_the_first() {
        let mut store = beacon_store();
        // Three blocks in a line, each keyed under its own root, so each anchor
        // has a real slot to prune against.
        let mut parent = Root::zero();
        let mut roots = Vec::new();
        for slot in 0..3u64 {
            let signed = block(slot, parent);
            let root = signed.message_hash_tree_root();
            store.insert_beacon_block(root, &signed);
            roots.push(root);
            parent = root;
        }

        for root in &roots {
            store.promote_beacon_anchor(*root, &state(42));
        }

        assert_eq!(store.beacon_anchors(), vec![roots[1], roots[2]]);
        assert_eq!(store.beacon_state_snapshot(roots[0]), None);
        assert_eq!(store.beacon_state_snapshot(roots[1]), Some(state(42)));
        assert_eq!(store.beacon_state_snapshot(roots[2]), Some(state(42)));
    }

    #[test]
    fn promoting_an_anchor_prunes_the_index_below_the_oldest_kept_one() {
        let mut store = beacon_store();
        let mut parent = Root::zero();
        let mut roots = Vec::new();
        for slot in 0..5u64 {
            let signed = block(slot, parent);
            let root = signed.message_hash_tree_root();
            store.insert_beacon_block(root, &signed);
            roots.push(root);
            parent = root;
        }

        // Anchors at slots 2 and 4: the oldest kept one is slot 2, so slots 0
        // and 1 leave the index and slots 2 to 4 stay.
        store.promote_beacon_anchor(roots[2], &state(42));
        store.promote_beacon_anchor(roots[4], &state(42));

        let index = store.beacon_block_index();
        assert_eq!(index.len(), 3);
        assert!(!index.contains_key(&roots[0]));
        assert!(!index.contains_key(&roots[1]));
        assert!(index.contains_key(&roots[2]));
        assert!(index.contains_key(&roots[4]));
    }
}
