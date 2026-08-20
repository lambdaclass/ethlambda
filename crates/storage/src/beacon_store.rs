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
//! `BlockRoots` is still not written on this path.
//! [`Store::beacon_canonical_blocks_by_range`], which is what serves
//! `beacon_blocks_by_range`, walks parent links back from the fork-choice head
//! instead. The walk is bounded by the retained window and answers with the
//! chain the head actually descends from, which a slot-keyed index could not do
//! on its own: a slot holds several blocks as soon as there is a fork, and
//! picking between them is exactly what the parent links decide.
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
use ethlambda_types::beacon::fork_choice::{LatestMessage, PowBlock};
use ethlambda_types::beacon::primitives::{Root, Slot};
use libssz::{SszDecode, SszEncode};
use libssz_derive::{SszDecode as SszDecodeDerive, SszEncode as SszEncodeDerive};

use crate::api::Table;
use crate::store::{
    BEACON_ANCHORS_KEPT, BEACON_PINNED_STATE_CAPACITY, KEY_BEACON_ANCHORS, KEY_BEACON_FINALIZED,
    KEY_BEACON_HIGHEST_IMPORTED_SLOT, KEY_BEACON_JUSTIFIED, KEY_BEACON_UNREALIZED_FINALIZED,
    KEY_BEACON_UNREALIZED_JUSTIFIED, KEY_TIME, Store, decode_state_value, encode_state_value,
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
    /// Writes all four rows in one batch: a half-written block would be visible
    /// to the children scan without being decodable, and a watermark ahead of
    /// the block it counts would make forward sync skip that block's slot.
    pub fn insert_beacon_block(&mut self, root: Root, block: &SignedBeaconBlock) {
        let entry = BeaconBlockEntry {
            slot: block.slot(),
            parent_root: block.parent_root(),
        };
        let key = beacon_root_key(root);

        let mut batch = self.backend.begin_write().expect("write batch");
        if entry.slot > self.beacon_highest_imported_slot() {
            let watermark = vec![(
                KEY_BEACON_HIGHEST_IMPORTED_SLOT.to_vec(),
                entry.slot.to_ssz(),
            )];
            batch
                .put_batch(Table::Metadata, watermark)
                .expect("put beacon highest imported slot");
        }
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

    /// Whether [`Store::cached_checkpoint_state`] would return `Some`.
    ///
    /// A `false` here means "not resident", never "does not exist": every caller
    /// derives on a miss. See [`BeaconCaches`](crate::store::BeaconCaches).
    pub fn has_checkpoint_state(&self, checkpoint: &Checkpoint) -> bool {
        self.cached_checkpoint_state(checkpoint).is_some()
    }

    /// Memoizes `state` as the state at `checkpoint`'s epoch boundary.
    pub fn cache_checkpoint_state(&self, checkpoint: Checkpoint, state: Arc<BeaconState>) {
        self.beacon_cache
            .lock()
            .unwrap()
            .checkpoint_states
            .put((checkpoint.epoch, checkpoint.root), state);
    }

    /// The `current_justified_checkpoint` of `root`'s post-state, if it is
    /// still remembered.
    ///
    /// `get_voting_source` needs exactly this one field for a block in the
    /// current epoch, and materializing a whole ~350MB state to read it was
    /// costing a 26-block replay per epoch on mainnet. A miss is not an error:
    /// the caller falls back to the state, same as every other beacon cache.
    pub fn block_justified_checkpoint(&self, root: Root) -> Option<Checkpoint> {
        self.beacon_cache
            .lock()
            .unwrap()
            .block_justified
            .get(&root)
            .copied()
    }

    /// Remembers `checkpoint` as `root`'s post-state justified checkpoint.
    pub fn cache_block_justified_checkpoint(&self, root: Root, checkpoint: Checkpoint) {
        self.beacon_cache
            .lock()
            .unwrap()
            .block_justified
            .put(root, checkpoint);
    }

    /// The root of `root`'s post-state, if this node computed it.
    ///
    /// Only ever holds roots the node merkleized itself, never one read off a
    /// block header: the value feeds `state.state_roots`, which is a consensus
    /// input. See
    /// [`BEACON_STATE_ROOT_CACHE_CAPACITY`](crate::store::BEACON_STATE_ROOT_CACHE_CAPACITY).
    pub fn cached_beacon_state_root(&self, root: Root) -> Option<Root> {
        self.beacon_cache
            .lock()
            .unwrap()
            .state_roots
            .get(&root)
            .copied()
    }

    /// Remembers `state_root` as the root of `root`'s post-state.
    pub fn cache_beacon_state_root(&self, root: Root, state_root: Root) {
        self.beacon_cache
            .lock()
            .unwrap()
            .state_roots
            .put(root, state_root);
    }

    /// The pinned post-state for `root`, if it is held.
    ///
    /// Checked by `block_state` after the recency cache and before the on-disk
    /// snapshot, so a pin turns a whole-epoch replay into a lookup. See
    /// [`BEACON_PINNED_STATE_CAPACITY`](crate::store::BEACON_PINNED_STATE_CAPACITY).
    pub fn pinned_beacon_state(&self, root: Root) -> Option<Arc<BeaconState>> {
        self.beacon_cache
            .lock()
            .unwrap()
            .pinned_states
            .get(&root)
            .cloned()
    }

    /// Pins `state` as `root`'s post-state, evicting the lowest-slot pin once
    /// the capacity is exceeded.
    ///
    /// Eviction is by slot rather than by insertion order because what makes a
    /// pin worth keeping is being *recent enough to still be reached*: the
    /// roots asked for by distance are always the newest boundaries, and a pin
    /// below finalization can never be asked for again. Takes `&self` for the
    /// same reason [`Store::cache_beacon_state`] does.
    pub fn pin_beacon_state(&self, root: Root, state: Arc<BeaconState>) {
        let mut cache = self.beacon_cache.lock().unwrap();
        cache.pinned_states.insert(root, state);
        while cache.pinned_states.len() > BEACON_PINNED_STATE_CAPACITY {
            let oldest = cache
                .pinned_states
                .iter()
                .min_by_key(|(_, state)| state.slot())
                .map(|(root, _)| *root)
                .expect("a map over capacity is not empty");
            cache.pinned_states.remove(&oldest);
        }
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

    /// The slot of the oldest anchor still kept, which is the oldest slot this
    /// node can serve a block for: `promote_beacon_anchor` prunes the block
    /// index below it, and nothing below the bootstrap anchor was ever fetched.
    ///
    /// This is what fulu's `Status` v2 calls `earliest_available_slot`.
    pub fn beacon_anchor_slot(&self) -> Slot {
        self.beacon_anchors()
            .first()
            .and_then(|root| self.beacon_block_entry(*root))
            .map_or(0, |(slot, _parent_root)| slot)
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

    /// The beacon store's clock, as **Unix seconds**.
    ///
    /// Shares `Metadata["time"]` with the lean clock, which counts 800 ms
    /// intervals since genesis instead. That is safe precisely because a
    /// directory holds one chain: nothing ever reads the key through the other
    /// chain's accessor. The unit difference is why there are two accessors and
    /// not one.
    pub fn beacon_time(&self) -> u64 {
        self.beacon_metadata(KEY_TIME)
    }

    /// Sets [`Store::beacon_time`].
    pub fn set_beacon_time(&mut self, time: u64) {
        self.set_beacon_metadata(KEY_TIME, &time);
    }

    /// Genesis, as Unix seconds. Read off the anchor state at bootstrap.
    pub fn beacon_genesis_time(&self) -> u64 {
        self.config().genesis_time
    }

    /// The highest slot the store holds a block for.
    ///
    /// The beacon counterpart to what [`Store::head_slot`] answers for lean, and
    /// deliberately not the same question: that one reads `Metadata["head"]`,
    /// which only the lean bootstrap and `update_checkpoints` ever write, so
    /// reaching it on a beacon store panics. The LMD GHOST head is
    /// `ethlambda_beacon::fork_choice::get_head`, which weighs every active
    /// validator over the whole filtered tree and is far too expensive for the
    /// per-`Status` and per-tick reads this answers.
    ///
    /// Monotone, and a watermark rather than a chain tip: a block only imports
    /// once its parent is in the store, so this is the slot forward sync has
    /// reached, which is exactly what a peer's advertised head is compared
    /// against. A reorg lowers the head without lowering this, which is the
    /// right way round: the slots below it have already been fetched.
    pub fn beacon_highest_imported_slot(&self) -> Slot {
        self.beacon_metadata(KEY_BEACON_HIGHEST_IMPORTED_SLOT)
    }

    /// The justified checkpoint fork choice is currently descending from.
    pub fn beacon_justified_checkpoint(&self) -> Checkpoint {
        self.beacon_metadata(KEY_BEACON_JUSTIFIED)
    }

    /// Sets [`Store::beacon_justified_checkpoint`]. No monotonicity check: the
    /// specification's own `update_checkpoints` owns that rule.
    pub fn set_beacon_justified_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.set_beacon_metadata(KEY_BEACON_JUSTIFIED, &checkpoint);
    }

    /// The finalized checkpoint. Fork choice never descends below it.
    pub fn beacon_finalized_checkpoint(&self) -> Checkpoint {
        self.beacon_metadata(KEY_BEACON_FINALIZED)
    }

    /// Sets [`Store::beacon_finalized_checkpoint`].
    pub fn set_beacon_finalized_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.set_beacon_metadata(KEY_BEACON_FINALIZED, &checkpoint);
    }

    /// The highest justified checkpoint seen in any block's post-state, whether
    /// or not its own chain has an epoch boundary that reflects it yet.
    pub fn beacon_unrealized_justified_checkpoint(&self) -> Checkpoint {
        self.beacon_metadata(KEY_BEACON_UNREALIZED_JUSTIFIED)
    }

    /// Sets [`Store::beacon_unrealized_justified_checkpoint`].
    pub fn set_beacon_unrealized_justified_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.set_beacon_metadata(KEY_BEACON_UNREALIZED_JUSTIFIED, &checkpoint);
    }

    /// The finalized counterpart to
    /// [`Store::beacon_unrealized_justified_checkpoint`].
    pub fn beacon_unrealized_finalized_checkpoint(&self) -> Checkpoint {
        self.beacon_metadata(KEY_BEACON_UNREALIZED_FINALIZED)
    }

    /// Sets [`Store::beacon_unrealized_finalized_checkpoint`].
    pub fn set_beacon_unrealized_finalized_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.set_beacon_metadata(KEY_BEACON_UNREALIZED_FINALIZED, &checkpoint);
    }

    /// Reads an SSZ metadata value that `init_beacon` guarantees exists.
    fn beacon_metadata<T: SszDecode>(&self, key: &[u8]) -> T {
        let view = self.backend.begin_read().expect("read view");
        let bytes = view
            .get(Table::Metadata, key)
            .expect("get")
            .expect("a beacon store writes every metadata key at bootstrap");
        T::from_ssz_bytes(&bytes).expect("valid encoding")
    }

    /// Writes an SSZ metadata value.
    fn set_beacon_metadata<T: SszEncode>(&self, key: &[u8], value: &T) {
        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .put_batch(Table::Metadata, vec![(key.to_vec(), value.to_ssz())])
            .expect("put beacon metadata");
        batch.commit().expect("commit");
    }

    /// The most recent timely, uncontested block seen this slot, or the zero
    /// root if none has arrived yet or a new slot has reset it.
    pub fn proposer_boost_root(&self) -> Root {
        self.beacon.lock().unwrap().proposer_boost_root
    }

    /// Sets [`Store::proposer_boost_root`].
    pub fn set_proposer_boost_root(&mut self, root: Root) {
        self.beacon.lock().unwrap().proposer_boost_root = root;
    }

    /// Whether `root`'s block arrived before the attestation deadline of the
    /// slot fork choice was in when it was imported.
    pub fn block_timeliness(&self, root: Root) -> Option<bool> {
        self.beacon
            .lock()
            .unwrap()
            .block_timeliness
            .get(&root)
            .copied()
    }

    /// Sets [`Store::block_timeliness`].
    pub fn set_block_timeliness(&mut self, root: Root, timely: bool) {
        self.beacon
            .lock()
            .unwrap()
            .block_timeliness
            .insert(root, timely);
    }

    /// Whether `index` has been caught attesting to two conflicting things.
    pub fn is_equivocating(&self, index: u64) -> bool {
        self.beacon
            .lock()
            .unwrap()
            .equivocating_indices
            .contains(&index)
    }

    /// Records `index` as an equivocator. Never reversed: an equivocation is a
    /// fact about history, not a state that expires.
    pub fn insert_equivocating_index(&mut self, index: u64) {
        self.beacon
            .lock()
            .unwrap()
            .equivocating_indices
            .insert(index);
    }

    /// `index`'s most recent LMD GHOST vote.
    pub fn latest_message(&self, index: u64) -> Option<LatestMessage> {
        self.beacon
            .lock()
            .unwrap()
            .latest_messages
            .get(&index)
            .copied()
    }

    /// Calls `f` once per recorded LMD GHOST vote whose voter is not a known
    /// equivocator.
    ///
    /// A closure rather than a returned collection: on mainnet this holds one
    /// entry per validator that has ever attested, and copying two million of
    /// them out for every fork-choice head would cost more than the walk the
    /// caller is there to do. The lock is held for the whole pass, which the
    /// single-threaded chain actor never contends.
    ///
    /// The equivocation filter is applied here rather than left to the caller
    /// for the same reason: [`Store::is_equivocating`] takes the same lock this
    /// pass holds, and a `std::sync::Mutex` is not reentrant, so a caller doing
    /// the obvious thing inside `f` would deadlock rather than fail.
    pub fn for_each_non_equivocating_latest_message(&self, mut f: impl FnMut(u64, LatestMessage)) {
        let beacon = self.beacon.lock().unwrap();
        for (index, message) in &beacon.latest_messages {
            if beacon.equivocating_indices.contains(index) {
                continue;
            }
            f(*index, *message);
        }
    }

    /// Sets [`Store::latest_message`]. No monotonicity check: the
    /// specification's own `update_latest_messages` owns that rule.
    pub fn set_latest_message(&mut self, index: u64, message: LatestMessage) {
        self.beacon
            .lock()
            .unwrap()
            .latest_messages
            .insert(index, message);
    }

    /// The PoW block with this hash, if bellatrix's merge check has been told
    /// about it.
    pub fn beacon_pow_block(&self, hash: Root) -> Option<PowBlock> {
        self.beacon.lock().unwrap().pow_blocks.get(&hash).copied()
    }

    /// Records a PoW block for later lookup by its own hash.
    pub fn insert_beacon_pow_block(&mut self, block: PowBlock) {
        self.beacon
            .lock()
            .unwrap()
            .pow_blocks
            .insert(block.block_hash, block);
    }

    /// The unrealized justified checkpoint computed for `root`'s own post-state.
    pub fn unrealized_justification(&self, root: Root) -> Option<Checkpoint> {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::BeaconForkChoice, &beacon_root_key(root))
            .expect("get")
            .map(|bytes| Checkpoint::from_ssz_bytes(&bytes).expect("valid checkpoint"))
    }

    /// Sets [`Store::unrealized_justification`].
    pub fn set_unrealized_justification(&mut self, root: Root, checkpoint: Checkpoint) {
        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .put_batch(
                Table::BeaconForkChoice,
                vec![(beacon_root_key(root), checkpoint.to_ssz())],
            )
            .expect("put unrealized justification");
        batch.commit().expect("commit");
    }

    /// The most recently computed LMD GHOST head, or `None` before the first
    /// `ethlambda_beacon::fork_choice::get_head` call this process has made.
    ///
    /// See [`BeaconScratch`](crate::store::BeaconScratch)'s module comment for
    /// why this is in-memory rather than a `Metadata` row: it is cheap to
    /// recompute from the block tree and checkpoints already on disk, so
    /// persisting it would only be a second value a bug could let drift from
    /// what a fresh computation produces. Distinct from
    /// [`Store::beacon_highest_imported_slot`], which tracks how far forward
    /// sync has fetched rather than which branch fork choice has settled on;
    /// the two can and do disagree while syncing.
    pub fn beacon_head(&self) -> Option<(Slot, Root)> {
        self.beacon.lock().unwrap().head
    }

    /// Sets [`Store::beacon_head`].
    pub fn set_beacon_head(&mut self, slot: Slot, root: Root) {
        self.beacon.lock().unwrap().head = Some((slot, root));
    }

    /// The canonical blocks in `start_slot ..= end_slot`, oldest first.
    ///
    /// "Canonical" means on the chain the fork-choice head descends from, which
    /// is what `beacon_blocks_by_range` is defined to return: the index alone
    /// cannot answer it, because a slot can hold several blocks once a fork
    /// exists and only one of them is on the head's chain.
    ///
    /// Found by walking parent links back from the head, so the walk visits
    /// exactly the canonical chain and nothing else. Slots with no block are
    /// simply absent from the result, which is what a peer expects: the
    /// specification's response is a list, not a slot-indexed array.
    ///
    /// Empty when there is no head yet, which is every moment before this
    /// process has computed one. A node that cannot say which chain is
    /// canonical has nothing honest to serve.
    pub fn beacon_canonical_blocks_by_range(
        &self,
        start_slot: Slot,
        end_slot: Slot,
    ) -> Vec<SignedBeaconBlock> {
        let Some((head_slot, head_root)) = self.beacon_head() else {
            return Vec::new();
        };
        if start_slot > end_slot || start_slot > head_slot {
            return Vec::new();
        }

        // Walk down from the head to `start_slot`, collecting the roots that
        // fall inside the window. The walk starts at the head rather than at
        // `end_slot` because only the parent links say which block at a given
        // slot is the canonical one.
        let mut roots = Vec::new();
        let mut cursor = head_root;
        // Ends when the walk leaves the retained window: `promote_beacon_anchor`
        // prunes below the oldest kept anchor, and a missing entry there is the
        // floor rather than a fault.
        while let Some((slot, parent_root)) = self.beacon_block_entry(cursor) {
            if slot < start_slot {
                break;
            }
            if slot <= end_slot {
                roots.push(cursor);
            }
            // Genesis is its own parent's root of zero; without this the walk
            // would look zero up and stop one iteration later anyway, but only
            // by accident.
            if slot == 0 {
                break;
            }
            cursor = parent_root;
        }

        // The walk produced newest-first; the response is oldest-first.
        roots.reverse();
        roots
            .into_iter()
            .filter_map(|root| self.beacon_block(root))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ethlambda_types::beacon::containers::BeaconState;
    use ethlambda_types::beacon::containers::phase0;
    use ethlambda_types::beacon::fork_choice::{LatestMessage, PowBlock};
    use ethlambda_types::beacon::primitives::Uint256;

    use super::*;
    // In scope for the concrete `Arc<InMemoryBackend>` the reopen test reads
    // through; the `impl` above reaches `dyn StorageBackend`, which resolves
    // its methods without the trait being imported.
    use crate::api::StorageBackend;
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

    /// Builds `anchor -> 1 -> 2 -> ... -> length` and returns each block's
    /// root by slot, with the head set to the last one.
    fn chain(store: &mut Store, length: u64) -> Vec<Root> {
        let mut roots = Vec::new();
        let mut parent = Root::zero();
        for slot in 1..=length {
            let signed = block(slot, parent);
            let root = signed.message_hash_tree_root();
            store.insert_beacon_block(root, &signed);
            roots.push(root);
            parent = root;
        }
        store.set_beacon_head(length, *roots.last().expect("length is nonzero"));
        roots
    }

    #[test]
    fn a_canonical_range_comes_back_oldest_first_and_inclusive_of_both_ends() {
        let mut store = beacon_store();
        chain(&mut store, 10);

        let blocks = store.beacon_canonical_blocks_by_range(3, 6);

        assert_eq!(
            blocks.iter().map(|block| block.slot()).collect::<Vec<_>>(),
            vec![3, 4, 5, 6]
        );
    }

    /// A slot holds more than one block as soon as there is a fork, and only
    /// the parent links say which of them the head descends from. Serving the
    /// other one would hand a peer a block off its own canonical chain.
    #[test]
    fn a_fork_sibling_at_the_same_slot_is_not_served() {
        let mut store = beacon_store();
        let roots = chain(&mut store, 5);

        // A competing block at slot 5, off slot 3, which the head does not
        // descend from.
        let sibling = block(5, roots[2]);
        let sibling_root = sibling.message_hash_tree_root();
        store.insert_beacon_block(sibling_root, &sibling);

        let served: Vec<_> = store
            .beacon_canonical_blocks_by_range(5, 5)
            .iter()
            .map(|block| block.message_hash_tree_root())
            .collect();

        assert_eq!(served, vec![roots[4]], "the head's own slot-5 block");
        assert!(!served.contains(&sibling_root));
    }

    /// The walk starts at the head, so anything above it is not canonical yet
    /// and must not be served, even though the store holds it.
    #[test]
    fn nothing_above_the_head_is_served() {
        let mut store = beacon_store();
        let roots = chain(&mut store, 5);
        let ahead = block(6, roots[4]);
        store.insert_beacon_block(ahead.message_hash_tree_root(), &ahead);

        let blocks = store.beacon_canonical_blocks_by_range(1, 10);

        assert_eq!(
            blocks.iter().map(|block| block.slot()).collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5],
            "the head bounds the answer, not the highest block stored"
        );
    }

    /// Before the first `get_head` call there is no canonical chain to name,
    /// and a node that cannot say which chain is canonical has nothing honest
    /// to serve.
    #[test]
    fn a_store_with_no_head_serves_nothing() {
        let mut store = beacon_store();
        let signed = block(1, Root::zero());
        store.insert_beacon_block(signed.message_hash_tree_root(), &signed);

        assert!(store.beacon_canonical_blocks_by_range(0, 10).is_empty());
    }

    /// The walk ends where pruning did, rather than failing on the first root
    /// `promote_beacon_anchor` removed from the index.
    #[test]
    fn a_range_reaching_below_the_retained_window_stops_there() {
        let mut store = beacon_store();
        let roots = chain(&mut store, 6);
        // Re-root the chain at slot 4 by making its parent unknown, which is
        // what a prune below the oldest anchor leaves behind.
        let orphaned = block(4, Root::repeat_byte(0xfe));
        let orphaned_root = orphaned.message_hash_tree_root();
        store.insert_beacon_block(orphaned_root, &orphaned);
        let five = block(5, orphaned_root);
        let five_root = five.message_hash_tree_root();
        store.insert_beacon_block(five_root, &five);
        store.set_beacon_head(5, five_root);
        let _ = roots;

        let blocks = store.beacon_canonical_blocks_by_range(1, 5);

        assert_eq!(
            blocks.iter().map(|block| block.slot()).collect::<Vec<_>>(),
            vec![4, 5],
            "the walk stops at the missing parent instead of panicking"
        );
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
    fn a_fresh_beacon_store_has_a_readable_local_head() {
        // The regression this pins: the beacon path used to answer its local
        // head with `Store::head_slot`, which reads a metadata key only lean
        // bootstrap writes, so the first peer `Status` panicked the P2P actor.
        let store = beacon_store();
        assert_eq!(store.beacon_highest_imported_slot(), 0);
    }

    #[test]
    fn the_local_head_follows_the_highest_imported_block() {
        let mut store = beacon_store();
        let anchor = block(64, Root::zero());
        let anchor_root = anchor.message_hash_tree_root();
        store.insert_beacon_block(anchor_root, &anchor);
        assert_eq!(store.beacon_highest_imported_slot(), 64);

        let next = block(65, anchor_root);
        store.insert_beacon_block(next.message_hash_tree_root(), &next);
        assert_eq!(store.beacon_highest_imported_slot(), 65);
    }

    #[test]
    fn a_lower_slot_import_does_not_lower_the_local_head() {
        // Forward sync fetches ranges in batches and a fork can land a block
        // below the watermark; either lowering it would refetch slots already
        // on disk, forever.
        let mut store = beacon_store();
        let tip = block(65, Root::zero());
        store.insert_beacon_block(tip.message_hash_tree_root(), &tip);

        let fork = block(64, Root::repeat_byte(3));
        store.insert_beacon_block(fork.message_hash_tree_root(), &fork);

        assert_eq!(store.beacon_highest_imported_slot(), 65);
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

    #[test]
    fn the_beacon_clock_and_checkpoints_round_trip() {
        let mut store = Store::init_beacon(Arc::new(InMemoryBackend::new()), 1_700);
        assert_eq!(store.beacon_genesis_time(), 1_700);
        assert_eq!(store.beacon_time(), 0);
        assert_eq!(store.beacon_justified_checkpoint(), Checkpoint::default());

        store.set_beacon_time(12);
        let justified = Checkpoint {
            epoch: 3,
            root: Root::repeat_byte(1),
        };
        let finalized = Checkpoint {
            epoch: 2,
            root: Root::repeat_byte(2),
        };
        store.set_beacon_justified_checkpoint(justified);
        store.set_beacon_finalized_checkpoint(finalized);
        store.set_beacon_unrealized_justified_checkpoint(justified);
        store.set_beacon_unrealized_finalized_checkpoint(finalized);

        assert_eq!(store.beacon_time(), 12);
        assert_eq!(store.beacon_justified_checkpoint(), justified);
        assert_eq!(store.beacon_finalized_checkpoint(), finalized);
        assert_eq!(store.beacon_unrealized_justified_checkpoint(), justified);
        assert_eq!(store.beacon_unrealized_finalized_checkpoint(), finalized);
    }

    #[test]
    fn fork_choice_scratch_round_trips_and_is_shared_across_clones() {
        let mut store = beacon_store();
        let clone = store.clone();
        let root = Root::repeat_byte(1);

        assert_eq!(store.proposer_boost_root(), Root::zero());
        assert_eq!(store.block_timeliness(root), None);
        assert!(!store.is_equivocating(7));
        assert_eq!(store.latest_message(7), None);
        assert_eq!(store.beacon_head(), None);

        store.set_proposer_boost_root(root);
        store.set_block_timeliness(root, true);
        store.insert_equivocating_index(7);
        store.set_latest_message(
            7,
            LatestMessage {
                epoch: 4,
                root: Root::repeat_byte(9),
            },
        );
        store.set_beacon_head(3, root);

        assert_eq!(clone.proposer_boost_root(), root);
        assert_eq!(clone.block_timeliness(root), Some(true));
        assert!(clone.is_equivocating(7));
        assert_eq!(clone.beacon_head(), Some((3, root)));
        assert_eq!(
            clone.latest_message(7),
            Some(LatestMessage {
                epoch: 4,
                root: Root::repeat_byte(9)
            })
        );
    }

    #[test]
    fn a_pow_block_is_looked_up_by_its_own_hash() {
        let mut store = beacon_store();
        let pow = PowBlock {
            block_hash: Root::repeat_byte(1),
            parent_hash: Root::repeat_byte(2),
            total_difficulty: Uint256::from(9u64),
        };

        assert_eq!(store.beacon_pow_block(pow.block_hash), None);
        store.insert_beacon_pow_block(pow);
        assert_eq!(store.beacon_pow_block(pow.block_hash), Some(pow));
    }

    #[test]
    fn an_unrealized_justification_survives_a_store_reopen() {
        // Unlike the scratch above, this one is persisted: get_voting_source
        // reads it for every block from a prior epoch, and recomputing it means
        // replaying epoch processing per lookup.
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::init_beacon(backend.clone(), 0);
        let root = Root::repeat_byte(1);
        let checkpoint = Checkpoint {
            epoch: 5,
            root: Root::repeat_byte(2),
        };

        assert_eq!(store.unrealized_justification(root), None);
        store.set_unrealized_justification(root, checkpoint);

        let view = backend.begin_read().expect("read view");
        assert!(
            view.get(Table::BeaconForkChoice, &root.0)
                .expect("get")
                .is_some()
        );
        drop(view);
        assert_eq!(store.unrealized_justification(root), Some(checkpoint));
    }
}
