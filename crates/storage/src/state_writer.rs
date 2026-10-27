//! How a post-state is represented in storage, in both directions, and the
//! background thread that commits a write.
//!
//! Owns the write plan ([`StateWrite`], [`plan_lean_state_write`],
//! [`plan_beacon_state_write`]), the single read path ([`read_state`]) that
//! [`Store::get_state`](crate::store::Store::get_state) calls directly, the
//! cache type both sides share ([`StateCache`], keyed by [`CacheKey`]), and
//! the handoff buffer ([`PendingStates`]) that keeps a state readable between
//! the moment [`Store::insert_state`](crate::store::Store::insert_state)
//! hands it off and the moment its write lands.
//!
//! [`Store::insert_state`](crate::store::Store::insert_state) does not
//! execute the plan itself: it builds a [`StateWriteRequest`] and hands it to
//! [`StateWriterHandle`], returning once the state is cached and buffered.
//! [`StateWriter`] is what actually runs the plan and commits it, on a thread
//! of its own, and the contract a caller (or a future reader of this module)
//! needs to hold in mind is:
//!
//! - **One worker, never a pool.** A beacon state's delta is computed against
//!   its parent's *encoded bytes*, so the backend walks in [`read_state`] are
//!   only safe because states are inserted parent-before-child *and committed
//!   in that same order*. A single thread draining one FIFO channel is what
//!   gives the second half of that for free; a pool would not.
//! - **The channel blocks when full**, at [`STATE_WRITE_QUEUE_CAPACITY`]
//!   entries, which is exactly what the write already did before it moved off
//!   the importer's thread: this can only ever degrade to that, never past it.
//! - **The handle joins the thread when the last `Store` clone drops** (see
//!   [`StateWriterHandle`]'s doc), which is what makes "dropped" and
//!   "settled" the same event for every test in this crate, and what makes a
//!   drop on an async executor's worker thread a blocking call elsewhere.
//! - **A write that panics is not retried, hidden, or cleaned up after.** The
//!   entry stays in [`PendingStates`] (see its doc), and the next hand-off
//!   observes the closed channel and fails loudly, rather than silently
//!   losing states behind a worker that kept going.
//!
//! Reading and writing live in one module because they are one contract, not
//! two: a change to what a write produces, such as the diff format or the
//! snapshot boundary, is a change to what a reader must be able to find.
//! Splitting them apart would let the two drift until a reader silently
//! failed to reconstruct what a writer had actually written.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

use ethlambda_types::{
    beacon::{containers::BeaconState, fork::ForkName},
    block::BlockHeader,
    primitives::H256,
    state::State,
};
use libssz::{SszDecode, SszEncode};
use lru::LruCache;
use tracing::error;

use crate::api::{StorageBackend, StorageReadViewExt, Table};
use crate::beacon_state_delta;
use crate::error::Error;
use crate::state_codec::{decode_lean_state_value, decode_state_value, encode_state_value};
use crate::state_diff::StateDiff;
use crate::store::Chain;
use crate::store::beacon_block_slot;

/// What a state insert will write, decided but not yet committed.
///
/// At least one of `snapshot` and `diff` is always `Some`: a write that
/// persists nothing would silently drop the state.
pub(crate) struct StateWrite {
    /// `Table::States` value. `Some` at a snapshot anchor.
    pub snapshot: Option<Vec<u8>>,
    /// `Table::StateDiffs` value. `Some` for every lean state, and for a
    /// beacon state that is not an anchor.
    pub diff: Option<Vec<u8>>,
    /// Beacon only: the target's [`encode_state_value`] bytes, for the
    /// writer's parent memo. `None` on the lean arm, which diffs in the field
    /// domain and never reads a parent's bytes.
    pub encoded: Option<Vec<u8>>,
}

/// States handed to the writer but not yet committed to the backend.
///
/// The handoff buffer between [`Store::insert_state`](crate::store::Store::insert_state)
/// and the code that executes the write. Consulted by [`read_state`] after the
/// LRU and before the backend, so a state is readable from the instant
/// `insert_state` returns rather than from whenever the write lands.
///
/// An entry is removed only *after* its `commit()` has returned, so there is
/// no instant at which neither this buffer nor the backend can answer for a
/// root. That is the whole point of it: the LRU alone cannot serve this role,
/// because it may evict an entry whose write has not happened yet.
///
/// An entry that outlives a failed write is deliberate, not a leak. Removing
/// it on unwind would turn a durability failure into a correctness one: a
/// reader would be told `None` for a root the importer was already told was
/// persisted. Retaining it means the buffer goes on answering truthfully for
/// a state the backend never received.
#[derive(Default)]
pub(crate) struct PendingStates(Mutex<HashMap<H256, Arc<BeaconState>>>);

impl PendingStates {
    pub(crate) fn insert(&self, root: H256, state: Arc<BeaconState>) {
        self.0.lock().unwrap().insert(root, state);
    }

    pub(crate) fn get(&self, root: &H256) -> Option<Arc<BeaconState>> {
        self.0.lock().unwrap().get(root).cloned()
    }

    pub(crate) fn remove(&self, root: &H256) {
        self.0.lock().unwrap().remove(root);
    }
}

/// What a cached state is keyed by.
///
/// One cache rather than two, so a single capacity bounds the total rather
/// than each kind separately overshooting it. A checkpoint state is keyed by
/// its epoch as well as its root because a checkpoint's root is the last block
/// at or before its boundary slot, so the same root can serve different epochs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CacheKey {
    /// A block's post-state, keyed by that block's root.
    BlockState(H256),
    /// The state advanced to a checkpoint's epoch boundary.
    CheckpointState { epoch: u64, root: H256 },
}

/// The shared state cache, memoizing post-states by block root.
pub(crate) type StateCache = Mutex<LruCache<CacheKey, Arc<BeaconState>>>;

/// Reads the post-state for `root`, from wherever it currently lives.
///
/// The single state read path, called both by
/// [`Store::get_state`](crate::store::Store::get_state) and by the writer
/// thread's own parent lookup, which is what lets the lean arm's parent fetch
/// run off the importer's thread while still hitting the shared LRU.
///
/// Lookup order is cache, then `pending`, then the backend. The cache and
/// `pending` hold the same `Arc` for a state in flight, so the order is not a
/// correctness question, only a cost one: every read consults the LRU anyway,
/// so putting it first means `pending` is reached only on a miss and stays a
/// safety net rather than a hot path.
///
/// The backend walks never have to consult `pending`, because states are
/// inserted parent before child *and committed in that same order*: any
/// descendant of a pending state is itself pending and is answered above, so
/// a diff chain can never run *through* a root the backend does not yet have.
/// The second half is what a single writer thread gives and a pool would not:
/// a grandchild committed while its ancestor is still pending would make this
/// walk return `Ok(None)` for a state that exists.
pub(crate) fn read_state(
    backend: &dyn StorageBackend,
    chain: Chain,
    cache: &StateCache,
    pending: &PendingStates,
    root: &H256,
) -> Result<Option<Arc<BeaconState>>, Error> {
    let key = CacheKey::BlockState(*root);
    if let Some(state) = cache.lock().unwrap().get(&key).cloned() {
        return Ok(Some(state));
    }
    if let Some(state) = pending.get(root) {
        return Ok(Some(state));
    }

    let state = match chain {
        Chain::Lean => {
            // Anchor snapshot in `States`, otherwise reconstruct from the diff chain.
            let snapshot = {
                let view = backend.begin_read().expect("read view");
                view.read_with(Table::States, &root.to_ssz(), decode_lean_state_value)
                    .expect("read")
            };
            let state = match snapshot {
                Some(state) => state,
                None => match reconstruct_state(backend, root)? {
                    Some(state) => state,
                    None => return Ok(None),
                },
            };
            BeaconState::Lean(state)
        }
        Chain::Beacon => {
            // Decoded exactly once, after every delta in the chain has already
            // been folded in the byte domain; see
            // `reconstruct_beacon_state_bytes`'s doc comment for why an SSZ
            // decode per hop instead would be the whole cost that delta layer
            // exists to avoid. A snapshot root decodes straight from the
            // backend's buffer.
            let Some(mut state) =
                reconstruct_beacon_state_bytes(backend, root, |bytes| decode_state_value(&bytes))?
            else {
                return Ok(None);
            };
            rebase_onto_resident(cache, &mut state);
            state
        }
    };

    // A cached `Arc` cannot be flushed later, so every root taken through it
    // would pay the slow, uncached hashing path.
    let mut state = state;
    state.apply_pending_mutations();
    let state = Arc::new(state);
    cache.lock().unwrap().put(key, state.clone());
    Ok(Some(state))
}

/// Makes a state just decoded from storage share memory with a resident one.
///
/// A decoded state's tree-backed fields (see `BeaconState::rebase_on`) are
/// fresh allocations, so without this every cache miss would hold a full
/// private copy of the registry next to cached states it is nearly identical
/// to. The parent's state is the closest relative when it is resident;
/// otherwise the most recently used state still shares nearly all of the
/// registry. The rebased state is equal to the decoded one: only which
/// allocations back it change.
///
/// The cache lock is released before rebasing, which walks the whole registry.
fn rebase_onto_resident(cache: &StateCache, state: &mut BeaconState) {
    let parent = CacheKey::BlockState(state.latest_block_header().parent_root);
    let base = {
        let cache = cache.lock().unwrap();
        cache
            .peek(&parent)
            .or_else(|| cache.iter().next().map(|(_, state)| state))
            .cloned()
    };
    if let Some(base) = base {
        state.rebase_on(&base);
    }
}

/// Reconstructs a beacon state's raw *encoded* bytes (see
/// [`encode_state_value`]) by walking `StateDiffs` back to the nearest
/// `States` snapshot and folding deltas forward, byte domain only.
///
/// Mirrors [`reconstruct_state`]'s walk-then-replay shape for lean, but
/// cannot share its body: a beacon `StateDiffs` record is a
/// [`beacon_state_delta::frame`]d byte delta, not a [`StateDiff`], so the
/// base root read off each hop comes from
/// [`beacon_state_delta::unframe`] instead of a `StateDiff`'s own field.
///
/// Hands the encoded bytes to `consume` rather than returning a decoded
/// [`BeaconState`], so that a caller that only needs the bytes (the writer
/// thread's `StateWriter::encoded_parent_bytes`, for its diff base) is never
/// made to pay for a decode it will not use.
/// [`Store::get_state`](crate::store::Store::get_state)'s beacon arm is the
/// one caller that decodes, and it does so exactly once, after every delta
/// has already been folded.
///
/// `consume` gets [`Cow::Borrowed`] when `root` is itself a snapshot: the
/// backend's own buffer, never copied. Otherwise the first delta reads the
/// borrowed snapshot as its base, and `consume` gets the folded result as
/// [`Cow::Owned`], so taking ownership costs no further copy either way
/// beyond the one a borrowed snapshot needs.
///
/// `Ok(None)` when `root` is unknown, or the chain runs off the retained
/// window before reaching a snapshot: a missing `StateDiffs` record below
/// the pruned boundary, matching how the lean walk in
/// [`reconstruct_state`] handles both cases.
pub(crate) fn reconstruct_beacon_state_bytes<T>(
    backend: &dyn StorageBackend,
    root: &H256,
    consume: impl FnOnce(Cow<'_, [u8]>) -> T,
) -> Result<Option<T>, Error> {
    let view = backend.begin_read().expect("read view");
    let mut records: Vec<Vec<u8>> = Vec::new();
    let mut consume = Some(consume);
    let mut cursor = *root;
    loop {
        let key = cursor.to_ssz();
        // The walk ends at the first snapshot, so the deltas collected so
        // far are folded onto it while it is still borrowed.
        let folded = view
            .read_with(Table::States, &key, |snapshot| {
                let consume = consume.take().expect("the walk ends at its first snapshot");
                // `records` runs target -> snapshot child; reverse to snapshot
                // child -> target, the order the chain was written in, so
                // folding forward replays it correctly.
                records.reverse();
                fold_beacon_state_deltas(snapshot, &records, consume)
            })
            .expect("read");
        if folded.is_some() {
            return Ok(folded);
        }
        let Some(diff_bytes) = view.get(Table::StateDiffs, &key).expect("get") else {
            return Ok(None);
        };
        let (base_root, _, _, _) = beacon_state_delta::unframe(&diff_bytes);
        cursor = base_root;
        records.push(diff_bytes);
    }
}

/// Applies `records` (snapshot child first) to a borrowed `snapshot` and
/// hands the result to `consume`: the snapshot itself when there is nothing
/// to apply, otherwise the owned output of the last delta.
fn fold_beacon_state_deltas<T>(
    snapshot: &[u8],
    records: &[Vec<u8>],
    consume: impl FnOnce(Cow<'_, [u8]>) -> T,
) -> T {
    let mut records = records.iter();
    let Some(first) = records.next() else {
        return consume(Cow::Borrowed(snapshot));
    };
    let (_, _, target_len, delta) = beacon_state_delta::unframe(first);
    let mut bytes = beacon_state_delta::decode(delta, snapshot, target_len as usize);
    for record in records {
        let (_, _, target_len, delta) = beacon_state_delta::unframe(record);
        bytes = beacon_state_delta::decode(delta, &bytes, target_len as usize);
    }
    consume(Cow::Owned(bytes))
}

/// Reconstruct a state from diffs and the nearest ancestor snapshot.
///
/// Walks `base_root` pointers back until a snapshot is found, fetches the
/// target's block header, and delegates the assembly to
/// [`state_diff::reconstruct`](crate::state_diff::reconstruct).
///
/// Lean directories only: the inlined `BlockHeaders` read below assumes a
/// bare [`BlockHeader`], which is what a lean directory stores there. A
/// beacon directory tags that table with a fork selector ahead of a
/// `SignedBeaconBlock`, so calling this on one would decode the wrong shape
/// and hit the `expect("valid header")` below instead of an explicit panic.
/// Nothing does today: [`read_state`]'s `Chain::Lean` arm is this function's
/// only caller, so that invariant is enforced by having exactly one caller
/// rather than by a runtime check, unlike
/// [`Store::get_block_header`](crate::store::Store::get_block_header)'s
/// `lean_only` guard.
///
/// Returns `Ok(None)` when the root is unknown or the diff chain is broken.
pub(crate) fn reconstruct_state(
    backend: &dyn StorageBackend,
    root: &H256,
) -> Result<Option<State>, Error> {
    // Walk back collecting diffs until we reach a snapshot.
    let view = backend.begin_read().expect("read view");
    let mut diffs: Vec<StateDiff> = Vec::new();
    let mut cursor = *root;
    let snapshot = loop {
        let key = cursor.to_ssz();
        if let Some(snapshot) = view
            .read_with(Table::States, &key, decode_lean_state_value)
            .expect("read")
        {
            break snapshot;
        }
        let Some(diff) = view
            .read_with(Table::StateDiffs, &key, |bytes| {
                StateDiff::from_ssz_bytes(bytes).expect("valid state diff")
            })
            .expect("read")
        else {
            return Ok(None);
        };
        cursor = diff.base_root;
        diffs.push(diff);
    };
    drop(view);

    // `diffs` runs target -> snapshot child; reverse to snapshot child -> target.
    diffs.reverse();

    // The latest block header lives in BlockHeaders; the stored state caches
    // the real state_root there, so it equals the header byte-for-byte.
    let view = backend.begin_read().expect("read view");
    let header = view
        .read_with(Table::BlockHeaders, &root.to_ssz(), |bytes| {
            BlockHeader::from_ssz_bytes(bytes).expect("valid header")
        })
        .expect("read");
    drop(view);
    let Some(latest_block_header) = header else {
        return Ok(None);
    };

    Ok(Some(crate::state_diff::reconstruct(
        snapshot,
        &diffs,
        latest_block_header,
    )))
}

/// Whether a state at `slot` crosses an `interval` snapshot boundary relative
/// to its parent.
///
/// `parent_slot` is `None` for the store's first-ever beacon state, which has
/// no parent block on record and is therefore always a snapshot: there is no
/// base to diff against.
///
/// Split out from the planning functions because the beacon arm has to know
/// the answer *before* deciding whether to read the parent's encoded bytes at
/// all: at an anchor it never diffs, and fetching a base it will not use would
/// turn an avoided read into a mandatory one on every anchor.
pub(crate) fn is_anchor(slot: u64, parent_slot: Option<u64>, interval: u64) -> bool {
    match parent_slot {
        Some(parent_slot) => slot / interval > parent_slot / interval,
        None => true,
    }
}

/// The bytes a lean post-state writes, given its parent state.
///
/// Every lean state records a `StateDiffs` entry; a snapshot is added only
/// when the block crosses a [`ForkName::snapshot_interval`] boundary. Takes
/// the post-state by value because [`StateDiff::from_states`] consumes it, and
/// the parent by reference because the diff only reads it.
pub(crate) fn plan_lean_state_write(state: State, parent: &State) -> StateWrite {
    let interval = ForkName::Lean.snapshot_interval();
    // Serialize before `state` is consumed by the diff below.
    let snapshot = is_anchor(state.slot, Some(parent.slot), interval)
        .then(|| encode_state_value(&BeaconState::Lean(state.clone())));
    let diff = StateDiff::from_states(parent, state)
        .expect("state transition produced a non-append historical_block_hashes")
        .to_ssz();
    StateWrite {
        snapshot,
        diff: Some(diff),
        encoded: None,
    }
}

/// The bytes a beacon post-state writes.
///
/// `parent` is `Some((parent_root, parent_encoded_bytes))` for a state that
/// diffs against its parent, and `None` for an anchor. Carrying the anchor
/// decision in this argument rather than in a separate flag is what keeps a
/// caller from fetching a base it will not use; see [`is_anchor`].
///
/// `slot` is passed rather than read off `state` because the caller has
/// already computed it for [`is_anchor`], and because
/// [`BeaconState::slot`] panics on the lean arm: a signature that cannot
/// reach that panic is worth more than one that merely never does.
pub(crate) fn plan_beacon_state_write(
    state: &BeaconState,
    slot: u64,
    parent: Option<(H256, &[u8])>,
) -> StateWrite {
    let target = encode_state_value(state);
    match parent {
        None => StateWrite {
            snapshot: Some(target.clone()),
            diff: None,
            encoded: Some(target),
        },
        Some((parent_root, base)) => {
            let delta = beacon_state_delta::encode(&target, base);
            // Deliberately not weakened to a plain `assert`: this repo's
            // release-fast profile keeps debug assertions on in tests while
            // stripping them from shipped binaries, so this round trip is
            // exercised on every test run without costing anything in
            // production.
            debug_assert_eq!(
                beacon_state_delta::decode(&delta, base, target.len()),
                target,
                "a beacon state delta must decode back to its target"
            );
            let target_len = target.len() as u64;
            let framed = beacon_state_delta::frame(parent_root, slot, target_len, &delta);
            StateWrite {
                snapshot: None,
                diff: Some(framed),
                encoded: Some(target),
            }
        }
    }
}

/// How many handed-off states may wait in the channel.
///
/// Two, so one import overlaps the previous write without letting the queue
/// become a memory sink: a mainnet `BeaconState` is large enough that an
/// unbounded queue would turn a slow disk into an out-of-memory kill. With a
/// full channel the send blocks, which is exactly what the write did before it
/// moved off the importer's thread, so this can only ever degrade to today and
/// never past it.
///
/// This bounds the channel, not every state alive at once: up to three are
/// live at a time in the worst case, two queued plus one the worker is
/// currently writing, and each of those three is also held by `PendingStates`
/// and the LRU.
pub(crate) const STATE_WRITE_QUEUE_CAPACITY: usize = 2;

/// One state handed to the writer.
pub(crate) struct StateWriteRequest {
    pub root: H256,
    pub state: Arc<BeaconState>,
}

/// The writer thread's own state.
///
/// Holds the individual `Arc`s it needs rather than a `Store`, which would be
/// a reference cycle through the [`StateWriterHandle`] that is supposed to
/// join it.
struct StateWriter {
    backend: Arc<dyn StorageBackend>,
    chain: Chain,
    cache: Arc<StateCache>,
    pending: Arc<PendingStates>,
    /// The most recently encoded beacon state, so the beacon write path does
    /// not re-encode a parent's whole SSZ on every import.
    ///
    /// Thread-local and a plain `Option`, not a shared `Mutex`: requests are
    /// drained in order by this one thread, so the parent of the state being
    /// written is whatever this thread wrote last.
    encoded_memo: Option<(H256, Vec<u8>)>,
}

impl StateWriter {
    fn run(mut self, rx: Receiver<StateWriteRequest>) {
        for request in rx {
            self.write(&request);
            // Only now, after the commit returned: until this line both the
            // buffer and the backend can answer for this root, and after it
            // the backend alone can. There is no instant where neither does.
            self.pending.remove(&request.root);
            crate::metrics::dec_state_write_queue_depth();
        }
    }

    fn write(&mut self, request: &StateWriteRequest) {
        let _timing = crate::metrics::time_state_write();
        let root = request.root;
        let write = match &*request.state {
            BeaconState::Lean(lean) => {
                let parent_root = lean.latest_block_header.parent_root;
                let parent = read_state(
                    self.backend.as_ref(),
                    self.chain,
                    &self.cache,
                    &self.pending,
                    &parent_root,
                )
                .expect("read parent state")
                .expect("parent state must exist to diff against");
                plan_lean_state_write(lean.clone(), parent.expect_lean())
            }
            beacon_state => {
                let slot = beacon_state.slot();
                let parent_root = beacon_state.latest_block_header().parent_root;
                let interval = beacon_state.fork_name().snapshot_interval();
                let parent_slot = beacon_block_slot(self.backend.as_ref(), &parent_root);
                let base = (!is_anchor(slot, parent_slot, interval))
                    .then(|| self.encoded_parent_bytes(parent_root));
                plan_beacon_state_write(
                    beacon_state,
                    slot,
                    base.as_deref().map(|base| (parent_root, base)),
                )
            }
        };

        debug_assert!(
            write.snapshot.is_some() || write.diff.is_some(),
            "a state write that persists nothing would silently drop the state"
        );
        let key = root.to_ssz();
        let mut batch = self.backend.begin_write().expect("write batch");
        if let Some(diff) = write.diff {
            batch
                .put_batch(Table::StateDiffs, vec![(key.clone(), diff)])
                .expect("put state diff");
        }
        if let Some(snapshot) = write.snapshot {
            batch
                .put_batch(Table::States, vec![(key, snapshot)])
                .expect("put state snapshot");
        }
        batch.commit().expect("commit");

        if let Some(encoded) = write.encoded {
            self.encoded_memo = Some((root, encoded));
        }
    }

    /// The parent's [`encode_state_value`] bytes, for the beacon delta.
    ///
    /// Checks the memo first: requests are drained in order, so the parent is
    /// almost always the state this thread wrote last, making this free. A
    /// miss folds the diff chain, which produces these exact bytes as a
    /// by-product, so nothing is decoded and then re-encoded to satisfy it.
    ///
    /// # Panics
    ///
    /// If `parent_root` has no state. This is only reached once
    /// [`beacon_block_slot`] has found a parent block, which is only ever true
    /// once that parent's own state has already been written: this thread
    /// committed it before pulling the request being served now.
    fn encoded_parent_bytes(&self, parent_root: H256) -> Vec<u8> {
        self.encoded_memo
            .as_ref()
            .filter(|(root, _)| *root == parent_root)
            .map(|(_, bytes)| bytes.clone())
            .unwrap_or_else(|| {
                reconstruct_beacon_state_bytes(self.backend.as_ref(), &parent_root, |bytes| {
                    bytes.into_owned()
                })
                .expect("read parent state")
                .expect("parent state must exist to diff against")
            })
    }
}

/// Owns the writer thread and joins it on drop.
///
/// Lives behind an `Arc` inside [`Store`](crate::store::Store), which is
/// `Clone`: a `Drop` on `Store` itself would fire on every clone, so the join
/// hangs off this instead and runs once, when the last clone releases it.
///
/// # Blocking
///
/// Dropping the last `Store` clone joins the writer, which blocks the
/// dropping thread until the queue drains and the in-flight write commits.
/// A drop on an async executor's worker thread (e.g. replacing a `Store`
/// behind a `tokio::sync::RwLock`) therefore blocks that worker for the same
/// span, not just the caller.
pub(crate) struct StateWriterHandle {
    /// `Option` so [`Drop`] can take it. Dropping the sender is what ends the
    /// thread's `recv` loop, and it has to happen before the join or the join
    /// waits forever.
    tx: Option<SyncSender<StateWriteRequest>>,
    join: Option<JoinHandle<()>>,
}

impl StateWriterHandle {
    pub(crate) fn spawn(
        backend: Arc<dyn StorageBackend>,
        chain: Chain,
        cache: Arc<StateCache>,
        pending: Arc<PendingStates>,
    ) -> Self {
        let (tx, rx) = sync_channel(STATE_WRITE_QUEUE_CAPACITY);
        let writer = StateWriter {
            backend,
            chain,
            cache,
            pending,
            encoded_memo: None,
        };
        let join = std::thread::Builder::new()
            .name("state-writer".into())
            .spawn(move || writer.run(rx))
            .expect("spawn the state writer thread");
        Self {
            tx: Some(tx),
            join: Some(join),
        }
    }

    /// Hands a state to the writer, blocking while the queue is full.
    ///
    /// Returns the instants just before and just after the blocking `send`,
    /// so a caller can report the hand-off wait apart from the work around
    /// it. The span is near zero unless the queue was full.
    ///
    /// # Panics
    ///
    /// If the writer thread is gone, which only happens after it panicked. Its
    /// own panic message is already on the default hook; this is the importer
    /// learning about it, one state later.
    pub(crate) fn send(&self, request: StateWriteRequest) -> (Instant, Instant) {
        let start = Instant::now();
        self.tx
            .as_ref()
            .expect("the sender is taken only in Drop")
            .send(request)
            .expect("the state writer thread died; see the logged panic above");
        (start, Instant::now())
    }
}

impl Drop for StateWriterHandle {
    fn drop(&mut self) {
        // Ends the thread's `recv` loop. Must precede the join.
        drop(self.tx.take());
        let Some(join) = self.join.take() else {
            return;
        };
        if join.join().is_err() {
            error!("the state writer thread panicked; queued state writes were lost");
            // Panicking during an unwind aborts the process, so the writer's
            // panic is re-raised here only when this drop is not itself
            // unwinding. Either way the thread's own panic message already
            // reached the default hook and the line above.
            assert!(
                std::thread::panicking(),
                "the state writer thread panicked; see the logged panic above"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::block::BlockHeader;
    use ethlambda_types::primitives::HashTreeRoot as _;
    use ethlambda_types::state::{PUBLIC_KEY_SIZE, Validator};

    fn base_state() -> State {
        let validators = vec![Validator {
            attestation_pubkey: [7u8; PUBLIC_KEY_SIZE],
            proposal_pubkey: [9u8; PUBLIC_KEY_SIZE],
            index: 0,
        }];
        State::from_genesis(1_000, validators)
    }

    /// A valid direct child of `parent` at `slot`, shaped the way the state
    /// transition leaves a post-state: the parent's block root appended to
    /// `historical_block_hashes`, zero-filled for any skipped slots, and
    /// `latest_block_header` set to this block's own header.
    fn child_state(parent: &State, slot: u64) -> State {
        let parent_root = parent.latest_block_header.hash_tree_root();
        let empty_slots = (slot - parent.slot - 1) as usize;

        let mut hbh = parent.historical_block_hashes.to_vec();
        hbh.push(parent_root);
        hbh.extend(std::iter::repeat_n(H256::ZERO, empty_slots));

        let mut child = parent.clone();
        child.slot = slot;
        child.historical_block_hashes = hbh.try_into().expect("within limit");
        child.latest_block_header = BlockHeader {
            slot,
            proposer_index: 0,
            parent_root,
            state_root: H256::ZERO,
            body_root: H256::ZERO,
        };
        child
    }

    #[test]
    fn a_first_state_with_no_parent_is_always_an_anchor() {
        assert!(is_anchor(5, None, 1_024));
        assert!(is_anchor(0, None, 1_024));
    }

    #[test]
    fn an_anchor_is_a_crossing_of_the_interval_boundary() {
        assert!(is_anchor(1_024, Some(1_023), 1_024));
        assert!(!is_anchor(1_023, Some(1_022), 1_024));
        assert!(!is_anchor(1_025, Some(1_024), 1_024));
        assert!(
            is_anchor(3_072, Some(1_000), 1_024),
            "a jump across several intervals is still one anchor"
        );
    }

    #[test]
    fn a_lean_plan_always_writes_a_diff_and_snapshots_only_at_an_anchor() {
        let interval = ForkName::Lean.snapshot_interval();

        let mut parent = base_state();
        parent.slot = interval - 1;
        parent.latest_block_header.slot = interval - 1;

        let crossing = child_state(&parent, interval);
        let expected = encode_state_value(&BeaconState::Lean(crossing.clone()));
        let plan = plan_lean_state_write(crossing, &parent);
        assert!(plan.diff.is_some(), "every lean state records a diff");
        assert_eq!(
            plan.snapshot.as_deref(),
            Some(expected.as_slice()),
            "the snapshot holds the anchored state's own bytes, not its parent's"
        );
        assert!(plan.encoded.is_none(), "the lean arm keeps no encoded memo");

        let mut inside = base_state();
        inside.slot = interval;
        inside.latest_block_header.slot = interval;
        let non_crossing = child_state(&inside, interval + 1);
        let plan = plan_lean_state_write(non_crossing, &inside);
        assert!(plan.diff.is_some());
        assert!(
            plan.snapshot.is_none(),
            "staying inside the interval does not"
        );
    }

    #[test]
    fn a_beacon_plan_with_no_parent_writes_a_snapshot_carrying_the_memo() {
        let state = BeaconState::Lean(base_state());
        let slot = state.expect_lean().slot;
        let plan = plan_beacon_state_write(&state, slot, None);
        assert!(
            plan.snapshot.is_some(),
            "no parent means no base to diff against"
        );
        assert!(plan.diff.is_none());
        assert_eq!(
            plan.encoded.as_deref(),
            plan.snapshot.as_deref(),
            "the memo is the very bytes that were snapshotted"
        );
    }

    /// A lean state stands in for a mainnet one here on purpose: the beacon
    /// write path diffs in the byte domain, so what it is fed is a `Vec<u8>`
    /// and nothing below `encode_state_value` knows or cares which fork
    /// produced it. That keeps this test free of a multi-megabyte fixture.
    #[test]
    fn a_beacon_delta_decodes_back_to_its_target() {
        let parent = base_state();
        let child = child_state(&parent, parent.slot + 1);
        let parent_root = parent.latest_block_header.hash_tree_root();

        let base = encode_state_value(&BeaconState::Lean(parent));
        let slot = child.slot;
        let state = BeaconState::Lean(child);
        let plan = plan_beacon_state_write(&state, slot, Some((parent_root, &base)));

        assert!(
            plan.snapshot.is_none(),
            "a parent means a diff, not a snapshot"
        );
        let framed = plan.diff.expect("a non-anchor records a diff");
        let (read_base_root, framed_slot, target_len, delta) = beacon_state_delta::unframe(&framed);
        assert_eq!(read_base_root, parent_root);
        assert_eq!(
            framed_slot, slot,
            "the frame carries the target state's slot"
        );
        assert_eq!(
            beacon_state_delta::decode(delta, &base, target_len as usize),
            plan.encoded
                .expect("the beacon arm always memoizes its target"),
        );
    }

    #[test]
    fn a_pending_state_is_readable_and_stops_being_pending_when_removed() {
        let pending = PendingStates::default();
        let state = Arc::new(BeaconState::Lean(base_state()));
        let root = H256([3u8; 32]);

        assert!(pending.get(&root).is_none());

        pending.insert(root, state.clone());
        // The hit is the same `Arc`, not a copy: this is the property
        // `read_state`'s doc leans on to say the buffer costs nothing beyond
        // an LRU miss even for a mainnet-sized state.
        assert!(Arc::ptr_eq(&pending.get(&root).unwrap(), &state));

        pending.remove(&root);
        assert!(pending.get(&root).is_none());
    }
}
