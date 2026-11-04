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
//!   the *encoded bytes of the nearest snapshot on its branch*, and that
//!   snapshot, like every ancestor, must already be committed when the delta is
//!   planned; the backend walks in [`read_state`] are likewise only safe because
//!   states are inserted parent-before-child *and committed in that same order*.
//!   A single thread draining one FIFO channel is what gives the second half of
//!   that for free; a pool would not.
//! - **The channel blocks when full**, at [`STATE_WRITE_QUEUE_CAPACITY`]
//!   entries, which is exactly what the write already did before it moved off
//!   the importer's thread: this can only ever degrade to that, never past it.
//! - **The handle joins the thread when the last `Store` clone drops** (see
//!   [`StateWriterHandle`]'s doc), which is what makes "dropped" and
//!   "settled" the same event for every test in this crate, and what makes a
//!   drop on an async executor's worker thread a blocking call elsewhere.
//! - **[`StateWriterHandle::flush`] is the only way to wait for a write.** It
//!   queues a marker behind every write handed off so far and blocks until
//!   the thread reaches it, which is how
//!   [`Store::prune_finalized_states`](crate::store::Store::prune_finalized_states)
//!   keeps a queued write below its cut from landing after its range delete.
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

use crate::api::{StorageBackend, StorageReadView, StorageReadViewExt, Table};
use crate::beacon_state_delta;
use crate::error::Error;
use crate::metrics::StateCacheMethod;
use crate::state_codec::{decode_lean_state_value, decode_state_value, encode_state_value};
use crate::state_diff::StateDiff;
use crate::store::{Chain, beacon_block_slot, block_slot, block_slot_in, encode_slot_root_key};

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
    /// writer's snapshot memo. `Some` exactly when the write is a snapshot:
    /// only a snapshot is ever a diff base, so a diff's own bytes are never
    /// kept. `None` on the lean arm, which diffs in the field domain and never
    /// reads a base's bytes.
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

/// Looks `key` up in `cache`, promoting it to most recently used, and counts
/// the lookup as `method`'s.
pub(crate) fn cache_get(
    cache: &StateCache,
    key: CacheKey,
    method: StateCacheMethod,
) -> Option<Arc<BeaconState>> {
    let state = cache.lock().unwrap().get(&key).cloned();
    crate::metrics::inc_state_cache_lookups(method, &key, state.is_some());
    state
}

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
    if let Some(state) = cache_get(cache, key, StateCacheMethod::Get) {
        return Ok(Some(state));
    }
    if let Some(state) = pending.get(root) {
        return Ok(Some(state));
    }

    let state = match chain {
        Chain::Lean => {
            // Anchor snapshot in `States`, otherwise reconstruct from the diff chain.
            // `States` is keyed by block slot then root, so a root with no
            // block row has no state to find.
            let Some(slot) = block_slot(backend, chain, root) else {
                return Ok(None);
            };
            let snapshot = {
                let view = backend.begin_read().expect("read view");
                let key = encode_slot_root_key(slot, root);
                view.read_with(Table::States, &key, decode_lean_state_value)
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
/// Every frame names its own base, and that is all this walk follows. A diff
/// written by [`plan_beacon_state_write`] names the snapshot of its interval, so
/// the walk is one hop and the fold applies exactly one delta. A diff written
/// parent-linked by an earlier build names its parent instead, and the same walk
/// still reaches the snapshot and folds the longer chain. That is why moving the
/// base from the parent to the snapshot needed no `DB_VERSION` bump, and why
/// this function must keep following `base_root` rather than assume one hop.
///
/// Mirrors [`reconstruct_state`]'s walk-then-replay shape for lean, but
/// cannot share its body: a beacon `StateDiffs` record is a
/// [`beacon_state_delta::frame`]d byte delta, not a [`StateDiff`], so the
/// base root read off each hop comes from
/// [`beacon_state_delta::unframe`] instead of a `StateDiff`'s own field.
///
/// Hands the encoded bytes to `consume` rather than returning a decoded
/// [`BeaconState`], so that a caller that only needs the bytes is never made to
/// pay for a decode it will not use.
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
/// Both tables are keyed by block slot then root, so each hop looks up its
/// own slot from that root's `BlockHeaders` row.
///
/// `Ok(None)` when `root` is unknown, or the chain runs off the retained
/// window before reaching a snapshot: a missing `StateDiffs` record below
/// the pruned boundary (see
/// [`Store::prune_finalized_states`](crate::store::Store::prune_finalized_states)),
/// matching how the lean walk in [`reconstruct_state`] handles both cases. A
/// hop whose block row is absent ends the walk the same way.
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
        let Some(slot) = block_slot_in(view.as_ref(), Chain::Beacon, &cursor) else {
            return Ok(None);
        };
        let key = encode_slot_root_key(slot, &cursor);
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

/// The root of the snapshot that `root`'s state belongs to, found by following
/// `StateDiffs` frames' `base_root` until a root has no diff row.
///
/// On a beacon directory a state is written as a snapshot xor a diff (see
/// [`plan_beacon_state_write`]), so a root with no `StateDiffs` row is a
/// snapshot. `States` is deliberately not probed to decide that: on RocksDB a
/// hit there materializes the whole blob value, which is over a hundred
/// megabytes, just to answer yes.
///
/// A diff written by this version names the snapshot directly, so the walk is
/// one hop. Following `base_root` all the way, rather than taking one hop and
/// trusting it, is what keeps a directory whose diffs were written
/// parent-linked by an older build working: that chain ends at the snapshot
/// too, only after more hops.
///
/// `None` when a root on the way has no block row, which is how a root the
/// store never heard of looks. Takes the caller's view because opening a second
/// one while holding the first can deadlock on a backend whose read lock is not
/// reentrant.
pub(crate) fn nearest_snapshot_root(view: &dyn StorageReadView, root: &H256) -> Option<H256> {
    let mut cursor = *root;
    loop {
        let slot = block_slot_in(view, Chain::Beacon, &cursor)?;
        let key = encode_slot_root_key(slot, &cursor);
        let base = view
            .read_with(Table::StateDiffs, &key, |frame| {
                beacon_state_delta::unframe(frame).0
            })
            .expect("read");
        match base {
            Some(base_root) => cursor = base_root,
            None => return Some(cursor),
        }
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
        let Some(slot) = block_slot_in(view.as_ref(), Chain::Lean, &cursor) else {
            return Ok(None);
        };
        let key = encode_slot_root_key(slot, &cursor);
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
/// the answer *before* deciding whether to fetch a snapshot's encoded bytes at
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
/// `base` is `Some((snapshot_root, snapshot_encoded_bytes))` for a state that
/// diffs, and `None` for an anchor. The base is the nearest snapshot on the
/// state's branch, not its parent: a diff then carries every change since that
/// snapshot, and reading any state back is one snapshot plus one delta however
/// far into the interval it sits. The frame names the snapshot as its
/// `base_root`. Carrying the anchor decision in this argument rather than in a
/// separate flag is what keeps a caller from fetching a base it will not use;
/// see [`is_anchor`].
///
/// `slot` is passed rather than read off `state` because the caller has
/// already computed it for [`is_anchor`], and because
/// [`BeaconState::slot`] panics on the lean arm: a signature that cannot
/// reach that panic is worth more than one that merely never does.
pub(crate) fn plan_beacon_state_write(
    state: &BeaconState,
    slot: u64,
    base: Option<(H256, &[u8])>,
) -> StateWrite {
    let target = encode_state_value(state);
    match base {
        None => StateWrite {
            snapshot: Some(target.clone()),
            diff: None,
            encoded: Some(target),
        },
        Some((snapshot_root, base)) => {
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
            let framed = beacon_state_delta::frame(snapshot_root, slot, target_len, &delta);
            StateWrite {
                snapshot: None,
                diff: Some(framed),
                encoded: None,
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

/// What travels down the writer's channel, served strictly in order.
enum Message {
    Write(StateWriteRequest),
    /// Answered once every message queued before it has been served; see
    /// [`StateWriterHandle::flush`].
    Flush(SyncSender<()>),
    /// Test-only: parks the thread until the paired sender sends or drops.
    #[cfg(test)]
    Pause(Receiver<()>),
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
    /// Root and [`encode_state_value`] bytes of the snapshot the newest beacon
    /// diffs are taken against, so a diff does not re-read a snapshot of over a
    /// hundred megabytes on every import.
    ///
    /// Set whenever this thread writes a beacon snapshot, and when it has to
    /// load one from the backend (after a restart, or a fork off an older
    /// interval). Thread-local and a plain `Option`, not a shared `Mutex`:
    /// requests are drained in order by this one thread.
    snapshot_memo: Option<(H256, Vec<u8>)>,
    /// The last beacon state this thread wrote and the snapshot root it
    /// belongs to (itself when it was a snapshot).
    ///
    /// Requests are drained in order, so the parent of the state being written
    /// is almost always this one, which answers "which snapshot does my parent
    /// belong to" without a read.
    last_base: Option<(H256, H256)>,
}

impl StateWriter {
    fn run(mut self, rx: Receiver<Message>) {
        for message in rx {
            match message {
                Message::Write(request) => {
                    self.write(&request);
                    // Only now, after the commit returned: until this line both
                    // the buffer and the backend can answer for this root, and
                    // after it the backend alone can. There is no instant where
                    // neither does.
                    self.pending.remove(&request.root);
                    crate::metrics::dec_state_write_queue_depth();
                }
                // The flusher may have given up waiting; nothing to do then.
                Message::Flush(done) => drop(done.send(())),
                #[cfg(test)]
                Message::Pause(resume) => drop(resume.recv()),
            }
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
                let snapshot_root = (!is_anchor(slot, parent_slot, interval))
                    .then(|| self.load_snapshot_base(parent_root));
                let base = snapshot_root.map(|root| {
                    let (memo_root, bytes) = self
                        .snapshot_memo
                        .as_ref()
                        .expect("load_snapshot_base fills the memo");
                    debug_assert_eq!(*memo_root, root);
                    (root, bytes.as_slice())
                });
                plan_beacon_state_write(beacon_state, slot, base)
            }
        };

        debug_assert!(
            write.snapshot.is_some() || write.diff.is_some(),
            "a state write that persists nothing would silently drop the state"
        );
        // Keyed by the slot of the block the state belongs to, which is what a
        // reader holding only a root recovers from `BlockHeaders`. Not
        // `state.slot()`: a beacon anchor state can be advanced past its block.
        let block_slot = match &*request.state {
            BeaconState::Lean(lean) => lean.latest_block_header.slot,
            beacon_state => beacon_state.latest_block_header().slot,
        };
        let key = encode_slot_root_key(block_slot, &root);
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

        if matches!(&*request.state, BeaconState::Lean(_)) {
            return;
        }
        match write.encoded {
            // A snapshot is its own base, and the next diffs are taken against it.
            Some(encoded) => {
                self.snapshot_memo = Some((root, encoded));
                self.last_base = Some((root, root));
            }
            None => {
                let (snapshot_root, _) = self
                    .snapshot_memo
                    .as_ref()
                    .expect("a beacon diff is planned against the memoized snapshot");
                self.last_base = Some((root, *snapshot_root));
            }
        }
    }

    /// Makes `snapshot_memo` hold the snapshot that `parent_root`'s state
    /// belongs to, and returns that snapshot's root.
    ///
    /// The common case is free: `last_base` names the snapshot of the state
    /// this thread wrote last, which is almost always the parent, and the memo
    /// holds that snapshot's bytes. A miss (a restart, or a fork off an older
    /// block) resolves the snapshot with [`nearest_snapshot_root`] and, if the
    /// memo is for another snapshot, reads its `States` row and replaces the
    /// memo.
    ///
    /// # Panics
    ///
    /// If the snapshot has no row. This is only reached once
    /// [`beacon_block_slot`] has found a parent block, which is only ever true
    /// once that parent's own state has already been written, and a state's
    /// snapshot is committed before the state itself: this thread is the only
    /// writer and drains requests in order.
    fn load_snapshot_base(&mut self, parent_root: H256) -> H256 {
        let snapshot_root = match self.last_base {
            Some((last_root, snapshot_root)) if last_root == parent_root => snapshot_root,
            _ => {
                let view = self.backend.begin_read().expect("read view");
                nearest_snapshot_root(view.as_ref(), &parent_root)
                    .expect("parent state must exist to diff against")
            }
        };
        if self
            .snapshot_memo
            .as_ref()
            .is_some_and(|(root, _)| *root == snapshot_root)
        {
            return snapshot_root;
        }
        let view = self.backend.begin_read().expect("read view");
        let slot = block_slot_in(view.as_ref(), Chain::Beacon, &snapshot_root)
            .expect("the snapshot's block must exist");
        let key = encode_slot_root_key(slot, &snapshot_root);
        let bytes = view
            .read_with(Table::States, &key, <[u8]>::to_vec)
            .expect("read")
            .expect("the parent's snapshot must be committed before the parent itself");
        self.snapshot_memo = Some((snapshot_root, bytes));
        snapshot_root
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
    tx: Option<SyncSender<Message>>,
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
            snapshot_memo: None,
            last_base: None,
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
        self.send_message(Message::Write(request));
        (start, Instant::now())
    }

    /// Blocks until every state handed off before this call has committed.
    ///
    /// The marker queues behind those writes like any other message, so this
    /// waits for at most a full queue plus the write in flight, the same bound
    /// a blocked [`send`](Self::send) already has. The writer never waits on a
    /// caller, so this cannot deadlock.
    ///
    /// # Panics
    ///
    /// If the writer thread is gone or dies before reaching the marker, for
    /// the same reason [`send`](Self::send) does.
    pub(crate) fn flush(&self) {
        let (done_tx, done_rx) = sync_channel(1);
        self.send_message(Message::Flush(done_tx));
        done_rx
            .recv()
            .expect("the state writer thread died; see the logged panic above");
    }

    /// Test-only: parks the writer once it reaches this point in the queue,
    /// until the returned sender sends or is dropped.
    #[cfg(test)]
    pub(crate) fn pause(&self) -> SyncSender<()> {
        let (resume_tx, resume_rx) = sync_channel(1);
        self.send_message(Message::Pause(resume_rx));
        resume_tx
    }

    fn send_message(&self, message: Message) {
        self.tx
            .as_ref()
            .expect("the sender is taken only in Drop")
            .send(message)
            .expect("the state writer thread died; see the logged panic above");
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
    fn a_beacon_plan_with_no_base_writes_a_snapshot_carrying_the_memo() {
        let state = BeaconState::Lean(base_state());
        let slot = state.expect_lean().slot;
        let plan = plan_beacon_state_write(&state, slot, None);
        assert!(
            plan.snapshot.is_some(),
            "no base means nothing to diff against"
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
        let snapshot = base_state();
        let child = child_state(&snapshot, snapshot.slot + 1);
        let snapshot_root = snapshot.latest_block_header.hash_tree_root();

        let base = encode_state_value(&BeaconState::Lean(snapshot));
        let slot = child.slot;
        let state = BeaconState::Lean(child);
        let target = encode_state_value(&state);
        let plan = plan_beacon_state_write(&state, slot, Some((snapshot_root, &base)));

        assert!(
            plan.snapshot.is_none(),
            "a base means a diff, not a snapshot"
        );
        assert!(
            plan.encoded.is_none(),
            "only a snapshot is a diff base, so a diff keeps no memo bytes"
        );
        let framed = plan.diff.expect("a non-anchor records a diff");
        let (read_base_root, framed_slot, target_len, delta) = beacon_state_delta::unframe(&framed);
        assert_eq!(
            read_base_root, snapshot_root,
            "the frame names the snapshot it was diffed against"
        );
        assert_eq!(
            framed_slot, slot,
            "the frame carries the target state's slot"
        );
        assert_eq!(
            beacon_state_delta::decode(delta, &base, target_len as usize),
            target
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
