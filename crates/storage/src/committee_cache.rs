//! The committee-shuffling cache: [`EpochCommittees`] shared across every
//! caller asking the same epoch's committees of a state that agrees on the
//! shuffling's deciding block.
//!
//! Held by the `Store`, shared by both actors this node runs the beacon half
//! on: the chain actor's state transition and fork choice, and p2p's gossip
//! validation tasks (blocking threads that call `Store::committee_cache`
//! concurrently with the chain actor). Held there rather than in a global or
//! rebuilt inside each helper, for the same reason [`crate::store::Store`]'s
//! `state_cache` is: which shufflings are worth keeping resident, and how
//! much memory that may cost, is the store's decision and not something a
//! leaf helper can answer. A caller with no `Store` of its own (a spec
//! runner, a one-off lookup, a unit test) holds a fresh
//! [`CommitteeCache::default`] for as long as that work lasts instead.
//!
//! This module knows nothing about a `BeaconState`: it is handed a
//! [`ShufflingKey`] and, on a miss, runs a builder closure that hands back
//! the finished [`EpochCommittees`]. The consensus logic that derives both
//! from a state (the active-set scan, the shuffle seed, the shuffle itself,
//! and the deciding-block lookup that makes a key sound to share across
//! states) lives in `ethlambda-state-transition`'s
//! `beacon::helpers::accessors`, in the `CommitteeCacheExt` trait this type
//! implements there: that crate depends on this one, not the other way
//! around, so the derivation cannot live here.

use std::sync::{Arc, Mutex, OnceLock};

use ethlambda_types::beacon::committees::EpochCommittees;
use ethlambda_types::beacon::primitives::{Epoch, Root};

/// What pins the committees a state names for an epoch: the epoch itself, and
/// the last block root that could still have changed them.
///
/// The same key lighthouse calls an `AttestationShufflingId`, and for the same
/// reason. An epoch `E`'s committees are fixed by two values and nothing else:
/// the active validator set at `E`, and the shuffle seed at `E`. The seed is
/// the RANDAO mix from epoch `E - MIN_SEED_LOOKAHEAD - 1`, complete once that
/// epoch ends. The active set moves only through `activation_epoch` and
/// `exit_epoch`, and every assignment to either goes through
/// `compute_activation_exit_epoch`, which lands at least `MAX_SEED_LOOKAHEAD`
/// epochs ahead of the epoch making the change. So no block after the end of
/// `E - 2` can alter either input.
///
/// The block root at the last slot of `E - 2` therefore identifies the
/// history that determines `E`'s committees: two states agreeing on it agree
/// on the committees of `E`, however much they disagree about everything
/// since. Epoch and decision root together are what makes a cross-state
/// cache sound where `epoch` or `seed` alone would not be.
///
/// Opaque to this module: `epoch` and `decision_root` are read only for
/// equality and (for eviction) ordering by `epoch`. `ethlambda-state-transition`'s
/// `beacon::helpers::accessors::shuffling_key` is what derives one from a
/// state and knows what the two fields mean; see its own documentation,
/// including for why epochs 0 and 1 are keyed on the genesis block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShufflingKey {
    pub epoch: Epoch,
    pub decision_root: Root,
}

/// How many distinct shufflings stay resident in a [`CommitteeCache`].
///
/// One block needs a pair: every fork's `process_attestation` accepts an
/// attestation whose target is the current or the previous epoch and no
/// other, and fork choice replays that same block's attestations against the
/// same pair. The rest of the room is for forks. Two branches that disagree
/// on an epoch's deciding block have different shufflings for it, so
/// importing their blocks in turn needs both branches' pairs resident at
/// once: with room for only one, each import would evict the entry the other
/// branch's next import asks for, and rebuild its own. A split that outlives
/// an epoch, or one between more than two branches, needs room for more pairs
/// still.
///
/// Tuned rather than derived. An entry is one `u64` per active validator,
/// about 19 MB at mainnet's ~2.4M, so this trades memory for how many
/// concurrent branches import without rebuilding; lighthouse's own default
/// (`DEFAULT_CACHE_SIZE` in its `shuffling_cache.rs`) is larger. It must
/// exceed [`HEAD_SHUFFLINGS`], which eviction never drops, so that a miss
/// always has an entry it may evict; that is checked at compile time below.
const COMMITTEE_CACHE_CAPACITY: usize = 8;

/// How many of the canonical head's shufflings [`CommitteeCache::pin_head`]
/// pins: its previous, current, and next epochs'.
const HEAD_SHUFFLINGS: usize = 3;

/// Where the head's current epoch sits among [`CommitteeCache::pin_head`]'s
/// keys, which name its previous, current and next epochs in that order.
const HEAD_CURRENT_EPOCH: usize = 1;

const _: () = assert!(
    COMMITTEE_CACHE_CAPACITY > HEAD_SHUFFLINGS,
    "the cache must hold at least one shuffling the head does not pin"
);

/// One [`CommitteeCache::get_or_init`] call's verdict on the key it was
/// given: whether an already-finished [`EpochCommittees`] was resident
/// (`Hit`), or the call had to wait on a shuffle instead, whether it ran
/// that shuffle itself or a concurrent call racing it did (`Miss`).
///
/// Recorded by the caller: `ethlambda-state-transition`'s
/// `CommitteeCacheExt::committees` is what turns this into
/// `lean_beacon_committee_cache_lookups_total`'s `hit`/`miss` labels; this
/// module never touches metrics; it does not know they exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup {
    Hit,
    Miss,
}

/// One resident shuffling's slot: empty until some call's builder fills it.
///
/// An `Arc` around the `OnceLock` (rather than the `OnceLock` sitting
/// directly in the entry list) is what lets [`CommitteeCache::evict_one`]
/// drop the entry list's own reference to a slot while a waiter elsewhere
/// still holds a clone of the same `Arc`, taken before eviction ran: the
/// waiter's `get_or_init` call keeps running against a slot that is no
/// longer reachable from the cache at all, exactly as safely as if it had
/// never been evicted.
type Slot = Arc<OnceLock<Arc<EpochCommittees>>>;

/// The state one [`Mutex`] in [`CommitteeCache`] guards: the resident entries
/// and the current head's pins. One lock over both, rather than two, because
/// eviction needs to check the pins while deciding which entry to drop, and
/// the lock is held only for that bookkeeping, never while a shuffle runs;
/// see [`CommitteeCache::get_or_init`].
#[derive(Debug, Default)]
struct CacheState {
    /// Resident shufflings in insertion order, which breaks ties between
    /// entries of the same epoch. Linear-scanned rather than hash-indexed
    /// because [`COMMITTEE_CACHE_CAPACITY`] is small enough that a `HashMap`
    /// would be more machinery than the comparisons it replaces.
    entries: Vec<(ShufflingKey, Slot)>,
    /// The block [`CommitteeCache::pin_head`] was last given, and the
    /// shufflings it pinned for it. `None` until the owner reports a head,
    /// and for a cache nobody reports one to, which then evicts on epoch
    /// alone.
    head: Option<(Root, [Option<ShufflingKey>; HEAD_SHUFFLINGS])>,
}

impl CacheState {
    /// Drops the entry for the oldest epoch the head does not pin, the
    /// earliest inserted among entries of the same epoch.
    fn evict_one(&mut self) {
        let pinned = |key: &ShufflingKey| {
            self.head
                .as_ref()
                .is_some_and(|(_, keys)| keys.contains(&Some(*key)))
        };
        let victim = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, (key, _))| !pinned(key))
            .min_by_key(|(_, (key, _))| key.epoch)
            .map(|(position, _)| position);
        // Always `Some` when the cache is full: the head pins at most
        // `HEAD_SHUFFLINGS` entries, and the capacity is asserted to exceed
        // it.
        if let Some(position) = victim {
            self.entries.remove(position);
        }
    }
}

/// [`EpochCommittees`] shared across the calls asking for the same epoch's
/// committees, so a block's attestations derive each epoch's shuffling once
/// between all of them instead of once apiece.
///
/// Internally synchronized, so every method takes `&self`: see the module
/// documentation for why (both the chain actor and p2p's gossip validation
/// tasks share one of these, held by the `Store`).
///
/// # Eviction
///
/// Lighthouse's rule (`ShufflingCache::prune_cache`): a miss on a full cache
/// drops the entry for the oldest epoch, but never one of the shufflings the
/// canonical head pins through [`Self::pin_head`]. Oldest-first rather
/// than least-recently-used because an older epoch's shuffling is less
/// likely to be asked for again than a newer one's, whichever branch either
/// belongs to, while the head's are the ones its next block is certain to
/// ask for. Every lookup is counted in
/// `lean_beacon_committee_cache_lookups_total`, whose misses are what show
/// whether the capacity is holding up.
#[derive(Debug, Default)]
pub struct CommitteeCache {
    state: Mutex<CacheState>,
}

impl CommitteeCache {
    /// `key`'s committees, running `build` on a miss and sharing the result
    /// with every other call naming the same `key`, including ones already
    /// waiting when this call arrives.
    ///
    /// The entry-list lock is held only long enough to find or insert `key`'s
    /// slot, never while `build` runs: `build` is a whole-epoch shuffle, and
    /// holding the lock across it would make every other lookup, of any key,
    /// wait on this one's shuffle rather than just the callers who share it.
    /// Concurrent misses on the same key instead race
    /// [`OnceLock::get_or_init`] on the slot they all found (having each, in
    /// turn, taken the lock and seen it already there): exactly one of them
    /// runs `build`, and the rest block on its result. A `build` that panics
    /// leaves the slot empty rather than poisoning anything, since nothing
    /// here wraps it in a `Mutex`; the next caller for this key retries it.
    pub fn get_or_init(
        &self,
        key: ShufflingKey,
        build: impl FnOnce() -> EpochCommittees,
    ) -> (Arc<EpochCommittees>, Lookup) {
        let slot = {
            let mut state = self.state.lock().unwrap();
            if let Some((_, slot)) = state
                .entries
                .iter()
                .find(|(entry_key, _)| *entry_key == key)
            {
                Arc::clone(slot)
            } else {
                let slot: Slot = Arc::new(OnceLock::new());
                if state.entries.len() >= COMMITTEE_CACHE_CAPACITY {
                    state.evict_one();
                }
                state.entries.push((key, Arc::clone(&slot)));
                slot
            }
        };

        // Checked outside the lock, and before the `get_or_init` call below
        // that may itself fill it: a slot already filled by an earlier, now
        // finished call is the only case this labels `Hit`. A slot this call
        // just inserted, or one a concurrent call inserted a moment ago and
        // has not finished building yet, is a `Miss` regardless of which of
        // the racing calls ends up actually running `build`.
        let lookup = if slot.get().is_some() {
            Lookup::Hit
        } else {
            Lookup::Miss
        };
        let committees = Arc::clone(slot.get_or_init(|| Arc::new(build())));
        (committees, lookup)
    }

    /// The block root last passed to [`Self::pin_head`], so the owner can
    /// skip re-pinning a head that has not moved.
    pub fn head_root(&self) -> Option<Root> {
        self.state
            .lock()
            .unwrap()
            .head
            .as_ref()
            .map(|(root, _)| *root)
    }

    /// Pins the shufflings `keys` names against eviction, and remembers
    /// `head_root` for [`Self::head_root`].
    ///
    /// Named distinctly from `ethlambda-state-transition`'s
    /// `CommitteeCacheExt::update_head`, rather than reusing that name here
    /// too, because inherent methods shadow trait methods of the same name on
    /// the same receiver: a caller with the extension trait in scope who
    /// meant to call it would silently reach this one instead, and the two
    /// take different arguments (a state there, already-derived keys here).
    /// [`CommitteeCacheExt::update_head`] is what derives `keys` from a head
    /// state's previous, current, and next epochs, and is every real
    /// caller's entry point; this method is the state-agnostic half it calls
    /// into; see its own documentation for why those three epochs are the
    /// right ones to pin.
    ///
    /// Only the pinning is replaced here: whatever the previous head pinned
    /// stays resident until an insertion evicts it on epoch like any other
    /// entry.
    pub fn pin_head(&self, head_root: Root, keys: [Option<ShufflingKey>; HEAD_SHUFFLINGS]) {
        self.state.lock().unwrap().head = Some((head_root, keys));
    }

    /// The pinned head's current-epoch committees, if that shuffling has been
    /// built.
    ///
    /// Never builds one: a caller that only wants a figure off the head (the
    /// active validator count gossipsub scoring sizes its expected message
    /// rates by) has no state to build from, and waiting for the chain actor
    /// to need that shuffling is cheaper than deriving it here. `None` until
    /// a head has been pinned and its current epoch's shuffling filled in.
    pub fn head_current_committees(&self) -> Option<Arc<EpochCommittees>> {
        let state = self.state.lock().unwrap();
        let (_, keys) = state.head.as_ref()?;
        let current = keys[HEAD_CURRENT_EPOCH]?;
        let (_, slot) = state.entries.iter().find(|(key, _)| *key == current)?;
        slot.get().cloned()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Barrier;
    use std::thread;

    use super::*;

    /// A trivial builder result: these tests exercise the cache's own
    /// bookkeeping (keying, eviction, pinning, single-flight, sharing), never
    /// the shuffle itself, so an empty `EpochCommittees` is as good as a real
    /// one for every assertion here.
    fn dummy_committees(epoch: Epoch) -> EpochCommittees {
        EpochCommittees::new(epoch, Vec::new(), 1)
    }

    fn key(epoch: Epoch, decision_root: u8) -> ShufflingKey {
        ShufflingKey {
            epoch,
            decision_root: Root::repeat_byte(decision_root),
        }
    }

    /// A second lookup of the same key must be served the first lookup's
    /// `EpochCommittees` rather than rebuilding it.
    #[test]
    fn a_repeat_lookup_is_served_from_the_cache() {
        let cache = CommitteeCache::default();
        let k = key(1, 0);

        let (first, first_lookup) = cache.get_or_init(k, || dummy_committees(1));
        let (second, second_lookup) = cache.get_or_init(k, || panic!("should not rebuild"));

        assert_eq!(first_lookup, Lookup::Miss);
        assert_eq!(second_lookup, Lookup::Hit);
        assert!(Arc::ptr_eq(&first, &second));
    }

    /// The cache must not grow past its capacity as distinct keys accumulate.
    #[test]
    fn the_cache_stays_within_its_capacity_bound() {
        let cache = CommitteeCache::default();
        for n in 0..COMMITTEE_CACHE_CAPACITY + 5 {
            let k = key(n as Epoch, n as u8);
            cache.get_or_init(k, move || dummy_committees(n as Epoch));
            assert!(cache.state.lock().unwrap().entries.len() <= COMMITTEE_CACHE_CAPACITY);
        }
    }

    /// A miss on a full cache drops the entry for the oldest epoch, not the
    /// first one inserted.
    #[test]
    fn a_miss_evicts_the_oldest_epoch_first() {
        let cache = CommitteeCache::default();
        // Insert newest epoch first, so eviction-by-epoch and
        // eviction-by-insertion-order disagree about which entry goes.
        let epochs: Vec<Epoch> = (0..COMMITTEE_CACHE_CAPACITY as Epoch).rev().collect();
        for (n, epoch) in epochs.iter().enumerate() {
            cache.get_or_init(key(*epoch, n as u8), move || dummy_committees(*epoch));
        }

        cache.get_or_init(key(1000, 0xAA), || dummy_committees(1000));

        let resident: Vec<ShufflingKey> = cache
            .state
            .lock()
            .unwrap()
            .entries
            .iter()
            .map(|(k, _)| *k)
            .collect();
        let oldest_epoch = *epochs.iter().min().unwrap();
        assert!(!resident.iter().any(|k| k.epoch == oldest_epoch));
        for epoch in &epochs {
            if *epoch != oldest_epoch {
                assert!(resident.iter().any(|k| k.epoch == *epoch));
            }
        }
    }

    /// The head's pinned shufflings survive any number of misses, even when
    /// they are the oldest entries resident, which is exactly what the epoch
    /// rule would otherwise drop first.
    #[test]
    fn the_heads_shufflings_are_never_evicted() {
        let cache = CommitteeCache::default();
        let pinned_keys = [Some(key(1, 1)), Some(key(2, 2)), Some(key(3, 3))];
        for k in pinned_keys.into_iter().flatten() {
            cache.get_or_init(k, move || dummy_committees(k.epoch));
        }
        cache.pin_head(Root::repeat_byte(0xAA), pinned_keys);
        assert_eq!(cache.head_root(), Some(Root::repeat_byte(0xAA)));

        for n in 0..COMMITTEE_CACHE_CAPACITY as u8 * 3 {
            let k = key(100 + n as Epoch, n);
            cache.get_or_init(k, move || dummy_committees(k.epoch));
        }

        let resident: Vec<ShufflingKey> = cache
            .state
            .lock()
            .unwrap()
            .entries
            .iter()
            .map(|(k, _)| *k)
            .collect();
        for k in pinned_keys.into_iter().flatten() {
            assert!(resident.contains(&k), "pinned {k:?} was evicted");
        }
        assert!(cache.state.lock().unwrap().entries.len() <= COMMITTEE_CACHE_CAPACITY);
    }

    /// `head_current_committees` answers with the pinned head's
    /// current-epoch entry, the middle of the three it pins, and only once
    /// that entry has been built: it is a read, never a derivation.
    #[test]
    fn the_head_current_committees_are_the_middle_pin_once_built() {
        let cache = CommitteeCache::default();
        assert!(cache.head_current_committees().is_none(), "nothing pinned");

        let pinned_keys = [Some(key(1, 1)), Some(key(2, 2)), Some(key(3, 3))];
        cache.pin_head(Root::repeat_byte(0xAA), pinned_keys);
        assert!(
            cache.head_current_committees().is_none(),
            "pinned but not built"
        );

        cache.get_or_init(key(2, 2), || EpochCommittees::new(2, vec![7, 8, 9], 1));
        let current = cache
            .head_current_committees()
            .expect("the current epoch's shuffling is built");
        assert_eq!(current.active_validator_count(), 3);
    }

    /// Concurrent misses on the same key must run `build` exactly once: the
    /// rest wait on the first call's result rather than each deriving their
    /// own. This is the property the module documentation calls load-bearing
    /// at an epoch boundary, where dozens of validation tasks miss the same
    /// key at once.
    #[test]
    fn concurrent_misses_on_one_key_run_the_builder_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let cache = Arc::new(CommitteeCache::default());
        let k = key(7, 7);
        let build_calls = Arc::new(AtomicUsize::new(0));
        let threads = 16;
        // Every thread reaches `get_or_init` before any of them may proceed
        // into it, so the race is real rather than accidentally serialized
        // by however fast each thread happens to spawn.
        let barrier = Arc::new(Barrier::new(threads));

        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let cache = Arc::clone(&cache);
                let build_calls = Arc::clone(&build_calls);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    let (committees, _) = cache.get_or_init(k, || {
                        build_calls.fetch_add(1, Ordering::SeqCst);
                        // A little work, so a thread that would have run its
                        // own independent shuffle has time to, if the
                        // single-flight guarantee did not hold.
                        thread::yield_now();
                        dummy_committees(k.epoch)
                    });
                    committees
                })
            })
            .collect();

        let results: Vec<Arc<EpochCommittees>> =
            handles.into_iter().map(|h| h.join().unwrap()).collect();

        assert_eq!(build_calls.load(Ordering::SeqCst), 1);
        for committees in &results[1..] {
            assert!(Arc::ptr_eq(&results[0], committees));
        }
    }

    /// Every clone of a `CommitteeCache` shares one underlying cache: a
    /// lookup through one clone is a hit through another. `CommitteeCache`
    /// does not itself derive `Clone` (its only owner, `Store`, holds it
    /// behind an `Arc` and clones that instead), so this wraps it the same
    /// way and checks the sharing the `Arc` is there to provide.
    #[test]
    fn clones_of_the_cache_share_one_underlying_cache() {
        let cache = Arc::new(CommitteeCache::default());
        let clone = Arc::clone(&cache);

        let (first, _) = cache.get_or_init(key(1, 1), || dummy_committees(1));
        let (second, lookup) = clone.get_or_init(key(1, 1), || panic!("should not rebuild"));

        assert_eq!(lookup, Lookup::Hit);
        assert!(Arc::ptr_eq(&first, &second));
    }
}
