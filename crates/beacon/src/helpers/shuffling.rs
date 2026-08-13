//! The committee shuffle.
//!
//! The specification shuffles with the "swap-or-not" construction, which has two
//! properties the beacon chain needs. It is a permutation, so every validator
//! lands in exactly one committee. And it can be evaluated for a single index
//! without computing the whole permutation, which is what lets a client work out
//! one committee without shuffling the entire registry.
//!
//! The cost is that shuffling one index runs `SHUFFLE_ROUND_COUNT` rounds of
//! hashing, so computing a whole committee this way rehashes the same rounds
//! repeatedly. That is the specification's own formulation and what the fixtures
//! pin down, so it is what this implements.

use std::sync::{Arc, Mutex};

use crate::error::{Error, Result};
use crate::hash::hash;
use crate::preset;
use crate::primitives::{Bytes32, Gwei, ValidatorIndex};

use super::math::bytes_to_uint64;

/// Where `index` ends up after shuffling a set of `index_count` items under
/// `seed`.
///
/// Fails if `index` is not in range, which the specification asserts.
pub fn compute_shuffled_index(index: u64, index_count: u64, seed: Bytes32) -> Result<u64> {
    crate::verify(index < index_count, "index < index_count")?;

    let mut index = index;
    for round in 0..preset::SHUFFLE_ROUND_COUNT {
        let round_byte = round as u8;

        // The pivot for this round, derived from the seed and the round number.
        let mut pivot_input = Vec::with_capacity(33);
        pivot_input.extend_from_slice(&seed.0);
        pivot_input.push(round_byte);
        let pivot = bytes_to_uint64(&hash(&pivot_input).0[0..8]) % index_count;

        // The position `index` would swap with, and the higher of the two, which
        // is the one the decision bit is drawn for. Taking the maximum is what
        // makes the swap symmetric, and therefore a permutation.
        let flip = (pivot + index_count - index) % index_count;
        let position = index.max(flip);

        // One bit out of a hash covering a 256-position window, so a whole
        // window's decisions come from a single hash.
        let mut source_input = Vec::with_capacity(37);
        source_input.extend_from_slice(&seed.0);
        source_input.push(round_byte);
        source_input.extend_from_slice(&((position / 256) as u32).to_le_bytes());
        let source = hash(&source_input);

        let byte = source.0[((position % 256) / 8) as usize];
        let bit = (byte >> (position % 8)) % 2;
        if bit == 1 {
            index = flip;
        }
    }

    Ok(index)
}

/// The `index`-th of `count` committees drawn from `indices` under `seed`.
pub fn compute_committee(
    indices: &[ValidatorIndex],
    seed: Bytes32,
    index: u64,
    count: u64,
) -> Result<Vec<ValidatorIndex>> {
    crate::verify(count > 0, "count > 0")?;

    let total = indices.len() as u64;
    let start = (total * index) / count;
    let end = (total * (index + 1)) / count;

    let mut committee = Vec::with_capacity((end - start) as usize);
    for position in start..end {
        let shuffled = compute_shuffled_index(position, total, seed)?;
        let validator = indices
            .get(shuffled as usize)
            .ok_or(Error::IndexOutOfBounds {
                index: shuffled as usize,
                len: indices.len(),
            })?;
        committee.push(*validator);
    }
    Ok(committee)
}

/// The `index`-th of `count` committees, sliced out of a whole-list shuffle
/// already computed by [`compute_shuffled_indices`] (or fetched warm from
/// [`cached_shuffled_indices`]), rather than re-deriving each member's
/// position with its own `SHUFFLE_ROUND_COUNT`-round call.
///
/// `shuffling` must be exactly `compute_shuffled_indices(indices.len() as u64,
/// seed)` for whichever `seed` produced it: this performs no round of hashing
/// itself, so nothing here checks that. [`super::accessors::EpochCommittees`]
/// is the only caller and is what upholds that invariant, by always pairing a
/// shuffling with the active set it was computed over.
pub(crate) fn compute_committee_from_shuffling(
    indices: &[ValidatorIndex],
    shuffling: &[u64],
    index: u64,
    count: u64,
) -> Result<Vec<ValidatorIndex>> {
    crate::verify(count > 0, "count > 0")?;

    let total = indices.len() as u64;
    let start = (total * index) / count;
    let end = (total * (index + 1)) / count;

    let mut committee = Vec::with_capacity((end - start) as usize);
    for position in start..end {
        let shuffled = shuffling[position as usize];
        let validator = indices
            .get(shuffled as usize)
            .ok_or(Error::IndexOutOfBounds {
                index: shuffled as usize,
                len: indices.len(),
            })?;
        committee.push(*validator);
    }
    Ok(committee)
}

/// The whole-list form of [`compute_shuffled_index`]: `result[p]` equals
/// `compute_shuffled_index(p, index_count, seed).unwrap()` for every `p` in
/// `0..index_count`, computed together instead of one call per `p`.
///
/// [`compute_shuffled_index`] rehashes from scratch for every position it is
/// asked about: `SHUFFLE_ROUND_COUNT` pivot hashes, and for each round a fresh
/// 256-position "source" window hash even though the caller only ever reads
/// one bit out of it. Asked about the same `(seed, index_count)` many times —
/// which is exactly what one epoch's worth of [`super::accessors::get_beacon_committee`]
/// calls does — that repeats the same rounds of hashing once per position
/// instead of once per epoch.
///
/// This instead processes one round across every position at a time: one
/// pivot hash, then one source hash per 256-position window
/// (`index_count.div_ceil(256)` of them — a permutation of `index_count`
/// positions covers every window at least once, so precomputing all of them
/// up front costs no more than the minimum any position in that window would
/// need) rather than one source hash per position queried, however many of
/// those there turn out to be.
///
/// Verified against [`compute_shuffled_index`] directly, over a range of
/// sizes and seeds including the 0-, 1-, and 2-element edge cases, by
/// [`tests::whole_list_shuffle_matches_the_per_index_shuffle`]: the two must
/// compute the same permutation, since this is a performance change to how
/// the permutation is derived and not a change to what the permutation is.
pub fn compute_shuffled_indices(index_count: u64, seed: Bytes32) -> Vec<u64> {
    let n = index_count;
    let mut positions: Vec<u64> = (0..n).collect();
    if n < 2 {
        // `compute_shuffled_index` would divide by `n` immediately below; for
        // `n == 1` every round's pivot, flip, and bit computation is moot
        // anyway, since the only valid index always flips to itself. `n == 0`
        // has no valid index at all, so the empty permutation is the only
        // sensible answer.
        return positions;
    }

    let window_count = n.div_ceil(256) as usize;
    let mut window_hashes: Vec<Bytes32> = Vec::with_capacity(window_count);

    for round in 0..preset::SHUFFLE_ROUND_COUNT {
        let round_byte = round as u8;

        let mut pivot_input = Vec::with_capacity(33);
        pivot_input.extend_from_slice(&seed.0);
        pivot_input.push(round_byte);
        let pivot = bytes_to_uint64(&hash(&pivot_input).0[0..8]) % n;

        window_hashes.clear();
        for window in 0..window_count {
            let mut source_input = Vec::with_capacity(37);
            source_input.extend_from_slice(&seed.0);
            source_input.push(round_byte);
            source_input.extend_from_slice(&(window as u32).to_le_bytes());
            window_hashes.push(hash(&source_input));
        }

        for value in positions.iter_mut() {
            let flip = (pivot + n - *value) % n;
            let position = (*value).max(flip);
            let window = &window_hashes[(position / 256) as usize];
            let byte = window.0[((position % 256) / 8) as usize];
            let bit = (byte >> (position % 8)) % 2;
            if bit == 1 {
                *value = flip;
            }
        }
    }

    positions
}

/// Bounds [`SHUFFLE_CACHE`]: how many distinct `(seed, index_count)`
/// shufflings stay memoized at once.
///
/// Two, not "a few" and not unbounded. A shuffling is `8 * index_count`
/// bytes — at mainnet's ~1M active validators, about 8 MB, a meaningful
/// fraction of the ~350 MB state it was derived from — so caching every
/// shuffling ever computed would eventually outgrow the state itself.
/// Two is enough because within the processing of a single block, at most two
/// distinct keys are ever in play: [`crate::stf::electra::process_attestation`]
/// (and its phase0/altair/deneb equivalents) accept an attestation whose
/// target is either the current or the previous epoch, and nothing in this
/// crate's attestation-processing path ever needs a third epoch's shuffling
/// at the same time. A single entry would thrash between those two on every
/// other attestation in a block that mixes both.
const SHUFFLE_CACHE_CAPACITY: usize = 2;

/// One [`SHUFFLE_CACHE`] entry: the `(seed, index_count)` key alongside the
/// shuffling it produced.
type ShuffleCacheEntry = (Bytes32, u64, Arc<Vec<u64>>);

/// The memo [`cached_shuffled_indices`] reads and writes.
///
/// Newest-used entry last, so eviction on a miss always drops index `0`: an
/// ordinary least-recently-used cache, just linear-scanned rather than
/// hash-indexed because [`SHUFFLE_CACHE_CAPACITY`] is 2 and a `HashMap` would
/// be more machinery than the two comparisons it replaces.
static SHUFFLE_CACHE: Mutex<Vec<ShuffleCacheEntry>> = Mutex::new(Vec::new());

/// [`compute_shuffled_indices`], memoized on its two inputs.
///
/// Keying on `(seed, index_count)` alone is sound because those two values
/// are the *entire* input to [`compute_shuffled_indices`]: nothing else in
/// its signature or body varies the result, so equal keys are guaranteed to
/// produce an identical permutation regardless of which state, epoch, or fork
/// asked for it this time. Contrast the *active validator set*
/// ([`super::accessors::get_active_validator_indices`]), which is a function
/// of the state's validator registry and therefore cannot soundly be
/// memoized on `epoch` or `seed` alone: see
/// [`super::accessors::EpochCommittees`]'s own documentation for why, and why
/// this crate does not attempt it.
pub(crate) fn cached_shuffled_indices(index_count: u64, seed: Bytes32) -> Arc<Vec<u64>> {
    let mut cache = SHUFFLE_CACHE
        .lock()
        .expect("shuffle cache mutex: nothing panics while holding it");

    if let Some(position) = cache.iter().position(|(cached_seed, cached_count, _)| {
        *cached_seed == seed && *cached_count == index_count
    }) {
        let entry = cache.remove(position);
        let shuffling = Arc::clone(&entry.2);
        cache.push(entry);
        return shuffling;
    }

    let shuffling = Arc::new(compute_shuffled_indices(index_count, seed));
    if cache.len() >= SHUFFLE_CACHE_CAPACITY {
        cache.remove(0);
    }
    cache.push((seed, index_count, Arc::clone(&shuffling)));
    shuffling
}

/// A proposer sampled from `indices`, weighted by effective balance.
///
/// Rejection sampling rather than a weighted draw: a candidate is picked
/// uniformly, then accepted with probability proportional to its effective
/// balance. That keeps the result computable from the seed alone, with no running
/// total to agree on, at the cost of an unbounded (but in practice very short)
/// number of attempts.
///
/// `effective_balance_of` returns the effective balance for a validator index, so
/// this stays independent of which fork's state it is reading.
///
/// Serves phase0 through deneb only. Electra widens the acceptance test's
/// random draw from one byte to two and weighs against
/// [`preset::MAX_EFFECTIVE_BALANCE_ELECTRA`] rather than a caller-supplied
/// ceiling (EIP-7251: a compounding validator's effective balance can now
/// reach values an 8-bit draw no longer discriminates finely enough between),
/// so from electra on the acceptance test itself changes, not only the
/// ceiling passed in here: [`crate::helpers::electra::compute_proposer_index`]
/// is electra's (and fulu's) own copy, not a caller of this one with a
/// different `max_effective_balance`.
/// [`crate::helpers::accessors::get_beacon_proposer_index`] is where the two
/// are dispatched between by fork; do not call this one directly for a state
/// that might be electra or later.
pub fn compute_proposer_index(
    indices: &[ValidatorIndex],
    seed: Bytes32,
    max_effective_balance: Gwei,
    mut effective_balance_of: impl FnMut(ValidatorIndex) -> Result<Gwei>,
) -> Result<ValidatorIndex> {
    crate::verify(!indices.is_empty(), "len(indices) > 0")?;

    const MAX_RANDOM_BYTE: u64 = u8::MAX as u64;
    let total = indices.len() as u64;

    let mut attempt = 0u64;
    loop {
        let shuffled = compute_shuffled_index(attempt % total, total, seed)?;
        let candidate = indices[shuffled as usize];

        let mut random_input = Vec::with_capacity(40);
        random_input.extend_from_slice(&seed.0);
        random_input.extend_from_slice(&(attempt / 32).to_le_bytes());
        let random_byte = hash(&random_input).0[(attempt % 32) as usize] as u64;

        let effective_balance = effective_balance_of(candidate)?;
        if effective_balance * MAX_RANDOM_BYTE >= max_effective_balance * random_byte {
            return Ok(candidate);
        }

        attempt += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shuffling_is_a_permutation() {
        // Every index must map to a distinct index in range, otherwise a
        // validator would land in two committees or none.
        let seed = Bytes32::repeat_byte(0x42);
        let count = 25u64;

        let mut seen = vec![false; count as usize];
        for index in 0..count {
            let shuffled = compute_shuffled_index(index, count, seed).unwrap();
            assert!(shuffled < count);
            assert!(!seen[shuffled as usize], "{shuffled} produced twice");
            seen[shuffled as usize] = true;
        }
        assert!(seen.into_iter().all(|hit| hit));
    }

    #[test]
    fn shuffling_depends_on_the_seed() {
        let count = 20u64;
        let a: Vec<u64> = (0..count)
            .map(|i| compute_shuffled_index(i, count, Bytes32::repeat_byte(1)).unwrap())
            .collect();
        let b: Vec<u64> = (0..count)
            .map(|i| compute_shuffled_index(i, count, Bytes32::repeat_byte(2)).unwrap())
            .collect();
        assert_ne!(a, b);
    }

    #[test]
    fn an_out_of_range_index_is_rejected() {
        assert!(compute_shuffled_index(5, 5, Bytes32::zero()).is_err());
    }

    #[test]
    fn committees_partition_the_validator_set() {
        // Splitting into `count` committees must cover every validator exactly
        // once, since the split is over positions of one permutation.
        let indices: Vec<ValidatorIndex> = (0..40).collect();
        let seed = Bytes32::repeat_byte(7);
        let count = 4;

        let mut all = Vec::new();
        for index in 0..count {
            all.extend(compute_committee(&indices, seed, index, count).unwrap());
        }
        all.sort_unstable();
        assert_eq!(all, indices);
    }

    #[test]
    fn proposer_selection_prefers_a_full_balance() {
        // With one full-balance validator and the rest at a token balance, the
        // full one should be chosen overwhelmingly often. This checks the
        // acceptance test is the right way round, which a uniform draw would not
        // catch.
        let indices: Vec<ValidatorIndex> = (0..16).collect();
        let max = 32_000_000_000u64;

        let mut chose_the_rich_one = 0;
        for trial in 0..32u8 {
            let chosen =
                compute_proposer_index(&indices, Bytes32::repeat_byte(trial), max, |index| {
                    Ok(if index == 3 { max } else { 1 })
                })
                .unwrap();
            if chosen == 3 {
                chose_the_rich_one += 1;
            }
        }
        assert!(
            chose_the_rich_one > 16,
            "the full-balance validator was chosen {chose_the_rich_one} times out of 32"
        );
    }

    #[test]
    fn proposer_selection_rejects_an_empty_set() {
        assert!(compute_proposer_index(&[], Bytes32::zero(), 1, |_| Ok(1)).is_err());
    }

    /// [`compute_shuffled_indices`] is a from-scratch reimplementation of the
    /// same permutation [`compute_shuffled_index`] computes one position at a
    /// time, sharing hashing across positions instead of repeating it. A bug
    /// in the sharing would produce *a* permutation, quietly wrong, not a
    /// panic or an out-of-range value — so this checks every position agrees
    /// with the per-index function directly, across sizes small enough to be
    /// exhaustive and large enough to cross several 256-position hash
    /// windows, and across several seeds so no single seed's structure hides
    /// a bug.
    ///
    /// Covers `index_count` 0, 1, and 2 explicitly (no shuffling, a
    /// single-element no-op, and the smallest case with an actual swap to
    /// get right), since those are exactly the sizes where an off-by-one in
    /// the pairing or the early-return guard would show up.
    #[test]
    fn whole_list_shuffle_matches_the_per_index_shuffle() {
        let seeds = [
            Bytes32::zero(),
            Bytes32::repeat_byte(0xff),
            Bytes32::repeat_byte(0x42),
            Bytes32::repeat_byte(0x17),
        ];
        let sizes = [
            0u64, 1, 2, 3, 4, 5, 16, 25, 100, 255, 256, 257, 511, 512, 1000,
        ];

        for seed in seeds {
            for &count in &sizes {
                let whole_list = compute_shuffled_indices(count, seed);
                assert_eq!(
                    whole_list.len(),
                    count as usize,
                    "count={count}, seed={seed:?}"
                );

                for position in 0..count {
                    let expected = compute_shuffled_index(position, count, seed)
                        .expect("position is in range by construction");
                    assert_eq!(
                        whole_list[position as usize], expected,
                        "count={count}, seed={seed:?}, position={position}"
                    );
                }
            }
        }
    }

    #[test]
    fn empty_shuffle_has_no_positions() {
        // `compute_shuffled_index` has no valid input at all when
        // `index_count` is 0 (every index is out of range), so the whole-list
        // form's only sensible answer is the empty permutation, checked here
        // rather than folded into the sweep above since there is no per-index
        // call to compare it against.
        assert!(compute_shuffled_indices(0, Bytes32::zero()).is_empty());
    }

    #[test]
    fn cached_shuffled_indices_matches_the_uncached_computation() {
        let seed = Bytes32::repeat_byte(0x99);
        let count = 130u64;
        assert_eq!(
            *cached_shuffled_indices(count, seed),
            compute_shuffled_indices(count, seed)
        );
        // A second call for the same key must hit the cache and still agree.
        assert_eq!(
            *cached_shuffled_indices(count, seed),
            compute_shuffled_indices(count, seed)
        );
    }

    #[test]
    fn shuffle_cache_stays_within_its_capacity_bound() {
        // Distinct keys, one per iteration, deliberately more than
        // `SHUFFLE_CACHE_CAPACITY`: every insertion must evict rather than
        // grow the cache without bound.
        for seed_byte in 0..(SHUFFLE_CACHE_CAPACITY as u8 + 5) {
            cached_shuffled_indices(4, Bytes32::repeat_byte(seed_byte));
            let cache = SHUFFLE_CACHE.lock().unwrap();
            assert!(cache.len() <= SHUFFLE_CACHE_CAPACITY, "{}", cache.len());
        }
    }
}
