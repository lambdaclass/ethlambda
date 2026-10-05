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
//! pin down, so [`compute_shuffled_index`] and [`compute_committee`] implement it
//! as written. [`shuffle_list`] computes the same permutation for a whole list at
//! once, which is what deriving every committee of an epoch actually wants.

use crate::beacon::error::{Error, Result};
use crate::beacon::hash::hash;
use crate::beacon::preset;
use crate::beacon::primitives::{Bytes32, Gwei, ValidatorIndex};

use super::math::bytes_to_uint64;

/// Where `index` ends up after shuffling a set of `index_count` items under
/// `seed`.
///
/// Fails if `index` is not in range, which the specification asserts.
pub fn compute_shuffled_index(index: u64, index_count: u64, seed: Bytes32) -> Result<u64> {
    crate::beacon::verify(index < index_count, "index < index_count")?;

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

/// The whole-list form of [`compute_shuffled_index`], applied to `list`:
/// position `i` of the result holds `list[compute_shuffled_index(i, n, seed)]`
/// for every `i` in `0..n`, where `n` is `list.len()`. That is the order
/// [`compute_committee`] reads its `indices` in, so shuffling an epoch's active
/// set through this once lays out every committee of the epoch as a contiguous
/// run of the result.
///
/// Shuffles `list` in place and hands the same buffer back, so the caller's
/// active set becomes the shuffled set with no second list alongside it.
///
/// # How
///
/// Each swap-or-not round is an involution on positions: it pairs `i` with
/// `(pivot - i) mod n`, and swaps a pair when the round's source bit at the
/// higher of the two positions is set. So a round needs one decision per
/// *pair*, not per position, and the pairs split into two runs that can each
/// be walked in order: `i + j = pivot` for `i, j` in `0..=pivot`, and
/// `i + j = pivot + n` for `i, j` in `pivot + 1..n`. Each run is walked from
/// its outer ends inward, with `j` the higher member, stepping down: the
/// source hash covers a 256-position window, so `j` rehashes only on crossing
/// into the next window down, and reloads its byte only every eighth
/// position. Self-paired positions (`i == j`) are fixed points and never
/// visited.
///
/// Rounds run last to first. [`compute_shuffled_index`] applies round `0`
/// first to an *index*, so gathering a *list* through the same rounds has to
/// apply them in the opposite order for position `i` to end up holding
/// `list[compute_shuffled_index(i)]`.
///
/// The algorithm is protolambda's, as lighthouse ships it in
/// `swap_or_not_shuffle::shuffle_list` with `forwards = false`. Verified
/// position by position against [`compute_shuffled_index`] by
/// `tests::whole_list_shuffle_matches_the_per_index_shuffle`: a mistake in
/// the pairing would still yield *a* permutation, quietly wrong, rather than a
/// panic.
pub fn shuffle_list(mut list: Vec<ValidatorIndex>, seed: Bytes32) -> Vec<ValidatorIndex> {
    let n = list.len();
    if n < 2 {
        // No pair to swap. `compute_shuffled_index` would also divide by `n`
        // below, and for `n == 1` the only position always flips to itself.
        return list;
    }

    // `seed || round || window`, the layout both of the specification's hash
    // inputs share: the pivot hashes the first 33 bytes, a source window all
    // 37. Written once per round and patched per window, rather than rebuilt.
    let mut input = [0u8; 37];
    input[..32].copy_from_slice(&seed.0);
    let source = |input: &mut [u8; 37], position: usize| {
        // `position` is below `VALIDATOR_REGISTRY_LIMIT`, so its window number
        // fits the specification's `uint32`.
        input[33..].copy_from_slice(&((position / 256) as u32).to_le_bytes());
        hash(&input[..]).0
    };

    for round in (0..preset::SHUFFLE_ROUND_COUNT).rev() {
        input[32] = round as u8;
        let pivot = (bytes_to_uint64(&hash(&input[..33]).0[0..8]) % n as u64) as usize;

        // Pairs `(i, pivot - i)`, `i` below the midpoint of `0..=pivot`.
        let mut window = source(&mut input, pivot);
        let mut byte = window[(pivot % 256) / 8];
        for i in 0..pivot.div_ceil(2) {
            let j = pivot - i;
            if j % 256 == 255 {
                window = source(&mut input, j);
            }
            if j % 8 == 7 {
                byte = window[(j % 256) / 8];
            }
            if (byte >> (j % 8)) & 1 == 1 {
                list.swap(i, j);
            }
        }

        // Pairs `(i, pivot + n - i)`, `i` from `pivot + 1` up to the midpoint
        // of `pivot + 1..n`, so `j` walks down from `n - 1`.
        let last = n - 1;
        let mut window = source(&mut input, last);
        let mut byte = window[(last % 256) / 8];
        for (step, i) in (pivot + 1..(pivot + n).div_ceil(2)).enumerate() {
            let j = last - step;
            if j % 256 == 255 {
                window = source(&mut input, j);
            }
            if j % 8 == 7 {
                byte = window[(j % 256) / 8];
            }
            if (byte >> (j % 8)) & 1 == 1 {
                list.swap(i, j);
            }
        }
    }

    list
}

/// The `index`-th of `count` committees drawn from `indices` under `seed`.
pub fn compute_committee(
    indices: &[ValidatorIndex],
    seed: Bytes32,
    index: u64,
    count: u64,
) -> Result<Vec<ValidatorIndex>> {
    crate::beacon::verify(count > 0, "count > 0")?;

    // Checked because `index` is only as bounded as the attestation it came
    // from, and the specification's `uint64` arithmetic raises where a release
    // build would wrap into a real committee's bounds.
    let overflow = || Error::ArithmeticOverflow("len(indices) * (index + 1)");
    let total = indices.len() as u64;
    let start = total.checked_mul(index).ok_or_else(overflow)? / count;
    let end = index
        .checked_add(1)
        .and_then(|past_index| total.checked_mul(past_index))
        .ok_or_else(overflow)?
        / count;

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
/// ceiling passed in here: [`crate::beacon::helpers::electra::compute_proposer_index`]
/// is electra's (and fulu's) own copy, not a caller of this one with a
/// different `max_effective_balance`.
/// [`crate::beacon::helpers::accessors::get_beacon_proposer_index`] is where the two
/// are dispatched between by fork; do not call this one directly for a state
/// that might be electra or later.
pub fn compute_proposer_index(
    indices: &[ValidatorIndex],
    seed: Bytes32,
    max_effective_balance: Gwei,
    mut effective_balance_of: impl FnMut(ValidatorIndex) -> Result<Gwei>,
) -> Result<ValidatorIndex> {
    crate::beacon::verify(!indices.is_empty(), "len(indices) > 0")?;

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
        assert!(compute_shuffled_index(5, 5, Bytes32::ZERO).is_err());
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
        assert!(compute_proposer_index(&[], Bytes32::ZERO, 1, |_| Ok(1)).is_err());
    }

    /// [`shuffle_list`] is a from-scratch reimplementation of the permutation
    /// [`compute_shuffled_index`] computes one position at a time, walking each
    /// round's swap pairs instead of each position. A bug in the pairing would
    /// produce *a* permutation, quietly wrong, not a panic or an out-of-range
    /// value, so this checks every position against the per-index function
    /// directly, across sizes small enough to be exhaustive and large enough
    /// to cross several 256-position hash windows, and across several seeds so
    /// no single seed's pivots hide a bug.
    ///
    /// The list shuffled is not `0..n` but values distinct from their own
    /// positions, so a result that permuted positions the wrong way round
    /// (scattering `list[i]` to `compute_shuffled_index(i)` rather than
    /// gathering from it) cannot pass by coincidence. Covers 0, 1, and 2
    /// explicitly (nothing to shuffle, a single fixed point, and the smallest
    /// real swap), and sizes on both sides of a window boundary, where an
    /// off-by-one in the rehash condition would show up.
    #[test]
    fn whole_list_shuffle_matches_the_per_index_shuffle() {
        let seeds = [
            Bytes32::ZERO,
            Bytes32::repeat_byte(0xff),
            Bytes32::repeat_byte(0x42),
            Bytes32::repeat_byte(0x17),
        ];
        let sizes = [
            0u64, 1, 2, 3, 4, 5, 16, 25, 100, 255, 256, 257, 511, 512, 1000, 1023, 1024, 1025, 2049,
        ];

        for seed in seeds {
            for &count in &sizes {
                let list: Vec<ValidatorIndex> = (0..count).map(|i| i * 3 + 7).collect();
                let shuffled = shuffle_list(list.clone(), seed);
                assert_eq!(shuffled.len(), list.len(), "count={count}, seed={seed:?}");

                for position in 0..count {
                    let source = compute_shuffled_index(position, count, seed)
                        .expect("position is in range by construction");
                    assert_eq!(
                        shuffled[position as usize], list[source as usize],
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
        // form's only sensible answer is the empty list, checked here rather
        // than folded into the sweep above since there is no per-index call to
        // compare it against.
        assert!(shuffle_list(Vec::new(), Bytes32::ZERO).is_empty());
    }
}
