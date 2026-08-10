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
}
