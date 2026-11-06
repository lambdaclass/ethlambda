//! Hashing a whole merkle layer per call.
//!
//! Every inner node of an SSZ tree is `SHA-256(left || right)`: a message of
//! exactly 64 bytes. Going through `Digest` for each pair buffers the input,
//! pads it and finalizes the state in generic code, and does so once per pair
//! of a layer that can hold millions. A 64-byte message is always one data
//! block plus one padding block, and the padding block is the same for every
//! pair, so a layer needs nothing but the block-level compression function:
//! start from the initial state, compress the pair, compress the constant
//! padding, read the state out.
//!
//! This module keeps that as one primitive, [`hash_layer`], that every fold in
//! this crate goes through. It sits on `sha2::compress256`, so the hardware
//! backend `sha2` selects at run time (aarch64 SHA2 instructions, x86 SHA-NI)
//! is the one used, and the output is byte-identical to
//! `libssz_merkle::hash_nodes(&Sha2Hasher, ..)`.
//!
//! The primitive takes the layer as a slice and writes digests to an output
//! slice, so a backend that hashes several independent messages per instruction
//! (AVX2 or AVX-512 lanes, or SHA-NI interleaved) replaces the loop body of
//! [`hash_pairs_into`] without changing a caller.

use libssz_merkle::ZERO_HASHES;
use sha2::compress256;
use sha2::digest::generic_array::{GenericArray, typenum::U64};

use crate::Hash256;

/// SHA-256's initial hash value (FIPS 180-4, section 5.3.3).
const SHA256_IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// The padding block that follows a 64-byte message: the `0x80` terminator,
/// zeros, and the message length in bits (512) as a big-endian `u64`.
const PADDING_BLOCK: [u8; 64] = {
    let mut block = [0u8; 64];
    block[0] = 0x80;
    block[62] = 0x02;
    block
};

/// Hashes every adjacent pair of `input` (`SHA-256(input[2i] || input[2i + 1])`)
/// into `output[i]`.
///
/// # Panics
///
/// If `input.len() != 2 * output.len()`.
pub(crate) fn hash_pairs_into(input: &[Hash256], output: &mut [Hash256]) {
    assert_eq!(input.len(), 2 * output.len(), "a pair per output");
    #[cfg(test)]
    if tests::LEGACY.load(std::sync::atomic::Ordering::Relaxed) {
        // The per-pair `Digest` path this module replaced, kept under test so
        // the benchmark can time old and new in one process.
        for (pair, out) in input.chunks_exact(2).zip(output.iter_mut()) {
            *out = libssz_merkle::hash_nodes(&libssz_merkle::Sha2Hasher, &pair[0], &pair[1]);
        }
        return;
    }
    let padding = GenericArray::<u8, U64>::clone_from_slice(&PADDING_BLOCK);
    for (pair, out) in input.chunks_exact(2).zip(output.iter_mut()) {
        let mut blocks = [padding, padding];
        blocks[0][..32].copy_from_slice(&pair[0]);
        blocks[0][32..].copy_from_slice(&pair[1]);
        let mut state = SHA256_IV;
        compress256(&mut state, &blocks);
        for (word, bytes) in state.iter().zip(out.chunks_exact_mut(4)) {
            bytes.copy_from_slice(&word.to_be_bytes());
        }
    }
}

/// `SHA-256(left || right)`.
pub(crate) fn hash_pair(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut out = [[0u8; 32]];
    hash_pairs_into(&[*left, *right], &mut out);
    out[0]
}

/// Folds `layer` one level up in place: node `i` of the result is the hash of
/// nodes `2i` and `2i + 1`, and a last odd node is paired with `zero`, the root
/// of an empty subtree of its own height. The layer ends up
/// `layer.len().div_ceil(2)` long.
pub(crate) fn hash_layer(layer: &mut Vec<Hash256>, zero: &Hash256) {
    if layer.len() % 2 == 1 {
        layer.push(*zero);
    }
    let pairs = layer.len() / 2;
    // Output index `i` is written after input indices `2i` and `2i + 1` were
    // read, and `i <= 2i`, so folding in place cannot overwrite an unread node.
    // The borrow checker cannot see that through one slice, so the first
    // `pairs` outputs go through a scratch copy of the hashes: a small, hot
    // buffer, and cheaper than allocating a second layer.
    const CHUNK: usize = 256;
    let mut scratch = [[0u8; 32]; CHUNK];
    let mut done = 0;
    while done < pairs {
        let n = (pairs - done).min(CHUNK);
        hash_pairs_into(&layer[2 * done..2 * (done + n)], &mut scratch[..n]);
        layer[done..done + n].copy_from_slice(&scratch[..n]);
        done += n;
    }
    layer.truncate(pairs);
}

/// The merkle root of `chunks` padded with zero chunks to `limit` leaves.
///
/// The same function as `libssz_merkle::merkleize(&Sha2Hasher, chunks,
/// Some(limit))`, with each level hashed as a batch. Padding is virtual: a
/// subtree wholly beyond `chunks` is read from [`ZERO_HASHES`].
///
/// # Panics
///
/// If `chunks.len() > limit`, which callers rule out by construction.
pub(crate) fn merkleize(chunks: &[Hash256], limit: usize) -> Hash256 {
    assert!(chunks.len() <= limit, "chunk count exceeds the limit");
    let depth = limit.next_power_of_two().trailing_zeros() as usize;
    if chunks.is_empty() {
        return ZERO_HASHES[depth];
    }
    let real_depth = chunks.len().next_power_of_two().trailing_zeros() as usize;
    let mut layer = chunks.to_vec();
    for zero in &ZERO_HASHES[..real_depth] {
        hash_layer(&mut layer, zero);
    }
    let mut root = layer[0];
    for zero in &ZERO_HASHES[real_depth..depth] {
        root = hash_pair(&root, zero);
    }
    root
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;

    use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
    use libssz_merkle::{Sha2Hasher, hash_nodes, merkleize as libssz_merkleize};
    use proptest::prelude::*;

    use crate::List;

    /// Routes [`hash_pairs_into`] through the per-pair `Digest` path.
    pub(super) static LEGACY: AtomicBool = AtomicBool::new(false);

    use super::*;

    fn nodes(seed: u64, n: usize) -> Vec<Hash256> {
        let mut state = seed | 1;
        (0..n)
            .map(|_| {
                let mut node = [0u8; 32];
                for byte in &mut node {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    *byte = (state >> 24) as u8;
                }
                node
            })
            .collect()
    }

    #[test]
    fn batched_pairs_match_hash_nodes() {
        for pairs in [0usize, 1, 2, 3, 7, 255, 256, 257, 1000, 5000] {
            let input = nodes(pairs as u64 + 1, 2 * pairs);
            let mut out = vec![[0u8; 32]; pairs];
            hash_pairs_into(&input, &mut out);
            for (i, got) in out.iter().enumerate() {
                let want = hash_nodes(&Sha2Hasher, &input[2 * i], &input[2 * i + 1]);
                assert_eq!(*got, want, "pairs {pairs}, pair {i}");
            }
        }
    }

    #[test]
    fn hash_layer_matches_hash_nodes_for_odd_and_even_layers() {
        let zero = [0xab; 32];
        for len in [0usize, 1, 2, 3, 4, 5, 511, 512, 513, 4097] {
            let mut layer = nodes(len as u64 + 9, len);
            let want: Vec<Hash256> = layer
                .chunks(2)
                .map(|p| hash_nodes(&Sha2Hasher, &p[0], p.get(1).unwrap_or(&zero)))
                .collect();
            hash_layer(&mut layer, &zero);
            assert_eq!(layer, want, "len {len}");
        }
    }

    proptest! {
        #[test]
        fn merkleize_matches_libssz(len in 0usize..300, extra in 0u32..4, seed in any::<u64>()) {
            let chunks = nodes(seed, len);
            let limit = (len.max(1)).next_power_of_two() << extra;
            prop_assert_eq!(
                merkleize(&chunks, limit),
                libssz_merkleize(&Sha2Hasher, &chunks, Some(limit))
            );
        }
    }

    /// Validator-sized composite: public key, credentials and four more words.
    #[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
    struct Validator {
        pubkey: [u8; 48],
        credentials: [u8; 32],
        balance: u64,
        slashed: bool,
        activation: u64,
        exit: u64,
        withdrawable: u64,
        effective: u64,
    }

    /// Runs `hash` on a fresh `setup()` value on each path and prints the
    /// median times of the hashing alone (setup is not timed). The two paths
    /// alternate so drift in machine load reaches both.
    fn report<S>(name: &str, setup: impl Fn() -> S, hash: impl Fn(S) -> Hash256) {
        LEGACY.store(true, Ordering::Relaxed);
        let old_root = hash(setup());
        LEGACY.store(false, Ordering::Relaxed);
        assert_eq!(old_root, hash(setup()), "{name}: roots differ");
        let reps = 9;
        let (mut old, mut new) = (Vec::new(), Vec::new());
        for _ in 0..reps {
            for legacy in [true, false] {
                let input = setup();
                LEGACY.store(legacy, Ordering::Relaxed);
                let start = Instant::now();
                std::hint::black_box(hash(input));
                let us = start.elapsed().as_secs_f64() * 1e6;
                LEGACY.store(false, Ordering::Relaxed);
                if legacy { old.push(us) } else { new.push(us) }
            }
        }
        old.sort_by(f64::total_cmp);
        new.sort_by(f64::total_cmp);
        let (old, new) = (old[reps / 2], new[reps / 2]);
        println!(
            "{name:<34} old {old:>10.0} us  new {new:>10.0} us  old/new {:.3}",
            old / new
        );
    }

    /// `cargo test -p ethlambda-ssz-tree --profile release-fast -- --ignored --nocapture batch_bench`
    #[test]
    #[ignore = "timing benchmark"]
    fn batch_bench() {
        let layer = nodes(7, 1 << 20);
        report(
            "layer fold, 2^20 nodes",
            || layer.clone(),
            |mut l| {
                while l.len() > 1 {
                    hash_layer(&mut l, &[0; 32]);
                }
                l[0]
            },
        );

        let balances: Vec<u64> = (0..1u64 << 20).collect();
        report(
            "List<u64> 2^20 fresh root",
            || List::<u64, { 1 << 40 }>::try_from(balances.clone()).unwrap(),
            |list| libssz_merkle::HashTreeRoot::hash_tree_root(&list, &Sha2Hasher),
        );

        let validators: Vec<Validator> = (0..1u64 << 18)
            .map(|i| Validator {
                pubkey: [i as u8; 48],
                credentials: [(i >> 8) as u8; 32],
                balance: i,
                slashed: false,
                activation: 0,
                exit: u64::MAX,
                withdrawable: u64::MAX,
                effective: 32,
            })
            .collect();
        report(
            "List<Validator> 2^18 fresh root",
            || List::<Validator, { 1 << 40 }>::try_from(validators.clone()).unwrap(),
            |list| libssz_merkle::HashTreeRoot::hash_tree_root(&list, &Sha2Hasher),
        );
    }
}
