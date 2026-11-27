//! Hashing many merkle pairs per call.
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
//! This module keeps that as one primitive, [`hash_pairs_into`], that every
//! hash in this crate goes through: a slice of pairs in, a slice of digests
//! out, so the callers gather a whole level's pairs into one call. By default
//! it sits on `sha2::compress256`, so the hardware backend `sha2` selects at
//! run time (aarch64 SHA2 instructions, x86 SHA-NI) is the one used, and the
//! output is byte-identical to `libssz_merkle::hash_nodes(&Sha2Hasher, ..)`.
//! With the `hashtree` feature, the pairs go to Prysm's multi-message kernels
//! instead (see `hashtree_backend`), which hash 16 messages per AVX-512 call or
//! two interleaved per SHA-NI call. [`hash_pairs`] splits a large call over
//! rayon.

use rayon::prelude::*;
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
    #[cfg(feature = "hashtree")]
    if hashtree_backend::hash_pairs(input, output) {
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

/// Prysm's `hashtree` kernels, which hash many independent 64-byte messages per
/// call: 16 per AVX-512 call, two interleaved per SHA-NI call, with the
/// padding block's message schedule precomputed.
///
/// On x86 the kernels are called directly, chosen here by CPU, as
/// `silver_state_hashing` does: whole groups of 16 to AVX-512 and the rest to
/// SHA-NI. `hashtree_rs::hash` instead goes through one process-wide function
/// pointer that any other user of the library may install.
#[cfg(feature = "hashtree")]
mod hashtree_backend {
    use crate::Hash256;

    /// Hashes the pairs with a `hashtree` kernel, or answers `false` when no
    /// kernel suits this CPU, leaving the work to the caller.
    pub(super) fn hash_pairs(input: &[Hash256], output: &mut [Hash256]) -> bool {
        if output.is_empty() {
            return true;
        }
        imp::hash_pairs(input, output)
    }

    #[cfg(target_arch = "x86_64")]
    mod imp {
        use std::arch::x86_64::_mm256_zeroupper;
        use std::sync::LazyLock;

        use crate::Hash256;

        // Linked from the static library `hashtree-rs` builds.
        use hashtree_rs as _;

        unsafe extern "C" {
            fn hashtree_sha256_avx512_x16(output: *mut u8, input: *const u8, count: u64);
            fn hashtree_sha256_shani_x2(output: *mut u8, input: *const u8, count: u64);
        }

        #[derive(Clone, Copy)]
        enum Kernel {
            Avx512ThenShani,
            Shani,
            Unsupported,
        }

        static KERNEL: LazyLock<Kernel> = LazyLock::new(|| {
            let sha = is_x86_feature_detected!("sha");
            let avx512 = is_x86_feature_detected!("avx512f")
                && is_x86_feature_detected!("avx512vl")
                && is_x86_feature_detected!("avx512bw");
            match (sha, avx512) {
                (true, true) => Kernel::Avx512ThenShani,
                (true, false) => Kernel::Shani,
                (false, _) => Kernel::Unsupported,
            }
        });

        /// The AVX-512 kernel takes whole groups of this many messages.
        const GROUP: usize = 16;

        pub(super) fn hash_pairs(input: &[Hash256], output: &mut [Hash256]) -> bool {
            let count = output.len();
            let (out, inp) = (
                output.as_mut_ptr().cast::<u8>(),
                input.as_ptr().cast::<u8>(),
            );
            match *KERNEL {
                // SAFETY: `KERNEL` checked the CPU for every kernel each arm
                // calls; `input` holds `2 * count` nodes, that is `count`
                // 64-byte messages, and `output` `count` 32-byte digests.
                Kernel::Avx512ThenShani => unsafe { avx512_then_shani(out, inp, count) },
                Kernel::Shani => unsafe { hashtree_sha256_shani_x2(out, inp, count as u64) },
                Kernel::Unsupported => return false,
            }
            true
        }

        #[target_feature(enable = "avx")]
        unsafe fn avx512_then_shani(output: *mut u8, input: *const u8, count: usize) {
            let grouped = count / GROUP * GROUP;
            if grouped > 0 {
                unsafe { hashtree_sha256_avx512_x16(output, input, grouped as u64) };
                // The assembly leaves the upper vector state dirty, which
                // slows every SSE instruction after it until cleared.
                _mm256_zeroupper();
            }
            let rest = (count - grouped) as u64;
            if rest > 0 {
                unsafe {
                    hashtree_sha256_shani_x2(
                        output.add(32 * grouped),
                        input.add(64 * grouped),
                        rest,
                    )
                };
            }
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    mod imp {
        use std::sync::LazyLock;

        use crate::Hash256;

        /// `hashtree` picks its kernel (on aarch64, the SHA2 instructions)
        /// into a global pointer on first use; this sets it once, before any
        /// thread hashes.
        static READY: LazyLock<()> = LazyLock::new(|| {
            hashtree_rs::init();
        });

        pub(super) fn hash_pairs(input: &[Hash256], output: &mut [Hash256]) -> bool {
            LazyLock::force(&READY);
            let count = output.len();
            hashtree_rs::hash(output.as_flattened_mut(), input.as_flattened(), count);
            true
        }
    }
}

/// At or above this many pairs in one call, [`hash_pairs`] splits them over
/// rayon.
const PARALLEL_PAIRS: usize = 4096;

/// Pairs per rayon task when [`hash_pairs`] splits a call.
const PARALLEL_BLOCK: usize = 1024;

/// [`hash_pairs_into`], split over rayon when there are many pairs.
pub(crate) fn hash_pairs(pairs: &[Hash256], hashes: &mut [Hash256]) {
    if hashes.len() >= PARALLEL_PAIRS && rayon::current_num_threads() > 1 {
        pairs
            .par_chunks(2 * PARALLEL_BLOCK)
            .zip(hashes.par_chunks_mut(PARALLEL_BLOCK))
            .for_each(|(pairs, hashes)| hash_pairs_into(pairs, hashes));
    } else {
        hash_pairs_into(pairs, hashes);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;

    use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
    use libssz_merkle::{Sha2Hasher, hash_nodes};

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
        // Every size up to three AVX-512 groups and a SHA-NI remainder, then
        // a few larger ones.
        for pairs in (0usize..=49).chain([255, 256, 257, 1000, 5000]) {
            let input = nodes(pairs as u64 + 1, 2 * pairs);
            let mut out = vec![[0u8; 32]; pairs];
            hash_pairs_into(&input, &mut out);
            for (i, got) in out.iter().enumerate() {
                let want = hash_nodes(&Sha2Hasher, &input[2 * i], &input[2 * i + 1]);
                assert_eq!(*got, want, "pairs {pairs}, pair {i}");
            }
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
