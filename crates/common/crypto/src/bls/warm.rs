//! Validating a whole registry's public keys at once, when a state is loaded.
//!
//! `KeyValidate` costs tens of microseconds per key, so a mainnet-sized
//! registry validated lazily taxes the first block imported after a start
//! with every key its committees touch. Doing the whole registry up front, in
//! parallel, moves that cost to load time, where nothing waits on it.

use rayon::prelude::*;

use super::{IndexedPubkey, KEY_DECODE_CHUNK, VALIDATED_PUBKEYS, decode_pubkeys};

/// Validates and caches every key in `pubkeys`, returning how many passed
/// `KeyValidate`, whether cached before the call or by it.
///
/// A key that fails is skipped and left uncached, so a later lookup of it
/// still fails exactly as it would have without this call; it does not stop
/// the others. Keys already cached are counted without being validated again.
pub fn warm_pubkeys(pubkeys: &[IndexedPubkey]) -> usize {
    warm(pubkeys).0
}

/// One pass over `pubkeys`: how many keys passed (cached before or by the
/// pass) and how many it ran `KeyValidate` on, so a test can tell a cache hit
/// from a fresh validation.
///
/// Each rayon task takes [`KEY_DECODE_CHUNK`] keys and hands the ones the cache
/// lacks to the batched decoder in one call, which is the size that decoder
/// keeps on the calling thread: the parallelism is across chunks here, so the
/// decoder does not queue work on the pool from inside a pool task.
fn warm(pubkeys: &[IndexedPubkey]) -> (usize, usize) {
    pubkeys
        .par_chunks(KEY_DECODE_CHUNK)
        .map(|chunk| {
            let mut passed = 0;
            let mut misses: Vec<&IndexedPubkey> = Vec::new();
            for key in chunk {
                if VALIDATED_PUBKEYS.get(key).is_some() {
                    passed += 1;
                } else {
                    misses.push(key);
                }
            }
            let encodings: Vec<_> = misses.iter().map(|key| key.pubkey.0).collect();
            for (key, point) in misses.iter().zip(decode_pubkeys(&encodings)) {
                if let Some(point) = point {
                    VALIDATED_PUBKEYS.insert(*key, point);
                    passed += 1;
                }
            }
            (passed, misses.len())
        })
        .reduce(|| (0, 0), |a, b| (a.0 + b.0, a.1 + b.1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::beacon::primitives::BlsPubkey;

    fn pubkey(seed: u64) -> BlsPubkey {
        let mut ikm = [0x3cu8; 32];
        ikm[..8].copy_from_slice(&seed.to_le_bytes());
        let secret = blst::min_pk::SecretKey::key_gen(&ikm, &[])
            .expect("32 bytes of input material is enough for key generation");
        BlsPubkey(secret.sk_to_pk().to_bytes())
    }

    fn indexed(index: u64, seed: u64) -> IndexedPubkey {
        IndexedPubkey {
            index,
            pubkey: pubkey(seed),
        }
    }

    #[test]
    fn valid_keys_are_cached_and_found_by_index() {
        let keys: Vec<_> = (0..600)
            .map(|i| indexed(3_100_000 + i, 70_000 + i))
            .collect();
        assert_eq!(warm_pubkeys(&keys), keys.len());
        for key in &keys {
            assert!(VALIDATED_PUBKEYS.get(key).is_some());
            // The index table answered, not the by-bytes map.
            assert!(VALIDATED_PUBKEYS.get_by_bytes(&key.pubkey).is_none());
        }
    }

    #[test]
    fn an_invalid_key_is_skipped_without_failing_its_neighbours() {
        let invalid = IndexedPubkey {
            index: 3_200_001,
            pubkey: BlsPubkey::default(),
        };
        let keys = [
            indexed(3_200_000, 71_000),
            invalid,
            indexed(3_200_002, 71_002),
        ];
        assert_eq!(warm_pubkeys(&keys), 2);
        assert!(VALIDATED_PUBKEYS.get(&keys[0]).is_some());
        assert!(VALIDATED_PUBKEYS.get(&keys[1]).is_none());
        assert!(VALIDATED_PUBKEYS.get(&keys[2]).is_some());
    }

    #[test]
    fn an_already_cached_key_is_counted_and_not_validated_again() {
        let keys = [indexed(3_300_000, 72_000), indexed(3_300_001, 72_001)];
        let first = warm(&keys);
        assert_eq!(first, (2, 2));
        let second = warm(&keys);
        assert_eq!(second, (2, 0));
    }

    #[test]
    fn empty_input_returns_zero() {
        assert_eq!(warm_pubkeys(&[]), 0);
    }
}
