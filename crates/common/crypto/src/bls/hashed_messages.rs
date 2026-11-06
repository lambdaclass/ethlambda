//! A cache of hashed messages, so a signing root is hashed to G2 once.
//!
//! Hashing a 32-byte signing root to a curve point costs about a hundred
//! microseconds, as much as several of a pairing's Miller loops, and the same
//! root is signed many times: every attester of a slot signs one, and it is
//! checked once off gossip and again inside the block that carries it.
//!
//! The cache is two generations, after the same cache in gattaca-com/silver.
//! New hashes go into `live`. When `live` reaches the cap it becomes `prev`
//! and `live` starts empty, dropping the generation before. A lookup reads
//! both and promotes a `prev` hit back into `live`, so a root that keeps being
//! asked for survives every swap, while one that stops is gone within two
//! generations. That bounds memory at twice the cap without tracking recency
//! per entry, and a hit takes only a read lock unless it is a promotion.
//!
//! The answer is a pure function of the root (and the fixed DST), so sharing
//! one process-wide copy between the state transition, fork choice and gossip
//! validation cannot change a verdict.

use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};

use blst::blst_p2_affine;

use ethlambda_types::beacon::primitives::Root;

use super::primitives;

/// How many hashed messages one generation holds. Silver's value: a few slots'
/// worth of distinct attestation data and block roots, with room for sync
/// committee and aggregate-selection roots.
const MAX_HASHED_MESSAGES: usize = 256;

/// Every message hashed so far that is still in the two newest generations.
static HASHED_MESSAGES: LazyLock<HashedMessages> =
    LazyLock::new(|| HashedMessages::new(MAX_HASHED_MESSAGES));

/// `root` hashed to G2 under the BLS DST, from the process-wide cache.
pub(super) fn hashed_message(root: &Root) -> blst_p2_affine {
    HASHED_MESSAGES.get(root)
}

#[derive(Default)]
struct Generations {
    live: HashMap<Root, blst_p2_affine>,
    prev: HashMap<Root, blst_p2_affine>,
}

/// The two-generation cache; see the module documentation.
struct HashedMessages {
    /// The most entries `live` takes before it is retired into `prev`.
    cap: usize,
    generations: RwLock<Generations>,
}

impl HashedMessages {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            generations: RwLock::default(),
        }
    }

    /// The hash of `root`, computed (outside any lock) on a miss.
    fn get(&self, root: &Root) -> blst_p2_affine {
        let promotable = {
            let generations = self.generations.read().unwrap();
            if let Some(point) = generations.live.get(root) {
                crate::metrics::inc_hashed_message_lookups(true);
                return *point;
            }
            generations.prev.get(root).copied()
        };
        if let Some(point) = promotable {
            crate::metrics::inc_hashed_message_lookups(true);
            self.insert(*root, point);
            return point;
        }
        crate::metrics::inc_hashed_message_lookups(false);
        let point = primitives::hash_to_g2(root.as_slice());
        self.insert(*root, point);
        point
    }

    /// Adds `root` to `live`, retiring `live` into `prev` first if it is full.
    /// A racing writer of the same root leaves the first entry in place.
    fn insert(&self, root: Root, point: blst_p2_affine) {
        let mut generations = self.generations.write().unwrap();
        if generations.live.contains_key(&root) {
            return;
        }
        if generations.live.len() >= self.cap {
            generations.prev = std::mem::take(&mut generations.live);
        }
        generations.live.insert(root, point);
    }

    /// Whether `root` is held in either generation.
    #[cfg(test)]
    fn holds(&self, root: &Root) -> bool {
        let generations = self.generations.read().unwrap();
        generations.live.contains_key(root) || generations.prev.contains_key(root)
    }

    /// Whether `root` is in the newest generation.
    #[cfg(test)]
    fn is_live(&self, root: &Root) -> bool {
        self.generations.read().unwrap().live.contains_key(root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(n: u64) -> Root {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&n.to_le_bytes());
        Root::from(bytes)
    }

    fn bytes_of(point: &blst_p2_affine) -> [u8; 96] {
        blst::min_pk::Signature::from(*point).to_bytes()
    }

    #[test]
    fn a_hit_returns_the_point_a_fresh_hash_does() {
        let message = root(1);
        let fresh = primitives::hash_to_g2(message.as_slice());
        let first = hashed_message(&message);
        let second = hashed_message(&message);
        assert_eq!(bytes_of(&first), bytes_of(&fresh));
        assert_eq!(bytes_of(&second), bytes_of(&fresh));
    }

    #[test]
    fn the_cached_hash_is_the_one_blst_signs_under() {
        let key = blst::min_pk::SecretKey::key_gen(&[7u8; 32], &[]).unwrap();
        let message = root(2);
        let signature = key.sign(message.as_slice(), super::super::DST, &[]);
        let hashed = hashed_message(&message);
        let pk = blst::blst_p1_affine::from(key.sk_to_pk());
        let sig = blst_p2_affine::from(signature);
        assert!(primitives::pairing_check(&[(&pk, &hashed)], &sig));
    }

    #[test]
    fn a_hot_root_survives_generation_swaps() {
        let cache = HashedMessages::new(8);
        let hot = root(1_000);
        cache.get(&hot);
        for n in 0..40 {
            cache.get(&root(n));
            cache.get(&hot);
            assert!(cache.holds(&hot), "hot root dropped after {n} other roots");
        }
    }

    #[test]
    fn a_cold_root_is_dropped_after_two_generations() {
        let cache = HashedMessages::new(4);
        let cold = root(1_000);
        cache.get(&cold);
        for n in 0..9 {
            cache.get(&root(n));
        }
        assert!(!cache.holds(&cold));
    }

    #[test]
    fn a_hit_in_the_previous_generation_is_promoted() {
        let cache = HashedMessages::new(2);
        let kept = root(1);
        cache.get(&kept);
        cache.get(&root(2));
        cache.get(&root(3)); // retires {kept, 2} into prev
        assert!(cache.holds(&kept) && !cache.is_live(&kept));
        cache.get(&kept);
        assert!(cache.is_live(&kept));
    }

    #[test]
    fn the_generations_stay_within_the_cap() {
        let cache = HashedMessages::new(8);
        for n in 0..100 {
            cache.get(&root(n));
        }
        let generations = cache.generations.read().unwrap();
        assert!(generations.live.len() <= 8 && generations.prev.len() <= 8);
    }
}
