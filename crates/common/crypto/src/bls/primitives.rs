//! The raw point and pairing calls the BLS layer needs, in one place.
//!
//! Everything above this module speaks in [`PublicKey`], [`Signature`] and
//! [`Root`](ethlambda_types::beacon::primitives::Root); the operations
//! `silver_crypto_simd` exposes as separate steps are here: hashing a message
//! to a G2 point, checking a product of pairings over points that are already
//! hashed, and the weighted sums a random-linear-combination batch needs.
//! Keeping them behind a few small functions leaves one place to re-point when
//! the backend changes.
//!
//! The reason these are not a library's one-shot `verify`: that hashes its
//! message on every call, so a message signed by many validators (every
//! attester of a slot signs the same root) is hashed once per check. Splitting
//! hashing out lets [`super::hashed_messages`] pay for it once.
//!
//! One rule lives here for every caller: a pairing check refuses an identity
//! public key. `silver_crypto_simd`'s product drops any pair holding the
//! identity, so a sum of cancelling keys (`P` and `-P`, both valid on their
//! own) would otherwise leave an equation the identity signature satisfies,
//! where `blst`'s own verifier failed it with `BLST_PK_IS_INFINITY`.

use blst::min_pk::{PublicKey, Signature};
use silver_crypto_simd::bls::{G1Point, G2Point, PairingProduct, blst_p1_affine};

use super::DST;

/// The bit of a compressed point's first byte that marks the point at
/// infinity, the same position in G1 and G2 encodings.
const INFINITY_FLAG: u8 = 0b0100_0000;

/// A key this module validated, as `silver_crypto_simd`'s point type.
///
/// Every [`PublicKey`] the BLS layer holds passed `KeyValidate` or is a sum of
/// keys that did, so it is a canonical point of G1's prime-order subgroup,
/// which is the whole of `from_trusted`'s contract.
pub(super) fn g1_point(pubkey: &PublicKey) -> G1Point {
    G1Point::from_trusted(blst_p1_affine::from(*pubkey))
}

/// Whether a signature point is the point at infinity.
///
/// Read off the compressed encoding, which `blst` writes with the infinity
/// flag exactly when every coordinate is zero.
pub(super) fn signature_is_identity(signature: &G2Point) -> bool {
    Signature::from(signature.into_blst()).to_bytes()[0] & INFINITY_FLAG != 0
}

/// `message` hashed to a G2 point under [`DST`], with the empty augmentation
/// the ciphersuite uses.
pub(super) fn hash_to_g2(message: &[u8]) -> G2Point {
    G2Point::hash_to_curve(message, DST)
}

/// Whether `e(pubkey, hashed) == e(G1, signature)`, as one product of two
/// pairings.
///
/// Refuses an identity `pubkey`; see the module documentation. Neither key nor
/// signature is validated here: callers pass points that already passed their
/// checks.
pub(super) fn core_pairing_check(pubkey: &G1Point, hashed: &G2Point, signature: &G2Point) -> bool {
    if pubkey.is_infinity() {
        return false;
    }
    PairingProduct::two_pairs_are_one(
        (&G1Point::negative_generator(), signature),
        (pubkey, hashed),
    )
}

/// Whether `prod_i e(key_i, hashed_i) == e(G1, signature)`, for `pairs` of
/// `(key, hashed message)`.
///
/// Refuses an empty `pairs` and any identity key; see the module
/// documentation. A signature at infinity is not refused here: the equation is
/// then `prod e(key_i, hashed_i) == 1`, which is the right answer for a single
/// check, and a batch that must not accept it refuses the sum itself.
pub(super) fn pairing_product_holds(pairs: &[(G1Point, G2Point)], signature: &G2Point) -> bool {
    if pairs.is_empty() || pairs.iter().any(|(key, _)| key.is_infinity()) {
        return false;
    }
    let mut product = PairingProduct::with_capacity(pairs.len() + 1);
    product.push(&G1Point::negative_generator(), signature);
    for (key, hashed) in pairs {
        product.push(key, hashed);
    }
    product.is_one()
}

/// The weights as the consecutive little-endian scalars the weighted sums
/// read.
fn scalar_bytes(weights: &[u64]) -> Vec<u8> {
    weights.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// `sum_i weights[i] * keys[i]`, one multi-scalar multiplication.
///
/// `keys` must be non-empty and the same length as `weights`.
pub(super) fn weighted_key_sum(keys: &[G1Point], weights: &[u64]) -> G1Point {
    debug_assert!(!keys.is_empty() && keys.len() == weights.len());
    G1Point::weighted_sum(keys, &scalar_bytes(weights))
}

/// `sum_i weights[i] * signatures[i]`, one multi-scalar multiplication.
///
/// `signatures` must be non-empty and the same length as `weights`.
pub(super) fn weighted_signature_sum(signatures: &[G2Point], weights: &[u64]) -> G2Point {
    debug_assert!(!signatures.is_empty() && signatures.len() == weights.len());
    G2Point::weighted_sum(signatures, &scalar_bytes(weights))
}
