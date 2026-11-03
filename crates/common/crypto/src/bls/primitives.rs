//! The raw `blst` point and pairing calls the BLS layer needs, in one place.
//!
//! Everything above this module speaks in [`PublicKey`], [`Signature`] and
//! [`Root`](ethlambda_types::beacon::primitives::Root); the few operations
//! `blst`'s own verification helpers do not expose as separate steps are here:
//! hashing a message to a G2 point, checking a product of pairings over points
//! that are already hashed, and the weighted sums a random-linear-combination
//! batch needs. Keeping them behind a few small functions leaves one place to
//! re-point when the backend changes, and the only `unsafe` in the BLS layer.
//!
//! The reason these are not `blst`'s `Signature::verify` and friends: those
//! hash their message on every call, so a message signed by many validators
//! (every attester of a slot signs the same root) is hashed once per check.
//! Splitting hashing out lets [`super::hashed_messages`] pay for it once.

use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, Signature};
use blst::{
    BLST_ERROR, MultiPoint, Pairing, blst_fp12, blst_hash_to_g2, blst_p1_affine, blst_p2,
    blst_p2_affine, blst_p2_to_affine,
};
use rayon::prelude::*;

use super::DST;

/// How many bits of each batch weight the weighted sums use: the width of the
/// `u64` weights the caller draws.
const WEIGHT_BITS: usize = u64::BITS as usize;

/// The bit of a compressed point's first byte that marks the point at
/// infinity, the same position in G1 and G2 encodings.
const INFINITY_FLAG: u8 = 0b0100_0000;

/// The fewest pairs one [`Pairing`] accumulator takes when a check is spread
/// across rayon's workers.
///
/// A Miller loop is cheap next to the final exponentiation, so a handful of
/// pairs gain nothing from a second thread: at or below this the check stays
/// on the calling thread, and above it the pairs are split into chunks no
/// smaller than this.
const MIN_PAIRS_PER_CHUNK: usize = 4;

/// Whether a public key is the point at infinity. Only a sum of keys can be:
/// a registry key that is the identity fails `key_validate`.
pub(super) fn key_is_identity(key: &PublicKey) -> bool {
    key.to_bytes()[0] & INFINITY_FLAG != 0
}

/// Whether a signature is the point at infinity.
pub(super) fn signature_is_identity(signature: &Signature) -> bool {
    signature.to_bytes()[0] & INFINITY_FLAG != 0
}

/// `message` hashed to a G2 point under [`DST`], in affine form (the form the
/// pairing takes), with the empty augmentation the ciphersuite uses.
pub(super) fn hash_to_g2(message: &[u8]) -> blst_p2_affine {
    let mut point = blst_p2::default();
    let mut affine = blst_p2_affine::default();
    let no_aug: &[u8] = &[];
    // SAFETY: `point` and `affine` are valid, exclusively borrowed outputs;
    // the message, DST and aug pointers are each valid for the length passed
    // with them (an empty slice's pointer is non-null and never read at
    // length zero).
    unsafe {
        blst_hash_to_g2(
            &mut point,
            message.as_ptr(),
            message.len(),
            DST.as_ptr(),
            DST.len(),
            no_aug.as_ptr(),
            no_aug.len(),
        );
        blst_p2_to_affine(&mut affine, &point);
    }
    affine
}

/// Whether `prod_i e(key_i, hashed_i) == e(G1, signature)`, for `pairs` of
/// `(key, hashed message)`.
///
/// Refuses an empty `pairs` and any identity key: a pairing with the identity
/// contributes nothing, so a hand-built check would let a sum of cancelling
/// keys drop out of the equation instead of failing it (`blst`'s own verify
/// refuses it with `BLST_PK_IS_INFINITY`). Neither keys nor signature are
/// validated here; callers pass points that already passed their checks.
///
/// With enough pairs the Miller loops are split across rayon's workers, one
/// [`Pairing`] per chunk, merged before the single final exponentiation. The
/// check `blst`'s batch ran was parallel on its own pool, and one thread made
/// large batches several times slower.
pub(super) fn pairing_check(
    pairs: &[(&blst_p1_affine, &blst_p2_affine)],
    signature: &blst_p2_affine,
) -> bool {
    if pairs.is_empty()
        || pairs
            .iter()
            .any(|(key, _)| key_is_identity(&PublicKey::from(**key)))
    {
        return false;
    }
    let accumulate = |chunk: &[(&blst_p1_affine, &blst_p2_affine)]| {
        let mut pairing = Pairing::new(true, DST);
        for (key, hashed) in chunk {
            pairing.raw_aggregate(hashed, key);
        }
        pairing.commit();
        pairing
    };
    let mut accumulators: Vec<Pairing> = if pairs.len() <= MIN_PAIRS_PER_CHUNK {
        vec![accumulate(pairs)]
    } else {
        let chunk_len = pairs
            .len()
            .div_ceil(rayon::current_num_threads())
            .max(MIN_PAIRS_PER_CHUNK);
        pairs.par_chunks(chunk_len).map(accumulate).collect()
    };
    let Some(mut total) = accumulators.pop() else {
        return false;
    };
    for other in &accumulators {
        if total.merge(other) != BLST_ERROR::BLST_SUCCESS {
            return false;
        }
    }
    let mut signature_side = blst_fp12::default();
    Pairing::aggregated(&mut signature_side, signature);
    total.finalverify(Some(&signature_side))
}

/// The weights as the consecutive little-endian scalars `MultiPoint::mult`
/// reads.
fn scalar_bytes(weights: &[u64]) -> Vec<u8> {
    weights.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// `sum_i weights[i] * keys[i]`, one multi-scalar multiplication.
///
/// `keys` must be non-empty and the same length as `weights`.
pub(super) fn weighted_key_sum(keys: &[PublicKey], weights: &[u64]) -> PublicKey {
    debug_assert!(!keys.is_empty() && keys.len() == weights.len());
    let sum: AggregatePublicKey = keys.mult(&scalar_bytes(weights), WEIGHT_BITS);
    sum.to_public_key()
}

/// `sum_i weights[i] * signatures[i]`, one multi-scalar multiplication.
///
/// `signatures` must be non-empty and the same length as `weights`.
pub(super) fn weighted_signature_sum(signatures: &[Signature], weights: &[u64]) -> Signature {
    debug_assert!(!signatures.is_empty() && signatures.len() == weights.len());
    let sum: AggregateSignature = signatures.mult(&scalar_bytes(weights), WEIGHT_BITS);
    sum.to_signature()
}
