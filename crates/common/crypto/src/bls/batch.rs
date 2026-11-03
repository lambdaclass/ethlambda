//! Signature checks resolved ahead of time, so a block's worth of them can be
//! verified in one pairing batch instead of one pairing each.
//!
//! # Why a batch is cheaper
//!
//! A signature check is two parts: resolving its inputs (validating the keys,
//! summing them, decoding the signature) and the pairing equation. The pairing
//! is dominated by its final exponentiation, which every standalone check pays
//! in full. Checking `n` equations `e(pk_i, H(m_i)) = e(g1, sig_i)` together
//! needs one Miller loop per set but only one final exponentiation for all of
//! them, so a block with a dozen signature sets spends a fraction of what a
//! dozen separate checks do. `silver_crypto_simd` runs those Miller loops eight
//! at a time on an IFMA CPU, which a batch gives it enough of to fill.
//!
//! # Why the weights are random
//!
//! Multiplying the equations together unweighted is unsound: an attacker who
//! can pick two invalid signatures `s1 * d` and `s2 / d` (for some group
//! element `d`) makes the product of the two checks hold although neither
//! check does. Each set is therefore weighted by its own random scalar
//! before the products are combined (the random linear combination of
//! <https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407>).
//! The weights must be unpredictable to whoever chose the signatures: with
//! independent uniform 64-bit weights, a forged batch passes with probability
//! about 2^-64, which is the soundness level every consensus client accepts.
//! They are drawn from `rand`'s thread-local CSPRNG, which is seeded from the
//! operating system's entropy and reseeded periodically, and a weight of zero
//! is redrawn, since it would drop its set from the equation altogether.
//!
//! The combined equation is `e(-g1, sum(r_i * sig_i)) * prod e(r_i * pk_i,
//! H(m_i)) == 1`: the weights go on the signatures through one multi-scalar
//! sum, and on each key through its own scalar multiplication, which in G1 is
//! the cheaper group to multiply in.
//!
//! # What a batch answers
//!
//! Only whether every set holds. When it fails it cannot say which set did;
//! callers that need to name one check the sets individually afterwards
//! ([`SignatureSet::verify`]), which is also the answer a standalone
//! [`super::verify`] or [`super::fast_aggregate_verify`] gives for the same
//! inputs.

use blst::min_pk::PublicKey;
use rand::RngExt;
use silver_crypto_simd::bls::{G1Point, G2Point, PairingProduct};

use ethlambda_types::beacon::primitives::{BlsSignature, Root};

use super::{
    AggregatePubkey, DST, PubkeySource, core_verify, decode_signature, g1_point, validated_pubkey,
    validated_pubkeys,
};

/// One signature check, resolved and ready, that may be verified alone or in a
/// batch.
///
/// Holds the signer's key already validated (and, for an aggregate, summed),
/// the signed message and the signature already validated, so building one is
/// everything a check does short of the pairing. That split is what lets a
/// caller decide *when* to pay for the pairing: at once ([`Self::verify`]) or
/// together with the other sets of a block ([`verify_signature_sets`]).
///
/// A single key and a sum of keys are checked by the same equation, so a set
/// does not record which one it holds; only a sum can be the identity, which
/// both checks refuse.
#[derive(Clone, Copy)]
pub struct SignatureSet {
    pubkey: PublicKey,
    message: Root,
    signature: G2Point,
}

impl SignatureSet {
    /// `bls.Verify`'s inputs.
    ///
    /// `None` when the key or the signature fails validation, which is exactly
    /// when [`super::verify`] returns false before reaching the pairing.
    pub fn single<K: PubkeySource>(
        pubkey: &K,
        message: Root,
        signature: &BlsSignature,
    ) -> Option<Self> {
        let pubkey = validated_pubkey(pubkey)?;
        let signature = decode_signature(signature)?;
        Some(Self {
            pubkey,
            message,
            signature,
        })
    }

    /// `bls.FastAggregateVerify`'s inputs.
    ///
    /// `None` for an empty `pubkeys`, any key that fails `KeyValidate`, or a
    /// signature that does not decode to a subgroup point: the cases
    /// [`super::fast_aggregate_verify`] answers false for before the pairing.
    pub fn fast_aggregate<K: PubkeySource>(
        pubkeys: &[K],
        message: Root,
        signature: &BlsSignature,
    ) -> Option<Self> {
        if pubkeys.is_empty() {
            return None;
        }
        let signature = decode_signature(signature)?;
        let points = validated_pubkeys(pubkeys)?;
        // Every point above already passed `KeyValidate`, so the sum does
        // not re-check them.
        let pubkey = super::sum_validated_points(&points)?;
        Some(Self {
            pubkey,
            message,
            signature,
        })
    }

    /// `bls.FastAggregateVerify`'s inputs with the key already summed, as
    /// committee key sums produce it.
    ///
    /// `None` when `signature` does not decode to a subgroup point. The key
    /// needs no check: a sum of validated points is in the subgroup, and the
    /// identity, the one sum that is not a valid key, is refused by
    /// [`Self::verify`] and by the batch before any pairing, as it is for a
    /// key summed here from scratch.
    pub fn from_aggregate(
        key: AggregatePubkey,
        message: Root,
        signature: &BlsSignature,
    ) -> Option<Self> {
        let signature = decode_signature(signature)?;
        Some(Self {
            pubkey: key.to_public_key(),
            message,
            signature,
        })
    }

    /// The pairing check on its own: the same answer [`super::verify`] or
    /// [`super::fast_aggregate_verify`] gives for these inputs.
    pub fn verify(&self) -> bool {
        core_verify(&self.pubkey, self.message, &self.signature)
    }

    /// Whether the key is the identity, which no signature can validly be
    /// made under. Only a sum of keys can be: a single registry key is
    /// rejected by `KeyValidate` if it is.
    ///
    /// `silver_crypto_simd`'s pairing product would drop the pair, so this
    /// check is what refuses the set; see `core_verify`.
    fn key_is_identity(&self) -> bool {
        g1_point(&self.pubkey).is_infinity()
    }
}

/// A random weight in `1..2^64`.
fn random_weight(rng: &mut impl RngExt) -> u64 {
    loop {
        let candidate: u64 = rng.random();
        if candidate != 0 {
            return candidate;
        }
    }
}

/// Whether every set verifies, in one random-linear-combination check with
/// 64-bit weights from the OS-seeded RNG and one final exponentiation. An
/// empty slice verifies.
///
/// See the module documentation for why the weights are random and where they
/// are applied. A single set skips them and is verified directly, since one
/// equation needs no combining. A set whose key is the identity fails the
/// batch, as it fails [`SignatureSet::verify`]: the pairing product would drop
/// that set's pair rather than refuse it.
pub fn verify_signature_sets(sets: &[SignatureSet]) -> bool {
    match sets {
        [] => return true,
        [only] => return only.verify(),
        _ => {}
    }
    if sets.iter().any(SignatureSet::key_is_identity) {
        return false;
    }
    let mut rng = rand::rng();
    let weights: Vec<u64> = sets.iter().map(|_| random_weight(&mut rng)).collect();
    let scalars: Vec<u8> = weights.iter().flat_map(|w| w.to_le_bytes()).collect();
    let signatures: Vec<G2Point> = sets.iter().map(|set| set.signature).collect();
    let signature_sum = G2Point::weighted_sum(&signatures, &scalars);

    let mut product = PairingProduct::with_capacity(sets.len() + 1);
    product.push(&G1Point::negative_generator(), &signature_sum);
    for (set, weight) in sets.iter().zip(&weights) {
        let weighted_key = G1Point::weighted_sum(&[g1_point(&set.pubkey)], &weight.to_le_bytes());
        let hash = G2Point::hash_to_curve(set.message.as_slice(), DST);
        product.push(&weighted_key, &hash);
    }
    product.is_one()
}

#[cfg(test)]
mod tests {
    use blst::min_pk::SecretKey;

    use super::*;
    use crate::bls;
    use ethlambda_types::beacon::primitives::BlsPubkey;

    fn secret_key(seed: u8) -> SecretKey {
        let mut ikm = [seed; 32];
        ikm[0] = ikm[0].wrapping_add(1);
        SecretKey::key_gen(&ikm, &[]).unwrap()
    }

    fn pubkey_of(key: &SecretKey) -> BlsPubkey {
        BlsPubkey(key.sk_to_pk().to_bytes())
    }

    fn sign(key: &SecretKey, message: Root) -> BlsSignature {
        BlsSignature(key.sign(message.as_slice(), DST, &[]).to_bytes())
    }

    fn message(byte: u8) -> Root {
        Root::from([byte; 32])
    }

    /// `n` single-key sets over distinct messages, all valid.
    fn valid_sets(n: u8) -> Vec<SignatureSet> {
        (0..n)
            .map(|i| {
                let key = secret_key(i);
                let msg = message(i);
                SignatureSet::single(&pubkey_of(&key), msg, &sign(&key, msg)).unwrap()
            })
            .collect()
    }

    #[test]
    fn a_valid_batch_of_ten_verifies() {
        assert!(verify_signature_sets(&valid_sets(10)));
    }

    #[test]
    fn an_empty_batch_verifies() {
        assert!(verify_signature_sets(&[]));
    }

    #[test]
    fn a_single_set_batch_verifies_or_fails_alone() {
        assert!(verify_signature_sets(&valid_sets(1)));
        let key = secret_key(1);
        let wrong =
            SignatureSet::single(&pubkey_of(&key), message(9), &sign(&key, message(8))).unwrap();
        assert!(!verify_signature_sets(&[wrong]));
    }

    #[test]
    fn one_bad_set_among_ten_fails() {
        for bad in [0u8, 4, 9] {
            let mut sets = valid_sets(10);
            let key = secret_key(bad);
            // A well-formed signature over a different message.
            sets[usize::from(bad)] =
                SignatureSet::single(&pubkey_of(&key), message(bad), &sign(&key, message(200)))
                    .unwrap();
            assert!(!verify_signature_sets(&sets), "bad set {bad}");
        }
    }

    #[test]
    fn swapped_signatures_fail() {
        let (k0, k1) = (secret_key(0), secret_key(1));
        let (m0, m1) = (message(0), message(1));
        let (s0, s1) = (sign(&k0, m0), sign(&k1, m1));
        let a = SignatureSet::single(&pubkey_of(&k0), m0, &s1).unwrap();
        let b = SignatureSet::single(&pubkey_of(&k1), m1, &s0).unwrap();
        assert!(!a.verify());
        assert!(!b.verify());
        assert!(!verify_signature_sets(&[a, b]));
    }

    #[test]
    fn repeated_messages_across_sets_verify() {
        let msg = message(7);
        let sets: Vec<SignatureSet> = (0..6)
            .map(|i| {
                let key = secret_key(i);
                SignatureSet::single(&pubkey_of(&key), msg, &sign(&key, msg)).unwrap()
            })
            .collect();
        assert!(verify_signature_sets(&sets));
    }

    #[test]
    fn single_and_aggregate_sets_mix_in_one_batch() {
        let mut sets = valid_sets(3);
        let keys: Vec<SecretKey> = (10..14).map(secret_key).collect();
        let msg = message(99);
        let signatures: Vec<BlsSignature> = keys.iter().map(|key| sign(key, msg)).collect();
        let aggregate = bls::aggregate(&signatures).unwrap();
        let pubkeys: Vec<BlsPubkey> = keys.iter().map(pubkey_of).collect();
        sets.push(SignatureSet::fast_aggregate(&pubkeys, msg, &aggregate).unwrap());
        assert!(verify_signature_sets(&sets));
    }

    #[test]
    fn verify_agrees_with_bls_verify() {
        let key = secret_key(3);
        let pubkey = pubkey_of(&key);
        let msg = message(3);
        let good = sign(&key, msg);
        let wrong_message = sign(&key, message(4));
        let other_key = sign(&secret_key(5), msg);
        for signature in [good, wrong_message, other_key] {
            let set = SignatureSet::single(&pubkey, msg, &signature).unwrap();
            assert_eq!(set.verify(), bls::verify(&pubkey, msg, &signature));
        }
    }

    #[test]
    fn verify_agrees_with_fast_aggregate_verify() {
        let keys: Vec<SecretKey> = (0..5).map(secret_key).collect();
        let pubkeys: Vec<BlsPubkey> = keys.iter().map(pubkey_of).collect();
        let msg = message(42);
        let signatures: Vec<BlsSignature> = keys.iter().map(|key| sign(key, msg)).collect();
        let good = bls::aggregate(&signatures).unwrap();
        let short = bls::aggregate(&signatures[1..]).unwrap();
        for (signature, message) in [(good, msg), (short, msg), (good, message(43))] {
            let set = SignatureSet::fast_aggregate(&pubkeys, message, &signature).unwrap();
            assert_eq!(
                set.verify(),
                bls::fast_aggregate_verify(&pubkeys, message, &signature)
            );
        }
    }

    #[test]
    fn invalid_inputs_build_no_set() {
        let key = secret_key(1);
        let pubkey = pubkey_of(&key);
        let msg = message(1);
        let signature = sign(&key, msg);
        let garbage_key = BlsPubkey([0xff; 48]);
        let garbage_signature = BlsSignature([0xff; 96]);

        assert!(SignatureSet::single(&garbage_key, msg, &signature).is_none());
        assert!(SignatureSet::single(&pubkey, msg, &garbage_signature).is_none());
        assert!(SignatureSet::fast_aggregate::<BlsPubkey>(&[], msg, &signature).is_none());
        assert!(SignatureSet::fast_aggregate(&[pubkey, garbage_key], msg, &signature).is_none());
        assert!(SignatureSet::fast_aggregate(&[pubkey], msg, &garbage_signature).is_none());
        // The identity signature is a valid encoding: it builds a set that fails.
        let infinity = BlsSignature(bls::G2_POINT_AT_INFINITY);
        let set = SignatureSet::single(&pubkey, msg, &infinity).unwrap();
        assert!(!set.verify());
    }

    #[test]
    fn an_infinity_signature_among_valid_sets_fails_the_batch() {
        let mut sets = valid_sets(4);
        let key = secret_key(1);
        let infinity = BlsSignature(bls::G2_POINT_AT_INFINITY);
        sets[1] = SignatureSet::single(&pubkey_of(&key), message(1), &infinity).unwrap();
        assert!(!verify_signature_sets(&sets));
    }

    /// `-P`, from `P`'s compressed encoding (the sort flag picks the other
    /// `y`). Valid on its own, so a registry can hold both.
    fn negated(pubkey: BlsPubkey) -> BlsPubkey {
        let mut bytes = pubkey.0;
        bytes[0] ^= 0b0010_0000;
        BlsPubkey(bytes)
    }

    #[test]
    fn keys_that_cancel_never_verify_alone_or_in_a_batch() {
        // `[P, -P]` sums to the identity, and with the identity signature that
        // is the cancellation the rule against identity keys exists for. A
        // real signature over the message must not pass either.
        let key = secret_key(20);
        let pubkey = pubkey_of(&key);
        let pair = [pubkey, negated(pubkey)];
        let msg = message(20);
        let infinity = BlsSignature(bls::G2_POINT_AT_INFINITY);
        for signature in [infinity, sign(&key, msg)] {
            let set = SignatureSet::fast_aggregate(&pair, msg, &signature).unwrap();
            assert!(set.key_is_identity());
            assert!(!set.verify());
            assert_eq!(
                set.verify(),
                bls::fast_aggregate_verify(&pair, msg, &signature)
            );

            let mut sets = valid_sets(3);
            sets.push(set);
            assert!(!verify_signature_sets(&sets));
        }

        // `P + P - P` is `P`, so `P`'s own signature verifies.
        let three = [pubkey, pubkey, negated(pubkey)];
        let set = SignatureSet::fast_aggregate(&three, msg, &sign(&key, msg)).unwrap();
        assert!(!set.key_is_identity());
        let mut sets = valid_sets(3);
        sets.push(set);
        assert!(verify_signature_sets(&sets));
    }

    /// The batch answers what checking every set alone through `blst` answers,
    /// at batch sizes on both sides of the pairing kernel's eight lanes (the
    /// batch adds one pair for the signature sum), with no bad set and with a
    /// bad set in each position class.
    #[test]
    fn a_batch_agrees_with_blst_checking_each_set_alone() {
        use blst::BLST_ERROR::BLST_SUCCESS;
        for n in [2u8, 7, 8, 9, 15, 16, 17] {
            for bad in [None, Some(0), Some(n / 2), Some(n - 1)] {
                let mut inputs: Vec<(BlsPubkey, Root, BlsSignature)> = (0..n)
                    .map(|i| {
                        let key = secret_key(100 + i);
                        let msg = message(i);
                        (pubkey_of(&key), msg, sign(&key, msg))
                    })
                    .collect();
                if let Some(bad) = bad {
                    let key = secret_key(100 + bad);
                    inputs[usize::from(bad)].2 = sign(&key, message(255));
                }
                let theirs = inputs.iter().all(|(pubkey, msg, signature)| {
                    let key = PublicKey::key_validate(pubkey.as_ref()).unwrap();
                    let sig =
                        blst::min_pk::Signature::sig_validate(signature.as_ref(), false).unwrap();
                    sig.verify(false, msg.as_slice(), DST, &[], &key, false) == BLST_SUCCESS
                });
                assert_eq!(theirs, bad.is_none());
                let sets: Vec<SignatureSet> = inputs
                    .iter()
                    .map(|(pubkey, msg, signature)| {
                        SignatureSet::single(pubkey, *msg, signature).unwrap()
                    })
                    .collect();
                assert_eq!(
                    verify_signature_sets(&sets),
                    theirs,
                    "{n} sets, bad {bad:?}"
                );
            }
        }
    }

    #[test]
    fn random_weights_are_never_zero() {
        let mut rng = rand::rng();
        for _ in 0..10_000 {
            assert_ne!(random_weight(&mut rng), 0);
        }
    }
}
