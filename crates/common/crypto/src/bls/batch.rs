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
//! dozen separate checks do.
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
//! They are drawn from `rand::rng()`, a thread-local ChaCha12 generator seeded
//! from the operating system (`SysRng`), and soundness rests on that
//! unpredictability alone: rand 0.10.1, the version locked here, also reseeds
//! it from the operating system after every 64 KiB of output, but nothing
//! here depends on that. A weight of zero is redrawn, since it would drop its
//! set from the equation altogether.
//!
//! # What a batch answers
//!
//! Only whether every set holds. When it fails it cannot say which set did;
//! callers that need to name one check the sets individually afterwards
//! ([`SignatureSet::verify`]), which is also the answer a standalone
//! [`super::verify`] or [`super::fast_aggregate_verify`] gives for the same
//! inputs.

use blst::BLST_ERROR;
use blst::blst_scalar;
use blst::min_pk::{PublicKey, Signature};
use rand::RngExt;

use ethlambda_types::beacon::primitives::{BlsPubkey, BlsSignature, Root};

use super::{DST, validated_pubkey, validated_pubkeys};

/// How many bits of each random weight the batch check uses.
const RAND_BITS: usize = 64;

/// One signature check, resolved and ready, that may be verified alone or in a
/// batch.
///
/// Holds the signer's key already validated (and, for an aggregate, summed),
/// the signed message and the signature already validated, so building one is
/// everything a check does short of the pairing. That split is what lets a
/// caller decide *when* to pay for the pairing: at once ([`Self::verify`]) or
/// together with the other sets of a block ([`verify_signature_sets`]).
///
/// `Clone` but not `Copy`: at about 300 bytes, a copy should be one the code
/// asks for.
#[derive(Clone)]
pub struct SignatureSet {
    pubkey: PublicKey,
    message: Root,
    signature: Signature,
    /// Whether `pubkey` is a sum of keys, checked the way
    /// `bls.FastAggregateVerify` checks one, rather than a single registry key.
    aggregated: bool,
}

impl SignatureSet {
    /// `bls.Verify`'s inputs.
    ///
    /// `None` when the key or the signature fails validation, which is exactly
    /// when [`super::verify`] returns false before reaching the pairing.
    pub fn single(pubkey: &BlsPubkey, message: Root, signature: &BlsSignature) -> Option<Self> {
        let pubkey = validated_pubkey(pubkey)?;
        let signature = Signature::sig_validate(signature.as_ref(), false).ok()?;
        Some(Self {
            pubkey,
            message,
            signature,
            aggregated: false,
        })
    }

    /// `bls.FastAggregateVerify`'s inputs.
    ///
    /// `None` for an empty `pubkeys`, any key that fails `key_validate`, or a
    /// signature that fails `sig_validate`: the cases
    /// [`super::fast_aggregate_verify`] answers false for before the pairing.
    pub fn fast_aggregate(
        pubkeys: &[BlsPubkey],
        message: Root,
        signature: &BlsSignature,
    ) -> Option<Self> {
        if pubkeys.is_empty() {
            return None;
        }
        let signature = Signature::sig_validate(signature.as_ref(), false).ok()?;
        let points = validated_pubkeys(pubkeys)?;
        // Every point above already passed `key_validate`, so the sum does
        // not re-check them.
        let pubkey = super::sum_validated_points(&points)?;
        Some(Self {
            pubkey,
            message,
            signature,
            aggregated: true,
        })
    }

    /// The pairing check on its own: the same answer [`super::verify`] or
    /// [`super::fast_aggregate_verify`] gives for these inputs.
    pub fn verify(&self) -> bool {
        let result = if self.aggregated {
            self.signature.fast_aggregate_verify_pre_aggregated(
                false,
                self.message.as_slice(),
                DST,
                &self.pubkey,
            )
        } else {
            self.signature.verify(
                false,
                self.message.as_slice(),
                DST,
                &[],
                &self.pubkey,
                false,
            )
        };
        result == BLST_ERROR::BLST_SUCCESS
    }
}

/// A random weight in `1..2^64`, as the little-endian scalar `blst` expects.
fn random_weight(rng: &mut impl RngExt) -> blst_scalar {
    let weight = loop {
        let candidate: u64 = rng.random();
        if candidate != 0 {
            break candidate;
        }
    };
    let mut scalar = blst_scalar::default();
    scalar.b[..8].copy_from_slice(&weight.to_le_bytes());
    scalar
}

/// Whether every set verifies, in one random-linear-combination check:
/// `verify_multiple_aggregate_signatures` with 64-bit scalars from the
/// OS-seeded RNG and one final exponentiation. An empty slice verifies.
///
/// See the module documentation for why the weights are random. A single set
/// skips them and is verified directly, since one equation needs no
/// combining.
///
/// A set whose key is the identity (keys that sum to it, such as `[P, -P]`)
/// fails here as it fails [`SignatureSet::verify`], with nothing in this crate
/// checking for it: blst refuses an infinite public key wherever it adds a
/// key to a pairing (`BLST_PK_IS_INFINITY` in `blst/src/aggregate.c`), which
/// both this batch and the single check go through.
pub fn verify_signature_sets(sets: &[SignatureSet]) -> bool {
    match sets {
        [] => return true,
        [only] => return only.verify(),
        _ => {}
    }
    let mut rng = rand::rng();
    let weights: Vec<blst_scalar> = sets.iter().map(|_| random_weight(&mut rng)).collect();
    let messages: Vec<&[u8]> = sets.iter().map(|set| set.message.as_slice()).collect();
    let pubkeys: Vec<&PublicKey> = sets.iter().map(|set| &set.pubkey).collect();
    let signatures: Vec<&Signature> = sets.iter().map(|set| &set.signature).collect();
    // Keys and signatures were validated when the sets were built.
    let result = Signature::verify_multiple_aggregate_signatures(
        &messages,
        DST,
        &pubkeys,
        false,
        &signatures,
        false,
        &weights,
        RAND_BITS,
    );
    result == BLST_ERROR::BLST_SUCCESS
}

#[cfg(test)]
mod tests {
    use blst::min_pk::SecretKey;

    use super::*;
    use crate::bls;

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
    fn an_invalid_aggregate_among_valid_sets_fails_the_batch() {
        // The batch check goes through blst's multi-signature routine and the
        // single check through `fast_aggregate_verify_pre_aggregated`, so an
        // aggregate both must refuse is checked inside a batch, where a false
        // accept would pass a block.
        let keys: Vec<SecretKey> = (20..24).map(secret_key).collect();
        let pubkeys: Vec<BlsPubkey> = keys.iter().map(pubkey_of).collect();
        let msg = message(77);
        let signed_by = |keys: &[SecretKey], msg: Root| {
            let signatures: Vec<BlsSignature> = keys.iter().map(|key| sign(key, msg)).collect();
            bls::aggregate(&signatures).unwrap()
        };
        let cases = [
            // One signer's share is missing from the signature.
            (
                "missing signer",
                pubkeys.clone(),
                signed_by(&keys[1..], msg),
            ),
            // Every signer signed, but another message.
            (
                "other message",
                pubkeys.clone(),
                signed_by(&keys, message(78)),
            ),
            // A key is claimed that never signed.
            (
                "extra key",
                [pubkeys.clone(), vec![pubkey_of(&secret_key(30))]].concat(),
                signed_by(&keys, msg),
            ),
        ];
        for (case, claimed, signature) in cases {
            let bad = SignatureSet::fast_aggregate(&claimed, msg, &signature).unwrap();
            assert!(!bad.verify(), "{case}: the single check accepted it");
            let mut sets = valid_sets(5);
            sets.insert(2, bad);
            assert!(
                !verify_signature_sets(&sets),
                "{case}: the batch accepted it"
            );
        }
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
        assert!(SignatureSet::fast_aggregate(&[], msg, &signature).is_none());
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
            assert!(
                set.pubkey == PublicKey::default(),
                "the keys sum to the identity"
            );
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
        assert!(set.pubkey != PublicKey::default());
        let mut sets = valid_sets(3);
        sets.push(set);
        assert!(verify_signature_sets(&sets));
    }

    #[test]
    fn random_weights_are_never_zero() {
        let mut rng = rand::rng();
        for _ in 0..10_000 {
            let weight = random_weight(&mut rng);
            assert!(weight.b[..8].iter().any(|byte| *byte != 0));
            assert!(weight.b[8..].iter().all(|byte| *byte == 0));
        }
    }
}
