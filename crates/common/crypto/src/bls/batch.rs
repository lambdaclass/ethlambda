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
//! # Why sets are grouped by message
//!
//! Validators attesting to the same data sign the same message, and bilinearity
//! lets their equations share a pairing: for the sets `i` of one message `m`,
//! `prod_i e(r_i * pk_i, H(m)) = e(sum_i r_i * pk_i, H(m))`. The batch sorts the
//! sets by message, sums `r_i * pk_i` per run of equal messages with one
//! multi-scalar multiplication, and checks
//! `prod_g e(sum_g r_i * pk_i, H(m_g)) == e(g1, sum_i r_i * sig_i)`: one Miller
//! loop per *distinct* message, one multiplication for all the signatures, one
//! final exponentiation. The grouping also means each distinct message is
//! hashed once, through the cache in `hashed_messages`.
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
//! Grouping adds two refusals. A weighted signature sum that is the point at
//! infinity fails the batch: the right-hand side would be trivial, and a pair
//! of keys `P` and `-P` whose weighted sum also vanished would let the
//! left-hand side drop out too. And a group whose weighted key sum is the
//! identity fails, as the pairing check refuses an identity key.
//!
//! # What a batch answers
//!
//! Only whether every set holds. When it fails it cannot say which set did;
//! callers that need to name one check the sets individually afterwards
//! ([`SignatureSet::verify`]), which is also the answer a standalone
//! [`super::verify`] or [`super::fast_aggregate_verify`] gives for the same
//! inputs.

use std::ops::Range;

use blst::min_pk::{PublicKey, Signature};
use blst::{blst_p1_affine, blst_p2_affine};
use rand::RngExt;
use rayon::prelude::*;

use ethlambda_types::beacon::primitives::{BlsSignature, Root};

use super::hashed_messages::hashed_message;
use super::{
    AggregatePubkey, PubkeySource, pairing_verify, primitives, validated_pubkey, validated_pubkeys,
};

/// One signature check, resolved and ready, that may be verified alone or in a
/// batch.
///
/// Holds the signer's key already validated (and, for an aggregate, summed),
/// the signed message and the signature already validated, so building one is
/// everything a check does short of the pairing. That split is what lets a
/// caller decide *when* to pay for the pairing: at once ([`Self::verify`]) or
/// together with the other sets of a block ([`verify_signature_sets`]).
#[derive(Clone, Copy)]
pub struct SignatureSet {
    pubkey: PublicKey,
    message: Root,
    signature: Signature,
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
        let signature = Signature::sig_validate(signature.as_ref(), false).ok()?;
        Some(Self {
            pubkey,
            message,
            signature,
        })
    }

    /// `bls.FastAggregateVerify`'s inputs.
    ///
    /// `None` for an empty `pubkeys`, any key that fails `key_validate`, or a
    /// signature that fails `sig_validate`: the cases
    /// [`super::fast_aggregate_verify`] answers false for before the pairing.
    pub fn fast_aggregate<K: PubkeySource>(
        pubkeys: &[K],
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
        })
    }

    /// `bls.FastAggregateVerify`'s inputs with the key already summed, as
    /// committee key sums produce it.
    ///
    /// `None` when `signature` fails `sig_validate`. The key needs no check: a
    /// sum of validated points is in the subgroup, and the identity, the one
    /// sum that is not a valid key, is refused by [`Self::verify`] and by the
    /// batch at pairing time, as it is for a key summed here from scratch.
    pub fn from_aggregate(
        key: AggregatePubkey,
        message: Root,
        signature: &BlsSignature,
    ) -> Option<Self> {
        let signature = Signature::sig_validate(signature.as_ref(), false).ok()?;
        Some(Self {
            pubkey: key.to_public_key(),
            message,
            signature,
        })
    }

    /// The pairing check on its own: the same answer [`super::verify`] or
    /// [`super::fast_aggregate_verify`] gives for these inputs.
    pub fn verify(&self) -> bool {
        pairing_verify(&self.pubkey, &self.message, &self.signature)
    }

    /// Whether the key is the identity, which no signature can validly be
    /// made under. Only a sum of keys can be: a single registry key is
    /// rejected by `key_validate` if it is.
    ///
    /// The pairing check refuses the same input itself, so this makes the
    /// rule explicit where a reader of the batch looks for it, and lets the
    /// batch return before doing any group arithmetic.
    fn key_is_identity(&self) -> bool {
        primitives::key_is_identity(&self.pubkey)
    }
}

/// A random weight in `1..2^64`.
fn random_weight(rng: &mut impl RngExt) -> u64 {
    loop {
        let candidate: u64 = rng.random();
        if candidate != 0 {
            break candidate;
        }
    }
}

/// The runs of equal messages in `sets` taken in `order`, as index ranges into
/// `order`. `order` must already be sorted by message.
fn message_runs(sets: &[SignatureSet], order: &[usize]) -> Vec<Range<usize>> {
    let mut runs = Vec::new();
    let mut start = 0;
    for end in 1..=order.len() {
        if end == order.len() || sets[order[end]].message != sets[order[start]].message {
            runs.push(start..end);
            start = end;
        }
    }
    runs
}

/// Whether every set verifies, in one random-linear-combination check grouped
/// by message: one pairing per distinct message and one final exponentiation.
/// An empty slice verifies.
///
/// See the module documentation for the equation and why the weights are
/// random (64-bit, nonzero, from the OS-seeded RNG). A single set skips them
/// and is verified directly, since one equation needs no combining. A set
/// whose key is the identity fails the batch, as it fails
/// [`SignatureSet::verify`], and so does a batch whose weighted signature sum
/// is the point at infinity.
pub fn verify_signature_sets(sets: &[SignatureSet]) -> bool {
    match sets {
        [] => return true,
        [only] => return only.verify(),
        _ => {}
    }
    if sets.iter().any(SignatureSet::key_is_identity) {
        return false;
    }
    let mut order: Vec<usize> = (0..sets.len()).collect();
    order.sort_unstable_by(|&a, &b| sets[a].message.as_slice().cmp(sets[b].message.as_slice()));

    let mut rng = rand::rng();
    let weights: Vec<u64> = order.iter().map(|_| random_weight(&mut rng)).collect();
    let keys: Vec<PublicKey> = order.iter().map(|&i| sets[i].pubkey).collect();
    let signatures: Vec<Signature> = order.iter().map(|&i| sets[i].signature).collect();

    // If the weighted signatures summed to the identity the right-hand side of
    // the equation would be trivial.
    let signature_sum = primitives::weighted_signature_sum(&signatures, &weights);
    if primitives::signature_is_identity(&signature_sum) {
        return false;
    }

    let runs = message_runs(sets, &order);
    let groups: Vec<(PublicKey, blst_p2_affine)> = runs
        .par_iter()
        .map(|run| {
            let key = primitives::weighted_key_sum(&keys[run.clone()], &weights[run.clone()]);
            (key, hashed_message(&sets[order[run.start]].message))
        })
        .collect();
    let group_keys: Vec<blst_p1_affine> = groups.iter().map(|(key, _)| (*key).into()).collect();
    let pairs: Vec<(&blst_p1_affine, &blst_p2_affine)> = group_keys
        .iter()
        .zip(&groups)
        .map(|(key, (_, hashed))| (key, hashed))
        .collect();
    primitives::pairing_check(&pairs, &signature_sum.into())
}

#[cfg(test)]
mod tests {
    use blst::min_pk::SecretKey;

    use super::*;
    use crate::bls::{self, DST};
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

    #[test]
    fn random_weights_are_never_zero() {
        let mut rng = rand::rng();
        for _ in 0..10_000 {
            let weight = random_weight(&mut rng);
            assert_ne!(weight, 0);
        }
    }

    /// `sets` of `count` single-key sets signing `msg`, valid unless `bad` is
    /// given, whose index then signs a different message.
    fn sets_over(msg: Root, seeds: std::ops::Range<u8>, bad: Option<u8>) -> Vec<SignatureSet> {
        seeds
            .map(|i| {
                let key = secret_key(i);
                let signed = if Some(i) == bad { message(250) } else { msg };
                SignatureSet::single(&pubkey_of(&key), msg, &sign(&key, signed)).unwrap()
            })
            .collect()
    }

    #[test]
    fn a_bad_set_among_sets_sharing_its_message_fails_the_batch() {
        for bad in [30u8, 33, 37] {
            let sets = sets_over(message(77), 30..38, Some(bad));
            assert!(!verify_signature_sets(&sets), "bad set {bad}");
            // Another message group alongside must not mask it.
            let mut mixed = valid_sets(3);
            mixed.extend(sets);
            assert!(!verify_signature_sets(&mixed), "bad set {bad} in a mix");
        }
        assert!(verify_signature_sets(&sets_over(message(77), 30..38, None)));
    }

    #[test]
    fn cancelling_keys_in_a_multi_set_group_never_verify() {
        let key = secret_key(40);
        let pubkey = pubkey_of(&key);
        let msg = message(40);
        let infinity = BlsSignature(bls::G2_POINT_AT_INFINITY);
        let real = sign(&key, msg);
        for (first, second) in [(infinity, infinity), (real, real), (real, infinity)] {
            let plus = SignatureSet::single(&pubkey, msg, &first).unwrap();
            let minus = SignatureSet::single(&negated(pubkey), msg, &second).unwrap();
            for _ in 0..20 {
                let mut sets = valid_sets(2);
                sets.push(plus);
                sets.push(minus);
                assert!(!verify_signature_sets(&sets));
                assert!(!verify_signature_sets(&[plus, minus]));
            }
        }
    }

    #[test]
    fn a_weighted_signature_sum_at_infinity_is_refused() {
        // Both signatures are the identity, so their weighted sum always is.
        let infinity = BlsSignature(bls::G2_POINT_AT_INFINITY);
        let sets: Vec<SignatureSet> = (50..54)
            .map(|i| {
                SignatureSet::single(&pubkey_of(&secret_key(i)), message(50), &infinity).unwrap()
            })
            .collect();
        for _ in 0..10 {
            assert!(!verify_signature_sets(&sets));
        }
        let signatures: Vec<Signature> = sets.iter().map(|set| set.signature).collect();
        let sum = primitives::weighted_signature_sum(&signatures, &[3, 5, 7, 9]);
        assert!(primitives::signature_is_identity(&sum));
    }

    /// The verdict plain blst gives for every set alone, ANDed.
    fn blst_checks_each(sets: &[SignatureSet]) -> bool {
        sets.iter().all(|set| {
            set.signature
                .verify(false, set.message.as_slice(), DST, &[], &set.pubkey, false)
                == blst::BLST_ERROR::BLST_SUCCESS
        })
    }

    #[test]
    fn the_grouped_batch_agrees_with_blst_checking_each_set() {
        use rand::RngExt;
        let mut rng = rand::rng();
        for size in 2..=20usize {
            for round in 0..4 {
                // Few distinct messages so groups are shared, a few keys so
                // the same key signs several messages.
                let distinct: u8 = rng.random_range(1..=size.min(6) as u8);
                let corrupt = round % 2 == 1;
                let bad_at = rng.random_range(0..size);
                let sets: Vec<SignatureSet> = (0..size)
                    .map(|i| {
                        let key = secret_key(rng.random_range(60..70));
                        let msg = message(rng.random_range(0..distinct));
                        let signed = if corrupt && i == bad_at {
                            message(200)
                        } else {
                            msg
                        };
                        SignatureSet::single(&pubkey_of(&key), msg, &sign(&key, signed)).unwrap()
                    })
                    .collect();
                assert_eq!(
                    verify_signature_sets(&sets),
                    blst_checks_each(&sets),
                    "size {size}, round {round}"
                );
            }
        }
    }
}
