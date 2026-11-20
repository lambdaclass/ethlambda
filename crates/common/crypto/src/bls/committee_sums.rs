//! Committee key sums: a committee's aggregate public key, kept as a curve
//! point so an attestation's key can be derived from it instead of re-summed.
//!
//! An attestation aggregate usually covers most of its committee, and its
//! verification key is the sum of its attesters' keys. Summing every attester
//! costs one point addition per signer; summing the *non*-attesters and
//! subtracting from the committee's own sum costs one per absentee, which on a
//! healthy network is a small fraction. The two are the same group element, so
//! the pairing check is unchanged and only the number of additions moves.
//!
//! This module holds the crypto half: [`AggregatePubkey`], a sum that can be
//! added to, subtracted from and verified against without ever being
//! serialized, and [`CommitteeKeySums`], one shuffling's committee sums
//! indexed by committee number. Which committees there are, who is in them and
//! when a sum is still valid belongs to `ethlambda-storage`'s `CommitteeCache`
//! and `ethlambda-state-transition`'s accessors; this module knows only keys.
//!
//! Every key reaches a sum through `validated_pubkeys`, so the guarantees of
//! the module documentation in [`super`] hold here too: a key that fails
//! `key_validate` is never summed, and a failure is reported as `None` rather
//! than as a sum that silently omits the key.

use blst::min_pk::{AggregatePublicKey, PublicKey};

use ethlambda_types::beacon::primitives::{BlsPubkey, BlsSignature, Root};

use super::{SignatureSet, sum_validated_projective, validated_pubkeys};

/// A sum of validated public keys, kept as a curve point. Never serialized.
///
/// Not a [`BlsPubkey`] on purpose: compressing a point costs a field inversion,
/// and the only consumer is a pairing check in this process, so the point stays
/// as it is. The sum may be the identity (every key subtracted away), which is
/// representable here and refused by [`Self::verify`], exactly as `blst`
/// refuses an infinite key at pairing time.
#[derive(Clone, Copy)]
pub struct AggregatePubkey(AggregatePublicKey);

impl AggregatePubkey {
    /// The sum of `pubkeys`, each validated through the pubkey cache. `None` if
    /// `pubkeys` is empty or any key fails validation.
    pub fn sum(pubkeys: &[BlsPubkey]) -> Option<Self> {
        let points = validated_pubkeys(pubkeys)?;
        sum_validated_projective(&points).map(Self)
    }

    /// `self - sum(pubkeys)`, with each key validated through the pubkey
    /// cache. `None` if any key fails validation; an empty `pubkeys` is `self`.
    ///
    /// Negation goes through `blst`'s own `sub_aggregate`, so no `unsafe` is
    /// needed here. Subtracting every key `self` was built from yields the
    /// identity, not an error: see [`Self::verify`].
    pub fn minus(&self, pubkeys: &[BlsPubkey]) -> Option<Self> {
        if pubkeys.is_empty() {
            return Some(*self);
        }
        let points = validated_pubkeys(pubkeys)?;
        let removed = sum_validated_projective(&points)?;
        let mut result = self.0;
        result.sub_aggregate(&removed);
        Some(Self(result))
    }

    /// `self + other`.
    pub fn plus(&self, other: &Self) -> Self {
        let mut result = self.0;
        result.add_aggregate(&other.0);
        Self(result)
    }

    /// `bls.FastAggregateVerify` with this already-summed key: false for an
    /// invalid signature, and false for the identity key, as the path that sums
    /// the keys itself is.
    ///
    /// The signature is validated here for the same reason
    /// [`super::fast_aggregate_verify`] validates it: nothing upstream
    /// guarantees a subgroup-correct point. The key needs no check, since a sum
    /// of validated points is in the subgroup; the identity is the one value
    /// that is not a valid key, and `blst` rejects it at pairing time.
    pub fn verify(&self, message: Root, signature: &BlsSignature) -> bool {
        SignatureSet::from_aggregate(*self, message, signature).is_some_and(|set| set.verify())
    }

    /// The sum as an affine key, the form a [`SignatureSet`] holds. One field
    /// inversion, which is why the sums stay projective until they are checked.
    pub(super) fn to_public_key(self) -> PublicKey {
        self.0.to_public_key()
    }

    /// The sum compressed, for comparing two sums in tests.
    #[cfg(test)]
    fn to_bytes(self) -> [u8; 48] {
        self.0.to_public_key().to_bytes()
    }
}

impl std::fmt::Debug for AggregatePubkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AggregatePubkey(..)")
    }
}

/// One shuffling's committee key sums, by committee number within the epoch
/// (`slot_offset * committees_per_slot + committee_index`, the position
/// `committee_number` computes). An entry is `None` when some member's key
/// fails validation, so that committee falls back to summing its attesters.
pub struct CommitteeKeySums {
    sums: Vec<Option<AggregatePubkey>>,
}

impl CommitteeKeySums {
    /// Wraps `sums`, one entry per committee of the epoch in committee-number order.
    pub fn new(sums: Vec<Option<AggregatePubkey>>) -> Self {
        Self { sums }
    }

    /// The sum of committee `committee_number`'s members' keys, or `None` when
    /// the number is out of range or that committee has no usable sum.
    pub fn get(&self, committee_number: usize) -> Option<&AggregatePubkey> {
        self.sums.get(committee_number)?.as_ref()
    }
}

impl std::fmt::Debug for CommitteeKeySums {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommitteeKeySums")
            .field("committees", &self.sums.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::super::DST;
    use super::*;
    use blst::min_pk::SecretKey;

    fn secret(seed: u64) -> SecretKey {
        let mut ikm = [0x3cu8; 32];
        ikm[..8].copy_from_slice(&seed.to_le_bytes());
        SecretKey::key_gen(&ikm, &[]).expect("32 bytes of input material")
    }

    fn pubkeys(count: usize) -> Vec<BlsPubkey> {
        (0..count)
            .map(|i| BlsPubkey(secret(i as u64 + 1000).sk_to_pk().to_bytes()))
            .collect()
    }

    /// The sum straight through `blst`, no cache and no helper of this module.
    fn direct(keys: &[BlsPubkey]) -> [u8; 48] {
        let points: Vec<PublicKey> = keys
            .iter()
            .map(|k| PublicKey::key_validate(k.as_ref()).unwrap())
            .collect();
        let refs: Vec<&PublicKey> = points.iter().collect();
        AggregatePublicKey::aggregate(&refs, false)
            .unwrap()
            .to_public_key()
            .to_bytes()
    }

    #[test]
    fn sum_matches_the_direct_sum_including_duplicates() {
        let keys = pubkeys(8);
        let mut with_duplicates = keys.clone();
        with_duplicates.push(keys[0]);
        with_duplicates.push(keys[0]);
        for set in [&keys[..1], &keys[..2], &keys[..], &with_duplicates[..]] {
            assert_eq!(AggregatePubkey::sum(set).unwrap().to_bytes(), direct(set));
        }
        let twice = [keys[0], keys[0]];
        assert_eq!(
            AggregatePubkey::sum(&twice).unwrap().to_bytes(),
            direct(&twice)
        );
    }

    #[test]
    fn sum_of_nothing_or_of_an_invalid_key_is_none() {
        assert!(AggregatePubkey::sum(&[]).is_none());
        let mut keys = pubkeys(3);
        keys.push(BlsPubkey::default());
        assert!(AggregatePubkey::sum(&keys).is_none());
    }

    /// `committee - absentees` is the attesters' sum for every mask shape.
    #[test]
    fn minus_and_plus_agree_with_the_direct_sum() {
        let keys = pubkeys(16);
        let total = AggregatePubkey::sum(&keys).unwrap();
        for absent in [0usize, 1, 8, 9, 15] {
            let attesters = &keys[absent..];
            let absentees = &keys[..absent];
            let derived = total.minus(absentees).unwrap();
            assert_eq!(derived.to_bytes(), direct(attesters), "absent {absent}");
        }
        let left = AggregatePubkey::sum(&keys[..5]).unwrap();
        let right = AggregatePubkey::sum(&keys[5..]).unwrap();
        assert_eq!(left.plus(&right).to_bytes(), total.to_bytes());
        assert_eq!(total.minus(&[]).unwrap().to_bytes(), total.to_bytes());
    }

    /// The same over random masks of a committee-sized run, with the attesters
    /// scattered rather than a prefix: `sum - absentees` and the direct sum of
    /// the attesters are the same bytes.
    #[test]
    fn minus_agrees_with_the_direct_sum_over_random_masks() {
        let keys = pubkeys(64);
        let total = AggregatePubkey::sum(&keys).unwrap();
        // xorshift64, fixed seed: reproducible without a seeded-RNG dependency.
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for round in 0..40 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let (attesters, absentees): (Vec<_>, Vec<_>) = keys
                .iter()
                .enumerate()
                .partition(|(position, _)| state >> position & 1 == 1);
            let attesters: Vec<BlsPubkey> = attesters.into_iter().map(|(_, key)| *key).collect();
            let absentees: Vec<BlsPubkey> = absentees.into_iter().map(|(_, key)| *key).collect();
            if attesters.is_empty() {
                continue;
            }
            let derived = total.minus(&absentees).unwrap();
            assert_eq!(derived.to_bytes(), direct(&attesters), "round {round}");
        }
    }

    #[test]
    fn minus_with_an_invalid_key_is_none() {
        let keys = pubkeys(4);
        let total = AggregatePubkey::sum(&keys).unwrap();
        assert!(total.minus(&[BlsPubkey::default()]).is_none());
    }

    fn signed(count: usize, seed: u64, message: Root) -> (Vec<BlsPubkey>, Vec<BlsSignature>) {
        let secrets: Vec<SecretKey> = (0..count as u64).map(|i| secret(i + seed)).collect();
        let keys = secrets
            .iter()
            .map(|s| BlsPubkey(s.sk_to_pk().to_bytes()))
            .collect();
        let sigs = secrets
            .iter()
            .map(|s| BlsSignature(s.sign(message.as_slice(), DST, &[]).to_bytes()))
            .collect();
        (keys, sigs)
    }

    #[test]
    fn verify_agrees_with_fast_aggregate_verify_on_real_signatures() {
        let message = Root::repeat_byte(9);
        let (keys, sigs) = signed(6, 50, message);
        let good = crate::bls::aggregate(&sigs).unwrap();
        let partial = crate::bls::aggregate(&sigs[1..]).unwrap();

        let total = AggregatePubkey::sum(&keys).unwrap();
        assert!(total.verify(message, &good));
        assert!(crate::bls::fast_aggregate_verify(&keys, message, &good));

        // The same key from `total - absentee`, against the matching signature.
        let derived = total.minus(&keys[..1]).unwrap();
        assert!(derived.verify(message, &partial));
        assert!(crate::bls::fast_aggregate_verify(
            &keys[1..],
            message,
            &partial
        ));

        // A wrong signature, a wrong message and a missing signature fail on both paths.
        assert!(!derived.verify(message, &good));
        assert!(!crate::bls::fast_aggregate_verify(
            &keys[1..],
            message,
            &good
        ));
        assert!(!total.verify(Root::repeat_byte(10), &good));
        assert!(!total.verify(message, &BlsSignature::default()));
    }

    #[test]
    fn the_identity_aggregate_never_verifies() {
        let message = Root::repeat_byte(1);
        let (keys, sigs) = signed(3, 90, message);
        let signature = crate::bls::aggregate(&sigs).unwrap();
        let identity = AggregatePubkey::sum(&keys).unwrap().minus(&keys).unwrap();
        assert!(!identity.verify(message, &signature));
    }

    #[test]
    fn committee_key_sums_index_by_committee_number() {
        let keys = pubkeys(2);
        let sums = CommitteeKeySums::new(vec![
            AggregatePubkey::sum(&keys[..1]),
            None,
            AggregatePubkey::sum(&keys),
        ]);
        assert!(sums.get(0).is_some());
        assert!(sums.get(1).is_none());
        assert!(sums.get(2).is_some());
        assert!(sums.get(3).is_none());
    }
}
