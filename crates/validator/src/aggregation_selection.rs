//! Whether a validator is an aggregator for a committee, and why it is not a
//! choice.
//!
//! # What the rule is for
//!
//! Every attester in a committee broadcasts its own vote. Somebody has to fold
//! those into one aggregate signature, or a block would have to carry a
//! signature per attester. The protocol picks who, and it picks by a rule
//! nobody can steer.
//!
//! A validator signs the slot under a dedicated domain, hashes that signature,
//! and is an aggregator when the first eight bytes, read as a little-endian
//! integer, divide evenly by a modulus derived from the committee's size. BLS
//! signatures are deterministic, so a validator gets exactly one answer per
//! slot and cannot search for a better one. It cannot decline either: the same
//! computation is what a beacon node checks the resulting aggregate against.
//!
//! # The modulus, and why the count is only approximate
//!
//! `committee_length / TARGET_AGGREGATORS_PER_COMMITTEE`, floored, and at least
//! one. With a 128-member committee and a target of 16 the modulus is 8, so
//! roughly one member in eight is selected, which is roughly sixteen
//! aggregators. Roughly, not exactly: each member's signature hash is
//! independent, so the count is binomial around the target rather than fixed,
//! and the protocol wants redundancy here rather than precision. Having no
//! aggregator for a committee costs that committee's votes their cheap path
//! into a block.
//!
//! A committee smaller than the target makes the division zero, which is why
//! the modulus floors at one. `x % 1 == 0` for every `x`, so every member of a
//! very small committee aggregates. That is the intended outcome, not an edge
//! case to guard: a committee that cannot supply sixteen aggregators should
//! supply all of them.

use ethlambda_types::beacon::primitives::BlsSignature;
use sha2::{Digest, Sha256};

use crate::beacon_node::dto::{AttesterDutyDto, parse_pubkey};
use crate::error::Result;
use crate::keys::ValidatorStore;
use crate::signing::SigningContext;

/// How many aggregators the protocol aims for per committee.
///
/// A validator-guide constant rather than a preset one, which is why it lives
/// here and not in `ethlambda-types`: it governs how this client behaves, not
/// what the chain agrees about, and no container's shape depends on it.
pub const TARGET_AGGREGATORS_PER_COMMITTEE: u64 = 16;

/// Whether `selection_proof` selects its signer as an aggregator for a
/// committee of `committee_length` members.
///
/// `selection_proof` must be the signature over the committee's slot under the
/// selection domain, and nothing else. Any other signature would still produce
/// a `bool` here, and it would be the wrong one in a way nothing downstream
/// could detect, because a beacon node re-derives this from the slot signature
/// carried in the aggregate.
pub fn is_aggregator(committee_length: u64, selection_proof: &BlsSignature) -> bool {
    let modulo = (committee_length / TARGET_AGGREGATORS_PER_COMMITTEE).max(1);

    let digest = Sha256::digest(selection_proof.0);
    // The specification's `bytes_to_uint64`, which is little-endian. Reading
    // these eight bytes the other way round would still select about one
    // validator in `modulo`, so the mistake would look statistically correct
    // and produce aggregates every beacon node rejects.
    let mut head = [0u8; 8];
    head.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(head) % modulo == 0
}

/// The selection proof for `duty`, if it selects that validator as an
/// aggregator for that committee.
///
/// One function for both callers, because they have to agree. The subscription
/// sent at the start of an epoch tells the beacon node which committees this
/// client will aggregate for, and the aggregation tick later in each slot acts
/// on that claim. A client that computed the two differently would either
/// claim a role it never performs, leaving a committee's votes to nobody, or
/// perform one it never claimed, against a node that did not collect the votes
/// to fold.
///
/// Returns the proof rather than a bare `bool` because the caller that acts on
/// it needs the signature itself: it goes into the published
/// `AggregateAndProof`, which is what makes the selection verifiable rather
/// than self-declared.
///
/// An unreadable pubkey or an unknown validator is an error rather than a
/// silent `None`. Both mean the duty cannot be served at all, and reporting
/// them as "not an aggregator" would hide a misconfiguration behind a role
/// this validator was never going to fill anyway.
pub fn selection_for(
    context: &SigningContext,
    store: &ValidatorStore,
    duty: &AttesterDutyDto,
) -> Result<Option<BlsSignature>> {
    let pubkey = parse_pubkey(&duty.pubkey)?;
    let proof = context.sign_selection_proof(store, &pubkey, duty.slot)?;
    Ok(is_aggregator(duty.committee_length, &proof).then_some(proof))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A signature whose SHA-256 digest starts with the little-endian bytes of
    /// `target`, found by search. Lets a test state the selection outcome it
    /// wants rather than hunting for a signature that happens to produce it.
    fn signature_hashing_to_multiple_of(modulo: u64) -> BlsSignature {
        for seed in 0u32..100_000 {
            let mut bytes = [0u8; 96];
            bytes[..4].copy_from_slice(&seed.to_le_bytes());
            let signature = BlsSignature(bytes);
            let digest = Sha256::digest(signature.0);
            let mut head = [0u8; 8];
            head.copy_from_slice(&digest[..8]);
            if u64::from_le_bytes(head) % modulo == 0 {
                return signature;
            }
        }
        panic!("no signature found hashing to a multiple of {modulo}");
    }

    fn signature_not_hashing_to_multiple_of(modulo: u64) -> BlsSignature {
        for seed in 0u32..100_000 {
            let mut bytes = [0u8; 96];
            bytes[..4].copy_from_slice(&seed.to_le_bytes());
            let signature = BlsSignature(bytes);
            let digest = Sha256::digest(signature.0);
            let mut head = [0u8; 8];
            head.copy_from_slice(&digest[..8]);
            if u64::from_le_bytes(head) % modulo != 0 {
                return signature;
            }
        }
        panic!("no signature found that is not a multiple of {modulo}");
    }

    /// A committee smaller than the target divides to zero, and a modulus of
    /// zero would panic. Flooring at one makes every member an aggregator,
    /// which is the intended answer: a committee that cannot supply the target
    /// number should supply all of them.
    #[test]
    fn every_member_of_a_committee_below_the_target_is_an_aggregator() {
        for length in [0, 1, TARGET_AGGREGATORS_PER_COMMITTEE - 1] {
            // Any signature at all, including one that fails a larger modulus.
            let signature = signature_not_hashing_to_multiple_of(8);
            assert!(
                is_aggregator(length, &signature),
                "committee of {length} must select everyone"
            );
        }
    }

    #[test]
    fn a_committee_of_exactly_the_target_still_selects_everyone() {
        // 16 / 16 is 1, so the modulus is 1 and every remainder is zero.
        let signature = signature_not_hashing_to_multiple_of(8);
        assert!(is_aggregator(TARGET_AGGREGATORS_PER_COMMITTEE, &signature));
    }

    /// A mainnet-sized committee: 128 members, target 16, modulus 8.
    #[test]
    fn a_full_committee_selects_only_matching_signatures() {
        let selected = signature_hashing_to_multiple_of(8);
        let rejected = signature_not_hashing_to_multiple_of(8);

        assert!(is_aggregator(128, &selected));
        assert!(!is_aggregator(128, &rejected));
    }

    /// The same signature must give the same answer every time. A validator
    /// gets one answer per slot and cannot search for a better one, which is
    /// the property that makes the role unsteerable.
    #[test]
    fn the_answer_is_a_function_of_the_signature_alone() {
        let signature = signature_hashing_to_multiple_of(8);
        let first = is_aggregator(128, &signature);
        for _ in 0..10 {
            assert_eq!(is_aggregator(128, &signature), first);
        }
    }

    /// Over many signatures the selected fraction should sit near one in
    /// `modulo`. Loose bounds on purpose: the count is binomial, and a test
    /// that pinned it exactly would be testing SHA-256's output rather than
    /// this function.
    #[test]
    fn roughly_one_in_modulo_signatures_is_selected() {
        let mut selected = 0;
        let total = 8_000;
        for seed in 0u32..total {
            let mut bytes = [0u8; 96];
            bytes[..4].copy_from_slice(&seed.to_le_bytes());
            if is_aggregator(128, &BlsSignature(bytes)) {
                selected += 1;
            }
        }
        // Modulus 8, so expect about 1000 of 8000.
        assert!(
            (700..=1300).contains(&selected),
            "expected roughly an eighth of {total} to be selected, got {selected}"
        );
    }

    /// The digest is read little-endian, as the specification's
    /// `bytes_to_uint64` does. Big-endian would also select about one in
    /// `modulo`, so the statistics test above cannot catch the difference;
    /// only comparing the two orderings on a signature where they disagree
    /// can.
    #[test]
    fn the_digest_is_read_little_endian() {
        let signature = (0u32..100_000)
            .find_map(|seed| {
                let mut bytes = [0u8; 96];
                bytes[..4].copy_from_slice(&seed.to_le_bytes());
                let digest = Sha256::digest(bytes);
                let mut head = [0u8; 8];
                head.copy_from_slice(&digest[..8]);
                let little = u64::from_le_bytes(head) % 8 == 0;
                let big = u64::from_be_bytes(head) % 8 == 0;
                (little != big).then_some((BlsSignature(bytes), little))
            })
            .expect("some signature must distinguish the two byte orders");

        assert_eq!(
            is_aggregator(128, &signature.0),
            signature.1,
            "the little-endian reading must be the one that decides"
        );
    }
}
