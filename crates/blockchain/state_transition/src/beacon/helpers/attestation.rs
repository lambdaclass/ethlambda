//! Turning an aggregate attestation into the attesters it covers.
//!
//! An [`Attestation`] names its attesters as a bitfield over a committee, which
//! is compact on the wire but useless for signature verification, since that
//! needs public keys and so needs indices. These three functions bridge the two
//! forms.
//!
//! These take phase0's attestation containers. Electra reshapes them, widening
//! the aggregation bits from one committee to a whole slot's worth and adding a
//! committee bitfield, so it gets its own versions rather than reusing these.

use crate::beacon::bls::{IndexedPubkey, SignatureSet};
use crate::beacon::constants;
use crate::beacon::containers::BeaconState;
use crate::beacon::containers::phase0::{Attestation, AttestingIndices, IndexedAttestation};
use crate::beacon::containers::shared::AttestationData;
use crate::beacon::error::Result;
use crate::beacon::helpers::accessors::{CommitteeCache, CommitteeCacheExt, get_domain};
use crate::beacon::helpers::misc::{compute_epoch_at_slot, compute_signing_root};
use crate::beacon::helpers::predicates::are_indices_sorted_and_unique;
use crate::beacon::preset;
use crate::beacon::primitives::{BlsSignature, Domain, HashTreeRoot as _, ValidatorIndex};

/// The committee members whose bit is set in `attestation`, in ascending order.
///
/// The specification returns a `Set` here and sorts it in
/// [`get_indexed_attestation`]. Sorting here instead gives every caller the same
/// order, which is what they all want: `get_indexed_attestation` because
/// [`is_valid_indexed_attestation`] requires sorted indices, and the epoch
/// accounting because it treats the result as a set.
///
/// The sort is not cosmetic. A committee is a *shuffled* slice of the validator
/// registry, so walking it in position order yields attesters in shuffle order,
/// which is almost never ascending.
///
/// `committees` supplies the slot's shuffling, derived for the whole epoch at
/// once. That pays off across the many attestations a block carries, which is
/// the reuse this parameter exists for, but it is more work than one
/// committee's own derivation: a caller with a single attestation and no cache
/// to share it through pays for the whole epoch to read one committee of it.
/// See [`CommitteeCache`].
pub fn get_attesting_indices(
    state: &BeaconState,
    attestation: &Attestation,
    committees: &CommitteeCache,
) -> Result<Vec<ValidatorIndex>> {
    let epoch = compute_epoch_at_slot(attestation.data.slot);
    let epoch_committees = committees.committees(state, epoch);
    let committee = epoch_committees.committee(attestation.data.slot, attestation.data.index)?;
    let mut indices: Vec<ValidatorIndex> = committee
        .iter()
        .enumerate()
        .filter(|(position, _)| attestation.aggregation_bits.get(*position).unwrap_or(false))
        .map(|(_, index)| *index)
        .collect();
    indices.sort_unstable();
    Ok(indices)
}

/// The same attestation with its attesters named rather than bit-encoded.
pub fn get_indexed_attestation(
    state: &BeaconState,
    attestation: &Attestation,
    committees: &CommitteeCache,
) -> Result<IndexedAttestation> {
    let indices = get_attesting_indices(state, attestation, committees)?;
    Ok(IndexedAttestation {
        attesting_indices: AttestingIndices::try_from(indices)?,
        data: attestation.data,
        signature: attestation.signature,
    })
}

/// Whether an indexed attestation names a valid attester set and carries their
/// aggregate signature.
///
/// Empty is invalid, and so is any ordering other than sorted and unique. Both
/// checks matter for more than tidiness: a repeated index would let one validator
/// be counted twice, and an unsorted list would make the same attester set have
/// more than one encoding, and so more than one root.
pub fn is_valid_indexed_attestation(
    state: &BeaconState,
    indexed_attestation: &IndexedAttestation,
) -> bool {
    indexed_attestation_signature_set(state, indexed_attestation).is_some_and(|set| set.verify())
}

/// The signature check [`is_valid_indexed_attestation`] makes, resolved but
/// not yet run, so a block can verify every attestation's signature in one
/// batch. See [`attesters_signature_set`] for the checks.
pub fn indexed_attestation_signature_set(
    state: &BeaconState,
    indexed_attestation: &IndexedAttestation,
) -> Option<SignatureSet> {
    attesters_signature_set(
        state,
        &indexed_attestation.attesting_indices,
        &indexed_attestation.data,
        &indexed_attestation.signature,
        None,
    )
}

/// `is_valid_indexed_attestation`'s check for any fork's indexed attestation,
/// resolved but not yet run: the one definition of the rules phase0's,
/// electra's and gloas's versions share, which differ only in the container
/// they read `attesting_indices`, `data` and `signature` from.
///
/// Every structural check happens here, at once, and `None` means the
/// attestation is invalid without needing a pairing: an empty attester list,
/// one longer than `MAX_VALIDATORS_PER_SLOT`, one not sorted and unique, an
/// index outside the registry, or a key or signature that does not validate.
/// The length bound is gloas's (EIP-7688 made its `AttestingIndices` an
/// unbounded progressive list); every earlier fork's list type is bounded at
/// or below it, so the check never changes an earlier fork's answer.
///
/// `domain` is the state's `DOMAIN_BEACON_ATTESTER` at the target epoch when
/// `None`. Gossip passes its own, for a state that may not have reached the
/// attestation's fork: see
/// [`crate::beacon::helpers::accessors::get_domain_from_schedule`].
pub(crate) fn attesters_signature_set(
    state: &BeaconState,
    attesting_indices: &[ValidatorIndex],
    data: &AttestationData,
    signature: &BlsSignature,
    domain: Option<Domain>,
) -> Option<SignatureSet> {
    if attesting_indices.is_empty()
        || attesting_indices.len() > preset::MAX_VALIDATORS_PER_SLOT
        || !are_indices_sorted_and_unique(attesting_indices)
    {
        return None;
    }

    let mut pubkeys = Vec::with_capacity(attesting_indices.len());
    for index in attesting_indices {
        match state.validator(*index) {
            Ok(validator) => pubkeys.push(IndexedPubkey {
                index: *index,
                pubkey: validator.pubkey,
            }),
            Err(_) => return None,
        }
    }

    let domain = domain.unwrap_or_else(|| {
        get_domain(
            state,
            constants::DOMAIN_BEACON_ATTESTER,
            Some(data.target.epoch),
        )
    });
    let signing_root = compute_signing_root(data.hash_tree_root(), domain);
    SignatureSet::fast_aggregate(&pubkeys, signing_root, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::helpers::test_state::{sign_for, with_validators};
    use crate::beacon::primitives::Root;

    /// The attester-list rules every fork shares refuse before any pairing,
    /// and a well-formed list with a well-formed signature builds a set.
    #[test]
    fn only_a_sorted_unique_list_of_known_validators_builds_a_set() {
        let state = with_validators(8);
        let data = AttestationData::default();
        // Any valid point: whether it verifies is the pairing's question.
        let signature = sign_for(1, Root::repeat_byte(1));
        let build = |indices: &[ValidatorIndex]| {
            attesters_signature_set(&state, indices, &data, &signature, None)
        };

        assert!(build(&[1, 2]).is_some(), "well formed");
        assert!(build(&[]).is_none(), "empty");
        assert!(build(&[2, 1]).is_none(), "unsorted");
        assert!(build(&[1, 1]).is_none(), "repeated");
        assert!(build(&[1, 8]).is_none(), "outside the registry");
    }
}
