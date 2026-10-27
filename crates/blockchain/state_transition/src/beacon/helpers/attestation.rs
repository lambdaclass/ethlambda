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

use crate::beacon::containers::BeaconState;
use crate::beacon::containers::phase0::{Attestation, AttestingIndices, IndexedAttestation};
use crate::beacon::error::Result;
use crate::beacon::helpers::accessors::{CommitteeCache, CommitteeCacheExt, get_domain};
use crate::beacon::helpers::misc::{compute_epoch_at_slot, compute_signing_root};
use crate::beacon::helpers::predicates::are_indices_sorted_and_unique;
use crate::beacon::primitives::{Domain, HashTreeRoot as _, ValidatorIndex};
use crate::beacon::{bls, constants};

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
    let domain = get_domain(
        state,
        constants::DOMAIN_BEACON_ATTESTER,
        Some(indexed_attestation.data.target.epoch),
    );
    is_valid_indexed_attestation_with_domain(state, indexed_attestation, domain)
}

/// [`is_valid_indexed_attestation`] under a signing domain the caller chose.
///
/// For gossip, which checks against a state that may not have reached the
/// attestation's fork: see
/// [`crate::beacon::helpers::accessors::get_domain_from_schedule`].
pub fn is_valid_indexed_attestation_with_domain(
    state: &BeaconState,
    indexed_attestation: &IndexedAttestation,
    domain: Domain,
) -> bool {
    let indices: &[ValidatorIndex] = &indexed_attestation.attesting_indices;
    if indices.is_empty() || !are_indices_sorted_and_unique(indices) {
        return false;
    }

    let mut pubkeys = Vec::with_capacity(indices.len());
    for index in indices {
        match state.validator(*index) {
            Ok(validator) => pubkeys.push(validator.pubkey),
            Err(_) => return false,
        }
    }

    let signing_root = compute_signing_root(indexed_attestation.data.hash_tree_root(), domain);
    bls::fast_aggregate_verify(&pubkeys, signing_root, &indexed_attestation.signature)
}
