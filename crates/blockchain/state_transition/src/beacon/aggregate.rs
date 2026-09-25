//! `beacon_aggregate_and_proof`'s gossip validation conditions.
//!
//! Split out of [`super::fork_choice`], which holds the handler
//! ([`super::fork_choice::on_gossip_aggregate`]) that calls this, for two
//! reasons. These conditions are `p2p-interface.md`'s rather than
//! `fork-choice.md`'s, and they are the only part of the aggregate path that
//! is pure: every function here reads a state and a block index and decides,
//! touching nothing.
//!
//! # What is here and what is not
//!
//! The specification's validator interleaves checks this node runs in three
//! different places, so this module is deliberately not all of it:
//!
//! | Condition | Where |
//! |---|---|
//! | epoch matches target, has participants, propagation range | `ethlambda-p2p`'s gossip handler, which needs no state for them |
//! | first aggregate for this `(epoch, aggregator)`, superset of bits already seen | the chain actor, which alone holds the verdict these are recorded on |
//! | target known, LMD/FFG consistency, slot in the past | [`super::fork_choice::validate_on_attestation`], which already runs them for every attestation |
//! | everything needing committees, pubkeys or the finalized chain | here |
//!
//! The seen-set gates are the actor's specifically because the specification
//! marks an aggregate seen only *after* its signatures verify. A set written
//! before the verdict is a one-message censorship attack: send a garbage
//! aggregate claiming some `(epoch, aggregator)` pair and the genuine
//! aggregate from that aggregator is dropped on arrival. Lighthouse splits it
//! the same way, reading the observed-sets in its early checks and writing
//! them only in `verify_late_checks`, after the signature.
//!
//! # Which state
//!
//! The specification resolves committees against
//! `store.block_states[get_head(store).root]`, this node against the
//! attestation's own target checkpoint state. That is stricter, not looser:
//! the head may sit on a branch the attestation does not vote for, whereas the
//! target checkpoint is an ancestor of the attested block by
//! [`super::fork_choice::validate_on_attestation`]'s own LMD/FFG consistency
//! check. Using it also means one state serves both these conditions and the
//! `on_attestation` application that follows, rather than two.

use std::collections::HashMap;

use ethlambda_storage::Store;

use crate::beacon::config::Config;
use crate::beacon::constants;
use crate::beacon::containers::{BeaconState, SignedAggregateAndProof};
use crate::beacon::error::{Error, Result, verify};
use crate::beacon::fork_choice::{get_checkpoint_block, get_current_store_epoch};
use crate::beacon::hash::hash;
use crate::beacon::helpers::accessors::{CommitteeCache, get_committee_count_per_slot, get_domain};
use crate::beacon::helpers::math::bytes_to_uint64;
use crate::beacon::helpers::misc::{compute_epoch_at_slot, compute_signing_root};
use crate::beacon::primitives::{BlsSignature, CommitteeIndex, HashTreeRoot as _, Root, Slot};
use crate::beacon::{bls, preset};

/// Whether `slot_signature` selects the validator as an aggregator for the
/// committee at `(slot, index)`.
///
/// `validator.md`'s `is_aggregator`. The selection is a function of the
/// signature's own hash, so it cannot be chosen: an aggregator proves its
/// selection by publishing a signature it could only produce with its own key,
/// and any peer recomputes the same verdict.
///
/// The modulo is floored at one, which is what makes every member of a
/// committee smaller than [`constants::TARGET_AGGREGATORS_PER_COMMITTEE`] an
/// aggregator rather than dividing by zero.
///
/// `committees` supplies the slot's shuffling. Deriving one shuffles the whole
/// active set, so a per-aggregate caller must pass a long-lived cache: a fresh
/// one per call costs a full shuffle per aggregate. See [`CommitteeCache`].
pub fn is_aggregator(
    state: &BeaconState,
    slot: Slot,
    index: CommitteeIndex,
    slot_signature: &BlsSignature,
    committees: &mut CommitteeCache,
) -> Result<bool> {
    let epoch_committees = committees.committees(state, compute_epoch_at_slot(slot));
    let committee = epoch_committees.committee(slot, index)?;
    let modulo = (committee.len() as u64 / constants::TARGET_AGGREGATORS_PER_COMMITTEE).max(1);
    let digest = hash(slot_signature.as_ref());
    Ok(bytes_to_uint64(&digest.0[0..8]).is_multiple_of(modulo))
}

/// Every `beacon_aggregate_and_proof` condition that needs a state, a
/// committee or the finalized chain.
///
/// `state` is the aggregate's target checkpoint state; see the module
/// documentation for why that rather than the head's. `index` is
/// [`Store::block_index`], taken as a parameter for the reason
/// [`super::fork_choice::on_block_attestation`] takes one: it is a full
/// `Table::LiveChain` scan, and a caller validating several aggregates against
/// one store should pay for it once. `committees` is taken for the same reason,
/// and matters more: see [`is_aggregator`].
///
/// Returns `Ok(())` only if every condition holds. The specification
/// distinguishes `IGNORE` from `REJECT` so a node can score the peer that sent
/// it; this node does neither, because it publishes nothing and runs gossipsub
/// without `validate_messages()`, so both collapse to the same refusal to
/// apply the aggregate.
pub fn validate_aggregate_and_proof_gossip(
    store: &Store,
    signed_aggregate: &SignedAggregateAndProof,
    state: &BeaconState,
    config: &Config,
    index: &HashMap<Root, (Slot, Root)>,
    committees: &mut CommitteeCache,
) -> Result<()> {
    let data = signed_aggregate.data();
    let target_epoch = data.target.epoch;

    // [REJECT] electra requires the committee in `committee_bits` and
    // `data.index` zero. Phase0 carries it in `data.index` and has no
    // bitfield, so this answers for both without the caller branching.
    if matches!(signed_aggregate, SignedAggregateAndProof::Electra(_)) {
        verify(data.index == 0, "aggregate.data.index == 0")?;
    }
    let committee_index = signed_aggregate
        .committee_index()
        .ok_or(Error::SpecAssert("len(committee_indices) == 1"))?;

    // [REJECT] The committee index is within the expected range.
    let committee_count = get_committee_count_per_slot(state, target_epoch);
    verify(
        committee_index < committee_count,
        "index < get_committee_count_per_slot(state, aggregate.data.target.epoch)",
    )?;

    // [IGNORE] The aggregate's epoch is the current or the previous one. Not
    // covered by `validate_on_attestation`'s equivalent check, which is scoped
    // to the *target* epoch; this one is on the attestation's own slot, and
    // electra added it separately.
    let attestation_epoch = compute_epoch_at_slot(data.slot);
    let current_epoch = get_current_store_epoch(store, config);
    let previous_epoch = current_epoch.saturating_sub(1);
    verify(
        attestation_epoch == current_epoch || attestation_epoch == previous_epoch,
        "is_current_or_previous_epoch(store, attestation_epoch)",
    )?;

    // [REJECT] The number of aggregation bits matches the committee size.
    // Meaningful for electra only because exactly one committee is named; see
    // `SignedAggregateAndProof::committee_index`.
    let epoch_committees = committees.committees(state, attestation_epoch);
    let committee = epoch_committees.committee(data.slot, committee_index)?;
    let aggregation_bits = signed_aggregate.aggregation_bits();
    verify(
        aggregation_bits.len() == committee.len(),
        "len(aggregation_bits) == len(committee)",
    )?;

    // [REJECT] The aggregate has participants. Checked here as well as in the
    // p2p handler, because this is the condition's real home: the handler's
    // copy is a cheap pre-filter that keeps an empty aggregate off the actor's
    // mailbox, not the authority on it.
    verify(
        aggregation_bits.iter().any(|bit| *bit),
        "len(attesting_indices) >= 1",
    )?;

    // [REJECT] The selection proof selects the validator as an aggregator.
    let selection_proof = signed_aggregate.selection_proof();
    verify(
        is_aggregator(
            state,
            data.slot,
            committee_index,
            &selection_proof,
            committees,
        )?,
        "is_aggregator(state, aggregate.data.slot, index, selection_proof)",
    )?;

    // [REJECT] The aggregator is a member of the committee.
    let aggregator_index = signed_aggregate.aggregator_index();
    verify(
        committee.contains(&aggregator_index),
        "aggregate_and_proof.aggregator_index in committee",
    )?;

    // [REJECT] The selection proof signature is valid.
    let aggregator = state.validator(aggregator_index)?;
    let domain = get_domain(state, constants::DOMAIN_SELECTION_PROOF, Some(target_epoch));
    let signing_root = compute_signing_root(data.slot.hash_tree_root(), domain);
    verify(
        bls::verify(&aggregator.pubkey, signing_root, &selection_proof),
        "bls.Verify(aggregator.pubkey, signing_root, selection_proof)",
    )?;

    // [REJECT] The aggregator signature is valid. Over the whole
    // `AggregateAndProof`, not over the aggregate alone, which is what binds
    // the selection proof to the votes it was published with.
    let domain = get_domain(
        state,
        constants::DOMAIN_AGGREGATE_AND_PROOF,
        Some(target_epoch),
    );
    let signing_root = compute_signing_root(aggregate_and_proof_root(signed_aggregate), domain);
    verify(
        bls::verify(
            &aggregator.pubkey,
            signing_root,
            &signed_aggregate.signature(),
        ),
        "bls.Verify(aggregator.pubkey, signing_root, signed_aggregate_and_proof.signature)",
    )?;

    // [IGNORE] The finalized checkpoint is an ancestor of the block being
    // voted for. Guards against an aggregate for a branch this node has
    // already finalized away, which no amount of signature validity makes
    // applicable.
    let finalized = store.beacon_finalized_checkpoint();
    let finalized_checkpoint_block =
        get_checkpoint_block(index, data.beacon_block_root, finalized.epoch)?;
    verify(
        finalized_checkpoint_block == finalized.root,
        "get_checkpoint_block(store, block_root, finalized_epoch) == store.finalized_checkpoint.root",
    )?;

    Ok(())
}

/// `hash_tree_root(aggregate_and_proof)`, the object the aggregator signs.
///
/// One dispatch here rather than an accessor on the enum, because the root is
/// only ever needed for this one signature check and both variants' inner
/// `AggregateAndProof` derive `HashTreeRoot` under their own fork's bounds.
fn aggregate_and_proof_root(signed_aggregate: &SignedAggregateAndProof) -> Root {
    match signed_aggregate {
        SignedAggregateAndProof::Phase0(signed) => signed.message.hash_tree_root(),
        SignedAggregateAndProof::Electra(signed) => signed.message.hash_tree_root(),
    }
}

/// Whether `seen` already covers every bit `candidate` sets.
///
/// The specification's `is_non_strict_superset`, which is what makes a
/// committee's sixteen aggregators cost one verification rather than sixteen:
/// once the union of what has been seen for one `AttestationData` covers a
/// later aggregate, that aggregate can add no vote and is dropped before any
/// pairing.
///
/// A `candidate` longer than `seen` is not covered, whatever the overlap says:
/// the extra bits are positions `seen` has no opinion on.
pub fn is_non_strict_superset(seen: &[bool], candidate: &[bool]) -> bool {
    if candidate.len() > seen.len() {
        return false;
    }
    candidate
        .iter()
        .zip(seen.iter())
        .all(|(wanted, have)| !*wanted || *have)
}

/// How many aggregates one slot can carry at most, which is what sizes the
/// actor's per-slot expectations and the deferral queue's bound.
///
/// `MAX_COMMITTEES_PER_SLOT` committees each selecting
/// [`constants::TARGET_AGGREGATORS_PER_COMMITTEE`] aggregators. An upper
/// bound rather than a forecast: a chain with fewer active validators has
/// fewer committees per slot, and selection is probabilistic around the
/// target rather than exact.
pub const MAX_AGGREGATES_PER_SLOT: u64 =
    preset::MAX_COMMITTEES_PER_SLOT as u64 * constants::TARGET_AGGREGATORS_PER_COMMITTEE;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_superset_covers_what_it_contains() {
        // Everything the candidate wants is already held.
        assert!(is_non_strict_superset(
            &[true, true, true],
            &[true, false, true]
        ));
        // Equal sets are non-strict supersets of each other.
        assert!(is_non_strict_superset(
            &[true, false, true],
            &[true, false, true]
        ));
        // The empty candidate adds nothing to anything.
        assert!(is_non_strict_superset(&[false, false], &[false, false]));
    }

    #[test]
    fn a_candidate_with_a_new_bit_is_not_covered() {
        // Position 1 is new, so this aggregate carries a vote the seen union
        // does not have and must not be dropped.
        assert!(!is_non_strict_superset(
            &[true, false, true],
            &[true, true, false]
        ));
    }

    /// A longer candidate is never covered, however much of its prefix
    /// overlaps: the positions past the end are ones the seen union has no
    /// opinion about, and treating them as covered would drop real votes.
    #[test]
    fn a_longer_candidate_is_never_covered() {
        assert!(!is_non_strict_superset(&[true], &[true, true]));
        assert!(!is_non_strict_superset(&[true, true], &[true, true, false]));
    }

    /// Pinned per preset rather than against the definition, which would
    /// restate the arithmetic instead of checking it. This bound is what sizes
    /// the actor's deferral queue, so the number each preset actually produces
    /// is worth having written down.
    #[test]
    fn the_per_slot_bound_is_committees_times_aggregators() {
        #[cfg(not(feature = "preset-minimal"))]
        assert_eq!(MAX_AGGREGATES_PER_SLOT, 1024);
        #[cfg(feature = "preset-minimal")]
        assert_eq!(MAX_AGGREGATES_PER_SLOT, 64);
    }
}
