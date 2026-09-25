//! What is left of `beacon_aggregate_and_proof`'s validation, now that its
//! gossip conditions have moved to
//! `ethlambda_state_transition::beacon::gossip::aggregate` (validated in
//! `ethlambda-p2p`, off the chain actor) and
//! [`super::fork_choice::apply_verified_aggregate`] only applies what gossip
//! already accepted.
//!
//! Two pieces the actor's own applied-bits gate
//! (`ethlambda_blockchain::beacon_aggregates::AggregateGossip`) still needs:
//! [`is_non_strict_superset`], the same "does one committee's coverage already
//! include this aggregate's bits" test the spec's `Seen` uses, and
//! [`MAX_AGGREGATES_PER_SLOT`], which sizes that gate's deferral queue. Neither
//! reads a state or a store, so neither had a reason to move with the rest.

use crate::beacon::constants;
use crate::beacon::preset;

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
