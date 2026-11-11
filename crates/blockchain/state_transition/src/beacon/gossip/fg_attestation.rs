//! Gossip validation for EIP-8453's `attestation_{subnet_id}` topics: one
//! validator's finality gadget attestation (`SingleAttestation`, modified).
//!
//! The rules are `validate_attestation_gossip`
//! (`specs/_features/eip8453/p2p-interface.md`), split like the other topics':
//! [`cheap_checks`] reads the message, the subnet, the clock and the seen set
//! and answers the round the attestation counts for; [`stateful_checks`] reads
//! the target block, the head state and the signature. On `Accept` the caller
//! hands the attestation and its round to
//! [`Eip8453Node::accept_attestation`](crate::beacon::eip8453_node::Eip8453Node::accept_attestation),
//! which pools it for proposals and marks it seen.
//!
//! FG attestations carry neither a slot nor a block root: an attestation
//! belongs to the latest slot of its committee that has started
//! (`get_latest_attestation_committee_slot`), which fixes its round.
//!
//! Departures, as for the head vote topic: a target seen without a post-state
//! is `IGNORE` (no bad-block cache), and the head state is advanced to the
//! attestation's epoch when older, so the domain is EIP-8453's in the fork's
//! first epoch.

use super::{IgnoreReason, Outcome, RejectReason};
use crate::beacon::bls;
use crate::beacon::config::Config;
use crate::beacon::constants::DOMAIN_FINALITY_ATTESTER;
use crate::beacon::containers::eip8453;
use crate::beacon::eip8453_fork_choice::{
    FinalizedDescent, get_latest_attestation_committee_slot, head_state_at_epoch,
    is_finalized_ancestor,
};
use crate::beacon::eip8453_node::{Eip8453Node, SharedEip8453Node};
use crate::beacon::fork_choice::Store;
use crate::beacon::helpers::accessors::get_domain;
use crate::beacon::helpers::eip8453::{
    compute_round_at_slot, get_attestation_committee, is_well_formed_attestation_data,
};
use crate::beacon::helpers::misc::{compute_epoch_at_slot, compute_signing_root};
use crate::beacon::preset;
use crate::beacon::primitives::{CommitteeIndex, HashTreeRoot as _};

/// `compute_subnet_for_attestation(committee_index)` (validator.md, modified):
/// the committee index modulo `ATTESTATION_SUBNET_COUNT`.
pub fn compute_subnet_for_attestation(config: &Config, committee_index: CommitteeIndex) -> u64 {
    committee_index % config.attestation_subnet_count.max(1)
}

/// The rules that read only the message, the subnet, the clock and the seen
/// set. On `Ok`, the round the attestation is cast in.
pub fn cheap_checks(
    node: &Eip8453Node,
    store: &Store,
    attestation: &eip8453::SingleAttestation,
    subnet_id: u64,
    now_ms: u64,
) -> Result<u64, Outcome> {
    let config = store.config();
    let committee_index = attestation.committee_index;
    // [REJECT] The committee index is within the expected range.
    if committee_index >= preset::ATTESTATION_COMMITTEES_PER_ROUND as u64 {
        return Err(Outcome::Reject(RejectReason::CommitteeIndex));
    }
    // [REJECT] The attestation is for the correct subnet.
    if compute_subnet_for_attestation(&config, committee_index) != subnet_id {
        return Err(Outcome::Reject(RejectReason::WrongSubnet));
    }
    let Ok(slot) = get_latest_attestation_committee_slot(&config, committee_index, now_ms) else {
        return Err(Outcome::Ignore(IgnoreReason::Internal));
    };
    let round = compute_round_at_slot(slot);
    // [IGNORE] No other valid attestation seen for this round and validator.
    if node.attestation_seen(round, attestation.attester_index) {
        return Err(Outcome::Ignore(IgnoreReason::AlreadySeen));
    }
    // [IGNORE] The attestation's epoch is the epoch of its committee's slot.
    if attestation.epoch != compute_epoch_at_slot(slot) {
        return Err(Outcome::Ignore(IgnoreReason::AttestationEpoch));
    }
    // [REJECT] The attestation data is well formed.
    if !is_well_formed_attestation_data(&attestation.data) {
        return Err(Outcome::Reject(RejectReason::MalformedAttestationData));
    }
    Ok(round)
}

/// A single attestation this node's own validator client submits: the gossip
/// rules for `subnet_id`, then, on `Accept`, pooled and marked seen exactly as
/// a gossip one is. The caller publishes it on `Accept`.
pub fn submit(
    store: &Store,
    node: &SharedEip8453Node,
    attestation: &eip8453::SingleAttestation,
    subnet_id: u64,
    now_ms: u64,
) -> Outcome {
    let round = match node.with(|n| cheap_checks(n, store, attestation, subnet_id, now_ms)) {
        Err(_) => return Outcome::Ignore(IgnoreReason::ForkChoiceInactive),
        Ok(Err(outcome)) => return outcome,
        Ok(Ok(round)) => round,
    };
    let outcome = stateful_checks(store, attestation);
    if outcome != Outcome::Accept {
        return outcome;
    }
    match node.with(|n| n.accept_attestation(attestation.clone(), round)) {
        Ok(true) => Outcome::Accept,
        Ok(false) => Outcome::Ignore(IgnoreReason::AlreadySeen),
        Err(_) => Outcome::Ignore(IgnoreReason::ForkChoiceInactive),
    }
}

/// The rules that need the target block and the head state. Runs on a
/// blocking thread.
pub fn stateful_checks(store: &Store, attestation: &eip8453::SingleAttestation) -> Outcome {
    let config = store.config();
    let target_root = attestation.data.target.root;
    // [IGNORE] The target block has been seen.
    if store.block_entry(&target_root).is_none() {
        return Outcome::Ignore(IgnoreReason::UnknownBlock);
    }
    // [REJECT] The target block passes validation (see the module
    // documentation).
    match store.has_state(&target_root) {
        Ok(true) => {}
        Ok(false) => return Outcome::Ignore(IgnoreReason::StateUnavailable),
        Err(_) => return Outcome::Ignore(IgnoreReason::Internal),
    }
    let Some(state) = head_state_at_epoch(store, attestation.epoch, &config) else {
        return Outcome::Ignore(IgnoreReason::StateUnavailable);
    };
    // [IGNORE] The finalized block is an ancestor of the target block.
    match is_finalized_ancestor(store, &state, target_root) {
        FinalizedDescent::Descends => {}
        FinalizedDescent::Conflicts => {
            return Outcome::Ignore(IgnoreReason::FinalizedNotAncestor);
        }
        FinalizedDescent::Unknown => return Outcome::Ignore(IgnoreReason::AncestryUnknown),
    }
    // [REJECT] The attester is a member of the committee.
    let Ok(committee) =
        get_attestation_committee(&state, attestation.epoch, attestation.committee_index)
    else {
        return Outcome::Ignore(IgnoreReason::StateUnavailable);
    };
    if !committee.contains(&attestation.attester_index) {
        return Outcome::Reject(RejectReason::NotInCommittee);
    }
    // [REJECT] The attestation signature is valid.
    let Ok(attester) = state.validator(attestation.attester_index) else {
        return Outcome::Reject(RejectReason::UnknownValidator);
    };
    let domain = get_domain(&state, DOMAIN_FINALITY_ATTESTER, Some(attestation.epoch));
    let signing_root = compute_signing_root(attestation.data.hash_tree_root(), domain);
    if !bls::verify(&attester.pubkey, signing_root, &attestation.signature) {
        return Outcome::Reject(RejectReason::BadSignature);
    }
    Outcome::Accept
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::eip8453_test_support::{Scene, scene};
    use crate::beacon::primitives::Root;

    fn data(target: Root) -> eip8453::AttestationData {
        eip8453::AttestationData {
            target: eip8453::HeightCheckpoint {
                height: 1,
                root: target,
            },
            timeout: false,
            finality: eip8453::HeightCheckpoint::empty(),
        }
    }

    fn validate(
        scene: &Scene,
        attestation: &eip8453::SingleAttestation,
        subnet: u64,
        now_ms: u64,
    ) -> Result<u64, Outcome> {
        let round = {
            let guard = scene.node.lock();
            cheap_checks(
                guard.as_ref().unwrap(),
                &scene.store,
                attestation,
                subnet,
                now_ms,
            )?
        };
        match stateful_checks(&scene.store, attestation) {
            Outcome::Accept => Ok(round),
            other => Err(other),
        }
    }

    #[test]
    fn a_committee_members_attestation_is_accepted_once_per_round() {
        let scene = scene(16);
        let slot = scene.anchor_slot;
        let now = scene.at(slot, 1_000);
        let (committee_index, members) = scene.attestation_committee_at(slot);
        let epoch = compute_epoch_at_slot(slot);
        let attestation =
            scene.attestation(members[0], committee_index, epoch, data(scene.anchor_root));
        let subnet = compute_subnet_for_attestation(&scene.config, committee_index);
        let round = validate(&scene, &attestation, subnet, now).expect("accepted");
        assert_eq!(round, compute_round_at_slot(slot));
        let accepted = scene
            .node
            .with(|node| node.accept_attestation(attestation.clone(), round))
            .unwrap();
        assert!(accepted);
        assert_eq!(
            validate(&scene, &attestation, subnet, now),
            Err(Outcome::Ignore(IgnoreReason::AlreadySeen))
        );
        scene
            .node
            .with(|node| assert_eq!(node.pooled_attestations(round).len(), 1))
            .unwrap();
    }

    #[test]
    fn a_submitted_attestation_is_judged_and_pooled_like_a_gossip_one() {
        let scene = scene(16);
        let slot = scene.anchor_slot;
        let now = scene.at(slot, 1_000);
        let (committee_index, members) = scene.attestation_committee_at(slot);
        let epoch = compute_epoch_at_slot(slot);
        let attestation =
            scene.attestation(members[0], committee_index, epoch, data(scene.anchor_root));
        let subnet = compute_subnet_for_attestation(&scene.config, committee_index);
        assert_eq!(
            submit(&scene.store, &scene.node, &attestation, subnet, now),
            Outcome::Accept
        );
        assert_eq!(
            submit(&scene.store, &scene.node, &attestation, subnet, now),
            Outcome::Ignore(IgnoreReason::AlreadySeen)
        );
    }

    #[test]
    fn the_rules_refuse_what_the_specification_refuses() {
        let scene = scene(16);
        let slot = scene.anchor_slot;
        let now = scene.at(slot, 1_000);
        let (committee_index, members) = scene.attestation_committee_at(slot);
        let epoch = compute_epoch_at_slot(slot);
        let subnet = compute_subnet_for_attestation(&scene.config, committee_index);
        let good = scene.attestation(members[0], committee_index, epoch, data(scene.anchor_root));

        let mut out_of_range = good.clone();
        out_of_range.committee_index = preset::ATTESTATION_COMMITTEES_PER_ROUND as u64;
        assert_eq!(
            validate(&scene, &out_of_range, subnet, now),
            Err(Outcome::Reject(RejectReason::CommitteeIndex))
        );
        assert_eq!(
            validate(&scene, &good, subnet + 1, now),
            Err(Outcome::Reject(RejectReason::WrongSubnet))
        );
        let mut wrong_epoch = good.clone();
        wrong_epoch.epoch = epoch + 1;
        assert_eq!(
            validate(&scene, &wrong_epoch, subnet, now),
            Err(Outcome::Ignore(IgnoreReason::AttestationEpoch))
        );
        let mut malformed = good.clone();
        malformed.data.target.height = 0;
        assert_eq!(
            validate(&scene, &malformed, subnet, now),
            Err(Outcome::Reject(RejectReason::MalformedAttestationData))
        );
        let unknown = scene.attestation(
            members[0],
            committee_index,
            epoch,
            data(Root::repeat_byte(5)),
        );
        assert_eq!(
            validate(&scene, &unknown, subnet, now),
            Err(Outcome::Ignore(IgnoreReason::UnknownBlock))
        );
        let outsider = scene.attestation(16, committee_index, epoch, data(scene.anchor_root));
        assert_eq!(
            validate(&scene, &outsider, subnet, now),
            Err(Outcome::Reject(RejectReason::NotInCommittee))
        );
        let mut forged = good.clone();
        forged.data.timeout = true;
        assert_eq!(
            validate(&scene, &forged, subnet, now),
            Err(Outcome::Reject(RejectReason::BadSignature))
        );
    }
}
