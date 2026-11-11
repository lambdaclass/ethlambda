//! Gossip validation for EIP-8453's `head_vote` topic: one head vote
//! committee member's `HeadVoteMessage`.
//!
//! The rules are `validate_head_vote_gossip` and
//! `verify_head_vote_payload_status` (`specs/_features/eip8453/p2p-interface.md`),
//! split like the other topics': [`cheap_checks`] reads the message, the clock
//! and the seen set; [`stateful_checks`] reads the voted block, the head state
//! and the signature. On `Accept` the caller hands the message and the
//! committee [`stateful_checks`] read to
//! [`Eip8453Node::accept_head_vote`](crate::beacon::eip8453_node::Eip8453Node::accept_head_vote),
//! which applies it to the fork choice and marks it seen.
//!
//! Deliberate departures, shared with the other vote topics:
//!
//! - A voted block seen without a post-state is `IGNORE` where the
//!   specification rejects it: without a bad-block cache this node cannot tell
//!   a failed block from one still importing.
//! - The head state is advanced to the vote's epoch when it is older
//!   (`get_pulled_up_state`, which `on_head_vote_message` reads), so the
//!   committee and the domain are answerable across the fork's first epoch.

use super::{IgnoreReason, Outcome, RejectReason, is_current_slot};
use crate::beacon::bls;
use crate::beacon::constants::{
    DOMAIN_HEAD_VOTE, PAYLOAD_STATUS_EMPTY, PAYLOAD_STATUS_FULL, PAYLOAD_STATUS_PENDING,
};
use crate::beacon::containers::eip8453;
use crate::beacon::eip8453_fork_choice::{
    FinalizedDescent, head_state_at_epoch, head_vote_committee, is_finalized_ancestor,
};
use crate::beacon::eip8453_node::Eip8453Node;
use crate::beacon::fork_choice::{self, Store};
use crate::beacon::helpers::accessors::get_domain;
use crate::beacon::helpers::misc::{compute_epoch_at_slot, compute_signing_root};
use crate::beacon::primitives::{HashTreeRoot as _, ValidatorIndex};

/// The rules that read only the message, the clock, the config and the seen
/// set.
pub fn cheap_checks(
    node: &Eip8453Node,
    store: &Store,
    message: &eip8453::HeadVoteMessage,
    now_ms: u64,
) -> Result<(), Outcome> {
    let config = store.config();
    let data = &message.data;
    // [REJECT] The head vote's slot is at or after the EIP-8453 fork.
    if compute_epoch_at_slot(data.slot) < config.eip8453_fork_epoch {
        return Err(Outcome::Reject(RejectReason::PreForkSlot));
    }
    // [IGNORE] This is the first valid head vote from this validator for the
    // slot.
    if node.head_vote_seen(data.slot, message.validator_index) {
        return Err(Outcome::Ignore(IgnoreReason::AlreadySeen));
    }
    // [IGNORE] The head vote is for the current slot.
    if !is_current_slot(&config, data.slot, now_ms) {
        return Err(Outcome::Ignore(IgnoreReason::NotCurrentSlot));
    }
    Ok(())
}

/// The rules that need the voted block and the head state. Runs on a blocking
/// thread. On `Ok`, the slot's head vote committee (read from the head state)
/// for [`Eip8453Node::accept_head_vote`].
pub fn stateful_checks(
    node_is_verified: impl Fn(&crate::beacon::primitives::Root) -> bool,
    store: &Store,
    message: &eip8453::HeadVoteMessage,
) -> Result<Vec<ValidatorIndex>, Outcome> {
    let config = store.config();
    let data = &message.data;
    let block_root = data.beacon_block_root;
    // [IGNORE] The block being voted for has been seen.
    let Some((block_slot, _)) = store.block_entry(&block_root) else {
        return Err(Outcome::Ignore(IgnoreReason::UnknownBlock));
    };
    // [REJECT] The block being voted for passes validation (see the module
    // documentation).
    match store.has_state(&block_root) {
        Ok(true) => {}
        Ok(false) => return Err(Outcome::Ignore(IgnoreReason::StateUnavailable)),
        Err(_) => return Err(Outcome::Ignore(IgnoreReason::Internal)),
    }
    // [REJECT] The block being voted for is not from a later slot than the
    // head vote.
    if block_slot > data.slot {
        return Err(Outcome::Reject(RejectReason::VoteBeforeBlock));
    }
    let epoch = compute_epoch_at_slot(data.slot);
    let Some(state) = head_state_at_epoch(store, epoch, &config) else {
        return Err(Outcome::Ignore(IgnoreReason::StateUnavailable));
    };
    // [IGNORE] The finalized block is an ancestor of the block being voted
    // for.
    match is_finalized_ancestor(store, &state, block_root) {
        FinalizedDescent::Descends => {}
        FinalizedDescent::Conflicts => {
            return Err(Outcome::Ignore(IgnoreReason::FinalizedNotAncestor));
        }
        FinalizedDescent::Unknown => return Err(Outcome::Ignore(IgnoreReason::AncestryUnknown)),
    }
    // The payload status is consistent with the block being voted for.
    verify_head_vote_payload_status(&node_is_verified, store, data, block_slot)?;
    // [REJECT] The validator is a member of the head vote committee.
    let Ok(committee) = head_vote_committee(&state, data.slot, &config) else {
        return Err(Outcome::Ignore(IgnoreReason::StateUnavailable));
    };
    if !committee.contains(&message.validator_index) {
        return Err(Outcome::Reject(RejectReason::NotInCommittee));
    }
    // [REJECT] The signature is valid.
    let Ok(validator) = state.validator(message.validator_index) else {
        return Err(Outcome::Reject(RejectReason::UnknownValidator));
    };
    let domain = get_domain(&state, DOMAIN_HEAD_VOTE, Some(epoch));
    let signing_root = compute_signing_root(data.hash_tree_root(), domain);
    if !bls::verify(&validator.pubkey, signing_root, &message.signature) {
        return Err(Outcome::Reject(RejectReason::BadSignature));
    }
    Ok(committee)
}

/// `verify_head_vote_payload_status`: a vote for its own slot's block names
/// it `Pending`, a vote for an earlier block names a payload decision, and a
/// `Full` vote needs a verified, validated payload. `is_verified` answers
/// `is_payload_verified` (the fork choice engine's record of verified
/// payloads).
pub fn verify_head_vote_payload_status(
    is_verified: impl Fn(&crate::beacon::primitives::Root) -> bool,
    store: &Store,
    data: &eip8453::HeadVoteData,
    block_slot: u64,
) -> Result<(), Outcome> {
    let status = data.payload_status;
    // [REJECT] A vote for the block of its own slot has a pending payload
    // status.
    if block_slot == data.slot && status != PAYLOAD_STATUS_PENDING {
        return Err(Outcome::Reject(RejectReason::SameSlotPayloadFlag));
    }
    // [REJECT] A vote for an earlier block has an empty or full payload
    // status.
    let is_payload_decision = status == PAYLOAD_STATUS_EMPTY || status == PAYLOAD_STATUS_FULL;
    if block_slot < data.slot && !is_payload_decision {
        return Err(Outcome::Reject(RejectReason::PayloadStatusMismatch));
    }
    if status != PAYLOAD_STATUS_FULL {
        return Ok(());
    }
    // [IGNORE] The corresponding execution payload envelope has been seen
    // and verified.
    if !is_verified(&data.beacon_block_root) {
        return Err(Outcome::Ignore(IgnoreReason::PayloadEnvelopeUnseen));
    }
    let validation = fork_choice::block_payload_status(store, data.beacon_block_root);
    // [IGNORE] The voted execution payload is not optimistic.
    if validation.is_not_validated() {
        return Err(Outcome::Ignore(IgnoreReason::PayloadOptimistic));
    }
    // [REJECT] The voted execution payload is processed and invalid.
    if validation.is_invalidated() {
        return Err(Outcome::Reject(RejectReason::PayloadInvalid));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::eip8453_test_support::{Scene, scene};
    use crate::beacon::primitives::Root;

    fn data(slot: u64, root: Root, status: u8) -> eip8453::HeadVoteData {
        eip8453::HeadVoteData {
            slot,
            beacon_block_root: root,
            payload_status: status,
        }
    }

    /// Run both halves the way the p2p layer does.
    fn validate(
        scene: &Scene,
        message: &eip8453::HeadVoteMessage,
        now_ms: u64,
    ) -> Result<Vec<ValidatorIndex>, Outcome> {
        let guard = scene.node.lock();
        let node = guard.as_ref().expect("installed");
        cheap_checks(node, &scene.store, message, now_ms)?;
        let is_verified = |root: &Root| node.engine().is_payload_verified(root);
        stateful_checks(is_verified, &scene.store, message)
    }

    fn voter(scene: &Scene, slot: u64) -> ValidatorIndex {
        scene.committee(slot)[0]
    }

    #[test]
    fn a_committee_members_vote_is_accepted_once_and_reaches_the_fork_choice() {
        let scene = scene(16);
        let slot = scene.anchor_slot + 1;
        let now = scene.at(slot, 1_000);
        let validator = voter(&scene, slot);
        let message = scene.head_vote(
            validator,
            data(slot, scene.anchor_root, PAYLOAD_STATUS_EMPTY),
        );
        let committee = validate(&scene, &message, now).expect("accepted");
        assert_eq!(committee, scene.committee(slot));
        scene
            .node
            .with(|node| node.accept_head_vote(message.clone(), committee, now))
            .unwrap()
            .expect("applied");
        scene
            .node
            .with(|node| assert_eq!(node.engine().head_vote_messages(slot).len(), 1))
            .unwrap();
        assert_eq!(
            validate(&scene, &message, now),
            Err(Outcome::Ignore(IgnoreReason::AlreadySeen))
        );
    }

    #[test]
    fn the_cheap_rules_refuse_pre_fork_and_off_slot_votes() {
        let scene = scene(16);
        let slot = scene.anchor_slot + 1;
        let validator = voter(&scene, slot);
        let early = scene.head_vote(validator, data(1, scene.anchor_root, PAYLOAD_STATUS_EMPTY));
        assert_eq!(
            validate(&scene, &early, scene.at(slot, 0)),
            Err(Outcome::Reject(RejectReason::PreForkSlot))
        );
        let message = scene.head_vote(
            validator,
            data(slot, scene.anchor_root, PAYLOAD_STATUS_EMPTY),
        );
        assert_eq!(
            validate(&scene, &message, scene.at(slot + 3, 0)),
            Err(Outcome::Ignore(IgnoreReason::NotCurrentSlot))
        );
    }

    #[test]
    fn the_stateful_rules_judge_block_payload_committee_and_signature() {
        let scene = scene(16);
        let slot = scene.anchor_slot + 1;
        let now = scene.at(slot, 1_000);
        let validator = voter(&scene, slot);
        let unknown = scene.head_vote(
            validator,
            data(slot, Root::repeat_byte(9), PAYLOAD_STATUS_EMPTY),
        );
        assert_eq!(
            validate(&scene, &unknown, now),
            Err(Outcome::Ignore(IgnoreReason::UnknownBlock))
        );
        let pending = scene.head_vote(
            validator,
            data(slot, scene.anchor_root, PAYLOAD_STATUS_PENDING),
        );
        assert_eq!(
            validate(&scene, &pending, now),
            Err(Outcome::Reject(RejectReason::PayloadStatusMismatch))
        );
        let full = scene.head_vote(
            validator,
            data(slot, scene.anchor_root, PAYLOAD_STATUS_FULL),
        );
        assert_eq!(
            validate(&scene, &full, now),
            Err(Outcome::Ignore(IgnoreReason::PayloadEnvelopeUnseen))
        );
        let outsider = scene.head_vote(16, data(slot, scene.anchor_root, PAYLOAD_STATUS_EMPTY));
        assert_eq!(
            validate(&scene, &outsider, now),
            Err(Outcome::Reject(RejectReason::NotInCommittee))
        );
        let mut forged = scene.head_vote(
            validator,
            data(slot, scene.anchor_root, PAYLOAD_STATUS_EMPTY),
        );
        forged.signature = scene
            .head_vote(
                validator,
                data(slot, scene.anchor_root, PAYLOAD_STATUS_FULL),
            )
            .signature;
        assert_eq!(
            validate(&scene, &forged, now),
            Err(Outcome::Reject(RejectReason::BadSignature))
        );

        // The block-slot rules, past the clock rule: a vote for its own slot's
        // block names it pending, and no vote names a later block.
        let is_verified = |_: &Root| false;
        let same_slot = scene.head_vote(
            validator,
            data(scene.anchor_slot, scene.anchor_root, PAYLOAD_STATUS_EMPTY),
        );
        assert_eq!(
            stateful_checks(is_verified, &scene.store, &same_slot),
            Err(Outcome::Reject(RejectReason::SameSlotPayloadFlag))
        );
        let before = scene.head_vote(
            validator,
            data(
                scene.anchor_slot - 1,
                scene.anchor_root,
                PAYLOAD_STATUS_EMPTY,
            ),
        );
        assert_eq!(
            stateful_checks(is_verified, &scene.store, &before),
            Err(Outcome::Reject(RejectReason::VoteBeforeBlock))
        );
    }

    #[test]
    fn a_full_vote_needs_a_verified_validated_payload() {
        let scene = scene(16);
        let slot = scene.anchor_slot + 1;
        let validator = voter(&scene, slot);
        let full = scene.head_vote(
            validator,
            data(slot, scene.anchor_root, PAYLOAD_STATUS_FULL),
        );
        let verified = |_: &Root| true;
        // No verdict recorded reads as optimistic.
        assert_eq!(
            stateful_checks(verified, &scene.store, &full).map(|_| ()),
            Err(Outcome::Ignore(IgnoreReason::PayloadOptimistic))
        );
        let mut store = scene.store.clone();
        store.insert_beacon_block_payload_status(
            scene.anchor_root,
            scene.anchor_slot,
            crate::beacon::fork_choice::PayloadStatusEnum::Valid,
        );
        assert!(stateful_checks(verified, &store, &full).is_ok());
        store.insert_beacon_block_payload_status(
            scene.anchor_root,
            scene.anchor_slot,
            crate::beacon::fork_choice::PayloadStatusEnum::Invalid,
        );
        assert_eq!(
            stateful_checks(verified, &store, &full).map(|_| ()),
            Err(Outcome::Reject(RejectReason::PayloadInvalid))
        );
    }
}
