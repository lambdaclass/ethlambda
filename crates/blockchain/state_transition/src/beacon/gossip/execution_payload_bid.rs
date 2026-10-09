//! Gossip validation for the gloas `execution_payload_bid` topic: a builder's
//! `SignedExecutionPayloadBid`, the commitment a proposer may choose in place
//! of building its own payload.
//!
//! The rules are the specification's `validate_execution_payload_bid_gossip`
//! (`specs/gloas/p2p-interface.md`), split like [`super::envelope`]:
//! [`cheap_checks`] reads only the message, the market's seen state and the
//! clock, so the p2p actor runs it inline; [`stateful_checks`] reads cached
//! states and verifies the signature, so it runs on a blocking thread. The
//! caller records the bid in the [`BuilderMarket`] on `Accept`.
//!
//! Deliberate departures from the specification (`docs/spec_deviations.md`):
//!
//! - Never queues. Every "MAY be queued" is IGNORE, and a state that is not
//!   cached is IGNORE rather than rebuilt from disk, so a verdict gossipsub
//!   waits on is never stalled by a replay.
//! - `store.block_states[parent]` advanced with `process_slots` to `bid.slot`
//!   becomes the parent's cached post-state when the bid is in the parent's
//!   own epoch (gloas's `process_slot` touches none of the fields rules 17 to
//!   22 read), and the cached checkpoint state of the bid's epoch otherwise.
//! - `get_head(store)` is the head the chain actor recorded, with a fresh walk
//!   only when none is recorded.
//! - `seen.execution_payloads` is the market's known payloads: envelopes gossip
//!   accepted or this node published, plus a pre-gloas parent's own payload.

use std::sync::Arc;

use ethlambda_storage::CacheKey;

use super::{
    IgnoreReason, Outcome, RejectReason, is_current_slot, is_gloas_slot,
    proposer_preferences::dependent_root_at,
};
use crate::beacon::builder_market::{BuilderMarket, KnownPayload};
use crate::beacon::config::Config;
use crate::beacon::constants::PAYLOAD_BUILDER_VERSION;
use crate::beacon::containers::{BeaconState, SignedBeaconBlock, gloas};
use crate::beacon::fork_choice::{self, ForkChoiceNode, PayloadStatus, Store};
use crate::beacon::helpers::accessors::{get_current_epoch, get_randao_mix};
use crate::beacon::helpers::gloas::{can_builder_cover_bid, is_active_builder};
use crate::beacon::helpers::misc::{compute_epoch_at_slot, compute_start_slot_at_epoch};
use crate::beacon::inclusion_list::get_inclusion_list_committee;
use crate::beacon::lean_boundary::lean_state_unreachable;
use crate::beacon::preset;
use crate::beacon::primitives::{Epoch, ExecutionBlockHash, Root, Slot};
use crate::beacon::stf;
use crate::beacon::stf::gloas::verify_execution_payload_bid_signature;

/// Gloas p2p preset: the largest decompressed `SignedExecutionPayloadBid`.
pub const MAX_SIGNED_EXECUTION_PAYLOAD_BID_SIZE: usize = 196_932;

/// Heze p2p preset: the largest decompressed heze `SignedExecutionPayloadBid`,
/// two bytes of `inclusion_list_bits` past gloas's. The bound a bid topic
/// checks, since one container carries both shapes and [`cheap_checks`]
/// rejects the one the bid's slot does not take.
pub const MAX_SIGNED_EXECUTION_PAYLOAD_BID_SIZE_HEZE: usize = 196_934;

/// The spec's `is_gas_limit_target_compatible`: whether `gas_limit` is what
/// the EIP-1559 transition rule from `parent_gas_limit` allows when steering
/// towards `target_gas_limit`.
pub fn is_gas_limit_target_compatible(
    parent_gas_limit: u64,
    gas_limit: u64,
    target_gas_limit: u64,
) -> bool {
    let max_difference = (parent_gas_limit / 1024).saturating_sub(1);
    let min_gas_limit = parent_gas_limit - max_difference;
    let max_gas_limit = parent_gas_limit.saturating_add(max_difference);
    if target_gas_limit < min_gas_limit {
        return gas_limit == min_gas_limit;
    }
    if target_gas_limit > max_gas_limit {
        return gas_limit == max_gas_limit;
    }
    gas_limit == target_gas_limit
}

/// The spec's `is_current_or_next_slot`.
pub(crate) fn is_current_or_next_slot(config: &Config, slot: Slot, now_ms: u64) -> bool {
    is_current_slot(config, slot, now_ms)
        || slot
            .checked_sub(1)
            .is_some_and(|previous| is_current_slot(config, previous, now_ms))
}

/// The rules that read only the message, the market's seen state and the
/// clock.
pub fn cheap_checks(
    market: &BuilderMarket,
    store: &Store,
    signed: &gloas::SignedExecutionPayloadBid,
    now_ms: u64,
) -> Result<(), Outcome> {
    let bid = &signed.message;
    let config = store.config();
    // [IGNORE] The first bid for this slot, parent and builder, and [IGNORE]
    // the highest value seen for the slot and parent.
    market.check_bid_seen(bid).map_err(Outcome::Ignore)?;
    // [IGNORE] The bid's slot is the current slot or the next slot.
    if !is_current_or_next_slot(&config, bid.slot, now_ms) {
        return Err(Outcome::Ignore(IgnoreReason::NotCurrentOrNextSlot));
    }
    // [REJECT] The bid's execution payment is zero.
    if bid.execution_payment != 0 {
        return Err(Outcome::Reject(RejectReason::ExecutionPaymentNonZero));
    }
    // [REJECT] The bid's block hash is not its parent block hash.
    if bid.block_hash == bid.parent_block_hash {
        return Err(Outcome::Reject(RejectReason::BlockHashEqualsParent));
    }
    // [REJECT] The commitment count is within the epoch's blob limit.
    let proposal_epoch = compute_epoch_at_slot(bid.slot);
    if bid.blob_kzg_commitments.len() as u64 > config.max_blobs_per_block(proposal_epoch) {
        return Err(Outcome::Reject(RejectReason::TooManyBlobs));
    }
    // Ours: a slot before the fork has no bids. Placed after the rejects so
    // a malformed message is still penalized, whichever fork it names.
    if !is_gloas_slot(&config, bid.slot) {
        return Err(Outcome::Ignore(IgnoreReason::PreGloasSlot));
    }
    // Ours: gloas and heze bids share one container, so a decode accepts
    // either shape (see `gloas::ExecutionPayloadBid`); the specification's
    // typed decoder rejects the shape the bid's slot does not take.
    if bid.fork_name() != config.fork_at_epoch(proposal_epoch) {
        return Err(Outcome::Reject(RejectReason::WrongForkShape));
    }
    Ok(())
}

/// A pre-gloas state's execution payload header, as far as a bid needs it:
/// `(block_hash, gas_limit)`. `None` for a state with no payload header.
fn pre_gloas_payload(state: &BeaconState) -> Option<(ExecutionBlockHash, u64)> {
    match state {
        BeaconState::Bellatrix(s) => {
            let header = &s.latest_execution_payload_header;
            Some((header.block_hash, header.gas_limit))
        }
        BeaconState::Capella(s) => {
            let header = &s.latest_execution_payload_header;
            Some((header.block_hash, header.gas_limit))
        }
        BeaconState::Deneb(s) => {
            let header = &s.latest_execution_payload_header;
            Some((header.block_hash, header.gas_limit))
        }
        BeaconState::Electra(s) => {
            let header = &s.latest_execution_payload_header;
            Some((header.block_hash, header.gas_limit))
        }
        BeaconState::Fulu(s) => {
            let header = &s.latest_execution_payload_header;
            Some((header.block_hash, header.gas_limit))
        }
        BeaconState::Phase0(_) | BeaconState::Altair(_) | BeaconState::Gloas(_) => None,
        BeaconState::Lean(_) => lean_state_unreachable("execution_payload_bid::pre_gloas_payload"),
    }
}

/// The head's payload-relevant facts, off whichever source answers.
enum HeadView {
    Gloas {
        node: ForkChoiceNode,
        parent_root: Root,
        bid_parent_hash: ExecutionBlockHash,
        bid_block_hash: ExecutionBlockHash,
    },
    PreGloas {
        root: Root,
        block_hash: ExecutionBlockHash,
    },
}

/// The head, from the chain actor's record (a fresh walk only when no status
/// is recorded), and its payload hashes from the cached post-state (the
/// decoded block when that is not cached).
fn head_view(store: &Store) -> Result<HeadView, Outcome> {
    let config = store.config();
    let internal = || Outcome::Ignore(IgnoreReason::Internal);
    let node = match (store.head().ok(), store.head_payload_status()) {
        (Some(root), Some(payload_status)) => ForkChoiceNode {
            root,
            payload_status,
        },
        _ => fork_choice::get_head_node(store, &config).map_err(|_| internal())?,
    };
    if let Some(state) = store.cached_state(CacheKey::BlockState(node.root)) {
        return match &*state {
            BeaconState::Gloas(inner) => Ok(HeadView::Gloas {
                node,
                parent_root: inner.latest_block_header.parent_root,
                bid_parent_hash: inner.latest_execution_payload_bid.parent_block_hash,
                bid_block_hash: inner.latest_execution_payload_bid.block_hash,
            }),
            other => match pre_gloas_payload(other) {
                Some((block_hash, _)) => Ok(HeadView::PreGloas {
                    root: node.root,
                    block_hash,
                }),
                None => Err(Outcome::Ignore(IgnoreReason::NotOnHeadBranch)),
            },
        };
    }
    let block = store
        .get_signed_block(&node.root)
        .map_err(|_| internal())?
        .ok_or(Outcome::Ignore(IgnoreReason::StateUnavailable))?;
    match block {
        SignedBeaconBlock::Gloas(block) => {
            let bid = &block.message.body.signed_execution_payload_bid.message;
            Ok(HeadView::Gloas {
                node,
                parent_root: block.message.parent_root,
                bid_parent_hash: bid.parent_block_hash,
                bid_block_hash: bid.block_hash,
            })
        }
        other => match other.execution_block_hash() {
            Some(block_hash) => Ok(HeadView::PreGloas {
                root: node.root,
                block_hash,
            }),
            None => Err(Outcome::Ignore(IgnoreReason::NotOnHeadBranch)),
        },
    }
}

/// The spec's `is_bid_compatible_with_head`, against the recorded head.
///
/// A pre-gloas head has no bid, so a bid is compatible when it builds on that
/// head and its payload (the boundary rule: pre-gloas parent payloads count as
/// full).
pub fn is_bid_compatible_with_head(
    store: &Store,
    bid: &gloas::ExecutionPayloadBid,
) -> Result<bool, Outcome> {
    match head_view(store)? {
        HeadView::PreGloas { root, block_hash } => {
            Ok(bid.parent_block_root == root && bid.parent_block_hash == block_hash)
        }
        HeadView::Gloas {
            node,
            parent_root,
            bid_parent_hash,
            bid_block_hash,
        } => {
            let builds_on_parent_block = bid.parent_block_root == parent_root;
            let builds_on_parent_payload = bid.parent_block_hash == bid_parent_hash;
            if builds_on_parent_block && builds_on_parent_payload {
                return Ok(true);
            }
            if bid.parent_block_root != node.root {
                return Ok(false);
            }
            let builds_on_head_payload = bid.parent_block_hash == bid_block_hash;
            // The head's status can only be PENDING if a caller recorded a
            // walk's intermediate node, which `get_head_node` never returns.
            debug_assert_ne!(node.payload_status, PayloadStatus::Pending);
            let build_on_full = fork_choice::should_build_on_full(store, node, bid.slot)
                .map_err(|_| Outcome::Ignore(IgnoreReason::Internal))?;
            Ok(if build_on_full {
                builds_on_head_payload
            } else {
                builds_on_parent_payload
            })
        }
    }
}

/// Cached-only: a `CheckpointState{epoch, root}` hit; else the cached
/// `BlockState(root)` advanced to the epoch start and cached. `None` = miss.
///
/// The rebuild-from-disk `fork_choice::checkpoint_state` does on a miss would
/// stall a gossip verdict, so a state that is not cached is a miss here.
pub(crate) fn cached_checkpoint_state(
    store: &Store,
    epoch: Epoch,
    root: Root,
) -> Option<Arc<BeaconState>> {
    let key = CacheKey::CheckpointState { epoch, root };
    if let Some(state) = store.cached_state(key) {
        return Some(state);
    }
    let state = store.cached_state(CacheKey::BlockState(root))?;
    let target_slot = compute_start_slot_at_epoch(epoch);
    let state = if state.slot() < target_slot {
        let mut advanced = (*state).clone();
        stf::process_slots(&mut advanced, target_slot, &store.config()).ok()?;
        Arc::new(advanced)
    } else {
        state
    };
    store.cache_state(key, state.clone());
    Some(state)
}

/// The exits a parent payload carried, for rule 21: the market's known payload
/// when it is the parent block's own, else the verified envelope in the store.
/// `None` when neither is available.
fn parent_payload_exits(
    store: &Store,
    market: &BuilderMarket,
    bid: &gloas::ExecutionPayloadBid,
) -> Option<
    Vec<(
        crate::beacon::primitives::BlsPubkey,
        crate::beacon::primitives::ExecutionAddress,
    )>,
> {
    if let Some(KnownPayload {
        beacon_block_root,
        builder_exits,
        ..
    }) = market.known_payload(bid.parent_block_hash)
        && beacon_block_root == bid.parent_block_root
    {
        return Some(builder_exits);
    }
    let envelope = store
        .get_execution_payload_envelope(&bid.parent_block_root)
        .ok()??;
    Some(
        envelope
            .message
            .execution_requests
            .builder_exits
            .iter()
            .map(|exit| (exit.pubkey, exit.source_address))
            .collect(),
    )
}

/// The rules that need states, then the signature. Runs on a blocking thread.
pub fn stateful_checks(
    store: &Store,
    market: &BuilderMarket,
    signed: &gloas::SignedExecutionPayloadBid,
) -> Outcome {
    match stateful_rules(store, market, signed) {
        Ok(()) => Outcome::Accept,
        Err(outcome) => outcome,
    }
}

fn stateful_rules(
    store: &Store,
    market: &BuilderMarket,
    signed: &gloas::SignedExecutionPayloadBid,
) -> Result<(), Outcome> {
    let bid = &signed.message;
    let ignore = |reason| Outcome::Ignore(reason);
    let reject = |reason| Outcome::Reject(reason);
    let proposal_epoch = compute_epoch_at_slot(bid.slot);

    // [IGNORE] The parent block is known (never queued).
    if !store.has_block(&bid.parent_block_root) {
        return Err(ignore(IgnoreReason::UnknownBlock));
    }
    // [REJECT] The bid is for a higher slot than its parent.
    let (parent_slot, _) = store
        .block_entry(&bid.parent_block_root)
        .ok_or(ignore(IgnoreReason::UnknownBlock))?;
    if bid.slot <= parent_slot {
        return Err(reject(RejectReason::NotAfterParent));
    }
    // [IGNORE] The parent has been imported (its post-state is cached).
    let parent_state = store
        .cached_state(CacheKey::BlockState(bid.parent_block_root))
        .ok_or(ignore(IgnoreReason::StateUnavailable))?;
    // [IGNORE] The bid's slot is within the parent's proposer lookahead.
    if proposal_epoch > get_current_epoch(&parent_state) + preset::MIN_SEED_LOOKAHEAD {
        return Err(ignore(IgnoreReason::BeyondLookahead));
    }
    // [IGNORE] The matching proposer preferences have been seen. Rule 10
    // keeps the dependent slot inside the parent state's `block_roots`.
    let dependent_root = dependent_root_at(&parent_state, bid.parent_block_root, bid.slot)
        .ok_or(ignore(IgnoreReason::AncestryUnknown))?;
    let preferences = market
        .preferences(bid.slot, dependent_root)
        .ok_or(ignore(IgnoreReason::PreferencesUnseen))?
        .message;
    // [IGNORE] The fee recipient matches the proposer's preference.
    if bid.fee_recipient != preferences.fee_recipient {
        return Err(ignore(IgnoreReason::FeeRecipientMismatch));
    }
    // [IGNORE] The parent block hash is a known execution payload. Across the
    // fork boundary, a pre-gloas parent's own payload counts.
    let parent_gas_limit = match market.known_payload(bid.parent_block_hash) {
        Some(known) => known.gas_limit,
        None => match pre_gloas_payload(&parent_state) {
            Some((block_hash, gas_limit)) if block_hash == bid.parent_block_hash => gas_limit,
            _ => return Err(ignore(IgnoreReason::ParentPayloadUnknown)),
        },
    };
    // [IGNORE] The gas limit is compatible with the proposer's target.
    if !is_gas_limit_target_compatible(
        parent_gas_limit,
        bid.gas_limit,
        preferences.target_gas_limit,
    ) {
        return Err(ignore(IgnoreReason::GasLimitIncompatible));
    }
    // [IGNORE] The bid is compatible with the head branch.
    if !is_bid_compatible_with_head(store, bid)? {
        return Err(ignore(IgnoreReason::NotOnHeadBranch));
    }
    // [REJECT] The previous randao is the parent state's.
    if bid.prev_randao != get_randao_mix(&parent_state, get_current_epoch(&parent_state)) {
        return Err(reject(RejectReason::PrevRandao));
    }

    // The parent state advanced to the bid's slot. Within the parent's own
    // epoch the parent state answers identically, see the module docs.
    let state = if proposal_epoch == get_current_epoch(&parent_state) {
        parent_state.clone()
    } else {
        cached_checkpoint_state(store, proposal_epoch, bid.parent_block_root)
            .ok_or(ignore(IgnoreReason::StateUnavailable))?
    };
    let BeaconState::Gloas(inner) = &*state else {
        // A bid in a gloas epoch is advanced into gloas by the epoch
        // transition; anything else is a state this cannot judge.
        return Err(ignore(IgnoreReason::StateUnavailable));
    };

    // [REJECT] The builder index is valid, [REJECT] it is a payload builder
    // and [REJECT] active.
    let builder = inner
        .builders
        .get(bid.builder_index as usize)
        .ok_or(reject(RejectReason::UnknownBuilder))?;
    if builder.version != PAYLOAD_BUILDER_VERSION {
        return Err(reject(RejectReason::NotPayloadBuilder));
    }
    if !is_active_builder(inner, bid.builder_index).unwrap_or(false) {
        return Err(reject(RejectReason::InactiveBuilder));
    }
    // [IGNORE] The builder can cover the bid.
    if !can_builder_cover_bid(inner, bid.builder_index, bid.value).unwrap_or(false) {
        return Err(ignore(IgnoreReason::BuilderCannotCover));
    }
    // [IGNORE] The parent's payload does not try to exit the builder. Only a
    // gloas parent has an envelope to carry the request.
    let parent_is_gloas = matches!(&*parent_state, BeaconState::Gloas(_));
    if parent_is_gloas && bid.parent_block_hash == inner.latest_execution_payload_bid.block_hash {
        let exits = parent_payload_exits(store, market, bid)
            .ok_or(ignore(IgnoreReason::ParentPayloadUnverified))?;
        if exits.iter().any(|(pubkey, source)| {
            *pubkey == builder.pubkey && *source == builder.execution_address
        }) {
            return Err(ignore(IgnoreReason::BuilderMayExit));
        }
    }
    // [IGNORE] The bid's inclusion list bits are inclusive of every timely
    // list this node holds for the previous slot (heze). A gloas bid has
    // none to check.
    if let Some(inclusion_list_bits) = &bid.inclusion_list_bits {
        let inclusion_list_slot = bid.slot - 1;
        let dependent_root =
            dependent_root_at(&parent_state, bid.parent_block_root, inclusion_list_slot)
                .ok_or(ignore(IgnoreReason::AncestryUnknown))?;
        let committee =
            get_inclusion_list_committee(&state, inclusion_list_slot, &*store.committee_cache())
                .map_err(|_| ignore(IgnoreReason::StateUnavailable))?;
        if !store.inclusion_list_store().is_bits_inclusive(
            &committee,
            inclusion_list_slot,
            dependent_root,
            inclusion_list_bits,
            true,
        ) {
            return Err(ignore(IgnoreReason::InclusionListBitsNotInclusive));
        }
    }
    // [REJECT] The signature is valid. An error (an index the state lacks)
    // is a signature that cannot be.
    if !matches!(
        verify_execution_payload_bid_signature(&state, signed),
        Ok(true)
    ) {
        return Err(reject(RejectReason::BadSignature));
    }
    Ok(())
}

/// Both halves. The caller records the bid on `Accept`: the specification's
/// `validate_execution_payload_bid_gossip`.
pub fn validate(
    market: &BuilderMarket,
    store: &Store,
    signed: &gloas::SignedExecutionPayloadBid,
    now_ms: u64,
) -> Outcome {
    if let Err(outcome) = cheap_checks(market, store, signed, now_ms) {
        return outcome;
    }
    stateful_checks(store, market, signed)
}

#[cfg(test)]
mod tests {
    use ethlambda_types::beacon::primitives::{
        BlsPubkey, Bytes32, ExecutionAddress, KzgCommitment,
    };

    use super::*;
    use crate::beacon::builder_market::test_support::{
        builder_secret, envelope_with_gas_limit, sign_preferences,
    };
    use crate::beacon::gossip::proposer_preferences::dependent_root_at;
    use crate::beacon::gossip::test_support::builder_scene::*;
    use crate::beacon::gossip::test_support::{slot_start_ms, store};
    use crate::beacon::helpers::accessors::get_current_epoch;
    use crate::beacon::precheck::fixed_proposer;

    fn ignore(reason: IgnoreReason) -> Outcome {
        Outcome::Ignore(reason)
    }

    fn reject(reason: RejectReason) -> Outcome {
        Outcome::Reject(reason)
    }

    /// `stateful_checks` on the scene's market and store.
    fn stateful(scene: &Scene, bid: &gloas::SignedExecutionPayloadBid) -> Outcome {
        stateful_checks(&scene.store, &scene.market, bid)
    }

    fn builder_pubkey() -> BlsPubkey {
        BlsPubkey(builder_secret(0).sk_to_pk().to_bytes())
    }

    #[test]
    fn the_scenes_bid_is_accepted() {
        let scene = scene();
        let outcome = validate(&scene.market, &scene.store, &scene.bid, scene.now_ms());
        assert_eq!(outcome, Outcome::Accept);
    }

    // ---- is_gas_limit_target_compatible ----

    #[test]
    fn a_gas_limit_may_step_towards_a_nearby_target() {
        let parent = 60_000_000;
        // max_difference = 60_000_000 / 1024 - 1 = 58_592.
        assert!(is_gas_limit_target_compatible(
            parent,
            parent + 100,
            parent + 100
        ));
        assert!(is_gas_limit_target_compatible(
            parent,
            parent - 10,
            parent - 10
        ));
        assert!(is_gas_limit_target_compatible(parent, parent, parent));
        assert!(!is_gas_limit_target_compatible(
            parent,
            parent + 99,
            parent + 100
        ));
    }

    #[test]
    fn a_gas_limit_is_pinned_to_the_step_limit_beyond_it() {
        let parent = 60_000_000;
        assert!(is_gas_limit_target_compatible(
            parent,
            parent + 58_592,
            100_000_000
        ));
        assert!(!is_gas_limit_target_compatible(
            parent,
            parent + 58_593,
            100_000_000
        ));
        assert!(!is_gas_limit_target_compatible(
            parent,
            parent + 58_591,
            100_000_000
        ));
        assert!(is_gas_limit_target_compatible(
            parent,
            parent - 58_592,
            30_000_000
        ));
        assert!(!is_gas_limit_target_compatible(
            parent,
            parent - 58_593,
            30_000_000
        ));
        // The edge itself: a target exactly at the limit is no longer beyond it.
        assert!(is_gas_limit_target_compatible(
            parent,
            parent + 58_592,
            parent + 58_592
        ));
    }

    #[test]
    fn a_small_parent_cannot_move() {
        // 1023 / 1024 = 0, so the allowed difference saturates to zero.
        assert!(is_gas_limit_target_compatible(1023, 1023, 5_000));
        assert!(!is_gas_limit_target_compatible(1023, 1024, 5_000));
        assert!(is_gas_limit_target_compatible(0, 0, 100));
    }

    #[test]
    fn the_step_limit_saturates_near_the_top_of_the_range() {
        let parent = u64::MAX - 5;
        assert!(is_gas_limit_target_compatible(parent, u64::MAX, u64::MAX));
        assert!(is_gas_limit_target_compatible(parent, parent, parent));
    }

    // ---- the clock ----

    #[test]
    fn a_bid_is_timely_from_just_before_the_previous_slot_until_just_after_its_own() {
        let store = store(0);
        let config = store.config();
        let slot = 34;
        let earliest = slot_start_ms(&store, slot - 1) - 500;
        let latest = slot_start_ms(&store, slot + 1) + 500;
        assert!(is_current_or_next_slot(&config, slot, earliest));
        assert!(!is_current_or_next_slot(&config, slot, earliest - 1));
        assert!(is_current_or_next_slot(&config, slot, latest));
        assert!(!is_current_or_next_slot(&config, slot, latest + 1));
        // Slot zero has no previous slot.
        assert!(is_current_or_next_slot(
            &config,
            0,
            slot_start_ms(&store, 0)
        ));
    }

    // ---- cheap rules ----

    fn cheap(scene: &Scene, bid: &gloas::SignedExecutionPayloadBid) -> Result<(), Outcome> {
        cheap_checks(&scene.market, &scene.store, bid, scene.now_ms())
    }

    #[test]
    fn a_builders_second_bid_for_a_parent_is_already_seen() {
        let scene = scene();
        assert!(scene.market.record_bid(scene.bid.clone()));
        assert_eq!(
            cheap(&scene, &scene.signed(|bid| bid.value = 9)),
            Err(ignore(IgnoreReason::AlreadySeen))
        );
    }

    #[test]
    fn a_bid_that_does_not_beat_the_best_is_not_highest() {
        let scene = scene();
        let mut other = scene.bid.clone();
        other.message.builder_index = 1;
        other.message.value = 5;
        assert!(scene.market.record_bid(other));
        assert_eq!(
            cheap(&scene, &scene.bid),
            Err(ignore(IgnoreReason::NotHighestBid))
        );
        assert_eq!(
            cheap(&scene, &scene.signed(|bid| bid.value = 5)),
            Err(ignore(IgnoreReason::NotHighestBid))
        );
    }

    #[test]
    fn a_bid_for_a_distant_slot_is_not_current_or_next() {
        let scene = scene();
        let far = scene.signed(|bid| bid.slot = 40);
        assert_eq!(
            cheap(&scene, &far),
            Err(ignore(IgnoreReason::NotCurrentOrNextSlot))
        );
    }

    #[test]
    fn a_bid_with_an_execution_payment_is_rejected() {
        let scene = scene();
        let paid = scene.signed(|bid| bid.execution_payment = 1);
        assert_eq!(
            cheap(&scene, &paid),
            Err(reject(RejectReason::ExecutionPaymentNonZero))
        );
    }

    #[test]
    fn a_bid_whose_block_hash_is_its_parents_is_rejected() {
        let scene = scene();
        let same = scene.signed(|bid| bid.block_hash = bid.parent_block_hash);
        assert_eq!(
            cheap(&scene, &same),
            Err(reject(RejectReason::BlockHashEqualsParent))
        );
    }

    #[test]
    fn a_bid_with_too_many_commitments_is_rejected() {
        let scene = scene();
        let limit = scene.store.config().max_blobs_per_block(1) as usize;
        let at_limit = scene.signed(|bid| {
            bid.blob_kzg_commitments = vec![KzgCommitment([0; 48]); limit].into();
        });
        assert_eq!(cheap(&scene, &at_limit), Ok(()));
        let over = scene.signed(|bid| {
            bid.blob_kzg_commitments = vec![KzgCommitment([0; 48]); limit + 1].into();
        });
        assert_eq!(
            cheap(&scene, &over),
            Err(reject(RejectReason::TooManyBlobs))
        );
    }

    #[test]
    fn a_bid_before_the_fork_is_ignored() {
        // A fulu-only store has no gloas slot at all.
        let fulu = store(0);
        let scene = scene();
        let now_ms = slot_start_ms(&fulu, BID_SLOT) + 100;
        assert_eq!(
            cheap_checks(&scene.market, &fulu, &scene.signed(|_| {}), now_ms),
            Err(ignore(IgnoreReason::PreGloasSlot))
        );
    }

    // ---- stateful rules ----

    #[test]
    fn a_bid_on_an_unknown_parent_is_ignored() {
        let scene = scene();
        let bid = scene.signed(|bid| bid.parent_block_root = Root::repeat_byte(9));
        assert_eq!(stateful(&scene, &bid), ignore(IgnoreReason::UnknownBlock));
    }

    #[test]
    fn a_bid_not_after_its_parent_is_rejected() {
        let scene = scene();
        let bid = scene.signed(|bid| bid.slot = 32);
        assert_eq!(stateful(&scene, &bid), reject(RejectReason::NotAfterParent));
    }

    #[test]
    fn a_parent_without_a_cached_state_is_ignored() {
        let mut scene = scene();
        let stateless = Root::repeat_byte(0x60);
        scene
            .store
            .insert_pending_block(stateless, block_at(10))
            .expect("insert the block");
        let bid = scene.signed(|bid| bid.parent_block_root = stateless);
        assert_eq!(
            stateful(&scene, &bid),
            ignore(IgnoreReason::StateUnavailable)
        );
    }

    #[test]
    fn a_bid_beyond_the_parents_lookahead_is_ignored() {
        let scene = scene();
        // The parent is in epoch 1, so epoch 3 is past its lookahead.
        let bid = scene.signed(|bid| bid.slot = 96);
        assert_eq!(
            stateful(&scene, &bid),
            ignore(IgnoreReason::BeyondLookahead)
        );
    }

    #[test]
    fn a_bid_without_preferences_is_ignored() {
        let scene = scene();
        let empty = BuilderMarket::default();
        assert_eq!(
            stateful_checks(&scene.store, &empty, &scene.bid),
            ignore(IgnoreReason::PreferencesUnseen)
        );
    }

    #[test]
    fn a_bid_for_another_fee_recipient_is_ignored() {
        let scene = scene();
        let bid = scene.signed(|bid| bid.fee_recipient = ExecutionAddress::repeat_byte(0x99));
        assert_eq!(
            stateful(&scene, &bid),
            ignore(IgnoreReason::FeeRecipientMismatch)
        );
    }

    #[test]
    fn a_bid_on_an_unknown_payload_is_ignored() {
        let scene = scene();
        let bid = scene.signed(|bid| bid.parent_block_hash = ExecutionBlockHash::repeat_byte(0x77));
        assert_eq!(
            stateful(&scene, &bid),
            ignore(IgnoreReason::ParentPayloadUnknown)
        );
    }

    #[test]
    fn a_gas_limit_the_target_cannot_reach_is_ignored() {
        let scene = scene();
        let bid = scene.signed(|bid| bid.gas_limit = PARENT_GAS_LIMIT + 1_000);
        assert_eq!(
            stateful(&scene, &bid),
            ignore(IgnoreReason::GasLimitIncompatible)
        );
    }

    #[test]
    fn a_bid_off_the_head_branch_is_ignored() {
        let scene = scene();
        // A known payload, but neither the head's nor its parent's.
        let other = ExecutionBlockHash::repeat_byte(0x44);
        scene
            .market
            .record_execution_payload(&envelope_with_gas_limit(
                other,
                PARENT_GAS_LIMIT,
                PARENT,
                vec![],
            ));
        let bid = scene.signed(|bid| bid.parent_block_hash = other);
        assert_eq!(
            stateful(&scene, &bid),
            ignore(IgnoreReason::NotOnHeadBranch)
        );
    }

    #[test]
    fn a_wrong_previous_randao_is_rejected() {
        let scene = scene();
        let bid = scene.signed(|bid| bid.prev_randao = Bytes32::repeat_byte(9));
        assert_eq!(stateful(&scene, &bid), reject(RejectReason::PrevRandao));
    }

    #[test]
    fn an_unregistered_builder_is_rejected() {
        let scene = scene();
        let bid = scene.signed(|bid| bid.builder_index = 5);
        assert_eq!(stateful(&scene, &bid), reject(RejectReason::UnknownBuilder));
    }

    #[test]
    fn a_builder_of_another_version_is_rejected() {
        let scene = scene_with(|state| state.builders[0].version = 7);
        assert_eq!(
            stateful(&scene, &scene.bid),
            reject(RejectReason::NotPayloadBuilder)
        );
    }

    #[test]
    fn an_inactive_builder_is_rejected() {
        let exiting = scene_with(|state| state.builders[0].withdrawable_epoch = 5);
        assert_eq!(
            stateful(&exiting, &exiting.bid),
            reject(RejectReason::InactiveBuilder)
        );
        // Deposited at or after the finalized epoch.
        let young = scene_with(|state| state.builders[0].deposit_epoch = 1);
        assert_eq!(
            stateful(&young, &young.bid),
            reject(RejectReason::InactiveBuilder)
        );
    }

    #[test]
    fn a_builder_that_cannot_cover_the_bid_is_ignored() {
        let scene = scene();
        let bid = scene.signed(|bid| bid.value = 200_000_000_000);
        assert_eq!(
            stateful(&scene, &bid),
            ignore(IgnoreReason::BuilderCannotCover)
        );
    }

    #[test]
    fn a_builder_the_parent_payload_exits_is_ignored() {
        let scene = scene();
        let exits = vec![(builder_pubkey(), ExecutionAddress::repeat_byte(1))];
        scene
            .market
            .record_execution_payload(&envelope_with_gas_limit(
                parent_block_hash(),
                PARENT_GAS_LIMIT,
                PARENT,
                exits,
            ));
        assert_eq!(
            stateful(&scene, &scene.bid),
            ignore(IgnoreReason::BuilderMayExit)
        );
    }

    #[test]
    fn an_exit_for_another_builder_does_not_matter() {
        let scene = scene();
        let wrong_key = (BlsPubkey([3; 48]), ExecutionAddress::repeat_byte(1));
        let wrong_source = (builder_pubkey(), ExecutionAddress::repeat_byte(9));
        scene
            .market
            .record_execution_payload(&envelope_with_gas_limit(
                parent_block_hash(),
                PARENT_GAS_LIMIT,
                PARENT,
                vec![wrong_key, wrong_source],
            ));
        assert_eq!(stateful(&scene, &scene.bid), Outcome::Accept);
    }

    #[test]
    fn exits_are_read_from_the_stored_envelope_when_the_known_payload_is_another_blocks() {
        let mut scene = scene();
        // The market knows the hash from some other block, so it cannot answer
        // for the parent's own envelope.
        scene
            .market
            .record_execution_payload(&envelope_with_gas_limit(
                parent_block_hash(),
                PARENT_GAS_LIMIT,
                Root::repeat_byte(0x61),
                vec![],
            ));
        assert_eq!(
            stateful(&scene, &scene.bid),
            ignore(IgnoreReason::ParentPayloadUnverified)
        );

        let exits = vec![(builder_pubkey(), ExecutionAddress::repeat_byte(1))];
        let envelope = gloas::SignedExecutionPayloadEnvelope {
            message: envelope_with_gas_limit(parent_block_hash(), PARENT_GAS_LIMIT, PARENT, exits),
            signature: Default::default(),
        };
        scene.store.insert_verified_payload(32, &envelope);
        assert_eq!(
            stateful(&scene, &scene.bid),
            ignore(IgnoreReason::BuilderMayExit)
        );
    }

    #[test]
    fn a_bad_signature_is_rejected() {
        let scene = scene();
        let mut bid = scene.bid.clone();
        bid.signature.0[5] ^= 1;
        assert_eq!(stateful(&scene, &bid), reject(RejectReason::BadSignature));
        // Signed by another builder's key.
        let forged = test_support_sign_by(&scene, 1);
        assert_eq!(
            stateful(&scene, &forged),
            reject(RejectReason::BadSignature)
        );
    }

    fn test_support_sign_by(scene: &Scene, secret: u64) -> gloas::SignedExecutionPayloadBid {
        crate::beacon::builder_market::test_support::sign_bid(
            &scene.state,
            scene.bid.message.clone(),
            secret,
        )
    }

    // ---- the parent's state stands in for the advanced one ----

    #[test]
    fn a_state_advanced_within_its_epoch_keeps_what_the_rules_read() {
        let scene = scene();
        let config = scene.store.config();
        let mut advanced = scene.state.clone();
        stf::process_slots(&mut advanced, BID_SLOT, &config).expect("advance");
        assert_eq!(advanced.slot(), BID_SLOT);
        let (BeaconState::Gloas(before), BeaconState::Gloas(after)) = (&scene.state, &advanced)
        else {
            unreachable!("gloas states")
        };
        assert_eq!(before.builders, after.builders);
        assert_eq!(before.finalized_checkpoint, after.finalized_checkpoint);
        assert_eq!(before.fork, after.fork);
        assert_eq!(
            before.builder_pending_payments,
            after.builder_pending_payments
        );
        assert_eq!(
            before.builder_pending_withdrawals,
            after.builder_pending_withdrawals
        );
        assert_eq!(
            before.latest_execution_payload_bid,
            after.latest_execution_payload_bid
        );
        assert_eq!(
            get_randao_mix(&scene.state, get_current_epoch(&scene.state)),
            get_randao_mix(&advanced, get_current_epoch(&advanced))
        );
    }

    #[test]
    fn a_bid_across_an_epoch_uses_and_caches_the_checkpoint_state() {
        // The parent is in epoch 2: a funded builder is active only after
        // finality passes its deposit epoch, which an epoch-1 chain cannot have.
        let scene = scene_at(64, |_| {});
        let slot = 96;
        // Preferences for the later epoch's proposer.
        let dependent = dependent_root_at(&scene.state, PARENT, slot).expect("in the window");
        let proposer = fixed_proposer(&scene.state, slot).expect("in the lookahead window");
        let preferences = sign_preferences(
            &scene.state,
            gloas::ProposerPreferences {
                dependent_root: dependent,
                proposal_slot: slot,
                validator_index: proposer,
                fee_recipient: fee_recipient(),
                target_gas_limit: PARENT_GAS_LIMIT,
            },
        );
        assert!(scene.market.record_preferences(preferences, slot - 1));
        let bid = scene.signed(|bid| bid.slot = slot);
        let key = CacheKey::CheckpointState {
            epoch: 3,
            root: PARENT,
        };
        assert!(scene.store.cached_state(key).is_none());
        assert_eq!(stateful(&scene, &bid), Outcome::Accept);
        let cached = scene.store.cached_state(key).expect("the advanced state");
        assert_eq!(get_current_epoch(&cached), 3);
        // A second bid finds it.
        assert_eq!(stateful(&scene, &bid), Outcome::Accept);
    }

    /// A fulu parent one slot before gloas's first epoch: the rules reach the
    /// advanced state (which the upgrade has made gloas, with no builders yet)
    /// only if the parent's own payload counted as a known one.
    fn fulu_parent_scene(
        edit: impl FnOnce(&mut crate::beacon::containers::BeaconState),
    ) -> (Store, BuilderMarket, gloas::SignedExecutionPayloadBid) {
        use ethlambda_storage::ForkCheckpoints;

        use crate::beacon::fork::ForkName;
        use crate::beacon::gossip::test_support::{GENESIS_TIME, builder_scene::block_at};
        use crate::beacon::helpers::test_state::with_signing_validators_at;

        let config = Config::mainnet()
            .with_fork_epoch(ForkName::Fulu, 0)
            .with_fork_epoch(ForkName::Gloas, 2);
        let parent = Root::repeat_byte(0x70);
        let header_hash = ExecutionBlockHash::repeat_byte(0x41);
        let mut state = with_signing_validators_at(ForkName::Fulu, 64);
        *state.slot_mut() = 62;
        if let BeaconState::Fulu(fulu) = &mut state {
            fulu.latest_execution_payload_header.block_hash = header_hash;
            fulu.latest_execution_payload_header.gas_limit = 30_000_000;
        }
        edit(&mut state);
        state.apply_pending_mutations();

        let mut store = Store::init_beacon(
            Arc::new(ethlambda_storage::backend::InMemoryBackend::new()),
            GENESIS_TIME,
            config,
            parent,
            ethlambda_types::checkpoint::Checkpoint {
                root: parent,
                slot: 62,
            },
            62,
        );
        store
            .insert_pending_block(parent, block_at(62))
            .expect("insert the parent");
        store
            .insert_state(parent, state.clone())
            .expect("insert the parent state");
        store
            .update_checkpoints(ForkCheckpoints::head_only(parent))
            .expect("move the head");
        // The status the chain actor records; a pre-gloas head has one node.
        store.set_head_payload_status(parent, PayloadStatus::Empty);

        let slot = 64;
        let market = BuilderMarket::default();
        let proposer = fixed_proposer(&state, slot).expect("in the window");
        let dependent_root = dependent_root_at(&state, parent, slot).expect("in the window");
        let preferences = sign_preferences(
            &state,
            gloas::ProposerPreferences {
                dependent_root,
                proposal_slot: slot,
                validator_index: proposer,
                fee_recipient: fee_recipient(),
                target_gas_limit: 30_000_000,
            },
        );
        assert!(market.record_preferences(preferences, slot - 1));
        let bid = gloas::SignedExecutionPayloadBid {
            message: gloas::ExecutionPayloadBid {
                parent_block_hash: header_hash,
                parent_block_root: parent,
                block_hash: ExecutionBlockHash::repeat_byte(0x33),
                prev_randao: get_randao_mix(&state, get_current_epoch(&state)),
                fee_recipient: fee_recipient(),
                gas_limit: 30_000_000,
                builder_index: 0,
                slot,
                value: 1,
                ..Default::default()
            },
            signature: Default::default(),
        };
        (store, market, bid)
    }

    #[test]
    fn a_pre_gloas_parents_payload_counts_as_known_with_its_header_gas_limit() {
        let (store, market, bid) = fulu_parent_scene(|_| {});
        // Past the payload, gas, head and randao rules, the advanced state is
        // gloas's first and has no builders yet.
        assert_eq!(
            stateful_checks(&store, &market, &bid),
            reject(RejectReason::UnknownBuilder)
        );
    }

    #[test]
    fn a_pre_gloas_parents_header_gas_limit_bounds_the_bid() {
        let (store, market, mut bid) = fulu_parent_scene(|_| {});
        bid.message.gas_limit += 1_000;
        assert_eq!(
            stateful_checks(&store, &market, &bid),
            ignore(IgnoreReason::GasLimitIncompatible)
        );
    }

    #[test]
    fn only_the_pre_gloas_parents_own_payload_hash_counts() {
        let (store, market, mut bid) = fulu_parent_scene(|_| {});
        bid.message.parent_block_hash = ExecutionBlockHash::repeat_byte(0x42);
        assert_eq!(
            stateful_checks(&store, &market, &bid),
            ignore(IgnoreReason::ParentPayloadUnknown)
        );
    }
}
