//! `data_column_sidecar_{subnet_id}` gossip validation: fulu's
//! `validate_data_column_sidecar_gossip` (`specs/fulu/p2p-interface.md`).
//!
//! Also every check the chain relies on before it keeps a sidecar gossip did
//! not accept ([`chain_checks`]): one fetched over req/resp, one gossip queued
//! or had no free permit for, or a parked one whose parent has since
//! imported. The chain actor stores whatever reaches it without checking it
//! again, so these are the only checks such a sidecar gets.

use ethlambda_storage::CacheKey;

use super::{
    IgnoreReason, Outcome, QueueReason, RejectReason, SeenColumns, finalized_ancestry,
    finalized_start_slot, is_future_slot,
};
use crate::beacon::bls;
use crate::beacon::config::Config;
use crate::beacon::constants::{DATA_COLUMN_SIDECAR_SUBNET_COUNT, DOMAIN_BEACON_PROPOSER};
use crate::beacon::containers::BeaconState;
use crate::beacon::containers::fulu::DataColumnSidecar;
use crate::beacon::fork_choice::{self, Store};
use crate::beacon::helpers::accessors::get_beacon_proposer_index;
use crate::beacon::helpers::misc::{compute_domain, compute_epoch_at_slot, compute_signing_root};
use crate::beacon::precheck;
use crate::beacon::primitives::HashTreeRoot as _;
use crate::beacon::primitives::{Slot, ValidatorIndex};
use crate::beacon::stf;
use crate::metrics;

/// The rules that read only the sidecar, the clock and the store's metadata.
///
/// `Err` carries the verdict; `Ok` sends the sidecar on to [`stateful_checks`].
pub fn cheap_checks(
    seen: &SeenColumns,
    store: &Store,
    sidecar: &DataColumnSidecar,
    subnet_id: u64,
    now_ms: u64,
) -> Result<(), Outcome> {
    let config = store.config();
    // [REJECT] The sidecar is structurally valid.
    if !fork_choice::verify_data_column_sidecar(sidecar, &config) {
        return Err(Outcome::Reject(RejectReason::Malformed));
    }
    // [REJECT] The sidecar is for the correct subnet.
    if sidecar.index % DATA_COLUMN_SIDECAR_SUBNET_COUNT != subnet_id {
        return Err(Outcome::Reject(RejectReason::WrongSubnet));
    }
    let header = &sidecar.signed_block_header.message;
    // [IGNORE] The sidecar is not from a future slot.
    if is_future_slot(&config, header.slot, now_ms) {
        return Err(Outcome::Ignore(IgnoreReason::FutureSlot));
    }
    // [IGNORE] The sidecar is from a slot greater than the latest finalized slot.
    if header.slot <= finalized_start_slot(store) {
        return Err(Outcome::Ignore(IgnoreReason::Finalized));
    }
    // [IGNORE] The first valid sidecar for its (slot, proposer, index).
    if seen.contains(header.slot, header.proposer_index, sidecar.index) {
        return Err(Outcome::Ignore(IgnoreReason::AlreadySeen));
    }
    // [IGNORE] Already stored, fetched over req/resp before gossip delivered
    // it. Everything past here is the expensive part and would change
    // nothing.
    if store.has_data_column(header.slot, &header.hash_tree_root(), sidecar.index) {
        return Err(Outcome::Ignore(IgnoreReason::AlreadyStored));
    }
    Ok(())
}

/// The rules that need the parent's post-state. Runs on a blocking thread,
/// and reads states only from the cache, as [`super::block::stateful_checks`]
/// does. The rules themselves are [`judge_against_parent`]'s, a permit held
/// while they run.
pub fn stateful_checks(store: &Store, sidecar: &DataColumnSidecar) -> Outcome {
    let header = &sidecar.signed_block_header.message;
    let parent_known = store.has_block(&header.parent_root);
    let parent_state = if parent_known {
        store.cached_state(CacheKey::BlockState(header.parent_root))
    } else {
        None
    };
    // [IGNORE] The parent has been seen and passed validation (MAY queue).
    // Every queued column still reaches the chain actor's
    // `PendingDataColumns`, so it gets the same signature-against-the-head-
    // state treatment a queued block does; see [`queue_unless_forged`].
    let Some(parent_state) = parent_state else {
        let reason = if parent_known {
            QueueReason::ParentNotReady
        } else {
            QueueReason::ParentUnknown
        };
        return queue_unless_forged(store, sidecar, reason);
    };
    judge_against_parent(store, sidecar, &parent_state, PastLookahead::Queue)
}

/// What the chain may do with a sidecar [`chain_checks`] judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainVerdict {
    /// Passed every rule: the chain stores it as it is.
    Keep,
    /// Its parent has no post-state yet. The chain parks it and sends it back
    /// through [`chain_checks`] once the parent imports.
    AwaitParent,
    /// Not kept. The outcome says why: an `Ignore` or a `Reject`, or
    /// `Queue(ParentNotReady)` when the parent has a post-state but its
    /// finalized-ancestry walk cannot finish, which no import will fix.
    Drop(Outcome),
}

/// Every check the chain relies on before it keeps a sidecar gossip did not
/// accept.
///
/// The gossip rules minus the two that only mean something on a gossip topic
/// (the subnet match and the seen cache), with two differences that both come
/// from running with no gossipsub cache waiting on the answer:
///
/// - The parent's post-state may come from the database, not only from the
///   state cache: a parent whose state was written out is still a parent.
/// - A slot outside the parent state's proposer lookahead is answered by
///   advancing a clone of that state to it ([`advanced_proposer`]), rather
///   than queued. Nothing would ever come along to answer it later.
///
/// Runs off both actors. It costs a KZG batch and a BLS verification per
/// sidecar, and those used to run on the chain actor's single thread.
pub fn chain_checks(store: &Store, sidecar: &DataColumnSidecar, now_ms: u64) -> ChainVerdict {
    let config = store.config();
    // [REJECT] The sidecar is structurally valid. First, so a peer answering
    // a fetch with garbage cannot make this pay for a state read or a KZG
    // batch.
    if !fork_choice::verify_data_column_sidecar(sidecar, &config) {
        return ChainVerdict::Drop(Outcome::Reject(RejectReason::Malformed));
    }
    let header = &sidecar.signed_block_header.message;
    // [IGNORE] Not from a future slot. Also what bounds `advanced_proposer`'s
    // `process_slots` below: a header naming a slot far ahead would otherwise
    // make it advance one slot at a time towards that slot.
    if is_future_slot(&config, header.slot, now_ms) {
        return ChainVerdict::Drop(Outcome::Ignore(IgnoreReason::FutureSlot));
    }
    // [IGNORE] From a slot greater than the latest finalized slot.
    if header.slot <= finalized_start_slot(store) {
        return ChainVerdict::Drop(Outcome::Ignore(IgnoreReason::Finalized));
    }
    // [IGNORE] Already stored. Common during a range sync, whose consecutive
    // batches ask for overlapping spans of columns, and everything after this
    // is the expensive part.
    if store.has_data_column(header.slot, &header.hash_tree_root(), sidecar.index) {
        return ChainVerdict::Drop(Outcome::Ignore(IgnoreReason::AlreadyStored));
    }
    let Ok(Some(parent_state)) = store.get_state(&header.parent_root) else {
        // Parked rather than dropped: the specification's "MAY be queued"
        // for a sidecar whose parent has not been seen. The head-state
        // signature check keeps a forged header from taking a
        // `PendingDataColumns` row while it waits.
        return match queue_unless_forged(store, sidecar, QueueReason::ParentUnknown) {
            Outcome::Queue(_) => ChainVerdict::AwaitParent,
            outcome => ChainVerdict::Drop(outcome),
        };
    };
    match judge_against_parent(store, sidecar, &parent_state, PastLookahead::Advance) {
        Outcome::Accept => ChainVerdict::Keep,
        outcome => ChainVerdict::Drop(outcome),
    }
}

/// What [`judge_against_parent`] does when the parent state's proposer
/// lookahead has no answer for the sidecar's slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PastLookahead {
    /// Queue it, as gossip does: advancing a state clone takes longer than a
    /// gossip verdict can wait.
    Queue,
    /// Advance a clone of the parent state to the slot and ask it, as
    /// [`chain_checks`] does.
    Advance,
}

/// The rules that read the parent's post-state, shared by [`stateful_checks`]
/// and [`chain_checks`].
///
/// Signature first, lookahead last, mirroring
/// [`super::block::stateful_checks`]'s own order: a forged header naming a
/// real parent is caught by [`header_signature_is_valid`] before this pays
/// for the finalized-ancestry walk (a full `LiveChain` scan) or the KZG
/// proof.
fn judge_against_parent(
    store: &Store,
    sidecar: &DataColumnSidecar,
    parent_state: &BeaconState,
    past_lookahead: PastLookahead,
) -> Outcome {
    let config = store.config();
    let header = &sidecar.signed_block_header.message;
    // [REJECT] The sidecar is from a higher slot than its parent.
    if header.slot <= parent_state.slot() {
        return Outcome::Reject(RejectReason::NotAfterParent);
    }
    // [REJECT] Signed by a validator the parent's state knows, over this
    // header.
    if let Err(outcome) = header_signature_is_valid(sidecar, parent_state, &config) {
        return outcome;
    }
    // [REJECT] Proposed by the proposer the parent's state fixes for the
    // slot. Read from its lookahead when that covers the slot; past it, only
    // the chain path pays to find out.
    let expected = match (
        precheck::fixed_proposer(parent_state, header.slot),
        past_lookahead,
    ) {
        (Some(expected), _) => Some(expected),
        (None, PastLookahead::Queue) => None,
        (None, PastLookahead::Advance) => {
            let Some(expected) = advanced_proposer(parent_state, header.slot, &config) else {
                return Outcome::Ignore(IgnoreReason::Internal);
            };
            Some(expected)
        }
    };
    if expected.is_some_and(|expected| header.proposer_index != expected) {
        return Outcome::Reject(RejectReason::WrongProposer);
    }
    // [REJECT] The finalized checkpoint is an ancestor of the sidecar's block.
    if let Err(outcome) = finalized_ancestry(store, header.parent_root).verdict() {
        return outcome;
    }
    // [REJECT] The commitments are the ones the block committed to.
    if !fork_choice::verify_data_column_sidecar_inclusion_proof(sidecar) {
        return Outcome::Reject(RejectReason::InclusionProof);
    }
    // [REJECT] Every cell matches its commitment and proof.
    let kzg = {
        let _timing = metrics::time_data_column_kzg_verify();
        fork_choice::verify_data_column_sidecar_kzg_proofs(sidecar)
    };
    if !matches!(kzg, Ok(true)) {
        return Outcome::Reject(RejectReason::Kzg);
    }
    // [IGNORE] The sidecar's slot is outside the parent state's proposer
    // lookahead window (MAY queue).
    if past_lookahead == PastLookahead::Queue
        && let Err(outcome) = lookahead_covers(parent_state, header.slot)
    {
        return outcome;
    }
    Outcome::Accept
}

/// The proposer `parent_state`, advanced to `slot`, names for it: the answer
/// [`precheck::fixed_proposer`] has no window for. `None` when the state
/// cannot be advanced or cannot name one.
///
/// Advances a clone, so the caller's copy (the store's cached `Arc`) is left
/// exactly as it was. Costs a `process_slots` over every slot between the
/// parent and `slot`, including a full state merkleization per empty slot
/// crossed, which is why only [`chain_checks`] calls this, and only for a
/// slot the lookahead does not cover.
fn advanced_proposer(
    parent_state: &BeaconState,
    slot: Slot,
    config: &Config,
) -> Option<ValidatorIndex> {
    let mut state = parent_state.clone();
    stf::process_slots(&mut state, slot, config).ok()?;
    get_beacon_proposer_index(&state).ok()
}

/// `Queue(reason)`, unless the head state already shows the header's
/// signature is forged.
///
/// Mirrors [`super::block::queue_unless_forged`]: validator indices never
/// move, so the head state's key for the header's proposer is the one it was
/// signed with, even when that state cannot yet say whether this proposer is
/// the *expected* one for the slot. A column queued here is written to the
/// chain actor's `PendingDataColumns`, so without this check a forged one
/// would sit there rather than being refused up front.
fn queue_unless_forged(store: &Store, sidecar: &DataColumnSidecar, reason: QueueReason) -> Outcome {
    let head_state = store
        .head()
        .ok()
        .and_then(|head| store.cached_state(CacheKey::BlockState(head)));
    let Some(head_state) = head_state else {
        return Outcome::Queue(reason);
    };
    match header_signature_is_valid(sidecar, &head_state, &store.config()) {
        Err(Outcome::Reject(RejectReason::BadSignature)) => {
            Outcome::Reject(RejectReason::BadSignature)
        }
        _ => Outcome::Queue(reason),
    }
}

/// `cheap_checks` then `stateful_checks`, for callers with no reason to split
/// them, such as the spec vectors.
pub fn validate(
    seen: &SeenColumns,
    store: &Store,
    sidecar: &DataColumnSidecar,
    subnet_id: u64,
    now_ms: u64,
) -> Outcome {
    if let Err(outcome) = cheap_checks(seen, store, sidecar, subnet_id, now_ms) {
        return outcome;
    }
    stateful_checks(store, sidecar)
}

/// Whether `parent_state`'s proposer lookahead covers `slot` at all.
///
/// Checked last in [`stateful_checks`], after every REJECT-worthy rule: the
/// proposer-identity and signature questions are both settled earlier, so a
/// sidecar reaching this has already cleared those, and the parent state may
/// simply have no answer yet for a slot this far out, which the spec lets us
/// queue rather than reject. The gossip counterpart of [`advanced_proposer`],
/// which advances a clone of the state with `process_slots` instead and so
/// can answer for a slot outside the lookahead window, at the cost of a state
/// clone this path cannot afford.
fn lookahead_covers(parent_state: &BeaconState, slot: Slot) -> Result<(), Outcome> {
    if precheck::fixed_proposer(parent_state, slot).is_none() {
        return Err(Outcome::Queue(QueueReason::ShufflingUnavailable));
    }
    Ok(())
}

/// Whether `sidecar`'s header carries `state`'s key for its `proposer_index`.
///
/// Checked in [`stateful_checks`] before the proposer-identity check and
/// every later rule, so a forged header is caught before the finalized-
/// ancestry walk or the KZG proof. Also what [`queue_unless_forged`] judges a
/// column on before its parent's own state is even available, against the
/// head state instead of the parent's. Neither caller can answer the
/// *expected*-proposer question the state `state` is judged against here (the
/// head state may predate the proposer's own deposit; the parent's state
/// knows the proposer but not always the slot's shuffling), so this checks
/// only what the signature alone can tell them: an unknown proposer or a bad
/// signature, never `WrongProposer`.
fn header_signature_is_valid(
    sidecar: &DataColumnSidecar,
    state: &BeaconState,
    config: &Config,
) -> Result<(), Outcome> {
    let header = &sidecar.signed_block_header.message;
    let Ok(proposer) = state.validator(header.proposer_index) else {
        return Err(Outcome::Reject(RejectReason::UnknownProposer));
    };
    // The domain comes from the fork schedule at the header's own epoch, not
    // from the state's `fork`, for the reason `precheck_block` gives.
    let fork_version =
        config.fork_version(config.fork_at_epoch(compute_epoch_at_slot(header.slot)));
    let domain = compute_domain(
        DOMAIN_BEACON_PROPOSER,
        fork_version,
        state.genesis_validators_root(),
    );
    let signing_root = compute_signing_root(header.hash_tree_root(), domain);
    if !bls::verify(
        &proposer.pubkey,
        signing_root,
        &sidecar.signed_block_header.signature,
    ) {
        return Err(Outcome::Reject(RejectReason::BadSignature));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::beacon::constants::MAXIMUM_GOSSIP_CLOCK_DISPARITY as DISPARITY;
    use crate::beacon::containers::{SignedBeaconBlock, electra, fulu, shared};
    use crate::beacon::gossip::test_support::{fulu_parent, seen_columns, slot_start_ms, store};
    use crate::beacon::gossip::{IgnoreReason, Outcome, QueueReason, RejectReason};
    use crate::beacon::helpers::misc::compute_start_slot_at_epoch;
    use crate::beacon::helpers::test_state::secret_key_for;
    use crate::beacon::preset;
    use crate::beacon::primitives::{
        BlsSignature, KzgCommitment, KzgProof, Root, Slot, ValidatorIndex,
    };

    /// A block that only needs to exist for [`Store::has_block`] to see its
    /// root: none of these tests read anything else out of it.
    fn parent_block(slot: Slot) -> SignedBeaconBlock {
        SignedBeaconBlock::Fulu(electra::SignedBeaconBlock {
            message: electra::BeaconBlock {
                slot,
                proposer_index: 0,
                parent_root: Root::ZERO,
                state_root: Root::ZERO,
                body: electra::BeaconBlockBody::empty(),
            },
            signature: Default::default(),
        })
    }

    /// Structurally valid (one commitment, one proof, one cell), so every
    /// check before the parent lookup can be reached.
    fn sidecar(slot: Slot, proposer: ValidatorIndex, index: u64) -> DataColumnSidecar {
        let cell: fulu::Cell = libssz_types::SszVector::try_from(vec![0u8; preset::BYTES_PER_CELL])
            .expect("exact cell size");
        DataColumnSidecar {
            index,
            column: vec![cell].try_into().expect("within the per-block limit"),
            kzg_commitments: vec![KzgCommitment::default()]
                .try_into()
                .expect("within the per-block limit"),
            kzg_proofs: vec![KzgProof::default()]
                .try_into()
                .expect("within the per-block limit"),
            signed_block_header: shared::SignedBeaconBlockHeader {
                message: shared::BeaconBlockHeader {
                    slot,
                    proposer_index: proposer,
                    parent_root: Root::repeat_byte(0x11),
                    ..Default::default()
                },
                signature: Default::default(),
            },
            kzg_commitments_inclusion_proof: vec![
                Root::ZERO;
                preset::KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH
            ]
            .try_into()
            .expect("exact depth"),
        }
    }

    #[test]
    fn a_well_formed_sidecar_on_its_subnet_passes() {
        let store = store(0);
        let subnet = 7 % DATA_COLUMN_SIDECAR_SUBNET_COUNT;
        assert_eq!(
            cheap_checks(
                &seen_columns(),
                &store,
                &sidecar(5, 1, 7),
                subnet,
                slot_start_ms(&store, 5)
            ),
            Ok(())
        );
    }

    #[test]
    fn a_sidecar_on_the_wrong_subnet_is_rejected() {
        let store = store(0);
        let wrong = (7 + 1) % DATA_COLUMN_SIDECAR_SUBNET_COUNT;
        assert_eq!(
            cheap_checks(
                &seen_columns(),
                &store,
                &sidecar(5, 1, 7),
                wrong,
                slot_start_ms(&store, 5)
            ),
            Err(Outcome::Reject(RejectReason::WrongSubnet))
        );
    }

    #[test]
    fn a_sidecar_with_no_commitments_is_rejected() {
        let store = store(0);
        let mut malformed = sidecar(5, 1, 0);
        malformed.kzg_commitments = Default::default();
        assert_eq!(
            cheap_checks(
                &seen_columns(),
                &store,
                &malformed,
                0,
                slot_start_ms(&store, 5)
            ),
            Err(Outcome::Reject(RejectReason::Malformed))
        );
    }

    #[test]
    fn future_finalized_and_seen_sidecars_are_ignored() {
        let store = store(32);
        let too_early = slot_start_ms(&store, 40) - (DISPARITY + 100);
        assert_eq!(
            cheap_checks(&seen_columns(), &store, &sidecar(40, 1, 0), 0, too_early),
            Err(Outcome::Ignore(IgnoreReason::FutureSlot))
        );
        assert_eq!(
            cheap_checks(
                &seen_columns(),
                &store,
                &sidecar(32, 1, 0),
                0,
                slot_start_ms(&store, 40)
            ),
            Err(Outcome::Ignore(IgnoreReason::Finalized))
        );
        let mut seen = seen_columns();
        seen.record(40, 1, 0);
        assert_eq!(
            cheap_checks(
                &seen,
                &store,
                &sidecar(40, 1, 0),
                0,
                slot_start_ms(&store, 40)
            ),
            Err(Outcome::Ignore(IgnoreReason::AlreadySeen))
        );
    }

    #[test]
    fn an_already_stored_sidecar_is_ignored() {
        let store = store(0);
        let card = sidecar(5, 1, 0);
        let header = &card.signed_block_header.message;
        store
            .put_data_column_sidecar(
                header.slot,
                &header.hash_tree_root(),
                card.index,
                Vec::new(),
            )
            .expect("store the column");
        assert_eq!(
            cheap_checks(&seen_columns(), &store, &card, 0, slot_start_ms(&store, 5)),
            Err(Outcome::Ignore(IgnoreReason::AlreadyStored))
        );
    }

    #[test]
    fn a_sidecar_whose_parent_was_never_seen_is_queued() {
        let store = store(0);
        assert_eq!(
            stateful_checks(&store, &sidecar(5, 1, 0)),
            Outcome::Queue(QueueReason::ParentUnknown)
        );
    }

    #[test]
    fn a_known_parent_with_no_cached_state_is_queued() {
        let mut store = store(0);
        let parent_root = Root::repeat_byte(0x11);
        store
            .insert_pending_block(parent_root, parent_block(4))
            .expect("insert pending parent");

        let mut card = sidecar(5, 1, 0);
        card.signed_block_header.message.parent_root = parent_root;

        // The parent is known but uncached, and no head state is cached
        // either, so no signature check applies: `queue_unless_forged`
        // returns the plain queue reason.
        assert_eq!(
            stateful_checks(&store, &card),
            Outcome::Queue(QueueReason::ParentNotReady)
        );
    }

    #[test]
    fn an_unknown_parent_with_a_cached_head_state_is_judged_on_its_signature() {
        let store = store(0);
        let config = store.config();
        let proposer: ValidatorIndex = 3;
        // `store()` sets the head to `Root::ZERO`, the same root
        // `queue_unless_forged` reads through `Store::head`.
        let head_state = fulu_parent(proposer);
        store.cache_state(
            CacheKey::BlockState(Root::ZERO),
            Arc::new(head_state.clone()),
        );

        let mut card = sidecar(head_state.slot() + 1, proposer, 0);
        card.signed_block_header.message.parent_root = Root::repeat_byte(0x22);

        // The default signature verifies against nobody.
        assert_eq!(
            stateful_checks(&store, &card),
            Outcome::Reject(RejectReason::BadSignature)
        );

        // The same header, properly signed by the head state's proposer.
        let good = signed(card, &head_state, &config, proposer);
        assert_eq!(
            stateful_checks(&store, &good),
            Outcome::Queue(QueueReason::ParentUnknown)
        );
    }

    #[test]
    fn a_sidecar_not_after_its_parent_is_rejected() {
        let mut store = store(0);
        let proposer: ValidatorIndex = 3;
        let parent = fulu_parent(proposer);
        let parent_root = Root::repeat_byte(0x33);
        store
            .insert_pending_block(parent_root, parent_block(parent.slot()))
            .expect("insert pending parent");
        store.cache_state(CacheKey::BlockState(parent_root), Arc::new(parent.clone()));

        let mut card = sidecar(parent.slot(), proposer, 0);
        card.signed_block_header.message.parent_root = parent_root;

        assert_eq!(
            stateful_checks(&store, &card),
            Outcome::Reject(RejectReason::NotAfterParent)
        );
    }

    #[test]
    fn a_sidecar_off_the_finalized_chain_is_rejected() {
        let mut store = store(0);
        let config = store.config();
        let proposer: ValidatorIndex = 3;
        let parent = fulu_parent(proposer);
        let parent_root = Root::repeat_byte(0x44);
        let fork_root = Root::repeat_byte(0x55);

        store
            .insert_pending_block(parent_root, parent_block(parent.slot()))
            .expect("insert pending parent");
        store.cache_state(CacheKey::BlockState(parent_root), Arc::new(parent.clone()));
        // The chain from `parent_root` reaches the finalized epoch's start
        // (slot 0, since the store is finalized at slot 0) at `fork_root`
        // rather than the store's finalized root (`Root::ZERO`): a fork.
        store.insert_live_chain_entry(parent.slot(), parent_root, fork_root);
        store.insert_live_chain_entry(0, fork_root, fork_root);

        let mut card = sidecar(parent.slot() + 1, proposer, 0);
        card.signed_block_header.message.parent_root = parent_root;
        // Properly signed: the signature and proposer-identity checks now run
        // before the finalized-ancestry walk, so an unsigned header would be
        // rejected on that instead of ever reaching the walk this test means
        // to exercise.
        let card = signed(card, &parent, &config, proposer);

        assert_eq!(
            stateful_checks(&store, &card),
            Outcome::Reject(RejectReason::FinalizedNotAncestor)
        );
    }

    #[test]
    fn a_failed_finalized_ancestry_walk_checks_the_parents_signature_before_queuing() {
        let mut store = store(0);
        let config = store.config();
        let proposer: ValidatorIndex = 3;
        let parent = fulu_parent(proposer);
        let parent_root = Root::repeat_byte(0x66);

        store
            .insert_pending_block(parent_root, parent_block(parent.slot()))
            .expect("insert pending parent");
        store.cache_state(CacheKey::BlockState(parent_root), Arc::new(parent.clone()));
        // No `LiveChain` row for the parent: the finalized-ancestry walk
        // cannot finish.

        let mut card = sidecar(parent.slot() + 1, proposer, 0);
        card.signed_block_header.message.parent_root = parent_root;

        // The default signature verifies against nobody.
        assert_eq!(
            stateful_checks(&store, &card),
            Outcome::Reject(RejectReason::BadSignature)
        );

        // The same header, properly signed by the parent's own proposer.
        let good = signed(card, &parent, &config, proposer);
        assert_eq!(
            stateful_checks(&store, &good),
            Outcome::Queue(QueueReason::ParentNotReady)
        );
    }

    fn signed(
        mut sidecar: DataColumnSidecar,
        state: &BeaconState,
        config: &Config,
        signer: ValidatorIndex,
    ) -> DataColumnSidecar {
        let header = &sidecar.signed_block_header.message;
        let fork_version =
            config.fork_version(config.fork_at_epoch(compute_epoch_at_slot(header.slot)));
        let domain = compute_domain(
            DOMAIN_BEACON_PROPOSER,
            fork_version,
            state.genesis_validators_root(),
        );
        let signing_root = compute_signing_root(header.hash_tree_root(), domain);
        let signature =
            secret_key_for(signer as usize).sign(signing_root.as_slice(), bls::DST, &[]);
        sidecar.signed_block_header.signature = BlsSignature(signature.to_bytes());
        sidecar
    }

    /// A correctly signed header from a validator the parent's state knows,
    /// but not the one its lookahead names for the slot: `stateful_checks`
    /// must still reject it, on `WrongProposer` rather than accepting it or
    /// mistaking the mismatch for a bad signature.
    #[test]
    fn a_correctly_signed_header_from_the_wrong_proposer_is_rejected() {
        let mut store = store(0);
        let config = store.config();
        let expected_proposer: ValidatorIndex = 3;
        let signer: ValidatorIndex = 5;
        let parent = fulu_parent(expected_proposer);
        let parent_root = Root::repeat_byte(0x77);

        store
            .insert_pending_block(parent_root, parent_block(parent.slot()))
            .expect("insert pending parent");
        store.cache_state(CacheKey::BlockState(parent_root), Arc::new(parent.clone()));

        let mut card = sidecar(parent.slot() + 1, signer, 0);
        card.signed_block_header.message.parent_root = parent_root;
        // A real signature from validator 5, who is not who the lookahead
        // (fixed to `expected_proposer` for every slot by `fulu_parent`)
        // names for this slot.
        let card = signed(card, &parent, &config, signer);

        assert_eq!(
            stateful_checks(&store, &card),
            Outcome::Reject(RejectReason::WrongProposer)
        );
    }

    /// [`lookahead_covers`] answers only whether the parent state's
    /// lookahead can name a proposer for the slot at all; a real proposer
    /// mismatch is [`RejectReason::WrongProposer`], checked earlier in
    /// [`stateful_checks`] and covered there by
    /// [`a_correctly_signed_header_from_the_wrong_proposer_is_rejected`].
    #[test]
    fn a_slot_past_the_lookahead_is_queued() {
        let parent = fulu_parent(3);
        let slot = parent.slot() + 1;
        assert_eq!(lookahead_covers(&parent, slot), Ok(()));

        let window_start = compute_start_slot_at_epoch(compute_epoch_at_slot(parent.slot()));
        let beyond = window_start + preset::PROPOSER_LOOKAHEAD_LENGTH as Slot;
        assert_eq!(
            lookahead_covers(&parent, beyond),
            Err(Outcome::Queue(QueueReason::ShufflingUnavailable))
        );
    }

    /// The signature and proposer-identity checks run before the lookahead
    /// check in [`stateful_checks`], so a forged header for a slot the
    /// lookahead cannot place is rejected rather than queued.
    #[test]
    fn a_forged_signature_past_the_lookahead_is_rejected_before_queuing() {
        let mut store = store(0);
        let proposer: ValidatorIndex = 3;
        let parent = fulu_parent(proposer);
        let parent_root = Root::repeat_byte(0x88);

        store
            .insert_pending_block(parent_root, parent_block(parent.slot()))
            .expect("insert pending parent");
        store.cache_state(CacheKey::BlockState(parent_root), Arc::new(parent.clone()));
        // No `LiveChain` row is set up: the forged signature must be caught
        // at the signature check, well before the finalized-ancestry walk
        // (let alone the lookahead check at the very end) is ever reached.

        let window_start = compute_start_slot_at_epoch(compute_epoch_at_slot(parent.slot()));
        let beyond = window_start + preset::PROPOSER_LOOKAHEAD_LENGTH as Slot;
        let mut card = sidecar(beyond, proposer, 0);
        card.signed_block_header.message.parent_root = parent_root;
        // The default signature verifies against nobody.

        assert_eq!(
            stateful_checks(&store, &card),
            Outcome::Reject(RejectReason::BadSignature)
        );
    }

    // -- chain_checks --------------------------------------------------------

    /// A store holding `parent_root` as a block, with `parent`'s post-state
    /// cached against it.
    fn store_with_parent(parent: &BeaconState, parent_root: Root) -> Store {
        let mut store = store(0);
        store
            .insert_pending_block(parent_root, parent_block(parent.slot()))
            .expect("insert pending parent");
        store.cache_state(CacheKey::BlockState(parent_root), Arc::new(parent.clone()));
        store
    }

    /// `sidecar(slot, proposer, 0)` under `parent_root`, signed by `signer`.
    fn signed_child(
        parent: &BeaconState,
        parent_root: Root,
        slot: Slot,
        proposer: ValidatorIndex,
        signer: ValidatorIndex,
        config: &Config,
    ) -> DataColumnSidecar {
        let mut card = sidecar(slot, proposer, 0);
        card.signed_block_header.message.parent_root = parent_root;
        signed(card, parent, config, signer)
    }

    #[test]
    fn chain_checks_drop_what_gossips_cheap_checks_would() {
        let store = store(32);
        let now = slot_start_ms(&store, 40);

        let mut malformed = sidecar(40, 1, 0);
        malformed.kzg_commitments = Default::default();
        assert_eq!(
            chain_checks(&store, &malformed, now),
            ChainVerdict::Drop(Outcome::Reject(RejectReason::Malformed))
        );
        assert_eq!(
            chain_checks(&store, &sidecar(41, 1, 0), now - (DISPARITY + 100)),
            ChainVerdict::Drop(Outcome::Ignore(IgnoreReason::FutureSlot))
        );
        assert_eq!(
            chain_checks(&store, &sidecar(32, 1, 0), now),
            ChainVerdict::Drop(Outcome::Ignore(IgnoreReason::Finalized))
        );

        let stored = sidecar(40, 1, 0);
        let header = &stored.signed_block_header.message;
        store
            .put_data_column_sidecar(header.slot, &header.hash_tree_root(), 0, Vec::new())
            .expect("store the column");
        assert_eq!(
            chain_checks(&store, &stored, now),
            ChainVerdict::Drop(Outcome::Ignore(IgnoreReason::AlreadyStored))
        );
    }

    #[test]
    fn chain_checks_park_a_sidecar_whose_parent_has_no_state() {
        let store = store(0);
        assert_eq!(
            chain_checks(&store, &sidecar(5, 1, 0), slot_start_ms(&store, 5)),
            ChainVerdict::AwaitParent
        );
    }

    /// The head-state signature check gossip runs before queuing runs before
    /// parking here too, so a forged header takes no `PendingDataColumns` row.
    #[test]
    fn chain_checks_drop_a_forged_header_rather_than_park_it() {
        let store = store(0);
        let proposer: ValidatorIndex = 3;
        let head_state = fulu_parent(proposer);
        store.cache_state(
            CacheKey::BlockState(Root::ZERO),
            Arc::new(head_state.clone()),
        );
        let slot = head_state.slot() + 1;
        let mut card = sidecar(slot, proposer, 0);
        card.signed_block_header.message.parent_root = Root::repeat_byte(0x22);

        assert_eq!(
            chain_checks(&store, &card, slot_start_ms(&store, slot)),
            ChainVerdict::Drop(Outcome::Reject(RejectReason::BadSignature))
        );
    }

    #[test]
    fn chain_checks_reject_a_header_from_the_wrong_proposer() {
        let parent = fulu_parent(3);
        let parent_root = Root::repeat_byte(0x99);
        let store = store_with_parent(&parent, parent_root);
        let config = store.config();
        let slot = parent.slot() + 1;
        let card = signed_child(&parent, parent_root, slot, 5, 5, &config);

        assert_eq!(
            chain_checks(&store, &card, slot_start_ms(&store, slot)),
            ChainVerdict::Drop(Outcome::Reject(RejectReason::WrongProposer))
        );
    }

    /// Where gossip queues, `chain_checks` drops: the parent already has a
    /// post-state, so no import will ever let the walk finish, and parking the
    /// sidecar would only wait for an import that has already happened.
    #[test]
    fn chain_checks_drop_a_sidecar_whose_ancestry_walk_cannot_finish() {
        let proposer: ValidatorIndex = 3;
        let parent = fulu_parent(proposer);
        let parent_root = Root::repeat_byte(0xaa);
        let store = store_with_parent(&parent, parent_root);
        let config = store.config();
        let slot = parent.slot() + 1;
        let card = signed_child(&parent, parent_root, slot, proposer, proposer, &config);

        assert_eq!(
            chain_checks(&store, &card, slot_start_ms(&store, slot)),
            ChainVerdict::Drop(Outcome::Queue(QueueReason::ParentNotReady))
        );
    }

    /// Past the parent state's lookahead, gossip queues the sidecar; the
    /// chain checks instead advance a clone of that state and judge the
    /// proposer against it. The parent descends from the finalized block
    /// here, so the finalized-ancestry walk passes and the placeholder
    /// inclusion proof is the first rule after the proposer check to fail.
    #[test]
    fn past_the_lookahead_chain_checks_advance_the_parent_state_instead_of_queuing() {
        let parent = fulu_parent(3);
        let parent_root = Root::repeat_byte(0xbb);
        let mut store = store_with_parent(&parent, parent_root);
        // The parent's own parent is the finalized root (`Root::ZERO`, at
        // slot 0), where the walk stops.
        store.insert_live_chain_entry(parent.slot(), parent_root, Root::ZERO);
        store.insert_live_chain_entry(0, Root::ZERO, Root::ZERO);
        let config = store.config();
        let window_start = compute_start_slot_at_epoch(compute_epoch_at_slot(parent.slot()));
        let beyond = window_start + preset::PROPOSER_LOOKAHEAD_LENGTH as Slot;
        let now = slot_start_ms(&store, beyond);
        let expected =
            advanced_proposer(&parent, beyond, &config).expect("the test state advances");
        let other = (expected + 1) % 8;

        let from_expected = signed_child(&parent, parent_root, beyond, expected, expected, &config);
        assert_eq!(
            stateful_checks(&store, &from_expected),
            Outcome::Reject(RejectReason::InclusionProof),
            "gossip reaches the same proof, having skipped the proposer check"
        );
        assert_eq!(
            chain_checks(&store, &from_expected, now),
            ChainVerdict::Drop(Outcome::Reject(RejectReason::InclusionProof))
        );

        let from_other = signed_child(&parent, parent_root, beyond, other, other, &config);
        assert_eq!(
            chain_checks(&store, &from_other, now),
            ChainVerdict::Drop(Outcome::Reject(RejectReason::WrongProposer))
        );
    }
}
