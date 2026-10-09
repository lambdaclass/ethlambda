//! Heze's inclusion lists (EIP-7805): the committee, the signature, the
//! fork-choice handler `on_inclusion_list`, and the honest validator's
//! assignment lookup.
//!
//! The lists themselves live in the storage crate's
//! [`InclusionListStore`](ethlambda_storage::pools::InclusionListStore),
//! reached through `Store::inclusion_list_store`; this module holds the
//! rules that decide what goes in, which need states and BLS. Gossip has its
//! own split of the same rules in [`super::gossip::inclusion_list`].

use std::sync::Arc;

use ethlambda_storage::CacheKey;

use crate::beacon::bls;
use crate::beacon::config::Config;
use crate::beacon::constants::DOMAIN_INCLUSION_LIST_COMMITTEE;
use crate::beacon::containers::BeaconState;
use crate::beacon::containers::heze::{InclusionList, SignedInclusionList};
use crate::beacon::error::{Error, Result, verify};
use crate::beacon::fork_choice::{
    Store, compute_shuffling_dependent_slot, compute_shuffling_lookahead_start_slot,
    get_current_slot, get_shuffling_dependent_root, get_slot_component_duration_ms,
};
use crate::beacon::gossip::execution_payload_bid::cached_checkpoint_state;
use crate::beacon::gossip::proposer_preferences::{dependent_root_at, is_valid_dependent_root};
use crate::beacon::helpers::accessors::{CommitteeCacheExt, get_current_epoch, get_domain};
use crate::beacon::helpers::misc::{
    compute_epoch_at_slot, compute_signing_root, compute_start_slot_at_epoch,
};
use crate::beacon::preset;
use crate::beacon::primitives::{
    BlsSignature, Epoch, HashTreeRoot as _, Root, Slot, ValidatorIndex,
};

/// The specification's `get_inclusion_list_committee`: every beacon committee
/// of `slot`, concatenated in committee order, then cycled to
/// `INCLUSION_LIST_COMMITTEE_SIZE` members.
///
/// The committees come through `committees`, the shared shuffling cache, so
/// the per-message gossip check does not reshuffle the epoch.
pub fn get_inclusion_list_committee(
    state: &BeaconState,
    slot: Slot,
    committees: &impl CommitteeCacheExt,
) -> Result<Vec<ValidatorIndex>> {
    let epoch = compute_epoch_at_slot(slot);
    let epoch_committees = committees.committees(state, epoch);
    let mut indices: Vec<ValidatorIndex> = Vec::new();
    for index in 0..epoch_committees.committees_per_slot() {
        let committee = epoch_committees
            .committee(slot, index)
            .map_err(|_| Error::SpecAssert("get_beacon_committee(state, slot, index)"))?;
        indices.extend_from_slice(committee);
    }
    verify(
        !indices.is_empty(),
        "get_inclusion_list_committee: the slot has committee members",
    )?;
    Ok((0..preset::INCLUSION_LIST_COMMITTEE_SIZE)
        .map(|i| indices[i % indices.len()])
        .collect())
}

/// The signing root a committee member signs its inclusion list under:
/// `DOMAIN_INCLUSION_LIST_COMMITTEE` at the list's own epoch.
pub fn inclusion_list_signing_root(state: &BeaconState, inclusion_list: &InclusionList) -> Root {
    let domain = get_domain(
        state,
        DOMAIN_INCLUSION_LIST_COMMITTEE,
        Some(compute_epoch_at_slot(inclusion_list.slot)),
    );
    compute_signing_root(inclusion_list.hash_tree_root(), domain)
}

/// The specification's `is_valid_inclusion_list_signature`.
pub fn is_valid_inclusion_list_signature(
    state: &BeaconState,
    signed_inclusion_list: &SignedInclusionList,
) -> bool {
    let message = &signed_inclusion_list.message;
    let Ok(validator) = state.validator(message.validator_index) else {
        return false;
    };
    let signing_root = inclusion_list_signing_root(state, message);
    bls::verify(
        &validator.pubkey,
        signing_root,
        &signed_inclusion_list.signature,
    )
}

/// `get_inclusion_list_due_ms` (heze `fork-choice.md`): how far into its
/// slot an inclusion list must arrive to count as timely.
pub fn get_inclusion_list_due_ms(config: &Config) -> u64 {
    get_slot_component_duration_ms(config.inclusion_list_due_bps, config)
}

/// Whether a list for `slot` received at `now_ms` is timely: it arrived in
/// its own slot, before [`get_inclusion_list_due_ms`]. `on_inclusion_list`'s
/// own rule, over the receipt time rather than the store's clock so a
/// gossip handler can judge a list the moment it arrives.
pub fn is_inclusion_list_timely(config: &Config, slot: Slot, now_ms: u64) -> bool {
    let since_genesis_ms = now_ms.saturating_sub(config.genesis_time_ms());
    let current_slot = since_genesis_ms / config.slot_duration_ms;
    let time_into_slot_ms = since_genesis_ms % config.slot_duration_ms;
    slot == current_slot && time_into_slot_ms < get_inclusion_list_due_ms(config)
}

/// The summed byte length of a list's transactions, which the gossip rules
/// and `on_inclusion_list` both bound.
pub fn transactions_size(inclusion_list: &InclusionList) -> u64 {
    inclusion_list
        .transactions
        .iter()
        .map(|transaction| transaction.len() as u64)
        .sum()
}

/// The dependent root an inclusion list for `slot` names on the chain whose
/// head is `head_root`: `get_shuffling_dependent_root(store, head_root,
/// epoch(slot))`. What a committee member signs over, and the key a proposer
/// or builder reads the previous slot's lists under.
pub fn inclusion_list_dependent_root(store: &Store, head_root: Root, slot: Slot) -> Root {
    let index = store.block_index();
    get_shuffling_dependent_root(&index, head_root, compute_epoch_at_slot(slot))
}

/// A state that answers `get_inclusion_list_committee` for a list at `slot`
/// under `dependent_root`: the specification's `block_states[dependent_root]`
/// advanced to `compute_shuffling_lookahead_start_slot(epoch)`.
///
/// Read from caches only, never rebuilt from disk, the way
/// `proposer_preferences` reads its lookahead state: the head's own state
/// when the head shares the dependent root (the canonical case, and a
/// dependent block about an epoch old is usually out of the state cache),
/// else the cached checkpoint state at the lookahead epoch. `None` when
/// neither is cached.
pub fn committee_state(
    store: &Store,
    slot: Slot,
    dependent_root: Root,
) -> Option<Arc<BeaconState>> {
    let epoch = compute_epoch_at_slot(slot);
    if let Ok(head_root) = store.head()
        && let Some(head_state) = store.cached_state(CacheKey::BlockState(head_root))
    {
        let head_epoch = get_current_epoch(&head_state);
        let covers = head_epoch == epoch || head_epoch + preset::MIN_SEED_LOOKAHEAD == epoch;
        if covers && dependent_root_at(&head_state, head_root, slot) == Some(dependent_root) {
            return Some(head_state);
        }
    }
    let lookahead_epoch = epoch.saturating_sub(preset::MIN_SEED_LOOKAHEAD);
    debug_assert_eq!(
        compute_start_slot_at_epoch(lookahead_epoch),
        compute_shuffling_lookahead_start_slot(epoch)
    );
    cached_checkpoint_state(store, lookahead_epoch, dependent_root)
}

/// The specification's `on_inclusion_list`, for a list that did not come
/// through gossip validation (req/resp, or this node's own Beacon API):
/// every check the handler makes, then `process_inclusion_list` with the
/// timeliness `now_ms` gives it. A failed check changes nothing.
///
/// Returns whether the list was newly stored.
pub fn on_inclusion_list(
    store: &Store,
    signed_inclusion_list: &SignedInclusionList,
    now_ms: u64,
) -> Result<bool> {
    let config = store.config();
    let inclusion_list = &signed_inclusion_list.message;
    let current_slot = get_current_slot(store, &config);

    // The slot must be within the retention window.
    verify(
        inclusion_list.slot <= current_slot,
        "inclusion_list.slot <= current_slot",
    )?;
    verify(
        inclusion_list.slot + config.min_slots_for_inclusion_lists_requests >= current_slot,
        "inclusion_list.slot + MIN_SLOTS_FOR_INCLUSION_LISTS_REQUESTS >= current_slot",
    )?;

    // The transactions must be non-empty and not exceed the maximum size.
    let size = transactions_size(inclusion_list);
    verify(size > 0, "transactions_size > 0")?;
    verify(
        size <= config.max_transactions_bytes_per_inclusion_list,
        "transactions_size <= MAX_TRANSACTIONS_BYTES_PER_INCLUSION_LIST",
    )?;
    // Every transaction must be non-empty.
    verify(
        inclusion_list.transactions.iter().all(|tx| !tx.is_empty()),
        "all(len(transaction) > 0)",
    )?;

    // The dependent block must be known.
    let dependent_root = inclusion_list.dependent_root;
    let (dependent_block_slot, _) = store.block_entry(&dependent_root).ok_or(Error::SpecAssert(
        "inclusion_list.dependent_root in store.blocks",
    ))?;
    verify(
        store.has_state(&dependent_root).unwrap_or(false),
        "inclusion_list.dependent_root in store.block_states",
    )?;

    // The dependent block's slot must not be after the shuffling dependent slot.
    let epoch: Epoch = compute_epoch_at_slot(inclusion_list.slot);
    let dependent_slot = compute_shuffling_dependent_slot(epoch);
    verify(
        dependent_block_slot <= dependent_slot,
        "store.blocks[inclusion_list.dependent_root].slot <= dependent_slot",
    )?;
    // The dependent block must be a possible dependent block for the
    // committee lookahead.
    verify(
        is_valid_dependent_root(store, dependent_root, dependent_slot),
        "is_valid_dependent_root(store, inclusion_list.dependent_root, dependent_slot)",
    )?;

    // Verify the validator is in the inclusion list committee.
    let state = committee_state(store, inclusion_list.slot, dependent_root).ok_or(
        Error::SpecAssert("inclusion_list.dependent_root in store.block_states"),
    )?;
    let committee =
        get_inclusion_list_committee(&state, inclusion_list.slot, &*store.committee_cache())?;
    verify(
        committee.contains(&inclusion_list.validator_index),
        "inclusion_list.validator_index in committee",
    )?;
    // Verify the signature.
    verify(
        is_valid_inclusion_list_signature(&state, signed_inclusion_list),
        "is_valid_inclusion_list_signature(state, signed_inclusion_list)",
    )?;

    let timely = is_inclusion_list_timely(&config, inclusion_list.slot, now_ms);
    Ok(store
        .inclusion_list_store()
        .process_inclusion_list(signed_inclusion_list.clone(), timely))
}

/// The honest validator's `get_inclusion_list_committee_assignment`: the
/// slot of `epoch` whose inclusion list committee `validator_index` sits on,
/// if any. `epoch` must be at most the state's next epoch.
pub fn get_inclusion_list_committee_assignment(
    state: &BeaconState,
    epoch: Epoch,
    validator_index: ValidatorIndex,
    committees: &impl CommitteeCacheExt,
) -> Result<Option<Slot>> {
    let next_epoch = get_current_epoch(state) + 1;
    verify(epoch <= next_epoch, "epoch <= next_epoch")?;
    let start_slot = compute_start_slot_at_epoch(epoch);
    for slot in start_slot..start_slot + preset::SLOTS_PER_EPOCH {
        if get_inclusion_list_committee(state, slot, committees)?.contains(&validator_index) {
            return Ok(Some(slot));
        }
    }
    Ok(None)
}

/// The honest validator's `get_inclusion_list_signature`, over a signing
/// closure rather than a private key: the node never holds one, and a
/// validator client signs the root this returns.
pub fn sign_inclusion_list(
    state: &BeaconState,
    inclusion_list: InclusionList,
    sign: impl FnOnce(Root) -> BlsSignature,
) -> SignedInclusionList {
    let signature = sign(inclusion_list_signing_root(state, &inclusion_list));
    SignedInclusionList {
        message: inclusion_list,
        signature,
    }
}

/// The inclusion list transactions `root`'s payload is judged against, the
/// first half of heze's `record_payload_inclusion_list_satisfaction`: the
/// timely lists of the slot before the block's, under the dependent root
/// the block's own chain gives that slot. `None` when the block is unknown.
pub fn payload_inclusion_list_transactions(
    store: &Store,
    root: Root,
) -> Option<Vec<crate::beacon::containers::gloas::Transaction>> {
    let (block_slot, _) = store.block_entry(&root)?;
    let slot = block_slot.checked_sub(1)?;
    let dependent_root = inclusion_list_dependent_root(store, root, slot);
    Some(
        store
            .inclusion_list_store()
            .transactions(slot, dependent_root, true),
    )
}
