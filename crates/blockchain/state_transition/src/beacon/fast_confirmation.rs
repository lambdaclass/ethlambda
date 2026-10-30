//! The Fast Confirmation Rule (FCR), after consensus-specs' `phase0`,
//! `bellatrix` and `gloas` `fast-confirmation.md`.
//!
//! **Spec version: consensus-specs `master` at commit `f993cf2`**, not the
//! `v1.7.0-beta.2` the rest of this crate is pinned to. The release ships no
//! FCR fixtures, so nothing ties this module to it, and `master` carries
//! fixes the release lacks: the gloas empty-slot support discount (#5672),
//! precise committee weight (#5670), the restart-resilient confirmed root
//! (#5673) and the `support_discount <= maximum_support` assertion (#5788).
//! A later bump should diff the three files above against that commit.
//!
//! One Rust function per specification function, named as the specification
//! names it, so the two can be read side by side. Two deliberate shapes differ
//! from the Python:
//!
//! - The specification's `FastConfirmationStore` holds a read-only `Store`
//!   beside the rule's own variables. [`FastConfirmationStore`] does the same
//!   (a borrowed [`Store`] plus the variables), and every function takes it
//!   where the specification takes `store` or `fcr_store`, so a function that
//!   takes both in Python takes one argument here.
//! - The variables live in the `Store` between runs
//!   ([`Store::fast_confirmation`]); [`run_fast_confirmation`] loads them,
//!   builds a [`FastConfirmationStore`] around them, runs
//!   [`on_fast_confirmation`] and writes them back.
//!
//! # Cost
//!
//! The specification is written for clarity: `get_node_support_between_slots`,
//! `compute_committee_weight_between_slots` and `get_attestation_score` each
//! walk the validator registry or the committees, and they are called once
//! per block of the confirmed chain. On mainnet (about a million active
//! validators) that would be tens of registry passes per slot, so the
//! per-run work is shared instead, in a [`RunContext`] built with the
//! [`FastConfirmationStore`] and dropped with it:
//!
//! - one pass over each balance source's registry ([`BalanceSource`]), at most
//!   three per run (previous and current observed justified checkpoints, and
//!   the pulled-up head state), shared by every later read;
//! - one bottom-up fold over the latest messages per balance source gives
//!   every block's `get_attestation_score` ([`attestation_scores`]), as
//!   `compute_weights` does for the head, instead of one scan per block;
//! - one sum per `(source, slot)` of a slot's committee weight, so a range
//!   inside one epoch is a sum over slots; a range crossing an epoch boundary
//!   without covering an epoch is the only case that deduplicates validators,
//!   and it is the smaller ranges;
//! - committees come from the store's shared committee cache.
//!
//! A run is therefore `O(V + M + B log B)` for `V` validators (the registry
//! passes), `M` latest messages and `B` unfinalized blocks, plus
//! `O(committee range)` for the few epoch-crossing or empty-slot ranges and
//! `O(votes * depth)` only in [`get_current_target_score`], which resolves
//! one checkpoint per distinct `(root, epoch)` vote rather than per vote.
//!
//! # Where the Rust departs from the Python
//!
//! - `store.blocks` is the store's live chain index, with the block table as a
//!   fallback for a root below the pruned window (see [`block`]).
//! - `store.unrealized_justifications[root]` falls back to the store's
//!   justified checkpoint for a block with no recorded value, as
//!   [`fork_choice::get_voting_source`] does, instead of raising.
//! - [`is_one_confirmed`] returns `False` for an optimistic (`NOT_VALIDATED`)
//!   block, which the specification requires in prose.
//! - [`get_slot_committee`] returns a `Vec`, not a `set`: one slot's committees
//!   are disjoint. Ranges across slots deduplicate where an epoch boundary
//!   makes that possible.
//! - A validator index past a balance source's registry counts as inactive
//!   there, where Python would raise `IndexError`.
//! - `get_root_confirmed_before_restart` is the root the previous process
//!   persisted ([`Store::take_fast_confirmation_restart_root`]).

use std::cell::{OnceCell, RefCell};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use ethlambda_storage::Store;
pub use ethlambda_types::beacon::fork_choice::FastConfirmationVariables;

use crate::beacon::committees::EpochCommittees;
use crate::beacon::config::Config;
use crate::beacon::containers::{BeaconState, Checkpoint};
use crate::beacon::error::{Error, Result, verify};
use crate::beacon::fork_choice::{
    self, ForkChoiceNode, ForkRules, LatestMessage, PayloadStatus, compute_slots_since_epoch_start,
};
use crate::beacon::helpers::accessors::{CommitteeCacheExt, get_current_epoch};
use crate::beacon::helpers::misc::{compute_epoch_at_slot, compute_start_slot_at_epoch};
use crate::beacon::helpers::predicates::is_active_validator;
use crate::beacon::preset;
use crate::beacon::primitives::{Epoch, Gwei, Root, Slot, ValidatorIndex};

/// Assumed maximum percentage of Byzantine validators among the validator set.
/// Not read from `config.yaml`: the key is not a [`Config`] field, and the
/// specification caps it at this same value.
pub const CONFIRMATION_BYZANTINE_THRESHOLD: u64 = 25;

// ---------------------------------------------------------------------------
// FastConfirmationStore
// ---------------------------------------------------------------------------

/// `FastConfirmationStore`: the rule's variables around a read-only view of
/// the fork-choice [`Store`], plus the per-run memo described in the module
/// documentation.
///
/// `head` is `get_head(store).root`, computed by the caller once and fixed for
/// the run: nothing the rule does moves it.
pub struct FastConfirmationStore<'a> {
    pub store: &'a Store,
    pub config: &'a Config,
    pub confirmed_root: Root,
    pub previous_epoch_observed_justified_checkpoint: Checkpoint,
    pub current_epoch_observed_justified_checkpoint: Checkpoint,
    pub previous_epoch_greatest_unrealized_checkpoint: Checkpoint,
    pub previous_slot_head: Root,
    pub current_slot_head: Root,
    run: RunContext,
}

impl<'a> FastConfirmationStore<'a> {
    /// A store around `variables`, for a run whose head is `head`.
    pub fn new(
        store: &'a Store,
        config: &'a Config,
        variables: FastConfirmationVariables,
        head: Root,
    ) -> Self {
        Self {
            store,
            config,
            confirmed_root: variables.confirmed_root,
            previous_epoch_observed_justified_checkpoint: variables
                .previous_epoch_observed_justified_checkpoint,
            current_epoch_observed_justified_checkpoint: variables
                .current_epoch_observed_justified_checkpoint,
            previous_epoch_greatest_unrealized_checkpoint: variables
                .previous_epoch_greatest_unrealized_checkpoint,
            previous_slot_head: variables.previous_slot_head,
            current_slot_head: variables.current_slot_head,
            run: RunContext::new(store, config, head),
        }
    }

    /// The variables to carry to the next run.
    pub fn variables(&self) -> FastConfirmationVariables {
        FastConfirmationVariables {
            confirmed_root: self.confirmed_root,
            previous_epoch_observed_justified_checkpoint: self
                .previous_epoch_observed_justified_checkpoint,
            current_epoch_observed_justified_checkpoint: self
                .current_epoch_observed_justified_checkpoint,
            previous_epoch_greatest_unrealized_checkpoint: self
                .previous_epoch_greatest_unrealized_checkpoint,
            previous_slot_head: self.previous_slot_head,
            current_slot_head: self.current_slot_head,
        }
    }

    /// `get_head(store).root`, fixed for the run.
    pub fn head(&self) -> Root {
        self.run.head
    }

    /// `get_current_slot(store)`.
    pub fn current_slot(&self) -> Slot {
        self.run.current_slot
    }

    /// `get_current_store_epoch(store)`.
    pub fn current_epoch(&self) -> Epoch {
        self.run.current_epoch
    }
}

/// Which state a [`BalanceSource`] was built from, which is also its memo key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum BalanceKey {
    /// `store.checkpoint_states[checkpoint]`.
    Checkpoint(Epoch, Root),
    /// `get_pulled_up_head_state(store)`.
    PulledUpHead,
}

impl BalanceKey {
    fn of(checkpoint: Checkpoint) -> Self {
        BalanceKey::Checkpoint(checkpoint.epoch, checkpoint.root)
    }
}

/// A registry flattened for the rule's sums, built in one pass over a state's
/// validators.
///
/// Every sum the specification takes over a balance source is a sum of
/// effective balances over validators that are active at the state's epoch,
/// and, for most, unslashed. A validator that fails the condition contributes
/// zero, so the two arrays below are all a sum needs, and "is this validator
/// in the set" never has to be asked on its own: an active validator with a
/// zero effective balance contributes the same zero either way.
pub struct BalanceSource {
    key: BalanceKey,
    /// Effective balance if active at the state's epoch, else zero (slashed
    /// validators included).
    active: Vec<Gwei>,
    /// Effective balance if active and not slashed, else zero.
    unslashed: Vec<Gwei>,
    /// The sum of `active`, before `get_total_balance`'s floor.
    total_active: Gwei,
    /// The sum of `unslashed`, before `get_total_balance`'s floor.
    total_unslashed: Gwei,
}

impl BalanceSource {
    fn build(key: BalanceKey, state: &BeaconState) -> Self {
        let epoch = get_current_epoch(state);
        let mut active = Vec::with_capacity(state.validator_count());
        let mut unslashed = Vec::with_capacity(state.validator_count());
        let (mut total_active, mut total_unslashed) = (0u64, 0u64);
        for validator in state.iter_validators() {
            let balance = if is_active_validator(validator, epoch) {
                validator.effective_balance
            } else {
                0
            };
            let unslashed_balance = if validator.slashed { 0 } else { balance };
            total_active = total_active.saturating_add(balance);
            total_unslashed = total_unslashed.saturating_add(unslashed_balance);
            active.push(balance);
            unslashed.push(unslashed_balance);
        }
        Self {
            key,
            active,
            unslashed,
            total_active,
            total_unslashed,
        }
    }

    fn active(&self, index: ValidatorIndex) -> Gwei {
        self.active.get(index as usize).copied().unwrap_or(0)
    }

    fn unslashed(&self, index: ValidatorIndex) -> Gwei {
        self.unslashed.get(index as usize).copied().unwrap_or(0)
    }
}

/// What one run computes once and every function after it reads. Interior
/// mutability so the specification's `&store`-shaped functions stay `&`.
struct RunContext {
    head: Root,
    current_slot: Slot,
    current_epoch: Epoch,
    rules: ForkRules,
    /// `root -> (slot, parent_root)` of the live chain.
    index: HashMap<Root, (Slot, Root)>,
    /// `store.equivocating_indices`, as one snapshot.
    equivocating: HashSet<ValidatorIndex>,
    head_state: OnceCell<Arc<BeaconState>>,
    pulled_up_head_state: OnceCell<Arc<BeaconState>>,
    committees: RefCell<HashMap<Epoch, Arc<EpochCommittees>>>,
    slot_committees: RefCell<HashMap<Slot, Arc<Vec<ValidatorIndex>>>>,
    sources: RefCell<HashMap<BalanceKey, Arc<BalanceSource>>>,
    scores: RefCell<HashMap<BalanceKey, Arc<HashMap<Root, Gwei>>>>,
    slot_weights: RefCell<HashMap<(BalanceKey, Slot), Gwei>>,
    range_weights: RefCell<HashMap<(BalanceKey, Slot, Slot), Gwei>>,
    equivocation_scores: RefCell<HashMap<(BalanceKey, Slot, Slot), Gwei>>,
}

impl RunContext {
    fn new(store: &Store, config: &Config, head: Root) -> Self {
        let current_slot = fork_choice::get_current_slot(store, config);
        let current_epoch = compute_epoch_at_slot(current_slot);
        Self {
            head,
            current_slot,
            current_epoch,
            rules: ForkRules::of(config.fork_at_epoch(current_epoch)),
            index: store.block_index(),
            equivocating: store.equivocating_indices(),
            head_state: OnceCell::new(),
            pulled_up_head_state: OnceCell::new(),
            committees: RefCell::default(),
            slot_committees: RefCell::default(),
            sources: RefCell::default(),
            scores: RefCell::default(),
            slot_weights: RefCell::default(),
            range_weights: RefCell::default(),
            equivocation_scores: RefCell::default(),
        }
    }
}

/// `get_fast_confirmation_store`: every variable at the finalized checkpoint.
///
/// Conservative: the confirmed block is advanced at the first epoch boundary
/// whose starting conditions hold, and until then the finalized block is the
/// confirmed one.
pub fn get_fast_confirmation_store<'a>(
    store: &'a Store,
    config: &'a Config,
    head: Root,
) -> FastConfirmationStore<'a> {
    let variables = FastConfirmationVariables::at_finalized(store.beacon_finalized_checkpoint());
    FastConfirmationStore::new(store, config, variables, head)
}

// ---------------------------------------------------------------------------
// Misc helper functions
// ---------------------------------------------------------------------------

/// `get_node_for_root`, with gloas's modification: a gloas node is `PENDING`,
/// matching either payload branch of the block. Pre-gloas nodes carry
/// [`PayloadStatus::Full`], as everywhere in this crate's fork choice.
pub fn get_node_for_root(fcr_store: &FastConfirmationStore, block_root: Root) -> ForkChoiceNode {
    let payload_status = match fcr_store.run.rules {
        ForkRules::PreGloas => PayloadStatus::Full,
        ForkRules::Gloas => PayloadStatus::Pending,
    };
    ForkChoiceNode {
        root: block_root,
        payload_status,
    }
}

/// `store.blocks[root]`, as `(slot, parent_root)`.
///
/// The live chain index first; the block table for a root below the window the
/// index prunes (a checkpoint older than the finalized block), which is rare
/// and costs a block decode.
fn block(fcr_store: &FastConfirmationStore, root: Root) -> Result<(Slot, Root)> {
    if let Some(entry) = fcr_store.run.index.get(&root) {
        return Ok(*entry);
    }
    fcr_store
        .store
        .block_entry(&root)
        .ok_or(Error::SpecAssert("block_root in store.blocks"))
}

/// `get_block_slot`.
pub fn get_block_slot(fcr_store: &FastConfirmationStore, block_root: Root) -> Result<Slot> {
    Ok(block(fcr_store, block_root)?.0)
}

/// `get_block_epoch`.
pub fn get_block_epoch(fcr_store: &FastConfirmationStore, block_root: Root) -> Result<Epoch> {
    Ok(compute_epoch_at_slot(get_block_slot(
        fcr_store, block_root,
    )?))
}

/// `get_ancestor` of `root` at `slot`, as a root: the pre-gloas rule, which
/// gloas's payload-aware version reduces to once the payload status is
/// dropped (its descent picks the next root by block slot alone).
fn get_ancestor_root(fcr_store: &FastConfirmationStore, root: Root, slot: Slot) -> Result<Root> {
    let mut root = root;
    loop {
        let (block_slot, parent_root) = block(fcr_store, root)?;
        if block_slot > slot {
            root = parent_root;
        } else {
            return Ok(root);
        }
    }
}

/// `is_ancestor` between two `get_node_for_root` nodes.
///
/// Every call in this module passes a [`get_node_for_root`] node as
/// `ancestor`: under gloas that is `PENDING`, the wildcard, for which the
/// payload-aware `is_ancestor` reduces to this root comparison.
fn is_ancestor(
    fcr_store: &FastConfirmationStore,
    node_root: Root,
    ancestor_root: Root,
) -> Result<bool> {
    let ancestor_slot = get_block_slot(fcr_store, ancestor_root)?;
    Ok(get_ancestor_root(fcr_store, node_root, ancestor_slot)? == ancestor_root)
}

/// `get_checkpoint_for_block`: the checkpoint at `epoch` in the chain of
/// `block_root`.
pub fn get_checkpoint_for_block(
    fcr_store: &FastConfirmationStore,
    block_root: Root,
    epoch: Epoch,
) -> Result<Checkpoint> {
    Ok(Checkpoint {
        epoch,
        root: get_ancestor_root(fcr_store, block_root, compute_start_slot_at_epoch(epoch))?,
    })
}

/// `get_current_target`: the current epoch's target on the head's chain.
pub fn get_current_target(fcr_store: &FastConfirmationStore) -> Result<Checkpoint> {
    get_checkpoint_for_block(fcr_store, fcr_store.run.head, fcr_store.run.current_epoch)
}

/// `is_start_slot_at_epoch`.
pub fn is_start_slot_at_epoch(slot: Slot) -> bool {
    compute_slots_since_epoch_start(slot) == 0
}

/// `get_ancestor_roots`: ancestors of `block_root`, itself included, down to
/// but excluding `terminal_root`, oldest first. Empty if `terminal_root` is
/// not on `block_root`'s chain.
pub fn get_ancestor_roots(
    fcr_store: &FastConfirmationStore,
    block_root: Root,
    terminal_root: Root,
) -> Result<Vec<Root>> {
    let terminal_slot = get_block_slot(fcr_store, terminal_root)?;
    let mut root = block_root;
    let mut ancestor_roots = Vec::new();
    loop {
        let (slot, parent_root) = block(fcr_store, root)?;
        if slot <= terminal_slot {
            // Terminal root not reached on this chain.
            return Ok(Vec::new());
        }
        ancestor_roots.push(root);
        root = parent_root;
        if root == terminal_root {
            ancestor_roots.reverse();
            return Ok(ancestor_roots);
        }
    }
}

// ---------------------------------------------------------------------------
// State helpers
// ---------------------------------------------------------------------------

/// The head's post-state, `store.block_states[head]`.
fn head_state(fcr_store: &FastConfirmationStore) -> Result<Arc<BeaconState>> {
    if let Some(state) = fcr_store.run.head_state.get() {
        return Ok(Arc::clone(state));
    }
    let state = fcr_store
        .store
        .get_state(&fcr_store.run.head)
        .expect("get")
        .ok_or(Error::SpecAssert("head in store.block_states"))?;
    let _ = fcr_store.run.head_state.set(Arc::clone(&state));
    Ok(state)
}

/// `epoch`'s committees as the head's state names them, from the store's
/// shared cache and memoized for the run.
fn epoch_committees(
    fcr_store: &FastConfirmationStore,
    epoch: Epoch,
) -> Result<Arc<EpochCommittees>> {
    if let Some(committees) = fcr_store.run.committees.borrow().get(&epoch) {
        return Ok(Arc::clone(committees));
    }
    let state = head_state(fcr_store)?;
    let committees = fcr_store.store.committee_cache().committees(&state, epoch);
    fcr_store
        .run
        .committees
        .borrow_mut()
        .insert(epoch, Arc::clone(&committees));
    Ok(committees)
}

/// `get_slot_committee`: participants of all committees in `slot`.
///
/// Supports every epoch from `current_epoch - 2`, the farthest the rule asks
/// for. A `Vec` rather than a set: the committees of one slot are disjoint.
pub fn get_slot_committee(
    fcr_store: &FastConfirmationStore,
    slot: Slot,
) -> Result<Arc<Vec<ValidatorIndex>>> {
    if let Some(participants) = fcr_store.run.slot_committees.borrow().get(&slot) {
        return Ok(Arc::clone(participants));
    }
    let committees = epoch_committees(fcr_store, compute_epoch_at_slot(slot))?;
    let mut participants = Vec::new();
    for index in 0..committees.committees_per_slot() {
        participants.extend_from_slice(committees.committee(slot, index)?);
    }
    let participants = Arc::new(participants);
    fcr_store
        .run
        .slot_committees
        .borrow_mut()
        .insert(slot, Arc::clone(&participants));
    Ok(participants)
}

/// Participants of the committees of every slot in `[start_slot, end_slot]`,
/// each validator once.
///
/// Inside one epoch the slots' committees are disjoint, so they concatenate;
/// across an epoch boundary a validator can sit in both epochs' committees,
/// and the specification's `set` is replaced by a bitmap.
fn participants_between_slots(
    fcr_store: &FastConfirmationStore,
    start_slot: Slot,
    end_slot: Slot,
) -> Result<Vec<ValidatorIndex>> {
    let mut participants = Vec::new();
    if start_slot > end_slot {
        return Ok(participants);
    }
    let crosses_epochs = compute_epoch_at_slot(start_slot) != compute_epoch_at_slot(end_slot);
    let mut seen: Vec<u64> = Vec::new();
    for slot in start_slot..=end_slot {
        for &index in get_slot_committee(fcr_store, slot)?.iter() {
            if crosses_epochs {
                let (word, bit) = ((index / 64) as usize, index % 64);
                if seen.len() <= word {
                    seen.resize(word + 1, 0);
                }
                if seen[word] & (1 << bit) != 0 {
                    continue;
                }
                seen[word] |= 1 << bit;
            }
            participants.push(index);
        }
    }
    Ok(participants)
}

/// `get_pulled_up_head_state`: the head's state, advanced to the current
/// epoch's first slot if it is from an earlier epoch.
///
/// Read through `checkpoint_state` for `(current_epoch, head)`, which is
/// exactly that advance, so a state the epoch precompute already built is
/// reused rather than replayed.
pub fn get_pulled_up_head_state(fcr_store: &FastConfirmationStore) -> Result<Arc<BeaconState>> {
    if let Some(state) = fcr_store.run.pulled_up_head_state.get() {
        return Ok(Arc::clone(state));
    }
    let head_state = head_state(fcr_store)?;
    let state = if get_current_epoch(&head_state) < fcr_store.run.current_epoch {
        let checkpoint = Checkpoint {
            epoch: fcr_store.run.current_epoch,
            root: fcr_store.run.head,
        };
        fork_choice::checkpoint_state(fcr_store.store, &checkpoint, fcr_store.config)?
    } else {
        head_state
    };
    let _ = fcr_store.run.pulled_up_head_state.set(Arc::clone(&state));
    Ok(state)
}

/// The flattened registry of `key`'s state, built once per run.
fn balance_source(
    fcr_store: &FastConfirmationStore,
    key: BalanceKey,
) -> Result<Arc<BalanceSource>> {
    if let Some(source) = fcr_store.run.sources.borrow().get(&key) {
        return Ok(Arc::clone(source));
    }
    let state = match key {
        BalanceKey::Checkpoint(epoch, root) => fork_choice::checkpoint_state(
            fcr_store.store,
            &Checkpoint { epoch, root },
            fcr_store.config,
        )?,
        BalanceKey::PulledUpHead => get_pulled_up_head_state(fcr_store)?,
    };
    let source = Arc::new(BalanceSource::build(key, &state));
    fcr_store
        .run
        .sources
        .borrow_mut()
        .insert(key, Arc::clone(&source));
    Ok(source)
}

/// `get_previous_balance_source`: the state of the previous epoch's observed
/// justified checkpoint.
fn get_previous_balance_source(fcr_store: &FastConfirmationStore) -> Result<Arc<BalanceSource>> {
    balance_source(
        fcr_store,
        BalanceKey::of(fcr_store.previous_epoch_observed_justified_checkpoint),
    )
}

/// `get_current_balance_source`: the state of the current epoch's observed
/// justified checkpoint.
fn get_current_balance_source(fcr_store: &FastConfirmationStore) -> Result<Arc<BalanceSource>> {
    balance_source(
        fcr_store,
        BalanceKey::of(fcr_store.current_epoch_observed_justified_checkpoint),
    )
}

/// `get_total_balance(source, indices)`'s floor: at least one
/// `EFFECTIVE_BALANCE_INCREMENT`, so no caller divides by zero.
fn total_balance(sum: Gwei) -> Gwei {
    sum.max(preset::EFFECTIVE_BALANCE_INCREMENT)
}

/// `get_total_active_balance(balance_source)`.
fn get_total_active_balance(balance_source: &BalanceSource) -> Gwei {
    total_balance(balance_source.total_active)
}

/// `compute_proposer_score(balance_source)`.
fn compute_proposer_score(
    fcr_store: &FastConfirmationStore,
    balance_source: &BalanceSource,
) -> Gwei {
    fork_choice::committee_fraction(
        total_balance(balance_source.total_unslashed),
        fcr_store.config.proposer_score_boost,
    )
}

/// `current_slot - 1`, which the specification computes on a `Uint64` and so
/// raises at slot zero.
fn previous_slot(fcr_store: &FastConfirmationStore) -> Result<Slot> {
    fcr_store
        .run
        .current_slot
        .checked_sub(1)
        .ok_or(Error::ArithmeticOverflow("current_slot - 1"))
}

// ---------------------------------------------------------------------------
// LMD-GHOST helpers
// ---------------------------------------------------------------------------

/// Whether `message` supports `node`, the equality in
/// `get_supported_node(store, message) == node`.
///
/// Before gloas a node is a bare root. Under gloas the root is compared first,
/// which settles all but the votes for the block itself, and only those pay
/// for `get_supported_node`'s payload branch.
fn supports_node(
    fcr_store: &FastConfirmationStore,
    message: LatestMessage,
    node: ForkChoiceNode,
) -> Result<bool> {
    if message.root != node.root {
        return Ok(false);
    }
    match fcr_store.run.rules {
        ForkRules::PreGloas => Ok(true),
        ForkRules::Gloas => Ok(fork_choice::get_supported_node(fcr_store.store, message)? == node),
    }
}

/// `get_node_support_between_slots`: support of `node` by validators assigned
/// to the slots in `[start_slot, end_slot]`, unslashed and active in
/// `balance_source`, excluding equivocators.
pub fn get_node_support_between_slots(
    fcr_store: &FastConfirmationStore,
    balance_source: &BalanceSource,
    node: ForkChoiceNode,
    start_slot: Slot,
    end_slot: Slot,
) -> Result<Gwei> {
    let mut support: Gwei = 0;
    for index in participants_between_slots(fcr_store, start_slot, end_slot)? {
        let balance = balance_source.unslashed(index);
        if balance == 0 || fcr_store.run.equivocating.contains(&index) {
            continue;
        }
        let Some(message) = fcr_store.store.latest_message(index) else {
            continue;
        };
        if supports_node(fcr_store, message, node)? {
            support = support.saturating_add(balance);
        }
    }
    Ok(support)
}

/// `is_full_validator_set_covered`: whether `[start_slot, end_slot]` includes
/// an entire epoch.
pub fn is_full_validator_set_covered(start_slot: Slot, end_slot: Slot) -> bool {
    let start_full_epoch = compute_epoch_at_slot(start_slot + preset::SLOTS_PER_EPOCH - 1);
    let end_full_epoch = compute_epoch_at_slot(end_slot + 1);
    start_full_epoch < end_full_epoch
}

/// The weight of one slot's committees in `balance_source`, memoized.
fn slot_committee_weight(
    fcr_store: &FastConfirmationStore,
    balance_source: &BalanceSource,
    slot: Slot,
) -> Result<Gwei> {
    let key = (balance_source.key, slot);
    if let Some(weight) = fcr_store.run.slot_weights.borrow().get(&key) {
        return Ok(*weight);
    }
    let weight = get_slot_committee(fcr_store, slot)?
        .iter()
        .fold(0, |sum: Gwei, &index| {
            sum.saturating_add(balance_source.active(index))
        });
    fcr_store.run.slot_weights.borrow_mut().insert(key, weight);
    Ok(weight)
}

/// `compute_committee_weight_between_slots`: total weight of the committees
/// of `[start_slot, end_slot]`.
pub fn compute_committee_weight_between_slots(
    fcr_store: &FastConfirmationStore,
    balance_source: &BalanceSource,
    start_slot: Slot,
    end_slot: Slot,
) -> Result<Gwei> {
    // Sanity check
    if start_slot > end_slot {
        return Ok(0);
    }

    // If an entire epoch is covered by the range, return the total active balance
    if is_full_validator_set_covered(start_slot, end_slot) {
        return Ok(get_total_active_balance(balance_source));
    }

    let key = (balance_source.key, start_slot, end_slot);
    if let Some(weight) = fcr_store.run.range_weights.borrow().get(&key) {
        return Ok(*weight);
    }

    // Validators assigned to committees of the range that are active in the
    // balance source; `active` is zero for the others.
    let weight = if compute_epoch_at_slot(start_slot) == compute_epoch_at_slot(end_slot) {
        let mut sum: Gwei = 0;
        for slot in start_slot..=end_slot {
            sum = sum.saturating_add(slot_committee_weight(fcr_store, balance_source, slot)?);
        }
        sum
    } else {
        participants_between_slots(fcr_store, start_slot, end_slot)?
            .into_iter()
            .fold(0, |sum: Gwei, index| {
                sum.saturating_add(balance_source.active(index))
            })
    };
    let weight = total_balance(weight);
    fcr_store.run.range_weights.borrow_mut().insert(key, weight);
    Ok(weight)
}

/// `get_equivocation_score`: total weight of the equivocating participants of
/// the committees of `[start_slot, end_slot]`.
///
/// Like the specification, it does not look in `balance_source` for slashed
/// validators: those are very likely already equivocators.
pub fn get_equivocation_score(
    fcr_store: &FastConfirmationStore,
    balance_source: &BalanceSource,
    start_slot: Slot,
    end_slot: Slot,
) -> Result<Gwei> {
    // The common case: nobody has equivocated, and there is nothing to intersect.
    if fcr_store.run.equivocating.is_empty() {
        return Ok(0);
    }
    let key = (balance_source.key, start_slot, end_slot);
    if let Some(score) = fcr_store.run.equivocation_scores.borrow().get(&key) {
        return Ok(*score);
    }
    let score = participants_between_slots(fcr_store, start_slot, end_slot)?
        .into_iter()
        .filter(|index| fcr_store.run.equivocating.contains(index))
        .fold(0, |sum: Gwei, index| {
            sum.saturating_add(balance_source.active(index))
        });
    fcr_store
        .run
        .equivocation_scores
        .borrow_mut()
        .insert(key, score);
    Ok(score)
}

/// `compute_adversarial_weight`: the most weight that can be adversarial in
/// the committees of `[start_slot, end_slot]`, assuming
/// [`CONFIRMATION_BYZANTINE_THRESHOLD`] and discounting equivocators.
pub fn compute_adversarial_weight(
    fcr_store: &FastConfirmationStore,
    balance_source: &BalanceSource,
    start_slot: Slot,
    end_slot: Slot,
) -> Result<Gwei> {
    let maximum_weight =
        compute_committee_weight_between_slots(fcr_store, balance_source, start_slot, end_slot)?;
    let max_adversarial_weight = maximum_weight / 100 * CONFIRMATION_BYZANTINE_THRESHOLD;

    // Discount total weight of equivocating validators
    let equivocation_score =
        get_equivocation_score(fcr_store, balance_source, start_slot, end_slot)?;
    Ok(max_adversarial_weight.saturating_sub(equivocation_score))
}

/// `get_adversarial_weight`: the most adversarial weight that can support the
/// block.
pub fn get_adversarial_weight(
    fcr_store: &FastConfirmationStore,
    balance_source: &BalanceSource,
    block_root: Root,
) -> Result<Gwei> {
    let current_slot_minus_one = previous_slot(fcr_store)?;
    let (block_slot, parent_root) = block(fcr_store, block_root)?;
    if get_block_epoch(fcr_store, block_root)? > get_block_epoch(fcr_store, parent_root)? {
        // Use the first epoch slot as the start slot when crossing epoch boundary
        let start_slot = compute_start_slot_at_epoch(get_block_epoch(fcr_store, block_root)?);
        compute_adversarial_weight(
            fcr_store,
            balance_source,
            start_slot,
            current_slot_minus_one,
        )
    } else {
        compute_adversarial_weight(
            fcr_store,
            balance_source,
            block_slot,
            current_slot_minus_one,
        )
    }
}

/// `compute_empty_slot_support_discount`: weight that can be discounted from
/// the safety threshold when empty slots precede the block.
pub fn compute_empty_slot_support_discount(
    fcr_store: &FastConfirmationStore,
    balance_source: &BalanceSource,
    block_root: Root,
) -> Result<Gwei> {
    let (block_slot, parent_root) = block(fcr_store, block_root)?;
    let (parent_slot, _) = block(fcr_store, parent_root)?;
    // No empty slot
    if parent_slot + 1 == block_slot {
        return Ok(0);
    }

    // Discount votes supporting the parent block if they are from the committees of empty slots.
    // Gloas's `get_ancestor` names the parent node by the payload branch this block builds on;
    // before it the node is the bare root.
    let parent_node = match fcr_store.run.rules {
        ForkRules::Gloas => fork_choice::gloas_get_ancestor(
            fcr_store.store,
            get_node_for_root(fcr_store, block_root),
            parent_slot,
        )?,
        ForkRules::PreGloas => ForkChoiceNode {
            root: get_ancestor_root(fcr_store, block_root, parent_slot)?,
            payload_status: PayloadStatus::Full,
        },
    };
    let parent_support_in_empty_slots = get_node_support_between_slots(
        fcr_store,
        balance_source,
        parent_node,
        parent_slot + 1,
        block_slot - 1,
    )?;
    // Adversarial weight is not discounted
    let adversarial_weight =
        compute_adversarial_weight(fcr_store, balance_source, parent_slot + 1, block_slot - 1)?;
    Ok(parent_support_in_empty_slots.saturating_sub(adversarial_weight))
}

/// `get_support_discount`: weight that can be discounted during the safety
/// threshold computation for the block.
pub fn get_support_discount(
    fcr_store: &FastConfirmationStore,
    balance_source: &BalanceSource,
    block_root: Root,
) -> Result<Gwei> {
    compute_empty_slot_support_discount(fcr_store, balance_source, block_root)
}

/// `compute_safety_threshold`: the LMD-GHOST safety threshold for
/// `block_root`.
pub fn compute_safety_threshold(
    fcr_store: &FastConfirmationStore,
    block_root: Root,
    balance_source: &BalanceSource,
) -> Result<Gwei> {
    let current_slot_minus_one = previous_slot(fcr_store)?;
    let (_, parent_root) = block(fcr_store, block_root)?;
    let (parent_slot, _) = block(fcr_store, parent_root)?;

    let proposer_score = compute_proposer_score(fcr_store, balance_source);
    let maximum_support = compute_committee_weight_between_slots(
        fcr_store,
        balance_source,
        parent_slot + 1,
        current_slot_minus_one,
    )?;
    let support_discount = get_support_discount(fcr_store, balance_source, block_root)?;
    let adversarial_weight = get_adversarial_weight(fcr_store, balance_source, block_root)?;

    // With precise committee weight support_discount must never exceed maximum_support
    verify(
        support_discount <= maximum_support,
        "support_discount <= maximum_support",
    )?;

    // (maximum_support + proposer_score - support_discount) // 2 + adversarial_weight
    Ok((maximum_support + proposer_score + 2 * adversarial_weight - support_discount) / 2)
}

/// `get_attestation_score(store, get_node_for_root(root), balance_source)`
/// for every block at once.
///
/// A vote counts for a block exactly when the block it supports descends from
/// it, so each vote is summed at its own block and every block's total is
/// folded into its parent, highest slot first (the fold `compute_weights`
/// does for the head). Under gloas the node is `PENDING`, which matches either
/// payload branch, so the walk is by root there too. A vote for a block
/// outside the index (pruned below finality) descends from no block scored
/// here, and the fold never reaches it.
fn attestation_scores(
    fcr_store: &FastConfirmationStore,
    balance_source: &BalanceSource,
) -> Arc<HashMap<Root, Gwei>> {
    if let Some(scores) = fcr_store.run.scores.borrow().get(&balance_source.key) {
        return Arc::clone(scores);
    }
    let mut scores: HashMap<Root, Gwei> = HashMap::new();
    // Nothing may read the store's own scratch inside this closure.
    fcr_store
        .store
        .for_each_non_equivocating_latest_message(|index, message| {
            let balance = balance_source.unslashed(index);
            if balance != 0 {
                let entry = scores.entry(message.root).or_default();
                *entry = entry.saturating_add(balance);
            }
        });

    let mut blocks: Vec<(Root, Slot, Root)> = fcr_store
        .run
        .index
        .iter()
        .map(|(root, (slot, parent_root))| (*root, *slot, *parent_root))
        .collect();
    blocks.sort_unstable_by(|left, right| right.1.cmp(&left.1).then(right.0.cmp(&left.0)));
    for (root, _slot, parent_root) in &blocks {
        let score = scores.get(root).copied().unwrap_or_default();
        if score != 0 && fcr_store.run.index.contains_key(parent_root) {
            let entry = scores.entry(*parent_root).or_default();
            *entry = entry.saturating_add(score);
        }
    }

    let scores = Arc::new(scores);
    fcr_store
        .run
        .scores
        .borrow_mut()
        .insert(balance_source.key, Arc::clone(&scores));
    scores
}

/// `get_attestation_score` of the block at `block_root` in `balance_source`.
fn get_attestation_score(
    fcr_store: &FastConfirmationStore,
    balance_source: &BalanceSource,
    block_root: Root,
) -> Gwei {
    attestation_scores(fcr_store, balance_source)
        .get(&block_root)
        .copied()
        .unwrap_or(0)
}

/// `is_one_confirmed`: whether the block is LMD-GHOST safe.
///
/// `False` for a block whose payload the execution client has not validated
/// (`NOT_VALIDATED`), as the specification requires.
pub fn is_one_confirmed(
    fcr_store: &FastConfirmationStore,
    balance_source: &BalanceSource,
    block_root: Root,
) -> Result<bool> {
    if fcr_store.store.is_beacon_optimistic(block_root) {
        return Ok(false);
    }
    let support = get_attestation_score(fcr_store, balance_source, block_root);
    let safety_threshold = compute_safety_threshold(fcr_store, block_root, balance_source)?;
    Ok(support > safety_threshold)
}

/// `is_confirmed_chain_safe`: whether every block of the confirmed chain from
/// the current epoch's observed justified checkpoint is LMD-GHOST safe.
pub fn is_confirmed_chain_safe(
    fcr_store: &FastConfirmationStore,
    confirmed_root: Root,
) -> Result<bool> {
    // Check if the confirmed_root has current_epoch_observed_justified_checkpoint in its chain
    let observed = fcr_store.current_epoch_observed_justified_checkpoint;
    if observed != get_checkpoint_for_block(fcr_store, confirmed_root, observed.epoch)? {
        return Ok(false);
    }

    let current_epoch = fcr_store.run.current_epoch;
    let start_root_exclusive = if observed.epoch + 1 >= current_epoch {
        // Exclude the justified checkpoint block if it is from the previous epoch
        // as then this block will always be canonical in this case.
        observed.root
    } else {
        // Limit reconfirmation to the first block of the previous epoch
        // as if it is successful, reconfirmation of the ancestors is implied.
        let ancestor_at_previous_epoch_start = get_ancestor_root(
            fcr_store,
            confirmed_root,
            compute_start_slot_at_epoch(current_epoch - 1),
        )?;
        if get_block_epoch(fcr_store, ancestor_at_previous_epoch_start)? + 1 == current_epoch {
            // The parent of the first block of the previous epoch
            block(fcr_store, ancestor_at_previous_epoch_start)?.1
        } else {
            // The last block of the epoch before the previous one
            ancestor_at_previous_epoch_start
        }
    };

    // Run is_one_confirmed for each block in the confirmed chain with the previous epoch balance source
    let chain_roots = get_ancestor_roots(fcr_store, confirmed_root, start_root_exclusive)?;
    let previous_balance_source = get_previous_balance_source(fcr_store)?;
    for root in chain_roots {
        if !is_one_confirmed(fcr_store, &previous_balance_source, root)? {
            return Ok(false);
        }
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// FFG helpers
// ---------------------------------------------------------------------------

/// `get_latest_message_epoch`, with gloas's modification: a gloas message is
/// dated by its slot.
fn get_latest_message_epoch(fcr_store: &FastConfirmationStore, message: &LatestMessage) -> Epoch {
    match fcr_store.run.rules {
        ForkRules::PreGloas => message.epoch,
        ForkRules::Gloas => compute_epoch_at_slot(message.slot),
    }
}

/// `get_current_target_score`: the estimate of FFG support of the current
/// epoch's target from LMD-GHOST votes. Must be used no later than the end of
/// the current epoch.
pub fn get_current_target_score(fcr_store: &FastConfirmationStore) -> Result<Gwei> {
    let target = get_current_target(fcr_store)?;
    let balance_source = balance_source(fcr_store, BalanceKey::PulledUpHead)?;

    // The weight behind each distinct `(root, epoch)` vote, so the checkpoint
    // walk below runs once per distinct vote and not once per validator.
    let mut by_vote: HashMap<(Root, Epoch), Gwei> = HashMap::new();
    fcr_store
        .store
        .for_each_non_equivocating_latest_message(|index, message| {
            let balance = balance_source.unslashed(index);
            if balance != 0 {
                let epoch = get_latest_message_epoch(fcr_store, &message);
                let entry = by_vote.entry((message.root, epoch)).or_default();
                *entry = entry.saturating_add(balance);
            }
        });

    let mut score: Gwei = 0;
    for ((root, epoch), balance) in by_vote {
        // A vote for a block this store no longer holds supports no target.
        if let Ok(checkpoint) = get_checkpoint_for_block(fcr_store, root, epoch)
            && checkpoint == target
        {
            score = score.saturating_add(balance);
        }
    }
    Ok(score)
}

/// `compute_honest_ffg_support_for_current_target`: the honest FFG support of
/// the current epoch's target, assuming [`CONFIRMATION_BYZANTINE_THRESHOLD`]
/// and synchrony, counting the votes received so far.
pub fn compute_honest_ffg_support_for_current_target(
    fcr_store: &FastConfirmationStore,
) -> Result<Gwei> {
    let current_slot = fcr_store.run.current_slot;
    let current_epoch = compute_epoch_at_slot(current_slot);
    let balance_source = balance_source(fcr_store, BalanceKey::PulledUpHead)?;
    let total_active_balance = get_total_active_balance(&balance_source);

    // Compute FFG support for the target
    let ffg_support_for_checkpoint = get_current_target_score(fcr_store)?;

    // Compute the total FFG weight up to, but excluding, the current slot
    let ffg_weight_till_now = compute_committee_weight_between_slots(
        fcr_store,
        &balance_source,
        compute_start_slot_at_epoch(current_epoch),
        previous_slot(fcr_store)?,
    )?;

    // Compute remaining honest FFG weight
    let remaining_ffg_weight = total_active_balance
        .checked_sub(ffg_weight_till_now)
        .ok_or(Error::ArithmeticOverflow(
            "total_active_balance - ffg_weight_till_now",
        ))?;
    let remaining_honest_ffg_weight =
        remaining_ffg_weight / 100 * (100 - CONFIRMATION_BYZANTINE_THRESHOLD);

    // Compute potential adversarial weight
    let adversarial_weight = compute_adversarial_weight(
        fcr_store,
        &balance_source,
        compute_start_slot_at_epoch(current_epoch),
        previous_slot(fcr_store)?,
    )?;

    // Compute min honest FFG support
    let min_honest_ffg_support = ffg_support_for_checkpoint.saturating_sub(adversarial_weight);

    Ok(min_honest_ffg_support + remaining_honest_ffg_weight)
}

/// `will_no_conflicting_checkpoint_be_justified`: whether no checkpoint
/// conflicting with the current target can ever be justified, assuming all
/// honest validators vote for the current target from now on.
pub fn will_no_conflicting_checkpoint_be_justified(
    fcr_store: &FastConfirmationStore,
) -> Result<bool> {
    // If the target is unrealized justified then no conflicting checkpoint can be justified
    if get_current_target(fcr_store)? == fcr_store.store.beacon_unrealized_justified_checkpoint() {
        return Ok(true);
    }

    let balance_source = balance_source(fcr_store, BalanceKey::PulledUpHead)?;
    let total_active_balance = get_total_active_balance(&balance_source);
    let honest_ffg_support = compute_honest_ffg_support_for_current_target(fcr_store)?;
    Ok(3 * u128::from(honest_ffg_support) > u128::from(total_active_balance))
}

/// `will_current_target_be_justified`: whether the current target will
/// eventually be justified, under the same assumption.
pub fn will_current_target_be_justified(fcr_store: &FastConfirmationStore) -> Result<bool> {
    let balance_source = balance_source(fcr_store, BalanceKey::PulledUpHead)?;
    let total_active_balance = get_total_active_balance(&balance_source);
    let honest_ffg_support = compute_honest_ffg_support_for_current_target(fcr_store)?;
    Ok(3 * u128::from(honest_ffg_support) >= 2 * u128::from(total_active_balance))
}

// ---------------------------------------------------------------------------
// The algorithm
// ---------------------------------------------------------------------------

/// `store.unrealized_justifications[root]`, falling back to the store's
/// justified checkpoint for a block with none recorded (see the module
/// documentation).
fn unrealized_justification(fcr_store: &FastConfirmationStore, root: Root) -> Checkpoint {
    fcr_store
        .store
        .unrealized_justification(&root)
        .unwrap_or_else(|| fcr_store.store.beacon_justified_checkpoint())
}

/// `fork_choice::get_voting_source` for a block of the live chain.
fn get_voting_source(fcr_store: &FastConfirmationStore, block_root: Root) -> Result<Checkpoint> {
    fork_choice::get_voting_source(
        fcr_store.store,
        &fcr_store.run.index,
        block_root,
        fcr_store.config,
    )
}

/// `update_fast_confirmation_variables`: advance the head pair and, at epoch
/// boundaries, the checkpoints. Exactly once per slot.
pub fn update_fast_confirmation_variables(fcr_store: &mut FastConfirmationStore) -> Result<()> {
    // Update prev and curr slot head
    fcr_store.previous_slot_head = fcr_store.current_slot_head;
    fcr_store.current_slot_head = fcr_store.run.head;

    let current_slot = fcr_store.run.current_slot;

    // Update greatest unrealized justified checkpoint at the last slot of an epoch
    if is_start_slot_at_epoch(current_slot + 1) {
        fcr_store.previous_epoch_greatest_unrealized_checkpoint =
            fcr_store.store.beacon_unrealized_justified_checkpoint();
    }

    // Update observed justified checkpoints at the start of an epoch
    if is_start_slot_at_epoch(current_slot) {
        fcr_store.previous_epoch_observed_justified_checkpoint =
            fcr_store.current_epoch_observed_justified_checkpoint;
        fcr_store.current_epoch_observed_justified_checkpoint =
            fcr_store.previous_epoch_greatest_unrealized_checkpoint;
    }
    Ok(())
}

/// `find_latest_confirmed_descendant`: the most recent confirmed block in the
/// suffix of the canonical chain from `latest_confirmed_root`.
///
/// Works only if `latest_confirmed_root` is canonical and from the previous or
/// current epoch.
pub fn find_latest_confirmed_descendant(
    fcr_store: &FastConfirmationStore,
    latest_confirmed_root: Root,
) -> Result<Root> {
    let head = fcr_store.run.head;
    let current_epoch = fcr_store.run.current_epoch;
    let current_slot = fcr_store.run.current_slot;
    let mut confirmed_root = latest_confirmed_root;

    let reconfirm_previous_epoch = get_block_epoch(fcr_store, confirmed_root)? + 1 == current_epoch
        && get_voting_source(fcr_store, fcr_store.previous_slot_head)?.epoch + 2 >= current_epoch
        && (is_start_slot_at_epoch(current_slot)
            || (will_no_conflicting_checkpoint_be_justified(fcr_store)?
                && (unrealized_justification(fcr_store, fcr_store.previous_slot_head).epoch + 1
                    >= current_epoch
                    || unrealized_justification(fcr_store, head).epoch + 1 >= current_epoch)));
    if reconfirm_previous_epoch {
        // Get suffix of the canonical chain
        let canonical_roots = get_ancestor_roots(fcr_store, head, confirmed_root)?;

        // Starting with the child of the latest_confirmed_root
        // move towards the head in attempt to advance the confirmed block
        // and stop when the first unconfirmed descendant is encountered
        let current_balance_source = get_current_balance_source(fcr_store)?;
        for block_root in canonical_roots {
            let block_epoch = get_block_epoch(fcr_store, block_root)?;

            // If the current epoch is reached, exit the loop
            // as this code is meant to confirm blocks from the previous epoch
            if block_epoch == current_epoch {
                break;
            }

            // The algorithm can only rely on the previous head
            // if it is a descendant of the block that is attempted to be confirmed
            if !is_ancestor(fcr_store, fcr_store.previous_slot_head, block_root)? {
                break;
            }

            if !is_one_confirmed(fcr_store, &current_balance_source, block_root)? {
                break;
            }

            confirmed_root = block_root;
        }
    }

    if is_start_slot_at_epoch(current_slot)
        || unrealized_justification(fcr_store, head).epoch + 1 >= current_epoch
    {
        // Get suffix of the canonical chain
        let canonical_roots = get_ancestor_roots(fcr_store, head, confirmed_root)?;

        let mut tentative_confirmed_root = confirmed_root;
        let current_balance_source = get_current_balance_source(fcr_store)?;

        for block_root in canonical_roots {
            let block_epoch = get_block_epoch(fcr_store, block_root)?;
            let tentative_confirmed_epoch = get_block_epoch(fcr_store, tentative_confirmed_root)?;

            // The following condition can only be true the first time
            // the algorithm advances to a block from the current epoch
            if block_epoch > tentative_confirmed_epoch {
                // To confirm blocks from the current epoch ensure that
                // current epoch target will be justified
                if !will_current_target_be_justified(fcr_store)? {
                    break;
                }
            }

            if !is_one_confirmed(fcr_store, &current_balance_source, block_root)? {
                break;
            }

            tentative_confirmed_root = block_root;
        }

        // The tentative_confirmed_root can only be confirmed
        // if it is for sure not going to be reorged out in either the current or next epoch.
        if get_block_epoch(fcr_store, tentative_confirmed_root)? == current_epoch
            || (get_voting_source(fcr_store, tentative_confirmed_root)?.epoch + 2 >= current_epoch
                && (is_start_slot_at_epoch(current_slot)
                    || will_no_conflicting_checkpoint_be_justified(fcr_store)?))
        {
            confirmed_root = tentative_confirmed_root;
        }
    }

    Ok(confirmed_root)
}

/// `get_latest_confirmed`: the most recent confirmed block, by executing the
/// FCR algorithm.
pub fn get_latest_confirmed(fcr_store: &FastConfirmationStore) -> Result<Root> {
    let store = fcr_store.store;
    let mut confirmed_root = fcr_store.confirmed_root;
    let current_epoch = fcr_store.run.current_epoch;
    let current_slot = fcr_store.run.current_slot;

    // Revert to finalized block if either of the following is true:
    // 1) the latest confirmed block's epoch is older than the previous epoch,
    // 2) the latest confirmed block does not belong to the canonical chain,
    // 3) the confirmed chain starting from the current epoch observed justified checkpoint
    //    cannot be re-confirmed at the start of the current epoch.
    let head = fcr_store.run.head;
    if get_block_epoch(fcr_store, confirmed_root)? + 1 < current_epoch
        || !is_ancestor(fcr_store, head, confirmed_root)?
        || (is_start_slot_at_epoch(current_slot)
            && !is_confirmed_chain_safe(fcr_store, confirmed_root)?)
    {
        confirmed_root = store.beacon_finalized_checkpoint().root;
    }

    // Restart the confirmation chain if each of the following conditions are true:
    // 1) it is the start of the current epoch,
    // 2) epoch of fcr_store.current_epoch_observed_justified_checkpoint.root equals to the previous epoch,
    // 3) fcr_store.current_epoch_observed_justified_checkpoint equals to unrealized justification of the head,
    // 4) confirmed block is older than the block of fcr_store.current_epoch_observed_justified_checkpoint.
    let observed = fcr_store.current_epoch_observed_justified_checkpoint;
    let is_epoch_start = is_start_slot_at_epoch(current_slot);
    let observed_justified_block_slot = get_block_slot(fcr_store, observed.root)?;
    let is_observed_justified_block_epoch_ok =
        compute_epoch_at_slot(observed_justified_block_slot) + 1 == current_epoch;
    let is_head_unrealized_justified_ok = observed == unrealized_justification(fcr_store, head);
    let is_confirmed_block_stale =
        get_block_slot(fcr_store, confirmed_root)? < observed_justified_block_slot;
    if is_epoch_start
        && is_observed_justified_block_epoch_ok
        && is_head_unrealized_justified_ok
        && is_confirmed_block_stale
    {
        confirmed_root = observed.root;
    }

    // Attempt to further advance the latest confirmed block
    if get_block_epoch(fcr_store, confirmed_root)? + 1 >= current_epoch {
        find_latest_confirmed_descendant(fcr_store, confirmed_root)
    } else {
        Ok(confirmed_root)
    }
}

/// `block_should_be_finalized`: whether a block is old enough that it has
/// either been finalized by now or finality is delayed.
pub fn block_should_be_finalized(
    fcr_store: &FastConfirmationStore,
    block_root: Root,
) -> Result<bool> {
    let block_slot = get_block_slot(fcr_store, block_root)?;
    let next_checkpoint_epoch = compute_epoch_at_slot(block_slot + preset::SLOTS_PER_EPOCH - 1);
    let earliest_finality_slot = compute_start_slot_at_epoch(next_checkpoint_epoch + 2);
    Ok(earliest_finality_slot <= fcr_store.run.current_slot)
}

/// `get_restart_resilient_confirmed_root`, given `root_before_restart` (the
/// specification's implementation-defined `get_root_confirmed_before_restart`).
///
/// Safe as long as synchrony has held for at least three epochs since the node
/// went offline. Call it once the node is synced and [`on_fast_confirmation`]
/// has run.
pub fn get_restart_resilient_confirmed_root(
    fcr_store: &FastConfirmationStore,
    root_before_restart: Root,
) -> Result<Root> {
    let root_before_restart_slot = get_block_slot(fcr_store, root_before_restart)?;

    // Recently confirmed block has advanced beyond the block that was confirmed
    // before the node restart
    if root_before_restart_slot <= get_block_slot(fcr_store, fcr_store.confirmed_root)? {
        return Ok(fcr_store.confirmed_root);
    }

    // If the block is old enough it either has been finalized already or
    // finality has been delayed which makes block confirmed before restart
    // unreliable
    if block_should_be_finalized(fcr_store, root_before_restart)? {
        return Ok(fcr_store.confirmed_root);
    }

    // If a block confirmed before the restart is not canonical,
    // return the recently confirmed block
    if !is_ancestor(fcr_store, fcr_store.run.head, root_before_restart)? {
        return Ok(fcr_store.confirmed_root);
    }

    Ok(root_before_restart)
}

/// `on_fast_confirmation`: the per-slot handler.
///
/// The call sequence is fixed by the specification: variables first, then the
/// algorithm. It must run once per slot, in the first part of the slot, after
/// attestations from past slots have been applied and before
/// `get_attestation_due_ms(epoch)` has elapsed.
pub fn on_fast_confirmation(fcr_store: &mut FastConfirmationStore) -> Result<()> {
    update_fast_confirmation_variables(fcr_store)?;
    fcr_store.confirmed_root = get_latest_confirmed(fcr_store)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

/// What one run reports: the most recent confirmed block and the slot the
/// run was for. The `fast_confirmation` event's three fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FastConfirmation {
    /// Root of the most recent confirmed block.
    pub block: Root,
    /// That block's slot.
    pub slot: Slot,
    /// The slot `store.time` is in: the run's own slot.
    pub current_slot: Slot,
}

/// Run the rule once against `store`: load its variables (starting from
/// [`get_fast_confirmation_store`] if it has none), [`on_fast_confirmation`],
/// apply the restart-resilient root on this process's first run, and write
/// the variables back.
///
/// `head` is `get_head(store).root`, which the caller has just computed. On an
/// error the stored variables are left as they were.
pub fn run_fast_confirmation(
    store: &Store,
    config: &Config,
    head: Root,
) -> Result<FastConfirmation> {
    let mut fcr_store = match store.fast_confirmation() {
        Some(variables) => FastConfirmationStore::new(store, config, variables, head),
        None => get_fast_confirmation_store(store, config, head),
    };
    on_fast_confirmation(&mut fcr_store)?;

    // Once per process, now that the node is synced and the rule has run.
    if let Some(root_before_restart) = store.take_fast_confirmation_restart_root()
        && block(&fcr_store, root_before_restart).is_ok()
    {
        fcr_store.confirmed_root =
            get_restart_resilient_confirmed_root(&fcr_store, root_before_restart)?;
    }

    let confirmed = FastConfirmation {
        block: fcr_store.confirmed_root,
        slot: get_block_slot(&fcr_store, fcr_store.confirmed_root)?,
        current_slot: fcr_store.run.current_slot,
    };
    store.set_fast_confirmation(fcr_store.variables());
    Ok(confirmed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// consensus-specs ships no FCR fixtures, so the scenarios of its pyspec tests
// (`tests/core/pyspec/.../phase0/fast_confirmation`) are ported here, on a
// fork-choice store built directly rather than through the state transition.
// The harness below stands in for the pyspec `FCRTest`: it fabricates blocks
// and their post-states, casts votes into the store's latest messages one slot
// late (as `on_attestation` applies them), and emulates the one thing a real
// state transition would supply, the FFG justification a given participation
// produces (see `Chain::justified_for_epoch` and `Chain::unrealized_for_block`).
// Every assertion that does not name FFG numbers is the pyspec one.
//
// Not ported, and why:
// - `test_fcr_current_epoch_*` and `test_fcr_previous_epoch_*` (130 generated
//   scenarios): each drives real attestations through the state transition
//   so that FFG justification, unrealized justification and late block
//   inclusion fall out of them; the emulation here covers the honest-chain
//   rule only, so these would test the emulation.
// - `test_ffg` (`will_*_be_justified` at exactly one and two thirds, and with
//   a validator activated in the head state), `test_restart_gu` and the
//   `test_revert_finality` scenarios built on late equivocations or a
//   non-descendant unrealized justification: they need exact integer
//   participation fractions and states with deposits and activations, which
//   this harness does not build.
// - The `test_reconfirmation` and `test_variables` scenarios beyond the
//   variable rotation and head tracking above, for the same reason.
// - The `test_is_one_confirmed` scenarios with large, recently activated or
//   inactive validators (they need a custom registry), and the
//   `..._with_empty_slot_and_attester_in_two_consecutive_slots`,
//   `..._precise_committee_weight` and `compute_committee_weight_between_slots`
//   vs fork-choice-weight pairs; the last are covered by the differential
//   tests against a set-based definition below.
// - The gloas scenario past its first step (see its test).

#[cfg(test)]
mod tests {
    use ethlambda_storage::backend::InMemoryBackend;

    use super::*;
    use crate::beacon::containers::{BeaconBlockHeader, SignedBeaconBlock, gloas, phase0};
    use crate::beacon::fork::ForkName;
    use crate::beacon::fork_choice::{
        get_forkchoice_store, get_head_node, on_tick, update_checkpoints,
        update_unrealized_checkpoints,
    };
    use crate::beacon::helpers::test_state;
    use crate::beacon::primitives::{ExecutionBlockHash, HashTreeRoot as _};

    const SPE: u64 = preset::SLOTS_PER_EPOCH;

    /// Validators in every test chain: 32 per slot, one committee per slot on
    /// either preset.
    fn validators() -> usize {
        (32 * SPE) as usize
    }

    fn phase0_block(slot: Slot, parent_root: Root, graffiti: Root) -> SignedBeaconBlock {
        SignedBeaconBlock::Phase0(phase0::SignedBeaconBlock {
            message: phase0::BeaconBlock {
                slot,
                proposer_index: 0,
                parent_root,
                state_root: Root::ZERO,
                body: phase0::BeaconBlockBody {
                    randao_reveal: Default::default(),
                    eth1_data: Default::default(),
                    graffiti,
                    proposer_slashings: Default::default(),
                    attester_slashings: Default::default(),
                    attestations: Default::default(),
                    deposits: Default::default(),
                    voluntary_exits: Default::default(),
                },
            },
            signature: Default::default(),
        })
    }

    /// An exact anchor pair, as `fork_choice`'s own tests build one: the state
    /// is the block's post-state, its header naming the block.
    fn anchor_pair(mut state: BeaconState) -> (BeaconState, SignedBeaconBlock) {
        let parent_root = state.latest_block_header().parent_root;
        let mut signed = phase0_block(state.slot(), parent_root, Root::ZERO);
        let SignedBeaconBlock::Phase0(inner) = &signed else {
            unreachable!("built as phase0");
        };
        *state.latest_block_header_mut() = BeaconBlockHeader {
            slot: inner.message.slot,
            proposer_index: inner.message.proposer_index,
            parent_root,
            state_root: Root::ZERO,
            body_root: inner.message.body.hash_tree_root(),
        };
        let state_root = state.hash_tree_root();
        let SignedBeaconBlock::Phase0(inner) = &mut signed else {
            unreachable!("built as phase0");
        };
        inner.message.state_root = state_root;
        (state, signed)
    }

    /// The pyspec `FCRTest`, minus the state transition.
    struct Chain {
        store: Store,
        config: Config,
        /// Template for every block's post-state.
        base: BeaconState,
        anchor_root: Root,
        anchor_slot: Slot,
        /// Participation (percent of the slot's committee) per attested slot.
        participation: HashMap<Slot, u64>,
        /// Votes cast this slot, applied by the next tick.
        pending_votes: Vec<(Vec<ValidatorIndex>, Root, Slot)>,
        rng: u64,
    }

    impl Chain {
        fn new() -> Self {
            let mut state = test_state::with_validators(validators());
            // Distinct shuffles per epoch, as a real chain's randao gives.
            for index in 0..preset::EPOCHS_PER_HISTORICAL_VECTOR {
                state.randao_mixes_mut()[index] = Root::repeat_byte(index as u8 + 1);
            }
            Self::from_state(state)
        }

        fn from_state(state: BeaconState) -> Self {
            let (anchor_state, anchor_block) = anchor_pair(state);
            let anchor_slot = anchor_state.slot();
            let anchor_root = anchor_block.message_hash_tree_root();
            let config = Config::active();
            let store = get_forkchoice_store(
                Arc::new(InMemoryBackend::new()),
                anchor_state.clone(),
                anchor_block,
                &config,
            )
            .expect("the pair matches");
            let mut chain = Self {
                store,
                config,
                base: anchor_state,
                anchor_root,
                anchor_slot,
                participation: HashMap::new(),
                pending_votes: Vec::new(),
                rng: 1,
            };
            chain.tick(anchor_slot);
            chain
        }

        fn current_slot(&self) -> Slot {
            fork_choice::get_current_slot(&self.store, &self.config)
        }

        fn current_epoch(&self) -> Epoch {
            compute_epoch_at_slot(self.current_slot())
        }

        fn head(&self) -> Root {
            get_head_node(&self.store, &self.config)
                .unwrap_or_else(|err| {
                    panic!(
                        "a head: {err}; has_block {} has_state {:?} justified {:?} unrealized {:?} slot {}",
                        self.store.has_block(&self.store.beacon_justified_checkpoint().root),
                        self.store.has_state(&self.store.beacon_justified_checkpoint().root),
                        self.store.beacon_justified_checkpoint(),
                        self.store.beacon_unrealized_justified_checkpoint(),
                        self.current_slot()
                    )
                })
                .root
        }

        fn tick(&mut self, slot: Slot) {
            on_tick(
                &mut self.store,
                slot * self.config.seconds_per_slot,
                &self.config,
            );
        }

        /// A throwaway FCR store over the current variables.
        fn fcr(&self) -> FastConfirmationStore<'_> {
            let variables = self.store.fast_confirmation().unwrap_or_else(|| {
                FastConfirmationVariables::at_finalized(self.store.beacon_finalized_checkpoint())
            });
            FastConfirmationStore::new(&self.store, &self.config, variables, self.head())
        }

        fn committee(&self, slot: Slot) -> Vec<ValidatorIndex> {
            get_slot_committee(&self.fcr(), slot)
                .expect("committee")
                .to_vec()
        }

        fn next_random(&mut self) -> u64 {
            self.rng ^= self.rng << 13;
            self.rng ^= self.rng >> 7;
            self.rng ^= self.rng << 17;
            self.rng
        }

        fn sample(
            &mut self,
            mut committee: Vec<ValidatorIndex>,
            percent: u64,
        ) -> Vec<ValidatorIndex> {
            let count = committee.len() * percent as usize / 100;
            for i in (1..committee.len()).rev() {
                let j = (self.next_random() % (i as u64 + 1)) as usize;
                committee.swap(i, j);
            }
            committee.truncate(count);
            committee
        }

        // -- FFG emulation ---------------------------------------------------

        fn epoch_start_root(&self, tip: Root, epoch: Epoch) -> Root {
            let index = self.store.block_index();
            fork_choice::get_ancestor(&index, tip, compute_start_slot_at_epoch(epoch))
                .expect("indexed")
        }

        /// Whether `epoch`'s votes, over all of its slots, reach two thirds.
        fn justified_by_end_of(&self, epoch: Epoch) -> bool {
            let start = compute_start_slot_at_epoch(epoch);
            let sum: u64 = (start..start + SPE)
                .map(|slot| self.participation.get(&slot).copied().unwrap_or(0))
                .sum();
            3 * sum >= 200 * SPE
        }

        /// The `current_justified_checkpoint` a state of `epoch` on `tip`'s
        /// chain carries: the latest epoch before it whose votes reached two
        /// thirds, else the anchor's.
        fn justified_for_epoch(&self, tip: Root, epoch: Epoch) -> Checkpoint {
            let anchor_epoch = compute_epoch_at_slot(self.anchor_slot);
            for justified in (anchor_epoch..epoch).rev() {
                if self.justified_by_end_of(justified) {
                    return Checkpoint {
                        epoch: justified,
                        root: self.epoch_start_root(tip, justified),
                    };
                }
            }
            Checkpoint {
                epoch: anchor_epoch,
                root: self.anchor_root,
            }
        }

        /// The unrealized justification of a block at `slot` on `parent`:
        /// its own epoch's target once the votes the block can include
        /// (earlier slots of the epoch) reach two thirds, else what its state
        /// has justified.
        fn unrealized_for_block(&self, parent: Root, slot: Slot) -> Checkpoint {
            let epoch = compute_epoch_at_slot(slot);
            let start = compute_start_slot_at_epoch(epoch);
            let sum: u64 = (start..slot)
                .map(|slot| self.participation.get(&slot).copied().unwrap_or(0))
                .sum();
            if slot > start && 3 * sum >= 200 * SPE {
                Checkpoint {
                    epoch,
                    root: self.epoch_start_root(parent, epoch),
                }
            } else {
                self.justified_for_epoch(parent, epoch)
            }
        }

        // -- Chain building --------------------------------------------------

        fn add_block_with(&mut self, parent: Root, slot: Slot, graffiti: Root) -> Root {
            let block = phase0_block(slot, parent, graffiti);
            let root = block.message_hash_tree_root();
            let epoch = compute_epoch_at_slot(slot);
            let justified = self.justified_for_epoch(parent, epoch);
            let unrealized = self.unrealized_for_block(parent, slot);
            let mut state = self.base.clone();
            *state.slot_mut() = slot;
            *state.current_justified_checkpoint_mut() = justified;
            // The store diffs a state against the one its own header names as
            // the parent, so the header has to be the block's.
            *state.latest_block_header_mut() = BeaconBlockHeader {
                slot,
                proposer_index: 0,
                parent_root: parent,
                state_root: Root::ZERO,
                body_root: Root::ZERO,
            };
            self.store.insert_signed_block(root, block).expect("insert");
            self.store.insert_state(root, state).expect("insert");
            self.store
                .set_unrealized_justification(root, slot, unrealized);
            let finalized_unrealized = self.store.beacon_unrealized_finalized_checkpoint();
            update_unrealized_checkpoints(&mut self.store, unrealized, finalized_unrealized);
            let finalized = self.store.beacon_finalized_checkpoint();
            update_checkpoints(&mut self.store, justified, finalized);
            root
        }

        fn add_block(&mut self, parent: Root, slot: Slot) -> Root {
            self.add_block_with(parent, slot, Root::ZERO)
        }

        /// Cast `indices`' votes for `root` at `slot`, applied by the next tick.
        fn vote(&mut self, indices: Vec<ValidatorIndex>, root: Root, slot: Slot) {
            self.pending_votes.push((indices, root, slot));
        }

        /// `FCRTest.attest`: `percent` of `slot`'s committee votes for `root`.
        fn attest(&mut self, root: Root, slot: Slot, percent: u64) {
            self.participation.insert(slot, percent);
            if percent == 0 {
                return;
            }
            let committee = self.committee(slot);
            let attesters = self.sample(committee, percent);
            self.vote(attesters, root, slot);
        }

        fn apply_votes(&mut self) {
            for (indices, root, slot) in std::mem::take(&mut self.pending_votes) {
                for index in indices {
                    let newer = self
                        .store
                        .latest_message(index)
                        .is_none_or(|message| message.slot < slot);
                    if newer {
                        self.store.set_latest_message(
                            index,
                            LatestMessage {
                                epoch: compute_epoch_at_slot(slot),
                                slot,
                                root,
                                payload_present: false,
                            },
                        );
                    }
                }
            }
        }

        fn next_slot(&mut self) {
            let slot = self.current_slot() + 1;
            self.tick(slot);
            self.apply_votes();
        }

        fn run_fcr(&mut self) -> FastConfirmation {
            let head = self.head();
            run_fast_confirmation(&self.store, &self.config, head).expect("the rule runs")
        }

        fn confirmed_root(&self) -> Root {
            self.store.fast_confirmed_root().expect("the rule has run")
        }

        /// `next_slot_with_block`: a block on `parent` (default the head) at
        /// the current slot, attested by `percent` of the slot's committee,
        /// then the next slot. The anchor's own slot gets no block.
        fn next_slot_with_block_on(&mut self, parent: Option<Root>, percent: u64) -> Root {
            let slot = self.current_slot();
            let root = if slot == self.anchor_slot {
                self.anchor_root
            } else {
                let parent = parent.unwrap_or_else(|| self.head());
                self.add_block(parent, slot)
            };
            let head = self.head();
            self.attest(head, slot, percent);
            self.next_slot();
            root
        }

        fn next_slot_with_block_and_fcr(&mut self, percent: u64) -> Root {
            let root = self.next_slot_with_block_on(None, percent);
            self.run_fcr();
            root
        }

        fn next_slot_with_block_on_and_fcr(&mut self, parent: Root, percent: u64) -> Root {
            let root = self.next_slot_with_block_on(Some(parent), percent);
            self.run_fcr();
            root
        }

        fn run_slots(&mut self, slots: u64, percent: u64) {
            for _ in 0..slots {
                self.next_slot_with_block_and_fcr(percent);
            }
        }

        /// `attest_and_next_slot_with_fast_confirmation`.
        fn attest_and_next_slot_with_fcr(&mut self, root: Option<Root>, percent: u64) {
            let slot = self.current_slot();
            let root = root.unwrap_or_else(|| self.head());
            self.attest(root, slot, percent);
            self.next_slot();
            self.run_fcr();
        }

        fn source(&self) -> Arc<BalanceSource> {
            get_current_balance_source(&self.fcr()).expect("balance source")
        }

        fn is_one_confirmed(&self, root: Root) -> bool {
            let fcr = self.fcr();
            let source = get_current_balance_source(&fcr).expect("balance source");
            is_one_confirmed(&fcr, &source, root).expect("is_one_confirmed")
        }

        fn parent_slot(&self, root: Root) -> Slot {
            let (_, parent) = self.store.block_entry(&root).expect("known");
            self.store.block_entry(&parent).expect("known parent").0
        }

        fn slot_of(&self, root: Root) -> Slot {
            self.store.block_entry(&root).expect("known").0
        }
    }

    /// The first block of a chain run through epoch 1 with full participation,
    /// where every `is_one_confirmed` scenario starts ("build through epoch 1
    /// to establish the balance source").
    fn chain_through_epoch_one() -> Chain {
        let mut chain = Chain::new();
        chain.run_slots(2 * SPE, 100);
        chain
    }

    // -- test_basic ----------------------------------------------------------

    #[test]
    fn fast_confirm_an_epoch() {
        let mut chain = Chain::new();
        for _ in 0..SPE {
            chain.next_slot_with_block_and_fcr(100);
            // Ensure head is confirmed
            assert_eq!(chain.confirmed_root(), chain.head());
        }
    }

    #[test]
    fn fast_confirm_with_low_participation() {
        let mut chain = Chain::new();
        for _ in 0..3 * SPE {
            chain.next_slot_with_block_and_fcr(90);
            // Ensure confirmed block is being advanced
            let confirmed_epoch = get_block_epoch(&chain.fcr(), chain.confirmed_root()).unwrap();
            assert!(confirmed_epoch + 1 >= chain.current_epoch());
        }
    }

    #[test]
    fn fast_confirm_with_asynchrony_at_epoch_boundary() {
        let mut chain = Chain::new();
        let first_epoch_start = chain.anchor_slot;

        // Move closer to epoch boundary
        while chain.current_slot() < first_epoch_start + SPE - 2 {
            chain.next_slot_with_block_and_fcr(100);
            assert_eq!(chain.confirmed_root(), chain.head());
        }

        // Run for a few slots with asynchrony
        while chain.current_slot() < first_epoch_start + SPE + 2 {
            chain.next_slot_with_block_and_fcr(75);
            // Confirmed block is behind the head
            assert_ne!(chain.confirmed_root(), chain.head());
        }

        // Restore participation and run for an epoch
        for _ in 0..SPE {
            chain.next_slot_with_block_and_fcr(100);
            let confirmed_epoch = get_block_epoch(&chain.fcr(), chain.confirmed_root()).unwrap();
            assert!(confirmed_epoch + 1 >= chain.current_epoch());
        }

        // After asynchrony followed by a period of good participation FCR provides 1-slot delay
        chain.next_slot_with_block_and_fcr(100);
        assert_eq!(chain.confirmed_root(), chain.head());
    }

    // -- test_is_one_confirmed ---------------------------------------------

    #[test]
    fn is_one_confirmed_passes_with_full_participation() {
        let mut chain = chain_through_epoch_one();
        let block_b = chain.next_slot_with_block_and_fcr(100);

        let parent_slot = chain.parent_slot(block_b);
        assert_eq!(parent_slot + 1, chain.slot_of(block_b), "consecutive slots");

        assert!(chain.is_one_confirmed(block_b));

        // Inspect the individual terms of the inequality
        let fcr = chain.fcr();
        let source = chain.source();
        let current_slot = chain.current_slot();
        let support = get_attestation_score(&fcr, &source, block_b);
        let proposer_score = compute_proposer_score(&fcr, &source);
        let maximum_support = compute_committee_weight_between_slots(
            &fcr,
            &source,
            parent_slot + 1,
            current_slot - 1,
        )
        .unwrap();
        let support_discount = get_support_discount(&fcr, &source, block_b).unwrap();
        let adversarial_weight = get_adversarial_weight(&fcr, &source, block_b).unwrap();

        // No empty slots, so the discount must be 0
        assert_eq!(support_discount, 0);
        let lhs = 2 * support + support_discount;
        let rhs = maximum_support + proposer_score + 2 * adversarial_weight;
        assert!(lhs > rhs, "inequality failed: lhs={lhs} vs rhs={rhs}");
    }

    #[test]
    fn is_one_confirmed_fails_with_low_participation() {
        let mut chain = chain_through_epoch_one();
        let block_b = chain.next_slot_with_block_and_fcr(50);
        assert_eq!(chain.parent_slot(block_b) + 1, chain.slot_of(block_b));

        assert!(!chain.is_one_confirmed(block_b));

        let fcr = chain.fcr();
        let source = chain.source();
        let maximum_support = compute_committee_weight_between_slots(
            &fcr,
            &source,
            chain.slot_of(block_b),
            chain.current_slot() - 1,
        )
        .unwrap();
        // Half the committee cannot outweigh the boost and the adversary.
        assert!(get_attestation_score(&fcr, &source, block_b) <= maximum_support / 2);
    }

    #[test]
    fn is_one_confirmed_support_accumulates_over_slots() {
        let mut chain = chain_through_epoch_one();
        let block_b = chain.next_slot_with_block_and_fcr(88);

        // One slot of support: the boost is too large
        assert!(!chain.is_one_confirmed(block_b));

        // A second slot of support dilutes it
        chain.attest_and_next_slot_with_fcr(Some(block_b), 88);
        assert!(chain.is_one_confirmed(block_b));
    }

    #[test]
    fn is_one_confirmed_slashing_non_supporters_helps() {
        let mut chain = chain_through_epoch_one();
        let block_b = chain.next_slot_with_block_and_fcr(88);
        let slot = chain.slot_of(block_b);

        let support_before;
        let adversarial_weight_before;
        {
            let fcr = chain.fcr();
            let source = chain.source();
            support_before = get_attestation_score(&fcr, &source, block_b);
            adversarial_weight_before = get_adversarial_weight(&fcr, &source, block_b).unwrap();
        }
        assert!(!chain.is_one_confirmed(block_b), "precondition");

        // Validators whose latest message is not for B
        let non_supporters: Vec<_> = chain
            .committee(slot)
            .into_iter()
            .filter(|&index| {
                chain
                    .store
                    .latest_message(index)
                    .is_none_or(|message| message.root != block_b)
            })
            .collect();
        assert!(!non_supporters.is_empty(), "need non-supporters to slash");
        for index in non_supporters {
            chain.store.insert_equivocating_index(index);
        }

        let fcr = chain.fcr();
        let source = chain.source();
        // Support unchanged: only non-voters were slashed
        assert_eq!(
            get_attestation_score(&fcr, &source, block_b),
            support_before
        );
        // Adversarial budget decreased
        assert!(
            get_adversarial_weight(&fcr, &source, block_b).unwrap() < adversarial_weight_before
        );
        // Slashing non-supporters helps
        assert!(is_one_confirmed(&fcr, &source, block_b).unwrap());
    }

    #[test]
    fn is_one_confirmed_slashing_supporters_does_not_hurt() {
        let mut chain = chain_through_epoch_one();
        let block_b = chain.next_slot_with_block_and_fcr(100);
        let slot = chain.slot_of(block_b);
        assert!(chain.is_one_confirmed(block_b));

        let (support_before, adversarial_before) = {
            let fcr = chain.fcr();
            let source = chain.source();
            (
                get_attestation_score(&fcr, &source, block_b),
                get_adversarial_weight(&fcr, &source, block_b).unwrap(),
            )
        };
        // One supporter equivocates: its vote leaves the support, and its
        // weight leaves the adversarial budget by the same amount.
        let supporter = chain.committee(slot)[0];
        chain.store.insert_equivocating_index(supporter);

        let fcr = chain.fcr();
        let source = chain.source();
        let balance = source.unslashed(supporter);
        assert_eq!(
            get_attestation_score(&fcr, &source, block_b),
            support_before - balance
        );
        assert_eq!(
            get_adversarial_weight(&fcr, &source, block_b).unwrap(),
            adversarial_before.saturating_sub(balance)
        );
        assert!(is_one_confirmed(&fcr, &source, block_b).unwrap());
    }

    #[test]
    fn is_one_confirmed_empty_slot_discount() {
        let mut chain = chain_through_epoch_one();

        // Block A: consecutive slot, no discount
        let block_a = chain.next_slot_with_block_and_fcr(100);
        {
            let fcr = chain.fcr();
            let source = chain.source();
            assert_eq!(get_support_discount(&fcr, &source, block_a).unwrap(), 0);
        }
        assert!(chain.is_one_confirmed(block_a));

        // Block B: after an empty slot
        let head_before_empty = chain.head();
        chain.attest_and_next_slot_with_fcr(Some(head_before_empty), 100);
        let block_b = chain.next_slot_with_block_on_and_fcr(head_before_empty, 100);

        let parent_slot = chain.parent_slot(block_b);
        let block_slot = chain.slot_of(block_b);
        assert!(parent_slot + 1 < block_slot, "an empty slot gap");

        {
            let fcr = chain.fcr();
            let source = chain.source();
            let discount = get_support_discount(&fcr, &source, block_b).unwrap();
            assert!(discount > 0);

            // discount = parent_support_in_empty_slots - adversarial_weight_in_empty_slots
            let parent_node = ForkChoiceNode {
                root: head_before_empty,
                payload_status: PayloadStatus::Full,
            };
            let parent_support = get_node_support_between_slots(
                &fcr,
                &source,
                parent_node,
                parent_slot + 1,
                block_slot - 1,
            )
            .unwrap();
            let adversarial =
                compute_adversarial_weight(&fcr, &source, parent_slot + 1, block_slot - 1).unwrap();
            assert_eq!(discount, parent_support - adversarial);
        }

        // One more slot of support, and B passes with the discount contributing
        chain.attest_and_next_slot_with_fcr(Some(block_b), 100);
        assert!(chain.is_one_confirmed(block_b));
        let fcr = chain.fcr();
        let source = chain.source();
        let discount = get_support_discount(&fcr, &source, block_b).unwrap();
        assert!(discount > 0, "the discount is still contributing");
    }

    #[test]
    fn is_one_confirmed_epoch_crossing_block() {
        let mut chain = Chain::new();
        // Most of epoch 1, to its last slot
        chain.run_slots(SPE - 1, 100);
        let parent_root = chain.head();

        // Skip the first slot of epoch 2, then propose across the boundary
        chain.attest_and_next_slot_with_fcr(Some(parent_root), 100);
        let block_b = chain.next_slot_with_block_on_and_fcr(parent_root, 100);

        let fcr = chain.fcr();
        let block_epoch = get_block_epoch(&fcr, block_b).unwrap();
        assert!(block_epoch > compute_epoch_at_slot(chain.parent_slot(block_b)));

        let source = chain.source();
        let current_slot = chain.current_slot();
        let epoch_start = compute_start_slot_at_epoch(block_epoch);
        let from_epoch_start =
            compute_adversarial_weight(&fcr, &source, epoch_start, current_slot - 1).unwrap();
        let from_block_slot =
            compute_adversarial_weight(&fcr, &source, chain.slot_of(block_b), current_slot - 1)
                .unwrap();
        // A crossing block's adversarial range starts at its epoch's first slot
        assert_eq!(
            get_adversarial_weight(&fcr, &source, block_b).unwrap(),
            from_epoch_start
        );
        assert!(from_epoch_start >= from_block_slot);
    }

    #[test]
    fn is_one_confirmed_fails_with_competing_branch() {
        let mut chain = chain_through_epoch_one();
        let fork_point = chain.head();
        let slot = chain.current_slot();
        // Two siblings at one slot; the committee splits between them
        let a = chain.add_block_with(fork_point, slot, Root::repeat_byte(0xaa));
        let b = chain.add_block_with(fork_point, slot, Root::repeat_byte(0xbb));
        let committee = chain.committee(slot);
        let (voters_a, voters_b) = committee.split_at(committee.len() / 2);
        chain.vote(voters_a.to_vec(), a, slot);
        chain.vote(voters_b.to_vec(), b, slot);
        chain.participation.insert(slot, 100);
        chain.next_slot();

        assert!(!chain.is_one_confirmed(a));
        assert!(!chain.is_one_confirmed(b));
    }

    #[test]
    fn is_one_confirmed_is_false_for_an_optimistic_block() {
        let mut chain = chain_through_epoch_one();
        let block_b = chain.next_slot_with_block_and_fcr(100);
        assert!(chain.is_one_confirmed(block_b));
        let slot = chain.slot_of(block_b);
        chain.store.insert_beacon_optimistic_root(block_b, slot);
        assert!(!chain.is_one_confirmed(block_b));
    }

    #[test]
    fn is_confirmed_chain_safe_passes_full_chain() {
        let mut chain = Chain::new();
        // Up to the first slot of epoch 2
        chain.run_slots(SPE, 100);
        assert_eq!(chain.current_slot(), compute_start_slot_at_epoch(2));
        let fcr = chain.fcr();
        assert!(is_confirmed_chain_safe(&fcr, chain.confirmed_root()).unwrap());
    }

    // -- the cached sums against the specification's own definitions -------

    /// `compute_committee_weight_between_slots`, written the way the
    /// specification writes it: a set of participants per range.
    fn naive_committee_weight(
        fcr: &FastConfirmationStore,
        source: &BalanceSource,
        start_slot: Slot,
        end_slot: Slot,
    ) -> Gwei {
        if start_slot > end_slot {
            return 0;
        }
        if is_full_validator_set_covered(start_slot, end_slot) {
            return get_total_active_balance(source);
        }
        let mut participants = HashSet::new();
        for slot in start_slot..=end_slot {
            participants.extend(get_slot_committee(fcr, slot).unwrap().iter().copied());
        }
        total_balance(
            participants
                .into_iter()
                .map(|index| source.active(index))
                .sum(),
        )
    }

    #[test]
    fn the_cached_sums_match_the_specifications_set_based_definitions() {
        let mut chain = Chain::new();
        chain.run_slots(2 * SPE + 3, 90);
        for index in (0..40).step_by(3) {
            chain.store.insert_equivocating_index(index);
        }
        let fcr = chain.fcr();
        let source = chain.source();
        let end_limit = chain.current_slot() - 1;
        let start_limit = chain.anchor_slot;

        for start in start_limit..=end_limit {
            for end in start..=end_limit {
                assert_eq!(
                    compute_committee_weight_between_slots(&fcr, &source, start, end).unwrap(),
                    naive_committee_weight(&fcr, &source, start, end),
                    "weight over [{start}, {end}]"
                );

                let mut committee = HashSet::new();
                for slot in start..=end {
                    committee.extend(get_slot_committee(&fcr, slot).unwrap().iter().copied());
                }
                let naive_equivocation: Gwei = committee
                    .iter()
                    .filter(|index| chain.store.is_equivocating(**index))
                    .map(|&index| source.active(index))
                    .sum();
                assert_eq!(
                    get_equivocation_score(&fcr, &source, start, end).unwrap(),
                    naive_equivocation,
                    "equivocation score over [{start}, {end}]"
                );
            }
        }
    }

    #[test]
    fn the_score_fold_matches_the_specifications_per_block_attestation_score() {
        let mut chain = Chain::new();
        chain.run_slots(SPE + 4, 80);
        // A fork whose votes split the committee
        let fork_point = chain.head();
        let slot = chain.current_slot();
        let a = chain.add_block_with(fork_point, slot, Root::repeat_byte(1));
        let b = chain.add_block_with(fork_point, slot, Root::repeat_byte(2));
        let committee = chain.committee(slot);
        let (voters_a, voters_b) = committee.split_at(committee.len() / 3);
        chain.vote(voters_a.to_vec(), a, slot);
        chain.vote(voters_b.to_vec(), b, slot);
        chain.next_slot();
        chain.store.insert_equivocating_index(voters_a[0]);

        let fcr = chain.fcr();
        let source = chain.source();
        let index = chain.store.block_index();
        let state = fork_choice::checkpoint_state(
            &chain.store,
            &fcr.current_epoch_observed_justified_checkpoint,
            &chain.config,
        )
        .unwrap();
        for &root in index.keys() {
            assert_eq!(
                get_attestation_score(&fcr, &source, root),
                fork_choice::get_attestation_score(&chain.store, &index, root, &state).unwrap(),
                "score of {root}"
            );
        }
    }

    // -- helpers --------------------------------------------------------------

    #[test]
    fn a_full_epoch_is_covered_and_a_partial_one_is_not() {
        assert!(is_full_validator_set_covered(0, SPE - 1));
        assert!(is_full_validator_set_covered(SPE, 2 * SPE - 1));
        assert!(!is_full_validator_set_covered(1, SPE - 1));
        assert!(!is_full_validator_set_covered(1, SPE));
        assert!(is_full_validator_set_covered(1, 2 * SPE - 1));
    }

    #[test]
    fn ancestor_roots_run_oldest_first_and_stop_before_the_terminal() {
        let mut chain = Chain::new();
        chain.run_slots(4, 100);
        let head = chain.head();
        let fcr = chain.fcr();
        let roots = get_ancestor_roots(&fcr, head, chain.anchor_root).unwrap();
        assert_eq!(roots.len(), 3, "the anchor is excluded");
        assert_eq!(*roots.last().unwrap(), head);
        let slots: Vec<_> = roots.iter().map(|&root| chain.slot_of(root)).collect();
        assert!(slots.windows(2).all(|pair| pair[0] < pair[1]));
        // The block itself, or a terminal off its chain, gives nothing
        assert!(get_ancestor_roots(&fcr, head, head).unwrap().is_empty());
        let fork = chain.add_block_with(
            chain.anchor_root,
            chain.anchor_slot + 1,
            Root::repeat_byte(9),
        );
        let fcr = chain.fcr();
        assert!(get_ancestor_roots(&fcr, head, fork).unwrap().is_empty());
    }

    // -- test_variables -------------------------------------------------------

    #[test]
    fn slot_head_variables_are_updated_every_slot() {
        let mut chain = Chain::new();
        let mut previous_head = None;
        for _ in 0..4 {
            chain.next_slot_with_block_and_fcr(100);
            let variables = chain.store.fast_confirmation().unwrap();
            assert_eq!(variables.current_slot_head, chain.head());
            if let Some(previous_head) = previous_head {
                assert_eq!(variables.previous_slot_head, previous_head);
            }
            previous_head = Some(variables.current_slot_head);
        }
    }

    #[test]
    fn observed_justified_checkpoints_rotate_at_the_start_of_an_epoch() {
        let mut chain = Chain::new();
        // To the last slot of epoch 1: the greatest unrealized checkpoint is
        // sampled by the run there.
        chain.run_slots(SPE - 1, 100);
        assert_eq!(chain.current_slot() + 1, compute_start_slot_at_epoch(2));
        let before = chain.store.fast_confirmation().unwrap();
        assert_eq!(
            before.previous_epoch_greatest_unrealized_checkpoint,
            chain.store.beacon_unrealized_justified_checkpoint()
        );

        // The first slot of epoch 2 rotates them
        chain.next_slot_with_block_and_fcr(100);
        let after = chain.store.fast_confirmation().unwrap();
        assert_eq!(
            after.previous_epoch_observed_justified_checkpoint,
            before.current_epoch_observed_justified_checkpoint
        );
        assert_eq!(
            after.current_epoch_observed_justified_checkpoint,
            before.previous_epoch_greatest_unrealized_checkpoint
        );

        // And nothing else moves them until the next boundary
        chain.next_slot_with_block_and_fcr(100);
        let later = chain.store.fast_confirmation().unwrap();
        assert_eq!(
            later.current_epoch_observed_justified_checkpoint,
            after.current_epoch_observed_justified_checkpoint
        );
        assert_eq!(
            later.previous_epoch_observed_justified_checkpoint,
            after.previous_epoch_observed_justified_checkpoint
        );
    }

    #[test]
    fn the_variables_start_at_the_finalized_checkpoint() {
        let chain = Chain::new();
        let finalized = chain.store.beacon_finalized_checkpoint();
        let fcr = get_fast_confirmation_store(&chain.store, &chain.config, chain.head());
        assert_eq!(fcr.confirmed_root, finalized.root);
        assert_eq!(fcr.previous_epoch_observed_justified_checkpoint, finalized);
        assert_eq!(fcr.current_epoch_observed_justified_checkpoint, finalized);
        assert_eq!(fcr.previous_epoch_greatest_unrealized_checkpoint, finalized);
        assert_eq!(fcr.previous_slot_head, finalized.root);
        assert_eq!(fcr.current_slot_head, finalized.root);
        assert_eq!(chain.store.fast_confirmed_root(), None, "nothing has run");
    }

    // -- test_empty_slots / test_revert_finality ----------------------------

    #[test]
    fn fcr_handles_a_single_empty_slot() {
        let mut chain = Chain::new();
        chain.run_slots(SPE / 2, 100);
        // An empty slot: everyone attests to the head, no block
        chain.attest_and_next_slot_with_fcr(None, 100);
        let head = chain.head();
        // Blocks resume after the gap and are confirmed again
        for _ in 0..4 {
            chain.next_slot_with_block_and_fcr(100);
        }
        assert_ne!(chain.head(), head);
        assert_eq!(chain.confirmed_root(), chain.head());
    }

    #[test]
    fn fcr_reverts_to_finalized_when_confirmed_is_not_canonical_mid_epoch() {
        let mut chain = Chain::new();
        chain.run_slots(SPE / 2, 100);
        let confirmed = chain.confirmed_root();
        assert_eq!(confirmed, chain.head());
        let finalized = chain.store.beacon_finalized_checkpoint().root;

        // A branch from the finalized block that every validator moves to
        let slot = chain.current_slot();
        let branch = chain.add_block_with(finalized, slot, Root::repeat_byte(0xee));
        let everyone: Vec<_> = (0..validators() as u64).collect();
        chain.vote(everyone, branch, slot);
        chain.next_slot();
        assert_eq!(chain.head(), branch, "the heavier branch is the head");

        let confirmation = chain.run_fcr();
        // The old confirmed block is off the canonical chain, so the rule
        // fell back to finalized; whatever it confirmed since is on the branch.
        let fcr = chain.fcr();
        assert!(is_ancestor(&fcr, branch, confirmation.block).unwrap());
        assert_ne!(confirmation.block, confirmed);
    }

    // -- restart resilience ---------------------------------------------------

    #[test]
    fn the_restart_resilient_root_follows_the_specifications_four_cases() {
        let mut chain = Chain::new();
        chain.run_slots(SPE / 2, 100);
        let head = chain.head();
        let fcr = chain.fcr();
        let anchor = chain.anchor_root;

        // The recently confirmed block is past the one confirmed before the restart
        assert_eq!(
            get_restart_resilient_confirmed_root(&fcr, anchor).unwrap(),
            fcr.confirmed_root
        );

        // A confirmed block that has fallen behind: the rule keeps the recent one
        let mut behind = chain.fcr();
        behind.confirmed_root = anchor;
        let mid = chain
            .store
            .block_entry(&head)
            .map(|(_, parent)| parent)
            .unwrap();
        assert_eq!(
            get_restart_resilient_confirmed_root(&behind, mid).unwrap(),
            mid,
            "a canonical block ahead of the recent one, not yet due to be final"
        );

        // A block confirmed before the restart that is not canonical
        let fork = chain.add_block_with(anchor, chain.anchor_slot + 1, Root::repeat_byte(7));
        let mut behind = chain.fcr();
        behind.confirmed_root = anchor;
        assert_eq!(
            get_restart_resilient_confirmed_root(&behind, fork).unwrap(),
            anchor
        );
    }

    #[test]
    fn a_block_should_be_finalized_two_epochs_after_its_checkpoint() {
        let mut chain = Chain::new();
        chain.run_slots(SPE / 2, 100);
        let block = chain.head();
        let fcr = chain.fcr();
        assert!(!block_should_be_finalized(&fcr, block).unwrap());

        // Far enough ahead that finality has had its two epochs
        let block_slot = chain.slot_of(block);
        let due = compute_start_slot_at_epoch(compute_epoch_at_slot(block_slot + SPE - 1) + 2);
        chain.tick(due);
        let fcr = chain.fcr();
        assert!(block_should_be_finalized(&fcr, block).unwrap());
    }

    /// A restarted process reads the confirmed root its predecessor persisted
    /// once, on its first synced run, and keeps it when it is canonical, recent
    /// and ahead of what the run itself confirms.
    #[test]
    fn the_first_synced_run_applies_the_persisted_root_once() {
        let mut chain = Chain::new();
        // A chain nobody attests to, so the run itself confirms nothing
        // beyond the finalized anchor.
        for _ in 0..SPE / 2 {
            chain.next_slot_with_block_on(None, 0);
        }
        let head = chain.head();
        let (_, parent) = chain.store.block_entry(&head).unwrap();
        let before_restart = parent;
        assert_ne!(before_restart, chain.anchor_root);

        // What the previous process left behind
        chain
            .store
            .set_fast_confirmation(FastConfirmationVariables::at_finalized(Checkpoint {
                epoch: 0,
                root: before_restart,
            }));
        chain.store.reset_fast_confirmation();

        let confirmation = chain.run_fcr();
        assert_eq!(confirmation.block, before_restart, "restored");

        // Offered once: the next run starts from what this one confirmed
        assert_eq!(chain.store.take_fast_confirmation_restart_root(), None);
    }

    #[test]
    fn without_a_persisted_root_an_unconfirmable_chain_stays_at_the_anchor() {
        let mut chain = Chain::new();
        for _ in 0..SPE / 2 {
            chain.next_slot_with_block_on(None, 0);
        }
        assert_eq!(chain.run_fcr().block, chain.anchor_root);
    }

    // -- gloas ---------------------------------------------------------------

    fn gloas_block(
        slot: Slot,
        parent_root: Root,
        parent_block_hash: ExecutionBlockHash,
        block_hash: ExecutionBlockHash,
    ) -> SignedBeaconBlock {
        SignedBeaconBlock::Gloas(gloas::SignedBeaconBlock {
            message: gloas::BeaconBlock {
                slot,
                proposer_index: 0,
                parent_root,
                state_root: Root::ZERO,
                body: gloas::BeaconBlockBody {
                    signed_execution_payload_bid: gloas::SignedExecutionPayloadBid {
                        message: gloas::ExecutionPayloadBid {
                            parent_block_hash,
                            block_hash,
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                    ..Default::default()
                },
            },
            signature: Default::default(),
        })
    }

    /// The gloas `test_is_one_confirmed_delayed_with_mixed_payload_votes_in_empty_slot`
    /// scenario, down to the term it exercises: after an empty slot, only the
    /// votes for the parent's payload branch that B builds on (FULL) count as
    /// parent support in the empty slot (the discount's first term), where
    /// pre-gloas every vote for the parent does. The scenario's later
    /// accumulation steps are not ported (no gloas chain builder here).
    #[test]
    fn gloas_empty_slot_support_counts_only_the_payload_branch_the_block_builds_on() {
        let config = Config::active().with_fork_epoch(ForkName::Gloas, 1);
        let gloas_start = compute_start_slot_at_epoch(1);
        let anchor_root = Root::repeat_byte(0xa0);
        let anchor = Checkpoint {
            epoch: 0,
            root: anchor_root,
        };
        let mut store = Store::init_beacon(
            Arc::new(InMemoryBackend::new()),
            0,
            config.clone(),
            anchor_root,
            Store::beacon_checkpoint_as_stored(anchor),
            0,
        );
        let hash = |byte| ExecutionBlockHash::repeat_byte(byte);
        let state = test_state::with_validators_at(ForkName::Gloas, validators());

        // anchor -> parent (slot s) -> [empty slot] -> block (slot s + 2),
        // block building on the parent's FULL payload.
        let parent_root = Root::repeat_byte(0xb0);
        let block_root = Root::repeat_byte(0xc0);
        let (parent_slot, block_slot) = (gloas_start, gloas_start + 2);
        for (root, signed) in [
            (
                anchor_root,
                gloas_block(0, Root::ZERO, ExecutionBlockHash::ZERO, hash(1)),
            ),
            (
                parent_root,
                gloas_block(parent_slot, anchor_root, hash(1), hash(2)),
            ),
            (
                block_root,
                gloas_block(block_slot, parent_root, hash(2), hash(3)),
            ),
        ] {
            store.insert_signed_block(root, signed).expect("insert");
            let mut post = state.clone();
            *post.slot_mut() = store.block_entry(&root).unwrap().0.max(gloas_start);
            store.insert_state(root, post).expect("insert state");
        }
        store
            .set_time_ms((block_slot + 1) * config.slot_duration_ms)
            .unwrap();

        // The empty slot's committee splits: half vote for the parent with
        // its payload, half without.
        let empty_slot = parent_slot + 1;
        let committee = {
            let variables = FastConfirmationVariables::at_finalized(anchor);
            let fcr = FastConfirmationStore::new(&store, &config, variables, block_root);
            get_slot_committee(&fcr, empty_slot).unwrap().to_vec()
        };
        let (full_voters, empty_voters) = committee.split_at(committee.len() / 2);
        for (voters, payload_present) in [(full_voters, true), (empty_voters, false)] {
            for &index in voters {
                store.set_latest_message(
                    index,
                    LatestMessage {
                        epoch: 1,
                        slot: empty_slot,
                        root: parent_root,
                        payload_present,
                    },
                );
            }
        }

        let discount_under = |config: &Config| {
            let variables = FastConfirmationVariables::at_finalized(anchor);
            let fcr = FastConfirmationStore::new(&store, config, variables, block_root);
            let source = balance_source(&fcr, BalanceKey::of(anchor)).unwrap();
            let support = get_node_support_between_slots(
                &fcr,
                &source,
                match fcr.run.rules {
                    ForkRules::Gloas => fork_choice::gloas_get_ancestor(
                        &store,
                        get_node_for_root(&fcr, block_root),
                        parent_slot,
                    )
                    .unwrap(),
                    ForkRules::PreGloas => ForkChoiceNode {
                        root: parent_root,
                        payload_status: PayloadStatus::Full,
                    },
                },
                empty_slot,
                empty_slot,
            )
            .unwrap();
            (fcr.run.rules, support)
        };

        let (rules, gloas_support) = discount_under(&config);
        assert_eq!(rules, ForkRules::Gloas);
        let (rules, pre_gloas_support) = discount_under(&Config::active());
        assert_eq!(rules, ForkRules::PreGloas);

        let state_for_weights = {
            let variables = FastConfirmationVariables::at_finalized(anchor);
            let fcr = FastConfirmationStore::new(&store, &config, variables, block_root);
            balance_source(&fcr, BalanceKey::of(anchor)).unwrap()
        };
        let full_weight: Gwei = full_voters
            .iter()
            .map(|&index| state_for_weights.unslashed(index))
            .sum();
        let all_weight: Gwei = committee
            .iter()
            .map(|&index| state_for_weights.unslashed(index))
            .sum();
        assert_eq!(gloas_support, full_weight, "only FULL votes");
        assert_eq!(pre_gloas_support, all_weight, "every vote for the parent");
        assert!(gloas_support < pre_gloas_support);
    }

    #[test]
    fn a_gloas_node_for_a_root_is_pending_and_a_pre_gloas_one_is_full() {
        let chain = Chain::new();
        let fcr = chain.fcr();
        assert_eq!(
            get_node_for_root(&fcr, chain.anchor_root).payload_status,
            PayloadStatus::Full
        );
        let gloas_config = Config::active().with_fork_epoch(ForkName::Gloas, 0);
        let variables =
            FastConfirmationVariables::at_finalized(chain.store.beacon_finalized_checkpoint());
        let fcr = FastConfirmationStore::new(&chain.store, &gloas_config, variables, chain.head());
        assert_eq!(
            get_node_for_root(&fcr, chain.anchor_root).payload_status,
            PayloadStatus::Pending
        );
    }
}
