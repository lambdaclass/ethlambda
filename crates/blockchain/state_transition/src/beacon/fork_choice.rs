//! The fork choice store: LMD GHOST, with FFG-derived justification and
//! finalization gating which branches are even eligible to be head.
//!
//! Implements `specs/phase0/fork-choice.md`, which is also every later fork's
//! fork choice through at least altair: none of them change anything here.
//! `Store` therefore accepts a block from any fork this module implements,
//! even though the algorithm applied to it is unconditionally phase0's.
//! `Store` tracks the block tree, attester votes, and the checkpoints fork
//! choice reasons about; the four handlers at the bottom of this file
//! ([`on_tick`], [`on_block`], [`on_attestation`], [`on_attester_slashing`])
//! are the only ones the specification lists as sole ways to change it,
//! matching its own framing: "Invalid calls to handlers must not modify
//! `store`." Every other function in this file takes `&Store`, with one
//! exception: [`get_head`] takes `&mut Store` too, since it records the head
//! it just computed; see its own documentation for why that write belongs
//! there rather than in a caller.
//!
//! # Units: one seconds-granularity clock, read out in milliseconds at the edges
//!
//! This module's entry points speak the specification's unit: both [`on_tick`]
//! and [`on_tick_per_slot`] take a `time: u64` in seconds, exactly like
//! `BeaconState.genesis_time`. The store underneath keeps one clock in
//! milliseconds,
//! [`Store::time_ms`](ethlambda_storage::Store::time_ms), so those two convert
//! on the way in and nothing else in this module reads the row directly:
//! `get_slots_since_genesis` and `get_current_slot` reduce to
//! [`Store::current_slot`](ethlambda_storage::Store::current_slot), and the
//! handlers that need to place a moment *within* the current slot against the
//! basis-point deadlines (`get_attestation_due_ms` and friends) read
//! [`Store::ms_since_genesis`](ethlambda_storage::Store::ms_since_genesis).
//!
//! The lean chain shares that row and those derivations, and reads it on a
//! third grid of its own, `Store::intervals_since_genesis`, which nothing here
//! touches.
//!
//! Milliseconds only appear where a handler needs to place a moment *within*
//! the current slot against the basis-point deadlines
//! (`get_attestation_due_ms` and friends, fractions of
//! `Config::slot_duration_ms`): [`seconds_to_milliseconds`] converts the
//! coarse seconds-since-genesis value at exactly that point, and nowhere else.
//! So this is not two clocks running at different rates; it is one
//! seconds-resolution clock with a millisecond-resolution read-out computed on
//! demand, purely for comparing against the sub-slot deadlines.
//!
//! # Why `Store::block_index` never needs to be a `BTreeMap`
//!
//! The one place this file iterates every block the store holds is
//! `filter_block_tree`'s scan of [`Store::block_index`](ethlambda_storage::Store::block_index)
//! for a block's children, and [`get_head`]'s equivalent scan of the tree
//! `filter_block_tree` already filtered down. Both immediately reduce that
//! scan to a single winner via an explicit, fully-ordered sort key
//! (`(weight, root)`, with `root` breaking ties the same way Python compares
//! two `bytes` values, since [`Root`]'s `Ord` compares its bytes in the same
//! order). Two distinct blocks never share a root, so that key never actually
//! ties, and the winner is the same regardless of which order the underlying
//! map happened to yield its entries in. Nothing else in this file examines a
//! map's keys as a whole, so `block_index` never needs an order of its own.
//!
//! # Signed blocks, not the specification's unsigned ones
//!
//! The specification's `store.blocks: Dict[Root, BeaconBlock]` holds the
//! unsigned message.
//! [`Store::insert_signed_block`](ethlambda_storage::Store::insert_signed_block)/
//! [`Store::get_signed_block`](ethlambda_storage::Store::get_signed_block)
//! hold [`SignedBeaconBlock`] instead: it is what every caller already has in
//! hand (a fixture case, a gossiped block, a `BlocksByRoot` response), the
//! extra signature is small next to a full body, and storage keys on the
//! *unsigned* message's root ([`SignedBeaconBlock::message_hash_tree_root`]),
//! so nothing about lookup or ancestry changes. [`get_forkchoice_store`]'s
//! `anchor_block` is signed for the same reason, even though a trusted
//! anchor's own signature is never actually checked.
//!
//! Holding the fork-generic enum here, rather than a concrete per-fork
//! struct, is what lets [`on_block`] accept a block from any fork this module
//! implements: every place in this file that reads a field off a block in hand
//! goes through the enum's shared accessors (`slot()`, `parent_root()`, and
//! so on) rather than a phase0-specific field. A block already *stored* is
//! read through [`Store::block_entry`](ethlambda_storage::Store::block_entry)
//! instead, which answers the only two fields this file ever wants of one
//! without decoding its body at all.
//!
//! # `on_block`'s execution engine
//!
//! [`stf::state_transition`] takes an [`stf::ExecutionEngine`] from bellatrix
//! on, for the one call a real client would route to its execution layer.
//! [`on_block`] always passes [`stf::ExecutionEngine::valid`]: no released
//! `fork_choice` fixture, at any fork or preset, ships an `execution.yaml` or
//! an `on_payload_info` step, so there is nothing yet for a caller to supply
//! a different answer for. `on_payload_info` is also a standing registry
//! keyed by block hash and updated over the course of a case, not a single
//! value fixed at construction time, so when a fixture exercising it does
//! arrive, threading it through will need more than a parameter on this
//! function.
//!
//! # [`Attestation`] and [`AttesterSlashing`]: a second fork-generic enum
//!
//! [`phase0::Attestation`] and [`phase0::AttesterSlashing`] keep the same
//! shape from phase0 through deneb, so [`on_attestation`] and
//! [`on_attester_slashing`] could stay phase0-typed through every fork this
//! crate implemented before electra. EIP-7549 breaks that: electra widens
//! `aggregation_bits` from one committee's worth to a whole slot's and adds
//! `committee_bits`, so [`electra::Attestation`] (and, following from it,
//! [`electra::IndexedAttestation`] and [`electra::AttesterSlashing`]) is a
//! different concrete type, not just a wider bound on the same one.
//!
//! [`Attestation`] and [`AttesterSlashing`] mirror [`SignedBeaconBlock`]'s own
//! answer to that problem: an enum over the two shapes, with two variants
//! rather than one per fork for the same reason `SignedBeaconBlock` has only
//! seven, not one per fork through fulu. But fork choice reads far less out
//! of an attestation than a block: `data.slot`, `data.target`,
//! `data.beacon_block_root`, and the attesting indices, per the module
//! documentation above. `AttestationData` (`crate::beacon::containers::shared`) is
//! already fork-invariant, so every function below except the two enums'
//! own methods reads it directly rather than matching on a fork tag it does
//! not need: [`validate_on_attestation`] and [`update_latest_messages`] take
//! `AttestationData` and a resolved `&[ValidatorIndex]`, not an
//! [`Attestation`]. The one place a fork's own shape actually matters is
//! resolving an [`Attestation`] into the attesters it names and checking
//! their aggregate signature, which needs the fork-specific
//! `get_indexed_attestation`/`is_valid_indexed_attestation` pair
//! ([`crate::beacon::helpers::attestation`] for phase0, [`crate::beacon::helpers::electra`]
//! for electra); [`Attestation::verified_attesting_indices`] and
//! [`AttesterSlashing::verified_attesting_indices`] are where that dispatch
//! happens, once, so [`on_attestation`] and [`on_attester_slashing`]
//! themselves never match on a fork at all.
//!
//! # Bellatrix's merge check, and data availability from deneb on
//!
//! [`on_block`] gains two more fork-conditional steps beyond `phase0/fork-
//! choice.md`, both because a later fork's own `fork-choice.md` modifies
//! `on_block` directly rather than leaving it to state transition:
//!
//! - Bellatrix requires a transitioning block's parent execution payload to
//!   sit on a valid terminal PoW block ([`validate_merge_block`]), checked
//!   against [`get_pow_block`] rather than a real execution client, the
//!   same way [`stf::ExecutionEngine`] stands in for one elsewhere in this
//!   crate. Capella's own `fork-choice.md` removes this check outright
//!   ("deletion of the verification of merge transition block conditions"),
//!   so it applies to bellatrix alone.
//! - Deneb, electra, and fulu each require `is_data_available` to hold
//!   before a block with blob commitments is even considered
//!   ([`is_data_available_blobs`] for deneb/electra's blob-and-proof shape,
//!   [`is_data_available_columns`] for fulu's column-sidecar shape). Both
//!   read `retrieve_blobs_and_proofs`/`retrieve_column_sidecars`'s answer out
//!   of [`DataAvailability`], a parameter on [`on_block`] rather than a
//!   `Store` field: unlike a PoW block, this evidence is scoped to the one
//!   block being considered right now, not a registry looked up by hash
//!   later. Both helpers are also "implementation and context dependent" in
//!   the specification's own words, exactly the class of thing
//!   [`stf::ExecutionEngine`] already collapses to whatever the fixture
//!   suites supply directly.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use ethlambda_storage::{CacheKey, ForkCheckpoints, StorageBackend};

use crate::beacon::config::Config;
use crate::beacon::constants;
use crate::beacon::containers::{AttestationData, BeaconState, Checkpoint, SignedBeaconBlock};
use crate::beacon::containers::{bellatrix, deneb, electra, fulu, phase0};
use crate::beacon::error::{Error, Result, verify};
use crate::beacon::helpers::accessors::{
    get_active_validator_indices, get_beacon_proposer_index, get_current_epoch,
    get_total_active_balance,
};
use crate::beacon::helpers::attestation as phase0_attestation;
use crate::beacon::helpers::electra as electra_helpers;
use crate::beacon::helpers::misc::{compute_epoch_at_slot, compute_start_slot_at_epoch};
use crate::beacon::helpers::predicates::{is_active_validator, is_slashable_attestation_data};
use crate::beacon::kzg;
use crate::beacon::lean_boundary::lean_block_unreachable;
use crate::beacon::preset;
use crate::beacon::primitives::{
    Epoch, Gwei, HashTreeRoot as _, KzgCommitment, KzgProof, Root, Slot, ValidatorIndex,
};
use crate::beacon::stf;

// ---------------------------------------------------------------------------
// LatestMessage, PowBlock
// ---------------------------------------------------------------------------

// Both live in `ethlambda-types` rather than here, because `ethlambda-storage`
// persists them and cannot depend on this crate. Re-exported at the paths they
// had when they were defined here, so [`Store`] and its callers are unchanged.
pub use ethlambda_types::beacon::fork_choice::{LatestMessage, PowBlock};

// ---------------------------------------------------------------------------
// Attestation, AttesterSlashing
// ---------------------------------------------------------------------------

/// An attestation, in whichever fork's shape it currently has. See the module
/// documentation for why this exists and what it lets the rest of this file
/// stay generic over.
///
/// Two variants, not one per fork: every fork through deneb shares
/// [`phase0::Attestation`] outright, and fulu shares [`electra::Attestation`]
/// the same way [`SignedBeaconBlock::Fulu`] shares
/// [`electra::SignedBeaconBlock`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attestation {
    Phase0(phase0::Attestation),
    Electra(electra::Attestation),
}

impl Attestation {
    /// The fork-invariant half of an attestation: everything
    /// [`validate_on_attestation`] and [`update_latest_messages`] need, which
    /// is why neither of them takes an [`Attestation`] at all.
    pub fn data(&self) -> AttestationData {
        match self {
            Attestation::Phase0(attestation) => attestation.data,
            Attestation::Electra(attestation) => attestation.data,
        }
    }

    /// The attesters this attestation names, once its aggregate signature and
    /// index ordering have both been checked against `state`.
    ///
    /// The one place this enum's two shapes actually matter: building the
    /// indexed form and checking it needs the fork-specific
    /// `get_indexed_attestation`/`is_valid_indexed_attestation` pair, so this
    /// dispatches once here rather than leaving that match to every caller.
    pub fn verified_attesting_indices(&self, state: &BeaconState) -> Result<Vec<ValidatorIndex>> {
        self.indices(state, true)
    }

    /// The attesters this attestation names, taking `state`'s word for the
    /// committees and checking nothing else.
    ///
    /// Only sound for an attestation that has already been through
    /// `process_block`, which is why [`on_block_attestation`] is its only
    /// caller: `process_attestation` runs the same `get_indexed_attestation`
    /// and the same `is_valid_indexed_attestation` the verifying sibling above
    /// does, so for a block's own attestations that verdict is already in hand
    /// and re-reaching it is the expensive part of the import.
    pub fn attesting_indices(&self, state: &BeaconState) -> Result<Vec<ValidatorIndex>> {
        self.indices(state, false)
    }

    /// The body both accessors above share: the one place this enum's two
    /// shapes actually matter, since building the indexed form and checking it
    /// needs the fork-specific
    /// `get_indexed_attestation`/`is_valid_indexed_attestation` pair. Kept as
    /// one dispatch so a new attestation shape cannot be added to the
    /// verifying path and forgotten on the other.
    fn indices(&self, state: &BeaconState, verify_signature: bool) -> Result<Vec<ValidatorIndex>> {
        match self {
            Attestation::Phase0(attestation) => {
                let indexed = phase0_attestation::get_indexed_attestation(state, attestation)?;
                if verify_signature {
                    verify(
                        phase0_attestation::is_valid_indexed_attestation(state, &indexed),
                        "is_valid_indexed_attestation(target_state, indexed_attestation)",
                    )?;
                }
                Ok(indexed.attesting_indices.into_inner())
            }
            Attestation::Electra(attestation) => {
                let indexed = electra_helpers::get_indexed_attestation(state, attestation)?;
                if verify_signature {
                    verify(
                        electra_helpers::is_valid_indexed_attestation(state, &indexed),
                        "is_valid_indexed_attestation(target_state, indexed_attestation)",
                    )?;
                }
                Ok(indexed.attesting_indices.into_inner())
            }
        }
    }
}

/// Evidence that a set of validators made two conflicting attestations, in
/// whichever fork's shape it currently has. See [`Attestation`] for why this
/// has the same two variants and no more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttesterSlashing {
    Phase0(phase0::AttesterSlashing),
    Electra(electra::AttesterSlashing),
}

impl AttesterSlashing {
    /// The fork-invariant half of both attestations `self` accuses of
    /// equivocating: what [`on_attester_slashing`] needs to check
    /// [`is_slashable_attestation_data`] before it looks at either half's
    /// attesters at all.
    pub fn data(&self) -> (AttestationData, AttestationData) {
        match self {
            AttesterSlashing::Phase0(slashing) => {
                (slashing.attestation_1.data, slashing.attestation_2.data)
            }
            AttesterSlashing::Electra(slashing) => {
                (slashing.attestation_1.data, slashing.attestation_2.data)
            }
        }
    }

    /// The attesting indices of both halves, once each has been checked as
    /// an individually valid indexed attestation against `state`. See
    /// [`Attestation::verified_attesting_indices`] for why this is where the
    /// fork-specific dispatch happens.
    pub fn verified_attesting_indices(
        &self,
        state: &BeaconState,
    ) -> Result<(Vec<ValidatorIndex>, Vec<ValidatorIndex>)> {
        match self {
            AttesterSlashing::Phase0(slashing) => {
                verify(
                    phase0_attestation::is_valid_indexed_attestation(
                        state,
                        &slashing.attestation_1,
                    ),
                    "is_valid_indexed_attestation(state, attestation_1)",
                )?;
                verify(
                    phase0_attestation::is_valid_indexed_attestation(
                        state,
                        &slashing.attestation_2,
                    ),
                    "is_valid_indexed_attestation(state, attestation_2)",
                )?;
                Ok((
                    slashing
                        .attestation_1
                        .attesting_indices
                        .iter()
                        .copied()
                        .collect(),
                    slashing
                        .attestation_2
                        .attesting_indices
                        .iter()
                        .copied()
                        .collect(),
                ))
            }
            AttesterSlashing::Electra(slashing) => {
                verify(
                    electra_helpers::is_valid_indexed_attestation(state, &slashing.attestation_1),
                    "is_valid_indexed_attestation(state, attestation_1)",
                )?;
                verify(
                    electra_helpers::is_valid_indexed_attestation(state, &slashing.attestation_2),
                    "is_valid_indexed_attestation(state, attestation_2)",
                )?;
                Ok((
                    slashing
                        .attestation_1
                        .attesting_indices
                        .iter()
                        .copied()
                        .collect(),
                    slashing
                        .attestation_2
                        .attesting_indices
                        .iter()
                        .copied()
                        .collect(),
                ))
            }
        }
    }
}

/// The attestations and attester slashings carried in `block`'s body, each
/// wrapped in the fork-generic shape [`on_block_attestation`] and
/// [`on_attester_slashing`] take.
///
/// Lives here, beside the two enums it builds, because the fork-to-shape
/// mapping is theirs: phase0 through deneb share
/// [`phase0::Attestation`]/[`phase0::AttesterSlashing`], electra and fulu the
/// `electra` pair. Both consumers of a block's own operations, the chain actor
/// and the `fork_choice` fixture runner, read it from here, so a new fork
/// reshaping `body.attestations` cannot be handled in one and forgotten in the
/// other.
pub fn block_operations(block: &SignedBeaconBlock) -> (Vec<Attestation>, Vec<AttesterSlashing>) {
    match block {
        SignedBeaconBlock::Electra(block) => (
            block
                .message
                .body
                .attestations
                .iter()
                .cloned()
                .map(Attestation::Electra)
                .collect(),
            block
                .message
                .body
                .attester_slashings
                .iter()
                .cloned()
                .map(AttesterSlashing::Electra)
                .collect(),
        ),
        SignedBeaconBlock::Fulu(block) => (
            block
                .message
                .body
                .attestations
                .iter()
                .cloned()
                .map(Attestation::Electra)
                .collect(),
            block
                .message
                .body
                .attester_slashings
                .iter()
                .cloned()
                .map(AttesterSlashing::Electra)
                .collect(),
        ),
        SignedBeaconBlock::Phase0(block) => phase0_operations(
            block.message.body.attestations.iter(),
            block.message.body.attester_slashings.iter(),
        ),
        SignedBeaconBlock::Altair(block) => phase0_operations(
            block.message.body.attestations.iter(),
            block.message.body.attester_slashings.iter(),
        ),
        SignedBeaconBlock::Bellatrix(block) => phase0_operations(
            block.message.body.attestations.iter(),
            block.message.body.attester_slashings.iter(),
        ),
        SignedBeaconBlock::Capella(block) => phase0_operations(
            block.message.body.attestations.iter(),
            block.message.body.attester_slashings.iter(),
        ),
        SignedBeaconBlock::Deneb(block) => phase0_operations(
            block.message.body.attestations.iter(),
            block.message.body.attester_slashings.iter(),
        ),
        SignedBeaconBlock::Lean(_) => lean_block_unreachable("fork_choice::block_operations"),
    }
}

/// Phase0 through deneb share one attestation and slashing shape, so their
/// five arms above share one body.
///
/// Takes iterators rather than the lists themselves: each fork's body names
/// its own `SszList` bound, so a parameter typed on the list would need one
/// generic per bound, and `.iter()` erases exactly that difference.
fn phase0_operations<'a>(
    attestations: impl Iterator<Item = &'a phase0::Attestation>,
    slashings: impl Iterator<Item = &'a phase0::AttesterSlashing>,
) -> (Vec<Attestation>, Vec<AttesterSlashing>) {
    (
        attestations.cloned().map(Attestation::Phase0).collect(),
        slashings.cloned().map(AttesterSlashing::Phase0).collect(),
    )
}

// ---------------------------------------------------------------------------
// DataAvailability
// ---------------------------------------------------------------------------

/// What [`on_block`] needs from `retrieve_blobs_and_proofs` (deneb, electra)
/// or `retrieve_column_sidecars` (fulu) to decide `is_data_available`.
///
/// Both are "implementation and context dependent" in the specification's
/// own words, exactly like [`stf::ExecutionEngine`]'s execution-payload
/// validity call; this collapses the same way, to whatever the fixture
/// suites supply directly for the one block being considered right now. A
/// `Store` field would be the wrong shape for that: unlike [`PowBlock`],
/// this evidence is never looked up again by some other hash later, so
/// [`on_block`] takes it as a parameter instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataAvailability {
    /// The block carries no blob commitments, or predates deneb: nothing for
    /// [`on_block`]'s data-availability check to do.
    NotRequired,
    /// Deneb and electra's shape: every blob and its proof, in
    /// `block.body.blob_kzg_commitments`'s own order. A length mismatch
    /// against the block's own commitments is not checked here; it is
    /// exactly what [`is_data_available_blobs`] rejects.
    Blobs {
        blobs: Vec<deneb::Blob>,
        proofs: Vec<KzgProof>,
    },
    /// Fulu's shape: the column sidecars sampled for this block.
    Columns(Vec<fulu::DataColumnSidecar>),
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// The fork choice store: the DB-backed store the lean chain already runs on,
/// rather than a struct defined in this file.
///
/// Every field the specification's own `Store` names has a home here:
/// checkpoints and the clock live in `Metadata`, blocks in the block tables,
/// unrealized justifications in their own table, and the per-slot/per-epoch
/// scratch (`proposer_boost_root`, `block_timeliness`, `equivocating_indices`,
/// `latest_messages`, `pow_blocks`) in an in-memory struct cheap enough to
/// rebuild after a restart rather than worth persisting. See
/// [`ethlambda_storage::Store`]'s own documentation for the full
/// field-by-field accounting; this module reads and writes it exclusively
/// through its public accessors.
///
/// The specification's `checkpoint_states` cache lives in
/// [`ethlambda_storage::Store::state_cache`], the same bounded LRU that
/// memoizes plain block states: [`checkpoint_state`] is what keys it by
/// [`CacheKey::CheckpointState`] and fills it on a miss; see its own
/// documentation.
pub use ethlambda_storage::Store;

/// The state advanced to the first slot of `checkpoint`'s epoch.
///
/// Checks the store's bounded state cache first, keyed by
/// [`CacheKey::CheckpointState`] (epoch and root both, since a checkpoint's
/// root is the last block at or before its boundary slot and so can serve
/// more than one epoch). A hit returns the same `Arc` with no reconstruction
/// and no `stf::process_slots` replay. A miss derives the value and records
/// it before returning; a miss is never an error, which is what makes the
/// cache a pure speed trade with no correctness stake. Nothing here may
/// become a consensus input: a decision that changed with cache residency
/// would be a bug, not a tuning choice.
///
/// Takes `&Store`, not `&mut Store`: it reads the checkpoint's state via
/// [`Store::get_state`](ethlambda_storage::Store::get_state), which is itself
/// `&self`, and advances only a local `BeaconState` clone through
/// `stf::process_slots` on a miss. Storage's state-cache accessors are
/// `&self` by design, using interior mutability, which is what lets this
/// read-only helper record a derived value on a miss without widening to
/// `&mut Store`.
fn checkpoint_state(
    store: &Store,
    checkpoint: &Checkpoint,
    config: &Config,
) -> Result<Arc<BeaconState>> {
    let key = CacheKey::CheckpointState {
        epoch: checkpoint.epoch,
        root: checkpoint.root,
    };
    if let Some(state) = store.cached_state(key) {
        return Ok(state);
    }

    let state = store
        .get_state(&checkpoint.root)
        .expect("get")
        .ok_or(Error::SpecAssert("checkpoint.root in store.block_states"))?;

    let target_slot = compute_start_slot_at_epoch(checkpoint.epoch);
    let state = if state.slot() < target_slot {
        let mut advanced = (*state).clone();
        stf::process_slots(&mut advanced, target_slot, config)?;
        Arc::new(advanced)
    } else {
        state
    };

    store.cache_state(key, state.clone());
    Ok(state)
}

// ---------------------------------------------------------------------------
// get_forkchoice_store
// ---------------------------------------------------------------------------

/// Builds the initial store from a trusted anchor state and block.
///
/// "Trusted" means fork choice will never roll back past this point: a full
/// client anchors at genesis, and a checkpoint-syncing client anchors at
/// whatever finalized state and block it fetched instead.
pub fn get_forkchoice_store(
    backend: Arc<dyn StorageBackend>,
    mut anchor_state: BeaconState,
    anchor_block: SignedBeaconBlock,
    config: &Config,
) -> Result<Store> {
    // The specification's `BeaconState` and `BeaconBlock` are already one
    // fork's own types, so a mismatch between them cannot even be expressed
    // there; here both are enums, so this module has to enforce the invariant
    // by hand, the same way `stf::state_transition` does for every later
    // block.
    verify(
        anchor_block.fork_name() == anchor_state.fork_name(),
        "anchor_block's fork matches anchor_state's",
    )?;

    let anchor_root = anchor_block.message_hash_tree_root();

    // The specification asserts `anchor_block.state_root ==
    // hash_tree_root(anchor_state)`, which holds only when the anchor state is
    // the block's own post-state. A checkpoint-synced anchor is not: the
    // Beacon API's finalized state is the state at
    // `finalized_checkpoint.epoch.start_slot()`, and when that slot was empty
    // the state has been advanced past its own `latest_block_header`.
    //
    // Lighthouse makes the same deviation, validating the header instead:
    // `beacon_node/beacon_chain/src/builder.rs`, `weak_subjectivity_state`.
    // The header root still pins the pair, since it names exactly one block.
    //
    // While the state is inside its block's own slot the header's `state_root`
    // is this state's own root, which the specification leaves zero;
    // substituting it is what `get_latest_block_root` does upstream. Cached
    // back into the state too, the way `on_block` does for every later block
    // and `Store::init_store` does for a lean anchor. Computed from the state
    // with the field cleared rather than trusting what a provider sent: an
    // anchor arriving with it populated is not a shape the specification
    // produces, and the value would land unchecked in `state_roots` a slot
    // later.
    let mut header = anchor_state.latest_block_header().clone();
    if anchor_state.slot() == header.slot {
        anchor_state.latest_block_header_mut().state_root = Root::ZERO;
        let anchor_state_root = anchor_state.hash_tree_root();
        anchor_state.latest_block_header_mut().state_root = anchor_state_root;
        header.state_root = anchor_state_root;
    }
    verify(
        header.hash_tree_root() == anchor_root,
        "hash_tree_root(anchor_state.latest_block_header) == hash_tree_root(anchor_block.message)",
    )?;

    let anchor_epoch = get_current_epoch(&anchor_state);
    let justified_checkpoint = Checkpoint {
        epoch: anchor_epoch,
        root: anchor_root,
    };
    // The specification gives finality the same starting value as
    // justification: a trusted anchor is finalized by fiat, not by having
    // actually gone through the FFG rules.
    let finalized_checkpoint = justified_checkpoint;

    // `SECONDS_PER_SLOT * anchor_state.slot` is arithmetic over values that
    // ultimately come from an externally supplied anchor, so this fails
    // loudly on overflow rather than silently wrapping the store's clock.
    let time = config
        .seconds_per_slot
        .checked_mul(anchor_state.slot())
        .and_then(|slot_seconds| slot_seconds.checked_add(anchor_state.genesis_time()))
        .ok_or(Error::ArithmeticOverflow(
            "anchor_state.genesis_time + SECONDS_PER_SLOT * anchor_state.slot",
        ))?;

    // The anchor is the store's first head and its justified and finalized
    // checkpoint at once, so `init_beacon` seeds all three rows, the same way
    // `init_store` does on a lean directory. That is what lets
    // `update_checkpoints` below read a head to move *from*.
    let mut store = Store::init_beacon(
        backend,
        anchor_state.genesis_time(),
        config.clone(),
        anchor_root,
        Store::beacon_checkpoint_as_stored(justified_checkpoint),
    );
    // The store's row is milliseconds; `time` above is the specification's
    // seconds, computed with its own overflow check just as the specification
    // writes it.
    store
        .set_time_ms(seconds_to_milliseconds(time))
        .expect("set time");

    store.set_beacon_unrealized_checkpoints(Some(justified_checkpoint), Some(finalized_checkpoint));

    // The specification stores the anchor state under both `block_states` and
    // `checkpoint_states` (`copy(anchor_state)` in each), which used to be
    // this file's only outright whole-`BeaconState` clone. `checkpoint_state`
    // now derives that second copy on demand instead of caching it, so the
    // anchor is written once.
    store
        .insert_signed_block(anchor_root, anchor_block)
        .expect("insert");
    store
        .insert_state(anchor_root, anchor_state)
        .expect("insert");
    store.set_unrealized_justification(anchor_root, justified_checkpoint);

    Ok(store)
}

// ---------------------------------------------------------------------------
// Time and slot helpers
// ---------------------------------------------------------------------------

/// How many whole slots have elapsed since genesis, as of `store.time`.
///
/// Through [`Store::current_slot`](ethlambda_storage::Store::current_slot),
/// the slot derivation both chains share, rather than a second copy of the
/// arithmetic here. Two reasons beyond not repeating it. The genesis time this
/// must measure from is the store's own, written at bootstrap off the anchor
/// state, and not necessarily the `genesis_time` of the `config` value a
/// caller happens to be holding; reading one field from each was a way for the
/// two to disagree. And a store's clock never reads earlier than its own
/// genesis, so the saturation that guarded against it belongs with the field
/// it guards.
pub fn get_slots_since_genesis(store: &Store, _config: &Config) -> u64 {
    store.current_slot()
}

/// The slot `store.time` currently falls in.
pub fn get_current_slot(store: &Store, config: &Config) -> Slot {
    constants::GENESIS_SLOT + get_slots_since_genesis(store, config)
}

/// The epoch `store.time` currently falls in.
pub fn get_current_store_epoch(store: &Store, config: &Config) -> Epoch {
    compute_epoch_at_slot(get_current_slot(store, config))
}

/// How many slots into its epoch `slot` is, `0` for the epoch's first slot.
pub fn compute_slots_since_epoch_start(slot: Slot) -> Slot {
    slot - compute_start_slot_at_epoch(compute_epoch_at_slot(slot))
}

/// The ancestor of `root` at `slot`: the block on `root`'s chain whose own
/// slot is at or before `slot`, found by walking parent links.
///
/// The specification defines this recursively; implemented here as a loop
/// instead, so that a long unfinalized suffix cannot risk a stack overflow.
/// An unknown `root` is exactly the "unhandled exception" case the
/// specification calls out as invalid (`store.blocks[root]` would raise
/// `KeyError` in the reference implementation), so it becomes a `SpecAssert`
/// here rather than a panic.
///
/// Takes `index` (`root -> (slot, parent_root)`, [`Store::block_index`]'s own
/// shape) rather than `&Store`: a caller in a per-validator loop
/// ([`get_weight`]) walks this once per active validator, so a point lookup
/// per hop here would multiply a scan the specification already writes as
/// naive by a backend round trip. Every caller builds `index` once, outside
/// its own loop, and threads it down.
pub fn get_ancestor(index: &HashMap<Root, (Slot, Root)>, root: Root, slot: Slot) -> Result<Root> {
    let mut root = root;
    loop {
        let &(block_slot, parent_root) = index
            .get(&root)
            .ok_or(Error::SpecAssert("root in store.blocks"))?;
        if block_slot > slot {
            root = parent_root;
        } else {
            return Ok(root);
        }
    }
}

// ---------------------------------------------------------------------------
// Committee-relative weight helpers
// ---------------------------------------------------------------------------

/// A committee's share of `state`'s total active balance, scaled by
/// `committee_percent` out of one hundred.
///
/// `committee_percent` is a plain percentage, not basis points: unlike the
/// `*_due_bps` configuration values (fractions of [`Config::slot_duration_ms`]
/// out of [`constants::BASIS_POINTS`]), the specification writes this
/// divisor as a bare `100` with no name of its own, since
/// [`Config::proposer_score_boost`] and the two `Config::reorg_*_threshold`
/// values it is called with are themselves already expressed on a 0-100
/// scale.
pub fn calculate_committee_fraction(state: &BeaconState, committee_percent: u64) -> Result<Gwei> {
    let committee_weight = get_total_active_balance(state)? / preset::SLOTS_PER_EPOCH;
    Ok(committee_weight.saturating_mul(committee_percent) / 100)
}

/// The checkpoint block for `epoch`, on `root`'s chain: the ancestor of `root`
/// at that epoch's first slot. See [`get_ancestor`] for why this takes the
/// block index rather than `&Store`.
pub fn get_checkpoint_block(
    index: &HashMap<Root, (Slot, Root)>,
    root: Root,
    epoch: Epoch,
) -> Result<Root> {
    get_ancestor(index, root, compute_start_slot_at_epoch(epoch))
}

/// The extra weight a timely, uncontested block gets over its competitors,
/// scaled to deter a "balancing" attack that splits votes right at a slot
/// boundary.
///
/// See [`calculate_committee_fraction`] for why this divides by a bare
/// `100` rather than [`constants::BASIS_POINTS`].
pub fn get_proposer_score(store: &Store, config: &Config) -> Result<Gwei> {
    let justified_checkpoint = store.beacon_justified_checkpoint();
    let justified_state = checkpoint_state(store, &justified_checkpoint, config)?;
    let committee_weight = get_total_active_balance(&justified_state)? / preset::SLOTS_PER_EPOCH;
    Ok(committee_weight.saturating_mul(config.proposer_score_boost) / 100)
}

/// The LMD GHOST weight of `root`: the effective balance of every
/// non-equivocating, active, unslashed validator whose latest vote descends
/// through `root`, plus the proposer boost if it applies.
///
/// Takes `index` rather than building it, the way [`filter_block_tree`] does,
/// and reuses it for every [`get_ancestor`] call this makes: one per active
/// validator, plus one for the proposer boost. See [`get_ancestor`]'s
/// documentation for why that matters.
///
/// The specification's own per-root definition, kept as written. [`get_head`]
/// calls [`compute_weights`] instead, which produces the same numbers for the
/// whole tree at once; this is what that is tested against.
pub fn get_weight(
    store: &Store,
    index: &HashMap<Root, (Slot, Root)>,
    root: Root,
    config: &Config,
) -> Result<Gwei> {
    let justified_checkpoint = store.beacon_justified_checkpoint();
    let state = checkpoint_state(store, &justified_checkpoint, config)?;
    let current_epoch = get_current_epoch(&state);
    let block_slot = index
        .get(&root)
        .ok_or(Error::SpecAssert("root in store.blocks"))?
        .0;

    let mut attestation_score: Gwei = 0;
    for validator_index in get_active_validator_indices(&state, current_epoch) {
        let validator = state.validator(validator_index)?;
        if validator.slashed || store.is_equivocating(validator_index) {
            continue;
        }
        let Some(message) = store.latest_message(validator_index) else {
            continue;
        };
        if get_ancestor(index, message.root, block_slot)? == root {
            attestation_score = attestation_score.saturating_add(validator.effective_balance);
        }
    }

    let proposer_boost_root = store.proposer_boost_root();
    if proposer_boost_root.is_zero() {
        return Ok(attestation_score);
    }

    let mut proposer_score: Gwei = 0;
    if get_ancestor(index, proposer_boost_root, block_slot)? == root {
        proposer_score = get_proposer_score(store, config)?;
    }
    Ok(attestation_score.saturating_add(proposer_score))
}

/// Every indexed block's LMD GHOST weight, in one pass over the votes.
///
/// [`get_weight`] is the specification's definition and is per-root, so a head
/// descent that calls it once per candidate re-walks every validator's vote at
/// every step: on mainnet that is a two-million-entry registry scan and a
/// parent walk per voter, repeated for each of the tens of blocks between the
/// justified checkpoint and the head. Measured on a live mainnet follower at
/// 2.36M validators, that walk was 62% of the whole process's CPU, more than
/// half of it inside `SipHash` on the block index's own keys, and imports ran
/// at 14 s against 12 s slots so the follower lost ground every slot.
///
/// The same numbers fall out of one bottom-up accumulation, because a vote
/// counts for a root exactly when the voted block descends from it: sum each
/// vote at its own block, then fold every block's total into its parent,
/// walking blocks from the highest slot down so a child is complete before its
/// parent reads it. A parent link always points at a strictly earlier slot, so
/// that order is a valid topological one. That is one index lookup per voter
/// rather than one per voter per level, over a map small enough to stay in
/// cache, and no registry scan at all.
///
/// A vote for a block no longer in `index` is dropped rather than raising.
/// `Store::promote_beacon_anchor` prunes the block index below the oldest kept
/// finalized anchor, and a validator whose freshest recorded vote is for a
/// block down there keeps that vote until it attests again. Such a vote cannot
/// distinguish between candidates above the justified checkpoint (all of them
/// descend from the finalized block it voted below), so it weighs nothing, and
/// the alternative is what a live node actually hit: one stale voter aborting
/// the whole head computation with `SpecAssert("root in store.blocks")` and
/// pinning the head for as long as it stayed stale.
pub fn compute_weights(
    store: &Store,
    index: &HashMap<Root, (Slot, Root)>,
    config: &Config,
) -> Result<HashMap<Root, Gwei>> {
    let justified_checkpoint = store.beacon_justified_checkpoint();
    let state = checkpoint_state(store, &justified_checkpoint, config)?;
    let current_epoch = get_current_epoch(&state);

    // Keyed on the voted block itself; the fold below turns these into subtree
    // totals in place.
    let mut weights: HashMap<Root, Gwei> = HashMap::new();
    // Equivocators are filtered by the store itself: see
    // `for_each_non_equivocating_latest_message` for why asking it per voter
    // from in here would deadlock.
    store.for_each_non_equivocating_latest_message(|validator_index, message| {
        // Not `get_active_validator_indices`: that allocates the whole active
        // set (~2 million entries on mainnet) to answer a membership question,
        // and an index past this state's registry is a validator that did not
        // exist yet at the justified checkpoint, which is a skip rather than an
        // error.
        let Ok(validator) = state.validator(validator_index) else {
            return;
        };
        if validator.slashed || !is_active_validator(validator, current_epoch) {
            return;
        }
        let entry = weights.entry(message.root).or_default();
        *entry = entry.saturating_add(validator.effective_balance);
    });

    // Highest slot first: see above for why that is a topological order.
    let mut blocks: Vec<(Root, Slot, Root)> = index
        .iter()
        .map(|(root, (slot, parent_root))| (*root, *slot, *parent_root))
        .collect();
    blocks.sort_unstable_by(|left, right| right.1.cmp(&left.1).then(right.0.cmp(&left.0)));

    for (root, _slot, parent_root) in &blocks {
        let subtree_weight = weights.get(root).copied().unwrap_or_default();
        if subtree_weight == 0 {
            continue;
        }
        // Only into a parent that is still indexed: the anchor's own parent is
        // below the retained window, and there is nothing there to weigh.
        if index.contains_key(parent_root) {
            let entry = weights.entry(*parent_root).or_default();
            *entry = entry.saturating_add(subtree_weight);
        }
    }

    let boost_root = store.proposer_boost_root();
    if !boost_root.is_zero() && index.contains_key(&boost_root) {
        // The specification gives the boost to every root the boosted block
        // descends from, which is every block on its ancestor walk. Ends at the
        // justified checkpoint: `get_head` never descends below it, and below
        // it the walk would leave the retained window.
        let justified_slot = index
            .get(&justified_checkpoint.root)
            .map_or(0, |(slot, _)| *slot);
        let proposer_score = get_proposer_score(store, config)?;
        let mut cursor = boost_root;
        while let Some((slot, parent_root)) = index.get(&cursor).copied() {
            let entry = weights.entry(cursor).or_default();
            *entry = entry.saturating_add(proposer_score);
            if slot <= justified_slot {
                break;
            }
            cursor = parent_root;
        }
    }

    Ok(weights)
}

/// The checkpoint a block would cast as its FFG source if it were canonical
/// head right now.
///
/// A block from a strictly earlier epoch than the store's current one has its
/// vote "pulled up" to the unrealized justification [`compute_pulled_up_tip`]
/// computed for it, rather than to whatever its own post-state's
/// `current_justified_checkpoint` happened to be at the time it was
/// processed; a block from the current epoch has no unrealized value to pull
/// up to yet, so its own post-state's checkpoint is used directly.
pub fn get_voting_source(
    store: &Store,
    index: &HashMap<Root, (Slot, Root)>,
    block_root: Root,
    config: &Config,
) -> Result<Checkpoint> {
    let (block_slot, _) = *index
        .get(&block_root)
        .ok_or(Error::SpecAssert("block_root in store.blocks"))?;
    let current_epoch = get_current_store_epoch(store, config);
    let block_epoch = compute_epoch_at_slot(block_slot);

    if current_epoch > block_epoch {
        store
            .unrealized_justification(&block_root)
            .ok_or(Error::SpecAssert(
                "block_root in store.unrealized_justifications",
            ))
    } else {
        let head_state = store
            .get_state(&block_root)
            .expect("get")
            .ok_or(Error::SpecAssert("block_root in store.block_states"))?;
        Ok(head_state.current_justified_checkpoint())
    }
}

// ---------------------------------------------------------------------------
// Filtering the block tree
// ---------------------------------------------------------------------------

/// Walks `block_root`'s subtree, adding every block on a viable branch to
/// `blocks`, and reporting whether `block_root` itself sits on one.
///
/// *Note*: external callers must pass `store.justified_checkpoint.root` for
/// `block_root`; only the recursive calls below pass anything else.
///
/// Recursive, following the specification directly rather than an explicit
/// stack: the subtree walked here is the unfinalized suffix since the
/// justified checkpoint, which stays shallow in ordinary operation.
///
/// Takes `index`, [`Store::block_index`] built once by
/// [`get_filtered_block_tree`] and threaded through every recursive call,
/// rather than re-scanning the store's blocks at each node: the children scan
/// below is exactly the whole-map iteration the module documentation says
/// this file never needs a `BTreeMap` for, and it runs once per node visited,
/// not once per node per DB round trip. `blocks`' value is `index`'s own
/// `(slot, parent_root)` shape rather than a whole [`SignedBeaconBlock`],
/// since [`get_head`], the only reader of this function's output, never needs
/// more than that.
pub fn filter_block_tree(
    store: &Store,
    index: &HashMap<Root, (Slot, Root)>,
    block_root: Root,
    blocks: &mut HashMap<Root, (Slot, Root)>,
    config: &Config,
) -> Result<bool> {
    let entry = *index
        .get(&block_root)
        .ok_or(Error::SpecAssert("block_root in store.blocks"))?;

    let children: Vec<Root> = index
        .iter()
        .filter(|&(_, &(_, parent_root))| parent_root == block_root)
        .map(|(&root, _)| root)
        .collect();

    // If any children branches contain expected finalized/justified
    // checkpoints, add to filtered block-tree and signal viability to parent.
    if !children.is_empty() {
        let mut any_viable = false;
        for child in children {
            if filter_block_tree(store, index, child, blocks, config)? {
                any_viable = true;
            }
        }
        if any_viable {
            blocks.insert(block_root, entry);
            return Ok(true);
        }
        return Ok(false);
    }

    let current_epoch = get_current_store_epoch(store, config);
    let voting_source = get_voting_source(store, index, block_root, config)?;

    // The voting source should be either at the same height as the store's
    // justified checkpoint or not more than two epochs ago.
    let justified_checkpoint = store.beacon_justified_checkpoint();
    let correct_justified = justified_checkpoint.epoch == constants::GENESIS_EPOCH
        || voting_source.epoch == justified_checkpoint.epoch
        || voting_source.epoch.saturating_add(2) >= current_epoch;

    let finalized_checkpoint = store.beacon_finalized_checkpoint();
    let finalized_checkpoint_block =
        get_checkpoint_block(index, block_root, finalized_checkpoint.epoch)?;

    let correct_finalized = finalized_checkpoint.epoch == constants::GENESIS_EPOCH
        || finalized_checkpoint.root == finalized_checkpoint_block;

    // If expected finalized/justified, add to viable block-tree and signal
    // viability to parent.
    if correct_justified && correct_finalized {
        blocks.insert(block_root, entry);
        return Ok(true);
    }

    Ok(false)
}

/// The filtered block tree: every block, from the justified checkpoint down,
/// whose leaf state's justified/finalized info agrees with `store`'s own.
pub fn get_filtered_block_tree(
    store: &Store,
    index: &HashMap<Root, (Slot, Root)>,
    config: &Config,
) -> Result<HashMap<Root, (Slot, Root)>> {
    let base = store.beacon_justified_checkpoint().root;
    let mut blocks = HashMap::new();
    filter_block_tree(store, index, base, &mut blocks, config)?;
    Ok(blocks)
}

/// The LMD GHOST head: starting from the justified checkpoint, repeatedly
/// step to the child with the greatest weight until a leaf is reached.
///
/// The children scan in the loop below reads `blocks`, [`get_filtered_block_tree`]'s
/// already-filtered, already in-memory result, not [`Store::block_index`]
/// itself: it is the specification's own second whole-`Dict` scan the module
/// documentation calls out, but it never costs a further backend round trip.
///
/// Takes `&mut Store`, unlike most functions in this file: it records the head
/// it just found through
/// [`Store::update_checkpoints`](ethlambda_storage::Store::update_checkpoints),
/// the head-and-checkpoint writer both chains share, so a restarted node has
/// something to answer from immediately rather than replaying this whole walk
/// on its first tick. That writer also keeps the canonical `BlockRoots` index
/// in step with the branch fork choice just picked.
///
/// Written unconditionally on every call, not only when the head changes: a
/// value written once and then left alone is a second source of truth a bug
/// can let drift, and the write is one small metadata row plus an index diff
/// that is empty whenever the head did not move, set against a whole weighted
/// tree walk.
pub fn get_head(store: &mut Store, config: &Config) -> Result<Root> {
    // One scan for the whole walk: the filtered tree and the weight table are
    // both built from it, instead of each rescanning the live chain for itself.
    let index = store.block_index();
    let blocks = get_filtered_block_tree(store, &index, config)?;
    // Every candidate's weight at once: see `compute_weights` for why the
    // specification's per-root `get_weight` is not what the descent calls.
    let weights = compute_weights(store, &index, config)?;
    let mut head = store.beacon_justified_checkpoint().root;
    loop {
        let children: Vec<Root> = blocks
            .iter()
            .filter(|&(_, &(_, parent_root))| parent_root == head)
            .map(|(&root, _)| root)
            .collect();
        if children.is_empty() {
            break;
        }

        // Sort by latest attesting balance with ties broken lexicographically,
        // favoring the higher root: pairing the weight with the root itself as
        // the sort key gives exactly that, and `Root`'s derived `Ord` compares
        // its bytes in order, matching Python's default comparison of a
        // `bytes` root.
        let mut ranked = Vec::with_capacity(children.len());
        for root in children {
            ranked.push((weights.get(&root).copied().unwrap_or_default(), root));
        }
        head = ranked
            .into_iter()
            .max()
            .expect("children is non-empty, checked above")
            .1;
    }

    store
        .update_checkpoints(ForkCheckpoints::head_only(head))
        .expect("record beacon head");

    Ok(head)
}

// ---------------------------------------------------------------------------
// Checkpoint bookkeeping
// ---------------------------------------------------------------------------

/// Advances `store`'s justified and finalized checkpoints to `justified` and
/// `finalized`, if each is more recent than what is already recorded.
///
/// Justification and finalization only ever move forward: a lower-epoch
/// checkpoint arriving later (as can happen while replaying blocks out of
/// order) must not roll a more advanced view back.
pub fn update_checkpoints(store: &mut Store, justified: Checkpoint, finalized: Checkpoint) {
    // Through the same `Store::update_checkpoints` lean advances: an epoch is
    // stored as its own start slot, so the two chains' checkpoints share one
    // row and one writer. The head is passed through unchanged, since this
    // moves only the checkpoints; `get_head` is what moves the head.
    let justified =
        (justified.epoch > store.beacon_justified_checkpoint().epoch).then_some(justified);
    let finalized =
        (finalized.epoch > store.beacon_finalized_checkpoint().epoch).then_some(finalized);
    if justified.is_none() && finalized.is_none() {
        return;
    }
    let head = store.head().expect("head block exists");
    let checkpoints = ForkCheckpoints::new(
        head,
        justified.map(Store::beacon_checkpoint_as_stored),
        finalized.map(Store::beacon_checkpoint_as_stored),
    );
    store
        .update_checkpoints(checkpoints)
        .expect("update beacon checkpoints");
}

/// The unrealized-checkpoint counterpart to [`update_checkpoints`].
pub fn update_unrealized_checkpoints(
    store: &mut Store,
    unrealized_justified: Checkpoint,
    unrealized_finalized: Checkpoint,
) {
    let justified = (unrealized_justified.epoch
        > store.beacon_unrealized_justified_checkpoint().epoch)
        .then_some(unrealized_justified);
    let finalized = (unrealized_finalized.epoch
        > store.beacon_unrealized_finalized_checkpoint().epoch)
        .then_some(unrealized_finalized);
    store.set_beacon_unrealized_checkpoints(justified, finalized);
}

// ---------------------------------------------------------------------------
// Millisecond time helpers
// ---------------------------------------------------------------------------
//
// See the module documentation for how these relate to `Store.time`, which
// stays in seconds throughout.

/// Converts `seconds` to milliseconds, saturating at [`constants::UINT64_MAX`]
/// instead of wrapping.
pub fn seconds_to_milliseconds(seconds: u64) -> u64 {
    seconds.checked_mul(1000).unwrap_or(constants::UINT64_MAX)
}

/// The duration, in milliseconds, that `basis_points` out of
/// [`constants::BASIS_POINTS`] of a slot spans.
pub fn get_slot_component_duration_ms(basis_points: u64, config: &Config) -> u64 {
    basis_points.saturating_mul(config.slot_duration_ms) / constants::BASIS_POINTS
}

/// How far into a slot, in milliseconds, an attestation is due.
///
/// `epoch` is accepted, matching the specification's signature, but not read:
/// the deadline is a fixed fraction of the slot in every epoch this module
/// implements.
pub fn get_attestation_due_ms(_epoch: Epoch, config: &Config) -> u64 {
    get_slot_component_duration_ms(config.attestation_due_bps, config)
}

/// How far into a slot, in milliseconds, a proposer must stop attempting a
/// late-block reorg. See [`get_attestation_due_ms`] for why `epoch` is unused.
pub fn get_proposer_reorg_cutoff_ms(_epoch: Epoch, config: &Config) -> u64 {
    get_slot_component_duration_ms(config.proposer_reorg_cutoff_bps, config)
}

/// How far into a slot, in milliseconds, an aggregate attestation is due. See
/// [`get_attestation_due_ms`] for why `epoch` is unused.
pub fn get_aggregate_due_ms(_epoch: Epoch, config: &Config) -> u64 {
    get_slot_component_duration_ms(config.aggregate_due_bps, config)
}

// ---------------------------------------------------------------------------
// Proposer head and reorg helpers
// ---------------------------------------------------------------------------
//
// The specification marks implementing these as optional, but a proposer
// that skips them simply always builds on `get_head`'s result rather than
// ever reorging out a late block; this module implements them so a validator
// client built on it can make that choice instead of having it made for it.

/// Whether `head_root`'s block arrived after the attestation deadline of the
/// slot it was imported in.
pub fn is_head_late(store: &Store, head_root: Root) -> Result<bool> {
    let timely = store
        .block_timeliness(&head_root)
        .ok_or(Error::SpecAssert("head_root in store.block_timeliness"))?;
    Ok(!timely)
}

/// Whether `slot` is not the first slot of its epoch, i.e. the proposer
/// shuffling in effect for it cannot change from reorging one slot.
pub fn is_shuffling_stable(slot: Slot) -> bool {
    !slot.is_multiple_of(preset::SLOTS_PER_EPOCH)
}

/// Whether `head_root` and `parent_root` would cast the same FFG vote if
/// either were head, so that reorging one for the other costs nothing on the
/// justification side.
pub fn is_ffg_competitive(store: &Store, head_root: Root, parent_root: Root) -> Result<bool> {
    let head = store
        .unrealized_justification(&head_root)
        .ok_or(Error::SpecAssert(
            "head_root in store.unrealized_justifications",
        ))?;
    let parent = store
        .unrealized_justification(&parent_root)
        .ok_or(Error::SpecAssert(
            "parent_root in store.unrealized_justifications",
        ))?;
    Ok(head == parent)
}

/// Whether the chain has finalized recently enough that a reorg is still
/// worth risking: reorgs are a liveness optimization, and this bounds how
/// much finality progress they may put at stake to pursue it.
pub fn is_finalization_ok(store: &Store, slot: Slot, config: &Config) -> bool {
    let epochs_since_finalization =
        compute_epoch_at_slot(slot).saturating_sub(store.beacon_finalized_checkpoint().epoch);
    epochs_since_finalization <= config.reorg_max_epochs_since_finalization
}

/// Whether `store.time` is early enough in the current slot that a proposer
/// building now still counts as on time.
pub fn is_proposing_on_time(store: &Store, config: &Config) -> bool {
    let time_into_slot_ms = store.ms_since_genesis() % config.slot_duration_ms;
    let epoch = get_current_store_epoch(store, config);
    time_into_slot_ms <= get_proposer_reorg_cutoff_ms(epoch, config)
}

/// Whether `head_root` has few enough votes to be overpowered by the
/// proposer's own boost, i.e. reorging it out would not be fighting an
/// already-decisive lead.
pub fn is_head_weak(store: &Store, head_root: Root, config: &Config) -> Result<bool> {
    let justified_checkpoint = store.beacon_justified_checkpoint();
    let justified_state = checkpoint_state(store, &justified_checkpoint, config)?;
    let reorg_threshold =
        calculate_committee_fraction(&justified_state, config.reorg_head_weight_threshold)?;
    Ok(get_weight(store, &store.block_index(), head_root, config)? < reorg_threshold)
}

/// Whether `parent_root` already has enough votes of its own that the missing
/// votes are assigned to it rather than being hoarded elsewhere.
pub fn is_parent_strong(store: &Store, parent_root: Root, config: &Config) -> Result<bool> {
    let justified_checkpoint = store.beacon_justified_checkpoint();
    let justified_state = checkpoint_state(store, &justified_checkpoint, config)?;
    let parent_threshold =
        calculate_committee_fraction(&justified_state, config.reorg_parent_weight_threshold)?;
    Ok(get_weight(store, &store.block_index(), parent_root, config)? > parent_threshold)
}

/// The block a proposer at `slot` should build on: `head_root`'s parent
/// instead of `head_root` itself, if every reorg condition holds, and
/// `head_root` otherwise.
///
/// *Note*: the ordering of conditions here is the specification's suggested
/// order, not a requirement; an implementation may reorder or short-circuit
/// for performance.
pub fn get_proposer_head(
    store: &Store,
    head_root: Root,
    slot: Slot,
    config: &Config,
) -> Result<Root> {
    let (head_slot, parent_root) = store
        .block_entry(&head_root)
        .ok_or(Error::SpecAssert("head_root in store.blocks"))?;
    let (parent_slot, _) = store
        .block_entry(&parent_root)
        .ok_or(Error::SpecAssert("parent_root in store.blocks"))?;

    // Only re-org the head block if it arrived later than the attestation
    // deadline.
    let head_late = is_head_late(store, head_root)?;
    // Do not re-org on an epoch boundary where the proposer shuffling could
    // change.
    let shuffling_stable = is_shuffling_stable(slot);
    // Ensure that the FFG information of the new head will be competitive
    // with the current head.
    let ffg_competitive = is_ffg_competitive(store, head_root, parent_root)?;
    // Do not re-org if the chain is not finalizing with acceptable frequency.
    let finalization_ok = is_finalization_ok(store, slot, config);
    // Only re-org if we are proposing on-time.
    let proposing_on_time = is_proposing_on_time(store, config);

    // Only re-org a single slot at most.
    let parent_slot_ok = parent_slot.checked_add(1) == Some(head_slot);
    let current_time_ok = head_slot.checked_add(1) == Some(slot);
    let single_slot_reorg = parent_slot_ok && current_time_ok;

    // Check that the head has few enough votes to be overpowered by our
    // proposer boost.
    verify(
        store.proposer_boost_root() != head_root,
        "store.proposer_boost_root != head_root",
    )?;
    let head_weak = is_head_weak(store, head_root, config)?;

    // Check that the missing votes are assigned to the parent and not being
    // hoarded.
    let parent_strong = is_parent_strong(store, parent_root, config)?;

    if head_late
        && shuffling_stable
        && ffg_competitive
        && finalization_ok
        && proposing_on_time
        && single_slot_reorg
        && head_weak
        && parent_strong
    {
        // We can re-org the current head by building upon its parent block.
        Ok(parent_root)
    } else {
        Ok(head_root)
    }
}

/// Whether a proposer confident it will build the next block should ask its
/// execution engine to build on `head_root`'s parent instead of `head_root`
/// itself, suppressing the `notify_forkchoice_updated` call bellatrix's
/// `ExecutionEngine` protocol would otherwise make right away.
///
/// `validator_is_connected` stands in for the specification's own
/// `validator_is_connected(validator_index: ValidatorIndex) -> bool`, "a
/// function that indicates whether the validator ... is connected to the
/// node (e.g. has sent an unexpired proposer preparation message)"
/// (`specs/bellatrix/fork-choice.md`). Every real answer is
/// implementation-specific, so a caller supplies its own policy here rather
/// than this module guessing at one; the fixture suites that exercise this
/// supply a fixed answer directly, the same way [`stf::ExecutionEngine`]
/// stands in for a real execution client elsewhere in this module.
///
/// Shares [`get_proposer_head`]'s own reorg conditions
/// (`is_head_late`/`is_shuffling_stable`/`is_ffg_competitive`/`is_finalization_ok`),
/// but evaluated against `proposal_slot` (`head_root`'s slot plus one)
/// rather than the caller's own current slot: this asks about the block a
/// confident proposer is *about* to build, one slot ahead of `head_root`,
/// not about reorging a block already received.
pub fn should_override_forkchoice_update(
    store: &Store,
    head_root: Root,
    validator_is_connected: impl Fn(ValidatorIndex) -> bool,
    config: &Config,
) -> Result<bool> {
    let (head_slot, parent_root) = store
        .block_entry(&head_root)
        .ok_or(Error::SpecAssert("head_root in store.blocks"))?;
    let (parent_slot, _) = store
        .block_entry(&parent_root)
        .ok_or(Error::SpecAssert("parent_root in store.blocks"))?;
    let current_slot = get_current_slot(store, config);
    let proposal_slot = head_slot.saturating_add(1);

    // Only re-org the head block if it arrived later than the attestation
    // deadline.
    let head_late = is_head_late(store, head_root)?;
    // Shuffling stable.
    let shuffling_stable = is_shuffling_stable(proposal_slot);
    // FFG information of the new head block will be competitive with the
    // current head.
    let ffg_competitive = is_ffg_competitive(store, head_root, parent_root)?;
    // Do not re-org if the chain is not finalizing with acceptable frequency.
    let finalization_ok = is_finalization_ok(store, proposal_slot, config);

    // Only suppress the fork choice update if we are confident that we will
    // propose the next block. `get_state` hands back a shared `Arc`, so this
    // clones out of it before advancing: matching the specification's own
    // `.copy()`, advancing to `proposal_slot` is only how this samples the
    // proposer that slot would draw, not a change the store's own cached
    // entry for `parent_root` should keep.
    let parent_state = store
        .get_state(&parent_root)
        .expect("get")
        .ok_or(Error::SpecAssert("parent_root in store.block_states"))?;
    let mut parent_state_advanced = (*parent_state).clone();
    stf::process_slots(&mut parent_state_advanced, proposal_slot, config)?;
    let proposer_index = get_beacon_proposer_index(&parent_state_advanced)?;
    let proposing_reorg_slot = validator_is_connected(proposer_index);

    // Single slot re-org.
    let parent_slot_ok = parent_slot.checked_add(1) == Some(head_slot);
    let proposing_on_time = is_proposing_on_time(store, config);
    // Note that this condition is different from `get_proposer_head`.
    let current_time_ok =
        head_slot == current_slot || (proposal_slot == current_slot && proposing_on_time);
    let single_slot_reorg = parent_slot_ok && current_time_ok;

    // Check the head weight only if the attestations from the head slot have
    // already been applied; before then, both conditions default to true
    // rather than judging the head on attestations that have not arrived
    // yet.
    let (head_weak, parent_strong) = if current_slot > head_slot {
        (
            is_head_weak(store, head_root, config)?,
            is_parent_strong(store, parent_root, config)?,
        )
    } else {
        (true, true)
    };

    Ok(head_late
        && shuffling_stable
        && ffg_competitive
        && finalization_ok
        && proposing_reorg_slot
        && single_slot_reorg
        && head_weak
        && parent_strong)
}

// ---------------------------------------------------------------------------
// Merge transition helpers (bellatrix)
// ---------------------------------------------------------------------------

/// Looks up a PoW block by hash, matching the specification's own
/// `get_pow_block`. See [`PowBlock`]'s documentation for why this reads
/// [`Store::beacon_pow_block`] rather than calling out to a real execution
/// client.
pub fn get_pow_block(store: &Store, hash: Root) -> Option<PowBlock> {
    store.beacon_pow_block(hash)
}

/// Records `pow_block` so later [`get_pow_block`] lookups by its own hash can
/// find it. Not one of the four handlers at the bottom of this file: there is
/// no validity condition to check first, since this only ever adds data a
/// fixture suite's `on_merge_block` step already trusts.
pub fn insert_pow_block(store: &mut Store, pow_block: PowBlock) {
    store.insert_beacon_pow_block(pow_block);
}

/// Whether `block` is the one PoW block where this chain's proof-of-work
/// history ends and its proof-of-stake history begins: its own total
/// difficulty has crossed [`Config::terminal_total_difficulty`], but its
/// parent's had not yet.
pub fn is_valid_terminal_pow_block(block: &PowBlock, parent: &PowBlock, config: &Config) -> bool {
    let is_total_difficulty_reached = block.total_difficulty >= config.terminal_total_difficulty;
    let is_parent_total_difficulty_valid =
        parent.total_difficulty < config.terminal_total_difficulty;
    is_total_difficulty_reached && is_parent_total_difficulty_valid
}

/// Checks that a bellatrix block's parent execution payload really does sit
/// on a valid terminal PoW block, the one condition [`on_block`] adds for
/// bellatrix and never again afterward: capella's own `fork-choice.md` drops
/// it outright ("deletion of the verification of merge transition block
/// conditions").
///
/// [`Config::terminal_block_hash`] is an emergency override that, if ever
/// set, replaces the PoW-chain lookup with a direct hash comparison; every
/// network that shipped the Merge left it unset, so the common path is the
/// `get_pow_block` chain below.
pub fn validate_merge_block(
    store: &Store,
    block: &bellatrix::BeaconBlock,
    config: &Config,
) -> Result<()> {
    let parent_hash = block.body.execution_payload.parent_hash;

    if !config.terminal_block_hash.is_zero() {
        verify(
            compute_epoch_at_slot(block.slot) >= config.terminal_block_hash_activation_epoch,
            "compute_epoch_at_slot(block.slot) >= TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH",
        )?;
        verify(
            parent_hash == config.terminal_block_hash,
            "block.body.execution_payload.parent_hash == TERMINAL_BLOCK_HASH",
        )?;
        return Ok(());
    }

    let pow_block = get_pow_block(store, parent_hash).ok_or(Error::SpecAssert(
        "get_pow_block(block.body.execution_payload.parent_hash) is not None",
    ))?;
    let pow_parent = get_pow_block(store, pow_block.parent_hash).ok_or(Error::SpecAssert(
        "get_pow_block(pow_block.parent_hash) is not None",
    ))?;
    verify(
        is_valid_terminal_pow_block(&pow_block, &pow_parent, config),
        "is_valid_terminal_pow_block(pow_block, pow_parent)",
    )
}

// ---------------------------------------------------------------------------
// Data availability helpers (deneb, electra, fulu)
// ---------------------------------------------------------------------------

/// The specification's `is_data_available` for deneb and electra
/// (`specs/deneb/fork-choice.md`): every commitment the block claims must
/// come with a blob and a proof that verify against it.
///
/// `retrieve_blobs_and_proofs` is "implementation and context dependent"
/// there; [`DataAvailability::Blobs`] is what a caller supplies in its place.
/// A length mismatch between `commitments` and the evidence's own blobs or
/// proofs is not checked separately here: `kzg::verify_blob_kzg_proof_batch`
/// already rejects it, which is exactly what deneb's own
/// `invalid_wrong_blobs_length`/`invalid_wrong_proofs_length` fixture cases
/// exercise.
pub fn is_data_available_blobs(
    commitments: &[KzgCommitment],
    evidence: &DataAvailability,
) -> Result<bool> {
    let (blobs, proofs) = match evidence {
        DataAvailability::Blobs { blobs, proofs } => (blobs.as_slice(), proofs.as_slice()),
        _ => (&[][..], &[][..]),
    };
    let blob_slices: Vec<&[u8]> = blobs.iter().map(|blob| &blob[..]).collect();
    kzg::verify_blob_kzg_proof_batch(&blob_slices, commitments, proofs)
}

/// The specification's `verify_data_column_sidecar`
/// (`specs/fulu/p2p-interface.md`): the structural checks a column sidecar
/// must pass before its KZG proofs are even worth checking.
pub fn verify_data_column_sidecar(sidecar: &fulu::DataColumnSidecar, config: &Config) -> bool {
    // The sidecar index must be within the valid range.
    if sidecar.index as usize >= preset::NUMBER_OF_COLUMNS {
        return false;
    }
    // A sidecar for zero blobs is invalid.
    if sidecar.kzg_commitments.is_empty() {
        return false;
    }
    // Check that the sidecar respects the blob limit.
    let epoch = compute_epoch_at_slot(sidecar.signed_block_header.message.slot);
    if sidecar.kzg_commitments.len() as u64 > config.max_blobs_per_block(epoch) {
        return false;
    }
    // The column length must be equal to the number of commitments/proofs.
    sidecar.column.len() == sidecar.kzg_commitments.len()
        && sidecar.column.len() == sidecar.kzg_proofs.len()
}

/// The specification's `verify_data_column_sidecar_kzg_proofs`
/// (`specs/fulu/p2p-interface.md`): batch-verifies every cell in `sidecar`'s
/// column against its own commitment and proof. Every cell shares
/// `sidecar.index` as its cell index, since a column names one cell position
/// across every blob in the block.
pub fn verify_data_column_sidecar_kzg_proofs(sidecar: &fulu::DataColumnSidecar) -> Result<bool> {
    let cell_indices = vec![sidecar.index; sidecar.column.len()];
    let mut cells = Vec::with_capacity(sidecar.column.len());
    for cell in sidecar.column.iter() {
        cells.push(
            c_kzg::Cell::from_bytes(&cell[..])
                .map_err(|_| Error::SpecAssert("len(cell) == BYTES_PER_CELL"))?,
        );
    }
    kzg::verify_cell_kzg_proof_batch(
        &sidecar.kzg_commitments,
        &cell_indices,
        &cells,
        &sidecar.kzg_proofs,
    )
}

/// The specification's `is_data_available` for fulu
/// (`specs/fulu/fork-choice.md`): every column sidecar sampled for this
/// block must be individually valid.
///
/// Unlike deneb's version, this takes no commitments of its own: fulu's
/// `is_data_available` does not either, since sampling checks each sidecar
/// against the commitment list it itself carries
/// ([`verify_data_column_sidecar`]) rather than the caller cross-checking a
/// separate list. An evidence value with no sidecars is vacuously
/// available, matching the specification's `all(... for ... in
/// column_sidecars)` over an empty sequence; a caller simulating "not all
/// required columns have been sampled" must reject the block itself rather
/// than relying on this to do it, since nothing about an empty list is
/// distinguishable here from "this block needed no sampling at all".
pub fn is_data_available_columns(evidence: &DataAvailability, config: &Config) -> Result<bool> {
    let DataAvailability::Columns(sidecars) = evidence else {
        return Ok(true);
    };
    for sidecar in sidecars {
        if !(verify_data_column_sidecar(sidecar, config)
            && verify_data_column_sidecar_kzg_proofs(sidecar)?)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// Pull-up tip helper
// ---------------------------------------------------------------------------

/// Eagerly computes what `block_root`'s post-state's justification and
/// finality *would* become at the next epoch boundary, without waiting for an
/// actual block at that boundary to realize it on-chain.
///
/// This is what lets [`get_voting_source`] treat a block from a prior epoch as
/// already having the checkpoint its own chain is clearly heading towards,
/// rather than being stuck with whatever its post-state's
/// `current_justified_checkpoint` was at the moment it was imported.
pub fn compute_pulled_up_tip(
    store: &mut Store,
    block_root: Root,
    block_slot: Slot,
    config: &Config,
) -> Result<()> {
    // `get_state` hands back a shared `Arc`, so this clones out of it,
    // matching the specification's own `.copy()`: the clone advances to the
    // next epoch boundary as a throwaway, and the store's own cached entry
    // for `block_root` must be left exactly as the block itself produced it.
    let state = store
        .get_state(&block_root)
        .expect("get")
        .ok_or(Error::SpecAssert("block_root in store.block_states"))?;
    let mut state = (*state).clone();

    // Through the fork-dispatching wrapper rather than phase0's version
    // directly. Altair rewrote this step to read participation flags instead of
    // replaying stored attestations, so calling phase0's against an altair or
    // later state fails outright, which is what made every `fork_choice` case
    // that crosses an epoch boundary fail.
    stf::epoch::process_justification_and_finalization(&mut state, config)?;

    let current_justified = state.current_justified_checkpoint();
    let finalized = state.finalized_checkpoint();

    store.set_unrealized_justification(block_root, current_justified);
    update_unrealized_checkpoints(store, current_justified, finalized);

    // If the block is from a prior epoch, apply the realized values. `block_slot`
    // is passed in rather than read back: the only caller is `on_block`, which
    // has the block itself in hand, so reading it here would decode a whole
    // stored block to recover a field the caller already had.
    let block_epoch = compute_epoch_at_slot(block_slot);
    let current_epoch = get_current_store_epoch(store, config);
    if block_epoch < current_epoch {
        update_checkpoints(store, current_justified, finalized);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// on_tick helpers
// ---------------------------------------------------------------------------

/// Advances `store` to `time`, one slot boundary at a time from where it was.
///
/// `on_tick` is what actually calls this in a loop to catch up more than one
/// slot at once; called directly, `time` must already be at most one slot
/// ahead of `store`'s current slot for the "new slot" resets below to fire at
/// the right boundary.
pub fn on_tick_per_slot(store: &mut Store, time: u64, config: &Config) {
    let previous_slot = get_current_slot(store, config);

    // `time` is the specification's seconds; the store's row is milliseconds.
    store
        .set_time_ms(seconds_to_milliseconds(time))
        .expect("set time");

    let current_slot = get_current_slot(store, config);

    // If this is a new slot, reset store.proposer_boost_root.
    if current_slot > previous_slot {
        store.set_proposer_boost_root(Root::ZERO);
    }

    // If a new epoch, pull-up justification and finalization from previous
    // epoch.
    if current_slot > previous_slot && compute_slots_since_epoch_start(current_slot) == 0 {
        let unrealized_justified = store.beacon_unrealized_justified_checkpoint();
        let unrealized_finalized = store.beacon_unrealized_finalized_checkpoint();
        update_checkpoints(store, unrealized_justified, unrealized_finalized);
    }
}

// ---------------------------------------------------------------------------
// on_attestation helpers
// ---------------------------------------------------------------------------

/// Rejects an attestation whose target is not the current or previous epoch,
/// relative to `store`'s own clock.
///
/// Only checked for attestations arriving directly (not inside a block):
/// a block-borne attestation may target an epoch that has since passed, since
/// the block itself is being processed after the fact.
///
/// Takes `data` directly rather than an [`Attestation`]: this and
/// [`validate_on_attestation`] read nothing from an attestation besides its
/// fork-invariant `data`, so neither needs to know which of
/// [`Attestation`]'s two shapes the caller actually has. See the module
/// documentation.
pub fn validate_target_epoch_against_current_time(
    store: &Store,
    data: AttestationData,
    config: &Config,
) -> Result<()> {
    let target = data.target;
    let current_epoch = get_current_store_epoch(store, config);
    // Use GENESIS_EPOCH for previous when genesis to avoid underflow.
    let previous_epoch = if current_epoch > constants::GENESIS_EPOCH {
        current_epoch - 1
    } else {
        constants::GENESIS_EPOCH
    };
    verify(
        target.epoch == current_epoch || target.epoch == previous_epoch,
        "target.epoch in [current_epoch, previous_epoch]",
    )
}

/// Every check `on_attestation` requires before it may look up or update
/// anything in `store`. See [`validate_target_epoch_against_current_time`]
/// for why this takes `data` rather than an [`Attestation`].
pub fn validate_on_attestation(
    store: &Store,
    data: AttestationData,
    is_from_block: bool,
    config: &Config,
) -> Result<()> {
    validate_on_attestation_indexed(store, data, is_from_block, config, &store.block_index())
}

/// [`validate_on_attestation`] against an already-built block index.
///
/// Takes `index` (`root -> (slot, parent_root)`, [`Store::block_index`]'s own
/// shape) for the reason [`filter_block_tree`] does: a caller validating every
/// attestation carried in one block ([`on_block_attestation`]) would otherwise
/// re-scan `Table::LiveChain` once per attestation, and that table grows one
/// row per imported block on a chain whose blocks are never pruned from it.
fn validate_on_attestation_indexed(
    store: &Store,
    data: AttestationData,
    is_from_block: bool,
    config: &Config,
    index: &HashMap<Root, (Slot, Root)>,
) -> Result<()> {
    let target = data.target;

    // If the given attestation is not from a beacon block message, we have to
    // check the target epoch scope.
    if !is_from_block {
        validate_target_epoch_against_current_time(store, data, config)?;
    }

    // Check that the epoch number and slot number are matching.
    verify(
        target.epoch == compute_epoch_at_slot(data.slot),
        "target.epoch == compute_epoch_at_slot(attestation.data.slot)",
    )?;

    // Attestation target must be for a known block. If target block is
    // unknown, delay consideration until block is found.
    verify(store.has_block(&target.root), "target.root in store.blocks")?;

    // Attestations must be for a known block. If block is unknown, delay
    // consideration until the block is found.
    let (head_block_slot, _) = *index.get(&data.beacon_block_root).ok_or(Error::SpecAssert(
        "attestation.data.beacon_block_root in store.blocks",
    ))?;
    // Attestations must not be for blocks in the future. If not, the
    // attestation should not be considered.
    verify(
        head_block_slot <= data.slot,
        "store.blocks[attestation.data.beacon_block_root].slot <= attestation.data.slot",
    )?;

    // LMD vote must be consistent with FFG vote target.
    let checkpoint_block = get_checkpoint_block(index, data.beacon_block_root, target.epoch)?;
    verify(
        target.root == checkpoint_block,
        "target.root == get_checkpoint_block(store, attestation.data.beacon_block_root, target.epoch)",
    )?;

    // Attestations can only affect the fork choice of subsequent slots. Delay
    // consideration in the fork choice until their slot is in the past.
    verify(
        get_current_slot(store, config) >= data.slot.saturating_add(1),
        "get_current_slot(store) >= attestation.data.slot + 1",
    )?;

    Ok(())
}

/// Records an attestation as each attester's latest message, for every
/// attesting index that is not a known equivocator.
///
/// An attester's latest message only ever moves to a later target epoch: an
/// attestation for an epoch already superseded by that attester's own later
/// vote is simply not the freshest thing known about them anymore.
///
/// Takes `attesting_indices` and `data` rather than an [`Attestation`]: by
/// the time [`on_attestation`] calls this, [`Attestation::verified_attesting_indices`]
/// has already resolved the one fork-specific fact this needed out of it.
pub fn update_latest_messages(
    store: &mut Store,
    attesting_indices: &[ValidatorIndex],
    data: AttestationData,
) {
    let target = data.target;
    let beacon_block_root = data.beacon_block_root;

    for &index in attesting_indices {
        if store.is_equivocating(index) {
            continue;
        }
        let should_update = match store.latest_message(index) {
            None => true,
            Some(existing) => target.epoch > existing.epoch,
        };
        if should_update {
            store.set_latest_message(
                index,
                LatestMessage {
                    epoch: target.epoch,
                    root: beacon_block_root,
                },
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------
//
// These four are the only functions in this file the specification itself
// lists as the sole ways to change `store`; each validates before it mutates
// anything, so a rejected call leaves `store` exactly as it found it, matching
// its requirement that "invalid calls to handlers must not modify store".
// [`get_head`], above, is the one non-handler that also takes `&mut Store`:
// it records the head it just computed, which is not a validity-gated
// mutation a rejected call would need rolled back, just a derived value kept
// in sync with every call.

/// Advances `store` to `time` (Unix seconds), running [`on_tick_per_slot`]
/// once per slot boundary crossed so that none of them are skipped even if
/// `time` jumps forward by more than one slot since the last call.
pub fn on_tick(store: &mut Store, time: u64, config: &Config) {
    let genesis_time = store.config().genesis_time;
    let tick_slot = time.saturating_sub(genesis_time) / config.seconds_per_slot;
    while get_current_slot(store, config) < tick_slot {
        let next_slot = get_current_slot(store, config).saturating_add(1);
        let previous_time =
            genesis_time.saturating_add(next_slot.saturating_mul(config.seconds_per_slot));
        on_tick_per_slot(store, previous_time, config);
    }
    on_tick_per_slot(store, time, config);
}

/// Validates and applies `signed_block`, adding it and its resulting
/// post-state to `store`.
///
/// Takes `signed_block` by value rather than by reference (a departure from
/// the specification's own signature, which makes no such distinction in
/// Python): every fork's block carries its whole body, and taking ownership
/// lets it move directly into
/// [`Store::insert_signed_block`](ethlambda_storage::Store::insert_signed_block)
/// on success instead of being cloned there. A caller that still needs its
/// own copy afterward clones before calling, same as the store's own state
/// entries do explicitly inside this function.
///
/// `blob_evidence` is this module's own addition, beyond the specification's
/// two-argument `on_block(store, signed_block)`: see [`DataAvailability`]'s
/// documentation for why deneb, electra, and fulu's data-availability check
/// needs one. A pre-deneb block, or one with no blob commitments, never
/// reads it; [`DataAvailability::NotRequired`] is the right value to pass in
/// that case.
pub fn on_block(
    store: &mut Store,
    signed_block: SignedBeaconBlock,
    config: &Config,
    blob_evidence: &DataAvailability,
) -> Result<()> {
    let block_root = signed_block.message_hash_tree_root();
    let parent_root = signed_block.parent_root();

    // Parent block must be known. `get_state` hands back a shared `Arc`, which
    // both checks the parent is known and gives the value to clone the copy
    // `state_transition` below mutates from: `state_transition` must not be
    // able to corrupt the parent's own cached post-state if this block turns
    // out to be invalid partway through applying it, and it can't, since this
    // is already an independent clone rather than a borrow of the store's own
    // cached entry.
    let parent_state = store
        .get_state(&parent_root)
        .expect("get")
        .ok_or(Error::SpecAssert("block.parent_root in store.block_states"))?;
    let mut state = (*parent_state).clone();

    // Blocks cannot be in the future. If they are, their consideration must
    // be delayed until they are in the past.
    verify(
        get_current_slot(store, config) >= signed_block.slot(),
        "get_current_slot(store) >= block.slot",
    )?;

    // Check that block is later than the finalized epoch slot (optimization
    // to reduce calls to get_ancestor).
    let finalized_checkpoint = store.beacon_finalized_checkpoint();
    let finalized_slot = compute_start_slot_at_epoch(finalized_checkpoint.epoch);
    verify(
        signed_block.slot() > finalized_slot,
        "block.slot > finalized_slot",
    )?;
    // Check block is a descendant of the finalized block at the checkpoint
    // finalized slot. A single-call index: see `get_ancestor`'s documentation
    // for why a per-hop lookup would be the wrong trade, which does not apply
    // to this one walk.
    let index = store.block_index();
    let finalized_checkpoint_block =
        get_checkpoint_block(&index, parent_root, finalized_checkpoint.epoch)?;
    verify(
        finalized_checkpoint.root == finalized_checkpoint_block,
        "store.finalized_checkpoint.root == finalized_checkpoint_block",
    )?;

    // [New in Deneb/Electra] Check if blob data is available. [New in Fulu]
    // The same check, over column sidecars instead of blobs. Both run before
    // `state_transition`, matching the specification's own ordering: an
    // unavailable block is not even worth transitioning.
    match &signed_block {
        SignedBeaconBlock::Deneb(block) => {
            verify(
                is_data_available_blobs(&block.message.body.blob_kzg_commitments, blob_evidence)?,
                "is_data_available(hash_tree_root(block), block.body.blob_kzg_commitments)",
            )?;
        }
        SignedBeaconBlock::Electra(block) => {
            verify(
                is_data_available_blobs(&block.message.body.blob_kzg_commitments, blob_evidence)?,
                "is_data_available(hash_tree_root(block), block.body.blob_kzg_commitments)",
            )?;
        }
        SignedBeaconBlock::Fulu(_) => {
            verify(
                is_data_available_columns(blob_evidence, config)?,
                "is_data_available(hash_tree_root(block))",
            )?;
        }
        _ => {}
    }

    // Check the block is valid and compute the post-state. See the module
    // documentation for why this always passes `ExecutionEngine::valid`.
    stf::state_transition(
        &mut state,
        &signed_block,
        true,
        config,
        &stf::ExecutionEngine::valid(),
    )?;

    // Cache the state root in the latest block header. Sound because the
    // `true` above means `state_transition` checked it against the root it
    // computed; see `BeaconState::compute_state_root`.
    state.latest_block_header_mut().state_root = signed_block.state_root();

    // [New in Bellatrix] Check the merge transition block conditions.
    // Capella's own `fork-choice.md` removes this check outright, so it
    // applies to bellatrix alone. Re-reads the store's own entry for
    // `parent_root` rather than `state`: that entry is still exactly the
    // parent's own post-state, since `state_transition` above mutated the
    // independent copy this function made of it, not the store's own.
    if let SignedBeaconBlock::Bellatrix(block) = &signed_block {
        let pre_state = store
            .get_state(&parent_root)
            .expect("get")
            .expect("checked above");
        if stf::bellatrix::is_merge_transition_block(
            &pre_state,
            &block.message.body.execution_payload,
        )? {
            validate_merge_block(store, &block.message, config)?;
        }
    }

    // Read the post-state's checkpoints out before `state` moves into the
    // store: unlike a map entry, an owned value can't be re-borrowed once
    // moved, and copying two `Checkpoint`s out is cheaper than reading the
    // whole state back from storage afterward.
    let current_justified = state.current_justified_checkpoint();
    let finalized = state.finalized_checkpoint();

    // Add new block to the store, and the new state for this block to the
    // store. `block_slot` is copied out first since `signed_block` moves next.
    let block_slot = signed_block.slot();
    store
        .insert_signed_block(block_root, signed_block)
        .expect("insert");
    store.insert_state(block_root, state).expect("insert");

    // Add block timeliness to the store.
    let time_into_slot_ms = store.ms_since_genesis() % config.slot_duration_ms;
    let epoch = get_current_store_epoch(store, config);
    let attestation_threshold_ms = get_attestation_due_ms(epoch, config);
    let is_before_attesting_interval = time_into_slot_ms < attestation_threshold_ms;
    let is_timely = get_current_slot(store, config) == block_slot && is_before_attesting_interval;
    store.set_block_timeliness(block_root, is_timely);

    // Add proposer score boost if the block is timely and not conflicting
    // with an existing block.
    let is_first_block = store.proposer_boost_root().is_zero();
    if is_timely && is_first_block {
        store.set_proposer_boost_root(block_root);
    }

    // Update checkpoints in store if necessary.
    update_checkpoints(store, current_justified, finalized);

    // Eagerly compute unrealized justification and finality.
    compute_pulled_up_tip(store, block_root, block_slot, config)?;

    Ok(())
}

/// Validates `attestation` and, if valid, records it as each attester's
/// latest message.
///
/// `is_from_block` marks an attestation carried inside a block rather than
/// received directly over gossip: [`validate_on_attestation`] skips the
/// current/previous-epoch target check for those, since a block can carry an
/// attestation for an epoch that has since passed.
pub fn on_attestation(
    store: &mut Store,
    attestation: &Attestation,
    is_from_block: bool,
    config: &Config,
) -> Result<()> {
    let data = attestation.data();
    validate_on_attestation(store, data, is_from_block, config)?;

    // The state at the `target` to fully validate attestation against.
    // `checkpoint_state` hands back an owned value now, so there is no borrow
    // of `store` left to release before `update_latest_messages` needs it
    // mutably below, unlike when this cached state lived behind a reference
    // into `store` itself.
    let target_state = checkpoint_state(store, &data.target, config)?;
    let attesting_indices = attestation.verified_attesting_indices(&target_state)?;

    // Update latest messages for attesting indices.
    update_latest_messages(store, &attesting_indices, data);

    Ok(())
}

/// [`on_attestation`] for an attestation carried inside a block, given the
/// post-state of the block that carried it.
///
/// Has the same effect on `store` as `on_attestation(store, attestation, true,
/// config)`, and reaches it without materializing the target checkpoint's
/// state. Two things make that equivalent rather than merely cheaper:
///
/// * The aggregate signature does not need checking again. `process_block`
///   ran `process_attestation` over this exact attestation on the way to
///   producing `block_state`, and that runs the same
///   `is_valid_indexed_attestation` the verifying path here would. A block
///   whose attestation failed it never became a block; one that is in the
///   store carries a verdict this node reached itself.
/// * `block_state` names the same committees the target checkpoint's state
///   would. `get_beacon_committee` for a slot in epoch `E` reads the active
///   validator set at `E` and the seed at `E`, and that seed is the randao mix
///   from `E - MIN_SEED_LOOKAHEAD - 1`, fixed before `E` began. The target
///   checkpoint is an ancestor of this block by
///   [`validate_on_attestation`]'s own LMD/FFG consistency check, so both
///   states share that history. It is the same equivalence `process_attestation`
///   relies on when it validates a previous-epoch attestation against the
///   current state.
///
/// What it buys: a target checkpoint's root is the last block at or before
/// the boundary *on the attester's branch*, so an attester whose view lagged
/// names a mid-epoch block. Once that block's post-state falls out of the
/// recency cache, [`checkpoint_state`] rebuilds a ~350MB state by replaying
/// every block since the last pinned boundary, and the attestation is not
/// even the reason the import is happening. Observed on a mainnet follower:
/// one import at 78.9s against a 3.6s steady state, on a 23-block replay for
/// a target 16 blocks behind the head.
/// `index` is [`Store::block_index`], built once for the whole block rather
/// than per attestation: it is a full `Table::LiveChain` scan, and that table
/// carries a row for every block this node ever imported.
pub fn on_block_attestation(
    store: &mut Store,
    attestation: &Attestation,
    block_state: &BeaconState,
    config: &Config,
    index: &HashMap<Root, (Slot, Root)>,
) -> Result<()> {
    let data = attestation.data();
    validate_on_attestation_indexed(store, data, true, config, index)?;

    let attesting_indices = attestation.attesting_indices(block_state)?;
    update_latest_messages(store, &attesting_indices, data);

    Ok(())
}

/// Records every validator common to both halves of `attester_slashing` as
/// equivocating, once both halves are confirmed to actually be slashable and
/// individually valid.
///
/// *Note*: the specification calls for maintaining the equivocation set from
/// at least the latest finalized checkpoint onward while syncing, which this
/// function does not enforce on its own; a caller replaying history is
/// responsible for calling this for every attester slashing it encounters
/// rather than only recent ones.
pub fn on_attester_slashing(store: &mut Store, attester_slashing: &AttesterSlashing) -> Result<()> {
    let (data_1, data_2) = attester_slashing.data();

    verify(
        is_slashable_attestation_data(&data_1, &data_2),
        "is_slashable_attestation_data(attestation_1.data, attestation_2.data)",
    )?;

    // `get_state` already hands back an owned value, so there is no borrow of
    // `store` left to release before `insert_equivocating_index` needs it
    // mutably below.
    let justified_root = store.beacon_justified_checkpoint().root;
    let state = store
        .get_state(&justified_root)
        .expect("get")
        .ok_or(Error::SpecAssert(
            "store.justified_checkpoint.root in store.block_states",
        ))?;
    let (indices_1, indices_2) = attester_slashing.verified_attesting_indices(&state)?;

    let indices_1: HashSet<ValidatorIndex> = indices_1.into_iter().collect();
    for index in indices_2 {
        if indices_1.contains(&index) {
            store.insert_equivocating_index(index);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use ethlambda_storage::backend::InMemoryBackend;

    use super::*;
    use crate::beacon::containers::BeaconBlockHeader;
    use crate::beacon::helpers::test_state;

    /// A store backed by a fresh in-memory backend, with every checkpoint at
    /// its default (genesis) value and no anchor block or state written.
    /// Tests populate only what the function under test actually reads.
    fn empty_store() -> Store {
        store_anchored_at(Root::ZERO)
    }

    /// A fresh store whose head and both realized checkpoints name `root` in
    /// the genesis epoch.
    ///
    /// Seeded at bootstrap rather than written afterwards, because the writer
    /// that moves a checkpoint moves the head with it and diffs the
    /// `BlockRoots` index across the two, so a store cannot be pointed at a
    /// root whose block it does not hold yet.
    fn store_anchored_at(root: Root) -> Store {
        let backend = Arc::new(InMemoryBackend::new());
        let anchor = Checkpoint {
            epoch: constants::GENESIS_EPOCH,
            root,
        };
        Store::init_beacon(
            backend,
            0,
            Config::active(),
            root,
            Store::beacon_checkpoint_as_stored(anchor),
        )
    }

    /// A signed block with an empty body and a zero signature, for tests that
    /// only care about `slot` and `parent_root`. Phase0-shaped since nothing
    /// under test here reads anything fork-specific.
    fn block(slot: Slot, parent_root: Root) -> SignedBeaconBlock {
        SignedBeaconBlock::Phase0(phase0::SignedBeaconBlock {
            message: phase0::BeaconBlock {
                slot,
                proposer_index: 0,
                parent_root,
                state_root: Root::ZERO,
                body: phase0::BeaconBlockBody {
                    randao_reveal: Default::default(),
                    eth1_data: Default::default(),
                    graffiti: Root::ZERO,
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

    /// An exact anchor pair: `state` is `block`'s own post-state.
    ///
    /// Built as a fixed point, the way the state transition produces one. The
    /// state's `latest_block_header` names the block with a zero `state_root`,
    /// which is how the specification leaves it inside the block's own slot;
    /// the state's root is then computed against that, and written back into
    /// the block. `BeaconBlock` and `BeaconBlockHeader` merkleize identically,
    /// five fields with the body's root standing in for the body, so the
    /// header root and the block root agree once the zero is substituted.
    fn anchor_pair() -> (BeaconState, SignedBeaconBlock) {
        anchor_pair_with(4)
    }

    /// [`anchor_pair`] over a registry of `count` validators, for the weight
    /// tests, which name a voter per validator index.
    fn anchor_pair_with(count: usize) -> (BeaconState, SignedBeaconBlock) {
        let mut state = test_state::with_validators(count);
        let parent_root = state.latest_block_header().parent_root;
        let mut signed = block(state.slot(), parent_root);

        let SignedBeaconBlock::Phase0(inner) = &signed else {
            unreachable!("`block` builds a phase0 signed block");
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
            unreachable!("`block` builds a phase0 signed block");
        };
        inner.message.state_root = state_root;

        (state, signed)
    }

    /// Advance a state one empty slot by hand, the way `process_slot` does:
    /// fill in the header's `state_root`, then move the slot on. The state is
    /// then past its own anchor block, which is the shape a checkpoint-synced
    /// anchor arrives in when the finalized epoch boundary was empty.
    fn advance_one_empty_slot(state: &mut BeaconState) {
        let root = state.hash_tree_root();
        state.latest_block_header_mut().state_root = root;
        *state.slot_mut() += 1;
    }

    /// A block index from `(root, slot, parent_root)` triples, the shape
    /// `Store::block_index` hands fork choice.
    fn index(entries: &[(Root, Slot, Root)]) -> HashMap<Root, (Slot, Root)> {
        entries
            .iter()
            .map(|&(root, slot, parent_root)| (root, (slot, parent_root)))
            .collect()
    }

    /// A store anchored on `count` validators, plus the anchor's own root and
    /// slot.
    ///
    /// The anchor is what `checkpoint_state` resolves the justified checkpoint
    /// to, which is the one thing both weight functions need from a real store.
    fn anchored_store(count: usize) -> (Store, Root, Slot) {
        let (anchor_state, anchor_block) = anchor_pair_with(count);
        let anchor_slot = anchor_state.slot();
        let anchor_root = anchor_block.message_hash_tree_root();
        let store = get_forkchoice_store(
            Arc::new(InMemoryBackend::new()),
            anchor_state,
            anchor_block,
            &Config::active(),
        )
        .expect("the pair matches");
        (store, anchor_root, anchor_slot)
    }

    /// `compute_weights` is the specification's `get_weight` for every root at
    /// once, so the two have to agree root by root: over a fork, over voters
    /// spread across both branches, and with the proposer boost applied.
    #[test]
    fn the_single_pass_weights_match_the_specifications_per_root_weight() {
        let config = Config::active();
        let (mut store, anchor_root, anchor_slot) = anchored_store(8);

        // anchor -> a -> {b, c}: a fork whose two leaves split the vote, so a
        // wrong fold shows up as a leaf carrying its sibling's balance.
        let a_root = Root::repeat_byte(0xa1);
        let b_root = Root::repeat_byte(0xb2);
        let c_root = Root::repeat_byte(0xc3);
        let index = index(&[
            (anchor_root, anchor_slot, Root::ZERO),
            (a_root, anchor_slot + 1, anchor_root),
            (b_root, anchor_slot + 2, a_root),
            (c_root, anchor_slot + 2, a_root),
        ]);

        // Three voters on `b`, one on `c`, one on the anchor itself (a vote
        // that counts for no candidate above it), and one equivocator whose
        // vote must not count at all.
        for (validator_index, root) in [(0, b_root), (1, b_root), (2, b_root), (3, c_root)] {
            store.set_latest_message(validator_index, LatestMessage { epoch: 0, root });
        }
        store.set_latest_message(
            4,
            LatestMessage {
                epoch: 0,
                root: anchor_root,
            },
        );
        store.set_latest_message(
            5,
            LatestMessage {
                epoch: 0,
                root: b_root,
            },
        );
        store.insert_equivocating_index(5);
        store.set_proposer_boost_root(b_root);

        let weights = compute_weights(&store, &index, &config).expect("the anchor state is there");

        for root in [anchor_root, a_root, b_root, c_root] {
            assert_eq!(
                weights.get(&root).copied().unwrap_or_default(),
                get_weight(&store, &index, root, &config).expect("every root is indexed"),
                "the two weights disagree at {root}"
            );
        }
        assert!(
            weights[&b_root] > weights[&c_root],
            "three voters and the boost must outweigh one voter"
        );
    }

    /// The failure a live mainnet follower hit: `promote_beacon_anchor` prunes
    /// the block index below the oldest kept anchor, and any validator whose
    /// freshest vote was for a block down there kept pointing at it. The
    /// specification's `get_weight` raises on that vote and takes the whole
    /// head computation with it; the head froze for as long as one stale voter
    /// stayed stale.
    #[test]
    fn a_vote_for_a_pruned_block_weighs_nothing_instead_of_failing() {
        let config = Config::active();
        let (mut store, anchor_root, anchor_slot) = anchored_store(8);
        let a_root = Root::repeat_byte(0xa1);
        let index = index(&[
            (anchor_root, anchor_slot, Root::ZERO),
            (a_root, anchor_slot + 1, anchor_root),
        ]);

        store.set_latest_message(
            0,
            LatestMessage {
                epoch: 0,
                root: a_root,
            },
        );
        store.set_latest_message(
            1,
            LatestMessage {
                epoch: 0,
                // Below the anchor, so no longer indexed.
                root: Root::repeat_byte(0xde),
            },
        );

        assert!(
            get_weight(&store, &index, a_root, &config).is_err(),
            "the specification's own version is what raises here; this test \
             exists because that took the whole head computation with it"
        );

        let weights = compute_weights(&store, &index, &config).expect("a pruned vote is not fatal");

        let one_validator_balance = weights[&a_root];
        assert!(one_validator_balance > 0, "the live vote still counts");
        assert_eq!(
            weights[&anchor_root], one_validator_balance,
            "and it counts exactly once, for a_root and everything it descends from"
        );
    }

    #[test]
    fn get_ancestor_walks_past_an_empty_slot_gap() {
        let genesis_root = Root::repeat_byte(1);
        let a_root = Root::repeat_byte(2);
        let b_root = Root::repeat_byte(3);

        let mut index = HashMap::new();
        index.insert(genesis_root, (0, Root::ZERO));
        index.insert(a_root, (1, genesis_root));
        // Slot 2 is empty: b's parent is a, two slots later.
        index.insert(b_root, (3, a_root));

        // At b's own slot, b is its own ancestor.
        assert_eq!(get_ancestor(&index, b_root, 3).unwrap(), b_root);
        // Querying the empty slot, or a's own slot, must land on a rather
        // than on b, since b's slot is strictly after both.
        assert_eq!(get_ancestor(&index, b_root, 2).unwrap(), a_root);
        assert_eq!(get_ancestor(&index, b_root, 1).unwrap(), a_root);
        // Querying before a's slot must walk one hop further, to genesis.
        assert_eq!(get_ancestor(&index, b_root, 0).unwrap(), genesis_root);
    }

    #[test]
    fn get_ancestor_rejects_an_unknown_root() {
        let index = HashMap::new();
        // The specification's own KeyError-on-unknown-root is exactly the
        // "unhandled exception" case it calls invalid, so this must be an
        // error rather than a panic.
        assert!(get_ancestor(&index, Root::repeat_byte(9), 0).is_err());
    }

    #[test]
    fn compute_slots_since_epoch_start_counts_from_the_epoch_boundary() {
        let epoch_start = compute_start_slot_at_epoch(3);
        assert_eq!(compute_slots_since_epoch_start(epoch_start), 0);
        assert_eq!(compute_slots_since_epoch_start(epoch_start + 1), 1);
        assert_eq!(
            compute_slots_since_epoch_start(epoch_start + preset::SLOTS_PER_EPOCH - 1),
            preset::SLOTS_PER_EPOCH - 1
        );
    }

    #[test]
    fn get_head_breaks_equal_weight_ties_by_higher_root() {
        let config = Config::active();
        let genesis_root = Root::repeat_byte(1);
        let low_root = Root::repeat_byte(2);
        let high_root = Root::repeat_byte(3);

        // Both checkpoints sit at the genesis epoch, which is what makes
        // `filter_block_tree` accept any leaf unconditionally (both of its
        // "correct_justified"/"correct_finalized" checks have a
        // `== GENESIS_EPOCH` escape hatch): the point of this test is the
        // weight tie-break in `get_head`, not the filtering rules.
        let mut store = store_anchored_at(genesis_root);

        store
            .insert_signed_block(genesis_root, block(0, Root::ZERO))
            .unwrap();
        store
            .insert_signed_block(low_root, block(1, genesis_root))
            .unwrap();
        store
            .insert_signed_block(high_root, block(1, genesis_root))
            .unwrap();

        // `get_weight` derives the justified checkpoint's state (now that
        // there is no cache to seed) from `store.get_state(&genesis_root)`,
        // only to enumerate active validators; with no latest messages
        // recorded, neither child gets any attesting balance, so both are
        // weight zero and the root comparison is all that can decide between
        // them.
        let state = crate::beacon::helpers::test_state::with_validators(1);
        store.insert_state(genesis_root, state.clone()).unwrap();
        // `get_voting_source` needs a post-state for each leaf, since both
        // children are in the store's current epoch (its clock is left at
        // the default of slot zero) and so take the "not pulled up" branch.
        store.insert_state(low_root, state.clone()).unwrap();
        store.insert_state(high_root, state).unwrap();

        let head = get_head(&mut store, &config).unwrap();
        assert_eq!(
            head, high_root,
            "a weight tie must be broken by the lexicographically higher root"
        );
    }

    #[test]
    fn get_voting_source_pulls_up_a_prior_epoch_blocks_vote() {
        let config = Config::active();
        let mut store = empty_store();
        // Put the store's clock two epochs ahead of the block below, so
        // `get_voting_source` takes the pulled-up branch
        // (`current_epoch > block_epoch`) rather than reading the block's own
        // post-state directly.
        store
            .set_time_ms(seconds_to_milliseconds(
                config.seconds_per_slot * preset::SLOTS_PER_EPOCH * 2,
            ))
            .unwrap();

        let block_root = Root::repeat_byte(5);
        store
            .insert_signed_block(block_root, block(0, Root::ZERO))
            .unwrap();

        let unrealized = Checkpoint {
            epoch: 1,
            root: Root::repeat_byte(6),
        };
        let realized = Checkpoint {
            epoch: 0,
            root: Root::repeat_byte(7),
        };
        assert_ne!(
            unrealized, realized,
            "the test must exercise two different values"
        );

        store.set_unrealized_justification(block_root, unrealized);

        let mut state = crate::beacon::helpers::test_state::with_validators(1);
        *state.current_justified_checkpoint_mut() = realized;
        store.insert_state(block_root, state).unwrap();

        let voting_source =
            get_voting_source(&store, &store.block_index(), block_root, &config).unwrap();
        assert_eq!(
            voting_source, unrealized,
            "a block from a prior epoch must vote its pulled-up (unrealized) checkpoint"
        );
    }

    #[test]
    fn get_head_persists_the_head_it_computed() {
        let config = Config::active();

        // Both checkpoints at the genesis epoch, so `filter_block_tree`
        // accepts the genesis leaf unconditionally; the point of this test is
        // the persistence side effect, not the filtering rules.
        let genesis_root = Root::repeat_byte(1);
        let mut store = store_anchored_at(genesis_root);

        store
            .insert_signed_block(genesis_root, block(0, Root::ZERO))
            .unwrap();
        let state = crate::beacon::helpers::test_state::with_validators(1);
        store.insert_state(genesis_root, state).unwrap();

        let head = get_head(&mut store, &config).expect("get_head");

        // Written on every call, so the stored value cannot drift from what a
        // fresh computation produces.
        let (slot, root) = store.beacon_head().expect("head recorded");
        assert_eq!(root, head);
        assert_eq!(slot, store.block_entry(&head).expect("head block").0);
    }

    /// The specification's assertion cannot hold for a checkpoint-synced
    /// anchor: the finalized state sits at the epoch boundary, so when that
    /// slot was empty it has advanced past its own `latest_block_header` and
    /// `block.state_root` is no longer the state's root. The header root is
    /// what still identifies the pair.
    #[test]
    fn get_forkchoice_store_accepts_a_state_advanced_past_its_anchor_block() {
        let (mut state, block) = anchor_pair();
        advance_one_empty_slot(&mut state);
        assert_ne!(block.state_root(), state.hash_tree_root());

        let store = get_forkchoice_store(
            Arc::new(InMemoryBackend::new()),
            state,
            block,
            &Config::active(),
        );

        assert!(store.is_ok(), "{:?}", store.err());
    }

    /// The exact pair, which the specification's own assertion accepts too,
    /// must keep working: a full client anchors at genesis this way.
    #[test]
    fn get_forkchoice_store_accepts_an_exact_anchor_pair() {
        let (state, block) = anchor_pair();

        let store = get_forkchoice_store(
            Arc::new(InMemoryBackend::new()),
            state,
            block,
            &Config::active(),
        );

        assert!(store.is_ok(), "{:?}", store.err());
    }

    /// Relaxing the state-root check must not accept any block at all: the
    /// header still names exactly one.
    #[test]
    fn get_forkchoice_store_rejects_a_block_the_state_does_not_name() {
        let (state, _) = anchor_pair();
        let unrelated = block(state.slot(), Root::repeat_byte(9));

        let store = get_forkchoice_store(
            Arc::new(InMemoryBackend::new()),
            state,
            unrelated,
            &Config::active(),
        );

        assert!(store.is_err());
    }
}
