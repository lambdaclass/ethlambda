//! The fork choice store: LMD GHOST, with FFG-derived justification and
//! finalization gating which branches are even eligible to be head.
//!
//! Implements `specs/phase0/fork-choice.md`, which is also every later fork's
//! fork choice through at least altair: none of them change anything here.
//! `Store` therefore accepts a block from any fork this crate implements (see
//! [`Store::blocks`]), even though the algorithm applied to it is
//! unconditionally phase0's. `Store` tracks the block tree,
//! attester votes, and the checkpoints fork choice reasons about; the four
//! handlers at the bottom of this file ([`on_tick`], [`on_block`],
//! [`on_attestation`], [`on_attester_slashing`]) are the only supported ways to
//! change it, matching the specification's own framing: "Invalid calls to
//! handlers must not modify `store`." Accordingly, every helper here takes
//! `&Store`, and only a handler takes `&mut Store`.
//!
//! # Units: one seconds-granularity clock, read out in milliseconds at the edges
//!
//! `Store.time` and `Store.genesis_time` are Unix seconds, exactly like
//! `BeaconState.genesis_time`: both [`on_tick`] and [`on_tick_per_slot`] take a
//! `time: u64` in seconds, and every slot computation on the store
//! (`get_slots_since_genesis`, `get_current_slot`) divides a seconds
//! difference by `Config::seconds_per_slot`. There is no separate
//! millisecond-granularity clock in `Store` itself.
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
//! # Why some maps here are not the spec's `Dict`
//!
//! [`Checkpoint`] derives neither `Hash` nor `Ord` in [`crate::containers`],
//! and this file cannot add either without editing that module. So
//! `checkpoint_states` is keyed on `(Epoch, Root)` instead of `Checkpoint`
//! itself; [`Store::checkpoint_state`], [`Store::has_checkpoint_state`], and
//! [`Store::insert_checkpoint_state`] hide that from every caller in this
//! file. Every other `Dict` becomes a [`std::collections::HashMap`] keyed on
//! its own spec type directly: [`Root`] and [`ValidatorIndex`] both hash the
//! way this file needs.
//!
//! # Why the hash maps here never need to be a `BTreeMap`
//!
//! The one place the specification iterates a whole `Dict`'s keys is
//! `filter_block_tree`'s scan of `store.blocks` for a block's children, and
//! [`get_head`]'s equivalent scan of the filtered tree. Both immediately
//! reduce that scan to a single winner via an explicit, fully-ordered sort key
//! (`(weight, root)`, with `root` breaking ties the same way Python compares
//! two `bytes` values, since [`Root`]'s `Ord` compares its bytes in the same
//! order). Two distinct blocks never share a root, so that key never actually
//! ties, and the winner is the same regardless of which order the underlying
//! map happened to yield its entries in. Nothing else in this file examines a
//! map's keys as a whole, so no map here needs an order of its own.
//!
//! # `Store::blocks` holds signed blocks, not the specification's unsigned ones
//!
//! The specification's `store.blocks: Dict[Root, BeaconBlock]` holds the
//! unsigned message. This file holds [`SignedBeaconBlock`] instead: it is
//! what every caller already has in hand (a fixture case, a gossiped block, a
//! `BlocksByRoot` response), the extra signature is small next to a full
//! body, and the map stays keyed on the *unsigned* message's root
//! ([`SignedBeaconBlock::message_hash_tree_root`]), so nothing about lookup or
//! ancestry changes. [`get_forkchoice_store`]'s `anchor_block` is signed for
//! the same reason, even though a trusted anchor's own signature is never
//! actually checked.
//!
//! Holding the fork-generic enum here, rather than a concrete per-fork
//! struct, is what lets [`on_block`] accept a block from any fork this crate
//! implements: every place in this file that reads a field off a stored block
//! goes through the enum's shared accessors (`slot()`, `parent_root()`, and
//! so on) rather than a phase0-specific field.
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
//! documentation above. `AttestationData` (`crate::containers::shared`) is
//! already fork-invariant, so every function below except the two enums'
//! own methods reads it directly rather than matching on a fork tag it does
//! not need: [`validate_on_attestation`] and [`update_latest_messages`] take
//! `AttestationData` and a resolved `&[ValidatorIndex]`, not an
//! [`Attestation`]. The one place a fork's own shape actually matters is
//! resolving an [`Attestation`] into the attesters it names and checking
//! their aggregate signature, which needs the fork-specific
//! `get_indexed_attestation`/`is_valid_indexed_attestation` pair
//! ([`crate::helpers::attestation`] for phase0, [`crate::helpers::electra`]
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
//!   against [`Store::pow_blocks`] rather than a real execution client, the
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

use crate::config::Config;
use crate::constants;
use crate::containers::{AttestationData, BeaconState, Checkpoint, SignedBeaconBlock};
use crate::containers::{bellatrix, deneb, electra, fulu, phase0};
use crate::error::{Error, Result, verify};
use crate::helpers::accessors::{
    get_active_validator_indices, get_beacon_proposer_index, get_current_epoch,
    get_total_active_balance,
};
use crate::helpers::attestation as phase0_attestation;
use crate::helpers::electra as electra_helpers;
use crate::helpers::misc::{compute_epoch_at_slot, compute_start_slot_at_epoch};
use crate::helpers::predicates::is_slashable_attestation_data;
use crate::kzg;
use crate::preset;
use crate::primitives::{Epoch, Gwei, KzgCommitment, KzgProof, Root, Slot, ValidatorIndex};
use crate::stf;
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
        match self {
            Attestation::Phase0(attestation) => {
                let indexed = phase0_attestation::get_indexed_attestation(state, attestation)?;
                verify(
                    phase0_attestation::is_valid_indexed_attestation(state, &indexed),
                    "is_valid_indexed_attestation(target_state, indexed_attestation)",
                )?;
                Ok(indexed.attesting_indices.into_inner())
            }
            Attestation::Electra(attestation) => {
                let indexed = electra_helpers::get_indexed_attestation(state, attestation)?;
                verify(
                    electra_helpers::is_valid_indexed_attestation(state, &indexed),
                    "is_valid_indexed_attestation(target_state, indexed_attestation)",
                )?;
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

/// Re-exported so this module's signatures name the same type the DB-backed
/// store builds. See [`ethlambda_storage::BeaconBlockIndex`].
pub type BeaconBlockIndex = HashMap<Root, (Slot, Root)>;

/// The fork choice store.
///
/// Constructed once, at genesis or at a checkpoint-sync anchor, by
/// [`get_forkchoice_store`], and after that changed only by the four handlers
/// at the bottom of this file. The specification requires that an invalid
/// call to any of them leave `store` untouched; the `Result`-returning
/// handlers below uphold that by validating before mutating, rather than by
/// rolling a partial mutation back.
///
/// Does not implement `Clone`. `block_states` and `checkpoint_states` each
/// hold a full [`BeaconState`] per entry, and the store keeps one for every
/// block still within the unfinalized window, so a whole-store clone would
/// silently duplicate an unbounded amount of state on every call. Nothing in
/// this file, or in the specification, ever needs a copy of the whole store.
#[derive(Debug)]
pub struct Store {
    /// The current time, as Unix seconds. See the module documentation for how
    /// this relates to the millisecond deadlines the reorg helpers compute.
    time: u64,
    genesis_time: u64,
    justified_checkpoint: Checkpoint,
    finalized_checkpoint: Checkpoint,
    /// The highest justified checkpoint observed in any block's post-state,
    /// whether or not that block's *own* chain has an on-chain epoch boundary
    /// that has caught up to reflect it yet.
    unrealized_justified_checkpoint: Checkpoint,
    /// The finalized-checkpoint counterpart to
    /// [`Store::unrealized_justified_checkpoint`].
    unrealized_finalized_checkpoint: Checkpoint,
    /// The most recent timely, uncontested block seen this slot, or the zero
    /// root if none has arrived yet or a new slot has reset it. While set,
    /// [`get_weight`] adds [`get_proposer_score`]'s boost to this block and
    /// every ancestor of it.
    proposer_boost_root: Root,
    /// Validators caught attesting to two conflicting things, via
    /// [`on_attester_slashing`]. [`get_weight`] excludes their vote entirely,
    /// rather than letting an equivocator's [`LatestMessage`] count for either
    /// side of the fork it created.
    pub equivocating_indices: HashSet<ValidatorIndex>,
    /// Keyed on the unsigned message's root, matching the specification's own
    /// `store.blocks`, even though the value held here is signed. See the
    /// module documentation for why.
    blocks: HashMap<Root, SignedBeaconBlock>,
    /// The post-state resulting from applying each block in
    /// [`Store::blocks`].
    pub block_states: HashMap<Root, BeaconState>,
    /// Whether each block in [`Store::blocks`] arrived before the attestation
    /// deadline of the slot fork choice was in when it was imported. Feeds
    /// [`is_head_late`], one of the inputs to a same-slot proposer reorg.
    block_timeliness: HashMap<Root, bool>,
    /// The state advanced to the first slot of each checkpoint's epoch, cached
    /// so that [`on_attestation`] does not replay [`stf::process_slots`] for
    /// every attestation that shares a target.
    ///
    /// Keyed on `(Epoch, Root)` rather than [`Checkpoint`] itself; see the
    /// module documentation. Read and write through
    /// [`Store::checkpoint_state`], [`Store::has_checkpoint_state`], and
    /// [`Store::insert_checkpoint_state`] rather than this field.
    checkpoint_states: HashMap<(Epoch, Root), BeaconState>,
    pub latest_messages: HashMap<ValidatorIndex, LatestMessage>,
    /// The unrealized justified checkpoint observed in each block's own
    /// post-state, kept up to date by [`compute_pulled_up_tip`] so that
    /// [`get_voting_source`] can "pull up" an older block's effective vote
    /// without replaying epoch processing on every lookup.
    pub unrealized_justifications: HashMap<Root, Checkpoint>,
    /// PoW blocks known to this store, keyed by [`PowBlock::block_hash`]. See
    /// [`PowBlock`]'s documentation for why this stands in for
    /// `get_pow_block` rather than this file calling out to a real execution
    /// client. Read through [`get_pow_block`], written through
    /// [`insert_pow_block`].
    pub pow_blocks: HashMap<Root, PowBlock>,
}

impl Store {
    /// The current time, as Unix seconds. See the module documentation for how
    /// this relates to the millisecond deadlines the reorg helpers compute.
    pub fn beacon_time(&self) -> u64 {
        self.time
    }

    /// Sets [`Store::beacon_time`].
    pub fn set_beacon_time(&mut self, time: u64) {
        self.time = time;
    }

    /// Genesis, as Unix seconds.
    pub fn beacon_genesis_time(&self) -> u64 {
        self.genesis_time
    }

    /// The justified checkpoint fork choice is currently descending from.
    pub fn beacon_justified_checkpoint(&self) -> Checkpoint {
        self.justified_checkpoint
    }

    /// Sets [`Store::beacon_justified_checkpoint`]. No monotonicity check:
    /// [`update_checkpoints`] owns that rule.
    pub fn set_beacon_justified_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.justified_checkpoint = checkpoint;
    }

    /// The finalized checkpoint. Fork choice never descends below it.
    pub fn beacon_finalized_checkpoint(&self) -> Checkpoint {
        self.finalized_checkpoint
    }

    /// Sets [`Store::beacon_finalized_checkpoint`].
    pub fn set_beacon_finalized_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.finalized_checkpoint = checkpoint;
    }

    /// The highest justified checkpoint observed in any block's post-state.
    pub fn beacon_unrealized_justified_checkpoint(&self) -> Checkpoint {
        self.unrealized_justified_checkpoint
    }

    /// Sets [`Store::beacon_unrealized_justified_checkpoint`].
    pub fn set_beacon_unrealized_justified_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.unrealized_justified_checkpoint = checkpoint;
    }

    /// The finalized counterpart to
    /// [`Store::beacon_unrealized_justified_checkpoint`].
    pub fn beacon_unrealized_finalized_checkpoint(&self) -> Checkpoint {
        self.unrealized_finalized_checkpoint
    }

    /// Sets [`Store::beacon_unrealized_finalized_checkpoint`].
    pub fn set_beacon_unrealized_finalized_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.unrealized_finalized_checkpoint = checkpoint;
    }

    /// The most recent timely, uncontested block seen this slot, or the zero
    /// root if none has arrived yet or a new slot has reset it.
    pub fn proposer_boost_root(&self) -> Root {
        self.proposer_boost_root
    }

    /// Sets [`Store::proposer_boost_root`].
    pub fn set_proposer_boost_root(&mut self, root: Root) {
        self.proposer_boost_root = root;
    }

    /// The block stored under `root`, body and all.
    pub fn beacon_block(&self, root: Root) -> Option<SignedBeaconBlock> {
        self.blocks.get(&root).cloned()
    }

    /// `root`'s slot and parent root, without decoding its body.
    pub fn beacon_block_entry(&self, root: Root) -> Option<(Slot, Root)> {
        self.blocks
            .get(&root)
            .map(|block| (block.slot(), block.parent_root()))
    }

    /// Whether a block is stored under `root`.
    pub fn has_beacon_block(&self, root: Root) -> bool {
        self.blocks.contains_key(&root)
    }

    /// Records `block` under `root`, the root of its unsigned message.
    pub fn insert_beacon_block(&mut self, root: Root, block: &SignedBeaconBlock) {
        self.blocks.insert(root, block.clone());
    }

    /// Every stored block as `root -> (slot, parent_root)`.
    ///
    /// Built once per tree walk and passed down, rather than re-read per hop:
    /// [`get_weight`] calls [`get_ancestor`] once per active validator, so a
    /// lookup per hop would multiply a scan the specification already writes as
    /// naive by a backend round trip.
    pub fn beacon_block_index(&self) -> BeaconBlockIndex {
        self.blocks
            .iter()
            .map(|(root, block)| (*root, (block.slot(), block.parent_root())))
            .collect()
    }

    /// Whether `root`'s block arrived before the attestation deadline of the
    /// slot fork choice was in when it was imported.
    pub fn block_timeliness(&self, root: Root) -> Option<bool> {
        self.block_timeliness.get(&root).copied()
    }

    /// Sets [`Store::block_timeliness`].
    pub fn set_block_timeliness(&mut self, root: Root, timely: bool) {
        self.block_timeliness.insert(root, timely);
    }

    /// The cached state at `checkpoint`, if [`store_target_checkpoint_state`]
    /// (or [`get_forkchoice_store`], for the anchor checkpoint) has already
    /// computed one.
    pub fn checkpoint_state(&self, checkpoint: &Checkpoint) -> Option<&BeaconState> {
        self.checkpoint_states
            .get(&(checkpoint.epoch, checkpoint.root))
    }

    /// Whether [`Store::checkpoint_state`] would return `Some` for
    /// `checkpoint`.
    pub fn has_checkpoint_state(&self, checkpoint: &Checkpoint) -> bool {
        self.checkpoint_states
            .contains_key(&(checkpoint.epoch, checkpoint.root))
    }

    /// Caches `state` as the state at `checkpoint`.
    pub fn insert_checkpoint_state(&mut self, checkpoint: Checkpoint, state: BeaconState) {
        self.checkpoint_states
            .insert((checkpoint.epoch, checkpoint.root), state);
    }
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
    anchor_state: BeaconState,
    anchor_block: SignedBeaconBlock,
    config: &Config,
) -> Result<Store> {
    // The specification's `BeaconState` and `BeaconBlock` are already one
    // fork's own types, so a mismatch between them cannot even be expressed
    // there; here both are enums, so this crate has to enforce the invariant
    // by hand, the same way `stf::state_transition` does for every later
    // block.
    verify(
        anchor_block.fork_name() == anchor_state.fork_name(),
        "anchor_block's fork matches anchor_state's",
    )?;
    verify(
        anchor_block.state_root() == anchor_state.hash_tree_root(),
        "anchor_block.state_root == hash_tree_root(anchor_state)",
    )?;

    let anchor_root = anchor_block.message_hash_tree_root();
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
    let genesis_time = anchor_state.genesis_time();

    let mut blocks = HashMap::new();
    blocks.insert(anchor_root, anchor_block);

    let mut block_states = HashMap::new();
    // The specification stores the anchor state under both `block_states` and
    // `checkpoint_states` (`copy(anchor_state)` in each). This is the only
    // place in this file that clones a whole `BeaconState` outright: genesis
    // happens once, and the two maps each need their own entry to
    // independently advance from here on.
    block_states.insert(anchor_root, anchor_state.clone());

    let mut checkpoint_states = HashMap::new();
    checkpoint_states.insert(
        (justified_checkpoint.epoch, justified_checkpoint.root),
        anchor_state,
    );

    let mut unrealized_justifications = HashMap::new();
    unrealized_justifications.insert(anchor_root, justified_checkpoint);

    Ok(Store {
        time,
        genesis_time,
        justified_checkpoint,
        finalized_checkpoint,
        unrealized_justified_checkpoint: justified_checkpoint,
        unrealized_finalized_checkpoint: finalized_checkpoint,
        proposer_boost_root: Root::zero(),
        equivocating_indices: HashSet::new(),
        blocks,
        block_states,
        block_timeliness: HashMap::new(),
        checkpoint_states,
        latest_messages: HashMap::new(),
        unrealized_justifications,
        pow_blocks: HashMap::new(),
    })
}

// ---------------------------------------------------------------------------
// Time and slot helpers
// ---------------------------------------------------------------------------

/// How many whole slots have elapsed since genesis, as of `store.time`.
pub fn get_slots_since_genesis(store: &Store, config: &Config) -> u64 {
    store
        .beacon_time()
        .saturating_sub(store.beacon_genesis_time())
        / config.seconds_per_slot
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
pub fn get_ancestor(index: &BeaconBlockIndex, root: Root, slot: Slot) -> Result<Root> {
    let mut root = root;
    loop {
        let (block_slot, parent_root) = index
            .get(&root)
            .copied()
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
/// at that epoch's first slot.
pub fn get_checkpoint_block(index: &BeaconBlockIndex, root: Root, epoch: Epoch) -> Result<Root> {
    get_ancestor(index, root, compute_start_slot_at_epoch(epoch))
}

/// The extra weight a timely, uncontested block gets over its competitors,
/// scaled to deter a "balancing" attack that splits votes right at a slot
/// boundary.
///
/// See [`calculate_committee_fraction`] for why this divides by a bare
/// `100` rather than [`constants::BASIS_POINTS`].
pub fn get_proposer_score(store: &Store, config: &Config) -> Result<Gwei> {
    let justified_state = store
        .checkpoint_state(&store.beacon_justified_checkpoint())
        .ok_or(Error::SpecAssert(
            "store.justified_checkpoint in store.checkpoint_states",
        ))?;
    let committee_weight = get_total_active_balance(justified_state)? / preset::SLOTS_PER_EPOCH;
    Ok(committee_weight.saturating_mul(config.proposer_score_boost) / 100)
}

/// The LMD GHOST weight of `root`: the effective balance of every
/// non-equivocating, active, unslashed validator whose latest vote descends
/// through `root`, plus the proposer boost if it applies.
pub fn get_weight(
    store: &Store,
    index: &BeaconBlockIndex,
    root: Root,
    config: &Config,
) -> Result<Gwei> {
    let state = store
        .checkpoint_state(&store.beacon_justified_checkpoint())
        .ok_or(Error::SpecAssert(
            "store.justified_checkpoint in store.checkpoint_states",
        ))?;
    let current_epoch = get_current_epoch(state);
    let (block_slot, _parent_root) = index
        .get(&root)
        .copied()
        .ok_or(Error::SpecAssert("root in store.blocks"))?;

    // `validator_index` rather than the specification's own `i`: `index` is the
    // block index this walk takes, and shadowing it here would silently make
    // `get_ancestor` below take the validator instead.
    let mut attestation_score: Gwei = 0;
    for validator_index in get_active_validator_indices(state, current_epoch) {
        let validator = state.validator(validator_index)?;
        if validator.slashed || store.equivocating_indices.contains(&validator_index) {
            continue;
        }
        let Some(message) = store.latest_messages.get(&validator_index) else {
            continue;
        };
        if get_ancestor(index, message.root, block_slot)? == root {
            attestation_score = attestation_score.saturating_add(validator.effective_balance);
        }
    }

    if store.proposer_boost_root().is_zero() {
        return Ok(attestation_score);
    }

    let mut proposer_score: Gwei = 0;
    if get_ancestor(index, store.proposer_boost_root(), block_slot)? == root {
        proposer_score = get_proposer_score(store, config)?;
    }
    Ok(attestation_score.saturating_add(proposer_score))
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
    index: &BeaconBlockIndex,
    block_root: Root,
    config: &Config,
) -> Result<Checkpoint> {
    let (block_slot, _parent_root) = index
        .get(&block_root)
        .copied()
        .ok_or(Error::SpecAssert("block_root in store.blocks"))?;
    let current_epoch = get_current_store_epoch(store, config);
    let block_epoch = compute_epoch_at_slot(block_slot);

    if current_epoch > block_epoch {
        store
            .unrealized_justifications
            .get(&block_root)
            .copied()
            .ok_or(Error::SpecAssert(
                "block_root in store.unrealized_justifications",
            ))
    } else {
        let head_state = store
            .block_states
            .get(&block_root)
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
/// Borrows `blocks` for the whole walk instead of the specification's owned
/// output dict, so this never clones a [`SignedBeaconBlock`] just to hand a
/// second reference to it to the caller.
pub fn filter_block_tree(
    store: &Store,
    index: &BeaconBlockIndex,
    block_root: Root,
    blocks: &mut HashSet<Root>,
    config: &Config,
) -> Result<bool> {
    // The specification indexes `store.blocks[block_root]` here, so an unknown
    // root is its own "unhandled exception" case rather than a childless leaf.
    // Kept explicit: without it a bad root would fall through to the leaf branch
    // and surface as some unrelated-looking error two calls later.
    verify(
        index.contains_key(&block_root),
        "block_root in store.blocks",
    )?;

    let children: Vec<Root> = index
        .iter()
        .filter(|(_, (_, parent_root))| *parent_root == block_root)
        .map(|(root, _)| *root)
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
            blocks.insert(block_root);
            return Ok(true);
        }
        return Ok(false);
    }

    let current_epoch = get_current_store_epoch(store, config);
    let voting_source = get_voting_source(store, index, block_root, config)?;

    // The voting source should be either at the same height as the store's
    // justified checkpoint or not more than two epochs ago.
    let justified = store.beacon_justified_checkpoint();
    let correct_justified = justified.epoch == constants::GENESIS_EPOCH
        || voting_source.epoch == justified.epoch
        || voting_source.epoch.saturating_add(2) >= current_epoch;

    let finalized = store.beacon_finalized_checkpoint();
    let finalized_checkpoint_block = get_checkpoint_block(index, block_root, finalized.epoch)?;

    let correct_finalized =
        finalized.epoch == constants::GENESIS_EPOCH || finalized.root == finalized_checkpoint_block;

    // If expected finalized/justified, add to viable block-tree and signal
    // viability to parent.
    if correct_justified && correct_finalized {
        blocks.insert(block_root);
        return Ok(true);
    }

    Ok(false)
}

/// The filtered block tree: every block, from the justified checkpoint down,
/// whose leaf state's justified/finalized info agrees with `store`'s own.
pub fn get_filtered_block_tree(
    store: &Store,
    index: &BeaconBlockIndex,
    config: &Config,
) -> Result<HashSet<Root>> {
    let base = store.beacon_justified_checkpoint().root;
    let mut blocks = HashSet::new();
    filter_block_tree(store, index, base, &mut blocks, config)?;
    Ok(blocks)
}

/// The LMD GHOST head: starting from the justified checkpoint, repeatedly
/// step to the child with the greatest weight until a leaf is reached.
pub fn get_head(store: &Store, config: &Config) -> Result<Root> {
    let index = store.beacon_block_index();
    let blocks = get_filtered_block_tree(store, &index, config)?;
    let mut head = store.beacon_justified_checkpoint().root;
    loop {
        let children: Vec<Root> = blocks
            .iter()
            .copied()
            .filter(|root| index.get(root).is_some_and(|(_, parent)| *parent == head))
            .collect();
        if children.is_empty() {
            return Ok(head);
        }

        // Sort by latest attesting balance with ties broken lexicographically,
        // favoring the higher root: pairing the weight with the root itself as
        // the sort key gives exactly that, and `Root`'s derived `Ord` compares
        // its bytes in order, matching Python's default comparison of a
        // `bytes` root.
        let mut ranked = Vec::with_capacity(children.len());
        for root in children {
            ranked.push((get_weight(store, &index, root, config)?, root));
        }
        head = ranked
            .into_iter()
            .max()
            .expect("children is non-empty, checked above")
            .1;
    }
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
    if justified.epoch > store.beacon_justified_checkpoint().epoch {
        store.set_beacon_justified_checkpoint(justified);
    }
    if finalized.epoch > store.beacon_finalized_checkpoint().epoch {
        store.set_beacon_finalized_checkpoint(finalized);
    }
}

/// The unrealized-checkpoint counterpart to [`update_checkpoints`].
pub fn update_unrealized_checkpoints(
    store: &mut Store,
    unrealized_justified: Checkpoint,
    unrealized_finalized: Checkpoint,
) {
    if unrealized_justified.epoch > store.beacon_unrealized_justified_checkpoint().epoch {
        store.set_beacon_unrealized_justified_checkpoint(unrealized_justified);
    }
    if unrealized_finalized.epoch > store.beacon_unrealized_finalized_checkpoint().epoch {
        store.set_beacon_unrealized_finalized_checkpoint(unrealized_finalized);
    }
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
/// the deadline is a fixed fraction of the slot in every epoch this crate
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
// ever reorging out a late block; this crate implements them so a validator
// client built on it can make that choice instead of having it made for it.

/// Whether `head_root`'s block arrived after the attestation deadline of the
/// slot it was imported in.
pub fn is_head_late(store: &Store, head_root: Root) -> Result<bool> {
    let timely = store
        .block_timeliness(head_root)
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
        .unrealized_justifications
        .get(&head_root)
        .ok_or(Error::SpecAssert(
            "head_root in store.unrealized_justifications",
        ))?;
    let parent = store
        .unrealized_justifications
        .get(&parent_root)
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
    let seconds_since_genesis = store
        .beacon_time()
        .saturating_sub(store.beacon_genesis_time());
    let time_into_slot_ms =
        seconds_to_milliseconds(seconds_since_genesis) % config.slot_duration_ms;
    let epoch = get_current_store_epoch(store, config);
    time_into_slot_ms <= get_proposer_reorg_cutoff_ms(epoch, config)
}

/// Whether `head_root` has few enough votes to be overpowered by the
/// proposer's own boost, i.e. reorging it out would not be fighting an
/// already-decisive lead.
pub fn is_head_weak(
    store: &Store,
    index: &BeaconBlockIndex,
    head_root: Root,
    config: &Config,
) -> Result<bool> {
    let justified_state = store
        .checkpoint_state(&store.beacon_justified_checkpoint())
        .ok_or(Error::SpecAssert(
            "store.justified_checkpoint in store.checkpoint_states",
        ))?;
    let reorg_threshold =
        calculate_committee_fraction(justified_state, config.reorg_head_weight_threshold)?;
    Ok(get_weight(store, index, head_root, config)? < reorg_threshold)
}

/// Whether `parent_root` already has enough votes of its own that the missing
/// votes are assigned to it rather than being hoarded elsewhere.
pub fn is_parent_strong(
    store: &Store,
    index: &BeaconBlockIndex,
    parent_root: Root,
    config: &Config,
) -> Result<bool> {
    let justified_state = store
        .checkpoint_state(&store.beacon_justified_checkpoint())
        .ok_or(Error::SpecAssert(
            "store.justified_checkpoint in store.checkpoint_states",
        ))?;
    let parent_threshold =
        calculate_committee_fraction(justified_state, config.reorg_parent_weight_threshold)?;
    Ok(get_weight(store, index, parent_root, config)? > parent_threshold)
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
    let index = store.beacon_block_index();
    let (head_slot, parent_root) = index
        .get(&head_root)
        .copied()
        .ok_or(Error::SpecAssert("head_root in store.blocks"))?;
    let (parent_slot, _grandparent_root) = index
        .get(&parent_root)
        .copied()
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
    let head_weak = is_head_weak(store, &index, head_root, config)?;

    // Check that the missing votes are assigned to the parent and not being
    // hoarded.
    let parent_strong = is_parent_strong(store, &index, parent_root, config)?;

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
/// than this crate guessing at one; the fixture suites that exercise this
/// supply a fixed answer directly, the same way [`stf::ExecutionEngine`]
/// stands in for a real execution client elsewhere in this crate.
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
    let index = store.beacon_block_index();
    let (head_slot, parent_root) = index
        .get(&head_root)
        .copied()
        .ok_or(Error::SpecAssert("head_root in store.blocks"))?;
    let (parent_slot, _grandparent_root) = index
        .get(&parent_root)
        .copied()
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
    // propose the next block. A clone, matching the specification's own
    // `.copy()`: advancing it to `proposal_slot` is only how this samples the
    // proposer that slot would draw, not a change
    // `store.block_states[parent_root]` should keep.
    let mut parent_state_advanced = store
        .block_states
        .get(&parent_root)
        .ok_or(Error::SpecAssert("parent_root in store.block_states"))?
        .clone();
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
            is_head_weak(store, &index, head_root, config)?,
            is_parent_strong(store, &index, parent_root, config)?,
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
/// [`Store::pow_blocks`] rather than calling out to a real execution client.
pub fn get_pow_block(store: &Store, hash: Root) -> Option<PowBlock> {
    store.pow_blocks.get(&hash).copied()
}

/// Records `pow_block` so later [`get_pow_block`] lookups by its own hash can
/// find it. Not one of the four handlers at the bottom of this file: there is
/// no validity condition to check first, since this only ever adds data a
/// fixture suite's `on_merge_block` step already trusts.
pub fn insert_pow_block(store: &mut Store, pow_block: PowBlock) {
    store.pow_blocks.insert(pow_block.block_hash, pow_block);
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
    index: &BeaconBlockIndex,
    block_root: Root,
    config: &Config,
) -> Result<()> {
    // A clone, matching the specification's own `.copy()`: this advances a
    // throwaway copy of the block's post-state to the next epoch boundary, and
    // `store.block_states[block_root]` must be left exactly as the block
    // itself produced it.
    let mut state = store
        .block_states
        .get(&block_root)
        .ok_or(Error::SpecAssert("block_root in store.block_states"))?
        .clone();

    // Through the fork-dispatching wrapper rather than phase0's version
    // directly. Altair rewrote this step to read participation flags instead of
    // replaying stored attestations, so calling phase0's against an altair or
    // later state fails outright, which is what made every `fork_choice` case
    // that crosses an epoch boundary fail.
    stf::epoch::process_justification_and_finalization(&mut state, config)?;

    let current_justified = state.current_justified_checkpoint();
    let finalized = state.finalized_checkpoint();

    store
        .unrealized_justifications
        .insert(block_root, current_justified);
    update_unrealized_checkpoints(store, current_justified, finalized);

    // If the block is from a prior epoch, apply the realized values.
    let (block_slot, _parent_root) = index
        .get(&block_root)
        .copied()
        .ok_or(Error::SpecAssert("block_root in store.blocks"))?;
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

    store.set_beacon_time(time);

    let current_slot = get_current_slot(store, config);

    // If this is a new slot, reset store.proposer_boost_root.
    if current_slot > previous_slot {
        store.set_proposer_boost_root(Root::zero());
    }

    // If a new epoch, pull-up justification and finalization from previous
    // epoch.
    if current_slot > previous_slot && compute_slots_since_epoch_start(current_slot) == 0 {
        let justified = store.beacon_unrealized_justified_checkpoint();
        let finalized = store.beacon_unrealized_finalized_checkpoint();
        update_checkpoints(store, justified, finalized);
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
    verify(
        store.has_beacon_block(target.root),
        "target.root in store.blocks",
    )?;

    // Attestations must be for a known block. If block is unknown, delay
    // consideration until the block is found.
    let index = store.beacon_block_index();
    let (head_block_slot, _parent_root) =
        index
            .get(&data.beacon_block_root)
            .copied()
            .ok_or(Error::SpecAssert(
                "attestation.data.beacon_block_root in store.blocks",
            ))?;
    // Attestations must not be for blocks in the future. If not, the
    // attestation should not be considered.
    verify(
        head_block_slot <= data.slot,
        "store.blocks[attestation.data.beacon_block_root].slot <= attestation.data.slot",
    )?;

    // LMD vote must be consistent with FFG vote target.
    let checkpoint_block = get_checkpoint_block(&index, data.beacon_block_root, target.epoch)?;
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

/// Caches the state at `target`'s epoch boundary if [`Store::checkpoint_state`]
/// does not already have one.
pub fn store_target_checkpoint_state(
    store: &mut Store,
    target: Checkpoint,
    config: &Config,
) -> Result<()> {
    if store.has_checkpoint_state(&target) {
        return Ok(());
    }

    // A clone, matching the specification's own `copy(store.block_states[...])`:
    // `process_slots` below advances this copy toward the checkpoint's epoch
    // boundary in place, and `store.block_states[target.root]` must be left as
    // the block itself produced it, for whatever else still reads it at its
    // own slot.
    let mut base_state = store
        .block_states
        .get(&target.root)
        .ok_or(Error::SpecAssert("target.root in store.block_states"))?
        .clone();

    let target_slot = compute_start_slot_at_epoch(target.epoch);
    if base_state.slot() < target_slot {
        stf::process_slots(&mut base_state, target_slot, config)?;
    }

    store.insert_checkpoint_state(target, base_state);
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
        if store.equivocating_indices.contains(&index) {
            continue;
        }
        let should_update = match store.latest_messages.get(&index) {
            None => true,
            Some(existing) => target.epoch > existing.epoch,
        };
        if should_update {
            store.latest_messages.insert(
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
// These four are the only functions in this file that take `&mut Store`.
// Each validates before it mutates anything, so a rejected call leaves
// `store` exactly as it found it, matching the specification's requirement
// that "invalid calls to handlers must not modify store".

/// Advances `store` to `time` (Unix seconds), running [`on_tick_per_slot`]
/// once per slot boundary crossed so that none of them are skipped even if
/// `time` jumps forward by more than one slot since the last call.
pub fn on_tick(store: &mut Store, time: u64, config: &Config) {
    let tick_slot = time.saturating_sub(store.beacon_genesis_time()) / config.seconds_per_slot;
    while get_current_slot(store, config) < tick_slot {
        let next_slot = get_current_slot(store, config).saturating_add(1);
        let previous_time = store
            .genesis_time
            .saturating_add(next_slot.saturating_mul(config.seconds_per_slot));
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
/// lets it move directly into [`Store::blocks`] on success instead of being
/// cloned there. A caller that still needs its own copy afterward clones
/// before calling, same as [`Store::block_states`]'s entries do explicitly
/// inside this function.
///
/// `blob_evidence` is this crate's own addition, beyond the specification's
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

    // Parent block must be known.
    verify(
        store.block_states.contains_key(&parent_root),
        "block.parent_root in store.block_states",
    )?;
    // Make a copy of the state to avoid mutability issues: `state_transition`
    // below must not be able to corrupt the parent's own post-state if this
    // block turns out to be invalid partway through applying it.
    let mut state = store
        .block_states
        .get(&parent_root)
        .expect("just checked above")
        .clone();

    // Blocks cannot be in the future. If they are, their consideration must
    // be delayed until they are in the past.
    verify(
        get_current_slot(store, config) >= signed_block.slot(),
        "get_current_slot(store) >= block.slot",
    )?;

    // Check that block is later than the finalized epoch slot (optimization
    // to reduce calls to get_ancestor).
    let finalized_slot = compute_start_slot_at_epoch(store.beacon_finalized_checkpoint().epoch);
    verify(
        signed_block.slot() > finalized_slot,
        "block.slot > finalized_slot",
    )?;
    // Check block is a descendant of the finalized block at the checkpoint
    // finalized slot. One index build serves both this walk and
    // `compute_pulled_up_tip`'s below, so a block import scans `LiveChain` once
    // rather than twice. That scan is bounded by the unfinalized window, since
    // anchor promotion prunes the index behind finalization.
    let index = store.beacon_block_index();
    let finalized_checkpoint_block = get_checkpoint_block(
        &index,
        parent_root,
        store.beacon_finalized_checkpoint().epoch,
    )?;
    verify(
        store.beacon_finalized_checkpoint().root == finalized_checkpoint_block,
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

    // [New in Bellatrix] Check the merge transition block conditions.
    // Capella's own `fork-choice.md` removes this check outright, so it
    // applies to bellatrix alone. Reads `store.block_states[parent_root]`
    // rather than `state`: that entry is still exactly the parent's own
    // post-state, since `state_transition` above mutated the *clone* this
    // function made of it, not the store's own copy.
    if let SignedBeaconBlock::Bellatrix(block) = &signed_block {
        let pre_state = store.block_states.get(&parent_root).expect("checked above");
        if stf::bellatrix::is_merge_transition_block(
            pre_state,
            &block.message.body.execution_payload,
        )? {
            validate_merge_block(store, &block.message, config)?;
        }
    }

    // Add new block to the store, and the new state for this block to the
    // store.
    let block_slot = signed_block.slot();
    store.insert_beacon_block(block_root, &signed_block);
    store.block_states.insert(block_root, state);

    // Add block timeliness to the store.
    let seconds_since_genesis = store
        .beacon_time()
        .saturating_sub(store.beacon_genesis_time());
    let time_into_slot_ms =
        seconds_to_milliseconds(seconds_since_genesis) % config.slot_duration_ms;
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

    // Update checkpoints in store if necessary. Read out of the post-state
    // before calling `update_checkpoints`, rather than while still borrowing
    // it from `store.block_states`, since that call needs `store` mutably.
    let (current_justified, finalized) = {
        let post_state = store
            .block_states
            .get(&block_root)
            .expect("just inserted above");
        (
            post_state.current_justified_checkpoint(),
            post_state.finalized_checkpoint(),
        )
    };
    update_checkpoints(store, current_justified, finalized);

    // Eagerly compute unrealized justification and finality. The index built
    // above predates this block, so the newly imported one is added to it
    // rather than the whole scan being repeated.
    let mut index = index;
    index.insert(block_root, (block_slot, parent_root));
    compute_pulled_up_tip(store, &index, block_root, config)?;

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

    store_target_checkpoint_state(store, data.target, config)?;

    // Get state at the `target` to fully validate attestation. The attesting
    // indices are collected into an owned `Vec` before the block ends, so the
    // borrow of `store.checkpoint_states` (via `target_state`) is released
    // before `update_latest_messages` needs `store` mutably.
    let attesting_indices = {
        let target_state = store
            .checkpoint_state(&data.target)
            .ok_or(Error::SpecAssert(
                "attestation.data.target in store.checkpoint_states",
            ))?;
        attestation.verified_attesting_indices(target_state)?
    };

    // Update latest messages for attesting indices.
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

    // The attesting indices are collected into owned `Vec`s before the block
    // ends, so the borrow of `store.block_states` (via `state`) is released
    // before `store.equivocating_indices` needs to be mutated below.
    let (indices_1, indices_2) = {
        let state = store
            .block_states
            .get(&store.beacon_justified_checkpoint().root)
            .ok_or(Error::SpecAssert(
                "store.justified_checkpoint.root in store.block_states",
            ))?;
        attester_slashing.verified_attesting_indices(state)?
    };

    let indices_1: HashSet<ValidatorIndex> = indices_1.into_iter().collect();
    for index in indices_2 {
        if indices_1.contains(&index) {
            store.equivocating_indices.insert(index);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store with every collection empty and every checkpoint at its
    /// default (genesis) value. Tests fill in only the fields the function
    /// under test actually reads.
    fn empty_store() -> Store {
        Store {
            time: 0,
            genesis_time: 0,
            justified_checkpoint: Checkpoint::default(),
            finalized_checkpoint: Checkpoint::default(),
            unrealized_justified_checkpoint: Checkpoint::default(),
            unrealized_finalized_checkpoint: Checkpoint::default(),
            proposer_boost_root: Root::zero(),
            equivocating_indices: HashSet::new(),
            blocks: HashMap::new(),
            block_states: HashMap::new(),
            block_timeliness: HashMap::new(),
            checkpoint_states: HashMap::new(),
            latest_messages: HashMap::new(),
            unrealized_justifications: HashMap::new(),
            pow_blocks: HashMap::new(),
        }
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
                state_root: Root::zero(),
                body: phase0::BeaconBlockBody {
                    randao_reveal: Default::default(),
                    eth1_data: Default::default(),
                    graffiti: Root::zero(),
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

    /// The block index `get_ancestor` and the tree walks take, built by hand.
    fn index(entries: &[(Root, Slot, Root)]) -> BeaconBlockIndex {
        entries
            .iter()
            .map(|&(root, slot, parent_root)| (root, (slot, parent_root)))
            .collect()
    }

    #[test]
    fn get_ancestor_walks_past_an_empty_slot_gap() {
        let genesis_root = Root::repeat_byte(1);
        let a_root = Root::repeat_byte(2);
        let b_root = Root::repeat_byte(3);
        // Slot 2 is empty: b's parent is a, two slots later.
        let index = index(&[
            (genesis_root, 0, Root::zero()),
            (a_root, 1, genesis_root),
            (b_root, 3, a_root),
        ]);

        // At b's own slot, b is its own ancestor.
        assert_eq!(get_ancestor(&index, b_root, 3).unwrap(), b_root);
        // Querying the empty slot, or a's own slot, must land on a rather than
        // on b, since b's slot is strictly after both.
        assert_eq!(get_ancestor(&index, b_root, 2).unwrap(), a_root);
        assert_eq!(get_ancestor(&index, b_root, 1).unwrap(), a_root);
        // Querying before a's slot must walk one hop further, to genesis.
        assert_eq!(get_ancestor(&index, b_root, 0).unwrap(), genesis_root);
    }

    #[test]
    fn get_ancestor_rejects_an_unknown_root() {
        // The specification's own KeyError-on-unknown-root is exactly the
        // "unhandled exception" case it calls invalid, so this must be an
        // error rather than a panic.
        let index = index(&[]);
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
        let mut store = empty_store();

        let genesis_root = Root::repeat_byte(1);
        let low_root = Root::repeat_byte(2);
        let high_root = Root::repeat_byte(3);

        // Both checkpoints sit at the genesis epoch, which is what makes
        // `filter_block_tree` accept any leaf unconditionally (both of its
        // "correct_justified"/"correct_finalized" checks have a
        // `== GENESIS_EPOCH` escape hatch): the point of this test is the
        // weight tie-break in `get_head`, not the filtering rules.
        store.set_beacon_justified_checkpoint(Checkpoint {
            epoch: constants::GENESIS_EPOCH,
            root: genesis_root,
        });
        store.set_beacon_finalized_checkpoint(store.beacon_justified_checkpoint());

        store.insert_beacon_block(genesis_root, &block(0, Root::zero()));
        store.insert_beacon_block(low_root, &block(1, genesis_root));
        store.insert_beacon_block(high_root, &block(1, genesis_root));

        // `get_weight` reads the justified checkpoint's cached state only to
        // enumerate active validators; with `latest_messages` left empty,
        // neither child gets any attesting balance, so both are weight zero
        // and the root comparison is all that can decide between them.
        let state = crate::helpers::test_state::with_validators(1);
        store.insert_checkpoint_state(store.beacon_justified_checkpoint(), state.clone());
        // `get_voting_source` needs a post-state for each leaf, since both
        // children are in the store's current epoch (its clock is left at
        // the default of slot zero) and so take the "not pulled up" branch.
        store.block_states.insert(low_root, state.clone());
        store.block_states.insert(high_root, state);

        let head = get_head(&store, &config).unwrap();
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
        store.set_beacon_time(config.seconds_per_slot * preset::SLOTS_PER_EPOCH * 2);

        let block_root = Root::repeat_byte(5);
        store.insert_beacon_block(block_root, &block(0, Root::zero()));

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

        store
            .unrealized_justifications
            .insert(block_root, unrealized);

        let mut state = crate::helpers::test_state::with_validators(1);
        *state.current_justified_checkpoint_mut() = realized;
        store.block_states.insert(block_root, state);

        let index = store.beacon_block_index();
        let voting_source = get_voting_source(&store, &index, block_root, &config).unwrap();
        assert_eq!(
            voting_source, unrealized,
            "a block from a prior epoch must vote its pulled-up (unrealized) checkpoint"
        );
    }
}
