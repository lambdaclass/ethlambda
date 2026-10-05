//! The fork choice store: LMD GHOST, with FFG-derived justification and
//! finalization gating which branches are even eligible to be head.
//!
//! Implements `specs/phase0/fork-choice.md`, which is also every later fork's
//! fork choice through at least altair: none of them change anything here.
//! `Store` therefore accepts a block from any fork this module implements,
//! even though the algorithm applied to it is unconditionally phase0's.
//! `Store` tracks the block tree, attester votes, and the checkpoints fork
//! choice reasons about; the handlers at the bottom of this file
//! ([`on_tick`], [`on_block`], [`on_attestation`], [`on_attester_slashing`],
//! and, from gloas on, [`on_execution_payload_envelope`] and
//! [`on_payload_attestation_message`]) are the ones the specification lists as
//! sole ways to change it, matching its own framing: "Invalid calls to
//! handlers must not modify `store`." Most other functions in this file take
//! `&Store`; the exceptions are [`get_head`] (records the head it just
//! computed; see its own documentation for why that write belongs there
//! rather than in a caller), [`notify_ptc_messages`] (a helper of
//! [`on_block`] that applies payload attestations through
//! [`on_payload_attestation_message`]), and `update_proposer_boost_root`,
//! which writes `store.proposer_boost_root` on [`on_block`]'s behalf:
//! [`on_block`] is its only caller.
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
//! [`on_block`] derives that engine from the [`PayloadValidity`] its caller
//! hands it: an `INVALIDATED` verdict makes `verify_and_notify_new_payload`
//! answer false and the transition fail from inside
//! `process_execution_payload`, which is where the specification puts that
//! failure; every other verdict answers true.
//!
//! No released `fork_choice` fixture, at any fork or preset, ships an
//! `execution.yaml` or an `on_payload_info` step, so that whole suite passes
//! [`PayloadValidity::NotRequired`] and behaves exactly as it did before the
//! verdict existed. The suite that does exercise a standing registry keyed by
//! execution block hash is `sync/optimistic`, which keeps it on the store
//! rather than in a parameter, because it is updated over the course of a case
//! rather than fixed at construction time.
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
//! answer to that problem: an enum over the shapes, with one variant per
//! shape rather than one per fork: a fork that leaves a container unchanged
//! reuses the earlier one, as [`SignedBeaconBlock::Fulu`] wraps electra's.
//! But fork choice reads far less out of an attestation than a block:
//! `data.slot`, `data.target`, `data.beacon_block_root`, and the attesting
//! indices, per the module documentation above. `AttestationData`
//! (`crate::beacon::containers::shared`) is already fork-invariant, so every
//! function below except the two enums' own methods reads it directly rather
//! than matching on a fork tag it does not need: [`validate_on_attestation`]
//! and [`update_latest_messages`] take `AttestationData` and a resolved
//! `&[ValidatorIndex]`, not an [`Attestation`]. Gloas gives `data.index` a
//! meaning and orders votes by slot, so those two also take a [`ForkRules`]
//! value, which [`Attestation::rules`] derives from the variant. The one place
//! a fork's own shape otherwise matters is resolving an [`Attestation`] into
//! the attesters it names and checking their aggregate signature, which needs
//! the fork-specific `get_indexed_attestation`/`is_valid_indexed_attestation`
//! pair ([`crate::beacon::helpers::attestation`] for phase0,
//! [`crate::beacon::helpers::electra`] for electra,
//! [`crate::beacon::helpers::gloas`] for gloas);
//! [`Attestation::verified_attesting_indices`] and
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
use ethlambda_types::ShortRoot;
use tracing::{error, warn};

use crate::beacon::config::Config;
use crate::beacon::constants;
use crate::beacon::containers::{AttestationData, BeaconState, Checkpoint, SignedBeaconBlock};
use crate::beacon::containers::{bellatrix, deneb, electra, fulu, gloas, phase0};
use crate::beacon::error::{Error, Result, verify};
use crate::beacon::fork::ForkName;
use crate::beacon::helpers::accessors::{
    CommitteeCache, CommitteeCacheExt, get_active_validator_indices, get_current_epoch,
    get_total_active_balance,
};
use crate::beacon::helpers::attestation as phase0_attestation;
use crate::beacon::helpers::electra as electra_helpers;
use crate::beacon::helpers::gloas as gloas_helpers;
use crate::beacon::helpers::misc::{
    compute_epoch_at_slot, compute_start_slot_at_epoch, is_valid_merkle_branch,
};
use crate::beacon::helpers::predicates::{is_active_validator, is_slashable_attestation_data};
use crate::beacon::kzg;
use crate::beacon::lean_boundary::{lean_block_unreachable, lean_fork_unreachable};
use crate::beacon::preset;
use crate::beacon::primitives::{
    Epoch, ExecutionBlockHash, Gwei, HashTreeRoot as _, KzgCommitment, KzgProof, Root, Slot,
    ValidatorIndex,
};
use crate::beacon::stf;
use crate::metrics;

// ---------------------------------------------------------------------------
// LatestMessage, PowBlock, PayloadStatusV1, ForkChoiceNode, PayloadStatus
// ---------------------------------------------------------------------------

// All of these live in `ethlambda-types` rather than here, because
// `ethlambda-storage` persists them and cannot depend on this crate.
// Re-exported at the paths they had when they were defined here, so [`Store`]
// and its callers are unchanged. `ForkChoiceNode` and `PayloadStatus` are new
// with gloas, but join them here for the same reason: `Store::block_index`'s
// sibling accessors, this crate's own way of walking the block tree, are all
// keyed on plain `Root`s, and nothing about either type needs storage of its
// own beyond what `BeaconScratch` already keeps.
pub use ethlambda_types::beacon::fork_choice::{
    BlockPayloadLink, ForkChoiceNode, JustifiedBalances, LatestMessage, PayloadStatus,
    PayloadStatusEnum, PayloadStatusV1, PowBlock,
};

// ---------------------------------------------------------------------------
// Attestation, AttesterSlashing
// ---------------------------------------------------------------------------

/// An attestation, in whichever fork's shape it currently has. See the module
/// documentation for why this exists and what it lets the rest of this file
/// stay generic over.
///
/// Three variants, not one per fork: every fork through deneb shares
/// [`phase0::Attestation`] outright, and fulu shares [`electra::Attestation`]
/// the same way [`SignedBeaconBlock::Fulu`] shares
/// [`electra::SignedBeaconBlock`]. Gloas has its own, since EIP-7688 makes its
/// `aggregation_bits` unbounded, which is a different Rust type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attestation {
    Phase0(phase0::Attestation),
    Electra(electra::Attestation),
    Gloas(gloas::Attestation),
}

/// Which fork's handler rules apply: to an attestation's `data.index` and to
/// the order of an attester's votes, and to a block or anchor's gloas-only
/// state.
///
/// Before gloas, `data.index` is a committee index (zero from electra on) and
/// votes are compared by target epoch. Gloas repurposes `index` as the payload
/// flag (`0` for the empty branch or a same-slot vote, `1` for the full
/// branch), and its `LatestMessage` is compared by slot. For attesters who do
/// not equivocate, the slot order and the epoch order agree.
///
/// Every value comes from an exhaustive match on a fork or a container
/// ([`ForkRules::of`], [`Attestation::rules`]), so a fork added after gloas has
/// to be given its rules there rather than falling into the pre-gloas ones. An
/// attestation's rules follow its own container, not the store's clock: an
/// attestation carried by a gloas block is a [`gloas::Attestation`] even when
/// its slot is in the last pre-gloas epoch. Such a vote has `index == 0`, which
/// both rule sets accept, and is then ordered the way gloas's own
/// `update_latest_messages` orders it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkRules {
    /// Phase0 through fulu.
    PreGloas,
    /// Gloas (EIP-7732).
    Gloas,
}

impl ForkRules {
    /// The rules a value of `fork` (a block, a state, or an anchor) is handled
    /// under. Names every fork, so the next one has to be placed here.
    pub fn of(fork: ForkName) -> Self {
        match fork {
            ForkName::Phase0
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb
            | ForkName::Electra
            | ForkName::Fulu => ForkRules::PreGloas,
            ForkName::Gloas => ForkRules::Gloas,
            ForkName::Lean => lean_fork_unreachable("ForkRules::of"),
        }
    }

    /// The [`BlockPayloadLink`] of a block handled under these rules, given
    /// the parent payload branch it builds on where the rules record one. The
    /// one place the rules' payload shape is stated: a pre-gloas block is a
    /// single FULL node whose payload ran inside it, so it has no payload
    /// branch of its parent to choose, and `parent_status` is ignored.
    fn payload_link(self, parent_status: Option<PayloadStatus>) -> BlockPayloadLink {
        match self {
            ForkRules::PreGloas => BlockPayloadLink::PreGloas,
            ForkRules::Gloas => BlockPayloadLink::Gloas { parent_status },
        }
    }
}

impl Attestation {
    /// The fork-invariant half of an attestation: everything
    /// [`validate_on_attestation`] and [`update_latest_messages`] need, which
    /// is why neither of them takes an [`Attestation`] at all.
    pub fn data(&self) -> AttestationData {
        match self {
            Attestation::Phase0(attestation) => attestation.data,
            Attestation::Electra(attestation) => attestation.data,
            Attestation::Gloas(attestation) => attestation.data,
        }
    }

    /// The rules [`validate_on_attestation`] and [`update_latest_messages`]
    /// apply to this attestation; see [`ForkRules`].
    pub fn rules(&self) -> ForkRules {
        match self {
            Attestation::Phase0(_) | Attestation::Electra(_) => ForkRules::PreGloas,
            Attestation::Gloas(_) => ForkRules::Gloas,
        }
    }

    /// The attesters this attestation names, once its aggregate signature and
    /// index ordering have both been checked against `state`.
    ///
    /// The one place this enum's shapes actually matter: building the
    /// indexed form and checking it needs the fork-specific
    /// `get_indexed_attestation`/`is_valid_indexed_attestation` pair, so this
    /// dispatches once here rather than leaving that match to every caller.
    pub fn verified_attesting_indices(
        &self,
        state: &BeaconState,
        committees: &CommitteeCache,
    ) -> Result<Vec<ValidatorIndex>> {
        self.indices(state, true, committees)
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
    pub fn attesting_indices(
        &self,
        state: &BeaconState,
        committees: &CommitteeCache,
    ) -> Result<Vec<ValidatorIndex>> {
        self.indices(state, false, committees)
    }

    /// The body both accessors above share: the one place this enum's
    /// shapes actually matter, since building the indexed form and checking it
    /// needs the fork-specific
    /// `get_indexed_attestation`/`is_valid_indexed_attestation` pair. Kept as
    /// one dispatch so a new attestation shape cannot be added to the
    /// verifying path and forgotten on the other.
    fn indices(
        &self,
        state: &BeaconState,
        verify_signature: bool,
        committees: &CommitteeCache,
    ) -> Result<Vec<ValidatorIndex>> {
        match self {
            Attestation::Phase0(attestation) => {
                let indexed =
                    phase0_attestation::get_indexed_attestation(state, attestation, committees)?;
                if verify_signature {
                    verify(
                        phase0_attestation::is_valid_indexed_attestation(state, &indexed),
                        "is_valid_indexed_attestation(target_state, indexed_attestation)",
                    )?;
                }
                Ok(indexed.attesting_indices.into_inner())
            }
            Attestation::Electra(attestation) => {
                let indexed =
                    electra_helpers::get_indexed_attestation(state, attestation, committees)?;
                if verify_signature {
                    verify(
                        electra_helpers::is_valid_indexed_attestation(state, &indexed),
                        "is_valid_indexed_attestation(target_state, indexed_attestation)",
                    )?;
                }
                Ok(indexed.attesting_indices.into_inner())
            }
            Attestation::Gloas(attestation) => {
                let indexed =
                    gloas_helpers::get_indexed_attestation(state, attestation, committees)?;
                if verify_signature {
                    verify(
                        gloas_helpers::is_valid_indexed_attestation(state, &indexed),
                        "is_valid_indexed_attestation(target_state, indexed_attestation)",
                    )?;
                }
                Ok(indexed.attesting_indices.iter().copied().collect())
            }
        }
    }
}

/// Evidence that a set of validators made two conflicting attestations, in
/// whichever fork's shape it currently has. See [`Attestation`] for why this
/// has the same variants and no more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttesterSlashing {
    Phase0(phase0::AttesterSlashing),
    Electra(electra::AttesterSlashing),
    Gloas(gloas::AttesterSlashing),
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
            AttesterSlashing::Gloas(slashing) => {
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
            AttesterSlashing::Gloas(slashing) => {
                verify(
                    gloas_helpers::is_valid_indexed_attestation(state, &slashing.attestation_1),
                    "is_valid_indexed_attestation(state, attestation_1)",
                )?;
                verify(
                    gloas_helpers::is_valid_indexed_attestation(state, &slashing.attestation_2),
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
/// `electra` pair, and gloas its own. Both consumers of a block's own
/// operations, the chain actor and the `fork_choice` fixture runner, read it
/// from here, so a new fork reshaping `body.attestations` cannot be handled in
/// one and forgotten in the other.
pub fn block_operations(block: &SignedBeaconBlock) -> (Vec<Attestation>, Vec<AttesterSlashing>) {
    match block {
        SignedBeaconBlock::Phase0(block) => wrap_operations(
            block.message.body.attestations.iter(),
            block.message.body.attester_slashings.iter(),
            Attestation::Phase0,
            AttesterSlashing::Phase0,
        ),
        SignedBeaconBlock::Altair(block) => wrap_operations(
            block.message.body.attestations.iter(),
            block.message.body.attester_slashings.iter(),
            Attestation::Phase0,
            AttesterSlashing::Phase0,
        ),
        SignedBeaconBlock::Bellatrix(block) => wrap_operations(
            block.message.body.attestations.iter(),
            block.message.body.attester_slashings.iter(),
            Attestation::Phase0,
            AttesterSlashing::Phase0,
        ),
        SignedBeaconBlock::Capella(block) => wrap_operations(
            block.message.body.attestations.iter(),
            block.message.body.attester_slashings.iter(),
            Attestation::Phase0,
            AttesterSlashing::Phase0,
        ),
        SignedBeaconBlock::Deneb(block) => wrap_operations(
            block.message.body.attestations.iter(),
            block.message.body.attester_slashings.iter(),
            Attestation::Phase0,
            AttesterSlashing::Phase0,
        ),
        SignedBeaconBlock::Electra(block) => wrap_operations(
            block.message.body.attestations.iter(),
            block.message.body.attester_slashings.iter(),
            Attestation::Electra,
            AttesterSlashing::Electra,
        ),
        SignedBeaconBlock::Fulu(block) => wrap_operations(
            block.message.body.attestations.iter(),
            block.message.body.attester_slashings.iter(),
            Attestation::Electra,
            AttesterSlashing::Electra,
        ),
        SignedBeaconBlock::Gloas(block) => wrap_operations(
            block.message.body.attestations.iter(),
            block.message.body.attester_slashings.iter(),
            Attestation::Gloas,
            AttesterSlashing::Gloas,
        ),
        SignedBeaconBlock::Lean(_) => lean_block_unreachable("fork_choice::block_operations"),
    }
}

/// Wraps one fork's attestations and slashings in the fork-generic enums, given
/// the two variant constructors for that fork's shape.
///
/// Takes iterators rather than the lists themselves: each fork's body names
/// its own list type and bound, so a parameter typed on the list would need one
/// generic per bound, and `.iter()` erases exactly that difference.
fn wrap_operations<'a, A: Clone + 'a, S: Clone + 'a>(
    attestations: impl Iterator<Item = &'a A>,
    slashings: impl Iterator<Item = &'a S>,
    wrap_attestation: fn(A) -> Attestation,
    wrap_slashing: fn(S) -> AttesterSlashing,
) -> (Vec<Attestation>, Vec<AttesterSlashing>) {
    (
        attestations.cloned().map(wrap_attestation).collect(),
        slashings.cloned().map(wrap_slashing).collect(),
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

/// What an execution client said about the payload of the block being imported
/// right now.
///
/// A parameter on [`on_block`] rather than a `Store` field, for the same reason
/// [`DataAvailability`] is one: it is evidence about this one block, not a
/// registry looked up by some other hash later. The fixture-seeded registry
/// keyed by execution block hash is the other half of that split and does live
/// on the store, next to [`PowBlock`].
///
/// [`Validated`](Self::Validated) and [`NotRequired`](Self::NotRequired) both
/// let a block in, and the difference is what gets recorded, not whether the
/// import succeeds: a `NotRequired` block was never the subject of a question,
/// so answering it "valid" would be a claim nobody made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadValidity {
    /// Nothing to ask: the block predates bellatrix and carries no payload, or
    /// no execution client is configured. Today's behaviour before any engine
    /// existed, and what every `fork_choice` fixture case still gets.
    NotRequired,
    /// `VALID`. The block and every ancestor leave `optimistic_roots`.
    Validated,
    /// `SYNCING` or `ACCEPTED`, `optimistic-sync.md`'s `NOT_VALIDATED` alias.
    /// The block is imported and joins `optimistic_roots`.
    Optimistic,
    /// `INVALID` or `INVALID_BLOCK_HASH`, its `INVALIDATED` alias. The import
    /// fails, and `latest_valid_hash` decides how much of the branch dies with
    /// it. `None` is the specification's `null`.
    Invalidated {
        latest_valid_hash: Option<ExecutionBlockHash>,
    },
}

/// Reads an execution client's status as the verdict [`on_block`] takes.
///
/// One function for both sources of a status: the real client's JSON-RPC answer
/// and the fixture runner's seeded registry. Keeping the mapping here rather
/// than at each call site is what lets the `sync/optimistic` suite prove the
/// production reading of `optimistic-sync.md`'s two aliases rather than a
/// test's own copy of it.
pub fn payload_validity(status: &PayloadStatusV1) -> PayloadValidity {
    if status.status.is_invalidated() {
        return PayloadValidity::Invalidated {
            latest_valid_hash: status.latest_valid_hash,
        };
    }
    if status.status.is_not_validated() {
        return PayloadValidity::Optimistic;
    }
    PayloadValidity::Validated
}

/// The block an `INVALID` verdict actually condemns, per `optimistic-sync.md`'s
/// `latestValidHash` table.
///
/// | `latest_valid_hash` | result |
/// |---|---|
/// | an execution hash found on this chain | the child of the block carrying it |
/// | all zeroes | the deepest indexed ancestor carrying a payload |
/// | `None`, or a hash not on this chain | `block_root` itself |
///
/// Walked up the rejected block's own ancestry rather than looked up in an index
/// over every block, because the specification scopes it that way: "the *child*
/// of a block with `body.execution_payload.block_hash == latestValidHash` **in
/// the chain containing the block with payload in question**". Two branches can
/// share a parent whose payload is the last valid one, and only the branch that
/// was rejected may die.
///
/// `parent_root` is a parameter rather than read out of `index`, because
/// `block_root` is not in `index`: an `INVALID` verdict arrives before the block
/// is imported, so the store has no row for it. That also makes the `None` and
/// unfindable cases self-enforcing: they answer `block_root`, and
/// [`invalidate_subtree`] on an unindexed root removes nothing, which is exactly
/// "only the block in question dies" for a block that never joined the tree.
///
/// The unfindable case is the specification's own instruction, not a
/// convenience: "When `latestValidHash` is a meaningful execution block hash but
/// consensus engine cannot find a block satisfying
/// `body.execution_payload.block_hash == latestValidHash`, consensus engine
/// SHOULD behave the same as if `latestValidHash` was `null`." A
/// checkpoint-synced follower meets this whenever the named block is below its
/// anchor.
pub fn resolve_invalid_block(
    store: &Store,
    index: &HashMap<Root, (Slot, Root)>,
    block_root: Root,
    parent_root: Root,
    latest_valid_hash: Option<ExecutionBlockHash>,
) -> Root {
    let Some(latest_valid_hash) = latest_valid_hash else {
        return block_root;
    };

    // All zeroes: every payload-carrying block on this chain is condemned, so
    // the answer is the earliest ancestor this store still indexes that carries
    // one. The walk moves toward genesis, so each step reaches a *shallower*
    // block, and the last one it can reach is the whole branch's root.
    if latest_valid_hash.is_zero() {
        let mut earliest_execution_block = block_root;
        let mut cursor = parent_root;
        while store.beacon_el_block_hash(cursor).is_some() {
            earliest_execution_block = cursor;
            let Some((_slot, parent)) = index.get(&cursor).copied() else {
                break;
            };
            cursor = parent;
        }
        return earliest_execution_block;
    }

    // Walk up from the parent, carrying the block we came from. The first
    // ancestor whose own payload hash matches is the last valid block, so the
    // child we arrived from is the first invalid one.
    let mut child = block_root;
    let mut cursor = parent_root;
    loop {
        if store.beacon_el_block_hash(cursor) == Some(latest_valid_hash) {
            return child;
        }
        let Some((_slot, parent)) = index.get(&cursor).copied() else {
            // Ran off the top of what this store indexes without finding it.
            return block_root;
        };
        child = cursor;
        cursor = parent;
    }
}

/// Removes `invalid_root` and every descendant from fork choice, returning how
/// many blocks were removed.
///
/// Removes nothing, and returns `0`, for a root at or below finality: see the
/// finality floor in the body for why that verdict is refused rather than
/// obeyed.
///
/// `optimistic-sync.md`: "a block deemed `INVALIDATED` at any point MUST NOT be
/// included in the canonical chain and the weights from those `INVALIDATED`
/// blocks MUST NOT be applied to any `VALID` or `NOT_VALIDATED` ancestors."
/// Deleting the `LiveChain` rows satisfies both halves at once, because
/// `Store::block_index` is the only source fork choice reads:
/// [`compute_node_weights`] folds a subtree total only into parents it finds in
/// that index and gates the proposer-boost walk on the same membership, so a
/// vote naming a removed root seeds an entry that is never folded anywhere;
/// [`filter_block_tree`] and [`walk_head`] are index-derived too.
///
/// One index scan builds the whole child map rather than rescanning per level:
/// the descendants of one root are a tiny fraction of the tree, but finding
/// them at all means knowing every block's parent.
///
/// # A dangling vote this can create
///
/// Unlike `Store::promote_beacon_anchor`, which only ever prunes below a
/// finality horizon, this removes rows from the *live* window, so a validator
/// whose freshest vote named a branch the execution layer has since rejected
/// keeps pointing at a root no longer in the index, until it attests again.
///
/// [`compute_node_weights`] already drops such a vote rather than raising, so
/// [`get_head`] is unaffected. [`get_weight`] deliberately does not: it is the
/// specification's own version, and
/// `tests::a_vote_for_a_pruned_block_weighs_nothing_instead_of_failing` pins
/// that divergence on purpose. Nothing on this node's paths calls it today
/// ([`get_proposer_head`] has no callers outside this file), but wiring up a
/// beacon proposer duty would make it reachable, and it should get
/// `compute_node_weights`' treatment first.
pub fn invalidate_subtree(store: &mut Store, invalid_root: Root) -> usize {
    let index = store.block_index();

    // A condemned root at or below finality means the execution client and this
    // node disagree about finalized history, which is an operator emergency, not
    // something to resolve by emptying fork choice. Obeying it would delete every
    // `LiveChain` row from the finalized block upward, after which [`get_head`]
    // fails its "block_root in store.blocks" check on every call and the node
    // only logs that it cannot compute a head until its database is rebuilt.
    //
    // Reachable without any disagreement about a *specific* block: EIP-3675 lets
    // an execution client answer `INVALID` with `latestValidHash = 0x00..0`,
    // meaning every payload on this chain is invalid, and
    // [`resolve_invalid_block`]'s zero branch then walks to the earliest ancestor
    // whose hash this store still caches, which the cache's own finality bound
    // keeps down to the finalized block.
    let finalized = store.beacon_finalized_checkpoint();
    let finalized_slot = compute_start_slot_at_epoch(finalized.epoch);
    let at_or_below_finality = index
        .get(&invalid_root)
        .is_some_and(|(slot, _parent)| *slot <= finalized_slot);
    if invalid_root == finalized.root || at_or_below_finality {
        error!(
            condemned = %ShortRoot(&invalid_root.0),
            finalized_slot,
            finalized_root = %ShortRoot(&finalized.root.0),
            "The execution client condemned a finalized block; refusing to invalidate. \
             The execution and consensus layers disagree about finalized history and \
             this node needs operator attention"
        );
        return 0;
    }

    let mut children: HashMap<Root, Vec<Root>> = HashMap::new();
    for (&root, &(_slot, parent_root)) in &index {
        children.entry(parent_root).or_default().push(root);
    }

    let mut doomed: Vec<(Slot, Root)> = Vec::new();
    let mut stack = vec![invalid_root];
    while let Some(root) = stack.pop() {
        let Some(&(slot, _parent_root)) = index.get(&root) else {
            continue;
        };
        doomed.push((slot, root));
        if let Some(kids) = children.get(&root) {
            stack.extend(kids.iter().copied());
        }
    }

    if doomed.is_empty() {
        return 0;
    }

    for (_slot, root) in &doomed {
        // No longer merely unvalidated: it is refused. `optimistic_roots` holds
        // only blocks still awaiting an answer.
        store.remove_beacon_optimistic_root(*root);
    }
    store.delete_live_chain_entries(&doomed);
    doomed.len()
}

/// Clears `root` and every optimistic ancestor from `optimistic_roots`.
///
/// `optimistic-sync.md`: "when a block transitions from `NOT_VALIDATED` to
/// `VALID`, all *ancestors* of the block MUST also transition". One walk up the
/// index clears the whole prefix, stopping at the first ancestor that is not
/// optimistic, because everything above it was already cleared when that one
/// was.
///
/// Reached from two places, which is why it is a function rather than an inline
/// walk: [`on_block`], when `engine_newPayloadV4` answers `VALID`, and the
/// actor's `forkchoiceUpdated` handler, which is how a block imported on
/// `SYNCING` eventually becomes validated.
pub fn mark_validated(store: &mut Store, root: Root) {
    store.remove_beacon_optimistic_root(root);

    // With a healthy execution client nothing is optimistic, and the walk below
    // would exit on its own first iteration. Ask that before paying for
    // `block_index`, which is an uncached prefix scan of the whole `LiveChain`
    // table (never pruned on beacon) plus a map build, on a path that runs once
    // per imported block and once per `forkchoiceUpdated`.
    if !store.has_beacon_optimistic_roots() {
        return;
    }

    let index = store.block_index();
    let mut cursor = root;
    while let Some((_slot, parent)) = index.get(&cursor).copied() {
        if !store.is_beacon_optimistic(parent) {
            break;
        }
        store.remove_beacon_optimistic_root(parent);
        cursor = parent;
    }
}

/// Whether a block may be imported before its payload has been validated.
///
/// `optimistic-sync.md`'s function of the same name. Two ways to qualify:
///
/// 1. The parent already has execution enabled. Any descendant of a merge block
///    is fair game, since the poisoning attack the horizon guards against needs
///    a *transition* block with a junk parent hash.
/// 2. The block is at least `safe_slots` behind the wall clock, so an honest
///    chain has had time to justify around any poison.
///
/// Reads `is_execution_block(parent)` off the cached execution hash rather than
/// decoding the parent block: the cache is populated at import for exactly the
/// blocks that have one, so its absence is the answer.
///
/// `safe_slots` is a parameter rather than the constant read directly, because
/// the specification requires the value to be operator-configurable.
pub fn is_optimistic_candidate_block(
    store: &Store,
    current_slot: Slot,
    block_slot: Slot,
    parent_root: Root,
    safe_slots: u64,
) -> bool {
    if store.beacon_el_block_hash(parent_root).is_some() {
        return true;
    }
    block_slot.saturating_add(safe_slots) <= current_slot
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
/// rebuild after a restart rather than worth persisting; the exceptions are
/// a gloas block's timeliness and verified payload, which are also stored
/// and reloaded on resume. See
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
///
/// Public so the Beacon API can take attestation data's source checkpoint
/// from the same cached, advanced state fork choice uses.
pub fn checkpoint_state(
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
///
/// A gloas anchor is accepted and seeds the three gloas-only tables the way
/// gloas's own `get_forkchoice_store` does: both block timeliness deadlines
/// met, an empty payload-attestation vote vector for each of the two vote
/// kinds, and no verified payload. Whether a node can *follow* a gloas chain
/// from there is the caller's question, not this function's: the live follower
/// refuses a gloas anchor at startup, since its node wiring cannot deliver
/// payload envelopes yet.
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
    let anchor_rules = ForkRules::of(anchor_state.fork_name());
    let anchor_slot = anchor_block.slot();

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
    // `anchor_state.slot()`, not the checkpoint's: the stored checkpoint is
    // epoch-denominated, so an anchor taken mid-epoch would record its epoch's
    // start slot and advertise a floor below anything this directory holds.
    let mut store = Store::init_beacon(
        backend,
        anchor_state.genesis_time(),
        config.clone(),
        anchor_root,
        Store::beacon_checkpoint_as_stored(justified_checkpoint),
        anchor_state.slot(),
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

    // [New in Gloas:EIP7732] `block_timeliness={anchor_root: [True, True]}`,
    // both vote vectors seeded with `[None] * PTC_SIZE`, and `payloads={}`
    // (nothing to insert: the anchor's own payload is not verified until an
    // envelope arrives for it). Earlier forks record none of these for the
    // anchor, and nothing reads them there.
    //
    // The anchor's payload link is recorded here as well. Its parent is not in
    // this store, so a gloas anchor has no parent status to compare bids for;
    // nothing reads one, since the head walk only asks for a status when the
    // parent is indexed.
    store.set_payload_link(anchor_root, anchor_slot, anchor_rules.payload_link(None));
    match anchor_rules {
        ForkRules::Gloas => {
            store.set_gloas_block_timeliness(anchor_root, [true, true]);
            store.set_payload_timeliness_vote(anchor_root, vec![None; preset::PTC_SIZE]);
            store.set_payload_data_availability_vote(anchor_root, vec![None; preset::PTC_SIZE]);
        }
        ForkRules::PreGloas => {}
    }

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
    Ok(committee_fraction(
        get_total_active_balance(state)?,
        committee_percent,
    ))
}

/// The arithmetic of [`calculate_committee_fraction`], for a caller that
/// already holds the total active balance (the [`JustifiedBalances`] snapshot's
/// own).
pub fn committee_fraction(total_active_balance: Gwei, committee_percent: u64) -> Gwei {
    let committee_weight = total_active_balance / preset::SLOTS_PER_EPOCH;
    committee_weight.saturating_mul(committee_percent) / 100
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
    let balances = justified_balances(store, config)?;
    Ok(committee_fraction(
        balances.total_active_balance(),
        config.proposer_score_boost,
    ))
}

/// The flat balances of the store's justified checkpoint state, built on first
/// use after the checkpoint moves and shared until it moves again.
///
/// Keyed by the checkpoint itself, which every writer of the justified
/// checkpoint (`update_checkpoints` from three handlers, store construction,
/// restart) already changes, so none of them needs a hook. The only source is
/// [`checkpoint_state`], the state `get_weight` reads, so the snapshot is
/// exactly what the specification's per-root definition sees; a later
/// post-state of the same epoch would not be, since `slashed` can differ.
/// A failed `checkpoint_state` fails the call, as it does for every other
/// fork-choice reader, and the head stays where it is.
pub fn justified_balances(store: &Store, config: &Config) -> Result<Arc<JustifiedBalances>> {
    let checkpoint = store.beacon_justified_checkpoint();
    if let Some(balances) = store.justified_balances(&checkpoint) {
        metrics::inc_justified_balances_lookups("hit");
        return Ok(balances);
    }
    metrics::inc_justified_balances_lookups("miss");
    let state = checkpoint_state(store, &checkpoint, config)?;
    let balances = Arc::new(build_justified_balances(checkpoint, &state));
    store.set_justified_balances(Arc::clone(&balances));
    Ok(balances)
}

/// One in-order pass over `state`'s registry: each validator's vote weight
/// (zero if inactive or slashed) and, in the same pass, the total active
/// balance with exactly the semantics of `get_total_active_balance`
/// (slashed-but-active validators count, saturating, floored at one increment).
fn build_justified_balances(checkpoint: Checkpoint, state: &BeaconState) -> JustifiedBalances {
    let _timing = metrics::time_justified_balances_build();
    // Activity at the state's own epoch, as `get_weight` reads it; not asserted
    // equal to `checkpoint.epoch`, which the unit-test stores do not keep.
    let epoch = get_current_epoch(state);
    let mut total: Gwei = 0;
    let balances = state
        .iter_validators()
        .map(|validator| {
            if !is_active_validator(validator, epoch) {
                return 0;
            }
            total = total.saturating_add(validator.effective_balance);
            if validator.slashed {
                0
            } else {
                validator.effective_balance
            }
        })
        .collect();
    JustifiedBalances::new(
        checkpoint,
        balances,
        total.max(preset::EFFECTIVE_BALANCE_INCREMENT),
    )
}

/// The effective balance of every non-equivocating, active, unslashed
/// validator in `state` whose latest vote descends through `root`: the
/// attestation half of [`get_weight`], without the proposer boost.
///
/// Takes `index` rather than building it, the way [`filter_block_tree`] does,
/// and reuses it for every [`get_ancestor`] call this makes: one per active
/// validator. See [`get_ancestor`]'s documentation for why that matters.
///
/// Split out of [`get_weight`] so [`is_head_weak`] and [`is_parent_strong`]
/// can score a root against the justified state without also asking whether
/// the proposer boost applies to it; the specification makes the same split,
/// since neither of those checks the boost.
///
/// **Implementation choice, not spec text**: a voter's last message counts
/// only when the ancestor walk from its root succeeds and lands on `root`;
/// a walk that meets a root missing from `index` (its own, or an ancestor
/// pruned below the finalized slot) contributes nothing, where
/// [`get_ancestor`] would raise `Error::SpecAssert`. [`compute_weights`]'s
/// own doc gives the reasoning this mirrors: pruning removes only index
/// entries below the finalized slot, and every root scored here is indexed
/// at or above it, so a walk that leaves the index cannot descend from, or
/// equal, the scored root, and the specification's own contribution for
/// such a vote is `0` too. This function is not only
/// [`get_weight`]'s own attestation half; [`is_head_weak`] and
/// [`is_parent_strong`] call it too, [`is_head_weak`] underneath the public
/// [`should_apply_proposer_boost`] and [`is_parent_strong`] underneath
/// [`get_proposer_head`]. The head walk does not: it reads the same scores
/// from [`compute_node_weights`], which drops such a vote too.
pub fn get_attestation_score(
    store: &Store,
    index: &HashMap<Root, (Slot, Root)>,
    root: Root,
    state: &BeaconState,
) -> Result<Gwei> {
    let current_epoch = get_current_epoch(state);
    let block_slot = index
        .get(&root)
        .ok_or(Error::SpecAssert("root in store.blocks"))?
        .0;

    let mut attestation_score: Gwei = 0;
    for validator_index in get_active_validator_indices(state, current_epoch) {
        let validator = state.validator(validator_index)?;
        if validator.slashed || store.is_equivocating(validator_index) {
            continue;
        }
        let Some(message) = store.latest_message(validator_index) else {
            continue;
        };
        if matches!(get_ancestor(index, message.root, block_slot), Ok(ancestor) if ancestor == root)
        {
            attestation_score = attestation_score.saturating_add(validator.effective_balance);
        }
    }
    Ok(attestation_score)
}

/// The LMD GHOST weight of `root`: [`get_attestation_score`] against the
/// justified checkpoint's state, plus the proposer boost if it applies.
///
/// The specification's own per-root definition, kept as written. [`get_head`]
/// weighs with [`compute_node_weights`] instead, which produces the same
/// numbers for the whole tree at once; this is what [`compute_weights`], its
/// pre-gloas reference, is tested against.
pub fn get_weight(
    store: &Store,
    index: &HashMap<Root, (Slot, Root)>,
    root: Root,
    config: &Config,
) -> Result<Gwei> {
    let justified_checkpoint = store.beacon_justified_checkpoint();
    let state = checkpoint_state(store, &justified_checkpoint, config)?;
    let attestation_score = get_attestation_score(store, index, root, &state)?;

    let proposer_boost_root = store.proposer_boost_root();
    if proposer_boost_root.is_zero() {
        return Ok(attestation_score);
    }

    let block_slot = index
        .get(&root)
        .ok_or(Error::SpecAssert("root in store.blocks"))?
        .0;
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
    let balances = justified_balances(store, config)?;

    // Keyed on the voted block itself; the fold below turns these into subtree
    // totals in place.
    let mut weights: HashMap<Root, Gwei> = HashMap::new();
    // Equivocators are filtered by the store itself: see
    // `for_each_non_equivocating_latest_message` for why asking it per voter
    // from in here would deadlock.
    store.for_each_non_equivocating_latest_message(|validator_index, message| {
        // An index past the snapshot is a validator that did not exist at the
        // justified checkpoint, and an inactive or slashed one is zero in it:
        // both are a skip rather than an error.
        let balance = balances.get(validator_index);
        if balance == 0 {
            return;
        }
        let entry = weights.entry(message.root).or_default();
        *entry = entry.saturating_add(balance);
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
        let proposer_score =
            committee_fraction(balances.total_active_balance(), config.proposer_score_boost);
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

/// The pre-gloas LMD GHOST head: starting from the justified checkpoint,
/// repeatedly step to the child with the greatest weight until a leaf is
/// reached.
///
/// **A reference, not the node's head computation.** [`get_head_node`] runs
/// [`walk_head`] for every fork, and on a pre-gloas tree the two agree; this
/// is kept, public, as the independent [`compute_weights`] algorithm the walk
/// is tested against (the fork-choice fixture harness and the randomized
/// differential test both call it).
///
/// The children scan in the loop below reads `blocks`, [`get_filtered_block_tree`]'s
/// already-filtered, already in-memory result, not [`Store::block_index`]
/// itself: it is the specification's own second whole-`Dict` scan the module
/// documentation calls out, but it never costs a further backend round trip.
///
/// Takes `&Store` rather than `&mut Store`: nothing here records the head it
/// finds. No node code calls it; only tests do.
///
/// Takes `index` rather than building it, matching [`get_filtered_block_tree`]
/// and [`compute_weights`], which this hands the same one to.
pub fn compute_head(
    store: &Store,
    index: &HashMap<Root, (Slot, Root)>,
    config: &Config,
) -> Result<Root> {
    let blocks = get_filtered_block_tree(store, index, config)?;
    // Every candidate's weight at once: see `compute_weights` for why the
    // specification's per-root `get_weight` is not what the descent calls.
    let weights = compute_weights(store, index, config)?;
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

    Ok(head)
}

// ---------------------------------------------------------------------------
// The head computation: one bottom-up walk for every fork
// ---------------------------------------------------------------------------
//
// One weight table and one descent serve both kinds of block. Every block is
// a `PENDING` node with two payload nodes under it (`EMPTY`, and `FULL` once
// its payload is verified), and a child block hangs off whichever of those its
// bid says it builds on. A pre-gloas block is the degenerate case: its only
// payload node is `FULL` (its payload ran inside the block), and every child
// builds on it. That is the fulu-to-gloas rule this crate decided on, stated
// once, in [`BlockPayloadLink`], instead of being repeated in a second head
// algorithm.
//
// # Why one pass over the votes gives the specification's weight
//
// The specification's `get_attestation_score(node)` adds the balance of every
// vote whose supported node `is_ancestor` of `node` matches: the chain from
// the supported node up through `get_ancestor`, where the wildcard `PENDING`
// ancestor matches either payload branch.
//
// Follow that chain from a vote's supported node `S = (r, s)`. `get_ancestor`
// at the slot of `node.root` returns `S` itself while `r`'s slot is at or
// below it, so `S` matches `node` exactly when `node.root == r` and either the
// statuses agree or `node` is `PENDING`. When `r`'s slot is above it, the
// descent replaces `S` by `(parent(r), status of r's parent payload)` and
// asks again. So the nodes a vote counts for are exactly those on this chain,
// in the node tree of the section above:
//
// ```text
//   S = (r, s)  ->  PENDING(r)  ->  (parent(r), ps(r))  ->  PENDING(parent(r)) -> ...
// ```
//
// where `ps(r)` is `get_parent_payload_status` of `r`, the first arrow exists
// only for `s` of `EMPTY` or `FULL`, and `PENDING(r)` is the last node of `r`
// on the chain (a vote for `PENDING(r)` counts for no `EMPTY` or `FULL` node of
// `r`, since the statuses differ and `node` is not the wildcard). The score of
// a node is therefore the sum, over the votes whose chain contains it, of the
// voter's balance; adding each vote at `S` and folding every node's total into
// the next node on its chain, children before parents, computes that sum for
// every node at once. `compute_weights` does the same for the pre-gloas tree,
// where the chain is the block chain.
//
// Children before parents needs a topological order, and processing blocks
// from the highest slot down gives one: a parent is at a strictly earlier
// slot, and a block's own `EMPTY` and `FULL` nodes are complete before its
// `PENDING` node reads them, since everything folded into them comes from a
// later slot.
//
// The proposer boost is the same sum with one extra voter at `PENDING(boost)`:
// `is_ancestor(PENDING(boost), node)` holds for exactly the nodes on that
// node's chain. It cannot be folded with the votes, because whether it applies
// depends on the parent's attestation score, which the fold produces; it is
// added along the chain afterwards.

/// How a head computation reads a block's payload dimension.
///
/// From `GLOAS_FORK_EPOCH` on, every block's payload dimension is read from
/// its [`BlockPayloadLink`]. Before it, no payload dimension exists: every
/// block is a single `FULL` node, whatever its bytes are, exactly as the
/// pre-gloas head algorithm treated it. Reading the links would change
/// nothing on a real chain (a gloas block cannot exist before the fork epoch),
/// but a store holding one anyway must give the answer the pre-gloas rules
/// give, so the rules, not the block, decide.
#[derive(Clone, Copy)]
struct PayloadTree<'a> {
    store: &'a Store,
    rules: ForkRules,
}

impl PayloadTree<'_> {
    /// `root`'s payload link under this tree's rules.
    fn link(&self, root: Root) -> Result<BlockPayloadLink> {
        match self.rules {
            ForkRules::PreGloas => Ok(self.rules.payload_link(None)),
            ForkRules::Gloas => block_payload_link(self.store, root)?
                .ok_or(Error::SpecAssert("root in store.blocks")),
        }
    }

    /// Which of its parent's payload branches `root` builds on.
    fn parent_status(&self, root: Root) -> Result<PayloadStatus> {
        self.link(root)?
            .parent_status()
            .ok_or(Error::SpecAssert("block.parent_root in store.blocks"))
    }
}

/// Every node's LMD GHOST weight, from one pass over the votes and one over the
/// blocks; see the section documentation above for why this equals the
/// specification's per-node `get_weight`.
///
/// Work is proportional to the number of latest messages plus the number of
/// indexed blocks at or above the finalized block (times two lookups each),
/// which is the unfinalized window, not the history since the anchor (see
/// [`compute_node_weights`]'s bound), against the specification's
/// messages times candidate nodes, each with block decodes along the ancestor
/// walk. Once the payload links are recorded, the only decodes left are the
/// equivocation scan under a weak previous-slot parent and the one-time
/// derivation of a link that was never recorded (after a restart); see
/// `docs/spec_deviations.md`.
///
/// A vote for a block no longer in `index` is dropped rather than raising, the
/// tolerance [`compute_weights`] documents; a missing `block_timeliness` entry
/// reads as not timely, the one [`should_apply_proposer_boost`] documents.
#[derive(Debug)]
pub struct NodeWeights {
    rules: ForkRules,
    current_slot: Slot,
    weights: HashMap<ForkChoiceNode, Gwei>,
}

impl NodeWeights {
    /// `node`'s weight, `block_slot` being its block's slot.
    ///
    /// Under gloas rules a `EMPTY` or `FULL` node of the previous slot's block
    /// weighs `0`: its votes are still arriving, so only the tiebreaker
    /// decides between the two (`is_previous_slot_payload_decision`). The
    /// pre-gloas rules have no such node.
    pub fn weight(&self, node: ForkChoiceNode, block_slot: Slot) -> Gwei {
        if self.rules == ForkRules::Gloas
            && is_payload_decision_at(block_slot, node.payload_status, self.current_slot)
        {
            return 0;
        }
        self.raw(node)
    }

    /// `node`'s weight before the previous-slot rule, the value the votes and
    /// the boost add up to.
    fn raw(&self, node: ForkChoiceNode) -> Gwei {
        self.weights.get(&node).copied().unwrap_or_default()
    }

    fn set(&mut self, node: ForkChoiceNode, weight: Gwei) {
        self.weights.insert(node, weight);
    }

    fn add(&mut self, node: ForkChoiceNode, amount: Gwei) {
        let entry = self.weights.entry(node).or_default();
        *entry = entry.saturating_add(amount);
    }
}

/// The node a block's own `PENDING` total is folded into: the parent block's
/// payload node that this block builds on.
fn parent_node(parent_root: Root, parent_status: PayloadStatus) -> ForkChoiceNode {
    ForkChoiceNode {
        root: parent_root,
        payload_status: parent_status,
    }
}

/// The lowest slot [`compute_node_weights`] weighs: the least of the finalized
/// block's slot, the justified block's slot and, when a proposer boost root is
/// set and indexed, its parent's slot. All three come from `index`.
///
/// A root that is not indexed gives `0` for the finalized and justified
/// blocks, which weighs everything. Why each term is there, and why the least
/// is the finalized block's slot on a live node, is argued once, in
/// [`compute_node_weights`]'s `# The bound` section.
fn walk_bound(store: &Store, index: &HashMap<Root, (Slot, Root)>) -> Slot {
    let slot_of = |root: Root| index.get(&root).map_or(0, |&(slot, _)| slot);
    let mut bound = slot_of(store.beacon_finalized_checkpoint().root)
        .min(slot_of(store.beacon_justified_checkpoint().root));
    let boost_root = store.proposer_boost_root();
    if let Some(&(_, parent_root)) = index.get(&boost_root)
        && let Some(&(parent_slot, _)) = index.get(&parent_root)
    {
        bound = bound.min(parent_slot);
    }
    bound
}

/// [`NodeWeights`] for `rules`, on the block tree `index`.
///
/// `rules` selects the two fork-dependent rules: how a block's payload
/// dimension is read (see [`PayloadTree`]) and whether the proposer boost is
/// gated by `should_apply_proposer_boost` (gloas) or applies whenever a boost
/// root is set (pre-gloas).
///
/// # The bound
///
/// Vote placement, the fold and the boost chain all stop at [`walk_bound`]'s
/// slot: a block below it gets no weight and is never read, so a head
/// computation covers the unfinalized window, not the history since the
/// anchor. (A beacon store never prunes its block index, so without the bound
/// every call would fold, and read the payload link of, every block down to
/// the anchor.) The bound is the least of the finalized block's slot, the
/// justified block's slot and the boosted block's parent's slot, and it
/// changes no answer the head reads, whichever of the three is least:
/// - The descent compares only descendants of the justified root, so every
///   node it weighs is at or above the justified block's slot, hence at or
///   above the bound.
/// - A vote for a block below the bound supports only nodes at or below that
///   block, since a vote counts for the nodes on its chain toward the root, so
///   it adds nothing to a node at or above the bound.
/// - The boost chain from a block adds to that block's ancestors, and it is
///   walked down to the bound, so every node at or above the bound gets what
///   the specification gives it. The gloas gate reads only the boosted block's
///   parent's score, and that parent is at or above the bound by
///   construction.
///
/// On a live node the least of the three is the finalized block's slot: the
/// justified block is at or above it, and the boosted block is a current-slot
/// block, which descends from the finalized root, so its parent is too. That
/// is what keeps the walk to the unfinalized window.
///
/// The weight of a node below the bound is not computed, and reads as `0`.
pub fn compute_node_weights(
    store: &Store,
    index: &HashMap<Root, (Slot, Root)>,
    config: &Config,
    committees: &CommitteeCache,
    rules: ForkRules,
) -> Result<NodeWeights> {
    let tree = PayloadTree { store, rules };
    let justified_checkpoint = store.beacon_justified_checkpoint();
    let state = checkpoint_state(store, &justified_checkpoint, config)?;
    // The vote loop reads each voter's weight from the snapshot of this same
    // checkpoint state rather than descending the registry per vote; `state`
    // stays for the boost gate, which wants the committees' state itself.
    let balances = justified_balances(store, config)?;
    let bound = walk_bound(store, index);
    let in_window = |root: &Root| index.get(root).is_some_and(|&(slot, _)| slot >= bound);

    // Votes, summed by what determines the node they support. Nothing that
    // reads the store's own scratch may run inside the closure: see
    // `for_each_non_equivocating_latest_message` for why asking it per voter
    // from in here would deadlock, and a payload link is such a read.
    let mut votes: HashMap<(Root, Slot, bool), Gwei> = HashMap::new();
    store.for_each_non_equivocating_latest_message(|validator_index, message| {
        // An index past the snapshot is a validator that did not exist at the
        // justified checkpoint, and an inactive or slashed one is zero in it:
        // both are a skip rather than an error, as is a zero balance, which
        // adds nothing either way.
        let balance = balances.get(validator_index);
        if balance == 0 {
            return;
        }
        let entry = votes
            .entry((message.root, message.slot, message.payload_present))
            .or_default();
        *entry = entry.saturating_add(balance);
    });

    let mut weights = NodeWeights {
        rules,
        current_slot: get_current_slot(store, config),
        weights: HashMap::new(),
    };
    for ((root, message_slot, payload_present), balance) in votes {
        let Some(&(block_slot, _)) = index.get(&root) else {
            continue;
        };
        if block_slot < bound {
            continue;
        }
        // `get_supported_node`: a vote made after its block's own slot names
        // one of the block's payload branches, and a pre-gloas block has only
        // the full one.
        let payload_status = if block_slot < message_slot {
            if !tree.link(root)?.is_gloas() || payload_present {
                PayloadStatus::Full
            } else {
                PayloadStatus::Empty
            }
        } else {
            PayloadStatus::Pending
        };
        weights.add(
            ForkChoiceNode {
                root,
                payload_status,
            },
            balance,
        );
    }

    // Fold, highest slot first. A block's total is its own votes plus what its
    // two payload nodes gathered from later blocks; it then moves into the
    // payload node of its parent that it builds on.
    let mut blocks: Vec<(Slot, Root, Root)> = index
        .iter()
        .filter(|&(_, &(slot, _))| slot >= bound)
        .map(|(root, (slot, parent_root))| (*slot, *root, *parent_root))
        .collect();
    blocks.sort_unstable_by_key(|block| std::cmp::Reverse(block.0));
    for &(_slot, root, parent_root) in &blocks {
        let pending = ForkChoiceNode {
            root,
            payload_status: PayloadStatus::Pending,
        };
        let total = [
            pending,
            ForkChoiceNode {
                root,
                payload_status: PayloadStatus::Empty,
            },
            ForkChoiceNode {
                root,
                payload_status: PayloadStatus::Full,
            },
        ]
        .into_iter()
        .fold(0, |sum: Gwei, node| sum.saturating_add(weights.raw(node)));
        if total == 0 {
            continue;
        }
        weights.set(pending, total);
        // Only into a parent that is still indexed and at or above the bound:
        // the finalized block's own parent is below it, and the anchor's is
        // below the retained window; there is nothing there to weigh.
        if in_window(&parent_root) {
            let parent_status = tree.parent_status(root)?;
            weights.add(parent_node(parent_root, parent_status), total);
        }
    }

    // The boost. Gloas asks `should_apply_proposer_boost`, fed the parent's
    // score from the table just built; before gloas it applies whenever a boost
    // root is set and still indexed, the tolerance `compute_weights` documents.
    let boost_root = store.proposer_boost_root();
    let boost_applies = match rules {
        ForkRules::PreGloas => !boost_root.is_zero() && in_window(&boost_root),
        ForkRules::Gloas => {
            should_apply_proposer_boost_with(store, config, committees, index, &state, |parent| {
                Ok(weights.raw(ForkChoiceNode {
                    root: parent,
                    payload_status: PayloadStatus::Pending,
                }))
            })?
        }
    };
    if boost_applies {
        let proposer_score = get_proposer_score(store, config)?;
        let mut root = boost_root;
        loop {
            weights.add(
                ForkChoiceNode {
                    root,
                    payload_status: PayloadStatus::Pending,
                },
                proposer_score,
            );
            let Some(&(_, parent_root)) = index.get(&root) else {
                break;
            };
            if !in_window(&parent_root) {
                break;
            }
            let parent_status = tree.parent_status(root)?;
            weights.add(parent_node(parent_root, parent_status), proposer_score);
            root = parent_root;
        }
    }

    Ok(weights)
}

/// The nodes directly under `node` in the payload-aware tree, for the head
/// descent: [`get_node_children`], answered from `children_of` (the filtered
/// tree's parent-to-children map) and the payload links instead of decoding
/// every block it touches.
fn walk_children(
    tree: PayloadTree,
    children_of: &HashMap<Root, Vec<Root>>,
    node: ForkChoiceNode,
) -> Result<Vec<ForkChoiceNode>> {
    if node.payload_status == PayloadStatus::Pending {
        if !tree.link(node.root)?.is_gloas() {
            return Ok(vec![ForkChoiceNode {
                root: node.root,
                payload_status: PayloadStatus::Full,
            }]);
        }
        let mut children = vec![ForkChoiceNode {
            root: node.root,
            payload_status: PayloadStatus::Empty,
        }];
        if tree.store.has_verified_payload(&node.root) {
            children.push(ForkChoiceNode {
                root: node.root,
                payload_status: PayloadStatus::Full,
            });
        }
        return Ok(children);
    }
    let mut children = Vec::new();
    for &child in children_of.get(&node.root).into_iter().flatten() {
        if tree.parent_status(child)? == node.payload_status {
            children.push(ForkChoiceNode {
                root: child,
                payload_status: PayloadStatus::Pending,
            });
        }
    }
    Ok(children)
}

/// The LMD GHOST head as a [`ForkChoiceNode`], for `rules`: the descent from
/// the justified checkpoint that both [`compute_head`] and [`gloas_get_head`]
/// perform, over the one weight table of [`compute_node_weights`].
///
/// At every step the heaviest child wins, ties going to the higher root and
/// then to [`get_payload_status_tiebreaker`], the key gloas's `get_head` sorts
/// by. Before gloas a step has one payload node and siblings always differ by
/// root, so neither of the last two keys can decide, and the answer is the
/// pre-gloas head, reported as `(root, Full)`.
///
/// Takes `index` rather than building it, like [`get_filtered_block_tree`]:
/// [`on_block`] already holds one.
fn walk_head(
    store: &Store,
    index: &HashMap<Root, (Slot, Root)>,
    config: &Config,
    committees: &CommitteeCache,
    rules: ForkRules,
) -> Result<ForkChoiceNode> {
    let tree = PayloadTree { store, rules };
    let blocks = get_filtered_block_tree(store, index, config)?;
    let weights = compute_node_weights(store, index, config, committees, rules)?;
    let current_slot = get_current_slot(store, config);

    let mut children_of: HashMap<Root, Vec<Root>> = HashMap::new();
    for (&root, &(_, parent_root)) in &blocks {
        children_of.entry(parent_root).or_default().push(root);
    }
    let block_entry = |root: Root| index.get(&root).copied();

    let mut head = ForkChoiceNode {
        root: store.beacon_justified_checkpoint().root,
        payload_status: PayloadStatus::Pending,
    };
    loop {
        let children = walk_children(tree, &children_of, head)?;
        if children.len() <= 1 {
            let Some(only) = children.first() else {
                return Ok(head);
            };
            head = *only;
            continue;
        }

        let mut best: Option<((Gwei, Root, u8), ForkChoiceNode)> = None;
        for child in children {
            let (block_slot, _) =
                block_entry(child.root).ok_or(Error::SpecAssert("node.root in store.blocks"))?;
            let tiebreak = match rules {
                ForkRules::Gloas => payload_status_tiebreaker_with(
                    store,
                    child,
                    current_slot,
                    block_entry,
                    proposer_parent_is_full_from_link,
                )?,
                ForkRules::PreGloas => child.payload_status as u8,
            };
            let key = (weights.weight(child, block_slot), child.root, tiebreak);
            if best.is_none_or(|(best_key, _)| key > best_key) {
                best = Some((key, child));
            }
        }
        head = best.expect("more than one child, checked above").1;
    }
}

/// The LMD GHOST head as a full [`ForkChoiceNode`] rather than just a root,
/// from the one bottom-up walk ([`compute_node_weights`] and the descent over
/// it) that serves every fork.
///
/// The current slot's own fork, via [`Config::fork_at_epoch`], not the head's
/// or the justified checkpoint's, selects the two rules that differ by fork
/// (see [`walk_head`]): from `GLOAS_FORK_EPOCH` on, blocks carry the payload
/// dimension their bids give them and the proposer boost is gated by
/// `should_apply_proposer_boost`, so the payload-aware rules take over as soon
/// as the chain could hold a gloas block at all, rather than waiting for a
/// block, or justification, to actually reach one. Before that epoch every
/// block is a single full node and the boost applies whenever it is set,
/// which is the head algorithm every pre-gloas fork uses.
///
/// [`gloas_get_head`] is the spec-literal algorithm this walk replaced, and
/// [`compute_head`] the [`compute_weights`] fold kept as the pre-gloas
/// reference. Neither is on the node's path any more: they are the references
/// its tests compare it with, at every `head` check of every fork-choice
/// fixture and on randomized trees.
///
/// A pre-gloas block has no payload dimension of its own: this crate treats
/// it as a single-variant node whose status is always
/// [`PayloadStatus::Full`] (its payload ran inside the block, with no
/// separate reveal to attest to), so a pre-gloas head is reported as
/// `(root, Full)` rather than `Pending`. That is a decided rule, not
/// something the specification states: gloas's own `fork-choice.md` only
/// ever describes a gloas-anchored `Store` and says nothing about a
/// pre-gloas parent, or a mixed tree that still has one in it (see
/// [`gloas_bid`]'s own doc for the matching gap one level down, at a single
/// block's own parent, and the module documentation's "Gloas: payload-aware
/// fork choice" section for the rule in full). consensus-specs PR
/// ethereum/consensus-specs#5125 (open, unmerged as of this writing) answers
/// a pre-gloas parent with the existing `PENDING` status instead of a new
/// one, and says Lighthouse does the same; our FULL rule differs from both.
/// Adopt PENDING here if that PR lands.
///
/// Committees are read through the store's shared [`Store::committee_cache`],
/// the cache `on_block` and the gossip checks use: gloas's boost gate reads
/// the committees of a weak parent's slot, and this runs every slot, so a
/// cache of its own would recompute every committee on every call.
pub fn get_head_node(store: &Store, config: &Config) -> Result<ForkChoiceNode> {
    let current_slot = get_current_slot(store, config);
    let rules = ForkRules::of(config.fork_at_epoch(compute_epoch_at_slot(current_slot)));
    let index = store.block_index();
    let committees = store.committee_cache();
    walk_head(store, &index, config, &committees, rules)
}

/// [`get_head_node`], recorded as the store's own head.
///
/// Takes `&mut Store`, unlike most functions in this file: it records the head
/// it just found through
/// [`Store::update_checkpoints`](ethlambda_storage::Store::update_checkpoints),
/// the head-and-checkpoint writer both chains share, so a restarted node has
/// something to answer from immediately rather than replaying this whole walk
/// on its first tick. That writer also keeps the canonical `BlockRoots` index
/// in step with the branch fork choice just picked.
///
/// The head node's payload status is recorded too ([`Store::head_payload_status`]):
/// the root alone cannot say which payload branch of a gloas block was picked.
///
/// Written unconditionally on every call, not only when the head changes: a
/// value written once and then left alone is a second source of truth a bug
/// can let drift, and the write is one small metadata row plus an index diff
/// that is empty whenever the head did not move, set against a whole weighted
/// tree walk.
pub fn get_head(store: &mut Store, config: &Config) -> Result<Root> {
    let head = get_head_node(store, config)?;
    // Recorded with its root, so a reader can tell which head the status is
    // for whichever of the two writes it sees first.
    store.set_head_payload_status(head.root, head.payload_status);
    store
        .update_checkpoints(ForkCheckpoints::head_only(head.root))
        .expect("record beacon head");
    Ok(head.root)
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
/// Gloas modifies the function (`fork-choice.md`'s "Modified
/// `get_attestation_due_ms`"): its deadline is the earlier
/// `ATTESTATION_DUE_BPS_GLOAS`, leaving room in the same slot for the payload
/// and payload attestation deadlines that follow.
///
/// Implementation choice, not spec text: the specification's function takes no
/// argument and each fork has its own. `epoch` is how this crate picks the
/// fork's rule, so one function serves both sides of the boundary.
pub fn get_attestation_due_ms(epoch: Epoch, config: &Config) -> u64 {
    let basis_points = match ForkRules::of(config.fork_at_epoch(epoch)) {
        ForkRules::PreGloas => config.attestation_due_bps,
        ForkRules::Gloas => config.attestation_due_bps_gloas,
    };
    get_slot_component_duration_ms(basis_points, config)
}

/// How far into a slot, in milliseconds, a proposer must stop attempting a
/// late-block reorg. Gloas does not modify this deadline.
pub fn get_proposer_reorg_cutoff_ms(config: &Config) -> u64 {
    get_slot_component_duration_ms(config.proposer_reorg_cutoff_bps, config)
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
///
/// Gloas widens `store.block_timeliness[root]` to two deadlines (see
/// [`Store::block_timeliness`](ethlambda_storage::Store::block_timeliness));
/// this reads only [`constants::ATTESTATION_TIMELINESS_INDEX`], the one
/// deadline this function ever checked, so its own behaviour is unchanged by
/// that widening.
pub fn is_head_late(store: &Store, head_root: Root) -> Result<bool> {
    let timely = store
        .block_timeliness(&head_root)
        .ok_or(Error::SpecAssert("head_root in store.block_timeliness"))?;
    Ok(!timely[constants::ATTESTATION_TIMELINESS_INDEX])
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
    time_into_slot_ms <= get_proposer_reorg_cutoff_ms(config)
}

/// Whether `head_root` has few enough votes to be overpowered by the
/// proposer's own boost, i.e. reorging it out would not be fighting an
/// already-decisive lead.
///
/// Counts an equivocating validator's effective balance toward `head_root`'s
/// weight whenever that validator sits in one of the head slot's committees,
/// on top of [`get_attestation_score`]'s own vote-based count. Without this,
/// the weight this reads could only fall as more equivocation evidence
/// arrived (an attester's vote stops counting once it is known to have
/// equivocated), so a head could flip from "weak" to "not weak" to "weak"
/// again as evidence trickled in; adding the equivocators' balance back in
/// keeps the total monotonic, so once a head is not weak it cannot become weak
/// again from something that was already true when it was imported.
///
/// `committees` derives the head slot's committees off `head_root`'s own
/// post-state, per bci's committee cache (`helpers/accessors.rs`), rather than
/// recomputing the shuffling by hand.
pub fn is_head_weak(
    store: &Store,
    head_root: Root,
    config: &Config,
    committees: &CommitteeCache,
) -> Result<bool> {
    let justified_checkpoint = store.beacon_justified_checkpoint();
    let justified_state = checkpoint_state(store, &justified_checkpoint, config)?;
    let index = store.block_index();
    let attestation_score = get_attestation_score(store, &index, head_root, &justified_state)?;
    let &(head_slot, _) = index
        .get(&head_root)
        .ok_or(Error::SpecAssert("head_root in store.blocks"))?;
    is_head_weak_with(
        store,
        head_root,
        head_slot,
        config,
        committees,
        &justified_state,
        attestation_score,
    )
}

/// [`is_head_weak`], given `head_root`'s [`get_attestation_score`] and its slot
/// instead of computing them.
///
/// The score is the one piece of [`is_head_weak`] that walks every vote, and
/// the head computation already holds it for every node in its weight table,
/// so [`should_apply_proposer_boost_with`] hands it in rather than paying for a
/// second pass over the votes. The slot comes from the same block index, which
/// spares the block decode that
/// [`Store::block_entry`](ethlambda_storage::Store::block_entry) costs on a
/// beacon store.
fn is_head_weak_with(
    store: &Store,
    head_root: Root,
    head_slot: Slot,
    config: &Config,
    committees: &CommitteeCache,
    justified_state: &BeaconState,
    attestation_score: Gwei,
) -> Result<bool> {
    let reorg_threshold =
        calculate_committee_fraction(justified_state, config.reorg_head_weight_threshold)?;
    let mut head_weight = attestation_score;

    let head_state = store
        .get_state(&head_root)
        .expect("get")
        .ok_or(Error::SpecAssert("head_root in store.block_states"))?;
    let epoch = compute_epoch_at_slot(head_slot);
    let epoch_committees = committees.committees(&head_state, epoch);
    for committee_index in 0..epoch_committees.committees_per_slot() {
        for &validator_index in epoch_committees.committee(head_slot, committee_index)? {
            if store.is_equivocating(validator_index) {
                let validator = justified_state.validator(validator_index)?;
                head_weight = head_weight.saturating_add(validator.effective_balance);
            }
        }
    }

    Ok(head_weight < reorg_threshold)
}

/// Whether `root`'s parent already has enough votes of its own that the
/// missing votes are assigned to it rather than being hoarded elsewhere.
///
/// Takes `root`, not the parent directly: the specification derives
/// `parent_root` from `store.blocks[root].parent_root` inside this function,
/// so a caller (`get_proposer_head`) that already looked up the parent for
/// its own purposes and this function's own lookup cannot disagree about
/// which block that is.
pub fn is_parent_strong(store: &Store, root: Root, config: &Config) -> Result<bool> {
    let justified_checkpoint = store.beacon_justified_checkpoint();
    let justified_state = checkpoint_state(store, &justified_checkpoint, config)?;
    let parent_threshold =
        calculate_committee_fraction(&justified_state, config.reorg_parent_weight_threshold)?;
    let (_, parent_root) = store
        .block_entry(&root)
        .ok_or(Error::SpecAssert("root in store.blocks"))?;
    let index = store.block_index();
    let parent_weight = get_attestation_score(store, &index, parent_root, &justified_state)?;
    Ok(parent_weight > parent_threshold)
}

/// Whether `root`'s proposer has published more than one block for its slot.
///
/// The specification scans every known block for one sharing `root`'s slot
/// and proposer. `index` is not free (it is a `Store::block_index` call, a
/// full `LiveChain` scan), but every caller here has already paid for one for
/// its own purposes and passes that same result on, so this answers the slot
/// half with no *further* scan, and pays for [`Store::get_signed_block`] only
/// on the handful of blocks that actually compete at that one slot, not the
/// whole indexed history.
pub fn is_proposer_equivocation(
    store: &Store,
    index: &HashMap<Root, (Slot, Root)>,
    root: Root,
) -> Result<bool> {
    let block = store
        .get_signed_block(&root)
        .expect("get")
        .ok_or(Error::SpecAssert("root in store.blocks"))?;
    let proposer_index = block.proposer_index();
    let slot = block.slot();

    let matching_roots = index
        .iter()
        .filter(|&(_, &(candidate_slot, _))| candidate_slot == slot)
        .filter_map(|(&candidate_root, _)| store.get_signed_block(&candidate_root).expect("get"))
        .filter(|candidate| candidate.proposer_index() == proposer_index)
        .count();

    Ok(matching_roots > 1)
}

/// The block a proposer at `slot` should build on: `head_root`'s parent
/// instead of `head_root` itself, if every reorg condition holds, and
/// `head_root` otherwise.
///
/// *Note*: the ordering of conditions here is the specification's suggested
/// order, not a requirement; an implementation may reorder or short-circuit
/// for performance.
///
/// Fulu (EIP-7917) drops the `shuffling_stable` requirement: `shuffling_stable`
/// is folded into `true` rather than left out of the `&&` chain, which reads
/// the same as the specification's own two near-identical copies of this
/// function without keeping two Rust copies to drift apart. Every fork through
/// fulu shares that one copy. Gloas modifies the function and has no version
/// here, since this node proposes on no gloas slot.
pub fn get_proposer_head(
    store: &Store,
    head_root: Root,
    slot: Slot,
    config: &Config,
    committees: &CommitteeCache,
) -> Result<Root> {
    // Read once and reused for `head_slot`/`parent_root` below and for the
    // fulu gate just after: `Store::block_entry` decodes the same signed
    // block internally on a beacon directory anyway (see its own
    // documentation), so this pays for one decode rather than two.
    let head_block = store
        .get_signed_block(&head_root)
        .expect("get")
        .ok_or(Error::SpecAssert("head_root in store.blocks"))?;
    let head_slot = head_block.slot();
    let parent_root = head_block.parent_root();
    let (parent_slot, _) = store
        .block_entry(&parent_root)
        .ok_or(Error::SpecAssert("parent_root in store.blocks"))?;

    // Only re-org the head block if it arrived later than the attestation
    // deadline.
    let head_late = is_head_late(store, head_root)?;
    // Do not re-org on an epoch boundary where the proposer shuffling could
    // change. [Modified in Fulu:EIP7917] The proposer lookahead fixes
    // assignments before the epoch boundary, so this is no longer a
    // requirement once the head being reorged is itself a fulu-or-later
    // block. Read off `head_block`'s own fork rather than
    // `Config::fork_at_epoch`: the config's schedule is the chain's real
    // activation epochs, which a small-slot fixture case never reaches, while
    // the block in hand already carries the fork that produced it.
    let shuffling_stable = head_block.fork_name() >= ForkName::Fulu || is_shuffling_stable(slot);
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
    let head_weak = is_head_weak(store, head_root, config, committees)?;

    // Check that the missing votes are assigned to the parent and not being
    // hoarded.
    let parent_strong = is_parent_strong(store, head_root, config)?;

    // Re-org more aggressively if there is a proposer equivocation in the
    // previous slot.
    let index = store.block_index();
    let proposer_equivocation = is_proposer_equivocation(store, &index, head_root)?;

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
    } else if head_weak && current_time_ok && proposer_equivocation {
        Ok(parent_root)
    } else {
        Ok(head_root)
    }
}

// ---------------------------------------------------------------------------
// Gloas: payload-aware fork choice
// ---------------------------------------------------------------------------
//
// EIP-7732 (ePBS) splits a block into two branches fork choice must weigh
// separately: the block may end up *empty* (no payload revealed, or the
// payload was not attested to as timely and available) or *full* (its
// builder's payload was revealed and attested to on time). A gloas
// [`ForkChoiceNode`] names both the block and which branch, where a pre-gloas
// one is a bare [`Root`] (see [`ForkChoiceNode`]'s own doc for why).
//
// Nodes are not stored: a `(root, PayloadStatus)` node is derived, on every
// call, from the block tree ([`Store::block_index`]), each block's own
// execution payload bid, and the set of verified payloads
// ([`is_payload_verified`]), exactly as [`get_node_children`] does. That
// mirrors the specification's own `Store`, which keeps `blocks` and
// `payloads` as the source of truth and builds a `ForkChoiceNode` on demand
// wherever one is needed, never as a third, separately maintained index.
//
// The specification's own gloas `fork-choice.md` only ever describes a
// gloas-anchored `Store`: `get_parent_payload_status` reads a parent's own
// execution payload bid, which a fulu (or earlier) parent does not have, and
// says nothing about the fulu-to-gloas boundary a real chain has to cross to
// ever reach a gloas-anchored store in the first place. This crate resolves
// that gap with a decided rule: a pre-gloas block is a single-variant node
// whose payload status is unconditionally FULL, since its payload ran inside
// the block itself and never had a separate empty branch to weigh against.
// Concretely: [`get_parent_payload_status`] of a gloas block with a
// pre-gloas parent answers FULL; a pre-gloas block's only child
// ([`get_node_children`]) is its FULL node; a vote for a pre-gloas block
// ([`get_supported_node`]) supports that FULL node whatever its own
// `payload_present` carries; [`gloas_get_ancestor`] stepping onto a
// pre-gloas block lands on FULL; a pre-gloas payload reads as already
// verified, timely and available ([`is_payload_verified`],
// [`payload_timeliness`], [`payload_data_availability`]), since it ran
// inside the block with no separate reveal to judge; and a pre-gloas head
// ([`get_head_node`]) is reported as `(root, Full)`. consensus-specs PR
// ethereum/consensus-specs#5125 (open, unmerged as of this writing) answers
// a pre-gloas parent with the existing `PENDING` status instead of a new
// one, and says Lighthouse does the same; our FULL rule differs from both.
// Adopt PENDING here if that PR lands.
//
// Functions here are named exactly as the specification names them, with a
// `gloas_` prefix only where a pre-gloas function of the same name already
// exists in this file and the two cannot be one function: `gloas_get_ancestor`,
// `gloas_get_weight`, `gloas_get_head`, `gloas_verify_data_column_sidecar` and
// `gloas_verify_data_column_sidecar_kzg_proofs`. The functions the specification
// modifies in a way one function can dispatch on (`get_attestation_due_ms`
// reads the fork of its `epoch`) are not split at all. Two further functions
// (`gloas_bid`, `gloas_get_attestation_score`) are private and have no name
// of their own in the specification at all; they stay `gloas_`-prefixed for
// the same reason, since both exist only to bind gloas's own semantics
// (a block's bid, an ancestor check with a payload dimension) into either a
// projection this crate needs or spec-unmodified text (`get_attestation_score`)
// that the specification's own per-fork composition binds differently per
// fork. `is_head_weak` needs no gloas copy at all: see its call site below
// for why the pre-gloas function already answers gloas's question. Every
// other function below is new to this file, pre-gloas and gloas alike, and
// keeps the specification's bare name.

/// `block`'s own execution payload bid, projected out of the fork-generic
/// [`SignedBeaconBlock`] enum.
///
/// Every function in this section assumes `block` is itself gloas-shaped,
/// which does not hold at the fulu-to-gloas boundary on its own: the first
/// gloas block's own parent is a fulu block with no bid at all.
/// [`parent_payload_status_of`] (behind both [`get_parent_payload_status`]
/// and [`derive_payload_link`]) and [`on_execution_payload_envelope`] call
/// this. The first never reaches here for a pre-gloas parent though: it
/// answers [`PayloadStatus::Full`] for one directly, per this crate's decided
/// rule for that boundary (see the module documentation's "Gloas:
/// payload-aware fork choice" section). A non-gloas block still reaching here
/// is therefore a caller bug, reported by name rather than assumed away, the
/// same projection `helpers::gloas::gloas_state_ref` gives a state.
fn gloas_bid(block: &SignedBeaconBlock) -> Result<&gloas::ExecutionPayloadBid> {
    match block {
        SignedBeaconBlock::Gloas(inner) => {
            Ok(&inner.message.body.signed_execution_payload_bid.message)
        }
        other => Err(Error::UnsupportedForFork {
            function: "gloas_bid",
            fork: other.fork_name(),
        }),
    }
}

/// Whether `root` names a block this store holds and that block is
/// pre-gloas: the one bit every function in this section needs to tell a
/// real payload-bearing block from a pre-gloas one whose payload ran inside
/// the block itself (this crate's decided rule for the fulu-to-gloas
/// boundary; see the module documentation's "Gloas: payload-aware fork
/// choice" section).
///
/// `false` for a root this store has never heard of, not `true`: a `None`
/// from [`Store::get_signed_block`](ethlambda_storage::Store::get_signed_block)
/// answers `Some(block) if ...` the same as a gloas one would, so callers
/// fall through to their own gloas-shaped behavior rather than assuming an
/// unknown root is pre-gloas, which would answer, say,
/// [`is_payload_verified`] `true` for a root the specification would never
/// call verified.
///
/// Needs only the block's fork, so it reads the recorded [`BlockPayloadLink`]
/// when there is one and otherwise decodes the block, without deriving (or
/// recording) the parent comparison a full link needs.
fn is_known_pre_gloas_block(store: &Store, root: Root) -> bool {
    if let Some(link) = store.payload_link(&root) {
        return !link.is_gloas();
    }
    matches!(
        store.get_signed_block(&root).expect("get"),
        Some(block) if is_pre_gloas(&block)
    )
}

/// `block`'s [`BlockPayloadLink`], derived from the block and, for a gloas
/// block, its parent's bid through [`parent_payload_status_of`].
///
/// The parent's status is `None` only when the parent block is not in the
/// store. A gloas block that is not the anchor always has its parent there
/// (`on_block` refuses it otherwise), and `on_block` records the link with the
/// status [`get_parent_payload_status`] returned, so the two agree by
/// construction; `the_recorded_payload_links_match_the_specifications_parent_status`
/// checks that they do.
fn derive_payload_link(store: &Store, block: &SignedBeaconBlock) -> Result<BlockPayloadLink> {
    let rules = ForkRules::of(block.fork_name());
    let parent_status = match rules {
        ForkRules::PreGloas => None,
        ForkRules::Gloas => store
            .get_signed_block(&block.parent_root())
            .expect("get")
            .map(|parent| parent_payload_status_of(block, &parent))
            .transpose()?,
    };
    Ok(rules.payload_link(parent_status))
}

/// `root`'s [`BlockPayloadLink`]: the entry `on_block` recorded, or, for a
/// block imported before the last restart (the scratch is in memory only) or
/// whose entry was pruned, one derived by decoding the block and recorded for
/// next time.
///
/// `None` when the store does not hold `root` at all. A link whose parent
/// status is unknown is recorded like any other: it is the anchor's, whose
/// parent is not in the store by construction, and re-deriving it on every
/// read would decode two blocks each time. A block persisted ahead of its
/// parent is not read here before `on_block` imports it, and `on_block`
/// records its own link over whatever is there.
fn block_payload_link(store: &Store, root: Root) -> Result<Option<BlockPayloadLink>> {
    if let Some(link) = store.payload_link(&root) {
        return Ok(Some(link));
    }
    let Some(block) = store.get_signed_block(&root).expect("get") else {
        return Ok(None);
    };
    let link = derive_payload_link(store, &block)?;
    store.set_payload_link(root, block.slot(), link);
    Ok(Some(link))
}

/// Makes sure `root`'s [`BlockPayloadLink`] is recorded, deriving it by
/// decoding the block if it is not (after a restart, which loses the scratch).
///
/// For the actor to call before pruning links at the finalized block, whose
/// own link the prune keys its bound on. Costs at most one derivation for a
/// finalized root that was imported before the restart.
pub fn ensure_payload_link(store: &Store, root: Root) -> Result<()> {
    block_payload_link(store, root).map(|_| ())
}

/// Whether `block` is handled under the pre-gloas rules, from an exhaustive
/// match on [`ForkRules`], so a fork added after gloas has to be placed there
/// rather than being read as "not gloas, therefore pre-gloas" by each caller.
fn is_pre_gloas(block: &SignedBeaconBlock) -> bool {
    match ForkRules::of(block.fork_name()) {
        ForkRules::PreGloas => true,
        ForkRules::Gloas => false,
    }
}

/// `is_payload_verified` (gloas `fork-choice.md`): whether `root`'s execution
/// payload envelope has been locally delivered and verified via
/// [`on_execution_payload_envelope`], the only caller of
/// [`Store::insert_verified_payload`](ethlambda_storage::Store::insert_verified_payload).
///
/// A pre-gloas block has no envelope to deliver at all: its payload ran
/// inside the block itself, so this answers `true` for one unconditionally,
/// per this crate's decided rule for the fulu-to-gloas boundary (see the
/// module documentation's "Gloas: payload-aware fork choice" section).
pub fn is_payload_verified(store: &Store, root: Root) -> bool {
    store.has_verified_payload(&root) || is_known_pre_gloas_block(store, root)
}

/// The execution verdict gloas's attestation gossip rules read for `root`'s
/// payload, as the specification's `block_payload_statuses`.
///
/// A pre-gloas block's payload ran inside the block, so its verdict is the
/// block's own: `NOT_VALIDATED` while it sits in the optimistic set, `VALID`
/// otherwise (an invalidated block is dropped from the store, so is never
/// asked about). This keeps an honest gloas-slot vote for the last pre-gloas
/// block, which this node's boundary rule treats as FULL, from being ignored as
/// optimistic. A gloas root reads [`Store::beacon_block_payload_status`].
pub fn block_payload_status(store: &Store, root: Root) -> PayloadStatusEnum {
    if is_known_pre_gloas_block(store, root) {
        if store.is_beacon_optimistic(root) {
            PayloadStatusEnum::Syncing
        } else {
            PayloadStatusEnum::Valid
        }
    } else {
        store.beacon_block_payload_status(root)
    }
}

/// `payload_timeliness` (gloas `fork-choice.md`): whether `root`'s payload is
/// considered `timely` (or not, when `timely` is `false`), taking into
/// account both local availability and the payload timeliness committee's
/// votes.
///
/// A pre-gloas block has no payload timeliness committee vote to read at
/// all, since the committee did not exist yet, and no separate reveal to
/// judge the timeliness of: it answers `timely` back unconditionally
/// (matching [`payload_data_availability`]'s own `available`), part of this
/// crate's decided rule for the fulu-to-gloas boundary (see the module
/// documentation's "Gloas: payload-aware fork choice" section). Checked
/// before the vote lookup below, not after: a pre-gloas root was never
/// registered in [`Store::payload_timeliness_vote`](ethlambda_storage::Store::payload_timeliness_vote)
/// in the first place, so reading it first would raise
/// `Error::SpecAssert` rather than ever reach the fallback that answers it.
pub fn payload_timeliness(store: &Store, root: Root, timely: bool) -> Result<bool> {
    if is_known_pre_gloas_block(store, root) {
        return Ok(timely);
    }

    let vote = store
        .payload_timeliness_vote(&root)
        .ok_or(Error::SpecAssert("root in store.payload_timeliness_vote"))?;

    // If the payload is not locally available, it is not considered
    // available regardless of the PTC vote.
    if !store.has_verified_payload(&root) {
        return Ok(!timely);
    }

    let votes: Vec<bool> = vote.into_iter().flatten().collect();
    let matching = votes.iter().filter(|&&v| v == timely).count() as u64;
    Ok(matching > preset::PAYLOAD_TIMELY_THRESHOLD)
}

/// `payload_data_availability` (gloas `fork-choice.md`): whether `root`'s
/// blob data is considered `available` (or not, when `available` is
/// `false`), the sibling check of [`payload_timeliness`].
///
/// A pre-gloas block's data availability was never a separate question
/// either: see [`payload_timeliness`]'s own doc for the matching reasoning
/// and why the check below runs before the vote lookup.
pub fn payload_data_availability(store: &Store, root: Root, available: bool) -> Result<bool> {
    if is_known_pre_gloas_block(store, root) {
        return Ok(available);
    }

    let vote = store
        .payload_data_availability_vote(&root)
        .ok_or(Error::SpecAssert(
            "root in store.payload_data_availability_vote",
        ))?;

    if !store.has_verified_payload(&root) {
        return Ok(!available);
    }

    let votes: Vec<bool> = vote.into_iter().flatten().collect();
    let matching = votes.iter().filter(|&&v| v == available).count() as u64;
    Ok(matching > preset::DATA_AVAILABILITY_TIMELY_THRESHOLD)
}

/// `get_parent_payload_status` (gloas `fork-choice.md`): whether `block`
/// builds on its parent's full payload branch or its empty one, found by
/// comparing the two blocks' own bids.
///
/// A pre-gloas parent has no bid to compare against, and no empty branch of
/// its own to have built one against: it answers FULL unconditionally, per
/// this crate's decided rule for the fulu-to-gloas boundary (see the module
/// documentation's "Gloas: payload-aware fork choice" section).
///
/// Takes `block: &SignedBeaconBlock`, not the specification's unsigned
/// `BeaconBlock`: see the module documentation's "Signed blocks" section for
/// why every function in this file does.
pub fn get_parent_payload_status(
    store: &Store,
    block: &SignedBeaconBlock,
) -> Result<PayloadStatus> {
    let parent = store
        .get_signed_block(&block.parent_root())
        .expect("get")
        .ok_or(Error::SpecAssert("block.parent_root in store.blocks"))?;
    parent_payload_status_of(block, &parent)
}

/// [`get_parent_payload_status`]'s comparison, given the parent block: the one
/// place a child's bid is read against its parent's, shared with
/// [`derive_payload_link`] so a recorded link cannot disagree with the
/// specification's function.
fn parent_payload_status_of(
    block: &SignedBeaconBlock,
    parent: &SignedBeaconBlock,
) -> Result<PayloadStatus> {
    if is_pre_gloas(parent) {
        return Ok(PayloadStatus::Full);
    }
    let parent_block_hash = gloas_bid(block)?.parent_block_hash;
    let message_block_hash = gloas_bid(parent)?.block_hash;
    Ok(if parent_block_hash == message_block_hash {
        PayloadStatus::Full
    } else {
        PayloadStatus::Empty
    })
}

/// `is_parent_node_full` (gloas `fork-choice.md`).
pub fn is_parent_node_full(store: &Store, block: &SignedBeaconBlock) -> Result<bool> {
    Ok(get_parent_payload_status(store, block)? == PayloadStatus::Full)
}

/// `get_ancestor` (gloas `fork-choice.md`, modified): `node`'s ancestor at
/// `slot`, carrying the payload status of each parent step the descent
/// passes through.
///
/// A loop rather than the specification's recursion, matching pre-gloas
/// [`get_ancestor`] for the same reason: a long unfinalized suffix must not
/// risk a stack overflow.
///
/// The descent picks each next root by `block.slot` alone, so the payload
/// status threaded through it never changes which root it lands on, only the
/// label a caller may then discard. That is why the specification's
/// `get_checkpoint_block`, which is this walk from a `Pending` node keeping
/// only `.root`, has no gloas function here: it answers what the pre-gloas,
/// index-only [`get_checkpoint_block`] does on any chain both could answer.
/// [`filter_block_tree`] (the only caller of [`get_checkpoint_block`] in this
/// file; [`get_voting_source`] never calls it) therefore keeps calling the
/// pre-gloas version, which is what lets [`get_filtered_block_tree`] serve
/// [`gloas_get_head`] with no per-block fetch.
pub fn gloas_get_ancestor(
    store: &Store,
    node: ForkChoiceNode,
    slot: Slot,
) -> Result<ForkChoiceNode> {
    let mut node = node;
    loop {
        let block = store
            .get_signed_block(&node.root)
            .expect("get")
            .ok_or(Error::SpecAssert("node.root in store.blocks"))?;
        if block.slot() > slot {
            let payload_status = get_parent_payload_status(store, &block)?;
            node = ForkChoiceNode {
                root: block.parent_root(),
                payload_status,
            };
        } else {
            return Ok(node);
        }
    }
}

/// `is_ancestor` (gloas `fork-choice.md`, modified): whether `ancestor` is on
/// `node`'s chain, with `ancestor.payload_status ==
/// PayloadStatus::Pending` acting as a wildcard that matches either branch.
///
/// No pre-gloas counterpart exists in this file: a pre-gloas `ForkChoiceNode`
/// is a bare root (see that type's own doc), so every pre-gloas call this
/// question would need instead compares two roots directly.
///
/// Against a `Pending` `ancestor`, the wildcard above makes this reduce to
/// `gloas_get_ancestor(node, ancestor_slot).root == ancestor.root`, and
/// `gloas_get_ancestor`'s own descent picks its next root by `block.slot`
/// alone (see [`gloas_get_ancestor`]'s own doc), so that root is
/// exactly what the pre-gloas, index-only [`get_ancestor`] would answer for
/// the same walk. The specification's `is_head_weak` and `is_parent_strong`
/// always score a `Pending` node (a bare block root), so the attestation
/// score they need takes this reduction and equals the pre-gloas,
/// root-based one; that is what lets `should_apply_proposer_boost` call the
/// pre-gloas [`is_head_weak`] directly rather than keep a gloas copy of it.
/// `gloas_get_weight` also scores `Empty` and `Full` nodes, which do not
/// reduce this way, so it keeps its own attestation score.
pub fn is_ancestor(store: &Store, node: ForkChoiceNode, ancestor: ForkChoiceNode) -> Result<bool> {
    let (ancestor_slot, _) = store
        .block_entry(&ancestor.root)
        .ok_or(Error::SpecAssert("ancestor.root in store.blocks"))?;
    let node_ancestor = gloas_get_ancestor(store, node, ancestor_slot)?;
    if node_ancestor.root != ancestor.root {
        return Ok(false);
    }
    Ok(node_ancestor.payload_status == ancestor.payload_status
        || ancestor.payload_status == PayloadStatus::Pending)
}

/// `get_supported_node` (gloas `fork-choice.md`): the node `message`
/// supports, full or empty once its slot has passed the block's own, pending
/// otherwise.
///
/// A vote for a pre-gloas block always supports its FULL node, whatever
/// `message.payload_present` carries: every pre-gloas attestation leaves
/// that field `false` (see [`LatestMessage::payload_present`]'s own doc),
/// which would otherwise read as a vote for an empty branch a pre-gloas
/// block never had. Part of this crate's decided rule for the
/// fulu-to-gloas boundary; see the module documentation's "Gloas:
/// payload-aware fork choice" section.
///
/// One [`Store::get_signed_block`](ethlambda_storage::Store::get_signed_block)
/// read answers both `block_slot` and the fork-shape check above, rather
/// than the cheaper [`Store::block_entry`](ethlambda_storage::Store::block_entry)
/// for the slot and a second decode for the shape: this runs once per voter
/// in [`gloas_get_attestation_score`]'s own per-candidate walk, so a second
/// decode there is not free.
pub fn get_supported_node(store: &Store, message: LatestMessage) -> Result<ForkChoiceNode> {
    let block = store
        .get_signed_block(&message.root)
        .expect("get")
        .ok_or(Error::SpecAssert("message.root in store.blocks"))?;
    let payload_status = if block.slot() < message.slot {
        if is_pre_gloas(&block) || message.payload_present {
            PayloadStatus::Full
        } else {
            PayloadStatus::Empty
        }
    } else {
        PayloadStatus::Pending
    };
    Ok(ForkChoiceNode {
        root: message.root,
        payload_status,
    })
}

/// `is_previous_slot_payload_decision` (gloas `fork-choice.md`): whether
/// `node` is the still-undecided empty/full choice for a block from the
/// previous slot, the one case [`gloas_get_weight`] cannot yet settle by
/// weight.
pub fn is_previous_slot_payload_decision(
    store: &Store,
    node: ForkChoiceNode,
    config: &Config,
) -> Result<bool> {
    let (block_slot, _) = store
        .block_entry(&node.root)
        .ok_or(Error::SpecAssert("node.root in store.blocks"))?;
    Ok(is_payload_decision_at(
        block_slot,
        node.payload_status,
        get_current_slot(store, config),
    ))
}

/// [`is_previous_slot_payload_decision`]'s test, with the block's slot and the
/// current slot already in hand, for the head computation that reads the slot
/// from its block index instead of decoding the block.
fn is_payload_decision_at(
    block_slot: Slot,
    payload_status: PayloadStatus,
    current_slot: Slot,
) -> bool {
    let is_previous_slot = block_slot.checked_add(1) == Some(current_slot);
    let is_payload_decision = matches!(payload_status, PayloadStatus::Empty | PayloadStatus::Full);
    is_previous_slot && is_payload_decision
}

/// `should_build_on_full` (gloas `fork-choice.md`): whether a proposer at
/// `slot` should build on `head`'s full payload branch rather than its empty
/// one.
pub fn should_build_on_full(store: &Store, head: ForkChoiceNode, slot: Slot) -> Result<bool> {
    verify(
        head.payload_status != PayloadStatus::Pending,
        "head.payload_status != PAYLOAD_STATUS_PENDING",
    )?;
    let (head_slot, _) = store
        .block_entry(&head.root)
        .ok_or(Error::SpecAssert("head.root in store.blocks"))?;
    if head_slot.checked_add(1) != Some(slot) {
        return Ok(head.payload_status == PayloadStatus::Full);
    }
    if head.payload_status == PayloadStatus::Empty {
        return Ok(false);
    }
    if payload_timeliness(store, head.root, false)? {
        return Ok(false);
    }
    if payload_data_availability(store, head.root, false)? {
        return Ok(false);
    }
    Ok(true)
}

/// `should_extend_payload` (gloas `fork-choice.md`): whether a proposer
/// building on `root`'s (previous-slot) payload should extend it rather than
/// build empty, favoring extension unless the PTC view is against it and the
/// current proposer-boosted block itself chose empty.
pub fn should_extend_payload(store: &Store, root: Root, config: &Config) -> Result<bool> {
    should_extend_payload_with(
        store,
        root,
        get_current_slot(store, config),
        |block_root| store.block_entry(&block_root),
        proposer_parent_is_full_from_blocks,
    )
}

/// [`should_extend_payload`] with the current slot, a block's
/// `(slot, parent_root)` lookup and the answer to the specification's
/// `is_parent_node_full` for the proposer-boosted block supplied by the
/// caller. The head computation answers both from its block index and the
/// payload links rather than decoding blocks
/// ([`proposer_parent_is_full_from_link`]); the public function keeps the
/// specification's own decode ([`proposer_parent_is_full_from_blocks`]), so
/// a test comparing the two does not compare the walk with itself on that leg.
fn should_extend_payload_with(
    store: &Store,
    root: Root,
    current_slot: Slot,
    block_entry: impl Fn(Root) -> Option<(Slot, Root)>,
    proposer_parent_is_full: impl Fn(&Store, Root) -> Result<bool>,
) -> Result<bool> {
    let (block_slot, _) = block_entry(root).ok_or(Error::SpecAssert("root in store.blocks"))?;
    verify(
        block_slot.checked_add(1) == Some(current_slot),
        "store.blocks[root].slot + 1 == get_current_slot(store)",
    )?;
    if !is_payload_verified(store, root) {
        return Ok(false);
    }
    let proposer_root = store.proposer_boost_root();
    let payload_is_timely = payload_timeliness(store, root, true)?;
    let payload_data_is_available = payload_data_availability(store, root, true)?;
    if payload_is_timely && payload_data_is_available {
        return Ok(true);
    }
    if proposer_root.is_zero() {
        return Ok(true);
    }
    let (_, proposer_parent_root) = block_entry(proposer_root).ok_or(Error::SpecAssert(
        "store.proposer_boost_root in store.blocks",
    ))?;
    if proposer_parent_root != root {
        return Ok(true);
    }
    proposer_parent_is_full(store, proposer_root)
}

/// `is_parent_node_full(store, store.blocks[proposer_root])`, the
/// specification's own call: both blocks decoded.
fn proposer_parent_is_full_from_blocks(store: &Store, proposer_root: Root) -> Result<bool> {
    let proposer_block =
        store
            .get_signed_block(&proposer_root)
            .expect("get")
            .ok_or(Error::SpecAssert(
                "store.proposer_boost_root in store.blocks",
            ))?;
    is_parent_node_full(store, &proposer_block)
}

/// The same answer from the block's [`BlockPayloadLink`], which records what
/// [`is_parent_node_full`] would compute; see [`derive_payload_link`].
fn proposer_parent_is_full_from_link(store: &Store, proposer_root: Root) -> Result<bool> {
    let link = block_payload_link(store, proposer_root)?.ok_or(Error::SpecAssert(
        "store.proposer_boost_root in store.blocks",
    ))?;
    let parent_status = link
        .parent_status()
        .ok_or(Error::SpecAssert("block.parent_root in store.blocks"))?;
    Ok(parent_status == PayloadStatus::Full)
}

/// `get_payload_status_tiebreaker` (gloas `fork-choice.md`): [`gloas_get_head`]'s
/// tiebreaker between a block's full and empty branches, once their weights
/// alone cannot decide (their weight is `0` while
/// [`is_previous_slot_payload_decision`] holds; see [`gloas_get_weight`]).
pub fn get_payload_status_tiebreaker(
    store: &Store,
    node: ForkChoiceNode,
    config: &Config,
) -> Result<u8> {
    let current_slot = get_current_slot(store, config);
    payload_status_tiebreaker_with(
        store,
        node,
        current_slot,
        |root| store.block_entry(&root),
        proposer_parent_is_full_from_blocks,
    )
}

/// [`get_payload_status_tiebreaker`] with the current slot and the block
/// lookup supplied by the caller; see [`should_extend_payload_with`].
fn payload_status_tiebreaker_with(
    store: &Store,
    node: ForkChoiceNode,
    current_slot: Slot,
    block_entry: impl Fn(Root) -> Option<(Slot, Root)>,
    proposer_parent_is_full: impl Fn(&Store, Root) -> Result<bool>,
) -> Result<u8> {
    let (block_slot, _) =
        block_entry(node.root).ok_or(Error::SpecAssert("node.root in store.blocks"))?;
    if is_payload_decision_at(block_slot, node.payload_status, current_slot) {
        if node.payload_status == PayloadStatus::Empty {
            return Ok(1);
        }
        if should_extend_payload_with(
            store,
            node.root,
            current_slot,
            &block_entry,
            proposer_parent_is_full,
        )? {
            return Ok(2);
        }
        Ok(0)
    } else {
        Ok(node.payload_status as u8)
    }
}

/// `should_apply_proposer_boost` (gloas `fork-choice.md`): whether the
/// current proposer-boosted block still deserves its boost. Applies
/// unconditionally unless the parent is exactly one slot behind it and
/// weak; even then, the boost is withheld only when a same-slot sibling of
/// the parent, sharing its proposer and itself timely by the PTC deadline
/// (an early equivocation), exists. With no such sibling, the boost still
/// applies.
///
/// **Implementation choice, not spec text**: a candidate with no recorded
/// [`Store::block_timeliness`](ethlambda_storage::Store::block_timeliness)
/// entry reads as not timely by either deadline, rather than raising
/// `Error::SpecAssert`. A gloas block's entry is stored and reloaded on
/// resume, so a gap is a block with no entry at all; reading it as "not an
/// early equivocation" rather than aborting the whole weight computation is the
/// conservative answer (it can only ever miss withholding a boost, never
/// wrongly withhold one), the same shape of tolerance
/// [`gloas_get_attestation_score`]'s own doc gives for a pruned vote.
pub fn should_apply_proposer_boost(
    store: &Store,
    config: &Config,
    committees: &CommitteeCache,
) -> Result<bool> {
    if store.proposer_boost_root().is_zero() {
        return Ok(false);
    }
    let justified_checkpoint = store.beacon_justified_checkpoint();
    let justified_state = checkpoint_state(store, &justified_checkpoint, config)?;
    let index = store.block_index();
    should_apply_proposer_boost_with(
        store,
        config,
        committees,
        &index,
        &justified_state,
        |parent_root| get_attestation_score(store, &index, parent_root, &justified_state),
    )
}

/// [`should_apply_proposer_boost`] with the block index, the justified state
/// and the parent's attestation score supplied by the caller.
///
/// The decision does not depend on which node is being weighed, and its only
/// expensive input is the parent's attestation score. The head computation
/// already holds that score for every node it weighs, so it passes a lookup
/// into its own table here, where the specification's per-node `get_weight`
/// recomputes it from the votes on every call.
///
/// `parent_score` is called at most once, with the parent's root, and only
/// when the parent is from the previous slot. It must return the same number
/// [`get_attestation_score`] does for that root.
fn should_apply_proposer_boost_with(
    store: &Store,
    config: &Config,
    committees: &CommitteeCache,
    index: &HashMap<Root, (Slot, Root)>,
    justified_state: &BeaconState,
    parent_score: impl FnOnce(Root) -> Result<Gwei>,
) -> Result<bool> {
    let proposer_boost_root = store.proposer_boost_root();
    if proposer_boost_root.is_zero() {
        return Ok(false);
    }

    let &(slot, parent_root) = index.get(&proposer_boost_root).ok_or(Error::SpecAssert(
        "store.proposer_boost_root in store.blocks",
    ))?;
    let &(parent_slot, _) = index
        .get(&parent_root)
        .ok_or(Error::SpecAssert("parent_root in store.blocks"))?;

    // Apply proposer boost if `parent` is not from the previous slot.
    if parent_slot.checked_add(1).is_some_and(|next| next < slot) {
        return Ok(true);
    }
    // Apply proposer boost if `parent` is not weak. Scored through the
    // pre-gloas `is_head_weak`, not a gloas copy: see `is_ancestor`'s own
    // doc for why a `Pending` node's score is the same either way.
    let parent_attestation_score = parent_score(parent_root)?;
    if !is_head_weak_with(
        store,
        parent_root,
        parent_slot,
        config,
        committees,
        justified_state,
        parent_attestation_score,
    )? {
        return Ok(true);
    }

    // If `parent` is weak and from the previous slot, apply proposer boost
    // if there are no early equivocations.
    let parent_block = store
        .get_signed_block(&parent_root)
        .expect("get")
        .ok_or(Error::SpecAssert("parent_root in store.blocks"))?;
    let mut has_equivocation = false;
    for (&candidate_root, &(candidate_slot, _)) in index {
        if candidate_root == parent_root {
            continue;
        }
        if candidate_slot.checked_add(1) != Some(slot) {
            continue;
        }
        let timely = store
            .block_timeliness(&candidate_root)
            .unwrap_or([false; constants::NUM_BLOCK_TIMELINESS_DEADLINES]);
        if !timely[constants::PTC_TIMELINESS_INDEX] {
            continue;
        }
        let candidate_block = store
            .get_signed_block(&candidate_root)
            .expect("get")
            .ok_or(Error::SpecAssert("root in store.blocks"))?;
        if candidate_block.proposer_index() == parent_block.proposer_index() {
            has_equivocation = true;
            break;
        }
    }

    Ok(!has_equivocation)
}

/// [`gloas_get_weight`]'s attestation half: unmodified spec text (phase0
/// `fork-choice.md`'s own `get_attestation_score`), bound here to gloas's own
/// [`is_ancestor`] and [`get_supported_node`] the way the specification's own
/// per-fork composition binds it, rather than to the collapsed
/// root-comparison the pre-gloas [`get_attestation_score`] uses (sound only
/// because a pre-gloas `ForkChoiceNode` is a bare root; see that function's
/// own doc).
///
/// **Implementation choice, not spec text**: a voter's last message is
/// skipped when its own root is not in the store at all, rather than
/// raising `Error::SpecAssert` the way [`get_supported_node`] otherwise
/// would, so one stale voter cannot abort the whole head computation. A
/// block pruned from the fork-choice index is still in the store, so a
/// vote for it passes this check and walks the block table, which is safe
/// and contributes nothing (it cannot descend from a scored node, the
/// reasoning [`compute_weights`]'s own doc gives); the skip fires only for
/// a root the store never held. Checked with `store.has_block`, not
/// [`Store::block_entry`](ethlambda_storage::Store::block_entry): the latter
/// decodes the whole block on a beacon store to answer two fields this
/// check does not even need, which would spend a decode on every voter just
/// to maybe skip [`get_supported_node`]'s own.
fn gloas_get_attestation_score(
    store: &Store,
    node: ForkChoiceNode,
    state: &BeaconState,
) -> Result<Gwei> {
    let current_epoch = get_current_epoch(state);
    let mut attestation_score: Gwei = 0;
    for validator_index in get_active_validator_indices(state, current_epoch) {
        let validator = state.validator(validator_index)?;
        if validator.slashed || store.is_equivocating(validator_index) {
            continue;
        }
        let Some(message) = store.latest_message(validator_index) else {
            continue;
        };
        if !store.has_block(&message.root) {
            continue;
        }
        let supported = get_supported_node(store, message)?;
        if is_ancestor(store, supported, node)? {
            attestation_score = attestation_score.saturating_add(validator.effective_balance);
        }
    }
    Ok(attestation_score)
}

/// `get_weight` (gloas `fork-choice.md`, modified).
///
/// **A reference, not the node's weight.** The node weighs with
/// [`compute_node_weights`], one bottom-up pass; this stays spec-literal, as the
/// per-node definition that table is tested against (the fork-choice harness
/// compares every `viable_for_head_roots_and_weights` leaf, and the randomized
/// differential test every node). Its costs are why the node does not call it:
/// - every latest message is walked afresh for every node visited;
/// - each [`gloas_get_ancestor`] hop decodes two signed blocks, and
///   [`get_supported_node`] a third, once per voter;
/// - telling a pre-gloas root from a gloas one is itself a decode;
/// - [`should_apply_proposer_boost`] reruns a full [`is_head_weak`] score on
///   every call, although its answer does not depend on `node`.
///
/// A vote for a block this store has pruned below its finalized anchor does not
/// abort the computation with `Error::SpecAssert`, the failure
/// [`compute_weights`]'s own doc describes pre-gloas `get_weight` having:
/// [`gloas_get_attestation_score`]'s own doc has the direct fix, and
/// [`get_attestation_score`]'s the one reached through
/// [`should_apply_proposer_boost`] into [`is_head_weak`].
pub fn gloas_get_weight(
    store: &Store,
    node: ForkChoiceNode,
    config: &Config,
    committees: &CommitteeCache,
) -> Result<Gwei> {
    if is_previous_slot_payload_decision(store, node, config)? {
        return Ok(0);
    }

    let justified_checkpoint = store.beacon_justified_checkpoint();
    let state = checkpoint_state(store, &justified_checkpoint, config)?;
    let attestation_score = gloas_get_attestation_score(store, node, &state)?;

    if !should_apply_proposer_boost(store, config, committees)? {
        // Return only attestation score if proposer boost should not apply.
        return Ok(attestation_score);
    }

    // Calculate proposer score if proposer boost should apply.
    let proposer_boost_node = ForkChoiceNode {
        root: store.proposer_boost_root(),
        payload_status: PayloadStatus::Pending,
    };
    // Boost is applied if `node` is an ancestor of `proposer_boost_node`.
    let proposer_score = if is_ancestor(store, proposer_boost_node, node)? {
        get_proposer_score(store, config)?
    } else {
        0
    };

    Ok(attestation_score.saturating_add(proposer_score))
}

/// `get_node_children` (gloas `fork-choice.md`, modified): the children of
/// `node` in the payload-aware tree, either its own empty/full branches (when
/// `node` is still `Pending`) or the next blocks that agree with `node`'s own
/// payload status about their shared parent.
///
/// A pre-gloas `node` has no empty branch of its own: its only child is its
/// FULL node, per this crate's decided rule for the fulu-to-gloas boundary
/// (see the module documentation's "Gloas: payload-aware fork choice"
/// section). The specification's own gloas `fork-choice.md` never describes
/// this case, since it only ever anchors a gloas `Store`.
///
/// **A reference, not the node's descent.** Telling a pre-gloas `node` apart
/// from a gloas one costs a full block decode here, on every `Pending` node.
/// The head walk answers the same question from `walk_children`, which reads
/// the payload links instead; see [`gloas_get_weight`] for the rest.
///
/// `blocks` is [`Store::block_index`]'s own shape, not the specification's
/// `Dict[Root, BeaconBlock]`: see the section documentation above for why
/// nodes, and the trees built from them, are derived rather than stored.
pub fn get_node_children(
    store: &Store,
    blocks: &HashMap<Root, (Slot, Root)>,
    node: ForkChoiceNode,
) -> Result<Vec<ForkChoiceNode>> {
    if node.payload_status == PayloadStatus::Pending {
        let block = store
            .get_signed_block(&node.root)
            .expect("get")
            .ok_or(Error::SpecAssert("node.root in store.blocks"))?;
        if is_pre_gloas(&block) {
            return Ok(vec![ForkChoiceNode {
                root: node.root,
                payload_status: PayloadStatus::Full,
            }]);
        }
        let mut children = vec![ForkChoiceNode {
            root: node.root,
            payload_status: PayloadStatus::Empty,
        }];
        // `store.has_verified_payload` directly, not `is_payload_verified`:
        // `block` above already confirmed this is a gloas node, so
        // `is_payload_verified`'s own fork-shape check would only redecode
        // the same block to reach the answer this already has in hand.
        if store.has_verified_payload(&node.root) {
            children.push(ForkChoiceNode {
                root: node.root,
                payload_status: PayloadStatus::Full,
            });
        }
        Ok(children)
    } else {
        let mut children = Vec::new();
        for (&root, &(_, parent_root)) in blocks {
            if parent_root != node.root {
                continue;
            }
            let block = store
                .get_signed_block(&root)
                .expect("get")
                .ok_or(Error::SpecAssert("root in blocks"))?;
            if node.payload_status == get_parent_payload_status(store, &block)? {
                children.push(ForkChoiceNode {
                    root,
                    payload_status: PayloadStatus::Pending,
                });
            }
        }
        Ok(children)
    }
}

/// `get_head` (gloas `fork-choice.md`, modified): the LMD GHOST head as a
/// full [`ForkChoiceNode`], breaking a weight tie between a block's full and
/// empty branches with [`get_payload_status_tiebreaker`] rather than weight
/// alone.
///
/// Reuses the pre-gloas, index-only [`get_filtered_block_tree`] for the
/// candidate tree: see [`gloas_get_ancestor`]'s own doc for why that
/// is sound rather than a shortcut.
///
/// **A reference, not the node's head computation.** [`get_head_node`] runs
/// [`walk_head`], which reaches the same node from one bottom-up weight table;
/// this is the spec-literal transcription its tests compare it with.
pub fn gloas_get_head(
    store: &Store,
    config: &Config,
    committees: &CommitteeCache,
) -> Result<ForkChoiceNode> {
    let index = store.block_index();
    let blocks = get_filtered_block_tree(store, &index, config)?;
    let mut head = ForkChoiceNode {
        root: store.beacon_justified_checkpoint().root,
        payload_status: PayloadStatus::Pending,
    };
    loop {
        let children = get_node_children(store, &blocks, head)?;
        if children.is_empty() {
            return Ok(head);
        }

        // Sort by latest attesting balance with ties broken lexicographically
        // by root, then by the payload-status tiebreaker: the same key the
        // specification's own `max` sorts by.
        let mut ranked = Vec::with_capacity(children.len());
        for child in children {
            let weight = gloas_get_weight(store, child, config, committees)?;
            let tiebreak = get_payload_status_tiebreaker(store, child, config)?;
            ranked.push(((weight, child.root, tiebreak), child));
        }
        head = ranked
            .into_iter()
            .max_by_key(|(key, _)| *key)
            .expect("children is non-empty, checked above")
            .1;
    }
}

/// `get_payload_attestation_due_ms` (gloas `fork-choice.md`): how far into a
/// slot, in milliseconds, the payload timeliness committee's votes are due.
pub fn get_payload_attestation_due_ms(config: &Config) -> u64 {
    get_slot_component_duration_ms(config.payload_attestation_due_bps, config)
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
/// find it. Not one of the handlers at the bottom of this file: there is
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
        DataAvailability::NotRequired => (&[][..], &[][..]),
        DataAvailability::Columns(_) => {
            return Err(Error::SpecAssert(
                "a deneb or electra block's data availability is judged on blobs",
            ));
        }
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
    verify_column_cells(
        sidecar.index,
        &sidecar.column,
        &sidecar.kzg_commitments,
        &sidecar.kzg_proofs,
    )
}

/// The batch check both forks' `verify_data_column_sidecar_kzg_proofs` run.
///
/// The one thing that differs between them is where `commitments` comes from:
/// fulu's sidecar carries them, and gloas's takes them from the bid of the
/// block it names. The cell check itself is the same, so it takes the four
/// slices and nothing about either container.
fn verify_column_cells(
    index: u64,
    column: &[fulu::Cell],
    commitments: &[KzgCommitment],
    proofs: &[KzgProof],
) -> Result<bool> {
    let cell_indices = vec![index; column.len()];
    let mut cells = Vec::with_capacity(column.len());
    for cell in column {
        cells.push(
            c_kzg::Cell::from_bytes(&cell[..])
                .map_err(|_| Error::SpecAssert("len(cell) == BYTES_PER_CELL"))?,
        );
    }
    kzg::verify_cell_kzg_proof_batch(commitments, &cell_indices, &cells, proofs)
}

/// `verify_data_column_sidecar` (gloas `p2p-interface.md`, modified): the
/// structural checks a gloas column sidecar must pass before its KZG proofs
/// are worth checking, against `kzg_commitments` from the bid of the block the
/// sidecar names.
///
/// Fulu's version reads the commitments off the sidecar and bounds their count
/// by the blob schedule. Gloas's does neither: the commitments are the
/// caller's, so the length checks compare the column against them directly.
pub fn gloas_verify_data_column_sidecar(
    sidecar: &gloas::DataColumnSidecar,
    kzg_commitments: &[KzgCommitment],
) -> bool {
    // The sidecar index must be within the valid range.
    if sidecar.index as usize >= preset::NUMBER_OF_COLUMNS {
        return false;
    }
    // A sidecar for zero blobs is invalid.
    if sidecar.column.is_empty() {
        return false;
    }
    // The column length must be equal to the number of commitments and proofs.
    sidecar.column.len() == kzg_commitments.len()
        && sidecar.column.len() == sidecar.kzg_proofs.len()
}

/// `verify_data_column_sidecar_kzg_proofs` (gloas `p2p-interface.md`,
/// modified): [`verify_data_column_sidecar_kzg_proofs`] with `kzg_commitments`
/// supplied by the caller rather than carried by the sidecar.
pub fn gloas_verify_data_column_sidecar_kzg_proofs(
    sidecar: &gloas::DataColumnSidecar,
    kzg_commitments: &[KzgCommitment],
) -> Result<bool> {
    verify_column_cells(
        sidecar.index,
        &sidecar.column,
        kzg_commitments,
        &sidecar.kzg_proofs,
    )
}

/// Where `blob_kzg_commitments` sits among `BeaconBlockBody`'s fields, as an
/// index into the leaves of the body's merkle tree.
///
/// Fulu's body's field count rounds up to two to the
/// `KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH`th power leaves, and this is a
/// position within them rather than a generalized index; the fixture suite
/// states the generalized index, which is this plus the leaf offset. Nothing
/// derives it from the container, because nothing here can: SSZ field order is
/// declaration order, and a field added to the body would move this silently.
/// `the_commitments_subtree_index_is_the_bodys_own_position` only pins this
/// constant against the fixture's stated generalized index, so it is a typo
/// guard, not a schema-change guard: it never touches `BeaconBlockBody`. What
/// actually catches a field shifting this position is the `merkle_proof`
/// fixtures' end-to-end check, which decodes a real `BeaconBlockBody`,
/// recomputes its `hash_tree_root()`, and drives it through
/// `verify_data_column_sidecar_inclusion_proof`.
pub const BLOB_KZG_COMMITMENTS_SUBTREE_INDEX: u64 = 11;

/// The specification's `verify_data_column_sidecar_inclusion_proof`
/// (`specs/fulu/p2p-interface.md`): the commitments a sidecar carries are the
/// ones the block it names actually committed to.
///
/// The third of the sidecar checks, and the one that ties a sidecar to a
/// block. Without it a peer could pair a valid column with any block header it
/// liked, and the KZG check would still pass, since that only compares cells
/// against the commitments in the same sidecar.
///
/// Every sidecar of one block proves the same list against the same body root,
/// so a caller checking many sidecars of one block may cache the result on
/// `(kzg_commitments, kzg_commitments_inclusion_proof, signed_block_header)`;
/// the specification says as much. Nothing caches it yet.
pub fn verify_data_column_sidecar_inclusion_proof(sidecar: &fulu::DataColumnSidecar) -> bool {
    is_valid_merkle_branch(
        sidecar.kzg_commitments.hash_tree_root(),
        &sidecar.kzg_commitments_inclusion_proof,
        preset::KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH as u64,
        BLOB_KZG_COMMITMENTS_SUBTREE_INDEX,
        sidecar.signed_block_header.message.body_root,
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
    let sidecars = match evidence {
        DataAvailability::Columns(sidecars) => sidecars,
        DataAvailability::NotRequired => return Ok(true),
        DataAvailability::Blobs { .. } => {
            return Err(Error::SpecAssert(
                "a fulu block's data availability is judged on column sidecars",
            ));
        }
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

/// `is_data_available` (gloas `fork-choice.md`, modified): every column
/// sidecar sampled for the payload must be individually valid against
/// `kzg_commitments`, the commitments on the bid of the block the payload
/// belongs to.
///
/// `sidecars` and `kzg_commitments` are the two values the specification's
/// `retrieve_column_sidecars_and_kzg_commitments` returns. The caller reads
/// the commitments off the stored block instead, since the store already holds
/// that bid. An empty `sidecars` is that retrieval returning none, and
/// `all()` over an empty list holds, so a live caller must not pass an empty
/// slice for a payload it has not sampled. That is the only encoding of "no
/// sidecars": gloas evidence has no variant of [`DataAvailability`], so
/// neither an older fork's check nor this one can read the other's evidence.
pub fn is_data_available_gloas_columns(
    sidecars: &[gloas::DataColumnSidecar],
    kzg_commitments: &[KzgCommitment],
) -> Result<bool> {
    for sidecar in sidecars {
        if !(gloas_verify_data_column_sidecar(sidecar, kzg_commitments)
            && gloas_verify_data_column_sidecar_kzg_proofs(sidecar, kzg_commitments)?)
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
// on_block helpers
// ---------------------------------------------------------------------------

/// `record_block_timeliness`'s verdict for a block at `block_slot`: whether it
/// arrived before each of its slot's two deadlines,
/// `[ATTESTATION_TIMELINESS_INDEX, PTC_TIMELINESS_INDEX]`, which is the value
/// [`on_block`] then stores as
/// [`Store::block_timeliness`](ethlambda_storage::Store::block_timeliness) for
/// [`update_proposer_boost_root`] and [`is_head_late`] to read back.
///
/// Split from the write so [`on_block`] can gate the (otherwise unconditional)
/// proposer-boost head computation on the same answer *before* the block joins
/// the store, and take the slot from the block it already holds rather than
/// decoding it back out of the store (`Store::block_entry` decodes the whole
/// signed block on a beacon directory).
///
/// Before gloas there is one deadline, the attestation one, so both entries
/// repeat its verdict: nothing before gloas tells a PTC deadline apart, and
/// [`is_head_late`] only reads the attestation entry. Gloas modifies the
/// function: a block is timely for a deadline only if it arrived in its own
/// slot and before that deadline, and the two deadlines are gloas's own
/// attestation deadline ([`get_attestation_due_ms`]) and the payload
/// timeliness committee's ([`get_payload_attestation_due_ms`]).
///
/// The attestation deadline is chosen by the clock's epoch and the PTC entry
/// by the block's own `rules`; they can disagree only when the block is not
/// from the current slot, where every entry is `false` either way.
fn block_timeliness(
    store: &Store,
    block_slot: Slot,
    rules: ForkRules,
    config: &Config,
) -> [bool; 2] {
    let time_into_slot_ms = store.ms_since_genesis() % config.slot_duration_ms;
    let is_current_slot = get_current_slot(store, config) == block_slot;
    let epoch = get_current_store_epoch(store, config);
    let attestation_threshold_ms = get_attestation_due_ms(epoch, config);
    match rules {
        ForkRules::PreGloas => {
            let is_timely = is_current_slot && time_into_slot_ms < attestation_threshold_ms;
            [is_timely, is_timely]
        }
        ForkRules::Gloas => {
            let ptc_threshold_ms = get_payload_attestation_due_ms(config);
            [
                is_current_slot && time_into_slot_ms < attestation_threshold_ms,
                is_current_slot && time_into_slot_ms < ptc_threshold_ms,
            ]
        }
    }
}

/// The first slot of the lookahead window `epoch`'s proposer shuffling opens
/// in: `MIN_SEED_LOOKAHEAD` epochs before `epoch` itself starts.
pub fn compute_shuffling_lookahead_start_slot(epoch: Epoch) -> Slot {
    let lookahead_epoch = epoch.saturating_sub(preset::MIN_SEED_LOOKAHEAD);
    compute_start_slot_at_epoch(lookahead_epoch)
}

/// The last slot before `epoch`'s proposer shuffling could still change: one
/// before [`compute_shuffling_lookahead_start_slot`].
pub fn compute_shuffling_dependent_slot(epoch: Epoch) -> Slot {
    compute_shuffling_lookahead_start_slot(epoch).saturating_sub(1)
}

/// Like [`get_ancestor`], but stops at the lowest indexed ancestor on
/// `root`'s chain instead of failing when the walk would need to step past
/// it.
///
/// The specification's own `get_ancestor` never needs this: a full node's
/// earliest block is genesis, at slot 0, so a walk toward any real target
/// slot always terminates there. A checkpoint-synced node's anchor is not
/// slot 0, and its `parent_root` is a real historical root this store never
/// held, so [`get_ancestor`] would raise `SpecAssert("root in store.blocks")`
/// stepping past it. [`get_shuffling_dependent_root`] is the one caller that
/// can ask for a slot below the anchor (shortly after sync, the dependent
/// slot for the current epoch can still be that low), so it uses this
/// instead: the lowest indexed ancestor is the anchor itself for every chain
/// this store holds, since everything in it descends from that one root, so
/// two different chains asking this the same question both land on it and
/// answer the same way `get_ancestor` would once genesis, rather than the
/// anchor, is the floor.
fn get_ancestor_or_lowest_indexed(
    index: &HashMap<Root, (Slot, Root)>,
    root: Root,
    slot: Slot,
) -> Root {
    let mut current = root;
    loop {
        let Some(&(block_slot, parent_root)) = index.get(&current) else {
            // `current` is not itself indexed. Every caller starts this walk
            // from an indexed root, so this only happens after stepping to a
            // `parent_root` the loop below already checked is indexed, which
            // makes this branch unreachable; kept as a safe fallback rather
            // than an `expect`, since returning wherever the walk got to is
            // still a sound answer even if that invariant ever slipped.
            return current;
        };
        if block_slot <= slot || !index.contains_key(&parent_root) {
            return current;
        }
        current = parent_root;
    }
}

/// The block that fixed `epoch`'s proposer shuffling on `root`'s chain: the
/// ancestor of `root` at [`compute_shuffling_dependent_slot`], or the lowest
/// indexed ancestor on `root`'s chain if that slot is not covered; see
/// [`get_ancestor_or_lowest_indexed`] for why the second case is sound.
///
/// Serves gloas unchanged. Gloas's `get_shuffling_dependent_root` walks from a
/// `PENDING` node with its payload-aware `get_ancestor` and returns the root of
/// the node it lands on; that walk picks each step by `block.slot` alone (see
/// [`gloas_get_ancestor`]), so the root is the one this index walk
/// answers, and the payload status the gloas walk threads through is
/// discarded.
pub fn get_shuffling_dependent_root(
    index: &HashMap<Root, (Slot, Root)>,
    root: Root,
    epoch: Epoch,
) -> Root {
    get_ancestor_or_lowest_indexed(index, root, compute_shuffling_dependent_slot(epoch))
}

/// Boosts `root`'s weight, if it is the first block seen for its slot, arrived
/// on time, and shares `head`'s proposer shuffling.
///
/// The shuffling check is what `v1.7.0` added over the boost's original rule
/// (timely and first, full stop): a block whose proposer shuffling has already
/// diverged from the chain fork choice currently follows is not boosted, so
/// the boost cannot itself be the thing that drags the head onto a branch with
/// a different, no-longer-relevant view of who was supposed to propose it.
///
/// `head` must be the head [`walk_head`] found *before* `root` joined the
/// store: [`on_block`] is this
/// function's only caller, and it passes exactly that. `index` should include
/// `root`'s own entry (`on_block` extends its own pre-insertion index with it
/// rather than re-scanning `LiveChain`), or the walk below falls back to
/// whatever the closest indexed ancestor answers, per
/// [`get_ancestor_or_lowest_indexed`].
///
/// `pub(crate)`, not `pub`: this one's `index` parameter is this crate's own
/// adaptation, not a transcription, and [`on_block`] is its only caller.
pub(crate) fn update_proposer_boost_root(
    store: &mut Store,
    index: &HashMap<Root, (Slot, Root)>,
    head: Root,
    root: Root,
    config: &Config,
) {
    let is_first_block = store.proposer_boost_root().is_zero();
    let is_timely = store
        .block_timeliness(&root)
        .expect("on_block records the block's timeliness before this runs, on the same root")
        [constants::ATTESTATION_TIMELINESS_INDEX];
    let epoch = get_current_store_epoch(store, config);
    let head_dependent_root = get_shuffling_dependent_root(index, head, epoch);
    let block_dependent_root = get_shuffling_dependent_root(index, root, epoch);
    let is_same_dependent_root = head_dependent_root == block_dependent_root;

    if is_timely && is_first_block && is_same_dependent_root {
        store.set_proposer_boost_root(root);
    }
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
/// [`Attestation`]'s shapes the caller actually has. See the module
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
///
/// `rules` selects gloas's `data.index` rules where the attestation is a gloas
/// one; see [`ForkRules`].
pub fn validate_on_attestation(
    store: &Store,
    data: AttestationData,
    rules: ForkRules,
    is_from_block: bool,
    config: &Config,
) -> Result<()> {
    validate_on_attestation_indexed(
        store,
        data,
        rules,
        is_from_block,
        config,
        &store.block_index(),
    )
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
    rules: ForkRules,
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

    // [New in Gloas:EIP7732] `index` is the payload flag, not a committee index.
    if rules == ForkRules::Gloas {
        verify(data.index <= 1, "attestation.data.index in [0, 1]")?;
        if head_block_slot == data.slot {
            verify(
                data.index == 0,
                "attestation.data.index == 0 for a same-slot vote",
            )?;
        }
        // If attesting for a full node, the payload must be known.
        if data.index == 1 {
            verify(
                is_payload_verified(store, data.beacon_block_root),
                "is_payload_verified(store, attestation.data.beacon_block_root)",
            )?;
        }
    }

    // LMD vote must be consistent with FFG vote target. Gloas's own
    // `get_checkpoint_block` answers the same root through a payload-aware walk
    // (see [`gloas_get_ancestor`]), so the index-only walk serves both
    // forks and spares a gloas attestation one block decode per hop.
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
/// Before gloas, an attester's latest message only ever moves to a later
/// target epoch: an attestation for an epoch already superseded by that
/// attester's own later vote is simply not the freshest thing known about
/// them anymore. Gloas orders by the attestation's slot instead, and records
/// whether the vote is for the block's full payload (`data.index == 1`); see
/// [`ForkRules`].
///
/// Takes `attesting_indices` and `data` rather than an [`Attestation`]: by
/// the time [`on_attestation`] calls this, [`Attestation::verified_attesting_indices`]
/// has already resolved the one fork-specific fact this needed out of it.
pub fn update_latest_messages(
    store: &mut Store,
    attesting_indices: &[ValidatorIndex],
    data: AttestationData,
    rules: ForkRules,
) {
    let target = data.target;
    let beacon_block_root = data.beacon_block_root;
    let payload_present = rules == ForkRules::Gloas && data.index == 1;

    for &index in attesting_indices {
        if store.is_equivocating(index) {
            continue;
        }
        let should_update = match (store.latest_message(index), rules) {
            (None, _) => true,
            (Some(existing), ForkRules::PreGloas) => target.epoch > existing.epoch,
            (Some(existing), ForkRules::Gloas) => data.slot > existing.slot,
        };
        if should_update {
            store.set_latest_message(
                index,
                LatestMessage {
                    epoch: target.epoch,
                    slot: data.slot,
                    root: beacon_block_root,
                    payload_present,
                },
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------
//
// These six are the only functions in this file the specification itself
// lists as the sole ways to change `store`; each validates before it mutates
// anything, so a rejected call leaves `store` exactly as it found it, matching
// its requirement that "invalid calls to handlers must not modify store".
// Two non-handlers also take `&mut Store`. [`get_head`], above, records the
// head it just computed, which is not a validity-gated mutation a rejected
// call would need rolled back, just a derived value kept in sync with every
// call. [`notify_ptc_messages`] applies a block's payload attestations through
// the same checks as [`on_payload_attestation_message`]; a failure partway
// leaves the votes of the messages before it, which no valid block can cause.

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
///
/// `payload_validity` is this module's second such addition: what an execution
/// client said about this block's payload, or [`PayloadValidity::NotRequired`]
/// when there was nothing to ask. See its own documentation, and the module
/// documentation's "`on_block`'s execution engine", for how it reaches
/// [`stf::state_transition`] and what it records.
pub fn on_block(
    store: &mut Store,
    signed_block: SignedBeaconBlock,
    config: &Config,
    blob_evidence: &DataAvailability,
    payload_validity: &PayloadValidity,
    committees: &CommitteeCache,
) -> Result<()> {
    let block_root = signed_block.message_hash_tree_root();
    let parent_root = signed_block.parent_root();

    // Return early if the block already has a post-state: a re-delivery must
    // not re-run `set_block_timeliness`/`update_proposer_boost_root` below
    // on a block already fully imported. The chain actor's own import cascade
    // already deduplicates a known root before ever reaching here
    // (`Store::has_state`, which also skips re-running `state_transition`;
    // see its own call site's documentation for the cost of not having that
    // check), so in practice this rarely fires from that path; it is the
    // specification's own guard, for every caller, mapped onto what
    // `store.blocks` membership means here.
    //
    // `Store::has_state`, not `Store::has_block`: the specification's
    // `store.blocks` only gains a root at the very end of `on_block`, once a
    // post-state has been computed for it, so membership there is really "has
    // been imported". This store's own `blocks` table does not line up with
    // that: a block the actor is holding for missing data columns is
    // persisted *before* import (`holding_a_block_persists_it_and_records_its_root`),
    // so `has_block` answers true for a root that has never actually run
    // `state_transition`. Guarding on it instead of `has_state` made this
    // function answer `Ok(())` for a held block without importing it, which
    // starved every later delivery naming it as an ancestor: none of them
    // could see a post-state either, so each walked back to this root, found
    // it "already known", and gave up without importing anything, forever.
    if store.has_state(&block_root).expect("get") {
        return Ok(());
    }

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

    // [New in Gloas:EIP7732] If this block builds on its parent's full payload,
    // that payload must have been verified by `on_execution_payload_envelope`.
    // A pre-gloas parent is a full node whose payload is verified by
    // definition (see `is_payload_verified`), so the first gloas block passes.
    //
    // The parent status is also what the head computation needs to place this
    // block in the payload tree, so it is kept as this block's payload link
    // (recorded once the block is stored, below) rather than decoded again on
    // every head computation.
    let rules = ForkRules::of(signed_block.fork_name());
    let parent_status = match rules {
        ForkRules::Gloas => {
            let parent_status = get_parent_payload_status(store, &signed_block)?;
            if parent_status == PayloadStatus::Full {
                verify(
                    is_payload_verified(store, parent_root),
                    "is_payload_verified(store, block.parent_root)",
                )?;
            }
            Some(parent_status)
        }
        ForkRules::PreGloas => None,
    };
    let payload_link = rules.payload_link(parent_status);

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
    //
    // `mut`, and kept alive for the rest of this function: the pre-import
    // head computation and the proposer-boost shuffling check further down
    // both want this same pre-insertion snapshot of `LiveChain` (`walk_head`
    // takes it as a parameter, matching `get_filtered_block_tree`), so it is
    // built once here rather than three times over. Once `block_root` itself
    // joins the store below, one `insert` keeps this index in step with it
    // instead of re-scanning for that alone.
    let mut index = store.block_index();
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
    //
    // The same match hands back the block's payload attestations, which only a
    // gloas body carries, so the one place that names every fork also decides
    // whether there is anything to notify the store about below.
    let payload_attestations: Option<&[gloas::PayloadAttestation]> = match &signed_block {
        SignedBeaconBlock::Deneb(block) => {
            verify(
                is_data_available_blobs(&block.message.body.blob_kzg_commitments, blob_evidence)?,
                "is_data_available(hash_tree_root(block), block.body.blob_kzg_commitments)",
            )?;
            None
        }
        SignedBeaconBlock::Electra(block) => {
            verify(
                is_data_available_blobs(&block.message.body.blob_kzg_commitments, blob_evidence)?,
                "is_data_available(hash_tree_root(block), block.body.blob_kzg_commitments)",
            )?;
            None
        }
        SignedBeaconBlock::Fulu(_) => {
            verify(
                is_data_available_columns(blob_evidence, config)?,
                "is_data_available(hash_tree_root(block))",
            )?;
            None
        }
        SignedBeaconBlock::Phase0(_)
        | SignedBeaconBlock::Altair(_)
        | SignedBeaconBlock::Bellatrix(_)
        | SignedBeaconBlock::Capella(_) => None,
        // [Modified in Gloas:EIP7732] The block itself is not gated on data
        // availability: the blob data arrives with the payload, so the check
        // moves to `on_execution_payload_envelope`, which is where a gloas
        // payload becomes usable. A block whose data never arrives is still
        // imported, and its full payload branch stays unreachable, since
        // building on it requires `is_payload_verified` above.
        SignedBeaconBlock::Gloas(block) => Some(&block.message.body.payload_attestations),
        SignedBeaconBlock::Lean(_) => lean_block_unreachable("fork_choice::on_block"),
    };

    // Check the block is valid and compute the post-state. The engine's answer
    // is read the way the specification reads it: an `INVALIDATED` verdict makes
    // `verify_and_notify_new_payload` return false, and everything else makes it
    // return true. Running the transition even when the verdict is already
    // `Invalidated` is deliberate. It costs a merkleization on a path that
    // should never run, and it buys the failure arriving from inside
    // `process_execution_payload`, which is where the specification puts it and
    // where a reviewer checks this code against it.
    let engine = match payload_validity {
        PayloadValidity::Invalidated { .. } => stf::ExecutionEngine::invalid(),
        PayloadValidity::NotRequired | PayloadValidity::Validated | PayloadValidity::Optimistic => {
            stf::ExecutionEngine::valid()
        }
    };
    let transition =
        stf::state_transition(&mut state, &signed_block, true, config, &engine, committees);

    // `optimistic-sync.md`: a block deemed `INVALIDATED` MUST NOT be included
    // in the canonical chain. That is stated here, on the verdict, rather than
    // left to `transition` having failed, because the transition only fails for
    // forks whose `process_execution_payload` consults the `ExecutionEngine` at
    // all: bellatrix gates that step on `is_execution_enabled`, and phase0 and
    // altair have no such step. A condemned block on one of those would
    // otherwise transition cleanly and be imported with nothing recorded.
    //
    // The transition still runs above, and its own error is still what this
    // returns when there is one. That is what keeps the failure arriving from
    // inside `process_execution_payload`, where the specification puts it and
    // where a reviewer checks this code against it, and what keeps the
    // `sync/optimistic` fixture exercising that path rather than this guard.
    //
    // The invalidation must land even though the import fails. The
    // `sync/optimistic` fixture's last step carries `valid: false` for the
    // rejected block while still requiring its whole branch to disappear, so it
    // cannot be deferred to a success path that never runs.
    if let PayloadValidity::Invalidated { latest_valid_hash } = payload_validity {
        let index = store.block_index();
        // `block_root` is not in `index`: this block never imported, which is
        // why `resolve_invalid_block` takes `parent_root` separately and starts
        // the walk there. The `None` and unfindable cases answer `block_root`,
        // and invalidating an unindexed root removes nothing, which is exactly
        // "only the block in question dies" for a block that never joined the
        // tree.
        let condemned =
            resolve_invalid_block(store, &index, block_root, parent_root, *latest_valid_hash);
        let removed = invalidate_subtree(store, condemned);
        warn!(
            block_root = %ShortRoot(&block_root.0),
            condemned = %ShortRoot(&condemned.0),
            removed,
            "Execution layer rejected a payload; invalidated its branch"
        );
        return Err(transition.err().unwrap_or(Error::SpecAssert(
            "the execution layer rejected this block's payload",
        )));
    }

    transition?;

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

    // [New in v1.7.0] Whether this block can even be a candidate for the
    // proposer boost, decided *before* it joins the store and before the one
    // fallible step below runs, so that a failure here leaves the store
    // exactly as it was. `update_proposer_boost_root`'s own gate is
    // `is_timely and is_first_block and <same shuffling as the pre-import
    // head>`; the first two conditions are cheap and already decide most
    // blocks, especially every block a follower receives while syncing, which
    // is never timely. Computing that head (`walk_head`: a filtered-tree walk
    // and a pass over every latest message and every block; see
    // `compute_weights` for why the votes matter at scale) is not
    // worth paying for on a block the shuffling check could not change the
    // answer for anyway.
    //
    // Gloas gates on its own attestation deadline. The head is computed by the
    // one walk under the block's own rules; when it is computed, its failing
    // fails the import. The head is only computed for a block that is timely,
    // which puts it in the current slot, so `get_head_node`'s choice of rules
    // by the current slot's fork would be the same here; calling the walk
    // directly reuses `committees` and `index` instead of building them.
    let block_slot = signed_block.slot();
    let timeliness = block_timeliness(store, block_slot, rules, config);
    let is_timely = timeliness[constants::ATTESTATION_TIMELINESS_INDEX];
    let is_first_block = store.proposer_boost_root().is_zero();
    let pre_block_head = if is_timely && is_first_block {
        Some(walk_head(store, &index, config, committees, rules)?.root)
    } else {
        None
    };

    // [New in Gloas:EIP7732] Notify the store about the payload attestations
    // the block carries. Runs before the block joins the store, unlike the
    // specification, so a failure leaves no block behind. The votes it writes
    // are for the parent (`process_payload_attestation` pins
    // `data.beacon_block_root` to `parent_root`), so nothing here reads the
    // block being imported. No failure is expected after a valid transition:
    // `process_payload_attestation` already ran the same `get_ptc` and
    // membership checks, and the parent's vote vectors always exist. Were one
    // to fail midway anyway, the parent would keep the votes of the messages
    // before it.
    if let Some(payload_attestations) = payload_attestations {
        notify_ptc_messages(store, &state, payload_attestations, config)?;
    }

    // Add new block to the store, and the new state for this block to the
    // store.
    let signed_block_el_hash = signed_block.execution_block_hash();
    store
        .insert_signed_block(block_root, signed_block)
        .expect("insert");
    store.insert_state(block_root, state).expect("insert");
    store.set_payload_link(block_root, block_slot, payload_link);
    // [New in Gloas:EIP7732] A new payload timeliness committee vote for this
    // block, for each of the two questions it votes on.
    match rules {
        ForkRules::Gloas => {
            store.set_payload_timeliness_vote(block_root, vec![None; preset::PTC_SIZE]);
            store.set_payload_data_availability_vote(block_root, vec![None; preset::PTC_SIZE]);
        }
        ForkRules::PreGloas => {}
    }
    // Keep `index` in step with the one block that changed, rather than
    // re-scanning `LiveChain` for it: see this function's earlier comment on
    // `index` for who below still needs it.
    index.insert(block_root, (block_slot, parent_root));

    // Cache this block's own execution hash for `forkchoiceUpdated` and for the
    // `latestValidHash` walk, and record whether the execution layer has
    // actually vouched for it yet.
    //
    // A zero hash is not cached, because the presence of an entry is what
    // [`is_optimistic_candidate_block`] reads as the specification's
    // `is_execution_block`, and that predicate is "the payload is not the
    // fork's own empty one", not "the container has a payload field". A
    // pre-merge bellatrix block carries a payload field whose every byte is
    // zero (see `stf::bellatrix::default_execution_payload`), and caching that
    // would make its children look like descendants of a merge block and skip
    // the age horizon that exists precisely to guard the merge transition.
    // Testing the block hash alone is enough: it is a keccak digest in a real
    // payload and zero in the empty one.
    if let Some(el_block_hash) = signed_block_el_hash
        && !el_block_hash.is_zero()
    {
        store.insert_beacon_el_block_hash(block_root, block_slot, el_block_hash);
    }
    match payload_validity {
        PayloadValidity::Optimistic => {
            store.insert_beacon_optimistic_root(block_root, block_slot);
        }
        PayloadValidity::Validated => mark_validated(store, block_root),
        PayloadValidity::NotRequired | PayloadValidity::Invalidated { .. } => {}
    }

    // Add block timeliness to the store, and boost its score if it is timely,
    // first, and shares the pre-import head's proposer shuffling. Both calls
    // are infallible: nothing from here to the end of this function can turn
    // into an `Err`, and the store has already been mutated above.
    match rules {
        ForkRules::Gloas => store.set_gloas_block_timeliness(block_root, timeliness),
        ForkRules::PreGloas => store.set_block_timeliness(block_root, timeliness),
    }
    if let Some(pre_block_head) = pre_block_head {
        update_proposer_boost_root(store, &index, pre_block_head, block_root, config);
    }

    // Update checkpoints in store if necessary.
    update_checkpoints(store, current_justified, finalized);

    // Eagerly compute unrealized justification and finality.
    compute_pulled_up_tip(store, block_root, block_slot, config)?;

    Ok(())
}

/// `notify_ptc_messages` (gloas `fork-choice.md`): feeds the payload
/// attestations a block carries to [`on_payload_attestation_message`], one
/// message per attester, so the store's votes reflect them.
///
/// `state` is the block's own post-state, which names the attesters through
/// `get_indexed_payload_attestation`, and the attestations are taken as
/// already verified by `process_block`, which is why each message is applied
/// with `is_from_block` set and a default signature. Each message is judged
/// against the state of the block its attestation names (the specification's
/// `store.block_states[data.beacon_block_root]`), read once per payload
/// attestation rather than once per attester. A genesis-slot state has no
/// payload attestation to read.
pub fn notify_ptc_messages(
    store: &mut Store,
    state: &BeaconState,
    payload_attestations: &[gloas::PayloadAttestation],
    config: &Config,
) -> Result<()> {
    if state.slot() == 0 {
        return Ok(());
    }
    for payload_attestation in payload_attestations {
        let indexed =
            gloas_helpers::get_indexed_payload_attestation(state, payload_attestation, config)?;
        if indexed.attesting_indices.is_empty() {
            continue;
        }
        let attested_state = store
            .get_state(&payload_attestation.data.beacon_block_root)
            .expect("get")
            .ok_or(Error::SpecAssert(
                "data.beacon_block_root in store.block_states",
            ))?;
        for &validator_index in indexed.attesting_indices.iter() {
            let message = gloas::PayloadAttestationMessage {
                validator_index,
                data: payload_attestation.data,
                signature: Default::default(),
            };
            apply_payload_attestation_message(
                store,
                &attested_state,
                &message,
                PtcMessageSource::Block,
                config,
            )?;
        }
    }
    Ok(())
}

/// `on_payload_attestation_message` (gloas `fork-choice.md`): records a
/// payload timeliness committee member's vote on whether a block's payload was
/// revealed on time and its blob data is available.
///
/// `is_from_block` marks a vote carried inside a block, which
/// [`notify_ptc_messages`] has already had verified; a vote received directly
/// must be for the current slot and carry a valid signature.
///
/// A member can hold more than one seat in the committee (it is drawn with
/// replacement), and the vote lands in every one of them. Every check runs
/// before either vote vector is written, so a rejected message changes
/// nothing.
pub fn on_payload_attestation_message(
    store: &mut Store,
    ptc_message: &gloas::PayloadAttestationMessage,
    is_from_block: bool,
    config: &Config,
) -> Result<()> {
    // PTC attestation must be for a known block. If block is unknown, delay
    // consideration until the block is found.
    let state = store
        .get_state(&ptc_message.data.beacon_block_root)
        .expect("get")
        .ok_or(Error::SpecAssert(
            "data.beacon_block_root in store.block_states",
        ))?;
    let source = if is_from_block {
        PtcMessageSource::Block
    } else {
        PtcMessageSource::Wire
    };
    apply_payload_attestation_message(store, &state, ptc_message, source, config)
}

/// [`on_payload_attestation_message`] for a message that
/// `ethlambda-p2p`'s `payload_attestation_message` gossip validation already
/// accepted: the same store-state checks (the block's state is known, the
/// vote is for the current slot, the validator holds a seat in the block's
/// committee, which also locates the seats to write), without the signature
/// check and the indexed-attestation validation behind it, which cost a BLS
/// verification per vote on the chain actor.
///
/// Only a gossip-verified message may call this. A message from anywhere else
/// (a block's payload attestations go through [`notify_ptc_messages`], which
/// has its own verified path) would be applied unauthenticated.
pub fn apply_verified_payload_attestation(
    store: &mut Store,
    ptc_message: &gloas::PayloadAttestationMessage,
    config: &Config,
) -> Result<()> {
    let state = store
        .get_state(&ptc_message.data.beacon_block_root)
        .expect("get")
        .ok_or(Error::SpecAssert(
            "data.beacon_block_root in store.block_states",
        ))?;
    apply_payload_attestation_message(
        store,
        &state,
        ptc_message,
        PtcMessageSource::VerifiedWire,
        config,
    )
}

/// Where a payload attestation message came from, which decides what
/// [`apply_payload_attestation_message`] still has to check.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PtcMessageSource {
    /// Inside a block, already verified with it: no slot or signature check.
    Block,
    /// Straight off the wire: current slot, then the signature.
    Wire,
    /// Off the wire and already signature-verified by gossip validation:
    /// current slot only.
    VerifiedWire,
}

/// The body of [`on_payload_attestation_message`] after its state read, given
/// `state`, the state of the block `ptc_message` names, so
/// [`notify_ptc_messages`] can read that state once for every attester of a
/// payload attestation.
fn apply_payload_attestation_message(
    store: &mut Store,
    state: &BeaconState,
    ptc_message: &gloas::PayloadAttestationMessage,
    source: PtcMessageSource,
    config: &Config,
) -> Result<()> {
    let data = ptc_message.data;

    // PTC votes can only change the vote for their assigned beacon block,
    // return early otherwise.
    if data.slot != state.slot() {
        return Ok(());
    }

    // Get all positions of the attester in the PTC.
    let ptc = gloas_helpers::get_ptc(state, data.slot, config)?;
    let ptc_indices: Vec<usize> = ptc
        .iter()
        .enumerate()
        .filter(|&(_, &validator_index)| validator_index == ptc_message.validator_index)
        .map(|(ptc_index, _)| ptc_index)
        .collect();

    // Check that the attester is from the PTC.
    verify(!ptc_indices.is_empty(), "len(ptc_indices) > 0")?;

    // Verify the signature and check that it is for the current slot if it is
    // coming from the wire.
    if source != PtcMessageSource::Block {
        verify(
            data.slot == get_current_slot(store, config),
            "data.slot == get_current_slot(store)",
        )?;
    }
    if source == PtcMessageSource::Wire {
        let indexed = gloas::IndexedPayloadAttestation {
            attesting_indices: gloas::PayloadTimelinessCommitteeIndices::try_from(vec![
                ptc_message.validator_index,
            ])?,
            data,
            signature: ptc_message.signature,
        };
        verify(
            gloas_helpers::is_valid_indexed_payload_attestation(state, &indexed),
            "is_valid_indexed_payload_attestation(state, indexed_payload_attestation)",
        )?;
    }

    // Update the votes for the block.
    let mut payload_timeliness_vote = store
        .payload_timeliness_vote(&data.beacon_block_root)
        .ok_or(Error::SpecAssert(
            "data.beacon_block_root in store.payload_timeliness_vote",
        ))?;
    let mut payload_data_availability_vote = store
        .payload_data_availability_vote(&data.beacon_block_root)
        .ok_or(Error::SpecAssert(
            "data.beacon_block_root in store.payload_data_availability_vote",
        ))?;
    for ptc_index in ptc_indices {
        let len = payload_timeliness_vote.len();
        *payload_timeliness_vote
            .get_mut(ptc_index)
            .ok_or(Error::IndexOutOfBounds {
                index: ptc_index,
                len,
            })? = Some(data.payload_present);
        let len = payload_data_availability_vote.len();
        *payload_data_availability_vote
            .get_mut(ptc_index)
            .ok_or(Error::IndexOutOfBounds {
                index: ptc_index,
                len,
            })? = Some(data.blob_data_available);
    }
    store.set_payload_timeliness_vote(data.beacon_block_root, payload_timeliness_vote);
    store
        .set_payload_data_availability_vote(data.beacon_block_root, payload_data_availability_vote);

    Ok(())
}

/// `on_execution_payload_envelope` (gloas `fork-choice.md`): verifies a
/// builder's payload envelope against the block it belongs to and, if it
/// holds, records the payload as verified, which is what lets a block build
/// on its full branch (see [`on_block`]) and a vote name it.
///
/// `sidecars` is what the specification's implementation-dependent
/// `retrieve_column_sidecars_and_kzg_commitments` returns for the block: the
/// sampled column sidecars. The commitments they are checked against are the
/// block's bid's own, read from the store. An empty slice reads as available;
/// see [`is_data_available_gloas_columns`]. `engine` answers the execution
/// layer's part of `verify_execution_payload_envelope`.
///
/// Every check runs before the payload is recorded, so a rejected envelope
/// changes nothing. An envelope delivered again for a payload already
/// verified is checked again and recorded again, which is idempotent.
pub fn on_execution_payload_envelope(
    store: &mut Store,
    signed_envelope: &gloas::SignedExecutionPayloadEnvelope,
    config: &Config,
    sidecars: &[gloas::DataColumnSidecar],
    engine: &stf::ExecutionEngine,
) -> Result<()> {
    check_execution_payload_envelope(store, signed_envelope, config, sidecars, engine)?;
    accept_execution_payload_envelope(store, signed_envelope);
    Ok(())
}

/// Every check of [`on_execution_payload_envelope`], without recording the
/// payload.
///
/// Split out so a caller whose execution engine answers over the network can
/// run the pure consensus checks first, ask the engine only about an envelope
/// that passed them, and record the payload with
/// [`accept_execution_payload_envelope`] once the answer allows it. The
/// `engine` argument still answers the engine's part of
/// `verify_execution_payload_envelope`; such a caller passes
/// [`stf::ExecutionEngine::valid`] and consults the real engine itself.
pub fn check_execution_payload_envelope(
    store: &Store,
    signed_envelope: &gloas::SignedExecutionPayloadEnvelope,
    config: &Config,
    sidecars: &[gloas::DataColumnSidecar],
    engine: &stf::ExecutionEngine,
) -> Result<()> {
    let envelope = &signed_envelope.message;
    let block_root = envelope.beacon_block_root;

    // The corresponding beacon block root needs to be known.
    let state = store
        .get_state(&block_root)
        .expect("get")
        .ok_or(Error::SpecAssert(
            "envelope.beacon_block_root in store.block_states",
        ))?;

    // Check if blob data is available. If not, this payload MAY be queued and
    // subsequently considered when blob data becomes available.
    let block = store
        .get_signed_block(&block_root)
        .expect("get")
        .ok_or(Error::SpecAssert(
            "envelope.beacon_block_root in store.blocks",
        ))?;
    let kzg_commitments = &gloas_bid(&block)?.blob_kzg_commitments;
    verify(
        is_data_available_gloas_columns(sidecars, kzg_commitments)?,
        "is_data_available(envelope.beacon_block_root)",
    )?;

    // Verify the execution payload envelope.
    stf::gloas::verify_execution_payload_envelope(&state, signed_envelope, config, engine)?;

    Ok(())
}

/// The recording half of [`on_execution_payload_envelope`]: adds a checked
/// envelope to the store. Persisted, so a restarted follower keeps the full
/// branch of this block.
///
/// The caller must have run [`check_execution_payload_envelope`] on the same
/// envelope; a block the store does not hold is the only case this refuses.
pub fn accept_execution_payload_envelope(
    store: &mut Store,
    signed_envelope: &gloas::SignedExecutionPayloadEnvelope,
) {
    let block_root = signed_envelope.message.beacon_block_root;
    let Some((slot, _parent)) = store.block_entry(&block_root) else {
        return;
    };
    store.insert_verified_payload(slot, signed_envelope);
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
    committees: &CommitteeCache,
) -> Result<()> {
    let data = attestation.data();
    let rules = attestation.rules();
    validate_on_attestation(store, data, rules, is_from_block, config)?;

    // The state at the `target` to fully validate attestation against.
    // `checkpoint_state` hands back an owned value now, so there is no borrow
    // of `store` left to release before `update_latest_messages` needs it
    // mutably below, unlike when this cached state lived behind a reference
    // into `store` itself.
    let target_state = checkpoint_state(store, &data.target, config)?;
    let attesting_indices = attestation.verified_attesting_indices(&target_state, committees)?;

    // Update latest messages for attesting indices.
    update_latest_messages(store, &attesting_indices, data, rules);

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
    committees: &CommitteeCache,
) -> Result<()> {
    let data = attestation.data();
    let rules = attestation.rules();
    validate_on_attestation_indexed(store, data, rules, true, config, index)?;

    let attesting_indices = attestation.attesting_indices(block_state, committees)?;
    update_latest_messages(store, &attesting_indices, data, rules);

    Ok(())
}

/// Apply an aggregate that reached the chain actor after
/// `ethlambda-p2p`'s beacon gossip validation already accepted it.
///
/// Every condition `beacon_aggregate_and_proof`'s own gossip rules add over a
/// plain attestation, the committee lookups, `is_aggregator`, committee
/// membership, and all three BLS checks, ran once in
/// `ethlambda_state_transition::beacon::gossip::aggregate` before this was
/// called, on the state that attestation's own target checkpoint names. This
/// function must not repeat any of it: doing so would be the reviewed defect
/// this replaced, committees rebuilt and signatures re-verified once per
/// aggregate on the chain actor's single thread.
///
/// What is left is exactly [`on_attestation`]'s own validity check and its
/// bookkeeping, since neither is gossip's to answer: [`validate_on_attestation_indexed`]
/// catches a target this node has since finalized past or a vote whose own
/// slot has not passed yet, both of which can change between p2p's verdict
/// and the chain actor picking the aggregate up, and [`update_latest_messages`]
/// records it against `attesting_indices`, resolved by the caller's gossip
/// validation rather than recomputed here.
///
/// The rules are those of the vote's own fork, read off `data.slot`: under
/// gloas `data.index` is the payload flag that [`update_latest_messages`]
/// records, and the electra-shaped callers that reach here (a gloas aggregate
/// has its own container but yields the same `AttestationData`) do not say
/// which fork they came from.
///
/// `is_from_block` is fixed at `false`, matching [`on_attestation`]'s call for
/// this topic: an aggregate here is by definition not carried in a block, so
/// the current-or-previous-epoch target check applies.
///
/// `index` is [`Store::block_index`], taken as a parameter rather than built
/// here so a caller applying several aggregates at once (the chain actor's
/// deferral queue, drained once per tick) pays for the full `Table::LiveChain`
/// scan once for the whole drain rather than once per aggregate.
pub fn apply_verified_aggregate(
    store: &mut Store,
    data: AttestationData,
    attesting_indices: &[ValidatorIndex],
    config: &Config,
    index: &HashMap<Root, (Slot, Root)>,
) -> Result<()> {
    let rules = ForkRules::of(config.fork_at_epoch(compute_epoch_at_slot(data.slot)));
    validate_on_attestation_indexed(store, data, rules, false, config, index)?;
    update_latest_messages(store, attesting_indices, data, rules);
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
    use crate::beacon::bls;
    use crate::beacon::containers::BeaconBlockHeader;
    use crate::beacon::helpers::accessors;
    use crate::beacon::helpers::misc::compute_signing_root;
    use crate::beacon::helpers::test_state;
    use crate::beacon::primitives::BlsSignature;

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
        store_anchored_at_on(Arc::new(InMemoryBackend::new()), root)
    }

    /// [`store_anchored_at`] over a backend the caller supplies, for tests
    /// that watch what the store reads.
    fn store_anchored_at_on(backend: Arc<dyn StorageBackend>, root: Root) -> Store {
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
            0,
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

    /// [`block`], with an explicit proposer index rather than the default
    /// `0`, for tests that care about which proposer a block names.
    fn block_with_proposer(
        slot: Slot,
        parent_root: Root,
        proposer_index: ValidatorIndex,
    ) -> SignedBeaconBlock {
        let SignedBeaconBlock::Phase0(mut inner) = block(slot, parent_root) else {
            unreachable!("`block` builds a phase0 signed block");
        };
        inner.message.proposer_index = proposer_index;
        SignedBeaconBlock::Phase0(inner)
    }

    /// A gloas signed block with an empty body and a zero signature, and an
    /// explicit bid `parent_block_hash`/`block_hash` pair: the gloas fork
    /// choice tests below name their blocks' payload dimension entirely
    /// through these two fields, per [`get_parent_payload_status`].
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

    /// Marks `root`'s payload verified by storing a default envelope for it.
    /// The block must already be in the store: the envelope's row is keyed by
    /// the block's slot.
    fn verify_payload(store: &mut Store, root: Root) {
        let payload = gloas::ExecutionPayload {
            parent_hash: Default::default(),
            fee_recipient: Default::default(),
            state_root: Default::default(),
            receipts_root: Default::default(),
            logs_bloom: crate::beacon::containers::bellatrix::LogsBloom::try_from(vec![
                0u8;
                preset::BYTES_PER_LOGS_BLOOM
            ])
            .expect("built at exactly BYTES_PER_LOGS_BLOOM"),
            prev_randao: Default::default(),
            block_number: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: 0,
            extra_data: Default::default(),
            base_fee_per_gas: Default::default(),
            block_hash: Default::default(),
            transactions: Default::default(),
            withdrawals: Default::default(),
            blob_gas_used: 0,
            excess_blob_gas: 0,
            block_access_list: Default::default(),
            slot_number: 0,
        };
        let envelope = gloas::SignedExecutionPayloadEnvelope {
            message: gloas::ExecutionPayloadEnvelope {
                payload,
                execution_requests: Default::default(),
                builder_index: 0,
                beacon_block_root: root,
                parent_beacon_block_root: Root::ZERO,
            },
            signature: Default::default(),
        };
        let slot = store
            .get_signed_block(&root)
            .expect("get")
            .expect("the block is in the store")
            .slot();
        store.insert_verified_payload(slot, &envelope);
    }

    /// A fulu signed block with an empty body and a zero signature, for the
    /// fulu-to-gloas boundary tests below, which need a pre-gloas block
    /// genuinely of fulu's own fork rather than the phase0-shaped [`block`]
    /// stand-in. Wraps [`electra::SignedBeaconBlock`], the same shape
    /// [`SignedBeaconBlock::Fulu`] itself wraps (see that variant's own doc).
    fn fulu_block(slot: Slot, parent_root: Root) -> SignedBeaconBlock {
        SignedBeaconBlock::Fulu(electra::SignedBeaconBlock {
            message: electra::BeaconBlock {
                slot,
                proposer_index: 0,
                parent_root,
                state_root: Root::ZERO,
                body: electra::BeaconBlockBody::empty(),
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
        anchor_pair_from(test_state::with_validators(count))
    }

    /// [`anchor_pair`] over a caller-built `state`, for tests that need a
    /// registry with slashed or inactive validators in it.
    fn anchor_pair_from(mut state: BeaconState) -> (BeaconState, SignedBeaconBlock) {
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
        anchored_store_from(test_state::with_validators(count))
    }

    /// [`anchored_store`] over a caller-built state.
    fn anchored_store_from(state: BeaconState) -> (Store, Root, Slot) {
        let (anchor_state, anchor_block) = anchor_pair_from(state);
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

    /// A `count`-validator state (`count >= 9`) whose registry has every kind
    /// of validator the weight paths must tell apart, at the state's own epoch:
    /// validator 6 is slashed but active, 7 activates one epoch later, 8 exited
    /// at this epoch, and the rest are plain active ones.
    fn state_with_slashed_and_inactive_validators(count: usize) -> BeaconState {
        let mut state = test_state::with_validators(count);
        let epoch = get_current_epoch(&state);
        state.validator_mut(6).expect("registered").slashed = true;
        state.validator_mut(7).expect("registered").activation_epoch = epoch + 1;
        state.validator_mut(8).expect("registered").exit_epoch = epoch;
        state.apply_pending_mutations();
        state
    }

    /// `compute_weights` is the specification's `get_weight` for every root at
    /// once, so the two have to agree root by root: over a fork, over voters
    /// spread across both branches, and with the proposer boost applied.
    #[test]
    fn the_single_pass_weights_match_the_specifications_per_root_weight() {
        let config = Config::active();
        // Validators 6 (slashed), 7 (not yet active) and 8 (exited) vote below
        // and must weigh nothing; validator 40 is past the registry.
        let (mut store, anchor_root, anchor_slot) =
            anchored_store_from(state_with_slashed_and_inactive_validators(12));

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
            store.set_latest_message(
                validator_index,
                LatestMessage {
                    epoch: 0,
                    slot: 0,
                    root,
                    payload_present: false,
                },
            );
        }
        store.set_latest_message(
            4,
            LatestMessage {
                epoch: 0,
                slot: 0,
                root: anchor_root,
                payload_present: false,
            },
        );
        store.set_latest_message(
            5,
            LatestMessage {
                epoch: 0,
                slot: 0,
                root: b_root,
                payload_present: false,
            },
        );
        store.insert_equivocating_index(5);
        for (validator_index, root) in [(6, c_root), (7, c_root), (8, c_root), (40, c_root)] {
            store.set_latest_message(
                validator_index,
                LatestMessage {
                    epoch: 0,
                    slot: 0,
                    root,
                    payload_present: false,
                },
            );
        }
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
        assert_eq!(
            weights[&c_root],
            preset::MAX_EFFECTIVE_BALANCE,
            "only validator 3 counts on c: the slashed, inactive, exited and unknown voters weigh nothing"
        );
        assert_eq!(
            weights[&b_root],
            3 * preset::MAX_EFFECTIVE_BALANCE
                + get_proposer_score(&store, &config).expect("the anchor state is there"),
        );
    }

    /// The boost's committee weight divides the total active balance, which
    /// counts a slashed validator that is still active and leaves out one that
    /// is not active yet or already exited: the snapshot's per-vote zeros for
    /// the first kind must not leak into the total.
    #[test]
    fn the_proposer_score_counts_a_slashed_but_active_validator() {
        let config = Config::active();
        let (store, _anchor_root, _anchor_slot) =
            anchored_store_from(state_with_slashed_and_inactive_validators(12));

        // 12 validators, 2 of them (7 and 8) inactive; the slashed one stays.
        let expected = committee_fraction(
            10 * preset::MAX_EFFECTIVE_BALANCE,
            config.proposer_score_boost,
        );
        assert_eq!(
            get_proposer_score(&store, &config).expect("the anchor state is there"),
            expected
        );
        assert_ne!(
            expected,
            committee_fraction(
                9 * preset::MAX_EFFECTIVE_BALANCE,
                config.proposer_score_boost
            ),
            "a total that dropped the slashed validator would differ"
        );
        // And it is the state's own definition, not a second one.
        let state = checkpoint_state(&store, &store.beacon_justified_checkpoint(), &config)
            .expect("the anchor state is there");
        assert_eq!(
            expected,
            calculate_committee_fraction(&state, config.proposer_score_boost).expect("total"),
        );
    }

    #[test]
    fn building_the_snapshot_handles_activation_exit_slashing_and_an_empty_set() {
        let mut state = test_state::with_validators(6);
        let epoch = get_current_epoch(&state);
        state.validator_mut(1).expect("registered").activation_epoch = epoch;
        state.validator_mut(2).expect("registered").activation_epoch = epoch + 1;
        state.validator_mut(3).expect("registered").exit_epoch = epoch;
        state.validator_mut(4).expect("registered").slashed = true;
        state.apply_pending_mutations();
        let checkpoint = Checkpoint {
            epoch,
            root: Root::repeat_byte(1),
        };

        let snapshot = build_justified_balances(checkpoint, &state);
        let full = preset::MAX_EFFECTIVE_BALANCE;
        // Activation at the epoch counts; exit at the epoch does not; a slashed
        // but active validator weighs zero as a voter and counts in the total.
        assert_eq!(
            [0, 1, 2, 3, 4, 5].map(|index| snapshot.get(index)),
            [full, full, 0, 0, 0, full]
        );
        assert_eq!(snapshot.total_active_balance(), 4 * full);
        assert_eq!(
            snapshot.total_active_balance(),
            get_total_active_balance(&state).expect("total")
        );
        assert_eq!(snapshot.get(6), 0, "past the registry reads zero");
        assert_eq!(snapshot.checkpoint(), checkpoint);

        // No active validator at all: the total is floored like the spec's.
        for index in 0..6 {
            state.validator_mut(index).expect("registered").exit_epoch = epoch;
        }
        state.apply_pending_mutations();
        let empty = build_justified_balances(checkpoint, &state);
        assert_eq!(
            empty.total_active_balance(),
            preset::EFFECTIVE_BALANCE_INCREMENT
        );
        assert_eq!(
            empty.total_active_balance(),
            get_total_active_balance(&state).expect("total")
        );
        assert_eq!(empty.get(0), 0);
    }

    #[test]
    fn a_new_justified_checkpoint_rebuilds_the_snapshot() {
        let config = Config::active();
        let (mut store, anchor_root, _anchor_slot) = anchored_store(8);

        let first = justified_balances(&store, &config).expect("the anchor state is there");
        let again = justified_balances(&store, &config).expect("cached");
        assert!(
            Arc::ptr_eq(&first, &again),
            "same checkpoint, same snapshot"
        );
        assert_eq!(first.get(0), preset::MAX_EFFECTIVE_BALANCE);

        // A later justified checkpoint over a state with different balances,
        // planted where `checkpoint_state` finds it.
        let next = Checkpoint {
            epoch: first.checkpoint().epoch + 1,
            root: Root::repeat_byte(0x77),
        };
        let mut state = test_state::with_validators(8);
        *state.slot_mut() = compute_start_slot_at_epoch(next.epoch);
        state
            .validator_mut(0)
            .expect("registered")
            .effective_balance = 5;
        state.validator_mut(1).expect("registered").slashed = true;
        state.apply_pending_mutations();
        store.cache_state(
            CacheKey::CheckpointState {
                epoch: next.epoch,
                root: next.root,
            },
            Arc::new(state),
        );
        let finalized = store.beacon_finalized_checkpoint();
        update_checkpoints(&mut store, next, finalized);
        assert_ne!(store.beacon_justified_checkpoint().root, anchor_root);

        let rebuilt = justified_balances(&store, &config).expect("planted state");
        assert!(!Arc::ptr_eq(&first, &rebuilt));
        assert_eq!(rebuilt.checkpoint(), next);
        assert_eq!(rebuilt.get(0), 5);
        assert_eq!(rebuilt.get(1), 0, "slashed in the new state");
        assert_eq!(rebuilt.get(2), preset::MAX_EFFECTIVE_BALANCE);
    }

    /// The failure a live mainnet follower hit: `promote_beacon_anchor` prunes
    /// the block index below the oldest kept anchor, and any validator whose
    /// freshest vote was for a block down there kept pointing at it. Both
    /// [`get_weight`] (through [`get_attestation_score`]'s own decided rule;
    /// see its doc) and [`compute_weights`] (its own independent bottom-up
    /// fold, which never called `get_attestation_score` and so never shared
    /// this bug) skip such a vote rather than raising, and agree on the
    /// weight it leaves behind.
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
                slot: 0,
                root: a_root,
                payload_present: false,
            },
        );
        store.set_latest_message(
            1,
            LatestMessage {
                epoch: 0,
                slot: 0,
                // Below the anchor, so no longer indexed.
                root: Root::repeat_byte(0xde),
                payload_present: false,
            },
        );

        let per_root_weight = get_weight(&store, &index, a_root, &config)
            .expect("a pruned vote is skipped, not fatal, in the per-root version either");
        assert!(per_root_weight > 0, "the live vote still counts");

        let weights = compute_weights(&store, &index, &config).expect("a pruned vote is not fatal");

        let one_validator_balance = weights[&a_root];
        assert!(one_validator_balance > 0, "the live vote still counts");
        assert_eq!(
            one_validator_balance, per_root_weight,
            "the per-root and bottom-up versions must agree"
        );
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

    /// A checkpoint-synced anchor's own `parent_root` names real history this
    /// store never held, so it is never indexed. `get_shuffling_dependent_root`
    /// asking for a dependent slot below such an anchor (which the import
    /// benchmark's `replay.rs` hits on its very first block: the clock is set
    /// to that block's own slot, so the current epoch can be as little as one
    /// past the anchor's) must not walk into that gap the way plain
    /// `get_ancestor` would.
    #[test]
    fn get_shuffling_dependent_root_stops_at_a_non_genesis_anchor() {
        let anchor_root = Root::repeat_byte(1);
        let anchor_slot = 100;
        let unindexed_parent = Root::repeat_byte(0xff);

        let mut index = HashMap::new();
        index.insert(anchor_root, (anchor_slot, unindexed_parent));

        // One epoch past the anchor's own: still low enough that the
        // dependent slot (`MIN_SEED_LOOKAHEAD` epochs, minus one, before it)
        // falls before `anchor_slot`.
        let epoch = compute_epoch_at_slot(anchor_slot) + 1;
        assert!(
            compute_shuffling_dependent_slot(epoch) < anchor_slot,
            "the scenario this test exists for requires a dependent slot \
             below the anchor"
        );

        assert_eq!(
            get_shuffling_dependent_root(&index, anchor_root, epoch),
            anchor_root,
            "the walk must stop at the lowest indexed ancestor rather than \
             stepping into `unindexed_parent`"
        );
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
    fn is_proposer_equivocation_true_for_two_blocks_from_the_same_proposer_and_slot() {
        let a_root = Root::repeat_byte(2);
        let b_root = Root::repeat_byte(3);
        let mut store = empty_store();
        store
            .insert_signed_block(a_root, block_with_proposer(1, Root::ZERO, 7))
            .unwrap();
        store
            .insert_signed_block(b_root, block_with_proposer(1, Root::ZERO, 7))
            .unwrap();
        let index = index(&[(a_root, 1, Root::ZERO), (b_root, 1, Root::ZERO)]);

        assert!(
            is_proposer_equivocation(&store, &index, a_root).unwrap(),
            "two blocks sharing a slot and a proposer must be an equivocation"
        );
    }

    #[test]
    fn is_proposer_equivocation_false_for_two_blocks_same_slot_different_proposers() {
        let a_root = Root::repeat_byte(2);
        let b_root = Root::repeat_byte(3);
        let mut store = empty_store();
        store
            .insert_signed_block(a_root, block_with_proposer(1, Root::ZERO, 7))
            .unwrap();
        store
            .insert_signed_block(b_root, block_with_proposer(1, Root::ZERO, 8))
            .unwrap();
        let index = index(&[(a_root, 1, Root::ZERO), (b_root, 1, Root::ZERO)]);

        assert!(
            !is_proposer_equivocation(&store, &index, a_root).unwrap(),
            "sharing a slot alone, with different proposers, is not an \
             equivocation"
        );
    }

    #[test]
    fn is_head_weak_counts_an_equivocating_validators_balance_from_the_head_slot_committees() {
        let config = Config::active();
        // Exactly `SLOTS_PER_EPOCH` active validators and one committee per
        // slot puts exactly one validator in the anchor's own slot's
        // committee 0, so which index the shuffle picks does not matter to
        // this test: it asks the same cache `is_head_weak` will.
        let (mut store, anchor_root, anchor_slot) =
            anchored_store(preset::SLOTS_PER_EPOCH as usize);
        let committees = CommitteeCache::default();

        assert!(
            is_head_weak(&store, anchor_root, &config, &committees).unwrap(),
            "a head with no votes and no equivocators must be weak"
        );

        let head_state = store
            .get_state(&anchor_root)
            .expect("get")
            .expect("state exists");
        let epoch = compute_epoch_at_slot(anchor_slot);
        let equivocator = committees
            .committees(&head_state, epoch)
            .committee(anchor_slot, 0)
            .expect("committee 0 of the anchor's own slot")[0];
        store.insert_equivocating_index(equivocator);

        assert!(
            !is_head_weak(&store, anchor_root, &config, &committees).unwrap(),
            "the equivocator's own effective balance must count toward the \
             head's weight, clearing the reorg threshold on its own"
        );
    }

    #[test]
    fn get_proposer_head_reorgs_a_weak_timely_head_on_proposer_equivocation() {
        let config = Config::active();
        let genesis_root = Root::repeat_byte(1);
        let parent_root = Root::repeat_byte(2);
        let head_root = Root::repeat_byte(3);
        let twin_root = Root::repeat_byte(4);
        let committees = CommitteeCache::default();

        let mut store = store_anchored_at(genesis_root);
        store
            .insert_signed_block(genesis_root, block(0, Root::ZERO))
            .unwrap();
        store
            .insert_signed_block(parent_root, block(1, genesis_root))
            .unwrap();
        store
            .insert_signed_block(head_root, block_with_proposer(2, parent_root, 9))
            .unwrap();
        // A second block for `head_root`'s own slot and proposer: the new
        // `is_proposer_equivocation` condition this test exercises.
        store
            .insert_signed_block(twin_root, block_with_proposer(2, parent_root, 9))
            .unwrap();

        let state = test_state::with_validators(1);
        store.insert_state(genesis_root, state.clone()).unwrap();
        store.insert_state(parent_root, state.clone()).unwrap();
        store.insert_state(head_root, state).unwrap();

        // Timely: `is_head_late` answers `false`, which alone keeps the main
        // reorg branch (`head_late && ...`) from firing, so a `parent_root`
        // result below can only come from the new `head_weak &&
        // current_time_ok && proposer_equivocation` branch.
        store.set_block_timeliness(head_root, [true, true]);

        // `is_ffg_competitive` needs both roots to already have an
        // unrealized justification on record; its value is irrelevant to the
        // branch under test as long as both calls succeed.
        let checkpoint = Checkpoint {
            epoch: 0,
            root: genesis_root,
        };
        store.set_unrealized_justification(head_root, checkpoint);
        store.set_unrealized_justification(parent_root, checkpoint);

        // One slot past `head_root`'s own slot (2): `current_time_ok`.
        let proposer_head = get_proposer_head(&store, head_root, 3, &config, &committees)
            .expect("every condition this test sets up should let this succeed");

        assert_eq!(
            proposer_head, parent_root,
            "a weak, timely head with a second block from its own proposer \
             must still be reorged out"
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

    /// [`on_block`]'s early-return guard must read `Store::has_state`, not
    /// `Store::has_block`: a block the actor is holding for missing data
    /// columns is written with
    /// [`Store::insert_pending_block`](ethlambda_storage::Store::insert_pending_block)
    /// before it ever imports, which stores the whole signed block in one
    /// `BlockHeaders` row (so `has_block` answers true) but writes no
    /// `LiveChain` entry (so [`Store::block_index`](ethlambda_storage::Store::block_index),
    /// a `LiveChain` scan, does not name it). Guarding on `has_block` instead
    /// of `has_state` made `on_block` answer `Ok(())` for a held block
    /// without importing it, so every later delivery naming it as an
    /// ancestor found it "already known" and gave up without importing
    /// anything either -- forever, since nothing ever gave the root a
    /// post-state.
    ///
    /// Delivered timely (the first block for its slot, before the
    /// attestation deadline), so this also proves `on_block`'s pre-import
    /// `compute_head` call (walking `Store::block_index`, for the new
    /// proposer-boost dependent-root gate) tolerates a held block sitting
    /// unindexed in the store: that walk never sees it, being a `LiveChain`
    /// scan, so it is untouched by the held block's absent post-state.
    ///
    /// Builds a genuinely valid child block (correct proposer, RANDAO reveal,
    /// and state root, all real BLS signatures over
    /// [`test_state::secret_key_for`]'s key) rather than the zero-signature
    /// [`block`] helper, since this exercises the real, signature-checking
    /// [`on_block`], not a fixture harness that can skip verification.
    #[test]
    fn on_block_imports_a_block_already_persisted_with_no_post_state() {
        let config = Config::active();
        let (anchor_state, anchor_block) = anchor_pair_with(1);
        let anchor_root = anchor_block.message_hash_tree_root();
        let target_slot = anchor_state.slot() + 1;

        // The proposer and signing domain for `target_slot` only depend on
        // advancing the slot clock, not on the block itself, so these are
        // derived from their own clone ahead of building the block.
        let mut probe_state = anchor_state.clone();
        stf::process_slots(&mut probe_state, target_slot, &config).expect("process_slots");
        let proposer_index =
            accessors::get_beacon_proposer_index(&probe_state).expect("get_beacon_proposer_index");
        let proposer_key = test_state::secret_key_for(proposer_index as usize);
        let proposer_domain =
            accessors::get_domain(&probe_state, constants::DOMAIN_BEACON_PROPOSER, None);
        let randao_domain = accessors::get_domain(&probe_state, constants::DOMAIN_RANDAO, None);
        let randao_epoch = get_current_epoch(&probe_state);
        let randao_reveal = BlsSignature(
            proposer_key
                .sign(
                    compute_signing_root(randao_epoch.hash_tree_root(), randao_domain).as_slice(),
                    bls::DST,
                    &[],
                )
                .to_bytes(),
        );

        let mut draft = block(target_slot, anchor_root);
        let SignedBeaconBlock::Phase0(inner) = &mut draft else {
            unreachable!("`block` builds a phase0 signed block");
        };
        inner.message.proposer_index = proposer_index;
        inner.message.body.randao_reveal = randao_reveal;

        // Learn the real post-state (and so the real state root) by running
        // the transition once, unvalidated, the way a proposer decides
        // everything but the signature and the state root before signing.
        let mut trial_state = anchor_state.clone();
        let trial_committees = CommitteeCache::default();
        stf::state_transition(
            &mut trial_state,
            &draft,
            false,
            &config,
            &stf::ExecutionEngine::valid(),
            &trial_committees,
        )
        .expect("the drafted block must transition cleanly");
        let state_root = trial_state.hash_tree_root();

        let SignedBeaconBlock::Phase0(inner) = &mut draft else {
            unreachable!("still phase0");
        };
        inner.message.state_root = state_root;
        let signing_root = compute_signing_root(draft.message_hash_tree_root(), proposer_domain);
        let SignedBeaconBlock::Phase0(inner) = &mut draft else {
            unreachable!("still phase0");
        };
        inner.signature = BlsSignature(
            proposer_key
                .sign(signing_root.as_slice(), bls::DST, &[])
                .to_bytes(),
        );
        let signed_block = draft;
        let block_root = signed_block.message_hash_tree_root();

        // The store holds the child block already, exactly the shape
        // `hold_block_for_columns` leaves it in: one `BlockHeaders` row (so
        // `has_block` is true and the block is readable back by root) but no
        // `LiveChain` entry (so `block_index` does not name it) and no
        // post-state (nothing has imported it yet).
        let mut store = get_forkchoice_store(
            Arc::new(InMemoryBackend::new()),
            anchor_state,
            anchor_block,
            &config,
        )
        .expect("the anchor pair matches");
        // `on_block` refuses a block from the future (`get_current_slot(store)
        // >= block.slot`), so the store's clock has to have reached the
        // child's own slot before this test's `on_block` call below. Set to
        // the slot's own start, its first block, so `block_timeliness` is
        // true and `on_block` runs its pre-import `compute_head` call too
        // (see this test's own doc for why that matters).
        store
            .set_time_ms(seconds_to_milliseconds(
                config.seconds_per_slot * target_slot,
            ))
            .expect("set time");
        store
            .insert_pending_block(block_root, signed_block.clone())
            .expect("insert");
        assert!(store.has_block(&block_root), "persisted above");
        assert!(
            !store.has_state(&block_root).expect("get"),
            "no import has run yet"
        );
        assert!(
            !store.block_index().contains_key(&block_root),
            "a held block carries no LiveChain entry"
        );

        let committees = CommitteeCache::default();
        on_block(
            &mut store,
            signed_block,
            &config,
            &DataAvailability::NotRequired,
            &PayloadValidity::NotRequired,
            &committees,
        )
        .expect("a validly signed, correctly rooted block must still import");

        assert!(
            store.has_state(&block_root).expect("get"),
            "on_block must not mistake a persisted-but-unimported (held) \
             block for an already-imported one"
        );
    }

    #[test]
    fn the_commitments_subtree_index_is_the_bodys_own_position() {
        // The generalized index the fixture states, minus the offset of a tree
        // with KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH levels. This only keeps
        // the constant and the fixture's generalized index from drifting
        // apart; it never touches BeaconBlockBody, so a field added there
        // that silently shifts the real position would pass this unchanged.
        // The merkle_proof fixtures' end-to-end check, which decodes a real
        // body, recomputes its hash_tree_root(), and drives it through
        // verify_data_column_sidecar_inclusion_proof, is what catches that.
        let depth = preset::KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH as u32;
        assert_eq!(
            BLOB_KZG_COMMITMENTS_SUBTREE_INDEX + 2u64.pow(depth),
            27,
            "the fixture's generalized index for blob_kzg_commitments"
        );
    }

    #[test]
    fn a_valid_status_becomes_a_validated_verdict() {
        let status = PayloadStatusV1 {
            status: PayloadStatusEnum::Valid,
            latest_valid_hash: Some(ExecutionBlockHash::repeat_byte(1)),
            validation_error: None,
        };
        assert_eq!(payload_validity(&status), PayloadValidity::Validated);
    }

    #[test]
    fn the_not_validated_statuses_become_an_optimistic_verdict() {
        for status in [PayloadStatusEnum::Syncing, PayloadStatusEnum::Accepted] {
            let status = PayloadStatusV1 {
                status,
                latest_valid_hash: None,
                validation_error: None,
            };
            assert_eq!(payload_validity(&status), PayloadValidity::Optimistic);
        }
    }

    #[test]
    fn the_invalidated_statuses_carry_their_latest_valid_hash_through() {
        for status in [
            PayloadStatusEnum::Invalid,
            PayloadStatusEnum::InvalidBlockHash,
        ] {
            let status = PayloadStatusV1 {
                status,
                latest_valid_hash: Some(ExecutionBlockHash::repeat_byte(9)),
                validation_error: Some("invalid".to_string()),
            };
            assert_eq!(
                payload_validity(&status),
                PayloadValidity::Invalidated {
                    latest_valid_hash: Some(ExecutionBlockHash::repeat_byte(9)),
                }
            );
        }
    }

    const BLOCK_0: Root = Root::repeat_byte(10);
    const CHAIN_A0: Root = Root::repeat_byte(11);
    const CHAIN_B0: Root = Root::repeat_byte(20);
    const CHAIN_B1: Root = Root::repeat_byte(21);
    /// The rejected block: never indexed, parented on `CHAIN_B1`.
    const CHAIN_B2: Root = Root::repeat_byte(22);

    /// The fixture's own topology, minus the block that gets rejected:
    ///
    /// ```text
    /// block_0 (el 0xb0) -- a0 (el 0xa0)
    ///                   \- b0 (el 0xc0) -- b1 (el 0xc1)
    /// ```
    ///
    /// The rejected block, `b2`, is deliberately absent: an `INVALID` verdict
    /// arrives before its block is ever indexed.
    fn store_with_two_branches() -> Store {
        let mut store = empty_store();
        // (beacon root, slot, parent root, execution hash)
        let rows = [
            (
                BLOCK_0,
                1u64,
                Root::ZERO,
                ExecutionBlockHash::repeat_byte(0xb0),
            ),
            (CHAIN_A0, 2, BLOCK_0, ExecutionBlockHash::repeat_byte(0xa0)),
            (CHAIN_B0, 2, BLOCK_0, ExecutionBlockHash::repeat_byte(0xc0)),
            (CHAIN_B1, 3, CHAIN_B0, ExecutionBlockHash::repeat_byte(0xc1)),
        ];
        for (root, slot, parent, el_hash) in rows {
            store.insert_live_chain_entry(slot, root, parent);
            store.insert_beacon_el_block_hash(root, slot, el_hash);
        }
        store
    }

    #[test]
    fn a_named_latest_valid_hash_condemns_the_child_of_the_last_valid_block() {
        let store = store_with_two_branches();
        let index = store.block_index();

        // b2 is rejected and block_0's payload is the last valid one. Walking
        // up b2's own chain, the child of block_0 is b0, so b0 and everything
        // under it is condemned.
        let condemned = resolve_invalid_block(
            &store,
            &index,
            CHAIN_B2,
            CHAIN_B1,
            Some(ExecutionBlockHash::repeat_byte(0xb0)),
        );

        assert_eq!(condemned, CHAIN_B0);
    }

    #[test]
    fn the_walk_stays_on_the_rejected_blocks_own_branch() {
        let store = store_with_two_branches();
        let index = store.block_index();

        // a0 is also a child of block_0, and must never be the answer for a
        // block on chain b.
        let condemned = resolve_invalid_block(
            &store,
            &index,
            CHAIN_B2,
            CHAIN_B1,
            Some(ExecutionBlockHash::repeat_byte(0xb0)),
        );

        assert_ne!(condemned, CHAIN_A0);
    }

    #[test]
    fn a_null_latest_valid_hash_condemns_only_the_block_in_question() {
        let store = store_with_two_branches();
        let index = store.block_index();

        let condemned = resolve_invalid_block(&store, &index, CHAIN_B2, CHAIN_B1, None);

        assert_eq!(condemned, CHAIN_B2);
    }

    #[test]
    fn an_unfindable_latest_valid_hash_behaves_as_null() {
        let store = store_with_two_branches();
        let index = store.block_index();

        let condemned = resolve_invalid_block(
            &store,
            &index,
            CHAIN_B2,
            CHAIN_B1,
            Some(ExecutionBlockHash::repeat_byte(0xee)),
        );

        assert_eq!(condemned, CHAIN_B2);
    }

    #[test]
    fn a_zero_latest_valid_hash_condemns_the_whole_execution_branch() {
        let store = store_with_two_branches();
        let index = store.block_index();

        // Every block on this chain carries a payload, so the deepest indexed
        // ancestor is block_0 itself.
        let condemned = resolve_invalid_block(&store, &index, CHAIN_B2, CHAIN_B1, Some(Root::ZERO));

        assert_eq!(condemned, BLOCK_0);
    }

    #[test]
    fn invalidating_a_subtree_removes_it_and_leaves_its_sibling_branch() {
        let mut store = store_with_two_branches();
        store.insert_beacon_optimistic_root(CHAIN_B0, 2);
        store.insert_beacon_optimistic_root(CHAIN_B1, 3);

        let removed = invalidate_subtree(&mut store, CHAIN_B0);

        assert_eq!(removed, 2);

        let index = store.block_index();
        // Chain b is gone.
        assert!(!index.contains_key(&CHAIN_B0));
        assert!(!index.contains_key(&CHAIN_B1));
        // block_0 and chain a survive.
        assert!(index.contains_key(&BLOCK_0));
        assert!(index.contains_key(&CHAIN_A0));
        // And the invalidated roots are no longer merely optimistic.
        assert!(!store.is_beacon_optimistic(CHAIN_B0));
        assert!(!store.is_beacon_optimistic(CHAIN_B1));
    }

    #[test]
    fn invalidating_a_leaf_removes_only_that_leaf() {
        let mut store = store_with_two_branches();

        let removed = invalidate_subtree(&mut store, CHAIN_B1);

        assert_eq!(removed, 1);
        let index = store.block_index();
        assert!(!index.contains_key(&CHAIN_B1));
        assert!(index.contains_key(&CHAIN_B0));
    }

    #[test]
    fn invalidating_a_root_the_index_never_held_removes_nothing() {
        let mut store = store_with_two_branches();

        // The `None`/unfindable `latestValidHash` case condemns the rejected
        // block itself, which never imported and so has no row.
        let removed = invalidate_subtree(&mut store, CHAIN_B2);

        assert_eq!(removed, 0);
        assert_eq!(store.block_index().len(), 4);
    }

    /// The checkpoint root is the last block at *or before* its epoch
    /// boundary, so a skipped boundary slot leaves the finalized block above
    /// the slot its own checkpoint is stored as. The slot comparison alone
    /// would miss it, which is why the floor names the root too.
    #[test]
    fn invalidating_the_finalized_block_itself_is_refused() {
        // Anchored at b0: the finalized checkpoint's root, in the genesis
        // epoch, while its block sits at slot 2.
        let mut store = store_anchored_at(CHAIN_B0);
        store.insert_live_chain_entry(2, CHAIN_B0, BLOCK_0);
        store.insert_live_chain_entry(3, CHAIN_B1, CHAIN_B0);

        let removed = invalidate_subtree(&mut store, CHAIN_B0);

        assert_eq!(
            removed, 0,
            "obeying this would delete every row from finality upward and \
             leave `get_head` nothing to compute a head from"
        );
        let index = store.block_index();
        assert!(index.contains_key(&CHAIN_B0));
        assert!(index.contains_key(&CHAIN_B1));

        // Not a blanket refusal: an unfinalized descendant still goes.
        assert_eq!(invalidate_subtree(&mut store, CHAIN_B1), 1);
    }

    /// An all-zero `latestValidHash` condemns every payload on the chain, and
    /// [`resolve_invalid_block`]'s walk for it stops only where the execution
    /// hash cache does, which finality bounds. So the ancestor it answers can
    /// be finalized history even when no block was named directly.
    #[test]
    fn invalidating_a_block_below_the_finalized_slot_is_refused() {
        let mut store = store_with_two_branches();
        let finalized = Checkpoint {
            epoch: 1,
            root: CHAIN_B1,
        };
        update_checkpoints(&mut store, finalized, finalized);

        // Every row in the fixture is below the epoch-1 start slot.
        let removed = invalidate_subtree(&mut store, CHAIN_B0);

        assert_eq!(removed, 0);
        assert_eq!(store.block_index().len(), 4);
    }

    #[test]
    fn a_child_of_an_execution_block_is_always_an_optimistic_candidate() {
        let store = store_with_two_branches();

        // block_0 carries a payload, so its child may be imported
        // optimistically whatever the clock says.
        assert!(is_optimistic_candidate_block(
            &store,
            /* current_slot */ 2,
            /* block_slot */ 2,
            /* parent_root */ BLOCK_0,
            constants::SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY,
        ));
    }

    #[test]
    fn a_block_on_a_payloadless_parent_needs_the_age_horizon() {
        let store = empty_store();
        let parent = Root::repeat_byte(77);
        let safe_slots = constants::SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY;

        // No cached execution hash for the parent: pre-merge, so only age
        // qualifies it.
        assert!(!is_optimistic_candidate_block(
            &store, 100, 90, parent, safe_slots
        ));
        assert!(is_optimistic_candidate_block(
            &store, 300, 90, parent, safe_slots
        ));
    }

    // ------------------------------------------------------------------
    // Gloas: payload-aware fork choice
    // ------------------------------------------------------------------

    #[test]
    fn get_node_children_offers_the_full_branch_only_once_the_payload_is_verified() {
        let mut store = empty_store();
        let a_root = Root::repeat_byte(0xa1);
        store
            .insert_signed_block(
                a_root,
                gloas_block(
                    1,
                    Root::ZERO,
                    ExecutionBlockHash::ZERO,
                    ExecutionBlockHash::repeat_byte(0xaa),
                ),
            )
            .unwrap();
        let blocks = store.block_index();
        let node = ForkChoiceNode {
            root: a_root,
            payload_status: PayloadStatus::Pending,
        };

        assert_eq!(
            get_node_children(&store, &blocks, node).unwrap(),
            vec![ForkChoiceNode {
                root: a_root,
                payload_status: PayloadStatus::Empty
            }],
            "no verified payload yet: only the empty branch exists"
        );

        verify_payload(&mut store, a_root);
        assert_eq!(
            get_node_children(&store, &blocks, node).unwrap(),
            vec![
                ForkChoiceNode {
                    root: a_root,
                    payload_status: PayloadStatus::Empty
                },
                ForkChoiceNode {
                    root: a_root,
                    payload_status: PayloadStatus::Full
                },
            ],
            "a verified payload adds the full branch alongside the empty one"
        );
    }

    #[test]
    fn get_parent_payload_status_matches_the_childs_bid_against_the_parents_block_hash() {
        let mut store = empty_store();
        let a_hash = ExecutionBlockHash::repeat_byte(0xaa);
        let a_root = Root::repeat_byte(0xa1);
        store
            .insert_signed_block(
                a_root,
                gloas_block(1, Root::ZERO, ExecutionBlockHash::ZERO, a_hash),
            )
            .unwrap();

        let full_root = Root::repeat_byte(0xb1);
        store
            .insert_signed_block(
                full_root,
                // Its bid names `a_root`'s own revealed block hash.
                gloas_block(2, a_root, a_hash, ExecutionBlockHash::repeat_byte(0xb2)),
            )
            .unwrap();
        let empty_root = Root::repeat_byte(0xc1);
        store
            .insert_signed_block(
                empty_root,
                // Its bid names a block hash `a_root` never revealed.
                gloas_block(
                    2,
                    a_root,
                    ExecutionBlockHash::repeat_byte(0xff),
                    ExecutionBlockHash::repeat_byte(0xc2),
                ),
            )
            .unwrap();

        let full_block = store.get_signed_block(&full_root).unwrap().unwrap();
        let empty_block = store.get_signed_block(&empty_root).unwrap().unwrap();

        assert_eq!(
            get_parent_payload_status(&store, &full_block).unwrap(),
            PayloadStatus::Full,
            "the child's bid names the parent's own revealed block hash"
        );
        assert!(is_parent_node_full(&store, &full_block).unwrap());

        assert_eq!(
            get_parent_payload_status(&store, &empty_block).unwrap(),
            PayloadStatus::Empty,
            "the child's bid names a different block hash than the parent revealed"
        );
        assert!(!is_parent_node_full(&store, &empty_block).unwrap());
    }

    /// A wrong ancestor walk that read the wrong child's bid at each step is
    /// caught here: comparing `c_root`'s own bid against `a_root` directly
    /// (skipping the step through `b_root`) would answer `Empty` (`c_root`'s
    /// bid names a different hash than `a_root` revealed), not the correct
    /// `Full` that `b_root`'s own bid (built on `a_root`'s revealed hash)
    /// actually names. The second half below repeats the same shape with a
    /// `b2_root` whose bid misses `a_hash`, so the walk must also come back
    /// empty, not just full.
    #[test]
    fn get_ancestor_carries_the_childs_view_of_the_stepped_over_parents_payload_status() {
        let mut store = empty_store();
        let a_hash = ExecutionBlockHash::repeat_byte(0xaa);
        let a_root = Root::repeat_byte(0xa1);
        store
            .insert_signed_block(
                a_root,
                gloas_block(1, Root::ZERO, ExecutionBlockHash::ZERO, a_hash),
            )
            .unwrap();

        let b_root = Root::repeat_byte(0xb1);
        let b_hash = ExecutionBlockHash::repeat_byte(0xbb);
        store
            .insert_signed_block(b_root, gloas_block(2, a_root, a_hash, b_hash))
            .unwrap();

        let c_root = Root::repeat_byte(0xc1);
        store
            .insert_signed_block(
                c_root,
                gloas_block(3, b_root, b_hash, ExecutionBlockHash::repeat_byte(0xcc)),
            )
            .unwrap();

        let start = ForkChoiceNode {
            root: c_root,
            payload_status: PayloadStatus::Pending,
        };
        let ancestor = gloas_get_ancestor(&store, start, 1).unwrap();

        assert_eq!(
            ancestor,
            ForkChoiceNode {
                root: a_root,
                payload_status: PayloadStatus::Full,
            },
            "b_root's bid names a_root's own revealed block hash, so stepping \
             past it labels a_root full"
        );

        // The same walk, but `b2_root`'s bid misses `a_hash`: stepping past
        // it must label `a_root` empty instead.
        let b2_root = Root::repeat_byte(0xb2);
        let b2_hash = ExecutionBlockHash::repeat_byte(0xee);
        store
            .insert_signed_block(
                b2_root,
                gloas_block(2, a_root, ExecutionBlockHash::repeat_byte(0xff), b2_hash),
            )
            .unwrap();
        let c2_root = Root::repeat_byte(0xc2);
        store
            .insert_signed_block(
                c2_root,
                gloas_block(3, b2_root, b2_hash, ExecutionBlockHash::repeat_byte(0xcc)),
            )
            .unwrap();

        let start2 = ForkChoiceNode {
            root: c2_root,
            payload_status: PayloadStatus::Pending,
        };
        let ancestor2 = gloas_get_ancestor(&store, start2, 1).unwrap();

        assert_eq!(
            ancestor2,
            ForkChoiceNode {
                root: a_root,
                payload_status: PayloadStatus::Empty,
            },
            "b2_root's bid misses a_root's own revealed block hash, so \
             stepping past it labels a_root empty"
        );
    }

    #[test]
    fn get_payload_status_tiebreaker_prefers_empty_then_a_verified_extended_payload() {
        let config = Config::active();
        let mut store = empty_store();

        let a_root = Root::repeat_byte(0xa1);
        let a_slot = 1;
        store
            .insert_signed_block(
                a_root,
                gloas_block(
                    a_slot,
                    Root::ZERO,
                    ExecutionBlockHash::ZERO,
                    ExecutionBlockHash::repeat_byte(0xaa),
                ),
            )
            .unwrap();
        // A previous-slot payload decision: `a_root`'s block is one slot
        // behind the store clock, which is what makes the tiebreaker matter
        // at all (`get_weight` scores it `0` otherwise).
        store
            .set_time_ms((a_slot + 1) * config.slot_duration_ms)
            .unwrap();

        let empty = ForkChoiceNode {
            root: a_root,
            payload_status: PayloadStatus::Empty,
        };
        let full = ForkChoiceNode {
            root: a_root,
            payload_status: PayloadStatus::Full,
        };

        assert_eq!(
            get_payload_status_tiebreaker(&store, empty, &config).unwrap(),
            1,
            "the empty branch always wins its own tiebreaker value"
        );
        assert_eq!(
            get_payload_status_tiebreaker(&store, full, &config).unwrap(),
            0,
            "a payload nobody verified must not be extended, so full loses the tiebreak"
        );

        verify_payload(&mut store, a_root);
        let strong_votes = vec![Some(true); preset::PTC_SIZE];
        store.set_payload_timeliness_vote(a_root, strong_votes.clone());
        store.set_payload_data_availability_vote(a_root, strong_votes);

        assert_eq!(
            get_payload_status_tiebreaker(&store, full, &config).unwrap(),
            2,
            "a verified, PTC-approved payload must win the tiebreak by extending"
        );
    }

    /// The spec compares with `>`, not `>=`: exactly the threshold's worth of
    /// matching votes must not be enough, only one more than it.
    #[test]
    fn payload_timeliness_and_data_availability_require_strictly_more_than_the_threshold() {
        let mut store = empty_store();
        let a_root = Root::repeat_byte(0xa1);
        store
            .insert_signed_block(
                a_root,
                gloas_block(
                    1,
                    Root::ZERO,
                    ExecutionBlockHash::ZERO,
                    ExecutionBlockHash::repeat_byte(0xaa),
                ),
            )
            .unwrap();
        verify_payload(&mut store, a_root);

        let exactly_threshold = vec![Some(true); preset::PAYLOAD_TIMELY_THRESHOLD as usize];
        store.set_payload_timeliness_vote(a_root, exactly_threshold.clone());
        assert!(
            !payload_timeliness(&store, a_root, true).unwrap(),
            "exactly the threshold's worth of matching votes must not be enough"
        );
        store.set_payload_timeliness_vote(
            a_root,
            vec![Some(true); preset::PAYLOAD_TIMELY_THRESHOLD as usize + 1],
        );
        assert!(
            payload_timeliness(&store, a_root, true).unwrap(),
            "one more than the threshold must be enough"
        );

        store.set_payload_data_availability_vote(a_root, exactly_threshold);
        assert!(
            !payload_data_availability(&store, a_root, true).unwrap(),
            "the same strict threshold applies to the data-availability vote"
        );
        store.set_payload_data_availability_vote(
            a_root,
            vec![Some(true); preset::DATA_AVAILABILITY_TIMELY_THRESHOLD as usize + 1],
        );
        assert!(payload_data_availability(&store, a_root, true).unwrap());
    }

    #[test]
    fn should_extend_payload_follows_the_ptc_vote_once_verified() {
        let config = Config::active();
        let mut store = empty_store();

        let a_root = Root::repeat_byte(0xa1);
        let a_slot = 1;
        let a_hash = ExecutionBlockHash::repeat_byte(0xaa);
        store
            .insert_signed_block(
                a_root,
                gloas_block(a_slot, Root::ZERO, ExecutionBlockHash::ZERO, a_hash),
            )
            .unwrap();

        // The current proposer-boosted block builds on `a_root` and itself
        // chose the empty branch, so neither of `should_extend_payload`'s two
        // other conditions holds: only the PTC's own vote can make it extend.
        let d_root = Root::repeat_byte(0xd1);
        store
            .insert_signed_block(
                d_root,
                gloas_block(
                    a_slot + 1,
                    a_root,
                    ExecutionBlockHash::repeat_byte(0xff), // does not match `a_hash`
                    ExecutionBlockHash::repeat_byte(0xdd),
                ),
            )
            .unwrap();
        store.set_proposer_boost_root(d_root);
        store
            .set_time_ms((a_slot + 1) * config.slot_duration_ms)
            .unwrap();

        assert!(
            !should_extend_payload(&store, a_root, &config).unwrap(),
            "a payload nobody verified must not be extended"
        );

        verify_payload(&mut store, a_root);
        let weak_votes = vec![Some(false); preset::PTC_SIZE];
        store.set_payload_timeliness_vote(a_root, weak_votes.clone());
        store.set_payload_data_availability_vote(a_root, weak_votes);
        assert!(
            !should_extend_payload(&store, a_root, &config).unwrap(),
            "verified but neither timely nor available, with the \
             proposer-boosted block itself choosing empty: must not extend"
        );

        // Timely but not available: both conditions are required (`&&`, not
        // `||`), so this must not extend either.
        store.set_payload_timeliness_vote(a_root, vec![Some(true); preset::PTC_SIZE]);
        store.set_payload_data_availability_vote(a_root, vec![Some(false); preset::PTC_SIZE]);
        assert!(
            !should_extend_payload(&store, a_root, &config).unwrap(),
            "timely alone, without availability, must not extend"
        );

        let strong_votes = vec![Some(true); preset::PTC_SIZE];
        store.set_payload_timeliness_vote(a_root, strong_votes.clone());
        store.set_payload_data_availability_vote(a_root, strong_votes);
        assert!(
            should_extend_payload(&store, a_root, &config).unwrap(),
            "a verified payload the PTC saw as timely and available must extend"
        );
    }

    #[test]
    fn gloas_get_head_picks_the_more_heavily_voted_payload_branch() {
        let config = Config::active();
        let anchor_root = Root::repeat_byte(1);
        let mut store = store_anchored_at(anchor_root);
        store
            .insert_signed_block(
                anchor_root,
                gloas_block(
                    0,
                    Root::ZERO,
                    ExecutionBlockHash::ZERO,
                    ExecutionBlockHash::ZERO,
                ),
            )
            .unwrap();

        let a_root = Root::repeat_byte(2);
        let a_slot = 1;
        store
            .insert_signed_block(
                a_root,
                gloas_block(
                    a_slot,
                    anchor_root,
                    // Does not match the anchor's own (zero) block hash, so
                    // `a_root` builds on the anchor's empty branch.
                    ExecutionBlockHash::repeat_byte(0xff),
                    ExecutionBlockHash::repeat_byte(0xaa),
                ),
            )
            .unwrap();
        verify_payload(&mut store, a_root);

        let state = test_state::with_validators_at(ForkName::Gloas, 4);
        store.insert_state(anchor_root, state.clone()).unwrap();
        store.insert_state(a_root, state).unwrap();

        // Past `a_root`'s own slot, but not by exactly one:
        // `is_previous_slot_payload_decision` would otherwise zero both
        // branches' weight and leave only the tiebreaker to decide, which is
        // not what this test exercises.
        store.set_time_ms(3 * config.slot_duration_ms).unwrap();

        // Three of four votes go to the empty branch, whose own tiebreaker
        // value (`PayloadStatus::Empty as u8 == 0`) is *lower* than full's
        // (`PayloadStatus::Full as u8 == 1`): a descent that ignored weight
        // and fell back on the tiebreaker alone would pick full here, so
        // this only passes if weight actually decides.
        for validator_index in 0..3 {
            store.set_latest_message(
                validator_index,
                LatestMessage {
                    epoch: 0,
                    slot: a_slot + 1,
                    root: a_root,
                    payload_present: false,
                },
            );
        }
        store.set_latest_message(
            3,
            LatestMessage {
                epoch: 0,
                slot: a_slot + 1,
                root: a_root,
                payload_present: true,
            },
        );

        let committees = CommitteeCache::default();
        let head = gloas_get_head(&store, &config, &committees).expect("known chain");
        assert_eq!(
            head,
            ForkChoiceNode {
                root: a_root,
                payload_status: PayloadStatus::Empty,
            },
            "three of four votes for the empty branch must outweigh the lone \
             vote for full, despite full's higher tiebreak value"
        );
    }

    /// `should_apply_proposer_boost`'s own blocks need no gloas bid at all
    /// (it never calls `gloas_bid`/`get_parent_payload_status`), so the
    /// plain phase0-shaped `block`/`block_with_proposer` helpers serve here.
    #[test]
    fn should_apply_proposer_boost_is_withheld_only_by_an_early_equivocation() {
        let config = Config::active();
        let (mut store, anchor_root, anchor_slot) = anchored_store(1);
        let committees = CommitteeCache::default();

        let b_root = Root::repeat_byte(0xb0);
        store
            .insert_signed_block(b_root, block(anchor_slot + 1, anchor_root))
            .unwrap();
        store.set_proposer_boost_root(b_root);

        // No votes recorded at all, so the parent (the anchor) is trivially
        // weak, per the same reading `is_head_weak_counts_an_equivocating_
        // validators_balance_from_the_head_slot_committees` gives "a head
        // with no votes and no equivocators must be weak". The parent is
        // also exactly one slot behind `b_root`. Neither of
        // `should_apply_proposer_boost`'s two early-return conditions fires,
        // so both checks below reach the equivocation scan.
        assert!(
            should_apply_proposer_boost(&store, &config, &committees).unwrap(),
            "no same-slot, same-proposer, PTC-timely sibling of the parent \
             exists yet, so the boost still applies"
        );

        // A same-slot sibling of the parent, sharing its proposer (both
        // default to index 0) and PTC-timely, is an early equivocation.
        let twin_root = Root::repeat_byte(0xb1);
        store
            .insert_signed_block(twin_root, block(anchor_slot, Root::ZERO))
            .unwrap();
        store.set_block_timeliness(twin_root, [false, true]);

        assert!(
            !should_apply_proposer_boost(&store, &config, &committees).unwrap(),
            "an early equivocation against the parent must withhold the boost"
        );
    }

    // ------------------------------------------------------------------
    // Gloas: the fulu-to-gloas boundary
    // ------------------------------------------------------------------
    //
    // A pre-gloas block is a single-variant node whose payload status is
    // always FULL: its payload ran inside the block, with no separate empty
    // branch to weigh against. The tests below exercise that rule at each of
    // its entry points (`get_parent_payload_status`, `get_node_children`,
    // `gloas_get_ancestor`, `get_supported_node`) and at the two places that
    // compose them (`gloas_get_head`, `get_head_node`'s own dispatch).

    #[test]
    fn mixed_tree_treats_the_fulu_prefix_as_a_single_full_node_at_every_gloas_entry_point() {
        let mut store = empty_store();

        let anchor_root = Root::repeat_byte(0xa0);
        store
            .insert_signed_block(anchor_root, fulu_block(0, Root::ZERO))
            .unwrap();

        let fulu_root = Root::repeat_byte(0xf1);
        store
            .insert_signed_block(fulu_root, fulu_block(1, anchor_root))
            .unwrap();

        // Its own bid never matters to whether it counts as fulu_root's
        // child: a pre-gloas parent is FULL regardless of what a gloas
        // child's bid claims about it.
        let gloas_root = Root::repeat_byte(0x90);
        store
            .insert_signed_block(
                gloas_root,
                gloas_block(
                    2,
                    fulu_root,
                    ExecutionBlockHash::repeat_byte(0xff),
                    ExecutionBlockHash::repeat_byte(0x99),
                ),
            )
            .unwrap();
        let gloas_block_value = store.get_signed_block(&gloas_root).unwrap().unwrap();

        assert_eq!(
            get_parent_payload_status(&store, &gloas_block_value).unwrap(),
            PayloadStatus::Full,
            "the first gloas block's fulu parent is a single-variant FULL node"
        );

        let blocks = store.block_index();
        let pending_fulu = ForkChoiceNode {
            root: fulu_root,
            payload_status: PayloadStatus::Pending,
        };
        assert_eq!(
            get_node_children(&store, &blocks, pending_fulu).unwrap(),
            vec![ForkChoiceNode {
                root: fulu_root,
                payload_status: PayloadStatus::Full,
            }],
            "a fulu block's only child node is its own FULL node, with no \
             empty branch and no dependency on a verified payload"
        );

        let start = ForkChoiceNode {
            root: gloas_root,
            payload_status: PayloadStatus::Pending,
        };
        assert_eq!(
            gloas_get_ancestor(&store, start, 1).unwrap(),
            ForkChoiceNode {
                root: fulu_root,
                payload_status: PayloadStatus::Full,
            },
            "stepping from a gloas node onto a pre-gloas block lands on its \
             FULL node rather than erroring"
        );
    }

    #[test]
    fn get_supported_node_counts_a_pre_gloas_vote_toward_its_full_node() {
        let mut store = empty_store();
        let a_root = Root::repeat_byte(0xa1);
        store
            .insert_signed_block(a_root, fulu_block(1, Root::ZERO))
            .unwrap();

        let message = LatestMessage {
            epoch: 0,
            slot: 2,
            root: a_root,
            // Every real pre-gloas attestation leaves this `false`: there is
            // no payload dimension to vote on before gloas.
            payload_present: false,
        };

        assert_eq!(
            get_supported_node(&store, message).unwrap(),
            ForkChoiceNode {
                root: a_root,
                payload_status: PayloadStatus::Full,
            },
            "a vote for a pre-gloas block supports its single FULL node, \
             whatever payload_present carries"
        );
    }

    #[test]
    fn gloas_get_head_descends_from_a_fulu_justified_root_through_the_boundary_to_the_heaviest_gloas_branch()
     {
        let config = Config::active();
        let anchor_root = Root::repeat_byte(0xa0);
        let mut store = store_anchored_at(anchor_root);
        store
            .insert_signed_block(anchor_root, fulu_block(0, Root::ZERO))
            .unwrap();
        let state = test_state::with_validators_at(ForkName::Fulu, 4);
        store.insert_state(anchor_root, state.clone()).unwrap();

        // Two gloas children of the fulu anchor: both are its FULL children
        // regardless of their own bid, since a pre-gloas parent is always
        // FULL.
        let heavy_root = Root::repeat_byte(0x91);
        store
            .insert_signed_block(
                heavy_root,
                gloas_block(
                    1,
                    anchor_root,
                    ExecutionBlockHash::repeat_byte(0xff),
                    ExecutionBlockHash::repeat_byte(0xaa),
                ),
            )
            .unwrap();
        store.insert_state(heavy_root, state.clone()).unwrap();

        let light_root = Root::repeat_byte(0x92);
        store
            .insert_signed_block(
                light_root,
                gloas_block(
                    1,
                    anchor_root,
                    ExecutionBlockHash::repeat_byte(0xff),
                    ExecutionBlockHash::repeat_byte(0xbb),
                ),
            )
            .unwrap();
        store.insert_state(light_root, state).unwrap();
        store.set_time_ms(2 * config.slot_duration_ms).unwrap();

        // Three votes for the heavier branch, one for the lighter. Neither
        // payload is verified, so once a branch is picked it offers only its
        // empty node next, and only the vote weight decides which branch
        // wins.
        for validator_index in 0..3 {
            store.set_latest_message(
                validator_index,
                LatestMessage {
                    epoch: 0,
                    slot: 2,
                    root: heavy_root,
                    payload_present: false,
                },
            );
        }
        store.set_latest_message(
            3,
            LatestMessage {
                epoch: 0,
                slot: 2,
                root: light_root,
                payload_present: false,
            },
        );

        let committees = CommitteeCache::default();
        let head = gloas_get_head(&store, &config, &committees).expect("known chain");
        assert_eq!(
            head,
            ForkChoiceNode {
                root: heavy_root,
                payload_status: PayloadStatus::Empty,
            },
            "the walk must cross the fulu anchor and pick the heavier gloas \
             branch"
        );
    }

    #[test]
    fn get_head_node_switches_from_the_pre_gloas_algorithm_to_gloas_at_the_fork_epoch() {
        let gloas_fork_epoch = 1;
        let config = Config::active().with_fork_epoch(ForkName::Gloas, gloas_fork_epoch);
        let first_gloas_slot = compute_start_slot_at_epoch(gloas_fork_epoch);

        let anchor_root = Root::repeat_byte(0xa0);
        let mut store = store_anchored_at(anchor_root);
        store
            .insert_signed_block(anchor_root, fulu_block(0, Root::ZERO))
            .unwrap();
        let state = test_state::with_validators_at(ForkName::Fulu, 1);
        store.insert_state(anchor_root, state.clone()).unwrap();

        // An unverified gloas block: gloas's own algorithm only ever offers
        // its EMPTY node as a candidate for one, while the pre-gloas
        // algorithm has no payload dimension at all and treats it as a
        // single, opaque, always-full root.
        let b_root = Root::repeat_byte(0xb0);
        store
            .insert_signed_block(
                b_root,
                gloas_block(
                    first_gloas_slot,
                    anchor_root,
                    ExecutionBlockHash::ZERO,
                    ExecutionBlockHash::repeat_byte(0xbb),
                ),
            )
            .unwrap();
        store.insert_state(b_root, state).unwrap();
        store.set_unrealized_justification(b_root, Checkpoint::default());

        store
            .set_time_ms((first_gloas_slot - 1) * config.slot_duration_ms)
            .unwrap();
        assert_eq!(
            get_head_node(&store, &config).unwrap(),
            ForkChoiceNode {
                root: b_root,
                payload_status: PayloadStatus::Full,
            },
            "one slot before the fork epoch, the pre-gloas algorithm still \
             runs and reports the gloas block as a single, full root"
        );

        store
            .set_time_ms(first_gloas_slot * config.slot_duration_ms)
            .unwrap();
        assert_eq!(
            get_head_node(&store, &config).unwrap(),
            ForkChoiceNode {
                root: b_root,
                payload_status: PayloadStatus::Empty,
            },
            "at its first slot, gloas's own algorithm takes over, and the \
             unverified payload leaves only the empty branch"
        );
    }

    /// The complement of `gloas_get_head_picks_the_more_heavily_voted_
    /// payload_branch`'s 3-empty/1-full case: a `get_supported_node` that
    /// ignored `payload_present` entirely (reading every vote below the
    /// block's own slot as empty) would send all four votes here to empty
    /// too, and empty would win instead of full.
    #[test]
    fn gloas_get_head_picks_full_when_it_has_the_greater_vote_weight() {
        let config = Config::active();
        let anchor_root = Root::repeat_byte(1);
        let mut store = store_anchored_at(anchor_root);
        store
            .insert_signed_block(
                anchor_root,
                gloas_block(
                    0,
                    Root::ZERO,
                    ExecutionBlockHash::ZERO,
                    ExecutionBlockHash::ZERO,
                ),
            )
            .unwrap();

        let a_root = Root::repeat_byte(2);
        let a_slot = 1;
        store
            .insert_signed_block(
                a_root,
                gloas_block(
                    a_slot,
                    anchor_root,
                    ExecutionBlockHash::repeat_byte(0xff),
                    ExecutionBlockHash::repeat_byte(0xaa),
                ),
            )
            .unwrap();
        verify_payload(&mut store, a_root);

        let state = test_state::with_validators_at(ForkName::Gloas, 4);
        store.insert_state(anchor_root, state.clone()).unwrap();
        store.insert_state(a_root, state).unwrap();

        // Past `a_root`'s own slot, but not by exactly one, so weight (not
        // the tiebreaker) decides.
        store.set_time_ms(3 * config.slot_duration_ms).unwrap();

        // Three of four votes go to the full branch, one to the empty
        // branch.
        for validator_index in 0..3 {
            store.set_latest_message(
                validator_index,
                LatestMessage {
                    epoch: 0,
                    slot: a_slot + 1,
                    root: a_root,
                    payload_present: true,
                },
            );
        }
        store.set_latest_message(
            3,
            LatestMessage {
                epoch: 0,
                slot: a_slot + 1,
                root: a_root,
                payload_present: false,
            },
        );

        let committees = CommitteeCache::default();
        let head = gloas_get_head(&store, &config, &committees).expect("known chain");
        assert_eq!(
            head,
            ForkChoiceNode {
                root: a_root,
                payload_status: PayloadStatus::Full,
            },
            "three of four votes for the full branch must outweigh the lone \
             vote for empty"
        );
    }

    #[test]
    fn should_apply_proposer_boost_applies_when_the_parent_is_not_from_the_previous_slot() {
        let config = Config::active();
        let (mut store, anchor_root, anchor_slot) = anchored_store(1);
        let committees = CommitteeCache::default();

        // Two slots ahead of the parent, not one: the first early return
        // fires before `is_head_weak` is ever consulted.
        let b_root = Root::repeat_byte(0xb0);
        store
            .insert_signed_block(b_root, block(anchor_slot + 2, anchor_root))
            .unwrap();
        store.set_proposer_boost_root(b_root);

        // Plant an equivocation the equivocation scan would find, were the
        // first early return missing: with no votes at all, the parent is
        // otherwise trivially weak (falling through to that scan), and a
        // same-proposer, PTC-timely block at `anchor_slot + 1` (one slot
        // behind `b_root`) matches its own condition.
        let poison_root = Root::repeat_byte(0xb2);
        store
            .insert_signed_block(poison_root, block(anchor_slot + 1, Root::ZERO))
            .unwrap();
        store.set_block_timeliness(poison_root, [false, true]);

        assert!(
            should_apply_proposer_boost(&store, &config, &committees).unwrap(),
            "a parent more than one slot behind the boosted block always \
             keeps the boost, even with an equivocation in place that would \
             otherwise withhold it"
        );
    }

    #[test]
    fn should_apply_proposer_boost_applies_when_the_parent_is_not_weak() {
        let config = Config::active();
        let (mut store, anchor_root, anchor_slot) =
            anchored_store(preset::SLOTS_PER_EPOCH as usize);
        let committees = CommitteeCache::default();

        let b_root = Root::repeat_byte(0xb0);
        store
            .insert_signed_block(b_root, block(anchor_slot + 1, anchor_root))
            .unwrap();
        store.set_proposer_boost_root(b_root);

        // A single committee member's vote for the parent (the anchor) is
        // already enough to clear the reorg threshold, the same reading
        // `is_head_weak_counts_an_equivocating_validators_balance_from_the_
        // head_slot_committees` relies on for its own equivocator.
        store.set_latest_message(
            0,
            LatestMessage {
                epoch: 0,
                slot: anchor_slot,
                root: anchor_root,
                payload_present: false,
            },
        );

        // Also plant a same-slot, same-proposer, PTC-timely sibling of the
        // parent: were the "parent is not weak" early return missing, the
        // equivocation scan below would find this sibling and withhold the
        // boost, flipping the assertion below.
        let twin_root = Root::repeat_byte(0xb1);
        store
            .insert_signed_block(twin_root, block(anchor_slot, Root::ZERO))
            .unwrap();
        store.set_block_timeliness(twin_root, [false, true]);

        assert!(
            should_apply_proposer_boost(&store, &config, &committees).unwrap(),
            "a parent with enough votes to not be weak keeps the boost \
             without ever reaching the equivocation scan"
        );
    }

    #[test]
    fn should_apply_proposer_boost_still_applies_against_a_same_slot_sibling_from_a_different_proposer()
     {
        let config = Config::active();
        let (mut store, anchor_root, anchor_slot) = anchored_store(1);
        let committees = CommitteeCache::default();

        let b_root = Root::repeat_byte(0xb0);
        store
            .insert_signed_block(b_root, block(anchor_slot + 1, anchor_root))
            .unwrap();
        store.set_proposer_boost_root(b_root);

        // A same-slot sibling of the parent, PTC-timely, but proposed by a
        // different validator than the parent's own (default) proposer: not
        // an equivocation, since that requires the same proposer, so the
        // boost still applies.
        let twin_root = Root::repeat_byte(0xb1);
        store
            .insert_signed_block(twin_root, block_with_proposer(anchor_slot, Root::ZERO, 1))
            .unwrap();
        store.set_block_timeliness(twin_root, [false, true]);

        assert!(
            should_apply_proposer_boost(&store, &config, &committees).unwrap(),
            "a same-slot sibling from a different proposer is not an \
             equivocation, so the boost still applies"
        );
    }

    #[test]
    fn is_payload_verified_is_true_for_a_fulu_root() {
        let mut store = empty_store();
        let a_root = Root::repeat_byte(0xa1);
        store
            .insert_signed_block(a_root, fulu_block(1, Root::ZERO))
            .unwrap();

        assert!(
            is_payload_verified(&store, a_root),
            "a pre-gloas block's payload ran inside the block itself, with \
             no separate envelope left to verify"
        );
    }

    #[test]
    fn a_pre_gloas_root_reads_its_own_validity_as_a_payload_status() {
        let mut store = empty_store();
        let root = Root::repeat_byte(0xa1);
        store
            .insert_signed_block(root, fulu_block(1, Root::ZERO))
            .unwrap();
        assert_eq!(block_payload_status(&store, root), PayloadStatusEnum::Valid);

        store.insert_beacon_optimistic_root(root, 1);
        assert_eq!(
            block_payload_status(&store, root),
            PayloadStatusEnum::Syncing
        );
    }

    #[test]
    fn a_root_with_no_recorded_verdict_is_not_validated() {
        let store = empty_store();
        assert!(
            block_payload_status(&store, Root::repeat_byte(0xee)).is_not_validated(),
            "the specification's default for a root absent from the map"
        );
    }

    #[test]
    fn is_payload_verified_is_false_for_an_unknown_root() {
        let store = empty_store();
        assert!(
            !is_payload_verified(&store, Root::repeat_byte(0xff)),
            "a root this store has never heard of must not be assumed \
             pre-gloas and so already verified"
        );
    }

    #[test]
    fn should_build_on_full_and_should_extend_payload_answer_without_error_for_a_previous_slot_pre_gloas_head()
     {
        let config = Config::active();
        let mut store = empty_store();
        let a_root = Root::repeat_byte(0xa1);
        let a_slot = 1;
        store
            .insert_signed_block(a_root, fulu_block(a_slot, Root::ZERO))
            .unwrap();
        store
            .set_time_ms((a_slot + 1) * config.slot_duration_ms)
            .unwrap();

        // `head` carries this crate's own decided status for a pre-gloas
        // block (Full), per `get_head_node`'s pre-gloas arm.
        let head = ForkChoiceNode {
            root: a_root,
            payload_status: PayloadStatus::Full,
        };
        assert!(
            should_build_on_full(&store, head, a_slot + 1).unwrap(),
            "a pre-gloas head is always FULL and its payload always \
             verified, timely and available, so a proposer one slot later \
             must build on full"
        );
        assert!(
            should_extend_payload(&store, a_root, &config).unwrap(),
            "a pre-gloas payload is always considered verified, timely and \
             available, so it must always be extended"
        );
    }

    /// The gloas-side counterpart of `a_vote_for_a_pruned_block_weighs_
    /// nothing_instead_of_failing`: a stale voter's last message can name a
    /// root pruned below the retained window on a live gloas chain too, and
    /// `gloas_get_attestation_score` must skip it rather than abort the
    /// whole weight computation.
    #[test]
    fn a_gloas_vote_for_a_root_not_in_the_store_weighs_nothing_instead_of_failing() {
        let config = Config::active();
        let anchor_root = Root::repeat_byte(1);
        let mut store = store_anchored_at(anchor_root);
        store
            .insert_signed_block(
                anchor_root,
                gloas_block(
                    0,
                    Root::ZERO,
                    ExecutionBlockHash::ZERO,
                    ExecutionBlockHash::ZERO,
                ),
            )
            .unwrap();

        let a_root = Root::repeat_byte(2);
        let a_slot = 1;
        store
            .insert_signed_block(
                a_root,
                gloas_block(
                    a_slot,
                    anchor_root,
                    ExecutionBlockHash::repeat_byte(0xff),
                    ExecutionBlockHash::repeat_byte(0xaa),
                ),
            )
            .unwrap();

        let state = test_state::with_validators_at(ForkName::Gloas, 2);
        store.insert_state(anchor_root, state.clone()).unwrap();
        store.insert_state(a_root, state).unwrap();
        store.set_time_ms(3 * config.slot_duration_ms).unwrap();

        // A live vote for `a_root`.
        store.set_latest_message(
            0,
            LatestMessage {
                epoch: 0,
                slot: a_slot + 1,
                root: a_root,
                payload_present: false,
            },
        );
        // A vote for a root the store never indexed at all (pruned below
        // the retained window).
        store.set_latest_message(
            1,
            LatestMessage {
                epoch: 0,
                slot: a_slot + 1,
                root: Root::repeat_byte(0xde),
                payload_present: false,
            },
        );

        let committees = CommitteeCache::default();
        let node = ForkChoiceNode {
            root: a_root,
            payload_status: PayloadStatus::Empty,
        };
        let weight = gloas_get_weight(&store, node, &config, &committees)
            .expect("a vote for a root not in the store must not be fatal");
        assert!(weight > 0, "the live vote still counts");
    }

    #[test]
    fn should_apply_proposer_boost_reads_a_missing_block_timeliness_entry_as_not_timely() {
        let config = Config::active();
        let (mut store, anchor_root, anchor_slot) = anchored_store(1);
        let committees = CommitteeCache::default();

        let b_root = Root::repeat_byte(0xb0);
        store
            .insert_signed_block(b_root, block(anchor_slot + 1, anchor_root))
            .unwrap();
        store.set_proposer_boost_root(b_root);

        // A same-slot, same-proposer sibling of the parent that would be an
        // early equivocation if its timeliness were known, but whose
        // `block_timeliness` entry was never recorded. Deliberately no
        // `store.set_block_timeliness(twin_root, ...)` call.
        let twin_root = Root::repeat_byte(0xb1);
        store
            .insert_signed_block(twin_root, block(anchor_slot, Root::ZERO))
            .unwrap();

        assert!(
            should_apply_proposer_boost(&store, &config, &committees).unwrap(),
            "a same-slot, same-proposer sibling with no recorded \
             timeliness must read as not timely, so it is not treated as \
             an equivocation and the boost still applies"
        );
    }

    /// The direct case `get_attestation_score`'s own doc describes: a pruned
    /// vote must not abort `is_head_weak`, which shares this function with
    /// [`get_weight`] and, through `should_apply_proposer_boost`, with
    /// [`gloas_get_weight`] too.
    #[test]
    fn is_head_weak_succeeds_with_a_pruned_vote() {
        let config = Config::active();
        let (mut store, anchor_root, _anchor_slot) =
            anchored_store(preset::SLOTS_PER_EPOCH as usize);
        let committees = CommitteeCache::default();

        // A vote for a root the store never indexed at all (pruned below
        // the retained window).
        store.set_latest_message(
            0,
            LatestMessage {
                epoch: 0,
                slot: 0,
                root: Root::repeat_byte(0xde),
                payload_present: false,
            },
        );

        assert!(
            is_head_weak(&store, anchor_root, &config, &committees).is_ok(),
            "a pruned vote must not abort is_head_weak"
        );
    }

    /// A vote for a block that is still indexed, on a branch whose parent the
    /// index no longer holds: the ancestor walk leaves the index part-way
    /// down, which must contribute nothing rather than abort `is_head_weak`.
    #[test]
    fn is_head_weak_succeeds_when_a_vote_walks_onto_a_pruned_parent() {
        let config = Config::active();
        let (mut store, anchor_root, anchor_slot) =
            anchored_store(preset::SLOTS_PER_EPOCH as usize);
        let committees = CommitteeCache::default();

        let orphan_root = Root::repeat_byte(0xd1);
        store
            .insert_signed_block(orphan_root, block(anchor_slot + 1, Root::repeat_byte(0xd0)))
            .unwrap();
        store.set_latest_message(
            0,
            LatestMessage {
                epoch: 0,
                slot: anchor_slot + 1,
                root: orphan_root,
                payload_present: false,
            },
        );

        assert!(
            is_head_weak(&store, anchor_root, &config, &committees).is_ok(),
            "a vote whose ancestor walk meets a pruned parent must not abort is_head_weak"
        );
    }

    /// `gloas_get_weight` reaches pre-gloas `get_attestation_score` too, not
    /// only its own `gloas_get_attestation_score`: it calls
    /// `should_apply_proposer_boost` on every node it weighs, which calls
    /// `is_head_weak` whenever the boosted block's parent is from the
    /// previous slot, the ordinary case rather than a corner one. A pruned
    /// vote reached that way must not abort `gloas_get_weight` or
    /// `gloas_get_head` either.
    #[test]
    fn gloas_get_weight_tolerates_a_pruned_vote_reached_through_should_apply_proposer_boost() {
        let config = Config::active();
        let (mut store, anchor_root, anchor_slot) =
            anchored_store(preset::SLOTS_PER_EPOCH as usize);
        let committees = CommitteeCache::default();

        let b_root = Root::repeat_byte(0xb0);
        store
            .insert_signed_block(b_root, block(anchor_slot + 1, anchor_root))
            .unwrap();
        store
            .insert_state(
                b_root,
                test_state::with_validators(preset::SLOTS_PER_EPOCH as usize),
            )
            .unwrap();
        store.set_unrealized_justification(b_root, Checkpoint::default());
        store.set_proposer_boost_root(b_root);

        // No votes for the anchor (the boosted block's parent, one slot
        // behind it) except a pruned one, so it is trivially weak, the same
        // reading `is_head_weak_counts_an_equivocating_validators_balance_
        // from_the_head_slot_committees` gives, and `should_apply_proposer_
        // boost` reaches `is_head_weak(anchor_root)`.
        store.set_latest_message(
            0,
            LatestMessage {
                epoch: 0,
                slot: 0,
                root: Root::repeat_byte(0xde),
                payload_present: false,
            },
        );

        let node = ForkChoiceNode {
            root: b_root,
            payload_status: PayloadStatus::Full,
        };
        gloas_get_weight(&store, node, &config, &committees)
            .expect("a pruned vote reached through should_apply_proposer_boost must not be fatal");
        gloas_get_head(&store, &config, &committees)
            .expect("the same tolerance must hold through the whole head walk");
    }

    // -----------------------------------------------------------------------
    // Gloas handlers
    // -----------------------------------------------------------------------

    const UNVERIFIED_PAYLOAD_PARENT: &str = "is_payload_verified(store, block.parent_root)";

    /// The message of the specification assertion `result` failed, or `None`
    /// if it succeeded or failed some other way. `Error` has no `PartialEq`,
    /// and what these tests pin is which assertion fired.
    fn failed_assertion<T>(result: Result<T>) -> Option<&'static str> {
        match result {
            Err(Error::SpecAssert(what)) => Some(what),
            _ => None,
        }
    }

    #[test]
    fn on_block_rejects_a_block_built_on_a_full_parent_whose_payload_is_unverified() {
        let config = Config::active().with_fork_epoch(ForkName::Gloas, 0);
        let anchor_root = Root::repeat_byte(0xa1);
        let anchor_hash = ExecutionBlockHash::repeat_byte(0x11);
        let mut store = store_anchored_at(anchor_root);
        store
            .insert_signed_block(
                anchor_root,
                gloas_block(0, Root::ZERO, ExecutionBlockHash::ZERO, anchor_hash),
            )
            .unwrap();
        store
            .insert_state(
                anchor_root,
                test_state::with_validators_at(ForkName::Gloas, 1),
            )
            .unwrap();
        store.set_time_ms(2 * config.slot_duration_ms).unwrap();

        let import = |store: &mut Store, block: SignedBeaconBlock| {
            on_block(
                store,
                block,
                &config,
                &DataAvailability::NotRequired,
                &PayloadValidity::NotRequired,
                &CommitteeCache::default(),
            )
        };

        // Names the anchor's own block hash as its parent's, so it builds on
        // the anchor's full branch.
        let full_child = gloas_block(
            1,
            anchor_root,
            anchor_hash,
            ExecutionBlockHash::repeat_byte(0x22),
        );
        let full_child_root = full_child.message_hash_tree_root();
        assert_eq!(
            failed_assertion(import(&mut store, full_child.clone())),
            Some(UNVERIFIED_PAYLOAD_PARENT),
            "a full parent whose envelope was never verified must fail the import"
        );
        assert!(
            !store.has_state(&full_child_root).unwrap(),
            "a rejected block leaves no post-state behind"
        );

        // A block on the empty branch needs no envelope, so it gets past this
        // check (and fails later, on the empty body it carries).
        let empty_child = gloas_block(
            1,
            anchor_root,
            ExecutionBlockHash::repeat_byte(0xee),
            ExecutionBlockHash::repeat_byte(0x33),
        );
        let rejected = import(&mut store, empty_child);
        assert!(rejected.is_err());
        assert_ne!(failed_assertion(rejected), Some(UNVERIFIED_PAYLOAD_PARENT));

        // Once the envelope is verified the full child clears the check too.
        verify_payload(&mut store, anchor_root);
        let rejected = import(&mut store, full_child);
        assert!(rejected.is_err());
        assert_ne!(failed_assertion(rejected), Some(UNVERIFIED_PAYLOAD_PARENT));
    }

    fn gloas_attestation_data(slot: Slot, index: u64, root: Root, target: Root) -> AttestationData {
        AttestationData {
            slot,
            index,
            beacon_block_root: root,
            source: Checkpoint::default(),
            target: Checkpoint {
                epoch: 0,
                root: target,
            },
        }
    }

    #[test]
    fn validate_on_attestation_applies_the_gloas_index_rules_only_to_a_gloas_attestation() {
        let config = Config::active().with_fork_epoch(ForkName::Gloas, 0);
        let anchor_root = Root::repeat_byte(0xa1);
        let b_root = Root::repeat_byte(0xb1);
        let mut store = store_anchored_at(anchor_root);
        store
            .insert_signed_block(
                anchor_root,
                gloas_block(
                    0,
                    Root::ZERO,
                    ExecutionBlockHash::ZERO,
                    ExecutionBlockHash::repeat_byte(0x11),
                ),
            )
            .unwrap();
        store
            .insert_signed_block(
                b_root,
                gloas_block(
                    1,
                    anchor_root,
                    ExecutionBlockHash::repeat_byte(0x11),
                    ExecutionBlockHash::repeat_byte(0x22),
                ),
            )
            .unwrap();
        store.set_time_ms(4 * config.slot_duration_ms).unwrap();

        let vote =
            |slot: Slot, index: u64| gloas_attestation_data(slot, index, b_root, anchor_root);

        // `index` is the payload flag: 0 and 1 only.
        let validate = |store: &Store, data: AttestationData, rules: ForkRules| {
            validate_on_attestation(store, data, rules, true, &config)
        };
        assert!(validate(&store, vote(2, 0), ForkRules::Gloas).is_ok());
        assert_eq!(
            failed_assertion(validate(&store, vote(2, 2), ForkRules::Gloas)),
            Some("attestation.data.index in [0, 1]")
        );
        // A vote in the block's own slot cannot name the full branch: the
        // payload is revealed after the block.
        assert_eq!(
            failed_assertion(validate(&store, vote(1, 1), ForkRules::Gloas)),
            Some("attestation.data.index == 0 for a same-slot vote")
        );
        // A later vote for the full branch needs the payload to be verified.
        assert_eq!(
            failed_assertion(validate(&store, vote(2, 1), ForkRules::Gloas)),
            Some("is_payload_verified(store, attestation.data.beacon_block_root)")
        );
        // The same attestations before gloas have no such rules.
        assert!(validate(&store, vote(2, 1), ForkRules::PreGloas).is_ok());
        assert!(validate(&store, vote(2, 2), ForkRules::PreGloas).is_ok());

        verify_payload(&mut store, b_root);
        assert!(validate(&store, vote(2, 1), ForkRules::Gloas).is_ok());
    }

    #[test]
    fn update_latest_messages_orders_gloas_votes_by_slot_and_records_the_payload_flag() {
        let root = Root::repeat_byte(0xb1);
        let mut store = empty_store();
        let vote = |slot: Slot, index: u64| gloas_attestation_data(slot, index, root, root);

        update_latest_messages(&mut store, &[0], vote(5, 0), ForkRules::Gloas);
        // Same target epoch, later slot: gloas replaces it, since it orders by
        // slot, and records that the vote is for the full branch.
        update_latest_messages(&mut store, &[0], vote(6, 1), ForkRules::Gloas);
        let message = store.latest_message(0).unwrap();
        assert_eq!((message.slot, message.payload_present), (6, true));
        // An earlier slot never replaces a later one.
        update_latest_messages(&mut store, &[0], vote(4, 0), ForkRules::Gloas);
        assert_eq!(store.latest_message(0).unwrap().slot, 6);

        // Before gloas the same pair of votes shares a target epoch, so the
        // second does not replace the first, and no vote is for a full branch.
        update_latest_messages(&mut store, &[1], vote(5, 0), ForkRules::PreGloas);
        update_latest_messages(&mut store, &[1], vote(6, 1), ForkRules::PreGloas);
        let message = store.latest_message(1).unwrap();
        assert_eq!((message.slot, message.payload_present), (5, false));

        // An equivocator's vote is dropped under either set of rules.
        store.insert_equivocating_index(2);
        for rules in [ForkRules::Gloas, ForkRules::PreGloas] {
            update_latest_messages(&mut store, &[2], vote(5, 0), rules);
            assert_eq!(store.latest_message(2), None);
        }
    }

    /// A store holding a gloas block at slot 1 whose state seats validator 3
    /// twice in the slot's committee (every other seat is validator 0), with
    /// empty vote vectors.
    fn payload_attestation_store(root: Root) -> Store {
        let mut store = store_anchored_at(root);
        store
            .insert_signed_block(
                root,
                gloas_block(
                    1,
                    Root::ZERO,
                    ExecutionBlockHash::ZERO,
                    ExecutionBlockHash::repeat_byte(0x22),
                ),
            )
            .unwrap();

        // The committee for slot 1 in a state at slot 1 is the window entry
        // `get_ptc` reads one epoch of slots in. Validator 3 is seated twice
        // and every other seat is validator 0.
        let mut state = test_state::with_validators_at(ForkName::Gloas, 4);
        let BeaconState::Gloas(inner) = &mut state else {
            unreachable!("with_validators_at(Gloas) builds a gloas state");
        };
        inner.slot = 1;
        let mut committee = vec![0; preset::PTC_SIZE];
        committee[2] = 3;
        committee[7] = 3;
        let window_index = (preset::SLOTS_PER_EPOCH + 1) as usize;
        inner.ptc_window[window_index] = committee.try_into().unwrap();
        store.insert_state(root, state).unwrap();
        store.set_payload_timeliness_vote(root, vec![None; preset::PTC_SIZE]);
        store.set_payload_data_availability_vote(root, vec![None; preset::PTC_SIZE]);
        store
    }

    #[test]
    fn on_payload_attestation_message_writes_every_seat_the_validator_holds() {
        let config = Config::active().with_fork_epoch(ForkName::Gloas, 0);
        let root = Root::repeat_byte(0xb1);
        let mut store = payload_attestation_store(root);

        let message = |validator_index: u64, slot: Slot| gloas::PayloadAttestationMessage {
            validator_index,
            data: gloas::PayloadAttestationData {
                beacon_block_root: root,
                slot,
                payload_present: true,
                blob_data_available: false,
            },
            signature: Default::default(),
        };
        let seats = |votes: Vec<Option<bool>>| -> Vec<(usize, bool)> {
            votes
                .into_iter()
                .enumerate()
                .filter_map(|(seat, vote)| vote.map(|vote| (seat, vote)))
                .collect()
        };

        // A vote for a slot other than the block's own changes nothing.
        on_payload_attestation_message(&mut store, &message(3, 2), true, &config).unwrap();
        assert!(seats(store.payload_timeliness_vote(&root).unwrap()).is_empty());

        // A validator outside the committee is rejected, and writes nothing.
        assert_eq!(
            failed_assertion(on_payload_attestation_message(
                &mut store,
                &message(2, 1),
                true,
                &config
            )),
            Some("len(ptc_indices) > 0")
        );
        assert!(seats(store.payload_timeliness_vote(&root).unwrap()).is_empty());

        // Both seats of validator 3 receive both answers.
        on_payload_attestation_message(&mut store, &message(3, 1), true, &config).unwrap();
        assert_eq!(
            seats(store.payload_timeliness_vote(&root).unwrap()),
            vec![(2, true), (7, true)]
        );
        assert_eq!(
            seats(store.payload_data_availability_vote(&root).unwrap()),
            vec![(2, false), (7, false)]
        );
    }

    fn payload_attestation_message(
        root: Root,
        validator_index: u64,
        slot: Slot,
    ) -> gloas::PayloadAttestationMessage {
        gloas::PayloadAttestationMessage {
            validator_index,
            data: gloas::PayloadAttestationData {
                beacon_block_root: root,
                slot,
                payload_present: true,
                blob_data_available: true,
            },
            signature: Default::default(),
        }
    }

    /// A gossip-verified vote is applied to every seat of its validator
    /// without a signature check (the zero signature here would fail one),
    /// but still only in the slot it is for, and only from a committee member.
    #[test]
    fn apply_verified_payload_attestation_skips_the_signature_but_not_the_slot() {
        let config = Config::active().with_fork_epoch(ForkName::Gloas, 0);
        let root = Root::repeat_byte(0xb1);
        let mut store = payload_attestation_store(root);
        let seated = |store: &Store| -> Vec<usize> {
            store
                .payload_timeliness_vote(&root)
                .unwrap()
                .iter()
                .enumerate()
                .filter_map(|(seat, vote)| vote.map(|_| seat))
                .collect()
        };

        // The store clock reads slot 0: a vote for slot 1 is not current yet.
        assert_eq!(
            failed_assertion(apply_verified_payload_attestation(
                &mut store,
                &payload_attestation_message(root, 3, 1),
                &config
            )),
            Some("data.slot == get_current_slot(store)")
        );
        assert!(seated(&store).is_empty());

        store
            .set_time_ms(config.slot_duration_ms)
            .expect("set the clock to slot 1");
        // A validator outside the committee still writes nothing.
        assert_eq!(
            failed_assertion(apply_verified_payload_attestation(
                &mut store,
                &payload_attestation_message(root, 2, 1),
                &config
            )),
            Some("len(ptc_indices) > 0")
        );
        apply_verified_payload_attestation(
            &mut store,
            &payload_attestation_message(root, 3, 1),
            &config,
        )
        .unwrap();
        assert_eq!(seated(&store), vec![2, 7]);

        // The unverified entry point refuses the same message: its signature
        // is not valid.
        let mut fresh = payload_attestation_store(root);
        fresh
            .set_time_ms(config.slot_duration_ms)
            .expect("set the clock to slot 1");
        assert!(
            on_payload_attestation_message(
                &mut fresh,
                &payload_attestation_message(root, 3, 1),
                false,
                &config
            )
            .is_err()
        );
    }

    /// A restarted follower holds a verified payload (restored from its table)
    /// but no payload-committee votes, which are never persisted. Both the
    /// head walk (`payload_timeliness` on the tiebreaker path) and the first
    /// child's payload attestations (`notify_ptc_messages` ends in this same
    /// vote update) read those vectors, so resume must reseed them empty.
    #[test]
    fn a_resumed_store_walks_the_head_and_takes_payload_attestations() {
        let config = Config::active().with_fork_epoch(ForkName::Gloas, 0);
        let anchor_root = Root::repeat_byte(0xb0);
        let root = Root::repeat_byte(0xb1);
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = store_anchored_at_on(backend.clone(), anchor_root);
        store
            .insert_signed_block(
                anchor_root,
                gloas_block(
                    0,
                    Root::ZERO,
                    ExecutionBlockHash::ZERO,
                    ExecutionBlockHash::ZERO,
                ),
            )
            .unwrap();
        store
            .insert_signed_block(
                root,
                gloas_block(
                    1,
                    anchor_root,
                    ExecutionBlockHash::repeat_byte(0xff),
                    ExecutionBlockHash::repeat_byte(0x22),
                ),
            )
            .unwrap();
        let mut state = test_state::with_validators_at(ForkName::Gloas, 4);
        store.insert_state(anchor_root, state.clone()).unwrap();
        let BeaconState::Gloas(inner) = &mut state else {
            unreachable!("with_validators_at(Gloas) builds a gloas state");
        };
        inner.slot = 1;
        let mut committee = vec![0; preset::PTC_SIZE];
        committee[2] = 3;
        let window_index = (preset::SLOTS_PER_EPOCH + 1) as usize;
        inner.ptc_window[window_index] = committee.try_into().unwrap();
        store.insert_state(root, state).unwrap();
        // What `on_block` records for each gloas block, then the envelope.
        for block_root in [anchor_root, root] {
            store.set_gloas_block_timeliness(block_root, [true, true]);
            store.set_payload_timeliness_vote(block_root, vec![None; preset::PTC_SIZE]);
            store.set_payload_data_availability_vote(block_root, vec![None; preset::PTC_SIZE]);
        }
        verify_payload(&mut store, root);
        // Dropping the last handle lets the state writer finish its queue.
        drop(store);

        let mut store = Store::from_db_state(backend)
            .expect("reopen")
            .expect("populated directory");
        assert!(store.has_verified_payload(&root));

        // The slot after the block's own: the head walk asks whether the
        // verified payload is timely, which reads the votes.
        store.set_time_ms(2 * config.slot_duration_ms).unwrap();
        let committees = CommitteeCache::default();
        let walked = gloas_get_head(&store, &config, &committees)
            .expect("a resumed store must walk the head over a verified payload");
        // The actor's own path: `walk_head` with the payload links re-derived
        // (none survive a restart) and the boost and weight helpers.
        let head = get_head_node(&store, &config)
            .expect("the live head walk must succeed on a resumed store");
        assert_eq!(head.root, walked.root);
        assert_eq!(get_head(&mut store, &config).unwrap(), walked.root);
        assert_eq!(store.head_payload_status(), Some(walked.payload_status));

        let message = gloas::PayloadAttestationMessage {
            validator_index: 3,
            data: gloas::PayloadAttestationData {
                beacon_block_root: root,
                slot: 1,
                payload_present: true,
                blob_data_available: true,
            },
            signature: Default::default(),
        };
        on_payload_attestation_message(&mut store, &message, true, &config)
            .expect("the first child's attestations must find the vote vectors");
        assert_eq!(store.payload_timeliness_vote(&root).unwrap()[2], Some(true));
    }

    #[test]
    fn get_forkchoice_store_seeds_a_gloas_anchor_and_leaves_an_earlier_one_alone() {
        // An exact anchor pair, built as `anchor_pair_with` builds a phase0 one.
        let mut state = test_state::with_validators_at(ForkName::Gloas, 1);
        let mut signed = gloas_block(
            state.slot(),
            Root::ZERO,
            ExecutionBlockHash::ZERO,
            ExecutionBlockHash::ZERO,
        );
        let SignedBeaconBlock::Gloas(inner) = &mut signed else {
            unreachable!("`gloas_block` builds a gloas signed block");
        };
        *state.latest_block_header_mut() = BeaconBlockHeader {
            slot: inner.message.slot,
            proposer_index: 0,
            parent_root: Root::ZERO,
            state_root: Root::ZERO,
            body_root: inner.message.body.hash_tree_root(),
        };
        inner.message.state_root = state.hash_tree_root();
        let anchor_root = signed.message_hash_tree_root();

        let store = get_forkchoice_store(
            Arc::new(InMemoryBackend::new()),
            state,
            signed,
            &Config::active().with_fork_epoch(ForkName::Gloas, 0),
        )
        .expect("a gloas anchor is accepted");
        assert_eq!(store.block_timeliness(&anchor_root), Some([true, true]));
        assert_eq!(
            store.payload_timeliness_vote(&anchor_root),
            Some(vec![None; preset::PTC_SIZE])
        );
        assert_eq!(
            store.payload_data_availability_vote(&anchor_root),
            Some(vec![None; preset::PTC_SIZE])
        );
        assert!(!store.has_verified_payload(&anchor_root));

        // Earlier forks record none of the three for their anchor.
        let (state, block) = anchor_pair();
        let anchor_root = block.message_hash_tree_root();
        let store = get_forkchoice_store(
            Arc::new(InMemoryBackend::new()),
            state,
            block,
            &Config::active(),
        )
        .unwrap();
        assert_eq!(store.block_timeliness(&anchor_root), None);
        assert_eq!(store.payload_timeliness_vote(&anchor_root), None);
        assert_eq!(store.payload_data_availability_vote(&anchor_root), None);
    }

    #[test]
    fn gloas_data_availability_is_judged_on_gloas_sidecars_only() {
        // No sidecars sampled: `all()` over an empty list holds.
        assert!(is_data_available_gloas_columns(&[], &[]).unwrap());

        // A sidecar for zero blobs is invalid.
        let empty = gloas::DataColumnSidecar::default();
        assert!(!is_data_available_gloas_columns(&[empty], &[]).unwrap());

        // One cell and one proof against no commitments: past the zero-blob
        // rule, and stopped by the length check against the bid.
        let cell = fulu::Cell::try_from(vec![0u8; preset::BYTES_PER_CELL]).unwrap();
        let one_blob = gloas::DataColumnSidecar {
            column: vec![cell].into(),
            kzg_proofs: vec![KzgProof::default()].into(),
            ..Default::default()
        };
        assert!(!gloas_verify_data_column_sidecar(&one_blob, &[]));
        assert!(gloas_verify_data_column_sidecar(
            &one_blob,
            &[KzgCommitment::default()]
        ));
        assert!(!is_data_available_gloas_columns(&[one_blob], &[]).unwrap());

        // Gloas evidence has no `DataAvailability` variant, so an older fork's
        // check cannot read it as its own, and each of theirs refuses the
        // other's evidence rather than reading it as available.
        let config = Config::active();
        assert!(
            is_data_available_columns(
                &DataAvailability::Blobs {
                    blobs: Vec::new(),
                    proofs: Vec::new(),
                },
                &config,
            )
            .is_err()
        );
        assert!(is_data_available_blobs(&[], &DataAvailability::Columns(Vec::new())).is_err());
    }

    // ------------------------------------------------------------------
    // The bottom-up head walk against the spec-literal references
    // ------------------------------------------------------------------

    /// SplitMix64: a seeded generator small enough to live in a test, so the
    /// crate needs no `rand` dependency and a failing seed reproduces.
    struct TestRng(u64);

    impl TestRng {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn below(&mut self, bound: u64) -> u64 {
            self.next_u64() % bound
        }

        fn chance(&mut self, numerator: u64, denominator: u64) -> bool {
            self.below(denominator) < numerator
        }

        fn root(&mut self) -> Root {
            let mut bytes = [0u8; 32];
            for chunk in bytes.chunks_mut(8) {
                chunk.copy_from_slice(&self.next_u64().to_le_bytes());
            }
            Root::from_slice(&bytes)
        }
    }

    const TREE_VALIDATORS: usize = 12;

    /// A random block tree over the fulu-to-gloas boundary, written straight
    /// into a store: a fulu prefix, gloas blocks whose bids make each parent
    /// status vary, some verified payloads, PTC votes of every shape, latest
    /// messages with random `payload_present`, equivocators and a boost root.
    ///
    /// Two seeds in three also move the justified checkpoint above the anchor,
    /// with each block's unrealized justification random, so that
    /// `filter_block_tree` has branches to drop once the store is far enough
    /// past them and some votes sit below the justified block. One of those
    /// two also stores blocks beside the anchor (at its slot) that the block
    /// index does not hold, as finality pruning leaves them, and some votes
    /// name them.
    struct RandomTree {
        store: Store,
        config: Config,
        roots: Vec<Root>,
        slots: Vec<Slot>,
        first_gloas_slot: Slot,
        justified_moved: bool,
    }

    fn random_tree(seed: u64, backend: Arc<dyn StorageBackend>) -> RandomTree {
        let mut rng = TestRng(seed);
        let config = Config::active().with_fork_epoch(ForkName::Gloas, 1);
        let first_gloas_slot = compute_start_slot_at_epoch(1);
        let slot_cap = 2 * preset::SLOTS_PER_EPOCH - 1;
        // The anchor stays at slot 0, the finalized slot every walk stops at;
        // the first block after it jumps to just before the fork epoch, so a
        // short chain crosses the boundary.
        let anchor_slot: Slot = 0;
        let phase = seed % 3;
        let justified_moved = phase != 0;
        let prunes_index = phase == 2;

        let anchor_root = rng.root();
        let mut store = store_anchored_at_on(backend, anchor_root);
        let fulu_state = test_state::with_validators_at(ForkName::Fulu, TREE_VALIDATORS);
        let gloas_state = test_state::with_validators_at(ForkName::Gloas, TREE_VALIDATORS);
        store
            .insert_signed_block(anchor_root, fulu_block(anchor_slot, Root::ZERO))
            .unwrap();
        store.insert_state(anchor_root, fulu_state.clone()).unwrap();
        store.set_unrealized_justification(anchor_root, Checkpoint::default());

        let mut roots = vec![anchor_root];
        let mut slots: Vec<Slot> = vec![anchor_slot];
        let mut hashes: Vec<Option<ExecutionBlockHash>> = vec![None];
        let mut parent_indices: Vec<usize> = vec![0];
        // The tree is built ancestors first, so a block's parent is always
        // earlier in these vectors.
        let count = 8 + rng.below(12) as usize;
        for i in 0..count {
            // Mostly extend a recent block so the tree reaches the gloas
            // epoch, and now and then add a same-slot sibling of an existing
            // block, which is what an early equivocation looks like.
            let (parent_index, slot) = if roots.len() > 1 && rng.chance(1, 4) {
                let sibling = 1 + rng.below(roots.len() as u64 - 1) as usize;
                (parent_indices[sibling], slots[sibling])
            } else {
                let recent = rng.below(roots.len().min(3) as u64) as usize;
                let parent_index = roots.len() - 1 - recent;
                let slot = if parent_index == 0 {
                    first_gloas_slot - 3 + rng.below(3)
                } else {
                    slots[parent_index] + 1 + rng.below(4)
                };
                (parent_index, slot)
            };
            if slot > slot_cap {
                continue;
            }
            let root = rng.root();
            let parent_root = roots[parent_index];
            if slot >= first_gloas_slot {
                let hash = ExecutionBlockHash::repeat_byte(1 + i as u8);
                let parent_hash = match hashes[parent_index] {
                    Some(parent_hash) if rng.chance(1, 2) => parent_hash,
                    _ => ExecutionBlockHash::repeat_byte(0xf0 + rng.below(8) as u8),
                };
                store
                    .insert_signed_block(root, gloas_block(slot, parent_root, parent_hash, hash))
                    .unwrap();
                store.insert_state(root, gloas_state.clone()).unwrap();
                if rng.chance(1, 2) {
                    verify_payload(&mut store, root);
                }
                for timely_votes in [true, false] {
                    let votes = match rng.below(4) {
                        0 => vec![None; preset::PTC_SIZE],
                        1 => vec![Some(true); preset::PTC_SIZE],
                        2 => vec![Some(false); preset::PTC_SIZE],
                        _ => (0..preset::PTC_SIZE)
                            .map(|_| rng.chance(2, 3).then(|| rng.chance(1, 2)))
                            .collect(),
                    };
                    if timely_votes {
                        store.set_payload_timeliness_vote(root, votes);
                    } else {
                        store.set_payload_data_availability_vote(root, votes);
                    }
                }
                hashes.push(Some(hash));
            } else {
                store
                    .insert_signed_block(root, fulu_block(slot, parent_root))
                    .unwrap();
                store.insert_state(root, fulu_state.clone()).unwrap();
                hashes.push(None);
            }
            let unrealized_epoch = if justified_moved { rng.below(2) } else { 0 };
            store.set_unrealized_justification(
                root,
                Checkpoint {
                    epoch: unrealized_epoch,
                    root: Root::ZERO,
                },
            );
            if rng.chance(3, 4) {
                store.set_block_timeliness(root, [rng.chance(1, 2), rng.chance(1, 2)]);
            }
            roots.push(root);
            slots.push(slot);
            parent_indices.push(parent_index);
        }

        // Justified above the anchor: the store follows the justified block's
        // own state, cached under the checkpoint so that no slot processing
        // is needed to reach it.
        if justified_moved && roots.len() > 1 {
            let pick = 1 + rng.below(roots.len() as u64 - 1) as usize;
            let justified = Checkpoint {
                epoch: 1,
                root: roots[pick],
            };
            let justified_state = store.get_state(&justified.root).unwrap().unwrap();
            store.cache_state(
                CacheKey::CheckpointState {
                    epoch: justified.epoch,
                    root: justified.root,
                },
                justified_state,
            );
            let finalized = store.beacon_finalized_checkpoint();
            update_checkpoints(&mut store, justified, finalized);
        }

        // Blocks the store holds but the index does not: what pruning at the
        // finalized anchor leaves behind, and what a stale vote can name.
        let mut outside_index: Vec<Root> = Vec::new();
        if prunes_index {
            for _ in 0..1 + rng.below(3) {
                let root = rng.root();
                store
                    .insert_signed_block(root, fulu_block(anchor_slot, Root::ZERO))
                    .unwrap();
                store.insert_state(root, fulu_state.clone()).unwrap();
                store.delete_live_chain_entries(&[(anchor_slot, root)]);
                outside_index.push(root);
            }
        }

        for validator_index in 0..TREE_VALIDATORS as u64 {
            if rng.chance(1, 6) {
                continue;
            }
            let (root, block_slot) = if !outside_index.is_empty() && rng.chance(1, 4) {
                (
                    outside_index[rng.below(outside_index.len() as u64) as usize],
                    anchor_slot,
                )
            } else if rng.chance(1, 12) {
                (rng.root(), 0)
            } else {
                let pick = rng.below(roots.len() as u64) as usize;
                (roots[pick], slots[pick])
            };
            store.set_latest_message(
                validator_index,
                LatestMessage {
                    epoch: 0,
                    slot: block_slot + rng.below(3),
                    root,
                    payload_present: rng.chance(1, 2),
                },
            );
            if rng.chance(1, 8) {
                store.insert_equivocating_index(validator_index);
            }
        }
        if roots.len() > 1 && rng.chance(2, 3) {
            let pick = 1 + rng.below(roots.len() as u64 - 1) as usize;
            store.set_proposer_boost_root(roots[pick]);
        }

        RandomTree {
            store,
            config,
            roots,
            slots,
            first_gloas_slot,
            justified_moved,
        }
    }

    /// What the differential test saw, so it can insist it was not vacuous.
    #[derive(Default, Debug)]
    struct WalkStats {
        full_heads: usize,
        empty_heads: usize,
        boost_applied: usize,
        boost_withheld: usize,
        previous_slot_decisions: usize,
        pre_fork_weights: usize,
        branches_filtered_out: usize,
    }

    /// Whether `root` is `justified` or a block below it in `index`.
    fn descends_from_justified(
        index: &HashMap<Root, (Slot, Root)>,
        root: Root,
        justified: Root,
    ) -> bool {
        let justified_slot = index[&justified].0;
        let mut cursor = root;
        while index[&cursor].0 > justified_slot {
            cursor = index[&cursor].1;
            if !index.contains_key(&cursor) {
                return false;
            }
        }
        cursor == justified
    }

    /// Runs the bottom-up walk and both references at `current_slot` and
    /// panics, naming the seed, on any disagreement.
    ///
    /// Node weights are compared only for nodes at or above `walk_bound`, which
    /// can be lower than the finalized slot: the walk weighs nothing below it
    /// (see `compute_node_weights`' bound), so those nodes read as `0` where
    /// the references count their votes.
    fn check_walk_against_references(
        seed: u64,
        tree: &mut RandomTree,
        current_slot: Slot,
        stats: &mut WalkStats,
    ) {
        let config = tree.config.clone();
        tree.store
            .set_time_ms(current_slot * config.slot_duration_ms)
            .unwrap();
        let store = &tree.store;
        let committees = store.committee_cache();
        let index = store.block_index();
        let walked = get_head_node(store, &config)
            .unwrap_or_else(|err| panic!("seed {seed} slot {current_slot}: walk failed: {err:?}"));
        let justified = store.beacon_justified_checkpoint().root;
        let bound = walk_bound(store, &index);
        let justified_subtree = tree
            .roots
            .iter()
            .filter(|&&root| descends_from_justified(&index, root, justified))
            .count();
        let kept = get_filtered_block_tree(store, &index, &config)
            .unwrap()
            .len();
        if kept < justified_subtree {
            stats.branches_filtered_out += 1;
        }

        if current_slot >= tree.first_gloas_slot {
            let reference = gloas_get_head(store, &config, &committees).unwrap_or_else(|err| {
                panic!("seed {seed} slot {current_slot}: gloas_get_head failed: {err:?}")
            });
            assert_eq!(
                walked, reference,
                "seed {seed} slot {current_slot}: head differs from gloas_get_head"
            );

            let weights =
                compute_node_weights(store, &index, &config, &committees, ForkRules::Gloas)
                    .unwrap_or_else(|err| panic!("seed {seed}: weights failed: {err:?}"));
            for (&root, &slot) in tree.roots.iter().zip(&tree.slots) {
                if slot < bound {
                    continue;
                }
                for payload_status in [
                    PayloadStatus::Pending,
                    PayloadStatus::Empty,
                    PayloadStatus::Full,
                ] {
                    let node = ForkChoiceNode {
                        root,
                        payload_status,
                    };
                    let expected = gloas_get_weight(store, node, &config, &committees)
                        .unwrap_or_else(|err| panic!("seed {seed}: reference weight: {err:?}"));
                    assert_eq!(
                        weights.weight(node, slot),
                        expected,
                        "seed {seed} slot {current_slot}: weight of {node:?} differs"
                    );
                    if is_payload_decision_at(slot, payload_status, current_slot) {
                        stats.previous_slot_decisions += 1;
                    }
                }
            }

            match walked.payload_status {
                PayloadStatus::Full => stats.full_heads += 1,
                PayloadStatus::Empty => stats.empty_heads += 1,
                PayloadStatus::Pending => {}
            }
            if !store.proposer_boost_root().is_zero() {
                if should_apply_proposer_boost(store, &config, &committees).unwrap() {
                    stats.boost_applied += 1;
                } else {
                    stats.boost_withheld += 1;
                }
            }
        } else {
            let root = compute_head(store, &index, &config).unwrap();
            assert_eq!(
                walked,
                ForkChoiceNode {
                    root,
                    payload_status: PayloadStatus::Full,
                },
                "seed {seed} slot {current_slot}: head differs from compute_head"
            );

            // Weights too, not only the head. `compute_weights` gives the boost
            // to a chain only down to the justified block, so the comparison
            // covers the blocks at or above it that descend from it.
            let reference = compute_weights(store, &index, &config).unwrap();
            let weights =
                compute_node_weights(store, &index, &config, &committees, ForkRules::PreGloas)
                    .unwrap_or_else(|err| panic!("seed {seed}: weights failed: {err:?}"));
            for (&root, &slot) in tree.roots.iter().zip(&tree.slots) {
                if slot < bound || !descends_from_justified(&index, root, justified) {
                    continue;
                }
                let node = ForkChoiceNode {
                    root,
                    payload_status: PayloadStatus::Pending,
                };
                assert_eq!(
                    weights.weight(node, slot),
                    reference.get(&root).copied().unwrap_or_default(),
                    "seed {seed} slot {current_slot}: weight of {root:?} differs from compute_weights"
                );
                stats.pre_fork_weights += 1;
            }
        }
    }

    /// The walk agrees with the spec-literal references on random trees, for a
    /// current slot before the fork epoch (against `compute_head`, gloas blocks
    /// in the tree read as single full nodes) and after it (against
    /// `gloas_get_head`, and node by node against `gloas_get_weight`).
    #[test]
    fn the_bottom_up_walk_matches_the_spec_literal_references_on_random_trees() {
        let mut stats = WalkStats::default();
        for seed in 0..400 {
            let mut tree = random_tree(seed, Arc::new(InMemoryBackend::new()));
            let max_slot = tree.slots.iter().copied().max().unwrap();
            let first = tree.first_gloas_slot;
            let mut current_slots = vec![
                first - 1,
                max_slot.max(first),
                max_slot.max(first) + 1,
                max_slot.max(first) + 2,
                max_slot.max(first) + 5,
            ];
            if tree.justified_moved {
                // Far enough past every block that a branch whose voting
                // source is stale is dropped from the filtered tree.
                current_slots.push(first + 3 * preset::SLOTS_PER_EPOCH);
            }
            for current_slot in current_slots {
                check_walk_against_references(seed, &mut tree, current_slot, &mut stats);
            }
        }
        assert!(stats.full_heads > 0, "no full head was chosen: {stats:?}");
        assert!(stats.empty_heads > 0, "no empty head was chosen: {stats:?}");
        assert!(
            stats.boost_applied > 0,
            "the boost never applied: {stats:?}"
        );
        assert!(
            stats.boost_withheld > 0,
            "the boost was never withheld: {stats:?}"
        );
        assert!(
            stats.previous_slot_decisions > 0,
            "no previous-slot decision was weighed: {stats:?}"
        );
        assert!(
            stats.pre_fork_weights > 0,
            "no weight was compared before the fork: {stats:?}"
        );
        assert!(
            stats.branches_filtered_out > 0,
            "the block filter never dropped a branch: {stats:?}"
        );
    }

    /// The payload link derived lazily from the blocks is the specification's
    /// parent payload status.
    ///
    /// `random_tree` writes its blocks straight into the store instead of
    /// importing them, so this covers the derivation only; the fork-choice
    /// fixture harness checks the links `on_block` records.
    #[test]
    fn the_recorded_payload_links_match_the_specifications_parent_status() {
        for seed in 0..100 {
            let tree = random_tree(seed, Arc::new(InMemoryBackend::new()));
            for &root in &tree.roots {
                let block = tree.store.get_signed_block(&root).unwrap().unwrap();
                let link = block_payload_link(&tree.store, root).unwrap().unwrap();
                assert_eq!(link.is_gloas(), !is_pre_gloas(&block), "seed {seed}");
                if root == tree.roots[0] {
                    assert_eq!(link.parent_status(), Some(PayloadStatus::Full));
                } else {
                    assert_eq!(
                        link.parent_status(),
                        Some(get_parent_payload_status(&tree.store, &block).unwrap()),
                        "seed {seed}"
                    );
                }
                assert_eq!(tree.store.payload_link(&root), Some(link), "seed {seed}");
            }
        }
    }

    type StorageError = Box<dyn std::error::Error + Send + Sync>;

    thread_local! {
        /// Block-table reads made by the current thread. Per thread, not
        /// per backend: the store's background state writer reads the same
        /// table from its own thread at times of its choosing, and only the
        /// reads the head computation itself makes are in question.
        static BLOCK_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// A backend that counts reads of the block table, to show the head walk
    /// decodes no block once the payload links are recorded.
    struct CountingBackend {
        inner: InMemoryBackend,
    }

    struct CountingView<'a> {
        inner: Box<dyn ethlambda_storage::StorageReadView + 'a>,
    }

    impl StorageBackend for CountingBackend {
        fn begin_read(
            &self,
        ) -> std::result::Result<Box<dyn ethlambda_storage::StorageReadView + '_>, StorageError>
        {
            Ok(Box::new(CountingView {
                inner: self.inner.begin_read()?,
            }))
        }

        fn begin_write(
            &self,
        ) -> std::result::Result<
            Box<dyn ethlambda_storage::StorageWriteBatch + 'static>,
            StorageError,
        > {
            self.inner.begin_write()
        }
    }

    impl ethlambda_storage::StorageReadView for CountingView<'_> {
        fn get(
            &self,
            table: ethlambda_storage::Table,
            key: &[u8],
        ) -> std::result::Result<Option<Vec<u8>>, StorageError> {
            if table == ethlambda_storage::Table::BlockHeaders {
                BLOCK_READS.with(|reads| reads.set(reads.get() + 1));
            }
            self.inner.get(table, key)
        }

        fn prefix_iterator(
            &self,
            table: ethlambda_storage::Table,
            prefix: &[u8],
        ) -> std::result::Result<
            Box<
                dyn Iterator<Item = std::result::Result<(Box<[u8]>, Box<[u8]>), StorageError>> + '_,
            >,
            StorageError,
        > {
            self.inner.prefix_iterator(table, prefix)
        }
    }

    /// The first head computation after a restart fills the payload links by
    /// decoding each block once; every later one decodes none, however many
    /// votes and blocks it weighs.
    ///
    /// The proposer boost stays set, and the current slot is the one after the
    /// latest block's, so the previous-slot payload decision, the tiebreaker
    /// and `should_extend_payload_with` all run. The one branch that decodes
    /// blocks is the equivocation scan under a weak previous-slot parent,
    /// rare and bounded by the candidates at one slot; a seed whose boost gate
    /// reaches it is left out of the comparison, and the test insists that
    /// enough seeds keep the boost set without reaching it.
    #[test]
    fn the_head_walk_decodes_no_block_once_the_payload_links_are_recorded() {
        let mut checked = 0;
        let mut boosted = 0;
        for seed in 0..40 {
            let backend = Arc::new(CountingBackend {
                inner: InMemoryBackend::new(),
            });
            let mut tree = random_tree(seed, backend);
            let max_slot = tree.slots.iter().copied().max().unwrap();
            let latest = max_slot.max(tree.first_gloas_slot);
            let scans = boost_gate_scans_for_equivocation(&tree);
            for (attempt, current_slot) in [latest + 1, latest + 2].into_iter().enumerate() {
                tree.store
                    .set_time_ms(current_slot * tree.config.slot_duration_ms)
                    .unwrap();

                let before = BLOCK_READS.with(|reads| reads.get());
                let first = get_head_node(&tree.store, &tree.config).unwrap();
                let after_first = BLOCK_READS.with(|reads| reads.get());
                let second = get_head_node(&tree.store, &tree.config).unwrap();
                let after_second = BLOCK_READS.with(|reads| reads.get());
                assert_eq!(first, second);
                if scans {
                    continue;
                }
                assert_eq!(
                    after_second, after_first,
                    "seed {seed} slot {current_slot}: the second head computation read a block"
                );
                if attempt == 0 && after_first > before {
                    checked += 1;
                    if !tree.store.proposer_boost_root().is_zero() {
                        boosted += 1;
                    }
                }
            }
        }
        assert!(checked > 0, "the counter never moved, so it proves nothing");
        assert!(boosted > 0, "no seed kept the boost without the scan");
    }

    /// Moves finality of `tree`'s store to a checkpoint that names its
    /// justified block: the first epoch that starts at or after that block's
    /// slot. Returns the justified checkpoint, whose root is now the finalized
    /// root too.
    fn finalize_at_justified(tree: &mut RandomTree) -> Checkpoint {
        let justified = tree.store.beacon_justified_checkpoint();
        let (justified_slot, _) = tree.store.block_index()[&justified.root];
        let finalized = Checkpoint {
            epoch: justified_slot.div_ceil(preset::SLOTS_PER_EPOCH),
            root: justified.root,
        };
        let before = tree.store.beacon_finalized_checkpoint();
        update_checkpoints(&mut tree.store, justified, finalized);
        assert_ne!(finalized, before);
        justified
    }

    /// Clears a boost root that a live node could not hold: the boosted block
    /// is a current-slot block, so it descends from the finalized block and is
    /// not that block itself.
    fn keep_only_a_live_boost(tree: &mut RandomTree, finalized_root: Root) {
        let boost_root = tree.store.proposer_boost_root();
        let index = tree.store.block_index();
        if boost_root == finalized_root
            || (!boost_root.is_zero()
                && !descends_from_justified(&index, boost_root, finalized_root))
        {
            tree.store.set_proposer_boost_root(Root::ZERO);
        }
    }

    /// The current slots the bounded walk is compared at: before the fork
    /// epoch, just after the latest block, and far enough on for the block
    /// filter to drop stale branches.
    fn comparison_slots(tree: &RandomTree) -> [Slot; 4] {
        let latest = tree
            .slots
            .iter()
            .copied()
            .max()
            .unwrap()
            .max(tree.first_gloas_slot);
        [
            tree.first_gloas_slot - 1,
            latest + 1,
            latest + 2,
            tree.first_gloas_slot + 3 * preset::SLOTS_PER_EPOCH,
        ]
    }

    /// Once finality has moved, the actor's prune of the payload links below the
    /// finalized block costs the head computation nothing: it weighs only blocks
    /// at or above the bound, so it neither reads the pruned links nor derives
    /// them again by decoding. The bounded walk still names the head, and gives
    /// every node at or above the bound the weight, that the unbounded
    /// references do, with a nonzero bound.
    #[test]
    fn pruning_links_below_the_finalized_block_changes_nothing_the_head_reads() {
        let mut stats = WalkStats::default();
        let mut pruned_some = 0;
        let mut read_nothing = 0;
        for seed in 0..200 {
            let backend = Arc::new(CountingBackend {
                inner: InMemoryBackend::new(),
            });
            let mut tree = random_tree(seed, backend);
            if !tree.justified_moved {
                continue;
            }
            let justified = finalize_at_justified(&mut tree);
            keep_only_a_live_boost(&mut tree, justified.root);
            if boost_gate_scans_for_equivocation(&tree) {
                continue;
            }

            // Every block's link is recorded, as `on_block` would have.
            for &root in &tree.roots {
                block_payload_link(&tree.store, root).unwrap().unwrap();
            }
            let linked = |tree: &RandomTree| {
                tree.roots
                    .iter()
                    .filter(|&&root| tree.store.payload_link(&root).is_some())
                    .count()
            };
            let before_prune = linked(&tree);

            // The actor's own prune.
            let checkpoint = tree.store.latest_finalized().unwrap();
            ensure_payload_link(&tree.store, checkpoint.root).unwrap();
            tree.store
                .prune_beacon_payload_links(checkpoint.slot, checkpoint.root);
            assert!(
                linked(&tree) < before_prune,
                "seed {seed}: nothing was pruned"
            );
            pruned_some += 1;

            let current_slot = comparison_slots(&tree)[2];
            tree.store
                .set_time_ms(current_slot * tree.config.slot_duration_ms)
                .unwrap();
            let before = BLOCK_READS.with(|reads| reads.get());
            get_head_node(&tree.store, &tree.config).unwrap();
            let after = BLOCK_READS.with(|reads| reads.get());
            assert_eq!(after, before, "seed {seed}: a pruned link was read again");
            read_nothing += 1;

            for current_slot in comparison_slots(&tree) {
                check_walk_against_references(seed, &mut tree, current_slot, &mut stats);
            }
        }
        assert!(pruned_some > 0, "no link was pruned, so nothing was tested");
        assert!(read_nothing > 0, "no seed checked that no block was read");
        assert!(
            stats.pre_fork_weights > 0,
            "no weight was compared: {stats:?}"
        );
    }

    /// The bound is the least of three slots so that it holds without assuming
    /// the boosted block descends from the finalized one: with the boost on the
    /// finalized block itself, the boost gate reads the score of a parent below
    /// the finalized slot, and the walk still agrees with the unbounded
    /// references on the head and on every node at or above the bound.
    #[test]
    fn the_bound_covers_a_boosted_finalized_block() {
        let mut stats = WalkStats::default();
        let mut boosted_finalized = 0;
        for seed in 0..200 {
            let mut tree = random_tree(seed, Arc::new(InMemoryBackend::new()));
            if !tree.justified_moved {
                continue;
            }
            let justified = finalize_at_justified(&mut tree);
            tree.store.set_proposer_boost_root(justified.root);
            if boost_gate_scans_for_equivocation(&tree) {
                continue;
            }
            boosted_finalized += 1;
            for current_slot in comparison_slots(&tree) {
                check_walk_against_references(seed, &mut tree, current_slot, &mut stats);
            }
        }
        assert!(
            boosted_finalized > 0,
            "the finalized block was never boosted"
        );
    }

    /// After a restart no link is recorded. Each cycle of the actor's sequence
    /// (record the finalized root's link, prune, compute the head) derives what
    /// it finds missing once, so the first cycle reads blocks and the next two
    /// read none.
    #[test]
    fn the_actors_prune_cycle_derives_links_once_after_a_restart() {
        let mut derived_first = 0;
        for seed in 0..60 {
            let backend = Arc::new(CountingBackend {
                inner: InMemoryBackend::new(),
            });
            let mut tree = random_tree(seed, backend);
            if !tree.justified_moved {
                continue;
            }
            let justified = finalize_at_justified(&mut tree);
            keep_only_a_live_boost(&mut tree, justified.root);
            if boost_gate_scans_for_equivocation(&tree) {
                continue;
            }
            let current_slot = comparison_slots(&tree)[2];
            tree.store
                .set_time_ms(current_slot * tree.config.slot_duration_ms)
                .unwrap();

            let mut reads_per_cycle = Vec::new();
            for _ in 0..3 {
                let before = BLOCK_READS.with(|reads| reads.get());
                let checkpoint = tree.store.latest_finalized().unwrap();
                ensure_payload_link(&tree.store, checkpoint.root).unwrap();
                tree.store
                    .prune_beacon_payload_links(checkpoint.slot, checkpoint.root);
                get_head_node(&tree.store, &tree.config).unwrap();
                reads_per_cycle.push(BLOCK_READS.with(|reads| reads.get()) - before);
            }
            assert_eq!(
                reads_per_cycle[1..],
                [0, 0],
                "seed {seed}: a later cycle read a block, reads {reads_per_cycle:?}"
            );
            if reads_per_cycle[0] > 0 {
                derived_first += 1;
            }
        }
        assert!(
            derived_first > 0,
            "no seed derived a link after the restart"
        );
    }

    /// Whether the boost gate of `tree`'s store reaches the equivocation scan:
    /// a boosted block whose parent is from the previous slot and weak.
    fn boost_gate_scans_for_equivocation(tree: &RandomTree) -> bool {
        let store = &tree.store;
        let boost_root = store.proposer_boost_root();
        if boost_root.is_zero() {
            return false;
        }
        let index = store.block_index();
        let (slot, parent_root) = index[&boost_root];
        if index[&parent_root].0 + 1 < slot {
            return false;
        }
        let committees = store.committee_cache();
        is_head_weak(store, parent_root, &tree.config, &committees).unwrap()
    }

    /// A gloas block whose parent the store does not hold, the anchor of a
    /// resumed directory, gets its link derived once and then recorded,
    /// although its parent status is unknown.
    #[test]
    fn the_link_of_a_gloas_block_without_its_parent_is_recorded_once() {
        let mut store = empty_store();
        let root = Root::repeat_byte(0xa1);
        let block = gloas_block(
            5,
            Root::repeat_byte(0xee),
            ExecutionBlockHash::repeat_byte(1),
            ExecutionBlockHash::repeat_byte(2),
        );
        store.insert_signed_block(root, block).unwrap();
        assert_eq!(store.payload_link(&root), None);

        let link = block_payload_link(&store, root).unwrap().unwrap();

        assert_eq!(
            link,
            BlockPayloadLink::Gloas {
                parent_status: None
            }
        );
        assert_eq!(store.payload_link(&root), Some(link));
    }
}
