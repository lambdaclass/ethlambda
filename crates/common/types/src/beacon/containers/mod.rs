//! The specification's containers.
//!
//! Containers whose shape is the same in every fork are defined once, in
//! [`shared`]. Containers that change are defined once per fork, in a module per
//! fork, and wrapped in an enum here.
//!
//! # Why an enum over per-fork structs
//!
//! Each per-fork struct derives its SSZ encoding, decoding, and merkleization.
//! That is the point: the per-fork field lists are not a growing tail, so
//! hand-written fork-conditional codecs would have to reproduce a lot of detail
//! that a derive gets from the struct definition.
//!
//! - phase0's `previous_epoch_attestations` and `current_epoch_attestations` do
//!   not exist from altair on. They are replaced in position by
//!   `previous_epoch_participation` and `current_epoch_participation`, which have
//!   a different type.
//! - `latest_execution_payload_header` keeps its name from bellatrix on, but is a
//!   different container in bellatrix, capella, and deneb; electra and fulu keep
//!   deneb's shape unchanged.
//! - The state's field count crosses a power of two at electra, so its merkle
//!   tree is five levels deep through deneb and six from electra on. The same
//!   logical field has a different generalized index in different forks.
//! - [`SignedBeaconBlock::Fulu`] is the reverse case: fulu changes no field of a
//!   block at all, so its variant wraps [`electra::SignedBeaconBlock`] rather
//!   than a `fulu` type that would otherwise be a copy of it. See that variant's
//!   doc for why it still needs to be its own variant rather than folded into
//!   `Electra`.
//!
//! # Reading the state without matching on the fork
//!
//! About twenty of the state's fields exist unchanged in every fork. The
//! `shared_state_accessors` macro generates their accessors from one list, and
//! that list is this crate's statement of which fields are fork-invariant: if a
//! future fork changes one, it leaves the list and gains an explicit match at
//! each use site.
//!
//! State transition functions therefore read through accessors and match on the
//! fork only where the specification itself changes behavior, so a match arm can
//! be reviewed against the spec's own diff.

pub mod altair;
pub mod bellatrix;
pub mod capella;
pub mod deneb;
pub mod electra;
pub mod fulu;
pub mod phase0;
pub mod shared;

pub use shared::*;

use libssz::{SszDecode as _, SszEncode as _};

use crate::beacon::error::{Error, Result};
use crate::beacon::fork::ForkName;
use crate::beacon::lean_unreachable;
use crate::beacon::primitives::{
    BlsSignature, Bytes32, Epoch, Gwei, HashTreeRoot as _, Root, Slot, ValidatorIndex,
    WithdrawalIndex,
};

/// Runs `$body` against whichever fork's state this is.
///
/// For the reads every beacon fork answers the same way: the arm list lives here
/// once instead of once per accessor, so a new fork is one line in this macro and
/// one in [`BeaconState::fork_name`] rather than one line in each of twenty match
/// ladders. `$function` names the accessor for the lean arm's panic only.
macro_rules! dispatch_state {
    ($self:expr, $function:expr, |$state:ident| $body:expr) => {
        match $self {
            BeaconState::Phase0($state) => $body,
            BeaconState::Altair($state) => $body,
            BeaconState::Bellatrix($state) => $body,
            BeaconState::Capella($state) => $body,
            BeaconState::Deneb($state) => $body,
            BeaconState::Electra($state) => $body,
            BeaconState::Fulu($state) => $body,
            BeaconState::Lean(_) => lean_unreachable!(state: $function),
        }
    };
}

/// Runs `$body` against the forks that carry a field, and names the ones that
/// predate it.
///
/// Same purpose as `dispatch_state!`, for a field the specification introduces
/// partway along the fork schedule: `carried_by` is the forks whose state has it,
/// `absent_from` the forks that answer [`Error::UnsupportedForFork`]. Both lists
/// are spelled out rather than one being derived from the other, so that a new
/// fork does not silently join either side.
macro_rules! dispatch_state_from {
    (
        $self:expr, $function:expr, |$state:ident| $body:expr,
        carried_by: [$($fork:ident),+ $(,)?],
        absent_from: [$($absent:ident),+ $(,)?],
    ) => {
        match $self {
            $(BeaconState::$fork($state) => Ok($body),)+
            $(BeaconState::$absent(_) => Err(Error::UnsupportedForFork {
                function: $function,
                fork: ForkName::$absent,
            }),)+
            BeaconState::Lean(_) => lean_unreachable!(state: $function),
        }
    };
}

/// Runs `$body` against whichever fork's block this is.
///
/// [`SignedBeaconBlock`] has no lean variant, so unlike `dispatch_state!` there
/// is no boundary arm and nothing to name in a panic.
macro_rules! dispatch_block {
    ($self:expr, |$block:ident| $body:expr) => {
        match $self {
            SignedBeaconBlock::Phase0($block) => $body,
            SignedBeaconBlock::Altair($block) => $body,
            SignedBeaconBlock::Bellatrix($block) => $body,
            SignedBeaconBlock::Capella($block) => $body,
            SignedBeaconBlock::Deneb($block) => $body,
            SignedBeaconBlock::Electra($block) => $body,
            SignedBeaconBlock::Fulu($block) => $body,
        }
    };
}

/// The beacon state, in whichever fork's shape it currently has, plus the lean
/// state.
///
/// [`BeaconState::Lean`] is not a Beacon Chain shape. It is here so that one
/// `BlockChainServer` can dispatch on a single state type; every accessor below
/// treats it as unreachable, and the enforced boundary is the single `match` at
/// the top of each handler.
#[derive(Debug, Clone, PartialEq)]
pub enum BeaconState {
    Phase0(phase0::BeaconState),
    Altair(altair::BeaconState),
    Bellatrix(bellatrix::BeaconState),
    Capella(capella::BeaconState),
    Deneb(deneb::BeaconState),
    Electra(electra::BeaconState),
    Fulu(fulu::BeaconState),
    Lean(crate::state::State),
}

impl BeaconState {
    /// The fork whose rules and shape apply to this state.
    pub fn fork_name(&self) -> ForkName {
        match self {
            BeaconState::Phase0(_) => ForkName::Phase0,
            BeaconState::Altair(_) => ForkName::Altair,
            BeaconState::Bellatrix(_) => ForkName::Bellatrix,
            BeaconState::Capella(_) => ForkName::Capella,
            BeaconState::Deneb(_) => ForkName::Deneb,
            BeaconState::Electra(_) => ForkName::Electra,
            BeaconState::Fulu(_) => ForkName::Fulu,
            BeaconState::Lean(_) => ForkName::Lean,
        }
    }

    /// Decodes a state of a known fork.
    ///
    /// The fork cannot be recovered from the bytes, since SSZ carries no type
    /// tag, so it comes from context: the caller's configuration, or the fixture
    /// directory being run. Every fork this crate implements has a shape, so
    /// unlike other fork-dispatching functions in this crate, there is no
    /// `Error::UnsupportedForFork` arm to fall through to here.
    pub fn from_ssz(fork: ForkName, bytes: &[u8]) -> Result<Self> {
        match fork {
            ForkName::Phase0 => Ok(BeaconState::Phase0(phase0::BeaconState::from_ssz_bytes(
                bytes,
            )?)),
            ForkName::Altair => Ok(BeaconState::Altair(altair::BeaconState::from_ssz_bytes(
                bytes,
            )?)),
            ForkName::Bellatrix => Ok(BeaconState::Bellatrix(
                bellatrix::BeaconState::from_ssz_bytes(bytes)?,
            )),
            ForkName::Capella => Ok(BeaconState::Capella(capella::BeaconState::from_ssz_bytes(
                bytes,
            )?)),
            ForkName::Deneb => Ok(BeaconState::Deneb(deneb::BeaconState::from_ssz_bytes(
                bytes,
            )?)),
            ForkName::Electra => Ok(BeaconState::Electra(electra::BeaconState::from_ssz_bytes(
                bytes,
            )?)),
            ForkName::Fulu => Ok(BeaconState::Fulu(fulu::BeaconState::from_ssz_bytes(bytes)?)),
            // Lean has a real shape, unlike SignedBeaconBlock::from_ssz's
            // ForkName::Lean arm: there is something to build here.
            ForkName::Lean => Ok(BeaconState::Lean(crate::state::State::from_ssz_bytes(
                bytes,
            )?)),
        }
    }

    /// Encodes the state.
    pub fn to_ssz(&self) -> Vec<u8> {
        dispatch_state!(self, "to_ssz", |state| state.to_ssz())
    }

    /// The state's merkle root, which a block's `state_root` must equal.
    pub fn hash_tree_root(&self) -> Root {
        dispatch_state!(self, "hash_tree_root", |state| state.hash_tree_root())
    }
}

/// Generates read and write accessors for state fields that every fork shares.
///
/// The `copy` and `reference` lists are this crate's statement of which state
/// fields are fork-invariant. A fork that changes one of them moves it out of the
/// list and gains an explicit match at each use site.
///
/// Two field lists rather than one, because returning a reference to a `u64`
/// would make the state transition noisier than it needs to be: `copy` fields are
/// returned by value, `reference` fields by reference. Both also get a `_mut`
/// accessor, and both names are given explicitly, since `macro_rules!` cannot
/// concatenate identifiers on stable Rust.
///
/// The arms come from `dispatch_state!`, which is also why the variant list is
/// not a parameter of this macro: `macro_rules!` zips two repetitions at the same
/// nesting depth rather than nesting them, so a `variants: [...]` list would be
/// iterated in lockstep with the field list instead of once per field. Calling
/// one macro from the other sidesteps that and keeps the fork list in one place.
macro_rules! shared_state_accessors {
    (
        copy: [$(($field:ident, $field_mut:ident, $ty:ty)),* $(,)?],
        reference: [$(($ref_field:ident, $ref_field_mut:ident, $ref_ty:ty)),* $(,)?],
    ) => {
        impl BeaconState {
            $(
                pub fn $field(&self) -> $ty {
                    dispatch_state!(self, stringify!($field), |state| state.$field)
                }

                pub fn $field_mut(&mut self) -> &mut $ty {
                    dispatch_state!(self, stringify!($field_mut), |state| &mut state.$field)
                }
            )*

            $(
                pub fn $ref_field(&self) -> &$ref_ty {
                    dispatch_state!(self, stringify!($ref_field), |state| &state.$ref_field)
                }

                pub fn $ref_field_mut(&mut self) -> &mut $ref_ty {
                    dispatch_state!(
                        self,
                        stringify!($ref_field_mut),
                        |state| &mut state.$ref_field
                    )
                }
            )*
        }
    };
}

shared_state_accessors!(
    copy: [
        (genesis_time, genesis_time_mut, u64),
        (genesis_validators_root, genesis_validators_root_mut, Root),
        (slot, slot_mut, Slot),
        (eth1_deposit_index, eth1_deposit_index_mut, u64),
        (previous_justified_checkpoint, previous_justified_checkpoint_mut, Checkpoint),
        (current_justified_checkpoint, current_justified_checkpoint_mut, Checkpoint),
        (finalized_checkpoint, finalized_checkpoint_mut, Checkpoint),
    ],
    reference: [
        (fork, fork_mut, Fork),
        (latest_block_header, latest_block_header_mut, BeaconBlockHeader),
        (block_roots, block_roots_mut, BlockRoots),
        (state_roots, state_roots_mut, StateRoots),
        (historical_roots, historical_roots_mut, HistoricalRoots),
        (eth1_data, eth1_data_mut, Eth1Data),
        (eth1_data_votes, eth1_data_votes_mut, Eth1DataVotes),
        (validators, validators_mut, Validators),
        (balances, balances_mut, Balances),
        (randao_mixes, randao_mixes_mut, RandaoMixes),
        (slashings, slashings_mut, Slashings),
        (justification_bits, justification_bits_mut, JustificationBits),
    ],
);

impl BeaconState {
    /// The validator at `index`.
    ///
    /// A named error rather than an `Option`, since the specification indexes the
    /// registry in many places and an out-of-range index is always a fault.
    pub fn validator(&self, index: ValidatorIndex) -> Result<&Validator> {
        self.validators()
            .get(index as usize)
            .ok_or(Error::UnknownValidator(index))
    }

    /// The validator at `index`, mutably.
    pub fn validator_mut(&mut self, index: ValidatorIndex) -> Result<&mut Validator> {
        self.validators_mut()
            .get_mut(index as usize)
            .ok_or(Error::UnknownValidator(index))
    }

    /// The balance of the validator at `index`.
    pub fn balance(&self, index: ValidatorIndex) -> Result<Gwei> {
        self.balances()
            .get(index as usize)
            .copied()
            .ok_or(Error::UnknownValidator(index))
    }

    /// The randao mix for `epoch`, which the specification indexes modulo the
    /// vector length so the vector acts as a ring buffer.
    pub fn randao_mix(&self, epoch: Epoch) -> Bytes32 {
        let mixes = self.randao_mixes();
        mixes[epoch as usize % mixes.len()]
    }

    /// The withdrawal sweep's cursor: how many withdrawals the chain has ever
    /// made, and which validator the next sweep resumes from.
    ///
    /// Both exist from capella on, so they cannot join
    /// `shared_state_accessors`' fork-invariant lists, and they are read
    /// through here rather than through a per-fork projection to a concrete
    /// state struct because the sweep that reads them is genuinely shared: deneb
    /// reuses capella's `get_expected_withdrawals` unchanged, and a projection
    /// returning `&capella::BeaconState` cannot serve a deneb state at all. That
    /// mistake was made once here and cost a runtime `UnsupportedForFork` on
    /// every deneb block carrying a withdrawal.
    pub fn withdrawal_cursor(&self) -> Result<(WithdrawalIndex, ValidatorIndex)> {
        dispatch_state_from!(
            self,
            "BeaconState::withdrawal_cursor",
            |state| (
                state.next_withdrawal_index,
                state.next_withdrawal_validator_index,
            ),
            carried_by: [Capella, Deneb, Electra, Fulu],
            absent_from: [Phase0, Altair, Bellatrix],
        )
    }

    /// The withdrawal sweep's cursor, mutably. See [`Self::withdrawal_cursor`].
    pub fn withdrawal_cursor_mut(&mut self) -> Result<(&mut WithdrawalIndex, &mut ValidatorIndex)> {
        dispatch_state_from!(
            self,
            "BeaconState::withdrawal_cursor_mut",
            |state| (
                &mut state.next_withdrawal_index,
                &mut state.next_withdrawal_validator_index,
            ),
            carried_by: [Capella, Deneb, Electra, Fulu],
            absent_from: [Phase0, Altair, Bellatrix],
        )
    }

    /// The three per-validator lists that exist from altair on, by reference and
    /// all at once.
    ///
    /// These cannot join `shared_state_accessors`' lists, since phase0 has
    /// none of them, and a per-fork projection to a concrete state struct (the
    /// way `ethlambda_beacon::helpers::altair::altair_state_ref` reaches them) cannot
    /// serve every fork that carries them: bellatrix, capella, deneb, electra,
    /// and fulu all keep the identical three fields, but each is a distinct
    /// Rust type, so a projection typed to return `&altair::BeaconState` can
    /// only ever answer for an altair state.
    ///
    /// Handed back together rather than one accessor per field for the same
    /// reason [`Self::altair_validator_lists_mut`] does: the fork condition
    /// that gates all three is identical, so one match serves every caller,
    /// including one that only needs one or two of the three and destructures
    /// the rest away with `_`.
    pub fn altair_validator_lists(
        &self,
    ) -> Result<(&EpochParticipation, &EpochParticipation, &InactivityScores)> {
        dispatch_state_from!(
            self,
            "BeaconState::altair_validator_lists",
            |state| (
                &state.previous_epoch_participation,
                &state.current_epoch_participation,
                &state.inactivity_scores,
            ),
            carried_by: [Altair, Bellatrix, Capella, Deneb, Electra, Fulu],
            absent_from: [Phase0],
        )
    }

    /// The three per-validator lists that exist from altair on, mutably and all
    /// at once. See [`Self::altair_validator_lists`] for why this cannot be a
    /// per-fork projection instead.
    ///
    /// Handed back together for two reasons that stack:
    /// `ethlambda_beacon::stf::operations::add_validator_to_registry` genuinely needs
    /// all three, since they are positionally parallel with `validators` and
    /// `balances`, so a validator entering the registry has to grow all five
    /// or leave the state internally inconsistent in a way nothing else would
    /// notice until a `hash_tree_root` came out wrong; and every caller that
    /// needs fewer than three still reaches them through this one accessor,
    /// discarding what it does not need, rather than a matching per-field
    /// accessor that would need the identical fork match written out again.
    ///
    /// Borrowing three fields of one struct at once is what the tuple is for.
    /// Rust permits it because the fields are disjoint, whereas three successive
    /// accessor calls would each borrow the whole enum.
    pub fn altair_validator_lists_mut(
        &mut self,
    ) -> Result<(
        &mut EpochParticipation,
        &mut EpochParticipation,
        &mut InactivityScores,
    )> {
        dispatch_state_from!(
            self,
            "BeaconState::altair_validator_lists_mut",
            |state| (
                &mut state.previous_epoch_participation,
                &mut state.current_epoch_participation,
                &mut state.inactivity_scores,
            ),
            carried_by: [Altair, Bellatrix, Capella, Deneb, Electra, Fulu],
            absent_from: [Phase0],
        )
    }

    /// The current and next sync committee, by reference.
    ///
    /// Both exist from altair on, byte-for-byte the same field in every later
    /// fork (see, for instance, bellatrix's own state doc), so they cannot
    /// join `shared_state_accessors`' lists, since phase0 predates sync
    /// committees entirely. A per-fork projection cannot serve here either:
    /// `ethlambda_beacon::stf::altair::process_sync_aggregate` is called for every
    /// fork from altair through fulu (see that function's own documentation),
    /// and a projection typed to return `&altair::BeaconState` can only ever answer
    /// for an altair state, not for the bellatrix, capella, deneb, electra, or
    /// fulu ones the same call site also has to serve.
    pub fn sync_committees(&self) -> Result<(&altair::SyncCommittee, &altair::SyncCommittee)> {
        dispatch_state_from!(
            self,
            "BeaconState::sync_committees",
            |state| (&state.current_sync_committee, &state.next_sync_committee),
            carried_by: [Altair, Bellatrix, Capella, Deneb, Electra, Fulu],
            absent_from: [Phase0],
        )
    }

    /// The current and next sync committee, mutably. See
    /// [`Self::sync_committees`] for why this cannot be a per-fork projection.
    ///
    /// Handed back together, rather than as two separate accessors, because
    /// `ethlambda_beacon::stf::epoch::altair::process_sync_committee_updates` rotates
    /// the pair by replacing one with the other at each sync committee period
    /// boundary, which needs both mutable borrows alive for the one
    /// `core::mem::replace` that does it.
    pub fn sync_committees_mut(
        &mut self,
    ) -> Result<(&mut altair::SyncCommittee, &mut altair::SyncCommittee)> {
        dispatch_state_from!(
            self,
            "BeaconState::sync_committees_mut",
            |state| (
                &mut state.current_sync_committee,
                &mut state.next_sync_committee,
            ),
            carried_by: [Altair, Bellatrix, Capella, Deneb, Electra, Fulu],
            absent_from: [Phase0],
        )
    }
}

/// A signed block, in whichever fork's shape it currently has.
///
/// `Fulu` wraps [`electra::SignedBeaconBlock`] rather than a `fulu` type of its
/// own, deliberately: fulu changes no field of a block (see the [`fulu`] module
/// doc), so there is no `fulu::SignedBeaconBlock`, and this crate must not
/// invent one just to fill out the enum. The variant still has to exist and
/// stay distinct from `Electra`, because fulu does change how a block is
/// processed even though it does not change what a block is: `get_blob_parameters`
/// makes the blob commitment limit `process_operations` checks depend on the
/// epoch rather than being a single fixed preset from electra on. Code that
/// dispatches on fork therefore still needs to be able to tell a fulu block
/// from an electra one, even though both carry the identical
/// `electra::SignedBeaconBlock` payload.
#[derive(Debug, Clone, PartialEq)]
pub enum SignedBeaconBlock {
    Phase0(phase0::SignedBeaconBlock),
    Altair(altair::SignedBeaconBlock),
    Bellatrix(bellatrix::SignedBeaconBlock),
    Capella(capella::SignedBeaconBlock),
    Deneb(deneb::SignedBeaconBlock),
    Electra(electra::SignedBeaconBlock),
    /// Fulu's block. See the enum doc for why this wraps
    /// [`electra::SignedBeaconBlock`] instead of a `fulu` type.
    Fulu(electra::SignedBeaconBlock),
}

impl SignedBeaconBlock {
    /// The fork whose rules apply to this block.
    ///
    /// Not the same question as "what shape is this value": `Fulu` and
    /// `Electra` answer this differently while sharing a shape, which is the
    /// whole reason `Fulu` is its own variant rather than being folded into
    /// `Electra`.
    pub fn fork_name(&self) -> ForkName {
        match self {
            SignedBeaconBlock::Phase0(_) => ForkName::Phase0,
            SignedBeaconBlock::Altair(_) => ForkName::Altair,
            SignedBeaconBlock::Bellatrix(_) => ForkName::Bellatrix,
            SignedBeaconBlock::Capella(_) => ForkName::Capella,
            SignedBeaconBlock::Deneb(_) => ForkName::Deneb,
            SignedBeaconBlock::Electra(_) => ForkName::Electra,
            SignedBeaconBlock::Fulu(_) => ForkName::Fulu,
        }
    }

    /// Decodes a signed block of a known fork.
    ///
    /// The fork cannot be recovered from the bytes, since SSZ carries no type
    /// tag, so it comes from context, the same way [`BeaconState::from_ssz`]'s
    /// does. `ForkName::Fulu` decodes as [`electra::SignedBeaconBlock`], since
    /// that is the type [`SignedBeaconBlock::Fulu`] wraps.
    pub fn from_ssz(fork: ForkName, bytes: &[u8]) -> Result<Self> {
        match fork {
            ForkName::Phase0 => Ok(SignedBeaconBlock::Phase0(
                phase0::SignedBeaconBlock::from_ssz_bytes(bytes)?,
            )),
            ForkName::Altair => Ok(SignedBeaconBlock::Altair(
                altair::SignedBeaconBlock::from_ssz_bytes(bytes)?,
            )),
            ForkName::Bellatrix => Ok(SignedBeaconBlock::Bellatrix(
                bellatrix::SignedBeaconBlock::from_ssz_bytes(bytes)?,
            )),
            ForkName::Capella => Ok(SignedBeaconBlock::Capella(
                capella::SignedBeaconBlock::from_ssz_bytes(bytes)?,
            )),
            ForkName::Deneb => Ok(SignedBeaconBlock::Deneb(
                deneb::SignedBeaconBlock::from_ssz_bytes(bytes)?,
            )),
            ForkName::Electra => Ok(SignedBeaconBlock::Electra(
                electra::SignedBeaconBlock::from_ssz_bytes(bytes)?,
            )),
            ForkName::Fulu => Ok(SignedBeaconBlock::Fulu(
                electra::SignedBeaconBlock::from_ssz_bytes(bytes)?,
            )),
            // There is no lean variant of SignedBeaconBlock, and this fork
            // value comes straight from the caller, so a bad argument is
            // reported rather than crashing.
            ForkName::Lean => Err(Error::UnsupportedForFork {
                function: "SignedBeaconBlock::from_ssz",
                fork: ForkName::Lean,
            }),
        }
    }

    /// Encodes the signed block.
    pub fn to_ssz(&self) -> Vec<u8> {
        dispatch_block!(self, |block| block.to_ssz())
    }

    /// The merkle root of the unsigned `message`, which is what the proposer's
    /// `signature` is actually over.
    ///
    /// Deliberately not named `hash_tree_root`: that name is left free for the
    /// root of the whole signed container (message and signature together),
    /// which no code in this crate needs yet but which would mean something
    /// different from this method if added later.
    pub fn message_hash_tree_root(&self) -> Root {
        dispatch_block!(self, |block| block.message.hash_tree_root())
    }
}

/// Generates read accessors for signed-block fields that every fork shares.
///
/// A signed block has far fewer share points than [`BeaconState`], and none of
/// them need a `_mut` accessor, since nothing in this crate mutates a decoded
/// block in place. The list is still split in two, the same way
/// `shared_state_accessors`'s is: every field here happens to be `Copy`, so
/// the split is not `copy` versus `reference` but `message` versus `outer`,
/// separating the fields nested under `message` from `signature`, the one
/// field [`SignedBeaconBlock`] carries directly. As with
/// `shared_state_accessors`, the arms come from `dispatch_block!` rather than
/// from a variant list of this macro's own.
macro_rules! signed_beacon_block_accessors {
    (
        message: [$(($field:ident, $ty:ty)),* $(,)?],
        outer: [$(($outer_field:ident, $outer_ty:ty)),* $(,)?],
    ) => {
        impl SignedBeaconBlock {
            $(
                pub fn $field(&self) -> $ty {
                    dispatch_block!(self, |block| block.message.$field)
                }
            )*

            $(
                pub fn $outer_field(&self) -> $outer_ty {
                    dispatch_block!(self, |block| block.$outer_field)
                }
            )*
        }
    };
}

signed_beacon_block_accessors!(
    message: [
        (slot, Slot),
        (proposer_index, ValidatorIndex),
        (parent_root, Root),
        (state_root, Root),
    ],
    outer: [
        (signature, BlsSignature),
    ],
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lean_state_reports_the_lean_fork() {
        let state = BeaconState::Lean(crate::state::State::from_genesis(0, Vec::new()));
        assert_eq!(state.fork_name(), ForkName::Lean);
    }

    #[test]
    #[should_panic(expected = "lean state reached a beacon accessor")]
    fn a_lean_state_panics_in_a_beacon_accessor() {
        // The guarantee is structural, not type-level: BeaconState::Lean is
        // constructible anywhere, so this pins the failure mode to a named
        // panic rather than a silent wrong answer.
        let state = BeaconState::Lean(crate::state::State::from_genesis(0, Vec::new()));
        let _ = state.slot();
    }
}
