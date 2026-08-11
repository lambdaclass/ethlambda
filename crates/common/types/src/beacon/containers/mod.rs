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
//! [`shared_state_accessors`] macro generates their accessors from one list, and
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
use crate::beacon::primitives::{
    BlsSignature, Bytes32, Epoch, Gwei, HashTreeRoot as _, Root, Slot, ValidatorIndex,
    WithdrawalIndex,
};

/// The beacon state, in whichever fork's shape it currently has.
#[derive(Debug, Clone, PartialEq)]
pub enum BeaconState {
    Phase0(phase0::BeaconState),
    Altair(altair::BeaconState),
    Bellatrix(bellatrix::BeaconState),
    Capella(capella::BeaconState),
    Deneb(deneb::BeaconState),
    Electra(electra::BeaconState),
    Fulu(fulu::BeaconState),
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
            // Lean has a real shape and Task 10 gives this a genuine decode
            // arm; until BeaconState::Lean exists there is nothing to build.
            ForkName::Lean => Err(Error::UnsupportedForFork {
                function: "BeaconState::from_ssz",
                fork: ForkName::Lean,
            }),
        }
    }

    /// Encodes the state.
    pub fn to_ssz(&self) -> Vec<u8> {
        match self {
            BeaconState::Phase0(state) => state.to_ssz(),
            BeaconState::Altair(state) => state.to_ssz(),
            BeaconState::Bellatrix(state) => state.to_ssz(),
            BeaconState::Capella(state) => state.to_ssz(),
            BeaconState::Deneb(state) => state.to_ssz(),
            BeaconState::Electra(state) => state.to_ssz(),
            BeaconState::Fulu(state) => state.to_ssz(),
        }
    }

    /// The state's merkle root, which a block's `state_root` must equal.
    pub fn hash_tree_root(&self) -> Root {
        match self {
            BeaconState::Phase0(state) => state.hash_tree_root(),
            BeaconState::Altair(state) => state.hash_tree_root(),
            BeaconState::Bellatrix(state) => state.hash_tree_root(),
            BeaconState::Capella(state) => state.hash_tree_root(),
            BeaconState::Deneb(state) => state.hash_tree_root(),
            BeaconState::Electra(state) => state.hash_tree_root(),
            BeaconState::Fulu(state) => state.hash_tree_root(),
        }
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
/// # Adding a fork
///
/// Add one match arm to each of the four accessor bodies below. The variant list
/// cannot be a macro parameter: `macro_rules!` zips two repetitions at the same
/// nesting depth rather than nesting them, so a `variants: [...]` list would be
/// iterated in lockstep with the field list instead of once per field. Spelling
/// the arms out is the simpler of the two ways around that, and it keeps the
/// expansion something you can read.
macro_rules! shared_state_accessors {
    (
        copy: [$(($field:ident, $field_mut:ident, $ty:ty)),* $(,)?],
        reference: [$(($ref_field:ident, $ref_field_mut:ident, $ref_ty:ty)),* $(,)?],
    ) => {
        impl BeaconState {
            $(
                pub fn $field(&self) -> $ty {
                    match self {
                        BeaconState::Phase0(state) => state.$field,
                        BeaconState::Altair(state) => state.$field,
                        BeaconState::Bellatrix(state) => state.$field,
                        BeaconState::Capella(state) => state.$field,
                        BeaconState::Deneb(state) => state.$field,
                        BeaconState::Electra(state) => state.$field,
                        BeaconState::Fulu(state) => state.$field,
                    }
                }

                pub fn $field_mut(&mut self) -> &mut $ty {
                    match self {
                        BeaconState::Phase0(state) => &mut state.$field,
                        BeaconState::Altair(state) => &mut state.$field,
                        BeaconState::Bellatrix(state) => &mut state.$field,
                        BeaconState::Capella(state) => &mut state.$field,
                        BeaconState::Deneb(state) => &mut state.$field,
                        BeaconState::Electra(state) => &mut state.$field,
                        BeaconState::Fulu(state) => &mut state.$field,
                    }
                }
            )*

            $(
                pub fn $ref_field(&self) -> &$ref_ty {
                    match self {
                        BeaconState::Phase0(state) => &state.$ref_field,
                        BeaconState::Altair(state) => &state.$ref_field,
                        BeaconState::Bellatrix(state) => &state.$ref_field,
                        BeaconState::Capella(state) => &state.$ref_field,
                        BeaconState::Deneb(state) => &state.$ref_field,
                        BeaconState::Electra(state) => &state.$ref_field,
                        BeaconState::Fulu(state) => &state.$ref_field,
                    }
                }

                pub fn $ref_field_mut(&mut self) -> &mut $ref_ty {
                    match self {
                        BeaconState::Phase0(state) => &mut state.$ref_field,
                        BeaconState::Altair(state) => &mut state.$ref_field,
                        BeaconState::Bellatrix(state) => &mut state.$ref_field,
                        BeaconState::Capella(state) => &mut state.$ref_field,
                        BeaconState::Deneb(state) => &mut state.$ref_field,
                        BeaconState::Electra(state) => &mut state.$ref_field,
                        BeaconState::Fulu(state) => &mut state.$ref_field,
                    }
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
    /// [`shared_state_accessors`]' fork-invariant lists, and they are read
    /// through here rather than through a per-fork projection to a concrete
    /// state struct because the sweep that reads them is genuinely shared: deneb
    /// reuses capella's `get_expected_withdrawals` unchanged, and a projection
    /// returning `&capella::BeaconState` cannot serve a deneb state at all. That
    /// mistake was made once here and cost a runtime `UnsupportedForFork` on
    /// every deneb block carrying a withdrawal.
    pub fn withdrawal_cursor(&self) -> Result<(WithdrawalIndex, ValidatorIndex)> {
        match self {
            BeaconState::Capella(state) => Ok((
                state.next_withdrawal_index,
                state.next_withdrawal_validator_index,
            )),
            BeaconState::Deneb(state) => Ok((
                state.next_withdrawal_index,
                state.next_withdrawal_validator_index,
            )),
            BeaconState::Electra(state) => Ok((
                state.next_withdrawal_index,
                state.next_withdrawal_validator_index,
            )),
            BeaconState::Fulu(state) => Ok((
                state.next_withdrawal_index,
                state.next_withdrawal_validator_index,
            )),
            other => Err(Error::UnsupportedForFork {
                function: "BeaconState::withdrawal_cursor",
                fork: other.fork_name(),
            }),
        }
    }

    /// The withdrawal sweep's cursor, mutably. See [`Self::withdrawal_cursor`].
    pub fn withdrawal_cursor_mut(&mut self) -> Result<(&mut WithdrawalIndex, &mut ValidatorIndex)> {
        match self {
            BeaconState::Capella(state) => Ok((
                &mut state.next_withdrawal_index,
                &mut state.next_withdrawal_validator_index,
            )),
            BeaconState::Deneb(state) => Ok((
                &mut state.next_withdrawal_index,
                &mut state.next_withdrawal_validator_index,
            )),
            BeaconState::Electra(state) => Ok((
                &mut state.next_withdrawal_index,
                &mut state.next_withdrawal_validator_index,
            )),
            BeaconState::Fulu(state) => Ok((
                &mut state.next_withdrawal_index,
                &mut state.next_withdrawal_validator_index,
            )),
            BeaconState::Phase0(_) | BeaconState::Altair(_) | BeaconState::Bellatrix(_) => {
                Err(Error::UnsupportedForFork {
                    function: "BeaconState::withdrawal_cursor_mut",
                    fork: match self {
                        BeaconState::Phase0(_) => ForkName::Phase0,
                        BeaconState::Altair(_) => ForkName::Altair,
                        _ => ForkName::Bellatrix,
                    },
                })
            }
        }
    }

    /// The three per-validator lists that exist from altair on, by reference and
    /// all at once.
    ///
    /// These cannot join [`shared_state_accessors`]' lists, since phase0 has
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
        match self {
            BeaconState::Phase0(_) => Err(Error::UnsupportedForFork {
                function: "BeaconState::altair_validator_lists",
                fork: ForkName::Phase0,
            }),
            BeaconState::Altair(state) => Ok((
                &state.previous_epoch_participation,
                &state.current_epoch_participation,
                &state.inactivity_scores,
            )),
            BeaconState::Bellatrix(state) => Ok((
                &state.previous_epoch_participation,
                &state.current_epoch_participation,
                &state.inactivity_scores,
            )),
            BeaconState::Capella(state) => Ok((
                &state.previous_epoch_participation,
                &state.current_epoch_participation,
                &state.inactivity_scores,
            )),
            BeaconState::Deneb(state) => Ok((
                &state.previous_epoch_participation,
                &state.current_epoch_participation,
                &state.inactivity_scores,
            )),
            BeaconState::Electra(state) => Ok((
                &state.previous_epoch_participation,
                &state.current_epoch_participation,
                &state.inactivity_scores,
            )),
            BeaconState::Fulu(state) => Ok((
                &state.previous_epoch_participation,
                &state.current_epoch_participation,
                &state.inactivity_scores,
            )),
        }
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
        match self {
            BeaconState::Phase0(_) => Err(Error::UnsupportedForFork {
                function: "BeaconState::altair_validator_lists_mut",
                fork: ForkName::Phase0,
            }),
            BeaconState::Altair(state) => Ok((
                &mut state.previous_epoch_participation,
                &mut state.current_epoch_participation,
                &mut state.inactivity_scores,
            )),
            BeaconState::Bellatrix(state) => Ok((
                &mut state.previous_epoch_participation,
                &mut state.current_epoch_participation,
                &mut state.inactivity_scores,
            )),
            BeaconState::Capella(state) => Ok((
                &mut state.previous_epoch_participation,
                &mut state.current_epoch_participation,
                &mut state.inactivity_scores,
            )),
            BeaconState::Deneb(state) => Ok((
                &mut state.previous_epoch_participation,
                &mut state.current_epoch_participation,
                &mut state.inactivity_scores,
            )),
            BeaconState::Electra(state) => Ok((
                &mut state.previous_epoch_participation,
                &mut state.current_epoch_participation,
                &mut state.inactivity_scores,
            )),
            BeaconState::Fulu(state) => Ok((
                &mut state.previous_epoch_participation,
                &mut state.current_epoch_participation,
                &mut state.inactivity_scores,
            )),
        }
    }

    /// The current and next sync committee, by reference.
    ///
    /// Both exist from altair on, byte-for-byte the same field in every later
    /// fork (see, for instance, bellatrix's own state doc), so they cannot
    /// join [`shared_state_accessors`]' lists, since phase0 predates sync
    /// committees entirely. A per-fork projection cannot serve here either:
    /// `ethlambda_beacon::stf::altair::process_sync_aggregate` is called for every
    /// fork from altair through fulu (see that function's own documentation),
    /// and a projection typed to return `&altair::BeaconState` can only ever answer
    /// for an altair state, not for the bellatrix, capella, deneb, electra, or
    /// fulu ones the same call site also has to serve.
    pub fn sync_committees(&self) -> Result<(&altair::SyncCommittee, &altair::SyncCommittee)> {
        match self {
            BeaconState::Phase0(_) => Err(Error::UnsupportedForFork {
                function: "BeaconState::sync_committees",
                fork: ForkName::Phase0,
            }),
            BeaconState::Altair(state) => {
                Ok((&state.current_sync_committee, &state.next_sync_committee))
            }
            BeaconState::Bellatrix(state) => {
                Ok((&state.current_sync_committee, &state.next_sync_committee))
            }
            BeaconState::Capella(state) => {
                Ok((&state.current_sync_committee, &state.next_sync_committee))
            }
            BeaconState::Deneb(state) => {
                Ok((&state.current_sync_committee, &state.next_sync_committee))
            }
            BeaconState::Electra(state) => {
                Ok((&state.current_sync_committee, &state.next_sync_committee))
            }
            BeaconState::Fulu(state) => {
                Ok((&state.current_sync_committee, &state.next_sync_committee))
            }
        }
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
        match self {
            BeaconState::Phase0(_) => Err(Error::UnsupportedForFork {
                function: "BeaconState::sync_committees_mut",
                fork: ForkName::Phase0,
            }),
            BeaconState::Altair(state) => Ok((
                &mut state.current_sync_committee,
                &mut state.next_sync_committee,
            )),
            BeaconState::Bellatrix(state) => Ok((
                &mut state.current_sync_committee,
                &mut state.next_sync_committee,
            )),
            BeaconState::Capella(state) => Ok((
                &mut state.current_sync_committee,
                &mut state.next_sync_committee,
            )),
            BeaconState::Deneb(state) => Ok((
                &mut state.current_sync_committee,
                &mut state.next_sync_committee,
            )),
            BeaconState::Electra(state) => Ok((
                &mut state.current_sync_committee,
                &mut state.next_sync_committee,
            )),
            BeaconState::Fulu(state) => Ok((
                &mut state.current_sync_committee,
                &mut state.next_sync_committee,
            )),
        }
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
        match self {
            SignedBeaconBlock::Phase0(block) => block.to_ssz(),
            SignedBeaconBlock::Altair(block) => block.to_ssz(),
            SignedBeaconBlock::Bellatrix(block) => block.to_ssz(),
            SignedBeaconBlock::Capella(block) => block.to_ssz(),
            SignedBeaconBlock::Deneb(block) => block.to_ssz(),
            SignedBeaconBlock::Electra(block) => block.to_ssz(),
            SignedBeaconBlock::Fulu(block) => block.to_ssz(),
        }
    }

    /// The merkle root of the unsigned `message`, which is what the proposer's
    /// `signature` is actually over.
    ///
    /// Deliberately not named `hash_tree_root`: that name is left free for the
    /// root of the whole signed container (message and signature together),
    /// which no code in this crate needs yet but which would mean something
    /// different from this method if added later.
    pub fn message_hash_tree_root(&self) -> Root {
        match self {
            SignedBeaconBlock::Phase0(block) => block.message.hash_tree_root(),
            SignedBeaconBlock::Altair(block) => block.message.hash_tree_root(),
            SignedBeaconBlock::Bellatrix(block) => block.message.hash_tree_root(),
            SignedBeaconBlock::Capella(block) => block.message.hash_tree_root(),
            SignedBeaconBlock::Deneb(block) => block.message.hash_tree_root(),
            SignedBeaconBlock::Electra(block) => block.message.hash_tree_root(),
            SignedBeaconBlock::Fulu(block) => block.message.hash_tree_root(),
        }
    }
}

/// Generates read accessors for signed-block fields that every fork shares.
///
/// A signed block has far fewer share points than [`BeaconState`], and none of
/// them need a `_mut` accessor, since nothing in this crate mutates a decoded
/// block in place. The list is still split in two, the same way
/// [`shared_state_accessors`]'s is: every field here happens to be `Copy`, so
/// the split is not `copy` versus `reference` but `message` versus `outer`,
/// separating the fields nested under `message` from `signature`, the one
/// field [`SignedBeaconBlock`] carries directly. As with
/// [`shared_state_accessors`], the variant list itself cannot be a macro
/// parameter, since `macro_rules!` zips repetitions at the same nesting depth
/// rather than nesting them, so each list's arms are spelled out in full.
macro_rules! signed_beacon_block_accessors {
    (
        message: [$(($field:ident, $ty:ty)),* $(,)?],
        outer: [$(($outer_field:ident, $outer_ty:ty)),* $(,)?],
    ) => {
        impl SignedBeaconBlock {
            $(
                pub fn $field(&self) -> $ty {
                    match self {
                        SignedBeaconBlock::Phase0(block) => block.message.$field,
                        SignedBeaconBlock::Altair(block) => block.message.$field,
                        SignedBeaconBlock::Bellatrix(block) => block.message.$field,
                        SignedBeaconBlock::Capella(block) => block.message.$field,
                        SignedBeaconBlock::Deneb(block) => block.message.$field,
                        SignedBeaconBlock::Electra(block) => block.message.$field,
                        SignedBeaconBlock::Fulu(block) => block.message.$field,
                    }
                }
            )*

            $(
                pub fn $outer_field(&self) -> $outer_ty {
                    match self {
                        SignedBeaconBlock::Phase0(block) => block.$outer_field,
                        SignedBeaconBlock::Altair(block) => block.$outer_field,
                        SignedBeaconBlock::Bellatrix(block) => block.$outer_field,
                        SignedBeaconBlock::Capella(block) => block.$outer_field,
                        SignedBeaconBlock::Deneb(block) => block.$outer_field,
                        SignedBeaconBlock::Electra(block) => block.$outer_field,
                        SignedBeaconBlock::Fulu(block) => block.$outer_field,
                    }
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
