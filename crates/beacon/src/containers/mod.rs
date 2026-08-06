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
//!   different container in bellatrix, capella, deneb, electra, and fulu.
//! - The state's field count crosses a power of two at electra, so its merkle
//!   tree is five levels deep through deneb and six from electra on. The same
//!   logical field has a different generalized index in different forks.
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

pub mod phase0;
pub mod shared;

pub use shared::*;

use libssz::{SszDecode as _, SszEncode as _};

use crate::error::{Error, Result};
use crate::fork::ForkName;
use crate::primitives::{Bytes32, Epoch, Gwei, HashTreeRoot as _, Root, Slot, ValidatorIndex};

/// The beacon state, in whichever fork's shape it currently has.
#[derive(Debug, Clone, PartialEq)]
pub enum BeaconState {
    Phase0(phase0::BeaconState),
}

impl BeaconState {
    /// The fork whose rules and shape apply to this state.
    pub fn fork_name(&self) -> ForkName {
        match self {
            BeaconState::Phase0(_) => ForkName::Phase0,
        }
    }

    /// Decodes a state of a known fork.
    ///
    /// The fork cannot be recovered from the bytes, since SSZ carries no type
    /// tag, so it comes from context: the caller's configuration, or the fixture
    /// directory being run.
    pub fn from_ssz(fork: ForkName, bytes: &[u8]) -> Result<Self> {
        match fork {
            ForkName::Phase0 => Ok(BeaconState::Phase0(phase0::BeaconState::from_ssz_bytes(
                bytes,
            )?)),
            _ => Err(Error::UnsupportedForFork {
                function: "BeaconState::from_ssz",
                fork,
            }),
        }
    }

    /// Encodes the state.
    pub fn to_ssz(&self) -> Vec<u8> {
        match self {
            BeaconState::Phase0(state) => state.to_ssz(),
        }
    }

    /// The state's merkle root, which a block's `state_root` must equal.
    pub fn hash_tree_root(&self) -> Root {
        match self {
            BeaconState::Phase0(state) => state.hash_tree_root(),
        }
    }
}

/// Generates read and write accessors for state fields that every fork shares.
///
/// Two rules, because returning a reference to a `u64` would make the state
/// transition noisier than it needs to be: `copy` fields are returned by value,
/// `reference` fields by reference. Both rules also generate a `_mut` accessor.
///
/// The write accessor is named explicitly rather than derived from the field
/// name, since `macro_rules!` cannot concatenate identifiers on stable Rust.
macro_rules! shared_state_accessors {
    (copy: [$(($field:ident, $field_mut:ident, $ty:ty)),* $(,)?]) => {
        impl BeaconState {
            $(
                pub fn $field(&self) -> $ty {
                    match self {
                        BeaconState::Phase0(state) => state.$field,
                    }
                }

                pub fn $field_mut(&mut self) -> &mut $ty {
                    match self {
                        BeaconState::Phase0(state) => &mut state.$field,
                    }
                }
            )*
        }
    };
    (reference: [$(($field:ident, $field_mut:ident, $ty:ty)),* $(,)?]) => {
        impl BeaconState {
            $(
                pub fn $field(&self) -> &$ty {
                    match self {
                        BeaconState::Phase0(state) => &state.$field,
                    }
                }

                pub fn $field_mut(&mut self) -> &mut $ty {
                    match self {
                        BeaconState::Phase0(state) => &mut state.$field,
                    }
                }
            )*
        }
    };
}

shared_state_accessors!(copy: [
    (genesis_time, genesis_time_mut, u64),
    (genesis_validators_root, genesis_validators_root_mut, Root),
    (slot, slot_mut, Slot),
    (eth1_deposit_index, eth1_deposit_index_mut, u64),
    (previous_justified_checkpoint, previous_justified_checkpoint_mut, Checkpoint),
    (current_justified_checkpoint, current_justified_checkpoint_mut, Checkpoint),
    (finalized_checkpoint, finalized_checkpoint_mut, Checkpoint),
]);

shared_state_accessors!(reference: [
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
]);

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
}
