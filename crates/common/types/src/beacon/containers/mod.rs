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
use crate::beacon::primitives::{
    BlsSignature, Bytes32, Epoch, Gwei, HashTreeRoot as _, Root, Slot, ValidatorIndex,
    WithdrawalIndex,
};
use crate::beacon::{beacon_value_unreachable, lean_block_unreachable, lean_state_unreachable};

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
            BeaconState::Lean(_) => lean_state_unreachable($function),
        }
    };
}

/// Runs `$body` against whichever state this is, the lean one included.
///
/// The counterpart to `dispatch_state!` for the two operations that are not
/// beacon-specific at all. Every variant is an SSZ container, lean's as much as
/// any fork's, so encoding one and merkleizing one mean the same thing whichever
/// chain it belongs to, and answering them for lean is what keeps
/// [`BeaconState::from_ssz`] from handing out a value its own encoder rejects.
///
/// No `$function` parameter, because no arm panics. `$body` has to typecheck for
/// all eight: `to_ssz` does because every variant derives `SszEncode`, and
/// `hash_tree_root` because [`crate::beacon::primitives::HashTreeRoot`] is
/// blanket-implemented over `libssz_merkle::HashTreeRoot` and is the only trait
/// of that name in scope here, so lean's state answers it too, with the same
/// bytes its own `crate::primitives::HashTreeRoot` would produce.
macro_rules! dispatch_state_including_lean {
    ($self:expr, |$state:ident| $body:expr) => {
        match $self {
            BeaconState::Phase0($state) => $body,
            BeaconState::Altair($state) => $body,
            BeaconState::Bellatrix($state) => $body,
            BeaconState::Capella($state) => $body,
            BeaconState::Deneb($state) => $body,
            BeaconState::Electra($state) => $body,
            BeaconState::Fulu($state) => $body,
            BeaconState::Lean($state) => $body,
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
            BeaconState::Lean(_) => lean_state_unreachable($function),
        }
    };
}

/// Runs `$body` against whichever fork's block this is.
///
/// The block-shaped counterpart to `dispatch_state!`: `$function` names the
/// accessor for the lean arm's panic, the same way it does there.
macro_rules! dispatch_block {
    ($self:expr, $function:expr, |$block:ident| $body:expr) => {
        match $self {
            SignedBeaconBlock::Phase0($block) => $body,
            SignedBeaconBlock::Altair($block) => $body,
            SignedBeaconBlock::Bellatrix($block) => $body,
            SignedBeaconBlock::Capella($block) => $body,
            SignedBeaconBlock::Deneb($block) => $body,
            SignedBeaconBlock::Electra($block) => $body,
            SignedBeaconBlock::Fulu($block) => $body,
            SignedBeaconBlock::Lean(_) => lean_block_unreachable($function),
        }
    };
}

/// Runs `$body` against whichever block this is, the lean one included.
///
/// The counterpart to `dispatch_block!` for the accessors every variant can
/// answer for real. Lean's `Block` declares `slot`, `proposer_index`,
/// `parent_root` and `state_root` under exactly those names and matching
/// types, which is why the `message:`/`outer:` split in
/// `signed_beacon_block_accessors!` is the same line as "answerable for lean".
///
/// No `$function` parameter, because no arm panics.
macro_rules! dispatch_block_including_lean {
    ($self:expr, |$block:ident| $body:expr) => {
        match $self {
            SignedBeaconBlock::Phase0($block) => $body,
            SignedBeaconBlock::Altair($block) => $body,
            SignedBeaconBlock::Bellatrix($block) => $body,
            SignedBeaconBlock::Capella($block) => $body,
            SignedBeaconBlock::Deneb($block) => $body,
            SignedBeaconBlock::Electra($block) => $body,
            SignedBeaconBlock::Fulu($block) => $body,
            SignedBeaconBlock::Lean($block) => $body,
        }
    };
}

/// The beacon state, in whichever fork's shape it currently has, plus the lean
/// state.
///
/// [`BeaconState::Lean`] is not a Beacon Chain shape. It is here so that one
/// `BlockChainServer` can dispatch on a single state type. Every accessor that
/// reads a *beacon* field treats it as unreachable, and the enforced boundary is
/// the single `match` at the top of each handler. The four operations that are
/// not beacon-specific answer it for real: [`BeaconState::fork_name`],
/// [`BeaconState::from_ssz`], [`BeaconState::to_ssz`] and
/// [`BeaconState::hash_tree_root`], the last three because every variant is an
/// SSZ container whatever chain it came from.
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
    /// The lean [`State`](crate::state::State) this value wraps.
    ///
    /// The mirror image of `dispatch_state!`'s `Lean` arm. That arm fires when a
    /// lean state reaches a beacon accessor; this one fires when a beacon state
    /// reaches a caller that only ever runs against a lean store, which every
    /// reader on the `/lean/v0` surface and in the lean state transition is.
    ///
    /// Such a caller would otherwise write the peel out by hand, so this owns it
    /// once: a data directory holds one chain for its whole life (see the storage
    /// crate's `Chain`), which is what makes the other arm unreachable rather
    /// than an error worth returning.
    ///
    /// `#[track_caller]` so the panic still reports the call site, the way the
    /// `let ... else { unreachable!() }` written inline there would have.
    #[track_caller]
    pub fn expect_lean(&self) -> &crate::state::State {
        match self {
            BeaconState::Lean(state) => state,
            other => beacon_value_unreachable("state", other.fork_name()),
        }
    }

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

    /// Byte offset of `slot` in an encoded beacon `BeaconState`.
    ///
    /// `genesis_time` (u64) and `genesis_validators_root` (Root) are both
    /// fixed-size and lead the container at every fork, so `slot` follows
    /// them at a constant offset with no variable-length offset to resolve
    /// first.
    const SLOT_OFFSET: usize = 8 + 32;

    /// The `slot` of an encoded beacon state, without decoding the rest.
    ///
    /// The inverse problem to [`BeaconState::from_ssz`]: that one is told the
    /// fork, this one recovers the value a caller works the fork out from.
    /// Checkpoint sync needs it because SSZ carries no type tag and the state
    /// arrives as bytes off an HTTP response.
    ///
    /// Reads the *beacon* layout. [`BeaconState::Lean`] opens with `config`
    /// instead, so lean bytes yield a meaningless number here rather than an
    /// error; every caller already knows which chain it is talking to.
    pub fn slot_from_ssz(bytes: &[u8]) -> Result<Slot> {
        let end = Self::SLOT_OFFSET + 8;
        let slot_bytes =
            bytes
                .get(Self::SLOT_OFFSET..end)
                .ok_or(libssz::DecodeError::InvalidByteLength {
                    expected: end,
                    got: bytes.len(),
                })?;
        Ok(Slot::from_ssz_bytes(slot_bytes)?)
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
            ForkName::Lean => Ok(BeaconState::Lean(crate::state::State::from_ssz_bytes(
                bytes,
            )?)),
        }
    }

    /// Encodes the state.
    ///
    /// Answers for [`BeaconState::Lean`] rather than treating it as unreachable,
    /// unlike the accessors that read a beacon field: this is the inverse of
    /// [`BeaconState::from_ssz`], which builds that variant, so refusing here
    /// would make decoding a state and re-encoding it panic.
    pub fn to_ssz(&self) -> Vec<u8> {
        dispatch_state_including_lean!(self, |state| state.to_ssz())
    }

    /// The state's merkle root, which a block's `state_root` must equal.
    ///
    /// Answers for [`BeaconState::Lean`] too, for the reason
    /// [`BeaconState::to_ssz`] gives. The digest is lean's own state root: both
    /// of this crate's `HashTreeRoot` traits merkleize through `libssz_merkle`
    /// with the same hasher, and only the wrapper type around the bytes differs.
    pub fn hash_tree_root(&self) -> Root {
        dispatch_state_including_lean!(self, |state| state.hash_tree_root())
    }

    /// This state's own merkle root, cached in `latest_block_header` if a
    /// writer put it there and merkleized through
    /// [`BeaconState::hash_tree_root`] otherwise.
    ///
    /// The cached field is the root of the state applying its block produced,
    /// so it describes this state only while the state is still inside that
    /// block's slot; one slot on it names the older one. The specification
    /// fills it on the way out of that slot, so it never satisfies both halves
    /// at once and every fixture state merkleizes here.
    ///
    /// The value reaches `state.state_roots`, a consensus input, so a wrong one
    /// forks silently. Only a root this node computed, or checked against one
    /// it computed, may be written: see `beacon::fork_choice::on_block` and
    /// `get_forkchoice_store`, the two writers.
    ///
    /// Panics on [`BeaconState::Lean`], like every other beacon accessor here.
    pub fn compute_state_root(&self) -> Root {
        let header = self.latest_block_header();
        if self.slot() == header.slot && !header.state_root.is_zero() {
            header.state_root
        } else {
            self.hash_tree_root()
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
    /// The genesis time of the chain this state belongs to.
    ///
    /// Answers for lean as well as every beacon fork. It is a genesis
    /// identity rather than a beacon field, and lean keeps it in
    /// `state.config.genesis_time` rather than at the top level. Widened for
    /// the same reason `dispatch_state_including_lean!` widens `to_ssz` and
    /// `hash_tree_root`: one comparison then recognizes either chain's own
    /// state, which is what lets checkpoint sync and the resume path share
    /// an implementation.
    pub fn genesis_time(&self) -> u64 {
        match self {
            BeaconState::Lean(state) => state.config.genesis_time,
            beacon => dispatch_state!(beacon, "genesis_time", |state| state.genesis_time),
        }
    }

    /// The root committing to the genesis validator registry.
    ///
    /// Lean has no such field. Its registry is fixed at genesis, nothing in
    /// the state transition mutates it, the same invariant `StateDiff` relies
    /// on when it omits `validators`, so the root of the registry at any
    /// slot is the root it had at genesis, which is the quantity beacon
    /// stores. That equivalence is what lets one comparison serve both
    /// chains.
    ///
    /// O(1) on beacon, where it is a stored field, and a merkleization of the
    /// registry on lean. Called at startup, not on a hot path.
    pub fn genesis_validators_root(&self) -> Root {
        match self {
            BeaconState::Lean(state) => state.validators.hash_tree_root(),
            beacon => dispatch_state!(beacon, "genesis_validators_root", |state| state
                .genesis_validators_root),
        }
    }

    /// Beacon-only, unlike the read above: genesis construction sets this
    /// field (`state_transition::beacon::genesis`), and a lean state has no
    /// such field to hand out a `&mut` to.
    pub fn genesis_time_mut(&mut self) -> &mut u64 {
        dispatch_state!(self, "genesis_time_mut", |state| &mut state.genesis_time)
    }

    /// Beacon-only, for the reason given on [`BeaconState::genesis_time_mut`].
    pub fn genesis_validators_root_mut(&mut self) -> &mut Root {
        dispatch_state!(self, "genesis_validators_root_mut", |state| &mut state
            .genesis_validators_root)
    }
}

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
    /// way the beacon STF's `helpers::altair::altair_state_ref` reaches them)
    /// cannot serve every fork that carries them: bellatrix, capella, deneb, electra,
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
    /// the beacon STF's `stf::operations::add_validator_to_registry` genuinely
    /// needs all three, since they are positionally parallel with `validators` and
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
    /// the beacon STF's `stf::altair::process_sync_aggregate` is called for every
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
    /// the beacon STF's `stf::epoch::altair::process_sync_committee_updates`
    /// rotates the pair by replacing one with the other at each sync committee period
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

    /// The Lean consensus protocol's block.
    ///
    /// Not a Beacon Chain shape, and here for the same reason
    /// [`BeaconState::Lean`] is: so the storage layer takes one block type and
    /// splits inside its methods rather than growing a method per chain.
    Lean(crate::block::SignedBlock),
}

impl SignedBeaconBlock {
    /// The lean [`SignedBlock`](crate::block::SignedBlock) this value wraps.
    ///
    /// The block-shaped counterpart to [`BeaconState::expect_lean`], and the
    /// mirror image of `dispatch_block!`'s `Lean` arm. Takes `self` by value,
    /// since the callers that peel a block back off go on to own it.
    ///
    /// For a caller that has some other arm to run instead of panicking, match
    /// on [`SignedBeaconBlock::Lean`] directly; this is for the callers whose
    /// store is lean by construction.
    #[track_caller]
    pub fn expect_lean(self) -> crate::block::SignedBlock {
        let fork = self.fork_name();
        match self {
            SignedBeaconBlock::Lean(block) => block,
            _ => beacon_value_unreachable("block", fork),
        }
    }

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
            SignedBeaconBlock::Lean(_) => ForkName::Lean,
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
            ForkName::Lean => Ok(SignedBeaconBlock::Lean(
                crate::block::SignedBlock::from_ssz_bytes(bytes)?,
            )),
        }
    }

    /// Encodes the signed block.
    ///
    /// Answers for [`SignedBeaconBlock::Lean`] rather than treating it as
    /// unreachable, unlike the accessors that read a beacon field: this is the
    /// inverse of [`SignedBeaconBlock::from_ssz`], which builds that variant,
    /// so refusing here would make decoding a block and re-encoding it panic.
    pub fn to_ssz(&self) -> Vec<u8> {
        dispatch_block_including_lean!(self, |block| block.to_ssz())
    }

    /// The merkle root of the unsigned `message`, which is what the proposer's
    /// `signature` is actually over.
    ///
    /// Deliberately not named `hash_tree_root`: that name is left free for the
    /// root of the whole signed container (message and signature together),
    /// which no code in this crate needs yet but which would mean something
    /// different from this method if added later.
    ///
    /// Answers for [`SignedBeaconBlock::Lean`] too, for the reason
    /// [`SignedBeaconBlock::to_ssz`] gives: lean's `Block` merkleizes through
    /// the same `HashTreeRoot` blanket impl as every beacon fork's `message`
    /// does, re-exported under this module's own `Root` alias.
    pub fn message_hash_tree_root(&self) -> Root {
        dispatch_block_including_lean!(self, |block| block.message.hash_tree_root())
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
/// field [`SignedBeaconBlock`] carries directly.
///
/// That split turns out to also be the lean boundary. Lean's `Block` declares
/// `slot`, `proposer_index`, `parent_root` and `state_root` under exactly the
/// `message:` names and types, so those accessors dispatch through
/// `dispatch_block_including_lean!` and answer for lean for real. `signature`
/// has no lean equivalent, since lean signs with a `MultiMessageAggregate`
/// proof rather than a `BlsSignature`, so it stays on the panicking
/// `dispatch_block!`.
macro_rules! signed_beacon_block_accessors {
    (
        message: [$(($field:ident, $ty:ty)),* $(,)?],
        outer: [$(($outer_field:ident, $outer_ty:ty)),* $(,)?],
    ) => {
        impl SignedBeaconBlock {
            $(
                pub fn $field(&self) -> $ty {
                    dispatch_block_including_lean!(self, |block| block.message.$field)
                }
            )*

            $(
                pub fn $outer_field(&self) -> $outer_ty {
                    dispatch_block!(self, stringify!($outer_field), |block| block.$outer_field)
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

    /// Single-validator lean state. The pubkeys are placeholders; nothing here
    /// verifies a signature.
    fn lean_state(genesis_time: u64, attestation_pubkey: u8) -> crate::state::State {
        crate::state::State::from_genesis(
            genesis_time,
            vec![crate::state::Validator {
                attestation_pubkey: [attestation_pubkey; 52],
                proposal_pubkey: [2u8; 52],
                index: 0,
            }],
        )
    }

    #[test]
    fn a_lean_state_answers_the_genesis_identity_reads() {
        let inner = lean_state(1_770_407_233, 1);
        let expected_root = inner.validators.hash_tree_root();
        let state = BeaconState::Lean(inner);

        assert_eq!(state.genesis_time(), 1_770_407_233);
        assert_eq!(state.genesis_validators_root(), expected_root);
    }

    #[test]
    fn a_different_lean_registry_gives_a_different_root() {
        let one = BeaconState::Lean(lean_state(1_770_407_233, 1));
        let other = BeaconState::Lean(lean_state(1_770_407_233, 9));

        assert_ne!(
            one.genesis_validators_root(),
            other.genesis_validators_root()
        );
    }

    /// The writes stay beacon-only: a lean state has no
    /// `genesis_validators_root` field to hand out a `&mut` to.
    #[test]
    #[should_panic(expected = "lean state reached a beacon accessor")]
    fn the_genesis_validators_root_write_stays_beacon_only() {
        let mut state = BeaconState::Lean(lean_state(0, 1));
        let _ = state.genesis_validators_root_mut();
    }

    #[test]
    fn a_lean_state_reports_the_lean_fork() {
        let state = BeaconState::Lean(crate::state::State::from_genesis(0, Vec::new()));
        assert_eq!(state.fork_name(), ForkName::Lean);
    }

    #[test]
    fn a_lean_state_round_trips_through_the_beacon_enum() {
        // `from_ssz` builds the Lean variant, so its inverse has to accept one.
        // Before `to_ssz` answered for lean, decoding a state and re-encoding it
        // panicked, which is the one asymmetry this enum cannot afford: it is
        // exactly what a `BlockChainServer` dispatching on a configured fork
        // does.
        let lean = crate::state::State::from_genesis(0, Vec::new());
        let bytes = BeaconState::Lean(lean.clone()).to_ssz();

        let decoded = BeaconState::from_ssz(ForkName::Lean, &bytes).expect("a lean state");
        assert_eq!(decoded, BeaconState::Lean(lean.clone()));
        assert_eq!(decoded.to_ssz(), bytes);
    }

    #[test]
    fn a_lean_state_merkleizes_to_its_own_root() {
        // Not merely "does not panic": the digest has to be the one lean's own
        // trait produces, since a block's `state_root` is checked against it.
        // Only the wrapper type around the bytes differs. Lean's trait is named
        // through its full path rather than imported: both are blanket impls
        // over `libssz_merkle::HashTreeRoot`, so bringing the second one into
        // scope would make the call ambiguous.
        let lean = crate::state::State::from_genesis(0, Vec::new());
        let via_beacon = BeaconState::Lean(lean.clone()).hash_tree_root();
        let via_lean = crate::primitives::HashTreeRoot::hash_tree_root(&lean);

        assert_eq!(via_beacon.0, via_lean.0);
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

    #[test]
    fn a_lean_block_answers_the_shared_accessors() {
        let lean = crate::block::SignedBlock {
            message: crate::block::Block {
                slot: 9,
                proposer_index: 3,
                parent_root: crate::primitives::H256::from([1u8; 32]),
                state_root: crate::primitives::H256::from([2u8; 32]),
                body: Default::default(),
            },
            proof: Default::default(),
        };
        let block = SignedBeaconBlock::Lean(lean);

        assert_eq!(block.fork_name(), ForkName::Lean);
        assert_eq!(block.slot(), 9);
        assert_eq!(block.proposer_index(), 3);
        assert_eq!(
            block.parent_root(),
            crate::primitives::H256::from([1u8; 32])
        );
        assert_eq!(block.state_root(), crate::primitives::H256::from([2u8; 32]));
    }

    #[test]
    #[should_panic(expected = "lean block reached a beacon accessor")]
    fn a_lean_block_has_no_bls_signature() {
        // A lean block carries a MultiMessageAggregate proof, not a
        // BlsSignature, so this accessor has nothing to answer with. Named
        // rather than silent, the same way the state accessors are.
        let lean = crate::block::SignedBlock {
            message: crate::block::Block {
                slot: 0,
                proposer_index: 0,
                parent_root: crate::primitives::H256::ZERO,
                state_root: crate::primitives::H256::ZERO,
                body: Default::default(),
            },
            proof: Default::default(),
        };
        let _ = SignedBeaconBlock::Lean(lean).signature();
    }

    #[test]
    fn slot_from_ssz_reads_the_slot_at_its_fixed_offset() {
        // The prefix every beacon fork's BeaconState opens with:
        // genesis_time (8) + genesis_validators_root (32) + slot (8).
        let mut bytes = vec![0u8; 48];
        bytes[..8].copy_from_slice(&1_606_824_023u64.to_le_bytes());
        bytes[8..40].copy_from_slice(&[7u8; 32]);
        bytes[40..48].copy_from_slice(&9_876_543u64.to_le_bytes());

        assert_eq!(BeaconState::slot_from_ssz(&bytes).unwrap(), 9_876_543);
    }

    #[test]
    fn slot_from_ssz_rejects_a_buffer_too_short_to_hold_one() {
        let bytes = vec![0u8; 47];
        assert!(BeaconState::slot_from_ssz(&bytes).is_err());
    }
}
