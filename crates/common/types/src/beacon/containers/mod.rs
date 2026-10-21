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
pub mod gloas;
pub mod phase0;
pub mod shared;

pub use shared::*;

use libssz::{SszDecode as _, SszEncode as _};

use crate::beacon::error::{Error, Result};
use crate::beacon::fork::ForkName;
use crate::beacon::primitives::{
    BlsSignature, Bytes32, CommitteeIndex, Epoch, ExecutionBlockHash, Gwei, HashTreeRoot as _,
    ParticipationFlags, Root, Slot, ValidatorIndex, WithdrawalIndex,
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
            BeaconState::Gloas($state) => $body,
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
            BeaconState::Gloas($state) => $body,
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
            SignedBeaconBlock::Gloas($block) => $body,
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
            SignedBeaconBlock::Gloas($block) => $body,
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
    Gloas(gloas::BeaconState),
    Lean(crate::state::State),
}

/// Hand-written rather than derived, unlike its sibling
/// [`SignedBeaconBlock`]'s `#[serde(untagged)]`.
///
/// Every beacon-fork variant still has to serialize as exactly the inner
/// value, with no tag added: the fork travels in the Beacon API response
/// envelope, as a `version` field and an `Eth-Consensus-Version` header, the
/// same reasoning [`SignedBeaconBlock`]'s derive relies on. What differs is
/// [`BeaconState::Lean`]. `SignedBeaconBlock::Lean` is real, servable JSON —
/// `/lean/v0/blocks/finalized` answers it — but lean's *state* stays
/// SSZ-only by design: `/lean/v0/states/finalized` serves SSZ and always
/// will, so `crate::state::State` deliberately has no `Serialize` impl, and
/// `#[derive(Serialize)]` here could not compile without inventing one.
///
/// So this impl lets every beacon fork serialize normally and turns the
/// `Lean` arm into a serde error instead of a tag or a fabricated encoding.
/// That mirrors how the lean/beacon split is enforced everywhere else in
/// this crate: at the boundary, not in the type system —
/// [`BeaconState::expect_lean`] panics, `dispatch_state!`'s `Lean` arm panics
/// for beacon-only accessors, and this is the same boundary reached through
/// serde instead of a direct call. A panic would be wrong here specifically
/// because serialization is fallible in the caller's vocabulary already (an
/// axum handler already has to handle a `serde_json::to_value` failure), so
/// an `Err` is the gentler member of that family rather than a new one.
///
/// If a future refactor "simplifies" this back into a derive, it will hit
/// the same missing-`Serialize`-on-`State` wall this impl exists to route
/// around, on purpose.
impl serde::Serialize for BeaconState {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            BeaconState::Phase0(state) => state.serialize(serializer),
            BeaconState::Altair(state) => state.serialize(serializer),
            BeaconState::Bellatrix(state) => state.serialize(serializer),
            BeaconState::Capella(state) => state.serialize(serializer),
            BeaconState::Deneb(state) => state.serialize(serializer),
            BeaconState::Electra(state) => state.serialize(serializer),
            BeaconState::Fulu(state) => state.serialize(serializer),
            BeaconState::Gloas(state) => state.serialize(serializer),
            BeaconState::Lean(_) => Err(serde::ser::Error::custom(
                "a lean state has no JSON encoding: /lean/v0/states/finalized serves SSZ only",
            )),
        }
    }
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
            BeaconState::Gloas(_) => ForkName::Gloas,
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
            ForkName::Gloas => Ok(BeaconState::Gloas(gloas::BeaconState::from_ssz_bytes(
                bytes,
            )?)),
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

/// Lists the tree-backed fields of one fork's state, once, and derives from
/// that list both the flush (`apply_pending_mutations`) and the pending check
/// (`has_pending_mutations`), so the two cannot drift apart when a field moves
/// onto the tree.
///
/// The fields are handed out as `dyn Buffered`, since they differ in element
/// type and update map.
macro_rules! tree_fields {
    ($fork:ty => $($field:ident),+ $(,)?) => {
        impl $fork {
            fn buffered(&self) -> [&dyn ethlambda_ssz_tree::Buffered; tree_fields!(@count $($field)+)] {
                [$(&self.$field),+]
            }

            fn buffered_mut(
                &mut self,
            ) -> [&mut dyn ethlambda_ssz_tree::Buffered; tree_fields!(@count $($field)+)] {
                [$(&mut self.$field),+]
            }
        }
    };
    (@count) => { 0usize };
    (@count $head:ident $($tail:ident)*) => { 1usize + tree_fields!(@count $($tail)*) };
}

tree_fields!(
    phase0::BeaconState => validators, balances, block_roots, state_roots, historical_roots, eth1_data_votes, randao_mixes, slashings
);
tree_fields!(
    altair::BeaconState => validators, balances, block_roots, state_roots, historical_roots, eth1_data_votes, randao_mixes, slashings, inactivity_scores
);
tree_fields!(
    bellatrix::BeaconState => validators, balances, block_roots, state_roots, historical_roots, eth1_data_votes, randao_mixes, slashings, inactivity_scores
);
tree_fields!(
    capella::BeaconState => validators, balances, block_roots, state_roots, historical_roots, eth1_data_votes, randao_mixes, slashings, inactivity_scores,
    historical_summaries
);
tree_fields!(
    deneb::BeaconState => validators, balances, block_roots, state_roots, historical_roots, eth1_data_votes, randao_mixes, slashings, inactivity_scores,
    historical_summaries
);
tree_fields!(
    electra::BeaconState => validators, balances, block_roots, state_roots, historical_roots, eth1_data_votes, randao_mixes, slashings, inactivity_scores,
    historical_summaries
);
tree_fields!(
    fulu::BeaconState => validators, balances, block_roots, state_roots, historical_roots, eth1_data_votes, randao_mixes, slashings, inactivity_scores,
    historical_summaries
);
// Gloas keeps `validators` and `balances` in progressive trees, and its
// `inactivity_scores` in a flat progressive list that buffers nothing, so the
// scores are not listed. Every other field is the shared tree type.
tree_fields!(
    gloas::BeaconState => validators, balances, block_roots, state_roots, historical_roots, eth1_data_votes, randao_mixes, slashings,
    historical_summaries
);

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

/// The registry of whichever list kind this state's fork uses.
///
/// Every fork through fulu backs `validators`/`balances` with the bounded,
/// tree-backed [`List`](ethlambda_ssz_tree::List); gloas (EIP-7688) backs them
/// with the unbounded, progressively merkleized
/// [`ProgressiveList`](ethlambda_ssz_tree::ProgressiveList) instead. The two
/// types share every method this crate calls on them (`len`, `get`, `get_mut`,
/// `push`, `apply_updates`, `hash_tree_root`, `has_pending_updates`,
/// `rebase_on`, `ptr_eq`), which is what lets [`dispatch_state!`] keep one body
/// for most of the accessors below. This enum exists only for the handful that
/// return the list itself rather than an element: `dispatch_state!`'s
/// `$body` still has to typecheck as one Rust type across every arm, and
/// `&Validators` and `&ProgressiveValidators` are not that.
enum Registry<'a> {
    Bounded(&'a Validators, &'a Balances),
    Progressive(&'a ProgressiveValidators, &'a ProgressiveBalances),
}

/// [`Registry`], mutably. A separate type rather than a lifetime trick on the
/// same one: an enum cannot hold either `&'a T` or `&'a mut T` depending on
/// the caller, so [`BeaconState::rebase_on`] needs its own mutable version to
/// match against.
enum RegistryMut<'a> {
    Bounded(&'a mut Validators, &'a mut Balances),
    Progressive(&'a mut ProgressiveValidators, &'a mut ProgressiveBalances),
}

/// The inactivity scores of a state, whichever list kind its fork uses.
///
/// Every fork before gloas keeps them in a tree-backed list, which has no
/// slice view; gloas keeps a flat progressive list. A read needs only length,
/// element and in-order access, which this offers over both.
#[derive(Clone, Copy)]
pub enum InactivityScoresRef<'a> {
    /// A tree-backed list (altair through fulu).
    Tree(&'a InactivityScores),
    /// A flat list (gloas).
    Flat(&'a [u64]),
}

impl<'a> From<&'a InactivityScores> for InactivityScoresRef<'a> {
    fn from(scores: &'a InactivityScores) -> Self {
        Self::Tree(scores)
    }
}

impl<'a> From<&'a gloas::InactivityScores> for InactivityScoresRef<'a> {
    fn from(scores: &'a gloas::InactivityScores) -> Self {
        Self::Flat(&scores[..])
    }
}

impl<'a> InactivityScoresRef<'a> {
    /// The number of scores.
    pub fn len(&self) -> usize {
        match self {
            Self::Tree(scores) => scores.len(),
            Self::Flat(scores) => scores.len(),
        }
    }

    /// Whether there are no scores.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The score at `index`, or `None` past the end. A tree descent for a
    /// tree-backed list: walk [`Self::iter`] when visiting many.
    pub fn get(&self, index: usize) -> Option<&'a u64> {
        match self {
            Self::Tree(scores) => scores.get(index),
            Self::Flat(scores) => scores.get(index),
        }
    }

    /// Every score in order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &'a u64> + use<'a> {
        match self {
            Self::Tree(scores) => ScoresIter::Tree(scores.iter()),
            Self::Flat(scores) => ScoresIter::Flat(scores.iter()),
        }
    }

    /// Whether a write is buffered and not yet folded into the tree. Always
    /// `false` for a flat list, which buffers nothing.
    pub fn has_pending_updates(&self) -> bool {
        match self {
            Self::Tree(scores) => scores.has_pending_updates(),
            Self::Flat(_) => false,
        }
    }

    /// Whether both are tree-backed lists sharing one allocation. Never true
    /// for a flat list, which shares nothing.
    pub fn ptr_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Tree(a), Self::Tree(b)) => a.ptr_eq(b),
            _ => false,
        }
    }

    /// The scores, copied out.
    pub fn to_vec(&self) -> Vec<u64> {
        self.iter().copied().collect()
    }
}

impl PartialEq for InactivityScoresRef<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}

impl std::fmt::Debug for InactivityScoresRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl std::ops::Index<usize> for InactivityScoresRef<'_> {
    type Output = u64;

    fn index(&self, index: usize) -> &u64 {
        self.get(index)
            .unwrap_or_else(|| panic!("index {index} out of bounds for {} scores", self.len()))
    }
}

/// The iterator behind [`InactivityScoresRef::iter`].
enum ScoresIter<'a> {
    Tree(ethlambda_ssz_tree::Iter<'a, u64, std::collections::BTreeMap<usize, u64>>),
    Flat(std::slice::Iter<'a, u64>),
}

impl<'a> Iterator for ScoresIter<'a> {
    type Item = &'a u64;

    fn next(&mut self) -> Option<&'a u64> {
        match self {
            Self::Tree(it) => it.next(),
            Self::Flat(it) => it.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::Tree(it) => it.size_hint(),
            Self::Flat(it) => it.size_hint(),
        }
    }
}

impl ExactSizeIterator for ScoresIter<'_> {}

/// An iterator over either registry list kind, so [`BeaconState::iter_validators`]
/// and [`BeaconState::iter_balances`] can promise one return type across every
/// fork despite [`Registry`]'s two underlying list types having different
/// concrete iterators. Private like `Registry`/`RegistryMut`: both accessors
/// hand it back only as the opaque `impl ExactSizeIterator` those two already
/// promised, so nothing outside this module ever names the concrete type.
enum RegistryIter<'a, T, U> {
    Bounded(ethlambda_ssz_tree::Iter<'a, T, U>),
    Progressive(ethlambda_ssz_tree::ProgressiveIter<'a, T, U>),
}

impl<'a, T: ethlambda_ssz_tree::Value, U: ethlambda_ssz_tree::UpdateMap<T>> Iterator
    for RegistryIter<'a, T, U>
{
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        match self {
            Self::Bounded(it) => it.next(),
            Self::Progressive(it) => it.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::Bounded(it) => it.size_hint(),
            Self::Progressive(it) => it.size_hint(),
        }
    }
}

impl<T: ethlambda_ssz_tree::Value, U: ethlambda_ssz_tree::UpdateMap<T>> ExactSizeIterator
    for RegistryIter<'_, T, U>
{
}

impl BeaconState {
    /// The number of validators in the registry.
    pub fn validator_count(&self) -> usize {
        dispatch_state!(self, "validator_count", |state| state.validators.len())
    }

    /// Every validator, in index order, pending writes included.
    ///
    /// An iterator rather than a slice: from gloas on the registry is a
    /// [`ethlambda_ssz_tree::ProgressiveList`] rather than a [`Validators`],
    /// and the two list types agree on `Item` and `ExactSizeIterator` but not
    /// on the concrete iterator type, so an iterator is what an accessor here
    /// can promise across every fork. Prefer this over [`Self::validator`] in
    /// a loop: each `validator()` call redoes the fork dispatch and a tree
    /// descent, where this walks the registry once, sequentially.
    pub fn iter_validators(&self) -> impl ExactSizeIterator<Item = &Validator> {
        match self.registry() {
            Some(Registry::Bounded(v, _)) => RegistryIter::Bounded(v.iter()),
            Some(Registry::Progressive(v, _)) => RegistryIter::Progressive(v.iter()),
            None => lean_state_unreachable("iter_validators"),
        }
    }

    /// Every balance, in index order, pending writes included. See
    /// [`Self::iter_validators`] for why this is an iterator.
    pub fn iter_balances(&self) -> impl ExactSizeIterator<Item = Gwei> {
        match self.registry() {
            Some(Registry::Bounded(_, b)) => RegistryIter::Bounded(b.iter()),
            Some(Registry::Progressive(_, b)) => RegistryIter::Progressive(b.iter()),
            None => lean_state_unreachable("iter_balances"),
        }
        .copied()
    }

    /// The validator at `index`.
    ///
    /// A named error rather than an `Option`, since the specification indexes the
    /// registry in many places and an out-of-range index is always a fault.
    pub fn validator(&self, index: ValidatorIndex) -> Result<&Validator> {
        dispatch_state!(self, "validator", |state| state
            .validators
            .get(index as usize))
        .ok_or(Error::UnknownValidator(index))
    }

    /// The validator at `index`, mutably. Call only when actually writing:
    /// the underlying list clones the element into its update buffer on this
    /// call alone, whether or not the caller goes on to change it.
    pub fn validator_mut(&mut self, index: ValidatorIndex) -> Result<&mut Validator> {
        dispatch_state!(self, "validator_mut", |state| state
            .validators
            .get_mut(index as usize))
        .ok_or(Error::UnknownValidator(index))
    }

    /// The balance of the validator at `index`.
    pub fn balance(&self, index: ValidatorIndex) -> Result<Gwei> {
        dispatch_state!(self, "balance", |state| state
            .balances
            .get(index as usize)
            .copied())
        .ok_or(Error::UnknownValidator(index))
    }

    /// The balance of the validator at `index`, mutably. Call only when
    /// actually writing; see [`Self::validator_mut`] for why.
    pub fn balance_mut(&mut self, index: ValidatorIndex) -> Result<&mut Gwei> {
        dispatch_state!(self, "balance_mut", |state| state
            .balances
            .get_mut(index as usize))
        .ok_or(Error::UnknownValidator(index))
    }

    /// Appends a validator and its balance together, keeping the two
    /// positionally parallel lists in step. From altair on there are three
    /// more such lists (`previous_epoch_participation`,
    /// `current_epoch_participation`, `inactivity_scores`); callers on those
    /// forks still push to them separately, through
    /// [`Self::altair_validator_lists_mut`], since this function only owns
    /// the two lists every fork has.
    pub fn push_validator(&mut self, validator: Validator, balance: Gwei) -> Result<()> {
        dispatch_state!(self, "push_validator", |state| {
            state.validators.push(validator)?;
            state.balances.push(balance)?;
            Ok(())
        })
    }

    /// The registry's own root: the value genesis records as
    /// `genesis_validators_root`.
    pub fn validators_root(&self) -> Root {
        dispatch_state!(self, "validators_root", |state| state
            .validators
            .hash_tree_root())
    }

    /// Whether both validator lists are backed by the same committed tree: a
    /// cheap check of sharing, not of equality. After `rebase_on` it holds
    /// exactly when the two registries are equal in content. The storage
    /// tests use it to prove `get_state` rebased a decoded state onto the
    /// resident parent. Balances are not compared: a state whose balances
    /// changed shares only its untouched subtrees, which a root-pointer
    /// check cannot see.
    pub fn validators_ptr_eq(&self, other: &BeaconState) -> bool {
        match (self.registry(), other.registry()) {
            (Some(Registry::Bounded(v, _)), Some(Registry::Bounded(ov, _))) => v.ptr_eq(ov),
            (Some(Registry::Progressive(v, _)), Some(Registry::Progressive(ov, _))) => v.ptr_eq(ov),
            _ => false,
        }
    }

    /// Both registry lists, whichever kind this fork uses, or `None` for
    /// lean. Private: callers use the element accessors above.
    ///
    /// Written out as its own match rather than through `dispatch_state!`:
    /// that macro inserts one `$body` verbatim into every arm, so it needs
    /// every arm's result to be the same Rust type. `Registry` exists
    /// precisely because [`Validators`] and [`ProgressiveValidators`] are not
    /// that type from gloas on.
    fn registry(&self) -> Option<Registry<'_>> {
        match self {
            BeaconState::Phase0(s) => Some(Registry::Bounded(&s.validators, &s.balances)),
            BeaconState::Altair(s) => Some(Registry::Bounded(&s.validators, &s.balances)),
            BeaconState::Bellatrix(s) => Some(Registry::Bounded(&s.validators, &s.balances)),
            BeaconState::Capella(s) => Some(Registry::Bounded(&s.validators, &s.balances)),
            BeaconState::Deneb(s) => Some(Registry::Bounded(&s.validators, &s.balances)),
            BeaconState::Electra(s) => Some(Registry::Bounded(&s.validators, &s.balances)),
            BeaconState::Fulu(s) => Some(Registry::Bounded(&s.validators, &s.balances)),
            BeaconState::Gloas(s) => Some(Registry::Progressive(&s.validators, &s.balances)),
            BeaconState::Lean(_) => None,
        }
    }

    /// [`Self::registry`], mutably. Kept separate rather than folded into one
    /// generic helper: the borrow checker needs the `&mut self` match here to
    /// be visibly distinct from the `&self` one above.
    fn registry_mut(&mut self) -> Option<RegistryMut<'_>> {
        match self {
            BeaconState::Phase0(s) => {
                Some(RegistryMut::Bounded(&mut s.validators, &mut s.balances))
            }
            BeaconState::Altair(s) => {
                Some(RegistryMut::Bounded(&mut s.validators, &mut s.balances))
            }
            BeaconState::Bellatrix(s) => {
                Some(RegistryMut::Bounded(&mut s.validators, &mut s.balances))
            }
            BeaconState::Capella(s) => {
                Some(RegistryMut::Bounded(&mut s.validators, &mut s.balances))
            }
            BeaconState::Deneb(s) => Some(RegistryMut::Bounded(&mut s.validators, &mut s.balances)),
            BeaconState::Electra(s) => {
                Some(RegistryMut::Bounded(&mut s.validators, &mut s.balances))
            }
            BeaconState::Fulu(s) => Some(RegistryMut::Bounded(&mut s.validators, &mut s.balances)),
            BeaconState::Gloas(s) => {
                Some(RegistryMut::Progressive(&mut s.validators, &mut s.balances))
            }
            BeaconState::Lean(_) => None,
        }
    }

    /// Folds every buffered write into the tree-backed fields (see
    /// `tree_fields!` for which ones), so the next `hash_tree_root` rehashes
    /// only the touched paths and keeps the hashes it computes.
    ///
    /// Hashing with writes still pending gives the right root but caches
    /// nothing for those paths, so the state transition calls this before
    /// every state-root computation. A no-op on a lean state, which has no
    /// tree-backed fields.
    pub fn apply_pending_mutations(&mut self) {
        if matches!(self, BeaconState::Lean(_)) {
            return;
        }
        dispatch_state!(self, "apply_pending_mutations", |state| state
            .buffered_mut()
            .into_iter()
            .for_each(|field| field.apply_updates()))
    }

    /// Whether any tree-backed field has a write [`apply_pending_mutations`]
    /// has not folded into its tree yet.
    ///
    /// Always `false` on a lean state, which has no tree-backed fields. Meant
    /// for callers that cache an `Arc<BeaconState>`: once shared, a state
    /// cannot be flushed later, so every root taken through the `Arc` would
    /// pay the slow, uncached hashing path if a write were still pending.
    ///
    /// [`apply_pending_mutations`]: BeaconState::apply_pending_mutations
    pub fn has_pending_mutations(&self) -> bool {
        if matches!(self, BeaconState::Lean(_)) {
            return false;
        }
        dispatch_state!(self, "has_pending_mutations", |state| state
            .buffered()
            .into_iter()
            .any(|field| field.has_pending_updates()))
    }

    /// Makes this state's tree-backed fields share every unchanged subtree
    /// with `base`'s, so two nearly equal states do not each hold a full copy
    /// of the registry. The state's contents do not change, only which
    /// allocations back them.
    ///
    /// Works across every fork that shares a registry list kind with `base`,
    /// since `List::rebase_on` and `ProgressiveList::rebase_on` each take a
    /// `&Self`, not some common trait object; the other tree-backed fields
    /// have one type in every fork. A no-op if either state is lean, and the
    /// registry is left alone if the two disagree on list kind (a gloas state
    /// rebased onto a pre-gloas one, or vice versa): that pairing only
    /// happens across the fork boundary itself, where there is no shared tree
    /// to reuse anyway.
    pub fn rebase_on(&mut self, base: &BeaconState) {
        let Some(base_registry) = base.registry() else {
            return;
        };
        match (self.registry_mut(), base_registry) {
            (Some(RegistryMut::Bounded(v, b)), Registry::Bounded(bv, bb)) => {
                v.rebase_on(bv);
                b.rebase_on(bb);
            }
            (Some(RegistryMut::Progressive(v, b)), Registry::Progressive(bv, bb)) => {
                v.rebase_on(bv);
                b.rebase_on(bb);
            }
            // Self is lean (no registry at all), or the two states disagree
            // on list kind: exactly the fork-boundary case this function's
            // own doc names as a no-op.
            (None, _)
            | (Some(RegistryMut::Bounded(..)), Registry::Progressive(..))
            | (Some(RegistryMut::Progressive(..)), Registry::Bounded(..)) => {}
        }
        self.block_roots_mut().rebase_on(base.block_roots());
        self.state_roots_mut().rebase_on(base.state_roots());
        self.historical_roots_mut()
            .rebase_on(base.historical_roots());
        self.eth1_data_votes_mut().rebase_on(base.eth1_data_votes());
        self.randao_mixes_mut().rebase_on(base.randao_mixes());
        self.slashings_mut().rebase_on(base.slashings());
        self.rebase_inactivity_scores_on(base);
    }

    /// Whether `validators` or `balances` has a write
    /// [`Self::apply_pending_mutations`] has not folded into its tree yet.
    /// `false` on a lean state.
    ///
    /// The registry alone, unlike [`Self::has_pending_mutations`], which also
    /// counts the other tree-backed fields: the per-slot roots writes stay
    /// buffered by design until the next flush, so a caller asking whether
    /// the registry is flushed cannot use that one.
    pub fn registry_has_pending_updates(&self) -> bool {
        match self.registry() {
            Some(Registry::Bounded(v, b)) => v.has_pending_updates() || b.has_pending_updates(),
            Some(Registry::Progressive(v, b)) => v.has_pending_updates() || b.has_pending_updates(),
            None => false,
        }
    }

    /// Shares `inactivity_scores` with `base`'s where both are tree-backed.
    /// Phase0 has no scores, and gloas keeps a flat list with nothing to
    /// share, so those pairings (and any mix of the two kinds) do nothing.
    fn rebase_inactivity_scores_on(&mut self, base: &BeaconState) {
        if let (Ok((_, _, scores)), Ok((_, _, InactivityScoresRef::Tree(base_scores)))) = (
            self.altair_validator_lists_mut(),
            base.altair_validator_lists(),
        ) {
            scores.rebase_on(base_scores);
        }
    }

    /// Runs `f` over every balance in order through the list's write cursor
    /// (`ethlambda_ssz_tree::List::iter_cow`, or the progressive list's
    /// equivalent from gloas on), stopping at the first error and keeping the
    /// writes made before it.
    ///
    /// For a pass that rewrites most balances: nothing is buffered per element,
    /// and a leaf whose balances all come out unchanged keeps its hash.
    pub fn try_update_balances<E>(
        &mut self,
        mut f: impl FnMut(&mut ethlambda_ssz_tree::ElemCow<'_, Gwei>) -> core::result::Result<(), E>,
    ) -> core::result::Result<(), E> {
        dispatch_state!(self, "BeaconState::try_update_balances", |state| state
            .balances
            .try_update_each(&mut f))
    }

    /// Runs `f` over every validator in order through the registry's write
    /// cursor, with that validator's balance read in step.
    ///
    /// `validators` and `balances` are separate lists of the same state, so a
    /// pass that rewrites one while reading the other cannot go through
    /// [`Self::validator_mut`] and [`Self::balance`] one call at a time: this
    /// splits the borrow. It stops at the first error, keeping the writes made
    /// before it, and also stops (without error) when the balances run out
    /// before the validators do: the caller decides whether a short balances
    /// list is an error.
    pub fn try_update_validators_with_balances<E>(
        &mut self,
        mut f: impl FnMut(
            &mut ethlambda_ssz_tree::ElemCow<'_, Validator>,
            Gwei,
        ) -> core::result::Result<(), E>,
    ) -> core::result::Result<(), E> {
        dispatch_state!(
            self,
            "BeaconState::try_update_validators_with_balances",
            |state| {
                let mut balances = state.balances.iter();
                let mut pass = state.validators.iter_cow();
                while let Some(mut validator) = pass.next_cow() {
                    let Some(&balance) = balances.next() else {
                        break;
                    };
                    f(&mut validator, balance)?;
                }
                Ok(())
            }
        )
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
    /// Both exist from capella on, gloas included, so they cannot join
    /// `shared_state_accessors`' fork-invariant lists, and they are read
    /// through here rather than through a per-fork projection to a concrete
    /// state struct because the sweep that reads them is genuinely shared: deneb
    /// reuses capella's `get_expected_withdrawals` unchanged, and a projection
    /// returning `&capella::BeaconState` cannot serve a deneb state at all. That
    /// mistake was made once here and cost a runtime `UnsupportedForFork` on
    /// every deneb block carrying a withdrawal. Both fields keep their exact
    /// pre-gloas types (`WithdrawalIndex`, `ValidatorIndex`), unlike the three
    /// lists [`Self::altair_validator_lists`] reads, which is why gloas joins
    /// this accessor's `carried_by` rather than its `absent_from`.
    pub fn withdrawal_cursor(&self) -> Result<(WithdrawalIndex, ValidatorIndex)> {
        dispatch_state_from!(
            self,
            "BeaconState::withdrawal_cursor",
            |state| (
                state.next_withdrawal_index,
                state.next_withdrawal_validator_index,
            ),
            carried_by: [Capella, Deneb, Electra, Fulu, Gloas],
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
            carried_by: [Capella, Deneb, Electra, Fulu, Gloas],
            absent_from: [Phase0, Altair, Bellatrix],
        )
    }

    /// The three per-validator lists that exist from altair on, by reference and
    /// all at once: the two participation lists as plain slices, the inactivity
    /// scores as an [`InactivityScoresRef`] since a tree-backed list has no
    /// slice to hand out.
    ///
    /// These cannot join `shared_state_accessors`' lists, since phase0 has
    /// none of them, and a per-fork projection to a concrete state struct (the
    /// way the beacon STF's `helpers::altair::altair_state_ref` reaches them)
    /// cannot serve every fork that carries them: bellatrix, capella, deneb, electra,
    /// fulu, and gloas all keep the identical three fields, but each fork's own
    /// struct is a distinct Rust type, so a projection typed to return
    /// `&altair::BeaconState` can only ever answer for an altair state.
    ///
    /// Gloas joins `carried_by` here, unlike [`Self::altair_validator_lists_mut`]:
    /// EIP-7688 makes all three progressive lists on a gloas state
    /// (`ProgressiveList` rather than `SszList`), a different concrete Rust
    /// type from every earlier fork's, but both list kinds `Deref` to a plain
    /// `[T]`, and a slice is all a *read* ever needs (`.get`, `.len`,
    /// `.binary_search`, ...). Returning slices rather than the list types
    /// themselves is what lets one `dispatch_state_from!` body serve both
    /// kinds: the write side still needs the concrete container type, to grow
    /// or replace the whole list, which is why [`Self::altair_validator_lists_mut`]
    /// stays bounded-only. On gloas, element writes go through
    /// [`Self::inactivity_score_mut`], and growing or replacing a list goes
    /// through a per-fork projection.
    ///
    /// Handed back together rather than one accessor per field for the same
    /// reason [`Self::altair_validator_lists_mut`] does: the fork condition
    /// that gates all three is identical, so one match serves every caller,
    /// including one that only needs one or two of the three and destructures
    /// the rest away with `_`.
    pub fn altair_validator_lists(
        &self,
    ) -> Result<(
        &[ParticipationFlags],
        &[ParticipationFlags],
        InactivityScoresRef<'_>,
    )> {
        dispatch_state_from!(
            self,
            "BeaconState::altair_validator_lists",
            |state| (
                &state.previous_epoch_participation[..],
                &state.current_epoch_participation[..],
                InactivityScoresRef::from(&state.inactivity_scores),
            ),
            carried_by: [Altair, Bellatrix, Capella, Deneb, Electra, Fulu, Gloas],
            absent_from: [Phase0],
        )
    }

    /// The three per-validator lists that exist from altair on, mutably and all
    /// at once, as the fork's own concrete container type. See
    /// [`Self::altair_validator_lists`] for why this cannot be a per-fork
    /// projection instead, and for why, unlike that read-only accessor, this
    /// one does not extend to gloas.
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
    ///
    /// Gloas is in `absent_from` here, not `carried_by`: the container type
    /// this returns (`EpochParticipation`/`InactivityScores`, both `SszList`)
    /// is fixed to the pre-gloas one, and `gloas::BeaconState`'s own three
    /// lists are the progressive `ProgressiveList` instead, a different Rust
    /// type a shared return type cannot name. A gloas caller either grows the
    /// registry through a per-fork projection
    /// (`PendingQueueFields::push_empty_participation_and_inactivity`), writes
    /// one score in place through
    /// [`Self::inactivity_score_mut`], or replaces a whole list outright
    /// through its own state's own field, the way
    /// `stf::epoch::gloas::process_participation_flag_updates` does.
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
            absent_from: [Phase0, Gloas],
        )
    }

    /// One of `inactivity_scores`, mutably: an element write only, no
    /// whole-list replace or length change, which is what lets this include
    /// gloas where [`Self::altair_validator_lists_mut`] cannot (see that
    /// accessor's own doc). A `&mut u64` cannot grow or shrink either list
    /// kind, so handing one out cannot break its length invariant.
    ///
    /// On a tree-backed list (every fork before gloas) the element is copied
    /// into the pending-write map on first touch, whether or not the caller
    /// then changes it: write only when the value differs, so an unchanged
    /// score leaves the list shared with its parent.
    ///
    /// `stf::epoch::altair::process_inactivity_updates` (shared by every fork
    /// from altair on, gloas included) is the one caller: it only ever writes
    /// scores in place, never grows or replaces the list, which
    /// `add_validator_to_registry` and `process_participation_flag_updates`
    /// do instead (see [`Self::altair_validator_lists_mut`]'s own doc for
    /// where each of those goes).
    pub fn inactivity_score_mut(&mut self, index: usize) -> Result<&mut u64> {
        dispatch_state_from!(
            self,
            "BeaconState::inactivity_score_mut",
            |state| {
                let len = state.inactivity_scores.len();
                state
                    .inactivity_scores
                    .get_mut(index)
                    .ok_or(Error::IndexOutOfBounds { index, len })?
            },
            carried_by: [Altair, Bellatrix, Capella, Deneb, Electra, Fulu, Gloas],
            absent_from: [Phase0],
        )
    }

    /// `previous_epoch_participation` or `current_epoch_participation`,
    /// mutably and as a plain slice, whichever `current` selects: element
    /// writes only, the same contract [`Self::inactivity_score_mut`]'s own
    /// doc gives for why that is enough to include gloas where
    /// [`Self::altair_validator_lists_mut`] cannot.
    ///
    /// `crate::beacon::stf::gloas::process_attestation` is the one caller: like
    /// every earlier fork's own version, it only ever ORs a newly-satisfied
    /// flag into an existing validator's entry, never grows or replaces
    /// either list (that only ever happens through
    /// [`Self::altair_validator_lists_mut`], on a fork that carries it, or
    /// through a gloas caller's own per-fork projection, the way
    /// [`Self::altair_validator_lists_mut`]'s own doc describes).
    pub fn epoch_participation_mut(&mut self, current: bool) -> Result<&mut [ParticipationFlags]> {
        dispatch_state_from!(
            self,
            "BeaconState::epoch_participation_mut",
            |state| if current {
                &mut state.current_epoch_participation[..]
            } else {
                &mut state.previous_epoch_participation[..]
            },
            carried_by: [Altair, Bellatrix, Capella, Deneb, Electra, Fulu, Gloas],
            absent_from: [Phase0],
        )
    }

    /// The current and next sync committee, by reference.
    ///
    /// Both exist from altair on, byte-for-byte the same field in every later
    /// fork including gloas (see, for instance, bellatrix's own state doc), so
    /// they cannot join `shared_state_accessors`' lists, since phase0 predates
    /// sync committees entirely. A per-fork projection cannot serve here either:
    /// the beacon STF's `stf::altair::process_sync_aggregate` is called for every
    /// fork from altair on (see that function's own documentation),
    /// and a projection typed to return `&altair::BeaconState` can only ever answer
    /// for an altair state, not for the bellatrix, capella, deneb, electra,
    /// fulu, or gloas ones the same call site also has to serve.
    pub fn sync_committees(&self) -> Result<(&altair::SyncCommittee, &altair::SyncCommittee)> {
        dispatch_state_from!(
            self,
            "BeaconState::sync_committees",
            |state| (&state.current_sync_committee, &state.next_sync_committee),
            carried_by: [Altair, Bellatrix, Capella, Deneb, Electra, Fulu, Gloas],
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
            carried_by: [Altair, Bellatrix, Capella, Deneb, Electra, Fulu, Gloas],
            absent_from: [Phase0],
        )
    }
}

/// The one committee `bits` names, or `None` for none or several.
fn named_committee(bits: &electra::CommitteeBits) -> Option<CommitteeIndex> {
    let mut named = (0..bits.len()).filter(|&index| bits.get(index).unwrap_or(false));
    let first = named.next()?;
    // A second named committee disqualifies the aggregate outright.
    match named.next() {
        None => Some(first as CommitteeIndex),
        Some(_) => None,
    }
}

/// An aggregate attestation with the proof its aggregator was selected, in
/// whichever fork's shape it currently has.
///
/// Three variants, not one per fork, for the reason
/// [`SignedBeaconBlock::Fulu`] wraps electra's block: every fork through deneb
/// shares [`phase0::SignedAggregateAndProof`] outright, and fulu shares
/// electra's the same way. Gloas has its own: same bytes on the wire, but its
/// `Attestation` is a progressive container (EIP-7688), so the
/// `hash_tree_root` the aggregator's signature covers differs.
///
/// Here rather than beside the gossip decode in `ethlambda-p2p`, where it was
/// first declared, because the gossip path no longer ends at that decode: an
/// aggregate now travels over `ethlambda-network-api` to the chain actor and
/// into fork choice. That protocol crate depends on this one and on nothing
/// else, deliberately, so a fork-generic container every layer names has to
/// live here, next to [`SignedBeaconBlock`].
///
/// The accessors are the pure ones. Turning this into the fork-choice crate's
/// own `Attestation` needs that crate's enum, so it lives there as a
/// `From` implementation rather than as a method here.
#[derive(Debug, Clone, PartialEq)]
pub enum SignedAggregateAndProof {
    Phase0(phase0::SignedAggregateAndProof),
    Electra(electra::SignedAggregateAndProof),
    Gloas(gloas::SignedAggregateAndProof),
}

impl SignedAggregateAndProof {
    /// The validator that was selected to aggregate this committee's votes.
    pub fn aggregator_index(&self) -> ValidatorIndex {
        match self {
            Self::Phase0(signed) => signed.message.aggregator_index,
            Self::Electra(signed) => signed.message.aggregator_index,
            Self::Gloas(signed) => signed.message.aggregator_index,
        }
    }

    /// The slot the aggregated attestation votes at.
    pub fn slot(&self) -> Slot {
        match self {
            Self::Phase0(signed) => signed.message.aggregate.data.slot,
            Self::Electra(signed) => signed.message.aggregate.data.slot,
            Self::Gloas(signed) => signed.message.aggregate.data.slot,
        }
    }

    /// The fork-invariant half of the aggregate this carries.
    pub fn data(&self) -> AttestationData {
        match self {
            Self::Phase0(signed) => signed.message.aggregate.data,
            Self::Electra(signed) => signed.message.aggregate.data,
            Self::Gloas(signed) => signed.message.aggregate.data,
        }
    }

    /// The epoch and root the aggregate's `target` checkpoint names.
    pub fn target(&self) -> (Epoch, Root) {
        let target = self.data().target;
        (target.epoch, target.root)
    }

    /// The aggregator's signature over the aggregate's slot, which is what
    /// makes its selection verifiable rather than self-declared.
    pub fn selection_proof(&self) -> BlsSignature {
        match self {
            Self::Phase0(signed) => signed.message.selection_proof,
            Self::Electra(signed) => signed.message.selection_proof,
            Self::Gloas(signed) => signed.message.selection_proof,
        }
    }

    /// The aggregator's signature over the whole `AggregateAndProof`.
    pub fn signature(&self) -> BlsSignature {
        match self {
            Self::Phase0(signed) => signed.signature,
            Self::Electra(signed) => signed.signature,
            Self::Gloas(signed) => signed.signature,
        }
    }

    /// The one committee index the aggregate names, or `None` if it does not
    /// name exactly one.
    ///
    /// EIP-7549 moved the committee out of `data.index`, which electra
    /// requires to be zero, and into a `committee_bits` bitfield. Electra's
    /// gossip validation then requires that bitfield to select *exactly* one
    /// committee, so answering `None` for both zero and several is not a lost
    /// distinction: both are the same rejection, and collapsing them here is
    /// what keeps `ethlambda-state-transition`'s `beacon::gossip::aggregate`
    /// cheap checks (this crate cannot intra-link into that one) from having
    /// to know this enum's two shapes.
    ///
    /// The `len(aggregation_bits) == len(committee)` check downstream is only
    /// meaningful because of that "exactly one": electra's `aggregation_bits`
    /// spans every committee `committee_bits` names, so it equals one
    /// committee's width precisely when one committee is named.
    pub fn committee_index(&self) -> Option<CommitteeIndex> {
        match self {
            Self::Phase0(signed) => Some(signed.message.aggregate.data.index),
            // Gloas reuses electra's `CommitteeBits` outright.
            Self::Electra(signed) => named_committee(&signed.message.aggregate.committee_bits),
            Self::Gloas(signed) => named_committee(&signed.message.aggregate.committee_bits),
        }
    }

    /// The length of the aggregation bitfield, read without expanding it.
    ///
    /// For callers that must bound the bitfield before anything iterates it:
    /// gloas's is unbounded by its type.
    pub fn aggregation_bits_len(&self) -> usize {
        match self {
            Self::Phase0(signed) => signed.message.aggregate.aggregation_bits.len(),
            Self::Electra(signed) => signed.message.aggregate.aggregation_bits.len(),
            Self::Gloas(signed) => signed.message.aggregate.aggregation_bits.len(),
        }
    }

    /// How many attesters the aggregate covers.
    ///
    /// Counts set bits rather than reporting the bitfield's length: from
    /// electra on, `aggregation_bits` spans every committee named in
    /// `committee_bits`, so its length says how wide the aggregate could be,
    /// not how many validators actually signed.
    pub fn attester_count(&self) -> usize {
        match self {
            Self::Phase0(signed) => signed.message.aggregate.aggregation_bits.count_ones(),
            Self::Electra(signed) => signed.message.aggregate.aggregation_bits.count_ones(),
            Self::Gloas(signed) => signed.message.aggregate.aggregation_bits.count_ones(),
        }
    }

    /// The aggregation bits, as a plain vector of booleans.
    ///
    /// The shape the seen-set's superset test needs: it compares one
    /// aggregate's coverage against the union of what has already been seen
    /// for the same `AttestationData`, and neither bitfield type it could
    /// receive supports that directly.
    pub fn aggregation_bits(&self) -> Vec<bool> {
        match self {
            Self::Phase0(signed) => {
                let bits = &signed.message.aggregate.aggregation_bits;
                (0..bits.len())
                    .map(|i| bits.get(i).unwrap_or(false))
                    .collect()
            }
            Self::Electra(signed) => {
                let bits = &signed.message.aggregate.aggregation_bits;
                (0..bits.len())
                    .map(|i| bits.get(i).unwrap_or(false))
                    .collect()
            }
            Self::Gloas(signed) => {
                let bits = &signed.message.aggregate.aggregation_bits;
                (0..bits.len())
                    .map(|i| bits.get(i).unwrap_or(false))
                    .collect()
            }
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
///
/// `#[serde(untagged)]`: the Beacon API's response envelope carries the fork
/// name as `version` and as the `Eth-Consensus-Version` header, never as a
/// tag inside the block object, so serializing this enum must produce
/// exactly the inner value's JSON with no variant wrapper.
/// [`SignedBeaconBlock::Fulu`] and [`SignedBeaconBlock::Electra`] wrap the
/// identical `electra::SignedBeaconBlock` type, which is exactly why an
/// *envelope* tag is required to distinguish them on the wire and a data tag
/// would be actively wrong: `untagged` serialization always writes the
/// active variant's payload, so this holds even for that pair.
///
/// Unlike [`BeaconState`]'s enum, a plain derive works here:
/// [`SignedBeaconBlock::Lean`] is real, servable JSON —
/// `/lean/v0/blocks/finalized` answers it — so `crate::block::SignedBlock`
/// does implement `Serialize`, bare integers included. See `BeaconState`'s
/// hand-written impl for the state side of this asymmetry.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(untagged)]
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
    Gloas(gloas::SignedBeaconBlock),

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

    /// This block's own execution payload block hash, if it carries a payload.
    ///
    /// Written out by hand rather than through `signed_beacon_block_accessors!`,
    /// which generates accessors only for fields every fork shares: phase0 and
    /// altair predate the merge and have no payload at all, and lean is not a
    /// Beacon Chain shape. Those three answer `None`, which is a real answer
    /// rather than a failure — `is_execution_block` in the specification's
    /// optimistic sync document asks exactly this question and expects `False`
    /// for a pre-merge block.
    ///
    /// Named arms rather than a catch-all `_`, so a fork added to the enum
    /// breaks this match instead of silently defaulting to "no payload".
    ///
    /// `None` for [`Self::Gloas`] too, for a different reason than the
    /// pre-merge forks: ePBS (EIP-7732) removes the payload from the block
    /// entirely, so a gloas block carries only a builder's *bid* on a payload
    /// (`signed_execution_payload_bid`), not the payload itself. The block's
    /// own EL hash depends on whether that payload is later revealed and
    /// attested available, which this accessor, reading only the block,
    /// cannot answer. The hash a gloas block commits to is the bid's
    /// `block_hash` (`signed_execution_payload_bid.message.block_hash`), and it
    /// names an executed payload only once `on_execution_payload_envelope` has
    /// verified a matching envelope, which is store state, so a caller that
    /// needs it reads the store's payload verification for that block's root
    /// (`is_payload_verified(store, root)`) rather than this accessor.
    pub fn execution_block_hash(&self) -> Option<ExecutionBlockHash> {
        match self {
            Self::Phase0(_) | Self::Altair(_) | Self::Gloas(_) | Self::Lean(_) => None,
            Self::Bellatrix(block) => Some(block.message.body.execution_payload.block_hash),
            Self::Capella(block) => Some(block.message.body.execution_payload.block_hash),
            Self::Deneb(block) => Some(block.message.body.execution_payload.block_hash),
            Self::Electra(block) | Self::Fulu(block) => {
                Some(block.message.body.execution_payload.block_hash)
            }
        }
    }

    /// How many blob KZG commitments this block's body carries: zero before
    /// deneb, which introduced them.
    ///
    /// The one body field `beacon_block` gossip validation bounds before it
    /// consults any state.
    ///
    /// ePBS (EIP-7732) moves the list out of the body directly: a gloas
    /// block's commitments live on the builder's bid
    /// (`signed_execution_payload_bid.message.blob_kzg_commitments`), not on
    /// a `blob_kzg_commitments` field of the body itself. Unlike
    /// [`Self::execution_block_hash`], the block still carries this count on
    /// its own, so it is read from the bid rather than answered with a
    /// placeholder.
    pub fn blob_kzg_commitment_count(&self) -> usize {
        match self {
            Self::Phase0(_)
            | Self::Altair(_)
            | Self::Bellatrix(_)
            | Self::Capella(_)
            | Self::Lean(_) => 0,
            Self::Deneb(block) => block.message.body.blob_kzg_commitments.len(),
            Self::Electra(block) | Self::Fulu(block) => {
                block.message.body.blob_kzg_commitments.len()
            }
            Self::Gloas(block) => block
                .message
                .body
                .signed_execution_payload_bid
                .message
                .blob_kzg_commitments
                .len(),
        }
    }

    /// This block's execution payload timestamp, if it carries a payload.
    ///
    /// `None` before bellatrix, for the same reason as
    /// [`Self::execution_block_hash`], and `None` for [`Self::Gloas`] for the
    /// reason given there too: the builder's bid
    /// (`signed_execution_payload_bid.message`) carries no `timestamp` field,
    /// since ePBS's payload envelope, not the block, is what a timestamp
    /// would describe.
    pub fn execution_payload_timestamp(&self) -> Option<u64> {
        match self {
            Self::Phase0(_) | Self::Altair(_) | Self::Gloas(_) | Self::Lean(_) => None,
            Self::Bellatrix(block) => Some(block.message.body.execution_payload.timestamp),
            Self::Capella(block) => Some(block.message.body.execution_payload.timestamp),
            Self::Deneb(block) => Some(block.message.body.execution_payload.timestamp),
            Self::Electra(block) | Self::Fulu(block) => {
                Some(block.message.body.execution_payload.timestamp)
            }
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
            SignedBeaconBlock::Gloas(_) => ForkName::Gloas,
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
            ForkName::Gloas => Ok(SignedBeaconBlock::Gloas(
                gloas::SignedBeaconBlock::from_ssz_bytes(bytes)?,
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

    /// The `hash_tree_root` of this block's body.
    ///
    /// Not part of `signed_beacon_block_accessors!`, which hands back a field
    /// verbatim: every fork stores a different body container, so what a
    /// caller wants is the merkle root of whichever one this is, not a value
    /// to compare directly. `/eth/v1/beacon/headers/{id}` answers with a
    /// `SignedBeaconBlockHeader`, whose `body_root` is the one field the
    /// other accessors here cannot produce.
    ///
    /// Answers for [`SignedBeaconBlock::Lean`] too, for the reason
    /// [`SignedBeaconBlock::message_hash_tree_root`] gives: lean's `Block`
    /// also has a `body`, which merkleizes through the same `HashTreeRoot`
    /// blanket impl as every beacon fork's does.
    pub fn body_root(&self) -> Root {
        dispatch_block_including_lean!(self, |block| block.message.body.hash_tree_root())
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

/// A data column sidecar in either shape: fulu's carries a signed header and
/// an inclusion proof, gloas's names its block by root and reads its
/// commitments from that block's bid.
///
/// Two variants rather than one per fork, since the shape changes only at
/// gloas; [`DataColumnSidecar::fork`] answers which fork's rules apply.
// Fulu's carries a header and an inclusion proof inline, so the variants differ
// in size; a sidecar is held and passed by value, and boxing one would only make
// every reader dereference it.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataColumnSidecar {
    Fulu(fulu::DataColumnSidecar),
    Gloas(gloas::DataColumnSidecar),
}

impl DataColumnSidecar {
    /// The column this sidecar carries.
    pub fn index(&self) -> u64 {
        match self {
            Self::Fulu(sidecar) => sidecar.index,
            Self::Gloas(sidecar) => sidecar.index,
        }
    }

    /// The slot of the block this sidecar belongs to.
    pub fn slot(&self) -> Slot {
        match self {
            Self::Fulu(sidecar) => sidecar.signed_block_header.message.slot,
            Self::Gloas(sidecar) => sidecar.slot,
        }
    }

    /// The root of the block this sidecar belongs to: fulu's is the header's
    /// hash tree root, gloas's is named outright.
    pub fn block_root(&self) -> Root {
        match self {
            Self::Fulu(sidecar) => sidecar.signed_block_header.message.hash_tree_root(),
            Self::Gloas(sidecar) => sidecar.beacon_block_root,
        }
    }

    /// The fork whose rules apply to this sidecar.
    pub fn fork(&self) -> ForkName {
        match self {
            Self::Fulu(_) => ForkName::Fulu,
            Self::Gloas(_) => ForkName::Gloas,
        }
    }

    /// Decodes a sidecar of a known fork; the bytes carry no tag, so the fork
    /// comes from context (the gossip topic's digest, a request's fork digest).
    ///
    /// Forks before fulu have no data columns and lean has none at all, so
    /// they answer with an error rather than a panic: the fork comes off the
    /// wire.
    pub fn from_ssz(fork: ForkName, bytes: &[u8]) -> Result<Self> {
        match fork {
            ForkName::Fulu => Ok(Self::Fulu(fulu::DataColumnSidecar::from_ssz_bytes(bytes)?)),
            ForkName::Gloas => Ok(Self::Gloas(gloas::DataColumnSidecar::from_ssz_bytes(
                bytes,
            )?)),
            ForkName::Phase0
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb
            | ForkName::Electra
            | ForkName::Lean => Err(Error::UnsupportedForFork {
                function: "DataColumnSidecar",
                fork,
            }),
        }
    }

    /// Encodes the sidecar.
    pub fn to_ssz(&self) -> Vec<u8> {
        match self {
            Self::Fulu(sidecar) => sidecar.to_ssz(),
            Self::Gloas(sidecar) => sidecar.to_ssz(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::constants;
    use crate::beacon::preset;
    use crate::beacon::primitives::{ExecutionAddress, Uint256};

    /// A Fulu state with `count` validators, each with a full effective
    /// balance and otherwise eligible, and every other field at an all-zero
    /// placeholder sized to the preset. Good enough for the registry accessor
    /// tests below, which touch `validators`/`balances` only: nothing here
    /// verifies a signature or aggregates a sync committee.
    ///
    /// `ethlambda-types` cannot reuse `ethlambda-state-transition`'s
    /// `helpers::test_state` builder (dependency runs the other way), so this
    /// is a small copy of its Fulu literal.
    fn small_fulu_state(count: usize) -> BeaconState {
        let validators: Vec<Validator> = (0..count)
            .map(|_| Validator {
                effective_balance: preset::MAX_EFFECTIVE_BALANCE,
                activation_eligibility_epoch: 0,
                activation_epoch: 0,
                exit_epoch: constants::FAR_FUTURE_EPOCH,
                withdrawable_epoch: constants::FAR_FUTURE_EPOCH,
                ..Default::default()
            })
            .collect();
        let zero_root_vector = || -> BlockRoots {
            vec![Root::ZERO; preset::SLOTS_PER_HISTORICAL_ROOT]
                .try_into()
                .expect("the vector is built at its exact length")
        };
        let empty_sync_committee = || altair::SyncCommittee {
            pubkeys: vec![Default::default(); preset::SYNC_COMMITTEE_SIZE]
                .try_into()
                .expect("built at exactly SYNC_COMMITTEE_SIZE"),
            aggregate_pubkey: Default::default(),
        };

        BeaconState::Fulu(fulu::BeaconState {
            genesis_time: 0,
            genesis_validators_root: Root::ZERO,
            slot: preset::SLOTS_PER_EPOCH,
            fork: Default::default(),
            latest_block_header: Default::default(),
            block_roots: zero_root_vector(),
            state_roots: zero_root_vector(),
            historical_roots: Default::default(),
            eth1_data: Default::default(),
            eth1_data_votes: Default::default(),
            eth1_deposit_index: 0,
            validators: validators
                .try_into()
                .expect("count is far below VALIDATOR_REGISTRY_LIMIT"),
            balances: vec![preset::MAX_EFFECTIVE_BALANCE; count]
                .try_into()
                .expect("count is far below VALIDATOR_REGISTRY_LIMIT"),
            randao_mixes: vec![Bytes32::ZERO; preset::EPOCHS_PER_HISTORICAL_VECTOR]
                .try_into()
                .expect("the vector is built at its exact length"),
            slashings: vec![0; preset::EPOCHS_PER_SLASHINGS_VECTOR]
                .try_into()
                .expect("the vector is built at its exact length"),
            previous_epoch_participation: vec![0; count]
                .try_into()
                .expect("count is far below VALIDATOR_REGISTRY_LIMIT"),
            current_epoch_participation: vec![0; count]
                .try_into()
                .expect("count is far below VALIDATOR_REGISTRY_LIMIT"),
            justification_bits: Default::default(),
            previous_justified_checkpoint: Default::default(),
            current_justified_checkpoint: Default::default(),
            finalized_checkpoint: Default::default(),
            inactivity_scores: vec![0; count]
                .try_into()
                .expect("count is far below VALIDATOR_REGISTRY_LIMIT"),
            current_sync_committee: empty_sync_committee(),
            next_sync_committee: empty_sync_committee(),
            latest_execution_payload_header: deneb::ExecutionPayloadHeader {
                parent_hash: ExecutionBlockHash::ZERO,
                fee_recipient: ExecutionAddress::ZERO,
                state_root: Bytes32::ZERO,
                receipts_root: Bytes32::ZERO,
                logs_bloom: vec![0u8; preset::BYTES_PER_LOGS_BLOOM]
                    .try_into()
                    .expect("built at exactly BYTES_PER_LOGS_BLOOM"),
                prev_randao: Bytes32::ZERO,
                block_number: 0,
                gas_limit: 0,
                gas_used: 0,
                timestamp: 0,
                extra_data: Default::default(),
                base_fee_per_gas: Uint256::ZERO,
                block_hash: ExecutionBlockHash::ZERO,
                transactions_root: Root::ZERO,
                withdrawals_root: Root::ZERO,
                blob_gas_used: 0,
                excess_blob_gas: 0,
            },
            next_withdrawal_index: 0,
            next_withdrawal_validator_index: 0,
            historical_summaries: Default::default(),
            deposit_requests_start_index: constants::UNSET_DEPOSIT_REQUESTS_START_INDEX,
            deposit_balance_to_consume: 0,
            exit_balance_to_consume: 0,
            earliest_exit_epoch: 0,
            consolidation_balance_to_consume: 0,
            earliest_consolidation_epoch: 0,
            pending_deposits: Default::default(),
            pending_partial_withdrawals: Default::default(),
            pending_consolidations: Default::default(),
            proposer_lookahead: vec![0; preset::PROPOSER_LOOKAHEAD_LENGTH]
                .try_into()
                .expect("the vector is built at its exact length"),
        })
    }

    /// A Gloas state with `count` validators, mirroring [`small_fulu_state`]
    /// but for gloas's progressive registry
    /// ([`ProgressiveValidators`]/[`ProgressiveBalances`]) and its own
    /// builder/payload fields, each at an all-zero or empty placeholder.
    /// Good enough for the registry accessor tests below, which touch
    /// `validators`/`balances` only.
    fn small_gloas_state(count: usize) -> BeaconState {
        let validators: Vec<Validator> = (0..count)
            .map(|_| Validator {
                effective_balance: preset::MAX_EFFECTIVE_BALANCE,
                activation_eligibility_epoch: 0,
                activation_epoch: 0,
                exit_epoch: constants::FAR_FUTURE_EPOCH,
                withdrawable_epoch: constants::FAR_FUTURE_EPOCH,
                ..Default::default()
            })
            .collect();
        let zero_root_vector = || -> BlockRoots {
            vec![Root::ZERO; preset::SLOTS_PER_HISTORICAL_ROOT]
                .try_into()
                .expect("the vector is built at its exact length")
        };
        let empty_sync_committee = || altair::SyncCommittee {
            pubkeys: vec![Default::default(); preset::SYNC_COMMITTEE_SIZE]
                .try_into()
                .expect("built at exactly SYNC_COMMITTEE_SIZE"),
            aggregate_pubkey: Default::default(),
        };
        let empty_ptc: gloas::PayloadTimelinessCommittee = vec![0u64; preset::PTC_SIZE]
            .try_into()
            .expect("built at exactly PTC_SIZE");

        BeaconState::Gloas(gloas::BeaconState {
            genesis_time: 0,
            genesis_validators_root: Root::ZERO,
            slot: preset::SLOTS_PER_EPOCH,
            fork: Default::default(),
            latest_block_header: Default::default(),
            block_roots: zero_root_vector(),
            state_roots: zero_root_vector(),
            historical_roots: Default::default(),
            eth1_data: Default::default(),
            eth1_data_votes: Default::default(),
            eth1_deposit_index: 0,
            validators: validators.into(),
            balances: vec![preset::MAX_EFFECTIVE_BALANCE; count].into(),
            randao_mixes: vec![Bytes32::ZERO; preset::EPOCHS_PER_HISTORICAL_VECTOR]
                .try_into()
                .expect("the vector is built at its exact length"),
            slashings: vec![0; preset::EPOCHS_PER_SLASHINGS_VECTOR]
                .try_into()
                .expect("the vector is built at its exact length"),
            previous_epoch_participation: vec![0; count].into(),
            current_epoch_participation: vec![0; count].into(),
            justification_bits: Default::default(),
            previous_justified_checkpoint: Default::default(),
            current_justified_checkpoint: Default::default(),
            finalized_checkpoint: Default::default(),
            inactivity_scores: vec![0; count].into(),
            current_sync_committee: empty_sync_committee(),
            next_sync_committee: empty_sync_committee(),
            latest_block_hash: ExecutionBlockHash::ZERO,
            next_withdrawal_index: 0,
            next_withdrawal_validator_index: 0,
            historical_summaries: Default::default(),
            deposit_requests_start_index: constants::UNSET_DEPOSIT_REQUESTS_START_INDEX,
            deposit_balance_to_consume: 0,
            exit_balance_to_consume: 0,
            earliest_exit_epoch: 0,
            consolidation_balance_to_consume: 0,
            earliest_consolidation_epoch: 0,
            pending_deposits: Default::default(),
            pending_partial_withdrawals: Default::default(),
            pending_consolidations: Default::default(),
            proposer_lookahead: vec![0; preset::PROPOSER_LOOKAHEAD_LENGTH]
                .try_into()
                .expect("the vector is built at its exact length"),
            builders: Default::default(),
            next_withdrawal_builder_index: 0,
            execution_payload_availability: Default::default(),
            builder_pending_payments: vec![
                gloas::BuilderPendingPayment::default();
                preset::BUILDER_PENDING_PAYMENTS_LENGTH
            ]
            .try_into()
            .expect("the vector is built at its exact length"),
            builder_pending_withdrawals: Default::default(),
            latest_execution_payload_bid: Default::default(),
            payload_expected_withdrawals: Default::default(),
            ptc_window: vec![empty_ptc; preset::PTC_WINDOW_LENGTH]
                .try_into()
                .expect("the vector is built at its exact length"),
        })
    }

    #[test]
    fn registry_accessors_read_and_write_elements() {
        let mut state = small_fulu_state(3); // 3 validators, balances 32 ETH
        assert_eq!(state.validator_count(), 3);
        assert_eq!(state.iter_validators().len(), 3);
        assert_eq!(
            state.iter_balances().sum::<Gwei>(),
            3 * preset::MAX_EFFECTIVE_BALANCE
        );

        *state.balance_mut(1).unwrap() += 5;
        assert_eq!(state.balance(1).unwrap(), preset::MAX_EFFECTIVE_BALANCE + 5);

        let validator = state.validator(0).unwrap().clone();
        state.push_validator(validator, 7).unwrap();
        assert_eq!(state.validator_count(), 4);
        assert_eq!(state.balance(3).unwrap(), 7);
        assert!(state.balance_mut(4).is_err());
        assert!(state.validator(4).is_err());

        // Order, the pending balance write, and the pending push all land
        // where expected.
        assert_eq!(
            state.iter_balances().collect::<Vec<_>>(),
            vec![
                preset::MAX_EFFECTIVE_BALANCE,
                preset::MAX_EFFECTIVE_BALANCE + 5,
                preset::MAX_EFFECTIVE_BALANCE,
                7,
            ]
        );

        // A `validator_mut` write is visible through `iter_validators`, not
        // just through `validator`.
        state.validator_mut(2).unwrap().effective_balance = 1;
        assert_eq!(state.iter_validators().nth(2).unwrap().effective_balance, 1);
    }

    /// Same coverage as `registry_accessors_read_and_write_elements`, on a
    /// gloas state instead of a fulu one: the registry there is a
    /// [`ethlambda_ssz_tree::ProgressiveList`] (`Registry::Progressive`), not
    /// a bounded [`List`], and this is what proves the element accessors
    /// take that arm too rather than only ever exercising
    /// `Registry::Bounded`.
    #[test]
    fn gloas_registry_accessors_read_and_write_elements() {
        let mut state = small_gloas_state(3); // 3 validators, balances 32 ETH
        assert_eq!(state.validator_count(), 3);
        assert_eq!(state.iter_validators().len(), 3);
        assert_eq!(
            state.iter_balances().sum::<Gwei>(),
            3 * preset::MAX_EFFECTIVE_BALANCE
        );

        *state.balance_mut(1).unwrap() += 5;
        assert_eq!(state.balance(1).unwrap(), preset::MAX_EFFECTIVE_BALANCE + 5);

        let validator = state.validator(0).unwrap().clone();
        state.push_validator(validator, 7).unwrap();
        assert_eq!(state.validator_count(), 4);
        assert_eq!(state.balance(3).unwrap(), 7);
        assert!(state.balance_mut(4).is_err());
        assert!(state.validator(4).is_err());

        assert_eq!(
            state.iter_balances().collect::<Vec<_>>(),
            vec![
                preset::MAX_EFFECTIVE_BALANCE,
                preset::MAX_EFFECTIVE_BALANCE + 5,
                preset::MAX_EFFECTIVE_BALANCE,
                7,
            ]
        );

        state.validator_mut(2).unwrap().effective_balance = 1;
        assert_eq!(state.iter_validators().nth(2).unwrap().effective_balance, 1);
    }

    /// [`BeaconState::rebase_on`] and [`BeaconState::validators_ptr_eq`]
    /// across two gloas states: the `Registry::Progressive` arm of both,
    /// which nothing above exercises. Two independently built states with
    /// equal content start out backed by different allocations
    /// (`validators_ptr_eq` false); `rebase_on` shares every subtree the
    /// content agrees on, so `validators_ptr_eq` becomes true afterward, the
    /// same invariant the storage crate's tests rely on for a decoded state
    /// rebased onto its resident parent.
    #[test]
    fn gloas_registry_rebases_onto_an_equal_gloas_parent() {
        let base = small_gloas_state(3);
        let mut derived = small_gloas_state(3);
        assert!(!derived.validators_ptr_eq(&base));

        derived.rebase_on(&base);
        assert!(derived.validators_ptr_eq(&base));
    }

    /// A fulu state and a gloas state disagree on registry list kind
    /// (`Registry::Bounded` vs `Registry::Progressive`), which is exactly
    /// the fork boundary [`BeaconState::rebase_on`]'s own documentation
    /// describes as a no-op: there is no shared tree to reuse between a
    /// bounded and a progressive registry. Pins that the mismatch is
    /// silently inert rather than a panic, and changes nothing about either
    /// state.
    #[test]
    fn a_fulu_and_a_gloas_registry_do_not_rebase_across_the_fork_boundary() {
        let fulu = small_fulu_state(3);
        let mut gloas = small_gloas_state(3);
        let before = gloas.clone();

        gloas.rebase_on(&fulu);

        assert_eq!(gloas, before, "a mixed-kind rebase must be a no-op");
        assert!(!gloas.validators_ptr_eq(&fulu));
    }

    /// Single-validator lean state. The pubkeys are placeholders; nothing here
    /// verifies a signature.
    fn lean_state(genesis_time: u64, attestation_pubkey: u8) -> crate::state::State {
        crate::state::State::from_genesis(
            genesis_time,
            vec![crate::state::Validator {
                attestation_pubkey: [attestation_pubkey; crate::state::PUBLIC_KEY_SIZE],
                proposal_pubkey: [2u8; crate::state::PUBLIC_KEY_SIZE],
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
    fn a_lean_block_reports_its_body_root() {
        let block = crate::block::SignedBlock {
            message: crate::block::Block {
                slot: 1,
                proposer_index: 0,
                parent_root: crate::primitives::H256::ZERO,
                state_root: crate::primitives::H256::ZERO,
                body: crate::block::BlockBody::default(),
            },
            proof: crate::block::MultiMessageAggregate::default(),
        };
        let expected =
            crate::primitives::HashTreeRoot::hash_tree_root(&crate::block::BlockBody::default());

        let wrapped = SignedBeaconBlock::Lean(block);
        assert_eq!(wrapped.body_root(), expected);
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

    // -- execution_block_hash --

    /// An otherwise-empty phase0 block, built field by field: phase0's
    /// containers derive `Debug, Clone, PartialEq, Eq, SszEncode, SszDecode,
    /// HashTreeRoot` but not `Default`, unlike their sub-fields.
    ///
    /// Only phase0 is built here. `execution_block_hash`'s implementation
    /// groups `Phase0`, `Altair` and `Lean` into one match arm
    /// (`Self::Phase0(_) | Self::Altair(_) | Self::Lean(_) => None`), so an
    /// Altair block would only prove something about the enum, not about the
    /// method; Lean's `SignedBlock` does not derive `Default` either, which
    /// would make it the most expensive of the three to build for no extra
    /// coverage.
    fn empty_phase0_signed_block() -> phase0::SignedBeaconBlock {
        phase0::SignedBeaconBlock {
            message: phase0::BeaconBlock {
                slot: 0,
                proposer_index: 0,
                parent_root: Root::default(),
                state_root: Root::default(),
                body: phase0::BeaconBlockBody {
                    randao_reveal: BlsSignature::default(),
                    eth1_data: Eth1Data::default(),
                    graffiti: Bytes32::default(),
                    proposer_slashings: Default::default(),
                    attester_slashings: Default::default(),
                    attestations: Default::default(),
                    deposits: Default::default(),
                    voluntary_exits: Default::default(),
                },
            },
            signature: BlsSignature::default(),
        }
    }

    /// An otherwise-empty electra-shaped block whose execution payload's own
    /// `block_hash` is `block_hash`.
    ///
    /// Also stands in for a fulu block: [`SignedBeaconBlock::Fulu`] wraps
    /// this same [`electra::SignedBeaconBlock`] type rather than a
    /// fulu-specific one (see that variant's own doc), so this builder is
    /// shared rather than duplicated.
    fn empty_electra_signed_block(block_hash: ExecutionBlockHash) -> electra::SignedBeaconBlock {
        electra::SignedBeaconBlock {
            message: electra::BeaconBlock {
                slot: 0,
                proposer_index: 0,
                parent_root: Root::default(),
                state_root: Root::default(),
                body: electra::BeaconBlockBody {
                    randao_reveal: BlsSignature::default(),
                    eth1_data: Eth1Data::default(),
                    graffiti: Bytes32::default(),
                    proposer_slashings: Default::default(),
                    attester_slashings: Default::default(),
                    attestations: Default::default(),
                    deposits: Default::default(),
                    voluntary_exits: Default::default(),
                    sync_aggregate: altair::SyncAggregate::default(),
                    execution_payload: deneb::ExecutionPayload {
                        parent_hash: ExecutionBlockHash::default(),
                        fee_recipient: ExecutionAddress::default(),
                        state_root: Bytes32::default(),
                        receipts_root: Bytes32::default(),
                        // A fixed-length vector rather than a list, so unlike
                        // its neighbors it has no `Default`; sized by hand.
                        logs_bloom: bellatrix::LogsBloom::try_from(vec![
                            0u8;
                            preset::BYTES_PER_LOGS_BLOOM
                        ])
                        .expect("built at exactly BYTES_PER_LOGS_BLOOM"),
                        prev_randao: Bytes32::default(),
                        block_number: 0,
                        gas_limit: 0,
                        gas_used: 0,
                        timestamp: 0,
                        extra_data: Default::default(),
                        base_fee_per_gas: Uint256::default(),
                        block_hash,
                        transactions: Default::default(),
                        withdrawals: Default::default(),
                        blob_gas_used: 0,
                        excess_blob_gas: 0,
                    },
                    bls_to_execution_changes: Default::default(),
                    blob_kzg_commitments: Default::default(),
                    execution_requests: electra::ExecutionRequests {
                        deposits: Default::default(),
                        withdrawals: Default::default(),
                        consolidations: Default::default(),
                    },
                },
            },
            signature: BlsSignature::default(),
        }
    }

    #[test]
    fn execution_block_hash_is_none_before_the_merge() {
        let block = SignedBeaconBlock::Phase0(empty_phase0_signed_block());
        assert_eq!(block.execution_block_hash(), None);
    }

    #[test]
    fn execution_block_hash_reads_the_electra_payloads_own_hash() {
        let expected = ExecutionBlockHash::repeat_byte(7);
        let block = SignedBeaconBlock::Electra(empty_electra_signed_block(expected));
        assert_eq!(block.execution_block_hash(), Some(expected));
    }

    #[test]
    fn execution_block_hash_reads_the_fulu_payloads_own_hash() {
        // Kept separate from the electra test above: `Fulu` wraps
        // `electra::SignedBeaconBlock` (an enum quirk explained on
        // `SignedBeaconBlock::Fulu`'s own doc), so this pins that the *enum
        // variant* reaches the right match arm, not just the wrapped struct.
        let expected = ExecutionBlockHash::repeat_byte(7);
        let block = SignedBeaconBlock::Fulu(empty_electra_signed_block(expected));
        assert_eq!(block.execution_block_hash(), Some(expected));
    }

    // -- body_root --

    #[test]
    fn a_beacon_blocks_body_root_is_its_bodys_own_merkle_root() {
        // Computed independently of `body_root`'s own implementation, through
        // the raw `libssz_merkle` trait rather than this crate's convenience
        // wrapper, so a body_root that only ever ran on the lean arm would be
        // caught here rather than passing by construction.
        let signed = empty_phase0_signed_block();
        let body = signed.message.body.clone();
        let expected = crate::primitives::H256(libssz_merkle::HashTreeRoot::hash_tree_root(
            &body,
            &libssz_merkle::Sha2Hasher,
        ));

        let block = SignedBeaconBlock::Phase0(signed);
        assert_eq!(block.body_root(), expected);
    }

    #[test]
    fn a_fulu_block_reports_its_blob_commitments_and_payload_timestamp() {
        use crate::beacon::containers::electra;
        use crate::beacon::primitives::{KzgCommitment, Root};

        let mut body = electra::BeaconBlockBody::empty();
        body.execution_payload.timestamp = 1_234;
        body.blob_kzg_commitments = vec![KzgCommitment::default(); 3]
            .try_into()
            .expect("within MAX_BLOB_COMMITMENTS_PER_BLOCK");
        let block = SignedBeaconBlock::Fulu(electra::SignedBeaconBlock {
            message: electra::BeaconBlock {
                slot: 1,
                proposer_index: 0,
                parent_root: Root::ZERO,
                state_root: Root::ZERO,
                body,
            },
            signature: Default::default(),
        });

        assert_eq!(block.blob_kzg_commitment_count(), 3);
        assert_eq!(block.execution_payload_timestamp(), Some(1_234));
    }

    #[test]
    fn a_phase0_block_has_no_blob_commitments_and_no_payload() {
        use crate::beacon::containers::phase0;
        use crate::beacon::primitives::Root;

        let block = SignedBeaconBlock::Phase0(phase0::SignedBeaconBlock {
            message: phase0::BeaconBlock {
                slot: 1,
                proposer_index: 0,
                parent_root: Root::ZERO,
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
        });

        assert_eq!(block.blob_kzg_commitment_count(), 0);
        assert_eq!(block.execution_payload_timestamp(), None);
    }

    fn fulu_sidecar(index: u64, header: BeaconBlockHeader) -> fulu::DataColumnSidecar {
        fulu::DataColumnSidecar {
            index,
            column: Default::default(),
            kzg_commitments: Default::default(),
            kzg_proofs: Default::default(),
            signed_block_header: SignedBeaconBlockHeader {
                message: header,
                signature: Default::default(),
            },
            kzg_commitments_inclusion_proof: vec![
                Root::ZERO;
                preset::KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH
            ]
            .try_into()
            .unwrap(),
        }
    }

    #[test]
    fn a_data_column_sidecar_round_trips_per_fork() {
        let header = BeaconBlockHeader {
            slot: 9,
            ..Default::default()
        };
        let fulu = DataColumnSidecar::Fulu(fulu_sidecar(7, header));
        let gloas = DataColumnSidecar::Gloas(gloas::DataColumnSidecar {
            index: 3,
            slot: 11,
            beacon_block_root: Root::from([5; 32]),
            ..Default::default()
        });
        for sidecar in [fulu, gloas] {
            let decoded = DataColumnSidecar::from_ssz(sidecar.fork(), &sidecar.to_ssz()).unwrap();
            assert_eq!(decoded, sidecar);
        }
    }

    #[test]
    fn a_data_column_sidecar_reports_its_block_root_per_variant() {
        let header = BeaconBlockHeader {
            slot: 9,
            proposer_index: 2,
            ..Default::default()
        };
        let fulu = DataColumnSidecar::Fulu(fulu_sidecar(7, header.clone()));
        assert_eq!(fulu.block_root(), header.hash_tree_root());
        assert_eq!((fulu.index(), fulu.slot()), (7, 9));
        assert_eq!(fulu.fork(), ForkName::Fulu);

        let root = Root::from([5; 32]);
        let gloas = DataColumnSidecar::Gloas(gloas::DataColumnSidecar {
            index: 3,
            slot: 11,
            beacon_block_root: root,
            ..Default::default()
        });
        assert_eq!(gloas.block_root(), root);
        assert_eq!((gloas.index(), gloas.slot()), (3, 11));
        assert_eq!(gloas.fork(), ForkName::Gloas);
    }

    #[test]
    fn a_data_column_sidecar_does_not_decode_before_fulu_or_as_lean() {
        let valid = DataColumnSidecar::Fulu(fulu_sidecar(7, BeaconBlockHeader::default())).to_ssz();
        // Bytes that decode fine as fulu's, so the error can only be the fork.
        assert!(DataColumnSidecar::from_ssz(ForkName::Fulu, &valid).is_ok());
        for fork in [ForkName::Electra, ForkName::Lean] {
            assert!(matches!(
                DataColumnSidecar::from_ssz(fork, &valid),
                Err(Error::UnsupportedForFork { fork: got, .. }) if got == fork
            ));
        }
    }
}
