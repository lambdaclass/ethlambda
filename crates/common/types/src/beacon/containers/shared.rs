//! Containers whose definition does not change between forks, and the SSZ
//! collection aliases the per-fork modules build on.
//!
//! A container belongs here only if every fork that has it defines it
//! identically. Anything a fork reshapes lives in that fork's module instead, so
//! that a reader looking for "what changed in electra" finds it in one place.
//!
//! This module grows as forks land. It currently covers what phase0 needs.

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::{SszBitvector, SszList, SszVector};

use crate::beacon::constants;
use crate::beacon::preset;
use crate::beacon::primitives::{
    BlsPubkey, BlsSignature, Bytes32, CommitteeIndex, Domain, Epoch, Gwei, ParticipationFlags,
    Root, Slot, ValidatorIndex, Version,
};

// ---------------------------------------------------------------------------
// Collection aliases
// ---------------------------------------------------------------------------
//
// A const-generic argument that is a path needs braces, so these read
// `{ preset::X }` rather than `preset::X`.

/// The rolling window of recent block roots the state keeps, indexed by slot
/// modulo its length so it acts as a ring buffer.
pub type BlockRoots = SszVector<Root, { preset::SLOTS_PER_HISTORICAL_ROOT }>;

/// The rolling window of recent state roots, indexed the same way as
/// [`BlockRoots`].
pub type StateRoots = SszVector<Root, { preset::SLOTS_PER_HISTORICAL_ROOT }>;

/// Accumulated roots of [`HistoricalBatch`], one appended per historical batch,
/// which is how the chain keeps a commitment to history older than the rolling
/// windows without keeping the roots themselves.
pub type HistoricalRoots = SszList<Root, { preset::HISTORICAL_ROOTS_LIMIT }>;

/// Eth1 data votes accumulated over one voting period, tallied and then reset.
pub type Eth1DataVotes = SszList<Eth1Data, { preset::SLOTS_PER_ETH1_VOTING_PERIOD }>;

/// The validator registry. Append-only: a validator is never removed, only
/// exited, since indices are referenced by attestations and must stay stable.
pub type Validators = SszList<Validator, { preset::VALIDATOR_REGISTRY_LIMIT }>;

/// Balances, positionally parallel to [`Validators`].
///
/// Kept separate from the registry rather than as a `Validator` field because it
/// changes every epoch while the rest of a validator's record rarely does, and a
/// separate list means rewards do not redirty the registry's merkle tree.
pub type Balances = SszList<Gwei, { preset::VALIDATOR_REGISTRY_LIMIT }>;

/// Past randao mixes, indexed by epoch modulo the vector length, so the state
/// retains a bounded history of the beacon chain's randomness.
pub type RandaoMixes = SszVector<Bytes32, { preset::EPOCHS_PER_HISTORICAL_VECTOR }>;

/// Slashed balance totals per epoch, indexed by epoch modulo the vector length.
/// Epoch processing reads the whole vector to size the proportional slashing
/// penalty, which is what makes correlated slashings cost more than isolated
/// ones.
pub type Slashings = SszVector<Gwei, { preset::EPOCHS_PER_SLASHINGS_VECTOR }>;

/// One bit per recent epoch recording whether it was justified, which is the
/// state that lets finalization look back over several epochs at once.
pub type JustificationBits = SszBitvector<{ constants::JUSTIFICATION_BITS_LENGTH }>;

/// The merkle path proving a deposit against the deposit contract's root.
///
/// One longer than the contract's tree depth, since the extra node is the
/// mix-in of the deposit count.
pub type DepositProof = SszVector<Bytes32, { constants::DEPOSIT_CONTRACT_TREE_DEPTH + 1 }>;

/// Per-validator participation flags for one epoch, positionally parallel to
/// [`Validators`]. Altair uses this in place of phase0's accumulated
/// attestations.
pub type EpochParticipation = SszList<ParticipationFlags, { preset::VALIDATOR_REGISTRY_LIMIT }>;

/// Per-validator inactivity scores, positionally parallel to [`Validators`]
/// (altair and later).
pub type InactivityScores = SszList<u64, { preset::VALIDATOR_REGISTRY_LIMIT }>;

/// Accumulated [`HistoricalSummary`] entries, which replace [`HistoricalRoots`]
/// as the commitment to history from capella onward.
pub type HistoricalSummaries = SszList<HistoricalSummary, { preset::HISTORICAL_ROOTS_LIMIT }>;

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

/// Which fork the chain is on, and which one it came from.
///
/// Both versions are kept because a signature is verified under the fork version
/// in effect when the message was signed, so a message from just before a fork
/// boundary still verifies just after it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct Fork {
    /// The version in effect before [`Fork::epoch`].
    pub previous_version: Version,
    /// The version in effect from [`Fork::epoch`] onward.
    pub current_version: Version,
    /// The epoch at which `current_version` took effect.
    pub epoch: Epoch,
}

/// A fork version paired with the chain's genesis validators root, hashed
/// together to produce a signing domain.
///
/// Including the genesis validators root is what separates two chains running
/// the same fork schedule: a signature from one never verifies on the other.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct ForkData {
    pub current_version: Version,
    pub genesis_validators_root: Root,
}

/// An epoch and the block root at its start: what attestations vote on and what
/// justification and finalization track.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct Checkpoint {
    pub epoch: Epoch,
    /// The root of the first block of [`Checkpoint::epoch`], or of the most
    /// recent block before it if that slot was empty.
    pub root: Root,
}

/// A registry entry for one validator.
#[derive(Debug, Clone, Default, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct Validator {
    /// The key attestations and proposals are signed with.
    pub pubkey: BlsPubkey,
    /// Where a withdrawal pays out. The first byte selects how the rest is
    /// interpreted; see the prefixes in [`crate::beacon::constants`].
    pub withdrawal_credentials: Bytes32,
    /// The balance actually used for voting weight and rewards, which is the
    /// real balance rounded down to a multiple of `EFFECTIVE_BALANCE_INCREMENT`
    /// and capped. Rounding with hysteresis is what keeps the merkle tree from
    /// being redirtied by every small balance change.
    pub effective_balance: Gwei,
    pub slashed: bool,
    /// The epoch the validator's balance first reached the activation minimum,
    /// making it a candidate for activation. Distinct from
    /// [`Validator::activation_epoch`], which is when the churn limit actually
    /// let it in: eligibility is immediate, activation is queued.
    pub activation_eligibility_epoch: Epoch,
    /// The epoch the validator became active.
    pub activation_epoch: Epoch,
    /// The epoch the validator stops being active.
    pub exit_epoch: Epoch,
    /// The epoch the validator's balance may be withdrawn, which lags
    /// [`Validator::exit_epoch`] so that slashable offences remain punishable
    /// for a while after exit.
    pub withdrawable_epoch: Epoch,
}

/// What an attestation actually attests to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct AttestationData {
    /// The slot being attested for.
    pub slot: Slot,
    /// Which of the slot's committees the attester belongs to.
    pub index: CommitteeIndex,
    /// The attester's view of the head of the chain, which is the LMD GHOST
    /// vote.
    pub beacon_block_root: Root,
    /// The justified checkpoint the attester builds on, which is the FFG vote's
    /// source.
    pub source: Checkpoint,
    /// The checkpoint the attester is trying to justify, which is the FFG vote's
    /// target.
    pub target: Checkpoint,
}

/// The execution chain's deposit state, as voted on by proposers.
#[derive(Debug, Clone, Default, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct Eth1Data {
    /// The deposit contract's merkle root at this point.
    pub deposit_root: Root,
    /// The total number of deposits the contract has ever seen, not the number
    /// still unprocessed.
    pub deposit_count: u64,
    pub block_hash: Root,
}

/// The parts of an execution layer block a proposer needs in order to vote on
/// [`Eth1Data`].
///
/// The specification defines only these three fields and notes the rest are
/// omitted, since nothing in consensus reads them.
#[derive(Debug, Clone, Default, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct Eth1Block {
    pub timestamp: u64,
    pub deposit_root: Root,
    pub deposit_count: u64,
}

/// A window of block and state roots, whose root is appended to
/// [`HistoricalRoots`] once the window is full.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct HistoricalBatch {
    pub block_roots: BlockRoots,
    pub state_roots: StateRoots,
}

/// A commitment to one historical window, replacing [`HistoricalBatch`] roots
/// from capella onward.
///
/// Keeping the two roots separately, rather than hashing them together as
/// [`HistoricalBatch`] does, is what lets a light client prove a block root
/// against history without also having the state roots.
#[derive(Debug, Clone, Default, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct HistoricalSummary {
    pub block_summary_root: Root,
    pub state_summary_root: Root,
}

/// A root paired with the domain it is signed under, hashed together to give the
/// message a signature actually covers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct SigningData {
    pub object_root: Root,
    pub domain: Domain,
}

// ---------------------------------------------------------------------------
// Deposits
// ---------------------------------------------------------------------------

/// The part of a deposit a depositor signs.
///
/// Separate from [`DepositData`] precisely because the signature cannot cover
/// itself: the signature in `DepositData` is over the `DepositMessage` with the
/// same fields.
#[derive(Debug, Clone, Default, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct DepositMessage {
    pub pubkey: BlsPubkey,
    pub withdrawal_credentials: Bytes32,
    pub amount: Gwei,
}

/// A deposit as recorded by the deposit contract.
#[derive(Debug, Clone, Default, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct DepositData {
    pub pubkey: BlsPubkey,
    pub withdrawal_credentials: Bytes32,
    pub amount: Gwei,
    /// Proof of possession over the corresponding [`DepositMessage`]. An invalid
    /// signature does not make the deposit invalid: it is simply not credited to
    /// a new validator, which is why the public key here is never assumed to be a
    /// valid curve point.
    pub signature: BlsSignature,
}

/// A deposit together with its merkle proof against the deposit contract root.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct Deposit {
    pub proof: DepositProof,
    pub data: DepositData,
}

// ---------------------------------------------------------------------------
// Block headers and operations
// ---------------------------------------------------------------------------

/// A block without its body, which is what the state retains and what proposer
/// slashings compare.
#[derive(Debug, Clone, Default, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct BeaconBlockHeader {
    pub slot: Slot,
    pub proposer_index: ValidatorIndex,
    pub parent_root: Root,
    /// The root of the state after applying this block. Left zero in the state's
    /// own copy of the latest header until the slot advances, since a block
    /// cannot commit to the root of the state that contains it.
    pub state_root: Root,
    /// The root of the body, which is what lets the header stand in for the
    /// whole block.
    pub body_root: Root,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct SignedBeaconBlockHeader {
    pub message: BeaconBlockHeader,
    pub signature: BlsSignature,
}

/// Evidence that a proposer signed two different blocks for the same slot.
#[derive(Debug, Clone, Default, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct ProposerSlashing {
    pub signed_header_1: SignedBeaconBlockHeader,
    pub signed_header_2: SignedBeaconBlockHeader,
}

/// A validator's request to stop validating.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct VoluntaryExit {
    /// The earliest epoch the exit may be processed at.
    pub epoch: Epoch,
    pub validator_index: ValidatorIndex,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct SignedVoluntaryExit {
    pub message: VoluntaryExit,
    pub signature: BlsSignature,
}

#[cfg(test)]
mod tests {
    use libssz::{SszDecode as _, SszEncode as _};

    use super::*;

    #[test]
    fn checkpoint_is_fixed_size() {
        // An epoch and a root, with nothing variable-length, so the encoding has
        // one length for every value.
        assert!(<Checkpoint as libssz::SszEncode>::is_fixed_size());
        assert_eq!(<Checkpoint as libssz::SszEncode>::fixed_size(), 8 + 32);
    }

    #[test]
    fn validator_round_trips_through_ssz() {
        let validator = Validator {
            pubkey: BlsPubkey([3; 48]),
            withdrawal_credentials: Bytes32::repeat_byte(7),
            effective_balance: 32_000_000_000,
            slashed: true,
            activation_eligibility_epoch: 1,
            activation_epoch: 2,
            exit_epoch: 3,
            withdrawable_epoch: 4,
        };

        let bytes = validator.to_ssz();
        assert_eq!(Validator::from_ssz_bytes(&bytes).unwrap(), validator);
    }

    #[test]
    fn deposit_is_fixed_size_despite_holding_a_proof() {
        // Every field of a Deposit is itself fixed-length, including the proof
        // vector, so the container is fixed-size and carries no offsets.
        assert!(<Deposit as libssz::SszEncode>::is_fixed_size());
    }

    #[test]
    fn every_fork_invariant_container_is_fixed_size() {
        // Worth asserting rather than assuming: none of the containers in this
        // module has a variable-length field, not even the ones holding
        // collections, since those collections are all `Vector`s of fixed-size
        // elements. Every variable-length container in phase0 (`Attestation` with
        // its bitlist, `BeaconBlockBody` with its operation lists, `BeaconState`)
        // is fork-specific and lives elsewhere. So an offset appearing anywhere
        // in this module's encodings would mean something changed shape.
        assert!(<Fork as libssz::SszEncode>::is_fixed_size());
        assert!(<ForkData as libssz::SszEncode>::is_fixed_size());
        assert!(<Validator as libssz::SszEncode>::is_fixed_size());
        assert!(<AttestationData as libssz::SszEncode>::is_fixed_size());
        assert!(<Eth1Data as libssz::SszEncode>::is_fixed_size());
        assert!(<Eth1Block as libssz::SszEncode>::is_fixed_size());
        assert!(<HistoricalBatch as libssz::SszEncode>::is_fixed_size());
        assert!(<HistoricalSummary as libssz::SszEncode>::is_fixed_size());
        assert!(<SigningData as libssz::SszEncode>::is_fixed_size());
        assert!(<DepositMessage as libssz::SszEncode>::is_fixed_size());
        assert!(<DepositData as libssz::SszEncode>::is_fixed_size());
        assert!(<BeaconBlockHeader as libssz::SszEncode>::is_fixed_size());
        assert!(<SignedBeaconBlockHeader as libssz::SszEncode>::is_fixed_size());
        assert!(<ProposerSlashing as libssz::SszEncode>::is_fixed_size());
        assert!(<VoluntaryExit as libssz::SszEncode>::is_fixed_size());
        assert!(<SignedVoluntaryExit as libssz::SszEncode>::is_fixed_size());
    }
}
