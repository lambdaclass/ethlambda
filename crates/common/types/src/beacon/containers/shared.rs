//! Containers whose definition does not change between forks, and the SSZ
//! collection aliases the per-fork modules build on.
//!
//! A container belongs here only if every fork that has it defines it
//! identically. Anything a fork reshapes lives in that fork's module instead, so
//! that a reader looking for "what changed in electra" finds it in one place.
//!
//! This module grows as forks land. It currently covers what phase0 needs.

use std::collections::BTreeMap;

use ethlambda_ssz_tree::{List, ProgressiveList as TreeProgressiveList, Vector};
use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::{SszBitvector, SszVector};

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
///
/// Tree-backed, like every large field: a slot writes one entry, so a derived
/// state shares nearly all of the buffer with its parent and rehashes only the
/// leaf it touched. Writes are buffered in a `BTreeMap`, since they are a
/// handful per flush, until `BeaconState::apply_pending_mutations`.
pub type BlockRoots = Vector<Root, { preset::SLOTS_PER_HISTORICAL_ROOT }, BTreeMap<usize, Root>>;

/// The rolling window of recent state roots, indexed the same way as
/// [`BlockRoots`].
pub type StateRoots = Vector<Root, { preset::SLOTS_PER_HISTORICAL_ROOT }, BTreeMap<usize, Root>>;

/// Accumulated roots of [`HistoricalBatch`], one appended per historical batch,
/// which is how the chain keeps a commitment to history older than the rolling
/// windows without keeping the roots themselves.
///
/// Tree-backed like [`BlockRoots`].
pub type HistoricalRoots = List<Root, { preset::HISTORICAL_ROOTS_LIMIT }, BTreeMap<usize, Root>>;

/// Eth1 data votes accumulated over one voting period, tallied and then reset.
///
/// Tree-backed like [`BlockRoots`].
pub type Eth1DataVotes =
    List<Eth1Data, { preset::SLOTS_PER_ETH1_VOTING_PERIOD }, BTreeMap<usize, Eth1Data>>;

/// The validator registry. Append-only: a validator is never removed, only
/// exited, since indices are referenced by attestations and must stay stable.
///
/// Kept in a persistent Merkle tree ([`List`]) rather than a `Vec`: a state
/// derived from another shares the unchanged part of the registry with it, and
/// re-hashing after a block only rehashes the records the block touched.
/// Writes are buffered in a `BTreeMap`, since they are rare and scattered,
/// until `BeaconState::apply_pending_mutations`.
pub type Validators =
    List<Validator, { preset::VALIDATOR_REGISTRY_LIMIT }, BTreeMap<usize, Validator>>;

/// Balances, positionally parallel to [`Validators`].
///
/// Kept separate from the registry rather than as a `Validator` field because it
/// changes every epoch while the rest of a validator's record rarely does, and a
/// separate list means rewards do not redirty the registry's merkle tree.
///
/// Tree-backed like [`Validators`], with writes buffered densely (the default
/// `VecMap`), since epoch processing writes every balance.
pub type Balances = List<Gwei, { preset::VALIDATOR_REGISTRY_LIMIT }>;

/// Past randao mixes, indexed by epoch modulo the vector length, so the state
/// retains a bounded history of the beacon chain's randomness.
///
/// Tree-backed like [`BlockRoots`].
pub type RandaoMixes =
    Vector<Bytes32, { preset::EPOCHS_PER_HISTORICAL_VECTOR }, BTreeMap<usize, Bytes32>>;

/// Slashed balance totals per epoch, indexed by epoch modulo the vector length.
/// Epoch processing reads the whole vector to size the proportional slashing
/// penalty, which is what makes correlated slashings cost more than isolated
/// ones.
///
/// Tree-backed like [`BlockRoots`].
pub type Slashings = Vector<Gwei, { preset::EPOCHS_PER_SLASHINGS_VECTOR }, BTreeMap<usize, Gwei>>;

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
///
/// Tree-backed: the state root otherwise re-merkleized both multi-megabyte
/// lists from scratch on every block, while a block flips flags for a few
/// thousand validators at most. With the tree, only the leaves holding those
/// validators are rehashed; a flag is one byte, so 32 share a chunk and a
/// block's writes dirty far fewer leaves than it has attesters.
///
/// Writes are buffered densely (the default `VecMap`), not in a `BTreeMap`
/// like the registry's. A block credits a thirty-second of the registry at
/// scattered positions, and measured at mainnet size the `BTreeMap`'s inserts
/// cost several times what the hashing it saves does (a few dozen
/// milliseconds against a few); the dense buffer is an indexed write, and its
/// slot-per-validator allocation is small next to that. The pass that writes
/// nearly every entry, the epoch rotation, does not buffer either: it replaces
/// the list with a freshly built one (see `process_participation_flag_updates`).
pub type EpochParticipation = List<ParticipationFlags, { preset::VALIDATOR_REGISTRY_LIMIT }>;

/// Per-validator inactivity scores, positionally parallel to [`Validators`]
/// (altair and later).
///
/// Tree-backed: outside a leak almost every score is zero and epoch processing
/// skips writes that change nothing, so a state derived from another shares
/// nearly the whole list with it and rehashes only the touched leaves. Writes
/// are buffered in a `BTreeMap`, since they are sparse in that case.
pub type InactivityScores = List<u64, { preset::VALIDATOR_REGISTRY_LIMIT }, BTreeMap<usize, u64>>;

/// Accumulated [`HistoricalSummary`] entries, which replace [`HistoricalRoots`]
/// as the commitment to history from capella onward.
///
/// Tree-backed like [`BlockRoots`].
pub type HistoricalSummaries =
    List<HistoricalSummary, { preset::HISTORICAL_ROOTS_LIMIT }, BTreeMap<usize, HistoricalSummary>>;

/// The gloas validator registry (EIP-7688): unbounded and progressively
/// merkleized, tree-backed like [`Validators`] for the same reason (a
/// derived state shares the unchanged part of the registry, and re-hashing
/// after a block only rehashes the records the block touched). Writes are
/// buffered sparsely in a `BTreeMap`, the same as [`Validators`].
pub type ProgressiveValidators = TreeProgressiveList<Validator, BTreeMap<usize, Validator>>;

/// The gloas balances, positionally parallel to [`ProgressiveValidators`].
/// Tree-backed like [`Balances`], with writes buffered densely (the default
/// `VecMap`), since epoch processing writes every balance.
pub type ProgressiveBalances = TreeProgressiveList<Gwei>;

/// The gloas participation flags, positionally parallel to
/// [`ProgressiveValidators`]. Tree-backed and buffered like [`EpochParticipation`].
pub type ProgressiveEpochParticipation = TreeProgressiveList<ParticipationFlags>;

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

/// Which fork the chain is on, and which one it came from.
///
/// Both versions are kept because a signature is verified under the fork version
/// in effect when the message was signed, so a message from just before a fork
/// boundary still verifies just after it.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot,
)]
pub struct Fork {
    /// The version in effect before [`Fork::epoch`].
    #[serde(with = "crate::beacon::serde_helpers::hex_array")]
    pub previous_version: Version,
    /// The version in effect from [`Fork::epoch`] onward.
    #[serde(with = "crate::beacon::serde_helpers::hex_array")]
    pub current_version: Version,
    /// The epoch at which `current_version` took effect.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub epoch: Epoch,
}

/// A fork version paired with the chain's genesis validators root, hashed
/// together to produce a signing domain.
///
/// Including the genesis validators root is what separates two chains running
/// the same fork schedule: a signature from one never verifies on the other.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot,
)]
pub struct ForkData {
    #[serde(with = "crate::beacon::serde_helpers::hex_array")]
    pub current_version: Version,
    pub genesis_validators_root: Root,
}

/// An epoch and the block root at its start: what attestations vote on and what
/// justification and finalization track.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct Checkpoint {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub epoch: Epoch,
    /// The root of the first block of [`Checkpoint::epoch`], or of the most
    /// recent block before it if that slot was empty.
    pub root: Root,
}

/// A registry entry for one validator.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot,
)]
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
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub effective_balance: Gwei,
    pub slashed: bool,
    /// The epoch the validator's balance first reached the activation minimum,
    /// making it a candidate for activation. Distinct from
    /// [`Validator::activation_epoch`], which is when the churn limit actually
    /// let it in: eligibility is immediate, activation is queued.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub activation_eligibility_epoch: Epoch,
    /// The epoch the validator became active.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub activation_epoch: Epoch,
    /// The epoch the validator stops being active.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub exit_epoch: Epoch,
    /// The epoch the validator's balance may be withdrawn, which lags
    /// [`Validator::exit_epoch`] so that slashable offences remain punishable
    /// for a while after exit.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub withdrawable_epoch: Epoch,
}

/// What an attestation actually attests to.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct AttestationData {
    /// The slot being attested for.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub slot: Slot,
    /// Which of the slot's committees the attester belongs to.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
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
#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct Eth1Data {
    /// The deposit contract's merkle root at this point.
    pub deposit_root: Root,
    /// The total number of deposits the contract has ever seen, not the number
    /// still unprocessed.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub deposit_count: u64,
    pub block_hash: Root,
}

/// The parts of an execution layer block a proposer needs in order to vote on
/// [`Eth1Data`].
///
/// The specification defines only these three fields and notes the rest are
/// omitted, since nothing in consensus reads them.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot,
)]
pub struct Eth1Block {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub timestamp: u64,
    pub deposit_root: Root,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub deposit_count: u64,
}

/// A window of block and state roots, whose root is appended to
/// [`HistoricalRoots`] once the window is full.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot)]
pub struct HistoricalBatch {
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub block_roots: BlockRoots,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub state_roots: StateRoots,
}

/// A commitment to one historical window, replacing [`HistoricalBatch`] roots
/// from capella onward.
///
/// Keeping the two roots separately, rather than hashing them together as
/// [`HistoricalBatch`] does, is what lets a light client prove a block root
/// against history without also having the state roots.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot,
)]
pub struct HistoricalSummary {
    pub block_summary_root: Root,
    pub state_summary_root: Root,
}

/// A root paired with the domain it is signed under, hashed together to give the
/// message a signature actually covers.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot,
)]
pub struct SigningData {
    pub object_root: Root,
    #[serde(with = "crate::beacon::serde_helpers::hex_array")]
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
#[derive(
    Debug, Clone, Default, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot,
)]
pub struct DepositMessage {
    pub pubkey: BlsPubkey,
    pub withdrawal_credentials: Bytes32,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub amount: Gwei,
}

/// A deposit as recorded by the deposit contract.
#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct DepositData {
    pub pubkey: BlsPubkey,
    pub withdrawal_credentials: Bytes32,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub amount: Gwei,
    /// Proof of possession over the corresponding [`DepositMessage`]. An invalid
    /// signature does not make the deposit invalid: it is simply not credited to
    /// a new validator, which is why the public key here is never assumed to be a
    /// valid curve point.
    pub signature: BlsSignature,
}

/// A deposit together with its merkle proof against the deposit contract root.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct Deposit {
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub proof: DepositProof,
    pub data: DepositData,
}

// ---------------------------------------------------------------------------
// Block headers and operations
// ---------------------------------------------------------------------------

/// A block without its body, which is what the state retains and what proposer
/// slashings compare.
#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct BeaconBlockHeader {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub slot: Slot,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
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

#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct SignedBeaconBlockHeader {
    pub message: BeaconBlockHeader,
    pub signature: BlsSignature,
}

/// Evidence that a proposer signed two different blocks for the same slot.
#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct ProposerSlashing {
    pub signed_header_1: SignedBeaconBlockHeader,
    pub signed_header_2: SignedBeaconBlockHeader,
}

/// A validator's request to stop validating.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct VoluntaryExit {
    /// The earliest epoch the exit may be processed at.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub epoch: Epoch,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub validator_index: ValidatorIndex,
}

#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
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

    /// Flags of mixed values, so a packing or ordering mistake changes the root.
    fn flags(len: usize) -> Vec<ParticipationFlags> {
        (0..len)
            .map(|i| (i * 7 % 8) as ParticipationFlags)
            .collect()
    }

    /// Lengths that hit an empty list, part of one chunk, exactly one chunk, a
    /// partial last chunk and several leaf pages.
    const LENGTHS: [usize; 8] = [0, 1, 31, 32, 33, 1000, 65_536 + 5, 300_001];

    #[test]
    fn tree_backed_participation_hashes_like_the_flat_list() {
        use crate::primitives::HashTreeRoot as _;
        type Flat = libssz_types::SszList<ParticipationFlags, { preset::VALIDATOR_REGISTRY_LIMIT }>;

        for len in LENGTHS {
            let values = flags(len);
            let flat = Flat::try_from(values.clone()).unwrap();
            let tree = EpochParticipation::try_from(values).unwrap();
            assert_eq!(tree.hash_tree_root(), flat.hash_tree_root(), "len {len}");
            assert_eq!(tree.to_ssz(), flat.to_ssz(), "len {len}");
        }
    }

    #[test]
    fn participation_writes_rehash_like_a_rebuilt_list() {
        use crate::primitives::HashTreeRoot as _;
        type Flat = libssz_types::SszList<ParticipationFlags, { preset::VALIDATOR_REGISTRY_LIMIT }>;

        let mut values = flags(70_000);
        let mut tree = EpochParticipation::try_from(values.clone()).unwrap();
        // Warm every cached hash, so the writes below must invalidate the paths
        // they touch rather than recompute the whole list.
        tree.apply_updates();
        let _ = tree.hash_tree_root();

        for index in [0usize, 31, 32, 4_095, 4_096, 69_999] {
            values[index] |= 0b100;
            *tree.get_mut(index).unwrap() |= 0b100;
        }
        tree.push(0b11).unwrap();
        values.push(0b11);
        tree.apply_updates();

        let flat = Flat::try_from(values).unwrap();
        assert_eq!(tree.hash_tree_root(), flat.hash_tree_root());
        assert_eq!(tree.to_ssz(), flat.to_ssz());
    }

    #[test]
    fn progressive_participation_hashes_like_the_flat_list() {
        use crate::primitives::HashTreeRoot as _;

        for len in LENGTHS {
            let values = flags(len);
            let flat = libssz_types::ProgressiveList::<ParticipationFlags>::from(values.clone());
            let tree = ProgressiveEpochParticipation::from(values);
            assert_eq!(tree.hash_tree_root(), flat.hash_tree_root(), "len {len}");
            assert_eq!(tree.to_ssz(), flat.to_ssz(), "len {len}");
        }
    }

    /// Run with `--ignored --nocapture`. Compares what a state root pays for
    /// the two participation lists after one block, before (flat lists,
    /// rehashed whole) and after (trees) at mainnet registry size. The block
    /// credits one slot's worth of validators (a thirty-second of the
    /// registry, at pseudo-random positions as committee shuffling places
    /// them) in the current epoch's list; the previous one is untouched.
    #[test]
    #[ignore = "benchmark"]
    fn participation_root_after_a_block_of_writes_bench() {
        use crate::primitives::HashTreeRoot as _;
        use std::time::Instant;
        type Flat = libssz_types::SszList<ParticipationFlags, { preset::VALIDATOR_REGISTRY_LIMIT }>;

        const COUNT: usize = 2_400_000;
        const TOUCHED: usize = COUNT / 32;
        let values = flags(COUNT);
        let mut state = 12345u64;
        let touched: Vec<usize> = (0..TOUCHED)
            .map(|_| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (state >> 33) as usize % COUNT
            })
            .collect();

        let flat_previous = Flat::try_from(values.clone()).unwrap();
        let mut flat_current = Flat::try_from(values.clone()).unwrap();
        let mut tree_previous = EpochParticipation::try_from(values.clone()).unwrap();
        let mut tree_current = EpochParticipation::try_from(values).unwrap();
        for tree in [&mut tree_previous, &mut tree_current] {
            tree.apply_updates();
            let _ = tree.hash_tree_root();
        }

        let start = Instant::now();
        for &index in &touched {
            flat_current[index] |= 0b100;
        }
        let flat_roots = (
            flat_previous.hash_tree_root(),
            flat_current.hash_tree_root(),
        );
        let flat_time = start.elapsed();

        let start = Instant::now();
        for &index in &touched {
            *tree_current.get_mut(index).unwrap() |= 0b100;
        }
        let write_time = start.elapsed();
        tree_previous.apply_updates();
        tree_current.apply_updates();
        let apply_time = start.elapsed();
        let tree_roots = (
            tree_previous.hash_tree_root(),
            tree_current.hash_tree_root(),
        );
        let tree_time = start.elapsed();
        println!("tree phases: writes {write_time:?}, apply {apply_time:?}, hash {tree_time:?}");

        assert_eq!(flat_roots, tree_roots);
        println!("flat: {flat_time:?}, tree: {tree_time:?} ({TOUCHED} of {COUNT} entries written)");
    }

    /// Run with `--ignored --nocapture`. Times the participation part of one
    /// `process_attestation` at mainnet registry size: read the current flags
    /// of ~75k ascending attesters, then write the new ones. "per-index" is
    /// the first tree-backed version (a descent per `get`, then a `get_mut`
    /// that copies the old value into the write buffer); the others swap in
    /// the sorted reader and the blind `set`.
    #[test]
    #[ignore = "benchmark"]
    fn attestation_pass_bench() {
        use crate::primitives::HashTreeRoot as _;
        use std::time::Instant;

        const COUNT: usize = 2_400_000;
        const ATTESTERS: usize = COUNT / 32;
        let mut state = 99u64;
        let mut attesters: Vec<usize> = (0..ATTESTERS)
            .map(|_| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (state >> 33) as usize % COUNT
            })
            .collect();
        attesters.sort_unstable();
        attesters.dedup();

        let fresh = || {
            let mut list = EpochParticipation::try_from(flags(COUNT)).unwrap();
            list.apply_updates();
            let _ = list.hash_tree_root();
            list
        };

        for (name, sorted_reads, blind_writes) in [
            ("per-index get + get_mut", false, false),
            ("per-index get + set", false, true),
            ("sorted reader + get_mut", true, false),
            ("sorted reader + set", true, true),
        ] {
            // Best of several runs: the first is cold.
            let mut best = (std::time::Duration::MAX, std::time::Duration::MAX);
            for _ in 0..5 {
                let mut list = fresh();
                let start = Instant::now();
                let mut updates: Vec<(usize, ParticipationFlags)> = Vec::new();
                if sorted_reads {
                    let mut reader = list.sorted_reader();
                    for &index in &attesters {
                        let current = *reader.get(index).unwrap();
                        updates.push((index, current));
                    }
                } else {
                    for &index in &attesters {
                        let current = *list.get(index).unwrap();
                        updates.push((index, current));
                    }
                }
                let read = start.elapsed();
                let start = Instant::now();
                for &(index, current) in &updates {
                    if blind_writes {
                        assert!(list.set(index, current | 0b100));
                    } else {
                        *list.get_mut(index).unwrap() |= 0b100;
                    }
                }
                let write = start.elapsed();
                best = (best.0.min(read), best.1.min(write));
            }
            println!(
                "{name}: read {:?}, write {:?}, total {:?} ({} attesters)",
                best.0,
                best.1,
                best.0 + best.1,
                attesters.len()
            );
        }
    }

    /// Run with `--ignored --nocapture`. Times the epoch rotation's new
    /// current-epoch participation list at mainnet registry size, then the
    /// state root that follows: built from a zeroed `Vec` (what the rotation
    /// did) against `List::repeat`.
    #[test]
    #[ignore = "benchmark"]
    fn participation_rotation_bench() {
        use crate::primitives::HashTreeRoot as _;
        use std::time::Instant;

        const COUNT: usize = 2_400_000;
        for _ in 0..3 {
            let start = Instant::now();
            let from_vec = EpochParticipation::try_from(vec![0u8; COUNT]).unwrap();
            let build_vec = start.elapsed();
            let start = Instant::now();
            let root_vec = from_vec.hash_tree_root();
            let hash_vec = start.elapsed();

            let start = Instant::now();
            let repeated = EpochParticipation::repeat(0, COUNT).unwrap();
            let build_repeat = start.elapsed();
            let start = Instant::now();
            let root_repeat = repeated.hash_tree_root();
            let hash_repeat = start.elapsed();

            assert_eq!(root_vec, root_repeat);
            println!(
                "vec: build {build_vec:?} + hash {hash_vec:?} = {:?}; repeat: build {build_repeat:?} + hash {hash_repeat:?} = {:?}",
                build_vec + hash_vec,
                build_repeat + hash_repeat
            );
        }
    }
}
