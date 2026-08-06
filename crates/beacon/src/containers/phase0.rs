//! Containers whose shape is specific to phase0.
//!
//! The distinguishing feature of phase0's state is that it accumulates whole
//! attestations, in `previous_epoch_attestations` and
//! `current_epoch_attestations`, and replays them at the epoch boundary to work
//! out who voted for what. Altair replaces that with per-validator participation
//! flags recorded as each attestation is processed, which is both cheaper and
//! bounded, and drops these two fields entirely.

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::{SszBitlist, SszList};

use super::shared::{
    AttestationData, BeaconBlockHeader, Checkpoint, Deposit, Eth1Data, Eth1DataVotes, Fork,
    ProposerSlashing, SignedVoluntaryExit,
};
use super::shared::{
    Balances, BlockRoots, HistoricalRoots, JustificationBits, RandaoMixes, Slashings, StateRoots,
    Validators,
};
use crate::preset;
use crate::primitives::{BlsSignature, Bytes32, Root, Slot, ValidatorIndex};

/// The attesters covered by one aggregate, as a bit per committee member.
///
/// Bounded by the largest a single committee can be, since a phase0 attestation
/// covers exactly one committee. Electra widens this to a whole slot's worth of
/// committees.
pub type AggregationBits = SszBitlist<{ preset::MAX_VALIDATORS_PER_COMMITTEE }>;

/// The attesters covered by one aggregate, named explicitly rather than as a
/// bitfield, which is the form signature verification needs.
pub type AttestingIndices = SszList<ValidatorIndex, { preset::MAX_VALIDATORS_PER_COMMITTEE }>;

/// Attestations retained in the state, awaiting the epoch boundary.
pub type PendingAttestations = SszList<PendingAttestation, { preset::MAX_PENDING_ATTESTATIONS }>;

// ---------------------------------------------------------------------------
// Attestations
// ---------------------------------------------------------------------------

/// An aggregate attestation, as gossiped and as included in a block.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct Attestation {
    pub aggregation_bits: AggregationBits,
    pub data: AttestationData,
    /// The aggregate signature of every attester set in `aggregation_bits`, over
    /// `data`.
    pub signature: BlsSignature,
}

/// An attestation with its attesters named rather than bit-encoded.
///
/// Signature verification needs the public keys, which needs the indices, so the
/// state transition converts an [`Attestation`] into this form before checking
/// it. Slashing evidence is expressed in this form too, since a slashing has to
/// be checkable without the committee that produced it.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct IndexedAttestation {
    /// The attesters, which the specification requires to be sorted and unique.
    pub attesting_indices: AttestingIndices,
    pub data: AttestationData,
    pub signature: BlsSignature,
}

/// Evidence that a set of validators made two conflicting attestations.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct AttesterSlashing {
    pub attestation_1: IndexedAttestation,
    pub attestation_2: IndexedAttestation,
}

/// An attestation retained in the state until the epoch boundary.
///
/// Phase0 cannot score an attestation when it arrives, because the reward
/// depends on facts not yet settled, so it stores the attestation along with the
/// two things it will need later and defers the work.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct PendingAttestation {
    pub aggregation_bits: AggregationBits,
    pub data: AttestationData,
    /// How many slots passed between the attested slot and the block that
    /// included this attestation. Rewards scale inversely with it, which is what
    /// pays for prompt attesting.
    pub inclusion_delay: Slot,
    /// Who included it, so that the proposer reward can be paid at the epoch
    /// boundary to a proposer identified when the attestation arrived.
    pub proposer_index: ValidatorIndex,
}

// ---------------------------------------------------------------------------
// Blocks
// ---------------------------------------------------------------------------

/// The contents of a block: everything the proposer chose to include.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct BeaconBlockBody {
    /// The proposer's contribution to the chain's randomness, which is a
    /// signature over the current epoch and so cannot be chosen freely.
    pub randao_reveal: BlsSignature,
    /// The proposer's vote on the execution chain's deposit state.
    pub eth1_data: Eth1Data,
    /// Arbitrary proposer-chosen bytes, which consensus never reads.
    pub graffiti: Bytes32,
    pub proposer_slashings: SszList<ProposerSlashing, { preset::MAX_PROPOSER_SLASHINGS }>,
    pub attester_slashings: SszList<AttesterSlashing, { preset::MAX_ATTESTER_SLASHINGS }>,
    pub attestations: SszList<Attestation, { preset::MAX_ATTESTATIONS }>,
    pub deposits: SszList<Deposit, { preset::MAX_DEPOSITS }>,
    pub voluntary_exits: SszList<SignedVoluntaryExit, { preset::MAX_VOLUNTARY_EXITS }>,
}

/// A block.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct BeaconBlock {
    pub slot: Slot,
    pub proposer_index: ValidatorIndex,
    pub parent_root: Root,
    /// The root of the state after this block is applied, which the state
    /// transition recomputes and compares.
    pub state_root: Root,
    pub body: BeaconBlockBody,
}

#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct SignedBeaconBlock {
    pub message: BeaconBlock,
    pub signature: BlsSignature,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// The phase0 beacon state: 21 fields, in the specification's order.
///
/// Field order is load-bearing. SSZ encoding and merkleization both follow
/// declaration order, so reordering or omitting a field silently produces a
/// wrong `hash_tree_root`.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct BeaconState {
    // -- Versioning --
    pub genesis_time: u64,
    /// The root of the genesis validator registry, which separates this chain
    /// from any other running the same fork schedule.
    pub genesis_validators_root: Root,
    pub slot: Slot,
    pub fork: Fork,

    // -- History --
    /// The most recent block's header, with `state_root` left zero until the slot
    /// advances, since a block cannot commit to the root of the state containing
    /// it.
    pub latest_block_header: BeaconBlockHeader,
    pub block_roots: BlockRoots,
    pub state_roots: StateRoots,
    pub historical_roots: HistoricalRoots,

    // -- Eth1 --
    pub eth1_data: Eth1Data,
    pub eth1_data_votes: Eth1DataVotes,
    /// How many deposits from the contract have been processed, which is where
    /// the next one will be read from.
    pub eth1_deposit_index: u64,

    // -- Registry --
    pub validators: Validators,
    pub balances: Balances,

    // -- Randomness --
    pub randao_mixes: RandaoMixes,

    // -- Slashings --
    pub slashings: Slashings,

    // -- Attestations --
    /// Attestations for the previous epoch, replayed at the epoch boundary. Only
    /// phase0 has these; altair replaces them with participation flags.
    pub previous_epoch_attestations: PendingAttestations,
    /// Attestations for the current epoch, which become
    /// `previous_epoch_attestations` at the next boundary.
    pub current_epoch_attestations: PendingAttestations,

    // -- Finality --
    pub justification_bits: JustificationBits,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
}

// ---------------------------------------------------------------------------
// Validator-side containers
// ---------------------------------------------------------------------------

/// An aggregate together with proof that its aggregator was selected to produce
/// it.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct AggregateAndProof {
    pub aggregator_index: ValidatorIndex,
    pub aggregate: Attestation,
    /// The aggregator's signature over the slot, which is what makes selection
    /// verifiable rather than self-declared.
    pub selection_proof: BlsSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct SignedAggregateAndProof {
    pub message: AggregateAndProof,
    pub signature: BlsSignature,
}

#[cfg(test)]
mod tests {
    use libssz::{SszDecode as _, SszEncode as _};

    use super::*;

    #[test]
    fn pending_attestation_round_trips_through_ssz() {
        let attestation = PendingAttestation {
            aggregation_bits: {
                let mut bits = AggregationBits::with_length(5).unwrap();
                bits.set(0, true).unwrap();
                bits.set(3, true).unwrap();
                bits
            },
            data: AttestationData::default(),
            inclusion_delay: 2,
            proposer_index: 9,
        };

        let bytes = attestation.to_ssz();
        assert_eq!(
            PendingAttestation::from_ssz_bytes(&bytes).unwrap(),
            attestation
        );
    }

    #[test]
    fn variable_length_containers_carry_offsets() {
        // Each of these holds at least one list or bitlist, so its encoding
        // begins with offsets rather than being a fixed layout. The state, the
        // body, and an attestation are the three that matter.
        assert!(!<BeaconState as libssz::SszEncode>::is_fixed_size());
        assert!(!<BeaconBlockBody as libssz::SszEncode>::is_fixed_size());
        assert!(!<BeaconBlock as libssz::SszEncode>::is_fixed_size());
        assert!(!<Attestation as libssz::SszEncode>::is_fixed_size());
        assert!(!<IndexedAttestation as libssz::SszEncode>::is_fixed_size());
        assert!(!<PendingAttestation as libssz::SszEncode>::is_fixed_size());
    }

    #[test]
    fn block_body_round_trips_while_empty() {
        // An empty body is the common case for a skipped-operation slot, and it
        // exercises every offset in the encoding with zero-length payloads.
        let body = BeaconBlockBody {
            randao_reveal: BlsSignature::default(),
            eth1_data: Eth1Data::default(),
            graffiti: Bytes32::zero(),
            proposer_slashings: Default::default(),
            attester_slashings: Default::default(),
            attestations: Default::default(),
            deposits: Default::default(),
            voluntary_exits: Default::default(),
        };

        let bytes = body.to_ssz();
        assert_eq!(BeaconBlockBody::from_ssz_bytes(&bytes).unwrap(), body);
    }
}
