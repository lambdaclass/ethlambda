//! Containers whose shape is specific to altair.
//!
//! Altair's headline change is sync committees: a small, rotating subset of the
//! validator set that signs every block so a light client can follow the
//! chain's head from a single, cheaply verifiable aggregate rather than
//! replaying full state transitions. [`SyncAggregate`] carries the per-block
//! result into [`BeaconBlockBody`], [`SyncCommittee`] carries the current and
//! next committees into [`BeaconState`], and the remaining containers here are
//! the off-chain messages a sync committee member and its aggregator exchange
//! over gossip to produce one: [`SyncCommitteeMessage`],
//! [`SyncCommitteeContribution`], [`ContributionAndProof`],
//! [`SignedContributionAndProof`], and [`SyncAggregatorSelectionData`]. Those
//! five are transcribed from `validator.md` rather than `beacon-chain.md`,
//! since the specification splits sync committee duties into their own
//! document the same way it does phase0's attestation duties.
//!
//! The other change is incentive accounting: altair replaces phase0's
//! accumulate-then-replay attestations with per-validator participation flags
//! recorded as each attestation is processed. Concretely, [`BeaconState`] drops
//! `previous_epoch_attestations` and `current_epoch_attestations` and puts
//! `previous_epoch_participation` and `current_epoch_participation` in the exact
//! same two slots, so this is a type change in place, not an appended pair.
//! Altair then appends `inactivity_scores` and the two sync committee fields
//! after `finalized_checkpoint`.
//!
//! Attestations themselves ([`super::phase0::Attestation`],
//! [`super::phase0::AttesterSlashing`]) are unchanged in altair, so this module
//! imports them rather than redefining them. Electra is where they next change
//! shape; do not go looking for altair-specific versions of them.

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::{SszBitvector, SszList, SszVector};

use super::phase0::{Attestation, AttesterSlashing};
use super::shared::{
    Balances, BlockRoots, EpochParticipation, Eth1DataVotes, HistoricalRoots, InactivityScores,
    JustificationBits, RandaoMixes, Slashings, StateRoots, Validators,
};
use super::shared::{
    BeaconBlockHeader, Checkpoint, Deposit, Eth1Data, Fork, ProposerSlashing, SignedVoluntaryExit,
};
use crate::beacon::primitives::{BlsPubkey, BlsSignature, Bytes32, Root, Slot, ValidatorIndex};
use crate::beacon::{constants, preset};

/// One bit per sync committee member, recording who contributed to a
/// [`SyncAggregate`].
pub type SyncCommitteeBits = SszBitvector<{ preset::SYNC_COMMITTEE_SIZE }>;

/// The public keys making up a sync committee, one per seat.
///
/// May contain duplicates: `get_next_sync_committee_indices` draws seats with
/// replacement weighted by effective balance, so one validator can hold more
/// than one seat in the same committee.
pub type SyncCommitteePubkeys = SszVector<BlsPubkey, { preset::SYNC_COMMITTEE_SIZE }>;

/// One bit per member of a single sync subcommittee (one
/// `SYNC_COMMITTEE_SUBNET_COUNT`th of a full sync committee), recording who
/// contributed to one [`SyncCommitteeContribution`].
pub type SyncSubcommitteeBits = SszBitvector<SYNC_SUBCOMMITTEE_SIZE>;

/// Members per sync subcommittee: `SYNC_COMMITTEE_SIZE // SYNC_COMMITTEE_SUBNET_COUNT`,
/// the width of one [`SyncCommitteeContribution`]'s `aggregation_bits` and of
/// one `sync_committee_{subnet_id}` subnet's share of the committee.
pub const SYNC_SUBCOMMITTEE_SIZE: usize =
    preset::SYNC_COMMITTEE_SIZE / constants::SYNC_COMMITTEE_SUBNET_COUNT;
// Seen caches pack a subcommittee's bits into a `u128`.
const _: () = assert!(SYNC_SUBCOMMITTEE_SIZE <= 128);

// ---------------------------------------------------------------------------
// Sync committees
// ---------------------------------------------------------------------------

/// A block's summary of sync committee participation: who signed, and the
/// resulting aggregate signature.
///
/// Carried in every altair-and-later [`BeaconBlockBody`], since every block
/// needs one regardless of how many attestations or other operations it
/// includes.
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
pub struct SyncAggregate {
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex")]
    pub sync_committee_bits: SyncCommitteeBits,
    /// The aggregate of every signature from a member set in
    /// `sync_committee_bits`, over the previous slot's block root.
    pub sync_committee_signature: BlsSignature,
}

/// The committee currently responsible for signing sync aggregates, plus its
/// combined key precomputed for the common case where every member
/// participates.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot)]
pub struct SyncCommittee {
    #[serde(serialize_with = "crate::beacon::serde_helpers::seq::serialize")]
    pub pubkeys: SyncCommitteePubkeys,
    /// The aggregate of every key in `pubkeys`, so `process_sync_aggregate` does
    /// not have to re-aggregate from scratch when the whole committee signs.
    pub aggregate_pubkey: BlsPubkey,
}

// ---------------------------------------------------------------------------
// Blocks
// ---------------------------------------------------------------------------

/// The contents of a block: phase0's operations, plus the sync committee's
/// contribution to this block.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot,
)]
pub struct BeaconBlockBody {
    /// The proposer's contribution to the chain's randomness, which is a
    /// signature over the current epoch and so cannot be chosen freely.
    pub randao_reveal: BlsSignature,
    /// The proposer's vote on the execution chain's deposit state.
    pub eth1_data: Eth1Data,
    /// Arbitrary proposer-chosen bytes, which consensus never reads.
    pub graffiti: Bytes32,
    #[serde(serialize_with = "crate::beacon::serde_helpers::seq::serialize")]
    pub proposer_slashings: SszList<ProposerSlashing, { preset::MAX_PROPOSER_SLASHINGS }>,
    #[serde(serialize_with = "crate::beacon::serde_helpers::seq::serialize")]
    pub attester_slashings: SszList<AttesterSlashing, { preset::MAX_ATTESTER_SLASHINGS }>,
    #[serde(serialize_with = "crate::beacon::serde_helpers::seq::serialize")]
    pub attestations: SszList<Attestation, { preset::MAX_ATTESTATIONS }>,
    #[serde(serialize_with = "crate::beacon::serde_helpers::seq::serialize")]
    pub deposits: SszList<Deposit, { preset::MAX_DEPOSITS }>,
    #[serde(serialize_with = "crate::beacon::serde_helpers::seq::serialize")]
    pub voluntary_exits: SszList<SignedVoluntaryExit, { preset::MAX_VOLUNTARY_EXITS }>,
    /// The aggregated sync committee signature over the previous slot's block
    /// root, plus which members contributed. This is what lets a light client
    /// trust the chain's head without processing every block: it only has to
    /// check that a supermajority of a known committee signed.
    pub sync_aggregate: SyncAggregate,
}

/// A block.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot)]
pub struct BeaconBlock {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub slot: Slot,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub proposer_index: ValidatorIndex,
    pub parent_root: Root,
    /// The root of the state after this block is applied, which the state
    /// transition recomputes and compares.
    pub state_root: Root,
    pub body: BeaconBlockBody,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot)]
pub struct SignedBeaconBlock {
    pub message: BeaconBlock,
    pub signature: BlsSignature,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// The altair beacon state: 24 fields, in the specification's order.
///
/// Field order is load-bearing. SSZ encoding and merkleization both follow
/// declaration order, so reordering or omitting a field silently produces a
/// wrong `hash_tree_root`.
///
/// Fields through `slashings` are identical to phase0's, field for field. From
/// there, altair replaces phase0's `previous_epoch_attestations` and
/// `current_epoch_attestations` (`List<PendingAttestation, _>`) with
/// `previous_epoch_participation` and `current_epoch_participation`
/// (`List<ParticipationFlags, _>`) in those same two positions, keeps
/// `justification_bits` through `finalized_checkpoint` unchanged, and appends
/// `inactivity_scores`, `current_sync_committee`, and `next_sync_committee`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot)]
pub struct BeaconState {
    // -- Versioning --
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub genesis_time: u64,
    /// The root of the genesis validator registry, which separates this chain
    /// from any other running the same fork schedule.
    pub genesis_validators_root: Root,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub slot: Slot,
    pub fork: Fork,

    // -- History --
    /// The most recent block's header, with `state_root` left zero until the
    /// slot advances, since a block cannot commit to the root of the state
    /// containing it.
    pub latest_block_header: BeaconBlockHeader,
    #[serde(serialize_with = "crate::beacon::serde_helpers::seq::serialize")]
    pub block_roots: BlockRoots,
    #[serde(serialize_with = "crate::beacon::serde_helpers::seq::serialize")]
    pub state_roots: StateRoots,
    #[serde(serialize_with = "crate::beacon::serde_helpers::seq::serialize")]
    pub historical_roots: HistoricalRoots,

    // -- Eth1 --
    pub eth1_data: Eth1Data,
    #[serde(serialize_with = "crate::beacon::serde_helpers::seq::serialize")]
    pub eth1_data_votes: Eth1DataVotes,
    /// How many deposits from the contract have been processed, which is where
    /// the next one will be read from.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub eth1_deposit_index: u64,

    // -- Registry --
    #[serde(serialize_with = "crate::beacon::serde_helpers::seq::serialize")]
    pub validators: Validators,
    #[serde(serialize_with = "crate::beacon::serde_helpers::quoted_u64_seq::serialize")]
    pub balances: Balances,

    // -- Randomness --
    #[serde(serialize_with = "crate::beacon::serde_helpers::seq::serialize")]
    pub randao_mixes: RandaoMixes,

    // -- Slashings --
    #[serde(serialize_with = "crate::beacon::serde_helpers::quoted_u64_seq::serialize")]
    pub slashings: Slashings,

    // -- Participation --
    /// Per-validator participation flags for the previous epoch, positionally
    /// parallel to `validators`. Occupies the position phase0 gives
    /// `previous_epoch_attestations`: altair scores an attestation the moment
    /// it is processed instead of deferring to the epoch boundary, so there is
    /// no longer a backlog of whole attestations to keep around, only a flag
    /// per validator per epoch.
    #[serde(serialize_with = "crate::beacon::serde_helpers::quoted_u64_seq::serialize")]
    pub previous_epoch_participation: EpochParticipation,
    /// Flags for the current epoch, which become `previous_epoch_participation`
    /// at the next epoch boundary.
    #[serde(serialize_with = "crate::beacon::serde_helpers::quoted_u64_seq::serialize")]
    pub current_epoch_participation: EpochParticipation,

    // -- Finality --
    #[serde(serialize_with = "crate::beacon::serde_helpers::ssz_hex::serialize")]
    pub justification_bits: JustificationBits,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,

    // -- Inactivity --
    /// Per-validator inactivity score, positionally parallel to `validators`.
    /// Rises for a validator that misses the timely-target flag during a
    /// non-finalizing epoch and falls otherwise, which is what lets the
    /// inactivity leak single out validators who are actually offline rather
    /// than penalizing everyone during a stall.
    #[serde(serialize_with = "crate::beacon::serde_helpers::quoted_u64_seq::serialize")]
    pub inactivity_scores: InactivityScores,

    // -- Sync committees --
    /// The committee currently signing sync aggregates.
    pub current_sync_committee: SyncCommittee,
    /// The committee that takes over from `current_sync_committee` at the next
    /// sync committee period boundary. Precomputing it one period ahead is what
    /// lets a light client know the next committee before it needs it.
    pub next_sync_committee: SyncCommittee,
}

// ---------------------------------------------------------------------------
// Validator-side containers
// ---------------------------------------------------------------------------
//
// These five are gossiped between sync committee members and their
// aggregators, never stored in the state or a block body, and are transcribed
// from `validator.md` rather than `beacon-chain.md`.

/// One sync committee member's vote for a slot's block root, before
/// aggregation.
///
/// The sync committee analogue of a phase0 attestation, but unaggregated: a
/// committee member gossips one of these every slot, and an aggregator
/// combines a subcommittee's worth into a [`SyncCommitteeContribution`].
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
pub struct SyncCommitteeMessage {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub slot: Slot,
    pub beacon_block_root: Root,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub validator_index: ValidatorIndex,
    pub signature: BlsSignature,
}

/// An aggregator's combination of one subcommittee's [`SyncCommitteeMessage`]s
/// for a slot.
///
/// Scoped to `subcommittee_index` rather than the whole committee, because
/// `SYNC_COMMITTEE_SUBNET_COUNT` aggregators work in parallel on disjoint
/// slices of the committee, the same way phase0 attestation aggregation is
/// scoped to one committee rather than the whole active set.
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
pub struct SyncCommitteeContribution {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub slot: Slot,
    pub beacon_block_root: Root,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub subcommittee_index: u64,
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex")]
    pub aggregation_bits: SyncSubcommitteeBits,
    /// The aggregate signature of every member set in `aggregation_bits`, over
    /// `beacon_block_root`.
    pub signature: BlsSignature,
}

/// A [`SyncCommitteeContribution`] together with proof that its aggregator was
/// selected to produce it.
///
/// The sync committee analogue of phase0's `AggregateAndProof`.
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
pub struct ContributionAndProof {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub aggregator_index: ValidatorIndex,
    pub contribution: SyncCommitteeContribution,
    /// The aggregator's signature over the selection data, which is what makes
    /// selection verifiable rather than self-declared.
    pub selection_proof: BlsSignature,
}

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
pub struct SignedContributionAndProof {
    pub message: ContributionAndProof,
    pub signature: BlsSignature,
}

/// What a prospective sync committee aggregator signs to prove it was
/// selected, before it has anything to aggregate yet.
///
/// Separate from [`ContributionAndProof::selection_proof`]'s signature target
/// only in name: this is the unsigned message that signature covers.
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
pub struct SyncAggregatorSelectionData {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub slot: Slot,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub subcommittee_index: u64,
}

#[cfg(test)]
mod tests {
    use libssz::{SszDecode as _, SszEncode as _};

    use super::*;

    #[test]
    fn sync_committee_and_aggregate_are_fixed_size() {
        // A sync committee is a vector of pubkeys plus one more pubkey, and a
        // sync aggregate is a bitvector plus a signature: nothing
        // variable-length in either, unlike the block body and state that
        // carry them.
        assert!(<SyncCommittee as libssz::SszEncode>::is_fixed_size());
        assert!(<SyncAggregate as libssz::SszEncode>::is_fixed_size());
    }

    #[test]
    fn variable_length_containers_carry_offsets() {
        // The state and the body each hold at least one list, so both begin
        // their encoding with offsets rather than a fixed layout, and the
        // block inherits that from its body.
        assert!(!<BeaconState as libssz::SszEncode>::is_fixed_size());
        assert!(!<BeaconBlockBody as libssz::SszEncode>::is_fixed_size());
        assert!(!<BeaconBlock as libssz::SszEncode>::is_fixed_size());
    }

    #[test]
    fn block_body_round_trips_while_empty() {
        // An empty body is the common case for a skipped-operation slot, and it
        // exercises every offset in the encoding with zero-length payloads,
        // plus the fixed-size sync aggregate altair adds alongside them.
        let body = BeaconBlockBody {
            randao_reveal: BlsSignature::default(),
            eth1_data: Eth1Data::default(),
            graffiti: Bytes32::ZERO,
            proposer_slashings: Default::default(),
            attester_slashings: Default::default(),
            attestations: Default::default(),
            deposits: Default::default(),
            voluntary_exits: Default::default(),
            sync_aggregate: SyncAggregate::default(),
        };

        let bytes = body.to_ssz();
        assert_eq!(BeaconBlockBody::from_ssz_bytes(&bytes).unwrap(), body);
    }

    /// Serializes `value` and reads it back, returning the JSON for shape checks.
    fn json_round_trip<T>(value: &T) -> serde_json::Value
    where
        T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let json = serde_json::to_value(value).unwrap();
        let back: T = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(&back, value);
        json
    }

    #[test]
    fn sync_committee_containers_round_trip_through_json() {
        // The Beacon API carries these as JSON in both directions: quoted
        // integers, and bitvectors as `0x` hex of their SSZ bytes.
        let mut aggregation_bits = SyncSubcommitteeBits::default();
        aggregation_bits.set(0, true).unwrap();
        aggregation_bits
            .set(SYNC_SUBCOMMITTEE_SIZE - 1, true)
            .unwrap();
        let contribution = SyncCommitteeContribution {
            slot: 7,
            beacon_block_root: Root::repeat_byte(0x11),
            subcommittee_index: 3,
            aggregation_bits,
            signature: BlsSignature([0x22; 96]),
        };
        let json = json_round_trip(&contribution);
        assert_eq!(json["slot"], "7");
        assert_eq!(json["subcommittee_index"], "3");
        let bits = json["aggregation_bits"].as_str().unwrap();
        assert_eq!(bits.len(), 2 + 2 * SYNC_SUBCOMMITTEE_SIZE / 8);

        let message = SyncCommitteeMessage {
            slot: 9,
            beacon_block_root: Root::repeat_byte(0x33),
            validator_index: 42,
            signature: BlsSignature([0x44; 96]),
        };
        assert_eq!(json_round_trip(&message)["validator_index"], "42");

        let signed = SignedContributionAndProof {
            message: ContributionAndProof {
                aggregator_index: 5,
                contribution,
                selection_proof: BlsSignature([0x55; 96]),
            },
            signature: BlsSignature([0x66; 96]),
        };
        json_round_trip(&signed);
        json_round_trip(&SyncAggregatorSelectionData {
            slot: 1,
            subcommittee_index: 2,
        });

        let mut sync_committee_bits = SyncCommitteeBits::default();
        sync_committee_bits
            .set(preset::SYNC_COMMITTEE_SIZE - 1, true)
            .unwrap();
        json_round_trip(&SyncAggregate {
            sync_committee_bits,
            sync_committee_signature: BlsSignature([0x77; 96]),
        });
    }
}
