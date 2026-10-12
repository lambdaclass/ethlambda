//! Containers of the `decoupled` fork: fulu's chain with the decoupled
//! consensus protocol (Goldfish + graded stabilization gadget + height-based
//! finality gadget, `fradamt/verified-consensus`) in place of LMD-GHOST and
//! Casper FFG.
//!
//! The state is fulu's, unchanged: the protocol's per-block chain state σ is
//! derived by every node from block contents (`σ[B] = state_transition(σ[B.parent], B)`)
//! and kept beside the beacon state rather than in it, because σ names the
//! block it belongs to (`L`, and `T_h ← L` on a height advance), which a state
//! root committed to by that same block cannot contain. The FFG fields of the
//! state stay at their values from the fork boundary.
//!
//! The block body is electra's (the type fulu's block wraps) with the three
//! protocol fields appended. Appending keeps `blob_kzg_commitments` at field
//! index 11 and the body at sixteen fields, so fulu's data column sidecars and
//! their inclusion proof (`KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH`) carry over
//! unchanged. `attestations` and `attester_slashings` must be empty: the fork
//! has no LMD/FFG votes.
//!
//! Votes are BLS-aggregated by identical data, the way attestations are: a
//! Goldfish vote signs `(slot, head)` and a combined attestation signs its
//! whole [`AttestationData`], so honest validators with the same view produce
//! one aggregate between them.

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::{SszBitlist, SszList};

use super::altair::SyncAggregate;
use super::capella::SignedBLSToExecutionChange;
use super::deneb::{ExecutionPayload, KzgCommitments};
use super::electra::{Attestations, AttesterSlashings, ExecutionRequests};
use super::shared::{Deposit, Eth1Data, ProposerSlashing, SignedVoluntaryExit};
use crate::beacon::preset;
use crate::beacon::primitives::{BlsSignature, Bytes32, Root, Slot, ValidatorIndex};
pub use crate::decoupled::AttestationData;

/// Goldfish vote aggregates a block may carry: one per distinct head voted in
/// the previous slot. Honest committees vote for one or two heads; an
/// equivocator adds at most two more.
pub const MAX_GOLDFISH_VOTE_AGGREGATES: usize = 128;

/// Combined attestation aggregates a block may carry: one per distinct
/// attestation data in the SG window.
pub const MAX_COMBINED_ATTESTATION_AGGREGATES: usize = 128;

/// What a Goldfish vote signs: `(slot, head)`. The voter is not part of the
/// signed message, so votes with the same view aggregate.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct GoldfishVoteData {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub slot: Slot,
    pub head: Root,
}

/// One validator's Goldfish vote, as gossiped on `goldfish_vote` and submitted
/// by a validator client. Signed under `DOMAIN_GOLDFISH_VOTE` at the vote's
/// epoch.
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
pub struct SignedGoldfishVote {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub validator_index: ValidatorIndex,
    pub data: GoldfishVoteData,
    pub signature: BlsSignature,
}

/// The Goldfish votes of one slot for one head, aggregated.
///
/// `aggregation_bits` has one bit per member of slot `data.slot`'s committee
/// `𝒦_s`: the slot's beacon committees concatenated in committee-index order,
/// electra's layout for a whole-slot attestation.
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
pub struct GoldfishVoteAggregate {
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex")]
    pub aggregation_bits: SszBitlist<{ preset::MAX_VALIDATORS_PER_SLOT }>,
    pub data: GoldfishVoteData,
    pub signature: BlsSignature,
}

/// One validator's combined attestation, as gossiped on `combined_attestation`
/// and submitted by a validator client. Signed under
/// `DOMAIN_COMBINED_ATTESTATION` at the epoch of the round's opening slot.
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
pub struct SignedCombinedAttestation {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub validator_index: ValidatorIndex,
    pub data: AttestationData,
    pub signature: BlsSignature,
}

/// Combined attestations with identical data, aggregated. `aggregation_bits`
/// is indexed by validator index: every validator attests once per round.
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
pub struct CombinedAttestationAggregate {
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex")]
    pub aggregation_bits: SszBitlist<{ preset::VALIDATOR_REGISTRY_LIMIT }>,
    pub data: AttestationData,
    pub signature: BlsSignature,
}

/// The decoupled block body: electra's thirteen fields, then the protocol's
/// three.
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
pub struct BeaconBlockBody {
    pub randao_reveal: BlsSignature,
    pub eth1_data: Eth1Data,
    pub graffiti: Bytes32,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub proposer_slashings: SszList<ProposerSlashing, { preset::MAX_PROPOSER_SLASHINGS }>,
    /// Always empty in this fork.
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub attester_slashings: AttesterSlashings,
    /// Always empty in this fork.
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub attestations: Attestations,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub deposits: SszList<Deposit, { preset::MAX_DEPOSITS }>,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub voluntary_exits: SszList<SignedVoluntaryExit, { preset::MAX_VOLUNTARY_EXITS }>,
    pub sync_aggregate: SyncAggregate,
    pub execution_payload: ExecutionPayload,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub bls_to_execution_changes:
        SszList<SignedBLSToExecutionChange, { preset::MAX_BLS_TO_EXECUTION_CHANGES }>,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub blob_kzg_commitments: KzgCommitments,
    pub execution_requests: ExecutionRequests,

    /// `B.votes`: the previous slot's Goldfish votes, aggregated per head.
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub goldfish_votes: SszList<GoldfishVoteAggregate, MAX_GOLDFISH_VOTE_AGGREGATES>,
    /// `B.support_votes ⊆ B.votes`: bit `i` set when `goldfish_votes[i]` was
    /// resolved at proposal time. Resolution depends only on the head, which
    /// an aggregate shares, so one bit per aggregate is exact.
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex")]
    pub goldfish_support: SszBitlist<MAX_GOLDFISH_VOTE_AGGREGATES>,
    /// `B.attestations`.
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub combined_attestations:
        SszList<CombinedAttestationAggregate, MAX_COMBINED_ATTESTATION_AGGREGATES>,
}

impl BeaconBlockBody {
    /// Electra's empty body plus empty protocol fields.
    pub fn empty() -> Self {
        Self::from_electra(super::electra::BeaconBlockBody::empty())
    }

    /// The electra fields of `body`, with empty protocol fields.
    pub fn from_electra(body: super::electra::BeaconBlockBody) -> Self {
        Self {
            randao_reveal: body.randao_reveal,
            eth1_data: body.eth1_data,
            graffiti: body.graffiti,
            proposer_slashings: body.proposer_slashings,
            attester_slashings: body.attester_slashings,
            attestations: body.attestations,
            deposits: body.deposits,
            voluntary_exits: body.voluntary_exits,
            sync_aggregate: body.sync_aggregate,
            execution_payload: body.execution_payload,
            bls_to_execution_changes: body.bls_to_execution_changes,
            blob_kzg_commitments: body.blob_kzg_commitments,
            execution_requests: body.execution_requests,
            goldfish_votes: Default::default(),
            goldfish_support: Default::default(),
            combined_attestations: Default::default(),
        }
    }

    /// The electra-shaped view of this body: the thirteen shared fields, for
    /// code paths (payload, operations, data availability) that read only
    /// those.
    pub fn to_electra(&self) -> super::electra::BeaconBlockBody {
        super::electra::BeaconBlockBody {
            randao_reveal: self.randao_reveal.clone(),
            eth1_data: self.eth1_data.clone(),
            graffiti: self.graffiti,
            proposer_slashings: self.proposer_slashings.clone(),
            attester_slashings: self.attester_slashings.clone(),
            attestations: self.attestations.clone(),
            deposits: self.deposits.clone(),
            voluntary_exits: self.voluntary_exits.clone(),
            sync_aggregate: self.sync_aggregate.clone(),
            execution_payload: self.execution_payload.clone(),
            bls_to_execution_changes: self.bls_to_execution_changes.clone(),
            blob_kzg_commitments: self.blob_kzg_commitments.clone(),
            execution_requests: self.execution_requests.clone(),
        }
    }
}

/// A decoupled block.
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
pub struct BeaconBlock {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub slot: Slot,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub proposer_index: ValidatorIndex,
    pub parent_root: Root,
    pub state_root: Root,
    pub body: BeaconBlockBody,
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
pub struct SignedBeaconBlock {
    pub message: BeaconBlock,
    pub signature: BlsSignature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::primitives::HashTreeRoot;

    #[test]
    fn the_body_keeps_the_commitments_at_fulus_index() {
        // Sixteen fields, `blob_kzg_commitments` still the twelfth: fulu's
        // column inclusion proof is a depth-4 branch to index 11.
        let body = BeaconBlockBody::empty();
        let electra = body.to_electra();
        assert_eq!(BeaconBlockBody::from_electra(electra.clone()), body);
        assert_ne!(body.hash_tree_root(), electra.hash_tree_root());
    }
}
