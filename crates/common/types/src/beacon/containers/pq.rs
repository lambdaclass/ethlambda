//! Containers whose shape is specific to the PQ fork (consensus-specs
//! `specs/_features/pq`, on the `pq` branch at
//! `a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c`).
//!
//! The fork replaces BLS with leanXMSS. Every signed container trades its
//! `BLSSignature` for an [`XmssSignature`]; [`Attestation`] loses its signature
//! altogether, a block instead carrying one [`AttestationProof`] of every
//! attestation's signatures; the RANDAO reveal becomes a [`VrfProof`]; sync
//! committees, voluntary exits, BLS-to-execution changes and payload
//! attestations leave the block body; and the state trades the sync committees
//! and EIP-8483's registrations for preregistrations and the aggregation
//! committee window.
//!
//! # Gaps
//!
//! The big containers are EIP-7495 progressive containers, and a field the fork
//! removes leaves a gap in the merkle tree rather than shifting every later
//! field's position. The `active_fields` attribute on each container below
//! spells the specification's `active_fields(width=.., gaps=(..))` out bit by
//! bit; serialization only ever sees the active fields.
//!
//! # Two records with the shared shape in memory
//!
//! [`Validator`] and the builders in [`Builders`] hold the specification's
//! 32-byte [`XmssPubkey`] where every earlier fork holds a 48-byte BLS key. In
//! memory they keep the earlier forks' records ([`shared::Validator`],
//! [`gloas::Builder`]) with the key in the 48-byte form an execution-layer
//! request names it by, 16 zero bytes then the XMSS key
//! ([`XmssPubkey::to_request_key`]), which is the form the specification itself
//! compares request keys in. Their SSZ encoding and merkleization are written by
//! hand, through the specification's own field list (`ValidatorRecord`,
//! `BuilderRecord`), so the bytes and roots are the PQ containers' exactly.
//!
//! That is what lets every function that reads a validator's balance, epochs or
//! credentials, the bulk of the state transition, run unchanged on a PQ state:
//! the registry hands out [`shared::Validator`] references at every fork. A
//! [`Validator`]'s `vrf_root` sits beside that record and is read only by the
//! PQ code that needs it.

use libssz::{DecodeError, SszDecode, SszEncode};
use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_merkle::{HashTreeRoot, Node, Sha256Hasher};
use libssz_types::{ProgressiveBitlist, ProgressiveList, SszBitvector, SszList, SszVector};

use super::fulu::ProposerLookahead;
use super::gloas::{
    self, BuilderDepositRequests, BuilderExitRequests, BuilderIndex, BuilderPendingPayments,
    BuilderPendingWithdrawals, ConsolidationRequests, DepositRequests, Deposits,
    EpochParticipation, ExecutionPayload, ExecutionPayloadAvailability, ExecutionPayloadBid,
    InactivityScores, PayloadAttestationData, PayloadTimelinessCommitteeWindow,
    PendingConsolidations, PendingDeposits, PendingPartialWithdrawals, ProposerPreferences,
    WithdrawalRequests, Withdrawals,
};
use super::shared::{
    self, AttestationData, BeaconBlockHeader, BlockRoots, Checkpoint, Eth1Data, Eth1DataVotes,
    Fork, HistoricalRoots, HistoricalSummaries, JustificationBits, ProgressiveBalances,
    RandaoMixes, Slashings, StateRoots,
};
use crate::beacon::constants::VRF_TREE_DEPTH;
use crate::beacon::preset;
use crate::beacon::primitives::{
    Bytes32, CommitteeIndex, Epoch, ExecutionAddress, ExecutionBlockHash, Gwei, Root, Slot,
    ValidatorIndex, WithdrawalIndex, XmssPubkey, XmssSignature,
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Bits marking which of a slot's (at most `MAX_COMMITTEES_PER_SLOT_PQ`)
/// committees take part in an attestation.
pub type CommitteeBits = SszBitvector<{ preset::MAX_COMMITTEES_PER_SLOT_PQ }>;

/// A leaf of the tree under a validator's VRF root, then the leaf's Merkle
/// branch: the PQ fork's RANDAO reveal.
pub type VrfProof = SszVector<Bytes32, { VRF_TREE_DEPTH + 1 }>;

/// A proof of the XMSS signatures of attestations. In the specification's
/// reference encoding, which [`ethlambda_crypto`'s `stark`] reproduces, the
/// signatures concatenated.
pub type AttestationProof = SszList<u8, { preset::MAX_STARK_PROOF_SIZE }>;

pub type AggregationBits = ProgressiveBitlist;
pub type AttestingIndices = ProgressiveList<ValidatorIndex>;
pub type Attestations = ProgressiveList<Attestation>;
pub type AttesterSlashings = ProgressiveList<AttesterSlashing>;
pub type ProposerSlashings = ProgressiveList<ProposerSlashing>;

pub type ValidatorPreregistrationRequests = ProgressiveList<ValidatorPreregistrationRequest>;
pub type BuilderPreregistrationRequests = ProgressiveList<BuilderPreregistrationRequest>;
pub type ValidatorPreregistrations = ProgressiveList<ValidatorPreregistration>;
pub type BuilderPreregistrations = ProgressiveList<BuilderPreregistration>;
pub type VoluntaryExitRequests = ProgressiveList<VoluntaryExitRequest>;

/// The aggregators of one beacon committee.
pub type AggregationCommittee = ProgressiveList<ValidatorIndex>;
/// The aggregation committee of each beacon committee of a slot, in committee
/// order.
pub type AggregationCommittees = ProgressiveList<AggregationCommittee>;
/// The aggregation committees of the previous, current, and lookahead epochs.
pub type AggregationCommitteeWindow =
    SszVector<AggregationCommittees, { preset::AGGREGATION_COMMITTEE_WINDOW_LENGTH }>;

/// The PQ validator registry: tree-backed and progressively merkleized like
/// gloas's [`shared::ProgressiveValidators`], over this fork's [`Validator`].
pub type Validators =
    ethlambda_ssz_tree::ProgressiveList<Validator, std::collections::BTreeMap<usize, Validator>>;

// ---------------------------------------------------------------------------
// The registry element
// ---------------------------------------------------------------------------

/// A PQ registry entry: the shared record, holding the XMSS key in its 48-byte
/// request form, and the validator's VRF root. See the module doc.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Validator {
    /// Every field but `vrf_root`, with `pubkey` as
    /// [`XmssPubkey::to_request_key`] of the validator's XMSS key.
    pub record: shared::Validator,
    /// The root of the tree of per-slot secrets the validator's RANDAO reveals
    /// open (`is_valid_vrf_proof`).
    pub vrf_root: Root,
}

impl Validator {
    /// The validator's XMSS public key.
    pub fn pubkey(&self) -> XmssPubkey {
        XmssPubkey::from_request_key(&self.record.pubkey)
    }

    fn to_wire(&self) -> ValidatorRecord {
        let record = &self.record;
        ValidatorRecord {
            pubkey: self.pubkey(),
            vrf_root: self.vrf_root,
            withdrawal_credentials: record.withdrawal_credentials,
            effective_balance: record.effective_balance,
            slashed: record.slashed,
            activation_eligibility_epoch: record.activation_eligibility_epoch,
            activation_epoch: record.activation_epoch,
            exit_epoch: record.exit_epoch,
            withdrawable_epoch: record.withdrawable_epoch,
        }
    }

    fn from_wire(wire: ValidatorRecord) -> Self {
        Self {
            record: shared::Validator {
                pubkey: wire.pubkey.to_request_key(),
                withdrawal_credentials: wire.withdrawal_credentials,
                effective_balance: wire.effective_balance,
                slashed: wire.slashed,
                activation_eligibility_epoch: wire.activation_eligibility_epoch,
                activation_epoch: wire.activation_epoch,
                exit_epoch: wire.exit_epoch,
                withdrawable_epoch: wire.withdrawable_epoch,
            },
            vrf_root: wire.vrf_root,
        }
    }
}

/// The specification's PQ `Validator` container, field for field: what a
/// [`Validator`] encodes and merkleizes as.
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
pub struct ValidatorRecord {
    pub pubkey: XmssPubkey,
    pub vrf_root: Root,
    pub withdrawal_credentials: Bytes32,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub effective_balance: Gwei,
    pub slashed: bool,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub activation_eligibility_epoch: Epoch,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub activation_epoch: Epoch,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub exit_epoch: Epoch,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub withdrawable_epoch: Epoch,
}

impl From<ValidatorRecord> for Validator {
    fn from(wire: ValidatorRecord) -> Self {
        Self::from_wire(wire)
    }
}

impl From<&Validator> for ValidatorRecord {
    fn from(validator: &Validator) -> Self {
        validator.to_wire()
    }
}

impl SszEncode for Validator {
    fn is_fixed_size() -> bool {
        <ValidatorRecord as SszEncode>::is_fixed_size()
    }

    fn fixed_size() -> usize {
        <ValidatorRecord as SszEncode>::fixed_size()
    }

    fn encoded_len(&self) -> usize {
        <ValidatorRecord as SszEncode>::fixed_size()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.to_wire().ssz_append(buf);
    }
}

impl SszDecode for Validator {
    fn is_fixed_size() -> bool {
        <ValidatorRecord as SszDecode>::is_fixed_size()
    }

    fn fixed_size() -> usize {
        <ValidatorRecord as SszDecode>::fixed_size()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        ValidatorRecord::from_ssz_bytes(bytes).map(Self::from_wire)
    }
}

impl HashTreeRoot for Validator {
    fn hash_tree_root(&self, hasher: &impl Sha256Hasher) -> Node {
        self.to_wire().hash_tree_root(hasher)
    }
}

impl serde::Serialize for Validator {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_wire().serialize(serializer)
    }
}

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

/// The specification's PQ `Builder` container, field for field: what each of
/// [`Builders`]' records encodes and merkleizes as.
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
pub struct BuilderRecord {
    pub pubkey: XmssPubkey,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub version: u8,
    pub execution_address: ExecutionAddress,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub balance: Gwei,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub deposit_epoch: Epoch,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub withdrawable_epoch: Epoch,
}

impl From<&gloas::Builder> for BuilderRecord {
    fn from(builder: &gloas::Builder) -> Self {
        Self {
            pubkey: XmssPubkey::from_request_key(&builder.pubkey),
            version: builder.version,
            execution_address: builder.execution_address,
            balance: builder.balance,
            deposit_epoch: builder.deposit_epoch,
            withdrawable_epoch: builder.withdrawable_epoch,
        }
    }
}

impl From<BuilderRecord> for gloas::Builder {
    fn from(record: BuilderRecord) -> Self {
        Self {
            pubkey: record.pubkey.to_request_key(),
            version: record.version,
            execution_address: record.execution_address,
            balance: record.balance,
            deposit_epoch: record.deposit_epoch,
            withdrawable_epoch: record.withdrawable_epoch,
        }
    }
}

/// The PQ builder registry: gloas's records in memory, each builder's XMSS key
/// in its 48-byte request form, encoded and merkleized as a
/// `ProgressiveList[Builder]` of [`BuilderRecord`]s. Derefs to the gloas list,
/// so the builder code every gloas-family fork shares reads it unchanged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Builders(pub gloas::Builders);

impl Builders {
    fn records(&self) -> ProgressiveList<BuilderRecord> {
        self.0
            .iter()
            .map(BuilderRecord::from)
            .collect::<Vec<_>>()
            .into()
    }
}

impl core::ops::Deref for Builders {
    type Target = gloas::Builders;

    fn deref(&self) -> &gloas::Builders {
        &self.0
    }
}

impl core::ops::DerefMut for Builders {
    fn deref_mut(&mut self) -> &mut gloas::Builders {
        &mut self.0
    }
}

impl SszEncode for Builders {
    fn is_fixed_size() -> bool {
        false
    }

    fn fixed_size() -> usize {
        0
    }

    fn encoded_len(&self) -> usize {
        self.0.len() * <BuilderRecord as SszEncode>::fixed_size()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        for builder in self.0.iter() {
            BuilderRecord::from(builder).ssz_append(buf);
        }
    }
}

impl SszDecode for Builders {
    fn is_fixed_size() -> bool {
        false
    }

    fn fixed_size() -> usize {
        0
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let records = ProgressiveList::<BuilderRecord>::from_ssz_bytes(bytes)?;
        let builders: Vec<gloas::Builder> = records.iter().cloned().map(Into::into).collect();
        Ok(Self(builders.into()))
    }
}

impl HashTreeRoot for Builders {
    fn hash_tree_root(&self, hasher: &impl Sha256Hasher) -> Node {
        self.records().hash_tree_root(hasher)
    }
}

impl serde::Serialize for Builders {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(BuilderRecord::from))
    }
}

// ---------------------------------------------------------------------------
// Execution-layer requests
// ---------------------------------------------------------------------------

/// A binding of an XMSS key to its withdrawal credentials and VRF root, which a
/// deposit for the key must match while it is active (EIP-8205). The system
/// contract verifies the key's signature before emitting it, so it carries
/// none.
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
pub struct ValidatorPreregistrationRequest {
    pub pubkey: XmssPubkey,
    pub withdrawal_credentials: Bytes32,
    pub vrf_root: Root,
}

/// A stored validator preregistration, enforced until `expiry_slot`.
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
pub struct ValidatorPreregistration {
    pub pubkey: XmssPubkey,
    pub withdrawal_credentials: Bytes32,
    pub vrf_root: Root,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub expiry_slot: Slot,
}

/// The builder counterpart of [`ValidatorPreregistrationRequest`]: a builder
/// has no VRF root.
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
pub struct BuilderPreregistrationRequest {
    pub pubkey: XmssPubkey,
    pub withdrawal_credentials: Bytes32,
}

/// A stored builder preregistration, enforced until `expiry_slot`.
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
pub struct BuilderPreregistration {
    pub pubkey: XmssPubkey,
    pub withdrawal_credentials: Bytes32,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub expiry_slot: Slot,
}

/// A voluntary exit, now an execution-layer request: the system contract
/// verifies the validator's signature at a reserved leaf before emitting it.
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
pub struct VoluntaryExitRequest {
    pub pubkey: XmssPubkey,
}

/// Gloas's five request lists, then the preregistrations and voluntary exits.
/// EIP-8483's two registration lists are gaps (`width=10, gaps=(5, 6)`).
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
#[ssz(progressive_container, active_fields = [1, 1, 1, 1, 1, 0, 0, 1, 1, 1])]
pub struct ExecutionRequests {
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub deposits: DepositRequests,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub withdrawals: WithdrawalRequests,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub consolidations: ConsolidationRequests,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub builder_deposits: BuilderDepositRequests,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub builder_exits: BuilderExitRequests,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub validator_preregistrations: ValidatorPreregistrationRequests,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub builder_preregistrations: BuilderPreregistrationRequests,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub voluntary_exits: VoluntaryExitRequests,
}

// ---------------------------------------------------------------------------
// Signed containers
// ---------------------------------------------------------------------------

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
    pub signature: XmssSignature,
}

/// Two headers a proposer signed at one slot. Both are signed at the same leaf,
/// which exposes that leaf of the proposer's key; the proposer is slashed.
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
pub struct SignedExecutionPayloadBid {
    pub message: ExecutionPayloadBid,
    pub signature: XmssSignature,
}

/// Gloas's envelope, carrying the PQ fork's [`ExecutionRequests`].
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
#[ssz(progressive_container)]
pub struct ExecutionPayloadEnvelope {
    pub payload: ExecutionPayload,
    pub execution_requests: ExecutionRequests,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub builder_index: BuilderIndex,
    pub beacon_block_root: Root,
    pub parent_beacon_block_root: Root,
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
pub struct SignedExecutionPayloadEnvelope {
    pub message: ExecutionPayloadEnvelope,
    pub signature: XmssSignature,
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
pub struct PayloadAttestationMessage {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub validator_index: ValidatorIndex,
    pub data: PayloadAttestationData,
    pub signature: XmssSignature,
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
pub struct SingleAttestation {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub committee_index: CommitteeIndex,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub attester_index: ValidatorIndex,
    pub data: AttestationData,
    pub signature: XmssSignature,
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
pub struct SignedProposerPreferences {
    pub message: ProposerPreferences,
    pub signature: XmssSignature,
}

// ---------------------------------------------------------------------------
// Attestations
// ---------------------------------------------------------------------------

/// Gloas's aggregate attestation without its signature (`width=4, gaps=(2,)`):
/// the signatures travel in a separate [`AttestationProof`].
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
#[ssz(progressive_container, active_fields = [1, 1, 0, 1])]
pub struct Attestation {
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex")]
    pub aggregation_bits: AggregationBits,
    pub data: AttestationData,
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex")]
    pub committee_bits: CommitteeBits,
}

/// An attestation with its attesters named, and the proof of their signatures
/// in place of the aggregate signature (`width=3`: `proof` takes the removed
/// `signature`'s position).
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
#[ssz(progressive_container)]
pub struct IndexedAttestation {
    #[serde(
        serialize_with = "crate::beacon::serde_helpers::quoted_u64_seq::serialize",
        deserialize_with = "crate::beacon::serde_helpers::quoted_u64_seq::deserialize_progressive"
    )]
    pub attesting_indices: AttestingIndices,
    pub data: AttestationData,
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex")]
    pub proof: AttestationProof,
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
pub struct AttesterSlashing {
    pub attestation_1: IndexedAttestation,
    pub attestation_2: IndexedAttestation,
}

/// An aggregate as gossiped: the aggregate and the proof of its attesters'
/// signatures. The selection proof is gone, aggregators being the state's
/// aggregation committee rather than self-selected.
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
pub struct AggregateAndProof {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub aggregator_index: ValidatorIndex,
    pub aggregate: Attestation,
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex")]
    pub proof: AttestationProof,
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
pub struct SignedAggregateAndProof {
    pub message: AggregateAndProof,
    pub signature: XmssSignature,
}

/// What the Beacon API's `aggregate_attestation` answers at a PQ slot: a
/// committee's network aggregate and the proof of its attesters'
/// signatures, which the aggregator wraps in its `AggregateAndProof`. Not a
/// consensus container; the shape is Lighthouse's PQ branch's `PqAggregate`.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, SszEncode, SszDecode,
)]
pub struct ProvenAggregate {
    pub aggregate: Attestation,
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex")]
    pub proof: AttestationProof,
}

// ---------------------------------------------------------------------------
// Blocks
// ---------------------------------------------------------------------------

/// The PQ block body (`width=14, gaps=(7, 8, 9, 11)`): gloas's without
/// `voluntary_exits`, `sync_aggregate`, `bls_to_execution_changes` and
/// `payload_attestations`, with a VRF proof for its RANDAO reveal and the
/// `proof` of every attestation's signatures appended.
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
#[ssz(
    progressive_container,
    active_fields = [1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1]
)]
pub struct BeaconBlockBody {
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub randao_reveal: VrfProof,
    pub eth1_data: Eth1Data,
    pub graffiti: Bytes32,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub proposer_slashings: ProposerSlashings,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub attester_slashings: AttesterSlashings,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub attestations: Attestations,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub deposits: Deposits,
    pub signed_execution_payload_bid: SignedExecutionPayloadBid,
    pub parent_execution_requests: ExecutionRequests,
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex")]
    pub proof: AttestationProof,
}

/// An all-zero [`VrfProof`], which [`SszVector`] has no `Default` for.
pub fn empty_vrf_proof() -> VrfProof {
    VrfProof::try_from(vec![Bytes32::default(); VRF_TREE_DEPTH + 1])
        .expect("VRF_TREE_DEPTH + 1 roots fit VrfProof's exact length")
}

impl BeaconBlockBody {
    /// An empty body: no operations, a zero VRF proof, an empty proof.
    pub fn empty() -> Self {
        Self {
            randao_reveal: empty_vrf_proof(),
            eth1_data: Default::default(),
            graffiti: Default::default(),
            proposer_slashings: Default::default(),
            attester_slashings: Default::default(),
            attestations: Default::default(),
            deposits: Default::default(),
            signed_execution_payload_bid: Default::default(),
            parent_execution_requests: Default::default(),
            proof: Default::default(),
        }
    }
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
    pub signature: XmssSignature,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// The PQ beacon state (`width=51, gaps=(22, 23, 46, 47)`): gloas's fields
/// without the two sync committees, EIP-8483's registrations removed in turn,
/// and the preregistrations and aggregation committee window appended. 47
/// fields, in the specification's order.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot)]
#[ssz(
    progressive_container,
    active_fields = [
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1
    ]
)]
pub struct BeaconState {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub genesis_time: u64,
    pub genesis_validators_root: Root,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub slot: Slot,
    pub fork: Fork,
    pub latest_block_header: BeaconBlockHeader,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub block_roots: BlockRoots,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub state_roots: StateRoots,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub historical_roots: HistoricalRoots,
    pub eth1_data: Eth1Data,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub eth1_data_votes: Eth1DataVotes,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub eth1_deposit_index: u64,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub validators: Validators,
    #[serde(with = "crate::beacon::serde_helpers::quoted_u64_seq")]
    pub balances: ProgressiveBalances,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub randao_mixes: RandaoMixes,
    #[serde(with = "crate::beacon::serde_helpers::quoted_u64_seq")]
    pub slashings: Slashings,
    #[serde(with = "crate::beacon::serde_helpers::quoted_u64_seq")]
    pub previous_epoch_participation: EpochParticipation,
    #[serde(with = "crate::beacon::serde_helpers::quoted_u64_seq")]
    pub current_epoch_participation: EpochParticipation,
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex")]
    pub justification_bits: JustificationBits,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
    #[serde(with = "crate::beacon::serde_helpers::quoted_u64_seq")]
    pub inactivity_scores: InactivityScores,
    // Gaps: `current_sync_committee` (22), `next_sync_committee` (23).
    pub latest_block_hash: ExecutionBlockHash,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub next_withdrawal_index: WithdrawalIndex,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub next_withdrawal_validator_index: ValidatorIndex,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub historical_summaries: HistoricalSummaries,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub deposit_requests_start_index: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub deposit_balance_to_consume: Gwei,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub exit_balance_to_consume: Gwei,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub earliest_exit_epoch: Epoch,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub consolidation_balance_to_consume: Gwei,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub earliest_consolidation_epoch: Epoch,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub pending_deposits: PendingDeposits,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub pending_partial_withdrawals: PendingPartialWithdrawals,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub pending_consolidations: PendingConsolidations,
    #[serde(with = "crate::beacon::serde_helpers::quoted_u64_seq")]
    pub proposer_lookahead: ProposerLookahead,
    pub builders: Builders,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub next_withdrawal_builder_index: BuilderIndex,
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex")]
    pub execution_payload_availability: ExecutionPayloadAvailability,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub builder_pending_payments: BuilderPendingPayments,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub builder_pending_withdrawals: BuilderPendingWithdrawals,
    pub latest_execution_payload_bid: ExecutionPayloadBid,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub payload_expected_withdrawals: Withdrawals,
    #[serde(serialize_with = "crate::beacon::serde_helpers::nested_quoted_u64_seq::serialize")]
    pub ptc_window: PayloadTimelinessCommitteeWindow,
    // Gaps: `validator_pq_registrations` (46), `builder_pq_registrations` (47).
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub validator_preregistrations: ValidatorPreregistrations,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub builder_preregistrations: BuilderPreregistrations,
    #[serde(serialize_with = "serialize_window")]
    pub aggregation_committee_window: AggregationCommitteeWindow,
}

/// The Beacon API's JSON for the window: per slot, per committee, the
/// aggregators' indices as quoted integers.
fn serialize_window<S: serde::Serializer>(
    window: &AggregationCommitteeWindow,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    struct Committees<'a>(&'a AggregationCommittees);
    impl serde::Serialize for Committees<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.collect_seq(self.0.iter().map(Committee))
        }
    }
    struct Committee<'a>(&'a AggregationCommittee);
    impl serde::Serialize for Committee<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.collect_seq(self.0.iter().map(u64::to_string))
        }
    }
    serializer.collect_seq(window.iter().map(Committees))
}

/// An all-empty [`AggregationCommitteeWindow`], which [`SszVector`] has no
/// `Default` for: what the fork upgrade starts from before
/// `initialize_aggregation_committee_window` fills it.
pub fn empty_aggregation_committee_window() -> AggregationCommitteeWindow {
    let empty = vec![AggregationCommittees::default(); preset::AGGREGATION_COMMITTEE_WINDOW_LENGTH];
    AggregationCommitteeWindow::try_from(empty)
        .expect("AGGREGATION_COMMITTEE_WINDOW_LENGTH entries fit the window's exact length")
}

#[cfg(test)]
mod tests {
    use libssz::{SszDecode as _, SszEncode as _};
    use libssz_merkle::{HashTreeRoot as _, Sha2Hasher};

    use super::*;

    fn validator() -> Validator {
        Validator {
            record: shared::Validator {
                pubkey: XmssPubkey([9; 32]).to_request_key(),
                withdrawal_credentials: Bytes32::repeat_byte(1),
                effective_balance: 32_000_000_000,
                slashed: false,
                activation_eligibility_epoch: 1,
                activation_epoch: 2,
                exit_epoch: 3,
                withdrawable_epoch: 4,
            },
            vrf_root: Root::repeat_byte(5),
        }
    }

    /// A [`Validator`] encodes and merkleizes exactly as the specification's
    /// nine-field container does, built here independently field by field.
    #[test]
    fn validator_is_the_specifications_container() {
        let validator = validator();
        let mut expected = Vec::new();
        expected.extend_from_slice(&[9; 32]);
        expected.extend_from_slice(&[5; 32]);
        expected.extend_from_slice(&[1; 32]);
        expected.extend_from_slice(&32_000_000_000u64.to_le_bytes());
        expected.push(0);
        for epoch in 1u64..=4 {
            expected.extend_from_slice(&epoch.to_le_bytes());
        }
        assert_eq!(validator.to_ssz(), expected);
        assert_eq!(<Validator as SszEncode>::fixed_size(), 137);
        assert_eq!(Validator::from_ssz_bytes(&expected).unwrap(), validator);
        assert_eq!(
            validator.hash_tree_root(&Sha2Hasher),
            ValidatorRecord::from(&validator).hash_tree_root(&Sha2Hasher)
        );
    }

    #[test]
    fn builders_round_trip_through_their_records() {
        let builder = gloas::Builder {
            pubkey: XmssPubkey([3; 32]).to_request_key(),
            version: 0,
            execution_address: Default::default(),
            balance: 7,
            deposit_epoch: 1,
            withdrawable_epoch: u64::MAX,
        };
        let builders = Builders(vec![builder.clone(), builder].into());
        let bytes = builders.to_ssz();
        assert_eq!(bytes.len(), 2 * 77);
        assert_eq!(Builders::from_ssz_bytes(&bytes).unwrap(), builders);
        assert_eq!(
            builders.hash_tree_root(&Sha2Hasher),
            builders.records().hash_tree_root(&Sha2Hasher)
        );
    }

    #[test]
    fn the_window_round_trips() {
        let mut window = empty_aggregation_committee_window();
        window[3] = vec![vec![1u64, 2].into(), vec![].into()].into();
        let bytes = window.to_ssz();
        assert_eq!(
            AggregationCommitteeWindow::from_ssz_bytes(&bytes).unwrap(),
            window
        );
    }

    /// The largest attestation proof a block or aggregate can carry.
    fn largest_proof() -> AttestationProof {
        AttestationProof::try_from(vec![0u8; preset::MAX_STARK_PROOF_SIZE])
            .expect("MAX_STARK_PROOF_SIZE bytes fit the proof's bound")
    }

    /// The most attesters one attestation can name: every member of every
    /// committee of a slot.
    const MAX_ATTESTERS: usize =
        preset::MAX_VALIDATORS_PER_COMMITTEE * preset::MAX_COMMITTEES_PER_SLOT_PQ;

    fn largest_indexed_attestation() -> IndexedAttestation {
        IndexedAttestation {
            attesting_indices: vec![0; MAX_ATTESTERS].into(),
            data: Default::default(),
            proof: largest_proof(),
        }
    }

    /// The specification's own maximum encodings (`pq.yaml`'s type-specific
    /// SSZ bounds), against values built at every bound: the offsets, field
    /// widths and the fields the fork removed all show up in these lengths.
    /// Serialization only; `active_fields` changes roots, not bytes.
    #[test]
    fn the_largest_values_encode_to_the_specifications_bounds() {
        let slashing = AttesterSlashing {
            attestation_1: largest_indexed_attestation(),
            attestation_2: largest_indexed_attestation(),
        };
        assert_eq!(
            slashing.to_ssz().len(),
            preset::MAX_ATTESTER_SLASHING_SIZE_PQ
        );

        let aggregate = SignedAggregateAndProof {
            message: AggregateAndProof {
                aggregator_index: 0,
                aggregate: Attestation {
                    aggregation_bits: ProgressiveBitlist::with_length(MAX_ATTESTERS),
                    data: Default::default(),
                    committee_bits: Default::default(),
                },
                proof: largest_proof(),
            },
            signature: Default::default(),
        };
        assert_eq!(
            aggregate.to_ssz().len(),
            preset::MAX_SIGNED_AGGREGATE_AND_PROOF_SIZE_PQ
        );

        let commitments = vec![Default::default(); preset::MAX_BLOB_COMMITMENTS_PER_BLOCK];
        let bid = SignedExecutionPayloadBid {
            message: ExecutionPayloadBid {
                blob_kzg_commitments: commitments.into(),
                ..Default::default()
            },
            signature: Default::default(),
        };
        assert_eq!(
            bid.to_ssz().len(),
            preset::MAX_SIGNED_EXECUTION_PAYLOAD_BID_SIZE_PQ
        );
    }
}

/// What block production hands a PQ proposer: the unsigned block and the
/// unsigned envelope revealing its payload, which the proposer signs at their
/// own leaves. ethlambda's own validator-client exchange: Lighthouse's PQ
/// branch has an equivalent (`PqBlockAndEnvelope`), the Beacon API none yet.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
pub struct BlockContents {
    pub block: BeaconBlock,
    pub execution_payload_envelope: ExecutionPayloadEnvelope,
}
