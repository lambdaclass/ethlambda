//! Containers whose shape is specific to EIP-8483 (consensus-specs
//! `specs/_features/eip8483`, on the `pq` branch at
//! `4c296784bb6ff54cbdcf72ebdda2a1057cce8893`).
//!
//! EIP-8483 adds two execution-layer requests with which validators and
//! builders register opaque post-quantum material: 64 bytes for a validator
//! (an XMSS public key and a VRF root, as the PQ fork reads them) and 32 for a
//! builder (an XMSS public key). The state keeps at most one entry per
//! validator, keyed by index, and one per builder, keyed by public key, since a
//! builder index is reused once its builder has withdrawn. This fork gives the
//! material no meaning beyond requiring each 32-byte part to be unique; the PQ
//! fork ([`super::pq`]) is what adopts it.
//!
//! Every other container is gloas's. [`ExecutionRequests`] gains the two
//! request lists, which reshapes every container holding one:
//! [`BeaconBlockBody`] (`parent_execution_requests`) and so
//! [`BeaconBlock`]/[`SignedBeaconBlock`], and [`ExecutionPayloadEnvelope`] and
//! so [`SignedExecutionPayloadEnvelope`]. [`BeaconState`] is gloas's with the
//! two registration lists appended.

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::ProgressiveList;

use super::altair::{SyncAggregate, SyncCommittee};
use super::fulu::ProposerLookahead;
use super::gloas::{
    Attestations, AttesterSlashings, BlsToExecutionChanges, BuilderDepositRequests,
    BuilderExitRequests, BuilderIndex, BuilderPendingPayments, BuilderPendingWithdrawals, Builders,
    ConsolidationRequests, DepositRequests, Deposits, EpochParticipation, ExecutionPayload,
    ExecutionPayloadAvailability, ExecutionPayloadBid, InactivityScores, PayloadAttestations,
    PayloadTimelinessCommitteeWindow, PendingConsolidations, PendingDeposits,
    PendingPartialWithdrawals, ProposerSlashings, SignedExecutionPayloadBid, VoluntaryExits,
    WithdrawalRequests, Withdrawals,
};
use super::shared::{
    BeaconBlockHeader, BlockRoots, Checkpoint, Eth1Data, Eth1DataVotes, Fork, HistoricalRoots,
    HistoricalSummaries, JustificationBits, ProgressiveBalances, ProgressiveValidators,
    RandaoMixes, Slashings, StateRoots,
};
use crate::beacon::primitives::{
    BlsPubkey, BlsSignature, Bytes32, Epoch, ExecutionAddress, ExecutionBlockHash, Gwei, Root,
    Slot, ValidatorIndex, WithdrawalIndex,
};

/// A validator's registered PQ material: an XMSS public key, then a VRF root,
/// as the PQ fork reads them.
pub type PqData = [u8; 64];

/// The validator PQ registration requests of one execution payload.
pub type ValidatorPqRegistrationRequests = ProgressiveList<ValidatorPqRegistrationRequest>;
/// The registered validator PQ material, at most one entry per validator.
pub type ValidatorPqRegistrations = ProgressiveList<ValidatorPqRegistration>;
/// The builder PQ registration requests of one execution payload.
pub type BuilderPqRegistrationRequests = ProgressiveList<BuilderPqRegistrationRequest>;
/// The registered builder PQ material, at most one entry per builder.
pub type BuilderPqRegistrations = ProgressiveList<BuilderPqRegistration>;

/// A validator's request to register PQ material. Its SSZ encoding is the
/// 132-byte record the validator predeploy contract returns.
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
pub struct ValidatorPqRegistrationRequest {
    pub source_address: ExecutionAddress,
    pub validator_pubkey: BlsPubkey,
    #[serde(with = "crate::beacon::serde_helpers::hex_array")]
    pub pq_data: PqData,
}

/// One validator's registered PQ material.
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
pub struct ValidatorPqRegistration {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub validator_index: ValidatorIndex,
    #[serde(with = "crate::beacon::serde_helpers::hex_array")]
    pub pq_data: PqData,
}

/// A builder's request to register PQ material. Its SSZ encoding is the
/// 100-byte record the builder predeploy contract returns.
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
pub struct BuilderPqRegistrationRequest {
    pub source_address: ExecutionAddress,
    pub builder_pubkey: BlsPubkey,
    pub pq_data: Bytes32,
}

/// One builder's registered PQ material, keyed by the builder's BLS key.
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
pub struct BuilderPqRegistration {
    pub builder_pubkey: BlsPubkey,
    pub pq_data: Bytes32,
}

/// Gloas's execution requests plus EIP-8483's two registration lists.
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
#[ssz(progressive_container)]
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
    pub validator_pq_registrations: ValidatorPqRegistrationRequests,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub builder_pq_registrations: BuilderPqRegistrationRequests,
}

/// Gloas's envelope, carrying EIP-8483's wider [`ExecutionRequests`].
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
    pub signature: BlsSignature,
}

/// Gloas's block body, with `parent_execution_requests` now EIP-8483's
/// [`ExecutionRequests`].
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
#[ssz(progressive_container)]
pub struct BeaconBlockBody {
    pub randao_reveal: BlsSignature,
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
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub voluntary_exits: VoluntaryExits,
    pub sync_aggregate: SyncAggregate,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub bls_to_execution_changes: BlsToExecutionChanges,
    pub signed_execution_payload_bid: SignedExecutionPayloadBid,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub payload_attestations: PayloadAttestations,
    pub parent_execution_requests: ExecutionRequests,
}

impl BeaconBlockBody {
    /// An empty body, for parity with every earlier fork's `empty()`.
    pub fn empty() -> Self {
        Self::default()
    }
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
    Default,
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

/// The EIP-8483 beacon state: gloas's 46 fields, then the two registration
/// lists, 48 in all, in the specification's order.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, SszEncode, SszDecode, HashTreeRoot)]
#[ssz(progressive_container)]
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
    pub validators: ProgressiveValidators,
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
    pub current_sync_committee: SyncCommittee,
    pub next_sync_committee: SyncCommittee,
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
    #[serde(with = "crate::beacon::serde_helpers::seq")]
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
    // -- EIP-8483 --
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub validator_pq_registrations: ValidatorPqRegistrations,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub builder_pq_registrations: BuilderPqRegistrations,
}

#[cfg(test)]
mod tests {
    use libssz::{SszDecode as _, SszEncode as _};

    use super::*;

    /// The predeploy contracts' record sizes the specification's notes give.
    #[test]
    fn request_records_have_the_predeploys_sizes() {
        let validator = ValidatorPqRegistrationRequest {
            source_address: Default::default(),
            validator_pubkey: Default::default(),
            pq_data: [7; 64],
        };
        assert_eq!(validator.to_ssz().len(), 132);
        assert_eq!(BuilderPqRegistrationRequest::default().to_ssz().len(), 100);
        let decoded = ValidatorPqRegistrationRequest::from_ssz_bytes(&validator.to_ssz()).unwrap();
        assert_eq!(decoded, validator);
    }
}
