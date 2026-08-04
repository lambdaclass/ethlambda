//! Shared execution primitives for leanSpec fixtures.
//!
//! Both the offline spec-test binaries and Hive's HTTP test driver use these
//! functions so fixture replay cannot drift between the two entry points.

use ethlambda_storage::Store;
use ethlambda_test_fixtures::{RejectionReason, fork_choice::ForkChoiceStep};
use ethlambda_types::{
    attestation::{
        AggregationBits, HashedAttestationData, SignedAggregatedAttestation, SignedAttestation,
    },
    block::{ByteList512KiB, SingleMessageAggregate},
};

use crate::{
    MILLISECONDS_PER_INTERVAL, MILLISECONDS_PER_SLOT,
    store::{self, StoreError},
};

/// Prefix emitted by leanSpec's mocked aggregation prover.
const MOCK_PROOF_PREFIX: &[u8] = b"\x00MOCKED-AGGREGATION-PROOF\x00";

/// Why a fork-choice fixture step failed.
///
/// Distinguishes a client rejection, which negative fixtures assert against
/// their `rejectionReason`, from a harness failure, which means the fixture
/// asked for something this runner cannot replay.
#[derive(Debug, thiserror::Error)]
pub enum StepError {
    /// The store rejected the step.
    #[error(transparent)]
    Store(#[from] StoreError),

    /// The step is malformed or names something the runner cannot replay. Never
    /// a client rejection, so it never satisfies an expected `rejectionReason`.
    #[error("{0}")]
    Harness(String),
}

impl StepError {
    /// The leanSpec rejection reason this failure corresponds to, if any.
    pub fn rejection_reason(&self) -> Option<RejectionReason> {
        match self {
            Self::Store(err) => rejection_reason(err),
            Self::Harness(_) => None,
        }
    }
}

/// Classify a store rejection into the reason leanSpec would report for it,
/// mirroring the spec's `classify_rejection`.
///
/// `None` means the variant has no spec counterpart, which the spec-test runners
/// report as an unclassified rejection rather than accepting silently. The match
/// is exhaustive so a new [`StoreError`] variant forces that decision here.
///
/// `StateTransitionFailed` is the one context-dependent variant: it defers to
/// the state-transition classification, which the STF runner asserts directly.
pub fn rejection_reason(err: &StoreError) -> Option<RejectionReason> {
    let reason = match err {
        StoreError::MissingParentState { .. } => RejectionReason::UnknownParentBlock,
        StoreError::ValidatorNotInState { .. } => RejectionReason::ValidatorNotInState,
        StoreError::AttesterIndexOutOfRange { .. } => RejectionReason::ValidatorIndexOutOfRange,
        StoreError::ProposerIndexOutOfRange { .. } => RejectionReason::ProposerIndexOutOfRange,
        StoreError::SignatureDecodingFailed | StoreError::SignatureVerificationFailed => {
            RejectionReason::InvalidSignature
        }
        StoreError::StateTransitionFailed(err) => err.into(),
        StoreError::UnknownSourceBlock(_) => RejectionReason::UnknownSourceBlock,
        StoreError::UnknownTargetBlock(_) => RejectionReason::UnknownTargetBlock,
        StoreError::UnknownHeadBlock(_) => RejectionReason::UnknownHeadBlock,
        StoreError::SourceExceedsTarget => RejectionReason::SourceAfterTarget,
        StoreError::HeadOlderThanTarget { .. } => RejectionReason::HeadOlderThanTarget,
        StoreError::SourceSlotMismatch { .. } => RejectionReason::SourceSlotMismatch,
        StoreError::TargetSlotMismatch { .. } => RejectionReason::TargetSlotMismatch,
        StoreError::HeadSlotMismatch { .. } => RejectionReason::HeadSlotMismatch,
        StoreError::SourceNotAncestorOfTarget => RejectionReason::SourceNotAncestorOfTarget,
        StoreError::TargetNotAncestorOfHead => RejectionReason::TargetNotAncestorOfHead,
        StoreError::HeadNotDescendantOfFinalized { .. } => {
            RejectionReason::HeadNotDescendantOfFinalized
        }
        StoreError::AttestationSlotBeforeHead { .. } => RejectionReason::AttestationSlotBeforeHead,
        StoreError::AttestationTooFarInFuture { .. } => RejectionReason::AttestationTooFarInFuture,
        StoreError::AggregateVerificationFailed(_) => RejectionReason::InvalidSignature,
        StoreError::BlockProofVerificationFailed(_) => RejectionReason::InvalidBlockProof,
        StoreError::EmptyAggregationBits => RejectionReason::EmptyAggregationBits,
        StoreError::NotProposer { .. } => RejectionReason::WrongProposer,
        StoreError::DuplicateAttestationData { .. } => RejectionReason::DuplicateAttestationData,
        StoreError::TooManyAttestationData { .. } => RejectionReason::TooManyAttestationData,
        StoreError::BlockSlotGapTooLarge { .. } => RejectionReason::BlockSlotGapTooLarge,
        StoreError::BlockTooFarInFuture { .. } => RejectionReason::BlockTooFarInFuture,

        // Internal failures with no spec counterpart: the spec has no undecodable
        // registry pubkey, no aggregation step inside validation, no state that
        // can go missing behind a known block, and no slot width limit (its
        // slots are unbounded where ours narrow to the XMSS epoch's u32).
        StoreError::PubkeyDecodingFailed(_)
        | StoreError::SignatureAggregationFailed(_)
        | StoreError::MissingTargetState(_)
        | StoreError::SlotOutOfRange(_) => return None,
    };
    Some(reason)
}

/// Apply one fork-choice fixture step.
///
/// `proofs_are_mocked` is supplied by complete offline vectors through their
/// `proofSetting`. Hive sends individual steps, so `None` detects the mocked
/// prover's sentinel directly from the proof bytes.
pub fn apply_fork_choice_step(
    store: &mut Store,
    step: &ForkChoiceStep,
    proofs_are_mocked: Option<bool>,
) -> Result<(), StepError> {
    match step.step_type.as_str() {
        "tick" => {
            let genesis_time = store.config().expect("config exists").genesis_time;
            let timestamp_ms = match (step.time, step.interval) {
                (Some(time_s), _) => time_s * 1000,
                (None, Some(interval)) => {
                    genesis_time * 1000 + interval * MILLISECONDS_PER_INTERVAL
                }
                (None, None) => {
                    return Err(StepError::Harness(
                        "tick step missing time and interval".to_string(),
                    ));
                }
            };
            store::on_tick(store, timestamp_ms, step.has_proposal.unwrap_or(false));
            Ok(())
        }
        "block" => {
            let block_data = step
                .block
                .as_ref()
                .ok_or_else(|| StepError::Harness("block step missing block data".to_string()))?;
            let signed_block = block_data.to_blank_signed_block();
            if step.tick_to_slot {
                let block_time_ms = store.config().expect("config exists").genesis_time * 1000
                    + signed_block.message.slot * MILLISECONDS_PER_SLOT;
                store::on_tick(store, block_time_ms, true);
            }
            store::on_block_without_verification(store, signed_block)?;

            let block = block_data.to_block();
            let entries = block.body.attestations.iter().map(|att| {
                (
                    HashedAttestationData::new(att.data.clone()),
                    SingleMessageAggregate::empty(att.aggregation_bits.clone()),
                )
            });
            store.insert_known_aggregated_payloads_batch(entries.collect());
            store::update_head(store);
            Ok(())
        }
        "attestation" => {
            let att = step
                .attestation
                .as_ref()
                .ok_or_else(|| StepError::Harness("attestation step missing data".to_string()))?;
            let signed = SignedAttestation {
                validator_id: att.validator_id.ok_or_else(|| {
                    StepError::Harness("attestation step missing validatorId".to_string())
                })?,
                data: att.data.clone().into(),
                signature: att.signature.clone().ok_or_else(|| {
                    StepError::Harness("attestation step missing signature".to_string())
                })?,
            };
            store::on_gossip_attestation(store, &signed, step.is_aggregator.unwrap_or(false))?;
            Ok(())
        }
        "gossipAggregatedAttestation" => {
            let att = step.attestation.as_ref().ok_or_else(|| {
                StepError::Harness("gossipAggregatedAttestation step missing data".to_string())
            })?;
            let proof = att.proof.as_ref().ok_or_else(|| {
                StepError::Harness("gossipAggregatedAttestation step missing proof".to_string())
            })?;
            let participants: AggregationBits = proof.participants.clone().into();
            let proof_bytes: Vec<u8> = proof.proof.clone().into();
            let is_mocked =
                proofs_are_mocked.unwrap_or_else(|| proof_bytes.starts_with(MOCK_PROOF_PREFIX));
            let proof_data = ByteList512KiB::try_from(proof_bytes).map_err(|err| {
                StepError::Harness(format!("aggregated proof data too large: {err:?}"))
            })?;
            let aggregated = SignedAggregatedAttestation {
                proof: SingleMessageAggregate::new(participants, proof_data),
                data: att.data.clone().into(),
            };
            if is_mocked {
                store::on_gossip_aggregated_attestation_without_verification(store, aggregated)?;
            } else {
                store::on_gossip_aggregated_attestation(store, aggregated)?;
            }
            Ok(())
        }
        "checks" => Ok(()),
        other => Err(StepError::Harness(format!("unknown step type: {other}"))),
    }
}
