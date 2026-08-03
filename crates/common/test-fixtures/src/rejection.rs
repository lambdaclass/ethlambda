//! Language-neutral rejection reasons carried by negative leanSpec fixtures.
//!
//! Fixtures that expect their input to be rejected name *why* in a
//! `rejectionReason` field. Asserting only that the client failed lets a test
//! pass for the wrong reason (a state-root mismatch standing in for the rule the
//! fixture meant to exercise), so the spec-test runners compare the reason the
//! client's error maps to against the reason the fixture names.

use serde::{Deserialize, Deserializer};
use std::fmt;

/// Language-neutral reason the spec rejects an invalid input.
///
/// Mirrors leanSpec's `RejectionReason` StrEnum
/// (`src/lean_spec/spec/forks/lstar/errors.py`), which is the vocabulary fixtures
/// use for their `rejectionReason` field. Clients match on the reason code, never
/// on a human-readable message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectionReason {
    // Block validation
    /// The block slot is not strictly greater than the current state slot.
    BlockSlotNotInFuture,
    /// The block slot runs so far beyond its parent it would force an unbounded
    /// empty-slot walk.
    BlockSlotGapTooLarge,
    /// The block slot is beyond the store's accepted future horizon.
    BlockTooFarInFuture,
    /// The block slot is not newer than the latest block header.
    BlockOlderThanLatestHeader,
    /// The block slot disagrees with the state slot after slot processing.
    BlockSlotMismatch,
    /// The block parent root disagrees with the latest block header root.
    ParentRootMismatch,
    /// The block state root disagrees with the computed post-state root.
    StateRootMismatch,
    /// The block references a parent the store has never seen.
    UnknownParentBlock,
    /// The proposer index does not address any registered validator.
    ProposerIndexOutOfRange,
    /// The registry holds no validators, so no proposer can be scheduled.
    EmptyValidatorRegistry,
    /// The block proposer is not the scheduled proposer for its slot.
    WrongProposer,
    /// The block carries more distinct attestation data entries than allowed.
    TooManyAttestationData,
    /// The block carries the same attestation data entry more than once.
    DuplicateAttestationData,
    /// An aggregated attestation references no validator at all.
    EmptyAggregationBits,

    // Attestation validation
    /// The attestation source root is not a known block.
    UnknownSourceBlock,
    /// The attestation target root is not a known block.
    UnknownTargetBlock,
    /// The attestation head root is not a known block.
    UnknownHeadBlock,
    /// The attestation source checkpoint slot exceeds its target slot.
    SourceAfterTarget,
    /// The attestation head checkpoint is older than its target.
    HeadOlderThanTarget,
    /// The source checkpoint slot disagrees with the referenced block.
    SourceSlotMismatch,
    /// The target checkpoint slot disagrees with the referenced block.
    TargetSlotMismatch,
    /// The head checkpoint slot disagrees with the referenced block.
    HeadSlotMismatch,
    /// The attestation source checkpoint is not an ancestor of its target.
    SourceNotAncestorOfTarget,
    /// The attestation target checkpoint is not an ancestor of its head.
    TargetNotAncestorOfHead,
    /// The attestation head checkpoint does not descend from the finalized block.
    HeadNotDescendantOfFinalized,
    /// The attestation slot is beyond the store's acceptance horizon.
    AttestationTooFarInFuture,
    /// The attestation slot precedes its head block's slot.
    AttestationSlotBeforeHead,
    /// The referenced validator does not exist in the state registry.
    ValidatorNotInState,
    /// The validator index does not address any registered validator.
    ValidatorIndexOutOfRange,
    /// A justification query named a slot beyond the tracked window.
    JustifiedSlotOutOfRange,
    /// A tracked justification root is the zero hash, which is not a valid root.
    ZeroHashJustificationRoot,
    /// The flat vote list length is not the tracked-root count times the
    /// validator count.
    JustificationVotesLengthMismatch,

    // Cryptographic verification
    /// An attestation signature or aggregate proof fails verification.
    InvalidSignature,
    /// The block's multi-message aggregate proof fails verification.
    InvalidBlockProof,

    // Anchor initialization
    /// The anchor block state root disagrees with the anchor state.
    AnchorStateRootMismatch,

    // Wire decoding
    /// The input bytes cannot be decoded into the expected structure.
    DecodeError,

    /// A reason string this build does not know.
    ///
    /// Fixtures track leanSpec's latest release, so a new reason can arrive
    /// before this enum learns it. Deserialization keeps it verbatim (the Hive
    /// test driver must still answer such a step rather than reject the request)
    /// and the offline runners fail on it, naming the string to add here.
    Unknown(String),
}

impl RejectionReason {
    /// Every reason this build knows, in declaration order.
    ///
    /// [`Self::as_str`] and [`From<&str>`] are two parallel tables; this list is
    /// what `every_known_reason_round_trips` walks to prove they agree, so a new
    /// variant belongs here alongside its two arms.
    pub const ALL: &'static [Self] = &[
        Self::BlockSlotNotInFuture,
        Self::BlockSlotGapTooLarge,
        Self::BlockTooFarInFuture,
        Self::BlockOlderThanLatestHeader,
        Self::BlockSlotMismatch,
        Self::ParentRootMismatch,
        Self::StateRootMismatch,
        Self::UnknownParentBlock,
        Self::ProposerIndexOutOfRange,
        Self::EmptyValidatorRegistry,
        Self::WrongProposer,
        Self::TooManyAttestationData,
        Self::DuplicateAttestationData,
        Self::EmptyAggregationBits,
        Self::UnknownSourceBlock,
        Self::UnknownTargetBlock,
        Self::UnknownHeadBlock,
        Self::SourceAfterTarget,
        Self::HeadOlderThanTarget,
        Self::SourceSlotMismatch,
        Self::TargetSlotMismatch,
        Self::HeadSlotMismatch,
        Self::SourceNotAncestorOfTarget,
        Self::TargetNotAncestorOfHead,
        Self::HeadNotDescendantOfFinalized,
        Self::AttestationTooFarInFuture,
        Self::AttestationSlotBeforeHead,
        Self::ValidatorNotInState,
        Self::ValidatorIndexOutOfRange,
        Self::JustifiedSlotOutOfRange,
        Self::ZeroHashJustificationRoot,
        Self::JustificationVotesLengthMismatch,
        Self::InvalidSignature,
        Self::InvalidBlockProof,
        Self::AnchorStateRootMismatch,
        Self::DecodeError,
    ];

    /// The wire spelling fixtures use for this reason.
    pub fn as_str(&self) -> &str {
        match self {
            Self::BlockSlotNotInFuture => "BLOCK_SLOT_NOT_IN_FUTURE",
            Self::BlockSlotGapTooLarge => "BLOCK_SLOT_GAP_TOO_LARGE",
            Self::BlockTooFarInFuture => "BLOCK_TOO_FAR_IN_FUTURE",
            Self::BlockOlderThanLatestHeader => "BLOCK_OLDER_THAN_LATEST_HEADER",
            Self::BlockSlotMismatch => "BLOCK_SLOT_MISMATCH",
            Self::ParentRootMismatch => "PARENT_ROOT_MISMATCH",
            Self::StateRootMismatch => "STATE_ROOT_MISMATCH",
            Self::UnknownParentBlock => "UNKNOWN_PARENT_BLOCK",
            Self::ProposerIndexOutOfRange => "PROPOSER_INDEX_OUT_OF_RANGE",
            Self::EmptyValidatorRegistry => "EMPTY_VALIDATOR_REGISTRY",
            Self::WrongProposer => "WRONG_PROPOSER",
            Self::TooManyAttestationData => "TOO_MANY_ATTESTATION_DATA",
            Self::DuplicateAttestationData => "DUPLICATE_ATTESTATION_DATA",
            Self::EmptyAggregationBits => "EMPTY_AGGREGATION_BITS",
            Self::UnknownSourceBlock => "UNKNOWN_SOURCE_BLOCK",
            Self::UnknownTargetBlock => "UNKNOWN_TARGET_BLOCK",
            Self::UnknownHeadBlock => "UNKNOWN_HEAD_BLOCK",
            Self::SourceAfterTarget => "SOURCE_AFTER_TARGET",
            Self::HeadOlderThanTarget => "HEAD_OLDER_THAN_TARGET",
            Self::SourceSlotMismatch => "SOURCE_SLOT_MISMATCH",
            Self::TargetSlotMismatch => "TARGET_SLOT_MISMATCH",
            Self::HeadSlotMismatch => "HEAD_SLOT_MISMATCH",
            Self::SourceNotAncestorOfTarget => "SOURCE_NOT_ANCESTOR_OF_TARGET",
            Self::TargetNotAncestorOfHead => "TARGET_NOT_ANCESTOR_OF_HEAD",
            Self::HeadNotDescendantOfFinalized => "HEAD_NOT_DESCENDANT_OF_FINALIZED",
            Self::AttestationTooFarInFuture => "ATTESTATION_TOO_FAR_IN_FUTURE",
            Self::AttestationSlotBeforeHead => "ATTESTATION_SLOT_BEFORE_HEAD",
            Self::ValidatorNotInState => "VALIDATOR_NOT_IN_STATE",
            Self::ValidatorIndexOutOfRange => "VALIDATOR_INDEX_OUT_OF_RANGE",
            Self::JustifiedSlotOutOfRange => "JUSTIFIED_SLOT_OUT_OF_RANGE",
            Self::ZeroHashJustificationRoot => "ZERO_HASH_JUSTIFICATION_ROOT",
            Self::JustificationVotesLengthMismatch => "JUSTIFICATION_VOTES_LENGTH_MISMATCH",
            Self::InvalidSignature => "INVALID_SIGNATURE",
            Self::InvalidBlockProof => "INVALID_BLOCK_PROOF",
            Self::AnchorStateRootMismatch => "ANCHOR_STATE_ROOT_MISMATCH",
            Self::DecodeError => "DECODE_ERROR",
            Self::Unknown(reason) => reason,
        }
    }
}

/// Parse a fixture's `rejectionReason`, keeping an unrecognised one verbatim.
///
/// The catch-all is why a missing arm here cannot pass silently: an unmapped
/// reason becomes [`RejectionReason::Unknown`], which every runner reports as a
/// failure naming the string to add.
impl From<&str> for RejectionReason {
    fn from(reason: &str) -> Self {
        match reason {
            "BLOCK_SLOT_NOT_IN_FUTURE" => Self::BlockSlotNotInFuture,
            "BLOCK_SLOT_GAP_TOO_LARGE" => Self::BlockSlotGapTooLarge,
            "BLOCK_TOO_FAR_IN_FUTURE" => Self::BlockTooFarInFuture,
            "BLOCK_OLDER_THAN_LATEST_HEADER" => Self::BlockOlderThanLatestHeader,
            "BLOCK_SLOT_MISMATCH" => Self::BlockSlotMismatch,
            "PARENT_ROOT_MISMATCH" => Self::ParentRootMismatch,
            "STATE_ROOT_MISMATCH" => Self::StateRootMismatch,
            "UNKNOWN_PARENT_BLOCK" => Self::UnknownParentBlock,
            "PROPOSER_INDEX_OUT_OF_RANGE" => Self::ProposerIndexOutOfRange,
            "EMPTY_VALIDATOR_REGISTRY" => Self::EmptyValidatorRegistry,
            "WRONG_PROPOSER" => Self::WrongProposer,
            "TOO_MANY_ATTESTATION_DATA" => Self::TooManyAttestationData,
            "DUPLICATE_ATTESTATION_DATA" => Self::DuplicateAttestationData,
            "EMPTY_AGGREGATION_BITS" => Self::EmptyAggregationBits,
            "UNKNOWN_SOURCE_BLOCK" => Self::UnknownSourceBlock,
            "UNKNOWN_TARGET_BLOCK" => Self::UnknownTargetBlock,
            "UNKNOWN_HEAD_BLOCK" => Self::UnknownHeadBlock,
            "SOURCE_AFTER_TARGET" => Self::SourceAfterTarget,
            "HEAD_OLDER_THAN_TARGET" => Self::HeadOlderThanTarget,
            "SOURCE_SLOT_MISMATCH" => Self::SourceSlotMismatch,
            "TARGET_SLOT_MISMATCH" => Self::TargetSlotMismatch,
            "HEAD_SLOT_MISMATCH" => Self::HeadSlotMismatch,
            "SOURCE_NOT_ANCESTOR_OF_TARGET" => Self::SourceNotAncestorOfTarget,
            "TARGET_NOT_ANCESTOR_OF_HEAD" => Self::TargetNotAncestorOfHead,
            "HEAD_NOT_DESCENDANT_OF_FINALIZED" => Self::HeadNotDescendantOfFinalized,
            "ATTESTATION_TOO_FAR_IN_FUTURE" => Self::AttestationTooFarInFuture,
            "ATTESTATION_SLOT_BEFORE_HEAD" => Self::AttestationSlotBeforeHead,
            "VALIDATOR_NOT_IN_STATE" => Self::ValidatorNotInState,
            "VALIDATOR_INDEX_OUT_OF_RANGE" => Self::ValidatorIndexOutOfRange,
            "JUSTIFIED_SLOT_OUT_OF_RANGE" => Self::JustifiedSlotOutOfRange,
            "ZERO_HASH_JUSTIFICATION_ROOT" => Self::ZeroHashJustificationRoot,
            "JUSTIFICATION_VOTES_LENGTH_MISMATCH" => Self::JustificationVotesLengthMismatch,
            "INVALID_SIGNATURE" => Self::InvalidSignature,
            "INVALID_BLOCK_PROOF" => Self::InvalidBlockProof,
            "ANCHOR_STATE_ROOT_MISMATCH" => Self::AnchorStateRootMismatch,
            "DECODE_ERROR" => Self::DecodeError,
            other => Self::Unknown(other.to_string()),
        }
    }
}

impl fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RejectionReason {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(String::deserialize(deserializer)?.as_str().into())
    }
}

/// Check a client rejection against the reason its fixture named.
///
/// `context` names the failing case (a test name or step index) and `err` is
/// reported verbatim so a mismatch is debuggable. Returns the message the
/// spec-test runners surface as the test failure.
///
/// Both an unclassified rejection and a reason this build does not know are
/// failures: accepting either would silently restore "any error will do", which
/// is what pinning the reason exists to prevent.
pub fn check_rejection_reason(
    context: &str,
    expected: &RejectionReason,
    actual: Option<&RejectionReason>,
    err: &dyn fmt::Debug,
) -> Result<(), String> {
    if let RejectionReason::Unknown(reason) = expected {
        return Err(format!(
            "{context} expects rejection reason '{reason}', which this build does not know. \
             Add it to `RejectionReason` and classify the error that must produce it."
        ));
    }
    match actual {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(format!(
            "{context} was rejected for the wrong reason: expected {expected}, got {actual} \
             ({err:?})"
        )),
        None => Err(format!(
            "{context} expected rejection reason {expected} but the error carries no reason: \
             {err:?}. Classify it in the runner's `rejection_reason` mapping."
        )),
    }
}

/// Classify a state-transition failure, mirroring leanSpec's
/// `classify_rejection`.
///
/// Total on purpose: the match is exhaustive, so a new
/// [`ethlambda_state_transition::Error`] variant is a compile error here until
/// someone names the reason it corresponds to.
impl From<&ethlambda_state_transition::Error> for RejectionReason {
    fn from(err: &ethlambda_state_transition::Error) -> Self {
        use ethlambda_state_transition::Error;

        match err {
            Error::StateSlotIsNewer { .. } => Self::BlockSlotNotInFuture,
            Error::SlotMismatch { .. } => Self::BlockSlotMismatch,
            Error::ParentSlotIsNewer { .. } => Self::BlockOlderThanLatestHeader,
            Error::InvalidProposer { .. } => Self::WrongProposer,
            Error::InvalidParent { .. } => Self::ParentRootMismatch,
            Error::NoValidators => Self::EmptyValidatorRegistry,
            Error::StateRootMismatch { .. } => Self::StateRootMismatch,
            Error::SlotGapTooLarge { .. } => Self::BlockSlotGapTooLarge,
            Error::ZeroHashInJustificationRoots => Self::ZeroHashJustificationRoot,
            Error::JustificationVotesLengthMismatch { .. } => {
                Self::JustificationVotesLengthMismatch
            }
            Error::EmptyAggregationBits => Self::EmptyAggregationBits,
            // The spec indexes a per-root vote list with each participant index,
            // so a bit set beyond the registry is an out-of-range validator
            // index rather than a malformed bitlist.
            Error::AggregationBitsOutOfBounds { .. } => Self::ValidatorIndexOutOfRange,
            Error::JustifiedSlotOutOfRange { .. } => Self::JustifiedSlotOutOfRange,
            Error::TooManyAttestationData { .. } => Self::TooManyAttestationData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Walk every known reason through both tables. A spelling that appears in
    /// only one of them, or twice in [`RejectionReason::as_str`] (which would
    /// leave one variant unreachable from a fixture), fails here.
    #[test]
    fn every_known_reason_round_trips() {
        let mut spellings = std::collections::HashSet::new();
        for reason in RejectionReason::ALL {
            let spelling = reason.as_str();
            assert_eq!(
                &RejectionReason::from(spelling),
                reason,
                "'{spelling}' does not parse back to {reason:?}"
            );
            assert!(
                spellings.insert(spelling),
                "'{spelling}' is the wire spelling of more than one reason"
            );
        }
    }

    #[test]
    fn known_reasons_round_trip_through_their_wire_spelling() {
        let reason = RejectionReason::from("HEAD_NOT_DESCENDANT_OF_FINALIZED");
        assert_eq!(reason, RejectionReason::HeadNotDescendantOfFinalized);
        assert_eq!(reason.as_str(), "HEAD_NOT_DESCENDANT_OF_FINALIZED");
    }

    #[test]
    fn unknown_reasons_keep_their_string_verbatim() {
        let reason = RejectionReason::from("REASON_FROM_A_NEWER_SPEC");
        assert_eq!(
            reason,
            RejectionReason::Unknown("REASON_FROM_A_NEWER_SPEC".to_string())
        );
        assert_eq!(reason.as_str(), "REASON_FROM_A_NEWER_SPEC");
    }

    #[test]
    fn deserializes_from_a_json_string() {
        let reason: RejectionReason = serde_json::from_str("\"SOURCE_AFTER_TARGET\"").unwrap();
        assert_eq!(reason, RejectionReason::SourceAfterTarget);
    }
}
