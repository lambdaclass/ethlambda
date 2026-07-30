//! Language-neutral rejection reasons carried by negative leanSpec fixtures.
//!
//! Fixtures that expect their input to be rejected name *why* in a
//! `rejectionReason` field. Asserting only that the client failed lets a test
//! pass for the wrong reason (a state-root mismatch standing in for the rule the
//! fixture meant to exercise), so the spec-test runners compare the reason the
//! client's error maps to against the reason the fixture names.

use serde::{Deserialize, Deserializer};
use std::fmt;

/// Declare the reason vocabulary once and derive the enum plus its wire
/// spellings from a single table, so the mirror of leanSpec's `RejectionReason`
/// cannot drift between the type and the strings it parses.
macro_rules! rejection_reasons {
    (
        $(
            $(#[doc = $doc:literal])*
            $variant:ident => $wire:literal,
        )*
    ) => {
        /// Language-neutral reason the spec rejects an invalid input.
        ///
        /// Mirrors leanSpec's `RejectionReason` StrEnum
        /// (`src/lean_spec/spec/forks/lstar/errors.py`), which is the vocabulary
        /// fixtures use for their `rejectionReason` field. Clients match on the
        /// reason code, never on a human-readable message.
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum RejectionReason {
            $(
                $(#[doc = $doc])*
                $variant,
            )*
            /// A reason string this build does not know.
            ///
            /// Fixtures track leanSpec's latest release, so a new reason can
            /// arrive before the mapping below learns it. Deserialization keeps
            /// it verbatim (the Hive test driver must still answer such a step
            /// rather than reject the request) and the offline runners fail on
            /// it, naming the string to add here.
            Unknown(String),
        }

        impl RejectionReason {
            /// The wire spelling fixtures use for this reason.
            pub fn as_str(&self) -> &str {
                match self {
                    $( Self::$variant => $wire, )*
                    Self::Unknown(reason) => reason,
                }
            }
        }

        impl From<&str> for RejectionReason {
            fn from(reason: &str) -> Self {
                match reason {
                    $( $wire => Self::$variant, )*
                    other => Self::Unknown(other.to_string()),
                }
            }
        }
    };
}

rejection_reasons! {
    // Block validation
    /// The block slot is not strictly greater than the current state slot.
    BlockSlotNotInFuture => "BLOCK_SLOT_NOT_IN_FUTURE",
    /// The block slot runs so far beyond its parent it would force an unbounded
    /// empty-slot walk.
    BlockSlotGapTooLarge => "BLOCK_SLOT_GAP_TOO_LARGE",
    /// The block slot is beyond the store's accepted future horizon.
    BlockTooFarInFuture => "BLOCK_TOO_FAR_IN_FUTURE",
    /// The block slot is not newer than the latest block header.
    BlockOlderThanLatestHeader => "BLOCK_OLDER_THAN_LATEST_HEADER",
    /// The block slot disagrees with the state slot after slot processing.
    BlockSlotMismatch => "BLOCK_SLOT_MISMATCH",
    /// The block parent root disagrees with the latest block header root.
    ParentRootMismatch => "PARENT_ROOT_MISMATCH",
    /// The block state root disagrees with the computed post-state root.
    StateRootMismatch => "STATE_ROOT_MISMATCH",
    /// The block references a parent the store has never seen.
    UnknownParentBlock => "UNKNOWN_PARENT_BLOCK",
    /// The proposer index does not address any registered validator.
    ProposerIndexOutOfRange => "PROPOSER_INDEX_OUT_OF_RANGE",
    /// The registry holds no validators, so no proposer can be scheduled.
    EmptyValidatorRegistry => "EMPTY_VALIDATOR_REGISTRY",
    /// The block proposer is not the scheduled proposer for its slot.
    WrongProposer => "WRONG_PROPOSER",
    /// The block carries more distinct attestation data entries than allowed.
    TooManyAttestationData => "TOO_MANY_ATTESTATION_DATA",
    /// The block carries the same attestation data entry more than once.
    DuplicateAttestationData => "DUPLICATE_ATTESTATION_DATA",
    /// An aggregated attestation references no validator at all.
    EmptyAggregationBits => "EMPTY_AGGREGATION_BITS",

    // Attestation validation
    /// The attestation source root is not a known block.
    UnknownSourceBlock => "UNKNOWN_SOURCE_BLOCK",
    /// The attestation target root is not a known block.
    UnknownTargetBlock => "UNKNOWN_TARGET_BLOCK",
    /// The attestation head root is not a known block.
    UnknownHeadBlock => "UNKNOWN_HEAD_BLOCK",
    /// The attestation source checkpoint slot exceeds its target slot.
    SourceAfterTarget => "SOURCE_AFTER_TARGET",
    /// The attestation head checkpoint is older than its target.
    HeadOlderThanTarget => "HEAD_OLDER_THAN_TARGET",
    /// The source checkpoint slot disagrees with the referenced block.
    SourceSlotMismatch => "SOURCE_SLOT_MISMATCH",
    /// The target checkpoint slot disagrees with the referenced block.
    TargetSlotMismatch => "TARGET_SLOT_MISMATCH",
    /// The head checkpoint slot disagrees with the referenced block.
    HeadSlotMismatch => "HEAD_SLOT_MISMATCH",
    /// The attestation source checkpoint is not an ancestor of its target.
    SourceNotAncestorOfTarget => "SOURCE_NOT_ANCESTOR_OF_TARGET",
    /// The attestation target checkpoint is not an ancestor of its head.
    TargetNotAncestorOfHead => "TARGET_NOT_ANCESTOR_OF_HEAD",
    /// The attestation head checkpoint does not descend from the finalized block.
    HeadNotDescendantOfFinalized => "HEAD_NOT_DESCENDANT_OF_FINALIZED",
    /// The attestation slot is beyond the store's acceptance horizon.
    AttestationTooFarInFuture => "ATTESTATION_TOO_FAR_IN_FUTURE",
    /// The attestation slot precedes its head block's slot.
    AttestationSlotBeforeHead => "ATTESTATION_SLOT_BEFORE_HEAD",
    /// The referenced validator does not exist in the state registry.
    ValidatorNotInState => "VALIDATOR_NOT_IN_STATE",
    /// The validator index does not address any registered validator.
    ValidatorIndexOutOfRange => "VALIDATOR_INDEX_OUT_OF_RANGE",
    /// A justification query named a slot beyond the tracked window.
    JustifiedSlotOutOfRange => "JUSTIFIED_SLOT_OUT_OF_RANGE",
    /// A tracked justification root is the zero hash, which is not a valid root.
    ZeroHashJustificationRoot => "ZERO_HASH_JUSTIFICATION_ROOT",
    /// The flat vote list length is not the tracked-root count times the
    /// validator count.
    JustificationVotesLengthMismatch => "JUSTIFICATION_VOTES_LENGTH_MISMATCH",

    // Cryptographic verification
    /// An attestation signature or aggregate proof fails verification.
    InvalidSignature => "INVALID_SIGNATURE",
    /// The block's multi-message aggregate proof fails verification.
    InvalidBlockProof => "INVALID_BLOCK_PROOF",

    // Anchor initialization
    /// The anchor block state root disagrees with the anchor state.
    AnchorStateRootMismatch => "ANCHOR_STATE_ROOT_MISMATCH",

    // Wire decoding
    /// The input bytes cannot be decoded into the expected structure.
    DecodeError => "DECODE_ERROR",
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
