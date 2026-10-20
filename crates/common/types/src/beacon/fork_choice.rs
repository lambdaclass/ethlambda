//! Fork-choice-adjacent data that is neither a block nor a state.
//!
//! Two kinds share this file. `LatestMessage` and `PowBlock` are SSZ
//! consensus containers moved out of the `beacon::fork_choice` module of
//! `ethlambda-state-transition`, which re-exports both at their old paths so
//! every use site inside it is unchanged. `PayloadStatusEnum` and
//! `PayloadStatusV1` are plain Engine-API-shaped data with no such former
//! home. All four live here rather than there for the same reason: the
//! DB-backed `ethlambda_storage::Store` holds them, and `ethlambda-storage`
//! cannot depend on `ethlambda-state-transition`, which pulls in `blst` and
//! `c-kzg`.

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};

use crate::beacon::primitives::{Epoch, ExecutionBlockHash, Root, Uint256};

/// One validator's most recent attestation: the epoch it targeted, and the
/// block it attested to (the LMD GHOST vote).
///
/// `Copy`, matching the specification's `@dataclass(eq=True, frozen=True)`:
/// there is nothing here worth borrowing rather than copying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatestMessage {
    pub epoch: Epoch,
    pub root: Root,
}

/// The execution chain's own block header, as far as bellatrix's merge
/// transition check needs it: `specs/bellatrix/fork-choice.md`'s `PowBlock`.
///
/// The specification's own `get_pow_block(hash) -> Optional[PowBlock]` is
/// "implementation and context dependent": a real client would ask its
/// execution engine. The fork choice store's own record of these, populated by
/// the fixture suites' `on_merge_block` step, is what stands in for that.
///
/// Defined at the top level here, unlike in its former home: this module has no
/// `Result` alias of its own for the `SszDecode` derive's generated code to
/// collide with, so the nested module that used to shield it is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct PowBlock {
    pub block_hash: Root,
    pub parent_hash: Root,
    /// The total work behind `block_hash`, compared against
    /// [`crate::beacon::config::Config::terminal_total_difficulty`] to decide
    /// whether this is the one PoW block the merge transitioned at.
    pub total_difficulty: Uint256,
}

/// The status an execution client returns for a payload.
///
/// `PayloadStatusV1.status` from the Engine API's `paris.md`. The two aliases
/// `optimistic-sync.md` defines over it are methods rather than a second enum:
/// `INVALIDATED` is `Invalid` or `InvalidBlockHash`, and `NOT_VALIDATED` is
/// `Syncing` or `Accepted`. Naming them here keeps every call site reading the
/// specification's own word for the case it is handling.
///
/// Named with the `Enum` suffix, rather than plain `PayloadStatus`, so it can
/// sit next to [`PayloadStatusV1`] without the two names clashing;
/// `alloy-rpc-types-engine` pairs the same two names for the same reason, so
/// an EL-integration reader already knows which is which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadStatusEnum {
    Valid,
    Invalid,
    Syncing,
    Accepted,
    InvalidBlockHash,
}

impl PayloadStatusEnum {
    /// `optimistic-sync.md`'s `INVALIDATED` alias.
    pub fn is_invalidated(self) -> bool {
        matches!(self, Self::Invalid | Self::InvalidBlockHash)
    }

    /// `optimistic-sync.md`'s `NOT_VALIDATED` alias.
    pub fn is_not_validated(self) -> bool {
        matches!(self, Self::Syncing | Self::Accepted)
    }
}

/// An execution client's full answer about one payload.
///
/// `PayloadStatusV1` from the Engine API's `paris.md`. Held in the store's
/// beacon scratch keyed by execution block hash, the same way [`PowBlock`] is
/// held keyed by its own hash and for the same reason: both stand in for a
/// call to an execution client, and the fork choice fixture format seeds both
/// through a step of its own.
///
/// `validation_error` is kept rather than dropped even though nothing branches
/// on it: it is the only place an execution client explains *why* it rejected
/// a payload, and losing it would make an `INVALID` verdict unattributable in
/// a log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadStatusV1 {
    pub status: PayloadStatusEnum,
    /// The most recent valid block hash on the branch, when the client can
    /// name one. `None` is the specification's `null`.
    pub latest_valid_hash: Option<ExecutionBlockHash>,
    pub validation_error: Option<String>,
}

#[cfg(test)]
mod tests {
    use libssz::{SszDecode as _, SszEncode as _};

    use super::*;

    #[test]
    fn a_pow_block_round_trips_through_ssz() {
        // The store persists these, so the derive has to survive the move out
        // of `ethlambda-state-transition` intact.
        let block = PowBlock {
            block_hash: Root::repeat_byte(1),
            parent_hash: Root::repeat_byte(2),
            total_difficulty: Uint256::from(3u64),
        };
        let bytes = block.to_ssz();
        assert_eq!(
            PowBlock::from_ssz_bytes(&bytes).expect("valid pow block"),
            block
        );
    }

    #[test]
    fn the_two_invalid_statuses_are_the_invalidated_alias() {
        assert!(PayloadStatusEnum::Invalid.is_invalidated());
        assert!(PayloadStatusEnum::InvalidBlockHash.is_invalidated());
        assert!(!PayloadStatusEnum::Valid.is_invalidated());
        assert!(!PayloadStatusEnum::Syncing.is_invalidated());
        assert!(!PayloadStatusEnum::Accepted.is_invalidated());
    }

    #[test]
    fn the_two_pending_statuses_are_the_not_validated_alias() {
        assert!(PayloadStatusEnum::Syncing.is_not_validated());
        assert!(PayloadStatusEnum::Accepted.is_not_validated());
        assert!(!PayloadStatusEnum::Valid.is_not_validated());
        assert!(!PayloadStatusEnum::Invalid.is_not_validated());
        assert!(!PayloadStatusEnum::InvalidBlockHash.is_not_validated());
    }
}
