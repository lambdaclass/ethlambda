//! Fork-choice-adjacent data that is neither a block nor a state.
//!
//! Four kinds share this file. `LatestMessage` and `PowBlock` are SSZ
//! consensus containers moved out of the `beacon::fork_choice` module of
//! `ethlambda-state-transition`, which re-exports both at their old paths so
//! every use site inside it is unchanged. `PayloadStatusEnum` and
//! `PayloadStatusV1` are plain Engine-API-shaped data with no such former
//! home. `PayloadStatus` and `ForkChoiceNode` are gloas's own fork-choice
//! node types, new here rather than moved, since nothing named them before
//! gloas. `BlockPayloadLink` is not a specification type at all: it is the
//! per-block record the head walk reads instead of decoding the block. All
//! seven live here for the same reason: the DB-backed
//! `ethlambda_storage::Store` holds `LatestMessage`, `PowBlock`,
//! `PayloadStatusV1` and `BlockPayloadLink`, and `ethlambda-storage` cannot
//! depend on `ethlambda-state-transition`, which pulls in `blst` and
//! `c-kzg`; `PayloadStatus` and `ForkChoiceNode` join them here rather than
//! living beside `ethlambda-state-transition`'s own fork choice, so that a
//! `LatestMessage`'s `payload_present` field and a stored node's own
//! `PayloadStatus` share one crate with no dependency to cross.

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};

use crate::beacon::containers::Checkpoint;
use crate::beacon::primitives::{
    Epoch, ExecutionBlockHash, Gwei, Root, Slot, Uint256, ValidatorIndex,
};

/// One validator's most recent attestation: the epoch it targeted, and the
/// block it attested to (the LMD GHOST vote).
///
/// `Copy`, matching the specification's `@dataclass(eq=True, frozen=True)`:
/// there is nothing here worth borrowing rather than copying.
///
/// `epoch` and `slot` both live here rather than one replacing the other:
/// every fork through fulu keeps `epoch`, the field gloas's own modified
/// `LatestMessage` drops in favour of `slot` (gloas compares messages by slot,
/// since a payload can be revealed a slot late and a slot-grained comparison
/// is what lets `update_latest_messages` tell such a re-vote apart from a
/// stale one). Splitting the two into per-fork types would mean every reader
/// of a [`LatestMessage`] picks a variant instead of a field, for a value that
/// is otherwise identical; carrying both instead lets one constructor,
/// `update_latest_messages`, fill in both for every fork (`epoch` from the
/// attestation's target, `slot` from its data), with only the fork's own
/// comparison reading one of them: pre-gloas orders by `epoch`, gloas by
/// `slot`. `payload_present` is the one field a fork leaves neutral
/// (`false` before gloas).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatestMessage {
    pub epoch: Epoch,
    /// The attestation's slot. Gloas compares messages by slot; earlier
    /// forks keep comparing `epoch`.
    pub slot: Slot,
    pub root: Root,
    /// Gloas: whether the vote is for the block's full node (`data.index ==
    /// 1`). Always `false` before gloas, which has no payload dimension to
    /// vote on.
    pub payload_present: bool,
}

/// A fork-choice node's payload dimension (gloas `fork-choice.md`'s new
/// `PayloadStatus`): whether a [`ForkChoiceNode`] stands for a block whose
/// payload is known to be empty, known to be full, or not yet decided either
/// way.
///
/// Ordered `Empty < Full < Pending`, matching the specification's own integer
/// values (`PAYLOAD_STATUS_EMPTY = 0`, `PAYLOAD_STATUS_FULL = 1`,
/// `PAYLOAD_STATUS_PENDING = 2`): nothing in this crate compares two
/// `PayloadStatus` values by order today, but the derive is kept alongside
/// the discriminants it agrees with rather than left for a future caller to
/// get wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PayloadStatus {
    Empty = 0,
    Full = 1,
    Pending = 2,
}

/// What fork choice needs to know about a block's payload dimension, recorded
/// when the block is imported so that walking the tree never decodes a block
/// to learn it.
///
/// Two facts, both read off a block's own bytes and both fixed for the life of
/// the block: which rules it is handled under, and which of its parent's
/// payload branches it builds on (`get_parent_payload_status`). Neither
/// changes after import, so the record is a cache that is correct whenever it
/// is present and can be rederived by decoding the block when it is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockPayloadLink {
    /// A pre-gloas block: a single FULL node whose payload ran inside the
    /// block itself. It builds on its parent's FULL branch, the
    /// fulu-to-gloas boundary rule.
    PreGloas,
    /// A gloas block.
    Gloas {
        /// The parent payload branch the block builds on, `None` when the
        /// store does not hold the parent (a gloas anchor, whose parent is
        /// below the retained window, so there is no bid to compare against).
        ///
        /// `Some(Full)` for a block whose parent is pre-gloas, by the same
        /// boundary rule.
        parent_status: Option<PayloadStatus>,
    },
}

impl BlockPayloadLink {
    /// Whether the block is a gloas block.
    pub fn is_gloas(self) -> bool {
        match self {
            BlockPayloadLink::PreGloas => false,
            BlockPayloadLink::Gloas { .. } => true,
        }
    }

    /// The parent payload branch the block builds on, `None` when unknown.
    pub fn parent_status(self) -> Option<PayloadStatus> {
        match self {
            BlockPayloadLink::PreGloas => Some(PayloadStatus::Full),
            BlockPayloadLink::Gloas { parent_status } => parent_status,
        }
    }
}

/// A gloas fork-choice node (`fork-choice.md`'s modified `ForkChoiceNode`): a
/// block, and which of its payload branches.
///
/// Every earlier fork's own `ForkChoiceNode` is a one-to-one mapping with a
/// `BeaconBlock` (see `specs/phase0/fork-choice.md`'s own note), so this
/// crate collapses it to a bare [`Root`] wherever a pre-gloas function reads
/// one; only gloas needs the pair, since ePBS (EIP-7732) splits a block into
/// two branches fork choice must weigh separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ForkChoiceNode {
    pub root: Root,
    pub payload_status: PayloadStatus,
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

/// The justified checkpoint state's balances, flattened for the fork-choice
/// vote loop: `store.checkpoint_states[checkpoint]` as `get_weight` and
/// `get_proposer_score` read it.
///
/// A tree descent per vote (`state.validator(i)`) is an order of magnitude
/// dearer than an array read, and the loop runs once per `get_head` over every
/// voter. This is built once per justified checkpoint and keyed by it, so a
/// reader compares [`Self::checkpoint`] with the store's current one and
/// rebuilds on a mismatch, with no hook on the code that moves the checkpoint.
///
/// Held in the store, hence here rather than in `ethlambda-state-transition`;
/// the builder lives there, next to the state accessors.
#[derive(Debug, PartialEq, Eq)]
pub struct JustifiedBalances {
    checkpoint: Checkpoint,
    /// Zero unless the validator is active at `checkpoint.epoch` and unslashed,
    /// the two conditions under which a vote weighs anything.
    balances: Box<[Gwei]>,
    /// `get_total_active_balance` of the checkpoint state: unlike `balances`
    /// it counts slashed validators, and it is floored at one increment.
    total_active_balance: Gwei,
}

impl JustifiedBalances {
    /// Wraps already-computed values; see the field docs for what they mean.
    pub fn new(checkpoint: Checkpoint, balances: Box<[Gwei]>, total_active_balance: Gwei) -> Self {
        Self {
            checkpoint,
            balances,
            total_active_balance,
        }
    }

    /// The checkpoint these balances were derived from.
    pub fn checkpoint(&self) -> Checkpoint {
        self.checkpoint
    }

    /// The weight of `index`'s vote: zero when inactive or slashed, and also
    /// past the end, since that validator did not exist at the checkpoint.
    pub fn get(&self, index: ValidatorIndex) -> Gwei {
        usize::try_from(index)
            .ok()
            .and_then(|index| self.balances.get(index))
            .copied()
            .unwrap_or_default()
    }

    /// The checkpoint state's total active balance, as the specification's
    /// `get_total_active_balance` defines it.
    pub fn total_active_balance(&self) -> Gwei {
        self.total_active_balance
    }
}

#[cfg(test)]
mod tests {
    use libssz::{SszDecode as _, SszEncode as _};

    use super::*;

    #[test]
    fn justified_balances_read_zero_past_the_registry() {
        let balances = JustifiedBalances::new(Checkpoint::default(), vec![7, 0, 9].into(), 16);
        assert_eq!(balances.get(0), 7);
        assert_eq!(balances.get(1), 0);
        assert_eq!(balances.get(2), 9);
        assert_eq!(balances.get(3), 0);
        assert_eq!(balances.get(u64::MAX), 0);
        assert_eq!(balances.total_active_balance(), 16);
    }

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
