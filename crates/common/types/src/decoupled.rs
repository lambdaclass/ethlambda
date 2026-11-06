//! Decoupled consensus (EIP-8453) payloads shared by the engine and the lean
//! chain.
//!
//! The objects of EIP-8453's finality gadget (FG) and available chain (AC), as
//! specified on consensus-specs branch `decoupled-consensus` at
//! `0f4fa3ffdd26ec083ff4dba65645d81433178413` (`specs/_features/eip8453/`).
//! The protocol logic lives in `ethlambda-decoupled`; the unsigned objects live
//! here so the lean wire containers (`crate::lean_decoupled`), which this crate
//! defines, can embed them. A beacon host builds the same values from its own
//! containers (`HeightCheckpoint` and `HeadVoteData` have the same fields).

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use serde::{Deserialize, Serialize};

use crate::primitives::H256;

pub type Slot = u64;
pub type Round = u64;
pub type Height = u64;
pub type ValidatorIndex = u64;

/// A fork-choice node's payload dimension (gloas `PayloadStatus`): whether a
/// [`ForkChoiceNode`] stands for a block whose payload is known empty, known
/// full, or not yet decided.
///
/// The discriminants are the specification's (`PAYLOAD_STATUS_EMPTY = 0`,
/// `PAYLOAD_STATUS_FULL = 1`, `PAYLOAD_STATUS_PENDING = 2`), and
/// `get_payload_status_tiebreaker` compares them as integers.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum PayloadStatus {
    Empty = 0,
    Full = 1,
    #[default]
    Pending = 2,
}

impl From<PayloadStatus> for u8 {
    fn from(status: PayloadStatus) -> Self {
        status as u8
    }
}

impl TryFrom<u8> for PayloadStatus {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Empty),
            1 => Ok(Self::Full),
            2 => Ok(Self::Pending),
            other => Err(other),
        }
    }
}

/// A block and one of its payload branches (gloas `ForkChoiceNode`).
///
/// A host without execution payloads (lean) has a `Pending` and an `Empty`
/// node per block and never a `Full` one.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default,
)]
pub struct ForkChoiceNode {
    pub root: H256,
    pub payload_status: PayloadStatus,
}

impl ForkChoiceNode {
    pub fn pending(root: H256) -> Self {
        Self {
            root,
            payload_status: PayloadStatus::Pending,
        }
    }

    pub fn empty(root: H256) -> Self {
        Self {
            root,
            payload_status: PayloadStatus::Empty,
        }
    }

    pub fn full(root: H256) -> Self {
        Self {
            root,
            payload_status: PayloadStatus::Full,
        }
    }
}

/// `HeightCheckpoint` (beacon-chain.md): a height of the finality gadget and
/// its target block.
///
/// [`HeightCheckpoint::empty`] stands for an absent finality pair.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct HeightCheckpoint {
    pub height: Height,
    pub root: H256,
}

impl HeightCheckpoint {
    pub fn new(height: Height, root: H256) -> Self {
        Self { height, root }
    }

    /// `HeightCheckpoint.empty()`.
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        *self == Self::empty()
    }
}

/// `AttestationData` (beacon-chain.md, modified): the height pair is
/// `(target, timeout)`, a target vote when `timeout` is false and a timeout
/// when it is true; the finality pair is `finality`, the empty checkpoint when
/// absent.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct AttestationData {
    pub target: HeightCheckpoint,
    pub timeout: bool,
    pub finality: HeightCheckpoint,
}

/// `HeadVoteData` (beacon-chain.md): a head vote of `slot` for a block and one
/// of its payload branches.
///
/// `payload_status` is the wire byte; [`HeadVoteData::payload_status`] reads it,
/// `None` for a value outside the three statuses (which
/// `is_valid_head_vote_message` refuses). The spec names the block field
/// `beacon_block_root`; on lean it is the decoupled block's root.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct HeadVoteData {
    pub slot: Slot,
    pub block_root: H256,
    pub payload_status: u8,
}

impl HeadVoteData {
    pub fn new(slot: Slot, node: ForkChoiceNode) -> Self {
        Self {
            slot,
            block_root: node.root,
            payload_status: node.payload_status.into(),
        }
    }

    pub fn payload_status(&self) -> Option<PayloadStatus> {
        PayloadStatus::try_from(self.payload_status).ok()
    }

    /// The node the vote supports, when its status byte is valid.
    pub fn supported_node(&self) -> Option<ForkChoiceNode> {
        Some(ForkChoiceNode {
            root: self.block_root,
            payload_status: self.payload_status()?,
        })
    }
}

/// `HeadVoteMessage` without its signature: what one committee member says.
/// Each chain wraps it in its own signed envelope.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct HeadVoteMessage {
    pub validator_index: ValidatorIndex,
    pub data: HeadVoteData,
}

/// A block identified by root and slot, for status reports.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct BlockRef {
    pub root: H256,
    pub slot: Slot,
}

/// A node's view of the available chain and the finality gadget, for
/// operators and tests: what `GET /lean/v0/decoupled/status` serves.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecoupledStatus {
    /// The node's protocol clock.
    pub slot: Slot,
    pub round: Round,
    /// `get_head(store)`.
    pub head: BlockRef,
    pub head_payload_status: PayloadStatus,
    /// `get_confirmed_node(store)`: the confirmed tip an execution layer
    /// would read as its safe block.
    pub confirmed: BlockRef,
    /// `store.latest_confirmed`.
    pub latest_confirmed: BlockRef,
    /// `store.finalized_checkpoint` and its block's slot.
    pub finalized: HeightCheckpoint,
    pub finalized_slot: Slot,
    /// `store.justified_checkpoint` and its block's slot.
    pub justified: HeightCheckpoint,
    pub justified_slot: Slot,
    /// `store.max_height`.
    pub max_height: Height,
    /// `is_fg_contest(store)`.
    pub fg_contest: bool,
    /// Live AC locks.
    pub live_locks: u64,
    /// Blocks in the processed tree.
    pub blocks: u64,
}

/// The latest [`DecoupledStatus`], written by a chain actor and read by the
/// HTTP server. `None` until the actor's first tick.
pub type SharedDecoupledStatus = std::sync::Arc<std::sync::RwLock<Option<DecoupledStatus>>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::HashTreeRoot as _;
    use libssz::{SszDecode as _, SszEncode as _};

    #[test]
    fn payload_status_round_trips_through_its_byte() {
        for status in [
            PayloadStatus::Empty,
            PayloadStatus::Full,
            PayloadStatus::Pending,
        ] {
            assert_eq!(PayloadStatus::try_from(u8::from(status)), Ok(status));
        }
        assert_eq!(PayloadStatus::try_from(3), Err(3));
    }

    #[test]
    fn attestation_data_encodes_as_three_fields() {
        let data = AttestationData {
            target: HeightCheckpoint::new(3, H256([1; 32])),
            timeout: true,
            finality: HeightCheckpoint::empty(),
        };
        let bytes = data.to_ssz();
        // Two checkpoints of 8 + 32 bytes and one boolean byte.
        assert_eq!(bytes.len(), 2 * 40 + 1);
        assert_eq!(AttestationData::from_ssz_bytes(&bytes).unwrap(), data);
        assert_ne!(
            data.hash_tree_root(),
            AttestationData::default().hash_tree_root()
        );
    }
}
