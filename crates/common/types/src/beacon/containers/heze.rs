//! Containers heze introduces (EIP-7805, fork-choice enforced inclusion lists).
//!
//! Heze reshapes no container of its own beyond adding these: the only field
//! it adds to an existing one is `inclusion_list_bits` on the execution
//! payload bid, which [`super::gloas::ExecutionPayloadBid`] carries as an
//! `Option` rather than this module redefining the bid and, through it, the
//! block body, the block, and the state that embed it. See that type's doc
//! for how the two shapes are told apart on the wire.

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::{SszBitvector, SszVector};

use super::gloas::Transactions;
use crate::beacon::preset;
use crate::beacon::primitives::{BlsSignature, Root, Slot, ValidatorIndex};

/// A bitfield over the inclusion list committee, one bit per member in
/// committee order.
pub type InclusionListBits = SszBitvector<{ preset::INCLUSION_LIST_COMMITTEE_SIZE }>;

/// The inclusion list committee of a slot: every beacon committee of the slot
/// concatenated in order, cycled to `INCLUSION_LIST_COMMITTEE_SIZE` members.
pub type InclusionListCommittee =
    SszVector<ValidatorIndex, { preset::INCLUSION_LIST_COMMITTEE_SIZE }>;

/// The transactions one inclusion list committee member asks the next
/// payload to include.
///
/// `dependent_root` pins the shuffling the member's committee seat was drawn
/// from, so lists built on different branches are kept apart in the
/// inclusion list store rather than compared against each other.
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
pub struct InclusionList {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub slot: Slot,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub validator_index: ValidatorIndex,
    pub dependent_root: Root,
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex_seq")]
    pub transactions: Transactions,
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
pub struct SignedInclusionList {
    pub message: InclusionList,
    pub signature: BlsSignature,
}
