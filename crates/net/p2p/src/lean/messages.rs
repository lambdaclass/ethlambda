//! The containers this chain's request/response protocols carry.
//!
//! The counterpart of [`crate::beacon::messages`]. Only the bodies live here;
//! the [`crate::req_resp::Request`] and [`crate::req_resp::ResponsePayload`]
//! variants that carry them are shared with beacon, because a message is
//! dispatched the same way whichever chain it came from.

use ethlambda_types::{checkpoint::Checkpoint, primitives::H256};
use libssz_derive::{SszDecode, SszEncode};
use libssz_types::SszList;

/// What each side of a connection tells the other about its chain.
///
/// Two checkpoints, where beacon's `Status` carries a fork digest and a
/// head/finalized pair of its own: the two protocols share a name and nothing
/// else, which is why [`crate::req_resp::Request`] prefixes this one.
#[derive(Debug, Clone, SszEncode, SszDecode)]
pub struct Status {
    pub finalized: Checkpoint,
    pub head: Checkpoint,
}

pub type RequestedBlockRoots = SszList<H256, 1024>;

#[derive(Debug, Clone, SszEncode, SszDecode)]
pub struct BlocksByRootRequest {
    pub roots: RequestedBlockRoots,
}

/// `blocks_by_range/1`'s body **as it goes on this chain's wire**.
///
/// Two fields where beacon's body has three: this chain has no deprecated
/// `step`. The shared
/// [`BlocksByRangeRequest`](crate::req_resp::messages::BlocksByRangeRequest)
/// that [`crate::req_resp::Request`] carries has one, so `crate::lean::encoding`
/// converts, filling it with 1 on the way in and dropping it on the way out.
///
/// `BlocksByRootRequest` needs no such counterpart: its body is the same list
/// either chain asks for, and only beacon's lack of a container around it
/// differs, which beacon's encoder handles.
#[derive(Debug, Clone, SszEncode, SszDecode)]
pub struct LeanBlocksByRangeRequest {
    pub start_slot: u64,
    pub count: u64,
}
