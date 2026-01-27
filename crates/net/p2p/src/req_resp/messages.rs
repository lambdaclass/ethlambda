use ethlambda_types::state::Checkpoint;
use ssz_derive::{Decode, Encode};

use crate::messages::blocks_by_root::{BlocksByRootRequest, BlocksByRootResponse};

#[derive(Debug, Clone)]
pub enum Request {
    Status(Status),
    BlocksByRoot(BlocksByRootRequest),
}

#[derive(Debug, Clone)]
pub enum Response {
    Status(Status),
    BlocksByRoot(BlocksByRootResponse),
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct Status {
    pub finalized: Checkpoint,
    pub head: Checkpoint,
}
