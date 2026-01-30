use ethlambda_types::{block::SignedBlockWithAttestation, primitives::H256, state::Checkpoint};
use ssz_derive::{Decode, Encode};
use ssz_types::typenum;

pub const STATUS_PROTOCOL_V1: &str = "/leanconsensus/req/status/1/ssz_snappy";
pub const BLOCKS_BY_ROOT_PROTOCOL_V1: &str = "/leanconsensus/req/blocks_by_root/1/ssz_snappy";

#[derive(Debug, Clone)]
pub enum Request {
    Status(Status),
    BlocksByRoot(BlocksByRootRequest),
}

#[derive(Debug, Clone)]
pub struct Response {
    pub result: ResponseResult,
    pub payload: ResponsePayload,
}

impl Response {
    pub fn new(result: ResponseResult, payload: ResponsePayload) -> Self {
        Self { result, payload }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseResult {
    Success = 0,
    InvalidRequest = 1,
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ResponsePayload {
    Status(Status),

    // TODO: here we assume there's a single block per request
    BlocksByRoot(SignedBlockWithAttestation),
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct Status {
    pub finalized: Checkpoint,
    pub head: Checkpoint,
}

type MaxRequestBlocks = typenum::U1024;

pub type RequestedBlockRoots = ssz_types::VariableList<H256, MaxRequestBlocks>;

#[derive(Debug, Clone, Encode, Decode)]
pub struct BlocksByRootRequest {
    pub roots: RequestedBlockRoots,
}
