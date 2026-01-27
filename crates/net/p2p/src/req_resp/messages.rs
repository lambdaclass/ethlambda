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
    result: ResponseResult,
    payload: ResponsePayload,
}

impl Response {
    pub fn new(result: ResponseResult, payload: ResponsePayload) -> Self {
        Self { result, payload }
    }

    pub fn result(&self) -> ResponseResult {
        self.result
    }

    pub fn payload(&self) -> &ResponsePayload {
        &self.payload
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseResult {
    Success = 0,
    InvalidRequest = 1,
}

#[derive(Debug, Clone)]
pub enum ResponsePayload {
    Status(Status),
    BlocksByRoot(BlocksByRootResponse),
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct Status {
    pub finalized: Checkpoint,
    pub head: Checkpoint,
}

type MaxRequestBlocks = typenum::U1024;

pub type BlocksByRootRequest = ssz_types::VariableList<H256, MaxRequestBlocks>;
pub type BlocksByRootResponse =
    ssz_types::VariableList<SignedBlockWithAttestation, MaxRequestBlocks>;
