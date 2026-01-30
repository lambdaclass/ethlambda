use ethlambda_types::{block::SignedBlockWithAttestation, primitives::H256, state::Checkpoint};
use ssz::Decode as SszDecode;
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

impl BlocksByRootRequest {
    /// Decode from SSZ bytes with backward compatibility.
    ///
    /// Tries to decode as new format (container with `roots` field) first.
    /// Falls back to old format (transparent - direct list of roots) if that fails.
    pub fn from_ssz_bytes_compat(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        // Try new format (container) first
        SszDecode::from_ssz_bytes(bytes).or_else(|_| {
            // Fall back to old format (transparent/direct list)
            SszDecode::from_ssz_bytes(bytes).map(|roots| Self { roots })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::Encode as SszEncode;

    #[test]
    fn test_blocks_by_root_backward_compatibility() {
        // Create some test roots
        let root1 = H256::from_slice(&[1u8; 32]);
        let root2 = H256::from_slice(&[2u8; 32]);
        let roots_list =
            RequestedBlockRoots::new(vec![root1, root2]).expect("Failed to create roots list");

        // Encode as old format (direct list, similar to transparent)
        let old_format_bytes = roots_list.as_ssz_bytes();

        // Encode as new format (container)
        let new_request = BlocksByRootRequest {
            roots: roots_list.clone(),
        };
        let new_format_bytes = new_request.as_ssz_bytes();

        // Both formats should decode successfully
        let decoded_from_old = BlocksByRootRequest::from_ssz_bytes_compat(&old_format_bytes)
            .expect("Failed to decode old format");
        let decoded_from_new = BlocksByRootRequest::from_ssz_bytes_compat(&new_format_bytes)
            .expect("Failed to decode new format");

        // Both should have the same roots
        assert_eq!(decoded_from_old.roots.len(), 2);
        assert_eq!(decoded_from_new.roots.len(), 2);
        assert_eq!(decoded_from_old.roots[0], root1);
        assert_eq!(decoded_from_old.roots[1], root2);
        assert_eq!(decoded_from_new.roots[0], root1);
        assert_eq!(decoded_from_new.roots[1], root2);
    }
}
