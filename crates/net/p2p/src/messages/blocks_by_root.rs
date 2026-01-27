use ethlambda_types::{block::SignedBlockWithAttestation, primitives::H256};
use ssz_types::typenum;

pub const BLOCKS_BY_ROOT_PROTOCOL_V1: &str = "/leanconsensus/req/blocks_by_root/1/ssz_snappy";

#[allow(dead_code)]
const MAX_REQUEST_BLOCKS: usize = 1024;
type MaxRequestBlocks = typenum::U1024;

pub type BlocksByRootRequest = ssz_types::VariableList<H256, MaxRequestBlocks>;
pub type BlocksByRootResponse =
    ssz_types::VariableList<SignedBlockWithAttestation, MaxRequestBlocks>;
