pub mod status;

pub const MAX_PAYLOAD_SIZE: usize = 10 * 1024 * 1024; // 10 MB

// https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/p2p-interface.md#max_message_size
pub const MAX_COMPRESSED_PAYLOAD_SIZE: usize = 32 + MAX_PAYLOAD_SIZE + MAX_PAYLOAD_SIZE / 6 + 1024; // ~12 MB
