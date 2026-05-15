use crate::api::{StorageWriteBatch, Table};
use crate::config::EMPTY_BODY_ROOT;
use ethlambda_types::{
    block::{Block, SignedBlock},
    primitives::H256,
};
use libssz::SszEncode;

/// Encode a LiveChain key (slot, root) to bytes.
/// Layout: slot (8 bytes BE) || root (32 bytes).
/// Big-endian ensures lexicographic ordering matches numeric ordering.
pub fn encode_live_chain_key(slot: u64, root: &H256) -> Vec<u8> {
    let mut result = slot.to_be_bytes().to_vec();
    result.extend_from_slice(&root.0);
    result
}

pub fn decode_live_chain_key(bytes: &[u8]) -> (u64, H256) {
    let slot = u64::from_be_bytes(bytes[..8].try_into().expect("valid slot bytes"));
    let root = H256::from_slice(&bytes[8..]);
    (slot, root)
}

/// Write block header, body, and signatures onto an existing batch.
///
/// Returns the deserialized [`Block`] so callers can access fields
/// without re-deserializing.
pub fn write_signed_block(
    batch: &mut dyn StorageWriteBatch,
    root: &H256,
    signed_block: SignedBlock,
) -> Block {
    let SignedBlock {
        message: block,
        signature,
    } = signed_block;

    let header = block.header();
    let root_bytes = root.to_ssz();

    let header_entries = vec![(root_bytes.clone(), header.to_ssz())];
    batch
        .put_batch(Table::BlockHeaders, header_entries)
        .expect("put block header");

    // Skip storing empty bodies - they can be reconstructed from the header's body_root
    if header.body_root != *EMPTY_BODY_ROOT {
        let body_entries = vec![(root_bytes.clone(), block.body.to_ssz())];
        batch
            .put_batch(Table::BlockBodies, body_entries)
            .expect("put block body");
    }

    let sig_entries = vec![(root_bytes, signature.to_ssz())];
    batch
        .put_batch(Table::BlockSignatures, sig_entries)
        .expect("put block signatures");

    block
}
