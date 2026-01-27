/// Decompress data using raw snappy format (for gossipsub messages).
pub fn decompress_message(data: &[u8]) -> snap::Result<Vec<u8>> {
    let uncompressed_size = snap::raw::decompress_len(data)?;
    let mut uncompressed_data = vec![0u8; uncompressed_size];
    snap::raw::Decoder::new().decompress(data, &mut uncompressed_data)?;
    Ok(uncompressed_data)
}

/// Compress data using raw snappy format (for gossipsub messages).
pub fn compress_message(data: &[u8]) -> Vec<u8> {
    let max_compressed_len = snap::raw::max_compress_len(data.len());
    let mut compressed = vec![0u8; max_compressed_len];
    let compressed_len = snap::raw::Encoder::new()
        .compress(data, &mut compressed)
        .expect("snappy compression should not fail");
    compressed.truncate(compressed_len);
    compressed
}

#[cfg(test)]
mod tests {
    use ethlambda_types::block::SignedBlockWithAttestation;
    use ssz::Decode;

    #[test]
    #[ignore = "Test data uses old BlockSignatures field order (proposer_signature, attestation_signatures). Needs regeneration with correct order (attestation_signatures, proposer_signature)."]
    fn test_decode_block() {
        // Sample uncompressed block sent by Zeam (commit b153373806aa49f65aadc47c41b68ead4fab7d6e)
        let block_bytes = include_bytes!("../../test_data/signed_block_with_attestation.ssz");
        let _block = SignedBlockWithAttestation::from_ssz_bytes(block_bytes).unwrap();
    }
}
