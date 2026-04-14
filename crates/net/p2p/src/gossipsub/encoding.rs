use crate::req_resp::MAX_PAYLOAD_SIZE;

#[derive(Debug)]
pub enum DecompressError {
    Snap(snap::Error),
    TooLarge { size: usize, max: usize },
}

impl std::fmt::Display for DecompressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Snap(e) => write!(f, "{e}"),
            Self::TooLarge { size, max } => {
                write!(f, "uncompressed size {size} exceeds maximum {max}")
            }
        }
    }
}

impl From<snap::Error> for DecompressError {
    fn from(e: snap::Error) -> Self {
        Self::Snap(e)
    }
}

/// Decompress data using raw snappy format (for gossipsub messages).
/// Rejects payloads whose claimed uncompressed size exceeds MAX_PAYLOAD_SIZE
/// to prevent decompression bomb attacks.
pub fn decompress_message(data: &[u8]) -> Result<Vec<u8>, DecompressError> {
    let uncompressed_size = snap::raw::decompress_len(data)?;
    if uncompressed_size > MAX_PAYLOAD_SIZE {
        return Err(DecompressError::TooLarge {
            size: uncompressed_size,
            max: MAX_PAYLOAD_SIZE,
        });
    }
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
    use ethlambda_types::block::SignedBlock;
    use libssz::SszDecode;

    #[test]
    #[ignore = "devnet3 SSZ fixture — needs devnet4 block (SignedBlock without BlockWithAttestation wrapper)"]
    fn test_decode_block() {
        let block_bytes = include_bytes!("../../test_data/signed_block.ssz");
        let _block = SignedBlock::from_ssz_bytes(block_bytes).unwrap();
    }
}
