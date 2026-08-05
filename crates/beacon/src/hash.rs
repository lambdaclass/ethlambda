//! SHA-256, the specification's `hash` function.

use sha2::{Digest, Sha256};

use crate::primitives::{Bytes32, H256};

/// The specification's `hash(data)`.
pub fn hash(data: &[u8]) -> Bytes32 {
    H256(Sha256::digest(data).into())
}

/// Hashes the concatenation of two byte strings.
///
/// The specification writes this as `hash(a + b)`, which appears in seed
/// derivation, the shuffling, and merkle proof verification.
pub fn hash_concat(a: &[u8], b: &[u8]) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(b);
    H256(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_known_digest() {
        // The SHA-256 of the empty string.
        assert_eq!(
            hex::encode(hash(&[]).0),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn concat_matches_hashing_the_joined_bytes() {
        assert_eq!(hash_concat(b"ab", b"cd"), hash(b"abcd"));
    }
}
