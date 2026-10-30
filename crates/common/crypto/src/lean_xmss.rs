//! leanXMSS over Keccak-256, the scheme of EIP-8450's key registry, through the `lean-pq` bindings.
//!
//! It is a different scheme from the lean chain's own XMSS:
//!
//! ```text
//!     hash      Keccak-256 truncated to 16 bytes (lean chain: BLAKE2s)
//!     chains    58, digit sum 106               (lean chain: 42)
//!     trees     two layers of height 16         (lean chain: one of height 32)
//! ```
//!
//! The scheme is the generalized XMSS of Drake, Khovratovich, Kudinov and Wagner.
//! See "Hash-Based Multi-Signatures for Post-Quantum Ethereum", IACR CiC 2(1), 2025.

pub use lean_pq::Error;
pub use lean_pq::xmss::{PublicKey, SIGNATURE_LEN, SecretKey, Signature};

/// Verifies a leanXMSS signature of a 32-byte message under a public key.
///
/// The key and the signature are the scheme's own 32- and 2404-byte encodings.
/// They are also their SSZ encodings in EIP-8450's containers.
/// The leaf index travels inside the signature.
///
/// # Errors
///
/// Fails when an encoding has the wrong length, or when the signature does not verify.
pub fn verify(public_key: &[u8], message: &[u8; 32], signature: &[u8]) -> Result<(), Error> {
    let public_key = PublicKey::from_bytes(public_key)?;
    let signature = Signature::from_bytes(signature)?;
    public_key.verify(message, &signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signature_verifies_only_for_its_own_message() {
        // One key from a fixed seed; signing builds its top tree of 2^16 leaves.
        let key = SecretKey::from_seed([7; 32]);
        let public_key = key.public_key().to_bytes();

        // Leaf 0 signs a message of all 0x11 bytes.
        let message = [0x11; 32];
        let signature = key.sign(&message, 0).unwrap().to_bytes();
        assert_eq!(signature.len(), SIGNATURE_LEN);
        assert!(verify(&public_key, &message, &signature).is_ok());

        // Mutation: one flipped message byte must fail verification.
        let mut other = message;
        other[0] ^= 1;
        assert!(matches!(
            verify(&public_key, &other, &signature),
            Err(Error::XmssVerify { leaf_index: 0, .. })
        ));
    }

    #[test]
    fn a_short_signature_is_refused_before_verification() {
        // 2403 bytes: one short of the fixed encoding.
        let key = SecretKey::from_seed([7; 32]).public_key().to_bytes();
        let short = [0; SIGNATURE_LEN - 1];

        assert!(matches!(
            verify(&key, &[0; 32], &short),
            Err(Error::InvalidLength {
                expected: SIGNATURE_LEN,
                actual: 2403,
                ..
            })
        ));
    }
}
