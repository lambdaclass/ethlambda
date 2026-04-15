use std::ops::Range;

use leansig::{
    serialization::Serializable,
    signature::{SignatureScheme, SignatureSchemeSecretKey as _, SigningError},
};

use crate::primitives::H256;

/// The XMSS signature scheme used for validator signatures.
///
/// This is a post-quantum secure signature scheme based on hash functions.
/// Uses Poseidon1 hashing with an aborting hypercube message hash,
/// 32-bit lifetime (2^32 signatures per key), dimension 46, and base 8.
pub type LeanSignatureScheme = leansig::signature::generalized_xmss::instantiations_aborting::lifetime_2_to_the_32::SchemeAbortingTargetSumLifetime32Dim46Base8;

/// The public key type from the leansig library.
pub type LeanSigPublicKey = <LeanSignatureScheme as SignatureScheme>::PublicKey;

/// The signature type from the leansig library.
pub type LeanSigSignature = <LeanSignatureScheme as SignatureScheme>::Signature;

/// The secret key type from the leansig library.
pub type LeanSigSecretKey = <LeanSignatureScheme as SignatureScheme>::SecretKey;

pub type Signature = LeanSigSignature;

/// Size of an XMSS signature in bytes.
///
/// Computed from: path(32*8*4) + rho(7*4) + hashes(46*8*4) + ssz_offsets(3*4) = 2536
pub const SIGNATURE_SIZE: usize = 2536;

/// Error returned when parsing signature or key bytes fails.
#[derive(Debug, Clone, thiserror::Error)]
#[error("signature parse error: {0}")]
pub struct SignatureParseError(pub String);

#[derive(Clone)]
pub struct ValidatorSignature {
    inner: LeanSigSignature,
}

impl ValidatorSignature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureParseError> {
        let sig = LeanSigSignature::from_bytes(bytes)
            .map_err(|e| SignatureParseError(format!("{e:?}")))?;
        Ok(Self { inner: sig })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }

    pub fn is_valid(&self, pubkey: &ValidatorPublicKey, slot: u32, message: &H256) -> bool {
        LeanSignatureScheme::verify(&pubkey.inner, slot, &message.0, &self.inner)
    }

    pub fn into_inner(self) -> LeanSigSignature {
        self.inner
    }
}

#[derive(Clone)]
pub struct ValidatorPublicKey {
    inner: LeanSigPublicKey,
}

impl ValidatorPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureParseError> {
        let pk = LeanSigPublicKey::from_bytes(bytes)
            .map_err(|e| SignatureParseError(format!("{e:?}")))?;
        Ok(Self { inner: pk })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }

    pub fn into_inner(self) -> LeanSigPublicKey {
        self.inner
    }
}

/// Validator private key for signing attestations and blocks.
pub struct ValidatorSecretKey {
    inner: LeanSigSecretKey,
}

impl ValidatorSecretKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureParseError> {
        let sk = LeanSigSecretKey::from_bytes(bytes)
            .map_err(|e| SignatureParseError(format!("{e:?}")))?;
        Ok(Self { inner: sk })
    }

    /// Sign a message with this private key.
    ///
    /// The slot is used as part of the XMSS signature scheme to track
    /// one-time signature usage.
    pub fn sign(&self, slot: u32, message: &H256) -> Result<ValidatorSignature, SigningError> {
        let sig = LeanSignatureScheme::sign(&self.inner, slot, &message.0)?;
        Ok(ValidatorSignature { inner: sig })
    }

    /// Returns true if the key is prepared to sign at the given slot.
    ///
    /// XMSS keys maintain a sliding window of two bottom trees. Only slots
    /// within this window can be signed without advancing the preparation.
    pub fn is_prepared_for(&self, slot: u32) -> bool {
        self.inner.get_prepared_interval().contains(&(slot as u64))
    }

    /// Returns the slot range currently covered by the prepared window.
    pub fn get_prepared_interval(&self) -> Range<u64> {
        self.inner.get_prepared_interval()
    }

    /// Advance the prepared window forward by one bottom tree.
    ///
    /// Each call slides the window by sqrt(LIFETIME) = 65,536 slots.
    /// If the window is already at the end of the key's activation interval,
    /// this is a no-op.
    pub fn advance_preparation(&mut self) {
        self.inner.advance_preparation();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use leansig::serialization::Serializable;
    use rand::{SeedableRng, rngs::StdRng};

    const LEAVES_PER_BOTTOM_TREE: u32 = 1 << 16; // 65,536

    /// Generate a ValidatorSecretKey with 3 bottom trees so advance_preparation can be tested.
    ///
    /// This is slow (~minutes) because it computes 3 bottom trees of 65,536 leaves each.
    fn generate_key_with_three_bottom_trees() -> ValidatorSecretKey {
        let mut rng = StdRng::seed_from_u64(42);
        // Request enough active epochs for 3 bottom trees (> 2 * 65,536)
        let num_active_epochs = (LEAVES_PER_BOTTOM_TREE as usize) * 2 + 1;
        let (_pk, sk) = LeanSignatureScheme::key_gen(&mut rng, 0, num_active_epochs);
        let sk_bytes = sk.to_bytes();
        ValidatorSecretKey::from_bytes(&sk_bytes).expect("valid secret key")
    }

    #[test]
    #[ignore = "slow: generates production-size XMSS key (~minutes)"]
    fn test_advance_preparation_duration() {
        println!("Generating XMSS key with 3 bottom trees (this takes a while)...");
        let keygen_start = std::time::Instant::now();
        let mut sk = generate_key_with_three_bottom_trees();
        println!("Key generation took: {:?}", keygen_start.elapsed());

        // Initial window covers [0, 131072)
        assert!(sk.is_prepared_for(0));
        assert!(sk.is_prepared_for(LEAVES_PER_BOTTOM_TREE - 1));
        assert!(sk.is_prepared_for(2 * LEAVES_PER_BOTTOM_TREE - 1));
        assert!(!sk.is_prepared_for(2 * LEAVES_PER_BOTTOM_TREE));

        // Time the advance_preparation call
        let advance_start = std::time::Instant::now();
        sk.advance_preparation();
        let advance_duration = advance_start.elapsed();

        println!("advance_preparation() took: {advance_duration:?}");

        // Window should now cover [65536, 196608)
        assert!(!sk.is_prepared_for(0));
        assert!(sk.is_prepared_for(LEAVES_PER_BOTTOM_TREE));
        assert!(sk.is_prepared_for(3 * LEAVES_PER_BOTTOM_TREE - 1));

        // Verify signing works in the new window
        let message = H256::from([42u8; 32]);
        let slot = 2 * LEAVES_PER_BOTTOM_TREE; // slot 131,072 — the one that crashed the devnet
        let sign_start = std::time::Instant::now();
        let result = sk.sign(slot, &message);
        println!("Signing at slot {slot} took: {:?}", sign_start.elapsed());
        assert!(
            result.is_ok(),
            "signing should succeed after advance: {}",
            result.err().map_or(String::new(), |e| e.to_string())
        );
    }
}
