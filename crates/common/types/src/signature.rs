use std::ops::Range;

use ssz::{Decode, Encode};
use xmss::{
    PUB_KEY_SSZ_LEN, SIGNATURE_SSZ_LEN, XmssPublicKey, XmssSecretKey, XmssSignature,
    XmssSignatureError, xmss_sign, xmss_verify,
};

use crate::primitives::H256;

/// The public key type from leanVM's xmss crate.
pub type LeanSigPublicKey = XmssPublicKey;

/// The signature type from leanVM's xmss crate.
pub type LeanSigSignature = XmssSignature;

/// The secret key type from leanVM's xmss crate.
pub type LeanSigSecretKey = XmssSecretKey;

pub type Signature = LeanSigSignature;

/// Size of an SSZ-encoded XMSS signature in bytes.
///
/// Sourced from leanVM's xmss crate rather than hardcoded, so it tracks the
/// scheme parameters (`WOTS_SIG_SIZE_FE`, `LOG_LIFETIME`, `XMSS_DIGEST_LEN`).
pub const SIGNATURE_SIZE: usize = SIGNATURE_SSZ_LEN;

/// Size of an SSZ-encoded XMSS public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = PUB_KEY_SSZ_LEN;

/// Error returned when parsing signature or key bytes fails.
#[derive(Debug, Clone, thiserror::Error)]
#[error("signature parse error: {0}")]
pub struct SignatureParseError(pub String);

#[derive(Clone)]
pub struct ValidatorSignature {
    inner: LeanSigSignature,
}

impl ValidatorSignature {
    /// Parse from the SSZ-encoded wire form (`SIGNATURE_SIZE` bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureParseError> {
        let sig = LeanSigSignature::from_ssz_bytes(bytes)
            .map_err(|e| SignatureParseError(format!("{e:?}")))?;
        Ok(Self { inner: sig })
    }

    /// Encode to the SSZ wire form (`SIGNATURE_SIZE` bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.as_ssz_bytes()
    }

    pub fn is_valid(&self, pubkey: &ValidatorPublicKey, slot: u32, message: &H256) -> bool {
        xmss_verify(&pubkey.inner, slot, &message.0, &self.inner).is_ok()
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
    /// Parse from the SSZ-encoded wire form (`PUBLIC_KEY_SIZE` bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureParseError> {
        let pk = LeanSigPublicKey::from_ssz_bytes(bytes)
            .map_err(|e| SignatureParseError(format!("{e:?}")))?;
        Ok(Self { inner: pk })
    }

    /// Encode to the SSZ wire form (`PUBLIC_KEY_SIZE` bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.as_ssz_bytes()
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
    /// Parse from the postcard-encoded key file produced by the genesis generator.
    ///
    /// leanVM's `XmssSecretKey` uses serde (postcard) rather than the SSZ-style
    /// `Serializable` of the old leanSig scheme.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureParseError> {
        let sk = postcard::from_bytes::<LeanSigSecretKey>(bytes)
            .map_err(|e| SignatureParseError(format!("{e:?}")))?;
        Ok(Self { inner: sk })
    }

    /// Serialize the secret key to its postcard key-file form.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SignatureParseError> {
        postcard::to_allocvec(&self.inner).map_err(|e| SignatureParseError(format!("{e:?}")))
    }

    /// The public key derived from this secret key.
    pub fn public_key(&self) -> ValidatorPublicKey {
        ValidatorPublicKey {
            inner: self.inner.public_key(),
        }
    }

    /// Sign a message at `slot`.
    ///
    /// The slot indexes the one-time XMSS leaf; never sign two different
    /// messages at the same slot.
    pub fn sign(
        &self,
        slot: u32,
        message: &H256,
    ) -> Result<ValidatorSignature, XmssSignatureError> {
        let sig = xmss_sign(&self.inner, slot, &message.0)?;
        Ok(ValidatorSignature { inner: sig })
    }

    /// Returns true if the key can sign at the given slot.
    ///
    /// leanVM's xmss keys cover a fixed activation range (fixed at key
    /// generation); there is no sliding preparation window as in the old
    /// leanSig scheme.
    pub fn is_prepared_for(&self, slot: u32) -> bool {
        self.inner.activation_slots().contains(&slot)
    }

    /// The half-open slot range this key can sign for.
    pub fn get_prepared_interval(&self) -> Range<u64> {
        let range = self.inner.activation_slots();
        (*range.start() as u64)..(*range.end() as u64 + 1)
    }

    /// No-op retained for API compatibility.
    ///
    /// The old leanSig scheme advanced a two-bottom-tree preparation window;
    /// leanVM's xmss keys have a fixed activation range and warm their signing
    /// cache on demand inside `sign`, so there is nothing to advance.
    pub fn advance_preparation(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmss::xmss_key_gen_from_seed;

    /// Generate a validator key pair over a small activation range.
    fn generate_key(
        seed: [u8; 32],
        activation_slot: u64,
        num_active_slots: u64,
    ) -> ValidatorSecretKey {
        let (_pk, sk) = xmss_key_gen_from_seed(seed, activation_slot, num_active_slots)
            .expect("valid activation range");
        ValidatorSecretKey { inner: sk }
    }

    #[test]
    #[ignore = "slow: XMSS key generation and signing"]
    fn sign_verify_round_trip() {
        let sk = generate_key([7u8; 32], 0, 64);
        let pk = sk.public_key();

        assert!(sk.is_prepared_for(0));
        assert!(sk.is_prepared_for(63));
        assert!(!sk.is_prepared_for(64));
        assert_eq!(sk.get_prepared_interval(), 0..64);

        let message = H256::from([42u8; 32]);
        let slot = 10u32;
        let sig = sk.sign(slot, &message).expect("sign");
        assert!(sig.is_valid(&pk, slot, &message));
        assert!(!sig.is_valid(&pk, slot, &H256::from([43u8; 32])));
        assert!(!sig.is_valid(&pk, slot + 1, &message));
    }

    #[test]
    #[ignore = "slow: XMSS key generation and signing"]
    fn sign_out_of_range_fails() {
        let sk = generate_key([9u8; 32], 100, 32);
        let message = H256::from([1u8; 32]);
        // Slot 0 is outside the key's activation range [100, 132).
        assert!(sk.sign(0, &message).is_err());
    }

    #[test]
    #[ignore = "slow: XMSS key generation"]
    fn public_key_ssz_round_trip() {
        let sk = generate_key([3u8; 32], 0, 16);
        let pk = sk.public_key();
        let bytes = pk.to_bytes();
        assert_eq!(bytes.len(), PUBLIC_KEY_SIZE);
        let parsed = ValidatorPublicKey::from_bytes(&bytes).expect("round trip");
        assert_eq!(parsed.to_bytes(), bytes);
    }
}
