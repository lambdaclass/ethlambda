use leansig::{
    serialization::Serializable,
    signature::{SignatureScheme, SigningError},
};
use ssz::DecodeError;
use ssz_types::typenum::{Diff, U488, U3600};

use crate::primitives::H256;

/// The XMSS signature scheme used for validator signatures.
///
/// This is a post-quantum secure signature scheme based on hash functions.
/// The specific instantiation uses Poseidon hashing with a 32-bit lifetime
/// (2^32 signatures per key), dimension 64, and base 8.
pub type LeanSignatureScheme = leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;

/// The public key type from the leansig library.
pub type LeanSigPublicKey = <LeanSignatureScheme as SignatureScheme>::PublicKey;

/// The signature type from the leansig library.
pub type LeanSigSignature = <LeanSignatureScheme as SignatureScheme>::Signature;

/// The secret key type from the leansig library.
pub type LeanSigSecretKey = <LeanSignatureScheme as SignatureScheme>::SecretKey;

pub type Signature = LeanSigSignature;

pub type SignatureSize = Diff<U3600, U488>;

pub struct ValidatorSignature {
    inner: LeanSigSignature,
}

impl ValidatorSignature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let sig = LeanSigSignature::from_bytes(bytes)?;
        Ok(Self { inner: sig })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }

    pub fn is_valid(&self, pubkey: &ValidatorPublicKey, epoch: u32, message: &H256) -> bool {
        LeanSignatureScheme::verify(&pubkey.inner, epoch, message, &self.inner)
    }

    /// Get a reference to the inner leansig signature.
    ///
    /// This is useful for passing to lean-multisig aggregation functions.
    pub fn as_inner(&self) -> &LeanSigSignature {
        &self.inner
    }
}

#[derive(Clone)]
pub struct ValidatorPublicKey {
    inner: LeanSigPublicKey,
}

impl ValidatorPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let pk = LeanSigPublicKey::from_bytes(bytes)?;
        Ok(Self { inner: pk })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }

    /// Get a reference to the inner leansig public key.
    ///
    /// This is useful for passing to lean-multisig aggregation functions.
    pub fn as_inner(&self) -> &LeanSigPublicKey {
        &self.inner
    }
}

/// Validator private key for signing attestations and blocks.
pub struct ValidatorSecretKey {
    inner: LeanSigSecretKey,
}

impl ValidatorSecretKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let sk = LeanSigSecretKey::from_bytes(bytes)?;
        Ok(Self { inner: sk })
    }

    /// Sign a message with this private key.
    ///
    /// The epoch is used as part of the XMSS signature scheme to track
    /// one-time signature usage.
    pub fn sign(&self, epoch: u32, message: &H256) -> Result<ValidatorSignature, SigningError> {
        let sig = LeanSignatureScheme::sign(&self.inner, epoch, message)?;
        Ok(ValidatorSignature { inner: sig })
    }
}
