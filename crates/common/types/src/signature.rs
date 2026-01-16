use leansig::{
    serialization::Serializable,
    signature::{SignatureScheme, SigningError},
};
use ssz::DecodeError;
use ssz_types::typenum::{Diff, U488, U3600};

use crate::primitives::H256;

type LeanSignatureScheme = leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;

type LeanSigPublicKey = <LeanSignatureScheme as SignatureScheme>::PublicKey;
type LeanSigSignature = <LeanSignatureScheme as SignatureScheme>::Signature;
type LeanSigSecretKey = <LeanSignatureScheme as SignatureScheme>::SecretKey;

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
}

pub struct ValidatorPublicKey {
    inner: LeanSigPublicKey,
}

impl ValidatorPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let pk = LeanSigPublicKey::from_bytes(bytes)?;
        Ok(Self { inner: pk })
    }

    pub fn is_valid(&self, epoch: u32, message: &H256, signature: &ValidatorSignature) -> bool {
        LeanSignatureScheme::verify(&self.inner, epoch, message, &signature.inner)
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
