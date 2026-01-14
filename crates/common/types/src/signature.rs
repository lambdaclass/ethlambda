use leansig::{serialization::Serializable, signature::SignatureScheme};
use ssz::DecodeError;
use ssz_types::typenum::{Diff, U488, U3600};

use crate::primitives::H256;

type LeanSignatureScheme = leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;

type LeanSigPublicKey = <LeanSignatureScheme as SignatureScheme>::PublicKey;
type LeanSigSignature = <LeanSignatureScheme as SignatureScheme>::Signature;

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
