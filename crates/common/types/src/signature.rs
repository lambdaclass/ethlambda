use leansig::signature::SignatureScheme;
use ssz_types::typenum::{Diff, U488, U3600};

pub type LeanSignatureScheme = leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;

type LeanSigSignature = <LeanSignatureScheme as SignatureScheme>::Signature;

pub type Signature = LeanSigSignature;

pub type SignatureSize = Diff<U3600, U488>;

pub type LeanPublicKey = <LeanSignatureScheme as SignatureScheme>::PublicKey;
