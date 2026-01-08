use leansig::signature::SignatureScheme;

type LeanSignatureScheme = leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;

type LeanSigSignature = <LeanSignatureScheme as SignatureScheme>::Signature;

pub type Signature = LeanSigSignature;
