#![allow(dead_code)]

pub use ethlambda_test_fixtures::*;

use ethlambda_types::attestation::Attestation as DomainAttestation;
use serde::Deserialize;

// ============================================================================
// ProposerAttestation (forkchoice/signature tests only)
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct ProposerAttestation {
    #[serde(rename = "validatorId")]
    pub validator_id: u64,
    pub data: AttestationData,
}

impl From<ProposerAttestation> for DomainAttestation {
    fn from(value: ProposerAttestation) -> Self {
        Self {
            validator_id: value.validator_id,
            data: value.data.into(),
        }
    }
}
