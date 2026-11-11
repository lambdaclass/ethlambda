//! Containers EIP-8483 (post-quantum material registration) introduces.
//!
//! Transcribed from consensus-specs #5809 (`specs/_features/eip8483/`, head
//! `a043fda6`), which builds the feature on heze. Two execution layer
//! triggered requests let a validator's withdrawal address register 64 bytes
//! of opaque post-quantum material, and a builder's execution address 32
//! bytes, ahead of a later fork that migrates to post-quantum signatures. The
//! state keeps one entry per validator (keyed by index) and one per builder
//! (keyed by public key, since builder indices are reused).
//!
//! The two request lists ride in [`super::gloas::ExecutionRequests`] as one
//! `Option` ([`PQRegistrationRequests`]) rather than in a restated container:
//! the same choice heze made for the bid's `inclusion_list_bits`, so the
//! envelope, the block body's `parent_execution_requests` and the engine's
//! `NewPayloadRequest` keep serving every fork from gloas on. See that type's
//! doc for how the two shapes are told apart.

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::ProgressiveList;

use crate::beacon::primitives::{
    BlsPubkey, Bytes32, Bytes64, ExecutionAddress, ValidatorIndex,
};

/// The validator PQ registration requests pertaining to a single execution
/// payload.
pub type ValidatorPQRegistrationRequests = ProgressiveList<ValidatorPQRegistrationRequest>;
/// The registered validator PQ material, at most one entry per validator.
pub type ValidatorPQRegistrations = ProgressiveList<ValidatorPQRegistration>;
/// The builder PQ registration requests pertaining to a single execution
/// payload.
pub type BuilderPQRegistrationRequests = ProgressiveList<BuilderPQRegistrationRequest>;
/// The registered builder PQ material, at most one entry per builder.
pub type BuilderPQRegistrations = ProgressiveList<BuilderPQRegistration>;

/// A request from a validator's withdrawal address to register `pq_data` for
/// that validator.
///
/// Its SSZ serialization is the 132-byte record the validator predeploy
/// contract returns (`source_address ++ validator_pubkey ++ pq_data`).
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct ValidatorPQRegistrationRequest {
    pub source_address: ExecutionAddress,
    pub validator_pubkey: BlsPubkey,
    pub pq_data: Bytes64,
}

/// One validator's registered PQ material.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct ValidatorPQRegistration {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub validator_index: ValidatorIndex,
    pub pq_data: Bytes64,
}

/// A request from a builder's execution address to register `pq_data` for
/// that builder.
///
/// Its SSZ serialization is the 100-byte record the builder predeploy
/// contract returns (`source_address ++ builder_pubkey ++ pq_data`).
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct BuilderPQRegistrationRequest {
    pub source_address: ExecutionAddress,
    pub builder_pubkey: BlsPubkey,
    pub pq_data: Bytes32,
}

/// One builder's registered PQ material, keyed by public key: a builder index
/// is reused once its builder has withdrawn, so an index-keyed entry could be
/// inherited by an unrelated builder.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct BuilderPQRegistration {
    pub builder_pubkey: BlsPubkey,
    pub pq_data: Bytes32,
}

/// The two request lists EIP-8483 appends to `ExecutionRequests`, held
/// together so that a value carries both or neither.
///
/// `ExecutionRequests` flattens this into its own JSON object, so the Beacon
/// API sees the specification's two field names side by side with the other
/// request kinds.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PQRegistrationRequests {
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub validator_pq_registrations: ValidatorPQRegistrationRequests,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub builder_pq_registrations: BuilderPQRegistrationRequests,
}

impl PQRegistrationRequests {
    /// Whether both lists are empty.
    pub fn is_empty(&self) -> bool {
        self.validator_pq_registrations.is_empty() && self.builder_pq_registrations.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use libssz::{SszDecode as _, SszEncode as _};

    use super::*;

    /// The request containers' encodings are the predeploy contracts' records,
    /// so their sizes are part of the cross-layer contract.
    #[test]
    fn request_records_have_the_contracts_sizes() {
        assert!(<ValidatorPQRegistrationRequest as libssz::SszEncode>::is_fixed_size());
        assert!(<BuilderPQRegistrationRequest as libssz::SszEncode>::is_fixed_size());
        assert_eq!(
            <ValidatorPQRegistrationRequest as libssz::SszEncode>::fixed_size(),
            132
        );
        assert_eq!(
            <BuilderPQRegistrationRequest as libssz::SszEncode>::fixed_size(),
            100
        );
        assert_eq!(<ValidatorPQRegistration as libssz::SszEncode>::fixed_size(), 72);
        assert_eq!(<BuilderPQRegistration as libssz::SszEncode>::fixed_size(), 80);
    }

    #[test]
    fn a_validator_request_encodes_as_address_then_pubkey_then_data() {
        let request = ValidatorPQRegistrationRequest {
            source_address: ExecutionAddress::from_slice(&[0x11; 20]),
            validator_pubkey: BlsPubkey([0x22; 48]),
            pq_data: Bytes64([0x33; 64]),
        };
        let bytes = request.to_ssz();
        let mut expected = vec![0x11; 20];
        expected.extend([0x22; 48]);
        expected.extend([0x33; 64]);
        assert_eq!(bytes, expected);
        assert_eq!(
            ValidatorPQRegistrationRequest::from_ssz_bytes(&bytes).unwrap(),
            request
        );
    }

    #[test]
    fn a_builder_request_encodes_as_address_then_pubkey_then_data() {
        let request = BuilderPQRegistrationRequest {
            source_address: ExecutionAddress::from_slice(&[0x11; 20]),
            builder_pubkey: BlsPubkey([0x22; 48]),
            pq_data: Bytes32::repeat_byte(0x33),
        };
        let bytes = request.to_ssz();
        let mut expected = vec![0x11; 20];
        expected.extend([0x22; 48]);
        expected.extend([0x33; 32]);
        assert_eq!(bytes, expected);
        assert_eq!(
            BuilderPQRegistrationRequest::from_ssz_bytes(&bytes).unwrap(),
            request
        );
    }
}
