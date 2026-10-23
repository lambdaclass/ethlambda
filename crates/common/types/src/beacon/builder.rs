//! The builder API's own containers (`ethereum/builder-specs`), which the
//! MEV-Boost relay flow exchanges between a validator client, this node and a
//! relay.
//!
//! Not consensus containers. Nothing here enters a state, and only
//! [`BlindedBeaconBlock`] has a root anything depends on: it equals the full
//! block's, because a payload header's root is the root of the payload it
//! summarizes. That equality is what lets a validator sign a blinded block for
//! a full one it never sees.
//!
//! Electra and fulu shapes only, which are identical, as the consensus
//! containers they extend are.

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::SszList;

use crate::beacon::containers::deneb::{ExecutionPayloadHeader, KzgCommitments};
use crate::beacon::containers::electra::ExecutionRequests;
use crate::beacon::preset;
use crate::beacon::primitives::{BlsPubkey, BlsSignature, ExecutionAddress, Uint256};

// ---------------------------------------------------------------------------
// Registrations
// ---------------------------------------------------------------------------

/// A validator's building preferences, as it sends them to builders through
/// its beacon node (`registerValidator`), builder-specs `bellatrix/builder.md`.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct ValidatorRegistrationV1 {
    pub fee_recipient: ExecutionAddress,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub gas_limit: u64,
    /// Seconds since the Unix epoch. Builders keep a validator's latest
    /// registration by this, so re-sending an unchanged one must reuse it.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub timestamp: u64,
    pub pubkey: BlsPubkey,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct SignedValidatorRegistrationV1 {
    pub message: ValidatorRegistrationV1,
    pub signature: BlsSignature,
}

/// The `registerValidator` request body's SSZ form, in both the Beacon API
/// and the builder API.
pub type SignedValidatorRegistrations =
    SszList<SignedValidatorRegistrationV1, { preset::VALIDATOR_REGISTRY_LIMIT }>;

// ---------------------------------------------------------------------------
// Bids
// ---------------------------------------------------------------------------

/// A relay's offer of an execution payload, builder-specs `electra/builder.md`
/// (fulu leaves it unchanged): the payload's header, its blob commitments and
/// execution requests, and what it pays.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct BuilderBid {
    pub header: ExecutionPayloadHeader,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub blob_kzg_commitments: KzgCommitments,
    pub execution_requests: ExecutionRequests,
    /// What the proposer is paid, in Wei.
    pub value: Uint256,
    /// The key the bid is signed with, under
    /// [`DOMAIN_APPLICATION_BUILDER`](crate::beacon::constants::DOMAIN_APPLICATION_BUILDER).
    pub pubkey: BlsPubkey,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct SignedBuilderBid {
    pub message: BuilderBid,
    pub signature: BlsSignature,
}

#[cfg(test)]
mod tests {
    use libssz::{SszDecode as _, SszEncode as _};

    use super::*;

    /// A vendored builder-specs example file (see the fixtures' README).
    macro_rules! example {
        ($path:literal) => {
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/builder_specs/",
                $path
            ))
        };
    }

    /// The object an example `.json` holds under its `value` key.
    fn example_value(json: &[u8]) -> serde_json::Value {
        let mut document: serde_json::Value = serde_json::from_slice(json).unwrap();
        document["value"].take()
    }

    #[test]
    fn the_registration_example_decodes_from_both_encodings() {
        let ssz = example!("bellatrix/signed_validator_registrations.ssz");
        let from_ssz = SignedValidatorRegistrations::from_ssz_bytes(ssz).unwrap();
        let from_json: Vec<SignedValidatorRegistrationV1> = serde_json::from_value(
            example_value(example!("bellatrix/signed_validator_registrations.json")),
        )
        .unwrap();

        assert_eq!(from_ssz.to_vec(), from_json);
        assert_eq!(from_ssz.to_ssz(), ssz.to_vec());
        assert_eq!(from_json[0].message.gas_limit, 100);
        assert_eq!(from_json[0].message.timestamp, 100);
    }

    #[test]
    fn the_bid_example_decodes_from_both_encodings() {
        let ssz = example!("fulu/signed_builder_bid.ssz");
        let from_ssz = SignedBuilderBid::from_ssz_bytes(ssz).unwrap();
        let value = example_value(example!("fulu/signed_builder_bid.json"));
        assert_eq!(value["version"], "fulu");
        let from_json: SignedBuilderBid = serde_json::from_value(value["data"].clone()).unwrap();

        assert_eq!(from_ssz, from_json);
        assert_eq!(from_ssz.to_ssz(), ssz.to_vec());
        assert_eq!(from_json.message.value, Uint256::from(1u64));
        assert_eq!(from_json.message.blob_kzg_commitments.len(), 1);
    }
}
