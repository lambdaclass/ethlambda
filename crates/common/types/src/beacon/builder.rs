//! The builder API's own containers (`ethereum/builder-specs`), which the
//! MEV-Boost relay flow exchanges between a validator client, this node and a
//! relay.
//!
//! Not consensus containers: nothing here enters a state. Registrations and
//! bids are signed over their own roots, and [`BlindedBeaconBlock`]'s root must
//! also equal the full block's, which it does because a payload header's root
//! is the root of the payload it summarizes. That equality is what lets a
//! validator sign a blinded block for a full one it never sees.
//!
//! Electra and fulu shapes only, which are identical, as the consensus
//! containers they extend are.

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::SszList;

use crate::beacon::containers::altair::SyncAggregate;
use crate::beacon::containers::capella::SignedBLSToExecutionChange;
use crate::beacon::containers::deneb::{ExecutionPayloadHeader, KzgCommitments};
use crate::beacon::containers::electra::{
    self, Attestations, AttesterSlashings, ExecutionRequests,
};
use crate::beacon::containers::shared::{Deposit, Eth1Data, ProposerSlashing, SignedVoluntaryExit};
use crate::beacon::preset;
use crate::beacon::primitives::{
    BlsPubkey, BlsSignature, Bytes32, ExecutionAddress, Root, Slot, Uint256, ValidatorIndex,
};

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
    /// Seconds since the Unix epoch. Builders sequence a validator's
    /// registrations by this and reject one older than the latest they hold.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub timestamp: u64,
    pub pubkey: BlsPubkey,
}

/// A [`ValidatorRegistrationV1`] signed by its validator under
/// [`DOMAIN_APPLICATION_BUILDER`](crate::beacon::constants::DOMAIN_APPLICATION_BUILDER).
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

/// A [`BuilderBid`] signed by its `pubkey` under
/// [`DOMAIN_APPLICATION_BUILDER`](crate::beacon::constants::DOMAIN_APPLICATION_BUILDER).
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

// ---------------------------------------------------------------------------
// Blinded blocks
// ---------------------------------------------------------------------------

/// [`electra::BeaconBlockBody`] with the payload's header in place of the
/// payload, builder-specs `electra/builder.md`. Otherwise the same container
/// field for field, which is why its root equals the full body's.
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
pub struct BlindedBeaconBlockBody {
    pub randao_reveal: BlsSignature,
    pub eth1_data: Eth1Data,
    pub graffiti: Bytes32,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub proposer_slashings: SszList<ProposerSlashing, { preset::MAX_PROPOSER_SLASHINGS }>,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub attester_slashings: AttesterSlashings,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub attestations: Attestations,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub deposits: SszList<Deposit, { preset::MAX_DEPOSITS }>,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub voluntary_exits: SszList<SignedVoluntaryExit, { preset::MAX_VOLUNTARY_EXITS }>,
    pub sync_aggregate: SyncAggregate,
    pub execution_payload_header: ExecutionPayloadHeader,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub bls_to_execution_changes:
        SszList<SignedBLSToExecutionChange, { preset::MAX_BLS_TO_EXECUTION_CHANGES }>,
    #[serde(with = "crate::beacon::serde_helpers::seq")]
    pub blob_kzg_commitments: KzgCommitments,
    pub execution_requests: ExecutionRequests,
}

impl BlindedBeaconBlockBody {
    /// `body` with its payload swapped for `execution_payload_header`.
    ///
    /// The header is taken as given, so the result's root equals `body`'s only
    /// when the header is `body.execution_payload`'s own. Blinded block
    /// production relies on the header being kept as given: it builds the body
    /// around a stand-in payload and blinds it with the builder's header.
    pub fn from_parts(
        body: electra::BeaconBlockBody,
        execution_payload_header: ExecutionPayloadHeader,
    ) -> Self {
        Self {
            randao_reveal: body.randao_reveal,
            eth1_data: body.eth1_data,
            graffiti: body.graffiti,
            proposer_slashings: body.proposer_slashings,
            attester_slashings: body.attester_slashings,
            attestations: body.attestations,
            deposits: body.deposits,
            voluntary_exits: body.voluntary_exits,
            sync_aggregate: body.sync_aggregate,
            execution_payload_header,
            bls_to_execution_changes: body.bls_to_execution_changes,
            blob_kzg_commitments: body.blob_kzg_commitments,
            execution_requests: body.execution_requests,
        }
    }
}

/// Blinds a full body: its payload replaced by that payload's own header.
impl From<electra::BeaconBlockBody> for BlindedBeaconBlockBody {
    fn from(body: electra::BeaconBlockBody) -> Self {
        let header = ExecutionPayloadHeader::from(&body.execution_payload);
        Self::from_parts(body, header)
    }
}

/// [`electra::BeaconBlock`] around a [`BlindedBeaconBlockBody`]. What a
/// validator signs when a builder supplies the payload.
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
pub struct BlindedBeaconBlock {
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub slot: Slot,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub proposer_index: ValidatorIndex,
    pub parent_root: Root,
    pub state_root: Root,
    pub body: BlindedBeaconBlockBody,
}

impl BlindedBeaconBlock {
    /// `block` with its body's payload swapped for `execution_payload_header`;
    /// see [`BlindedBeaconBlockBody::from_parts`]. The block's `state_root` is
    /// copied as is, so a caller passing a header other than the payload's own
    /// must recompute it, as blinded block production does.
    pub fn from_parts(
        block: electra::BeaconBlock,
        execution_payload_header: ExecutionPayloadHeader,
    ) -> Self {
        Self {
            slot: block.slot,
            proposer_index: block.proposer_index,
            parent_root: block.parent_root,
            state_root: block.state_root,
            body: BlindedBeaconBlockBody::from_parts(block.body, execution_payload_header),
        }
    }
}

/// Blinds a full block: its payload replaced by that payload's own header,
/// keeping the block's root.
impl From<electra::BeaconBlock> for BlindedBeaconBlock {
    fn from(block: electra::BeaconBlock) -> Self {
        let header = ExecutionPayloadHeader::from(&block.body.execution_payload);
        Self::from_parts(block, header)
    }
}

/// A [`BlindedBeaconBlock`] signed by its proposer under the full block's
/// domain, `DOMAIN_BEACON_PROPOSER`, since the two share a root.
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
pub struct SignedBlindedBeaconBlock {
    pub message: BlindedBeaconBlock,
    pub signature: BlsSignature,
}

#[cfg(test)]
mod tests {
    use libssz::{SszDecode as _, SszEncode as _};

    use super::*;
    use crate::beacon::containers::deneb::ExecutionPayload;
    use crate::beacon::primitives::HashTreeRoot as _;

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
        let value = example_value(example!("bellatrix/signed_validator_registrations.json"));
        let from_json: Vec<SignedValidatorRegistrationV1> =
            serde_json::from_value(value.clone()).unwrap();

        assert_eq!(from_ssz.to_vec(), from_json);
        // What this node would send a relay.
        assert_eq!(serde_json::to_value(from_ssz.to_vec()).unwrap(), value);
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
        assert_eq!(serde_json::to_value(&from_ssz).unwrap(), value["data"]);
        assert_eq!(from_ssz.to_ssz(), ssz.to_vec());
        assert_eq!(from_json.message.value, Uint256::from(1u64));
        assert_eq!(from_json.message.blob_kzg_commitments.len(), 1);
    }

    /// A block with every list populated. Empty lists with equal limits share
    /// a root, so a body with empty ones would not notice two of its fields
    /// swapping places.
    fn full_block() -> electra::BeaconBlock {
        crate::beacon::containers::json_tests::electra_block().message
    }

    #[test]
    fn a_blinded_block_has_the_full_blocks_root() {
        let block = full_block();
        let blinded = BlindedBeaconBlock::from(block.clone());
        assert_eq!(blinded.body.hash_tree_root(), block.body.hash_tree_root());
        assert_eq!(blinded.hash_tree_root(), block.hash_tree_root());
        assert_eq!(blinded.state_root, block.state_root);
    }

    #[test]
    fn from_parts_keeps_the_header_it_is_given() {
        let block = full_block();
        let other = ExecutionPayloadHeader::from(&ExecutionPayload {
            block_number: 99,
            ..block.body.execution_payload.clone()
        });
        let blinded = BlindedBeaconBlock::from_parts(block.clone(), other.clone());
        assert_eq!(blinded.body.execution_payload_header, other);
        assert_ne!(blinded.hash_tree_root(), block.hash_tree_root());
    }

    // The example's sync aggregate is mainnet-sized (`SYNC_COMMITTEE_SIZE`
    // bits), which the minimal preset's container does not decode.
    #[cfg(not(feature = "preset-minimal"))]
    #[test]
    fn the_blinded_block_example_decodes_from_both_encodings() {
        let ssz = example!("fulu/signed_blinded_beacon_block.ssz");
        let from_ssz = SignedBlindedBeaconBlock::from_ssz_bytes(ssz).unwrap();
        let value = example_value(example!("fulu/signed_blinded_beacon_block.json"));
        let from_json: SignedBlindedBeaconBlock = serde_json::from_value(value.clone()).unwrap();

        assert_eq!(from_ssz, from_json);
        assert_eq!(serde_json::to_value(&from_ssz).unwrap(), value);
        assert_eq!(from_ssz.to_ssz(), ssz.to_vec());
    }
}
