//! Signing through a Web3Signer remote signer.
//!
//! The key never enters this process: each signature is a `POST
//! /api/v1/eth2/sign/{pubkey}` carrying the message, the fork it is signed
//! under and the signing root, and the signer answers with the signature. The
//! message travels in full rather than as its root alone because the signer
//! keeps the slashing-protection record this client does not (see
//! `docs/spec_deviations.md`), and it can only refuse a double vote it can
//! read. The root is sent as well so the signer can check the two agree.
//!
//! Request shapes follow Web3Signer's own OpenAPI
//! (`core/src/main/resources/openapi-specs/eth2/signing/schemas.yaml`):
//! quoted integers, `0x`-prefixed hex, and a fork-named `version` on the
//! containers that changed shape across forks.

use std::time::Duration;

use ethlambda_types::beacon::containers::altair::{
    ContributionAndProof, SyncAggregatorSelectionData,
};
use ethlambda_types::beacon::containers::gloas::{
    ExecutionPayloadEnvelope, PayloadAttestationData,
};
use ethlambda_types::beacon::containers::shared::{AttestationData, BeaconBlockHeader, Fork};
use ethlambda_types::beacon::containers::{electra, gloas};
use ethlambda_types::beacon::primitives::{BLS_SIGNATURE_SIZE, BlsPubkey, BlsSignature, Root};
use serde::Serialize;

use crate::beacon_node::dto::{encode_hex, parse_signature};
use crate::error::{Error, Result};

/// How long one signing request may take. The same bound the beacon node
/// client uses; every duty is cut off by its own slot deadline anyway, and a
/// signer slower than this is one whose signatures arrive too late to count.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);

/// Web3Signer's answer when its slashing protection refused the message.
const SLASHING_PROTECTION_REFUSED: u16 = 412;

/// One remote signer, shared by every validator whose key it holds.
pub struct Web3Signer {
    base_url: String,
    client: reqwest::Client,
}

impl Web3Signer {
    /// Build a client for the signer at `url`, which is the server's base
    /// (`https://signer:9000`), not the signing path.
    pub fn new(url: &str) -> Result<Self> {
        let base_url = url.trim_end_matches('/').to_string();
        let parsed = reqwest::Url::parse(&base_url).map_err(|err| Error::Keystore {
            path: base_url.clone(),
            reason: format!("not a valid remote signer URL: {err}"),
        })?;
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return Err(Error::Keystore {
                path: base_url,
                reason: "a remote signer URL must be http or https".to_string(),
            });
        }
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|err| Error::Keystore {
                path: base_url.clone(),
                reason: format!("could not build an HTTP client: {err}"),
            })?;
        Ok(Self { base_url, client })
    }

    /// The signer's base URL, with any trailing slash already stripped.
    pub fn url(&self) -> &str {
        &self.base_url
    }

    /// Ask the signer for `pubkey`'s signature over `request`.
    ///
    /// Every failure is an [`Error::Signing`]: a refusal by the signer's
    /// slashing protection, a key the signer does not hold, and a transport
    /// failure all cost this one signature and nothing else, and none of them
    /// is something retrying within the slot would change.
    pub async fn sign(
        &self,
        pubkey: &BlsPubkey,
        request: &SigningRequest<'_>,
    ) -> Result<BlsSignature> {
        let pubkey_hex = encode_hex(&pubkey.0);
        let url = format!("{}/api/v1/eth2/sign/{pubkey_hex}", self.base_url);
        let failed = |reason: String| Error::Signing {
            pubkey: *pubkey,
            reason,
        };

        let response = self
            .client
            .post(&url)
            .header(reqwest::header::ACCEPT, "application/json")
            .json(request)
            .send()
            .await
            .map_err(|err| failed(format!("remote signer {}: {err}", self.base_url)))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|err| failed(format!("remote signer {}: {err}", self.base_url)))?;

        if status.as_u16() == SLASHING_PROTECTION_REFUSED {
            return Err(failed(format!(
                "remote signer {} refused to sign: its slashing protection rejected the message",
                self.base_url
            )));
        }
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(failed(format!(
                "remote signer {} does not hold this key",
                self.base_url
            )));
        }
        if !status.is_success() {
            return Err(failed(format!(
                "remote signer {} answered {status}: {}",
                self.base_url,
                body.trim()
            )));
        }

        parse_signature_body(&body)
            .map_err(|err| failed(format!("remote signer {}: {err}", self.base_url)))
    }
}

/// The signature out of a `200` body: `{"signature": "0x..."}` when the
/// signer honoured `Accept: application/json`, or the bare hex string an
/// older signer answers with regardless.
fn parse_signature_body(body: &str) -> Result<BlsSignature> {
    #[derive(serde::Deserialize)]
    struct SignatureResponse {
        signature: String,
    }
    let hex = match serde_json::from_str::<SignatureResponse>(body) {
        Ok(response) => response.signature,
        Err(_) => body.trim().trim_matches('"').to_string(),
    };
    let signature = parse_signature(&hex).map_err(|err| {
        Error::Decode(format!(
            "the signature in the response is unreadable: {err}"
        ))
    })?;
    debug_assert_eq!(signature.0.len(), BLS_SIGNATURE_SIZE);
    Ok(signature)
}

/// The fork a message is signed under, as the signer wants it told.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ForkInfo {
    pub fork: Fork,
    pub genesis_validators_root: Root,
}

/// One signing request: what kind of message, under which fork, over which
/// root, and the message itself.
#[derive(Serialize)]
pub struct SigningRequest<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    pub fork_info: ForkInfo,
    #[serde(rename = "signingRoot")]
    pub signing_root: Root,
    #[serde(flatten)]
    pub body: SigningBody<'a>,
}

impl<'a> SigningRequest<'a> {
    pub fn new(fork_info: ForkInfo, signing_root: Root, body: SigningBody<'a>) -> Self {
        Self {
            kind: body.kind(),
            fork_info,
            signing_root,
            body,
        }
    }
}

/// The message half of a request, one field per Web3Signer request type.
///
/// Untagged on purpose: the `type` discriminator is a sibling of these fields
/// in the request, not a tag around them, so the variant contributes its one
/// field and [`SigningRequest`] writes the `type` beside it.
#[derive(Serialize)]
#[serde(untagged)]
pub enum SigningBody<'a> {
    Attestation {
        attestation: &'a AttestationData,
    },
    RandaoReveal {
        randao_reveal: RandaoReveal,
    },
    Block {
        beacon_block: VersionedHeader,
    },
    AggregationSlot {
        aggregation_slot: AggregationSlot,
    },
    AggregateAndProof {
        aggregate_and_proof: Versioned<AggregateAndProofRef<'a>>,
    },
    SyncCommitteeMessage {
        sync_committee_message: SyncCommitteeMessage,
    },
    SyncCommitteeSelectionProof {
        sync_aggregator_selection_data: SyncAggregatorSelectionData,
    },
    SyncCommitteeContributionAndProof {
        contribution_and_proof: &'a ContributionAndProof,
    },
    ExecutionPayloadEnvelope {
        execution_payload_envelope: Versioned<&'a ExecutionPayloadEnvelope>,
    },
    PayloadAttestationMessage {
        payload_attestation_message: Versioned<&'a PayloadAttestationData>,
    },
}

impl SigningBody<'_> {
    /// Web3Signer's `type` for this message.
    fn kind(&self) -> &'static str {
        match self {
            Self::Attestation { .. } => "ATTESTATION",
            Self::RandaoReveal { .. } => "RANDAO_REVEAL",
            Self::Block { .. } => "BLOCK_V2",
            Self::AggregationSlot { .. } => "AGGREGATION_SLOT",
            Self::AggregateAndProof { .. } => "AGGREGATE_AND_PROOF_V2",
            Self::SyncCommitteeMessage { .. } => "SYNC_COMMITTEE_MESSAGE",
            Self::SyncCommitteeSelectionProof { .. } => "SYNC_COMMITTEE_SELECTION_PROOF",
            Self::SyncCommitteeContributionAndProof { .. } => {
                "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF"
            }
            Self::ExecutionPayloadEnvelope { .. } => "EXECUTION_PAYLOAD_ENVELOPE",
            Self::PayloadAttestationMessage { .. } => "PAYLOAD_ATTESTATION_MESSAGE",
        }
    }
}

#[derive(Serialize)]
pub struct RandaoReveal {
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    pub epoch: u64,
}

#[derive(Serialize)]
pub struct AggregationSlot {
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    pub slot: u64,
}

#[derive(Serialize)]
pub struct SyncCommitteeMessage {
    pub beacon_block_root: Root,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    pub slot: u64,
}

/// A block, as the signer wants it: the fork's name and the header alone.
/// The body never travels; its root in the header is what the signature
/// covers.
#[derive(Serialize)]
pub struct VersionedHeader {
    pub version: String,
    pub block_header: BeaconBlockHeader,
}

/// A container whose JSON shape the signer selects by fork name.
#[derive(Serialize)]
pub struct Versioned<T> {
    pub version: String,
    pub data: T,
}

/// An `AggregateAndProof` of either fork this client publishes, by reference.
#[derive(Clone, Copy, Serialize)]
#[serde(untagged)]
pub enum AggregateAndProofRef<'a> {
    Electra(&'a electra::AggregateAndProof),
    Gloas(&'a gloas::AggregateAndProof),
}

impl AggregateAndProofRef<'_> {
    /// The slot of the votes being republished, which is the slot the
    /// wrapper's signature is domained on.
    pub fn slot(&self) -> u64 {
        match self {
            Self::Electra(message) => message.aggregate.data.slot,
            Self::Gloas(message) => message.aggregate.data.slot,
        }
    }

    pub fn hash_tree_root(&self) -> Root {
        use ethlambda_types::beacon::primitives::HashTreeRoot as _;
        match self {
            Self::Electra(message) => message.hash_tree_root(),
            Self::Gloas(message) => message.hash_tree_root(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::beacon::containers::shared::Checkpoint;
    use serde_json::json;

    fn fork_info() -> ForkInfo {
        ForkInfo {
            fork: Fork {
                previous_version: [0, 0, 0, 0],
                current_version: [1, 0, 0, 0],
                epoch: 74_240,
            },
            genesis_validators_root: Root::repeat_byte(0xaa),
        }
    }

    fn attestation_data() -> AttestationData {
        AttestationData {
            slot: 3200,
            index: 2,
            beacon_block_root: Root::repeat_byte(1),
            source: Checkpoint {
                epoch: 99,
                root: Root::repeat_byte(2),
            },
            target: Checkpoint {
                epoch: 100,
                root: Root::repeat_byte(3),
            },
        }
    }

    fn encode(request: &SigningRequest<'_>) -> serde_json::Value {
        serde_json::to_value(request).expect("serializes")
    }

    /// The exact wire shape, pinned against Web3Signer's `AttestationSigning`
    /// schema: `type` beside `fork_info`, `signingRoot` camel-cased, every
    /// integer quoted, every hash `0x`-prefixed.
    #[test]
    fn an_attestation_request_has_web3signers_shape() {
        let data = attestation_data();
        let request = SigningRequest::new(
            fork_info(),
            Root::repeat_byte(9),
            SigningBody::Attestation { attestation: &data },
        );
        assert_eq!(
            encode(&request),
            json!({
                "type": "ATTESTATION",
                "fork_info": {
                    "fork": {
                        "previous_version": "0x00000000",
                        "current_version": "0x01000000",
                        "epoch": "74240"
                    },
                    "genesis_validators_root": format!("0x{}", "aa".repeat(32))
                },
                "signingRoot": format!("0x{}", "09".repeat(32)),
                "attestation": {
                    "slot": "3200",
                    "index": "2",
                    "beacon_block_root": format!("0x{}", "01".repeat(32)),
                    "source": { "epoch": "99", "root": format!("0x{}", "02".repeat(32)) },
                    "target": { "epoch": "100", "root": format!("0x{}", "03".repeat(32)) }
                }
            })
        );
    }

    #[test]
    fn every_body_names_its_type_and_its_one_field() {
        let data = attestation_data();
        let header = BeaconBlockHeader {
            slot: 3200,
            proposer_index: 7,
            parent_root: Root::repeat_byte(1),
            state_root: Root::repeat_byte(2),
            body_root: Root::repeat_byte(3),
        };
        let cases: Vec<(SigningBody<'_>, &str, &str)> = vec![
            (
                SigningBody::Attestation { attestation: &data },
                "ATTESTATION",
                "attestation",
            ),
            (
                SigningBody::RandaoReveal {
                    randao_reveal: RandaoReveal { epoch: 100 },
                },
                "RANDAO_REVEAL",
                "randao_reveal",
            ),
            (
                SigningBody::Block {
                    beacon_block: VersionedHeader {
                        version: "ELECTRA".to_string(),
                        block_header: header,
                    },
                },
                "BLOCK_V2",
                "beacon_block",
            ),
            (
                SigningBody::AggregationSlot {
                    aggregation_slot: AggregationSlot { slot: 3200 },
                },
                "AGGREGATION_SLOT",
                "aggregation_slot",
            ),
            (
                SigningBody::SyncCommitteeMessage {
                    sync_committee_message: SyncCommitteeMessage {
                        beacon_block_root: Root::ZERO,
                        slot: 3200,
                    },
                },
                "SYNC_COMMITTEE_MESSAGE",
                "sync_committee_message",
            ),
            (
                SigningBody::SyncCommitteeSelectionProof {
                    sync_aggregator_selection_data: SyncAggregatorSelectionData {
                        slot: 3200,
                        subcommittee_index: 1,
                    },
                },
                "SYNC_COMMITTEE_SELECTION_PROOF",
                "sync_aggregator_selection_data",
            ),
        ];
        for (body, kind, field) in cases {
            let encoded = encode(&SigningRequest::new(fork_info(), Root::ZERO, body));
            assert_eq!(encoded["type"], kind);
            assert!(
                encoded.get(field).is_some(),
                "{kind} must carry its message under `{field}`: {encoded}"
            );
            assert_eq!(
                encoded.as_object().expect("object").len(),
                4,
                "{kind}: type, fork_info, signingRoot and the message, nothing else"
            );
        }
    }

    #[test]
    fn a_block_request_carries_the_fork_name_and_the_header_only() {
        let header = BeaconBlockHeader {
            slot: 3200,
            proposer_index: 7,
            parent_root: Root::repeat_byte(1),
            state_root: Root::repeat_byte(2),
            body_root: Root::repeat_byte(3),
        };
        let request = SigningRequest::new(
            fork_info(),
            Root::ZERO,
            SigningBody::Block {
                beacon_block: VersionedHeader {
                    version: "FULU".to_string(),
                    block_header: header,
                },
            },
        );
        assert_eq!(
            encode(&request)["beacon_block"],
            json!({
                "version": "FULU",
                "block_header": {
                    "slot": "3200",
                    "proposer_index": "7",
                    "parent_root": format!("0x{}", "01".repeat(32)),
                    "state_root": format!("0x{}", "02".repeat(32)),
                    "body_root": format!("0x{}", "03".repeat(32))
                }
            })
        );
    }

    #[test]
    fn a_payload_attestation_request_is_versioned_gloas() {
        let data = PayloadAttestationData {
            beacon_block_root: Root::repeat_byte(5),
            slot: 3200,
            payload_present: true,
            blob_data_available: false,
        };
        let request = SigningRequest::new(
            fork_info(),
            Root::ZERO,
            SigningBody::PayloadAttestationMessage {
                payload_attestation_message: Versioned {
                    version: "GLOAS".to_string(),
                    data: &data,
                },
            },
        );
        assert_eq!(
            encode(&request)["payload_attestation_message"],
            json!({
                "version": "GLOAS",
                "data": {
                    "beacon_block_root": format!("0x{}", "05".repeat(32)),
                    "slot": "3200",
                    "payload_present": true,
                    "blob_data_available": false
                }
            })
        );
    }

    #[test]
    fn the_signature_is_read_from_json_or_from_a_bare_string() {
        let hex = format!("0x{}", "ab".repeat(BLS_SIGNATURE_SIZE));
        let from_json =
            parse_signature_body(&format!("{{\"signature\":\"{hex}\"}}")).expect("json");
        let from_text = parse_signature_body(&format!("{hex}\n")).expect("text");
        assert_eq!(from_json, from_text);
        assert_eq!(from_json.0, [0xab; BLS_SIGNATURE_SIZE]);
        assert!(parse_signature_body("0x1234").is_err());
    }

    #[test]
    fn the_url_must_be_http_or_https() {
        assert!(Web3Signer::new("https://signer:9000/").is_ok());
        assert_eq!(
            Web3Signer::new("https://signer:9000/")
                .expect("valid")
                .url(),
            "https://signer:9000"
        );
        assert!(Web3Signer::new("ftp://signer:9000").is_err());
        assert!(Web3Signer::new("signer:9000").is_err());
        assert!(Web3Signer::new("not a url").is_err());
    }
}
