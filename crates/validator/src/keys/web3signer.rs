//! Signing through a Web3Signer remote signer.
//!
//! The key never enters this process: each signature is a `POST
//! /api/v1/eth2/sign/{pubkey}` carrying the message, the fork it is signed
//! under and the signing root, and the signer answers with the signature. The
//! message travels in full rather than as its root alone because the signer
//! keeps a slashing-protection record of its own, beside this client's (see
//! [`crate::slashing_protection`]), and it can only refuse a double vote it
//! can read. The root is sent as well so the signer can check the two agree.
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
use ethlambda_types::beacon::containers::shared::{
    AttestationData, BeaconBlockHeader, Fork, VoluntaryExit,
};
use ethlambda_types::beacon::containers::{electra, gloas};
use ethlambda_types::beacon::primitives::{BLS_SIGNATURE_SIZE, BlsPubkey, BlsSignature, Root};
use serde::Serialize;
use tokio::sync::Semaphore;

use crate::beacon_node::dto::{encode_hex, parse_signature};
use crate::error::{Error, Result};

/// How long one signing request may take. The same bound the beacon node
/// client uses; every duty is cut off by its own slot deadline anyway, and a
/// signer slower than this is one whose signatures arrive too late to count.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);

/// Web3Signer's answer when its slashing protection refused the message.
const SLASHING_PROTECTION_REFUSED: u16 = 412;

/// The most requests one signer is sent at once; the rest of a batch waits
/// its turn.
///
/// The client speaks HTTP/1.1, so every request in flight is a connection of
/// its own. A duty asks for all its signatures together, and uncapped that is
/// a socket per key: a thousand remote keys at an epoch boundary would open a
/// thousand, past the usual 1024 descriptor limit, at which point `connect`
/// fails and every remote signature with it. Capped, a signer costs this many
/// descriptors however many keys it holds, and its connections are reused
/// from one capful to the next. A healthy signer answers in milliseconds, so
/// a thousand signatures still fit many times over in the signing budget.
pub const MAX_CONCURRENT_REQUESTS: usize = 64;

/// One remote signer, shared by every validator whose key it holds.
pub struct Web3Signer {
    base_url: String,
    client: reqwest::Client,
    /// One permit per request in flight; see [`MAX_CONCURRENT_REQUESTS`].
    /// Per signer, so one that is slow holds up only its own keys.
    in_flight: Semaphore,
}

impl Web3Signer {
    /// Build a client for the signer at `url`, which is the server's base
    /// (`https://signer:9000`), not the signing path.
    ///
    /// Building one sets up a TLS configuration and a connection pool, so it
    /// is not free: callers that hold a lock build it before taking the lock
    /// (see [`crate::keys::ValidatorStore::insert_remote_signer`]).
    pub fn new(url: &str) -> Result<Self> {
        Self::with_cap(url, MAX_CONCURRENT_REQUESTS)
    }

    /// [`Self::new`], sent at most `cap` requests at once.
    pub(crate) fn with_cap(url: &str, cap: usize) -> Result<Self> {
        let base_url = url.trim_end_matches('/').to_string();
        // Every error below names the URL as `redact` renders it, never as
        // given: these errors are logged, at startup and on import, and a URL
        // refused for its shape may still carry a `user:password@` that the
        // credentials check further down never got to reject.
        let invalid = |reason: &str| Error::Keystore {
            path: redact(&base_url),
            reason: reason.to_string(),
        };
        let parsed = reqwest::Url::parse(&base_url)
            .map_err(|err| invalid(&format!("not a valid remote signer URL: {err}")))?;
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return Err(invalid("a remote signer URL must be http or https"));
        }
        // The URL is named in every error this client raises about the
        // signer, and those are logged. Credentials embedded in it would be
        // logged with them, so they are refused rather than redacted: the
        // signer's own authentication is TLS, not basic auth.
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(invalid("a remote signer URL must not carry credentials"));
        }
        // The signing path is appended to the base, so a query or fragment
        // would swallow it (`https://signer?token=abc` would request `/`), and
        // a token in the query would be logged with every signing error.
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(invalid(
                "a remote signer URL must not carry a query string or fragment",
            ));
        }
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|err| invalid(&format!("could not build an HTTP client: {err}")))?;
        Ok(Self {
            base_url,
            client,
            in_flight: Semaphore::new(cap),
        })
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

        // Held until the answer is read. Waiting for one is part of what the
        // caller's deadline bounds, and a request dropped at that deadline
        // gives its permit back at once.
        let _permit = self.in_flight.acquire().await.map_err(|_| {
            failed(format!(
                "remote signer {} is no longer in use",
                self.base_url
            ))
        })?;
        // The round trip alone, from here to the answer or the failure: the
        // wait for a permit above is this client's own queue, not the signer.
        let _timing = crate::metrics::time_remote_signer_request();

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
                truncate(body.trim())
            )));
        }

        parse_signature_body(&body)
            .map_err(|err| failed(format!("remote signer {}: {err}", self.base_url)))
    }
}

/// The most of a failed response's body that goes into an error, and so into
/// a log line: enough to say why, not a whole error page.
const MAX_LOGGED_BODY: usize = 200;

fn truncate(body: &str) -> String {
    match body.char_indices().nth(MAX_LOGGED_BODY) {
        Some((cut, _)) => format!("{}...", &body[..cut]),
        None => body.to_string(),
    }
}

/// `url` with anything that could be a credential cut out, for an error
/// message: the userinfo before an `@` in the authority, and any query string
/// or fragment. Works on text rather than a parsed URL, since it is what
/// reports a URL that does not parse.
fn redact(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (Some(scheme), rest),
        None => (None, url),
    };
    let rest = rest.split(['?', '#']).next().unwrap_or_default();
    let (authority, path) = match rest.find('/') {
        Some(cut) => rest.split_at(cut),
        None => (rest, ""),
    };
    let host = match authority.rsplit_once('@') {
        Some((_, host)) => host,
        None => authority,
    };
    match scheme {
        Some(scheme) => format!("{scheme}://{host}{path}"),
        None => format!("{host}{path}"),
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
    VoluntaryExit {
        voluntary_exit: &'a VoluntaryExit,
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
            Self::VoluntaryExit { .. } => "VOLUNTARY_EXIT",
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
        let exit = VoluntaryExit {
            epoch: 100,
            validator_index: 7,
        };
        let cases: Vec<(SigningBody<'_>, &str, &str)> = vec![
            (
                SigningBody::Attestation { attestation: &data },
                "ATTESTATION",
                "attestation",
            ),
            (
                SigningBody::VoluntaryExit {
                    voluntary_exit: &exit,
                },
                "VOLUNTARY_EXIT",
                "voluntary_exit",
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

    /// Web3Signer's `VoluntaryExit` schema: both fields quoted integers.
    #[test]
    fn a_voluntary_exit_request_has_web3signers_shape() {
        let exit = VoluntaryExit {
            epoch: 269_568,
            validator_index: 1234,
        };
        let encoded = encode(&SigningRequest::new(
            fork_info(),
            Root::repeat_byte(0x11),
            SigningBody::VoluntaryExit {
                voluntary_exit: &exit,
            },
        ));
        assert_eq!(encoded["type"], "VOLUNTARY_EXIT");
        assert_eq!(
            encoded["voluntary_exit"],
            serde_json::json!({ "epoch": "269568", "validator_index": "1234" })
        );
        assert_eq!(
            encoded["signingRoot"],
            format!("0x{}", "11".repeat(32)),
            "the root travels, so the signer can refuse one it does not derive itself"
        );
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
    fn a_failed_response_body_is_cut_short_before_it_is_reported() {
        let long = "x".repeat(1_000);
        assert_eq!(truncate(&long).len(), MAX_LOGGED_BODY + 3);
        assert_eq!(truncate("short"), "short");
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
        let Err(err) = Web3Signer::new("https://user:secret@signer:9000") else {
            panic!("a URL carrying credentials must be refused");
        };
        assert!(!err.to_string().contains("secret"), "{err}");
        assert!(Web3Signer::new("signer:9000").is_err());
        assert!(Web3Signer::new("not a url").is_err());
    }

    /// A URL refused for its shape must not put its credentials into the
    /// error either: the scheme and parse checks run before the credentials
    /// one, and every one of these errors is logged.
    #[test]
    fn no_refusal_echoes_the_urls_credentials() {
        for url in [
            "ftp://admin:s3cret@signer:9000",
            "https://admin:s3cret@signer:notaport",
            "https://admin:s3cret@signer:9000",
            "https://signer:9000?token=s3cret",
            "https://signer:9000/#s3cret",
        ] {
            let Err(err) = Web3Signer::new(url) else {
                panic!("{url} must be refused");
            };
            assert!(!err.to_string().contains("s3cret"), "{url}: {err}");
        }
    }

    #[test]
    fn a_url_with_a_query_or_fragment_is_refused() {
        assert!(Web3Signer::new("https://signer:9000?token=abc").is_err());
        assert!(Web3Signer::new("https://signer:9000/#frag").is_err());
        assert!(Web3Signer::new("https://signer:9000/prefix").is_ok());
    }

    #[test]
    fn redaction_keeps_the_host_and_path_only() {
        assert_eq!(
            redact("https://user:pw@signer:9000/base?x=1#y"),
            "https://signer:9000/base"
        );
        assert_eq!(redact("signer:9000"), "signer:9000");
        assert_eq!(redact("a@b"), "b");
    }
}
