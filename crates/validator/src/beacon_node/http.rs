//! The Beacon API over HTTP.
//!
//! # Which error a failure becomes
//!
//! Two of this crate's variants could plausibly claim a bad response, so the
//! split is fixed here rather than decided per call site:
//!
//! - `BeaconNodeFailure::classify` is called **only** on a `send` failure, so
//!   it only ever describes transport: a timeout, a refused connection, a body
//!   that stopped arriving. That is a property of the node or the network.
//! - A response that arrives whole but does not deserialise is
//!   `Error::Decode`. That is a property of what the node said.
//! - A response that deserialises but contradicts what was asked for is
//!   `Error::InconsistentResponse`, raised here. It used to be raised by the
//!   caller, which was wrong for one specific reason: `FallbackBeaconNode`
//!   wraps these methods, so a check above them runs only after this node's
//!   answer has already been accepted, and the next node is never tried. See
//!   the contract on `BeaconNodeApi::attestation_data`.
//!
//! Keeping `classify` off the `json` path is what stops `reqwest`'s own
//! `is_decode` from competing with `Error::Decode` for the same failure.

use std::time::Duration;

use async_trait::async_trait;
use ethlambda_types::beacon::builder::SignedValidatorRegistrationV1;
use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::containers::altair;
use ethlambda_types::beacon::containers::electra::Attestation;
use ethlambda_types::beacon::containers::gloas;
use ethlambda_types::beacon::containers::shared::{AttestationData, SignedVoluntaryExit};
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::primitives::{BlsPubkey, Epoch, Root, Slot, ValidatorIndex};
use reqwest::{Client, StatusCode};
use serde::Serialize;
use tracing::{debug, warn};

use libssz::SszDecode as _;

use crate::beacon_node::block_contents::{ProducedBlock, Producer};
use crate::beacon_node::dto::{
    AttestationDataDto, AttestationDto, AttesterDutyDto, BlockRootResponse,
    CommitteeSubscriptionDto, DataResponse, DutiesResponse, ErrorMessageDto, GenesisDto,
    IndexedErrorResponse, LivenessDto, ProduceBlockV3Response, ProposerDutyDto,
    ProposerPreparationDto, PtcDutyDto, SignedAggregateAndProofOutDto, SingleAttestationDto,
    SyncCommitteeSubscriptionDto, SyncDutyDto, SyncingDto, ValidatorDetailsDto, ValidatorEntryDto,
    VersionedResponse, config_from_spec_response, encode_hex, parse_pubkey, parse_root,
};
use crate::beacon_node::{
    AggregateAttestation, AggregateKind, AttesterDuties, BeaconNodeApi, BlockRequest, Delivery,
    Genesis, Liveness, ProposerDuties, PtcDuties, Published, SignedAggregates, ValidatorDetails,
    ValidatorEntry, validate_attestation_data, validate_liveness, validate_produced_block,
    validate_sync_contribution,
};
use crate::error::{BeaconNodeFailure, Error, Result};

/// How long any single request may take.
///
/// A fixed 8 seconds, sized for mainnet-family slot times (12 seconds and up);
/// it is not derived from the network's configured slot duration, which is
/// only known after a successful [`HttpBeaconNode::spec`] call through this
/// same client. A network with shorter slots would need this revisited, since
/// a stalled request could then outlive the slot it was serving.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);

/// How long establishing a connection (TCP, and TLS for `https`) may take,
/// within [`REQUEST_TIMEOUT`].
///
/// Its own bound so that a node that cannot be reached fails as a connect
/// error, which says the request never left, rather than as the total
/// timeout, which cannot say whether it did. That difference decides how a
/// blinded publish is reported: a block that never reached the node is a
/// missed proposal, while one the node may have handed to its relay is
/// unconfirmed (see [`BeaconNodeApi::publish_blinded_block`]). Without it, an
/// unreachable producing node counted a slot that was certainly missed as one
/// the relay might still publish.
///
/// Three seconds is far beyond a healthy handshake, local or across a
/// continent, and leaves most of the request budget to the answer.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// How long `register_validator` may take. Longer than [`REQUEST_TIMEOUT`]
/// because an ethlambda node forwards the registrations to its relay and waits
/// up to 10 s for the answer before replying; a client that gave up at 8 s
/// would report a failure for a registration the node went on to install.
const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(12);

/// How much of a failed answer's body is read. Enough for a pool submission's
/// 400, which lists each refused entry and is parsed for them.
const ERROR_BODY_READ_LIMIT: usize = 1024 * 1024;

/// How much of a failed answer's body an error carries, and so a log line.
const ERROR_TEXT_LIMIT: usize = 1024;

/// A failed answer's body, read up to [`ERROR_BODY_READ_LIMIT`] bytes, so a
/// node answering with an endless body cannot hold the client on it. Only
/// what fits is copied out of each chunk.
async fn read_error_body(mut response: reqwest::Response) -> String {
    let mut bytes = Vec::new();
    while let Ok(Some(chunk)) = response.chunk().await {
        let room = ERROR_BODY_READ_LIMIT - bytes.len();
        bytes.extend_from_slice(&chunk[..chunk.len().min(room)]);
        if bytes.len() == ERROR_BODY_READ_LIMIT {
            break;
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Text a node sent, as an error or a log line shows it: control characters
/// and line separators written out (`\n`, `\u{1b}`, ...), so the line it lands
/// in stays one line and carries no terminal escapes, and cut to
/// [`ERROR_TEXT_LIMIT`] bytes without splitting a character or an escape,
/// ending in `...` when it is cut.
///
/// The same function the beacon node's builder client writes a relay's text
/// through, [`ethlambda_types::text::one_line`].
fn error_text(text: &str) -> String {
    ethlambda_types::text::one_line(text, ERROR_TEXT_LIMIT)
}

/// [`read_error_body`] as [`error_text`] shows it.
async fn error_body(response: reqwest::Response) -> String {
    error_text(&read_error_body(response).await)
}

/// What an SSZ answer carries besides its bytes: the fork, which only a header
/// can say, and the two booleans the block endpoints use to say what the bytes
/// are.
struct SszResponse {
    fork: ForkName,
    /// `Eth-Execution-Payload-Blinded`, sent by `produceBlockV3` only.
    blinded: Option<bool>,
    /// `Eth-Execution-Payload-Included`, sent by `produceBlockV4` only.
    payload_included: Option<bool>,
    body: Vec<u8>,
}

/// `produceBlockV3`'s `Accept`: SSZ preferred, JSON taken. The
/// specification's own example. See [`HttpBeaconNode::get_block_v3`] for why
/// JSON is named at all.
const SSZ_OR_JSON: &str = "application/octet-stream;q=1.0,application/json;q=0.9";

/// What `produceBlockV3` answered, in either encoding: the fork, whether the
/// block is blinded, and the body, still to be decoded as the container those
/// two select.
struct BlockAnswer {
    fork: ForkName,
    blinded: bool,
    body: BlockBody,
}

enum BlockBody {
    Ssz(Vec<u8>),
    /// The answer's `data`, the rest of its body already read.
    Json(serde_json::Value),
}

/// Whether `content_type` names `media_type`, ignoring case and any
/// parameters (`application/json; charset=utf-8` names `application/json`).
fn is_media_type(content_type: &str, media_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .is_some_and(|named| named.trim().eq_ignore_ascii_case(media_type))
}

/// The body `produceBlockV4` requires: the node decodes it, as the
/// specification demands, even when it builds locally.
///
/// `builders` stays empty, since the builder API (relay or `builder_pubkeys`
/// bids) is a later phase. The top-level `min_bid` and factor govern the pooled
/// p2p bids. The factor is the configured `builder_boost_factor` with
/// `--builder-proposals`, so such a bid can win on value, and `0` without it:
/// the local payload unless it cannot be built, as beacon-APIs defines `0`.
/// A node whose local build fails may then still build on a pooled bid (see
/// `proposal.rs`'s module doc for why that block is signed). `min_bid` is
/// `--builder-min-bid`, in gwei, the floor below which no p2p bid is taken,
/// with or without builder proposals, so it also bounds that fallback.
fn builder_config(boost_factor: Option<u64>, min_bid: u64) -> String {
    let factor = boost_factor.unwrap_or(0);
    format!(r#"{{"min_bid":"{min_bid}","builder_boost_factor":"{factor}","builders":[]}}"#)
}

/// A [`BeaconNodeApi`] backed by one beacon node's standard REST Beacon API.
pub struct HttpBeaconNode {
    base_url: String,
    client: Client,
}

impl HttpBeaconNode {
    /// Builds a client for the node at `base_url`, stripping any trailing
    /// slash so callers may pass either form.
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        Self::with_connect_timeout(base_url, CONNECT_TIMEOUT)
    }

    /// [`Self::new`] with `connect_timeout` in place of [`CONNECT_TIMEOUT`],
    /// so a test can see a connect timeout without waiting three seconds.
    fn with_connect_timeout(
        base_url: impl Into<String>,
        connect_timeout: Duration,
    ) -> Result<Self> {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        let client = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(connect_timeout)
            .build()
            .map_err(|err| Error::BeaconNode {
                url: base_url.clone(),
                failure: BeaconNodeFailure::classify(&err),
                detail: err.to_string(),
            })?;
        Ok(Self { base_url, client })
    }

    /// The node's base URL, with any trailing slash already stripped.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}{path}", self.base_url);
        debug!(%url, "Beacon API GET");
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|err| Error::BeaconNode {
                url: url.clone(),
                failure: BeaconNodeFailure::classify(&err),
                detail: err.to_string(),
            })?;
        Self::decode(response).await
    }

    async fn post<B: Serialize, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        consensus_version: Option<&str>,
    ) -> Result<T> {
        let url = format!("{}{path}", self.base_url);
        debug!(%url, "Beacon API POST");
        let mut request = self.client.post(&url).json(body);
        if let Some(version) = consensus_version {
            request = request.header("Eth-Consensus-Version", version);
        }
        let response = request.send().await.map_err(|err| Error::BeaconNode {
            url: url.clone(),
            failure: BeaconNodeFailure::classify(&err),
            detail: err.to_string(),
        })?;
        Self::decode(response).await
    }

    /// POST where the beacon node answers with an empty body on success.
    async fn post_no_content<B: Serialize>(
        &self,
        path: &str,
        body: &B,
        consensus_version: Option<&str>,
    ) -> Result<()> {
        self.post_no_content_within(path, body, consensus_version, None)
            .await
    }

    /// [`Self::post_no_content`] with `timeout` in place of the client's
    /// default, when given.
    async fn post_no_content_within<B: Serialize>(
        &self,
        path: &str,
        body: &B,
        consensus_version: Option<&str>,
        timeout: Option<Duration>,
    ) -> Result<()> {
        let url = format!("{}{path}", self.base_url);
        let mut request = self.client.post(&url).json(body);
        if let Some(version) = consensus_version {
            request = request.header("Eth-Consensus-Version", version);
        }
        if let Some(timeout) = timeout {
            request = request.timeout(timeout);
        }
        let response = request.send().await.map_err(|err| Error::BeaconNode {
            url: url.clone(),
            failure: BeaconNodeFailure::classify(&err),
            detail: err.to_string(),
        })?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let body = error_body(response).await;
        Err(Error::BeaconNodeStatus {
            status: status.as_u16(),
            body,
        })
    }

    /// POST an SSZ body with the fork it is for, returning the URL beside the
    /// outcome so each caller maps a transport failure its own way: a full
    /// block's is an ordinary error, a blinded block's may be unconfirmed.
    async fn post_ssz_body(
        &self,
        path: &str,
        fork: ForkName,
        body: &[u8],
    ) -> (
        String,
        std::result::Result<reqwest::Response, reqwest::Error>,
    ) {
        let url = format!("{}{path}", self.base_url);
        let sent = self
            .client
            .post(&url)
            .header("Eth-Consensus-Version", fork.as_str())
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(body.to_vec())
            .send()
            .await;
        (url, sent)
    }

    /// Fetch a body as SSZ, returning the fork the node named alongside it.
    ///
    /// For what this client decodes from SSZ only: today the gloas payload
    /// envelope. `produceBlockV3` is not fetched through here; it takes JSON
    /// as well and goes through [`Self::get_block_v3`].
    ///
    /// `Accept` names SSZ alone, deliberately narrower than the specification's
    /// own example. That example, [`SSZ_OR_JSON`], says JSON is acceptable at
    /// lower preference, which is the right header for a request whose answer
    /// this client can decode either way. For one it can only decode from SSZ,
    /// a node taking the `q=0.9` offer would be answering correctly and failing
    /// the request on every node in the failover list. (Aggregates do not come
    /// through here either; they are fetched as JSON, because Lighthouse sends
    /// JSON for them regardless.)
    ///
    /// Naming only what can be decoded makes 406 the node's one legal way out,
    /// and `send_for_answer` turns that into an ordinary error failover moves
    /// past. The content-type check in [`Self::ssz_answer`] stays as the
    /// backstop for a node that ignores the header entirely.
    ///
    /// The fork comes back from `Eth-Consensus-Version` because it cannot come
    /// from the bytes: SSZ carries no type tag. A missing or unrecognised
    /// header is therefore a hard error, not a default, since guessing the
    /// fork means decoding a block into the wrong shape and signing whatever
    /// root that produces. The comparison is case-insensitive: the schema's
    /// enum is lowercase but nothing in the specification says a client must
    /// match it that way.
    async fn get_ssz(&self, path: &str) -> Result<SszResponse> {
        let url = format!("{}{path}", self.base_url);
        debug!(%url, "Beacon API GET (ssz)");
        let request = self
            .client
            .get(&url)
            .header(reqwest::header::ACCEPT, "application/octet-stream");
        Self::read_ssz(url, request).await
    }

    /// POST a JSON body and read the answer as SSZ, the way [`Self::get_ssz`]
    /// does. For `produceBlockV4`, which is a POST because it carries the
    /// builder configuration.
    ///
    /// SSZ alone, unlike `produceBlockV3`: this client has no JSON path for a
    /// gloas block, and has not needed one, since the proxy that made it add
    /// one for `produceBlockV3` (blobber, see [`Self::get_block_v3`]) does not
    /// intercept this endpoint.
    async fn post_json_for_ssz(
        &self,
        path: &str,
        json_body: String,
        consensus_version: &str,
    ) -> Result<SszResponse> {
        let url = format!("{}{path}", self.base_url);
        debug!(%url, "Beacon API POST (json in, ssz out)");
        let request = self
            .client
            .post(&url)
            .header(reqwest::header::ACCEPT, "application/octet-stream")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header("Eth-Consensus-Version", consensus_version)
            .body(json_body);
        Self::read_ssz(url, request).await
    }

    async fn read_ssz(url: String, request: reqwest::RequestBuilder) -> Result<SszResponse> {
        let response = Self::send_for_answer(&url, request).await?;
        Self::ssz_answer(url, response).await
    }

    /// Send `request` and hand back the answer when it is a success. A 503 is
    /// the node syncing; any other failure status is an error carrying the
    /// body.
    async fn send_for_answer(
        url: &str,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response> {
        let response = request.send().await.map_err(|err| Error::BeaconNode {
            url: url.to_string(),
            failure: BeaconNodeFailure::classify(&err),
            detail: err.to_string(),
        })?;

        let status = response.status();
        if status == StatusCode::SERVICE_UNAVAILABLE {
            return Err(Error::BeaconNodeSyncing);
        }
        if !status.is_success() {
            let body = error_body(response).await;
            return Err(Error::BeaconNodeStatus {
                status: status.as_u16(),
                body,
            });
        }
        Ok(response)
    }

    /// A successful answer read as SSZ, with the headers that say what its
    /// bytes are.
    async fn ssz_answer(url: String, response: reqwest::Response) -> Result<SszResponse> {
        let header = |name: &str| Self::header(&response, name);

        // A node that ignored the Accept header and sent JSON would otherwise
        // reach the SSZ decoder as bytes that happen not to parse, and be
        // reported as a malformed block rather than as the content-type
        // mismatch it is.
        if let Some(content_type) = header(reqwest::header::CONTENT_TYPE.as_str())
            && !is_media_type(&content_type, "application/octet-stream")
        {
            return Err(Error::InconsistentResponse(format!(
                "asked for SSZ, node answered with {content_type}"
            )));
        }

        let version = header("eth-consensus-version").ok_or_else(|| {
            Error::InconsistentResponse(
                "response carries no Eth-Consensus-Version, so the fork it encodes is unknown"
                    .to_string(),
            )
        })?;
        let fork = Self::known_fork(&version, "Eth-Consensus-Version")?;

        // Reported, not judged. Each is sent by one endpoint only, so requiring
        // it here would break every other caller of this helper; whether its
        // absence matters is the caller's question.
        let blinded = Self::bool_header(header("eth-execution-payload-blinded"), "Blinded")?;
        let payload_included =
            Self::bool_header(header("eth-execution-payload-included"), "Included")?;

        let body = Self::answer_bytes(url, response).await?;
        Ok(SszResponse {
            fork,
            blinded,
            payload_included,
            body,
        })
    }

    /// GET `produceBlockV3`, taking the answer as SSZ or as JSON.
    ///
    /// `Accept` is [`SSZ_OR_JSON`], where every other SSZ fetch names SSZ
    /// alone (see [`Self::get_ssz`]). A node honouring it answers SSZ, which is
    /// read exactly as before. JSON is named because a proxy can make it the
    /// only answer: ethereum-package's blobber (marioevz/blobber v1.1.0,
    /// `validator_proxy/proxy.go`) sits between a validator client and its
    /// node, rewrites `Accept` to `application/json` on this endpoint and on
    /// `/eth/v2/validator/blocks/{slot}`, and relays the node's answer, headers
    /// included, unchanged. A client taking SSZ alone lost every proposal
    /// behind it.
    ///
    /// Which encoding arrived is read off `Content-Type`.
    /// `application/octet-stream`, or no content type at all, is SSZ, as for
    /// [`Self::get_ssz`]; `application/json` is JSON, read by
    /// [`Self::json_block_answer`]; anything else is refused rather than
    /// guessed at.
    async fn get_block_v3(&self, path: &str) -> Result<BlockAnswer> {
        let url = format!("{}{path}", self.base_url);
        debug!(%url, "Beacon API GET (ssz or json)");
        let request = self
            .client
            .get(&url)
            .header(reqwest::header::ACCEPT, SSZ_OR_JSON);
        let response = Self::send_for_answer(&url, request).await?;

        match Self::header(&response, reqwest::header::CONTENT_TYPE.as_str()) {
            Some(content_type) if is_media_type(&content_type, "application/json") => {
                Self::json_block_answer(url, response).await
            }
            Some(content_type) if !is_media_type(&content_type, "application/octet-stream") => {
                Err(Error::InconsistentResponse(format!(
                    "asked for SSZ or JSON, node answered with {content_type}"
                )))
            }
            _ => {
                let SszResponse {
                    fork,
                    blinded,
                    body,
                    ..
                } = Self::ssz_answer(url, response).await?;
                // Required on this endpoint, so its absence is an error rather
                // than a default. The specification marks it required precisely
                // because it selects which container the bytes are, and a
                // blinded body is a different shape entirely; guessing
                // "unblinded" would send a blinded answer to the decoder and
                // surface it as an opaque malformed block.
                let blinded = blinded.ok_or_else(|| {
                    Error::InconsistentResponse(
                        "response carries no Eth-Execution-Payload-Blinded, so whether it is a \
                         block or a blinded block is unknown"
                            .to_string(),
                    )
                })?;
                Ok(BlockAnswer {
                    fork,
                    blinded,
                    body: BlockBody::Ssz(body),
                })
            }
        }
    }

    /// A successful `produceBlockV3` answer read as JSON, into the same
    /// [`BlockAnswer`] an SSZ one gives.
    ///
    /// The fork comes from the body's `version`, falling back on
    /// `Eth-Consensus-Version`, and whether the block is blinded from
    /// `execution_payload_blinded`, falling back on
    /// `Eth-Execution-Payload-Blinded`. The specification requires both body
    /// fields, and both headers beside them; a header only stands in for a
    /// field the body left out, since it says the same thing.
    ///
    /// When a field and its header are both present they must agree. A node
    /// naming two forks, or calling a block both blinded and not, has not said
    /// which container `data` is, and decoding it as either one risks signing a
    /// root that is not the block's; as an `Err` it is one failover moves past.
    /// When neither is present the answer is refused, as an SSZ answer missing
    /// the header is.
    ///
    /// A body that is not a block answer but the specification's error
    /// message is the error it reports (see [`Self::relayed_error`]).
    async fn json_block_answer(url: String, response: reqwest::Response) -> Result<BlockAnswer> {
        let header_version = Self::header(&response, "eth-consensus-version");
        let header_blinded = Self::bool_header(
            Self::header(&response, "eth-execution-payload-blinded"),
            "Blinded",
        )?;
        let bytes = Self::answer_bytes(url, response).await?;
        let answer: ProduceBlockV3Response = serde_json::from_slice(&bytes).map_err(|err| {
            Self::relayed_error(&bytes)
                .unwrap_or_else(|| Error::Decode(format!("produceBlockV3 JSON answer: {err}")))
        })?;

        let fork = match (answer.version, header_version) {
            (Some(version), Some(header)) => {
                let fork = Self::known_fork(&version, "the answer's version")?;
                if Self::known_fork(&header, "Eth-Consensus-Version")? != fork {
                    return Err(Error::InconsistentResponse(format!(
                        "the answer's version names fork {version} and its \
                         Eth-Consensus-Version fork {header}"
                    )));
                }
                fork
            }
            (Some(version), None) => Self::known_fork(&version, "the answer's version")?,
            (None, Some(header)) => Self::known_fork(&header, "Eth-Consensus-Version")?,
            (None, None) => {
                return Err(Error::InconsistentResponse(
                    "answer names its fork in neither its version nor Eth-Consensus-Version, so \
                     the fork its data encodes is unknown"
                        .to_string(),
                ));
            }
        };

        let blinded = match (answer.execution_payload_blinded, header_blinded) {
            (Some(body), Some(header)) if body != header => {
                return Err(Error::InconsistentResponse(format!(
                    "the answer's execution_payload_blinded is {body} and its \
                     Eth-Execution-Payload-Blinded {header}"
                )));
            }
            (body, header) => body.or(header).ok_or_else(|| {
                Error::InconsistentResponse(
                    "answer says in neither execution_payload_blinded nor \
                     Eth-Execution-Payload-Blinded whether it is a block or a blinded block"
                        .to_string(),
                )
            })?,
        };

        Ok(BlockAnswer {
            fork,
            blinded,
            body: BlockBody::Json(answer.data),
        })
    }

    /// The error a success answer's body reports, when the body is the
    /// specification's `ErrorMessage` with a 4xx or 5xx `code`: what
    /// [`Self::send_for_answer`] would have returned had the status said it.
    ///
    /// blobber (`validator_proxy/proxy.go`, `proxyHandler`) relays the node's
    /// headers and body but never its status, so a node failing
    /// `produceBlockV3` behind it answers `200 application/json` with the
    /// failure in the body. Read as a block answer that is a missing `data`, a
    /// malformed block rather than the node's own error, and a syncing node
    /// would stop being reported as one.
    fn relayed_error(bytes: &[u8]) -> Option<Error> {
        let error: ErrorMessageDto = serde_json::from_slice(bytes).ok()?;
        if !(400..600).contains(&error.code) {
            return None;
        }
        if error.code == StatusCode::SERVICE_UNAVAILABLE.as_u16() {
            return Some(Error::BeaconNodeSyncing);
        }
        Some(Error::BeaconNodeStatus {
            status: error.code,
            body: error_text(&String::from_utf8_lossy(bytes)),
        })
    }

    /// The header `name`, when present and readable as text.
    fn header(response: &reqwest::Response, name: &str) -> Option<String> {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    }

    /// The fork `version` names, `named_by` saying where it was read for the
    /// error when this client does not know it.
    fn known_fork(version: &str, named_by: &str) -> Result<ForkName> {
        ForkName::parse(&version.to_ascii_lowercase()).ok_or_else(|| {
            Error::InconsistentResponse(format!(
                "{named_by} names fork {version}, which this client does not know"
            ))
        })
    }

    /// A successful answer's whole body.
    async fn answer_bytes(url: String, response: reqwest::Response) -> Result<Vec<u8>> {
        let body = response.bytes().await.map_err(|err| Error::BeaconNode {
            url,
            failure: BeaconNodeFailure::classify(&err),
            detail: err.to_string(),
        })?;
        Ok(body.to_vec())
    }

    /// A `true`/`false` header, `None` when absent, an error when it is
    /// anything else.
    fn bool_header(value: Option<String>, name: &str) -> Result<Option<bool>> {
        match value {
            Some(value) if value.eq_ignore_ascii_case("true") => Ok(Some(true)),
            Some(value) if value.eq_ignore_ascii_case("false") => Ok(Some(false)),
            Some(value) => Err(Error::InconsistentResponse(format!(
                "Eth-Execution-Payload-{name} is {value}, expected true or false"
            ))),
            None => Ok(None),
        }
    }

    /// A GET for which the `absent` status is an answer ("nothing to report")
    /// and not a failure: a 204 from an endpoint that has nothing yet, a 404
    /// from one asked about something the node does not know.
    async fn get_optional<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        absent: StatusCode,
    ) -> Result<Option<T>> {
        let url = format!("{}{path}", self.base_url);
        debug!(%url, "Beacon API GET");
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|err| Error::BeaconNode {
                url: url.clone(),
                failure: BeaconNodeFailure::classify(&err),
                detail: err.to_string(),
            })?;
        if response.status() == absent {
            return Ok(None);
        }
        Self::decode(response).await.map(Some)
    }

    /// `produceBlockV4`: a POST carrying the builder configuration, asking for
    /// the self-built payload to be included.
    ///
    /// `include_payload=true` saves the proposal a round trip, which matters
    /// because the whole proposal, envelope included, has to fit before the
    /// attesters' deadline. The node says whether it complied in
    /// `Eth-Execution-Payload-Included`, and a missing header is an error for
    /// the reason the blinded flag's absence is on the v3 path: it selects which
    /// container the bytes are.
    async fn produce_gloas_block(&self, request: &BlockRequest) -> Result<ProducedBlock> {
        let path = format!(
            "/eth/v4/validator/blocks/{}?randao_reveal={}&graffiti={}&include_payload=true",
            request.slot,
            encode_hex(&request.randao_reveal.0),
            encode_hex(&request.graffiti.0),
        );
        let response = self
            .post_json_for_ssz(
                &path,
                builder_config(request.builder_boost_factor, request.builder_min_bid),
                request.fork.as_str(),
            )
            .await?;
        if response.fork != ForkName::Gloas {
            return Err(Error::InconsistentResponse(format!(
                "asked for a gloas block for slot {}, node answered with a {} one",
                request.slot,
                response.fork.as_str()
            )));
        }
        let included = response.payload_included.ok_or_else(|| {
            Error::InconsistentResponse(
                "response carries no Eth-Execution-Payload-Included, so whether the body is \
                 block contents or a bare block is unknown"
                    .to_string(),
            )
        })?;
        let block = ProducedBlock::from_gloas_ssz(included, &response.body)?;
        // Enforced here rather than at the call site so failover works: see the
        // contract on `BeaconNodeApi::produce_block`.
        validate_produced_block(request, &block)?;
        Ok(block)
    }

    /// The path for one slot's attestation data, the same at every fork.
    ///
    /// `committee_index=0` is sent even at gloas slots, against the Beacon
    /// API's "for slots in Gloas and later, this parameter SHOULD be omitted".
    /// Lighthouse (v8.3.3, and `unstable`) still declares the parameter
    /// required and answers a query without it with a 400, which would cost
    /// every gloas attestation against a Lighthouse node. Sending it is safe:
    /// Lighthouse's handler produces the data for committee 0 whatever the
    /// query names, ethlambda's own beacon node ignores the parameter, and the
    /// answer's `index` is the payload signal whatever was asked. Omit it at
    /// gloas once Lighthouse accepts a query without it.
    fn attestation_data_path(slot: Slot) -> String {
        format!("/eth/v1/validator/attestation_data?slot={slot}&committee_index=0")
    }

    /// The query string for one aggregate.
    ///
    /// A pure function so it can be asserted on directly. It is built with a
    /// string continuation, and Rust strips the newline *and* the following
    /// indentation, so a misplaced one would put a space inside a query
    /// parameter. The beacon node would then answer about a different
    /// committee, or 400, with nothing in this client naming the cause.
    fn aggregate_path(slot: Slot, attestation_data_root: Root, committee_index: u64) -> String {
        format!(
            "/eth/v2/validator/aggregate_attestation?attestation_data_root={}&slot={slot}\
             &committee_index={committee_index}",
            encode_hex(&attestation_data_root.0),
        )
    }

    /// The query string for one sync committee contribution.
    ///
    /// A pure function for the reason [`Self::aggregate_path`] is.
    fn sync_contribution_path(
        slot: Slot,
        subcommittee_index: u64,
        beacon_block_root: Root,
    ) -> String {
        format!(
            "/eth/v1/validator/sync_committee_contribution?slot={slot}\
             &subcommittee_index={subcommittee_index}&beacon_block_root={}",
            encode_hex(&beacon_block_root.0),
        )
    }

    /// Turn a non-2xx response from the pool-attestations endpoint into
    /// either a partial success or an error.
    ///
    /// Split out from `submit_attestations` as a pure function of the status
    /// and body text, so a batch's partial-failure body can be exercised in a
    /// unit test with no real HTTP round trip involved.
    ///
    /// A 400 whose body parses as [`IndexedErrorResponse`] and names fewer
    /// failures than `submitted` is a partial success: the beacon node has
    /// already stored and gossiped whichever entries were not in the list, so
    /// this returns `Ok` with that count rather than collapsing it into one
    /// opaque error the way `post_no_content` would, which would make
    /// `inc_attestations_published` never fire for a batch that mostly
    /// succeeded. Anything else, a total rejection, an unparsable body, or a
    /// different status, is still reported as `Err`, unchanged from before.
    fn handle_pool_submission(status: StatusCode, body: String, submitted: usize) -> Result<usize> {
        if status == StatusCode::BAD_REQUEST
            && let Ok(error) = serde_json::from_str::<IndexedErrorResponse>(&body)
        {
            let failed = error.failures.len();
            if failed > 0 && failed < submitted {
                for failure in &error.failures {
                    // The node's text, so written out and capped like a whole
                    // error body: one line per failure, whatever it sent.
                    warn!(
                        submission_index = failure.index,
                        reason = %error_text(&failure.message),
                        "One attestation in this slot's batch was rejected"
                    );
                }
                return Ok(submitted - failed);
            }
        }

        Err(Error::BeaconNodeStatus {
            status: status.as_u16(),
            body: error_text(&body),
        })
    }

    /// The proposer duties for `epoch` at the endpoint's `version` (`v1` or
    /// `v2`), which differ only in which `dependent_root` they report.
    async fn proposer_duties_at(&self, version: &str, epoch: Epoch) -> Result<ProposerDuties> {
        let response: DutiesResponse<Vec<ProposerDutyDto>> = self
            .get(&format!("/eth/{version}/validator/duties/proposer/{epoch}"))
            .await?;
        Ok(ProposerDuties {
            dependent_root: parse_root(&response.dependent_root)?,
            duties: response.data,
        })
    }

    async fn decode<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> Result<T> {
        let status = response.status();
        if status == StatusCode::SERVICE_UNAVAILABLE {
            return Err(Error::BeaconNodeSyncing);
        }
        if !status.is_success() {
            let body = error_body(response).await;
            return Err(Error::BeaconNodeStatus {
                status: status.as_u16(),
                body,
            });
        }
        response
            .json()
            .await
            .map_err(|err| Error::Decode(err.to_string()))
    }
}

#[async_trait]
impl BeaconNodeApi for HttpBeaconNode {
    /// Fetches the chain's genesis time and validators root.
    async fn genesis(&self) -> Result<Genesis> {
        let response: DataResponse<GenesisDto> = self.get("/eth/v1/beacon/genesis").await?;
        Ok(Genesis {
            genesis_time: response.data.genesis_time,
            genesis_validators_root: parse_root(&response.data.genesis_validators_root)?,
        })
    }

    /// Fetches the network's configuration, as far as this client reads it.
    ///
    /// The spec endpoint returns every configuration value as a quoted
    /// string. Only the keys [`config_from_spec_response`] names are read
    /// (the fork schedule, the slot duration, the duty offsets and
    /// `SHARD_COMMITTEE_PERIOD`); the rest of `Config` keeps its mainnet
    /// defaults, so nothing in this client may rely on those.
    async fn spec(&self) -> Result<Config> {
        let response: DataResponse<serde_json::Value> = self.get("/eth/v1/config/spec").await?;
        config_from_spec_response(&response.data)
    }

    async fn is_optimistic_or_syncing(&self) -> Result<bool> {
        let response: DataResponse<SyncingDto> = self.get("/eth/v1/node/syncing").await?;
        let syncing = response.data.is_syncing;
        let optimistic = response.data.is_optimistic.unwrap_or(false);

        // Reported rather than acted on. An execution client that has just gone
        // offline leaves the node with the head it validated before that, which
        // is still a head worth attesting to; the moment that stops being true
        // the node reports it as optimistic instead.
        if response.data.el_offline.unwrap_or(false) {
            warn!(
                url = %self.base_url,
                "Beacon node reports its execution client is offline; it will go optimistic if it \
                 has not already"
            );
        }
        if optimistic && !syncing {
            warn!(
                url = %self.base_url,
                "Beacon node has finished syncing but is tracking an unvalidated head; refusing \
                 to sign against it"
            );
        }
        Ok(syncing || optimistic)
    }

    /// Resolves each pubkey to its validator index and current status.
    async fn validator_indices(&self, pubkeys: &[BlsPubkey]) -> Result<Vec<ValidatorEntry>> {
        // See the contract on the trait: an empty list means "every validator"
        // to this endpoint, so asking is the one thing that must not happen.
        if pubkeys.is_empty() {
            return Ok(Vec::new());
        }

        #[derive(Serialize)]
        struct Body {
            ids: Vec<String>,
        }
        let body = Body {
            ids: pubkeys.iter().map(|key| encode_hex(&key.0)).collect(),
        };
        let response: DataResponse<Vec<ValidatorEntryDto>> = self
            .post("/eth/v1/beacon/states/head/validators", &body, None)
            .await?;
        response
            .data
            .into_iter()
            .map(|entry| {
                Ok(ValidatorEntry {
                    index: entry.index,
                    pubkey: parse_pubkey(&entry.validator.pubkey)?,
                    status: entry.status,
                })
            })
            .collect()
    }

    async fn attester_duties(
        &self,
        epoch: Epoch,
        indices: &[ValidatorIndex],
    ) -> Result<AttesterDuties> {
        let body: Vec<String> = indices.iter().map(|index| index.to_string()).collect();
        let response: DutiesResponse<Vec<AttesterDutyDto>> = self
            .post(
                &format!("/eth/v1/validator/duties/attester/{epoch}"),
                &body,
                None,
            )
            .await?;
        Ok(AttesterDuties {
            dependent_root: parse_root(&response.dependent_root)?,
            duties: response.data,
        })
    }

    /// A GET with no body, unlike the attester equivalent's POST: the endpoint
    /// answers for every proposer in the epoch rather than for a submitted
    /// list, so there is nothing to send.
    async fn proposer_duties(&self, epoch: Epoch) -> Result<ProposerDuties> {
        self.proposer_duties_at("v1", epoch).await
    }

    /// [`Self::proposer_duties`] against the v2 path, whose `dependent_root`
    /// is the shuffling dependent root proposer preferences must carry.
    async fn proposer_duties_v2(&self, epoch: Epoch) -> Result<ProposerDuties> {
        self.proposer_duties_at("v2", epoch).await
    }

    async fn attestation_data(&self, slot: Slot, fork: ForkName) -> Result<AttestationData> {
        let response: DataResponse<AttestationDataDto> =
            self.get(&Self::attestation_data_path(slot)).await?;
        let data = AttestationData::try_from(&response.data)?;
        // Enforced here rather than at the call site so that failover works:
        // see the contract on `BeaconNodeApi::attestation_data`. An `Err` here
        // is what lets `FallbackBeaconNode` move to the next node; the same
        // check one layer up runs only after this node's answer was already
        // accepted.
        validate_attestation_data(slot, fork, &data)?;
        Ok(data)
    }

    /// `builder_boost_factor` is how this client says whether it does the
    /// builder flow: the request's factor when builder proposals are on, `0`
    /// when they are off (`None`).
    ///
    /// The parameter is a bid comparison: the node returns the local execution
    /// payload when its value is at least `factor / 100` of the builder's, so
    /// zero makes the local payload win on value.
    ///
    /// It is a preference, not a demand, and an earlier version of this comment
    /// said otherwise. The specification's words are "prefer the local
    /// execution node payload **unless an error makes it unviable**", so a node
    /// with a builder configured and a failing execution client may still
    /// answer with a blinded block. The one unconditional guarantee is the
    /// other half: a node with no builder configured MUST return a full block.
    ///
    /// A blinded answer is therefore never assumed away. With builder proposals
    /// off (`None`) it is rejected: this client would not publish it through
    /// `blinded_blocks`, so signing one would burn the slot's slashing-protection
    /// record for a block that can never be sent. With them on it is decoded as
    /// a blinded block, which `publish_blinded_block` sends.
    async fn produce_block(&self, request: &BlockRequest) -> Result<ProducedBlock> {
        if request.fork >= ForkName::Gloas {
            return self.produce_gloas_block(request).await;
        }
        let path = format!(
            "/eth/v3/validator/blocks/{}?randao_reveal={}&graffiti={}&builder_boost_factor={}",
            request.slot,
            encode_hex(&request.randao_reveal.0),
            encode_hex(&request.graffiti.0),
            request.builder_boost_factor.unwrap_or(0),
        );
        // SSZ or JSON, the fork and blindedness settled either way; see
        // `get_block_v3`.
        let BlockAnswer {
            fork,
            blinded,
            body,
        } = self.get_block_v3(&path).await?;
        if blinded && request.builder_boost_factor.is_none() {
            return Err(Error::InconsistentResponse(format!(
                "node produced a blinded block for slot {}; builder proposals are off, so this \
                 client cannot publish one",
                request.slot
            )));
        }

        let block = match body {
            BlockBody::Ssz(bytes) if blinded => ProducedBlock::from_blinded_ssz(fork, &bytes)?,
            BlockBody::Ssz(bytes) => ProducedBlock::from_ssz(fork, &bytes)?,
            BlockBody::Json(data) if blinded => ProducedBlock::from_blinded_json(fork, data)?,
            BlockBody::Json(data) => ProducedBlock::from_json(fork, data)?,
        };
        // Enforced here rather than at the call site so failover works: see the
        // contract on `BeaconNodeApi::produce_block`.
        validate_produced_block(request, &block)?;
        Ok(block)
    }

    /// 202 is not an error and not a clean success, so it is neither mapped to
    /// `Err` nor flattened into `Ok(())`. See [`Published`].
    async fn publish_block(&self, fork: ForkName, body: &[u8]) -> Result<Published> {
        let (url, sent) = self
            .post_ssz_body("/eth/v2/beacon/blocks", fork, body)
            .await;
        let response = sent.map_err(|err| Error::BeaconNode {
            url: url.clone(),
            failure: BeaconNodeFailure::classify(&err),
            detail: err.to_string(),
        })?;

        let status = response.status();
        if status == StatusCode::ACCEPTED {
            return Ok(Published::BroadcastNotImported);
        }
        if status.is_success() {
            return Ok(Published::Imported);
        }
        let body = error_body(response).await;
        Err(Error::BeaconNodeStatus {
            status: status.as_u16(),
            body,
        })
    }

    /// Maps the answer as the trait's contract says: 2xx is handed to the
    /// builder (202 is the node's broadcast-without-import, as for a full
    /// block); a 4xx, a 503 and a connection that was never established are
    /// definite; every other 5xx, and any failure once connected, is
    /// [`Error::BlindedUnconfirmed`].
    ///
    /// A connect error covers a connection refused and one that timed out
    /// ([`CONNECT_TIMEOUT`]); reqwest reports the latter as both a connect
    /// error and a timeout, and the connect check comes first.
    ///
    /// The status alone cannot always tell, and three edges are knowingly
    /// read the wrong way. Some of ethlambda's own 500s are definite (no
    /// builder configured, the blinded block failing the node's checks) and
    /// are read as unconfirmed. A pooled connection the node had already
    /// closed fails without the request being written, but is not a connect
    /// error, so it is read as unconfirmed too. A 503 from a proxy that had
    /// already forwarded the request is read as definite. None changes what
    /// happens next: nothing is retried and nothing is signed again either
    /// way. Only the log line and the counter it lands on are wrong.
    async fn publish_blinded_block(
        &self,
        // For the fallback, which picks the node that produced this block;
        // one node has nothing to choose.
        _producer: Producer,
        fork: ForkName,
        body: &[u8],
    ) -> Result<Published> {
        let (url, sent) = self
            .post_ssz_body("/eth/v2/beacon/blinded_blocks", fork, body)
            .await;
        let response = sent.map_err(|err| {
            if err.is_connect() {
                Error::BeaconNode {
                    url: url.clone(),
                    failure: BeaconNodeFailure::classify(&err),
                    detail: err.to_string(),
                }
            } else {
                Error::BlindedUnconfirmed {
                    status: None,
                    detail: format!("{url}: {err}"),
                }
            }
        })?;

        let status = response.status();
        if status == StatusCode::ACCEPTED {
            return Ok(Published::BroadcastNotImported);
        }
        if status.is_success() {
            return Ok(Published::HandedToBuilder);
        }
        let body = error_body(response).await;
        if status.is_server_error() && status != StatusCode::SERVICE_UNAVAILABLE {
            return Err(Error::BlindedUnconfirmed {
                status: Some(status.as_u16()),
                detail: format!("{url} answered {status}: {body}"),
            });
        }
        Err(Error::BeaconNodeStatus {
            status: status.as_u16(),
            body,
        })
    }

    /// JSON, an empty list never reaching the wire.
    async fn register_validators(
        &self,
        registrations: &[SignedValidatorRegistrationV1],
    ) -> Result<()> {
        if registrations.is_empty() {
            return Ok(());
        }
        // Its own timeout: the node waits up to 10 s on the relay before it
        // answers, which is longer than every other request's default.
        self.post_no_content_within(
            "/eth/v1/validator/register_validator",
            &registrations,
            None,
            Some(REGISTRATION_TIMEOUT),
        )
        .await
    }

    /// JSON, which every beacon node must accept, an empty list never reaching
    /// the wire. The gloas container serialises as the endpoint's JSON itself.
    /// One node, so an acceptance is always [`Delivery::Everywhere`].
    async fn submit_proposer_preferences(
        &self,
        fork: ForkName,
        preferences: &[gloas::SignedProposerPreferences],
    ) -> Result<Delivery> {
        if preferences.is_empty() {
            return Ok(Delivery::Everywhere);
        }
        self.post_no_content(
            "/eth/v1/validator/proposer_preferences",
            &preferences,
            Some(fork.as_str()),
        )
        .await
        .map(|()| Delivery::Everywhere)
    }

    async fn execution_payload_envelope(
        &self,
        slot: Slot,
        block_root: Root,
    ) -> Result<gloas::ExecutionPayloadEnvelope> {
        let path = format!(
            "/eth/v1/validator/execution_payload_envelopes/{slot}/{}",
            encode_hex(&block_root.0)
        );
        let response = self.get_ssz(&path).await?;
        if response.fork != ForkName::Gloas {
            return Err(Error::InconsistentResponse(format!(
                "node answered an envelope request with a {} body",
                response.fork.as_str()
            )));
        }
        let envelope = gloas::ExecutionPayloadEnvelope::from_ssz_bytes(&response.body)
            .map_err(|err| Error::Decode(format!("execution payload envelope: {err:?}")))?;
        // The envelope is signed as it stands, so one for another block must
        // never reach the signing path. Enforced here so failover can act on it.
        if envelope.beacon_block_root != block_root {
            return Err(Error::InconsistentResponse(format!(
                "asked for the envelope of block {}, node answered with one for block {}",
                encode_hex(&block_root.0),
                encode_hex(&envelope.beacon_block_root.0)
            )));
        }
        Ok(envelope)
    }

    async fn publish_execution_payload_envelope(
        &self,
        body: &[u8],
        blob_data_included: bool,
    ) -> Result<()> {
        let url = format!(
            "{}/eth/v1/beacon/execution_payload_envelopes",
            self.base_url
        );
        let response = self
            .client
            .post(&url)
            .header("Eth-Consensus-Version", ForkName::Gloas.as_str())
            .header("Eth-Blob-Data-Included", blob_data_included.to_string())
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(body.to_vec())
            .send()
            .await
            .map_err(|err| Error::BeaconNode {
                url: url.clone(),
                failure: BeaconNodeFailure::classify(&err),
                detail: err.to_string(),
            })?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let body = error_body(response).await;
        Err(Error::BeaconNodeStatus {
            status: status.as_u16(),
            body,
        })
    }

    async fn ptc_duties(&self, epoch: Epoch, indices: &[ValidatorIndex]) -> Result<PtcDuties> {
        let body: Vec<String> = indices.iter().map(|index| index.to_string()).collect();
        let response: DutiesResponse<Vec<PtcDutyDto>> = self
            .post(
                &format!("/eth/v1/validator/duties/ptc/{epoch}"),
                &body,
                None,
            )
            .await?;
        Ok(PtcDuties {
            dependent_root: parse_root(&response.dependent_root)?,
            duties: response.data,
        })
    }

    async fn payload_attestation_data(
        &self,
        slot: Slot,
    ) -> Result<Option<gloas::PayloadAttestationData>> {
        let path = format!("/eth/v1/validator/payload_attestation_data?slot={slot}");
        let response: Option<VersionedResponse<gloas::PayloadAttestationData>> =
            self.get_optional(&path, StatusCode::NO_CONTENT).await?;
        let Some(response) = response else {
            return Ok(None);
        };
        // Enforced here for the reason the other fetches' checks are: this is
        // signable material, and a node answering about another slot must be
        // failed over from rather than signed for.
        if response.data.slot != slot {
            return Err(Error::InconsistentResponse(format!(
                "requested payload attestation data for slot {slot}, node answered for slot {}",
                response.data.slot
            )));
        }
        Ok(Some(response.data))
    }

    /// The same partial-success reading as attestations: see
    /// [`Self::handle_pool_submission`].
    async fn submit_payload_attestations(
        &self,
        messages: &[gloas::PayloadAttestationMessage],
    ) -> Result<usize> {
        let url = format!("{}/eth/v1/beacon/pool/payload_attestations", self.base_url);
        let response = self
            .client
            .post(&url)
            .header("Eth-Consensus-Version", ForkName::Gloas.as_str())
            .json(messages)
            .send()
            .await
            .map_err(|err| Error::BeaconNode {
                url: url.clone(),
                failure: BeaconNodeFailure::classify(&err),
                detail: err.to_string(),
            })?;
        let status = response.status();
        if status.is_success() {
            return Ok(messages.len());
        }
        let body = read_error_body(response).await;
        Self::handle_pool_submission(status, body, messages.len())
    }

    /// Distinct from `post_no_content`: this endpoint's 400s are not always
    /// total failures. See [`Self::handle_pool_submission`].
    async fn submit_attestations(
        &self,
        attestations: &[SingleAttestationDto],
        fork_name: &str,
    ) -> Result<usize> {
        let path = "/eth/v2/beacon/pool/attestations";
        let url = format!("{}{path}", self.base_url);
        let response = self
            .client
            .post(&url)
            .header("Eth-Consensus-Version", fork_name)
            .json(attestations)
            .send()
            .await
            .map_err(|err| Error::BeaconNode {
                url: url.clone(),
                failure: BeaconNodeFailure::classify(&err),
                detail: err.to_string(),
            })?;

        let status = response.status();
        if status.is_success() {
            return Ok(attestations.len());
        }
        let body = read_error_body(response).await;
        Self::handle_pool_submission(status, body, attestations.len())
    }

    /// Three required query parameters, and the third is the one electra added.
    /// See the contract on [`BeaconNodeApi::aggregate_attestation`] for why the
    /// root alone is no longer enough to name a committee's votes.
    async fn aggregate_attestation(
        &self,
        slot: Slot,
        attestation_data_root: Root,
        committee_index: u64,
    ) -> Result<AggregateAttestation> {
        let path = Self::aggregate_path(slot, attestation_data_root, committee_index);
        // JSON, not SSZ, and not by preference: Lighthouse answers this endpoint
        // in JSON whatever `Accept` says. See `AttestationDto` for why that is
        // safe here when it would not be for a block.
        //
        // The body is read as untyped JSON first, because the layout of `data`
        // depends on the `version` beside it.
        let response: VersionedResponse<serde_json::Value> = self.get(&path).await?;
        let fork = ForkName::parse(&response.version.to_ascii_lowercase()).ok_or_else(|| {
            Error::InconsistentResponse(format!(
                "aggregate names fork {}, which this client does not know",
                response.version
            ))
        })?;
        // Refused by name rather than left to fail as an opaque decode error,
        // the same way a pre-electra block is (see `ProducedBlock::from_ssz`).
        // Electra widened `Attestation` with `committee_bits`, so an earlier
        // fork's bytes are a different shape and this client has no container
        // for them. Named explicitly rather than `fork < ForkName::Electra`,
        // so a fork added after gloas is not silently waved through as
        // gloas-shaped.
        let attestation = match fork {
            ForkName::Phase0
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb
            | ForkName::Lean => {
                return Err(Error::InconsistentResponse(format!(
                    "node produced a {} aggregate, which this client does not publish; electra \
                     is the earliest supported",
                    fork.as_str()
                )));
            }
            ForkName::Electra | ForkName::Fulu => {
                let dto: AttestationDto = serde_json::from_value(response.data)
                    .map_err(|err| Error::Decode(format!("electra aggregate: {err}")))?;
                AggregateKind::Electra(Attestation::try_from(&dto)?)
            }
            // Gloas's attestation is its own container, with its own hash tree
            // root, so it is decoded as one and signed over as one.
            ForkName::Gloas => {
                let attestation: gloas::Attestation = serde_json::from_value(response.data)
                    .map_err(|err| Error::Decode(format!("gloas aggregate: {err}")))?;
                AggregateKind::Gloas(attestation)
            }
        };
        // The same contract the other two fetches carry, enforced here so a
        // node answering about the wrong slot is failed over from rather than
        // wrapped in a signature. `committee_index` is deliberately not checked
        // against `committee_bits`: which committees an aggregate covers is the
        // node's answer to the question, and electra's gossip rules already
        // require exactly one.
        if attestation.data().slot != slot {
            return Err(Error::InconsistentResponse(format!(
                "requested an aggregate for slot {slot}, node answered for slot {}",
                attestation.data().slot
            )));
        }
        Ok(AggregateAttestation { fork, attestation })
    }

    /// JSON, because Lighthouse answers an SSZ body here with 415. See the
    /// contract on [`BeaconNodeApi::publish_aggregates`].
    async fn publish_aggregates(
        &self,
        fork: ForkName,
        aggregates: &SignedAggregates,
    ) -> Result<()> {
        const PATH: &str = "/eth/v2/validator/aggregate_and_proofs";
        match aggregates {
            SignedAggregates::Electra(list) => {
                let body: Vec<SignedAggregateAndProofOutDto> = list
                    .iter()
                    .map(SignedAggregateAndProofOutDto::from)
                    .collect();
                self.post_no_content(PATH, &body, Some(fork.as_str())).await
            }
            // The gloas container serialises as the endpoint's JSON itself
            // (hex bitfields, quoted integers), so there is no second DTO.
            SignedAggregates::Gloas(list) => {
                self.post_no_content(PATH, list, Some(fork.as_str())).await
            }
        }
    }

    async fn prepare_beacon_proposer(&self, preparations: &[ProposerPreparationDto]) -> Result<()> {
        self.post_no_content(
            "/eth/v1/validator/prepare_beacon_proposer",
            &preparations,
            None,
        )
        .await
    }

    async fn subscribe_committees(&self, subscriptions: &[CommitteeSubscriptionDto]) -> Result<()> {
        self.post_no_content(
            "/eth/v1/validator/beacon_committee_subscriptions",
            &subscriptions,
            None,
        )
        .await
    }

    async fn sync_duties(
        &self,
        epoch: Epoch,
        indices: &[ValidatorIndex],
    ) -> Result<Vec<SyncDutyDto>> {
        let body: Vec<String> = indices.iter().map(|index| index.to_string()).collect();
        let response: DataResponse<Vec<SyncDutyDto>> = self
            .post(
                &format!("/eth/v1/validator/duties/sync/{epoch}"),
                &body,
                None,
            )
            .await?;
        Ok(response.data)
    }

    async fn head_block_root(&self) -> Result<Root> {
        let response: BlockRootResponse = self.get("/eth/v1/beacon/blocks/head/root").await?;
        // The same error a 503 gets, so failover moves to the next node. See
        // the contract on `BeaconNodeApi::head_block_root`.
        if response.execution_optimistic.unwrap_or(false) {
            return Err(Error::BeaconNodeSyncing);
        }
        parse_root(&response.data.root)
    }

    async fn canonical_block_root(&self, slot: Slot) -> Result<Option<Root>> {
        // A 404 is this endpoint's "no block at that slot", per the
        // specification.
        let path = format!("/eth/v1/beacon/headers/{slot}");
        let response: Option<crate::beacon_node::dto::BlockHeaderResponse> =
            self.get_optional(&path, StatusCode::NOT_FOUND).await?;
        let Some(response) = response else {
            return Ok(None);
        };
        let answered = response.data.header.message.slot;
        if answered != slot {
            return Err(Error::InconsistentResponse(format!(
                "asked for the block at slot {slot}, node answered with one at slot {answered}"
            )));
        }
        parse_root(&response.data.root).map(Some)
    }

    /// The same partial-success reading as attestations: see
    /// [`Self::handle_pool_submission`].
    async fn submit_sync_committee_messages(
        &self,
        messages: &[altair::SyncCommitteeMessage],
    ) -> Result<usize> {
        let url = format!("{}/eth/v1/beacon/pool/sync_committees", self.base_url);
        let response = self
            .client
            .post(&url)
            .json(messages)
            .send()
            .await
            .map_err(|err| Error::BeaconNode {
                url: url.clone(),
                failure: BeaconNodeFailure::classify(&err),
                detail: err.to_string(),
            })?;
        let status = response.status();
        if status.is_success() {
            return Ok(messages.len());
        }
        let body = read_error_body(response).await;
        Self::handle_pool_submission(status, body, messages.len())
    }

    async fn sync_committee_contribution(
        &self,
        slot: Slot,
        subcommittee_index: u64,
        beacon_block_root: Root,
    ) -> Result<altair::SyncCommitteeContribution> {
        let path = Self::sync_contribution_path(slot, subcommittee_index, beacon_block_root);
        let response: DataResponse<altair::SyncCommitteeContribution> = self.get(&path).await?;
        validate_sync_contribution(slot, subcommittee_index, beacon_block_root, &response.data)?;
        Ok(response.data)
    }

    async fn publish_contribution_and_proofs(
        &self,
        contributions: &[altair::SignedContributionAndProof],
    ) -> Result<()> {
        self.post_no_content(
            "/eth/v1/validator/contribution_and_proofs",
            &contributions,
            None,
        )
        .await
    }

    async fn subscribe_sync_committees(
        &self,
        subscriptions: &[SyncCommitteeSubscriptionDto],
    ) -> Result<()> {
        self.post_no_content(
            "/eth/v1/validator/sync_committee_subscriptions",
            &subscriptions,
            None,
        )
        .await
    }

    async fn validator(&self, pubkey: &BlsPubkey) -> Result<Option<ValidatorDetails>> {
        let path = format!(
            "/eth/v1/beacon/states/head/validators/{}",
            encode_hex(&pubkey.0)
        );
        // A 404 is this endpoint's "validator not found", per the
        // specification.
        let response: Option<DataResponse<ValidatorDetailsDto>> =
            self.get_optional(&path, StatusCode::NOT_FOUND).await?;
        let Some(response) = response else {
            return Ok(None);
        };
        let entry = response.data;
        // The answer names the key it describes; a node answering about
        // another validator must not have its index signed into an exit.
        let answered = parse_pubkey(&entry.validator.pubkey)?;
        if answered != *pubkey {
            return Err(Error::InconsistentResponse(format!(
                "asked about validator {}, node answered about {}",
                encode_hex(&pubkey.0),
                entry.validator.pubkey
            )));
        }
        Ok(Some(ValidatorDetails {
            index: entry.index,
            status: entry.status,
            activation_epoch: entry.validator.activation_epoch,
            exit_epoch: entry.validator.exit_epoch,
            withdrawable_epoch: entry.validator.withdrawable_epoch,
        }))
    }

    async fn submit_voluntary_exit(&self, exit: &SignedVoluntaryExit) -> Result<()> {
        self.post_no_content("/eth/v1/beacon/pool/voluntary_exits", exit, None)
            .await
    }

    /// Asks this node whether it is syncing first, once for every epoch, per
    /// the trait's contract: the answer that clears a key must come from a
    /// node that has the chain, and only this node's own status says whether
    /// this one does. The epochs are then asked about at once.
    async fn liveness(
        &self,
        epochs: &[Epoch],
        indices: &[ValidatorIndex],
    ) -> Result<Vec<Vec<Liveness>>> {
        if indices.is_empty() || epochs.is_empty() {
            return Ok(vec![Vec::new(); epochs.len()]);
        }
        if self.is_optimistic_or_syncing().await? {
            return Err(Error::BeaconNodeSyncing);
        }
        let body: Vec<String> = indices.iter().map(ValidatorIndex::to_string).collect();
        let body = &body;
        let queries = epochs.iter().map(|epoch| async move {
            let response: DataResponse<Vec<LivenessDto>> = self
                .post(&format!("/eth/v1/validator/liveness/{epoch}"), body, None)
                .await?;
            let answers: Vec<Liveness> = response
                .data
                .into_iter()
                .map(|entry| Liveness {
                    index: entry.index,
                    is_live: entry.is_live,
                })
                .collect();
            validate_liveness(indices, &answers)?;
            Ok(answers)
        });
        futures_util::future::try_join_all(queries).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_trims_a_trailing_slash_from_the_base_url() {
        let node = HttpBeaconNode::new("http://x/").expect("builds");
        assert_eq!(node.base_url(), "http://x");
    }

    /// An `IndexedErrorMessage` naming fewer failures than the batch size is
    /// a partial success: the valid entries are already stored and gossiped,
    /// so this must report their count rather than turn the whole submission
    /// into an error.
    #[test]
    fn a_partial_batch_rejection_reports_how_many_succeeded() {
        let body = serde_json::json!({
            "code": 400,
            "message": "some failed to verify",
            "failures": [
                { "index": 1, "message": "invalid signature" }
            ]
        })
        .to_string();

        let published = HttpBeaconNode::handle_pool_submission(StatusCode::BAD_REQUEST, body, 3)
            .expect("a partial rejection is not an error");
        assert_eq!(published, 2);
    }

    /// The opposite edge from the test above: every submitted entry is named
    /// as a failure, so nothing actually succeeded and this must still be
    /// reported as an error, exactly like the pre-existing behaviour for a
    /// bad response with no per-index detail at all.
    #[test]
    fn a_total_batch_rejection_is_still_an_error() {
        let body = serde_json::json!({
            "code": 400,
            "message": "all failed to verify",
            "failures": [
                { "index": 0, "message": "invalid signature" },
                { "index": 1, "message": "invalid signature" }
            ]
        })
        .to_string();

        let err = HttpBeaconNode::handle_pool_submission(StatusCode::BAD_REQUEST, body, 2)
            .expect_err("every entry failed; must not be reported as a success");
        assert!(matches!(err, Error::BeaconNodeStatus { .. }), "got {err:?}");
    }

    /// A 400 with no `failures` field at all (or one that fails to parse)
    /// must fall back to the old opaque-error behaviour rather than panicking
    /// or silently reporting a made-up count.
    #[test]
    fn an_unparsable_body_falls_back_to_an_opaque_error() {
        let err = HttpBeaconNode::handle_pool_submission(
            StatusCode::BAD_REQUEST,
            "not json".to_string(),
            2,
        )
        .expect_err("must fail");
        assert!(matches!(err, Error::BeaconNodeStatus { .. }), "got {err:?}");
    }

    #[test]
    fn a_non_400_failure_status_is_still_an_error() {
        let err = HttpBeaconNode::handle_pool_submission(
            StatusCode::INTERNAL_SERVER_ERROR,
            "boom".to_string(),
            2,
        )
        .expect_err("must fail");
        assert!(matches!(err, Error::BeaconNodeStatus { .. }), "got {err:?}");
    }

    #[test]
    fn the_aggregate_query_has_no_stray_whitespace() {
        let path = HttpBeaconNode::aggregate_path(12_345, Root::repeat_byte(0xab), 7);
        assert!(
            !path.contains(' '),
            "a string continuation must not leave a space in the query: {path}"
        );
        assert_eq!(
            path,
            format!(
                "/eth/v2/validator/aggregate_attestation?attestation_data_root=0x{}&slot=12345&committee_index=7",
                "ab".repeat(32)
            )
        );
    }

    /// All three parameters are required by the specification, and the third is
    /// the one electra added. Losing it would silently ask about whichever
    /// committee the node picked.
    #[test]
    fn the_aggregate_query_carries_all_three_required_parameters() {
        let path = HttpBeaconNode::aggregate_path(1, Root::ZERO, 63);
        for parameter in ["attestation_data_root=", "slot=", "committee_index="] {
            assert!(path.contains(parameter), "{parameter} missing from {path}");
        }
    }

    #[test]
    fn the_sync_contribution_query_carries_all_three_parameters_without_whitespace() {
        let path = HttpBeaconNode::sync_contribution_path(7, 2, Root::repeat_byte(0xab));
        assert_eq!(
            path,
            format!(
                "/eth/v1/validator/sync_committee_contribution?slot=7&subcommittee_index=2\
                 &beacon_block_root=0x{}",
                "ab".repeat(32)
            )
        );
        assert!(!path.contains(' '));
    }

    /// The query names committee 0 at every fork, gloas included, where the
    /// Beacon API says to omit it: Lighthouse answers a query without it with
    /// a 400. Driven through `attestation_data` rather than the path function,
    /// so the fork the caller passes is part of what is checked.
    #[tokio::test]
    async fn the_committee_index_is_sent_at_every_fork() {
        for fork in [ForkName::Fulu, ForkName::Gloas] {
            let served = serve(500, vec![], vec![]).await;
            let _ = served.node.attestation_data(96, fork).await;
            let seen = served.seen.lock().expect("lock");
            assert_eq!(seen.len(), 1, "one request at {fork:?}");
            assert_eq!(
                seen[0].0, "/eth/v1/validator/attestation_data?slot=96&committee_index=0",
                "at {fork:?}"
            );
        }
    }

    /// The body `produceBlockV4` requires: no builders, the boost factor
    /// being the configured one or `0`, and the minimum bid as given.
    #[test]
    fn the_builder_config_carries_the_factor_or_zero_and_the_min_bid() {
        for (factor, expected) in [(None, "0"), (Some(250), "250"), (Some(0), "0")] {
            let value: serde_json::Value =
                serde_json::from_str(&builder_config(factor, 0)).expect("valid json");
            assert_eq!(value["min_bid"], "0");
            assert_eq!(value["builder_boost_factor"], expected, "{factor:?}");
            assert_eq!(value["builders"], serde_json::json!([]));
        }
        let value: serde_json::Value =
            serde_json::from_str(&builder_config(Some(100), u64::MAX)).expect("valid json");
        assert_eq!(value["min_bid"], u64::MAX.to_string(), "quoted, as a Gwei");
    }

    /// The body reaches the wire: a gloas production request posts it.
    #[tokio::test]
    async fn a_gloas_production_request_posts_the_factor_and_min_bid_in_its_body() {
        let cases = [
            (None, 0, "0", "0"),
            (None, 1_000_000, "0", "1000000"),
            (Some(250), 1_000_000, "250", "1000000"),
        ];
        for (factor, min_bid, expected_factor, expected_min_bid) in cases {
            let served = serve(500, vec![], vec![]).await;
            let request = BlockRequest {
                fork: ForkName::Gloas,
                builder_min_bid: min_bid,
                ..block_request(factor)
            };
            let _ = served.node.produce_block(&request).await;
            let seen = served.seen.lock().expect("lock");
            assert_eq!(seen.len(), 1);
            assert!(seen[0].0.contains("/eth/v4/validator/blocks/5"));
            assert_eq!(
                seen[0].2["accept"], "application/octet-stream",
                "gloas stays SSZ-only"
            );
            let body: serde_json::Value = serde_json::from_slice(&seen[0].1).expect("json body");
            assert_eq!(body["builder_boost_factor"], expected_factor);
            assert_eq!(body["min_bid"], expected_min_bid);
        }
    }

    /// A Beacon API double that answers every route the same way: whatever
    /// the handler sees is pushed to `seen` as (uri, body, request headers),
    /// and the answer is `status` with `headers` and `reply` as the body.
    type Seen = std::sync::Arc<std::sync::Mutex<Vec<(String, Vec<u8>, axum::http::HeaderMap)>>>;
    type Canned = (Seen, u16, Vec<(&'static str, &'static str)>, Vec<u8>);

    struct Served {
        node: HttpBeaconNode,
        seen: Seen,
    }

    async fn serve(
        status: u16,
        headers: Vec<(&'static str, &'static str)>,
        reply: Vec<u8>,
    ) -> Served {
        use axum::body::Bytes;
        use axum::extract::State;
        use axum::http::Uri;
        use axum::response::IntoResponse;

        let seen: Seen = Default::default();
        let state = (seen.clone(), status, headers, reply);
        let handler = |State(state): State<Canned>,
                       uri: Uri,
                       request_headers: axum::http::HeaderMap,
                       body: Bytes| async move {
            let (seen, status, headers, reply) = state;
            seen.lock()
                .expect("lock")
                .push((uri.to_string(), body.to_vec(), request_headers));
            let mut response = (
                axum::http::StatusCode::from_u16(status).expect("a status"),
                reply,
            )
                .into_response();
            for (name, value) in headers {
                response
                    .headers_mut()
                    .insert(name, axum::http::HeaderValue::from_static(value));
            }
            response
        };
        let app = axum::Router::new().fallback(handler).with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds");
        let address = listener.local_addr().expect("address");
        tokio::spawn(async move { axum::serve(listener, app).await });
        Served {
            node: HttpBeaconNode::new(format!("http://{address}")).expect("builds"),
            seen,
        }
    }

    fn block_request(factor: Option<u64>) -> BlockRequest {
        BlockRequest {
            slot: 5,
            fork: ForkName::Fulu,
            proposer_index: 7,
            randao_reveal: Default::default(),
            graffiti: Default::default(),
            builder_boost_factor: factor,
            builder_min_bid: 0,
        }
    }

    const SSZ_HEADERS: [(&str, &str); 3] = [
        ("content-type", "application/octet-stream"),
        ("eth-consensus-version", "fulu"),
        ("eth-execution-payload-blinded", "true"),
    ];

    fn blinded_bytes() -> Vec<u8> {
        use libssz::SszEncode as _;
        ethlambda_types::beacon::builder::BlindedBeaconBlock::from(
            crate::beacon_node::block_contents::empty_block_for(5, 7),
        )
        .to_ssz()
    }

    #[tokio::test]
    async fn the_boost_factor_is_zero_without_builder_proposals_and_the_factor_with() {
        for (factor, expected) in [
            (None, "builder_boost_factor=0"),
            (Some(250), "builder_boost_factor=250"),
        ] {
            let served = serve(500, vec![], vec![]).await;
            let _ = served.node.produce_block(&block_request(factor)).await;
            let seen = served.seen.lock().expect("lock");
            assert_eq!(seen.len(), 1);
            assert!(
                seen[0].0.contains(expected),
                "{} lacks {expected}",
                seen[0].0
            );
        }
    }

    #[tokio::test]
    async fn a_blinded_answer_is_refused_without_builder_proposals() {
        let served = serve(200, SSZ_HEADERS.to_vec(), blinded_bytes()).await;
        let err = served
            .node
            .produce_block(&block_request(None))
            .await
            .expect_err("a blinded block cannot be published here");
        assert!(matches!(err, Error::InconsistentResponse(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn a_blinded_answer_decodes_as_blinded_with_builder_proposals() {
        let served = serve(200, SSZ_HEADERS.to_vec(), blinded_bytes()).await;
        let produced = served
            .node
            .produce_block(&block_request(Some(100)))
            .await
            .expect("decodes");
        assert!(produced.is_blinded());
        assert_eq!(produced.slot(), 5);
        assert_eq!(produced.proposer_index(), 7);
    }

    /// SSZ first, JSON at lower preference: the specification's own example,
    /// so a proxy rewriting it to JSON (blobber) still gets an answer decoded.
    #[tokio::test]
    async fn a_block_request_asks_for_ssz_first_and_json_second() {
        let served = serve(500, vec![], vec![]).await;
        let _ = served.node.produce_block(&block_request(None)).await;
        let seen = served.seen.lock().expect("lock");
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0].2["accept"],
            "application/octet-stream;q=1.0,application/json;q=0.9"
        );
    }

    /// The headers a node sends beside a JSON `produceBlockV3` answer.
    fn json_headers(
        version: &'static str,
        blinded: &'static str,
    ) -> Vec<(&'static str, &'static str)> {
        vec![
            ("content-type", "application/json; charset=utf-8"),
            ("eth-consensus-version", version),
            ("eth-execution-payload-blinded", blinded),
        ]
    }

    /// A JSON `produceBlockV3` answer around `data`, its body naming the fork
    /// and blindedness only when given them.
    fn json_answer(
        version: Option<&str>,
        blinded: Option<bool>,
        data: serde_json::Value,
    ) -> Vec<u8> {
        let mut answer = serde_json::json!({
            "execution_payload_value": "42",
            "consensus_block_value": "0",
            "data": data,
        });
        if let Some(version) = version {
            answer["version"] = version.into();
        }
        if let Some(blinded) = blinded {
            answer["execution_payload_blinded"] = blinded.into();
        }
        serde_json::to_vec(&answer).expect("serialises")
    }

    /// `empty_block_for(5, 7)`'s contents at `fork` (electra or fulu) with one
    /// blob, as a JSON answer's `data` and as SSZ. The block in `data` is
    /// written by its container's own serde, the one an ethlambda beacon node
    /// serves it with; the proofs and blobs as the hex strings the Beacon API
    /// specifies.
    fn block_contents_at(fork: ForkName) -> (serde_json::Value, Vec<u8>) {
        use crate::beacon_node::block_contents::{
            BlockContents, FuluBlockContents, empty_blob, empty_block_for,
        };
        use ethlambda_types::beacon::preset;
        use ethlambda_types::beacon::primitives::KzgProof;
        use libssz::SszEncode as _;

        let block = empty_block_for(5, 7);
        let proofs = if fork == ForkName::Fulu {
            preset::CELLS_PER_EXT_BLOB
        } else {
            1
        };
        let data = serde_json::json!({
            "block": serde_json::to_value(&block).expect("serialises"),
            "kzg_proofs": vec![encode_hex(&[3u8; 48]); proofs],
            "blobs": [encode_hex(&vec![0u8; preset::BYTES_PER_BLOB])],
        });
        let kzg_proofs = vec![KzgProof([3; 48]); proofs];
        let blobs = vec![empty_blob()];
        let ssz = if fork == ForkName::Fulu {
            FuluBlockContents {
                block,
                kzg_proofs: kzg_proofs.try_into().expect("in bounds"),
                blobs: blobs.try_into().expect("in bounds"),
            }
            .to_ssz()
        } else {
            BlockContents {
                block,
                kzg_proofs: kzg_proofs.try_into().expect("in bounds"),
                blobs: blobs.try_into().expect("in bounds"),
            }
            .to_ssz()
        };
        (data, ssz)
    }

    /// The property the JSON path exists to keep: the block decoded from a
    /// JSON answer is the one its SSZ would give, root included, at every fork
    /// `produceBlockV3` serves this client.
    #[tokio::test]
    async fn a_json_answer_decodes_into_the_block_its_ssz_would() {
        use ethlambda_types::beacon::primitives::HashTreeRoot as _;

        for fork in [ForkName::Electra, ForkName::Fulu] {
            let (data, ssz) = block_contents_at(fork);
            let version = fork.as_str();
            let reply = json_answer(Some(version), Some(false), data);
            let served = serve(200, json_headers(version, "false"), reply).await;
            let request = BlockRequest {
                fork,
                ..block_request(None)
            };
            let produced = served.node.produce_block(&request).await.expect("decodes");

            let expected = ProducedBlock::from_ssz(fork, &ssz).expect("the SSZ decodes");
            assert_eq!(produced, expected, "{version}");
            assert_eq!(produced.blob_count(), 1, "{version}");
            assert_eq!(
                produced.block_root(),
                crate::beacon_node::block_contents::empty_block_for(5, 7).hash_tree_root(),
                "{version}"
            );
        }
    }

    #[tokio::test]
    async fn a_blinded_json_answer_decodes_as_blinded_with_builder_proposals() {
        use ethlambda_types::beacon::builder::BlindedBeaconBlock;
        use ethlambda_types::beacon::primitives::HashTreeRoot as _;
        use libssz::SszEncode as _;

        let full = crate::beacon_node::block_contents::empty_block_for(5, 7);
        let blinded = BlindedBeaconBlock::from(full.clone());
        let data = serde_json::to_value(&blinded).expect("serialises");
        let reply = json_answer(Some("fulu"), Some(true), data);
        let served = serve(200, json_headers("fulu", "true"), reply).await;
        let produced = served
            .node
            .produce_block(&block_request(Some(100)))
            .await
            .expect("decodes");

        assert!(produced.is_blinded());
        let expected = ProducedBlock::from_blinded_ssz(ForkName::Fulu, &blinded.to_ssz())
            .expect("the SSZ decodes");
        assert_eq!(produced, expected);
        assert_eq!(produced.block_root(), full.hash_tree_root());
    }

    #[tokio::test]
    async fn a_blinded_json_answer_is_refused_without_builder_proposals() {
        use ethlambda_types::beacon::builder::BlindedBeaconBlock;

        let blinded =
            BlindedBeaconBlock::from(crate::beacon_node::block_contents::empty_block_for(5, 7));
        let data = serde_json::to_value(&blinded).expect("serialises");
        let reply = json_answer(Some("fulu"), Some(true), data);
        let served = serve(200, json_headers("fulu", "true"), reply).await;
        let err = served
            .node
            .produce_block(&block_request(None))
            .await
            .expect_err("a blinded block cannot be published here");
        assert!(matches!(err, Error::InconsistentResponse(_)), "got {err:?}");
    }

    /// A header stands in for a body field that is missing, since it says the
    /// same thing.
    #[tokio::test]
    async fn a_json_answer_missing_its_version_and_blindedness_falls_back_on_the_headers() {
        let (data, ssz) = block_contents_at(ForkName::Fulu);
        let reply = json_answer(None, None, data);
        let served = serve(200, json_headers("fulu", "false"), reply).await;
        let produced = served
            .node
            .produce_block(&block_request(None))
            .await
            .expect("decodes");
        let expected = ProducedBlock::from_ssz(ForkName::Fulu, &ssz).expect("the SSZ decodes");
        assert_eq!(produced, expected);
    }

    /// A body and a header that disagree have not said which container `data`
    /// is: refused, whichever of the two facts they disagree on.
    #[tokio::test]
    async fn a_json_answer_whose_body_and_headers_disagree_is_refused() {
        let cases = [
            // The fork: a fulu body under an electra header.
            (Some("fulu"), Some(false), "electra", "false"),
            // Blindedness: an unblinded body under a blinded header.
            (Some("fulu"), Some(false), "fulu", "true"),
        ];
        for (version, blinded, header_version, header_blinded) in cases {
            let (data, _) = block_contents_at(ForkName::Fulu);
            let reply = json_answer(version, blinded, data);
            let headers = json_headers(header_version, header_blinded);
            let served = serve(200, headers, reply).await;
            let err = served
                .node
                .produce_block(&block_request(Some(100)))
                .await
                .expect_err("contradicts itself");
            assert!(
                matches!(err, Error::InconsistentResponse(_)),
                "{header_version}/{header_blinded}: got {err:?}"
            );
        }
    }

    /// Neither the body nor a header names the fork: not a default to guess
    /// at, as on the SSZ path.
    #[tokio::test]
    async fn a_json_answer_naming_no_fork_is_refused() {
        let (data, _) = block_contents_at(ForkName::Fulu);
        let reply = json_answer(None, Some(false), data);
        let headers = vec![("content-type", "application/json")];
        let served = serve(200, headers, reply).await;
        let err = served
            .node
            .produce_block(&block_request(None))
            .await
            .expect_err("the fork is unknown");
        assert!(matches!(err, Error::InconsistentResponse(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn a_block_answer_neither_ssz_nor_json_is_refused() {
        let headers = vec![
            ("content-type", "text/plain"),
            ("eth-consensus-version", "fulu"),
            ("eth-execution-payload-blinded", "false"),
        ];
        let served = serve(200, headers, b"a block".to_vec()).await;
        let err = served
            .node
            .produce_block(&block_request(None))
            .await
            .expect_err("neither encoding asked for");
        assert!(matches!(err, Error::InconsistentResponse(_)), "got {err:?}");
    }

    /// blobber relays a failed `produceBlockV3` under a 200: the error message
    /// in the body is the error, as its status would have been, and a 503 in
    /// it is still the node syncing.
    #[tokio::test]
    async fn an_error_message_relayed_under_a_success_is_the_error_it_reports() {
        let headers = || vec![("content-type", "application/json")];
        let syncing = br#"{"code":503,"message":"Beacon node is currently syncing"}"#;
        let served = serve(200, headers(), syncing.to_vec()).await;
        let err = served
            .node
            .produce_block(&block_request(None))
            .await
            .expect_err("the node failed");
        assert!(matches!(err, Error::BeaconNodeSyncing), "got {err:?}");

        let failed = br#"{"code":500,"message":"Failed to produce block"}"#;
        let served = serve(200, headers(), failed.to_vec()).await;
        let err = served
            .node
            .produce_block(&block_request(None))
            .await
            .expect_err("the node failed");
        let Error::BeaconNodeStatus { status, body } = err else {
            panic!("got {err:?}");
        };
        assert_eq!(status, 500);
        assert!(body.contains("Failed to produce block"), "{body}");

        // A `code` that is not a failure is no error message; the answer is
        // a malformed block answer, as before.
        let not_an_error = br#"{"code":200,"message":"ok"}"#;
        let served = serve(200, headers(), not_an_error.to_vec()).await;
        let err = served
            .node
            .produce_block(&block_request(None))
            .await
            .expect_err("no block");
        assert!(matches!(err, Error::Decode(_)), "got {err:?}");
    }

    /// A builder-specs example vendored in `ethlambda-types` (see that
    /// directory's README): JSON and SSZ for one object, written by neither
    /// this client nor an ethlambda node.
    macro_rules! builder_specs_example {
        ($path:literal) => {
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../common/types/tests/fixtures/builder_specs/",
                $path
            ))
        };
    }

    /// The object an example `.json` holds under OpenAPI's `value` wrapper.
    fn example_value(json: &[u8]) -> serde_json::Value {
        let mut document: serde_json::Value = serde_json::from_slice(json).expect("json");
        document["value"].take()
    }

    /// The fulu blinded block example, decoded from its SSZ, and its
    /// `message` as JSON.
    fn blinded_block_example() -> (
        ethlambda_types::beacon::builder::BlindedBeaconBlock,
        serde_json::Value,
    ) {
        use ethlambda_types::beacon::builder::SignedBlindedBeaconBlock;
        use libssz::SszDecode as _;

        let ssz = builder_specs_example!("fulu/signed_blinded_beacon_block.ssz");
        let signed = SignedBlindedBeaconBlock::from_ssz_bytes(ssz).expect("the SSZ decodes");
        let json = builder_specs_example!("fulu/signed_blinded_beacon_block.json");
        let message = example_value(json)["message"].take();
        (signed.message, message)
    }

    /// builder-specs' `ExecutionPayloadAndBlobsBundle` at fulu, for decoding
    /// its example's SSZ. A module of its own because the SSZ derive names a
    /// bare `Result`, which `use super::*` would make this crate's.
    mod the_bundle {
        use crate::beacon_node::block_contents::{Blobs, CellKzgProofs};
        use ethlambda_types::beacon::containers::deneb::{ExecutionPayload, KzgCommitments};

        /// `BlobsBundle` at fulu: one proof per cell.
        #[derive(libssz_derive::SszDecode)]
        pub struct BlobsBundle {
            pub commitments: KzgCommitments,
            pub proofs: CellKzgProofs,
            pub blobs: Blobs,
        }

        #[derive(libssz_derive::SszDecode)]
        pub struct ExecutionPayloadAndBlobsBundle {
            pub execution_payload: ExecutionPayload,
            pub blobs_bundle: BlobsBundle,
        }
    }

    /// A request the example block answers: its own slot and proposer.
    fn request_for(
        block: &ethlambda_types::beacon::builder::BlindedBeaconBlock,
        factor: Option<u64>,
    ) -> BlockRequest {
        BlockRequest {
            slot: block.slot,
            proposer_index: block.proposer_index,
            ..block_request(factor)
        }
    }

    /// The JSON path checked against JSON this repository did not write: the
    /// builder-specs blinded block, every list in its body populated, decodes
    /// as a blinded `produceBlockV3` answer into the block its SSZ gives.
    #[tokio::test]
    async fn the_builder_specs_blinded_block_decodes_from_json_as_from_ssz() {
        use ethlambda_types::beacon::primitives::HashTreeRoot as _;
        use libssz::SszEncode as _;

        let (expected, data) = blinded_block_example();
        let reply = json_answer(Some("fulu"), Some(true), data);
        let served = serve(200, json_headers("fulu", "true"), reply).await;
        let produced = served
            .node
            .produce_block(&request_for(&expected, Some(100)))
            .await
            .expect("decodes");

        let from_ssz = ProducedBlock::from_blinded_ssz(ForkName::Fulu, &expected.to_ssz())
            .expect("the SSZ decodes");
        assert_eq!(produced, from_ssz);
        assert_eq!(produced.block_root(), expected.hash_tree_root());
    }

    /// `the_builder_specs_blinded_block_decodes_from_json_as_from_ssz` for a
    /// full fulu block: the example block around the builder-specs
    /// payload, with that example's cell proofs and blob. Each part is held to
    /// its own example's SSZ: everything but the payload to the blinded
    /// block's, the payload and blob material to the bundle's.
    #[tokio::test]
    async fn the_builder_specs_full_block_decodes_from_json_as_from_ssz() {
        use crate::beacon_node::block_contents::Contents;
        use ethlambda_types::beacon::builder::BlindedBeaconBlock;
        use libssz::SszDecode as _;
        use the_bundle::ExecutionPayloadAndBlobsBundle;

        let (blinded, mut block) = blinded_block_example();
        let ssz = builder_specs_example!("fulu/execution_payload_and_blobs_bundle.ssz");
        let bundle = ExecutionPayloadAndBlobsBundle::from_ssz_bytes(ssz).expect("the SSZ decodes");
        let json = builder_specs_example!("fulu/execution_payload_and_blobs_bundle.json");
        let mut bundle_json = example_value(json)["data"].take();

        let body = block["body"].as_object_mut().expect("a body");
        body.remove("execution_payload_header")
            .expect("a blinded body");
        body.insert(
            "execution_payload".to_string(),
            bundle_json["execution_payload"].take(),
        );
        let data = serde_json::json!({
            "block": block,
            "kzg_proofs": bundle_json["blobs_bundle"]["proofs"].take(),
            "blobs": bundle_json["blobs_bundle"]["blobs"].take(),
        });
        let reply = json_answer(Some("fulu"), Some(false), data);
        let served = serve(200, json_headers("fulu", "false"), reply).await;
        let produced = served
            .node
            .produce_block(&request_for(&blinded, None))
            .await
            .expect("decodes");

        let Contents::WithCellProofs {
            block,
            kzg_proofs,
            blobs,
        } = produced.contents
        else {
            panic!("a fulu block with cell proofs, got {:?}", produced.contents);
        };
        let header = blinded.body.execution_payload_header.clone();
        assert_eq!(
            BlindedBeaconBlock::from_parts(block.clone(), header),
            blinded
        );
        assert_eq!(block.body.execution_payload, bundle.execution_payload);
        assert_eq!(kzg_proofs, bundle.blobs_bundle.proofs);
        assert_eq!(blobs, bundle.blobs_bundle.blobs);
        // The two examples are independent, so the bundle's commitments are
        // not the block's; it carries one per blob all the same.
        assert_eq!(bundle.blobs_bundle.commitments.len(), blobs.len());
    }

    /// The header endpoint's answer, in the shape the specification gives
    /// it, read for its root; a 404 is no block at the slot, and a header for
    /// another slot is an answer to another question.
    #[tokio::test]
    async fn a_canonical_block_root_is_read_off_the_header_at_the_slot() {
        let root = format!("0x{}", "ab".repeat(32));
        let header = |slot: u64| {
            serde_json::json!({
                "execution_optimistic": false,
                "finalized": false,
                "data": {
                    "root": root,
                    "canonical": true,
                    "header": {
                        "message": {
                            "slot": slot.to_string(),
                            "proposer_index": "7",
                            "parent_root": format!("0x{}", "00".repeat(32)),
                            "state_root": format!("0x{}", "00".repeat(32)),
                            "body_root": format!("0x{}", "00".repeat(32)),
                        },
                        "signature": format!("0x{}", "00".repeat(96)),
                    },
                },
            })
            .to_string()
            .into_bytes()
        };
        let json = vec![("content-type", "application/json")];

        let served = serve(200, json.clone(), header(41)).await;
        let answer = served.node.canonical_block_root(41).await.expect("answers");
        assert_eq!(answer, Some(Root::from([0xab; 32])));
        assert_eq!(
            served.seen.lock().expect("lock")[0].0,
            "/eth/v1/beacon/headers/41"
        );

        let served = serve(404, json.clone(), br#"{"code":404}"#.to_vec()).await;
        assert_eq!(
            served.node.canonical_block_root(41).await.expect("answers"),
            None
        );

        let served = serve(200, json, header(40)).await;
        let err = served
            .node
            .canonical_block_root(41)
            .await
            .expect_err("a header for another slot");
        assert!(matches!(err, Error::InconsistentResponse(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn registrations_are_posted_as_json_that_round_trips() {
        use ethlambda_types::beacon::builder::{
            SignedValidatorRegistrationV1, ValidatorRegistrationV1,
        };
        use ethlambda_types::beacon::primitives::{BlsPubkey, BlsSignature, H160};

        let registrations = vec![SignedValidatorRegistrationV1 {
            message: ValidatorRegistrationV1 {
                fee_recipient: H160([0xab; 20]),
                gas_limit: 36_000_000,
                timestamp: 1_700_000_000,
                pubkey: BlsPubkey([3; 48]),
            },
            signature: BlsSignature([4; 96]),
        }];
        let served = serve(200, vec![], vec![]).await;
        served
            .node
            .register_validators(&registrations)
            .await
            .expect("accepted");

        let seen = served.seen.lock().expect("lock");
        assert_eq!(seen.len(), 1);
        assert!(seen[0].0.ends_with("/eth/v1/validator/register_validator"));
        let decoded: Vec<SignedValidatorRegistrationV1> =
            serde_json::from_slice(&seen[0].1).expect("the body is the JSON a relay takes");
        assert_eq!(decoded, registrations);
        // The integers as quoted decimal strings, which builder-specs requires
        // and other clients' nodes insist on: a round trip through the same
        // serde impl would pass with bare numbers too.
        let raw: serde_json::Value = serde_json::from_slice(&seen[0].1).expect("json");
        let message = &raw[0]["message"];
        assert_eq!(message["gas_limit"], "36000000");
        assert_eq!(message["timestamp"], "1700000000");
        let fee_recipient = format!("0x{}", "ab".repeat(20));
        assert_eq!(message["fee_recipient"], fee_recipient.as_str());
    }

    #[tokio::test]
    async fn an_empty_registration_list_never_reaches_the_wire() {
        let served = serve(200, vec![], vec![]).await;
        served.node.register_validators(&[]).await.expect("a no-op");
        assert!(served.seen.lock().expect("lock").is_empty());
    }

    /// A node's error body reaches the logs on one line and cut short, saying
    /// so: a body with line breaks cannot forge log lines, a long one cannot
    /// flood them, and a cut one does not read as all the node said.
    #[tokio::test]
    async fn an_error_body_is_one_line_and_capped() {
        let reply = "first line\nsecond line\r\n".repeat(200).into_bytes();
        let served = serve(400, vec![], reply).await;
        let err = served.node.genesis().await.expect_err("a 400");
        let Error::BeaconNodeStatus { status, body } = err else {
            panic!("got {err:?}");
        };
        assert_eq!(status, 400);
        assert!(!body.contains('\n') && !body.contains('\r'));
        // Written out, then cut to the cap less the marker's three bytes,
        // which here falls inside a word.
        let written = "first line\\nsecond line\\r\\n".repeat(200);
        let kept = ERROR_TEXT_LIMIT - "...".len();
        assert_eq!(body, format!("{}...", &written[..kept]));
    }

    /// The cap applies to the written-out text and never splits a character
    /// or an escape: a body of escapes keeps whole ones, then the marker.
    #[test]
    fn error_text_cuts_on_a_character_or_escape_boundary() {
        let room = ERROR_TEXT_LIMIT - "...".len();
        let text = error_text(&"é".repeat(ERROR_TEXT_LIMIT));
        assert_eq!(text, format!("{}...", "é".repeat(room / 2)));
        let text = error_text(&"\u{1b}".repeat(ERROR_TEXT_LIMIT));
        let escapes = "\\u{1b}".repeat(room / "\\u{1b}".len());
        assert_eq!(text, format!("{escapes}..."));
        assert_eq!(error_text("short"), "short");
    }

    #[test]
    fn error_text_writes_out_every_control_character() {
        let text = error_text("a\u{1b}[31mb\tc\u{2028}d");
        assert_eq!(text, "a\\u{1b}[31mb\\tc\\u{2028}d");
    }

    #[tokio::test]
    async fn proposer_preferences_are_posted_as_json_with_the_fork_header() {
        use ethlambda_types::beacon::primitives::{BlsSignature, H160};

        let preferences = vec![gloas::SignedProposerPreferences {
            message: gloas::ProposerPreferences {
                dependent_root: Root::from([9u8; 32]),
                proposal_slot: 70,
                validator_index: 4,
                fee_recipient: H160([0xcd; 20]),
                target_gas_limit: 36_000_000,
            },
            signature: BlsSignature([5; 96]),
        }];
        let served = serve(200, vec![], vec![]).await;
        let delivery = served
            .node
            .submit_proposer_preferences(ForkName::Fulu, &preferences)
            .await
            .expect("accepted");
        assert_eq!(delivery, Delivery::Everywhere, "one node is every node");

        let seen = served.seen.lock().expect("lock");
        assert_eq!(seen.len(), 1);
        assert!(
            seen[0]
                .0
                .ends_with("/eth/v1/validator/proposer_preferences")
        );
        assert_eq!(seen[0].2["eth-consensus-version"], "fulu");
        let decoded: Vec<gloas::SignedProposerPreferences> =
            serde_json::from_slice(&seen[0].1).expect("the body is the endpoint's JSON");
        assert_eq!(decoded, preferences);
    }

    #[tokio::test]
    async fn an_empty_preference_list_never_reaches_the_wire() {
        let served = serve(200, vec![], vec![]).await;
        served
            .node
            .submit_proposer_preferences(ForkName::Fulu, &[])
            .await
            .expect("a no-op");
        assert!(served.seen.lock().expect("lock").is_empty());
    }

    #[tokio::test]
    async fn v2_proposer_duties_use_the_v2_path() {
        let reply = br#"{"dependent_root":"0x0909090909090909090909090909090909090909090909090909090909090909","execution_optimistic":false,"data":[]}"#.to_vec();
        let served = serve(200, vec![("content-type", "application/json")], reply).await;
        let duties = served.node.proposer_duties_v2(3).await.expect("decodes");
        assert_eq!(duties.dependent_root, Root::from([9u8; 32]));
        let seen = served.seen.lock().expect("lock");
        assert!(seen[0].0.ends_with("/eth/v2/validator/duties/proposer/3"));
    }

    #[tokio::test]
    async fn a_blinded_publish_maps_each_status() {
        for (status, expected) in [
            (200, Published::HandedToBuilder),
            (202, Published::BroadcastNotImported),
        ] {
            let served = serve(status, vec![], vec![]).await;
            let published = served
                .node
                .publish_blinded_block(Producer::default(), ForkName::Fulu, &[1, 2, 3])
                .await
                .expect("accepted");
            assert_eq!(published, expected, "status {status}");
            let seen = served.seen.lock().expect("lock");
            assert!(seen[0].0.ends_with("/eth/v2/beacon/blinded_blocks"));
            assert_eq!(seen[0].1, vec![1, 2, 3]);
            assert_eq!(seen[0].2["eth-consensus-version"], "fulu");
            assert_eq!(seen[0].2["content-type"], "application/octet-stream");
        }

        let served = serve(400, vec![], b"bad".to_vec()).await;
        let err = served
            .node
            .publish_blinded_block(Producer::default(), ForkName::Fulu, &[1])
            .await
            .expect_err("a refusal");
        assert!(
            matches!(err, Error::BeaconNodeStatus { status: 400, .. }),
            "got {err:?}"
        );

        let served = serve(500, vec![], b"boom".to_vec()).await;
        let err = served
            .node
            .publish_blinded_block(Producer::default(), ForkName::Fulu, &[1])
            .await
            .expect_err("unconfirmed");
        assert!(
            matches!(
                err,
                Error::BlindedUnconfirmed {
                    status: Some(500),
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    /// The request never left, so the relay cannot have the block: a definite
    /// failure, not an unconfirmed one.
    #[tokio::test]
    async fn a_blinded_publish_that_cannot_connect_is_a_definite_failure() {
        // Nothing listens on port 1.
        let node = HttpBeaconNode::new("http://127.0.0.1:1").expect("builds");
        let err = node
            .publish_blinded_block(Producer::default(), ForkName::Fulu, &[1])
            .await
            .expect_err("no answer");
        assert!(matches!(err, Error::BeaconNode { .. }), "got {err:?}");
    }

    /// A connection that never completes is a connect error too, not the
    /// total timeout, so it is definite: nothing was sent. The listener
    /// accepts TCP but never answers the TLS handshake, which is part of
    /// connecting, so the connect timeout fires on every platform and with no
    /// unroutable address involved.
    #[tokio::test]
    async fn a_blinded_publish_whose_connection_times_out_is_a_definite_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds");
        let address = listener.local_addr().expect("address");
        let held = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        let connect_timeout = Duration::from_millis(200);
        let node =
            HttpBeaconNode::with_connect_timeout(format!("https://{address}"), connect_timeout)
                .expect("builds");

        let started = std::time::Instant::now();
        let err = node
            .publish_blinded_block(Producer::default(), ForkName::Fulu, &[1])
            .await
            .expect_err("never connects");
        held.abort();

        assert!(
            matches!(
                err,
                Error::BeaconNode {
                    failure: BeaconNodeFailure::Connect,
                    ..
                }
            ),
            "got {err:?}"
        );
        assert!(
            started.elapsed() < REQUEST_TIMEOUT,
            "the connect timeout, not the request's, ended it"
        );
    }

    /// A syncing node refuses before it hands anything to a builder.
    #[tokio::test]
    async fn a_blinded_publish_to_a_syncing_node_is_a_definite_failure() {
        let served = serve(503, vec![], b"syncing".to_vec()).await;
        let err = served
            .node
            .publish_blinded_block(Producer::default(), ForkName::Fulu, &[1])
            .await
            .expect_err("refused");
        assert!(
            matches!(err, Error::BeaconNodeStatus { status: 503, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn a_boolean_header_is_read_strictly() {
        assert_eq!(
            HttpBeaconNode::bool_header(Some("True".into()), "Included").expect("ok"),
            Some(true)
        );
        assert_eq!(
            HttpBeaconNode::bool_header(None, "Included").expect("ok"),
            None
        );
        HttpBeaconNode::bool_header(Some("yes".into()), "Included").expect_err("not a boolean");
    }

    /// Every liveness request a [`serve_liveness`] node received, as (path,
    /// JSON body).
    type LivenessSeen = std::sync::Arc<std::sync::Mutex<Vec<(String, serde_json::Value)>>>;

    /// A node that answers `/eth/v1/node/syncing` with `is_syncing` and every
    /// liveness request with `reply`, recording what it was asked.
    async fn serve_liveness(
        is_syncing: bool,
        reply: serde_json::Value,
    ) -> (HttpBeaconNode, LivenessSeen) {
        use axum::extract::{Json, State};
        use axum::http::Uri;
        use axum::routing::{get, post};

        let seen: LivenessSeen = Default::default();
        let syncing = serde_json::json!({
            "data": { "head_slot": "1", "sync_distance": "0", "is_syncing": is_syncing,
                      "is_optimistic": false, "el_offline": false }
        });
        let app = axum::Router::new()
            .route(
                "/eth/v1/node/syncing",
                get(move || async move { Json(syncing) }),
            )
            .route(
                "/eth/v1/validator/liveness/{epoch}",
                post(
                    |State((seen, reply)): State<(LivenessSeen, serde_json::Value)>,
                     uri: Uri,
                     Json(body): Json<serde_json::Value>| async move {
                        seen.lock()
                            .expect("lock")
                            .push((uri.path().to_string(), body));
                        Json(reply)
                    },
                ),
            )
            .with_state((seen.clone(), reply));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds");
        let address = listener.local_addr().expect("address");
        tokio::spawn(async move { axum::serve(listener, app).await });
        let node = HttpBeaconNode::new(format!("http://{address}")).expect("builds");
        (node, seen)
    }

    /// The wire shape both ways: the epoch in the path, the indices a JSON
    /// array of quoted integers, and the answer's quoted `index` read back.
    #[tokio::test]
    async fn liveness_posts_quoted_indices_and_reads_quoted_ones_back() {
        let reply = serde_json::json!({ "data": [
            { "index": "7", "is_live": true },
            { "index": "3", "is_live": false },
        ]});
        let (node, seen) = serve_liveness(false, reply).await;
        let answers = node.liveness(&[12], &[3, 7]).await.expect("answers");
        assert_eq!(
            answers,
            vec![vec![
                Liveness {
                    index: 7,
                    is_live: true
                },
                Liveness {
                    index: 3,
                    is_live: false
                },
            ]]
        );
        let seen = seen.lock().expect("lock");
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, "/eth/v1/validator/liveness/12");
        assert_eq!(seen[0].1, serde_json::json!(["3", "7"]));
    }

    /// One request per epoch, each answer kept in the order the epochs
    /// were named.
    #[tokio::test]
    async fn liveness_asks_about_each_epoch() {
        let reply = serde_json::json!({ "data": [{ "index": "3", "is_live": false }] });
        let (node, seen) = serve_liveness(false, reply).await;
        let answers = node.liveness(&[11, 12], &[3]).await.expect("answers");
        assert_eq!(answers.len(), 2);
        let mut paths: Vec<String> = seen
            .lock()
            .expect("lock")
            .iter()
            .map(|(path, _)| path.clone())
            .collect();
        paths.sort();
        assert_eq!(
            paths,
            vec![
                "/eth/v1/validator/liveness/11".to_string(),
                "/eth/v1/validator/liveness/12".to_string(),
            ]
        );
    }

    /// A syncing node is not asked: its "nobody is live" would clear keys
    /// it has not watched the network for.
    #[tokio::test]
    async fn a_syncing_node_is_not_asked_about_liveness() {
        let reply = serde_json::json!({ "data": [{ "index": "3", "is_live": false }] });
        let (node, seen) = serve_liveness(true, reply).await;
        let err = node.liveness(&[12], &[3]).await.expect_err("syncing");
        assert!(matches!(err, Error::BeaconNodeSyncing), "got {err:?}");
        assert!(seen.lock().expect("lock").is_empty());
    }

    /// An answer that leaves an index out is one to fail over from.
    #[tokio::test]
    async fn a_liveness_answer_missing_an_index_is_refused() {
        let reply = serde_json::json!({ "data": [{ "index": "3", "is_live": false }] });
        let (node, _) = serve_liveness(false, reply).await;
        let err = node.liveness(&[12], &[3, 7]).await.expect_err("incomplete");
        assert!(matches!(err, Error::InconsistentResponse(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn no_liveness_request_is_sent_for_no_indices() {
        let (node, seen) = serve_liveness(false, serde_json::json!({ "data": [] })).await;
        let answers = node.liveness(&[12], &[]).await.expect("empty");
        assert_eq!(answers, vec![Vec::new()]);
        assert!(seen.lock().expect("lock").is_empty());
    }
}
