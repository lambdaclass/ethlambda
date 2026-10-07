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
use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::containers::altair;
use ethlambda_types::beacon::containers::electra::Attestation;
use ethlambda_types::beacon::containers::gloas;
use ethlambda_types::beacon::containers::shared::AttestationData;
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::primitives::{BlsPubkey, Epoch, Root, Slot, ValidatorIndex};
use reqwest::{Client, StatusCode};
use serde::Serialize;
use tracing::{debug, warn};

use libssz::SszDecode as _;

use crate::beacon_node::block_contents::ProducedBlock;
use crate::beacon_node::dto::{
    AttestationDataDto, AttestationDto, AttesterDutyDto, BlockRootResponse,
    CommitteeSubscriptionDto, DataResponse, DutiesResponse, GenesisDto, IndexedErrorResponse,
    ProposerDutyDto, ProposerPreparationDto, PtcDutyDto, SignedAggregateAndProofOutDto,
    SingleAttestationDto, SyncCommitteeSubscriptionDto, SyncDutyDto, SyncingDto, ValidatorEntryDto,
    VersionedResponse, config_from_spec_response, encode_hex, parse_pubkey, parse_root,
};
use crate::beacon_node::{
    AggregateAttestation, AggregateKind, AttesterDuties, BeaconNodeApi, BlockRequest, Genesis,
    ProposerDuties, PtcDuties, Published, SignedAggregates, ValidatorEntry,
    validate_attestation_data, validate_produced_block, validate_sync_contribution,
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

/// The body `produceBlockV4` requires. Self-build only, so no minimum bid, no
/// boost and no builders: the node decodes it, as the specification demands,
/// and builds locally.
const BUILDER_CONFIG: &str = r#"{"min_bid":"0","builder_boost_factor":"0","builders":[]}"#;

/// A [`BeaconNodeApi`] backed by one beacon node's standard REST Beacon API.
pub struct HttpBeaconNode {
    base_url: String,
    client: Client,
}

impl HttpBeaconNode {
    /// Builds a client for the node at `base_url`, stripping any trailing
    /// slash so callers may pass either form.
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        let client = Client::builder()
            .timeout(REQUEST_TIMEOUT)
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
        let url = format!("{}{path}", self.base_url);
        let mut request = self.client.post(&url).json(body);
        if let Some(version) = consensus_version {
            request = request.header("Eth-Consensus-Version", version);
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
        let body = response.text().await.unwrap_or_default();
        Err(Error::BeaconNodeStatus {
            status: status.as_u16(),
            body,
        })
    }

    /// Fetch a body as SSZ, returning the fork the node named alongside it.
    ///
    /// `Accept` names SSZ alone, deliberately narrower than the specification's
    /// own example.
    ///
    /// That example is `application/octet-stream;q=1.0,application/json;q=0.9`,
    /// which says JSON is acceptable at lower preference. It is the right
    /// header for a client that can decode both. This one cannot: there is no
    /// JSON path for a block, so a node taking the `q=0.9` offer would be
    /// answering correctly and losing this client the proposal on every node in
    /// the failover list. (Aggregates do not come through here; they are
    /// fetched as JSON, because Lighthouse sends JSON for them regardless.)
    ///
    /// Naming only what can be decoded makes 406 the node's one legal way out,
    /// and `decode_status` turns that into an ordinary error failover moves
    /// past. The content-type check below stays as the backstop for a node that
    /// ignores the header entirely.
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
    /// builder configuration, and answers in SSZ like its predecessor.
    async fn post_json_for_ssz(
        &self,
        path: &str,
        json_body: &'static str,
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
        let response = request.send().await.map_err(|err| Error::BeaconNode {
            url: url.clone(),
            failure: BeaconNodeFailure::classify(&err),
            detail: err.to_string(),
        })?;

        let status = response.status();
        if status == StatusCode::SERVICE_UNAVAILABLE {
            return Err(Error::BeaconNodeSyncing);
        }
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(Error::BeaconNodeStatus {
                status: status.as_u16(),
                body,
            });
        }

        let header = |name: &str| -> Option<String> {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
        };

        // A node that ignored the Accept header and sent JSON would otherwise
        // reach the SSZ decoder as bytes that happen not to parse, and be
        // reported as a malformed block rather than as the content-type
        // mismatch it is.
        if let Some(content_type) = header(reqwest::header::CONTENT_TYPE.as_str())
            && !content_type.starts_with("application/octet-stream")
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
        let fork = ForkName::parse(&version.to_ascii_lowercase()).ok_or_else(|| {
            Error::InconsistentResponse(format!(
                "Eth-Consensus-Version names fork {version}, which this client does not know"
            ))
        })?;

        // Reported, not judged. Each is sent by one endpoint only, so requiring
        // it here would break every other caller of this helper; whether its
        // absence matters is the caller's question.
        let blinded = Self::bool_header(header("eth-execution-payload-blinded"), "Blinded")?;
        let payload_included =
            Self::bool_header(header("eth-execution-payload-included"), "Included")?;

        let body = response.bytes().await.map_err(|err| Error::BeaconNode {
            url,
            failure: BeaconNodeFailure::classify(&err),
            detail: err.to_string(),
        })?;
        Ok(SszResponse {
            fork,
            blinded,
            payload_included,
            body: body.to_vec(),
        })
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

    /// A GET whose success may be a 204, which is an answer ("nothing to
    /// report") and not a failure.
    async fn get_optional<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<Option<T>> {
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
        if response.status() == StatusCode::NO_CONTENT {
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
            .post_json_for_ssz(&path, BUILDER_CONFIG, request.fork.as_str())
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

    /// The path for one slot's attestation data.
    ///
    /// Gloas omits `committee_index`: the parameter is optional there, and the
    /// answer's `index` is the payload signal rather than a committee, so
    /// asking about committee 0 would only suggest the old meaning.
    fn attestation_data_path(slot: Slot, fork: ForkName) -> String {
        if fork >= ForkName::Gloas {
            format!("/eth/v1/validator/attestation_data?slot={slot}")
        } else {
            format!("/eth/v1/validator/attestation_data?slot={slot}&committee_index=0")
        }
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
                    warn!(
                        submission_index = failure.index,
                        reason = %failure.message,
                        "One attestation in this slot's batch was rejected"
                    );
                }
                return Ok(submitted - failed);
            }
        }

        Err(Error::BeaconNodeStatus {
            status: status.as_u16(),
            body,
        })
    }

    async fn decode<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> Result<T> {
        let status = response.status();
        if status == StatusCode::SERVICE_UNAVAILABLE {
            return Err(Error::BeaconNodeSyncing);
        }
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
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

    /// Fetches the network's fork schedule and slot duration.
    ///
    /// The spec endpoint returns every configuration value as a quoted
    /// string. Only the fork schedule and the slot duration are read here;
    /// the rest of `Config` keeps its mainnet defaults, which is correct for
    /// every network whose presets this binary was compiled against.
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
        let response: DutiesResponse<Vec<ProposerDutyDto>> = self
            .get(&format!("/eth/v1/validator/duties/proposer/{epoch}"))
            .await?;
        Ok(ProposerDuties {
            dependent_root: parse_root(&response.dependent_root)?,
            duties: response.data,
        })
    }

    async fn attestation_data(&self, slot: Slot, fork: ForkName) -> Result<AttestationData> {
        let response: DataResponse<AttestationDataDto> =
            self.get(&Self::attestation_data_path(slot, fork)).await?;
        let data = AttestationData::try_from(&response.data)?;
        // Enforced here rather than at the call site so that failover works:
        // see the contract on `BeaconNodeApi::attestation_data`. An `Err` here
        // is what lets `FallbackBeaconNode` move to the next node; the same
        // check one layer up runs only after this node's answer was already
        // accepted.
        validate_attestation_data(slot, &data)?;
        Ok(data)
    }

    /// `builder_boost_factor=0` is how this client says it does not do the
    /// builder flow.
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
    /// A blinded answer is therefore rejected below rather than assumed away.
    /// This client cannot publish what it cannot unblind, so signing one would
    /// burn the slot's proposal guard entry for a block that can never be
    /// sent.
    async fn produce_block(&self, request: &BlockRequest) -> Result<ProducedBlock> {
        if request.fork >= ForkName::Gloas {
            return self.produce_gloas_block(request).await;
        }
        let path = format!(
            "/eth/v3/validator/blocks/{}?randao_reveal={}&graffiti={}&builder_boost_factor=0",
            request.slot,
            encode_hex(&request.randao_reveal.0),
            encode_hex(&request.graffiti.0),
        );
        let SszResponse {
            fork,
            blinded,
            body,
            ..
        } = self.get_ssz(&path).await?;
        // Required on this endpoint, so its absence is an error rather than a
        // default. The specification marks it required precisely because it
        // selects which container the bytes are, and a blinded body is a
        // different shape entirely; guessing "unblinded" would send a blinded
        // answer to the decoder and surface it as an opaque malformed block.
        let blinded = blinded.ok_or_else(|| {
            Error::InconsistentResponse(
                "response carries no Eth-Execution-Payload-Blinded, so whether it is a block or \
                 a blinded block is unknown"
                    .to_string(),
            )
        })?;
        if blinded {
            return Err(Error::InconsistentResponse(format!(
                "node produced a blinded block for slot {}; this client does not implement the \
                 builder flow and cannot publish one",
                request.slot
            )));
        }

        let block = ProducedBlock::from_ssz(fork, &body)?;
        // Enforced here rather than at the call site so failover works: see the
        // contract on `BeaconNodeApi::produce_block`.
        validate_produced_block(request, &block)?;
        Ok(block)
    }

    /// 202 is not an error and not a clean success, so it is neither mapped to
    /// `Err` nor flattened into `Ok(())`. See [`Published`].
    async fn publish_block(&self, fork: ForkName, body: &[u8]) -> Result<Published> {
        let path = "/eth/v2/beacon/blocks";
        let url = format!("{}{path}", self.base_url);
        let response = self
            .client
            .post(&url)
            .header("Eth-Consensus-Version", fork.as_str())
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
        if status == StatusCode::ACCEPTED {
            return Ok(Published::BroadcastNotImported);
        }
        if status.is_success() {
            return Ok(Published::Imported);
        }
        let body = response.text().await.unwrap_or_default();
        Err(Error::BeaconNodeStatus {
            status: status.as_u16(),
            body,
        })
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
        let body = response.text().await.unwrap_or_default();
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
        let response: Option<VersionedResponse<gloas::PayloadAttestationData>> = self
            .get_optional(&format!(
                "/eth/v1/validator/payload_attestation_data?slot={slot}"
            ))
            .await?;
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
        let body = response.text().await.unwrap_or_default();
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
        let body = response.text().await.unwrap_or_default();
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
        let body = response.text().await.unwrap_or_default();
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

    /// Before gloas the query still names committee 0, exactly as it always
    /// has; from gloas it is omitted.
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

    #[test]
    fn the_committee_index_is_omitted_from_gloas_on() {
        assert_eq!(
            HttpBeaconNode::attestation_data_path(96, ForkName::Fulu),
            "/eth/v1/validator/attestation_data?slot=96&committee_index=0"
        );
        assert_eq!(
            HttpBeaconNode::attestation_data_path(96, ForkName::Gloas),
            "/eth/v1/validator/attestation_data?slot=96"
        );
    }

    /// The body `produceBlockV4` requires: self-build only, so no builders.
    #[test]
    fn the_builder_config_is_the_documented_self_build_body() {
        let value: serde_json::Value = serde_json::from_str(BUILDER_CONFIG).expect("valid json");
        assert_eq!(value["min_bid"], "0");
        assert_eq!(value["builder_boost_factor"], "0");
        assert_eq!(value["builders"], serde_json::json!([]));
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
}
