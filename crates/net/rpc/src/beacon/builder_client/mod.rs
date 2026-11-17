//! The builder API client (`ethereum/builder-specs`): how this node talks to
//! MEV-Boost, or to a relay directly, on a proposer's behalf.
//!
//! One client per URL, with an encoding chosen per call:
//! - `getHeader` asks SSZ first. A 406 fails that call with no retry, since a
//!   retry restarts the clock the proposer is waiting on; later calls ask for
//!   JSON.
//! - `registerValidator` is always JSON: MEV-Boost forwards the body
//!   unchanged to every relay and answers 200 if any one accepts it.
//! - `submitBlindedBlockV2` sends SSZ, which MEV-Boost converts per relay.
//!   After its own 415 it resends the block in JSON, and sends JSON from then
//!   on.
//!
//! Responses are decoded by their own `Content-Type`, not by what was asked
//! for: a builder may answer JSON to an SSZ request without refusing it.
//!
//! Every call is timed into `lean_beacon_builder_request_seconds`, by call
//! and outcome.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ethlambda_types::beacon::builder::{
    SignedBlindedBeaconBlock, SignedBuilderBid, SignedValidatorRegistrationV1,
};
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::primitives::{BlsPubkey, ExecutionBlockHash, Slot};
use libssz::{SszDecode as _, SszEncode as _};
use reqwest::StatusCode;
use reqwest::header::{self, HeaderMap};
use tracing::info;

use crate::metrics::observe_builder_request;

mod error;
#[cfg(test)]
pub(crate) mod mock_relay;
#[cfg(test)]
mod tests;

pub use error::BuilderError;

const JSON_CONTENT_TYPE: &str = "application/json";

/// The most a builder answer may hold. A fulu bid at its list limits is
/// under 2 MiB in SSZ and about twice that in JSON.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// How much of an error body is kept: enough to read, not a proxy's
/// whole error page in a log line or a 400 passed back to the caller.
const MAX_ERROR_TEXT: usize = 1024;

/// `getHeader`'s `Accept` while the URL still takes SSZ: SSZ preferred and
/// JSON acceptable, so a JSON-only builder answers instead of refusing.
const ACCEPT_SSZ_FIRST: &str = "application/octet-stream;q=1.0,application/json;q=0.9";

/// builder-specs gives `registerValidator` no deadline. Ten seconds covers a
/// batch of a few thousand registrations.
const REGISTER_TIMEOUT: Duration = Duration::from_secs(10);

/// At least MEV-Boost's own default of four seconds, which it spends
/// fetching the payload from its relays before it answers.
const SUBMIT_TIMEOUT: Duration = Duration::from_secs(5);

/// A builder API endpoint: a relay, or MEV-Boost in front of several.
#[derive(Debug, Clone)]
pub struct BuilderClient {
    base_url: String,
    http: reqwest::Client,
    header_timeout: Duration,
    /// Set once the URL refuses SSZ. Clones share it, so the switch holds
    /// for the URL rather than for one copy of the client.
    json_only: Arc<AtomicBool>,
}

/// A bid, with the fork its builder says it was built for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionedBid {
    pub fork: ForkName,
    pub bid: SignedBuilderBid,
}

impl BuilderClient {
    /// A client for `base_url` that identifies itself as `user_agent`.
    ///
    /// `header_timeout` bounds `getHeader`. It is also sent to the builder as
    /// `X-Timeout-Ms`, so the builder can hold its answer for as long as the
    /// proposer will wait and no longer.
    pub fn new(
        base_url: impl Into<String>,
        header_timeout: Duration,
        user_agent: &str,
    ) -> Result<Self, BuilderError> {
        let base_url = base_url.into();
        let url = reqwest::Url::parse(&base_url)
            .map_err(|err| BuilderError::InvalidUrl(err.to_string()))?;
        // `localhost:18550` parses, with `localhost` as its scheme.
        if !matches!(url.scheme(), "http" | "https") {
            return Err(BuilderError::InvalidUrl(format!(
                "expected an http or https url, got scheme {:?}",
                url.scheme()
            )));
        }
        let http = reqwest::Client::builder()
            .user_agent(user_agent)
            .build()
            .map_err(|err| BuilderError::Transport(err.without_url().to_string()))?;
        let base_url = base_url.trim_end_matches('/').to_owned();
        Ok(Self {
            base_url,
            http,
            header_timeout,
            json_only: Arc::default(),
        })
    }

    /// `getHeader`: the builder's best bid for `slot`, on top of
    /// `parent_hash`, for the proposer `pubkey`. `None` when it has none
    /// (204).
    pub async fn get_header(
        &self,
        slot: Slot,
        parent_hash: ExecutionBlockHash,
        pubkey: &BlsPubkey,
    ) -> Result<Option<VersionedBid>, BuilderError> {
        let started = Instant::now();
        let result = self.try_get_header(slot, parent_hash, pubkey).await;
        let outcome = match &result {
            Ok(Some(_)) => "ok",
            Ok(None) => "no_bid",
            Err(err) => err.label(),
        };
        observe_builder_request("get_header", outcome, started.elapsed());
        result
    }

    async fn try_get_header(
        &self,
        slot: Slot,
        parent_hash: ExecutionBlockHash,
        pubkey: &BlsPubkey,
    ) -> Result<Option<VersionedBid>, BuilderError> {
        let path = format!(
            "/eth/v1/builder/header/{slot}/0x{}/0x{}",
            hex::encode(parent_hash.0),
            hex::encode(pubkey.0)
        );
        let asked_ssz = !self.json_only.load(Ordering::Relaxed);
        let response = self.send_get_header(&path).await?;
        match response.status() {
            StatusCode::OK => decode_bid(response, self.header_timeout).await.map(Some),
            StatusCode::NO_CONTENT => Ok(None),
            status => {
                // No retry: a second request would get a fresh timeout, and
                // one call could then take twice the proposer's budget. The
                // next call asks for JSON instead.
                if status == StatusCode::NOT_ACCEPTABLE && asked_ssz {
                    self.fall_back_to_json();
                }
                Err(BuilderError::from_status(response, self.header_timeout).await)
            }
        }
    }

    async fn send_get_header(&self, path: &str) -> Result<reqwest::Response, BuilderError> {
        let accept = if self.json_only.load(Ordering::Relaxed) {
            JSON_CONTENT_TYPE
        } else {
            ACCEPT_SSZ_FIRST
        };
        self.http
            .get(self.url(path))
            .timeout(self.header_timeout)
            .header(header::ACCEPT, accept)
            .header("x-timeout-ms", self.header_timeout.as_millis().to_string())
            .header("date-milliseconds", unix_millis().to_string())
            .send()
            .await
            .map_err(|err| BuilderError::from_reqwest(err, self.header_timeout))
    }

    /// `registerValidator`: forwards signed registrations in one request.
    ///
    /// Always in JSON. MEV-Boost passes a registration's body and content
    /// type to every relay unchanged and answers 200 if any one accepts it,
    /// so an SSZ registration would be dropped without a word by every relay
    /// that does not take SSZ.
    pub async fn register_validators(
        &self,
        registrations: &[SignedValidatorRegistrationV1],
    ) -> Result<(), BuilderError> {
        let started = Instant::now();
        let result = self.try_register_validators(registrations).await;
        observe_builder_request("register_validators", outcome(&result), started.elapsed());
        result
    }

    async fn try_register_validators(
        &self,
        registrations: &[SignedValidatorRegistrationV1],
    ) -> Result<(), BuilderError> {
        let body = serde_json::to_vec(registrations)
            .map_err(|err| BuilderError::Encode(err.to_string()))?;
        let response = self
            .http
            .post(self.url("/eth/v1/builder/validators"))
            .timeout(REGISTER_TIMEOUT)
            .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .body(body)
            .send()
            .await
            .map_err(|err| BuilderError::from_reqwest(err, REGISTER_TIMEOUT))?;
        match response.status() {
            StatusCode::OK => Ok(()),
            _ => Err(BuilderError::from_status(response, REGISTER_TIMEOUT).await),
        }
    }

    /// `submitBlindedBlockV2`: hands a signed blinded block to the builder,
    /// which publishes the full block and its blobs itself.
    ///
    /// Only a 202 is success. The proposer is committed once this is sent,
    /// so a caller has no local block to fall back on whatever this returns.
    pub async fn submit_blinded_block(
        &self,
        block: &SignedBlindedBeaconBlock,
        fork: ForkName,
    ) -> Result<(), BuilderError> {
        let started = Instant::now();
        let result = self.try_submit_blinded_block(block, fork).await;
        observe_builder_request("submit_blinded_block", outcome(&result), started.elapsed());
        result
    }

    async fn try_submit_blinded_block(
        &self,
        block: &SignedBlindedBeaconBlock,
        fork: ForkName,
    ) -> Result<(), BuilderError> {
        let path = "/eth/v2/builder/blinded_blocks";
        if !self.json_only.load(Ordering::Relaxed) {
            let response = self
                .send_block(path, crate::SSZ_CONTENT_TYPE, block.to_ssz(), fork)
                .await?;
            // A 415 is this URL refusing SSZ, answered at once: send the
            // same block again in JSON, and JSON from now on.
            if response.status() != StatusCode::UNSUPPORTED_MEDIA_TYPE {
                return submission_result(response).await;
            }
            self.fall_back_to_json();
        }
        let body =
            serde_json::to_vec(block).map_err(|err| BuilderError::Encode(err.to_string()))?;
        let response = self.send_block(path, JSON_CONTENT_TYPE, body, fork).await?;
        submission_result(response).await
    }

    async fn send_block(
        &self,
        path: &str,
        content_type: &'static str,
        body: Vec<u8>,
        fork: ForkName,
    ) -> Result<reqwest::Response, BuilderError> {
        self.http
            .post(self.url(path))
            .timeout(SUBMIT_TIMEOUT)
            .header(header::CONTENT_TYPE, content_type)
            .header("eth-consensus-version", fork.as_str())
            .body(body)
            .send()
            .await
            .map_err(|err| BuilderError::from_reqwest(err, SUBMIT_TIMEOUT))
    }

    fn fall_back_to_json(&self) {
        info!("Builder refused SSZ; using JSON from now on");
        self.json_only.store(true, Ordering::Relaxed);
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }
}

/// A bid, decoded by the response's own `Content-Type`.
async fn decode_bid(
    response: reqwest::Response,
    deadline: Duration,
) -> Result<VersionedBid, BuilderError> {
    let ssz = is_ssz(response.headers());
    let named_fork = response
        .headers()
        .get("eth-consensus-version")
        .and_then(|value| value.to_str().ok())
        .map(str::to_ascii_lowercase);
    let body = read_body(response, deadline).await?;

    if ssz {
        // builder-specs requires this header on an SSZ answer, since nothing
        // else in an SSZ body names its fork and the bid's shape depends on it.
        let version = named_fork.ok_or_else(|| {
            BuilderError::Incomplete("an SSZ bid without Eth-Consensus-Version".to_owned())
        })?;
        let fork = bid_fork(&version)?;
        let bid = SignedBuilderBid::from_ssz_bytes(&body)
            .map_err(|err| BuilderError::Decode(format!("{err:?}")))?;
        return Ok(VersionedBid { fork, bid });
    }
    // Two typed passes over the same bytes, each ignoring the other's field,
    // so the bid is never built as an intermediate `serde_json::Value`.
    let Version { version } =
        serde_json::from_slice(&body).map_err(|err| BuilderError::Decode(err.to_string()))?;
    let fork = bid_fork(&version.to_ascii_lowercase())?;
    let Data { data: bid } =
        serde_json::from_slice(&body).map_err(|err| BuilderError::Decode(err.to_string()))?;
    Ok(VersionedBid { fork, bid })
}

/// The whole body, or `TooLarge` as soon as it would pass the cap.
pub(super) async fn read_body(
    mut response: reqwest::Response,
    deadline: Duration,
) -> Result<Vec<u8>, BuilderError> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| BuilderError::from_reqwest(err, deadline))?
    {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(BuilderError::TooLarge {
                limit: MAX_RESPONSE_BYTES,
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// `text` cut to at most [`MAX_ERROR_TEXT`] bytes, at a char boundary.
pub(super) fn truncate_error_text(mut text: String) -> String {
    if text.len() > MAX_ERROR_TEXT {
        let mut end = MAX_ERROR_TEXT;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

/// The fork `version` names, if its bids have the shape [`SignedBuilderBid`]
/// decodes. Electra and fulu share it; no other fork does.
fn bid_fork(version: &str) -> Result<ForkName, BuilderError> {
    match ForkName::parse(version) {
        Some(fork @ (ForkName::Electra | ForkName::Fulu)) => Ok(fork),
        _ => Err(BuilderError::UnsupportedFork(version.to_owned())),
    }
}

/// `getHeader`'s JSON body holds its fork under `version`...
#[derive(serde::Deserialize)]
struct Version {
    version: String,
}

/// ...and the bid under `data`.
#[derive(serde::Deserialize)]
struct Data {
    data: SignedBuilderBid,
}

fn is_ssz(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with(crate::SSZ_CONTENT_TYPE))
}

/// How a call whose success is just `ok` ended, as a metric label.
fn outcome<T>(result: &Result<T, BuilderError>) -> &'static str {
    result.as_ref().map_or_else(BuilderError::label, |_| "ok")
}

/// A submission's answer: only 202 is success.
async fn submission_result(response: reqwest::Response) -> Result<(), BuilderError> {
    match response.status() {
        StatusCode::ACCEPTED => Ok(()),
        _ => Err(BuilderError::from_status(response, SUBMIT_TIMEOUT).await),
    }
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_millis())
}
