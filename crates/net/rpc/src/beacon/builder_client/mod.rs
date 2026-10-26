//! The builder API client (`ethereum/builder-specs`): how this node talks to
//! MEV-Boost, or to a relay directly, on a proposer's behalf.
//!
//! One client per URL. Requests go out in SSZ until the URL refuses it (406
//! or 415), then in JSON for good, since a builder either takes SSZ or it
//! does not. Responses are decoded by their own `Content-Type`, not by what
//! was asked for: a builder may answer JSON to an SSZ request without
//! refusing it.
//!
//! Every call is timed into `lean_beacon_builder_request_seconds`, by call
//! and outcome.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ethlambda_types::beacon::builder::SignedBuilderBid;
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::primitives::{BlsPubkey, ExecutionBlockHash, Slot};
use libssz::SszDecode as _;
use reqwest::StatusCode;
use reqwest::header::{self, HeaderMap};
use tracing::debug;

use crate::metrics::observe_builder_request;

mod error;
#[cfg(test)]
pub(crate) mod mock_relay;
#[cfg(test)]
mod tests;

pub use error::BuilderError;

const JSON_CONTENT_TYPE: &str = "application/json";

/// `getHeader`'s `Accept` while the URL still takes SSZ: SSZ preferred and
/// JSON acceptable, so a JSON-only builder answers instead of refusing.
const ACCEPT_SSZ_FIRST: &str = "application/octet-stream;q=1.0,application/json;q=0.9";

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
        let http = reqwest::Client::builder()
            .user_agent(user_agent)
            .build()
            .map_err(|err| BuilderError::Transport(err.to_string()))?;
        let base_url = base_url.into().trim_end_matches('/').to_owned();
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
        let mut response = self.send_get_header(&path).await?;
        if response.status() == StatusCode::NOT_ACCEPTABLE
            && !self.json_only.load(Ordering::Relaxed)
        {
            self.fall_back_to_json();
            response = self.send_get_header(&path).await?;
        }
        match response.status() {
            StatusCode::OK => decode_bid(response, self.header_timeout).await.map(Some),
            StatusCode::NO_CONTENT => Ok(None),
            _ => Err(BuilderError::from_status(response).await),
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
            .map_err(|err| BuilderError::from_reqwest(&err, self.header_timeout))
    }

    fn fall_back_to_json(&self) {
        debug!(url = %self.base_url, "Builder refused SSZ; using JSON from now on");
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
    let body = response
        .bytes()
        .await
        .map_err(|err| BuilderError::from_reqwest(&err, deadline))?;

    if ssz {
        // builder-specs makes this header optional, but an SSZ body has no
        // other way to name its fork, and the bid's shape depends on it.
        let version = named_fork.ok_or_else(|| {
            BuilderError::Incomplete("an SSZ bid without Eth-Consensus-Version".to_owned())
        })?;
        let fork = bid_fork(&version)?;
        let bid = SignedBuilderBid::from_ssz_bytes(&body)
            .map_err(|err| BuilderError::Decode(format!("{err:?}")))?;
        return Ok(VersionedBid { fork, bid });
    }
    let envelope: JsonBid =
        serde_json::from_slice(&body).map_err(|err| BuilderError::Decode(err.to_string()))?;
    let fork = bid_fork(&envelope.version.to_ascii_lowercase())?;
    let bid = serde_json::from_value(envelope.data)
        .map_err(|err| BuilderError::Decode(err.to_string()))?;
    Ok(VersionedBid { fork, bid })
}

/// The fork `version` names, if its bids have the shape [`SignedBuilderBid`]
/// decodes. Electra and fulu share it; no other fork does.
fn bid_fork(version: &str) -> Result<ForkName, BuilderError> {
    match ForkName::parse(version) {
        Some(fork @ (ForkName::Electra | ForkName::Fulu)) => Ok(fork),
        _ => Err(BuilderError::UnsupportedFork(version.to_owned())),
    }
}

/// `getHeader`'s JSON body: the bid under `data`, its fork under `version`.
#[derive(serde::Deserialize)]
struct JsonBid {
    version: String,
    data: serde_json::Value,
}

fn is_ssz(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with(crate::SSZ_CONTENT_TYPE))
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_millis())
}
