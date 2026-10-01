//! The JSON-RPC client, its retry ladder, and the four methods.

use std::time::Duration;

use ethlambda_types::beacon::containers::{deneb, gloas};
use ethlambda_types::beacon::primitives::{Bytes32, Root};
use serde_json::json;
use tracing::{debug, warn};

use crate::auth::JwtSecret;
use crate::error::EngineError;
use crate::types::{
    ClientVersionV1, ExecutionPayloadV3, ExecutionPayloadV4, ForkchoiceStateV1,
    ForkchoiceUpdatedResponse, PayloadStatusV1, data,
};

/// Per-attempt timeout.
///
/// The specification's own value for `engine_newPayload` and
/// `engine_forkchoiceUpdated`. It is a ceiling, not a target: a healthy
/// `newPayload` on mainnet answers in 50-500 ms.
pub const ENGINE_TIMEOUT: Duration = Duration::from_secs(8);

/// Per-attempt timeout for `engine_newPayloadV5`, the value `amsterdam.md`
/// gives that method. Tighter than [`ENGINE_TIMEOUT`], which stays the default
/// for the older methods.
pub const ENGINE_NEW_PAYLOAD_V5_TIMEOUT: Duration = Duration::from_secs(6);

/// How many times one call is attempted before it is given up on.
///
/// Three, not the ten `ethlambda-p2p` uses for a peer fetch. Those are different
/// numbers measuring different things: a peer ladder is bounded by a millisecond
/// backoff and a per-request timeout of its own, while every attempt here can
/// cost [`ENGINE_TIMEOUT`], and the import cascade awaits it inline. Three
/// attempts bound one block's worst case at about twenty-five seconds of a
/// stalled actor; ten would bound it at roughly twenty mainnet slots.
///
/// An execution client that has not answered three calls at this timeout is not
/// going to answer a fourth.
pub const ENGINE_MAX_ATTEMPTS: u32 = 3;

/// First backoff between attempts, doubling thereafter.
///
/// Not the peer ladder's few milliseconds. That value is sized for a LAN round
/// trip to another node; an execution client that just failed a call is busy,
/// and asking again a few milliseconds later only makes it busier.
pub const ENGINE_INITIAL_BACKOFF: Duration = Duration::from_millis(500);

const BACKOFF_MULTIPLIER: u32 = 2;

/// A connection to one execution client's Engine API endpoint.
#[derive(Debug, Clone)]
pub struct EngineClient {
    http: reqwest::Client,
    endpoint: String,
    secret: JwtSecret,
}

impl EngineClient {
    pub fn new(endpoint: String, secret: JwtSecret) -> Result<Self, EngineError> {
        let http = reqwest::Client::builder()
            .timeout(ENGINE_TIMEOUT)
            .build()
            .map_err(|err| EngineError::Transport(err.to_string()))?;
        Ok(Self {
            http,
            endpoint,
            secret,
        })
    }

    /// The endpoint this client posts to, for a startup log line.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// One JSON-RPC call, retried up to [`ENGINE_MAX_ATTEMPTS`] times.
    ///
    /// Only failures to get an answer are retried. An [`EngineError::Rpc`] is
    /// the execution client answering: with a refusal, but an answer, so asking
    /// again would get the same refusal and burn the ladder for nothing.
    ///
    /// After the last attempt this returns `Err`, and the caller must not import
    /// the block: `optimistic-sync.md` requires exactly that, and the caller may
    /// queue the block for later. It is worth being explicit that nothing here
    /// re-drives a given-up call, so a persistently unreachable execution client
    /// parks the follower's head behind the first block it could not ask about.
    /// That is a known and accepted limitation of this phase; the fix is a
    /// tick-driven re-drive of the pending set.
    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T, EngineError> {
        self.call_with_timeout(method, params, ENGINE_TIMEOUT).await
    }

    /// [`Self::call`] with a per-attempt `timeout` of the method's own.
    async fn call_with_timeout<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
        timeout: Duration,
    ) -> Result<T, EngineError> {
        let mut backoff = ENGINE_INITIAL_BACKOFF;
        let mut last = EngineError::Transport("no attempt was made".to_string());

        for attempt in 1..=ENGINE_MAX_ATTEMPTS {
            match self.call_once(method, &params, timeout).await {
                Ok(value) => return Ok(value),
                // An answer, not a failure to get one. Do not retry.
                Err(err @ EngineError::Rpc { .. }) => return Err(err),
                Err(err) => {
                    warn!(method, attempt, %err, "Engine call failed");
                    last = err;
                }
            }
            if attempt < ENGINE_MAX_ATTEMPTS {
                tokio::time::sleep(backoff).await;
                backoff *= BACKOFF_MULTIPLIER;
            }
        }

        Err(last)
    }

    async fn call_once<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: &serde_json::Value,
        timeout: Duration,
    ) -> Result<T, EngineError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let response = self
            .http
            .post(&self.endpoint)
            .bearer_auth(self.secret.token())
            .timeout(timeout)
            .json(&body)
            .send()
            .await
            .map_err(|err| {
                if err.is_timeout() {
                    EngineError::Timeout(timeout)
                } else {
                    EngineError::Transport(err.to_string())
                }
            })?;

        // Check the status before parsing. A rejected JWT answers 401 with a
        // body that is not a JSON-RPC envelope, and a reverse proxy in front of
        // the execution client can answer 5xx with HTML; parsing either first
        // turns a precise, actionable failure into an opaque decode error.
        // Transport rather than a terminal error, so an execution client that
        // is merely still starting up gets the rest of the ladder.
        let status = response.status();
        if !status.is_success() {
            return Err(EngineError::Transport(format!(
                "the execution client answered HTTP {status}"
            )));
        }

        let envelope: serde_json::Value = response
            .json()
            .await
            .map_err(|err| EngineError::Decode(err.to_string()))?;

        if let Some(error) = envelope.get("error") {
            return Err(EngineError::Rpc {
                code: error
                    .get("code")
                    .and_then(|code| code.as_i64())
                    .unwrap_or(0),
                message: error
                    .get("message")
                    .and_then(|message| message.as_str())
                    .unwrap_or("(no message)")
                    .to_string(),
            });
        }

        let result = envelope.get("result").ok_or_else(|| {
            EngineError::Decode("response carried neither result nor error".to_string())
        })?;

        serde_json::from_value(result.clone()).map_err(|err| EngineError::Decode(err.to_string()))
    }

    /// `engine_newPayloadV4`.
    ///
    /// Osaka's `newPayload`: Osaka adds no version of its own, and V5 is
    /// Amsterdam's. The four parameters are the payload, the versioned hashes
    /// the block's blob commitments imply, the parent beacon block root, and the
    /// EIP-7685 execution requests list.
    pub async fn new_payload(
        &self,
        payload: &deneb::ExecutionPayload,
        versioned_hashes: &[Bytes32],
        parent_beacon_block_root: Root,
        execution_requests: &[Vec<u8>],
    ) -> Result<PayloadStatusV1, EngineError> {
        let hashes: Vec<String> = versioned_hashes.iter().map(|hash| data(&hash.0)).collect();
        let requests: Vec<String> = execution_requests
            .iter()
            .map(|request| data(request))
            .collect();
        let params = json!([
            ExecutionPayloadV3(payload),
            hashes,
            data(&parent_beacon_block_root.0),
            requests,
        ]);
        self.call("engine_newPayloadV4", params).await
    }

    /// `engine_newPayloadV5`: Amsterdam's `newPayload`, which gloas asks about
    /// a revealed execution payload envelope.
    ///
    /// The parameters are the same four as V4's, with the payload as
    /// `ExecutionPayloadV4` (adding `blockAccessList` and `slotNumber`). The
    /// response is V4's. An execution client answers `-38005` when the
    /// payload's timestamp is not Amsterdam's, which surfaces as
    /// [`EngineError::Rpc`] and is not retried.
    pub async fn new_payload_v5(
        &self,
        payload: &gloas::ExecutionPayload,
        versioned_hashes: &[Bytes32],
        parent_beacon_block_root: Root,
        execution_requests: &[Vec<u8>],
    ) -> Result<PayloadStatusV1, EngineError> {
        let hashes: Vec<String> = versioned_hashes.iter().map(|hash| data(&hash.0)).collect();
        let requests: Vec<String> = execution_requests
            .iter()
            .map(|request| data(request))
            .collect();
        let params = json!([
            ExecutionPayloadV4(payload),
            hashes,
            data(&parent_beacon_block_root.0),
            requests,
        ]);
        self.call_with_timeout("engine_newPayloadV5", params, ENGINE_NEW_PAYLOAD_V5_TIMEOUT)
            .await
    }

    /// `engine_forkchoiceUpdatedV3`, always with a `null` `payloadAttributes`.
    ///
    /// A follower never proposes, so it never asks an execution client to start
    /// building. That also keeps this call outside the fork-scheduling rules
    /// attached to `payloadAttributes.timestamp`.
    pub async fn forkchoice_updated(
        &self,
        state: &ForkchoiceStateV1,
    ) -> Result<PayloadStatusV1, EngineError> {
        let params = json!([state, serde_json::Value::Null]);
        let response: ForkchoiceUpdatedResponse =
            self.call("engine_forkchoiceUpdatedV3", params).await?;
        Ok(response.payload_status)
    }

    /// `engine_forkchoiceUpdatedV3` with `payloadAttributes`: the same fork
    /// choice notification, plus a request to start building a payload on the
    /// head for the slot the attributes describe.
    ///
    /// Returns the head's status and the build process's id; the id is `None`
    /// when the execution client declined to build.
    pub async fn forkchoice_updated_with_attributes(
        &self,
        state: &ForkchoiceStateV1,
        attributes: &crate::building::PayloadAttributesV3,
    ) -> Result<(PayloadStatusV1, Option<crate::building::PayloadId>), EngineError> {
        let params = json!([state, attributes]);
        let response: ForkchoiceUpdatedResponse =
            self.call("engine_forkchoiceUpdatedV3", params).await?;
        Ok((response.payload_status, response.payload_id))
    }

    /// `engine_getPayloadV5`: the payload a build process has assembled so
    /// far, with its blobs bundle and execution requests.
    pub async fn get_payload(
        &self,
        payload_id: crate::building::PayloadId,
    ) -> Result<crate::building::BuiltPayload, EngineError> {
        let response: crate::building::GetPayloadV5Response = self
            .call("engine_getPayloadV5", json!([payload_id]))
            .await?;
        response.try_into()
    }

    /// `engine_exchangeCapabilities`. Returns what the execution client says it
    /// supports.
    pub async fn exchange_capabilities(&self, ours: &[&str]) -> Result<Vec<String>, EngineError> {
        self.call("engine_exchangeCapabilities", json!([ours]))
            .await
    }

    /// `engine_getClientVersionV1`.
    pub async fn client_version(
        &self,
        ours: &ClientVersionV1,
    ) -> Result<Vec<ClientVersionV1>, EngineError> {
        self.call("engine_getClientVersionV1", json!([ours])).await
    }

    /// Runs the startup handshake, logging what the execution client is and
    /// warning about any method this client needs that it does not advertise.
    ///
    /// Warns rather than refuses: an execution client that under-reports its
    /// capabilities still works, and refusing to start over a handshake would
    /// turn a cosmetic mismatch into an outage.
    pub async fn handshake(&self, ours: &ClientVersionV1) -> Result<(), EngineError> {
        let theirs = self
            .exchange_capabilities(crate::ETHLAMBDA_ENGINE_CAPABILITIES)
            .await?;
        for required in ["engine_newPayloadV4", "engine_forkchoiceUpdatedV3"] {
            if !theirs.iter().any(|method| method == required) {
                warn!(
                    method = required,
                    "The execution client does not advertise a method this node needs"
                );
            }
        }
        // Kept out of the list above: V5 is only called from gloas on, and a
        // node on an earlier fork never needs it.
        if !theirs.iter().any(|method| method == "engine_newPayloadV5") {
            warn!(
                method = "engine_newPayloadV5",
                "The execution client does not advertise a method this node needs from gloas on"
            );
        }
        match self.client_version(ours).await {
            Ok(versions) => {
                for version in versions {
                    debug!(
                        code = %version.code,
                        name = %version.name,
                        version = %version.version,
                        commit = %version.commit,
                        "Execution client"
                    );
                }
            }
            // Optional by the specification's own word ("SHOULD support").
            Err(err) => debug!(%err, "The execution client did not report its version"),
        }
        Ok(())
    }
}
