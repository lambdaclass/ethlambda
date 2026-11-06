//! The JSON-RPC client, its retry ladder, and the four methods.

use std::time::Duration;

use ethlambda_types::beacon::containers::{deneb, gloas};
use ethlambda_types::beacon::primitives::{Bytes32, Root};
use serde_json::json;
use tracing::{debug, warn};

use crate::auth::JwtSecret;
use crate::error::EngineError;
use crate::types::{
    ClientVersionV1, CustodyColumns, ExecutionPayloadV3, ExecutionPayloadV4, ForkchoiceStateV1,
    ForkchoiceUpdatedResponse, ForkchoiceUpdatedV5Response, PayloadStatusV1, PayloadStatusV2, data,
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

/// Per-attempt timeout for `engine_getInclusionListV1`, the value `bogota.md`
/// gives that method: the list is due well inside the slot, so a slow answer
/// is no answer.
pub const ENGINE_GET_INCLUSION_LIST_TIMEOUT: Duration = Duration::from_secs(1);

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

    /// `engine_newPayloadV6`: Bogota's `newPayload`, which heze asks about a
    /// revealed execution payload envelope (EIP-7805).
    ///
    /// V5's four parameters plus the inclusion list transactions the payload
    /// is judged against; the answer adds whether a `VALID` payload satisfied
    /// them. Same timeout as V5.
    pub async fn new_payload_v6(
        &self,
        payload: &gloas::ExecutionPayload,
        versioned_hashes: &[Bytes32],
        parent_beacon_block_root: Root,
        execution_requests: &[Vec<u8>],
        inclusion_list_transactions: &[Vec<u8>],
    ) -> Result<PayloadStatusV2, EngineError> {
        let hashes: Vec<String> = versioned_hashes.iter().map(|hash| data(&hash.0)).collect();
        let requests: Vec<String> = execution_requests
            .iter()
            .map(|request| data(request))
            .collect();
        let transactions: Vec<String> = inclusion_list_transactions
            .iter()
            .map(|transaction| data(transaction))
            .collect();
        let params = json!([
            ExecutionPayloadV4(payload),
            hashes,
            data(&parent_beacon_block_root.0),
            requests,
            transactions,
        ]);
        self.call_with_timeout("engine_newPayloadV6", params, ENGINE_NEW_PAYLOAD_V5_TIMEOUT)
            .await
    }

    /// `engine_forkchoiceUpdatedV5`: Bogota's fork choice notification, with a
    /// `null` `payloadAttributes` and the custody set, answering with a
    /// [`PayloadStatusV2`] that says whether a `VALID` head satisfied its
    /// inclusion lists.
    pub async fn forkchoice_updated_v5(
        &self,
        state: &ForkchoiceStateV1,
        custody_columns: Option<CustodyColumns>,
    ) -> Result<PayloadStatusV2, EngineError> {
        let params = forkchoice_updated_v4_params(state, custody_columns);
        let response: ForkchoiceUpdatedV5Response =
            self.call("engine_forkchoiceUpdatedV5", params).await?;
        Ok(response.payload_status)
    }

    /// `engine_forkchoiceUpdatedV5` with `PayloadAttributesV5`: a build request
    /// whose payload must satisfy the attributes' inclusion list transactions.
    pub async fn forkchoice_updated_v5_with_attributes(
        &self,
        state: &ForkchoiceStateV1,
        attributes: &crate::building::PayloadAttributesV5,
        custody_columns: Option<CustodyColumns>,
    ) -> Result<(PayloadStatusV2, Option<crate::building::PayloadId>), EngineError> {
        let params = json!([state, attributes, custody_columns]);
        let response: ForkchoiceUpdatedV5Response =
            self.call("engine_forkchoiceUpdatedV5", params).await?;
        Ok((response.payload_status, response.payload_id))
    }

    /// `engine_getInclusionListV1`: the transactions the execution client would
    /// put in an inclusion list now, from its view of the mempool. Each is an
    /// EIP-2718 transaction's bytes.
    pub async fn get_inclusion_list_v1(&self) -> Result<Vec<Vec<u8>>, EngineError> {
        let transactions: Vec<String> = self
            .call_with_timeout(
                "engine_getInclusionListV1",
                json!([]),
                ENGINE_GET_INCLUSION_LIST_TIMEOUT,
            )
            .await?;
        transactions
            .iter()
            .map(|transaction| crate::building::parse_data(transaction))
            .collect()
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

    /// `engine_forkchoiceUpdatedV4`: Amsterdam's fork choice notification, with
    /// a `null` `payloadAttributes` and the consensus client's custody set.
    ///
    /// Follower only: there is no variant taking `PayloadAttributesV4`, since a
    /// follower never asks for a build. `custody_columns` of `None` sends
    /// `null`, meaning the consensus client provides no custody. The response
    /// is V3's.
    pub async fn forkchoice_updated_v4(
        &self,
        state: &ForkchoiceStateV1,
        custody_columns: Option<CustodyColumns>,
    ) -> Result<PayloadStatusV1, EngineError> {
        let params = forkchoice_updated_v4_params(state, custody_columns);
        let response: ForkchoiceUpdatedResponse =
            self.call("engine_forkchoiceUpdatedV4", params).await?;
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

    /// `engine_forkchoiceUpdatedV4` with `payloadAttributes`: Amsterdam's fork
    /// choice notification plus a request to build a payload for the slot the
    /// attributes name, with the consensus client's custody set.
    ///
    /// Returns the head's status and the build process's id; the id is `None`
    /// when the execution client declined to build.
    pub async fn forkchoice_updated_v4_with_attributes(
        &self,
        state: &ForkchoiceStateV1,
        attributes: &crate::building::PayloadAttributesV4,
        custody_columns: Option<CustodyColumns>,
    ) -> Result<(PayloadStatusV1, Option<crate::building::PayloadId>), EngineError> {
        let params = json!([state, attributes, custody_columns]);
        let response: ForkchoiceUpdatedResponse =
            self.call("engine_forkchoiceUpdatedV4", params).await?;
        Ok((response.payload_status, response.payload_id))
    }

    /// `engine_getPayloadV6`: [`Self::get_payload`] for Amsterdam, answering
    /// with `ExecutionPayloadV4` (`blockAccessList` and `slotNumber` included).
    pub async fn get_payload_v6(
        &self,
        payload_id: crate::building::PayloadId,
    ) -> Result<crate::building::BuiltGloasPayload, EngineError> {
        let response: crate::building::GetPayloadV6Response = self
            .call("engine_getPayloadV6", json!([payload_id]))
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
    /// `gloas_scheduled` says whether the network's fork schedule includes
    /// gloas, which is what makes `engine_newPayloadV5` a needed method;
    /// `heze_scheduled` does the same for heze's three Bogota methods.
    ///
    /// Warns rather than refuses: an execution client that under-reports its
    /// capabilities still works, and refusing to start over a handshake would
    /// turn a cosmetic mismatch into an outage.
    pub async fn handshake(
        &self,
        ours: &ClientVersionV1,
        gloas_scheduled: bool,
        heze_scheduled: bool,
    ) -> Result<(), EngineError> {
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
        // Kept out of the list above: these are only called from gloas on, so a
        // network that does not schedule gloas never needs it, and an
        // execution client that predates Amsterdam is right not to offer it.
        if gloas_scheduled {
            for required in [
                "engine_newPayloadV5",
                "engine_forkchoiceUpdatedV4",
                "engine_getPayloadV6",
            ] {
                if !theirs.iter().any(|method| method == required) {
                    warn!(
                        method = required,
                        "The execution client does not advertise a method this node needs from gloas on"
                    );
                }
            }
        }
        if heze_scheduled {
            for required in [
                "engine_newPayloadV6",
                "engine_forkchoiceUpdatedV5",
                "engine_getInclusionListV1",
            ] {
                if !theirs.iter().any(|method| method == required) {
                    warn!(
                        method = required,
                        "The execution client does not advertise a method this node needs from heze on"
                    );
                }
            }
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

/// The three positional parameters of `engine_forkchoiceUpdatedV4`: the state,
/// a `null` `payloadAttributes`, and the custody bitmap or `null`.
fn forkchoice_updated_v4_params(
    state: &ForkchoiceStateV1,
    custody_columns: Option<CustodyColumns>,
) -> serde_json::Value {
    json!([state, serde_json::Value::Null, custody_columns])
}

#[cfg(test)]
mod tests {
    use ethlambda_types::beacon::primitives::ExecutionBlockHash;

    use super::*;

    fn state() -> ForkchoiceStateV1 {
        ForkchoiceStateV1 {
            head_block_hash: ExecutionBlockHash::repeat_byte(1),
            safe_block_hash: ExecutionBlockHash::repeat_byte(2),
            finalized_block_hash: ExecutionBlockHash::repeat_byte(3),
        }
    }

    #[test]
    fn forkchoice_updated_v4_params_are_state_null_and_bitmap() {
        let columns = CustodyColumns::from_indices([0, 9]);
        let params = forkchoice_updated_v4_params(&state(), columns);
        let params = params.as_array().expect("an array of params");
        assert_eq!(params.len(), 3);
        assert!(params[0].get("headBlockHash").is_some());
        assert!(params[1].is_null());
        assert_eq!(params[2], "0x01020000000000000000000000000000");
    }

    #[test]
    fn forkchoice_updated_v4_without_custody_sends_a_third_null() {
        let params = forkchoice_updated_v4_params(&state(), None);
        let params = params.as_array().expect("an array of params");
        assert_eq!(params.len(), 3);
        assert!(params[2].is_null());
    }
}
