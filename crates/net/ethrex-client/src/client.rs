//! `EngineClient` — typed wrapper around the engine_* JSON-RPC methods.
//!
//! Single `reqwest::Client` instance per `EngineClient`, mints a fresh JWT
//! per request (cheap — HMAC-SHA256 over ~70 bytes).

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{debug, trace};

use crate::{
    auth::JwtSecret,
    error::EngineClientError,
    types::{
        ExecutionPayloadV3, ForkChoiceState, ForkChoiceUpdatedResponse, PayloadAttributesV3,
        PayloadId, PayloadStatus,
    },
};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Debug, Clone)]
pub struct EngineClient {
    http: reqwest::Client,
    url: String,
    secret: JwtSecret,
}

impl EngineClient {
    /// Build a client targeting `url` (e.g. `http://127.0.0.1:8551`) with
    /// the given shared secret.
    pub fn new(url: impl Into<String>, secret: JwtSecret) -> Result<Self, EngineClientError> {
        let http = reqwest::Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .build()?;
        Ok(Self {
            http,
            url: url.into(),
            secret,
        })
    }

    /// Build a client with a caller-supplied `reqwest::Client` (lets the
    /// caller plug in a custom timeout / connector). Useful for tests.
    pub fn with_http_client(
        url: impl Into<String>,
        secret: JwtSecret,
        http: reqwest::Client,
    ) -> Self {
        Self {
            http,
            url: url.into(),
            secret,
        }
    }

    /// Endpoint URL this client targets.
    pub fn endpoint(&self) -> &str {
        &self.url
    }

    async fn rpc_call<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> Result<T, EngineClientError> {
        let token = self.secret.sign_now()?;
        let body = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method,
            params,
        };
        let body_str = serde_json::to_string(&body).map_err(EngineClientError::SerializeRequest)?;
        trace!(method, body = %body_str, "engine RPC request");

        let raw = self
            .http
            .post(&self.url)
            .bearer_auth(&token)
            .header("content-type", "application/json")
            .body(body_str)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        trace!(method, response = %raw, "engine RPC response");

        let envelope: JsonRpcEnvelope =
            serde_json::from_str(&raw).map_err(EngineClientError::DeserializeResponse)?;
        if let Some(err) = envelope.error {
            return Err(EngineClientError::Rpc {
                code: err.code,
                message: err.message,
                data: err.data,
            });
        }
        let result = envelope.result.ok_or(EngineClientError::EmptyResponse)?;
        serde_json::from_value(result).map_err(EngineClientError::DeserializeResponse)
    }

    /// `engine_exchangeCapabilities` — sent at startup. Returns the
    /// intersection of what we advertise and what the EL supports.
    pub async fn exchange_capabilities(
        &self,
        our_capabilities: &[&str],
    ) -> Result<Vec<String>, EngineClientError> {
        let params = json!([our_capabilities]);
        let caps: Vec<String> = self.rpc_call("engine_exchangeCapabilities", params).await?;
        debug!(count = caps.len(), "received EL capabilities");
        Ok(caps)
    }

    /// `engine_forkchoiceUpdatedV3` — head/safe/finalized update, with
    /// optional payload attributes to request a build.
    pub async fn forkchoice_updated_v3(
        &self,
        state: ForkChoiceState,
        payload_attributes: Option<PayloadAttributesV3>,
    ) -> Result<ForkChoiceUpdatedResponse, EngineClientError> {
        let params = json!([state, payload_attributes]);
        self.rpc_call("engine_forkchoiceUpdatedV3", params).await
    }

    /// `engine_newPayloadV3` — submit a Cancun-era payload to the EL.
    pub async fn new_payload_v3(
        &self,
        payload: ExecutionPayloadV3,
        expected_blob_versioned_hashes: Vec<ethlambda_types::primitives::H256>,
        parent_beacon_block_root: ethlambda_types::primitives::H256,
    ) -> Result<PayloadStatus, EngineClientError> {
        let params = json!([
            payload,
            expected_blob_versioned_hashes,
            parent_beacon_block_root
        ]);
        self.rpc_call("engine_newPayloadV3", params).await
    }

    /// `engine_getPayloadV3` — fetch a payload built under a previously
    /// returned `payload_id`.
    pub async fn get_payload_v3(&self, payload_id: PayloadId) -> Result<Value, EngineClientError> {
        // Returns a tagged blob containing `executionPayload`, `blockValue`,
        // `blobsBundle`, `shouldOverrideBuilder`. We surface the raw JSON
        // until block-import path needs to consume it.
        let params = json!([payload_id.to_hex()]);
        self.rpc_call("engine_getPayloadV3", params).await
    }

    /// `engine_getClientVersionV1` — used for diagnostics in startup logs.
    pub async fn get_client_version_v1(&self) -> Result<Value, EngineClientError> {
        let our = json!({
            "code": "EL",
            "name": "ethlambda",
            "version": "0",
            "commit": "0x00000000",
        });
        self.rpc_call("engine_getClientVersionV1", json!([our]))
            .await
    }
}

// ---------- JSON-RPC envelope ----------

#[derive(Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: Value,
}

#[derive(Deserialize)]
struct JsonRpcEnvelope {
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<JsonRpcError>,
}

#[derive(Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
    #[serde(default)]
    data: Option<Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::JwtSecret;

    fn fake_secret() -> JwtSecret {
        JwtSecret::from_bytes(vec![7u8; 32]).unwrap()
    }

    #[test]
    fn client_builds_with_url() {
        let c = EngineClient::new("http://127.0.0.1:8551", fake_secret()).unwrap();
        assert_eq!(c.endpoint(), "http://127.0.0.1:8551");
    }

    #[tokio::test]
    async fn transport_error_surfaced_when_no_server() {
        // Unbound localhost port — connection should fail.
        let c = EngineClient::new("http://127.0.0.1:1", fake_secret()).unwrap();
        let err = c
            .exchange_capabilities(crate::ETHLAMBDA_ENGINE_CAPABILITIES)
            .await
            .unwrap_err();
        assert!(matches!(err, EngineClientError::Transport(_)));
    }
}
