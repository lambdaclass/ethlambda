use crate::auth::JwtSecretError;

#[derive(Debug, thiserror::Error)]
pub enum EngineClientError {
    #[error("JWT auth error: {0}")]
    Auth(#[from] JwtSecretError),

    #[error("HTTP transport error: {0}")]
    Transport(#[from] reqwest::Error),

    #[error("failed to serialize request: {0}")]
    SerializeRequest(serde_json::Error),

    #[error("failed to deserialize response: {0}")]
    DeserializeResponse(serde_json::Error),

    #[error("EL returned RPC error {code} ({message})")]
    Rpc {
        code: i64,
        message: String,
        data: Option<serde_json::Value>,
    },

    #[error("EL response missing both `result` and `error` fields")]
    EmptyResponse,
}
