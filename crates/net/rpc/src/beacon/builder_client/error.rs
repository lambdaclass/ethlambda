//! What can go wrong talking to a builder.

use std::time::Duration;

use reqwest::StatusCode;

use super::{read_body, truncate_error_text};

/// A failed builder API call.
///
/// A Beacon API handler answers [`BadRequest`](Self::BadRequest) with the
/// builder's own 400 and anything else with a 500.
#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    /// No complete answer within the call's deadline.
    #[error("builder did not answer within {0:?}")]
    Timeout(Duration),
    /// The request did not complete: refused, reset, DNS, TLS.
    #[error("builder unreachable: {0}")]
    Transport(String),
    /// The builder refused the request as invalid, with its reason.
    #[error("builder refused the request: {0}")]
    BadRequest(String),
    /// A status the call does not expect.
    #[error("builder answered {status}: {body}")]
    Status { status: u16, body: String },
    /// A body that does not decode as what the call returns.
    #[error("builder response did not decode: {0}")]
    Decode(String),
    /// A response missing something it needs to be read.
    #[error("builder response is incomplete: {0}")]
    Incomplete(String),
    /// A bid for a fork whose containers this node does not decode.
    #[error("builder offered a bid for {0}")]
    UnsupportedFork(String),
    /// An answer longer than the client reads.
    #[error("builder answer larger than {limit} bytes")]
    TooLarge { limit: usize },
    /// A builder URL that does not parse.
    #[error("invalid builder url: {0}")]
    InvalidUrl(String),
    /// A request body this node could not encode.
    #[error("request did not encode: {0}")]
    Encode(String),
}

impl BuilderError {
    /// The URL is dropped from the message: it may carry credentials, and
    /// the error ends up in logs and response bodies.
    pub(super) fn from_reqwest(err: reqwest::Error, deadline: Duration) -> Self {
        let err = err.without_url();
        if err.is_timeout() {
            Self::Timeout(deadline)
        } else {
            Self::Transport(err.to_string())
        }
    }

    /// The error a status other than the call's success stands for. A 400
    /// carries the builder's `message`, or its raw body if it sent no JSON.
    pub(super) async fn from_status(response: reqwest::Response, deadline: Duration) -> Self {
        let status = response.status();
        let body = read_body(response, deadline).await.unwrap_or_default();
        let body = String::from_utf8_lossy(&body).into_owned();
        if status != StatusCode::BAD_REQUEST {
            return Self::Status {
                status: status.as_u16(),
                body: truncate_error_text(body),
            };
        }
        let message = serde_json::from_str::<ErrorMessage>(&body)
            .map(|error| error.message)
            .unwrap_or(body);
        Self::BadRequest(truncate_error_text(message))
    }

    /// How the call ended, as a metric label.
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Timeout(_) => "timeout",
            Self::Transport(_) => "unreachable",
            Self::BadRequest(_) => "bad_request",
            Self::Status { .. } => "unexpected_status",
            Self::Decode(_) | Self::Incomplete(_) | Self::TooLarge { .. } => "invalid_response",
            Self::InvalidUrl(_) => "invalid_url",
            Self::UnsupportedFork(_) => "unsupported_fork",
            Self::Encode(_) => "encode",
        }
    }
}

/// builder-specs' `ErrorMessage`, of which only the message is kept.
#[derive(serde::Deserialize)]
struct ErrorMessage {
    message: String,
}
