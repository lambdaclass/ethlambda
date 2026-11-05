//! What can go wrong talking to a builder.

use std::time::Duration;

use reqwest::header;
use reqwest::{StatusCode, Url};

use super::{error_text, read_body};

/// A failed builder API call.
///
/// A Beacon API handler for registrations or blinded blocks answers
/// [`BadRequest`](Self::BadRequest) with the builder's own 400 and anything
/// else with a 500. On `produceBlockV3` any error just means no bid, and the
/// node builds locally.
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
    /// A success status other than the 202 `submitBlindedBlockV2` succeeds
    /// with. Told apart from [`Status`](Self::Status) because the builder may
    /// well have taken the block: 200 is what the V1 call answered.
    #[error(
        "builder answered {status}, a success but not the 202 Accepted submitBlindedBlockV2 requires; it may have taken the block anyway"
    )]
    UnexpectedSuccess { status: u16 },
    /// A redirect the client did not follow: any redirect without
    /// `--builder-follow-redirects`, and with it a 301, 302 or 303, an https
    /// to http downgrade, or the hop past the tenth.
    #[error(
        "builder redirected the request to {location} ({status}), which was not followed; \
         only --builder-follow-redirects follows a redirect, and then only a 307 or 308, \
         up to ten, never from https to http"
    )]
    Redirected { status: u16, location: String },
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
    /// A redirect carries its target.
    pub(super) async fn from_status(response: reqwest::Response, deadline: Duration) -> Self {
        let status = response.status();
        if is_redirect(status) {
            return Self::Redirected {
                status: status.as_u16(),
                location: shown_location(&response),
            };
        }
        let body = read_body(response, deadline).await.unwrap_or_default();
        let body = String::from_utf8_lossy(&body).into_owned();
        if status != StatusCode::BAD_REQUEST {
            return Self::Status {
                status: status.as_u16(),
                body: error_text(body),
            };
        }
        let message = serde_json::from_str::<ErrorMessage>(&body)
            .map(|error| error.message)
            .unwrap_or(body);
        Self::BadRequest(error_text(message))
    }

    /// How the call ended, as a metric label.
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Timeout(_) => "timeout",
            Self::Transport(_) => "unreachable",
            Self::BadRequest(_) => "bad_request",
            Self::Status { .. } => "unexpected_status",
            Self::UnexpectedSuccess { .. } => "unexpected_success",
            Self::Redirected { .. } => "redirected",
            Self::Decode(_) | Self::Incomplete(_) | Self::TooLarge { .. } => "invalid_response",
            Self::InvalidUrl(_) => "invalid_url",
            Self::UnsupportedFork(_) => "unsupported_fork",
            Self::Encode(_) => "encode",
        }
    }
}

/// Whether `status` is a redirect: one of the five statuses a client
/// follows, and the only ones reqwest consults its redirect policy on. Any
/// other 3xx (a 304 answering a conditional request, a 300 offering choices)
/// sends the client nowhere, so it is an ordinary unexpected status.
fn is_redirect(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

/// What a redirect shows when its target cannot be shown safely.
const UNSHOWN_LOCATION: &str = "a Location that does not resolve to a URL with a host";

/// A redirect's target as an error shows it.
fn shown_location(response: &reqwest::Response) -> String {
    let Some(value) = response.headers().get(header::LOCATION) else {
        return "nowhere (no Location header)".to_owned();
    };
    shown_target(response.url(), value.as_bytes())
}

/// `location` resolved against `base`, the URL that answered with it, as a
/// client following it would, then shown without any user or password and
/// cut to the error text cap: the error ends up in logs and response bodies
/// (see `from_reqwest`).
///
/// Never the raw value. `//user:pass@host/x` is a relative reference, so it
/// does not parse as a URL on its own, yet it carries credentials; resolved,
/// it is an absolute URL whose credentials can be removed. Resolving also
/// strips any `--builder` credentials a relative target would inherit from
/// `base`. A value that does not resolve, or resolves to a URL with no host
/// to hold credentials (`mailto:`), is shown as a fixed placeholder.
pub(super) fn shown_target(base: &Url, location: &[u8]) -> String {
    let location = String::from_utf8_lossy(location);
    base.join(&location)
        .ok()
        .and_then(without_credentials)
        .map_or_else(
            || UNSHOWN_LOCATION.to_owned(),
            |url| error_text(url.into()),
        )
}

/// `url` without its user and password, or `None` when it cannot hold them
/// and so cannot have them removed either.
pub(super) fn without_credentials(mut url: Url) -> Option<Url> {
    url.set_username("").ok()?;
    url.set_password(None).ok()?;
    Some(url)
}

/// builder-specs' `ErrorMessage`, of which only the message is kept.
#[derive(serde::Deserialize)]
struct ErrorMessage {
    message: String,
}
