//! What a response is encoded as, and how it says so.
//!
//! The Beacon API negotiates on `Accept`: JSON unless the caller asks for
//! `application/octet-stream`, which is the same order lighthouse serves
//! (`beacon_node/http_api/src/lib.rs`, the `get_beacon_block` and
//! `get_debug_beacon_states` handlers). The lean surface predates this and
//! defaults the other way on its two SSZ endpoints, so the default is the
//! caller's to pass rather than a constant here.

use axum::{
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};
use ethlambda_types::beacon::fork::ForkName;

/// Which encoding a response body carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Encoding {
    Json,
    Ssz,
}

impl Encoding {
    /// Read an `Accept` header, defaulting to JSON.
    ///
    /// Ranked by the `q` weight the header gives each type, since a client that
    /// accepts both states its preference that way and ignoring it would serve
    /// SSZ to a caller who merely tolerates it. An absent, wildcard or unknown
    /// type is JSON: it is the encoding every consumer can read.
    pub(crate) fn from_accept(accept: Option<&str>) -> Self {
        let Some(accept) = accept else {
            return Encoding::Json;
        };

        let mut best = (Encoding::Json, -1.0f32);
        for entry in accept.split(',') {
            let mut parts = entry.split(';');
            let media = parts.next().unwrap_or("").trim();
            let encoding = match media {
                "application/octet-stream" => Encoding::Ssz,
                "application/json" => Encoding::Json,
                _ => continue,
            };
            let weight = parts
                .find_map(|p| p.trim().strip_prefix("q=")?.parse::<f32>().ok())
                .unwrap_or(1.0);
            if weight > best.1 {
                best = (encoding, weight);
            }
        }

        best.0
    }
}

/// Tag a response with the fork its body was encoded under.
///
/// Required on every response carrying a fork-versioned container, in both
/// encodings, so an SSZ caller can tell which container it just received.
pub(crate) fn with_consensus_version(mut response: Response, fork: ForkName) -> Response {
    if let Ok(value) = HeaderValue::from_str(fork.as_str()) {
        response
            .headers_mut()
            .insert("eth-consensus-version", value);
    }
    response
}

/// An SSZ body, with the content type the specification names for it.
pub(crate) fn ssz_response(bytes: Vec<u8>) -> Response {
    let mut response = bytes.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(crate::SSZ_CONTENT_TYPE),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_accept_header_means_json() {
        assert_eq!(Encoding::from_accept(None), Encoding::Json);
    }

    #[test]
    fn octet_stream_means_ssz() {
        assert_eq!(
            Encoding::from_accept(Some("application/octet-stream")),
            Encoding::Ssz
        );
    }

    #[test]
    fn a_q_weighted_header_picks_the_higher_weight() {
        // Lighthouse and the curl default both send lists; the spec orders by q.
        assert_eq!(
            Encoding::from_accept(Some("application/json;q=0.9,application/octet-stream")),
            Encoding::Ssz
        );
        assert_eq!(
            Encoding::from_accept(Some("application/octet-stream;q=0.1,application/json")),
            Encoding::Json
        );
    }

    #[test]
    fn a_wildcard_or_unknown_type_falls_back_to_json() {
        assert_eq!(Encoding::from_accept(Some("*/*")), Encoding::Json);
        assert_eq!(Encoding::from_accept(Some("text/html")), Encoding::Json);
    }
}
