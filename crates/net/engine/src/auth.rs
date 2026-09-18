//! JWT authentication for the Engine API.
//!
//! `authentication.md`: HMAC-SHA256 over a JOSE header and a claim set whose
//! only member is `iat`, the issued-at time in seconds. Execution clients accept
//! a skew of ±60 seconds, so a token is good for about two minutes; this mints a
//! fresh one per request rather than caching, because minting is two hashes and
//! a cache would need its own clock.

use std::path::Path;

use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::EngineError;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The fixed JOSE header, `{"alg":"HS256","typ":"JWT"}`, pre-encoded.
///
/// Constant because nothing about it varies: the specification names exactly one
/// algorithm, and a header serialized fresh per request would risk a different
/// key order producing a different signature over the same logical header.
const HEADER_B64: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

/// The 32-byte shared secret an execution client authenticates against.
#[derive(Clone)]
pub struct JwtSecret([u8; 32]);

impl std::fmt::Debug for JwtSecret {
    /// Never prints the secret. A `#[derive(Debug)]` here would put the shared
    /// secret into any log line that formats a config struct.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JwtSecret(<redacted>)")
    }
}

impl JwtSecret {
    pub fn new(secret: [u8; 32]) -> Self {
        Self(secret)
    }

    /// Parses a 64-character hex string, with or without a `0x` prefix.
    pub fn from_hex(value: &str) -> Result<Self, EngineError> {
        let trimmed = value.trim().trim_start_matches("0x");
        let bytes = hex::decode(trimmed)
            .map_err(|err| EngineError::Jwt(format!("secret is not hex: {err}")))?;
        let secret: [u8; 32] = bytes
            .try_into()
            .map_err(|_| EngineError::Jwt("secret is not 32 bytes".to_string()))?;
        Ok(Self(secret))
    }

    /// Reads a hex secret from a file, as `--execution-jwt-secret` names one.
    pub fn from_file(path: &Path) -> Result<Self, EngineError> {
        let contents = std::fs::read_to_string(path)
            .map_err(|err| EngineError::Jwt(format!("reading {}: {err}", path.display())))?;
        Self::from_hex(&contents)
    }

    /// A token whose `iat` is the current wall clock.
    pub fn token(&self) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0);
        self.token_at(now)
    }

    /// A token for an explicit `iat`. Separated from [`token`](Self::token) so
    /// tests can pin the clock; a token is a pure function of the secret and
    /// that one number.
    pub fn token_at(&self, issued_at: u64) -> String {
        let claim = format!(r#"{{"iat":{issued_at}}}"#);
        let payload = B64.encode(claim.as_bytes());
        let signing_input = format!("{HEADER_B64}.{payload}");

        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.0)
            .expect("HMAC accepts a key of any length");
        mac.update(signing_input.as_bytes());
        let signature = B64.encode(mac.finalize().into_bytes());

        format!("{signing_input}.{signature}")
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use super::*;

    const SECRET: [u8; 32] = [0x0f; 32];

    #[test]
    fn a_token_has_three_base64url_segments() {
        let secret = JwtSecret::new(SECRET);
        let token = secret.token_at(1_700_000_000);

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        // base64url, unpadded: no '+', '/' or '=' anywhere.
        assert!(!token.contains('+'));
        assert!(!token.contains('/'));
        assert!(!token.contains('='));
    }

    #[test]
    fn the_claim_carries_iat_and_nothing_else() {
        let secret = JwtSecret::new(SECRET);
        let token = secret.token_at(1_700_000_000);

        let payload = token.split('.').nth(1).expect("a three-segment token");
        let decoded = B64.decode(payload).expect("the payload is base64url");
        let claim: serde_json::Value = serde_json::from_slice(&decoded).expect("the claim is JSON");

        assert_eq!(claim["iat"], 1_700_000_000u64);
        assert_eq!(claim.as_object().expect("a JSON object").len(), 1);
    }

    #[test]
    fn the_same_second_gives_the_same_token_and_a_later_one_differs() {
        let secret = JwtSecret::new(SECRET);
        assert_eq!(secret.token_at(1_000), secret.token_at(1_000));
        assert_ne!(secret.token_at(1_000), secret.token_at(1_001));
    }

    #[test]
    fn a_hex_secret_parses_with_or_without_the_prefix() {
        let bare = "0f".repeat(32);
        let prefixed = format!("0x{bare}");

        assert_eq!(
            JwtSecret::from_hex(&bare).expect("valid hex").token_at(5),
            JwtSecret::from_hex(&prefixed)
                .expect("valid hex")
                .token_at(5)
        );
    }

    #[test]
    fn a_secret_that_is_not_32_bytes_is_refused() {
        assert!(JwtSecret::from_hex(&"0f".repeat(16)).is_err());
        assert!(JwtSecret::from_hex("nonsense").is_err());
    }

    #[test]
    fn the_debug_impl_never_prints_the_secret() {
        let rendered = format!("{:?}", JwtSecret::new(SECRET));
        assert_eq!(rendered, "JwtSecret(<redacted>)");
        assert!(!rendered.contains("0f"));
    }
}
