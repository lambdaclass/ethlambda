//! Engine API JWT authentication.
//!
//! Per the execution-apis spec, every request to the auth RPC endpoint
//! must carry a fresh `Authorization: Bearer <token>` header. The token is
//! a JWT signed with HS256 using a 32-byte secret shared out of band
//! between CL and EL.
//!
//! Token claims:
//! - `iat` (issued-at, seconds since Unix epoch). EL accepts a window of
//!   ±60s around its own clock.
//!
//! Secret format follows the convention shared by Lighthouse/Teku/Prysm/
//! ethrex: a single-line hex string (optionally `0x`-prefixed) in a file.

use std::path::Path;

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};

/// A 32-byte shared secret used for HS256 token signing.
#[derive(Debug, Clone)]
pub struct JwtSecret {
    bytes: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum JwtSecretError {
    #[error("failed to read JWT secret from {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("JWT secret hex decode failed: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("JWT secret must decode to 32 bytes (got {0})")]
    WrongLength(usize),
    #[error("failed to encode JWT: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("system clock is before Unix epoch")]
    ClockBeforeEpoch,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    /// Issued-at (Unix seconds).
    iat: u64,
}

impl JwtSecret {
    /// Construct from raw bytes; must be exactly 32 bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, JwtSecretError> {
        if bytes.len() != 32 {
            return Err(JwtSecretError::WrongLength(bytes.len()));
        }
        Ok(Self { bytes })
    }

    /// Parse from a hex string (with or without `0x` prefix).
    pub fn from_hex(hex_str: &str) -> Result<Self, JwtSecretError> {
        let trimmed = hex_str.trim();
        let stripped = trimmed.strip_prefix("0x").unwrap_or(trimmed);
        let bytes = hex::decode(stripped)?;
        Self::from_bytes(bytes)
    }

    /// Read a hex-encoded secret from a file path.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, JwtSecretError> {
        let path_ref = path.as_ref();
        let contents = std::fs::read_to_string(path_ref).map_err(|source| JwtSecretError::Io {
            path: path_ref.display().to_string(),
            source,
        })?;
        Self::from_hex(&contents)
    }

    /// Generate a fresh bearer token signed with this secret and the given
    /// issued-at time (seconds since the Unix epoch). Token is valid for
    /// ~60s on the EL side.
    pub fn sign(&self, iat_secs: u64) -> Result<String, JwtSecretError> {
        let claims = Claims { iat: iat_secs };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(&self.bytes),
        )?;
        Ok(token)
    }

    /// Generate a bearer token using the current system clock.
    pub fn sign_now(&self) -> Result<String, JwtSecretError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| JwtSecretError::ClockBeforeEpoch)?
            .as_secs();
        self.sign(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_HEX: &str = "0x0102030405060708091011121314151617181920212223242526272829303132";

    #[test]
    fn parses_hex_with_and_without_prefix() {
        let with = JwtSecret::from_hex(SAMPLE_HEX).unwrap();
        let without = JwtSecret::from_hex(SAMPLE_HEX.strip_prefix("0x").unwrap()).unwrap();
        assert_eq!(with.bytes, without.bytes);
        assert_eq!(with.bytes.len(), 32);
    }

    #[test]
    fn rejects_wrong_length() {
        let short = "0x010203";
        assert!(matches!(
            JwtSecret::from_hex(short),
            Err(JwtSecretError::WrongLength(_))
        ));
    }

    #[test]
    fn sign_is_deterministic_for_fixed_iat() {
        let secret = JwtSecret::from_hex(SAMPLE_HEX).unwrap();
        let a = secret.sign(1_700_000_000).unwrap();
        let b = secret.sign(1_700_000_000).unwrap();
        assert_eq!(a, b);
        // Header.Payload.Signature
        assert_eq!(a.matches('.').count(), 2);
    }

    #[test]
    fn sign_differs_for_different_iat() {
        let secret = JwtSecret::from_hex(SAMPLE_HEX).unwrap();
        let a = secret.sign(1_700_000_000).unwrap();
        let b = secret.sign(1_700_000_001).unwrap();
        assert_ne!(a, b);
    }
}
