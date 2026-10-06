//! The `BuilderConfig` a validator client sends with `produceBlockV4`.
//!
//! Stubs until filled. Field types below are placeholders; the SSZ and JSON
//! forms are added with the real containers.

use axum::http::HeaderMap;

use crate::beacon::ApiError;

#[allow(dead_code)] // filled by Agent C
pub(crate) const MAX_BUILDER_ENTRIES: usize = 64;
#[allow(dead_code)] // filled by Agent C
pub(crate) const MAX_BUILDER_URL_SIZE: usize = 2048;
#[allow(dead_code)] // filled by Agent C
pub(crate) const MAX_BUILDER_PUBKEYS: usize = 64;
#[allow(dead_code)] // filled by Agent C
pub(crate) const MAX_BUILDER_AUTH_DATA_SIZE: usize = 4096;

#[derive(Debug, Clone, Default)]
#[allow(dead_code)] // filled by Agent C
pub(crate) struct BuilderEntry {
    pub(crate) url: String,
    pub(crate) auth_data: Vec<u8>,
    pub(crate) auth_slot: u64,
    pub(crate) min_bid: u64,
    pub(crate) builder_boost_factor: u64,
}

#[derive(Debug, Clone, Default)]
#[allow(dead_code)] // filled by Agent C
pub(crate) struct BuilderConfig {
    pub(crate) min_bid: u64,
    pub(crate) builder_boost_factor: u64,
    pub(crate) builders: Vec<BuilderEntry>,
}

#[allow(dead_code)] // filled by Agent C
impl BuilderEntry {
    /// A non-empty url, non-empty `auth.data` and `auth.message.slot == slot`.
    /// An unusable entry never fails the request.
    pub(crate) fn is_usable_for(&self, _slot: u64) -> bool {
        false
    }
}

/// A missing or undecodable body is a 400.
#[allow(dead_code)] // filled by Agent C
pub(crate) fn decode_builder_config(
    _headers: &HeaderMap,
    _body: &[u8],
) -> Result<BuilderConfig, ApiError> {
    Err(ApiError::BadRequest("the body is not a BuilderConfig"))
}
