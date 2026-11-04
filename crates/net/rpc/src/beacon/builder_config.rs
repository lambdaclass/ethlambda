//! The `BuilderConfig` a validator client sends with `produceBlockV4`.
//!
//! Its containers are the Beacon API's own (`types/gloas/builder_entry.yaml`
//! and `request_auth.yaml`), not consensus containers, so they live with the
//! API. Each has the SSZ form the specification gives and the JSON form with
//! quoted integers and hex byte strings.
//!
//! Only the top-level `min_bid` and `builder_boost_factor` are used today: they
//! govern the bids this node sees over p2p. The `builders` entries (bid
//! requests to a builder's URL) are decoded and left alone.

use axum::http::{HeaderMap, header};
use ethlambda_types::beacon::primitives::{BlsPubkey, BlsSignature};
use libssz_derive::{SszDecode, SszEncode};
use libssz_types::SszList;
use serde::{Deserialize, Serialize};

use crate::beacon::ApiError;

pub(crate) const MAX_BUILDER_ENTRIES: usize = 64;
pub(crate) const MAX_BUILDER_URL_SIZE: usize = 2048;
pub(crate) const MAX_BUILDER_PUBKEYS: usize = 64;
pub(crate) const MAX_BUILDER_AUTH_DATA_SIZE: usize = 4096;

/// The builder-specs' `BuilderRequestAuth`: opaque authentication bytes and the
/// slot they authorize.
#[derive(Debug, Clone, Default, PartialEq, Eq, SszEncode, SszDecode, Serialize, Deserialize)]
pub(crate) struct BuilderRequestAuth {
    #[serde(with = "ethlambda_types::beacon::serde_helpers::ssz_hex")]
    pub(crate) data: SszList<u8, MAX_BUILDER_AUTH_DATA_SIZE>,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    pub(crate) slot: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, SszEncode, SszDecode, Serialize, Deserialize)]
pub(crate) struct SignedBuilderRequestAuth {
    pub(crate) message: BuilderRequestAuth,
    pub(crate) signature: BlsSignature,
}

/// The URL as the SSZ container holds it (UTF-8 bytes) and JSON writes it (a
/// string).
mod url_text {
    use super::{MAX_BUILDER_URL_SIZE, SszList};

    pub fn serialize<S: serde::Serializer>(
        value: &SszList<u8, MAX_BUILDER_URL_SIZE>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&String::from_utf8_lossy(value))
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<SszList<u8, MAX_BUILDER_URL_SIZE>, D::Error> {
        let text = <String as serde::Deserialize>::deserialize(deserializer)?;
        SszList::try_from(text.into_bytes())
            .map_err(|_| serde::de::Error::custom("url exceeds MAX_BUILDER_URL_SIZE"))
    }
}

/// A per-builder bid request a validator client supplies.
#[derive(Debug, Clone, Default, PartialEq, Eq, SszEncode, SszDecode, Serialize, Deserialize)]
pub(crate) struct BuilderEntry {
    #[serde(with = "url_text")]
    pub(crate) url: SszList<u8, MAX_BUILDER_URL_SIZE>,
    pub(crate) auth: SignedBuilderRequestAuth,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::seq")]
    pub(crate) builder_pubkeys: SszList<BlsPubkey, MAX_BUILDER_PUBKEYS>,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    pub(crate) max_execution_payment: u64,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    pub(crate) min_bid: u64,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    pub(crate) builder_boost_factor: u64,
}

/// The resolved per-key builder config of one block-production request.
#[derive(Debug, Clone, Default, PartialEq, Eq, SszEncode, SszDecode, Serialize, Deserialize)]
pub(crate) struct BuilderConfig {
    /// Minimum total payment, in Gwei, accepted from a p2p bid.
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    pub(crate) min_bid: u64,
    /// Percentage multiplier applied to a p2p bid against the local build.
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    pub(crate) builder_boost_factor: u64,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::seq")]
    pub(crate) builders: SszList<BuilderEntry, MAX_BUILDER_ENTRIES>,
}

impl BuilderEntry {
    /// A non-empty url, non-empty `auth.data` and `auth.message.slot == slot`.
    /// An unusable entry never fails the request: it yields no bid.
    pub(crate) fn is_usable_for(&self, slot: u64) -> bool {
        !self.url.is_empty() && !self.auth.message.data.is_empty() && self.auth.message.slot == slot
    }
}

impl BuilderConfig {
    /// How many entries a builder request could be made for at `slot`.
    pub(crate) fn usable_entries(&self, slot: u64) -> usize {
        self.builders
            .iter()
            .filter(|entry| entry.is_usable_for(slot))
            .count()
    }
}

/// Decodes the request body as a `BuilderConfig`: SSZ for an
/// `application/octet-stream` body, JSON otherwise (what a client with no
/// `Content-Type` sends). A missing or undecodable body is a 400.
pub(crate) fn decode_builder_config(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<BuilderConfig, ApiError> {
    let invalid = || ApiError::BadRequest("the body is not a BuilderConfig");
    let ssz = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with(crate::SSZ_CONTENT_TYPE));
    if ssz {
        <BuilderConfig as libssz::SszDecode>::from_ssz_bytes(body).map_err(|_| invalid())
    } else {
        serde_json::from_slice(body).map_err(|_| invalid())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libssz::SszEncode as _;

    fn entry(url: &str, data: &[u8], slot: u64) -> BuilderEntry {
        BuilderEntry {
            url: SszList::try_from(url.as_bytes().to_vec()).unwrap(),
            auth: SignedBuilderRequestAuth {
                message: BuilderRequestAuth {
                    data: SszList::try_from(data.to_vec()).unwrap(),
                    slot,
                },
                signature: BlsSignature::default(),
            },
            builder_pubkeys: vec![BlsPubkey::default()].try_into().unwrap(),
            max_execution_payment: 7,
            min_bid: 5,
            builder_boost_factor: 120,
        }
    }

    fn config(entries: Vec<BuilderEntry>) -> BuilderConfig {
        BuilderConfig {
            min_bid: 10_000_000,
            builder_boost_factor: 100,
            builders: entries.try_into().unwrap(),
        }
    }

    fn ssz_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            crate::SSZ_CONTENT_TYPE.parse().unwrap(),
        );
        headers
    }

    #[test]
    fn json_and_ssz_round_trip_with_entries() {
        let original = config(vec![
            entry("https://builder.example.com", b"auth", 9),
            entry("https://other.example.com", b"x", 9),
        ]);
        let json = serde_json::to_vec(&original).unwrap();
        assert_eq!(
            decode_builder_config(&HeaderMap::new(), &json).unwrap(),
            original
        );
        let ssz = original.to_ssz();
        assert_eq!(
            decode_builder_config(&ssz_headers(), &ssz).unwrap(),
            original
        );
    }

    #[test]
    fn the_json_form_quotes_integers_and_writes_bytes_as_hex() {
        let json =
            serde_json::to_value(config(vec![entry("https://b.example", b"\x12\x34", 9)])).unwrap();
        assert_eq!(json["min_bid"], "10000000");
        assert_eq!(json["builder_boost_factor"], "100");
        let builder = &json["builders"][0];
        assert_eq!(builder["url"], "https://b.example");
        assert_eq!(builder["auth"]["message"]["data"], "0x1234");
        assert_eq!(builder["auth"]["message"]["slot"], "9");
        assert_eq!(builder["max_execution_payment"], "7");
        assert_eq!(builder["min_bid"], "5");
        assert_eq!(builder["builder_boost_factor"], "120");
    }

    #[test]
    fn an_unusable_entry_still_decodes() {
        let slot = 9;
        let unusable = [
            entry("", b"auth", slot),
            entry("https://b.example", b"", slot),
            entry("https://b.example", b"auth", slot + 1),
        ];
        for bad in &unusable {
            assert!(!bad.is_usable_for(slot));
        }
        let usable = entry("https://b.example", b"auth", slot);
        assert!(usable.is_usable_for(slot));
        let original = config(vec![
            unusable[0].clone(),
            unusable[1].clone(),
            unusable[2].clone(),
            usable,
        ]);
        let json = serde_json::to_vec(&original).unwrap();
        let decoded = decode_builder_config(&HeaderMap::new(), &json).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.usable_entries(slot), 1);
        let ssz = decode_builder_config(&ssz_headers(), &original.to_ssz()).unwrap();
        assert_eq!(ssz, original);
    }

    #[test]
    fn an_undecodable_or_oversized_body_is_a_400() {
        for body in [
            &b""[..],
            b"not json",
            br#"{"min_bid": "1"}"#,
            br#"{"min_bid": "x", "builder_boost_factor": "1", "builders": []}"#,
        ] {
            assert!(matches!(
                decode_builder_config(&HeaderMap::new(), body),
                Err(ApiError::BadRequest(_))
            ));
        }
        // SSZ: too short, and an offset that points nowhere.
        for body in [&[][..], &[0u8; 19][..], &[1u8; 20][..]] {
            assert!(decode_builder_config(&ssz_headers(), body).is_err());
        }
        // More than MAX_BUILDER_ENTRIES entries.
        let many = serde_json::json!({
            "min_bid": "0",
            "builder_boost_factor": "0",
            "builders": vec![
                serde_json::to_value(entry("https://b.example", b"a", 1)).unwrap();
                MAX_BUILDER_ENTRIES + 1
            ],
        });
        assert!(
            decode_builder_config(&HeaderMap::new(), &serde_json::to_vec(&many).unwrap()).is_err()
        );
        // A url above the bound.
        let long = "a".repeat(MAX_BUILDER_URL_SIZE + 1);
        let mut json = serde_json::to_value(config(vec![entry("https://b", b"a", 1)])).unwrap();
        json["builders"][0]["url"] = long.into();
        assert!(
            decode_builder_config(&HeaderMap::new(), &serde_json::to_vec(&json).unwrap()).is_err()
        );
    }

    #[test]
    fn the_empty_local_preferred_config_decodes() {
        let body = br#"{"min_bid":"0","builder_boost_factor":"0","builders":[]}"#;
        let decoded = decode_builder_config(&HeaderMap::new(), body).unwrap();
        assert_eq!(decoded, BuilderConfig::default());
        // Twenty bytes: the two integers and the offset of the empty list.
        let ssz =
            decode_builder_config(&ssz_headers(), &BuilderConfig::default().to_ssz()).unwrap();
        assert_eq!(ssz, decoded);
    }
}
