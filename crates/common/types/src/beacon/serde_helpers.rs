//! Deserializers for the two scalar shapes an eth2 `config.yaml` uses.
//!
//! Neither is serde's default, and both appear in every real configuration
//! file, so every numeric and version field in [`crate::beacon::config::Config`]
//! routes through one of them.

use serde::{Deserialize as _, Deserializer};

/// An integer written either quoted or bare.
///
/// The specification's own configuration files quote large integers so that a
/// JavaScript client does not lose precision reading them, but the convention
/// is not universal and a generator may emit either. Accepting only one form
/// silently leaves the field at its default, which is the failure mode this
/// avoids.
///
/// Every scalar is taken as a string and parsed, rather than matched against
/// an untagged enum of "string or integer". YAML resolves a bare `0x...` to an
/// integer, and an untagged enum makes serde buffer the value first, which
/// fails outright on `DEPOSIT_CONTRACT_ADDRESS`: twenty bytes of hex overflow
/// `u128` and the buffered value cannot even be constructed. Asking for a
/// string hands us the scalar's own text whether or not it was quoted, which
/// is the same coercion Teku applies and the reason Teku has none of the
/// quoting bugs Prysm worked around.
pub mod quoted_or_bare {
    use super::*;

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: std::str::FromStr,
        T::Err: std::fmt::Display,
    {
        let text = String::deserialize(deserializer)?;
        text.trim().parse().map_err(serde::de::Error::custom)
    }
}

/// A fixed-width byte array written as hex, with or without a `0x` prefix.
///
/// Used for fork versions and the snappy message domains, which are four
/// bytes, and for the deposit contract address, which is twenty.
pub mod hex_array {
    use super::*;

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        let digits = text.trim();
        let digits = digits.strip_prefix("0x").unwrap_or(digits);

        if digits.len() != N * 2 {
            return Err(serde::de::Error::custom(format!(
                "expected {N} bytes of hex, got {} characters",
                digits.len()
            )));
        }

        let mut out = [0u8; N];
        hex::decode_to_slice(digits, &mut out).map_err(serde::de::Error::custom)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Sample {
        #[serde(deserialize_with = "super::quoted_or_bare::deserialize")]
        count: u64,
        #[serde(deserialize_with = "super::hex_array::deserialize")]
        version: [u8; 4],
    }

    #[test]
    fn quoted_and_bare_integers_parse_identically() {
        let quoted: Sample = serde_yaml_ng::from_str("count: '64'\nversion: '0x01000000'").unwrap();
        let bare: Sample = serde_yaml_ng::from_str("count: 64\nversion: 0x01000000").unwrap();
        assert_eq!(quoted.count, 64);
        assert_eq!(bare.count, 64);
        assert_eq!(quoted.version, [0x01, 0x00, 0x00, 0x00]);
        assert_eq!(bare.version, [0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn hex_without_prefix_parses() {
        let sample: Sample = serde_yaml_ng::from_str("count: 1\nversion: '01000000'").unwrap();
        assert_eq!(sample.version, [0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn a_hex_value_of_the_wrong_length_is_an_error() {
        let err = serde_yaml_ng::from_str::<Sample>("count: 1\nversion: '0x0100'")
            .unwrap_err()
            .to_string();
        assert!(err.contains("expected 4 bytes"), "got {err}");
    }

    /// Twenty bytes of unquoted hex, exactly as `eth-clients/mainnet` writes
    /// `DEPOSIT_CONTRACT_ADDRESS`. This is the case that rules out reading a
    /// scalar through an untagged "string or integer" enum: the value exceeds
    /// `u128`, so serde cannot buffer it and the parse fails before any of our
    /// code runs. Asking for a `String` sees the scalar's own text instead.
    #[test]
    fn a_twenty_byte_unquoted_address_parses() {
        #[derive(Debug, serde::Deserialize)]
        struct Address {
            #[serde(deserialize_with = "super::hex_array::deserialize")]
            deposit_contract_address: [u8; 20],
        }

        let parsed: Address = serde_yaml_ng::from_str(
            "deposit_contract_address: 0x00000000219ab540356cBB839Cbe05303d7705Fa",
        )
        .expect("an unquoted twenty-byte address parses");
        assert_eq!(
            parsed.deposit_contract_address[0..4],
            [0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(parsed.deposit_contract_address[19], 0xfa);
    }
}
