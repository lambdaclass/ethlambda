//! Parsing one network's `config.yaml`.
//!
//! Two passes over the same text: [`Config`], then the document's keys alone,
//! to report the ones no field claimed.
//!
//! Two passes rather than one untyped map the typed pass reads out of,
//! because this document has no untyped representation. Both
//! `TERMINAL_TOTAL_DIFFICULTY` and an unquoted `DEPOSIT_CONTRACT_ADDRESS`
//! parse as integers wider than `u64`, and `serde_yaml_ng::Value` has no
//! variant that holds one; serde's own buffering, which a
//! `#[serde(flatten)]` catch-all field would route every scalar through, is
//! no better. The key pass therefore reads its values as [`IgnoredAny`],
//! which skips each one whole rather than typing it. The file is a few
//! kilobytes and this runs once at startup.

use std::collections::BTreeMap;

use ethlambda_types::beacon::config::Config;
use serde::Deserialize;
use serde::de::{IgnoredAny, Visitor};

/// What one `config.yaml` yields.
#[derive(Debug)]
pub(crate) struct ConfigFile {
    /// The typed runtime configuration, `PRESET_BASE` and `CONFIG_NAME`
    /// included.
    pub(crate) config: Config,
    /// Keys no field claimed: a typo, or a fork this build cannot process.
    pub(crate) ignored: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ConfigFileError {
    #[error("could not parse the network config: {0}")]
    Malformed(#[from] serde_yaml_ng::Error),
}

impl ConfigFile {
    /// Parse one `config.yaml`'s text.
    pub(crate) fn parse(text: &str) -> Result<Self, ConfigFileError> {
        let config: Config = serde_yaml_ng::from_str(text)?;
        let document: BTreeMap<String, IgnoredAny> = serde_yaml_ng::from_str(text)?;

        let claimed = config_field_names();
        let ignored = document
            .into_keys()
            .filter(|key| !claimed.contains(&key.as_str()))
            .collect();

        Ok(Self { config, ignored })
    }

    /// Log what was ignored, as one line naming each key.
    ///
    /// One line rather than one per key: a current `config.yaml` carries
    /// schedules this build does not claim (later forks' and
    /// `GAS_LIMIT_SCHEDULE`), so per-key lines would flood every valid
    /// startup with one warning per ignored key and bury a real typo among
    /// them.
    pub(crate) fn warn_about_ignored_keys(&self) {
        if self.ignored.is_empty() {
            return;
        }
        tracing::warn!(
            count = self.ignored.len(),
            keys = %self.ignored.join(", "),
            "Ignored config keys this build does not read"
        );
    }
}

/// The keys [`Config`]'s derived `Deserialize` accepts.
///
/// serde's derive hands its field list to `Deserializer::deserialize_struct`
/// and nowhere else, so capturing that argument is how a caller reads it from
/// outside the macro. Asking the derive rather than keeping a list here is
/// what holds the two in step: a field added to `Config` is claimed here with
/// nothing to update.
fn config_field_names() -> &'static [&'static str] {
    let mut fields: &'static [&'static str] = &[];
    // Always `Err`: the list arrives before any field is read, and there is
    // nothing here to build a `Config` out of.
    let _ = Config::deserialize(CaptureFields(&mut fields));
    fields
}

/// A deserializer that answers nothing and takes only the field list.
struct CaptureFields<'a>(&'a mut &'static [&'static str]);

impl<'de> serde::Deserializer<'de> for CaptureFields<'_> {
    // Borrowed rather than declared: nothing reads the message, so the type
    // only has to satisfy `de::Error`.
    type Error = serde::de::value::Error;

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        *self.0 = fields;
        Err(serde::de::Error::custom("field list captured"))
    }

    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        // Reached only if `Config` stops deserializing as a plain struct: a
        // `#[serde(flatten)]` field makes the derive call `deserialize_map`
        // and publish no field list at all. The capture then stays empty and
        // every key reads as ignored, which the tests below fail on.
        Err(serde::de::Error::custom("Config is not a plain struct"))
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map enum identifier ignored_any
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEVNET: &str = include_str!("../../tests/fixtures/networks/devnet/config.yaml");
    const MAINNET: &str = include_str!("../../assets/mainnet/config.yaml");

    #[test]
    fn the_devnets_values_are_read() {
        let parsed = ConfigFile::parse(DEVNET).unwrap();
        assert_eq!(parsed.config.config_name.as_str(), "ethlambda-devnet");
        assert_eq!(parsed.config.preset_base.as_str(), "mainnet");
        assert_eq!(parsed.config.deposit_chain_id, 3_151_908);
        assert_eq!(parsed.config.seconds_per_slot, 6);
    }

    #[test]
    fn the_keys_this_build_does_not_read_are_reported_as_ignored() {
        let parsed = ConfigFile::parse(DEVNET).unwrap();
        assert!(
            parsed.ignored.contains(&"GAS_LIMIT_SCHEDULE".to_string()),
            "GAS_LIMIT_SCHEDULE not reported"
        );
    }

    #[test]
    fn the_heze_keys_are_claimed_rather_than_ignored() {
        // HEZE_* and the inclusion list keys used to be reported as ignored;
        // now that `Config` has fields for them, they must not be.
        let parsed = ConfigFile::parse(DEVNET).unwrap();
        for key in [
            "HEZE_FORK_VERSION",
            "HEZE_FORK_EPOCH",
            "INCLUSION_LIST_DUE_BPS",
        ] {
            assert!(
                !parsed.ignored.contains(&key.to_string()),
                "{key} reported as ignored"
            );
        }
        assert_eq!(parsed.config.heze_fork_version, [0x08, 0, 0, 0]);
    }

    #[test]
    fn the_gloas_keys_are_claimed_rather_than_ignored() {
        // GLOAS_* and PAYLOAD_DUE_BPS used to be reported as ignored
        // alongside heze's; now that `Config` has fields for them, they must
        // not be.
        let parsed = ConfigFile::parse(DEVNET).unwrap();
        for key in ["GLOAS_FORK_VERSION", "GLOAS_FORK_EPOCH", "PAYLOAD_DUE_BPS"] {
            assert!(
                !parsed.ignored.contains(&key.to_string()),
                "{key} reported as ignored"
            );
        }
        assert_eq!(parsed.config.gloas_fork_version, [0x07, 0, 0, 0]);
    }

    #[test]
    fn preset_base_and_config_name_are_not_reported_as_ignored() {
        // Both are `Config` fields now, so the derive claims them.
        let parsed = ConfigFile::parse(DEVNET).unwrap();
        assert!(!parsed.ignored.iter().any(|key| key == "PRESET_BASE"));
        assert!(!parsed.ignored.iter().any(|key| key == "CONFIG_NAME"));
    }

    #[test]
    fn a_valid_mainnet_config_reports_nothing_ignored() {
        let parsed = ConfigFile::parse(MAINNET).unwrap();
        assert!(
            parsed.ignored.is_empty(),
            "unexpectedly ignored: {:?}",
            parsed.ignored
        );
    }

    #[test]
    fn a_misspelled_key_is_reported_as_ignored() {
        let parsed = ConfigFile::parse("SECONDS_PER_SLOTT: 12").unwrap();
        assert_eq!(parsed.ignored, ["SECONDS_PER_SLOTT"]);
    }

    #[test]
    fn a_malformed_document_is_an_error() {
        let err = ConfigFile::parse("ALTAIR_FORK_EPOCH: [1, 2]")
            .unwrap_err()
            .to_string();
        assert!(err.contains("ALTAIR_FORK_EPOCH"), "got {err}");
    }

    #[test]
    fn the_claimed_keys_come_from_the_derive() {
        let claimed = config_field_names();
        // A populated list is what proves the capture fired at all.
        assert!(claimed.contains(&"ALTAIR_FORK_EPOCH"));
        // The one renamed field is listed under its wire name, not its Rust
        // one, so a rename stays claimed without a second edit here.
        assert!(claimed.contains(&"MAX_BLOBS_PER_BLOCK"));
        assert!(!claimed.contains(&"MAX_BLOBS_PER_BLOCK_DENEB"));
        // `#[serde(skip)]` fields are not deserialized, so the derive does not
        // list them: a config carrying one is ignored, and reported as such.
        assert!(!claimed.contains(&"GENESIS_TIME"));
    }

    #[test]
    fn the_document_has_no_untyped_representation() {
        // Why the key pass reads `IgnoredAny` values, and why the three passes
        // cannot collapse into one map the others read out of: both of these
        // parse as integers wider than `u64`, which `Value` cannot hold.
        for line in [
            "TERMINAL_TOTAL_DIFFICULTY: 58750000000000000000000",
            "DEPOSIT_CONTRACT_ADDRESS: 0x00000000219ab540356cBB839Cbe05303d7705Fa",
        ] {
            let err = serde_yaml_ng::from_str::<serde_yaml_ng::Mapping>(line).unwrap_err();
            assert!(
                err.to_string().contains("invalid type: integer"),
                "got {err}"
            );
        }
        // Skipping the values rather than typing them is what makes the same
        // document readable, which is what `parse` relies on.
        serde_yaml_ng::from_str::<BTreeMap<String, IgnoredAny>>(MAINNET).unwrap();
    }
}
