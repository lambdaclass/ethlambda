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
    #[error(
        "SECONDS_PER_SLOT ({seconds}) and SLOT_DURATION_MS ({millis}) disagree: \
         SECONDS_PER_SLOT * 1000 must equal SLOT_DURATION_MS"
    )]
    SlotTimeMismatch { seconds: u64, millis: u64 },
    #[error(
        "SLOT_DURATION_MS is {millis}, but a beacon slot is a non-zero whole number of seconds"
    )]
    SlotDurationNotWholeSeconds { millis: u64 },
    #[error(
        "SECONDS_PER_SLOT is {seconds}, too large for its SLOT_DURATION_MS \
         (SECONDS_PER_SLOT * 1000) to fit in a u64"
    )]
    SlotDurationOverflow { seconds: u64 },
}

impl ConfigFile {
    /// Parse one `config.yaml`'s text.
    pub(crate) fn parse(text: &str) -> Result<Self, ConfigFileError> {
        let mut config: Config = serde_yaml_ng::from_str(text)?;
        let document: BTreeMap<String, IgnoredAny> = serde_yaml_ng::from_str(text)?;

        reconcile_slot_time(
            &mut config,
            document.contains_key("SECONDS_PER_SLOT"),
            document.contains_key("SLOT_DURATION_MS"),
        )?;

        let claimed = config_field_names();
        let ignored = document
            .into_keys()
            .filter(|key| !claimed.contains(&key.as_str()))
            .collect();

        Ok(Self { config, ignored })
    }

    /// Log what was ignored, as one line naming each key.
    ///
    /// One line rather than one per key: a current `config.yaml` carries the
    /// heze schedule, which this build does not claim, so per-key lines
    /// would flood every valid startup with one warning per ignored key and
    /// bury a real typo among them.
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

/// Make `seconds_per_slot` and `slot_duration_ms` agree, from whichever the
/// file actually carried.
///
/// `Config` has a container-level serde `default`, so a missing key and a key
/// holding the default value parse identically; only the raw key set tells
/// them apart, hence the two flags. A beacon slot is a whole number of
/// seconds, and generated configs (kurtosis' ethereum-genesis-generator)
/// carry only `SLOT_DURATION_MS` since consensus-specs dropped
/// `SECONDS_PER_SLOT`, so:
/// - both present: they must agree, since either could be the stale one and
///   guessing would run every duty at the wrong time;
/// - only `SLOT_DURATION_MS`: it must be a non-zero whole number of seconds,
///   and the seconds are derived from it, rather than left at mainnet's 12;
/// - only `SECONDS_PER_SLOT`: the milliseconds are derived from it, and a
///   value whose milliseconds do not fit in a `u64` is refused rather than
///   saturated, which would leave the two fields disagreeing;
/// - neither: the defaults stand.
///
/// Shared by a loaded directory and the built-in networks, which both parse
/// through [`ConfigFile::parse`], so one place owns the rule. A zero
/// `SECONDS_PER_SLOT` passes here (0 ms agrees with it) and is refused by the
/// directory loader.
fn reconcile_slot_time(
    config: &mut Config,
    has_seconds: bool,
    has_millis: bool,
) -> Result<(), ConfigFileError> {
    match (has_seconds, has_millis) {
        (true, true) => {
            let (seconds, millis) = (config.seconds_per_slot, config.slot_duration_ms);
            if seconds.checked_mul(1_000) != Some(millis) {
                return Err(ConfigFileError::SlotTimeMismatch { seconds, millis });
            }
        }
        (false, true) => {
            let millis = config.slot_duration_ms;
            if millis == 0 || !millis.is_multiple_of(1_000) {
                return Err(ConfigFileError::SlotDurationNotWholeSeconds { millis });
            }
            config.seconds_per_slot = millis / 1_000;
        }
        (true, false) => {
            let seconds = config.seconds_per_slot;
            config.slot_duration_ms = seconds
                .checked_mul(1_000)
                .ok_or(ConfigFileError::SlotDurationOverflow { seconds })?;
        }
        (false, false) => {}
    }
    Ok(())
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
    fn slot_time_keys_are_reconciled_whichever_are_present() {
        let both_agree =
            ConfigFile::parse("SECONDS_PER_SLOT: 12\nSLOT_DURATION_MS: 12000").unwrap();
        assert_eq!(both_agree.config.slot_duration_ms, 12_000);

        let err = ConfigFile::parse("SECONDS_PER_SLOT: 12\nSLOT_DURATION_MS: 6000").unwrap_err();
        assert!(
            matches!(err, ConfigFileError::SlotTimeMismatch { .. }),
            "got {err}"
        );

        let secs_only = ConfigFile::parse("SECONDS_PER_SLOT: 6").unwrap();
        assert_eq!(secs_only.config.slot_duration_ms, 6_000);

        let millis_only = ConfigFile::parse("SLOT_DURATION_MS: 6000").unwrap();
        assert_eq!(millis_only.config.seconds_per_slot, 6);
    }

    #[test]
    fn seconds_only_is_refused_once_its_milliseconds_overflow() {
        let largest = u64::MAX / 1_000;
        let at_limit = ConfigFile::parse(&format!("SECONDS_PER_SLOT: {largest}")).unwrap();
        assert_eq!(at_limit.config.seconds_per_slot, largest);
        assert_eq!(at_limit.config.slot_duration_ms, largest * 1_000);

        let past_limit = largest + 1;
        let err = ConfigFile::parse(&format!("SECONDS_PER_SLOT: {past_limit}")).unwrap_err();
        assert!(
            matches!(err, ConfigFileError::SlotDurationOverflow { seconds } if seconds == past_limit),
            "got {err}"
        );
    }

    #[test]
    fn the_devnets_values_are_read() {
        let parsed = ConfigFile::parse(DEVNET).unwrap();
        assert_eq!(parsed.config.config_name.as_str(), "ethlambda-devnet");
        assert_eq!(parsed.config.preset_base.as_str(), "mainnet");
        assert_eq!(parsed.config.deposit_chain_id, 3_151_908);
        assert_eq!(parsed.config.seconds_per_slot, 6);
    }

    #[test]
    fn the_forks_this_build_cannot_process_are_reported_as_ignored() {
        let parsed = ConfigFile::parse(DEVNET).unwrap();
        for key in [
            "HEZE_FORK_VERSION",
            "HEZE_FORK_EPOCH",
            "GAS_LIMIT_SCHEDULE",
            "INCLUSION_LIST_DUE_BPS",
        ] {
            assert!(
                parsed.ignored.contains(&key.to_string()),
                "{key} not reported"
            );
        }
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
