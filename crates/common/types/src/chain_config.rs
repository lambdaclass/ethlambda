//! The node's own view of the chain's time grid.

use libssz::{DecodeError, SszDecode as _};
use libssz_derive::{SszDecode, SszEncode};

use crate::constants::{DEFAULT_MILLISECONDS_PER_SLOT, INTERVALS_PER_SLOT};
use crate::state::StateConfig;

/// Genesis time plus slot duration: everything needed to turn a wall-clock
/// reading into a slot and an interval within it.
///
/// A superset of [`StateConfig`], deliberately kept as a separate type. The
/// SSZ [`StateConfig`] is merkleized into [`crate::state::State`]'s hash tree
/// root, so its layout is fixed by the spec and cannot gain a field; the slot
/// duration is a launch parameter read from the network's config file. Keeping
/// the two apart means `state.config` stays byte-compatible with every other
/// client while this type carries what the node actually needs to schedule
/// duties.
///
/// Persisted in the storage backend's metadata table, where it doubles as the
/// data directory's network fingerprint: a config file whose slot duration
/// disagrees with the persisted one describes a different chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SszEncode, SszDecode)]
pub struct ChainConfig {
    /// UNIX timestamp in seconds at which slot 0 begins.
    pub genesis_time: u64,
    /// Slot duration in milliseconds. Always a multiple of
    /// [`INTERVALS_PER_SLOT`], enforced when the config file is parsed.
    pub milliseconds_per_slot: u64,
}

impl ChainConfig {
    pub fn new(genesis_time: u64, milliseconds_per_slot: u64) -> Self {
        Self {
            genesis_time,
            milliseconds_per_slot,
        }
    }

    /// Genesis as a millisecond timestamp, the zero point every tick
    /// computation measures from.
    pub fn genesis_time_ms(&self) -> u64 {
        self.genesis_time * 1_000
    }

    /// Interval duration in milliseconds.
    ///
    /// Exact because [`crate::genesis::GenesisConfig`] rejects a slot duration
    /// that is not a multiple of [`INTERVALS_PER_SLOT`].
    pub fn milliseconds_per_interval(&self) -> u64 {
        self.milliseconds_per_slot / INTERVALS_PER_SLOT
    }

    /// Decode a persisted config, accepting the layout written before
    /// `milliseconds_per_slot` existed.
    ///
    /// The legacy blob is a bare SSZ [`StateConfig`]: `genesis_time` alone.
    /// Every chain that wrote one ran the compile-time 4-second cadence, so
    /// filling in [`DEFAULT_MILLISECONDS_PER_SLOT`] reconstructs it exactly
    /// and a data directory written by an older build stays resumable.
    pub fn from_persisted_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::from_ssz_bytes(bytes).or_else(|err| {
            let legacy = StateConfig::from_ssz_bytes(bytes).map_err(|_| err)?;
            Ok(Self::new(
                legacy.genesis_time,
                DEFAULT_MILLISECONDS_PER_SLOT,
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libssz::SszEncode as _;

    #[test]
    fn derives_interval_from_slot_duration() {
        let config = ChainConfig::new(1_000, 8_000);
        assert_eq!(config.genesis_time_ms(), 1_000_000);
        assert_eq!(config.milliseconds_per_interval(), 1_600);
    }

    #[test]
    fn round_trips_through_ssz() {
        let config = ChainConfig::new(1_770_407_233, 8_000);
        let decoded = ChainConfig::from_persisted_ssz_bytes(&config.to_ssz()).unwrap();
        assert_eq!(decoded, config);
    }

    #[test]
    fn reads_legacy_config_as_the_default_cadence() {
        let legacy = StateConfig {
            genesis_time: 1_770_407_233,
        };
        let decoded = ChainConfig::from_persisted_ssz_bytes(&legacy.to_ssz()).unwrap();
        assert_eq!(
            decoded,
            ChainConfig::new(legacy.genesis_time, DEFAULT_MILLISECONDS_PER_SLOT)
        );
    }

    #[test]
    fn rejects_a_blob_that_is_neither_layout() {
        assert!(ChainConfig::from_persisted_ssz_bytes(&[0u8; 3]).is_err());
    }
}
