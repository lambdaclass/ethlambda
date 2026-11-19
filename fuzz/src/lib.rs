//! Helpers shared by the fuzz targets in `fuzz_targets/`.
//!
//! Every target is one binary with one `fuzz_target!`; what they share is
//! here so a target reads as the property it checks and nothing else.

use std::sync::OnceLock;

use ethlambda_types::beacon::config::Config;

/// Splits a selector byte off the front of the input.
///
/// A target that covers a family of decoders uses the selector to pick one,
/// so a single binary (and corpus) covers the family while libFuzzer still
/// sees the choice as part of the input it mutates. An empty input selects
/// the first entry with an empty payload.
pub fn split(data: &[u8]) -> (u8, &[u8]) {
    match data.split_first() {
        Some((selector, rest)) => (*selector, rest),
        None => (0, data),
    }
}

/// The mainnet beacon configuration, built once per process.
///
/// `Config::mainnet()` is what the live follower decodes under by default,
/// and the fork schedule it carries is what selects the container for a
/// slot, which is what the beacon targets are exercising.
pub fn mainnet_config() -> &'static Config {
    static CONFIG: OnceLock<Config> = OnceLock::new();
    CONFIG.get_or_init(Config::mainnet)
}
