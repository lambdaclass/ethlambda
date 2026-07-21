//! Slot-geometry bootstrap and the `offset_ms` calculation (CONTRACT.md §2).
//!
//! On startup the collector needs three numbers to translate an event's
//! `slot` into "how far into (or before) its slot did this arrive": the
//! chain's `genesis_time` (seconds), `MILLISECONDS_PER_SLOT`, and
//! `INTERVALS_PER_SLOT` (the last is only used for `/api/meta`, never for the
//! `offset_ms` math itself). `genesis_time` / `ms_per_slot` may be overridden
//! by config for offline testing; `intervals_per_slot` has no config
//! override and always comes from the network fetch (falling back to
//! [`DEFAULT_INTERVALS_PER_SLOT`] if no node is reachable).

use std::time::Duration;

use serde::Deserialize;

use crate::config::NodeConfig;

/// Fallback used only when no node answered `/lean/v0/config/spec` and the
/// config didn't need a network fetch at all (both `genesis_time` and
/// `ms_per_slot` overridden). Matches ethlambda's own default (5 intervals
/// per 4s slot).
pub const DEFAULT_INTERVALS_PER_SLOT: u64 = 5;

const FETCH_TIMEOUT: Duration = Duration::from_secs(3);

/// Resolved slot geometry used to compute `offset_ms` for incoming events.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    pub genesis_time: u64,
    pub ms_per_slot: u64,
    pub intervals_per_slot: u64,
}

impl Timing {
    /// `offset_ms = arrival_ms - (genesis_time*1000 + slot*ms_per_slot)`.
    ///
    /// May be negative: an event can arrive before its nominal slot start
    /// under clock skew between the collector and the node, or when the
    /// event's own timestamp precedes the slot boundary.
    pub fn offset_ms(&self, slot: u64, arrival_ms: i64) -> i64 {
        let slot_start_ms = self.genesis_time as i64 * 1000 + slot as i64 * self.ms_per_slot as i64;
        arrival_ms - slot_start_ms
    }
}

/// Config-supplied overrides for offline testing (CONTRACT.md §5).
#[derive(Debug, Clone, Copy, Default)]
pub struct TimingOverrides {
    pub genesis_time: Option<u64>,
    pub ms_per_slot: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct GenesisResponse {
    genesis_time: u64,
}

#[derive(Debug, Deserialize)]
struct SpecResponse {
    #[serde(rename = "MILLISECONDS_PER_SLOT")]
    milliseconds_per_slot: u64,
    #[serde(rename = "INTERVALS_PER_SLOT")]
    intervals_per_slot: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error(
        "no reachable node provided slot geometry and config did not override genesis_time/ms_per_slot"
    )]
    NoTimingSource,
}

struct Fetched {
    genesis_time: u64,
    ms_per_slot: u64,
    intervals_per_slot: u64,
}

/// Fetches genesis + spec from the first node that answers both, trying
/// nodes in configured order. Returns `None` if none are reachable; this is
/// not necessarily fatal since `overrides` may fully cover `genesis_time`
/// and `ms_per_slot`.
async fn fetch_from_first_reachable(
    nodes: &[NodeConfig],
    client: &reqwest::Client,
) -> Option<Fetched> {
    for node in nodes {
        let genesis_url = format!("{}/lean/v0/genesis", node.url.trim_end_matches('/'));
        let spec_url = format!("{}/lean/v0/config/spec", node.url.trim_end_matches('/'));

        let genesis = fetch_json::<GenesisResponse>(client, &genesis_url).await;
        let spec = fetch_json::<SpecResponse>(client, &spec_url).await;

        match (genesis, spec) {
            (Ok(genesis), Ok(spec)) => {
                return Some(Fetched {
                    genesis_time: genesis.genesis_time,
                    ms_per_slot: spec.milliseconds_per_slot,
                    intervals_per_slot: spec.intervals_per_slot,
                });
            }
            _ => {
                tracing::debug!(node = %node.name, "timing bootstrap: node unreachable or malformed response, trying next");
            }
        }
    }
    None
}

async fn fetch_json<T: for<'de> Deserialize<'de>>(
    client: &reqwest::Client,
    url: &str,
) -> Result<T, reqwest::Error> {
    client
        .get(url)
        .timeout(FETCH_TIMEOUT)
        .send()
        .await?
        .error_for_status()?
        .json::<T>()
        .await
}

/// Resolves [`Timing`], preferring config overrides and falling back to the
/// first reachable node for anything not overridden.
pub async fn bootstrap(
    nodes: &[NodeConfig],
    overrides: TimingOverrides,
    client: &reqwest::Client,
) -> Result<Timing, BootstrapError> {
    let fetched = fetch_from_first_reachable(nodes, client).await;

    let genesis_time = overrides
        .genesis_time
        .or_else(|| fetched.as_ref().map(|f| f.genesis_time))
        .ok_or(BootstrapError::NoTimingSource)?;
    let ms_per_slot = overrides
        .ms_per_slot
        .or_else(|| fetched.as_ref().map(|f| f.ms_per_slot))
        .ok_or(BootstrapError::NoTimingSource)?;
    let intervals_per_slot = fetched
        .map(|f| f.intervals_per_slot)
        .unwrap_or(DEFAULT_INTERVALS_PER_SLOT);

    Ok(Timing {
        genesis_time,
        ms_per_slot,
        intervals_per_slot,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timing() -> Timing {
        Timing {
            genesis_time: 1_770_407_233,
            ms_per_slot: 4_000,
            intervals_per_slot: 5,
        }
    }

    #[test]
    fn offset_ms_matches_contract_example() {
        // slot_start_ms = 1_770_407_233_000 + 128*4000 = 1_770_407_745_000
        let t = timing();
        let arrival_ms = 1_770_407_745_123_i64;
        assert_eq!(t.offset_ms(128, arrival_ms), 123);
    }

    #[test]
    fn offset_ms_is_zero_exactly_at_slot_start() {
        let t = timing();
        let slot_start = t.genesis_time as i64 * 1000 + 10 * t.ms_per_slot as i64;
        assert_eq!(t.offset_ms(10, slot_start), 0);
    }

    #[test]
    fn offset_ms_can_be_negative_under_clock_skew() {
        // Event arrives 50ms before its nominal slot boundary.
        let t = timing();
        let slot_start = t.genesis_time as i64 * 1000 + 10 * t.ms_per_slot as i64;
        assert_eq!(t.offset_ms(10, slot_start - 50), -50);
    }

    #[test]
    fn offset_ms_at_genesis_slot_zero() {
        let t = timing();
        let genesis_ms = t.genesis_time as i64 * 1000;
        assert_eq!(t.offset_ms(0, genesis_ms + 500), 500);
    }
}
