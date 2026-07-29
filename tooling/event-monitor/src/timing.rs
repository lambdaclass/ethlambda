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
use tokio::sync::watch;

use crate::config::NodeConfig;
use crate::hub::Hub;

/// Fallback used when no node answered `/lean/v0/config/spec`. Matches
/// ethlambda's own default (5 intervals per 4s slot). Unlike `genesis_time` and
/// `ms_per_slot` this has no config override, so it is the only source left when
/// the fetch comes back empty.
pub const DEFAULT_INTERVALS_PER_SLOT: u64 = 5;

const FETCH_TIMEOUT: Duration = Duration::from_secs(3);

/// How often slot geometry is re-resolved. A regenerated genesis is routine on
/// a devnet and silently invalidates every `offset_ms` computed against the old
/// epoch, so poll for it rather than relying on someone noticing that every dot
/// has piled up against one edge.
const REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Upper bound on `MILLISECONDS_PER_SLOT`. One hour per slot is already absurd
/// for a consensus client; anything past it is a malformed spec response, not a
/// configuration choice.
const MAX_MS_PER_SLOT: u64 = 3_600_000;

/// Upper bound on `genesis_time` (seconds): 2100-01-01. Its only job is to keep
/// `genesis_time * 1000` far inside `i64`, since [`Timing::offset_ms`] does that
/// multiply and an absurd value from a malformed response would otherwise
/// overflow — a panic in a debug build.
///
/// Note this bounds only the *absurd* side. A `genesis_time` in the near future
/// is legitimate: a devnet is routinely configured before its genesis fires.
const MAX_GENESIS_TIME: u64 = 4_102_444_800;

/// Resolved slot geometry used to compute `offset_ms` for incoming events.
///
/// `Serialize` so a change can be pushed to open dashboards on `/stream`
/// (CONTRACT.md §4 `event: geometry`); the field names are the same three
/// `/api/meta` publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Timing {
    pub genesis_time: u64,
    pub ms_per_slot: u64,
    pub intervals_per_slot: u64,
}

impl Timing {
    /// Rejects geometry that would make every downstream number meaningless.
    ///
    /// Nothing here crashes if it slips through — `slot_at` floors the divisor,
    /// the frontend defaults a zero `ms_per_slot` — but the result is every dot
    /// piled against one edge with no explanation, which for a monitoring tool
    /// is worse than refusing to start. Checked at the one place geometry
    /// enters the process, so both the network fetch and the config overrides
    /// go through it.
    fn validate(&self) -> Result<(), BootstrapError> {
        let reject = |reason: String| Err(BootstrapError::ImplausibleGeometry { reason });
        if self.ms_per_slot == 0 || self.ms_per_slot > MAX_MS_PER_SLOT {
            return reject(format!(
                "ms_per_slot is {}, expected 1..={MAX_MS_PER_SLOT}",
                self.ms_per_slot
            ));
        }
        if self.intervals_per_slot == 0 {
            return reject("intervals_per_slot is 0; the slot axis divides by it".to_string());
        }
        if self.genesis_time > MAX_GENESIS_TIME {
            return reject(format!(
                "genesis_time is {}, expected 0..={MAX_GENESIS_TIME}",
                self.genesis_time
            ));
        }
        Ok(())
    }

    /// `offset_ms = arrival_ms - (genesis_time*1000 + slot*ms_per_slot)`.
    ///
    /// May be negative: an event can arrive before its nominal slot start
    /// under clock skew between the collector and the node, or when the
    /// event's own timestamp precedes the slot boundary.
    pub fn offset_ms(&self, slot: u64, arrival_ms: i64) -> i64 {
        let slot_start_ms = self.genesis_time as i64 * 1000 + slot as i64 * self.ms_per_slot as i64;
        arrival_ms - slot_start_ms
    }

    /// The slot the collector's own clock is in at `now_ms`, used to bound how
    /// far ahead of us an event's slot may plausibly be. Saturates at slot 0
    /// for timestamps at or before genesis.
    pub fn slot_at(&self, now_ms: i64) -> u64 {
        let genesis_ms = self.genesis_time as i64 * 1000;
        let elapsed_ms = now_ms.saturating_sub(genesis_ms);
        if elapsed_ms <= 0 {
            return 0;
        }
        // `ms_per_slot` comes off the wire, so treat a bogus 0 as 1ms rather
        // than dividing by zero.
        elapsed_ms as u64 / self.ms_per_slot.max(1)
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
    #[error("implausible slot geometry: {reason}")]
    ImplausibleGeometry { reason: String },
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
        let genesis_url = node.endpoint("/lean/v0/genesis");
        let spec_url = node.endpoint("/lean/v0/config/spec");

        // The two fetches are independent; run them concurrently so a slow or
        // dead node costs one FETCH_TIMEOUT, not two in series.
        let (genesis, spec) = tokio::join!(
            fetch_json::<GenesisResponse>(client, &genesis_url),
            fetch_json::<SpecResponse>(client, &spec_url),
        );

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

    let timing = Timing {
        genesis_time,
        ms_per_slot,
        intervals_per_slot,
    };
    timing.validate()?;
    Ok(timing)
}

/// Re-resolves slot geometry every [`REFRESH_INTERVAL`] and republishes it on
/// `timing_tx` when it changes, so a regenerated genesis stops silently
/// corrupting every subsequent `offset_ms`.
///
/// On a change the retained history is dropped: those events' offsets were
/// computed against the previous epoch and their slot numbers belong to a
/// different chain, so keeping them would mix two incomparable series in one
/// backfill. Dropping them also clears the slot watermark, which the history
/// ring only ever moves upward and which a restarted chain's low slots would
/// otherwise sit below.
///
/// A failed refresh is logged and ignored: the current geometry is better than
/// none, and an unreachable node is expected during a rolling restart.
///
/// Already-loaded browser tabs keep the `ms_per_slot` / `intervals_per_slot`
/// they fetched from `/api/meta`, and their own client-side slot watermark,
/// which only ever moves up. A restarted chain's low slots therefore sit below
/// it and every event ages out of the window on arrival, so the tab goes blank —
/// indistinguishable from the chain having died, which is the question this tool
/// exists to answer. The change is broadcast on `/stream` (CONTRACT.md §4
/// `event: geometry`) so the tab can say so and offer a reload instead of
/// silently emptying. Server-computed `offset_ms` values are correct
/// immediately.
pub async fn run_refresher(
    nodes: Vec<NodeConfig>,
    overrides: TimingOverrides,
    client: reqwest::Client,
    timing_tx: watch::Sender<Timing>,
    hub: Hub,
) {
    let mut ticker = tokio::time::interval(REFRESH_INTERVAL);
    ticker.tick().await; // the first tick fires immediately; bootstrap just ran

    loop {
        ticker.tick().await;

        let fresh = match bootstrap(&nodes, overrides, &client).await {
            Ok(fresh) => fresh,
            Err(err) => {
                tracing::debug!(%err, "slot geometry refresh failed; keeping current geometry");
                continue;
            }
        };

        let current = *timing_tx.borrow();
        if fresh == current {
            continue;
        }

        tracing::warn!(
            old_genesis_time = current.genesis_time,
            new_genesis_time = fresh.genesis_time,
            old_ms_per_slot = current.ms_per_slot,
            new_ms_per_slot = fresh.ms_per_slot,
            "slot geometry changed; dropping retained history and re-basing offsets"
        );
        hub.reset_history();
        // Announce before switching over, so no subscriber can receive an event
        // stamped with the new geometry before being told the geometry moved.
        hub.publish_geometry(fresh);
        // A send error means every receiver is gone, i.e. we are shutting down.
        let _ = timing_tx.send(fresh);
    }
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

    #[test]
    fn slot_at_counts_whole_slots_since_genesis() {
        let t = timing();
        let genesis_ms = t.genesis_time as i64 * 1000;
        assert_eq!(t.slot_at(genesis_ms), 0);
        assert_eq!(t.slot_at(genesis_ms + 3_999), 0);
        assert_eq!(t.slot_at(genesis_ms + 4_000), 1);
        assert_eq!(t.slot_at(genesis_ms + 128 * 4_000 + 123), 128);
    }

    #[test]
    fn slot_at_saturates_at_zero_before_genesis() {
        let t = timing();
        let genesis_ms = t.genesis_time as i64 * 1000;
        assert_eq!(t.slot_at(genesis_ms - 1), 0);
        assert_eq!(t.slot_at(0), 0);
    }

    #[test]
    fn valid_geometry_passes_validation() {
        assert!(timing().validate().is_ok());
        // Genesis in the future is legitimate: a devnet is configured before it
        // fires, and until then every offset is simply negative.
        let future = Timing {
            genesis_time: MAX_GENESIS_TIME,
            ..timing()
        };
        assert!(future.validate().is_ok());
    }

    #[test]
    fn zero_or_absurd_ms_per_slot_is_rejected() {
        // A malformed spec response used to pass straight through: nothing
        // crashed, but every dot piled against one edge with no explanation.
        for ms_per_slot in [0, MAX_MS_PER_SLOT + 1] {
            let t = Timing {
                ms_per_slot,
                ..timing()
            };
            assert!(
                matches!(
                    t.validate(),
                    Err(BootstrapError::ImplausibleGeometry { .. })
                ),
                "ms_per_slot {ms_per_slot} should be rejected"
            );
        }
    }

    #[test]
    fn zero_intervals_per_slot_is_rejected() {
        // The beeswarm's axis split divides by it.
        let t = Timing {
            intervals_per_slot: 0,
            ..timing()
        };
        assert!(matches!(
            t.validate(),
            Err(BootstrapError::ImplausibleGeometry { .. })
        ));
    }

    #[test]
    fn a_genesis_time_that_would_overflow_the_offset_math_is_rejected() {
        // `offset_ms` multiplies genesis_time by 1000 as an i64, which panics in
        // a debug build on an absurd value off the wire.
        let t = Timing {
            genesis_time: u64::MAX,
            ..timing()
        };
        assert!(matches!(
            t.validate(),
            Err(BootstrapError::ImplausibleGeometry { .. })
        ));
    }

    #[test]
    fn the_largest_accepted_genesis_time_does_not_overflow_offset_ms() {
        // Pins the bound to what it exists for: the accepted maximum, at the
        // largest accepted slot duration, must stay inside i64.
        let t = Timing {
            genesis_time: MAX_GENESIS_TIME,
            ms_per_slot: MAX_MS_PER_SLOT,
            intervals_per_slot: 5,
        };
        assert!(t.validate().is_ok());
        assert!(
            MAX_GENESIS_TIME.checked_mul(1000).unwrap() < i64::MAX as u64,
            "MAX_GENESIS_TIME must keep genesis_time * 1000 inside i64"
        );
        // Non-panicking in a debug build is the assertion.
        let _ = t.offset_ms(0, 0);
    }

    #[test]
    fn slot_at_survives_a_bogus_zero_ms_per_slot() {
        // `ms_per_slot` comes off the wire, so a malformed spec response must
        // not divide by zero.
        let t = Timing {
            genesis_time: 0,
            ms_per_slot: 0,
            intervals_per_slot: 5,
        };
        assert_eq!(t.slot_at(5_000), 5_000);
    }
}
