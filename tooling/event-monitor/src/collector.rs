//! Per-node SSE collector: dials `GET {node.url}/lean/v0/events`, stamps
//! arrival time, normalizes, and republishes on the [`Hub`]. Reconnects with
//! capped exponential backoff and reports connection state changes plus a
//! periodic heartbeat (CONTRACT.md §2, §4).

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eventsource_stream::{Event as SseEvent, Eventsource};
use futures_util::StreamExt;
use tokio::sync::watch;

use crate::config::NodeConfig;
use crate::hub::Hub;
use crate::model::{self, NodeState, NodeStatus, NormalizeError};
use crate::timing::Timing;

const INITIAL_BACKOFF: Duration = Duration::from_millis(250);
const MAX_BACKOFF: Duration = Duration::from_secs(10);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
enum CollectorError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("event stream error: {0}")]
    Stream(String),
}

/// Outcome of one connection attempt, as the reconnect loop needs it.
struct Attempt {
    /// `true` once the connection stayed up for at least one
    /// [`HEARTBEAT_INTERVAL`] while streaming.
    ///
    /// Keyed on how *long* the session lasted rather than on how it ended: a
    /// node restart surfaces as an error after hours of healthy streaming and
    /// must not inherit the failure ramp, while a peer that accepts the
    /// request and instantly drops the stream ends cleanly yet must keep
    /// ramping instead of being hammered at [`INITIAL_BACKOFF`].
    healthy: bool,
    /// `None` on a clean end-of-stream, `Some` on a transport/parse failure.
    error: Option<CollectorError>,
}

impl Attempt {
    /// The connection was never established.
    fn failed(error: CollectorError) -> Self {
        Self {
            healthy: false,
            error: Some(error),
        }
    }
}

/// Exponential backoff capped at [`MAX_BACKOFF`]. Used both to pace
/// reconnect attempts and to decide whether the collector should report
/// `reconnecting` (still ramping up retries) or `down` (settled into
/// sustained failure at the cap).
struct Backoff {
    delay: Duration,
}

impl Backoff {
    fn new() -> Self {
        Self {
            delay: INITIAL_BACKOFF,
        }
    }

    fn reset(&mut self) {
        self.delay = INITIAL_BACKOFF;
    }

    /// Folds one attempt's outcome into the ramp: a session that proved
    /// healthy clears it, so the next reconnect starts from
    /// [`INITIAL_BACKOFF`] instead of inheriting the delay earned by earlier
    /// failures. Without this, every node restart ratchets the delay one step
    /// permanently and a perfectly healthy node eventually reports `down`.
    fn record(&mut self, attempt: &Attempt) {
        if attempt.healthy {
            self.reset();
        }
    }

    /// Returns the delay to wait before the next attempt, then doubles
    /// (capped) for next time.
    fn advance(&mut self) -> Duration {
        let current = self.delay;
        self.delay = (self.delay * 2).min(MAX_BACKOFF);
        current
    }
}

/// Tracks a rolling events-per-second rate over the time since the last
/// reset, driven by the collector's heartbeat.
struct RateTracker {
    count: u64,
    window_start: Instant,
}

impl RateTracker {
    fn new() -> Self {
        Self {
            count: 0,
            window_start: Instant::now(),
        }
    }

    fn tick(&mut self) {
        self.count += 1;
    }

    /// Events/sec since the last call, then resets the window.
    fn rate_and_reset(&mut self) -> f64 {
        let elapsed = self.window_start.elapsed().as_secs_f64().max(0.001);
        let rate = self.count as f64 / elapsed;
        self.count = 0;
        self.window_start = Instant::now();
        rate
    }
}

fn now_ms() -> i64 {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

fn node_status(name: &str, state: NodeState, events_per_sec: f64) -> NodeStatus {
    NodeStatus {
        node: name.to_string(),
        state,
        events_per_sec,
    }
}

/// Runs forever: connects, streams, and on any disconnect/error reconnects
/// with capped exponential backoff. Intended to be spawned as one long-lived
/// task per configured node.
pub async fn run_collector(
    node: NodeConfig,
    topics: Vec<String>,
    timing: watch::Receiver<Timing>,
    hub: Hub,
    client: reqwest::Client,
) {
    let mut backoff = Backoff::new();
    loop {
        hub.publish_status(node_status(&node.name, NodeState::Reconnecting, 0.0));

        let attempt = connect_and_stream(&node, &topics, &timing, &hub, &client).await;
        match &attempt.error {
            None => tracing::info!(node = %node.name, "SSE stream ended; reconnecting"),
            Some(err) => {
                tracing::warn!(node = %node.name, %err, "SSE connection failed; will retry");
            }
        }
        backoff.record(&attempt);

        let delay = backoff.advance();
        let state = if delay >= MAX_BACKOFF {
            NodeState::Down
        } else {
            NodeState::Reconnecting
        };
        hub.publish_status(node_status(&node.name, state, 0.0));
        tokio::time::sleep(delay).await;
    }
}

/// Opens one SSE connection and streams frames until the connection ends or
/// errors. The returned [`Attempt`] carries both how the session ended and
/// whether it lasted long enough to count as healthy.
async fn connect_and_stream(
    node: &NodeConfig,
    topics: &[String],
    timing: &watch::Receiver<Timing>,
    hub: &Hub,
    client: &reqwest::Client,
) -> Attempt {
    let url = format!(
        "{}?topics={}",
        node.endpoint("/lean/v0/events"),
        topics.join(",")
    );

    let response = match client
        .get(&url)
        .send()
        .await
        .and_then(|response| response.error_for_status())
    {
        Ok(response) => response,
        Err(err) => return Attempt::failed(err.into()),
    };
    let mut stream = response.bytes_stream().eventsource();

    hub.publish_status(node_status(&node.name, NodeState::Connected, 0.0));
    tracing::info!(node = %node.name, %url, "connected to SSE stream");

    let mut rate = RateTracker::new();
    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat.tick().await; // the first tick fires immediately; consume it
    let mut healthy = false;
    let mut warned_implausible_slot = false;

    loop {
        tokio::select! {
            frame = stream.next() => {
                match frame {
                    Some(Ok(event)) => {
                        rate.tick();
                        // Re-read per frame so a geometry refresh takes effect
                        // without tearing down the connection.
                        let geometry = *timing.borrow();
                        handle_frame(node, &event, geometry, hub, &mut warned_implausible_slot);
                    }
                    Some(Err(err)) => {
                        let error = Some(CollectorError::Stream(err.to_string()));
                        return Attempt { healthy, error };
                    }
                    None => return Attempt { healthy, error: None },
                }
            }
            _ = heartbeat.tick() => {
                // Surviving a whole heartbeat interval while streaming is what
                // marks the session healthy for backoff purposes.
                healthy = true;
                hub.publish_status(node_status(
                    &node.name,
                    NodeState::Connected,
                    rate.rate_and_reset(),
                ));
            }
        }
    }
}

/// Normalizes one already-parsed SSE frame and publishes it on the hub.
/// Never panics: an unknown topic or payload we can't parse is logged and
/// dropped (CONTRACT.md §2).
///
/// `warned_implausible_slot` latches the one-per-session warning for slots the
/// collector clock says cannot be real; a node on the wrong genesis produces
/// one such frame per event, and the point is to be noticed, not to flood.
fn handle_frame(
    node: &NodeConfig,
    event: &SseEvent,
    timing: Timing,
    hub: &Hub,
    warned_implausible_slot: &mut bool,
) {
    // Defensive: eventsource-stream already suppresses comment/keep-alive
    // lines (they never build a non-empty data buffer), but guard anyway.
    if event.data.is_empty() {
        return;
    }
    match model::normalize(&node.name, &event.event, &event.data, now_ms(), &timing) {
        Ok(normalized) => hub.publish_chain(normalized),
        Err(err @ NormalizeError::ImplausibleSlot { .. }) => {
            if !*warned_implausible_slot {
                *warned_implausible_slot = true;
                tracing::warn!(
                    node = %node.name,
                    %err,
                    "dropping events with implausible slots; is this node on a different genesis?"
                );
            }
        }
        Err(err) => {
            tracing::debug!(
                node = %node.name,
                topic = %event.event,
                %err,
                "skipping unparsable SSE frame"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_until_capped() {
        let mut backoff = Backoff::new();
        assert_eq!(backoff.advance(), Duration::from_millis(250));
        assert_eq!(backoff.advance(), Duration::from_millis(500));
        assert_eq!(backoff.advance(), Duration::from_millis(1_000));
        assert_eq!(backoff.advance(), Duration::from_millis(2_000));
        assert_eq!(backoff.advance(), Duration::from_millis(4_000));
        assert_eq!(backoff.advance(), Duration::from_millis(8_000));
        // 8s * 2 = 16s, capped to 10s.
        assert_eq!(backoff.advance(), MAX_BACKOFF);
        assert_eq!(backoff.advance(), MAX_BACKOFF);
    }

    #[test]
    fn backoff_reset_returns_to_initial_delay() {
        let mut backoff = Backoff::new();
        backoff.advance();
        backoff.advance();
        backoff.reset();
        assert_eq!(backoff.advance(), INITIAL_BACKOFF);
    }

    #[test]
    fn healthy_session_clears_the_ramp_even_when_it_ends_with_an_error() {
        // The common shape of a node restart: hours of healthy streaming, then
        // the connection drops with an error. The next reconnect must start
        // from INITIAL_BACKOFF, not inherit the ramp.
        let mut backoff = Backoff::new();
        backoff.advance();
        backoff.advance();
        backoff.record(&Attempt {
            healthy: true,
            error: Some(CollectorError::Stream(
                "connection reset by peer".to_string(),
            )),
        });
        assert_eq!(backoff.advance(), INITIAL_BACKOFF);
    }

    #[test]
    fn unhealthy_session_keeps_the_ramp_climbing_even_when_it_ends_cleanly() {
        // A peer that accepts the request and immediately closes the stream
        // ends cleanly, but must not be retried at INITIAL_BACKOFF forever.
        let mut backoff = Backoff::new();
        assert_eq!(backoff.advance(), INITIAL_BACKOFF);
        backoff.record(&Attempt {
            healthy: false,
            error: None,
        });
        assert_eq!(backoff.advance(), INITIAL_BACKOFF * 2);
    }

    #[test]
    fn repeated_healthy_sessions_never_ratchet_toward_down() {
        // Regression: with the reset keyed on clean end-of-stream instead of on
        // session health, each restart ratcheted the delay one step and after
        // ~7 restarts a healthy node was reported Down with 10s reconnects.
        let mut backoff = Backoff::new();
        for _ in 0..20 {
            let delay = backoff.advance();
            assert!(delay < MAX_BACKOFF, "delay ratcheted to the Down threshold");
            backoff.record(&Attempt {
                healthy: true,
                error: Some(CollectorError::Stream("node restarted".to_string())),
            });
        }
    }

    #[test]
    fn rate_tracker_counts_ticks_since_last_reset() {
        let mut rate = RateTracker::new();
        rate.tick();
        rate.tick();
        // Elapsed time is tiny but non-zero (clamped to a 1ms floor), so the
        // computed rate is finite and positive rather than NaN/infinite.
        let observed = rate.rate_and_reset();
        assert!(observed.is_finite());
        assert!(observed > 0.0);
    }
}
