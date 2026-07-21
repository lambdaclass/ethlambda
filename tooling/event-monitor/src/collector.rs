//! Per-node SSE collector: dials `GET {node.url}/lean/v0/events`, stamps
//! arrival time, normalizes, and republishes on the [`Hub`]. Reconnects with
//! capped exponential backoff and reports connection state changes plus a
//! periodic heartbeat (CONTRACT.md §2, §4).

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eventsource_stream::{Event as SseEvent, Eventsource};
use futures_util::StreamExt;

use crate::config::NodeConfig;
use crate::hub::Hub;
use crate::model::{self, NodeState, NodeStatus};
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

/// Runs forever: connects, streams, and on any disconnect/error reconnects
/// with capped exponential backoff. Intended to be spawned as one long-lived
/// task per configured node.
pub async fn run_collector(
    node: NodeConfig,
    topics: Vec<String>,
    timing: Arc<Timing>,
    hub: Hub,
    client: reqwest::Client,
) {
    let mut backoff = Backoff::new();
    loop {
        hub.publish_status(NodeStatus {
            node: node.name.clone(),
            state: NodeState::Reconnecting,
            events_per_sec: 0.0,
        });

        match connect_and_stream(&node, &topics, &timing, &hub, &client).await {
            Ok(()) => {
                tracing::info!(node = %node.name, "SSE stream ended; reconnecting");
                backoff.reset();
            }
            Err(err) => {
                tracing::warn!(node = %node.name, %err, "SSE connection failed; will retry");
            }
        }

        let delay = backoff.advance();
        let state = if delay >= MAX_BACKOFF {
            NodeState::Down
        } else {
            NodeState::Reconnecting
        };
        hub.publish_status(NodeStatus {
            node: node.name.clone(),
            state,
            events_per_sec: 0.0,
        });
        tokio::time::sleep(delay).await;
    }
}

/// Opens one SSE connection and streams frames until the connection ends or
/// errors. Returns `Ok(())` on a clean end-of-stream (server closed it),
/// `Err` on a transport/parse failure.
async fn connect_and_stream(
    node: &NodeConfig,
    topics: &[String],
    timing: &Timing,
    hub: &Hub,
    client: &reqwest::Client,
) -> Result<(), CollectorError> {
    let url = format!(
        "{}/lean/v0/events?topics={}",
        node.url.trim_end_matches('/'),
        topics.join(",")
    );

    let response = client.get(&url).send().await?.error_for_status()?;
    let mut stream = response.bytes_stream().eventsource();

    hub.publish_status(NodeStatus {
        node: node.name.clone(),
        state: NodeState::Connected,
        events_per_sec: 0.0,
    });
    tracing::info!(node = %node.name, %url, "connected to SSE stream");

    let mut rate = RateTracker::new();
    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat.tick().await; // the first tick fires immediately; consume it

    loop {
        tokio::select! {
            frame = stream.next() => {
                match frame {
                    Some(Ok(event)) => {
                        rate.tick();
                        handle_frame(node, &event, timing, hub);
                    }
                    Some(Err(err)) => return Err(CollectorError::Stream(err.to_string())),
                    None => return Ok(()),
                }
            }
            _ = heartbeat.tick() => {
                hub.publish_status(NodeStatus {
                    node: node.name.clone(),
                    state: NodeState::Connected,
                    events_per_sec: rate.rate_and_reset(),
                });
            }
        }
    }
}

/// Normalizes one already-parsed SSE frame and publishes it on the hub.
/// Never panics: an unknown topic or payload we can't parse is logged and
/// dropped (CONTRACT.md §2).
fn handle_frame(node: &NodeConfig, event: &SseEvent, timing: &Timing, hub: &Hub) {
    // Defensive: eventsource-stream already suppresses comment/keep-alive
    // lines (they never build a non-empty data buffer), but guard anyway.
    if event.data.is_empty() {
        return;
    }
    match model::normalize(&node.name, &event.event, &event.data, now_ms(), timing) {
        Ok(normalized) => hub.publish_chain(normalized),
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
