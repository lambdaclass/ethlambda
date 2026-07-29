//! axum HTTP server: static dashboard, the merged SSE `/stream`, and the
//! `/api/meta` bootstrap endpoint (CONTRACT.md §4).

use std::convert::Infallible;
use std::path::Path;
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::response::Json;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::get;
use futures_util::{Stream, StreamExt};
use serde::Serialize;
use tokio::sync::watch;
use tokio_stream::wrappers::BroadcastStream;
use tower_http::services::{ServeDir, ServeFile};

use crate::config::{Config, NodeConfig};
use crate::hub::{HistorySnapshot, Hub, HubMessage};
use crate::timing::Timing;

/// Keep-alive comment interval on `/stream`, independent of any per-node
/// heartbeat published on the hub (CONTRACT.md §4).
const SSE_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// One-shot bootstrap payload the frontend fetches on load (CONTRACT.md §4).
#[derive(Debug, Clone, Serialize)]
pub struct Meta {
    pub genesis_time: u64,
    pub ms_per_slot: u64,
    pub intervals_per_slot: u64,
    pub window_slots: u32,
    pub topics: Vec<String>,
    pub nodes: Vec<NodeConfig>,
}

/// The config-derived half of [`Meta`]. The timing half is read live per
/// request from the geometry watch channel, so a refresh
/// ([`crate::timing::run_refresher`]) reaches the next page load without a
/// restart.
#[derive(Debug, Clone)]
pub struct MetaConfig {
    window_slots: u32,
    topics: Vec<String>,
    nodes: Vec<NodeConfig>,
}

impl MetaConfig {
    pub fn new(config: &Config) -> Self {
        Self {
            window_slots: config.window_slots,
            topics: config.topics.clone(),
            nodes: config.nodes.clone(),
        }
    }

    fn with_timing(&self, timing: Timing) -> Meta {
        Meta {
            genesis_time: timing.genesis_time,
            ms_per_slot: timing.ms_per_slot,
            intervals_per_slot: timing.intervals_per_slot,
            window_slots: self.window_slots,
            topics: self.topics.clone(),
            nodes: self.nodes.clone(),
        }
    }
}

#[derive(Clone)]
struct AppState {
    hub: Hub,
    meta: MetaConfig,
    timing: watch::Receiver<Timing>,
}

/// Builds the full axum app: `/stream`, `/api/meta`, `/api/history`, and static
/// file serving rooted at `static_dir`.
///
/// `/` is routed to `index.html` explicitly and everything unmatched 404s. The
/// dashboard is one page, not a client-routed SPA, so a catch-all `index.html`
/// fallback bought nothing and cost the two signals worth having: a typo'd asset
/// path came back as `200 text/html` and surfaced as a mystery JS parse error,
/// and a wrong API path answered `200` instead of telling a frozen contract's
/// caller it had the path wrong.
pub fn build_router(
    hub: Hub,
    meta: MetaConfig,
    timing: watch::Receiver<Timing>,
    static_dir: &Path,
) -> Router {
    let state = AppState { hub, meta, timing };

    Router::new()
        .route("/stream", get(stream_handler))
        .route("/api/meta", get(meta_handler))
        .route("/api/history", get(history_handler))
        .route_service("/", ServeFile::new(static_dir.join("index.html")))
        .with_state(state)
        .fallback_service(ServeDir::new(static_dir))
}

async fn meta_handler(State(state): State<AppState>) -> Json<Meta> {
    // Copy the geometry out immediately rather than holding the watch borrow.
    let timing = *state.timing.borrow();
    Json(state.meta.with_timing(timing))
}

/// Backfill for `GET /api/history` (CONTRACT.md §4): recent chain events (each
/// identical in shape to a `/stream` `chain` event) plus the latest status per
/// node. The frontend seeds both panels from this before going live, de-duping
/// the small overlap with the live stream.
async fn history_handler(State(state): State<AppState>) -> Json<HistorySnapshot> {
    Json(state.hub.history_snapshot())
}

async fn stream_handler(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let receiver = state.hub.subscribe();
    let stream = BroadcastStream::new(receiver).filter_map(|message| async move {
        match message {
            Ok(HubMessage::Chain(event)) => Some(Ok(sse_event("chain", &event))),
            Ok(HubMessage::Status(status)) => Some(Ok(sse_event("status", &status))),
            Ok(HubMessage::Geometry(timing)) => Some(Ok(sse_event("geometry", &timing))),
            // Best-effort stream: a slow browser subscriber that falls
            // behind simply skips the messages it missed, same contract as
            // the upstream ethlambda SSE endpoint (CONTRACT.md §4).
            Err(_lagged) => None,
        }
    });

    Sse::new(stream).keep_alive(KeepAlive::default().interval(SSE_KEEP_ALIVE_INTERVAL))
}

/// Builds one named SSE event carrying `payload` as its JSON `data:` line.
/// Serialization of our own well-formed model types never fails; fall back
/// to an empty event of the same name in the unreachable error case rather
/// than panicking.
fn sse_event<T: Serialize>(name: &str, payload: &T) -> Event {
    Event::default()
        .event(name)
        .json_data(payload)
        .unwrap_or_else(|_| Event::default().event(name))
}
