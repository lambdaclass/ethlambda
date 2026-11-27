//! Per-block telemetry rows for ClickHouse, in Silver's `block_events` layout.
//!
//! One row per point in a block's life on this node, and per data column
//! arrival, written by a background task over ClickHouse's HTTP interface.
//! Off unless [`install`] ran: every [`emit`] without it is a no-op that does
//! not even build its rows. See `docs/telemetry.md`.

mod event;
mod metrics;
pub mod pq_timing;
mod writer;

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;

pub use event::{BlockEvent, SlotClock, TelemetryConfig};

/// Rows waiting for the writer task, which drains it continuously. A full
/// channel drops the new row rather than blocking the emitting actor.
const CHANNEL_CAPACITY: usize = 16_384;

/// The installed writer: where [`emit`] sends, and how [`shutdown`] reaches
/// it. The sender lives as long as the process, so the channel never closes
/// on its own; the writer flushes on [`shutdown`] instead.
struct Sink {
    tx: mpsc::Sender<BlockEvent>,
    shutdown: Arc<Notify>,
    writer: Mutex<Option<JoinHandle<()>>>,
}

static SINK: OnceLock<Sink> = OnceLock::new();

/// Start the writer task and route every later [`emit`] to it.
///
/// Must run inside a tokio runtime. A second call is ignored: the first
/// writer already owns the destination.
pub fn install(config: TelemetryConfig) {
    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    let shutdown = Arc::new(Notify::new());
    let sink = Sink {
        tx,
        shutdown: shutdown.clone(),
        writer: Mutex::new(None),
    };
    if SINK.set(sink).is_err() {
        tracing::warn!("Telemetry is already installed; ignoring a second install");
        return;
    }
    metrics::init();
    let writer = tokio::spawn(writer::run(config, rx, writer::Limits::DEFAULT, shutdown));
    if let Some(sink) = SINK.get() {
        *sink.writer.lock().expect("telemetry writer lock") = Some(writer);
    }
}

/// Flush the rows still queued and stop the writer, waiting at most `timeout`.
///
/// Every [`emit`] after this counts its rows as dropped. Rows the flush could
/// not deliver are counted as dropped too, except when `timeout` runs out
/// first, which is logged instead. A no-op without [`install`], and on a
/// second call.
pub async fn shutdown(timeout: Duration) {
    let Some(sink) = SINK.get() else {
        return;
    };
    let Some(writer) = sink.writer.lock().expect("telemetry writer lock").take() else {
        return;
    };
    sink.shutdown.notify_one();
    let _ = tokio::time::timeout(timeout, writer)
        .await
        .inspect_err(|_| tracing::warn!(?timeout, "Telemetry flush did not finish in time"));
}

/// Queue the events `build` returns, if telemetry is installed.
///
/// `build` runs only when it is, so an emit site pays nothing for its rows on
/// a node without a ClickHouse URL.
pub fn emit(build: impl FnOnce() -> Vec<BlockEvent>) {
    let Some(sink) = SINK.get() else {
        return;
    };
    for event in build() {
        let _ = sink
            .tx
            .try_send(event)
            .inspect_err(|_| metrics::inc_rows_dropped(1));
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    /// No test in this crate calls `install`, so the global stays empty here;
    /// keep it that way, or this one would race it.
    #[test]
    fn emit_builds_nothing_when_telemetry_is_not_installed() {
        let built = Cell::new(false);
        emit(|| {
            built.set(true);
            Vec::new()
        });
        assert!(!built.get());
    }
}
