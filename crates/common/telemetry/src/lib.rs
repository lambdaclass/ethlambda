//! Per-block telemetry rows for ClickHouse, in Silver's `block_events` layout.
//!
//! One row per point in a block's life on this node, and per data column
//! arrival, written by a background task over ClickHouse's HTTP interface.
//! Off unless [`install`] ran: every [`emit`] without it is a no-op that does
//! not even build its rows. See `docs/telemetry.md`.

mod event;
mod metrics;
mod writer;

use std::sync::OnceLock;

use tokio::sync::mpsc;

pub use event::{BlockEvent, SlotClock, TelemetryConfig};

/// Rows waiting for the writer task, which drains it continuously. A full
/// channel drops the new row rather than blocking the emitting actor.
const CHANNEL_CAPACITY: usize = 16_384;

static SINK: OnceLock<mpsc::Sender<BlockEvent>> = OnceLock::new();

/// Start the writer task and route every later [`emit`] to it.
///
/// Must run inside a tokio runtime. A second call is ignored: the first
/// writer already owns the destination.
pub fn install(config: TelemetryConfig) {
    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    if SINK.set(tx).is_err() {
        tracing::warn!("Telemetry is already installed; ignoring a second install");
        return;
    }
    metrics::init();
    tokio::spawn(writer::run(config, rx, writer::Limits::DEFAULT));
}

/// Queue the events `build` returns, if telemetry is installed.
///
/// `build` runs only when it is, so an emit site pays nothing for its rows on
/// a node without a ClickHouse URL.
pub fn emit(build: impl FnOnce() -> Vec<BlockEvent>) {
    let Some(tx) = SINK.get() else {
        return;
    };
    for event in build() {
        if tx.try_send(event).is_err() {
            metrics::inc_rows_dropped(1);
        }
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
