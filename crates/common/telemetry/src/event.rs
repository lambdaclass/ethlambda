//! A block event and its `block_events` row.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// Slots after a slot's start within which an event's wall clock still says
/// something about that slot. Past it the event is catch-up or backfill, and
/// its offset is left NULL rather than reported as lateness. Silver uses the
/// same window.
const LIVE_SLOTS: u64 = 2;

/// One point in a block's life on this node: a row of `block_events`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockEvent {
    /// Silver's stage name where the meaning matches, `<section>_start` or
    /// `<section>_end` for ethlambda's other sections.
    pub stage: &'static str,
    pub at: Instant,
    pub slot: u64,
    pub block_root: [u8; 32],
    /// How the block or column reached this node.
    pub source: &'static str,
    /// The execution client's verdict, on `el_verdict` rows only.
    pub verdict: Option<&'static str>,
    /// The data column's index, on `column_*` rows only.
    pub column_index: Option<u64>,
}

/// Genesis and slot length: what turns a slot into the wall clock it starts at.
#[derive(Debug, Clone, Copy)]
pub struct SlotClock {
    genesis_ms: u64,
    slot_ms: u64,
}

impl SlotClock {
    pub fn new(genesis_ms: u64, slot_ms: u64) -> Self {
        Self {
            genesis_ms,
            // A zero slot length would make the live window empty.
            slot_ms: slot_ms.max(1),
        }
    }

    fn slot_start_ms(&self, slot: u64) -> u64 {
        self.genesis_ms
            .saturating_add(slot.saturating_mul(self.slot_ms))
    }

    /// Milliseconds from `slot`'s start to `unix_ns`, or `None` outside the
    /// live window.
    fn offset_ms(&self, unix_ns: u64, slot: u64) -> Option<f64> {
        let start_ns = u128::from(self.slot_start_ms(slot)) * 1_000_000;
        let window_ns = u128::from(self.slot_ms) * u128::from(LIVE_SLOTS) * 1_000_000;
        let at = u128::from(unix_ns);
        (start_ns..start_ns + window_ns)
            .contains(&at)
            .then(|| (at - start_ns) as f64 / 1e6)
    }
}

/// What every row carries besides its event, and where rows go.
///
/// No `Debug`: the URL may carry credentials, and its `Debug` prints them.
#[derive(Clone)]
pub struct TelemetryConfig {
    /// ClickHouse's HTTP interface. Credentials in the URL's userinfo are
    /// sent as basic auth; query parameters such as `database` pass through.
    pub url: reqwest::Url,
    /// `meta_client_name` on every row.
    pub client_name: String,
    /// `meta_network_name` on every row.
    pub network_name: String,
    pub clock: SlotClock,
}

/// A monotonic and a wall-clock reading taken together.
///
/// Import timings are [`Instant`]s, which only subtract from one another, so
/// each is converted against a pair read at encoding time: the wall clock at
/// the anchor, minus how long before the anchor the instant was.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Anchor {
    instant: Instant,
    unix_ns: u64,
}

impl Anchor {
    pub(crate) fn now() -> Self {
        let unix_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|since| since.as_nanos() as u64)
            .unwrap_or_default();
        Self {
            instant: Instant::now(),
            unix_ns,
        }
    }

    fn unix_ns(&self, at: Instant) -> u64 {
        match at.checked_duration_since(self.instant) {
            Some(after) => self.unix_ns.saturating_add(after.as_nanos() as u64),
            None => self
                .unix_ns
                .saturating_sub(self.instant.duration_since(at).as_nanos() as u64),
        }
    }
}

/// One `block_events` row. Field names are the table's column names.
#[derive(Serialize)]
struct Row<'a> {
    /// Unix nanoseconds, which `DateTime64(9)` reads from a `JSONEachRow`
    /// integer as is.
    event_date_time: u64,
    stage: &'static str,
    slot: u64,
    /// `None` past what `DateTime` holds: ClickHouse wraps a larger value
    /// instead of rejecting it.
    slot_start_date_time: Option<u64>,
    time_into_slot_ms: Option<f64>,
    block_root: String,
    source: &'static str,
    verdict: Option<&'static str>,
    column_index: Option<u64>,
    meta_client_name: &'a str,
    meta_network_name: &'a str,
}

/// `event` as one `JSONEachRow` line, without the trailing newline.
pub(crate) fn encode(event: &BlockEvent, anchor: Anchor, config: &TelemetryConfig) -> String {
    let unix_ns = anchor.unix_ns(event.at);
    let row = Row {
        event_date_time: unix_ns,
        stage: event.stage,
        slot: event.slot,
        slot_start_date_time: Some(config.clock.slot_start_ms(event.slot) / 1_000)
            .filter(|seconds| *seconds <= u64::from(u32::MAX)),
        time_into_slot_ms: config.clock.offset_ms(unix_ns, event.slot),
        block_root: format!("0x{}", hex::encode(event.block_root)),
        source: event.source,
        verdict: event.verdict,
        column_index: event.column_index,
        meta_client_name: &config.client_name,
        meta_network_name: &config.network_name,
    };
    serde_json::to_string(&row).expect("a row of plain fields always serializes")
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    const GENESIS_MS: u64 = 1_000_000;
    const SLOT_MS: u64 = 12_000;

    fn config() -> TelemetryConfig {
        TelemetryConfig {
            url: "http://127.0.0.1:8123".parse().unwrap(),
            client_name: "node-a".into(),
            network_name: "mainnet".into(),
            clock: SlotClock::new(GENESIS_MS, SLOT_MS),
        }
    }

    /// An anchor whose instant sits `ms` milliseconds into `slot`.
    fn anchor_at(slot: u64, ms: u64) -> Anchor {
        Anchor {
            instant: Instant::now(),
            unix_ns: (GENESIS_MS + slot * SLOT_MS + ms) * 1_000_000,
        }
    }

    fn event(at: Instant, slot: u64) -> BlockEvent {
        BlockEvent {
            stage: "received",
            at,
            slot,
            block_root: [0xab; 32],
            source: "gossip",
            verdict: None,
            column_index: None,
        }
    }

    fn row(event: &BlockEvent, anchor: Anchor) -> serde_json::Value {
        serde_json::from_str(&encode(event, anchor, &config())).unwrap()
    }

    #[test]
    fn a_row_carries_silvers_columns() {
        let anchor = anchor_at(2, 300);
        let row = row(&event(anchor.instant, 2), anchor);

        let mut keys: Vec<_> = row.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        // The table definition is the source of truth for the columns.
        let mut columns: Vec<_> = crate::writer::DDL
            .lines()
            .skip(1)
            .take_while(|line| !line.starts_with(')'))
            .map(|line| line.split_whitespace().next().unwrap().to_owned())
            .collect();
        columns.sort();
        assert_eq!(keys, columns);
        assert_eq!(
            row["event_date_time"],
            (GENESIS_MS + 2 * SLOT_MS + 300) * 1_000_000
        );
        assert_eq!(row["stage"], "received");
        assert_eq!(row["slot"], 2);
        assert_eq!(
            row["slot_start_date_time"],
            (GENESIS_MS + 2 * SLOT_MS) / 1_000
        );
        assert_eq!(row["time_into_slot_ms"], 300.0);
        assert_eq!(row["block_root"], format!("0x{}", "ab".repeat(32)));
        assert_eq!(row["source"], "gossip");
        assert!(row["verdict"].is_null());
        assert!(row["column_index"].is_null());
        assert_eq!(row["meta_client_name"], "node-a");
        assert_eq!(row["meta_network_name"], "mainnet");
    }

    #[test]
    fn instants_convert_relative_to_the_anchor() {
        let anchor = anchor_at(2, 300);

        let later = row(
            &event(anchor.instant + Duration::from_millis(50), 2),
            anchor,
        );
        assert_eq!(later["time_into_slot_ms"], 350.0);

        // Rows are encoded after the fact, so most instants precede the anchor.
        let earlier_at = anchor
            .instant
            .checked_sub(Duration::from_millis(100))
            .unwrap();
        let earlier = row(&event(earlier_at, 2), anchor);
        assert_eq!(earlier["time_into_slot_ms"], 200.0);
    }

    #[test]
    fn the_slot_start_is_null_past_what_datetime_holds() {
        // ClickHouse wraps a DateTime above u32::MAX seconds rather than
        // rejecting it, so such a slot must not be sent as one.
        let anchor = Anchor {
            instant: Instant::now(),
            unix_ns: 0,
        };
        let row = row(&event(anchor.instant, 1 << 40), anchor);
        assert!(row["slot_start_date_time"].is_null());
        assert!(row["time_into_slot_ms"].is_null());
    }

    #[test]
    fn the_offset_is_null_outside_the_live_window() {
        // Two whole slots after its own slot started: catch-up, not lateness.
        let anchor = anchor_at(9, 0);
        let catch_up = row(&event(anchor.instant, 7), anchor);
        assert!(catch_up["time_into_slot_ms"].is_null());
        assert_eq!(
            catch_up["slot_start_date_time"],
            (GENESIS_MS + 7 * SLOT_MS) / 1_000
        );

        // Before its slot started.
        let anchor = anchor_at(6, 11_000);
        assert!(row(&event(anchor.instant, 7), anchor)["time_into_slot_ms"].is_null());

        // A slot late is still inside: late blocks are real.
        let anchor = anchor_at(8, 500);
        assert_eq!(
            row(&event(anchor.instant, 7), anchor)["time_into_slot_ms"],
            12_500.0
        );
    }
}
