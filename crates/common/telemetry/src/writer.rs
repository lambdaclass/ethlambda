//! The background task that moves rows from the channel into ClickHouse.
//!
//! Rows are read off the channel continuously, including while a request is
//! in flight, into a pending buffer; the channel's capacity therefore only
//! has to cover the gap between two polls of this task, not a slow request.
//! At most one request is in flight, and it starts on a tick, so a steady
//! trickle is one insert per tick: ClickHouse writes a part per insert. A
//! failed request leaves its rows at the front of the buffer for the next
//! tick, and the buffer drops its oldest rows past a cap, so an unreachable
//! ClickHouse costs bounded memory.

use std::collections::VecDeque;
use std::error::Error as _;
use std::time::Duration;

use reqwest::{Client, RequestBuilder, Url};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::{error, info, warn};

use crate::event::{Anchor, BlockEvent, TelemetryConfig, encode};
use crate::metrics;

/// Silver's `block_events` table, verbatim (gattaca-com/silver,
/// `crates/telemetry/src/block_events.rs`, MIT), so both clients' rows share
/// one table and one set of queries.
pub(crate) const DDL: &str = "CREATE TABLE IF NOT EXISTS block_events (
    event_date_time      DateTime64(9)                    COMMENT 'Node-local wall clock at the observation',
    stage                LowCardinality(String)           COMMENT 'Point in the block path through the node this row observes',
    slot                 Nullable(UInt64)                 COMMENT 'NULL when the root was first seen before the collector attached',
    slot_start_date_time Nullable(DateTime)               COMMENT 'Wall clock the slot started at',
    time_into_slot_ms    Nullable(Float64)                COMMENT 'Milliseconds from slot start; NULL outside the live window (replay or backfill)',
    block_root           String                           COMMENT '0x-prefixed beacon block root; rows written before 2026-08-18 lack the prefix',
    source               LowCardinality(String)           COMMENT 'How the node obtained the block',
    verdict              LowCardinality(Nullable(String)) COMMENT 'Execution payload status; set on el_verdict rows only',
    column_index         Nullable(UInt64)                 COMMENT 'Data-column index; set on column_* rows only',
    meta_client_name     LowCardinality(String)           COMMENT 'Hostname of the node that produced the row',
    meta_network_name    LowCardinality(String)           COMMENT 'Ethereum network the node is running'
) ENGINE = MergeTree
ORDER BY (meta_client_name, event_date_time)";

pub(crate) const INSERT: &str = "INSERT INTO block_events FORMAT JSONEachRow";

#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    pub(crate) flush_interval: Duration,
    pub(crate) max_rows_per_request: usize,
    pub(crate) max_pending_rows: usize,
    pub(crate) request_timeout: Duration,
}

impl Limits {
    pub(crate) const DEFAULT: Self = Self {
        flush_interval: Duration::from_secs(1),
        max_rows_per_request: 10_000,
        max_pending_rows: 100_000,
        request_timeout: Duration::from_secs(10),
    };
}

/// Longest prefix of ClickHouse's answer kept in a failure message.
const MAX_BODY_IN_MESSAGE: usize = 512;

/// Why a request failed.
struct Failure {
    message: String,
    /// ClickHouse refused the rows themselves (HTTP 400: a row it cannot
    /// parse or a value of the wrong type). Retrying the same rows would be
    /// refused again, and would hold back every row queued behind them.
    rejected: bool,
}

type Outcome = (Vec<String>, Result<(), Failure>);

/// A request in flight. Its rows come back with its result, so a failed one
/// can be retried; `rows` is what to count as dropped if its task panics and
/// the rows never come back.
struct InFlight {
    rows: usize,
    handle: JoinHandle<Outcome>,
}

/// Run until every sender is gone. Production keeps the sender in a static,
/// so there the task runs for the life of the process; when the channel does
/// close, the rows still pending are counted as dropped.
pub(crate) async fn run(
    config: TelemetryConfig,
    mut rx: mpsc::Receiver<BlockEvent>,
    limits: Limits,
) {
    let client = match Client::builder().timeout(limits.request_timeout).build() {
        Ok(client) => client,
        Err(err) => {
            error!(%err, "Telemetry disabled: could not build the HTTP client");
            return;
        }
    };
    // Credentials in the URL need no handling here: reqwest moves them into
    // basic auth itself, percent-decoded, and strips them from the URL.
    let urls = Urls::new(&config.url);
    let mut pending: VecDeque<String> = VecDeque::new();
    let mut in_flight: Option<InFlight> = None;
    // Before the first insert and after every failure: the statement is
    // idempotent, and rerunning it recreates a table dropped under us.
    let mut needs_schema = true;
    let mut failing = false;
    let mut tick = tokio::time::interval(limits.flush_interval);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            event = rx.recv() => {
                let Some(event) = event else {
                    metrics::inc_rows_dropped(pending.len() as u64);
                    break;
                };
                pending.push_back(encode(&event, Anchor::now(), &config));
                drop_past_cap(&mut pending, limits.max_pending_rows);
            }
            // Polled every period, whatever there is to send: a tick switched
            // off while idle would fire at once when switched back on, sending
            // the first row of the next burst on its own.
            _ = tick.tick() => {
                if in_flight.is_none() && !pending.is_empty() {
                    let batch = take_batch(&mut pending, limits.max_rows_per_request);
                    in_flight = Some(send(&client, &urls, batch, needs_schema));
                }
            }
            (batch, result) = join(&mut in_flight) => {
                in_flight = None;
                match result {
                    Ok(()) => {
                        metrics::inc_rows_inserted(batch.len() as u64);
                        needs_schema = false;
                        if failing {
                            failing = false;
                            info!("Telemetry inserts recovered");
                        }
                        // Only a full request goes ahead of the tick, so a
                        // backlog drains at once while a trickle still waits
                        // to be batched.
                        if pending.len() >= limits.max_rows_per_request {
                            let batch = take_batch(&mut pending, limits.max_rows_per_request);
                            in_flight = Some(send(&client, &urls, batch, needs_schema));
                        }
                    }
                    Err(Failure { message, rejected: true }) => {
                        metrics::inc_insert_failures();
                        metrics::inc_rows_dropped(batch.len() as u64);
                        warn!(rows = batch.len(), err = %message, "ClickHouse rejected a telemetry batch; dropping it");
                    }
                    Err(Failure { message, rejected: false }) => {
                        metrics::inc_insert_failures();
                        if !failing {
                            failing = true;
                            warn!(err = %message, "Telemetry insert failed; keeping the rows to retry");
                        }
                        needs_schema = true;
                        for row in batch.into_iter().rev() {
                            pending.push_front(row);
                        }
                        drop_past_cap(&mut pending, limits.max_pending_rows);
                    }
                }
            }
        }
    }
}

/// The in-flight request's outcome, or never when there is none.
async fn join(in_flight: &mut Option<InFlight>) -> Outcome {
    match in_flight {
        Some(InFlight { rows, handle }) => handle.await.unwrap_or_else(|err| {
            metrics::inc_rows_dropped(*rows as u64);
            let failure = Failure {
                message: format!("insert task failed: {err}"),
                rejected: false,
            };
            (Vec::new(), Err(failure))
        }),
        None => std::future::pending().await,
    }
}

fn take_batch(pending: &mut VecDeque<String>, max_rows: usize) -> Vec<String> {
    let rows = pending.len().min(max_rows);
    pending.drain(..rows).collect()
}

fn drop_past_cap(pending: &mut VecDeque<String>, max_rows: usize) {
    let excess = pending.len().saturating_sub(max_rows);
    if excess > 0 {
        pending.drain(..excess);
        metrics::inc_rows_dropped(excess as u64);
    }
}

fn send(client: &Client, urls: &Urls, batch: Vec<String>, needs_schema: bool) -> InFlight {
    let client = client.clone();
    let urls = urls.clone();
    let rows = batch.len();
    let handle = tokio::spawn(async move {
        let result = insert(&client, &urls, &batch, needs_schema).await;
        (batch, result)
    });
    InFlight { rows, handle }
}

/// The schema statement is best effort: a user that may insert but not create
/// still inserts into a table that exists. Only the insert's own failure counts,
/// with the schema statement's message attached when both failed.
async fn insert(
    client: &Client,
    urls: &Urls,
    batch: &[String],
    needs_schema: bool,
) -> Result<(), Failure> {
    let schema_error = if needs_schema {
        execute(client.post(urls.schema.clone()).body(DDL), false)
            .await
            .err()
    } else {
        None
    };
    execute(
        client.post(urls.insert.clone()).body(batch.join("\n")),
        true,
    )
    .await
    .map_err(|mut failure| {
        if let Some(schema) = schema_error {
            failure.message = format!(
                "{}; the schema statement also failed: {}",
                failure.message, schema.message
            );
        }
        failure
    })
}

/// A non-2xx answer is an error carrying ClickHouse's own message. With
/// `is_insert`, a 400 marks the rows as rejected.
async fn execute(request: RequestBuilder, is_insert: bool) -> Result<(), Failure> {
    let response = request.send().await.map_err(|err| {
        // Without the URL: it may carry credentials, and the error is logged.
        let err = err.without_url();
        let mut message = err.to_string();
        let mut source = err.source();
        while let Some(cause) = source {
            message.push_str(": ");
            message.push_str(&cause.to_string());
            source = cause.source();
        }
        Failure {
            message,
            rejected: false,
        }
    })?;
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    let body = response.text().await.unwrap_or_default();
    Err(Failure {
        message: format!("{status}: {}", truncate(body.trim(), MAX_BODY_IN_MESSAGE)),
        rejected: is_insert && status == reqwest::StatusCode::BAD_REQUEST,
    })
}

/// At most `max_bytes` of `text`, cut on a character boundary.
fn truncate(text: &str, max_bytes: usize) -> &str {
    let mut end = max_bytes.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Where the two statements go. The insert carries its statement as the
/// `query` parameter, since its POST body is the data; the schema statement
/// is the body itself.
#[derive(Clone)]
struct Urls {
    schema: Url,
    insert: Url,
}

impl Urls {
    fn new(url: &Url) -> Self {
        let mut insert = url.clone();
        insert.query_pairs_mut().append_pair("query", INSERT);
        Self {
            schema: url.clone(),
            insert,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use axum::Router;
    use axum::extract::{Query, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::post;

    use super::*;
    use crate::event::SlotClock;

    const FAST: Limits = Limits {
        flush_interval: Duration::from_millis(10),
        max_rows_per_request: 10_000,
        max_pending_rows: 100_000,
        request_timeout: Duration::from_secs(5),
    };

    #[derive(Clone)]
    struct Seen {
        query: String,
        params: HashMap<String, String>,
        authorization: Option<String>,
        body: String,
        ok: bool,
        at: Instant,
    }

    /// A stand-in for ClickHouse's HTTP interface that records every request.
    #[derive(Clone, Default)]
    struct Mock {
        requests: Arc<Mutex<Vec<Seen>>>,
        /// Requests that reached the handler, counted before any delay.
        started: Arc<AtomicU64>,
        /// Fail every request.
        fail: Arc<AtomicBool>,
        /// Fail inserts only, letting the schema statement through.
        fail_inserts: Arc<AtomicBool>,
        /// Fail the schema statement only.
        fail_schema: Arc<AtomicBool>,
        delay_ms: Arc<AtomicU64>,
    }

    impl Mock {
        fn requests(&self) -> Vec<Seen> {
            self.requests.lock().unwrap().clone()
        }

        fn failures(&self) -> usize {
            self.requests().iter().filter(|seen| !seen.ok).count()
        }

        /// The lines of every insert that succeeded, one `Vec` per request.
        fn inserted(&self) -> Vec<Vec<String>> {
            self.requests()
                .into_iter()
                .filter(|seen| seen.ok && seen.query == INSERT)
                .map(|seen| seen.body.lines().map(str::to_owned).collect())
                .collect()
        }
    }

    async fn handle(
        State(mock): State<Mock>,
        Query(params): Query<HashMap<String, String>>,
        headers: HeaderMap,
        body: String,
    ) -> StatusCode {
        mock.started.fetch_add(1, Ordering::SeqCst);
        let delay = mock.delay_ms.load(Ordering::SeqCst);
        if delay > 0 {
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        let query = params.get("query").cloned().unwrap_or_default();
        let authorization = headers
            .get("authorization")
            .map(|value| value.to_str().unwrap().to_owned());
        // A row ClickHouse cannot take: the whole insert is refused.
        let poisoned = query == INSERT && body.contains("\"slot\":666");
        let ok = !poisoned
            && !mock.fail.load(Ordering::SeqCst)
            && !(query == INSERT && mock.fail_inserts.load(Ordering::SeqCst))
            && !(query != INSERT && mock.fail_schema.load(Ordering::SeqCst));
        mock.requests.lock().unwrap().push(Seen {
            query,
            params,
            authorization,
            body,
            ok,
            at: Instant::now(),
        });
        if poisoned {
            StatusCode::BAD_REQUEST
        } else if ok {
            StatusCode::OK
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }

    async fn serve(mock: Mock) -> Url {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route("/", post(handle)).with_state(mock);
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/").parse().unwrap()
    }

    fn start_writer(url: Url, limits: Limits, capacity: usize) -> mpsc::Sender<BlockEvent> {
        let (tx, rx) = mpsc::channel(capacity);
        let config = TelemetryConfig {
            url,
            client_name: "test".into(),
            network_name: "testnet".into(),
            clock: SlotClock::new(0, 12_000),
        };
        tokio::spawn(run(config, rx, limits));
        tx
    }

    fn event(slot: u64) -> BlockEvent {
        BlockEvent {
            stage: "received",
            at: Instant::now(),
            slot,
            block_root: [1; 32],
            source: "gossip",
            verdict: None,
            column_index: None,
        }
    }

    fn slots(lines: &[String]) -> Vec<u64> {
        lines
            .iter()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()["slot"]
                    .as_u64()
                    .unwrap()
            })
            .collect()
    }

    async fn wait_until(what: &str, done: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test]
    async fn creates_the_table_then_inserts_json_each_row() {
        let mock = Mock::default();
        let tx = start_writer(serve(mock.clone()).await, FAST, 64);
        for slot in 0..3 {
            tx.send(event(slot)).await.unwrap();
        }

        wait_until("three rows", || mock.inserted().concat().len() == 3).await;
        let requests = mock.requests();
        assert!(
            requests[0]
                .body
                .starts_with("CREATE TABLE IF NOT EXISTS block_events")
        );
        assert_eq!(requests[1].query, INSERT);
        assert_eq!(slots(&mock.inserted().concat()), [0, 1, 2]);
    }

    #[tokio::test]
    async fn sends_nothing_without_rows() {
        let mock = Mock::default();
        let _tx = start_writer(serve(mock.clone()).await, FAST, 64);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(mock.requests().is_empty());
    }

    #[tokio::test]
    async fn splits_a_backlog_into_bounded_requests() {
        let mock = Mock::default();
        mock.fail.store(true, Ordering::SeqCst);
        let limits = Limits {
            max_rows_per_request: 2,
            ..FAST
        };
        let tx = start_writer(serve(mock.clone()).await, limits, 64);
        for slot in 0..5 {
            tx.send(event(slot)).await.unwrap();
        }
        wait_until("two failed attempts", || mock.failures() >= 2).await;

        mock.fail.store(false, Ordering::SeqCst);
        wait_until("every row", || mock.inserted().concat().len() == 5).await;
        assert!(mock.inserted().iter().all(|request| request.len() <= 2));
        assert_eq!(slots(&mock.inserted().concat()), [0, 1, 2, 3, 4]);
    }

    /// One insert succeeds first, so `needs_schema` is already false when the
    /// next one fails: the retry only recreates the table if the failure
    /// re-armed it.
    #[tokio::test]
    async fn retries_a_failed_insert_and_recreates_the_table_first() {
        let mock = Mock::default();
        let tx = start_writer(serve(mock.clone()).await, FAST, 64);
        tx.send(event(0)).await.unwrap();
        wait_until("the first insert", || mock.inserted().len() == 1).await;

        mock.fail_inserts.store(true, Ordering::SeqCst);
        tx.send(event(1)).await.unwrap();
        wait_until("a failed insert", || mock.failures() >= 1).await;
        mock.fail_inserts.store(false, Ordering::SeqCst);
        wait_until("both rows", || mock.inserted().concat().len() == 2).await;

        let requests = mock.requests();
        let is_schema = |seen: &Seen| {
            seen.body
                .starts_with("CREATE TABLE IF NOT EXISTS block_events")
        };
        let retry = requests
            .iter()
            .rposition(|seen| seen.ok && seen.query == INSERT)
            .unwrap();
        assert!(
            is_schema(&requests[retry - 1]) && requests[retry - 1].ok,
            "after a failed insert the table is recreated before the retry"
        );
        assert_eq!(slots(&mock.inserted().concat()), [0, 1]);
    }

    /// One insert per tick, not one per round trip: ClickHouse writes a part
    /// per insert, so a request per handful of rows would multiply the parts.
    #[tokio::test]
    async fn a_steady_trickle_is_one_insert_per_tick() {
        let mock = Mock::default();
        let limits = Limits {
            flush_interval: Duration::from_millis(200),
            ..FAST
        };
        let tx = start_writer(serve(mock.clone()).await, limits, 64);
        let start = Instant::now();
        for slot in 0..500 {
            tx.send(event(slot)).await.unwrap();
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let ticks = start.elapsed().as_millis() / 200;

        wait_until("every row", || mock.inserted().concat().len() == 500).await;
        let inserts = mock.inserted().len() as u128;
        assert!(inserts <= ticks + 2, "{inserts} inserts over {ticks} ticks");
    }

    /// A tick switched off while there is nothing to send would fire at once
    /// when re-enabled, sending the first row of a burst on its own.
    #[tokio::test]
    async fn a_burst_after_an_idle_spell_goes_out_as_one_insert() {
        let mock = Mock::default();
        let limits = Limits {
            flush_interval: Duration::from_millis(200),
            ..FAST
        };
        let tx = start_writer(serve(mock.clone()).await, limits, 64);
        tx.send(event(0)).await.unwrap();
        wait_until("the first insert", || mock.inserted().len() == 1).await;
        tokio::time::sleep(Duration::from_millis(500)).await;

        for slot in 1..=24 {
            tx.try_send(event(slot)).unwrap();
        }
        wait_until("the burst", || mock.inserted().concat().len() == 25).await;
        assert_eq!(mock.inserted().len(), 2, "the burst went out as one insert");
    }

    #[tokio::test]
    async fn drops_the_oldest_rows_past_the_cap() {
        let mock = Mock::default();
        mock.fail.store(true, Ordering::SeqCst);
        let limits = Limits {
            max_pending_rows: 3,
            ..FAST
        };
        let tx = start_writer(serve(mock.clone()).await, limits, 64);
        for slot in 0..5 {
            tx.send(event(slot)).await.unwrap();
        }
        wait_until("two failed attempts", || mock.failures() >= 2).await;

        mock.fail.store(false, Ordering::SeqCst);
        wait_until("an insert", || !mock.inserted().is_empty()).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(slots(&mock.inserted().concat()), [2, 3, 4]);
    }

    #[tokio::test]
    async fn keeps_reading_the_channel_while_a_request_is_in_flight() {
        let mock = Mock::default();
        mock.delay_ms.store(300, Ordering::SeqCst);
        // Room for four: the sends below only all fit if the writer keeps
        // draining while its request waits.
        let tx = start_writer(serve(mock.clone()).await, FAST, 4);
        tx.send(event(0)).await.unwrap();
        wait_until("a request in flight", || {
            mock.started.load(Ordering::SeqCst) >= 1
        })
        .await;

        for slot in 1..=20 {
            tx.try_send(event(slot))
                .expect("the writer drains the channel while a request is in flight");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }

        mock.delay_ms.store(0, Ordering::SeqCst);
        wait_until("every row", || mock.inserted().concat().len() == 21).await;
    }

    /// A batch ClickHouse refuses as malformed is dropped, not retried: it
    /// would be refused again and hold back every row queued behind it.
    #[tokio::test]
    async fn a_rejected_batch_is_dropped_not_retried() {
        let mock = Mock::default();
        let tx = start_writer(serve(mock.clone()).await, FAST, 64);
        tx.send(event(666)).await.unwrap();
        wait_until("the rejected insert", || mock.failures() >= 1).await;

        tx.send(event(2)).await.unwrap();
        tx.send(event(3)).await.unwrap();
        wait_until("the rows behind it", || mock.inserted().concat().len() == 2).await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(slots(&mock.inserted().concat()), [2, 3]);
        let attempts = mock
            .requests()
            .iter()
            .filter(|seen| seen.query == INSERT && seen.body.contains("\"slot\":666"))
            .count();
        assert_eq!(attempts, 1, "the rejected batch was sent again");
    }

    /// A full request goes out as soon as the previous one lands, without
    /// waiting for the next tick, so a backlog drains at once.
    #[tokio::test]
    async fn a_backlog_drains_without_waiting_for_ticks() {
        let mock = Mock::default();
        mock.fail.store(true, Ordering::SeqCst);
        let limits = Limits {
            flush_interval: Duration::from_millis(500),
            max_rows_per_request: 2,
            ..FAST
        };
        let tx = start_writer(serve(mock.clone()).await, limits, 64);
        for slot in 0..6 {
            tx.send(event(slot)).await.unwrap();
        }
        wait_until("two failed requests", || mock.failures() >= 2).await;

        mock.fail.store(false, Ordering::SeqCst);
        wait_until("every row", || mock.inserted().concat().len() == 6).await;
        let times: Vec<Instant> = mock
            .requests()
            .iter()
            .filter(|seen| seen.ok && seen.query == INSERT)
            .map(|seen| seen.at)
            .collect();
        let span = *times.last().unwrap() - times[0];
        assert!(
            span < limits.flush_interval,
            "the inserts took {span:?}, a tick apart"
        );
        assert_eq!(slots(&mock.inserted().concat()), [0, 1, 2, 3, 4, 5]);
    }

    #[tokio::test]
    async fn credentials_in_the_url_become_basic_auth_percent_decoded() {
        let mock = Mock::default();
        let url = serve(mock.clone()).await;
        let url = url.as_str().replace("http://", "http://user:p%40ss@");
        let tx = start_writer(url.parse().unwrap(), FAST, 64);
        tx.send(event(0)).await.unwrap();

        wait_until("an insert", || !mock.inserted().is_empty()).await;
        let requests = mock.requests();
        assert!(!requests.is_empty());
        for seen in requests {
            // base64 of `user:p@ss`
            assert_eq!(seen.authorization.as_deref(), Some("Basic dXNlcjpwQHNz"));
        }
    }

    #[tokio::test]
    async fn an_existing_query_parameter_survives() {
        let mock = Mock::default();
        let url = serve(mock.clone()).await.join("?database=x").unwrap();
        let tx = start_writer(url, FAST, 64);
        tx.send(event(0)).await.unwrap();

        wait_until("an insert", || !mock.inserted().is_empty()).await;
        let requests = mock.requests();
        let insert = requests
            .iter()
            .find(|seen| seen.query == INSERT)
            .expect("an insert request");
        assert_eq!(insert.params.get("database").map(String::as_str), Some("x"));
        assert_eq!(insert.params.get("query").map(String::as_str), Some(INSERT));
    }

    /// The schema statement is best effort: a user allowed to insert but not
    /// to create must still insert.
    #[tokio::test]
    async fn a_failed_schema_statement_does_not_stop_the_insert() {
        let mock = Mock::default();
        mock.fail_schema.store(true, Ordering::SeqCst);
        let tx = start_writer(serve(mock.clone()).await, FAST, 64);
        tx.send(event(0)).await.unwrap();

        wait_until("the row", || mock.inserted().concat().len() == 1).await;
        assert!(mock.failures() >= 1);
    }

    #[test]
    fn truncation_cuts_on_a_character_boundary() {
        assert_eq!(truncate("abcdef", 3), "abc");
        assert_eq!(truncate("ab", 3), "ab");
        // The second byte of a two-byte character is not a boundary.
        assert_eq!(truncate("aé", 2), "a");
    }
}
