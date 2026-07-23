//! Integration test: a fake in-process SSE server stands in for an
//! ethlambda node. A real `collector::run_collector` task dials it and we
//! assert the expected `NormalizedEvent`s land on the [`Hub`].

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::response::sse::{Event as SseEvent, Sse};
use axum::routing::get;
use futures_util::stream::{self, Stream};
use tokio::net::TcpListener;
use tokio::time::timeout;

use event_monitor::collector::run_collector;
use event_monitor::config::NodeConfig;
use event_monitor::hub::{Hub, HubMessage};
use event_monitor::model::NormalizedEvent;
use event_monitor::timing::Timing;

const RECV_TIMEOUT: Duration = Duration::from_secs(5);

/// Serves exactly the two frames the test asserts on: one `block` event and
/// one `attestation` event, using the exact JSON shapes from CONTRACT.md §2.
async fn fake_events_handler() -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let frames = vec![
        Ok(SseEvent::default()
            .event("block")
            .data(r#"{"slot":128,"block":"0xabc123"}"#)),
        Ok(SseEvent::default().event("attestation").data(
            r#"{"validator_id":7,"data":{"slot":128,"head":{"root":"0xh","slot":128},"target":{"root":"0xt","slot":124},"source":{"root":"0xs","slot":120}}}"#,
        )),
    ];
    Sse::new(stream::iter(frames))
}

/// Pulls `HubMessage`s off `rx` until `want` [`NormalizedEvent`]s (ignoring
/// `Status` heartbeats) have been collected, or `RECV_TIMEOUT` elapses.
async fn collect_chain_events(
    rx: &mut tokio::sync::broadcast::Receiver<HubMessage>,
    want: usize,
) -> Vec<NormalizedEvent> {
    let mut collected = Vec::with_capacity(want);
    timeout(RECV_TIMEOUT, async {
        while collected.len() < want {
            match rx.recv().await.expect("hub sender dropped unexpectedly") {
                HubMessage::Chain(event) => collected.push(event),
                HubMessage::Status(_) => continue,
            }
        }
    })
    .await
    .expect("timed out waiting for normalized events on the hub");
    collected
}

#[tokio::test]
async fn collector_normalizes_frames_from_a_live_sse_server() {
    let app = Router::new().route("/lean/v0/events", get(fake_events_handler));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind fake server");
    let addr = listener
        .local_addr()
        .expect("fake server has no local addr");
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("fake SSE server crashed");
    });

    let node = NodeConfig {
        name: "fake-node".to_string(),
        url: format!("http://{addr}"),
    };
    let timing = Arc::new(Timing {
        genesis_time: 0,
        ms_per_slot: 4_000,
        intervals_per_slot: 5,
    });
    let hub = Hub::new(64);
    let mut rx = hub.subscribe();
    let client = reqwest::Client::new();

    let topics = vec![
        "block".to_string(),
        "attestation".to_string(),
        "aggregate".to_string(),
    ];
    let collector_handle = tokio::spawn(run_collector(node, topics, timing, hub.clone(), client));

    let events = collect_chain_events(&mut rx, 2).await;
    collector_handle.abort();

    assert_eq!(events.len(), 2);

    let block_event = &events[0];
    assert_eq!(block_event.node, "fake-node");
    assert_eq!(block_event.topic, "block");
    assert_eq!(block_event.slot, 128);
    assert_eq!(block_event.id, Some("0xabc123".to_string()));
    assert_eq!(block_event.validator_id, None);
    assert_eq!(block_event.participants, None);
    // genesis_time=0, ms_per_slot=4000 => slot_start_ms = 512_000; arrival
    // is "now" (real wall clock), so offset_ms is a large positive number.
    assert!(block_event.offset_ms > 0);

    let attestation_event = &events[1];
    assert_eq!(attestation_event.node, "fake-node");
    assert_eq!(attestation_event.topic, "attestation");
    assert_eq!(attestation_event.slot, 128);
    assert_eq!(attestation_event.id, None);
    assert_eq!(attestation_event.validator_id, Some(7));
    assert_eq!(attestation_event.participants, None);
}

#[tokio::test]
async fn collector_publishes_connected_status_on_success() {
    let app = Router::new().route("/lean/v0/events", get(fake_events_handler));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind fake server");
    let addr = listener
        .local_addr()
        .expect("fake server has no local addr");
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("fake SSE server crashed");
    });

    let node = NodeConfig {
        name: "fake-node-2".to_string(),
        url: format!("http://{addr}"),
    };
    let timing = Arc::new(Timing {
        genesis_time: 0,
        ms_per_slot: 4_000,
        intervals_per_slot: 5,
    });
    let hub = Hub::new(64);
    let mut rx = hub.subscribe();
    let client = reqwest::Client::new();

    let collector_handle = tokio::spawn(run_collector(
        node,
        vec!["block".to_string()],
        timing,
        hub.clone(),
        client,
    ));

    let saw_connected = timeout(RECV_TIMEOUT, async {
        loop {
            if let HubMessage::Status(status) = rx.recv().await.expect("hub sender dropped")
                && status.node == "fake-node-2"
                && matches!(status.state, event_monitor::model::NodeState::Connected)
            {
                return true;
            }
        }
    })
    .await
    .unwrap_or(false);

    collector_handle.abort();
    assert!(saw_connected, "expected a Connected status update");
}
