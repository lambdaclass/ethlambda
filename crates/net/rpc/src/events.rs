//! `GET /lean/v0/events` — Server-Sent Events stream of chain events.
//!
//! The [`ethlambda_blockchain::BlockChainServer`] actor publishes
//! [`ethlambda_blockchain::ChainEvent`]s on the [`EventBus`]; this read-only
//! handler subscribes a new receiver per connection and forwards each event as
//! one SSE frame. The flow is strictly one-directional (actor → bus → SSE), so
//! RPC never writes into the actor.
//!
//! Framing: the topic name goes on the SSE `event:` line
//! ([`ethlambda_blockchain::ChainEvent::topic`]) and the `data:` line carries
//! the event's flat JSON payload; the topic is never repeated inside the body.
//!
//! Filtering: `?topics=head,block` (comma-separated [`Topic`] names) selects
//! which events to stream. `topics` is required (matching the Beacon API): a
//! missing, empty, or unknown value is a 400.

use std::{convert::Infallible, str::FromStr};

use axum::{
    Extension, Router,
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Response, Sse, sse::Event},
    routing::get,
};
use ethlambda_blockchain::{ChainEvent, EventBus, Topic};
use ethlambda_storage::Store;
use futures_util::{Stream, stream::unfold};
use serde::Deserialize;
use tokio::sync::broadcast::{self, error::RecvError};

#[derive(Deserialize)]
struct EventsParams {
    topics: Option<String>,
}

async fn get_events(
    Extension(events): Extension<EventBus>,
    Query(params): Query<EventsParams>,
) -> Response {
    // `topics` is required, matching the Beacon API: a missing or empty value
    // is a 400, as is any unknown topic name. See docs/rpc.md.
    //
    // The parsed selection lives here, in the sole consumer that filters, not
    // in the bus: a plain `Vec` since there are only a handful of topics.
    let topics: Vec<Topic> = match params.topics.as_deref() {
        None | Some("") => {
            return (
                StatusCode::BAD_REQUEST,
                "missing required query parameter: topics",
            )
                .into_response();
        }
        Some(list) => match list.split(',').map(Topic::from_str).collect() {
            Ok(topics) => topics,
            Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
        },
    };

    Sse::new(event_stream(events.subscribe(), topics))
        .keep_alive(axum::response::sse::KeepAlive::default())
        .into_response()
}

/// Bridge the receiver's `recv` loop into a stream of SSE frames, dropping
/// events the client's `topics` filter excludes.
fn event_stream(
    rx: broadcast::Receiver<ChainEvent>,
    topics: Vec<Topic>,
) -> impl Stream<Item = Result<Event, Infallible>> {
    unfold((rx, topics), |(mut rx, topics)| async move {
        loop {
            match rx.recv().await {
                // Not in the client's `?topics=` set: skip without a frame.
                Ok(ev) if !topics.contains(&ev.topic()) => continue,
                Ok(ev) => {
                    let frame = Event::default()
                        .event(ev.topic().as_str())
                        .json_data(&ev)
                        .inspect_err(
                            |err| tracing::warn!(%err, "Failed to serialize SSE chain event"),
                        );
                    // A frame that fails to serialize is skipped, not fatal.
                    if let Ok(frame) = frame {
                        return Some((Ok(frame), (rx, topics)));
                    }
                }
                // A slow client falls behind and the bounded broadcast channel
                // overwrites events it never read; skip past the gap rather
                // than ending the stream. The stream is best-effort by
                // contract: clients re-sync via the blocks endpoints.
                //
                // The comment frame below is wire-compatible with
                // Lighthouse's lagged-client marker
                // (`beacon_node/http_api/src/lib.rs:3298-3302`): same text,
                // same `Event::comment` mechanism. Comment lines are invisible
                // to browser `EventSource` consumers (only raw-stream readers
                // see them), so this is a best-effort signal, not a guarantee.
                Err(RecvError::Lagged(skipped)) => {
                    tracing::debug!(skipped, "SSE client lagged; dropped chain events");
                    let frame =
                        Event::default().comment(format!("error - dropped {skipped} messages"));
                    return Some((Ok(frame), (rx, topics)));
                }
                // Publisher dropped: the node is shutting down.
                Err(RecvError::Closed) => return None,
            }
        }
    })
}

pub(crate) fn routes() -> Router<Store> {
    Router::new().route("/lean/v0/events", get(get_events))
}

#[cfg(test)]
mod tests {
    use axum::{
        Extension,
        body::Body,
        http::{Request, StatusCode},
    };
    use ethlambda_blockchain::{ChainEvent, EventBus};
    use ethlambda_storage::{Store, backend::InMemoryBackend};
    use futures_util::StreamExt;
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    use crate::test_utils::create_test_state;

    async fn events_response(events: &EventBus, uri: &str) -> axum::response::Response {
        let store = Store::from_anchor_state(Arc::new(InMemoryBackend::new()), create_test_state());
        let app = crate::test_utils::test_api_router(store).layer(Extension(events.clone()));
        app.oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn first_frame(resp: axum::response::Response) -> String {
        let mut body = resp.into_body().into_data_stream();
        let chunk = body.next().await.unwrap().unwrap();
        String::from_utf8_lossy(&chunk).into_owned()
    }

    #[tokio::test]
    async fn events_streams_head_with_flat_payload() {
        let events = EventBus::new(16);

        // Issue the request first so the handler subscribes its receiver
        // before we publish — `emit` drops events with no live receivers.
        let resp = events_response(&events, "/lean/v0/events?topics=head").await;
        assert_eq!(resp.status(), StatusCode::OK);

        events.emit(ChainEvent::Head {
            slot: 3,
            block: Default::default(),
            state: Default::default(),
        });

        let text = first_frame(resp).await;

        // Topic on the `event:` line...
        assert!(
            text.contains("event:head") || text.contains("event: head"),
            "missing head event name in frame: {text}"
        );
        // ...and a flat payload: the variant's own fields (`slot`, `block`,
        // `state`) at the top level, `slot` as a plain number, with no
        // `event`/`data` wrapper keys inside the JSON body (the #460
        // double-tag bug).
        assert!(
            text.contains("\"slot\":3"),
            "missing top-level slot in frame: {text}"
        );
        assert!(
            text.contains("\"block\":") && text.contains("\"state\":"),
            "missing beacon-aligned block/state fields in frame: {text}"
        );
        assert!(
            !text.contains("\"data\":") && !text.contains("\"event\":"),
            "payload is not flat: {text}"
        );
    }

    #[tokio::test]
    async fn events_topics_filter_skips_unmatched() {
        let events = EventBus::new(16);

        let resp = events_response(&events, "/lean/v0/events?topics=head").await;
        assert_eq!(resp.status(), StatusCode::OK);

        // The block event lands first but is filtered out server-side, so the
        // first frame on the wire must be the head event.
        events.emit(ChainEvent::Block {
            slot: 1,
            block: Default::default(),
        });
        events.emit(ChainEvent::Head {
            slot: 2,
            block: Default::default(),
            state: Default::default(),
        });

        let text = first_frame(resp).await;
        assert!(
            text.contains("event:head") || text.contains("event: head"),
            "missing head event name in frame: {text}"
        );
        // Check the SSE `event:` topic line, not the body: every event now
        // carries a `block` *field*, so a substring check for "block" would
        // false-positive on the head payload itself.
        assert!(
            !text.contains("event:block") && !text.contains("event: block"),
            "filtered block event leaked into the stream: {text}"
        );
    }

    #[tokio::test]
    async fn events_lagged_subscriber_gets_dropped_comment() {
        // Capacity 2: emitting 3 events before anything is read forces the
        // broadcast channel to overwrite the oldest one, so the subscriber's
        // next recv() reports RecvError::Lagged(1).
        let events = EventBus::new(2);

        let resp = events_response(&events, "/lean/v0/events?topics=head").await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Emit before polling the body: the handler already subscribed while
        // handling the request above, so these land in the channel unread.
        for slot in 1..=3 {
            events.emit(ChainEvent::Head {
                slot,
                block: Default::default(),
                state: Default::default(),
            });
        }

        // The lag comment should appear among the first frames, ahead of (or
        // interleaved with) the surviving head events.
        let mut body = resp.into_body().into_data_stream();
        let mut frames = String::new();
        for _ in 0..4 {
            let Some(chunk) = body.next().await else {
                break;
            };
            frames.push_str(&String::from_utf8_lossy(&chunk.unwrap()));
            if frames.contains("error - dropped") {
                break;
            }
        }
        assert!(
            frames.contains(": error - dropped 1 messages"),
            "missing lagged-client comment frame: {frames}"
        );
    }

    #[tokio::test]
    async fn events_unknown_topic_returns_400() {
        let events = EventBus::new(16);

        let resp = events_response(&events, "/lean/v0/events?topics=head,bogus").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.contains("unknown topic: 'bogus'"),
            "unhelpful 400 body: {text}"
        );
    }

    #[tokio::test]
    async fn events_missing_or_empty_topics_returns_400() {
        let events = EventBus::new(16);

        // `topics` is required (Beacon-API-aligned): a fully absent parameter
        // and a present-but-empty one are both rejected, never defaulted.
        for uri in ["/lean/v0/events", "/lean/v0/events?topics="] {
            let resp = events_response(&events, uri).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "uri: {uri}");
        }
    }
}
