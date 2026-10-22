//! `GET /eth/v1/events`: the Beacon API eventstream.
//!
//! The same stream as the lean surface's `/lean/v0/events` (one SSE frame per
//! [`ChainEvent`], topic on the `event:` line, payload on `data:`; see
//! [`crate::events::sse_response`]). What differs is the request and the
//! payloads:
//!
//! - `topics` is the specification's repeated array parameter
//!   (`?topics=head&topics=block`), and a comma-separated value
//!   (`?topics=head,block`) is split too, as Lighthouse accepts it. Duplicates
//!   collapse. Every name in [`Topic::BEACON`] is accepted, though the node
//!   emits only some of them; see `docs/rpc.md`.
//! - A refusal is the Beacon API error body, `{"code": 400, "message": ...}`.
//! - The payloads are the chain actor's beacon variants, which quote every
//!   integer, so nothing here reshapes an event.
//!
//! Every event comes from the chain actor, the bus's only publisher; this
//! handler only subscribes.
//!
//! [`ChainEvent`]: ethlambda_blockchain::ChainEvent

use axum::{
    Extension, Router,
    extract::Query,
    response::{IntoResponse, Response},
    routing::get,
};
use ethlambda_blockchain::{EventBus, Topic};
use ethlambda_storage::Store;

use super::ApiError;

async fn get_events(
    Extension(events): Extension<EventBus>,
    Query(params): Query<Vec<(String, String)>>,
) -> Response {
    match requested_topics(&params) {
        Ok(topics) => crate::events::sse_response(&events, topics),
        Err(err) => err.into_response(),
    }
}

/// Every topic the query names, in first-mention order, without duplicates.
///
/// Read from the raw pairs rather than a struct: axum's `Query` cannot collect
/// a repeated key into a field. Empty names (`?topics=` or a trailing comma)
/// are skipped, so a query naming nothing else is the missing-parameter
/// error rather than an unknown topic called "".
fn requested_topics(params: &[(String, String)]) -> Result<Vec<Topic>, ApiError> {
    let mut topics = Vec::new();
    let names = params
        .iter()
        .filter(|(key, _)| key == "topics")
        .flat_map(|(_, value)| value.split(','))
        .map(str::trim)
        .filter(|name| !name.is_empty());
    for name in names {
        let topic = Topic::parse_accepted(name, Topic::BEACON)
            .map_err(|err| ApiError::BadRequestDetail(format!("Invalid topic: {}", err.name())))?;
        if !topics.contains(&topic) {
            topics.push(topic);
        }
    }
    if topics.is_empty() {
        return Err(ApiError::BadRequest(
            "missing required query parameter: topics",
        ));
    }
    Ok(topics)
}

pub(crate) fn routes() -> Router<Store> {
    Router::new().route("/eth/v1/events", get(get_events))
}

#[cfg(test)]
mod tests {
    use axum::{
        Extension,
        body::Body,
        http::{Request, StatusCode},
    };
    use ethlambda_blockchain::events::{
        BeaconBlockEvent, BeaconFinalizedCheckpointEvent, BeaconHeadEvent,
    };
    use ethlambda_blockchain::{ChainEvent, EventBus, Topic};
    use ethlambda_types::primitives::H256;
    use futures_util::StreamExt as _;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    use super::*;
    use crate::test_utils::beacon_fixture;

    async fn events_response(events: &EventBus, uri: &str) -> Response {
        let fixture = beacon_fixture(64);
        let app = routes()
            .with_state(fixture.store)
            .layer(Extension(events.clone()));
        app.oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn error_json(response: Response) -> serde_json::Value {
        let body = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    /// Read frames until one carries an `event:` line, skipping comments.
    async fn next_event_frame(response: Response) -> String {
        let mut body = response.into_body().into_data_stream();
        let mut frames = String::new();
        while let Some(chunk) = body.next().await {
            frames.push_str(&String::from_utf8_lossy(&chunk.unwrap()));
            if frames.contains("event:") {
                break;
            }
        }
        frames
    }

    fn head_event(slot: u64) -> ChainEvent {
        ChainEvent::BeaconHead(BeaconHeadEvent {
            slot,
            block: H256::repeat_byte(1),
            state: H256::repeat_byte(2),
            epoch_transition: false,
            previous_duty_dependent_root: H256::repeat_byte(3),
            current_duty_dependent_root: H256::repeat_byte(4),
            execution_optimistic: false,
        })
    }

    fn params(query: &[(&str, &str)]) -> Vec<(String, String)> {
        query
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    #[test]
    fn repeated_and_comma_separated_topics_both_parse_and_duplicates_collapse() {
        let topics = requested_topics(&params(&[
            ("topics", "head"),
            ("topics", "block,chain_reorg"),
            ("topics", "head"),
            ("other", "ignored"),
        ]))
        .unwrap();
        assert_eq!(topics, vec![Topic::Head, Topic::Block, Topic::ChainReorg]);
    }

    #[test]
    fn every_beacon_topic_is_accepted() {
        for topic in Topic::BEACON {
            let parsed = requested_topics(&params(&[("topics", topic.as_str())])).unwrap();
            assert_eq!(parsed, vec![*topic]);
        }
    }

    #[test]
    fn lean_only_topics_are_refused() {
        for name in ["justified_checkpoint", "aggregate"] {
            assert!(
                requested_topics(&params(&[("topics", name)])).is_err(),
                "{name} is a lean extension, not a Beacon API topic"
            );
        }
    }

    #[tokio::test]
    async fn an_unknown_topic_is_a_400_in_the_beacon_error_shape() {
        let response = events_response(
            &EventBus::new(16),
            "/eth/v1/events?topics=head&topics=weather_forecast",
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = error_json(response).await;
        assert_eq!(json["code"], 400);
        assert_eq!(json["message"], "Invalid topic: weather_forecast");
    }

    #[tokio::test]
    async fn a_missing_or_empty_topics_parameter_is_a_400() {
        for uri in [
            "/eth/v1/events",
            "/eth/v1/events?topics=",
            "/eth/v1/events?topics=,",
        ] {
            let response = events_response(&EventBus::new(16), uri).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "uri: {uri}");
            assert_eq!(error_json(response).await["code"], 400, "uri: {uri}");
        }
    }

    /// Accepted though never emitted: the specification lists it, and a
    /// client subscribing to it alongside others must not be turned away.
    #[tokio::test]
    async fn a_topic_the_node_never_emits_is_still_accepted() {
        let response =
            events_response(&EventBus::new(16), "/eth/v1/events?topics=voluntary_exit").await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn the_stream_is_unbuffered_server_sent_events() {
        let response = events_response(&EventBus::new(16), "/eth/v1/events?topics=head").await;
        let headers = response.headers();
        assert_eq!(headers["content-type"], "text/event-stream");
        assert_eq!(headers["x-accel-buffering"], "no");
    }

    #[tokio::test]
    async fn a_head_event_is_framed_with_its_topic_and_quoted_slot() {
        let events = EventBus::new(16);
        // Subscribe (by handling the request) before emitting: `emit` drops
        // events nobody is listening for.
        let response = events_response(&events, "/eth/v1/events?topics=head").await;
        events.emit(head_event(10));

        let frame = next_event_frame(response).await;
        assert!(
            frame.contains("event: head") || frame.contains("event:head"),
            "{frame}"
        );
        assert!(frame.contains("\"slot\":\"10\""), "{frame}");
        assert!(frame.contains("\"epoch_transition\":false"), "{frame}");
        assert!(frame.contains("\"execution_optimistic\":false"), "{frame}");
    }

    #[tokio::test]
    async fn only_the_requested_topics_are_streamed() {
        let events = EventBus::new(16);
        let response = events_response(&events, "/eth/v1/events?topics=finalized_checkpoint").await;
        events.emit(ChainEvent::BeaconBlock(BeaconBlockEvent {
            slot: 1,
            block: H256::ZERO,
            execution_optimistic: false,
        }));
        events.emit(head_event(1));
        events.emit(ChainEvent::BeaconFinalizedCheckpoint(
            BeaconFinalizedCheckpointEvent {
                block: H256::ZERO,
                state: H256::ZERO,
                epoch: 2,
                execution_optimistic: false,
            },
        ));

        let frame = next_event_frame(response).await;
        assert!(frame.contains("finalized_checkpoint"), "{frame}");
        assert!(frame.contains("\"epoch\":\"2\""), "{frame}");
        assert!(
            !frame.contains("event: head") && !frame.contains("event:head"),
            "{frame}"
        );
        assert!(
            !frame.contains("event: block") && !frame.contains("event:block"),
            "{frame}"
        );
    }

    #[tokio::test]
    async fn a_lagging_client_gets_the_dropped_messages_comment() {
        let events = EventBus::new(2);
        let response = events_response(&events, "/eth/v1/events?topics=head").await;
        for slot in 1..=3 {
            events.emit(head_event(slot));
        }

        let mut body = response.into_body().into_data_stream();
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
        assert!(frames.contains(": error - dropped 1 messages"), "{frames}");
    }
}
