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

use std::convert::Infallible;

use axum::{
    Extension, Router,
    response::{Sse, sse::Event},
    routing::get,
};
use ethlambda_blockchain::EventBus;
use ethlambda_storage::Store;
use futures_core::Stream;
use tokio_stream::{
    StreamExt,
    wrappers::{BroadcastStream, errors::BroadcastStreamRecvError},
};

async fn get_events(
    Extension(events): Extension<EventBus>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = BroadcastStream::new(events.subscribe()).filter_map(|res| {
        // A slow client falls behind and the bounded broadcast channel
        // overwrites events it never read; skip past the gap rather than
        // ending the stream. The stream is best-effort by contract: clients
        // re-sync via the blocks endpoints after a gap.
        let ev = match res {
            Ok(ev) => ev,
            Err(BroadcastStreamRecvError::Lagged(skipped)) => {
                tracing::debug!(skipped, "SSE client lagged; dropped chain events");
                return None;
            }
        };
        Some(Ok(Event::default()
            .event(ev.topic().as_str())
            .json_data(&ev)
            .inspect_err(|err| tracing::warn!(%err, "Failed to serialize SSE chain event"))
            .ok()?))
    });
    Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default())
}

pub(crate) fn routes() -> Router<Store> {
    Router::new().route("/lean/v0/events", get(get_events))
}

#[cfg(test)]
mod tests {
    use axum::{Extension, body::Body, http::Request};
    use ethlambda_blockchain::{ChainEvent, EventBus};
    use ethlambda_storage::{Store, backend::InMemoryBackend};
    use std::sync::Arc;
    use tower::ServiceExt;

    use crate::test_utils::create_test_state;

    #[tokio::test]
    async fn events_streams_head_with_flat_payload() {
        let events = EventBus::new(16);
        let store = Store::from_anchor_state(Arc::new(InMemoryBackend::new()), create_test_state());
        let app = crate::test_utils::test_api_router(store).layer(Extension(events.clone()));

        // Issue the request first so the handler subscribes its receiver
        // before we publish — `emit` drops events with no live receivers.
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/lean/v0/events")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        events.emit(ChainEvent::Head {
            slot: 3,
            block: Default::default(),
            state: Default::default(),
        });

        let mut body = resp.into_body().into_data_stream();
        let chunk = tokio_stream::StreamExt::next(&mut body)
            .await
            .unwrap()
            .unwrap();
        let text = String::from_utf8_lossy(&chunk);

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
}
