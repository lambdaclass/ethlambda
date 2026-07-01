//! `GET /lean/v0/events` — Server-Sent Events stream of chain events.
//!
//! The [`ethlambda_blockchain::BlockChainServer`] actor publishes
//! [`ChainEvent`]s on a broadcast channel; this read-only handler subscribes a
//! new receiver per connection and forwards each event as an SSE message. The
//! flow is strictly one-directional (actor → broadcast → SSE), so RPC never
//! writes into the actor.

use std::convert::Infallible;

use axum::{
    Extension, Router,
    response::{Sse, sse::Event},
    routing::get,
};
use ethlambda_blockchain::ChainEvent;
use ethlambda_storage::Store;
use futures_core::Stream;
use tokio::sync::broadcast;
use tokio_stream::{
    StreamExt,
    wrappers::{BroadcastStream, errors::BroadcastStreamRecvError},
};

async fn get_events(
    Extension(tx): Extension<broadcast::Sender<ChainEvent>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = BroadcastStream::new(tx.subscribe()).filter_map(|res| {
        // A slow client falls behind and the broadcast channel overwrites
        // events it never read. Surface that rather than silently dropping.
        let ev = match res {
            Ok(ev) => ev,
            Err(BroadcastStreamRecvError::Lagged(skipped)) => {
                tracing::debug!(skipped, "SSE client lagged; dropped chain events");
                return None;
            }
        };
        let name = match &ev {
            ChainEvent::Head { .. } => "head",
            ChainEvent::Block { .. } => "block",
            ChainEvent::FinalizedCheckpoint { .. } => "finalized_checkpoint",
        };
        Some(Ok(Event::default()
            .event(name)
            .json_data(ev)
            .inspect_err(|err| tracing::warn!(%err, "failed to serialize SSE chain event"))
            .ok()?))
    });
    Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default())
}

pub(crate) fn routes() -> Router<Store> {
    Router::new().route("/lean/v0/events", get(get_events))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use ethlambda_storage::{Store, backend::InMemoryBackend};
    use std::sync::Arc;
    use tower::ServiceExt;

    use crate::test_utils::create_test_state;

    #[tokio::test]
    async fn events_streams_head() {
        let (tx, _) = broadcast::channel::<ChainEvent>(16);
        let store = Store::from_anchor_state(Arc::new(InMemoryBackend::new()), create_test_state());
        let app = crate::build_api_router(store).layer(Extension(tx.clone()));

        // Issue the request first so the handler subscribes its receiver before
        // we publish — `broadcast::send` errors if there are no live receivers.
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

        tx.send(ChainEvent::Head {
            slot: 3,
            root: Default::default(),
            parent_root: Default::default(),
        })
        .unwrap();

        let mut body = resp.into_body().into_data_stream();
        let chunk = tokio_stream::StreamExt::next(&mut body)
            .await
            .unwrap()
            .unwrap();
        let text = String::from_utf8_lossy(&chunk);
        assert!(text.contains("event:head") || text.contains("event: head"));
    }
}
