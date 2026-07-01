//! Chain events emitted by the [`crate::BlockChainServer`] actor and streamed
//! to RPC clients over Server-Sent Events (`GET /lean/v0/events`).
//!
//! The flow is strictly one-directional: the actor (the sole writer) publishes
//! events on a [`broadcast`] channel, and the read-only RPC handler subscribes.
//! RPC never writes back into the actor.

use ethlambda_types::primitives::H256;
use serde::Serialize;
use tokio::sync::broadcast;

/// A consensus event broadcast to SSE subscribers.
///
/// Serialized with an external `event`/`data` tag so the JSON payload mirrors
/// the SSE framing (`event: head\ndata: {...}`).
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum ChainEvent {
    /// Fork choice selected a new head.
    Head {
        slot: u64,
        root: H256,
        parent_root: H256,
    },
    /// A block was imported into the store.
    Block { slot: u64, root: H256 },
    /// The finalized checkpoint advanced.
    FinalizedCheckpoint { slot: u64, root: H256 },
}

/// Sender half of the chain-event broadcast channel, owned by the actor.
pub type ChainEventTx = broadcast::Sender<ChainEvent>;

/// Capacity chosen so a briefly-stalled SSE client is dropped (lagged) rather
/// than back-pressuring the actor. Lagged clients re-sync via backfill.
pub const CHAIN_EVENT_CHANNEL_CAPACITY: usize = 256;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn channel_delivers_head_event() {
        let (tx, mut rx) = broadcast::channel::<ChainEvent>(CHAIN_EVENT_CHANNEL_CAPACITY);
        tx.send(ChainEvent::Head {
            slot: 7,
            root: H256::ZERO,
            parent_root: H256::ZERO,
        })
        .unwrap();
        match rx.recv().await.unwrap() {
            ChainEvent::Head { slot, .. } => assert_eq!(slot, 7),
            other => panic!("unexpected: {other:?}"),
        }
    }
}
