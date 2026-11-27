// Copyright 2026 Sigma Prime Pty Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use std::{
    collections::{HashSet, VecDeque},
    pin::Pin,
    task::{Context, Poll},
};

use async_channel::{Sender, bounded};
use bytes::Bytes;
use futures::{StreamExt, future::BoxFuture, stream::FuturesUnordered};
use libp2p::{
    PeerId,
    swarm::{
        ConnectionHandler, ConnectionHandlerEvent, ConnectionId,
        handler::{
            ConnectionEvent, DialUpgradeError, FullyNegotiatedInbound, FullyNegotiatedOutbound,
            StreamUpgradeError, SubstreamProtocol,
        },
    },
};

pub use super::substream::PieceSender;
use super::{
    config::Config,
    protocol::{InboundProtocol, OutboundProtocol, proto},
    substream::{Inbound, Outbound},
};

/// Instructions from the behaviour to the handler for managing topic streams.
#[derive(Debug)]
pub enum HandlerIn {
    /// Subscribe to a topic on this connection.
    ///
    /// `sender` is a clone of the sending half of the topic's channel; the
    /// subscription stream delivers its [`TopicEvent`]s on it, and closes
    /// when the channel closes.
    Subscribe {
        topic_id: Vec<u8>,
        sender: Sender<TopicEvent>,
    },
}

/// Events emitted by the handler to the behaviour.
#[derive(Debug)]
pub enum Event {
    /// The remote peer sent a valid subscription.
    /// `sender` queues pieces for the remote on this subscription.
    Subscribed {
        topic_id: Vec<u8>,
        sender: PieceSender,
    },
    /// The remote peer's subscription ended: the remote closed the stream,
    /// an error occurred, the connection closed, or every `sender` was
    /// dropped.
    Unsubscribed { topic_id: Vec<u8> },
    /// The connection closed while one of our subscription streams still
    /// owed the application topic events, at least its
    /// [`TopicEvent::Closed`]. The behaviour drives the delivery, so a full
    /// channel does not hold up the connection's shutdown.
    Undelivered(Delivery),
}

/// The delivery of the topic events a subscription stream still owed the
/// application when its connection closed. Completes once they are all
/// delivered, or the channel closed.
pub struct Delivery(pub(crate) BoxFuture<'static, ()>);

impl std::fmt::Debug for Delivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Delivery").finish_non_exhaustive()
    }
}

impl Future for Delivery {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.as_mut().poll(cx)
    }
}

/// A message on the channel of a topic we subscribed to.
///
/// Each of our subscription streams, one per connection to a peer, delivers
/// an `Opened`, then the pieces the peer sends on the topic, then a
/// `Closed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TopicEvent {
    /// Our subscription stream to a peer was established.
    Opened {
        /// The peer we subscribed to.
        peer_id: PeerId,
        /// The connection the stream is on.
        connection_id: ConnectionId,
    },
    /// A peer sent pieces on the topic.
    Pieces {
        /// The peer that sent the pieces.
        peer_id: PeerId,
        /// The connection the stream is on.
        connection_id: ConnectionId,
        /// The pieces.
        pieces: ObjectPieces,
    },
    /// Our subscription stream to a peer ended: the peer closed it, the
    /// stream failed, or the connection closed. No more pieces arrive on it.
    Closed {
        /// The peer we subscribed to.
        peer_id: PeerId,
        /// The connection the stream was on.
        connection_id: ConnectionId,
    },
}

/// A set of object pieces of one object, exchanged with a peer on a topic.
///
/// The fields are [`Bytes`], so cloning them does not copy their content:
/// what is sent to several peers can be queued for each of them without
/// holding it in memory once per peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectPieces {
    pub object_id: Bytes,
    pub metadata: Option<Bytes>,
    pub pieces: Option<Bytes>,
}

impl From<proto::ObjectPieces> for ObjectPieces {
    fn from(message: proto::ObjectPieces) -> Self {
        Self {
            object_id: message.object_id,
            metadata: message.pieces_metadata,
            pieces: message.pieces,
        }
    }
}

impl From<ObjectPieces> for proto::ObjectPieces {
    fn from(pieces: ObjectPieces) -> Self {
        Self {
            object_id: pieces.object_id,
            pieces_metadata: pieces.metadata,
            pieces: pieces.pieces,
        }
    }
}

/// Connection-level state for the waggle protocol.
///
/// Manages the topic subscription streams on one connection: the receive
/// streams of the topics we subscribed to, and the send streams of the
/// topics the remote peer subscribed to. Each stream is wired directly to a
/// channel handed to the application. Delivers events to the behaviour and
/// enforces the inbound stream limit.
pub struct Handler {
    /// Configuration for limits, queue sizes, and wire sizes.
    config: Config,
    /// The remote peer of the connection.
    peer_id: PeerId,
    /// The connection the handler manages.
    connection_id: ConnectionId,
    /// Negotiates inbound substreams and enforces the inbound stream limit.
    inbound_protocol: InboundProtocol,
    /// The receive streams of the topics we subscribed to on this connection.
    outbound_substreams: FuturesUnordered<Outbound>,
    /// The topics the remote peer subscribed to on this connection.
    inbound_subscriptions: HashSet<Vec<u8>>,
    /// The send streams for the topics the remote peer subscribed to.
    inbound_substreams: FuturesUnordered<Inbound>,
    /// The connection events to deliver to the swarm, drained in `poll`.
    pending_events: VecDeque<ConnectionHandlerEvent<OutboundProtocol, Sender<TopicEvent>, Event>>,
}

impl Handler {
    /// Creates a new `Handler` for the connection `connection_id` to
    /// `peer_id`.
    ///
    /// `config` holds the limits, queue sizes, and wire sizes.
    pub(crate) fn new(config: Config, peer_id: PeerId, connection_id: ConnectionId) -> Self {
        Self {
            inbound_protocol: InboundProtocol::new(
                config.max_protobuf_size(),
                config.max_topic_subscription(),
            ),
            config,
            peer_id,
            connection_id,
            outbound_substreams: FuturesUnordered::new(),
            inbound_subscriptions: HashSet::new(),
            inbound_substreams: FuturesUnordered::new(),
            pending_events: VecDeque::new(),
        }
    }
}

impl ConnectionHandler for Handler {
    type FromBehaviour = HandlerIn;
    type ToBehaviour = Event;
    type InboundProtocol = InboundProtocol;
    type OutboundProtocol = OutboundProtocol;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = Sender<TopicEvent>;

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        SubstreamProtocol::new(self.inbound_protocol.clone(), ())
    }

    fn on_behaviour_event(&mut self, hin: HandlerIn) {
        match hin {
            HandlerIn::Subscribe { topic_id, sender } => {
                self.pending_events
                    .push_back(ConnectionHandlerEvent::OutboundSubstreamRequest {
                        protocol: SubstreamProtocol::new(
                            OutboundProtocol {
                                max_protobuf_size: self.config.max_protobuf_size(),
                                topic_id,
                            },
                            sender,
                        ),
                    });
            }
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ConnectionHandlerEvent<Self::OutboundProtocol, Sender<TopicEvent>, Self::ToBehaviour>>
    {
        // Process the pending events first.
        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(event);
        }

        // Then drive the receive streams of the topics we subscribed to,
        // dropping the ones that completed.
        while let Poll::Ready(Some(())) = self.outbound_substreams.poll_next_unpin(cx) {}

        // Then drive the send streams of the topics the remote subscribed to,
        // dropping the ones that completed.
        if let Poll::Ready(Some(topic_id)) = self.inbound_substreams.poll_next_unpin(cx) {
            self.inbound_subscriptions.remove(&topic_id);
            self.inbound_protocol.stream_closed();
            return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                Event::Unsubscribed { topic_id },
            ));
        }

        Poll::Pending
    }

    fn poll_close(&mut self, _: &mut Context<'_>) -> Poll<Option<Self::ToBehaviour>> {
        // The remote subscriptions end with the connection. Their
        // notifications go behind the pending ones, so every remote
        // subscription is reported before it ends.
        self.inbound_substreams.clear();
        self.pending_events
            .extend(self.inbound_subscriptions.drain().map(|topic_id| {
                ConnectionHandlerEvent::NotifyBehaviour(Event::Unsubscribed { topic_id })
            }));
        // Our subscriptions end with the connection too. The behaviour
        // delivers what their streams still owe the application.
        self.pending_events.extend(
            std::mem::take(&mut self.outbound_substreams)
                .into_iter()
                .filter_map(Outbound::into_delivery)
                .map(|delivery| {
                    ConnectionHandlerEvent::NotifyBehaviour(Event::Undelivered(delivery))
                }),
        );

        while let Some(event) = self.pending_events.pop_front() {
            if let ConnectionHandlerEvent::NotifyBehaviour(event) = event {
                return Poll::Ready(Some(event));
            }
        }
        Poll::Ready(None)
    }

    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<
            Self::InboundProtocol,
            Self::OutboundProtocol,
            Self::InboundOpenInfo,
            Self::OutboundOpenInfo,
        >,
    ) {
        match event {
            ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound {
                protocol: (subscription, framed),
                ..
            }) => {
                if self
                    .config
                    .topic_whitelist
                    .as_ref()
                    .is_some_and(|w| !w.contains(&subscription.topic_id))
                {
                    tracing::debug!("Subscription to non-whitelisted topic rejected");
                    self.inbound_protocol.stream_closed();
                    return;
                }

                if self.inbound_subscriptions.contains(&subscription.topic_id) {
                    tracing::debug!("Subscription to a currently subscribed topic rejected");
                    self.inbound_protocol.stream_closed();
                    return;
                }

                self.inbound_subscriptions
                    .insert(subscription.topic_id.clone());

                // The remote subscribed to this topic: set up the stream we
                // send the topic's pieces on, and hand its sender to the
                // application.
                let (sender, receiver) = bounded(self.config.max_send_queue_limit().get());
                self.inbound_substreams.push(Inbound::new(
                    subscription.topic_id.clone(),
                    receiver,
                    framed,
                ));
                self.pending_events
                    .push_back(ConnectionHandlerEvent::NotifyBehaviour(Event::Subscribed {
                        topic_id: subscription.topic_id,
                        sender,
                    }));
            }
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound {
                protocol: (topic_id, substream),
                info: sender,
            }) => {
                // We subscribed to this topic: forward what we receive on the
                // stream to the topic's channel. If the topic was
                // unsubscribed in the meantime, the channel is closed and the
                // stream closes right away.
                self.outbound_substreams.push(Outbound::new(
                    topic_id,
                    self.peer_id,
                    self.connection_id,
                    substream,
                    sender,
                ));
            }
            ConnectionEvent::DialUpgradeError(DialUpgradeError {
                error: StreamUpgradeError::NegotiationFailed,
                ..
            }) => {
                tracing::debug!("Remote peer does not support waggle on this connection");
            }
            _ => {}
        }
    }
}
