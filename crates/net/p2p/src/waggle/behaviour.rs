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
// OR IMPLIED, BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use std::{
    collections::{HashMap, VecDeque},
    task::Poll,
};

use async_channel::{Receiver, Sender};
use futures::{StreamExt, future::BoxFuture, stream::FuturesUnordered};
use libp2p::{
    PeerId,
    swarm::{
        ConnectionClosed, ConnectionId, FromSwarm, NetworkBehaviour, NotifyHandler, ToSwarm,
        behaviour::ConnectionEstablished,
    },
};

use super::{
    config::Config,
    handler::{self, Delivery, HandlerIn, PieceSender, TopicEvent},
};

/// Event emitted by the waggle behaviour.
#[derive(Debug)]
pub enum Event {
    /// A remote peer subscribed to a topic.
    ///
    /// Pieces queued on `sender` are written to the peer's subscription
    /// stream on this connection.
    Subscribed {
        /// The remote peer that subscribed.
        peer_id: PeerId,
        /// The connection the peer subscribed on.
        connection_id: ConnectionId,
        /// The topic it subscribed to.
        topic_id: Vec<u8>,
        /// Queues pieces for the peer on this subscription.
        sender: PieceSender,
    },
    /// A remote peer's subscription to a topic ended.
    ///
    /// The peer unsubscribed, the stream failed, the connection closed, or
    /// every clone of the subscription's `sender` was dropped. The `sender`
    /// no longer accepts pieces.
    Unsubscribed {
        /// The remote peer that unsubscribed.
        peer_id: PeerId,
        /// The connection the peer was subscribed on.
        connection_id: ConnectionId,
        /// The topic it unsubscribed from.
        topic_id: Vec<u8>,
    },
}

/// Network behaviour that handles the waggle protocol.
///
/// Manages the topic subscriptions only. The pieces are exchanged on the
/// channels handed to the application by [`Behaviour::subscribe`] and in
/// [`Event::Subscribed`].
pub struct Behaviour {
    /// Behaviour configuration: queue sizes, limits, and whitelist.
    config: Config,
    /// Outbound events to the swarm, drained in `poll`.
    pending_events: VecDeque<ToSwarm<Event, HandlerIn>>,
    /// The remote peer behind each established connection.
    connections: HashMap<ConnectionId, PeerId>,
    /// The topics the local node is subscribed to, with the sending half of
    /// each topic's channel. A topic whose channel closed is unsubscribed,
    /// and forgotten in `poll`.
    subscribed_topics: HashMap<Vec<u8>, Sender<TopicEvent>>,
    /// Resolve with their topic when the application drops a topic's
    /// receiver.
    unsubscriptions: FuturesUnordered<BoxFuture<'static, Vec<u8>>>,
    /// The topic events closed connections still owe the application.
    deliveries: FuturesUnordered<Delivery>,
}

impl Behaviour {
    /// Creates a new waggle [`Behaviour`] instance with the given [`Config`].
    pub fn new(config: Config) -> Self {
        Self {
            config,
            pending_events: VecDeque::new(),
            connections: HashMap::new(),
            subscribed_topics: HashMap::new(),
            unsubscriptions: FuturesUnordered::new(),
            deliveries: FuturesUnordered::new(),
        }
    }

    /// Subscribes to a topic.
    ///
    /// Returns the receiver of the topic's [`TopicEvent`]s: the pieces all
    /// the peers we subscribed to send on the topic, along with the opening
    /// and closing of each peer's subscription stream. The subscription
    /// lasts until the receiver is dropped, which closes the topic's streams
    /// on every connection.
    ///
    /// Returns `None` if the topic is already subscribed.
    pub fn subscribe(&mut self, topic_id: Vec<u8>) -> Option<Receiver<TopicEvent>> {
        if self
            .subscribed_topics
            .get(&topic_id)
            .is_some_and(|sender| !sender.is_closed())
        {
            return None;
        }

        let (sender, receiver) = async_channel::bounded(self.config.max_receive_queue_len().get());
        // Hand every connection a clone of the topic's sender.
        for (connection_id, peer_id) in &self.connections {
            self.pending_events.push_back(ToSwarm::NotifyHandler {
                peer_id: *peer_id,
                handler: NotifyHandler::One(*connection_id),
                event: HandlerIn::Subscribe {
                    topic_id: topic_id.clone(),
                    sender: sender.clone(),
                },
            });
        }

        // `Sender::closed` borrows the sender, so the future owns a clone.
        let watched = sender.clone();
        let watched_topic = topic_id.clone();
        self.unsubscriptions.push(Box::pin(async move {
            watched.closed().await;
            watched_topic
        }));
        self.subscribed_topics.insert(topic_id, sender);
        Some(receiver)
    }

    /// Tracks a newly established connection.
    ///
    /// Subscribes the connection to all the topics we are subscribed to.
    fn on_connection_established(&mut self, connection_id: ConnectionId, peer_id: PeerId) {
        self.connections.insert(connection_id, peer_id);

        for (topic_id, sender) in &self.subscribed_topics {
            // The application unsubscribed, but `poll` has not forgotten the
            // topic yet.
            if sender.is_closed() {
                continue;
            }
            self.pending_events.push_back(ToSwarm::NotifyHandler {
                peer_id,
                handler: NotifyHandler::One(connection_id),
                event: HandlerIn::Subscribe {
                    topic_id: topic_id.clone(),
                    sender: sender.clone(),
                },
            });
        }
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = handler::Handler;

    type ToSwarm = Event;

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer_id: PeerId,
        _local_addr: &libp2p::Multiaddr,
        _remote_addr: &libp2p::Multiaddr,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        Ok(handler::Handler::new(
            self.config.clone(),
            peer_id,
            connection_id,
        ))
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer_id: PeerId,
        _addr: &libp2p::Multiaddr,
        _role_override: libp2p::core::Endpoint,
        _port_use: libp2p::core::transport::PortUse,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        Ok(handler::Handler::new(
            self.config.clone(),
            peer_id,
            connection_id,
        ))
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            // Track connections here rather than when creating the handler:
            // another behaviour may still deny the connection, which the
            // swarm then reports as a dial or listen failure instead.
            FromSwarm::ConnectionEstablished(ConnectionEstablished {
                peer_id,
                connection_id,
                ..
            }) => self.on_connection_established(connection_id, peer_id),
            FromSwarm::ConnectionClosed(ConnectionClosed { connection_id, .. }) => {
                self.connections.remove(&connection_id);
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: libp2p::PeerId,
        connection_id: libp2p::swarm::ConnectionId,
        event: libp2p::swarm::THandlerOutEvent<Self>,
    ) {
        let event = match event {
            handler::Event::Subscribed { topic_id, sender } => Event::Subscribed {
                peer_id,
                connection_id,
                topic_id,
                sender,
            },
            handler::Event::Unsubscribed { topic_id } => Event::Unsubscribed {
                peer_id,
                connection_id,
                topic_id,
            },
            handler::Event::Undelivered(delivery) => {
                self.deliveries.push(delivery);
                return;
            }
        };
        self.pending_events.push_back(ToSwarm::GenerateEvent(event));
    }

    fn poll(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, libp2p::swarm::THandlerInEvent<Self>>> {
        // Forget the topics the application unsubscribed from, unless it
        // subscribed again since.
        while let Poll::Ready(Some(topic_id)) = self.unsubscriptions.poll_next_unpin(cx) {
            if self
                .subscribed_topics
                .get(&topic_id)
                .is_some_and(Sender::is_closed)
            {
                self.subscribed_topics.remove(&topic_id);
            }
        }

        // Drive the deliveries of closed connections, dropping the ones that
        // completed.
        while let Poll::Ready(Some(())) = self.deliveries.poll_next_unpin(cx) {}

        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(event);
        }

        std::task::Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use std::task::{Context, Waker};

    use libp2p::Multiaddr;

    use super::*;

    const TOPIC: &[u8] = b"topic";

    fn poll(behaviour: &mut Behaviour) -> Poll<ToSwarm<Event, HandlerIn>> {
        behaviour.poll(&mut Context::from_waker(Waker::noop()))
    }

    #[test]
    fn dropping_receiver_unsubscribes() {
        let mut behaviour = Behaviour::new(Config::default());
        let receiver = behaviour.subscribe(TOPIC.to_vec()).unwrap();
        assert!(behaviour.subscribe(TOPIC.to_vec()).is_none());

        drop(receiver);
        assert!(poll(&mut behaviour).is_pending());
        assert!(behaviour.subscribed_topics.is_empty());
        assert!(behaviour.subscribe(TOPIC.to_vec()).is_some());
    }

    #[test]
    fn subscribing_again_before_poll() {
        let mut behaviour = Behaviour::new(Config::default());
        drop(behaviour.subscribe(TOPIC.to_vec()).unwrap());
        let _receiver = behaviour.subscribe(TOPIC.to_vec()).unwrap();

        // The dropped receiver does not end the new subscription.
        assert!(poll(&mut behaviour).is_pending());
        assert!(behaviour.subscribe(TOPIC.to_vec()).is_none());
    }

    #[test]
    fn dropped_subscription_is_not_sent_to_new_connections() {
        let mut behaviour = Behaviour::new(Config::default());
        drop(behaviour.subscribe(TOPIC.to_vec()).unwrap());

        // The connection is established before `poll` forgets the topic.
        behaviour.on_connection_established(ConnectionId::new_unchecked(0), PeerId::random());
        assert!(poll(&mut behaviour).is_pending());
    }

    #[test]
    fn denied_connection_is_not_tracked() {
        let mut behaviour = Behaviour::new(Config::default());
        // Another behaviour denies the connection after this one created its
        // handler, so the swarm never reports it as established.
        let addr = Multiaddr::empty();
        behaviour
            .handle_established_inbound_connection(
                ConnectionId::new_unchecked(0),
                PeerId::random(),
                &addr,
                &addr,
            )
            .unwrap();

        // No subscription is sent to the denied connection.
        let _receiver = behaviour.subscribe(TOPIC.to_vec()).unwrap();
        assert!(poll(&mut behaviour).is_pending());
    }
}
