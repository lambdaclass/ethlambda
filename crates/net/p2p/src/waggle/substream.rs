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
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, ARISING FROM, OUT OF
// OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use async_channel::{Receiver, Sender, TrySendError};
use asynchronous_codec::Framed;
use futures::{AsyncWriteExt, Sink, Stream, StreamExt, future::BoxFuture};
use libp2p::{PeerId, Stream as Libp2pStream, swarm::ConnectionId};

use super::{
    handler::{Delivery, ObjectPieces, TopicEvent},
    protocol::PieceCodec,
};

/// A per-topic outbound subscription stream.
///
/// Forwards the pieces of one topic read from our subscription stream to the
/// topic's channel, between a [`TopicEvent::Opened`] and a
/// [`TopicEvent::Closed`]. Stops reading while a message waits for room in
/// the channel. Completes once the stream ended and the `Closed` was
/// delivered, or once the channel closed and the stream with it: the
/// application dropped the receiver, unsubscribing from the topic.
pub struct Outbound {
    topic: Vec<u8>,
    /// The remote peer of the stream.
    peer_id: PeerId,
    /// The connection the stream is on.
    connection_id: ConnectionId,
    /// The sending half of the topic's channel.
    sender: Sender<TopicEvent>,
    /// Resolves when the channel closes.
    unsubscribed: BoxFuture<'static, ()>,
    /// The message waiting for room in the channel. Resolves to `false` when
    /// the channel closes.
    delivery: Option<BoxFuture<'static, bool>>,
    state: OutboundState,
}

impl std::fmt::Debug for Outbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outbound")
            .field("topic", &self.topic)
            .field("peer_id", &self.peer_id)
            .field("connection_id", &self.connection_id)
            .field("sender", &self.sender)
            .field("delivering", &self.delivery.is_some())
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl Outbound {
    /// Creates a new `Outbound` stream for a topic.
    ///
    /// `framed` is the negotiated subscription stream to `peer_id` on
    /// `connection_id`. `sender` is a clone of the sending half of the
    /// topic's channel; the stream closes when the channel closes.
    pub(crate) fn new(
        topic: Vec<u8>,
        peer_id: PeerId,
        connection_id: ConnectionId,
        framed: Framed<Libp2pStream, PieceCodec>,
        sender: Sender<TopicEvent>,
    ) -> Self {
        // `Sender::closed` borrows the sender, so the future owns a clone.
        let watched = sender.clone();
        let mut outbound = Self {
            topic,
            peer_id,
            connection_id,
            sender,
            unsubscribed: Box::pin(async move { watched.closed().await }),
            delivery: None,
            state: OutboundState::Active(framed),
        };
        outbound.deliver(TopicEvent::Opened {
            peer_id,
            connection_id,
        });
        outbound
    }

    /// Delivers `event` on the topic's channel, or keeps it until the channel
    /// has room.
    fn deliver(&mut self, event: TopicEvent) {
        match self.sender.try_send(event) {
            Ok(()) => {}
            // Stop reading until the application makes room.
            Err(TrySendError::Full(event)) => {
                let sender = self.sender.clone();
                self.delivery = Some(Box::pin(async move { sender.send(event).await.is_ok() }));
            }
            Err(TrySendError::Closed(_)) => self.unsubscribe(),
        }
    }

    /// The channel closed: the application unsubscribed. Drops the message
    /// waiting for room and closes the stream quietly.
    fn unsubscribe(&mut self) {
        tracing::debug!(topic = ?self.topic, "Receive channel closed");
        self.delivery = None;
        self.close_stream();
    }

    /// The stream ended: closes it and tells the application.
    fn end(&mut self) {
        self.close_stream();
        self.deliver(TopicEvent::Closed {
            peer_id: self.peer_id,
            connection_id: self.connection_id,
        });
    }

    /// Starts closing the stream, unless it is closing already.
    fn close_stream(&mut self) {
        self.state = match std::mem::replace(&mut self.state, OutboundState::Closed) {
            OutboundState::Active(framed) => OutboundState::closing(framed),
            state => state,
        };
    }

    /// Ends the stream with its connection.
    ///
    /// Returns the delivery of the events the application is still owed: the
    /// message waiting for room, and the `Closed` if the stream had not ended
    /// yet.
    pub(crate) fn into_delivery(self) -> Option<Delivery> {
        if self.sender.is_closed() {
            return None;
        }
        let closed = matches!(self.state, OutboundState::Active(_)).then_some(TopicEvent::Closed {
            peer_id: self.peer_id,
            connection_id: self.connection_id,
        });
        let Self {
            sender, delivery, ..
        } = self;
        if delivery.is_none() && closed.is_none() {
            return None;
        }
        Some(Delivery(Box::pin(async move {
            if let Some(delivery) = delivery
                && !delivery.await
            {
                return;
            }
            if let Some(closed) = closed {
                let _ = sender.send(closed).await;
            }
        })))
    }
}

/// State machine for a single outbound topic stream.
pub enum OutboundState {
    /// The stream is open and receiving pieces.
    Active(Framed<Libp2pStream, PieceCodec>),
    /// The stream is being closed.
    Closing(BoxFuture<'static, Result<(), std::io::Error>>),
    /// The stream is closed.
    Closed,
}

impl OutboundState {
    /// Starts closing the stream behind `framed`.
    fn closing(framed: Framed<Libp2pStream, PieceCodec>) -> Self {
        let mut stream = framed.into_inner();
        Self::Closing(Box::pin(async move { stream.close().await }))
    }
}

impl std::fmt::Debug for OutboundState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active(arg0) => f.debug_tuple("Active").field(arg0).finish(),
            Self::Closing(_) => f.debug_tuple("Closing").finish(),
            Self::Closed => f.debug_tuple("Closed").finish(),
        }
    }
}

impl Future for Outbound {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        loop {
            // Deliver the message waiting for room first: nothing is read
            // until it is delivered.
            if let Some(delivery) = &mut this.delivery {
                match delivery.as_mut().poll(cx) {
                    Poll::Ready(true) => this.delivery = None,
                    Poll::Ready(false) => this.unsubscribe(),
                    Poll::Pending => {}
                }
            }

            match &mut this.state {
                OutboundState::Active(framed) => {
                    if this.delivery.is_some() {
                        return Poll::Pending;
                    }

                    // The application dropped the receiver: close the stream
                    // without waiting for the next piece.
                    if this.unsubscribed.as_mut().poll(cx).is_ready() {
                        this.unsubscribe();
                        continue;
                    }

                    match framed.poll_next_unpin(cx) {
                        Poll::Ready(Some(Ok(pieces))) => this.deliver(TopicEvent::Pieces {
                            peer_id: this.peer_id,
                            connection_id: this.connection_id,
                            pieces: pieces.into(),
                        }),
                        Poll::Ready(Some(Err(err))) => {
                            // TODO: Report a protocol violation when data is invalid?
                            tracing::debug!("Failed to decode piece: {err}");
                            this.end();
                        }
                        // The peer closed the stream.
                        Poll::Ready(None) => this.end(),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                OutboundState::Closing(closing) => {
                    let Poll::Ready(result) = closing.as_mut().poll(cx) else {
                        return Poll::Pending;
                    };
                    if let Err(err) = result {
                        tracing::debug!("Error closing outbound stream: {err}");
                    }
                    this.state = OutboundState::Closed;
                }
                // Done once the `Closed` is delivered.
                OutboundState::Closed if this.delivery.is_some() => return Poll::Pending,
                OutboundState::Closed => return Poll::Ready(()),
            }
        }
    }
}

/// Queues object pieces for a remote peer subscribed to a topic.
///
/// Handed to the application for every remote subscription. The pieces are
/// written to the subscription stream the peer opened. Holds up to
/// [`Config::max_send_queue_limit`](super::config::Config::max_send_queue_limit)
/// messages.
pub type PieceSender = Sender<ObjectPieces>;

/// A per-topic inbound stream writer.
///
/// Reads the messages of one topic from its channel and writes them to the
/// subscription stream the remote peer opened for that topic. The future
/// completes with the topic when the remote closes its half of the stream,
/// every sender of the channel is dropped, or a write fails.
pub struct Inbound {
    topic: Vec<u8>,
    receiver: Pin<Box<Receiver<ObjectPieces>>>,
    framed: Pin<Box<Framed<Libp2pStream, PieceCodec>>>,
    state: InboundState,
}

impl Inbound {
    /// Creates a new `Inbound` stream writer for a topic.
    ///
    /// `receiver` is the channel with the messages to send on `topic`.
    /// `framed` is the subscription stream the remote peer opened.
    pub(crate) fn new(
        topic: Vec<u8>,
        receiver: Receiver<ObjectPieces>,
        framed: Framed<Libp2pStream, PieceCodec>,
    ) -> Self {
        Self {
            topic,
            receiver: Box::pin(receiver),
            framed: Box::pin(framed),
            state: InboundState::WaitingMessage,
        }
    }
}

enum InboundState {
    /// Waiting for the next message from the channel.
    WaitingMessage,
    /// A message was received; watching for sink readiness.
    WaitingReady { message: ObjectPieces },
    /// A message was accepted; the sink is flushing it.
    Flushing,
    /// The writer ended.
    Closed,
    /// Temporary state used during state transitions.
    Poisoned,
}

impl Future for Inbound {
    type Output = Vec<u8>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        // The remote sends nothing after subscribing: its half of the stream
        // only ends when it unsubscribes or the stream fails.
        if !matches!(this.state, InboundState::Closed)
            && let Poll::Ready(read) = this.framed.as_mut().poll_next(cx)
        {
            match read {
                None => tracing::debug!(topic = ?this.topic, "Remote closed inbound stream"),
                Some(Ok(_)) => {
                    tracing::debug!(topic = ?this.topic, "Unexpected message on inbound stream")
                }
                Some(Err(err)) => {
                    tracing::debug!(topic = ?this.topic, "Inbound stream error: {err}")
                }
            }
            this.state = InboundState::Closed;
            return Poll::Ready(this.topic.clone());
        }

        loop {
            let state = std::mem::replace(&mut this.state, InboundState::Poisoned);
            match state {
                InboundState::WaitingMessage => match this.receiver.as_mut().poll_next(cx) {
                    Poll::Ready(Some(message)) => {
                        this.state = InboundState::WaitingReady { message };
                    }
                    // The channel is closed and drained: the local side stopped it.
                    Poll::Ready(None) => {
                        tracing::debug!(topic = ?this.topic, "Outbound channel closed");
                        this.state = InboundState::Closed;
                        return Poll::Ready(this.topic.clone());
                    }
                    Poll::Pending => {
                        this.state = InboundState::WaitingMessage;
                        return Poll::Pending;
                    }
                },
                InboundState::WaitingReady { message } => {
                    match Sink::poll_ready(this.framed.as_mut(), cx) {
                        Poll::Ready(Ok(())) => {
                            match Sink::start_send(this.framed.as_mut(), message.into()) {
                                Ok(()) => this.state = InboundState::Flushing,
                                Err(err) => {
                                    tracing::debug!(
                                        topic = ?this.topic,
                                        "Failed to send message on inbound stream: {err}"
                                    );
                                    this.state = InboundState::Closed;
                                    return Poll::Ready(this.topic.clone());
                                }
                            }
                        }
                        Poll::Ready(Err(err)) => {
                            tracing::debug!(topic = ?this.topic, "Inbound stream error: {err}");
                            this.state = InboundState::Closed;
                            return Poll::Ready(this.topic.clone());
                        }
                        Poll::Pending => {
                            this.state = InboundState::WaitingReady { message };
                            return Poll::Pending;
                        }
                    }
                }
                InboundState::Flushing => match Sink::poll_flush(this.framed.as_mut(), cx) {
                    Poll::Ready(Ok(())) => this.state = InboundState::WaitingMessage,
                    Poll::Ready(Err(err)) => {
                        tracing::debug!(
                            topic = ?this.topic,
                            "Failed to flush inbound stream: {err}"
                        );
                        this.state = InboundState::Closed;
                        return Poll::Ready(this.topic.clone());
                    }
                    Poll::Pending => {
                        this.state = InboundState::Flushing;
                        return Poll::Pending;
                    }
                },
                InboundState::Closed => return Poll::Ready(this.topic.clone()),
                InboundState::Poisoned => {
                    panic!("entered poisoned inbound stream state")
                }
            }
        }
    }
}
