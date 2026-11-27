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

use std::{collections::HashSet, num::NonZeroUsize, sync::Arc};

/// Configuration for a Waggle protocol instance.
#[derive(Debug, Clone)]
pub struct Config {
    max_send_queue_limit: NonZeroUsize,
    max_receive_queue_len: NonZeroUsize,
    max_topic_subscription: usize,
    max_protobuf_size: usize,
    pub(crate) topic_whitelist: Option<Arc<HashSet<Vec<u8>>>>,
}

impl Config {
    /// The maximum number of messages queued for sending to one peer on one
    /// topic.
    ///
    /// When the queue is full, the topic's
    /// [`PieceSender`](super::handler::PieceSender) rejects further messages
    /// with [`TrySendError::Full`](async_channel::TrySendError::Full).
    ///
    /// Defaults to 100.
    pub fn max_send_queue_limit(&self) -> NonZeroUsize {
        self.max_send_queue_limit
    }

    /// Sets the maximum number of messages queued for sending to one peer on
    /// one topic.
    pub fn set_max_send_queue_limit(mut self, len: NonZeroUsize) -> Self {
        self.max_send_queue_limit = len;
        self
    }

    /// The maximum number of received messages buffered for the application
    /// on one subscribed topic.
    ///
    /// The buffer is shared by all the peers we subscribed to on the topic.
    /// When it is full, reading from them pauses until the application
    /// drains the receiver.
    ///
    /// Defaults to 100.
    pub fn max_receive_queue_len(&self) -> NonZeroUsize {
        self.max_receive_queue_len
    }

    /// Sets the maximum number of received messages buffered for the
    /// application on one subscribed topic.
    pub fn set_max_receive_queue_len(mut self, len: NonZeroUsize) -> Self {
        self.max_receive_queue_len = len;
        self
    }

    /// The maximum number of topics a single peer may subscribe to.
    ///
    /// Defaults to 50.
    pub fn max_topic_subscription(&self) -> usize {
        self.max_topic_subscription
    }

    /// Sets the maximum number of topics a single peer may subscribe to.
    pub fn set_max_topic_subscription(mut self, value: usize) -> Self {
        self.max_topic_subscription = value;
        self
    }

    /// The maximum size in bytes of a single protobuf message on the wire.
    ///
    /// Defaults to 65536 (64 KB).
    pub fn max_protobuf_size(&self) -> usize {
        self.max_protobuf_size
    }

    /// Sets the maximum size in bytes of a single protobuf message on the wire.
    pub fn set_max_protobuf_size(mut self, value: usize) -> Self {
        self.max_protobuf_size = value;
        self
    }

    /// The topic subscription whitelist.
    ///
    /// When it is `None`, all topic subscriptions are accepted.
    pub fn topic_whitelist(&self) -> Option<&HashSet<Vec<u8>>> {
        self.topic_whitelist.as_deref()
    }

    /// Sets the topic subscription whitelist.
    pub fn set_topic_whitelist(mut self, whitelist: Option<HashSet<Vec<u8>>>) -> Self {
        self.topic_whitelist = whitelist.map(Arc::new);
        self
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_send_queue_limit: NonZeroUsize::new(100).expect("100 is non-zero"),
            max_receive_queue_len: NonZeroUsize::new(100).expect("100 is non-zero"),
            max_topic_subscription: 50,
            topic_whitelist: None,
            max_protobuf_size: 65536,
        }
    }
}
