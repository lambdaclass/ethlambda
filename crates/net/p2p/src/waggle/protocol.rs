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

/// Include protobuf generated wire-format types.
pub(crate) mod proto {
    #![allow(unreachable_pub, dead_code)]
    include!("waggle.pb.rs");
}

use super::codec::{Codec, Error as CodecError};

use std::iter;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use asynchronous_codec::{Decoder, Encoder, Framed};
use bytes::BytesMut;
use futures::future::BoxFuture;
use futures::{FutureExt, SinkExt, StreamExt};
use libp2p::StreamProtocol;
use libp2p::core::upgrade::{InboundUpgrade, OutboundUpgrade, UpgradeInfo};
use libp2p::futures::{AsyncRead, AsyncWrite};

use proto::TopicSubscription;

const WAGGLE_PROTOCL: &str = "/waggle/1.0";

/// Protocol upgrade. On negotiation, creates a framed
/// substream for encoding and decoding protobuf messages.
#[derive(Debug, Clone)]
pub struct InboundProtocol {
    max_protobuf_size: usize,
    max_open_streams: usize,
    current_open_streams: Arc<AtomicUsize>,
}

impl InboundProtocol {
    pub(crate) fn new(max_protobuf_size: usize, max_open_streams: usize) -> Self {
        Self {
            max_protobuf_size,
            max_open_streams,
            current_open_streams: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(crate) fn stream_closed(&mut self) {
        self.current_open_streams.fetch_sub(1, Ordering::SeqCst);
    }
}

impl UpgradeInfo for InboundProtocol {
    type Info = StreamProtocol;
    type InfoIter = iter::Once<StreamProtocol>;

    fn protocol_info(&self) -> Self::InfoIter {
        iter::once(StreamProtocol::new(WAGGLE_PROTOCL))
    }
}

impl<C> InboundUpgrade<C> for InboundProtocol
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = (TopicSubscription, Framed<C, PieceCodec>);
    type Error = Error;
    type Future = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn upgrade_inbound(self, stream: C, _: Self::Info) -> Self::Future {
        let current_open_streams = self.current_open_streams.clone();
        let max_open_streams = self.max_open_streams;
        async move {
            let mut framed = Framed::new(stream, SubscriptionCodec::new(self.max_protobuf_size));
            let subscription = framed.next().await.ok_or(Error::ClosedStream)??;
            let parts = framed.into_parts().map_codec(Into::into);
            let framed = Framed::from_parts(parts);
            current_open_streams
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |cur| {
                    (cur < max_open_streams).then_some(cur + 1)
                })
                .map_err(|_| Error::MaxStreamsReached)?;
            Ok((subscription, framed))
        }
        .boxed()
    }
}

#[derive(Debug)]
pub struct OutboundProtocol {
    pub(crate) max_protobuf_size: usize,
    pub(crate) topic_id: Vec<u8>,
}

impl UpgradeInfo for OutboundProtocol {
    type Info = StreamProtocol;
    type InfoIter = iter::Once<StreamProtocol>;

    fn protocol_info(&self) -> Self::InfoIter {
        iter::once(StreamProtocol::new(WAGGLE_PROTOCL))
    }
}

impl<C> OutboundUpgrade<C> for OutboundProtocol
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = (Vec<u8>, Framed<C, PieceCodec>);
    type Error = CodecError;
    type Future = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn upgrade_outbound(self, stream: C, _: Self::Info) -> Self::Future {
        async move {
            let subscription = proto::TopicSubscription {
                topic_id: self.topic_id.clone(),
            };
            let mut framed = Framed::new(stream, SubscriptionCodec::new(self.max_protobuf_size));
            framed.send(subscription).await?;

            let parts = framed.into_parts().map_codec(Into::into);
            let framed = Framed::from_parts(parts);
            Ok((self.topic_id, framed))
        }
        .boxed()
    }
}

/// Codec for the initial [`proto::TopicSubscription`] message on a waggle substream.
#[derive(Debug)]
pub struct SubscriptionCodec {
    inner: Codec<proto::TopicSubscription>,
    max_protobuf_size: usize,
}

impl SubscriptionCodec {
    /// Creates a new `SubscriptionCodec` with the given maximum protobuf message size.
    pub fn new(max_protobuf_size: usize) -> Self {
        Self {
            inner: Codec::new(max_protobuf_size),
            max_protobuf_size,
        }
    }
}

impl Encoder for SubscriptionCodec {
    type Item<'a> = proto::TopicSubscription;
    type Error = CodecError;
    fn encode(&mut self, item: Self::Item<'_>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.inner.encode(item, dst)
    }
}
impl Decoder for SubscriptionCodec {
    type Item = proto::TopicSubscription;
    type Error = CodecError;
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.inner.decode(src)
    }
}

/// Codec for [`proto::ObjectPieces`] messages on an established waggle substream.
#[derive(Debug)]
pub struct PieceCodec {
    inner: Codec<proto::ObjectPieces>,
}

impl From<SubscriptionCodec> for PieceCodec {
    fn from(sub: SubscriptionCodec) -> Self {
        Self {
            inner: Codec::new(sub.max_protobuf_size),
        }
    }
}

impl Encoder for PieceCodec {
    type Item<'a> = proto::ObjectPieces;
    type Error = CodecError;
    fn encode(&mut self, item: Self::Item<'_>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.inner.encode(item, dst)
    }
}

impl Decoder for PieceCodec {
    type Item = proto::ObjectPieces;
    type Error = CodecError;
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.inner.decode(src)
    }
}

#[derive(Debug, thiserror::Error)]
/// Errors from negotiating waggle subscription streams.
pub enum Error {
    #[error("maximum number of open streams reached")]
    MaxStreamsReached,
    #[error("Remote peer closed the stream before subscribing")]
    ClosedStream,
    #[error("Received an invalid topic subscription message: {0}")]
    InvalidSubscription(#[from] CodecError),
}
