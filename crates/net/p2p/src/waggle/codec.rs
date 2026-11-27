//! A protobuf message framed by its unsigned-varint length, as
//! `prost-codec` (and rust-libp2p's other protobuf protocols) frame them.

use std::marker::PhantomData;

use asynchronous_codec::{Decoder, Encoder};
use bytes::{Buf, BufMut, BytesMut};

/// The longest unsigned varint a `u64` length takes.
const MAX_VARINT_LEN: usize = 10;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("message of {len} bytes exceeds the limit of {max}")]
    TooLarge { len: usize, max: usize },
    #[error("malformed length prefix")]
    BadLength,
    #[error("protobuf decode: {0}")]
    Decode(#[from] prost::DecodeError),
}

/// Frames messages of type `M`, refusing any longer than `max_len` bytes.
#[derive(Debug)]
pub struct Codec<M> {
    max_len: usize,
    message: PhantomData<M>,
}

impl<M> Codec<M> {
    pub fn new(max_len: usize) -> Self {
        Self {
            max_len,
            message: PhantomData,
        }
    }
}

impl<M: prost::Message> Encoder for Codec<M> {
    type Item<'a> = M;
    type Error = Error;

    fn encode(&mut self, item: M, dst: &mut BytesMut) -> Result<(), Error> {
        let len = item.encoded_len();
        if len > self.max_len {
            return Err(Error::TooLarge {
                len,
                max: self.max_len,
            });
        }
        let mut prefix = unsigned_varint::encode::usize_buffer();
        let prefix = unsigned_varint::encode::usize(len, &mut prefix);
        dst.reserve(prefix.len() + len);
        dst.put_slice(prefix);
        item.encode(dst)
            .expect("the buffer was reserved for the whole message");
        Ok(())
    }
}

impl<M: prost::Message + Default> Decoder for Codec<M> {
    type Item = M;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<M>, Error> {
        let (len, rest) = match unsigned_varint::decode::usize(src) {
            Ok(decoded) => decoded,
            Err(unsigned_varint::decode::Error::Insufficient) if src.len() < MAX_VARINT_LEN => {
                return Ok(None);
            }
            Err(_) => return Err(Error::BadLength),
        };
        if len > self.max_len {
            return Err(Error::TooLarge {
                len,
                max: self.max_len,
            });
        }
        let prefix_len = src.len() - rest.len();
        if rest.len() < len {
            src.reserve(prefix_len + len - src.len());
            return Ok(None);
        }
        src.advance(prefix_len);
        let message = src.split_to(len).freeze();
        Ok(Some(M::decode(message)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waggle::protocol::proto::{ObjectPieces, TopicSubscription};

    #[test]
    fn a_message_round_trips_split_at_every_byte() {
        let message = ObjectPieces {
            object_id: vec![7; 48].into(),
            pieces_metadata: Some(vec![1; 16].into()),
            pieces: Some(vec![9; 300].into()),
        };
        let mut encoded = BytesMut::new();
        Codec::<ObjectPieces>::new(1024)
            .encode(message.clone(), &mut encoded)
            .unwrap();

        // Fed byte by byte, nothing decodes until the last one arrives.
        let mut codec = Codec::<ObjectPieces>::new(1024);
        let mut src = BytesMut::new();
        for (i, byte) in encoded.iter().enumerate() {
            src.put_u8(*byte);
            let decoded = codec.decode(&mut src).unwrap();
            assert_eq!(decoded.is_some(), i == encoded.len() - 1);
            if let Some(decoded) = decoded {
                assert_eq!(decoded, message);
                assert!(src.is_empty());
            }
        }
    }

    #[test]
    fn a_message_over_the_limit_is_refused_both_ways() {
        let message = TopicSubscription {
            topic_id: vec![1; 100],
        };
        let mut encoded = BytesMut::new();
        assert!(matches!(
            Codec::<TopicSubscription>::new(50).encode(message.clone(), &mut encoded),
            Err(Error::TooLarge { .. })
        ));

        Codec::<TopicSubscription>::new(1024)
            .encode(message, &mut encoded)
            .unwrap();
        assert!(matches!(
            Codec::<TopicSubscription>::new(50).decode(&mut encoded),
            Err(Error::TooLarge { .. })
        ));
    }

    /// Lighthouse's crate writes a required field even when empty; the wire
    /// bytes of a subscription are therefore fixed by the protobuf schema.
    #[test]
    fn a_subscription_encodes_as_the_schema_says() {
        let mut encoded = BytesMut::new();
        Codec::<TopicSubscription>::new(1024)
            .encode(
                TopicSubscription {
                    topic_id: b"ab".to_vec(),
                },
                &mut encoded,
            )
            .unwrap();
        // Length 4; field 1, wire type 2 (bytes); length 2; "ab".
        assert_eq!(&encoded[..], &[4, 0x0a, 2, b'a', b'b']);
    }
}
