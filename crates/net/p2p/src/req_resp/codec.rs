use std::io;

use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libssz::{SszDecode, SszEncode};
use tracing::trace;

use super::{
    encoding::{decode_payload, invalid, write_payload},
    messages::{ErrorMessage, Request, Response, ResponseCode, ResponsePayload},
};

use crate::beacon::messages::{Goodbye, Ping};
use crate::beacon::{encoding as beacon_encoding, protocols};
use crate::lean::{encoding as lean_encoding, protocols as lean_protocols};
use crate::metrics;

/// Short label extracted from a libp2p protocol id, used as the `protocol`
/// label on req/resp size metrics.
fn protocol_label(protocol: &str) -> &'static str {
    lean_protocols::label(protocol)
        .or_else(|| protocols::label(protocol))
        .unwrap_or("unknown")
}

/// Write one success chunk: the code byte, then the compressed payload.
///
/// Four of the five [`ResponsePayload`] variants answer with exactly one chunk
/// and differ only in how the body is encoded. `LeanBlocks` is the exception,
/// writing a code byte per block, which is why this is a helper rather than the
/// tail of `write_response`.
pub(crate) async fn write_success_chunk<T>(
    io: &mut T,
    label: &'static str,
    encoded: Vec<u8>,
) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    io.write_all(&[ResponseCode::SUCCESS.into()]).await?;
    let compressed_size = write_payload(io, &encoded).await?;
    metrics::observe_reqresp_response_chunk_size(label, encoded.len(), compressed_size);
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub struct Codec;

impl libp2p::request_response::Codec for Codec {
    type Protocol = libp2p::StreamProtocol;
    type Request = Request;
    type Response = Response;

    async fn read_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let decoded = decode_payload(io).await?;
        let payload = decoded.uncompressed;
        let label = protocol_label(protocol.as_ref());
        metrics::observe_reqresp_request_size(label, payload.len(), decoded.compressed_size);

        // Each chain answers for its own protocol ids and `None` for anything
        // else, so neither module needs to know the other exists.
        if let Some(request) = lean_encoding::decode_request(protocol.as_ref(), &payload) {
            return request;
        }
        match protocol.as_ref() {
            protocols::STATUS_V1 | protocols::STATUS_V2 => Ok(Request::Status(
                beacon_encoding::decode_status(protocol.as_ref(), &payload)?,
            )),
            protocols::PING_V1 => Ok(Request::Ping(
                Ping::from_ssz_bytes(&payload).map_err(|err| invalid(format!("{err:?}")))?,
            )),
            // Resolved to the `'static` constant so the variant can hold it.
            protocols::METADATA_V1 => Ok(Request::MetaData(protocols::METADATA_V1)),
            protocols::METADATA_V2 => Ok(Request::MetaData(protocols::METADATA_V2)),
            protocols::METADATA_V3 => Ok(Request::MetaData(protocols::METADATA_V3)),
            protocols::GOODBYE_V1 => Ok(Request::Goodbye(
                Goodbye::from_ssz_bytes(&payload).map_err(|err| invalid(format!("{err:?}")))?,
            )),
            _ => Err(invalid(format!("unknown protocol: {}", protocol.as_ref()))),
        }
    }

    async fn read_response<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let label = protocol_label(protocol.as_ref());
        match protocol.as_ref() {
            lean_protocols::STATUS_V1 => {
                decode_single_chunk(io, protocol.as_ref(), label, |_, payload| {
                    lean_encoding::decode_status_response(payload)
                })
                .await
            }
            lean_protocols::BLOCKS_BY_ROOT_V1 | lean_protocols::BLOCKS_BY_RANGE_V1 => {
                lean_encoding::decode_blocks_response(io, label).await
            }
            protocols::STATUS_V1 | protocols::STATUS_V2 => {
                decode_single_chunk(io, protocol.as_ref(), label, |protocol, payload| {
                    beacon_encoding::decode_status(protocol, payload).map(ResponsePayload::Status)
                })
                .await
            }
            protocols::PING_V1 => {
                decode_single_chunk(io, protocol.as_ref(), label, |_, payload| {
                    Ping::from_ssz_bytes(payload)
                        .map(ResponsePayload::Pong)
                        .map_err(|err| invalid(format!("{err:?}")))
                })
                .await
            }
            protocols::METADATA_V1 | protocols::METADATA_V2 | protocols::METADATA_V3 => {
                decode_single_chunk(io, protocol.as_ref(), label, |protocol, payload| {
                    beacon_encoding::decode_metadata(protocol, payload)
                        .map(ResponsePayload::MetaData)
                })
                .await
            }
            _ => Err(invalid(format!("unknown protocol: {}", protocol.as_ref()))),
        }
    }

    async fn write_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        trace!(?req, "Writing request");

        // One arm per variant, each delegating to its own chain's module: this
        // is the whole of what the codec knows about either encoding.
        let encoded = match &req {
            Request::LeanStatus(status) => lean_encoding::encode_status(status),
            Request::LeanBlocksByRoot(request) => lean_encoding::encode_blocks_by_root(request),
            Request::LeanBlocksByRange(request) => lean_encoding::encode_blocks_by_range(request),
            Request::Status(status) => beacon_encoding::encode_status(protocol.as_ref(), status)?,
            Request::Ping(ping) => beacon_encoding::encode_ping(ping),
            // The spec's MetaData request is empty, and `write_payload` of an
            // empty slice emits no bytes at all.
            Request::MetaData(_) => Vec::new(),
            Request::Goodbye(goodbye) => beacon_encoding::encode_goodbye(goodbye),
        };

        let compressed_size = write_payload(io, &encoded).await?;
        let label = protocol_label(protocol.as_ref());
        metrics::observe_reqresp_request_size(label, encoded.len(), compressed_size);
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
        resp: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let label = protocol_label(protocol.as_ref());
        match resp {
            Response::Success { payload } => match &payload {
                ResponsePayload::LeanStatus(status) => {
                    write_success_chunk(io, label, lean_encoding::encode_status(status)).await
                }
                ResponsePayload::LeanBlocks(blocks) => {
                    lean_encoding::write_blocks_response(io, label, blocks).await
                }
                ResponsePayload::Status(status) => {
                    let encoded = beacon_encoding::encode_status(protocol.as_ref(), status)?;
                    write_success_chunk(io, label, encoded).await
                }
                ResponsePayload::Pong(ping) => {
                    write_success_chunk(io, label, beacon_encoding::encode_ping(ping)).await
                }
                ResponsePayload::MetaData(metadata) => {
                    let encoded = beacon_encoding::encode_metadata(protocol.as_ref(), metadata)?;
                    write_success_chunk(io, label, encoded).await
                }
            },
            Response::Error { code, message } => {
                // Send error code
                io.write_all(&[code.into()]).await?;

                // Error messages are SSZ-encoded as List[byte, 256]
                let encoded = message.to_ssz();

                let compressed_size = write_payload(io, &encoded).await?;
                metrics::observe_reqresp_response_chunk_size(label, encoded.len(), compressed_size);
                Ok(())
            }
        }
    }
}

/// Read a single-chunk response: one result-code byte, then one payload.
///
/// Lean's `Status` and every beacon protocol this node registers answer with
/// exactly one chunk, so there is no EOF loop here; the multi-chunk shape is
/// [`decode_blocks_response`]. `decode` turns the body into a payload, and is
/// handed the negotiated protocol id because the beacon containers pick their
/// version off it.
async fn decode_single_chunk<T, F>(
    io: &mut T,
    protocol: &str,
    protocol_label: &str,
    decode: F,
) -> io::Result<Response>
where
    T: AsyncRead + Unpin + Send,
    F: FnOnce(&str, &[u8]) -> io::Result<ResponsePayload>,
{
    let mut result_byte = 0_u8;
    io.read_exact(std::slice::from_mut(&mut result_byte))
        .await?;
    let code = ResponseCode::from(result_byte);

    let decoded = decode_payload(io).await?;
    let payload = decoded.uncompressed;
    metrics::observe_reqresp_response_chunk_size(
        protocol_label,
        payload.len(),
        decoded.compressed_size,
    );

    if code != ResponseCode::SUCCESS {
        let message = ErrorMessage::from_ssz_bytes(&payload)
            .map_err(|err| invalid(format!("Invalid error message: {err:?}")))?;
        let error_str = String::from_utf8_lossy(&message).into_owned();
        trace!(?code, %error_str, "Received error response");
        return Ok(Response::error(code, message));
    }

    Ok(Response::success(decode(protocol, &payload)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::messages::{
        AttnetsBits, BeaconMetaData, BeaconStatus, Goodbye, MetaDataV3, Ping, StatusV1,
        SyncnetsBits,
    };
    use crate::beacon::protocols;
    use ethlambda_types::beacon::primitives::Root;
    use futures::io::Cursor;
    use libp2p::StreamProtocol;
    use libp2p::request_response::Codec as _;

    fn status() -> BeaconStatus {
        BeaconStatus::V1(StatusV1 {
            fork_digest: [0x8c, 0x9f, 0x62, 0xfe],
            finalized_root: Root::ZERO,
            finalized_epoch: 0,
            head_root: Root::ZERO,
            head_slot: 0,
        })
    }

    /// Write a request, then read it back off the same buffer.
    async fn request_round_trip(protocol: &'static str, request: Request) -> Request {
        let stream_protocol = StreamProtocol::new(protocol);
        let mut buffer = Cursor::new(Vec::new());
        Codec
            .write_request(&stream_protocol, &mut buffer, request)
            .await
            .expect("writes");
        let mut buffer = Cursor::new(buffer.into_inner());
        Codec
            .read_request(&stream_protocol, &mut buffer)
            .await
            .expect("reads")
    }

    /// Write a response, then read it back off the same buffer.
    async fn response_round_trip(protocol: &'static str, response: Response) -> Response {
        let stream_protocol = StreamProtocol::new(protocol);
        let mut buffer = Cursor::new(Vec::new());
        Codec
            .write_response(&stream_protocol, &mut buffer, response)
            .await
            .expect("writes");
        let mut buffer = Cursor::new(buffer.into_inner());
        Codec
            .read_response(&stream_protocol, &mut buffer)
            .await
            .expect("reads")
    }

    #[tokio::test]
    async fn a_status_v1_request_round_trips_through_the_snappy_framing() {
        let decoded = request_round_trip(protocols::STATUS_V1, Request::Status(status())).await;
        assert!(matches!(decoded, Request::Status(BeaconStatus::V1(_))));
    }

    #[tokio::test]
    async fn the_protocol_version_selects_the_status_shape() {
        // A v1 payload on a v2 stream would be eight bytes short, so the
        // version has to come from the negotiated protocol rather than from
        // whichever variant the caller happened to build.
        let stream_protocol = StreamProtocol::new(protocols::STATUS_V2);
        let mut buffer = Cursor::new(Vec::new());
        let result = Codec
            .write_request(&stream_protocol, &mut buffer, Request::Status(status()))
            .await;
        assert!(
            result.is_err(),
            "writing a v1 Status on a v2 stream must be refused, not truncated"
        );
    }

    #[tokio::test]
    async fn a_ping_round_trips() {
        let decoded =
            request_round_trip(protocols::PING_V1, Request::Ping(Ping { seq_number: 5 })).await;
        assert!(matches!(decoded, Request::Ping(Ping { seq_number: 5 })));

        let decoded = response_round_trip(
            protocols::PING_V1,
            Response::success(ResponsePayload::Pong(Ping { seq_number: 5 })),
        )
        .await;
        assert!(matches!(
            decoded,
            Response::Success {
                payload: ResponsePayload::Pong(Ping { seq_number: 5 })
            }
        ));
    }

    #[tokio::test]
    async fn a_metadata_request_carries_no_payload() {
        // The spec's MetaData request is empty. `write_payload` of an empty
        // slice emits nothing at all, and `decode_payload` reads a zero-length
        // varint back, so the two agree on an empty stream.
        let decoded = request_round_trip(
            protocols::METADATA_V3,
            Request::MetaData(protocols::METADATA_V3),
        )
        .await;
        assert!(matches!(decoded, Request::MetaData(protocols::METADATA_V3)));
    }

    #[tokio::test]
    async fn a_metadata_v3_response_round_trips() {
        let metadata = BeaconMetaData::V3(MetaDataV3 {
            seq_number: 0,
            attnets: AttnetsBits::default(),
            syncnets: SyncnetsBits::default(),
            custody_group_count: 4,
        });
        let decoded = response_round_trip(
            protocols::METADATA_V3,
            Response::success(ResponsePayload::MetaData(metadata)),
        )
        .await;
        let Response::Success {
            payload: ResponsePayload::MetaData(BeaconMetaData::V3(v3)),
        } = decoded
        else {
            panic!("expected a v3 MetaData");
        };
        assert_eq!(v3.custody_group_count, 4);
    }

    #[tokio::test]
    async fn a_goodbye_round_trips() {
        let decoded = request_round_trip(
            protocols::GOODBYE_V1,
            Request::Goodbye(Goodbye { reason: 128 }),
        )
        .await;
        assert!(matches!(decoded, Request::Goodbye(Goodbye { reason: 128 })));
    }
}
