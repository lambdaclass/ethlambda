use std::io;

use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libssz::{SszDecode, SszEncode};
use tracing::{debug, trace, warn};

use super::{
    encoding::{MAX_PAYLOAD_SIZE, decode_payload, write_payload},
    messages::{
        BLOCKS_BY_RANGE_PROTOCOL_V1, BLOCKS_BY_ROOT_PROTOCOL_V1, ErrorMessage, Request, Response,
        ResponseCode, ResponsePayload, STATUS_PROTOCOL_V1, Status,
    },
};

use crate::beacon::messages::{
    BeaconMetaData, BeaconStatus, Goodbye, MetaDataV1, MetaDataV2, MetaDataV3, Ping, StatusV1,
    StatusV2,
};
use crate::beacon::protocols;
use crate::metrics;
use crate::req_resp::messages::{BeaconRequest, BeaconResponse};
use ethlambda_types::block::SignedBlock;

/// Short label extracted from a libp2p protocol id, used as the `protocol`
/// label on req/resp size metrics.
fn protocol_label(protocol: &str) -> &'static str {
    match protocol {
        STATUS_PROTOCOL_V1 => "status",
        BLOCKS_BY_ROOT_PROTOCOL_V1 => "blocks_by_root",
        BLOCKS_BY_RANGE_PROTOCOL_V1 => "blocks_by_range",
        other => crate::beacon::protocols::label(other).unwrap_or("unknown"),
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// Encode a `Status` for the negotiated protocol version.
///
/// A version mismatch is an error rather than a conversion: a v1 value written
/// on a v2 stream would be eight bytes short and the peer would read a
/// truncated container, which is worse than a refused write.
fn encode_beacon_status(protocol: &str, status: &BeaconStatus) -> io::Result<Vec<u8>> {
    match (protocol, status) {
        (protocols::STATUS_V1, BeaconStatus::V1(status)) => Ok(status.to_ssz()),
        (protocols::STATUS_V2, BeaconStatus::V2(status)) => Ok(status.to_ssz()),
        _ => Err(invalid(format!(
            "status version does not match protocol {protocol}"
        ))),
    }
}

fn decode_beacon_status(protocol: &str, payload: &[u8]) -> io::Result<BeaconStatus> {
    match protocol {
        protocols::STATUS_V1 => StatusV1::from_ssz_bytes(payload)
            .map(BeaconStatus::V1)
            .map_err(|err| invalid(format!("{err:?}"))),
        protocols::STATUS_V2 => StatusV2::from_ssz_bytes(payload)
            .map(BeaconStatus::V2)
            .map_err(|err| invalid(format!("{err:?}"))),
        _ => Err(invalid(format!("not a status protocol: {protocol}"))),
    }
}

fn encode_beacon_metadata(protocol: &str, metadata: &BeaconMetaData) -> io::Result<Vec<u8>> {
    match (protocol, metadata) {
        (protocols::METADATA_V1, BeaconMetaData::V1(value)) => Ok(value.to_ssz()),
        (protocols::METADATA_V2, BeaconMetaData::V2(value)) => Ok(value.to_ssz()),
        (protocols::METADATA_V3, BeaconMetaData::V3(value)) => Ok(value.to_ssz()),
        _ => Err(invalid(format!(
            "metadata version does not match protocol {protocol}"
        ))),
    }
}

fn decode_beacon_metadata(protocol: &str, payload: &[u8]) -> io::Result<BeaconMetaData> {
    match protocol {
        protocols::METADATA_V1 => MetaDataV1::from_ssz_bytes(payload)
            .map(BeaconMetaData::V1)
            .map_err(|err| invalid(format!("{err:?}"))),
        protocols::METADATA_V2 => MetaDataV2::from_ssz_bytes(payload)
            .map(BeaconMetaData::V2)
            .map_err(|err| invalid(format!("{err:?}"))),
        protocols::METADATA_V3 => MetaDataV3::from_ssz_bytes(payload)
            .map(BeaconMetaData::V3)
            .map_err(|err| invalid(format!("{err:?}"))),
        _ => Err(invalid(format!("not a metadata protocol: {protocol}"))),
    }
}

/// Bytes of `<context-bytes>` on an altair-and-later response chunk.
///
/// A fixed-width `ForkDigest`. Present on every `beacon_blocks_by_*/2` chunk and
/// on no v1 protocol, so it has to be consumed here or every following chunk
/// reads four bytes out of phase.
///
/// Source: `consensus-specs` `specs/altair/p2p-interface.md`, "`ForkDigest`-context".
const CONTEXT_BYTES_LEN: usize = 4;

#[derive(Debug, Clone, Default)]
pub struct Codec {
    /// The fork schedule, on a beacon swarm only.
    ///
    /// `beacon_blocks_by_*/2` chunks are fork-typed, so decoding one needs the
    /// schedule. Lean's swarm builds this codec with `Default::default()` and
    /// never reaches a protocol that reads it.
    beacon_config: Option<std::sync::Arc<ethlambda_types::beacon::config::Config>>,
}

impl Codec {
    /// The codec for a beacon swarm, carrying the schedule its block responses
    /// are decoded against.
    pub fn beacon(config: ethlambda_types::beacon::config::Config) -> Self {
        Self {
            beacon_config: Some(std::sync::Arc::new(config)),
        }
    }
}

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

        match protocol.as_ref() {
            STATUS_PROTOCOL_V1 => {
                let status = Status::from_ssz_bytes(&payload).map_err(|err| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("{err:?}"))
                })?;
                Ok(Request::Status(status))
            }
            BLOCKS_BY_ROOT_PROTOCOL_V1 => {
                let request = SszDecode::from_ssz_bytes(&payload).map_err(|err| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("{err:?}"))
                })?;
                Ok(Request::BlocksByRoot(request))
            }
            BLOCKS_BY_RANGE_PROTOCOL_V1 => {
                let request = SszDecode::from_ssz_bytes(&payload).map_err(|err| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("{err:?}"))
                })?;
                Ok(Request::BlocksByRange(request))
            }
            protocols::STATUS_V1 | protocols::STATUS_V2 => Ok(Request::Beacon(
                BeaconRequest::Status(decode_beacon_status(protocol.as_ref(), &payload)?),
            )),
            protocols::PING_V1 => Ok(Request::Beacon(BeaconRequest::Ping(
                Ping::from_ssz_bytes(&payload).map_err(|err| invalid(format!("{err:?}")))?,
            ))),
            // Resolved to the `'static` constant so the variant can hold it.
            protocols::METADATA_V1 => Ok(Request::Beacon(BeaconRequest::MetaData(
                protocols::METADATA_V1,
            ))),
            protocols::METADATA_V2 => Ok(Request::Beacon(BeaconRequest::MetaData(
                protocols::METADATA_V2,
            ))),
            protocols::METADATA_V3 => Ok(Request::Beacon(BeaconRequest::MetaData(
                protocols::METADATA_V3,
            ))),
            protocols::GOODBYE_V1 => Ok(Request::Beacon(BeaconRequest::Goodbye(
                Goodbye::from_ssz_bytes(&payload).map_err(|err| invalid(format!("{err:?}")))?,
            ))),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown protocol: {}", protocol.as_ref()),
            )),
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
            STATUS_PROTOCOL_V1 => decode_status_response(io, label).await,
            BLOCKS_BY_ROOT_PROTOCOL_V1 | BLOCKS_BY_RANGE_PROTOCOL_V1 => {
                decode_blocks_response(io, label).await
            }
            protocols::STATUS_V1 | protocols::STATUS_V2 => {
                decode_beacon_single_chunk(io, protocol.as_ref(), label, |protocol, payload| {
                    decode_beacon_status(protocol, payload).map(BeaconResponse::Status)
                })
                .await
            }
            protocols::PING_V1 => {
                decode_beacon_single_chunk(io, protocol.as_ref(), label, |_, payload| {
                    Ping::from_ssz_bytes(payload)
                        .map(BeaconResponse::Pong)
                        .map_err(|err| invalid(format!("{err:?}")))
                })
                .await
            }
            protocols::METADATA_V1 | protocols::METADATA_V2 | protocols::METADATA_V3 => {
                decode_beacon_single_chunk(io, protocol.as_ref(), label, |protocol, payload| {
                    decode_beacon_metadata(protocol, payload).map(BeaconResponse::MetaData)
                })
                .await
            }
            protocols::BEACON_BLOCKS_BY_RANGE_V2 | protocols::BEACON_BLOCKS_BY_ROOT_V2 => {
                let config = self.beacon_config.as_ref().ok_or_else(|| {
                    invalid("a beacon block response reached a codec with no fork schedule")
                })?;
                decode_beacon_blocks_response(io, label, config).await
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown protocol: {}", protocol.as_ref()),
            )),
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

        let encoded = match &req {
            Request::Status(status) => status.to_ssz(),
            Request::BlocksByRoot(request) => request.to_ssz(),
            Request::BlocksByRange(request) => request.to_ssz(),
            Request::Beacon(BeaconRequest::Status(status)) => {
                encode_beacon_status(protocol.as_ref(), status)?
            }
            Request::Beacon(BeaconRequest::Ping(ping)) => ping.to_ssz(),
            // The spec's MetaData request is empty, and `write_payload` of an
            // empty slice emits no bytes at all.
            Request::Beacon(BeaconRequest::MetaData(_)) => Vec::new(),
            Request::Beacon(BeaconRequest::Goodbye(goodbye)) => goodbye.to_ssz(),
            Request::Beacon(BeaconRequest::BlocksByRange(request)) => request.to_ssz(),
            Request::Beacon(BeaconRequest::BlocksByRoot(request)) => request.to_ssz(),
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
            Response::Success { payload } => {
                match &payload {
                    ResponsePayload::Status(status) => {
                        // Send success code (0)
                        io.write_all(&[ResponseCode::SUCCESS.into()]).await?;
                        let encoded = status.to_ssz();
                        let compressed_size = write_payload(io, &encoded).await?;
                        metrics::observe_reqresp_response_chunk_size(
                            label,
                            encoded.len(),
                            compressed_size,
                        );
                        Ok(())
                    }
                    ResponsePayload::Blocks(blocks) => {
                        // Write each block as a separate chunk.
                        // Encode first, then check size before writing the SUCCESS
                        // code byte. This avoids corrupting the stream if a block
                        // exceeds MAX_PAYLOAD_SIZE (the SUCCESS byte would already
                        // be on the wire with no payload following).
                        for block in blocks {
                            let encoded = block.to_ssz();
                            if encoded.len() > MAX_PAYLOAD_SIZE - 1024 {
                                warn!(
                                    size = encoded.len(),
                                    "Skipping oversized block in block response"
                                );
                                continue;
                            }
                            io.write_all(&[ResponseCode::SUCCESS.into()]).await?;
                            let compressed_size = write_payload(io, &encoded).await?;
                            metrics::observe_reqresp_response_chunk_size(
                                label,
                                encoded.len(),
                                compressed_size,
                            );
                        }
                        // Empty response if no blocks found (stream just ends)
                        Ok(())
                    }
                    ResponsePayload::Beacon(response) => {
                        let encoded = match response {
                            BeaconResponse::Status(status) => {
                                encode_beacon_status(protocol.as_ref(), status)?
                            }
                            BeaconResponse::Pong(ping) => ping.to_ssz(),
                            BeaconResponse::MetaData(metadata) => {
                                encode_beacon_metadata(protocol.as_ref(), metadata)?
                            }
                            // `beacon_blocks_by_*/2` are registered
                            // `ProtocolSupport::Outbound`, so libp2p never opens
                            // an inbound stream for one and this arm is
                            // unreachable. Refusing beats emitting a chunk with
                            // no `context-bytes`, which would desynchronize a
                            // peer's reader.
                            BeaconResponse::Blocks(_) => {
                                return Err(invalid(
                                    "this node does not serve beacon block responses",
                                ));
                            }
                        };
                        io.write_all(&[ResponseCode::SUCCESS.into()]).await?;
                        let compressed_size = write_payload(io, &encoded).await?;
                        metrics::observe_reqresp_response_chunk_size(
                            label,
                            encoded.len(),
                            compressed_size,
                        );
                        Ok(())
                    }
                }
            }
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

/// Read a single-chunk beacon response: one result-code byte, then one payload.
///
/// Every beacon protocol this node registers answers with exactly one chunk, so
/// there is no EOF loop here; the multi-chunk shape arrives with the block
/// protocols.
async fn decode_beacon_single_chunk<T, F>(
    io: &mut T,
    protocol: &str,
    protocol_label: &str,
    decode: F,
) -> io::Result<Response>
where
    T: AsyncRead + Unpin + Send,
    F: FnOnce(&str, &[u8]) -> io::Result<BeaconResponse>,
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

    Ok(Response::success(ResponsePayload::Beacon(decode(
        protocol, &payload,
    )?)))
}

/// Decodes a Status protocol response from a single-chunk response stream.
///
/// Reads the response code byte and payload, returning either a success response
/// with the peer's Status or an error response with the error code and message.
/// Unlike multi-chunk protocols, any error code from the peer is treated as a
/// valid response rather than a connection failure.
///
/// # Returns
///
/// Returns `Ok(Response::Success)` containing the peer's `Status` if the response
/// code is `SUCCESS`.
///
/// Returns `Ok(Response::Error)` containing the error code and message if the peer
/// returned a non-success response code.
///
/// # Errors
///
/// Returns `Err` if:
/// - I/O error occurs while reading the response code or payload
/// - Peer's error message cannot be SSZ-decoded (InvalidData)
/// - Peer's Status payload cannot be SSZ-decoded (InvalidData)
async fn decode_status_response<T>(io: &mut T, protocol_label: &str) -> io::Result<Response>
where
    T: AsyncRead + Unpin + Send,
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
        let message = ErrorMessage::from_ssz_bytes(&payload).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid error message: {err:?}"),
            )
        })?;
        let error_str = String::from_utf8_lossy(&message).into_owned();
        trace!(?code, %error_str, "Received error response");
        return Ok(Response::error(code, message));
    }

    let status = Status::from_ssz_bytes(&payload)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, format!("{err:?}")))?;
    Ok(Response::success(ResponsePayload::Status(status)))
}

/// Decodes a `beacon_blocks_by_{range,root}/2` response.
///
/// The chunk shape altair introduced and every later fork keeps:
///
/// ```text
/// response_chunk ::= <result> | <context-bytes> | <encoding-dependent-header> | <encoded-payload>
/// ```
///
/// `<context-bytes>` is the 4-byte `ForkDigest` naming the chunk's type. It is
/// read and discarded rather than mapped back to a fork: recovering a fork from
/// a digest needs `genesis_validators_root` as well as the schedule, and the
/// block's own slot answers the same question against the same schedule the
/// gossip path already uses (`beacon::decode::fork_at_slot`). A peer that sends
/// a digest from a fork this client does not know still decodes correctly, and
/// one that lies about the digest cannot make this decode the wrong shape.
///
/// Skipping the four bytes is not optional: without it every following chunk in
/// the stream reads out of phase.
async fn decode_beacon_blocks_response<T>(
    io: &mut T,
    protocol_label: &str,
    config: &ethlambda_types::beacon::config::Config,
) -> io::Result<Response>
where
    T: AsyncRead + Unpin + Send,
{
    use ethlambda_types::beacon::containers::SignedBeaconBlock;

    let mut blocks = Vec::new();

    loop {
        let mut result_byte = 0_u8;
        if let Err(err) = io.read_exact(std::slice::from_mut(&mut result_byte)).await {
            if err.kind() == io::ErrorKind::UnexpectedEof {
                break;
            }
            return Err(err);
        }
        let code = ResponseCode::from(result_byte);

        // Only a success chunk carries context bytes; the spec is explicit that
        // an error chunk's are empty.
        if code == ResponseCode::SUCCESS {
            let mut context = [0_u8; CONTEXT_BYTES_LEN];
            io.read_exact(&mut context).await?;
        }

        let decoded = decode_payload(io).await?;
        let payload = decoded.uncompressed;
        metrics::observe_reqresp_response_chunk_size(
            protocol_label,
            payload.len(),
            decoded.compressed_size,
        );

        if code != ResponseCode::SUCCESS {
            let error_message = ErrorMessage::from_ssz_bytes(&payload)
                .map(|msg| String::from_utf8_lossy(&msg).into_owned())
                .unwrap_or_else(|_| "<invalid error message>".to_string());
            debug!(?code, %error_message, "Skipping beacon block chunk with non-success code");
            continue;
        }

        let slot = crate::beacon::decode::block_slot(&payload)
            .map_err(|err| invalid(format!("beacon block chunk has no readable slot: {err:?}")))?;
        let fork = crate::beacon::decode::fork_at_slot(config, slot);
        let block = SignedBeaconBlock::from_ssz(fork, &payload).map_err(|err| {
            invalid(format!(
                "beacon block chunk at slot {slot} is not a valid {} block: {err:?}",
                fork.as_str()
            ))
        })?;
        blocks.push(block);
    }

    Ok(Response::success(ResponsePayload::Beacon(
        BeaconResponse::Blocks(blocks),
    )))
}

/// Decodes a block protocol response from a multi-chunk response stream.
///
/// Reads chunks until EOF, collecting successfully decoded blocks. Each chunk has
/// its own response code - chunks with error codes are logged and skipped rather
/// than terminating the stream. This allows partial success when some requested
/// blocks are unavailable. The stream ends naturally at EOF (peer closes after
/// sending all available blocks).
///
/// # Returns
///
/// Always returns `Ok(Response::Success)` containing a vector of successfully
/// decoded blocks. The vector may be empty if no SUCCESS chunks were received
/// before EOF (either no chunks sent, or all chunks had non-SUCCESS codes)
///
/// # Errors
///
/// Returns `Err` if:
/// - I/O error occurs while reading response codes or payloads (except `UnexpectedEof`
///   which signals normal stream termination)
/// - Block payload cannot be SSZ-decoded into `SignedBlock` (InvalidData)
///
/// Note: Error chunks from the peer (non-SUCCESS response codes) do not cause this
/// function to return `Err` - they are logged and skipped.
async fn decode_blocks_response<T>(io: &mut T, protocol_label: &str) -> io::Result<Response>
where
    T: AsyncRead + Unpin + Send,
{
    let mut blocks = Vec::new();

    loop {
        // Read chunk result code
        let mut result_byte = 0_u8;
        if let Err(e) = io.read_exact(std::slice::from_mut(&mut result_byte)).await {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                break;
            }
            return Err(e);
        }

        let code = ResponseCode::from(result_byte);
        let decoded = decode_payload(io).await?;
        let payload = decoded.uncompressed;
        metrics::observe_reqresp_response_chunk_size(
            protocol_label,
            payload.len(),
            decoded.compressed_size,
        );

        if code != ResponseCode::SUCCESS {
            let error_message = ErrorMessage::from_ssz_bytes(&payload)
                .map(|msg| String::from_utf8_lossy(&msg).into_owned())
                .unwrap_or_else(|_| "<invalid error message>".to_string());
            debug!(?code, %error_message, "Skipping block chunk with non-success code");
            continue;
        }

        let block = SignedBlock::from_ssz_bytes(&payload)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, format!("{err:?}")))?;
        blocks.push(block);
    }

    Ok(Response::success(ResponsePayload::Blocks(blocks)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::messages::{
        AttnetsBits, BeaconMetaData, BeaconStatus, Goodbye, MetaDataV3, Ping, StatusV1,
        SyncnetsBits,
    };
    use crate::beacon::protocols;
    use crate::req_resp::messages::{BeaconRequest, BeaconResponse};
    use ethlambda_types::beacon::primitives::Root;
    use futures::io::Cursor;
    use libp2p::StreamProtocol;
    use libp2p::request_response::Codec as _;

    fn status() -> BeaconStatus {
        BeaconStatus::V1(StatusV1 {
            fork_digest: [0x8c, 0x9f, 0x62, 0xfe],
            finalized_root: Root::zero(),
            finalized_epoch: 0,
            head_root: Root::zero(),
            head_slot: 0,
        })
    }

    /// Write a request, then read it back off the same buffer.
    async fn request_round_trip(protocol: &'static str, request: Request) -> Request {
        let stream_protocol = StreamProtocol::new(protocol);
        let mut buffer = Cursor::new(Vec::new());
        Codec::default()
            .write_request(&stream_protocol, &mut buffer, request)
            .await
            .expect("writes");
        let mut buffer = Cursor::new(buffer.into_inner());
        Codec::default()
            .read_request(&stream_protocol, &mut buffer)
            .await
            .expect("reads")
    }

    /// Write a response, then read it back off the same buffer.
    async fn response_round_trip(protocol: &'static str, response: Response) -> Response {
        let stream_protocol = StreamProtocol::new(protocol);
        let mut buffer = Cursor::new(Vec::new());
        Codec::default()
            .write_response(&stream_protocol, &mut buffer, response)
            .await
            .expect("writes");
        let mut buffer = Cursor::new(buffer.into_inner());
        Codec::default()
            .read_response(&stream_protocol, &mut buffer)
            .await
            .expect("reads")
    }

    #[tokio::test]
    async fn a_status_v1_request_round_trips_through_the_snappy_framing() {
        let decoded = request_round_trip(
            protocols::STATUS_V1,
            Request::Beacon(BeaconRequest::Status(status())),
        )
        .await;
        assert!(matches!(
            decoded,
            Request::Beacon(BeaconRequest::Status(BeaconStatus::V1(_)))
        ));
    }

    #[tokio::test]
    async fn the_protocol_version_selects_the_status_shape() {
        // A v1 payload on a v2 stream would be eight bytes short, so the
        // version has to come from the negotiated protocol rather than from
        // whichever variant the caller happened to build.
        let stream_protocol = StreamProtocol::new(protocols::STATUS_V2);
        let mut buffer = Cursor::new(Vec::new());
        let result = Codec::default()
            .write_request(
                &stream_protocol,
                &mut buffer,
                Request::Beacon(BeaconRequest::Status(status())),
            )
            .await;
        assert!(
            result.is_err(),
            "writing a v1 Status on a v2 stream must be refused, not truncated"
        );
    }

    #[tokio::test]
    async fn a_ping_round_trips() {
        let decoded = request_round_trip(
            protocols::PING_V1,
            Request::Beacon(BeaconRequest::Ping(Ping { seq_number: 5 })),
        )
        .await;
        assert!(matches!(
            decoded,
            Request::Beacon(BeaconRequest::Ping(Ping { seq_number: 5 }))
        ));

        let decoded = response_round_trip(
            protocols::PING_V1,
            Response::success(ResponsePayload::Beacon(BeaconResponse::Pong(Ping {
                seq_number: 5,
            }))),
        )
        .await;
        assert!(matches!(
            decoded,
            Response::Success {
                payload: ResponsePayload::Beacon(BeaconResponse::Pong(Ping { seq_number: 5 }))
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
            Request::Beacon(BeaconRequest::MetaData(protocols::METADATA_V3)),
        )
        .await;
        assert!(matches!(
            decoded,
            Request::Beacon(BeaconRequest::MetaData(protocols::METADATA_V3))
        ));
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
            Response::success(ResponsePayload::Beacon(BeaconResponse::MetaData(metadata))),
        )
        .await;
        let Response::Success {
            payload: ResponsePayload::Beacon(BeaconResponse::MetaData(BeaconMetaData::V3(v3))),
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
            Request::Beacon(BeaconRequest::Goodbye(Goodbye { reason: 128 })),
        )
        .await;
        assert!(matches!(
            decoded,
            Request::Beacon(BeaconRequest::Goodbye(Goodbye { reason: 128 }))
        ));
    }
}
