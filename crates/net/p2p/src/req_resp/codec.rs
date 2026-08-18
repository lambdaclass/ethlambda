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
    /// The chain's `genesis_validators_root`, on a beacon swarm only.
    ///
    /// Writing a block chunk needs it: the `context-bytes` prefix is the fork
    /// digest of the fork *the block belongs to*, and a fork digest is computed
    /// from the schedule and this root together. Reading does not, which is why
    /// it arrives with the write path rather than with the schedule.
    beacon_genesis_validators_root: ethlambda_types::beacon::primitives::Root,
}

impl Codec {
    /// The codec for a beacon swarm, carrying what its block chunks are decoded
    /// against and written with.
    pub fn beacon(
        config: ethlambda_types::beacon::config::Config,
        genesis_validators_root: ethlambda_types::beacon::primitives::Root,
    ) -> Self {
        Self {
            beacon_config: Some(std::sync::Arc::new(config)),
            beacon_genesis_validators_root: genesis_validators_root,
        }
    }

    /// The `context-bytes` for a block at `slot`: the fork digest of the fork
    /// whose rules that block was made under.
    ///
    /// Not this node's current digest. A range request spanning a fork boundary
    /// must label each chunk with its own fork, or the asking peer decodes the
    /// older blocks with the newer fork's container and gets nonsense.
    fn beacon_context_bytes(
        &self,
        slot: ethlambda_types::beacon::primitives::Slot,
    ) -> io::Result<ethlambda_types::beacon::primitives::ForkDigest> {
        let config = self
            .beacon_config
            .as_ref()
            .ok_or_else(|| invalid("a beacon block response needs the fork schedule"))?;
        let epoch = slot / ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;
        Ok(ethlambda_types::beacon::fork_digest::compute_fork_digest(
            config,
            self.beacon_genesis_validators_root,
            epoch,
        ))
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
                            // The only multi-chunk beacon response, and the
                            // only one carrying `context-bytes`, so it writes
                            // itself here and returns rather than falling
                            // through to the single-chunk write below.
                            BeaconResponse::Blocks(blocks) => {
                                for block in blocks {
                                    let encoded = block.to_ssz();
                                    // Encoded before the result byte goes out,
                                    // so an oversized block is skipped rather
                                    // than leaving a chunk header on the wire
                                    // with no payload behind it.
                                    if encoded.len() > MAX_PAYLOAD_SIZE - 1024 {
                                        warn!(
                                            slot = block.slot(),
                                            size = encoded.len(),
                                            "Skipping oversized block in a beacon block response"
                                        );
                                        continue;
                                    }
                                    let context = self.beacon_context_bytes(block.slot())?;
                                    io.write_all(&[ResponseCode::SUCCESS.into()]).await?;
                                    io.write_all(&context).await?;
                                    let compressed_size = write_payload(io, &encoded).await?;
                                    metrics::observe_reqresp_response_chunk_size(
                                        label,
                                        encoded.len(),
                                        compressed_size,
                                    );
                                }
                                // No blocks is a valid answer: the stream just
                                // ends, which is how the specification says "I
                                // have none of what you asked for".
                                return Ok(());
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
    use ethlambda_types::beacon::containers::phase0;
    use ethlambda_types::beacon::preset;
    use ethlambda_types::beacon::primitives::{BlsSignature, Bytes32, Root, Slot};
    use futures::io::Cursor;
    use libp2p::StreamProtocol;
    use libp2p::request_response::Codec as _;

    /// A phase0 block at `slot` with an empty body: the chunk framing is what
    /// is under test, not the contents.
    fn block_at(slot: Slot) -> phase0::SignedBeaconBlock {
        phase0::SignedBeaconBlock {
            message: phase0::BeaconBlock {
                slot,
                proposer_index: 7,
                parent_root: Root::repeat_byte(1),
                state_root: Root::repeat_byte(2),
                body: phase0::BeaconBlockBody {
                    randao_reveal: BlsSignature::default(),
                    eth1_data: Default::default(),
                    graffiti: Bytes32::zero(),
                    proposer_slashings: Default::default(),
                    attester_slashings: Default::default(),
                    attestations: Default::default(),
                    deposits: Default::default(),
                    voluntary_exits: Default::default(),
                },
            },
            signature: BlsSignature::default(),
        }
    }

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

    /// A block chunk is `<result><context-bytes><payload>`, and the reader
    /// consumes exactly those four context bytes before the payload. Writing
    /// the payload without them, or writing the wrong number of them, leaves
    /// every following chunk four bytes out of phase, so this asserts the
    /// blocks survive a full multi-chunk round trip rather than just the first.
    #[tokio::test]
    async fn beacon_block_chunks_round_trip_through_the_context_bytes() {
        let stream_protocol = StreamProtocol::new(protocols::BEACON_BLOCKS_BY_RANGE_V2);
        let blocks: Vec<_> = [64_u64, 65, 66]
            .into_iter()
            .map(|slot| {
                ethlambda_types::beacon::containers::SignedBeaconBlock::Phase0(block_at(slot))
            })
            .collect();
        let mut codec = Codec::beacon(
            ethlambda_types::beacon::config::Config::mainnet(),
            Root::repeat_byte(9),
        );

        let mut buffer = Cursor::new(Vec::new());
        codec
            .write_response(
                &stream_protocol,
                &mut buffer,
                Response::success(ResponsePayload::Beacon(BeaconResponse::Blocks(
                    blocks.clone(),
                ))),
            )
            .await
            .expect("writes");

        let mut buffer = Cursor::new(buffer.into_inner());
        let decoded = codec
            .read_response(&stream_protocol, &mut buffer)
            .await
            .expect("reads");

        let Response::Success {
            payload: ResponsePayload::Beacon(BeaconResponse::Blocks(read_back)),
        } = decoded
        else {
            panic!("a block response reads back as one");
        };
        assert_eq!(
            read_back
                .iter()
                .map(|block| block.slot())
                .collect::<Vec<_>>(),
            vec![64, 65, 66],
            "every chunk must survive, in order"
        );
        assert_eq!(read_back, blocks);
    }

    /// The context bytes name the fork *the block* belongs to, not the one the
    /// serving node is on. A range spanning a fork boundary labelled with one
    /// digest throughout would have the asking peer decode the older half with
    /// the newer fork's container.
    #[tokio::test]
    async fn each_chunk_is_labelled_with_its_own_forks_digest() {
        let config = ethlambda_types::beacon::config::Config::mainnet();
        let genesis_validators_root = Root::repeat_byte(9);
        let codec = Codec::beacon(config.clone(), genesis_validators_root);

        let phase0_slot = 0;
        let later_slot = config.altair_fork_epoch * preset::SLOTS_PER_EPOCH;

        let early = codec.beacon_context_bytes(phase0_slot).expect("computes");
        let late = codec.beacon_context_bytes(later_slot).expect("computes");

        assert_ne!(
            early, late,
            "two forks must not share a digest, or the label carries no information"
        );
        assert_eq!(
            late,
            ethlambda_types::beacon::fork_digest::compute_fork_digest(
                &config,
                genesis_validators_root,
                config.altair_fork_epoch,
            ),
            "and the digest is the one that fork's own epoch produces"
        );
    }

    /// No blocks is a legal answer, and it is what a checkpoint-synced node
    /// gives for a range below its anchor. The reader must see an empty list
    /// rather than an error or a hang.
    #[tokio::test]
    async fn an_empty_beacon_block_response_reads_back_as_no_blocks() {
        let stream_protocol = StreamProtocol::new(protocols::BEACON_BLOCKS_BY_RANGE_V2);
        let mut codec = Codec::beacon(
            ethlambda_types::beacon::config::Config::mainnet(),
            Root::zero(),
        );

        let mut buffer = Cursor::new(Vec::new());
        codec
            .write_response(
                &stream_protocol,
                &mut buffer,
                Response::success(ResponsePayload::Beacon(BeaconResponse::Blocks(Vec::new()))),
            )
            .await
            .expect("writes");
        assert!(
            buffer.get_ref().is_empty(),
            "an empty response puts nothing on the wire; the stream just ends"
        );

        let mut buffer = Cursor::new(buffer.into_inner());
        let decoded = codec
            .read_response(&stream_protocol, &mut buffer)
            .await
            .expect("reads");

        let Response::Success {
            payload: ResponsePayload::Beacon(BeaconResponse::Blocks(read_back)),
        } = decoded
        else {
            panic!("a block response reads back as one");
        };
        assert!(read_back.is_empty());
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
