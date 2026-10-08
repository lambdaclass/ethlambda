use std::io;
use std::sync::Arc;

use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libssz::{SszDecode, SszEncode};
use tracing::trace;

use super::{
    encoding::{decode_payload, invalid, write_payload},
    messages::{ErrorMessage, Request, Response, ResponseCode, ResponsePayload},
};

use crate::beacon::messages::{
    BeaconBlocksByRangeRequest, DataColumnsByRangeRequest, DataColumnsByRootIdentifiers, Goodbye,
    Ping,
};
use crate::beacon::{BeaconContext, encoding as beacon_encoding, protocols};
use crate::lean::messages::{BlocksByRootRequest, RequestedBlockRoots};
use crate::lean::{encoding as lean_encoding, protocols as lean_protocols};
use crate::metrics;

/// Protocols whose response payload has one shape forever write no context
/// bytes, which is every protocol here except the two beacon block ones and
/// the two beacon data column sidecar ones.
const NO_CONTEXT: &[u8] = &[];

/// Short label extracted from a libp2p protocol id, used as the `protocol`
/// label on req/resp size metrics.
fn protocol_label(protocol: &str) -> &'static str {
    lean_protocols::label(protocol)
        .or_else(|| protocols::label(protocol))
        .unwrap_or("unknown")
}

/// Write one success chunk: the code byte, the context bytes, then the
/// compressed payload.
///
/// `response_chunk ::= <result> | <context-bytes> | <encoding-dependent-header>
/// | <encoded-payload>`, and this writes it in that order. `context` is empty
/// on every lean protocol and on the beacon protocols whose payload shape does
/// not depend on the fork; it is the four-byte `ForkDigest` on the two block
/// protocols and the two data column sidecar protocols. Passing an empty slice
/// emits nothing, which is exactly what "`<context-bytes>` is empty by
/// default" means.
///
/// The single-chunk response payloads differ only in how their body is encoded,
/// so they all end here. The block and data column sidecar payloads write a
/// chunk per item, which is why this is a helper rather than the tail of
/// `write_response`.
pub(crate) async fn write_success_chunk<T>(
    io: &mut T,
    label: &'static str,
    context: &[u8],
    encoded: Vec<u8>,
) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    io.write_all(&[ResponseCode::SUCCESS.into()]).await?;
    if !context.is_empty() {
        io.write_all(context).await?;
    }
    let compressed_size = write_payload(io, &encoded).await?;
    metrics::observe_reqresp_response_chunk_size(label, encoded.len(), compressed_size);
    Ok(())
}

/// The request/response codec, for whichever chain the node is on.
///
/// One codec for both, mirroring the single [`Request`] and the single
/// dispatch above it. It is stateless for lean and for most of beacon's
/// protocols; the two block protocols and the two data column sidecar
/// protocols are the exception, because a chunk's `<context-bytes>` are a
/// function of the chunk's own slot, the fork schedule and the chain, none of
/// which the payload alone supplies.
///
/// Deliberately not `Default`. `request_response::Behaviour::new` would
/// construct one through that impl, and a beacon node whose codec came out
/// contextless would negotiate the block protocols and then fail every chunk;
/// [`crate::build_swarm`] uses `with_codec` and [`Codec::lean`] or
/// [`Codec::beacon`] instead, so
/// the context is decided in the same match that decides the protocol set.
#[derive(Debug, Clone)]
pub struct Codec {
    /// `None` on a lean node, which registers none of the protocols that read
    /// it.
    beacon: Option<Arc<BeaconContext>>,
}

impl Codec {
    /// The codec for a lean node: no beacon protocol is registered, so there is
    /// no context to carry.
    pub fn lean() -> Self {
        Self { beacon: None }
    }

    /// The codec for a beacon node, holding what the block protocols need.
    pub fn beacon(context: BeaconContext) -> Self {
        Self {
            beacon: Some(Arc::new(context)),
        }
    }

    /// The beacon context, or the error a block or sidecar chunk cannot be
    /// framed without.
    ///
    /// Unreachable in a correctly built node: the block and data column
    /// sidecar protocols are only registered on the beacon arm of
    /// [`crate::build_swarm`], which is the same arm that supplies the
    /// context. Surfaced as an error rather than an `expect` because it is
    /// reachable from a peer's stream, and a codec panic takes the whole swarm
    /// down.
    fn beacon_context(&self, protocol: &str) -> io::Result<&BeaconContext> {
        self.beacon.as_deref().ok_or_else(|| {
            invalid(format!(
                "{protocol} needs a beacon fork context, which this node has none of"
            ))
        })
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
        // MetaData's request body is empty on the wire by spec: no varint, no
        // snappy frame, nothing to read at all. Every other protocol's body is
        // a real SSZ field (possibly itself zero bytes, like an empty
        // BlocksByRoot root list), which the spec still frames the normal way,
        // so only this arm returns before `decode_payload` runs. Resolved to
        // the `'static` constant so the variant can hold it.
        let metadata_protocol = match protocol.as_ref() {
            protocols::METADATA_V1 => Some(protocols::METADATA_V1),
            protocols::METADATA_V2 => Some(protocols::METADATA_V2),
            protocols::METADATA_V3 => Some(protocols::METADATA_V3),
            _ => None,
        };
        if let Some(metadata_protocol) = metadata_protocol {
            metrics::observe_reqresp_request_size(protocol_label(protocol.as_ref()), 0, 0);
            return Ok(Request::MetaData(metadata_protocol));
        }

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
            // METADATA_V1/V2/V3 are handled above, before any bytes are read.
            protocols::GOODBYE_V1 => Ok(Request::Goodbye(
                Goodbye::from_ssz_bytes(&payload).map_err(|err| invalid(format!("{err:?}")))?,
            )),
            // Twenty-four bytes here against lean's sixteen, the third of them
            // the deprecated `step`. It is carried up rather than checked here:
            // a peer that sets it wrong is answered with INVALID_REQUEST by the
            // handler, which refusing at decode could not do.
            protocols::BLOCKS_BY_RANGE_V2 => {
                let wire = BeaconBlocksByRangeRequest::from_ssz_bytes(&payload)
                    .map_err(|err| invalid(format!("{err:?}")))?;
                Ok(Request::BlocksByRange(wire.into()))
            }
            // The bare list, with no container around it: this body is an SSZ
            // *field* where lean's is an SSZ container holding the same list.
            protocols::BLOCKS_BY_ROOT_V2 => Ok(Request::BlocksByRoot(BlocksByRootRequest {
                roots: RequestedBlockRoots::from_ssz_bytes(&payload)
                    .map_err(|err| invalid(format!("{err:?}")))?,
            })),
            // The bare list again, this time of identifiers rather than
            // roots; unwrapped into a plain `Vec` because nothing above the
            // codec needs the SSZ bound once decode has already enforced it.
            protocols::DATA_COLUMN_SIDECARS_BY_ROOT_V1 => {
                let identifiers = DataColumnsByRootIdentifiers::from_ssz_bytes(&payload)
                    .map_err(|err| invalid(format!("{err:?}")))?;
                Ok(Request::DataColumnsByRoot(identifiers.into_inner()))
            }
            protocols::DATA_COLUMN_SIDECARS_BY_RANGE_V1 => Ok(Request::DataColumnsByRange(
                DataColumnsByRangeRequest::from_ssz_bytes(&payload)
                    .map_err(|err| invalid(format!("{err:?}")))?,
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
            protocols::BLOCKS_BY_RANGE_V2 | protocols::BLOCKS_BY_ROOT_V2 => {
                let context = self.beacon_context(protocol.as_ref())?;
                let blocks = beacon_encoding::decode_blocks_response(
                    io,
                    label,
                    &context.config,
                    context.genesis_validators_root,
                )
                .await?;
                Ok(Response::success(ResponsePayload::Blocks(blocks)))
            }
            protocols::DATA_COLUMN_SIDECARS_BY_RANGE_V1
            | protocols::DATA_COLUMN_SIDECARS_BY_ROOT_V1 => {
                let context = self.beacon_context(protocol.as_ref())?;
                let sidecars = beacon_encoding::decode_data_column_sidecars_response(
                    io,
                    label,
                    &context.config,
                    context.genesis_validators_root,
                )
                .await?;
                Ok(Response::success(ResponsePayload::DataColumnSidecars(
                    sidecars,
                )))
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

        // MetaData has no request body at all by spec, unlike, say, an empty
        // BlocksByRoot root list, which is still a real, if zero-length, SSZ
        // field the spec frames the normal way. `write_payload` always writes
        // a varint length and a snappy stream header even for an empty slice,
        // so encoding this to `Vec::new()` and falling into the shared
        // `write_payload` call below would put eleven bytes on the wire where
        // the spec puts none. Returning here keeps this the only variant that
        // skips it.
        if let Request::MetaData(_) = &req {
            let label = protocol_label(protocol.as_ref());
            metrics::observe_reqresp_request_size(label, 0, 0);
            return Ok(());
        }

        // One arm per variant, each delegating to its own chain's module: this
        // is the whole of what the codec knows about either encoding. The two
        // block requests are the exception, because one variant is carried by
        // both wires and only the negotiated protocol says which framing to
        // write.
        let encoded = match &req {
            Request::LeanStatus(status) => lean_encoding::encode_status(status),
            Request::BlocksByRoot(request) => match protocol.as_ref() {
                lean_protocols::BLOCKS_BY_ROOT_V1 => lean_encoding::encode_blocks_by_root(request),
                // The bare list: beacon's body is an SSZ field, so the
                // container lean wraps it in comes back off here.
                protocols::BLOCKS_BY_ROOT_V2 => request.roots.to_ssz(),
                other => return Err(invalid(format!("not a blocks_by_root protocol: {other}"))),
            },
            Request::BlocksByRange(request) => match protocol.as_ref() {
                lean_protocols::BLOCKS_BY_RANGE_V1 => {
                    lean_encoding::encode_blocks_by_range(request)
                }
                protocols::BLOCKS_BY_RANGE_V2 => BeaconBlocksByRangeRequest::from(request).to_ssz(),
                other => return Err(invalid(format!("not a blocks_by_range protocol: {other}"))),
            },
            Request::Status(status) => beacon_encoding::encode_status(protocol.as_ref(), status)?,
            // Versionless bodies, so there is nothing for the beacon module to
            // decide and they encode straight from the container.
            Request::Ping(ping) => ping.to_ssz(),
            // Handled and returned from above, before this match is reached.
            Request::MetaData(_) => unreachable!("Request::MetaData returns earlier in this fn"),
            Request::Goodbye(goodbye) => goodbye.to_ssz(),
            // The bound is re-applied here rather than trusted from wherever
            // the `Vec` was built: it is only enforced on the way in by
            // `read_request`'s `DataColumnsByRootIdentifiers::from_ssz_bytes`,
            // and nothing stops a caller building an oversized `Vec` directly.
            Request::DataColumnsByRoot(identifiers) => {
                DataColumnsByRootIdentifiers::try_from(identifiers.clone())
                    .map_err(|err| invalid(format!("{err:?}")))?
                    .to_ssz()
            }
            Request::DataColumnsByRange(request) => request.to_ssz(),
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
                    write_success_chunk(io, label, NO_CONTEXT, lean_encoding::encode_status(status))
                        .await
                }
                // One payload, two framings, picked by the negotiated
                // protocol the same way the two block requests are.
                ResponsePayload::Blocks(blocks) => match protocol.as_ref() {
                    lean_protocols::BLOCKS_BY_ROOT_V1 | lean_protocols::BLOCKS_BY_RANGE_V1 => {
                        lean_encoding::write_blocks_response(io, label, blocks).await
                    }
                    protocols::BLOCKS_BY_RANGE_V2 | protocols::BLOCKS_BY_ROOT_V2 => {
                        let context = self.beacon_context(protocol.as_ref())?;
                        beacon_encoding::write_blocks_response(
                            io,
                            label,
                            &context.config,
                            context.genesis_validators_root,
                            blocks,
                        )
                        .await
                    }
                    other => Err(invalid(format!("not a block protocol: {other}"))),
                },
                ResponsePayload::Status(status) => {
                    let encoded = beacon_encoding::encode_status(protocol.as_ref(), status)?;
                    write_success_chunk(io, label, NO_CONTEXT, encoded).await
                }
                ResponsePayload::Pong(ping) => {
                    write_success_chunk(io, label, NO_CONTEXT, ping.to_ssz()).await
                }
                ResponsePayload::MetaData(metadata) => {
                    let encoded = beacon_encoding::encode_metadata(protocol.as_ref(), metadata)?;
                    write_success_chunk(io, label, NO_CONTEXT, encoded).await
                }
                ResponsePayload::DataColumnSidecars(sidecars) => {
                    let context = self.beacon_context(protocol.as_ref())?;
                    beacon_encoding::write_data_column_sidecars_response(
                        io,
                        label,
                        &context.config,
                        context.genesis_validators_root,
                        sidecars,
                    )
                    .await
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
/// Lean's `Status` and every beacon protocol but the two block ones answer with
/// exactly one chunk, so there is no EOF loop here; the multi-chunk shape is
/// [`crate::lean::encoding::decode_blocks_response`] and its beacon
/// counterpart, both of which run the shared
/// [`crate::req_resp::encoding::read_chunked_response`] loop. `decode` turns the
/// body into a payload, and is handed the negotiated protocol id because the
/// beacon containers pick their version off it.
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
        AttnetsBits, BeaconMetaData, BeaconStatus, DataColumnsByRangeRequest, Goodbye, MetaDataV3,
        Ping, StatusV1, SyncnetsBits,
    };
    use crate::beacon::protocols;
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::containers::fulu::{
        self, ColumnIndices, DataColumnsByRootIdentifier,
    };
    use ethlambda_types::beacon::containers::shared;
    use ethlambda_types::beacon::preset;
    use ethlambda_types::beacon::primitives::Root;
    use futures::io::Cursor;
    use libp2p::StreamProtocol;
    use libp2p::request_response::Codec as _;

    /// Ethereum mainnet's `genesis_validators_root`.
    fn mainnet_gvr() -> Root {
        Root::from_slice(
            &hex::decode("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")
                .expect("valid hex"),
        )
    }

    /// A codec built the way `build_swarm`'s beacon arm builds one.
    fn codec() -> Codec {
        Codec::beacon(BeaconContext {
            config: Config::mainnet(),
            genesis_validators_root: mainnet_gvr(),
        })
    }

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
        codec()
            .write_request(&stream_protocol, &mut buffer, request)
            .await
            .expect("writes");
        let mut buffer = Cursor::new(buffer.into_inner());
        codec()
            .read_request(&stream_protocol, &mut buffer)
            .await
            .expect("reads")
    }

    /// Write a response, then read it back off the same buffer.
    async fn response_round_trip(protocol: &'static str, response: Response) -> Response {
        let stream_protocol = StreamProtocol::new(protocol);
        let mut buffer = Cursor::new(Vec::new());
        codec()
            .write_response(&stream_protocol, &mut buffer, response)
            .await
            .expect("writes");
        let mut buffer = Cursor::new(buffer.into_inner());
        codec()
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
        let result = codec()
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
        // The spec's MetaData request is empty: `write_request` returns before
        // writing anything, and `read_request` returns before reading
        // anything, so the two agree on an empty stream without either side
        // touching `write_payload`/`decode_payload`. This round-trip alone
        // would pass even with the old, wrong framing (a varint zero plus a
        // bare snappy header), since both ends of one process agree with
        // themselves either way; see `a_metadata_request_writes_zero_bytes_on_the_wire`
        // below for the assertion that actually pins the wire bytes.
        let decoded = request_round_trip(
            protocols::METADATA_V3,
            Request::MetaData(protocols::METADATA_V3),
        )
        .await;
        assert!(matches!(decoded, Request::MetaData(protocols::METADATA_V3)));
    }

    #[tokio::test]
    async fn a_metadata_request_writes_zero_bytes_on_the_wire() {
        // What the round-trip test above cannot catch: a peer sending the
        // spec's empty body would see exactly zero bytes, not the eleven a
        // varint-zero-plus-snappy-header framing used to put on the wire.
        let stream_protocol = StreamProtocol::new(protocols::METADATA_V3);
        let mut buffer = Cursor::new(Vec::new());
        codec()
            .write_request(
                &stream_protocol,
                &mut buffer,
                Request::MetaData(protocols::METADATA_V3),
            )
            .await
            .expect("writes");
        assert!(
            buffer.into_inner().is_empty(),
            "a MetaData request must write zero bytes, not a varint+snappy header"
        );
    }

    #[tokio::test]
    async fn read_request_does_not_block_on_a_truly_empty_metadata_stream() {
        // The regression this whole fix is about: a peer that actually sends
        // the spec's zero bytes must decode cleanly rather than hang
        // `read_varint` waiting for a length byte that will never arrive.
        // An empty buffer stands in for "the peer wrote nothing and closed",
        // which is exactly what `read_request` must accept without reading
        // past it.
        let stream_protocol = StreamProtocol::new(protocols::METADATA_V3);
        let mut buffer = Cursor::new(Vec::<u8>::new());
        let decoded = codec()
            .read_request(&stream_protocol, &mut buffer)
            .await
            .expect("reads a truly empty MetaData body");
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

    #[tokio::test]
    async fn a_by_root_column_request_round_trips() {
        let request = Request::DataColumnsByRoot(vec![DataColumnsByRootIdentifier {
            block_root: Root::repeat_byte(1),
            columns: ColumnIndices::try_from(vec![0, 3]).unwrap(),
        }]);
        let decoded = request_round_trip(protocols::DATA_COLUMN_SIDECARS_BY_ROOT_V1, request).await;
        match decoded {
            Request::DataColumnsByRoot(identifiers) => {
                assert_eq!(identifiers.len(), 1);
                assert_eq!(identifiers[0].columns.to_vec(), vec![0, 3]);
            }
            other => panic!("decoded as {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_by_range_column_request_round_trips() {
        let request = Request::DataColumnsByRange(DataColumnsByRangeRequest {
            start_slot: 10,
            count: 5,
            columns: ColumnIndices::try_from(vec![1, 2, 3]).unwrap(),
        });
        let decoded =
            request_round_trip(protocols::DATA_COLUMN_SIDECARS_BY_RANGE_V1, request).await;
        match decoded {
            Request::DataColumnsByRange(wire) => {
                assert_eq!(wire.start_slot, 10);
                assert_eq!(wire.count, 5);
                assert_eq!(wire.columns.to_vec(), vec![1, 2, 3]);
            }
            other => panic!("decoded as {other:?}"),
        }
    }

    /// A minimal sidecar naming `slot` and `index`; every other field is its
    /// type's default, since neither test below reads past what
    /// `write_data_column_sidecars_response` and
    /// `decode_data_column_sidecars_response` themselves touch: the slot
    /// (for the per-item context digest) and the index (to tell sidecars
    /// apart).
    fn data_column_sidecar(slot: u64, index: u64) -> fulu::DataColumnSidecar {
        fulu::DataColumnSidecar {
            index,
            column: Default::default(),
            kzg_commitments: Default::default(),
            kzg_proofs: Default::default(),
            signed_block_header: shared::SignedBeaconBlockHeader {
                message: shared::BeaconBlockHeader {
                    slot,
                    ..Default::default()
                },
                signature: Default::default(),
            },
            kzg_commitments_inclusion_proof: vec![
                Root::ZERO;
                preset::KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH
            ]
            .try_into()
            .expect("exactly the required depth"),
        }
    }

    /// Exercises `write_data_column_sidecars_response` into
    /// `decode_data_column_sidecars_response` directly, unlike
    /// [`a_by_range_column_request_round_trips`] and
    /// [`a_by_root_column_request_round_trips`] above, which only round-trip
    /// the thin SSZ-derive request wrappers and never touch this pair.
    ///
    /// The two sidecars straddle mainnet's altair fork boundary on purpose,
    /// so their digests actually differ: each chunk's `<context-bytes>` is
    /// derived from *that sidecar's own* slot
    /// (`write_data_column_sidecars_response`'s doc explains why — a
    /// backfill answer labels each chunk with its own fork), so an
    /// implementation that computed one digest for the whole response
    /// (from, say, the first sidecar's epoch) would still round-trip a
    /// batch that never crosses a fork boundary but fail this one.
    #[tokio::test]
    async fn a_data_column_sidecars_response_round_trips_with_a_per_item_context() {
        let sidecar_a = data_column_sidecar(3, 0);
        let post_altair_slot = Config::mainnet().altair_fork_epoch * preset::SLOTS_PER_EPOCH + 1;
        let sidecar_b = data_column_sidecar(post_altair_slot, 7);

        let decoded = response_round_trip(
            protocols::DATA_COLUMN_SIDECARS_BY_RANGE_V1,
            Response::success(ResponsePayload::DataColumnSidecars(vec![
                sidecar_a.clone(),
                sidecar_b.clone(),
            ])),
        )
        .await;

        match decoded {
            Response::Success {
                payload: ResponsePayload::DataColumnSidecars(sidecars),
            } => {
                assert_eq!(sidecars, vec![sidecar_a, sidecar_b]);
            }
            other => panic!("decoded as {other:?}"),
        }
    }

    /// A peer's `genesis_validators_root` differing from ours means every
    /// digest it labels a chunk with is for the wrong chain, even though the
    /// chunk decodes cleanly on its own. `decode_data_column_sidecars_response`
    /// checks the digest against what *this* node's own root implies, so
    /// reading the same bytes back through a codec built with a different
    /// root must abort the stream rather than hand back a sidecar under the
    /// wrong context — mirroring the block response's own fork-mismatch
    /// check, which nothing here exercised before.
    #[tokio::test]
    async fn a_data_column_sidecars_response_aborts_on_a_fork_digest_mismatch() {
        let sidecar = data_column_sidecar(3, 0);
        let stream_protocol = StreamProtocol::new(protocols::DATA_COLUMN_SIDECARS_BY_RANGE_V1);

        let mut buffer = Cursor::new(Vec::new());
        codec()
            .write_response(
                &stream_protocol,
                &mut buffer,
                Response::success(ResponsePayload::DataColumnSidecars(vec![sidecar])),
            )
            .await
            .expect("writes");

        let mut buffer = Cursor::new(buffer.into_inner());
        let mut mismatched_gvr_codec = Codec::beacon(BeaconContext {
            config: Config::mainnet(),
            genesis_validators_root: Root::repeat_byte(0xee),
        });
        let result = mismatched_gvr_codec
            .read_response(&stream_protocol, &mut buffer)
            .await;

        assert!(
            result.is_err(),
            "a fork digest mismatch must abort the stream rather than decode successfully"
        );
    }
}
