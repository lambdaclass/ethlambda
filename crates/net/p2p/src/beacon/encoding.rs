//! How this chain's request/response bodies go on and off the wire.
//!
//! The counterpart of [`crate::lean::encoding`]. Everything above these two
//! modules is shared: one `Request`, one `ResponsePayload`, one dispatch, one
//! set of handlers. Encoding is where the chains genuinely differ, so it is
//! where the split lives.
//!
//! The two block *requests* are not among the differences. What a peer is
//! asking for is the same question on either chain, so
//! [`crate::req_resp::Request`] carries one request for both wires: a shared
//! struct of its own for the range, which belongs to neither wire, and lean's
//! container for the root list, whose contents beacon sends bare. The
//! conversions below are the whole of what this wire adds: a deprecated `step`
//! on the range body, and no container around the root list. See
//! [`crate::req_resp::messages::Request`].
//!
//! Two things differ here. The first is **version dispatch**: `status` and
//! `metadata` carry a different container per negotiated version, and picking
//! the wrong one puts a short body on the wire. The second is
//! **`<context-bytes>`**: a block chunk names the fork its payload is shaped
//! for, because a `SignedBeaconBlock` has had seven shapes and SSZ carries no
//! type tag. Lean has neither.
//!
//! The context bytes follow the spec's rule verbatim: the epoch is
//! `compute_epoch_at_slot(signed_beacon_block.message.slot)`, and the digest is
//! `compute_fork_digest(genesis_validators_root, epoch)` at that epoch. It is
//! computed per chunk rather than looked up in a per-fork table, because from
//! fulu on the digest also moves at every blob-schedule boundary, so a fork
//! name alone does not determine it. The two data column sidecar protocols
//! share this exact rule, keyed off `signed_block_header.message.slot` rather
//! than a block's own slot, since a sidecar carries a header rather than a
//! full block.

use std::io;

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::containers::DataColumnSidecar;
use ethlambda_types::beacon::containers::SignedBeaconBlock;
use ethlambda_types::beacon::fork_digest::compute_fork_digest;
use ethlambda_types::beacon::preset;
use ethlambda_types::beacon::primitives::Root;
use libp2p::futures::{AsyncRead, AsyncWrite};
use libssz::{SszDecode, SszEncode};
use tracing::warn;

use super::decode;
use super::fork_schedule::ForkSchedule;
use super::messages::{
    BeaconBlocksByRangeRequest, BeaconMetaData, BeaconStatus, MetaDataV1, MetaDataV2, MetaDataV3,
    StatusV1, StatusV2,
};
use super::protocols::{self, MAX_REQUEST_BLOCKS_DENEB};
use crate::req_resp::codec::write_success_chunk;
use crate::req_resp::encoding::{ChunkLimits, MAX_PAYLOAD_SIZE, invalid, read_chunked_response};
use crate::req_resp::messages::BlocksByRangeRequest;

/// This chain's wire body for a slot window. Every field is shared, since this
/// is the wire the shared request's `step` exists for.
impl From<&BlocksByRangeRequest> for BeaconBlocksByRangeRequest {
    fn from(request: &BlocksByRangeRequest) -> Self {
        Self {
            start_slot: request.start_slot,
            count: request.count,
            step: request.step,
        }
    }
}

/// The shared request a wire body describes.
///
/// `step` is carried through rather than validated here. The spec deprecates it
/// and says a requester MUST set it to 1, but a peer that gets that wrong
/// deserves to be told which rule it broke, and only a handler holding the
/// response channel can say so; refusing at decode drops the stream instead.
/// See `handle_beacon_blocks_by_range_request`.
impl From<BeaconBlocksByRangeRequest> for BlocksByRangeRequest {
    fn from(wire: BeaconBlocksByRangeRequest) -> Self {
        Self {
            start_slot: wire.start_slot,
            count: wire.count,
            step: wire.step,
        }
    }
}

/// Encode a `Status` for the negotiated protocol version.
///
/// A version mismatch is an error rather than a conversion: a v1 value written
/// on a v2 stream would be eight bytes short and the peer would read a
/// truncated container, which is worse than a refused write.
pub fn encode_status(protocol: &str, status: &BeaconStatus) -> io::Result<Vec<u8>> {
    match (protocol, status) {
        (protocols::STATUS_V1, BeaconStatus::V1(status)) => Ok(status.to_ssz()),
        (protocols::STATUS_V2, BeaconStatus::V2(status)) => Ok(status.to_ssz()),
        _ => Err(invalid(format!(
            "status version does not match protocol {protocol}"
        ))),
    }
}

pub fn decode_status(protocol: &str, payload: &[u8]) -> io::Result<BeaconStatus> {
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

pub fn encode_metadata(protocol: &str, metadata: &BeaconMetaData) -> io::Result<Vec<u8>> {
    match (protocol, metadata) {
        (protocols::METADATA_V1, BeaconMetaData::V1(value)) => Ok(value.to_ssz()),
        (protocols::METADATA_V2, BeaconMetaData::V2(value)) => Ok(value.to_ssz()),
        (protocols::METADATA_V3, BeaconMetaData::V3(value)) => Ok(value.to_ssz()),
        _ => Err(invalid(format!(
            "metadata version does not match protocol {protocol}"
        ))),
    }
}

pub fn decode_metadata(protocol: &str, payload: &[u8]) -> io::Result<BeaconMetaData> {
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

/// Write a block response: one result code, one `ForkDigest` and one payload per
/// block.
///
/// The counterpart of [`crate::lean::encoding::write_blocks_response`], and the
/// same shape apart from the four context bytes. Each block is encoded before
/// its code byte goes out, so an oversized block is skipped rather than leaving
/// a SUCCESS byte on the wire with no payload behind it. An empty response is a
/// stream that just ends, which is the honest answer for a range this node does
/// not hold.
pub async fn write_blocks_response<T>(
    io: &mut T,
    label: &'static str,
    config: &Config,
    genesis_validators_root: Root,
    blocks: &[SignedBeaconBlock],
) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    for block in blocks {
        let encoded = block.to_ssz();
        if encoded.len() > MAX_PAYLOAD_SIZE - 1024 {
            warn!(
                slot = block.slot(),
                size = encoded.len(),
                "Skipping oversized block in beacon block response"
            );
            continue;
        }
        // The block's own epoch, not the one this node runs on, so a backfill
        // labels each chunk with its own fork.
        let epoch = block.slot() / preset::SLOTS_PER_EPOCH;
        let digest = compute_fork_digest(config, genesis_validators_root, epoch);
        write_success_chunk(io, label, &digest, encoded).await?;
    }
    Ok(())
}

/// Read a block response: one `SignedBeaconBlock` per chunk, until the peer
/// closes.
///
/// The fork a chunk decodes under comes from the **slot inside the payload**,
/// through the same [`decode::decode_block`] the gossip path uses, rather than
/// from the context bytes. The context bytes are then checked against the digest
/// that slot implies, which is a stronger test than using them as the decoder
/// key would be: it catches a peer whose `genesis_validators_root` or fork
/// schedule differs from ours, which is exactly what the digest exists to say
/// and is not otherwise visible until a signature fails.
///
/// A mismatch ends the stream rather than skipping the chunk. A peer past the
/// handshake already agreed with us about the *current* digest, so disagreeing
/// about a historical one means its schedule or its chain is not ours, and none
/// of what it sent is worth keeping. It is logged at `warn` with both digests,
/// because the one way to reach it in good faith is a blob schedule of ours that
/// has fallen behind the network's.
pub async fn decode_blocks_response<T>(
    io: &mut T,
    protocol_label: &str,
    config: &Config,
    genesis_validators_root: Root,
) -> io::Result<Vec<SignedBeaconBlock>>
where
    T: AsyncRead + Unpin + Send,
{
    let limits = ChunkLimits {
        has_context: true,
        // The deneb ceiling rather than the phase0 one, because it bounds what
        // *this* node asks for and nothing else opens one of these streams.
        max_chunks: MAX_REQUEST_BLOCKS_DENEB as usize,
    };
    read_chunked_response(io, protocol_label, limits, |context, payload| {
        let block = decode::decode_block(config, payload)
            .map_err(|err| invalid(format!("beacon block chunk: {err}")))?;
        let epoch = block.slot() / preset::SLOTS_PER_EPOCH;
        let expected = compute_fork_digest(config, genesis_validators_root, epoch);
        if context != expected {
            warn!(
                slot = block.slot(),
                fork = %block.fork_name(),
                peer_context = %hex::encode(context),
                our_context = %hex::encode(expected),
                "Beacon block chunk names another fork digest"
            );
            return Err(invalid(format!(
                "block chunk context {} does not match {} for slot {}",
                hex::encode(context),
                hex::encode(expected),
                block.slot(),
            )));
        }
        Ok(block)
    })
    .await
}

/// Write a data column sidecar response: one result code, one `ForkDigest` and
/// one payload per sidecar.
///
/// The counterpart of [`write_blocks_response`] for the two column protocols,
/// and the same shape apart from what is being encoded. Each sidecar is
/// encoded before its code byte goes out, so an oversized one is skipped
/// rather than leaving a SUCCESS byte on the wire with no payload behind it.
/// An empty response is a stream that just ends, which is the honest answer
/// for a request this node holds nothing for.
pub async fn write_data_column_sidecars_response<T>(
    io: &mut T,
    label: &'static str,
    config: &Config,
    genesis_validators_root: Root,
    sidecars: &[DataColumnSidecar],
) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    for sidecar in sidecars {
        let encoded = sidecar.to_ssz();
        if encoded.len() > MAX_PAYLOAD_SIZE - 1024 {
            warn!(
                index = sidecar.index(),
                size = encoded.len(),
                "Skipping oversized data column sidecar in response"
            );
            continue;
        }
        // The sidecar's own epoch rather than the one this node runs on, so a
        // backfill labels each chunk with its own fork.
        let epoch = sidecar.slot() / preset::SLOTS_PER_EPOCH;
        let digest = compute_fork_digest(config, genesis_validators_root, epoch);
        write_success_chunk(io, label, &digest, encoded).await?;
    }
    Ok(())
}

/// Read a data column sidecar response: one `DataColumnSidecar` per chunk,
/// until the peer closes.
///
/// The counterpart of [`decode_blocks_response`]. A gloas sidecar carries no
/// header to read a slot from ahead of decoding, so the fork comes from the
/// chunk's context bytes instead ([`ForkSchedule::fork_for_digest`]), and
/// [`super::decode::decode_data_column_sidecar`] decodes by it. A digest no
/// scheduled fork uses ends the stream like any other mismatch. The context
/// bytes are then checked against the digest the sidecar's own slot implies,
/// for the same reason a block chunk's are: it catches a peer whose
/// `genesis_validators_root` or fork schedule differs from ours, which a
/// signature failure would otherwise be the only way to notice. It also
/// catches a sidecar of one fork's shape sent under another's context.
///
/// A mismatch ends the stream rather than skipping the chunk, matching
/// [`decode_blocks_response`]: a peer that disagrees about a historical digest
/// after having agreed about the current one during the handshake is not
/// running our schedule, and nothing else it sent is worth keeping.
pub async fn decode_data_column_sidecars_response<T>(
    io: &mut T,
    protocol_label: &str,
    config: &Config,
    genesis_validators_root: Root,
) -> io::Result<Vec<DataColumnSidecar>>
where
    T: AsyncRead + Unpin + Send,
{
    let limits = ChunkLimits {
        has_context: true,
        // The widest a single request can legitimately ask for, on either
        // column protocol; see `protocols::max_request_data_column_sidecars`.
        max_chunks: protocols::max_request_data_column_sidecars() as usize,
    };
    let schedule = ForkSchedule::new(config, genesis_validators_root);
    read_chunked_response(io, protocol_label, limits, |context, payload| {
        let Some(fork) = <[u8; 4]>::try_from(context)
            .ok()
            .and_then(|digest| schedule.fork_for_digest(digest))
        else {
            return Err(invalid(format!(
                "data column sidecar chunk context {} is no scheduled fork digest",
                hex::encode(context),
            )));
        };
        let sidecar = decode::decode_data_column_sidecar(fork, payload)
            .map_err(|err| invalid(format!("data column sidecar chunk: {err}")))?;
        let slot = sidecar.slot();
        let expected = schedule.digest_at(slot / preset::SLOTS_PER_EPOCH);
        if context != expected {
            warn!(
                slot,
                index = sidecar.index(),
                peer_context = %hex::encode(context),
                our_context = %hex::encode(expected),
                "Data column sidecar chunk names another fork digest"
            );
            return Err(invalid(format!(
                "data column sidecar chunk context {} does not match {} for slot {}",
                hex::encode(context),
                hex::encode(expected),
                slot,
            )));
        }
        Ok(sidecar)
    })
    .await
}
