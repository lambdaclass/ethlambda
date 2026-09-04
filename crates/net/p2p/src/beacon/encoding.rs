//! How this chain's request/response bodies go on and off the wire.
//!
//! The counterpart of [`crate::lean::encoding`]. Everything above these two
//! modules is shared: one `Request`, one `ResponsePayload`, one dispatch, one
//! set of handlers. Encoding is where the chains genuinely differ, so it is
//! where the split lives.
//!
//! What differs here is **version dispatch**: `status` and `metadata` carry a
//! different container per negotiated version, and picking the wrong one puts a
//! short body on the wire. Lean has no versions and no equivalent of this file's
//! `(protocol, container)` matching.

use std::io;

use libssz::{SszDecode, SszEncode};

use super::messages::{
    BeaconMetaData, BeaconStatus, Goodbye, MetaDataV1, MetaDataV2, MetaDataV3, Ping, StatusV1,
    StatusV2,
};
use super::protocols;
use crate::req_resp::encoding::invalid;

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

/// Encode a `ping/1` body. Versionless, unlike the two above.
pub fn encode_ping(ping: &Ping) -> Vec<u8> {
    ping.to_ssz()
}

/// Encode a `goodbye/1` body. Versionless, unlike the two above.
pub fn encode_goodbye(goodbye: &Goodbye) -> Vec<u8> {
    goodbye.to_ssz()
}
