//! The request/response protocols `ethlambda beacon` registers.
//!
//! Registered by direction, following the same subscribe-only-what-you-consume
//! rule the topics follow. The two data column sidecar protocols are
//! registered because this node custodies the columns its node id selects
//! (`BeaconWire::custody_columns`) and can answer for them out of
//! `Table::DataColumns`. The blob sidecar protocols stay absent: nothing here
//! custodies a whole blob, only the erasure-coded columns fulu derives it
//! into, and an unregistered protocol is still refused at stream negotiation
//! rather than answered with a lie.
//!
//! The two gloas execution payload envelope protocols are registered for the
//! same reason the column ones are: the server side answers out of
//! `Table::ExecutionPayloadEnvelopes`. Nothing requests them yet.
//!
//! Heze's `inclusion_lists_by_indices/1` is registered inbound only: the
//! server side answers out of the inclusion list store, and this node sends no
//! such request yet, so it does not offer the outbound half.
//!
//! Only version 2 of the two block protocols is registered. Version 1 is
//! deprecated by the spec, which lets a client answer it with an empty list,
//! and its chunks carry no `<context-bytes>`, so serving it would mean a second
//! encoder for a shape no mainnet peer needs.

use ethlambda_types::beacon::preset;
use libp2p::StreamProtocol;
use libp2p::request_response::ProtocolSupport;

pub const STATUS_V1: &str = "/eth2/beacon_chain/req/status/1/ssz_snappy";
pub const STATUS_V2: &str = "/eth2/beacon_chain/req/status/2/ssz_snappy";
pub const PING_V1: &str = "/eth2/beacon_chain/req/ping/1/ssz_snappy";
pub const METADATA_V1: &str = "/eth2/beacon_chain/req/metadata/1/ssz_snappy";
pub const METADATA_V2: &str = "/eth2/beacon_chain/req/metadata/2/ssz_snappy";
pub const METADATA_V3: &str = "/eth2/beacon_chain/req/metadata/3/ssz_snappy";
pub const GOODBYE_V1: &str = "/eth2/beacon_chain/req/goodbye/1/ssz_snappy";
pub const BLOCKS_BY_RANGE_V2: &str = "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy";
pub const BLOCKS_BY_ROOT_V2: &str = "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy";
pub const DATA_COLUMN_SIDECARS_BY_RANGE_V1: &str =
    "/eth2/beacon_chain/req/data_column_sidecars_by_range/1/ssz_snappy";
pub const DATA_COLUMN_SIDECARS_BY_ROOT_V1: &str =
    "/eth2/beacon_chain/req/data_column_sidecars_by_root/1/ssz_snappy";
pub const EXECUTION_PAYLOAD_ENVELOPES_BY_RANGE_V1: &str =
    "/eth2/beacon_chain/req/execution_payload_envelopes_by_range/1/ssz_snappy";
pub const EXECUTION_PAYLOAD_ENVELOPES_BY_ROOT_V1: &str =
    "/eth2/beacon_chain/req/execution_payload_envelopes_by_root/1/ssz_snappy";
pub const INCLUSION_LISTS_BY_INDICES_V1: &str =
    "/eth2/beacon_chain/req/inclusion_lists_by_indices/1/ssz_snappy";

/// `MAX_REQUEST_INCLUSION_LIST`: the ceiling on one `InclusionListsByIndices`
/// answer. The request's `indices` is a bitvector over the sixteen-member
/// committee, so it can never ask for more.
pub const MAX_REQUEST_INCLUSION_LIST: u64 = 16;

/// `MAX_REQUEST_PAYLOADS`: the ceiling on either gloas envelope request, and
/// on the list a response carries.
pub const MAX_REQUEST_PAYLOADS: u64 = 128;

/// `MAX_REQUEST_BLOCKS`: the ceiling phase0 put on either block request.
///
/// This is what an inbound request is *judged* against, because it is the
/// widest a peer may ever legitimately have been built to ask for.
pub const MAX_REQUEST_BLOCKS: u64 = 1024;

/// `MAX_REQUEST_BLOCKS_DENEB`: the ceiling from deneb on, and so the real one
/// on any live network.
///
/// This is what an outbound request is *built* to, and what an answer is
/// truncated to. Kept separate from [`MAX_REQUEST_BLOCKS`] rather than
/// collapsed into it, because the two ceilings answer different questions:
/// asking for more than this is a protocol violation, while *receiving* a
/// request for more than this is only a peer running pre-deneb logic. The spec
/// allows "Clients MAY limit the number of blocks in the response", so that
/// peer is answered with this many rather than refused.
pub const MAX_REQUEST_BLOCKS_DENEB: u64 = 128;

// Everything this node sends is built to the deneb ceiling and everything it
// serves is truncated to it, while an inbound request is judged against the
// phase0 one. Reversing the two would put every outbound request over the limit
// the peer enforces, so it is refused at compile time rather than in a test.
const _: () = assert!(
    MAX_REQUEST_BLOCKS_DENEB < MAX_REQUEST_BLOCKS,
    "the ceiling requests are built to has to fit inside the one they are judged against"
);

/// `max_request_data_column_sidecars`: the ceiling on one request.
///
/// Every column of every block a peer may ask for at once. Answers are
/// truncated to it rather than refused, the same way the block protocols treat
/// a peer asking past the deneb ceiling.
pub fn max_request_data_column_sidecars() -> u64 {
    MAX_REQUEST_BLOCKS_DENEB * preset::NUMBER_OF_COLUMNS as u64
}

/// The protocols this node registers, with the direction it supports each in.
///
/// `goodbye/1` is inbound only: this node logs the reason code a peer sends and
/// never sends one itself, because it has no opinion worth disconnecting over.
/// Everything else is bidirectional, since the handshake runs in both
/// directions on every connection.
pub fn registrations() -> Vec<(StreamProtocol, ProtocolSupport)> {
    vec![
        (StreamProtocol::new(STATUS_V1), ProtocolSupport::Full),
        (StreamProtocol::new(STATUS_V2), ProtocolSupport::Full),
        (StreamProtocol::new(PING_V1), ProtocolSupport::Full),
        (StreamProtocol::new(METADATA_V1), ProtocolSupport::Full),
        (StreamProtocol::new(METADATA_V2), ProtocolSupport::Full),
        (StreamProtocol::new(METADATA_V3), ProtocolSupport::Full),
        (StreamProtocol::new(GOODBYE_V1), ProtocolSupport::Inbound),
        (
            StreamProtocol::new(BLOCKS_BY_RANGE_V2),
            ProtocolSupport::Full,
        ),
        (
            StreamProtocol::new(BLOCKS_BY_ROOT_V2),
            ProtocolSupport::Full,
        ),
        (
            StreamProtocol::new(DATA_COLUMN_SIDECARS_BY_RANGE_V1),
            ProtocolSupport::Full,
        ),
        (
            StreamProtocol::new(DATA_COLUMN_SIDECARS_BY_ROOT_V1),
            ProtocolSupport::Full,
        ),
        (
            StreamProtocol::new(EXECUTION_PAYLOAD_ENVELOPES_BY_RANGE_V1),
            ProtocolSupport::Full,
        ),
        (
            StreamProtocol::new(EXECUTION_PAYLOAD_ENVELOPES_BY_ROOT_V1),
            ProtocolSupport::Full,
        ),
        (
            StreamProtocol::new(INCLUSION_LISTS_BY_INDICES_V1),
            ProtocolSupport::Inbound,
        ),
    ]
}

/// Short label for the `protocol` dimension on req/resp size metrics.
pub fn label(protocol: &str) -> Option<&'static str> {
    match protocol {
        STATUS_V1 => Some("beacon_status_v1"),
        STATUS_V2 => Some("beacon_status_v2"),
        PING_V1 => Some("beacon_ping"),
        METADATA_V1 => Some("beacon_metadata_v1"),
        METADATA_V2 => Some("beacon_metadata_v2"),
        METADATA_V3 => Some("beacon_metadata_v3"),
        GOODBYE_V1 => Some("beacon_goodbye"),
        BLOCKS_BY_RANGE_V2 => Some("beacon_blocks_by_range_v2"),
        BLOCKS_BY_ROOT_V2 => Some("beacon_blocks_by_root_v2"),
        DATA_COLUMN_SIDECARS_BY_RANGE_V1 => Some("beacon_data_column_sidecars_by_range"),
        DATA_COLUMN_SIDECARS_BY_ROOT_V1 => Some("beacon_data_column_sidecars_by_root"),
        EXECUTION_PAYLOAD_ENVELOPES_BY_RANGE_V1 => {
            Some("beacon_execution_payload_envelopes_by_range")
        }
        EXECUTION_PAYLOAD_ENVELOPES_BY_ROOT_V1 => {
            Some("beacon_execution_payload_envelopes_by_root")
        }
        INCLUSION_LISTS_BY_INDICES_V1 => Some("beacon_inclusion_lists_by_indices"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_ids_are_the_mainnet_strings() {
        // Read verbatim off a throwaway probe binary that completed the
        // handshake against live mainnet clients with exactly these strings.
        assert_eq!(STATUS_V1, "/eth2/beacon_chain/req/status/1/ssz_snappy");
        assert_eq!(STATUS_V2, "/eth2/beacon_chain/req/status/2/ssz_snappy");
        assert_eq!(PING_V1, "/eth2/beacon_chain/req/ping/1/ssz_snappy");
        assert_eq!(METADATA_V2, "/eth2/beacon_chain/req/metadata/2/ssz_snappy");
        assert_eq!(METADATA_V3, "/eth2/beacon_chain/req/metadata/3/ssz_snappy");
        assert_eq!(GOODBYE_V1, "/eth2/beacon_chain/req/goodbye/1/ssz_snappy");
    }

    #[test]
    fn every_registration_has_a_metric_label() {
        for (protocol, _) in registrations() {
            assert!(
                label(protocol.as_ref()).is_some(),
                "{protocol} has no metric label"
            );
        }
    }

    #[test]
    fn the_sidecar_protocol_ids_are_the_mainnet_strings() {
        assert_eq!(
            DATA_COLUMN_SIDECARS_BY_ROOT_V1,
            "/eth2/beacon_chain/req/data_column_sidecars_by_root/1/ssz_snappy"
        );
        assert_eq!(
            DATA_COLUMN_SIDECARS_BY_RANGE_V1,
            "/eth2/beacon_chain/req/data_column_sidecars_by_range/1/ssz_snappy"
        );
    }

    #[test]
    fn the_envelope_protocol_ids_are_the_spec_strings() {
        assert_eq!(
            EXECUTION_PAYLOAD_ENVELOPES_BY_RANGE_V1,
            "/eth2/beacon_chain/req/execution_payload_envelopes_by_range/1/ssz_snappy"
        );
        assert_eq!(
            EXECUTION_PAYLOAD_ENVELOPES_BY_ROOT_V1,
            "/eth2/beacon_chain/req/execution_payload_envelopes_by_root/1/ssz_snappy"
        );
    }

    #[test]
    fn the_inclusion_list_protocol_id_is_the_spec_string() {
        assert_eq!(
            INCLUSION_LISTS_BY_INDICES_V1,
            "/eth2/beacon_chain/req/inclusion_lists_by_indices/1/ssz_snappy"
        );
    }

    #[test]
    fn inclusion_lists_by_indices_is_inbound_only() {
        let registration = registrations()
            .into_iter()
            .find(|(protocol, _)| protocol.as_ref() == INCLUSION_LISTS_BY_INDICES_V1)
            .expect("inclusion_lists_by_indices is registered");
        assert!(matches!(registration.1, ProtocolSupport::Inbound));
    }

    #[test]
    fn a_sidecar_request_is_bounded_by_the_block_ceiling_times_the_columns() {
        assert_eq!(
            max_request_data_column_sidecars(),
            MAX_REQUEST_BLOCKS_DENEB * ethlambda_types::beacon::preset::NUMBER_OF_COLUMNS as u64
        );
    }

    #[test]
    fn goodbye_is_inbound_only() {
        let goodbye = registrations()
            .into_iter()
            .find(|(protocol, _)| protocol.as_ref() == GOODBYE_V1)
            .expect("goodbye is registered");
        assert!(matches!(goodbye.1, ProtocolSupport::Inbound));
    }
}
