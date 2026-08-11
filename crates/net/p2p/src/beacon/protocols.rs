//! The request/response protocols `ethlambda beacon` registers.
//!
//! Registered by direction, following the same subscribe-only-what-you-consume
//! rule the topics follow. `beacon_blocks_by_{range,root}/2` are registered
//! outbound now that the anchor-to-head fetch calls them. The sidecar protocols
//! stay absent: nothing consumes them, and an unregistered protocol is refused
//! at stream negotiation rather than answered with a lie.

use libp2p::StreamProtocol;
use libp2p::request_response::ProtocolSupport;

pub const STATUS_V1: &str = "/eth2/beacon_chain/req/status/1/ssz_snappy";
pub const STATUS_V2: &str = "/eth2/beacon_chain/req/status/2/ssz_snappy";
pub const PING_V1: &str = "/eth2/beacon_chain/req/ping/1/ssz_snappy";
pub const METADATA_V1: &str = "/eth2/beacon_chain/req/metadata/1/ssz_snappy";
pub const METADATA_V2: &str = "/eth2/beacon_chain/req/metadata/2/ssz_snappy";
pub const METADATA_V3: &str = "/eth2/beacon_chain/req/metadata/3/ssz_snappy";
pub const GOODBYE_V1: &str = "/eth2/beacon_chain/req/goodbye/1/ssz_snappy";
pub const BEACON_BLOCKS_BY_RANGE_V2: &str =
    "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy";
pub const BEACON_BLOCKS_BY_ROOT_V2: &str =
    "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy";

/// The protocols this node registers, with the direction it supports each in.
///
/// `goodbye/1` is inbound only: this node logs the reason code a peer sends and
/// never sends one itself, because it has no opinion worth disconnecting over.
///
/// The two block protocols are **outbound only**: this node asks for blocks to
/// close the anchor-to-head gap, and serves none. It cannot honestly serve
/// them, because checkpoint sync leaves it with nothing below its anchor, and
/// answering a range request with a short response is worse for the asking peer
/// than declining the stream outright.
///
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
            StreamProtocol::new(BEACON_BLOCKS_BY_RANGE_V2),
            ProtocolSupport::Outbound,
        ),
        (
            StreamProtocol::new(BEACON_BLOCKS_BY_ROOT_V2),
            ProtocolSupport::Outbound,
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
        BEACON_BLOCKS_BY_RANGE_V2 => Some("beacon_blocks_by_range_v2"),
        BEACON_BLOCKS_BY_ROOT_V2 => Some("beacon_blocks_by_root_v2"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_ids_are_the_mainnet_strings() {
        // Read verbatim off the mainnet_gossip probe binary, which completed
        // the handshake against live mainnet clients with exactly these.
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
    fn goodbye_is_inbound_only() {
        let goodbye = registrations()
            .into_iter()
            .find(|(protocol, _)| protocol.as_ref() == GOODBYE_V1)
            .expect("goodbye is registered");
        assert!(matches!(goodbye.1, ProtocolSupport::Inbound));
    }

    #[test]
    fn no_sidecar_protocol_is_registered() {
        // Still deliberate: nothing consumes the sidecars, and a registered
        // protocol with no caller is an untested encoder that peers can reach.
        //
        // The two block protocols used to be on this list. They came off it
        // when the anchor-to-head fetch landed, which is the event the original
        // test was scoped to wait for; the sidecar half of its intent is
        // unchanged, and `the_block_protocols_are_registered_outbound` below
        // now pins the other half from the opposite side.
        let absent = [
            "blob_sidecars_by_range",
            "blob_sidecars_by_root",
            "data_column_sidecars_by_range",
            "data_column_sidecars_by_root",
        ];
        for (protocol, _) in registrations() {
            for name in absent {
                assert!(
                    !protocol.as_ref().contains(name),
                    "{protocol} must not be registered"
                );
            }
        }
    }

    #[test]
    fn the_block_protocols_are_registered_outbound() {
        // Verified against consensus-specs specs/deneb/p2p-interface.md, which
        // gives both protocol ids; the `ssz_snappy` suffix is the encoding
        // strategy every mainnet client negotiates.
        assert_eq!(
            BEACON_BLOCKS_BY_RANGE_V2,
            "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy"
        );
        assert_eq!(
            BEACON_BLOCKS_BY_ROOT_V2,
            "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy"
        );

        for id in [BEACON_BLOCKS_BY_RANGE_V2, BEACON_BLOCKS_BY_ROOT_V2] {
            let (_, support) = registrations()
                .into_iter()
                .find(|(protocol, _)| protocol.as_ref() == id)
                .unwrap_or_else(|| panic!("{id} is registered"));
            assert!(
                matches!(support, ProtocolSupport::Outbound),
                "{id} is requested, never served: a checkpoint-synced node has \
                 nothing below its anchor to answer with"
            );
        }
    }
}
