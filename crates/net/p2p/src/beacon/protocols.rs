//! The request/response protocols `ethlambda beacon` registers.
//!
//! Registered by direction, following the same subscribe-only-what-you-consume
//! rule the topics follow. `beacon_blocks_by_{range,root}/2` are deliberately
//! absent: nothing calls them until the anchor-to-head fetch lands, and an
//! unregistered protocol is refused at stream negotiation rather than answered
//! with a lie. The sidecar protocols are absent for the same reason.

use libp2p::StreamProtocol;
use libp2p::request_response::ProtocolSupport;

pub const STATUS_V1: &str = "/eth2/beacon_chain/req/status/1/ssz_snappy";
pub const STATUS_V2: &str = "/eth2/beacon_chain/req/status/2/ssz_snappy";
pub const PING_V1: &str = "/eth2/beacon_chain/req/ping/1/ssz_snappy";
pub const METADATA_V1: &str = "/eth2/beacon_chain/req/metadata/1/ssz_snappy";
pub const METADATA_V2: &str = "/eth2/beacon_chain/req/metadata/2/ssz_snappy";
pub const METADATA_V3: &str = "/eth2/beacon_chain/req/metadata/3/ssz_snappy";
pub const GOODBYE_V1: &str = "/eth2/beacon_chain/req/goodbye/1/ssz_snappy";

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
    fn no_block_or_sidecar_protocol_is_registered() {
        // Deliberate: nothing consumes them until the anchor-to-head fetch
        // lands, and a registered protocol with no caller is an untested
        // encoder that peers can reach.
        let absent = [
            "beacon_blocks_by_range",
            "beacon_blocks_by_root",
            "blob_sidecars_by_range",
            "blob_sidecars_by_root",
            "data_column_sidecars_by_range",
            "data_column_sidecars_by_root",
        ];
        for (protocol, _) in registrations() {
            for name in absent {
                assert!(
                    !protocol.as_ref().contains(name),
                    "{protocol} must not be registered yet"
                );
            }
        }
    }
}
