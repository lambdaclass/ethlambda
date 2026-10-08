//! The request/response side of the swarm: one `request_response::Behaviour`
//! per protocol id, plus the construction that decides which of them register
//! a protocol at all.

use libp2p::{StreamProtocol, request_response, swarm::NetworkBehaviour};

use crate::{
    WireConfig, beacon,
    lean::protocols::{
        BLOCKS_BY_RANGE_V1 as BLOCKS_BY_RANGE_PROTOCOL_V1,
        BLOCKS_BY_ROOT_V1 as BLOCKS_BY_ROOT_PROTOCOL_V1, STATUS_V1 as STATUS_PROTOCOL_V1,
    },
    req_resp::Codec,
};

/// Every request/response protocol this node can speak, one
/// `request_response::Behaviour<Codec>` field per protocol id.
///
/// A field per id, rather than one field registering every id: a shared
/// behaviour hands an outbound request to a positional FIFO queue
/// (`requested_outbound` in the pinned fork's
/// `protocols/request-response/src/handler.rs`) that is drained in
/// substream-negotiation order, not send order, so two requests on different
/// protocols sent back to back on one connection can be matched to each
/// other's substreams once their negotiations complete out of order. A field
/// per protocol makes that structurally unreachable: `NetworkBehaviour`'s
/// derive nests each field's `ConnectionHandler` behind
/// `ConnectionHandlerSelect`, which offers the union of every child's protocol
/// ids to multistream-select and routes a negotiated substream back to exactly
/// the one child that offered it (`swarm/src/handler/select.rs`), so each
/// field's own FIFO queue only ever sees requests sent on its own one
/// protocol. Nesting this whole struct as a single field of
/// [`crate::Behaviour`] keeps that: the outer derive selects into this one,
/// and this one selects into its fourteen.
///
/// Each field is built with either its real, one-entry protocol list or an
/// empty one, decided by the [`WireConfig`] [`ReqResp::new`] is handed: a lean
/// node's beacon-only fields, and a beacon node's lean-only fields, register
/// nothing, so the aggregate multistream-select offer a peer sees is exactly
/// the protocol set for this node's own wire, unchanged from before the split.
/// See [`crate::ReqRespProtocol`], which names these fields for anything that
/// needs to pick one at runtime (sending a request, or tagging an inbound
/// event with the field it arrived on).
///
/// The fields are `pub(crate)` because picking one by
/// [`crate::ReqRespProtocol`] is what sending a request means; see
/// `execute_command` in `swarm_adapter.rs`.
#[derive(NetworkBehaviour)]
pub(crate) struct ReqResp {
    pub(crate) lean_status: request_response::Behaviour<Codec>,
    pub(crate) lean_blocks_by_root: request_response::Behaviour<Codec>,
    pub(crate) lean_blocks_by_range: request_response::Behaviour<Codec>,
    pub(crate) beacon_status_v1: request_response::Behaviour<Codec>,
    pub(crate) beacon_status_v2: request_response::Behaviour<Codec>,
    pub(crate) beacon_ping: request_response::Behaviour<Codec>,
    pub(crate) beacon_metadata_v1: request_response::Behaviour<Codec>,
    pub(crate) beacon_metadata_v2: request_response::Behaviour<Codec>,
    pub(crate) beacon_metadata_v3: request_response::Behaviour<Codec>,
    pub(crate) beacon_goodbye: request_response::Behaviour<Codec>,
    pub(crate) beacon_blocks_by_range: request_response::Behaviour<Codec>,
    pub(crate) beacon_blocks_by_root: request_response::Behaviour<Codec>,
    pub(crate) data_column_sidecars_by_range: request_response::Behaviour<Codec>,
    pub(crate) data_column_sidecars_by_root: request_response::Behaviour<Codec>,
}

impl ReqResp {
    /// One `with_codec` call per field, each registering at most the one
    /// protocol its field is named for.
    ///
    /// The codec is built by the caller rather than here: the two beacon block
    /// protocols frame their chunks against the fork schedule and the chain,
    /// so whatever decides that those protocols are registered has to decide
    /// that the context is there. See [`Codec`].
    pub(crate) fn new(codec: Codec, wire: &WireConfig) -> Self {
        let is_lean = matches!(wire, WireConfig::Lean(_));
        let is_beacon = !is_lean;

        Self {
            lean_status: request_response::Behaviour::with_codec(
                codec.clone(),
                one_protocol(
                    is_lean,
                    STATUS_PROTOCOL_V1,
                    request_response::ProtocolSupport::Full,
                ),
                handshake_protocol_config(),
            ),
            lean_blocks_by_root: request_response::Behaviour::with_codec(
                codec.clone(),
                one_protocol(
                    is_lean,
                    BLOCKS_BY_ROOT_PROTOCOL_V1,
                    request_response::ProtocolSupport::Full,
                ),
                fetch_protocol_config(),
            ),
            lean_blocks_by_range: request_response::Behaviour::with_codec(
                codec.clone(),
                one_protocol(
                    is_lean,
                    BLOCKS_BY_RANGE_PROTOCOL_V1,
                    request_response::ProtocolSupport::Full,
                ),
                fetch_protocol_config(),
            ),
            beacon_status_v1: request_response::Behaviour::with_codec(
                codec.clone(),
                one_protocol(
                    is_beacon,
                    beacon::protocols::STATUS_V1,
                    request_response::ProtocolSupport::Full,
                ),
                handshake_protocol_config(),
            ),
            beacon_status_v2: request_response::Behaviour::with_codec(
                codec.clone(),
                one_protocol(
                    is_beacon,
                    beacon::protocols::STATUS_V2,
                    request_response::ProtocolSupport::Full,
                ),
                handshake_protocol_config(),
            ),
            beacon_ping: request_response::Behaviour::with_codec(
                codec.clone(),
                one_protocol(
                    is_beacon,
                    beacon::protocols::PING_V1,
                    request_response::ProtocolSupport::Full,
                ),
                handshake_protocol_config(),
            ),
            beacon_metadata_v1: request_response::Behaviour::with_codec(
                codec.clone(),
                one_protocol(
                    is_beacon,
                    beacon::protocols::METADATA_V1,
                    request_response::ProtocolSupport::Full,
                ),
                handshake_protocol_config(),
            ),
            beacon_metadata_v2: request_response::Behaviour::with_codec(
                codec.clone(),
                one_protocol(
                    is_beacon,
                    beacon::protocols::METADATA_V2,
                    request_response::ProtocolSupport::Full,
                ),
                handshake_protocol_config(),
            ),
            beacon_metadata_v3: request_response::Behaviour::with_codec(
                codec.clone(),
                one_protocol(
                    is_beacon,
                    beacon::protocols::METADATA_V3,
                    request_response::ProtocolSupport::Full,
                ),
                handshake_protocol_config(),
            ),
            // Inbound only: this node logs a peer's reason code and never
            // sends one itself. See `beacon::protocols::registrations`'s doc
            // comment.
            beacon_goodbye: request_response::Behaviour::with_codec(
                codec.clone(),
                one_protocol(
                    is_beacon,
                    beacon::protocols::GOODBYE_V1,
                    request_response::ProtocolSupport::Inbound,
                ),
                handshake_protocol_config(),
            ),
            beacon_blocks_by_range: request_response::Behaviour::with_codec(
                codec.clone(),
                one_protocol(
                    is_beacon,
                    beacon::protocols::BLOCKS_BY_RANGE_V2,
                    request_response::ProtocolSupport::Full,
                ),
                fetch_protocol_config(),
            ),
            beacon_blocks_by_root: request_response::Behaviour::with_codec(
                codec.clone(),
                one_protocol(
                    is_beacon,
                    beacon::protocols::BLOCKS_BY_ROOT_V2,
                    request_response::ProtocolSupport::Full,
                ),
                fetch_protocol_config(),
            ),
            data_column_sidecars_by_range: request_response::Behaviour::with_codec(
                codec.clone(),
                one_protocol(
                    is_beacon,
                    beacon::protocols::DATA_COLUMN_SIDECARS_BY_RANGE_V1,
                    request_response::ProtocolSupport::Full,
                ),
                fetch_protocol_config(),
            ),
            data_column_sidecars_by_root: request_response::Behaviour::with_codec(
                codec,
                one_protocol(
                    is_beacon,
                    beacon::protocols::DATA_COLUMN_SIDECARS_BY_ROOT_V1,
                    request_response::ProtocolSupport::Full,
                ),
                fetch_protocol_config(),
            ),
        }
    }
}

/// Per-connection concurrent-stream budget for a protocol whose exchange runs
/// once per connection lifetime (`status`, `ping`, `metadata`, `goodbye`).
///
/// Left at the request-response layer's own unmodified default, every one of
/// these fields would carry that same ceiling, which is sized for a single
/// shared behaviour speaking every protocol at once, not for one behaviour
/// per protocol: split across this many handshake-only fields plus the two
/// [`FETCH_MAX_CONCURRENT_STREAMS`] fields, the *aggregate* per-connection
/// budget would inflate well past what a handshake, sent once per connection,
/// ever needs open at a time. A retried handshake after `UnsupportedProtocols`
/// (see `retry_status_on_other_version`) is the only case that can ever hold
/// two of these open on one field at once, so this stays a small multiple of
/// that rather than the layer's own default.
const HANDSHAKE_MAX_CONCURRENT_STREAMS: usize = 8;

/// Per-connection concurrent-stream budget for a protocol that carries real
/// fetch traffic: both block protocols and both data column sidecar
/// protocols, on either wire.
///
/// Sized for a range-sync batch's request plus a handful of concurrent by-root
/// lookups (missing parents, missing columns) on the same connection, which is
/// comfortably under the request-response layer's own unmodified default. That
/// default is sized for one behaviour carrying every protocol's traffic, not
/// for one of the several fields these fetch protocols are now split across.
const FETCH_MAX_CONCURRENT_STREAMS: usize = 32;

/// The `request_response::Config` for a [`ReqResp`] field whose protocol is a
/// once-per-connection handshake. See [`HANDSHAKE_MAX_CONCURRENT_STREAMS`].
fn handshake_protocol_config() -> request_response::Config {
    request_response::Config::default()
        .with_max_concurrent_streams(HANDSHAKE_MAX_CONCURRENT_STREAMS)
}

/// The `request_response::Config` for a [`ReqResp`] field whose protocol
/// carries real fetch traffic. See [`FETCH_MAX_CONCURRENT_STREAMS`].
fn fetch_protocol_config() -> request_response::Config {
    request_response::Config::default().with_max_concurrent_streams(FETCH_MAX_CONCURRENT_STREAMS)
}

/// The protocol list for one [`ReqResp`] field: this protocol alone when
/// `active` (this node speaks the wire it belongs to), or none at all
/// otherwise.
///
/// Every field is built through this, on both wires, so a field that belongs
/// to the wire this node is *not* speaking is constructed with an empty list
/// rather than left out: [`ReqResp`] is one monomorphic struct for both wires
/// (see its doc comment), and an empty protocol list is what keeps that field
/// from ever being offered to a peer or accepting a request, which is the
/// whole of what "not speaking that wire" has to mean here.
fn one_protocol(
    active: bool,
    protocol: &'static str,
    support: request_response::ProtocolSupport,
) -> Vec<(StreamProtocol, request_response::ProtocolSupport)> {
    if active {
        vec![(StreamProtocol::new(protocol), support)]
    } else {
        Vec::new()
    }
}
