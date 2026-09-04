//! The beacon request/response payloads this node speaks.
//!
//! All fixed-size, so every one has an exact wire length. The tests assert
//! those lengths, which is what catches a reordered or mistyped field: SSZ has
//! no field names on the wire, so a swapped pair of same-width fields is
//! otherwise invisible until a peer disagrees about our chain.

use ethlambda_types::beacon::primitives::{Epoch, ForkDigest, Root, Slot};
use libssz_derive::{SszDecode, SszEncode};
use libssz_types::SszBitvector;

use super::constants::{ATTESTATION_SUBNET_COUNT, SYNC_COMMITTEE_SUBNET_COUNT};

/// `attnets`: which attestation subnets a node serves.
pub type AttnetsBits = SszBitvector<{ ATTESTATION_SUBNET_COUNT as usize }>;
/// `syncnets`: which sync committee subnets a node serves.
pub type SyncnetsBits = SszBitvector<SYNC_COMMITTEE_SUBNET_COUNT>;

/// `Status` v1: the pre-fulu handshake.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
pub struct StatusV1 {
    pub fork_digest: ForkDigest,
    pub finalized_root: Root,
    pub finalized_epoch: Epoch,
    pub head_root: Root,
    pub head_slot: Slot,
}

/// `Status` v2: v1 plus the oldest slot the peer can serve, which fulu adds so
/// a peer can advertise how far its backfill reaches.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
pub struct StatusV2 {
    pub fork_digest: ForkDigest,
    pub finalized_root: Root,
    pub finalized_epoch: Epoch,
    pub head_root: Root,
    pub head_slot: Slot,
    pub earliest_available_slot: Slot,
}

/// A `Status` in whichever version the negotiated protocol asked for.
///
/// The version is a property of the stream, not of the value, so it is carried
/// alongside the fields rather than being recovered from them: v1 and v2 differ
/// only by a trailing `uint64`, which SSZ cannot tell apart from a truncated
/// v2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeaconStatus {
    V1(StatusV1),
    V2(StatusV2),
}

impl BeaconStatus {
    pub fn fork_digest(&self) -> ForkDigest {
        match self {
            BeaconStatus::V1(status) => status.fork_digest,
            BeaconStatus::V2(status) => status.fork_digest,
        }
    }

    pub fn head_slot(&self) -> Slot {
        match self {
            BeaconStatus::V1(status) => status.head_slot,
            BeaconStatus::V2(status) => status.head_slot,
        }
    }

    pub fn finalized_epoch(&self) -> Epoch {
        match self {
            BeaconStatus::V1(status) => status.finalized_epoch,
            BeaconStatus::V2(status) => status.finalized_epoch,
        }
    }
}

/// `Ping`, and its response: a metadata sequence number, so a peer can tell
/// whether the `MetaData` it holds for us is stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SszEncode, SszDecode)]
pub struct Ping {
    pub seq_number: u64,
}

/// `Goodbye`: a reason code. This node only ever receives one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SszEncode, SszDecode)]
pub struct Goodbye {
    pub reason: u64,
}

/// `MetaData` v1: phase0.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
pub struct MetaDataV1 {
    pub seq_number: u64,
    pub attnets: AttnetsBits,
}

/// `MetaData` v2: altair adds the sync committee subnets.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
pub struct MetaDataV2 {
    pub seq_number: u64,
    pub attnets: AttnetsBits,
    pub syncnets: SyncnetsBits,
}

/// `MetaData` v3: fulu adds the custody group count.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
pub struct MetaDataV3 {
    pub seq_number: u64,
    pub attnets: AttnetsBits,
    pub syncnets: SyncnetsBits,
    pub custody_group_count: u64,
}

/// A `MetaData` in whichever version the negotiated protocol asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeaconMetaData {
    V1(MetaDataV1),
    V2(MetaDataV2),
    V3(MetaDataV3),
}

#[cfg(test)]
mod tests {
    use super::*;
    use libssz::{SszDecode as _, SszEncode as _};

    fn status_v2() -> StatusV2 {
        StatusV2 {
            fork_digest: [0x8c, 0x9f, 0x62, 0xfe],
            finalized_root: Root::repeat_byte(1),
            finalized_epoch: 419_072,
            head_root: Root::repeat_byte(2),
            head_slot: 13_410_304,
            earliest_available_slot: 13_400_000,
        }
    }

    #[test]
    fn status_has_the_spec_wire_lengths() {
        // v1: 4 + 32 + 8 + 32 + 8. v2 appends one more uint64.
        let v1 = StatusV1 {
            fork_digest: [0x8c, 0x9f, 0x62, 0xfe],
            finalized_root: Root::repeat_byte(1),
            finalized_epoch: 419_072,
            head_root: Root::repeat_byte(2),
            head_slot: 13_410_304,
        };
        assert_eq!(v1.to_ssz().len(), 84);
        assert_eq!(status_v2().to_ssz().len(), 92);
    }

    #[test]
    fn status_round_trips() {
        let encoded = status_v2().to_ssz();
        assert_eq!(StatusV2::from_ssz_bytes(&encoded).unwrap(), status_v2());
    }

    #[test]
    fn a_v2_status_does_not_decode_as_v1() {
        // The two differ only by a trailing uint64, so this is the one thing
        // that stops a v1 stream from silently accepting a v2 payload.
        assert!(StatusV1::from_ssz_bytes(&status_v2().to_ssz()).is_err());
    }

    #[test]
    fn metadata_has_the_spec_wire_lengths() {
        // v1: 8 + 8 (64 bits of attnets). v2 adds 1 byte of syncnets. v3 adds
        // a uint64 custody group count.
        let v1 = MetaDataV1 {
            seq_number: 0,
            attnets: AttnetsBits::default(),
        };
        let v2 = MetaDataV2 {
            seq_number: 0,
            attnets: AttnetsBits::default(),
            syncnets: SyncnetsBits::default(),
        };
        let v3 = MetaDataV3 {
            seq_number: 0,
            attnets: AttnetsBits::default(),
            syncnets: SyncnetsBits::default(),
            custody_group_count: super::super::constants::CUSTODY_REQUIREMENT,
        };
        assert_eq!(v1.to_ssz().len(), 16);
        assert_eq!(v2.to_ssz().len(), 17);
        assert_eq!(v3.to_ssz().len(), 25);
    }

    #[test]
    fn metadata_round_trips() {
        let v3 = MetaDataV3 {
            seq_number: 7,
            attnets: AttnetsBits::default(),
            syncnets: SyncnetsBits::default(),
            custody_group_count: 4,
        };
        let encoded = v3.to_ssz();
        assert_eq!(MetaDataV3::from_ssz_bytes(&encoded).unwrap(), v3);
    }

    #[test]
    fn ping_and_goodbye_are_bare_uint64s() {
        assert_eq!(Ping { seq_number: 3 }.to_ssz().len(), 8);
        assert_eq!(Goodbye { reason: 1 }.to_ssz().len(), 8);
        assert_eq!(
            Ping::from_ssz_bytes(&Ping { seq_number: 3 }.to_ssz()).unwrap(),
            Ping { seq_number: 3 }
        );
    }
}
