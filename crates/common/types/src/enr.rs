//! ENR entries ethlambda advertises for discv5 peer discovery.
//!
//! Layout follows the beacon-chain phase0 p2p interface spec's discovery
//! domain, so that whatever lean standardizes on later has the best chance of
//! already matching.
//!
//! Note that lean defines no fork schedule and its fork digest is a
//! compile-time constant rather than a genesis-derived value, so every field of
//! [`EnrForkId`] is currently fixed. The `eth2` check therefore separates lean
//! from non-lean, but not one lean devnet from another.

use libssz_derive::{SszDecode, SszEncode};

use crate::constants::FORK_DIGEST;

/// Fork version of the next planned hard fork. The spec says to set this to the
/// current fork version when no fork is planned; lean has neither.
pub const NEXT_FORK_VERSION: [u8; 4] = [0; 4];

/// Sentinel for "no fork is scheduled", per the beacon spec.
pub const FAR_FUTURE_EPOCH: u64 = u64::MAX;

/// The `eth2` ENR entry: SSZ, 16 bytes, byte-identical to the beacon-chain
/// `ENRForkID` container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SszEncode, SszDecode)]
pub struct EnrForkId {
    pub fork_digest: [u8; 4],
    pub next_fork_version: [u8; 4],
    pub next_fork_epoch: u64,
}

impl EnrForkId {
    /// This node's fork id. Constant for the lifetime of the process.
    pub fn local() -> Self {
        Self {
            fork_digest: fork_digest(),
            next_fork_version: NEXT_FORK_VERSION,
            next_fork_epoch: FAR_FUTURE_EPOCH,
        }
    }
}

/// [`FORK_DIGEST`] as raw bytes. The constant is the same hex string embedded in
/// every gossipsub topic name, so the ENR and the topics cannot disagree.
pub fn fork_digest() -> [u8; 4] {
    u32::from_str_radix(FORK_DIGEST, 16)
        .expect("FORK_DIGEST must be 8 hex digits")
        .to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use libssz::{SszDecode, SszEncode};
    #[test]
    fn fork_digest_parses_the_constant() {
        assert_eq!(fork_digest(), [0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn enr_fork_id_is_sixteen_bytes_and_round_trips() {
        let id = EnrForkId::local();
        let bytes = id.to_ssz();
        assert_eq!(bytes.len(), 16, "ENRForkID is 4 + 4 + 8 bytes");
        assert_eq!(EnrForkId::from_ssz_bytes(&bytes).unwrap(), id);
    }

    #[test]
    fn local_fork_id_has_no_planned_fork() {
        let id = EnrForkId::local();
        assert_eq!(id.fork_digest, fork_digest());
        assert_eq!(id.next_fork_version, NEXT_FORK_VERSION);
        assert_eq!(id.next_fork_epoch, FAR_FUTURE_EPOCH);
    }
}
