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

use std::collections::HashSet;

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

/// Encode subscribed attestation subnets as the `attnets` bitfield: bit `i` set
/// means subnet `i` is subscribed.
///
/// Lighthouse uses a fixed-width SSZ `BitVector` because the beacon
/// `ATTESTATION_SUBNET_COUNT` is a spec constant. ethlambda's
/// `attestation_committee_count` is runtime configuration, so the length is
/// derived from it and readers must tolerate a length other than their own.
/// Subnet ids at or beyond `committee_count` are dropped.
pub fn encode_attnets(subnets: &HashSet<u64>, committee_count: u64) -> Vec<u8> {
    let mut bits = vec![0u8; committee_count.div_ceil(8) as usize];
    for &subnet in subnets {
        if subnet < committee_count {
            bits[(subnet / 8) as usize] |= 1 << (subnet % 8);
        }
    }
    bits
}

/// Whether `bits` advertises `subnet`. A subnet past the end of the bitfield
/// reads as unsubscribed rather than as an error.
pub fn attnets_contains(bits: &[u8], subnet: u64) -> bool {
    bits.get((subnet / 8) as usize)
        .is_some_and(|byte| byte & (1 << (subnet % 8)) != 0)
}

/// Every subnet set in `bits`, ascending.
pub fn decode_attnets(bits: &[u8]) -> Vec<u64> {
    (0..(bits.len() as u64) * 8)
        .filter(|&subnet| attnets_contains(bits, subnet))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use libssz::{SszDecode, SszEncode};
    use std::collections::HashSet;

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

    #[test]
    fn attnets_sets_exactly_the_subscribed_bits() {
        let subnets = HashSet::from([0u64, 3, 9]);
        let bits = encode_attnets(&subnets, 16);

        assert_eq!(bits.len(), 2, "16 subnets need ceil(16/8) = 2 bytes");
        for subnet in 0..16u64 {
            assert_eq!(
                attnets_contains(&bits, subnet),
                subnets.contains(&subnet),
                "subnet {subnet}"
            );
        }
    }

    #[test]
    fn attnets_rounds_the_byte_length_up() {
        let bits = encode_attnets(&HashSet::from([0u64]), 1);
        assert_eq!(bits.len(), 1);
        assert!(attnets_contains(&bits, 0));
    }

    #[test]
    fn attnets_ignores_out_of_range_subnets() {
        // A misconfigured subnet id must not panic or corrupt neighbouring bits.
        let bits = encode_attnets(&HashSet::from([0u64, 99]), 8);
        assert_eq!(bits, vec![0b0000_0001]);
    }

    #[test]
    fn attnets_reads_past_the_end_as_unset() {
        // A peer advertising a shorter bitfield than our committee count is not
        // an error; the missing subnets simply read as unsubscribed.
        let bits = encode_attnets(&HashSet::from([0u64]), 8);
        assert!(!attnets_contains(&bits, 64));
    }

    #[test]
    fn decode_attnets_lists_set_subnets_in_order() {
        let bits = encode_attnets(&HashSet::from([9u64, 0, 3]), 16);
        assert_eq!(decode_attnets(&bits), vec![0, 3, 9]);
    }
}
