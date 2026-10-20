//! Which attestation subnets this node subscribes to, and which one an
//! attestation belongs on.
//!
//! `p2p-interface.md` makes a node's long-lived subnet subscription a public
//! function of its node id, so any peer can compute what any other peer should
//! be listening to without asking it. This module is that function and the
//! attestation-to-subnet mapping, and nothing else.
//!
//! # Why this is wire code and not state-transition code
//!
//! Every function here is a pure function of a node id, a slot and
//! [`Config`]. None of them touches a `BeaconState`, so none of them belongs
//! with the state transition; what they describe is which topic a message goes
//! on, which is this crate's subject. The two state-transition primitives they
//! do need, the swap-or-not shuffle and SHA-256, are imported.
//!
//! [`ethlambda_state_transition::beacon::das`] is the same shape for columns
//! rather than attestations and stays where it is, because the `networking`
//! consensus-spec fixture suite has handlers for `get_custody_groups` and
//! `compute_columns_for_custody_group` and its runner lives beside it. That
//! suite has no attestation-subnet handler, so nothing anchors this module
//! there.
//!
//! # Why a beacon node with no validators subscribes at all
//!
//! Phase 0 has no shard committees, so nothing gives the attestation subnets a
//! stable membership of their own. `p2p-interface.md`'s "Attestation subnet
//! subscription" answers that by asking *every* beacon node to hold
//! [`Config::subnets_per_node`] subscriptions for their own sake, advertised
//! in the ENR's `attnets`, so that a validator publishing to a subnet finds a
//! mesh already there. A follower therefore subscribes, verifies and relays on
//! its own subnets without ever applying what arrives to its fork choice: the
//! subscription is owed to the network, not to this node's head.
//!
//! # No rotation
//!
//! The specification frames the subscription as lasting
//! `EPOCHS_PER_SUBNET_SUBSCRIPTION` epochs, with `epoch` an argument to
//! [`compute_subscribed_subnets`] precisely so the set rotates. This node
//! computes the set once at startup and keeps it for the lifetime of the
//! process, which is also what lighthouse does: its `compute_attestation_subnets`
//! is documented as subscribing "for the duration of the node's runtime", and
//! nothing there reads `epochs_per_subnet_subscription` at all. The argument is
//! kept rather than dropped so that adding rotation later is a matter of
//! calling this again, not of changing its shape. See `docs/spec_deviations.md`.

// The state transition crate owns the swap-or-not shuffle and the SHA-256 this
// builds on, and the error type they report through. Nothing here needs a
// state; what it needs is those two primitives, which no other crate has, so
// they are imported rather than the module living beside them. See the module
// documentation.
use ethlambda_state_transition::beacon::error::{Result, verify};
use ethlambda_state_transition::beacon::hash::hash;
use ethlambda_state_transition::beacon::helpers::shuffling::compute_shuffled_index;
use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::preset;
use ethlambda_types::beacon::primitives::{CommitteeIndex, Slot};

/// The width of a discv5 node id, in bits. `p2p-interface.md`'s `NODE_ID_BITS`.
pub const NODE_ID_BITS: u32 = 256;

/// The subnet an attestation for `committee_index` at `slot` belongs on.
///
/// `validator.md`'s `compute_subnet_for_attestation`. Takes the subnet count
/// off [`Config`] rather than reading a constant, so a devnet that narrows the
/// subnet space maps its attestations the way its own configuration says
/// rather than the way mainnet's does.
///
/// `committees_per_slot` is the caller's, because it is a function of the
/// state at the attestation's epoch and this module holds no state.
pub fn compute_subnet_for_attestation(
    committees_per_slot: u64,
    slot: Slot,
    committee_index: CommitteeIndex,
    config: &Config,
) -> u64 {
    let slots_since_epoch_start = slot % preset::SLOTS_PER_EPOCH;
    let committees_since_epoch_start = committees_per_slot.saturating_mul(slots_since_epoch_start);
    committees_since_epoch_start.saturating_add(committee_index) % config.attestation_subnet_count
}

/// How many leading bits of a node id select its subnet, as
/// `compute_attestation_subnet_prefix_bits`.
///
/// Derived from the subnet count and the extra bits rather than read off
/// [`Config::attestation_subnet_prefix_bits`], although that key has a typed
/// home and mainnet's published file carries it. The specification defines
/// this as a derivation, so deriving it cannot disagree with the subnet count
/// it is taken over, whereas reading the field can: a configuration that
/// narrows `ATTESTATION_SUBNET_COUNT` and leaves the prefix key out falls back
/// to mainnet's 6 and would shuffle over a space its own subnet count does not
/// match. `the_shipped_configs_agree_with_the_derivation` pins the two
/// together for the configurations that do carry it.
fn attestation_subnet_prefix_bits(config: &Config) -> u32 {
    let count = config.attestation_subnet_count.max(1);
    // ceillog2: how many bits it takes to index `count` values. Exact for the
    // powers of two every shipped configuration uses, and rounds up for
    // anything else, which is what `ceillog2` means.
    let ceil_log2 = u64::BITS - (count - 1).leading_zeros();
    ceil_log2 + config.attestation_subnet_extra_bits as u32
}

/// One of the subnets `node_id` subscribes to at `epoch`, by `index`.
///
/// `p2p-interface.md`'s `compute_subscribed_subnet`. `node_id` is the discv5
/// node id, 32 bytes big endian, the same form
/// [`ethlambda_state_transition::beacon::das::get_custody_groups`] takes and the same form a peer reads off
/// an ENR.
///
/// Two byte-order traps, either of which produces a plausible-looking set that
/// agrees with no other client:
///
/// * `node_id >> (NODE_ID_BITS - prefix_bits)` is a shift on the *number*, so
///   the prefix is the leading bits of the big-endian encoding.
/// * `uint_to_bytes` is SSZ's, so the seed is hashed over the **little-endian**
///   eight bytes of the subscription period, not its big-endian ones. This is
///   the mirror image of the trap `get_custody_groups` documents, where the
///   number being hashed is the node id itself.
pub fn compute_subscribed_subnet(
    node_id: [u8; 32],
    epoch: u64,
    index: u64,
    config: &Config,
) -> Result<u64> {
    let prefix_bits = attestation_subnet_prefix_bits(config);
    // Strictly less than `u64::BITS`: `1u64 << prefix_bits` below requires a
    // shift strictly less than the type's width, and `prefix_bits ==
    // u64::BITS` would overflow it (a panic in debug, `1` itself in release,
    // either way not the value the shift asks for).
    verify(
        prefix_bits > 0 && prefix_bits < u64::BITS,
        "the attestation subnet prefix fits in a u64",
    )?;
    let period = config.epochs_per_subnet_subscription.max(1);

    let node_id_prefix = leading_bits(node_id, prefix_bits);
    let node_offset = modulo(node_id, period);
    // Integer division, so every epoch in one subscription period hashes to the
    // same seed and therefore selects the same subnet: that is what makes the
    // subscription long-lived rather than per-epoch.
    let subscription_period = epoch.saturating_add(node_offset) / period;
    let permutation_seed = hash(&subscription_period.to_le_bytes());

    // `node_id_prefix < 2^prefix_bits` holds by construction, which is
    // `compute_shuffled_index`'s own precondition.
    let permutated_prefix =
        compute_shuffled_index(node_id_prefix, 1u64 << prefix_bits, permutation_seed)?;
    Ok(permutated_prefix.saturating_add(index) % config.attestation_subnet_count)
}

/// Every subnet `node_id` subscribes to at `epoch`, sorted ascending and
/// deduplicated.
///
/// `p2p-interface.md`'s `compute_subscribed_subnets`. Sorted and deduplicated
/// where the specification's list comprehension is neither, for the reason
/// [`ethlambda_state_transition::beacon::das::custody_columns`] sorts: the callers subscribe to a set of
/// topics and set a set of ENR bits, and a repeated entry there would mean a
/// second `subscribe()` call and a topic count that disagrees with the map
/// beside it. A repeat is reachable whenever [`Config::subnets_per_node`] is
/// not smaller than [`Config::attestation_subnet_count`], since the index is
/// added modulo the count.
pub fn compute_subscribed_subnets(
    node_id: [u8; 32],
    epoch: u64,
    config: &Config,
) -> Result<Vec<u64>> {
    let mut subnets = Vec::with_capacity(config.subnets_per_node as usize);
    for index in 0..config.subnets_per_node {
        let subnet = compute_subscribed_subnet(node_id, epoch, index, config)?;
        if !subnets.contains(&subnet) {
            subnets.push(subnet);
        }
    }
    subnets.sort_unstable();
    Ok(subnets)
}

/// The leading `bits` bits of a big-endian 256-bit integer, as a `u64`.
///
/// `node_id >> (NODE_ID_BITS - bits)`. Walks only the bytes the prefix can
/// touch rather than materializing a 256-bit shift, since `bits` is at most
/// [`u64::BITS`] and the caller has already checked that.
fn leading_bits(node_id: [u8; 32], bits: u32) -> u64 {
    // The bytes the prefix spans, rounded up: a prefix of 6 bits lives entirely
    // in the first byte, one of 9 bits spans the first two.
    let byte_count = bits.div_ceil(8) as usize;
    let mut value: u64 = 0;
    for &byte in &node_id[..byte_count] {
        value = (value << 8) | u64::from(byte);
    }
    // `value` now holds `byte_count * 8` bits, which is `bits` rounded up to a
    // byte boundary, so drop the extra low bits the rounding pulled in.
    value >> (byte_count as u32 * 8 - bits)
}

/// A big-endian 256-bit integer modulo `modulus`.
///
/// Long division a byte at a time, in `u128` so the intermediate
/// `remainder << 8` cannot overflow: `remainder` is below `modulus`, which is
/// at most [`u64::MAX`], so the shifted value needs 72 bits.
fn modulo(node_id: [u8; 32], modulus: u64) -> u64 {
    let modulus = u128::from(modulus);
    let mut remainder: u128 = 0;
    for &byte in &node_id {
        remainder = ((remainder << 8) | u128::from(byte)) % modulus;
    }
    remainder as u64
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    /// The specification derives the prefix bits; the published configurations
    /// also carry the answer as a key. They must agree, or one of the two
    /// readings is shuffling over the wrong space.
    #[test]
    fn the_shipped_configs_agree_with_the_derivation() {
        for config in [Config::mainnet(), Config::minimal()] {
            assert_eq!(
                u64::from(attestation_subnet_prefix_bits(&config)),
                config.attestation_subnet_prefix_bits,
                "the derived prefix must match the configured one"
            );
        }
    }

    /// A prefix of exactly 64 bits must be refused rather than reaching the
    /// `1u64 << prefix_bits` shift below, which is exactly as wide as `u64`
    /// and would overflow it.
    #[test]
    fn a_prefix_of_exactly_64_bits_is_refused() {
        let config = Config {
            attestation_subnet_count: 64,
            // `attestation_subnet_prefix_bits` is `ceillog2(64) + extra_bits`
            // = `6 + extra_bits`, so 58 extra bits makes the derived prefix
            // exactly `u64::BITS`.
            attestation_subnet_extra_bits: 58,
            ..Config::mainnet()
        };
        assert_eq!(attestation_subnet_prefix_bits(&config), u64::BITS);
        assert!(compute_subscribed_subnet([0u8; 32], 0, 0, &config).is_err());
    }

    #[test]
    fn mainnet_takes_the_top_six_bits_of_the_node_id() {
        let config = Config::mainnet();
        assert_eq!(attestation_subnet_prefix_bits(&config), 6);
        // 0b1010_1100: the top six bits are 0b101011, which is 43.
        let mut node_id = [0u8; 32];
        node_id[0] = 0b1010_1100;
        assert_eq!(leading_bits(node_id, 6), 43);
    }

    /// A prefix spanning more than one byte must not pick up the low bits of
    /// the byte it only partly covers.
    #[test]
    fn a_prefix_spanning_two_bytes_drops_the_rounding_bits() {
        let mut node_id = [0u8; 32];
        node_id[0] = 0b1111_1111;
        node_id[1] = 0b1000_0000;
        // Nine bits: eight ones, then the one.
        assert_eq!(leading_bits(node_id, 9), 0b1_1111_1111);
        // Ten bits: the tenth is the zero after it.
        assert_eq!(leading_bits(node_id, 10), 0b11_1111_1110);
    }

    #[test]
    fn the_modulo_reads_the_whole_256_bit_number() {
        // 256 as a big-endian 256-bit integer: a one in the second-lowest byte.
        let mut node_id = [0u8; 32];
        node_id[30] = 1;
        assert_eq!(modulo(node_id, 1000), 256);
        // All ones mod 2 is 1, which no truncation to the low or the high bytes
        // alone gets right for every modulus.
        assert_eq!(modulo([0xff; 32], 2), 1);
    }

    #[test]
    fn a_node_subscribes_to_subnets_per_node_subnets() {
        let config = Config::mainnet();
        let subnets = compute_subscribed_subnets([7u8; 32], 0, &config).unwrap();
        assert_eq!(subnets.len() as u64, config.subnets_per_node);
        for subnet in &subnets {
            assert!(*subnet < config.attestation_subnet_count);
        }
    }

    #[test]
    fn the_subnets_are_sorted_and_distinct() {
        let config = Config::mainnet();
        for seed in 0u8..32 {
            let subnets = compute_subscribed_subnets([seed; 32], 0, &config).unwrap();
            let mut sorted = subnets.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(
                subnets, sorted,
                "node id {seed} produced an unsorted or repeated set"
            );
        }
    }

    /// The property the whole subscription rests on: the set holds for a
    /// subscription period rather than being redrawn every epoch. Without it,
    /// "long-lived subscription" would be a per-epoch churn no mesh could form
    /// around.
    #[test]
    fn the_set_is_stable_across_a_subscription_period() {
        let config = Config::mainnet();
        let node_id = [3u8; 32];
        // The node offset shifts where a node's period boundaries fall, so step
        // an epoch at a time and require the set to turn over at most once,
        // rather than assuming epoch 0 begins a period.
        let mut changes = 0;
        let mut previous = compute_subscribed_subnets(node_id, 0, &config).unwrap();
        for epoch in 1..config.epochs_per_subnet_subscription {
            let current = compute_subscribed_subnets(node_id, epoch, &config).unwrap();
            if current != previous {
                changes += 1;
                previous = current;
            }
        }
        assert!(
            changes <= 1,
            "a span of one period may turn over at most once, saw {changes} changes"
        );
    }

    /// Different node ids must generally select different sets, or the
    /// subscription is not spreading nodes over the subnet space at all.
    #[test]
    fn different_node_ids_spread_across_subnets() {
        let config = Config::mainnet();
        let mut seen = HashSet::new();
        for seed in 0u8..64 {
            let mut node_id = [0u8; 32];
            node_id[0] = seed.wrapping_mul(4);
            seen.extend(compute_subscribed_subnets(node_id, 0, &config).unwrap());
        }
        assert!(
            seen.len() > 8,
            "64 node ids covered only {} subnets, which is not a spread",
            seen.len()
        );
    }

    #[test]
    fn an_attestation_maps_to_its_subnet() {
        let config = Config::mainnet();
        // Slot 0 of an epoch, committee 0: the first subnet.
        assert_eq!(compute_subnet_for_attestation(4, 0, 0, &config), 0);
        // The same slot, third committee.
        assert_eq!(compute_subnet_for_attestation(4, 0, 2, &config), 2);
        // The epoch's second slot, with four committees per slot, starts at 4.
        assert_eq!(compute_subnet_for_attestation(4, 1, 0, &config), 4);
        assert_eq!(compute_subnet_for_attestation(4, 1, 3, &config), 7);
    }

    /// The mapping wraps at the subnet count rather than running past it, which
    /// is what keeps a full slot's worth of committees inside the bitfield.
    #[test]
    fn the_subnet_mapping_wraps_at_the_subnet_count() {
        let config = Config::mainnet();
        let count = config.attestation_subnet_count;
        // 64 committees per slot at slot 1 is 64 committees since the epoch
        // began, which wraps to 0.
        assert_eq!(compute_subnet_for_attestation(count, 1, 0, &config), 0);
        for slot in 0..preset::SLOTS_PER_EPOCH {
            for index in 0..4 {
                assert!(compute_subnet_for_attestation(4, slot, index, &config) < count);
            }
        }
    }
}
