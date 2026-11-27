//! Data availability sampling: which columns this node owes the network.
//!
//! `das-core.md` splits the extended data matrix's columns into custody
//! groups and assigns each node a set of them as a public function of its node
//! id, so any peer can compute what any other peer should be able to serve
//! without asking it. This module is that function and nothing else: the
//! sidecar verifiers live with their fork-choice siblings in
//! [`super::fork_choice`], and the matrix helpers `compute_matrix` and
//! `recover_matrix` are deliberately absent, since both exist for
//! reconstruction and reconstruction needs half the matrix while this node
//! holds [`constants::CUSTODY_REQUIREMENT`]'s worth of it.
//!
//! Two properties of [`get_custody_groups`] are load-bearing and both are
//! covered by fixtures. The selection is an *extension*, not a reshuffle: a
//! node that raises its custody count keeps every group it already had, which
//! is what lets a peer guess a node's custody from the default when its real
//! count is unknown. And the walk wraps at `UINT256_MAX` rather than
//! overflowing: any `current_id` the walk drives up to the maximum reaches
//! the wrap, and the all-ones node id is simply the one input that reaches it
//! on the very first step.

use crate::beacon::config::Config;
use crate::beacon::constants;
use crate::beacon::containers::BeaconState;
use crate::beacon::error::{Result, verify};
use crate::beacon::hash::hash;
use crate::beacon::helpers::math::bytes_to_uint64;
use crate::beacon::preset;
use crate::beacon::primitives::{ColumnIndex, Gwei, ValidatorIndex};

/// The index of a custody group: `das-core.md`'s `CustodyIndex`.
///
/// The specification lists this as a custom type alongside
/// [`crate::beacon::primitives::ColumnIndex`], but only this module's own
/// functions need it, so it is defined here instead of in
/// `crate::beacon::primitives`, the same reasoning
/// [`crate::beacon::containers::fulu::RowIndex`] gives for staying beside its
/// only consumers.
pub type CustodyIndex = u64;

/// How many custody groups a node samples each slot given what it custodies.
///
/// `das-core.md`, "Custody sampling": a node samples the larger of the floor
/// and its own custody, so a node at the minimum still samples
/// [`constants::SAMPLES_PER_SLOT`] groups and its custody set is a subset of
/// what it samples.
pub fn sampling_size(custody_group_count: u64) -> u64 {
    custody_group_count.max(constants::SAMPLES_PER_SLOT)
}

/// How many custody groups the validators attached to a node require it to
/// custody: fulu `validator.md`, "Validator custody",
/// `get_validators_custody_requirement`.
///
/// `None` when no index in `validator_indices` names a validator in `state`'s
/// registry. The specification's function answers
/// `VALIDATOR_CUSTODY_REQUIREMENT` for an empty list, but its prose applies
/// the requirement only to "any node with at least one validator attached",
/// so a node whose validator client named nobody this state knows (none
/// attached, or indices of validators not yet deposited) owes nothing beyond
/// its own `CUSTODY_REQUIREMENT`. Answering the floor there would raise every
/// plain follower to it.
///
/// Unknown indices are skipped rather than refused: they come from a
/// validator client's API calls, not from the chain.
pub fn get_validators_custody_requirement(
    state: &BeaconState,
    validator_indices: &[ValidatorIndex],
    config: &Config,
) -> Option<u64> {
    let mut attached = false;
    let mut total_node_balance: Gwei = 0;
    for &index in validator_indices {
        if let Ok(validator) = state.validator(index) {
            attached = true;
            total_node_balance = total_node_balance.saturating_add(validator.effective_balance);
        }
    }
    attached.then(|| validators_custody_requirement(total_node_balance, config))
}

/// The arithmetic half of [`get_validators_custody_requirement`]: one custody
/// group per `BALANCE_PER_ADDITIONAL_CUSTODY_GROUP` of `total_node_balance`,
/// at least `VALIDATOR_CUSTODY_REQUIREMENT` and at most
/// `NUMBER_OF_CUSTODY_GROUPS`.
///
/// Both configuration values are read from `config` rather than from
/// constants, since a network's `config.yaml` sets them. A zero
/// `BALANCE_PER_ADDITIONAL_CUSTODY_GROUP` (a broken network directory, since
/// no published one sets it) asks for every group, the answer the division
/// tends to as the divisor shrinks.
pub fn validators_custody_requirement(total_node_balance: Gwei, config: &Config) -> u64 {
    let count = total_node_balance
        .checked_div(config.balance_per_additional_custody_group)
        .unwrap_or(u64::MAX);
    count
        .max(config.validator_custody_requirement)
        .min(constants::NUMBER_OF_CUSTODY_GROUPS)
}

/// The gossip subnet a data column sidecar travels on:
/// `p2p-interface.md`, `compute_subnet_for_data_column_sidecar`.
pub fn compute_subnet_for_data_column_sidecar(column_index: ColumnIndex) -> u64 {
    column_index % constants::DATA_COLUMN_SIDECAR_SUBNET_COUNT
}

/// The custody groups `node_id` is assigned, sorted ascending.
///
/// `node_id` is the discv5 node id, 32 bytes big endian, which is how a peer
/// reads it off an ENR. The walk hashes the *little endian* encoding of that
/// number, since the specification's `uint_to_bytes` is SSZ's, and SSZ
/// integers are little endian; hashing the big-endian bytes produces a
/// plausible-looking set that agrees with no other client.
///
/// The walk increments `node_id` after each hash and wraps at `UINT256_MAX`
/// rather than overflowing (see [`increment_wrapping`]). The all-ones node id
/// reaches that wrap on its very first increment, which is why it is the
/// fixture input that exercises it; any other starting id reaches the same
/// wrap eventually, just later.
pub fn get_custody_groups(
    node_id: [u8; 32],
    custody_group_count: u64,
) -> Result<Vec<CustodyIndex>> {
    verify(
        custody_group_count <= constants::NUMBER_OF_CUSTODY_GROUPS,
        "custody_group_count <= NUMBER_OF_CUSTODY_GROUPS",
    )?;

    // Skip the walk when everything is custodied: it would take an unbounded
    // number of iterations to collect the last few groups by chance.
    if custody_group_count == constants::NUMBER_OF_CUSTODY_GROUPS {
        return Ok((0..constants::NUMBER_OF_CUSTODY_GROUPS).collect());
    }

    let mut current_id = node_id;
    let mut groups: Vec<CustodyIndex> = Vec::with_capacity(custody_group_count as usize);
    while (groups.len() as u64) < custody_group_count {
        let mut little_endian = current_id;
        little_endian.reverse();
        let digest = hash(&little_endian);
        let group = bytes_to_uint64(&digest.0[0..8]) % constants::NUMBER_OF_CUSTODY_GROUPS;
        if !groups.contains(&group) {
            groups.push(group);
        }
        increment_wrapping(&mut current_id);
    }

    groups.sort_unstable();
    Ok(groups)
}

/// The columns belonging to `custody_group`: an interleave, not a contiguous
/// block. A group holds `custody_group`, then
/// `custody_group + NUMBER_OF_CUSTODY_GROUPS`, and so on, striding across the
/// whole column range rather than owning a run of adjacent columns.
///
/// Relies on `preset::NUMBER_OF_COLUMNS` being an exact multiple of
/// [`constants::NUMBER_OF_CUSTODY_GROUPS`] so that stride divides evenly and
/// every column lands in exactly one group; see that constant's own doc for
/// why the two are equal today, and
/// `number_of_columns_is_a_multiple_of_custody_groups` in
/// `crate::beacon::constants`'s tests for where the invariant is checked.
pub fn compute_columns_for_custody_group(custody_group: CustodyIndex) -> Result<Vec<ColumnIndex>> {
    verify(
        custody_group < constants::NUMBER_OF_CUSTODY_GROUPS,
        "custody_group < NUMBER_OF_CUSTODY_GROUPS",
    )?;
    let columns_per_group = preset::NUMBER_OF_COLUMNS as u64 / constants::NUMBER_OF_CUSTODY_GROUPS;
    Ok((0..columns_per_group)
        .map(|index| constants::NUMBER_OF_CUSTODY_GROUPS * index + custody_group)
        .collect())
}

/// Every column `node_id` custodies at `custody_group_count`, sorted ascending.
///
/// The union of the two helpers above, which is what every caller in this
/// repository actually wants: the subnet subscription, the availability check
/// and the by-root fetch all reason about columns, never about groups.
pub fn custody_columns(node_id: [u8; 32], custody_group_count: u64) -> Result<Vec<ColumnIndex>> {
    let mut columns = Vec::new();
    for group in get_custody_groups(node_id, custody_group_count)? {
        columns.extend(compute_columns_for_custody_group(group)?);
    }
    columns.sort_unstable();
    Ok(columns)
}

/// Adds one to a big-endian 256-bit integer, wrapping to all-zero rather than
/// overflowing past the all-ones maximum.
///
/// Carries from the last byte (the least significant one, since `value` is
/// big-endian) toward the first, stopping as soon as a byte absorbs the carry
/// without itself overflowing.
fn increment_wrapping(value: &mut [u8; 32]) {
    for byte in value.iter_mut().rev() {
        let (next, carried) = byte.overflowing_add(1);
        *byte = next;
        if !carried {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A node id with every byte set, which is `UINT256_MAX`. Exercises
    /// `get_custody_groups`'s two early-return branches below, both of which
    /// return before the walk begins; [`increment_wrapping`]'s own carry
    /// propagation, which only the walk reaches, is exercised directly by the
    /// tests further down instead.
    const MAX_NODE_ID: [u8; 32] = [0xff; 32];

    #[test]
    fn a_full_custody_count_returns_every_group_without_hashing() {
        let groups = get_custody_groups(MAX_NODE_ID, constants::NUMBER_OF_CUSTODY_GROUPS).unwrap();
        assert_eq!(
            groups,
            (0..constants::NUMBER_OF_CUSTODY_GROUPS).collect::<Vec<_>>()
        );
    }

    #[test]
    fn asking_for_more_groups_than_exist_is_refused() {
        assert!(get_custody_groups(MAX_NODE_ID, constants::NUMBER_OF_CUSTODY_GROUPS + 1).is_err());
    }

    #[test]
    fn wraps_at_the_maximum_id() {
        let mut id = MAX_NODE_ID;
        increment_wrapping(&mut id);
        assert_eq!(id, [0u8; 32]);
    }

    #[test]
    fn carries_across_multiple_bytes() {
        let mut id = [0u8; 32];
        id[30] = 0xff;
        id[31] = 0xff;
        increment_wrapping(&mut id);
        assert_eq!(id[29], 1);
        assert_eq!(id[30], 0);
        assert_eq!(id[31], 0);
    }

    #[test]
    fn get_custody_groups_walks_through_the_wrap() {
        assert!(get_custody_groups(MAX_NODE_ID, 8).is_ok());
    }

    #[test]
    fn groups_are_sorted_and_unique() {
        let groups = get_custody_groups([7; 32], 8).unwrap();
        assert_eq!(groups.len(), 8);
        let mut sorted = groups.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(groups, sorted);
    }

    #[test]
    fn a_larger_count_extends_the_same_selection() {
        // das-core: "Increasing the custody_size parameter for a given node_id
        // extends the returned list (rather than being an entirely new
        // shuffle)". A node raising its custody must not have to re-backfill
        // what it already held.
        let small = get_custody_groups([3; 32], 4).unwrap();
        let large = get_custody_groups([3; 32], 8).unwrap();
        for group in small {
            assert!(
                large.contains(&group),
                "group {group} was dropped by a larger count"
            );
        }
    }

    #[test]
    fn a_group_maps_to_its_own_column_when_the_counts_are_equal() {
        for group in [0, 1, 55, constants::NUMBER_OF_CUSTODY_GROUPS - 1] {
            assert_eq!(
                compute_columns_for_custody_group(group).unwrap(),
                vec![group]
            );
        }
    }

    #[test]
    fn a_group_outside_the_range_is_refused() {
        assert!(compute_columns_for_custody_group(constants::NUMBER_OF_CUSTODY_GROUPS).is_err());
    }

    #[test]
    fn the_sampling_size_is_the_floor_for_a_minimal_custodian() {
        assert_eq!(
            sampling_size(constants::CUSTODY_REQUIREMENT),
            constants::SAMPLES_PER_SLOT
        );
        assert_eq!(
            sampling_size(constants::NUMBER_OF_CUSTODY_GROUPS),
            constants::NUMBER_OF_CUSTODY_GROUPS
        );
    }

    const ETH: Gwei = 1_000_000_000;

    #[test]
    fn validator_custody_is_one_group_per_32_eth() {
        let config = Config::mainnet();
        assert_eq!(config.balance_per_additional_custody_group, 32 * ETH);
        assert_eq!(validators_custody_requirement(9 * 32 * ETH, &config), 9);
        // Integer division: a remainder short of the next 32 ETH buys nothing.
        assert_eq!(
            validators_custody_requirement(10 * 32 * ETH - 1, &config),
            9
        );
        assert_eq!(validators_custody_requirement(100 * 32 * ETH, &config), 100);
    }

    #[test]
    fn validator_custody_is_floored_at_the_validator_requirement() {
        let config = Config::mainnet();
        assert_eq!(config.validator_custody_requirement, 8);
        assert_eq!(validators_custody_requirement(0, &config), 8);
        assert_eq!(validators_custody_requirement(32 * ETH, &config), 8);
        assert_eq!(validators_custody_requirement(8 * 32 * ETH, &config), 8);
    }

    #[test]
    fn validator_custody_is_capped_at_every_group() {
        let config = Config::mainnet();
        // 4096 ETH is the supernode threshold.
        assert_eq!(validators_custody_requirement(4096 * ETH, &config), 128);
        assert_eq!(
            validators_custody_requirement(1_000_000 * ETH, &config),
            128
        );
        assert_eq!(validators_custody_requirement(u64::MAX, &config), 128);
    }

    #[test]
    fn a_zero_balance_per_group_asks_for_every_group() {
        let config = Config {
            balance_per_additional_custody_group: 0,
            ..Config::mainnet()
        };
        assert_eq!(
            validators_custody_requirement(32 * ETH, &config),
            constants::NUMBER_OF_CUSTODY_GROUPS
        );
    }

    #[test]
    fn the_requirement_sums_the_attached_validators_effective_balances() {
        let config = Config::mainnet();
        let mut state = crate::beacon::helpers::test_state::with_validators(200);
        // Every validator the builder makes has 32 ETH effective balance.
        let ten: Vec<ValidatorIndex> = (0..10).collect();
        assert_eq!(
            get_validators_custody_requirement(&state, &ten, &config),
            Some(10)
        );
        // Effective balance, not the count of validators: one 2048 ETH
        // validator alone is 64 groups' worth.
        state.validator_mut(0).unwrap().effective_balance = 2048 * ETH;
        assert_eq!(
            get_validators_custody_requirement(&state, &[0], &config),
            Some(64)
        );
        let all: Vec<ValidatorIndex> = (0..200).collect();
        assert_eq!(
            get_validators_custody_requirement(&state, &all, &config),
            Some(constants::NUMBER_OF_CUSTODY_GROUPS)
        );
    }

    #[test]
    fn unknown_validators_count_for_nothing() {
        let config = Config::mainnet();
        let state = crate::beacon::helpers::test_state::with_validators(4);
        // An index past the registry is skipped, not refused.
        assert_eq!(
            get_validators_custody_requirement(&state, &[1, 1_000], &config),
            Some(8)
        );
        // No validator this state knows: no requirement at all, rather than
        // the floor a node with a validator attached would owe.
        assert_eq!(
            get_validators_custody_requirement(&state, &[1_000], &config),
            None
        );
        assert_eq!(
            get_validators_custody_requirement(&state, &[], &config),
            None
        );
    }

    #[test]
    fn custody_columns_are_sorted_and_match_the_groups() {
        let node_id = [9; 32];
        let groups = get_custody_groups(node_id, 8).unwrap();
        let columns = custody_columns(node_id, 8).unwrap();
        assert_eq!(columns.len(), groups.len());
        let mut sorted = columns.clone();
        sorted.sort_unstable();
        assert_eq!(columns, sorted);
        for group in groups {
            assert!(columns.contains(&group));
        }
    }
}
