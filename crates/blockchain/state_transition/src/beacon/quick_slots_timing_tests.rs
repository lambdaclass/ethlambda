//! EIP-8198 (quick slots): the wall-clock helpers across the fork where the
//! slot duration changes.
//!
//! The pinned spec fixtures keep one slot duration throughout, so these are
//! the coverage for a duration that changes at Heze. The schedule is 12 s
//! slots until epoch 2, 9 s after it.

use crate::beacon::config::Config;
use crate::beacon::fork_choice::{get_proposer_reorg_cutoff_ms, get_slot_component_duration_ms};
use crate::beacon::gossip::{is_current_slot, is_future_epoch, is_future_slot, slot_start_ms};
use crate::beacon::inclusion_list::{get_inclusion_list_due_ms, is_inclusion_list_timely};
use crate::beacon::preset;

const GENESIS_TIME: u64 = 1_000;
const FORK_SLOT: u64 = 2 * preset::SLOTS_PER_EPOCH;

fn quick_slots() -> Config {
    Config {
        genesis_time: GENESIS_TIME,
        slot_duration_ms: 12_000,
        slot_duration_ms_heze: 9_000,
        heze_fork_epoch: 2,
        ..Config::mainnet()
    }
}

#[test]
fn a_slot_component_is_a_fraction_of_its_own_epochs_slot() {
    let config = quick_slots();
    assert_eq!(get_slot_component_duration_ms(5_000, 1, &config), 6_000);
    assert_eq!(get_slot_component_duration_ms(5_000, 2, &config), 4_500);
    assert_eq!(
        get_proposer_reorg_cutoff_ms(1, &config),
        config.proposer_reorg_cutoff_bps * 12_000 / 10_000
    );
    assert_eq!(
        get_proposer_reorg_cutoff_ms(2, &config),
        config.proposer_reorg_cutoff_bps * 9_000 / 10_000
    );
}

#[test]
fn slot_starts_follow_the_schedule() {
    let config = quick_slots();
    let genesis_ms = GENESIS_TIME * 1_000;
    assert_eq!(
        slot_start_ms(&config, FORK_SLOT),
        genesis_ms + FORK_SLOT * 12_000
    );
    assert_eq!(
        slot_start_ms(&config, FORK_SLOT + 1),
        genesis_ms + FORK_SLOT * 12_000 + 9_000
    );
}

#[test]
fn the_current_and_future_slot_checks_use_the_post_fork_duration() {
    let config = quick_slots();
    let next_start = slot_start_ms(&config, FORK_SLOT + 2);
    let disparity = config.maximum_gossip_clock_disparity;
    // Slot FORK_SLOT + 1 is a 9 s slot: it ends 9 s after it starts, and the
    // slot after it is future only once the clock plus the disparity
    // allowance reaches its start.
    let start = slot_start_ms(&config, FORK_SLOT + 1);
    assert_eq!(next_start - start, 9_000);
    assert!(is_current_slot(&config, FORK_SLOT + 1, start + 8_999));
    assert!(!is_current_slot(
        &config,
        FORK_SLOT + 1,
        next_start + disparity + 1
    ));
    assert!(is_future_slot(
        &config,
        FORK_SLOT + 2,
        next_start - disparity - 1
    ));
    assert!(!is_future_slot(
        &config,
        FORK_SLOT + 2,
        next_start - disparity
    ));
}

#[test]
fn the_future_epoch_check_uses_the_schedule() {
    let config = quick_slots();
    let epoch_3_start = slot_start_ms(&config, 3 * preset::SLOTS_PER_EPOCH);
    let disparity = config.maximum_gossip_clock_disparity;
    assert!(is_future_epoch(&config, 3, epoch_3_start - disparity - 1));
    assert!(!is_future_epoch(&config, 3, epoch_3_start - disparity));
}

#[test]
fn an_inclusion_list_is_timely_for_a_fraction_of_the_post_fork_slot() {
    let config = quick_slots();
    let slot = FORK_SLOT + 1;
    let start = slot_start_ms(&config, slot);
    let due_ms = get_inclusion_list_due_ms(2, &config);
    assert_eq!(due_ms, config.inclusion_list_due_bps * 9_000 / 10_000);
    assert!(is_inclusion_list_timely(&config, slot, start + due_ms - 1));
    assert!(!is_inclusion_list_timely(&config, slot, start + due_ms));
    // A pre-fork slot keeps the longer deadline.
    let old_slot = FORK_SLOT - 1;
    let old_start = slot_start_ms(&config, old_slot);
    let old_due_ms = get_inclusion_list_due_ms(1, &config);
    assert_eq!(old_due_ms, config.inclusion_list_due_bps * 12_000 / 10_000);
    assert!(is_inclusion_list_timely(
        &config,
        old_slot,
        old_start + old_due_ms - 1
    ));
    assert!(!is_inclusion_list_timely(
        &config,
        old_slot,
        old_start + old_due_ms
    ));
    // And a list for the post-fork slot is not timely at the old slot's
    // would-be offset past the new slot's end.
    assert!(!is_inclusion_list_timely(&config, slot, start + 9_000));
}
