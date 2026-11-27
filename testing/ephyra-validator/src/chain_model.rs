//! Portable schedule inputs and checks derived from `chain_check`'s docs.
//! Generator and shrinker adapters live in the integration test crate.

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::constants::FAR_FUTURE_EPOCH;
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::primitives::{Epoch, Root};
use ethlambda_validator::beacon_node::Genesis;
use ethlambda_validator::chain_check::{
    ChainId, Served, first_chain_difference, follow_schedule, merge_schedule,
};

pub const NOW: Epoch = 500_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForkReport {
    /// Distance after NOW, or no scheduled epoch.
    pub fulu: Option<u16>,
    pub gloas: Option<u16>,
    pub fulu_version: u8,
    pub gloas_version: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeReport {
    pub forks: ForkReport,
    pub say: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduleCase {
    pub current: ForkReport,
    pub nodes: Vec<NodeReport>,
    /// All nodes serve this same set of duty offsets, preserving permutation
    /// invariance while exercising the merge's offset setters.
    pub node_offset: u64,
    pub difference_kind: u8,
}

/// A schedule with distinct offsets served by each node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OffsetCase {
    pub schedule: ScheduleCase,
    pub offsets: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnorderedCase {
    pub current_fulu: u16,
    pub current_gloas: u16,
    pub served_fulu: u16,
    pub served_gloas: u16,
    pub version: u8,
}

pub fn valid_unordered_case(case: &UnorderedCase) -> bool {
    (2..=200).contains(&case.current_fulu)
        && (1..case.current_fulu).contains(&case.current_gloas)
        && (1..=200).contains(&case.served_fulu)
        && (case.served_fulu..=200).contains(&case.served_gloas)
        && case.version <= 3
}

pub fn check_unordered_repair(case: &UnorderedCase) {
    assert!(valid_unordered_case(case));
    let current = Config::mainnet()
        .with_fork_epoch(ForkName::Fulu, NOW + u64::from(case.current_fulu))
        .with_fork_epoch(ForkName::Gloas, NOW + u64::from(case.current_gloas));
    assert!(!in_order(&current));
    let served = current
        .clone()
        .with_fork_epoch(ForkName::Fulu, NOW + u64::from(case.served_fulu))
        .with_fork_epoch(ForkName::Gloas, NOW + u64::from(case.served_gloas))
        .with_fork_version(ForkName::Fulu, [case.version, 0, 0, 0])
        .with_fork_version(ForkName::Gloas, [case.version, 0, 0, 0]);
    assert!(in_order(&served));
    let merged = merge_schedule(&current, &[(0, served.clone())], &[0], NOW);
    assert!(
        in_order(&merged.config),
        "ordered answer failed to repair: {case:?}"
    );
    assert_eq!(
        merged.config, served,
        "ordered answer was not adopted: {case:?}"
    );
    assert!(
        !merged
            .disagreements
            .iter()
            .any(|line| line.contains("before the one it follows")),
        "repair was blocked by an order disagreement: {case:?}"
    );
}

pub fn valid_report(r: &ForkReport) -> bool {
    let valid_delta = |value: Option<u16>| value.is_none_or(|n| (1..=200).contains(&n));
    valid_delta(r.fulu)
        && valid_delta(r.gloas)
        && match (r.fulu, r.gloas) {
            (None, Some(_)) => false,
            (Some(a), Some(b)) => a <= b,
            _ => true,
        }
}

pub fn valid_case(c: &ScheduleCase) -> bool {
    c.nodes.len() <= 4
        && valid_report(&c.current)
        && c.nodes.iter().all(|node| valid_report(&node.forks))
        && (1..=9_000).contains(&c.node_offset)
        && c.difference_kind <= 6
}

fn epoch(delta: Option<u16>) -> Epoch {
    delta.map_or(FAR_FUTURE_EPOCH, |delta| NOW + u64::from(delta))
}

fn configuration(report: &ForkReport) -> Config {
    Config::mainnet()
        .with_fork_epoch(ForkName::Fulu, epoch(report.fulu))
        .with_fork_version(ForkName::Fulu, [report.fulu_version, 0, 0, 0])
        .with_fork_epoch(ForkName::Gloas, epoch(report.gloas))
        .with_fork_version(ForkName::Gloas, [report.gloas_version, 0, 0, 0])
}

fn served_with_offsets(case: &ScheduleCase, offsets: &[u64]) -> Served {
    assert_eq!(case.nodes.len(), offsets.len());
    Served {
        configs: case
            .nodes
            .iter()
            .enumerate()
            .map(|(position, node)| {
                let mut config = configuration(&node.forks);
                let offset = offsets[position];
                config.attestation_due_bps = offset;
                config.aggregate_due_bps = offset;
                config.attestation_due_bps_gloas = offset;
                config.aggregate_due_bps_gloas = offset;
                config.sync_message_due_bps = offset;
                config.contribution_due_bps = offset;
                config.sync_message_due_bps_gloas = offset;
                config.contribution_due_bps_gloas = offset;
                config.payload_due_bps = offset;
                config.payload_attestation_due_bps = offset;
                (position, config)
            })
            .collect(),
        say: case
            .nodes
            .iter()
            .enumerate()
            .filter_map(|(position, node)| node.say.then_some(position))
            .collect(),
    }
}

fn served(case: &ScheduleCase) -> Served {
    served_with_offsets(case, &vec![case.node_offset; case.nodes.len()])
}

pub fn valid_offset_case(case: &OffsetCase) -> bool {
    valid_case(&case.schedule)
        && (2..=4).contains(&case.offsets.len())
        && case.offsets.len() == case.schedule.nodes.len()
        && case
            .offsets
            .iter()
            .all(|offset| (1..=9_000).contains(offset))
        && case.offsets[0] != case.offsets[1]
}

fn offset_values(config: &Config) -> [u64; 10] {
    [
        config.attestation_due_bps,
        config.aggregate_due_bps,
        config.attestation_due_bps_gloas,
        config.aggregate_due_bps_gloas,
        config.sync_message_due_bps,
        config.contribution_due_bps,
        config.sync_message_due_bps_gloas,
        config.contribution_due_bps_gloas,
        config.payload_due_bps,
        config.payload_attestation_due_bps,
    ]
}

fn restore_offsets(config: &mut Config, source: &Config) {
    config.attestation_due_bps = source.attestation_due_bps;
    config.aggregate_due_bps = source.aggregate_due_bps;
    config.attestation_due_bps_gloas = source.attestation_due_bps_gloas;
    config.aggregate_due_bps_gloas = source.aggregate_due_bps_gloas;
    config.sync_message_due_bps = source.sync_message_due_bps;
    config.contribution_due_bps = source.contribution_due_bps;
    config.sync_message_due_bps_gloas = source.sync_message_due_bps_gloas;
    config.contribution_due_bps_gloas = source.contribution_due_bps_gloas;
    config.payload_due_bps = source.payload_due_bps;
    config.payload_attestation_due_bps = source.payload_attestation_due_bps;
}

pub fn check_different_offsets(case: &OffsetCase) {
    assert!(valid_offset_case(case));
    let current = configuration(&case.schedule.current);
    let served = served_with_offsets(&case.schedule, &case.offsets);
    let expected = merge_schedule(&current, &served.configs, &served.say, NOW);
    assert_eq!(offset_values(&expected.config), [case.offsets[0]; 10]);

    // Node positions (and therefore their say) travel with each report.
    // Reordering the answer list changes only which node is first for offsets.
    permutations(&served.configs, &mut |permuted| {
        let merged = merge_schedule(&current, &permuted, &served.say, NOW);
        let first = offset_values(&permuted[0].1)[0];
        assert_eq!(offset_values(&merged.config), [first; 10], "{case:?}");
        let mut actual_without_offsets = merged.config.clone();
        let mut expected_without_offsets = expected.config.clone();
        restore_offsets(&mut actual_without_offsets, &current);
        restore_offsets(&mut expected_without_offsets, &current);
        assert_eq!(
            actual_without_offsets, expected_without_offsets,
            "node permutation changed another field: {case:?}"
        );
        assert_eq!(
            merged.disagreements.len(),
            expected.disagreements.len(),
            "node permutation changed disagreement count: {case:?}"
        );
        assert_eq!(
            follow_schedule(
                &current,
                &Served {
                    configs: permuted,
                    say: served.say.clone()
                },
                NOW,
                false
            ),
            (merged.config != current).then_some(merged.config),
            "follow result disagreed: {case:?}"
        );
    });
}

fn in_order(config: &Config) -> bool {
    ForkName::ALL
        .windows(2)
        .all(|pair| config.fork_epoch(pair[0]) <= config.fork_epoch(pair[1]))
}

pub fn check_order(case: &ScheduleCase) {
    assert!(
        valid_case(case),
        "generator supplied unordered schedules: {case:?}"
    );
    let current = configuration(&case.current);
    let served = served(case);
    assert!(in_order(&current));
    assert!(served.configs.iter().all(|(_, config)| in_order(config)));
    let merged = merge_schedule(&current, &served.configs, &served.say, NOW);
    assert!(in_order(&merged.config), "merge broke fork order: {case:?}");
    for fork in ForkName::ALL {
        if current.fork_epoch(fork) <= NOW {
            assert_eq!(
                merged.config.fork_epoch(fork),
                current.fork_epoch(fork),
                "merge moved an active fork: {case:?}"
            );
            assert_eq!(
                merged.config.fork_version(fork),
                current.fork_version(fork),
                "merge changed an active fork version: {case:?}"
            );
        }
        if current.fork_epoch(fork) != FAR_FUTURE_EPOCH {
            assert_ne!(
                merged.config.fork_epoch(fork),
                FAR_FUTURE_EPOCH,
                "merge unscheduled an adopted fork: {case:?}"
            );
        }
    }
}

fn permutations<T: Clone>(items: &[T], visit: &mut impl FnMut(Vec<T>)) {
    fn enumerate<T: Clone>(items: &mut [T], at: usize, visit: &mut impl FnMut(Vec<T>)) {
        if at == items.len() {
            visit(items.to_vec());
            return;
        }
        for i in at..items.len() {
            items.swap(at, i);
            enumerate(items, at + 1, visit);
            items.swap(at, i);
        }
    }
    enumerate(&mut items.to_vec(), 0, visit);
}

pub fn check_response_order(case: &ScheduleCase) {
    assert!(valid_case(case));
    let current = configuration(&case.current);
    let served = served(case);
    let expected = merge_schedule(&current, &served.configs, &served.say, NOW);
    // All reports share the case's duty offsets. A changed first node
    // therefore cannot change the one intentionally order-sensitive field.
    permutations(&served.configs, &mut |permuted| {
        let actual = merge_schedule(&current, &permuted, &served.say, NOW);
        assert_eq!(
            actual.config, expected.config,
            "node permutation changed the fork result: {case:?}"
        );
        assert_eq!(
            actual.changes, expected.changes,
            "node permutation changed the applied changes: {case:?}"
        );
        assert_eq!(
            actual.disagreements.len(),
            expected.disagreements.len(),
            "node permutation changed disagreement count: {case:?}"
        );
    });
}

fn mismatch_when_active(a: &ForkReport, b: &ForkReport) -> bool {
    let differs = |a_epoch: Option<u16>, a_version: u8, b_epoch: Option<u16>, b_version: u8| {
        a_epoch != b_epoch || a_epoch.is_some() && a_version != b_version
    };
    differs(a.fulu, a.fulu_version, b.fulu, b.fulu_version)
        || differs(a.gloas, a.gloas_version, b.gloas, b.gloas_version)
}

pub fn check_chain_boundary(case: &ScheduleCase) {
    assert!(valid_case(case));
    let genesis = Genesis {
        genesis_time: 1_606_824_023,
        genesis_validators_root: Root::ZERO,
    };
    let ours = ChainId {
        genesis,
        config: configuration(&case.current),
    };
    for node in &case.nodes {
        let theirs = ChainId {
            genesis,
            config: configuration(&node.forks),
        };
        assert_eq!(
            first_chain_difference(&ours, &theirs, NOW),
            None,
            "future fork disagreement was treated as another chain: {case:?}"
        );
        assert_eq!(
            first_chain_difference(&ours, &theirs, NOW + 1000).is_some(),
            mismatch_when_active(&case.current, &node.forks),
            "active fork disagreement classification was wrong: {case:?}"
        );
    }
    // The documented field order is observable in the diagnostic when more
    // than one mismatch exists. Make each first difference explicit.
    let mut base = ChainId {
        genesis,
        config: Config::mainnet(),
    };
    let expected = match case.difference_kind {
        0 => {
            base.config = Config::minimal();
            base.genesis.genesis_time += 1;
            "PRESET_BASE"
        }
        1 => {
            base.genesis.genesis_time += 1;
            base.genesis.genesis_validators_root = Root::repeat_byte(1);
            "genesis_time"
        }
        2 => {
            base.genesis.genesis_validators_root = Root::repeat_byte(1);
            base.config.slot_duration_ms += 1;
            "genesis_validators_root"
        }
        3 => {
            base.config.slot_duration_ms += 1;
            let mut version = base.config.fork_version(ForkName::Phase0);
            version[0] ^= 0x80;
            base.config = base.config.with_fork_version(ForkName::Phase0, version);
            "slot_duration_ms"
        }
        4 => {
            let mut version = base.config.fork_version(ForkName::Phase0);
            version[0] ^= 0x80;
            base.config = base.config.with_fork_version(ForkName::Phase0, version);
            "GENESIS_FORK_VERSION"
        }
        5 => {
            let epoch = base.config.fork_epoch(ForkName::Fulu);
            base.config = base.config.with_fork_epoch(ForkName::Fulu, epoch + 1);
            "FULU_FORK_EPOCH"
        }
        _ => {
            let mut version = base.config.fork_version(ForkName::Fulu);
            version[0] ^= 0x80;
            base.config = base.config.with_fork_version(ForkName::Fulu, version);
            "FULU_FORK_VERSION"
        }
    };
    let reference = ChainId {
        genesis,
        config: Config::mainnet(),
    };
    let actual = first_chain_difference(&reference, &base, NOW).expect("deliberate mismatch");
    assert!(
        actual.starts_with(expected),
        "wrong first difference: expected {expected}, got {actual}"
    );
}

pub fn check_follow(case: &ScheduleCase) {
    assert!(valid_case(case));
    let current = configuration(&case.current);
    let served = served(case);
    let merged = merge_schedule(&current, &served.configs, &served.say, NOW);
    let followed = follow_schedule(&current, &served, NOW, false);
    assert_eq!(
        followed,
        (merged.config != current).then_some(merged.config),
        "follow_schedule differed from the merge result: {case:?}"
    );
    let warned = follow_schedule(&current, &served, NOW, true);
    assert_eq!(
        warned, followed,
        "warning disagreements changed the follow result: {case:?}"
    );
}
