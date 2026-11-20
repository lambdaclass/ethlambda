//! Keeping the client on one chain across every configured beacon node, and
//! following the fork schedule as the network publishes it.
//!
//! The client learns its chain from the beacon nodes at startup, and this
//! module is what keeps that answer honest afterwards:
//!
//! - Every node is compared with the chain the client started on
//!   ([`first_chain_difference`]). A node on another chain is skipped by every
//!   fallback call until a later check finds it compatible again (see
//!   [`crate::beacon_node::fallback::FallbackBeaconNode::check_nodes`]).
//! - A fork the network schedules after startup is taken from the compatible
//!   nodes ([`merge_schedule`]) and swapped into the configuration the slot
//!   clock and the signing domains share, so a node upgraded to a new fork
//!   does not leave the client signing under the old one.
//!
//! [`run`] drives both from one background task. It is separate from the duty
//! loop, so a node that hangs until its request timeout delays a check and
//! never a duty.

use std::sync::Arc;
use std::time::SystemTime;

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::constants::FAR_FUTURE_EPOCH;
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::preset::slots_per_epoch;
use ethlambda_types::beacon::primitives::{Epoch, Version};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::beacon_node::fallback::{CheckScope, FallbackBeaconNode, NodeAnswer};
use crate::beacon_node::{BeaconNodeApi, Genesis};
use crate::signing::SigningContext;
use crate::slot_clock::SlotClock;

/// What identifies a chain to this client: its genesis and the configuration
/// a node serves for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainId {
    pub genesis: Genesis,
    pub config: Config,
}

fn epoch_text(epoch: Epoch) -> String {
    if epoch == FAR_FUTURE_EPOCH {
        "unscheduled".to_string()
    } else {
        epoch.to_string()
    }
}

fn version_text(version: Version) -> String {
    format!("0x{}", hex::encode(version))
}

fn fork_key(fork: ForkName, suffix: &str) -> String {
    format!("{}_FORK_{suffix}", fork.as_str().to_uppercase())
}

/// The first field that makes `theirs` a different chain from `ours`, named
/// with both values, or `None` when a node serving `theirs` can be used.
///
/// Checked in this order: `PRESET_BASE`, the genesis time and validators root,
/// the slot duration, `GENESIS_FORK_VERSION`, then each fork from altair on.
///
/// A fork's epoch and version must match, except while the fork is in the
/// future under both schedules (both epochs are greater than `current_epoch`):
/// there the two may differ, because one node is upgraded and the other not
/// yet, and [`merge_schedule`] follows the change. It is the rule the beacon
/// node's `first_config_difference` applies to a fork that may still move on a
/// resume. Once either schedule has the fork active, the two have to agree.
///
/// The preset comes first: a node naming another one (`PRESET_BASE`) has other
/// SSZ bounds and another epoch length, which every later field would be read
/// against. A node whose spec cannot be parsed under its own preset's values
/// at all (`Error::Preset`) is incompatible for the same reason.
pub fn first_chain_difference(
    ours: &ChainId,
    theirs: &ChainId,
    current_epoch: Epoch,
) -> Option<String> {
    if ours.config.preset_base != theirs.config.preset_base {
        return Some(format!(
            "PRESET_BASE (ours {}, theirs {})",
            ours.config.preset_base, theirs.config.preset_base
        ));
    }
    if ours.genesis.genesis_time != theirs.genesis.genesis_time {
        return Some(format!(
            "genesis_time (ours {}, theirs {})",
            ours.genesis.genesis_time, theirs.genesis.genesis_time
        ));
    }
    if ours.genesis.genesis_validators_root != theirs.genesis.genesis_validators_root {
        return Some(format!(
            "genesis_validators_root (ours {:?}, theirs {:?})",
            ours.genesis.genesis_validators_root, theirs.genesis.genesis_validators_root
        ));
    }
    if ours.config.slot_duration_ms != theirs.config.slot_duration_ms {
        return Some(format!(
            "slot_duration_ms (ours {}, theirs {})",
            ours.config.slot_duration_ms, theirs.config.slot_duration_ms
        ));
    }
    let (ours, theirs) = (&ours.config, &theirs.config);
    let genesis_version = ForkName::Phase0;
    if ours.fork_version(genesis_version) != theirs.fork_version(genesis_version) {
        return Some(format!(
            "GENESIS_FORK_VERSION (ours {}, theirs {})",
            version_text(ours.fork_version(genesis_version)),
            version_text(theirs.fork_version(genesis_version))
        ));
    }
    for fork in ForkName::ALL {
        if fork == ForkName::Phase0 {
            continue;
        }
        let (our_epoch, their_epoch) = (ours.fork_epoch(fork), theirs.fork_epoch(fork));
        if our_epoch > current_epoch && their_epoch > current_epoch {
            continue;
        }
        if our_epoch != their_epoch {
            return Some(format!(
                "{} (ours {}, theirs {})",
                fork_key(fork, "EPOCH"),
                epoch_text(our_epoch),
                epoch_text(their_epoch)
            ));
        }
        if ours.fork_version(fork) != theirs.fork_version(fork) {
            return Some(format!(
                "{} (ours {}, theirs {})",
                fork_key(fork, "VERSION"),
                version_text(ours.fork_version(fork)),
                version_text(theirs.fork_version(fork))
            ));
        }
    }
    None
}

/// The result of [`merge_schedule`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleMerge {
    /// The configuration to run on: `current` with the changes applied.
    pub config: Config,
    /// One line per field that changed, old value to new.
    pub changes: Vec<String>,
    /// One line per future fork the compatible nodes disagree about.
    pub disagreements: Vec<String>,
}

/// The duty offsets, by their key, as read and written on a [`Config`].
type Offset = (&'static str, fn(&Config) -> u64, fn(&mut Config, u64));

const OFFSETS: [Offset; 10] = [
    (
        "ATTESTATION_DUE_BPS",
        |c| c.attestation_due_bps,
        |c, v| c.attestation_due_bps = v,
    ),
    (
        "AGGREGATE_DUE_BPS",
        |c| c.aggregate_due_bps,
        |c, v| c.aggregate_due_bps = v,
    ),
    (
        "ATTESTATION_DUE_BPS_GLOAS",
        |c| c.attestation_due_bps_gloas,
        |c, v| c.attestation_due_bps_gloas = v,
    ),
    (
        "AGGREGATE_DUE_BPS_GLOAS",
        |c| c.aggregate_due_bps_gloas,
        |c, v| c.aggregate_due_bps_gloas = v,
    ),
    (
        "SYNC_MESSAGE_DUE_BPS",
        |c| c.sync_message_due_bps,
        |c, v| c.sync_message_due_bps = v,
    ),
    (
        "CONTRIBUTION_DUE_BPS",
        |c| c.contribution_due_bps,
        |c, v| c.contribution_due_bps = v,
    ),
    (
        "SYNC_MESSAGE_DUE_BPS_GLOAS",
        |c| c.sync_message_due_bps_gloas,
        |c, v| c.sync_message_due_bps_gloas = v,
    ),
    (
        "CONTRIBUTION_DUE_BPS_GLOAS",
        |c| c.contribution_due_bps_gloas,
        |c, v| c.contribution_due_bps_gloas = v,
    ),
    (
        "PAYLOAD_DUE_BPS",
        |c| c.payload_due_bps,
        |c, v| c.payload_due_bps = v,
    ),
    (
        "PAYLOAD_ATTESTATION_DUE_BPS",
        |c| c.payload_attestation_due_bps,
        |c, v| c.payload_attestation_due_bps = v,
    ),
];

/// What the client's schedule becomes given what the compatible `nodes` serve,
/// as `(position, configuration)` pairs in list order.
///
/// Only a fork that is still in the future under `current` (its epoch is
/// greater than `current_epoch`) may change, and only to an epoch that is also
/// in the future: a fork that is active, or about to be by the clock, is part
/// of what the client has already signed under and is left alone. A node that
/// reports another epoch or version for such a fork is not compatible, and
/// [`first_chain_difference`] has already left it out of `nodes`.
///
/// For each such fork the node reporting the lowest epoch wins, with its
/// version, and list order breaks a tie: a node that has the fork scheduled
/// beats one that reports it as unscheduled, because the network moves toward
/// the fork, and a node that has not been upgraded yet is the one behind. Nodes
/// that disagree about a fork are listed in
/// [`ScheduleMerge::disagreements`], since the one without the fork becomes
/// incompatible when its epoch arrives.
///
/// The duty offsets are taken from the first node, because an upgraded node
/// may start serving the gloas offsets and they identify no chain.
///
/// Everything else (genesis, slot duration, past forks) stays as it is.
pub fn merge_schedule(
    current: &Config,
    nodes: &[(usize, Config)],
    current_epoch: Epoch,
) -> ScheduleMerge {
    let mut config = current.clone();
    let mut changes = Vec::new();
    let mut disagreements = Vec::new();

    for fork in ForkName::ALL {
        if fork == ForkName::Phase0 || current.fork_epoch(fork) <= current_epoch {
            continue;
        }
        let reports: Vec<(usize, Epoch, Version)> = nodes
            .iter()
            .filter(|(_, node)| node.fork_epoch(fork) > current_epoch)
            .map(|(position, node)| (*position, node.fork_epoch(fork), node.fork_version(fork)))
            .collect();
        // The first of the lowest epochs, so list order breaks a tie.
        let Some(&(_, epoch, version)) = reports.iter().min_by_key(|(_, epoch, _)| *epoch) else {
            continue;
        };

        // The version of an unscheduled fork says nothing, so two nodes that
        // both leave a fork unscheduled agree whatever it holds.
        let differs = |(_, other_epoch, other_version): &(usize, Epoch, Version)| {
            *other_epoch != epoch || (epoch != FAR_FUTURE_EPOCH && *other_version != version)
        };
        if reports.iter().any(differs) {
            let lines: Vec<String> = reports
                .iter()
                .map(|(position, epoch, _)| format!("node {position}: {}", epoch_text(*epoch)))
                .collect();
            disagreements.push(format!(
                "{} ({})",
                fork_key(fork, "EPOCH"),
                lines.join(", ")
            ));
        }

        let old_epoch = current.fork_epoch(fork);
        if epoch == FAR_FUTURE_EPOCH && old_epoch == FAR_FUTURE_EPOCH {
            continue;
        }
        if epoch != old_epoch {
            changes.push(format!(
                "{} {} -> {}",
                fork_key(fork, "EPOCH"),
                epoch_text(old_epoch),
                epoch_text(epoch)
            ));
            config = config.with_fork_epoch(fork, epoch);
        }
        // An unscheduled fork keeps the version it had: the node's is a
        // default, not a decision.
        if epoch != FAR_FUTURE_EPOCH && version != current.fork_version(fork) {
            changes.push(format!(
                "{} {} -> {}",
                fork_key(fork, "VERSION"),
                version_text(current.fork_version(fork)),
                version_text(version)
            ));
            config = config.with_fork_version(fork, version);
        }
    }

    if let Some((_, first)) = nodes.first() {
        for (key, get, set) in OFFSETS {
            if get(first) != get(&config) {
                changes.push(format!("{key} {} -> {}", get(&config), get(first)));
                set(&mut config, get(first));
            }
        }
    }

    ScheduleMerge {
        config,
        changes,
        disagreements,
    }
}

/// One round of the check: ask the nodes `scope` selects, and after a check of
/// every node, follow the schedule the compatible ones serve.
///
/// The client's schedule is only ever replaced here, and only from a check of
/// every node, so one slow answer cannot move it on its own.
pub async fn check_once<B: BeaconNodeApi>(
    nodes: &FallbackBeaconNode<B>,
    genesis: Genesis,
    context: &SigningContext,
    epoch: Epoch,
    scope: CheckScope,
) {
    let ours = ChainId {
        genesis,
        config: (*context.config()).clone(),
    };
    let answers = nodes.check_nodes(&ours, epoch, scope).await;
    if scope != CheckScope::All {
        return;
    }

    let compatible: Vec<(usize, Config)> = answers
        .into_iter()
        .filter_map(|(position, answer)| match answer {
            NodeAnswer::Compatible(config) => Some((position, *config)),
            _ => None,
        })
        .collect();
    let merge = merge_schedule(&ours.config, &compatible, epoch);
    for disagreement in &merge.disagreements {
        warn!(
            %epoch,
            %disagreement,
            "Beacon nodes disagree about a fork that is not active yet; a node without it stops \
             being used when its epoch arrives"
        );
    }
    if merge.config != ours.config {
        let changes = merge.changes.join("; ");
        context.replace_config(merge.config);
        warn!(
            %epoch,
            %changes,
            "The beacon nodes changed the fork schedule; the validator client now follows it"
        );
    }
}

/// Run the check until `shutdown`: the nodes that are not usable every slot,
/// every node at the first slot of each epoch.
///
/// The startup check already covered every node, so the first full one is at
/// the next epoch's first slot.
pub async fn run<B: BeaconNodeApi>(
    nodes: Arc<FallbackBeaconNode<B>>,
    genesis: Genesis,
    clock: SlotClock,
    context: Arc<SigningContext>,
    shutdown: CancellationToken,
) {
    let mut full_checked = clock.now().map(|slot| clock.epoch_of(slot));
    loop {
        let now = SystemTime::now();
        let next = clock.slot_at(now).map_or(0, |slot| slot + 1);
        let delay = clock
            .start_of(next)
            .duration_since(now)
            .unwrap_or(std::time::Duration::ZERO);
        tokio::select! {
            () = shutdown.cancelled() => return,
            () = tokio::time::sleep(delay) => {}
        }

        let slot = clock.slot_at(SystemTime::now()).unwrap_or(next);
        let epoch = clock.epoch_of(slot);
        let scope = if full_checked == Some(epoch) {
            CheckScope::OnlyUnusable
        } else {
            full_checked = Some(epoch);
            CheckScope::All
        };
        tokio::select! {
            () = shutdown.cancelled() => return,
            () = check_once(&nodes, genesis, &context, epoch, scope) => {}
        }
    }
}

/// The epoch the wall clock is in on `chain`, or 0 before its genesis.
pub fn current_epoch_of(chain: &ChainId) -> Epoch {
    let clock = SlotClock::from_config(chain.genesis.genesis_time, &chain.config);
    clock.now().map_or(0, |slot| slot / slots_per_epoch())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::beacon::primitives::Root;

    fn chain(config: Config) -> ChainId {
        ChainId {
            genesis: Genesis {
                genesis_time: 1_606_824_023,
                genesis_validators_root: Root::repeat_byte(0xaa),
            },
            config,
        }
    }

    fn mainnet() -> ChainId {
        chain(Config::mainnet())
    }

    /// A current epoch after every mainnet fork up to fulu, before gloas.
    const NOW: Epoch = 500_000;

    #[test]
    fn identical_chains_have_no_difference() {
        assert_eq!(first_chain_difference(&mainnet(), &mainnet(), NOW), None);
    }

    #[test]
    fn a_different_preset_is_named_first() {
        let mut other = chain(Config::minimal());
        other.genesis.genesis_time += 1;
        let difference = first_chain_difference(&mainnet(), &other, NOW).expect("differs");
        assert!(difference.starts_with("PRESET_BASE"), "got {difference}");
    }

    #[test]
    fn a_different_genesis_is_named() {
        let mut other = mainnet();
        other.genesis.genesis_time += 1;
        let difference = first_chain_difference(&mainnet(), &other, NOW).expect("differs");
        assert!(difference.starts_with("genesis_time"), "got {difference}");

        let mut other = mainnet();
        other.genesis.genesis_validators_root = Root::repeat_byte(0xbb);
        let difference = first_chain_difference(&mainnet(), &other, NOW).expect("differs");
        assert!(
            difference.starts_with("genesis_validators_root"),
            "got {difference}"
        );
    }

    #[test]
    fn a_different_slot_duration_or_genesis_version_is_named() {
        let mut config = Config::mainnet();
        config.slot_duration_ms = 6_000;
        let difference = first_chain_difference(&mainnet(), &chain(config), NOW).expect("differs");
        assert!(
            difference.starts_with("slot_duration_ms"),
            "got {difference}"
        );

        let config = Config::mainnet().with_fork_version(ForkName::Phase0, [9, 9, 9, 9]);
        let difference = first_chain_difference(&mainnet(), &chain(config), NOW).expect("differs");
        assert!(
            difference.starts_with("GENESIS_FORK_VERSION"),
            "got {difference}"
        );
    }

    #[test]
    fn a_moved_active_fork_is_a_difference_in_epoch_or_version() {
        let epoch = Config::mainnet().fork_epoch(ForkName::Electra);
        let moved = Config::mainnet().with_fork_epoch(ForkName::Electra, epoch + 1);
        let difference = first_chain_difference(&mainnet(), &chain(moved), NOW).expect("differs");
        assert!(
            difference.starts_with("ELECTRA_FORK_EPOCH"),
            "got {difference}"
        );

        let reversioned = Config::mainnet().with_fork_version(ForkName::Electra, [1, 2, 3, 4]);
        let difference =
            first_chain_difference(&mainnet(), &chain(reversioned), NOW).expect("differs");
        assert!(
            difference.starts_with("ELECTRA_FORK_VERSION"),
            "got {difference}"
        );
    }

    #[test]
    fn a_fork_in_the_future_under_both_schedules_may_differ() {
        let scheduled = Config::mainnet().with_fork_epoch(ForkName::Gloas, NOW + 100);
        assert_eq!(
            first_chain_difference(&mainnet(), &chain(scheduled.clone()), NOW),
            None
        );
        let later = Config::mainnet().with_fork_epoch(ForkName::Gloas, NOW + 200);
        assert_eq!(
            first_chain_difference(&chain(scheduled), &chain(later), NOW),
            None
        );
    }

    /// Once the fork is active under either schedule the two must agree: a
    /// node still holding it as unscheduled is the one that was not upgraded.
    #[test]
    fn a_fork_that_has_arrived_must_be_on_both_schedules() {
        let scheduled = Config::mainnet().with_fork_epoch(ForkName::Gloas, NOW + 100);
        let difference = first_chain_difference(&chain(scheduled.clone()), &mainnet(), NOW + 100)
            .expect("differs");
        assert!(
            difference.starts_with("GLOAS_FORK_EPOCH"),
            "got {difference}"
        );
        // Active under ours only, the other direction too.
        let difference =
            first_chain_difference(&mainnet(), &chain(scheduled), NOW + 100).expect("differs");
        assert!(
            difference.starts_with("GLOAS_FORK_EPOCH"),
            "got {difference}"
        );
    }

    fn with_gloas(epoch: Epoch, version: Version) -> Config {
        Config::mainnet()
            .with_fork_epoch(ForkName::Gloas, epoch)
            .with_fork_version(ForkName::Gloas, version)
    }

    #[test]
    fn a_newly_scheduled_fork_is_taken_from_the_nodes() {
        let current = Config::mainnet();
        let nodes = [(0, with_gloas(NOW + 100, [8, 0, 0, 0]))];
        let merge = merge_schedule(&current, &nodes, NOW);

        assert_eq!(merge.config.fork_epoch(ForkName::Gloas), NOW + 100);
        assert_eq!(merge.config.fork_version(ForkName::Gloas), [8, 0, 0, 0]);
        assert_eq!(merge.changes.len(), 2, "got {:?}", merge.changes);
        assert!(merge.disagreements.is_empty());
    }

    #[test]
    fn nothing_changes_when_the_nodes_agree_with_the_client() {
        let current = with_gloas(NOW + 100, [7, 0, 0, 0]);
        let nodes = [(0, current.clone()), (1, current.clone())];
        let merge = merge_schedule(&current, &nodes, NOW);
        assert_eq!(merge.config, current);
        assert!(merge.changes.is_empty());
        assert!(merge.disagreements.is_empty());
    }

    /// One node upgraded, one not: the upgraded one's epoch wins, and the
    /// disagreement is reported for the warning.
    #[test]
    fn nodes_disagreeing_about_a_future_fork_take_the_lowest_epoch() {
        let current = Config::mainnet();
        let nodes = [
            (0, Config::mainnet()),
            (1, with_gloas(NOW + 100, [7, 0, 0, 0])),
            (2, with_gloas(NOW + 300, [7, 0, 0, 0])),
        ];
        let merge = merge_schedule(&current, &nodes, NOW);

        assert_eq!(merge.config.fork_epoch(ForkName::Gloas), NOW + 100);
        assert_eq!(
            merge.disagreements.len(),
            1,
            "got {:?}",
            merge.disagreements
        );
        let line = &merge.disagreements[0];
        assert!(
            line.contains("GLOAS_FORK_EPOCH")
                && line.contains("node 0: unscheduled")
                && line.contains("node 1")
                && line.contains("node 2"),
            "got {line}"
        );
    }

    #[test]
    fn a_tie_goes_to_the_earlier_node() {
        let current = Config::mainnet();
        let nodes = [
            (0, with_gloas(NOW + 100, [7, 0, 0, 0])),
            (1, with_gloas(NOW + 100, [8, 0, 0, 0])),
        ];
        let merge = merge_schedule(&current, &nodes, NOW);
        assert_eq!(merge.config.fork_version(ForkName::Gloas), [7, 0, 0, 0]);
        assert_eq!(merge.disagreements.len(), 1, "the versions differ");
    }

    #[test]
    fn a_fork_that_is_not_in_the_future_is_never_moved() {
        // Fulu is active in the client's schedule; a node reporting another
        // epoch for it has no say here (it is incompatible by the check).
        let current = Config::mainnet();
        let moved = Config::mainnet().with_fork_epoch(ForkName::Fulu, NOW + 5);
        let merge = merge_schedule(&current, &[(0, moved)], NOW);
        assert_eq!(merge.config, current);
    }

    #[test]
    fn a_fork_every_node_leaves_unscheduled_stays_as_it_is() {
        let current = Config::mainnet();
        let mut node = Config::mainnet();
        node.gloas_fork_version = [9, 9, 9, 9];
        let merge = merge_schedule(&current, &[(0, node), (1, Config::mainnet())], NOW);
        assert_eq!(merge.config, current);
        assert!(merge.disagreements.is_empty());
    }

    #[test]
    fn the_duty_offsets_follow_the_first_node() {
        let current = Config::mainnet();
        let mut upgraded = Config::mainnet();
        upgraded.attestation_due_bps_gloas = 2_000;
        let merge = merge_schedule(&current, &[(0, upgraded), (1, Config::mainnet())], NOW);
        assert_eq!(merge.config.attestation_due_bps_gloas, 2_000);
        assert_eq!(merge.changes.len(), 1, "got {:?}", merge.changes);
    }

    // The checks through the fallback, against scripted mock nodes.

    use crate::beacon_node::mock::MockBeaconNode;
    use crate::error::Error;
    use crate::shared_config::SharedConfig;
    use ethlambda_types::beacon::constants::DOMAIN_BEACON_ATTESTER;
    use ethlambda_types::beacon::signing::compute_domain;

    fn genesis() -> Genesis {
        Genesis {
            genesis_time: 1_606_824_023,
            genesis_validators_root: Root::repeat_byte(0xaa),
        }
    }

    /// A node on mainnet's schedule and `genesis()`'s chain.
    fn node() -> MockBeaconNode {
        let mut node = MockBeaconNode::new();
        node.genesis = Some(genesis());
        node
    }

    async fn established(nodes: Vec<MockBeaconNode>) -> Arc<FallbackBeaconNode<MockBeaconNode>> {
        let fallback = Arc::new(FallbackBeaconNode::new(nodes));
        fallback
            .establish(|_| Ok(NOW))
            .await
            .expect("a node answers");
        fallback
    }

    fn context_and_clock() -> (Arc<SigningContext>, SlotClock) {
        let shared = SharedConfig::new(Config::mainnet());
        let context = Arc::new(SigningContext::with_shared(
            shared.clone(),
            genesis().genesis_validators_root,
        ));
        let clock = SlotClock::from_shared(genesis().genesis_time, shared);
        (context, clock)
    }

    /// The issue's failover case: node 1 is on another chain, so when node 0
    /// fails no duty call reaches it, and the error says it was skipped.
    #[tokio::test]
    async fn a_node_on_another_chain_is_never_called_for_a_duty() {
        let first = node().failing_call("attester_duties", "duties down");
        let second = node()
            .with_genesis_root(Root::repeat_byte(0xbb))
            .with_duties(3, Root::repeat_byte(7), vec![]);
        let fallback = established(vec![first, second]).await;

        let err = fallback
            .attester_duties(3, &[])
            .await
            .expect_err("the only compatible node fails");

        assert!(matches!(err, Error::AllBeaconNodesFailed(_)), "got {err:?}");
        assert!(err.to_string().contains("skipped"), "got {err}");
        assert_eq!(*fallback.nodes()[1].duties_calls.lock().expect("lock"), 0);
    }

    #[tokio::test]
    async fn every_node_unusable_is_an_error_that_says_so() {
        let fallback = established(vec![node(), node()]).await;
        let (context, _) = context_and_clock();
        // Both nodes now claim another chain.
        for node in fallback.nodes() {
            node.set_spec(Config::mainnet().with_fork_version(ForkName::Phase0, [5, 5, 5, 5]));
        }
        check_once(&fallback, genesis(), &context, NOW, CheckScope::All).await;

        let err = fallback
            .attester_duties(3, &[])
            .await
            .expect_err("no node is usable");
        assert!(
            err.to_string().contains("no configured beacon node is on"),
            "got {err}"
        );
    }

    /// A node on the minimal preset while the reference is mainnet is marked
    /// incompatible and never asked for a duty.
    #[tokio::test]
    async fn a_node_on_another_preset_is_incompatible() {
        let second =
            node()
                .with_spec(Config::minimal())
                .with_duties(3, Root::repeat_byte(7), vec![]);
        let fallback =
            established(vec![node().failing_call("attester_duties", "down"), second]).await;

        let err = fallback
            .attester_duties(3, &[])
            .await
            .expect_err("only the first node is usable, and it fails");
        assert!(matches!(err, Error::AllBeaconNodesFailed(_)), "got {err:?}");
        assert_eq!(*fallback.nodes()[1].duties_calls.lock().expect("lock"), 0);
    }

    #[tokio::test]
    async fn startup_fails_when_no_node_answers() {
        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::failing("down"),
            MockBeaconNode::failing("also down"),
        ]);
        let err = fallback
            .establish(|_| Ok(NOW))
            .await
            .expect_err("nothing answers");
        assert!(matches!(err, Error::AllBeaconNodesFailed(_)), "got {err:?}");
        assert!(err.to_string().contains("also down"), "got {err}");
    }

    /// A node that did not answer at startup has never been checked, so it is
    /// not failed over to until a later check verifies it.
    #[tokio::test]
    async fn a_node_that_never_answered_is_not_used_until_checked() {
        let (context, _) = context_and_clock();
        let second = node().with_duties(3, Root::repeat_byte(7), vec![]);
        second
            .failures
            .lock()
            .expect("lock")
            .insert("genesis", "booting".to_string());
        let fallback =
            established(vec![node().failing_call("attester_duties", "down"), second]).await;

        let err = fallback.attester_duties(3, &[]).await.expect_err("skipped");
        assert!(matches!(err, Error::AllBeaconNodesFailed(_)), "got {err:?}");
        assert_eq!(*fallback.nodes()[1].duties_calls.lock().expect("lock"), 0);

        // It comes up and the next unusable-nodes round lets it in.
        fallback.nodes()[1].failures.lock().expect("lock").clear();
        check_once(
            &fallback,
            genesis(),
            &context,
            NOW,
            CheckScope::OnlyUnusable,
        )
        .await;
        let duties = fallback.attester_duties(3, &[]).await.expect("node 1 now");
        assert_eq!(duties.dependent_root, Root::repeat_byte(7));
    }

    /// A node that reports a gloas epoch after startup moves the clock and
    /// the signing domains through the shared handle.
    #[tokio::test]
    async fn a_fork_scheduled_after_startup_is_followed() {
        let (context, clock) = context_and_clock();
        let fallback = established(vec![node()]).await;
        let gloas_epoch = NOW + 100;
        let gloas_slot = gloas_epoch * slots_per_epoch();
        assert!(!clock.is_gloas(gloas_slot));

        fallback.nodes()[0].set_spec(with_gloas(gloas_epoch, [8, 0, 0, 0]));
        check_once(&fallback, genesis(), &context, NOW, CheckScope::All).await;

        assert!(clock.is_gloas(gloas_slot), "the clock shares the handle");
        assert_eq!(
            context.domain(DOMAIN_BEACON_ATTESTER, gloas_epoch),
            compute_domain(
                DOMAIN_BEACON_ATTESTER,
                [8, 0, 0, 0],
                genesis().genesis_validators_root
            )
        );
    }

    /// A node that moves a fork already active is on another chain: it is
    /// marked incompatible and the client keeps its schedule.
    #[tokio::test]
    async fn a_node_moving_an_active_fork_is_incompatible_and_the_schedule_stays() {
        let (context, _) = context_and_clock();
        let fallback = established(vec![node()]).await;
        let electra = Config::mainnet().fork_epoch(ForkName::Electra);
        fallback.nodes()[0]
            .set_spec(Config::mainnet().with_fork_epoch(ForkName::Electra, electra + 1));

        check_once(&fallback, genesis(), &context, NOW, CheckScope::All).await;

        assert_eq!(*context.config(), Config::mainnet());
        let err = fallback
            .attester_duties(3, &[])
            .await
            .expect_err("the node is out");
        assert!(matches!(err, Error::AllBeaconNodesFailed(_)), "got {err:?}");
        assert_eq!(*fallback.nodes()[0].duties_calls.lock().expect("lock"), 0);
    }

    /// An outage says nothing about the chain: the flag stays up.
    #[tokio::test]
    async fn an_unreachable_node_keeps_its_flag() {
        let (context, _) = context_and_clock();
        let fallback = established(vec![node().with_duties(3, Root::repeat_byte(7), vec![])]).await;
        fallback.nodes()[0]
            .failures
            .lock()
            .expect("lock")
            .insert("spec", "down".to_string());
        check_once(&fallback, genesis(), &context, NOW, CheckScope::All).await;
        fallback.nodes()[0].failures.lock().expect("lock").clear();

        fallback
            .attester_duties(3, &[])
            .await
            .expect("still usable");
    }
}
