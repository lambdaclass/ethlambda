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
//! - With `--network`, the chain the client starts on must also be the one the
//!   operator named ([`ExpectedNetwork`]): its identity
//!   ([`first_identity_difference`]) decides which node may be the reference,
//!   and its fork schedule is compared with the one the client follows
//!   ([`schedule_differences`]), with a warning but never a refusal.
//! - A fork the network schedules after startup is taken from the compatible
//!   nodes once every one of them still answering schedules it alike
//!   ([`merge_schedule`]), and swapped into the configuration the slot clock
//!   and the signing domains share, so nodes upgraded to a new fork do not
//!   leave the client signing under the old one, and no single node can put
//!   one there.
//!
//! [`run`] drives both from one background task. It is separate from the duty
//! loop, so a node that hangs until its request timeout delays a check and
//! never a duty.

use std::sync::Arc;
use std::time::SystemTime;

use ethlambda_types::beacon::config::{Config, GasLimitSchedule, MAX_GAS_LIMIT_SCHEDULE_ENTRIES};
use ethlambda_types::beacon::constants::FAR_FUTURE_EPOCH;
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::preset::slots_per_epoch;
use ethlambda_types::beacon::primitives::{Epoch, Version};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::beacon_node::dto::{encode_hex, fork_epoch_key, fork_version_key};
use crate::beacon_node::fallback::FallbackBeaconNode;
use crate::beacon_node::{BeaconNodeApi, Genesis};
use crate::proposer_settings::ProposerSettings;
use crate::signing::SigningContext;
use crate::slot_clock::SlotClock;

/// What identifies a chain to this client: its genesis and the configuration
/// a node serves for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainId {
    pub genesis: Genesis,
    pub config: Config,
}

/// The network `--network` names, resolved from the binary's built-in
/// networks or a directory of published network files.
///
/// Only ever compared against, never run on: the client's configuration is
/// still the reference node's, and its schedule is still followed from the
/// beacon nodes. What this adds is which node may be the reference (one whose
/// identity matches, see [`first_identity_difference`]) and a warning when
/// the schedule the client follows differs from this one
/// ([`warn_if_schedule_differs`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedNetwork {
    /// The network's name, for logs and errors.
    pub name: String,
    pub chain: ChainId,
}

fn epoch_text(epoch: Epoch) -> String {
    if epoch == FAR_FUTURE_EPOCH {
        "unscheduled".to_string()
    } else {
        epoch.to_string()
    }
}

fn version_text(version: Version) -> String {
    encode_hex(&version)
}

/// `[epoch: gas limit, ...]`, for a log line: the change line and the startup
/// line.
///
/// Bounded like every other text a node sends that reaches a log line. A node
/// can serve a schedule of any length (only a beacon node's own config file is
/// held to [`MAX_GAS_LIMIT_SCHEDULE_ENTRIES`]), so at most that many entries
/// are written out and the rest are counted.
pub(crate) fn gas_limit_schedule_text(schedule: &GasLimitSchedule) -> String {
    let entries = schedule.entries();
    let shown: Vec<String> = entries
        .iter()
        .take(MAX_GAS_LIMIT_SCHEDULE_ENTRIES)
        .map(|entry| format!("{}: {}", entry.epoch, entry.gas_limit))
        .collect();
    let rest = entries.len() - shown.len();
    if rest == 0 {
        format!("[{}]", shown.join(", "))
    } else {
        format!("[{}, ... and {rest} more]", shown.join(", "))
    }
}

/// Whether every fork in `config` comes at or after the one before it. An
/// unscheduled fork is at `FAR_FUTURE_EPOCH`, so a schedule that leaves a fork
/// out has every later one unscheduled too.
fn forks_in_order(config: &Config) -> bool {
    ForkName::ALL
        .windows(2)
        .all(|pair| config.fork_epoch(pair[0]) <= config.fork_epoch(pair[1]))
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
///
/// Everything up to the forks is [`first_identity_difference`].
pub fn first_chain_difference(
    ours: &ChainId,
    theirs: &ChainId,
    current_epoch: Epoch,
) -> Option<String> {
    if let Some(difference) = first_identity_difference(ours, theirs) {
        return Some(difference);
    }
    let (ours, theirs) = (&ours.config, &theirs.config);
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
                fork_epoch_key(fork),
                epoch_text(our_epoch),
                epoch_text(their_epoch)
            ));
        }
        if ours.fork_version(fork) != theirs.fork_version(fork) {
            return Some(format!(
                "{} (ours {}, theirs {})",
                fork_version_key(fork),
                version_text(ours.fork_version(fork)),
                version_text(theirs.fork_version(fork))
            ));
        }
    }
    None
}

/// The first field that makes `theirs` a different network from `ours`
/// whatever either schedules: `PRESET_BASE`, the genesis time and validators
/// root, the slot duration, then `GENESIS_FORK_VERSION`, named with both
/// values. `None` when the two are one network.
///
/// What `--network` is checked with ([`ExpectedNetwork`]). None of these moves
/// over a network's life, so a node that differs in one is on another network
/// and never will be on this one, where a fork that differs may only mean
/// that the node or this binary predates a schedule change. Those are left to
/// [`first_chain_difference`] (between nodes) and [`schedule_differences`]
/// (against the named network).
pub fn first_identity_difference(ours: &ChainId, theirs: &ChainId) -> Option<String> {
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
    None
}

/// Every fork from altair on whose epoch, or version while scheduled, differs
/// between the schedule the client `follows` and the `network` config's, one
/// line each naming both values.
///
/// The version of a fork both leave unscheduled is a placeholder, so it is
/// not compared.
pub fn schedule_differences(follows: &Config, network: &Config) -> Vec<String> {
    let mut differences = Vec::new();
    for fork in ForkName::ALL {
        if fork == ForkName::Phase0 {
            continue;
        }
        let (followed_epoch, network_epoch) = (follows.fork_epoch(fork), network.fork_epoch(fork));
        if followed_epoch != network_epoch {
            differences.push(format!(
                "{} (beacon nodes {}, network config {})",
                fork_epoch_key(fork),
                epoch_text(followed_epoch),
                epoch_text(network_epoch)
            ));
        } else if followed_epoch != FAR_FUTURE_EPOCH
            && follows.fork_version(fork) != network.fork_version(fork)
        {
            differences.push(format!(
                "{} (beacon nodes {}, network config {})",
                fork_version_key(fork),
                version_text(follows.fork_version(fork)),
                version_text(network.fork_version(fork))
            ));
        }
    }
    differences
}

/// Warn when the schedule the client `follows` differs from the named
/// `network`'s ([`schedule_differences`]).
///
/// A warning and never a refusal: the client keeps following the beacon
/// nodes. Either side can be the stale one, the nodes not yet upgraded for a
/// fork the network scheduled, or this binary built before the network moved
/// one, and refusing on the second would stop every validator of an
/// operator who upgraded the nodes but not the client once the fork came.
pub fn warn_if_schedule_differs(network: &ExpectedNetwork, follows: &Config, epoch: Epoch) {
    let differences = schedule_differences(follows, &network.chain.config);
    if differences.is_empty() {
        return;
    }
    warn!(
        %epoch,
        network = %network.name,
        differences = %differences.join("; "),
        "The fork schedule the beacon nodes serve differs from --network's config; the client \
         follows the beacon nodes. One side is out of date: the beacon nodes, or --network's \
         config (this binary's for a built-in network, the directory's config.yaml \
         otherwise), whichever predates the network's schedule"
    );
}

/// What the schedule is followed from: see
/// [`FallbackBeaconNode::served_configs`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Served {
    /// The configuration each usable node last served, with its position, in
    /// list order. The duty offsets are read from the first.
    pub configs: Vec<(usize, Config)>,
    /// The positions, among `configs`, of the nodes with a say in the fork
    /// schedule: those that answered one of their last
    /// [`crate::beacon_node::fallback::MISSES_BEFORE_SAY_IS_LOST`] checks. A
    /// node quiet for longer has none, whatever it served before, so a node
    /// that went away (restarting for an upgrade, say) cannot hold a fork
    /// where it last saw it. One missed check does not cost the say, though:
    /// a single timeout would otherwise leave the other nodes to move the
    /// schedule without it, and a fork taken or moved that way is never
    /// undone (see [`merge_schedule`]).
    pub say: Vec<usize>,
}

/// The result of [`merge_schedule`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleMerge {
    /// The configuration to run on: `current` with the changes applied.
    pub config: Config,
    /// One line per field that changed, old value to new.
    pub changes: Vec<String>,
    /// Whether a fork's epoch or version is among `changes`, rather than only
    /// the duty offsets or the gas limit schedule.
    pub forks_changed: bool,
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
/// as `(position, configuration)` pairs in list order, of which only the
/// positions in `say` have a say in the forks (see [`Served::say`]).
///
/// Only a fork that is still in the future under `current` (its epoch is
/// greater than `current_epoch`) may change, and only to an epoch that is also
/// in the future: a fork that is active, or about to be by the clock, is part
/// of what the client has already signed under and is left alone. A node that
/// reports another epoch or version for such a fork is not compatible, and
/// [`first_chain_difference`] has already left it out of `nodes`.
///
/// For each such fork, among the nodes with a say:
///
/// - A fork the client has unscheduled is taken only when every one of them
///   schedules it, at the same epoch and with the same version. A node that
///   reports it unscheduled holds it off, as does one that schedules it
///   differently: one node (misconfigured, or lying) cannot put a fork on the
///   client's schedule that the others do not have, and refuse them all once
///   its epoch arrives. A node not yet upgraded therefore holds the fork off
///   until it is upgraded, or until it restarts for the upgrade and, missing
///   enough checks in a row, loses its say (see [`Served::say`]).
/// - A fork the client already has scheduled moves only once every one of
///   them that schedules it agrees on where to; one that reports it
///   unscheduled has not been upgraded, and does not hold a postponement off.
///   So one node cannot pull a fork the others agree on to another epoch or
///   version.
///
/// A fork the client has scheduled is never unscheduled: no node reporting it
/// does not mean the network dropped it. The node that had it may be
/// restarting for the upgrade, out of the merge for a few epochs, and
/// unscheduling the fork would refuse that node for good once the fork's
/// epoch arrives. A fork the network does cancel needs a restart.
///
/// Nodes that disagree about a fork are listed in
/// [`ScheduleMerge::disagreements`], since the ones the client's schedule does
/// not match become incompatible when its epoch arrives.
///
/// Each fork is merged on its own, so the result is checked as a whole: a
/// merge that would put a fork before the one it follows (fulu postponed past
/// gloas, say) leaves every fork where it was, and is reported as a
/// disagreement. `Config::fork_at_epoch` would otherwise answer a fork for
/// the epochs in between that matches no real one.
///
/// The duty offsets are taken from the first of `nodes`, say or not, because
/// an upgraded node may start serving the gloas offsets, and they identify no
/// chain. `GAS_LIMIT_SCHEDULE` is taken from the first of `nodes` that serves
/// a non-empty one, for the same reason, and empty when none does: a node
/// that leaves the key out (one that predates it, or Lighthouse while gloas
/// is unscheduled) reads as an empty schedule, which must not erase the one
/// another node serves. The caller passes what each node last served, so the
/// first node stays the first through a round it does not answer.
///
/// Everything else (genesis, slot duration, past forks) stays as it is.
pub fn merge_schedule(
    current: &Config,
    nodes: &[(usize, Config)],
    say: &[usize],
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
            .filter(|(position, node)| {
                say.contains(position) && node.fork_epoch(fork) > current_epoch
            })
            .map(|(position, node)| (*position, node.fork_epoch(fork), node.fork_version(fork)))
            .collect();
        let old_epoch = current.fork_epoch(fork);
        let old_version = current.fork_version(fork);
        // The lowest epoch reported, which is where the fork goes when the
        // nodes agree: what they agree on, or, for a scheduled fork, the one
        // epoch the nodes scheduling it name.
        let Some(&(_, lowest, lowest_version)) = reports.iter().min_by_key(|(_, epoch, _)| *epoch)
        else {
            continue;
        };

        // The version of an unscheduled fork says nothing, so two nodes that
        // both leave a fork unscheduled agree whatever it holds.
        let same = |(epoch_a, version_a): (Epoch, Version),
                    (epoch_b, version_b): (Epoch, Version)| {
            epoch_a == epoch_b && (epoch_a == FAR_FUTURE_EPOCH || version_a == version_b)
        };
        let agrees = |(_, epoch, version): &(usize, Epoch, Version)| {
            same((*epoch, *version), (lowest, lowest_version))
        };
        let scheduled_agree = reports
            .iter()
            .filter(|(_, epoch, _)| *epoch != FAR_FUTURE_EPOCH)
            .all(agrees);
        let all_agree = reports.iter().all(agrees);
        // Where the fork goes: see the doc above for each case.
        let taken = if old_epoch == FAR_FUTURE_EPOCH {
            all_agree
        } else {
            lowest != FAR_FUTURE_EPOCH && scheduled_agree
        };
        let (epoch, version) = if taken {
            (lowest, lowest_version)
        } else {
            (old_epoch, old_version)
        };

        let differs = |(_, other_epoch, other_version): &(usize, Epoch, Version)| {
            !same((*other_epoch, *other_version), (epoch, version))
        };
        if reports.iter().any(differs) {
            // The version too, for a scheduled fork: two nodes can agree on the
            // epoch and differ only there.
            let lines: Vec<String> = reports
                .iter()
                .map(|(position, epoch, version)| {
                    if *epoch == FAR_FUTURE_EPOCH {
                        format!("node {position}: unscheduled")
                    } else {
                        format!("node {position}: {epoch} ({})", version_text(*version))
                    }
                })
                .collect();
            disagreements.push(format!("{} ({})", fork_epoch_key(fork), lines.join(", ")));
        }

        if epoch == FAR_FUTURE_EPOCH && old_epoch == FAR_FUTURE_EPOCH {
            continue;
        }
        if epoch != old_epoch {
            changes.push(format!(
                "{} {} -> {}",
                fork_epoch_key(fork),
                epoch_text(old_epoch),
                epoch_text(epoch)
            ));
            config = config.with_fork_epoch(fork, epoch);
        }
        // An unscheduled fork keeps the version it had: the node's is a
        // default, not a decision.
        if epoch != FAR_FUTURE_EPOCH && version != old_version {
            changes.push(format!(
                "{} {} -> {}",
                fork_version_key(fork),
                version_text(old_version),
                version_text(version)
            ));
            config = config.with_fork_version(fork, version);
        }
    }

    // Only when the client's own schedule is in order, so a schedule that
    // was never ordered does not freeze every fork for good.
    if !changes.is_empty() && !forks_in_order(&config) && forks_in_order(current) {
        disagreements.push(format!(
            "the merged schedule would put a fork before the one it follows ({}); keeping \
             the client's",
            changes.join("; ")
        ));
        config = current.clone();
        changes.clear();
    }

    let forks_changed = !changes.is_empty();

    if let Some((_, first)) = nodes.first() {
        for (key, get, set) in OFFSETS {
            if get(first) != get(&config) {
                changes.push(format!("{key} {} -> {}", get(&config), get(first)));
                set(&mut config, get(first));
            }
        }
    }
    // The gas limit schedule too: it only names a default gas limit and
    // identifies no chain. A node may start serving it later (Lighthouse
    // leaves the key out while gloas is unscheduled), and [`run`] hands it
    // to the proposer settings. Only a node that serves one has a say.
    if !nodes.is_empty() {
        let served = nodes
            .iter()
            .map(|(_, node)| &node.gas_limit_schedule)
            .find(|schedule| !schedule.is_empty())
            .cloned()
            .unwrap_or_default();
        if served != config.gas_limit_schedule {
            changes.push(format!(
                "GAS_LIMIT_SCHEDULE {} -> {}",
                gas_limit_schedule_text(&config.gas_limit_schedule),
                gas_limit_schedule_text(&served)
            ));
            config.gas_limit_schedule = served;
        }
    }

    ScheduleMerge {
        config,
        changes,
        forks_changed,
        disagreements,
    }
}

/// One round of the check: ask every node, and follow the schedule the
/// compatible ones serve as each answer arrives.
///
/// Each answer is judged and merged the moment it arrives
/// ([`FallbackBeaconNode::check_nodes`]), so a node that hangs until its
/// request timeout holds back only its own: a prompt answer is judged while a
/// fork it reports is still ahead, rather than after the slow node's timeout
/// has carried the clock past the fork's epoch. `epoch_now` is read when
/// each answer is in, not before the requests go out: a request can take most
/// of its timeout, which on a short-slot network crosses an epoch boundary,
/// and a fork first learned at or after its epoch must be judged at the epoch
/// it is learned in (see [`first_chain_difference`]), not adopted as if it
/// were still ahead. Everything after that read is synchronous, so the
/// classification and the swap see the same epoch and the same schedule.
///
/// The schedule is merged from what every usable node last served
/// (`FallbackBeaconNode::served_configs`), not from this round's answers
/// alone: a node that misses one round keeps its configuration, so the merge
/// does not flip the duty offsets to the next node's while it is away. It
/// keeps its say in the forks only for a few missed checks, so a single
/// timeout does not hand the schedule to the other nodes, and a node that
/// stays away cannot hold a fork at an epoch the network has since moved
/// (see [`Served::say`]). A node still to answer
/// this round has the say its previous answer gave it, so one fast node
/// cannot take a fork the others, answering a moment later, do not have.
/// After startup the client's schedule is only ever replaced here.
///
/// A swap that changes `GAS_LIMIT_SCHEDULE` hands it to `settings` in the same
/// step, with no await in between, so the default gas limit follows the
/// schedule from the answer that moved it, not from the end of the round: a
/// node that hangs until its timeout does not hold it back either. Startup
/// gave `settings` the configuration's own schedule, so the two never differ
/// past that step.
///
/// Disagreements between nodes are warned about only when
/// `warn_disagreements`, once every answer is in: the caller asks once per
/// epoch, since a round runs every slot.
pub async fn check_once<B: BeaconNodeApi>(
    nodes: &FallbackBeaconNode<B>,
    genesis: Genesis,
    context: &SigningContext,
    settings: &ProposerSettings,
    epoch_now: impl Fn() -> Epoch,
    warn_disagreements: bool,
) {
    let ours = || ChainId {
        genesis,
        config: (*context.config()).clone(),
    };
    let follow = |epoch: Epoch, warn_disagreements: bool| {
        let current = (*context.config()).clone();
        let served = nodes.served_configs(epoch);
        if let Some(config) = follow_schedule(&current, &served, epoch, warn_disagreements) {
            // Proposer preferences, builder registrations and the
            // keymanager's `gas_limit` read the default gas limit from the
            // settings, which hold their own copy of the schedule.
            if config.gas_limit_schedule != current.gas_limit_schedule {
                settings.set_gas_limit_schedule(config.gas_limit_schedule.clone());
            }
            context.replace_config(config);
        }
    };
    nodes
        .check_nodes(ours, &epoch_now, |epoch| follow(epoch, false))
        .await;
    // Once more with every answer in, for the disagreement warnings.
    follow(epoch_now(), warn_disagreements);
}

/// [`merge_schedule`] with its outcome logged: the configuration to move to
/// when the compatible nodes serve a schedule that differs from `current`,
/// `None` when there is nothing to change.
pub fn follow_schedule(
    current: &Config,
    served: &Served,
    epoch: Epoch,
    warn_disagreements: bool,
) -> Option<Config> {
    let merge = merge_schedule(current, &served.configs, &served.say, epoch);
    let disagreements = if warn_disagreements {
        merge.disagreements.as_slice()
    } else {
        &[]
    };
    for disagreement in disagreements {
        warn!(
            %epoch,
            %disagreement,
            "Beacon nodes disagree about a fork that is not active yet; a node without it stops \
             being used when its epoch arrives"
        );
    }
    if merge.config == *current {
        return None;
    }
    let changes = merge.changes.join("; ");
    if merge.forks_changed {
        warn!(
            %epoch,
            %changes,
            "The beacon nodes changed the fork schedule; the validator client now follows it"
        );
    } else {
        info!(
            %epoch,
            %changes,
            "The beacon nodes changed a duty offset or the gas limit schedule; the validator \
             client now follows it"
        );
    }
    Some(merge.config)
}

/// Run the check until `shutdown`: every node, at the start of every slot.
///
/// Every node, not only the ones out of use: a node that was fine at the
/// epoch's first slot can be upgraded later in the epoch for a fork at the
/// next one, and the client has to read that schedule while the fork is still
/// ahead. Read only at the next epoch, the fork would be active already, and
/// the upgraded node refused for it. Two small requests per node per slot is
/// the price of that.
///
/// Disagreements are warned about once per epoch, at the epoch's first round,
/// and so, with `--network`, is a schedule that differs from the network's
/// ([`warn_if_schedule_differs`]), compared once that round's merge is done.
/// The first round is a slot after startup, so a difference the reference
/// node already had is said then.
///
/// `settings` get every gas limit schedule a round swaps into the client's
/// configuration (see [`check_once`]): they name the default gas limit from
/// it, and hold their own copy of it.
pub async fn run<B: BeaconNodeApi>(
    nodes: Arc<FallbackBeaconNode<B>>,
    genesis: Genesis,
    clock: SlotClock,
    context: Arc<SigningContext>,
    settings: Arc<ProposerSettings>,
    network: Option<ExpectedNetwork>,
    shutdown: CancellationToken,
) {
    let mut warned_epoch = None;
    let epoch_now = || clock.now().map_or(0, |slot| clock.epoch_of(slot));
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

        let epoch = epoch_now();
        let warn_disagreements = warned_epoch != Some(epoch);
        warned_epoch = Some(epoch);
        let round = check_once(
            &nodes,
            genesis,
            &context,
            &settings,
            epoch_now,
            warn_disagreements,
        );
        tokio::select! {
            () = shutdown.cancelled() => return,
            () = round => {}
        }
        if warn_disagreements && let Some(network) = &network {
            warn_if_schedule_differs(network, &context.config(), epoch);
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

    /// [`merge_schedule`] with every node given a say.
    fn merge(current: &Config, nodes: &[(usize, Config)], current_epoch: Epoch) -> ScheduleMerge {
        let say: Vec<usize> = nodes.iter().map(|(position, _)| *position).collect();
        merge_schedule(current, nodes, &say, current_epoch)
    }

    #[test]
    fn a_newly_scheduled_fork_is_taken_from_the_nodes() {
        let current = Config::mainnet();
        let nodes = [(0, with_gloas(NOW + 100, [8, 0, 0, 0]))];
        let merge = merge(&current, &nodes, NOW);

        assert_eq!(merge.config.fork_epoch(ForkName::Gloas), NOW + 100);
        assert_eq!(merge.config.fork_version(ForkName::Gloas), [8, 0, 0, 0]);
        assert_eq!(merge.changes.len(), 2, "got {:?}", merge.changes);
        assert!(merge.forks_changed);
        assert!(merge.disagreements.is_empty());
    }

    #[test]
    fn nothing_changes_when_the_nodes_agree_with_the_client() {
        let current = with_gloas(NOW + 100, [7, 0, 0, 0]);
        let nodes = [(0, current.clone()), (1, current.clone())];
        let merge = merge(&current, &nodes, NOW);
        assert_eq!(merge.config, current);
        assert!(merge.changes.is_empty());
        assert!(merge.disagreements.is_empty());
    }

    /// Nodes that do not all schedule a fork alike leave it off the client's
    /// schedule, and the disagreement is reported for the warning. One node
    /// reporting a fork the others do not have (misconfigured, or lying) would
    /// otherwise put it on the schedule alone, and every other node would be
    /// refused once its epoch arrived.
    #[test]
    fn a_fork_only_some_nodes_schedule_is_not_taken() {
        let current = Config::mainnet();
        let nodes = [
            (0, Config::mainnet()),
            (1, with_gloas(NOW + 100, [7, 0, 0, 0])),
            (2, with_gloas(NOW + 300, [7, 0, 0, 0])),
        ];
        let merge = merge(&current, &nodes, NOW);

        assert_eq!(merge.config, current);
        assert!(merge.changes.is_empty(), "got {:?}", merge.changes);
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

    /// Two nodes scheduling a fork at the same epoch with different versions
    /// do not agree, so neither version is taken.
    #[test]
    fn nodes_scheduling_a_fork_differently_hold_it_off() {
        let current = Config::mainnet();
        let nodes = [
            (0, with_gloas(NOW + 100, [7, 0, 0, 0])),
            (1, with_gloas(NOW + 100, [8, 0, 0, 0])),
        ];
        let merge = merge(&current, &nodes, NOW);
        assert_eq!(merge.config, current);
        assert_eq!(merge.disagreements.len(), 1, "the versions differ");
    }

    /// Every node with a say scheduling the fork alike is what takes it.
    #[test]
    fn a_fork_every_node_schedules_alike_is_taken() {
        let current = Config::mainnet();
        let upgraded = with_gloas(NOW + 100, [7, 0, 0, 0]);
        let nodes = [(0, upgraded.clone()), (1, upgraded)];
        let merge = merge(&current, &nodes, NOW);
        assert_eq!(merge.config.fork_epoch(ForkName::Gloas), NOW + 100);
        assert!(merge.disagreements.is_empty());
    }

    /// A node without a say (its last check failed: restarting for the
    /// upgrade, say) does not hold a fork off with what it served before.
    #[test]
    fn a_node_without_a_say_does_not_hold_a_fork_off() {
        let current = Config::mainnet();
        let nodes = [
            (0, Config::mainnet()),
            (1, with_gloas(NOW + 100, [7, 0, 0, 0])),
        ];
        let merge = merge_schedule(&current, &nodes, &[1], NOW);
        assert_eq!(merge.config.fork_epoch(ForkName::Gloas), NOW + 100);
        assert!(merge.disagreements.is_empty());
    }

    #[test]
    fn a_fork_that_is_not_in_the_future_is_never_moved() {
        // Fulu is active in the client's schedule; a node reporting another
        // epoch for it has no say here (it is incompatible by the check).
        let current = Config::mainnet();
        let moved = Config::mainnet().with_fork_epoch(ForkName::Fulu, NOW + 5);
        let merge = merge(&current, &[(0, moved)], NOW);
        assert_eq!(merge.config, current);
    }

    #[test]
    fn a_fork_every_node_leaves_unscheduled_stays_as_it_is() {
        let current = Config::mainnet();
        let mut node = Config::mainnet();
        node.gloas_fork_version = [9, 9, 9, 9];
        let merge = merge(&current, &[(0, node), (1, Config::mainnet())], NOW);
        assert_eq!(merge.config, current);
        assert!(merge.disagreements.is_empty());
    }

    #[test]
    fn the_duty_offsets_follow_the_first_node() {
        let current = Config::mainnet();
        let mut upgraded = Config::mainnet();
        upgraded.attestation_due_bps_gloas = 2_000;
        let merge = merge(&current, &[(0, upgraded), (1, Config::mainnet())], NOW);
        assert_eq!(merge.config.attestation_due_bps_gloas, 2_000);
        assert_eq!(merge.changes.len(), 1, "got {:?}", merge.changes);
    }

    fn with_gas_limit_schedule(epoch: Epoch, gas_limit: u64) -> Config {
        let mut config = Config::mainnet();
        config.gas_limit_schedule =
            vec![ethlambda_types::beacon::config::GasLimitScheduleEntry { epoch, gas_limit }]
                .into();
        config
    }

    /// A gas limit schedule the first node starts serving after startup (a
    /// Lighthouse node shows the key only once gloas is scheduled) is taken,
    /// as the duty offsets are, and so is one it changes; a later node's
    /// counts only while every node before it serves none, so a node without
    /// the key cannot erase a schedule another one serves.
    #[test]
    fn the_gas_limit_schedule_follows_the_first_node() {
        let current = Config::mainnet();
        let served = with_gas_limit_schedule(NOW + 10, 200_000_000);
        let taken = merge(&current, &[(0, served.clone()), (1, current.clone())], NOW);
        assert_eq!(taken.config.gas_limit_schedule, served.gas_limit_schedule);
        assert_eq!(
            taken.changes,
            [format!(
                "GAS_LIMIT_SCHEDULE [] -> [{}: 200000000]",
                NOW + 10
            )]
        );

        assert!(!taken.forks_changed);

        let other = with_gas_limit_schedule(NOW + 10, 100_000_000);
        let both = merge(&current, &[(0, other.clone()), (1, served.clone())], NOW);
        assert_eq!(both.config.gas_limit_schedule, other.gas_limit_schedule);

        // The first node serves none: the second's is taken, and once it is
        // held, the first node does not take it away.
        let second_only = merge(&current, &[(0, current.clone()), (1, served.clone())], NOW);
        assert_eq!(
            second_only.config.gas_limit_schedule,
            served.gas_limit_schedule
        );
        let kept = merge(&served, &[(0, current.clone()), (1, served.clone())], NOW);
        assert!(kept.changes.is_empty(), "got {:?}", kept.changes);

        // No node serves one any more: the schedule empties.
        let dropped = merge(&served, &[(0, current.clone()), (1, current.clone())], NOW);
        assert!(dropped.config.gas_limit_schedule.is_empty());

        let changed = with_gas_limit_schedule(NOW + 20, 300_000_000);
        let moved = merge(&served, &[(0, changed.clone())], NOW);
        assert_eq!(moved.config.gas_limit_schedule, changed.gas_limit_schedule);
    }

    /// A node can serve a schedule of any length, and its text goes into the
    /// change line and the startup line: at most
    /// `MAX_GAS_LIMIT_SCHEDULE_ENTRIES` entries are written out, the rest
    /// counted.
    #[test]
    fn the_gas_limit_schedule_text_is_bounded() {
        use ethlambda_types::beacon::config::GasLimitScheduleEntry;

        let schedule = |count: u64| -> GasLimitSchedule {
            let entries = (0..count).map(|epoch| GasLimitScheduleEntry {
                epoch,
                gas_limit: 60_000_000,
            });
            entries.collect::<Vec<_>>().into()
        };
        assert_eq!(gas_limit_schedule_text(&schedule(0)), "[]");
        assert_eq!(
            gas_limit_schedule_text(&schedule(2)),
            "[0: 60000000, 1: 60000000]"
        );

        let full = gas_limit_schedule_text(&schedule(MAX_GAS_LIMIT_SCHEDULE_ENTRIES as u64));
        assert!(!full.contains("more"), "{full}");

        let over = gas_limit_schedule_text(&schedule(100_000));
        let last_shown = format!("{}: 60000000", MAX_GAS_LIMIT_SCHEDULE_ENTRIES - 1);
        let first_hidden = format!(" {MAX_GAS_LIMIT_SCHEDULE_ENTRIES}: 60000000");
        let hidden = 100_000 - MAX_GAS_LIMIT_SCHEDULE_ENTRIES;
        assert!(over.contains(&last_shown), "{over}");
        assert!(!over.contains(&first_hidden), "{over}");
        assert!(
            over.ends_with(&format!(", ... and {hidden} more]")),
            "{over}"
        );
        assert!(over.len() < full.len() + 64, "{} bytes", over.len());
    }

    /// The only node that scheduled the fork is out of the merge (restarting
    /// for the upgrade, say) and the one left reports it unscheduled: the
    /// client keeps the fork, so the upgraded node is still usable when it
    /// comes back after the fork's epoch.
    #[test]
    fn an_adopted_fork_is_never_unscheduled() {
        let current = with_gloas(NOW + 10, [8, 0, 0, 0]);
        let merge = merge(&current, &[(1, Config::mainnet())], NOW);
        assert_eq!(merge.config, current);
        assert!(merge.changes.is_empty(), "got {:?}", merge.changes);
        assert_eq!(merge.disagreements.len(), 1, "the node without it");
    }

    /// One node reporting an earlier epoch, or another version, for a fork the
    /// client already schedules does not move it while another node keeps it.
    #[test]
    fn one_node_cannot_move_an_adopted_fork_the_others_keep() {
        let current = with_gloas(NOW + 10, [8, 0, 0, 0]);
        for other in [
            with_gloas(NOW + 2, [8, 0, 0, 0]),
            with_gloas(NOW + 10, [9, 9, 9, 9]),
        ] {
            let nodes = [(0, other), (1, current.clone())];
            let merge = merge(&current, &nodes, NOW);
            assert_eq!(merge.config, current);
            assert_eq!(merge.disagreements.len(), 1);
        }
    }

    /// A postponement every node that schedules the fork agrees on is
    /// followed, even while a node not yet upgraded leaves it unscheduled.
    #[test]
    fn an_adopted_fork_moves_once_every_node_scheduling_it_agrees() {
        let current = with_gloas(NOW + 10, [8, 0, 0, 0]);
        let nodes = [
            (0, with_gloas(NOW + 100, [8, 0, 0, 0])),
            (1, Config::mainnet()),
            (2, with_gloas(NOW + 100, [8, 0, 0, 0])),
        ];
        let merge = merge(&current, &nodes, NOW);
        assert_eq!(merge.config.fork_epoch(ForkName::Gloas), NOW + 100);
        assert_eq!(merge.changes.len(), 1, "got {:?}", merge.changes);
    }

    /// A merge that would leave a fork before the one it follows is refused
    /// whole: here the nodes agree on a gloas epoch before the client's
    /// scheduled fulu.
    #[test]
    fn a_merge_that_puts_forks_out_of_order_is_refused() {
        let current = Config::mainnet()
            .with_fork_epoch(ForkName::Fulu, NOW + 100)
            .with_fork_epoch(ForkName::Gloas, NOW + 200);
        let early_gloas = current.clone().with_fork_epoch(ForkName::Gloas, NOW + 50);
        let merge = merge(&current, &[(0, early_gloas.clone()), (1, early_gloas)], NOW);

        assert_eq!(merge.config, current);
        assert!(merge.changes.is_empty(), "got {:?}", merge.changes);
        assert!(
            merge
                .disagreements
                .iter()
                .any(|line| line.contains("before the one it follows")),
            "got {:?}",
            merge.disagreements
        );
    }

    /// The identity is what `--network` refuses on, so it must not include a
    /// fork: a moved fork is a schedule change the nodes may be ahead of.
    #[test]
    fn the_identity_leaves_the_forks_out() {
        let epoch = Config::mainnet().fork_epoch(ForkName::Electra);
        let moved = Config::mainnet().with_fork_epoch(ForkName::Electra, epoch + 1);
        assert_eq!(first_identity_difference(&mainnet(), &chain(moved)), None);

        let mut other = mainnet();
        other.genesis.genesis_validators_root = Root::repeat_byte(0xbb);
        let difference = first_identity_difference(&mainnet(), &other).expect("differs");
        assert!(
            difference.starts_with("genesis_validators_root"),
            "got {difference}"
        );

        let config = Config::mainnet().with_fork_version(ForkName::Phase0, [9, 9, 9, 9]);
        let difference = first_identity_difference(&mainnet(), &chain(config)).expect("differs");
        assert!(
            difference.starts_with("GENESIS_FORK_VERSION"),
            "got {difference}"
        );
    }

    #[test]
    fn a_schedule_differs_from_the_network_by_epoch_or_scheduled_version() {
        let network = with_gloas(NOW + 100, [8, 0, 0, 0]);
        assert!(schedule_differences(&network, &network).is_empty());

        // The nodes not upgraded yet, or this binary older than the network's
        // schedule: either way both values are named.
        let differences = schedule_differences(&Config::mainnet(), &network);
        assert_eq!(differences.len(), 1, "got {differences:?}");
        assert!(
            differences[0].starts_with("GLOAS_FORK_EPOCH")
                && differences[0].contains("beacon nodes unscheduled")
                && differences[0].contains(&format!("network config {}", NOW + 100)),
            "got {differences:?}"
        );

        let reversioned = with_gloas(NOW + 100, [9, 0, 0, 0]);
        let differences = schedule_differences(&reversioned, &network);
        assert_eq!(differences.len(), 1, "got {differences:?}");
        assert!(
            differences[0].starts_with("GLOAS_FORK_VERSION"),
            "got {differences:?}"
        );
    }

    /// An unscheduled fork's version is a placeholder, so two schedules that
    /// both leave the fork out agree whatever it holds.
    #[test]
    fn an_unscheduled_forks_version_is_no_schedule_difference() {
        let mut placeholder = Config::mainnet();
        placeholder.gloas_fork_version = [9, 9, 9, 9];
        assert!(schedule_differences(&placeholder, &Config::mainnet()).is_empty());
    }

    // The checks through the fallback, against scripted mock nodes.

    use crate::beacon_node::fallback::NodeAnswer;
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

    /// Proposer settings on `Config::mainnet()`'s empty gas limit schedule,
    /// as startup leaves them for `context_and_clock()`'s configuration.
    fn settings() -> ProposerSettings {
        ProposerSettings::new(ethlambda_types::beacon::primitives::Bytes32::ZERO, None)
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
        check_once(&fallback, genesis(), &context, &settings(), || NOW, true).await;

        let err = fallback
            .attester_duties(3, &[])
            .await
            .expect_err("no node is usable");
        assert!(
            err.to_string().contains("no configured beacon node is on"),
            "got {err}"
        );
    }

    /// `--network` on `genesis()`'s chain, on mainnet's config.
    fn named_network() -> ExpectedNetwork {
        ExpectedNetwork {
            name: "testnet".to_string(),
            chain: ChainId {
                genesis: genesis(),
                config: Config::mainnet(),
            },
        }
    }

    /// The first node answers, but on another network: the second, on the
    /// named one, is the reference, and the first never gets a duty call.
    #[tokio::test]
    async fn a_node_off_the_named_network_is_never_the_reference() {
        let first = node()
            .with_genesis_root(Root::repeat_byte(0xbb))
            .with_duties(3, Root::repeat_byte(7), vec![]);
        let second = node().failing_call("attester_duties", "down");
        let fallback = FallbackBeaconNode::new(vec![first, second]);

        let network = named_network();
        let mut seen = None;
        let chain = fallback
            .establish_on(Some(&network), |reference| {
                seen = Some(reference.clone());
                Ok(NOW)
            })
            .await
            .expect("the second node is on the network");

        assert_eq!(chain.genesis, genesis());
        assert_eq!(
            seen,
            Some(chain),
            "with_reference saw the named network's chain"
        );
        fallback
            .attester_duties(3, &[])
            .await
            .expect_err("only the second node is usable, and it fails");
        assert_eq!(*fallback.nodes()[0].duties_calls.lock().expect("lock"), 0);
    }

    /// Without a network named, the same first node is the reference, as it
    /// always was.
    #[tokio::test]
    async fn without_a_named_network_the_first_answer_is_the_reference() {
        let first = node().with_genesis_root(Root::repeat_byte(0xbb));
        let fallback = FallbackBeaconNode::new(vec![first, node()]);
        let chain = fallback
            .establish_on(None, |_| Ok(NOW))
            .await
            .expect("a node answers");
        assert_eq!(
            chain.genesis.genesis_validators_root,
            Root::repeat_byte(0xbb)
        );
    }

    /// Two nodes on the named network that disagree on a fork: the first
    /// listed is the reference, though the second's schedule is the
    /// network's. The network's config may be the stale side (a binary built
    /// before a reschedule), so it never picks the schedule the client starts
    /// from; the warning names the difference instead.
    #[tokio::test]
    async fn the_named_networks_schedule_does_not_pick_the_reference() {
        let network = named_network();
        let gloas_at = network.chain.config.fork_epoch(ForkName::Gloas);
        let moved = Config::mainnet().with_fork_epoch(ForkName::Gloas, NOW + 10);
        assert_ne!(moved.fork_epoch(ForkName::Gloas), gloas_at);

        let fallback = FallbackBeaconNode::new(vec![node().with_spec(moved), node()]);
        let chain = fallback
            .establish_on(Some(&network), |_| Ok(NOW))
            .await
            .expect("both nodes are on the network");
        assert_eq!(chain.config.fork_epoch(ForkName::Gloas), NOW + 10);
    }

    /// Every node answered, each on another network or preset: waiting would
    /// change nothing, so startup fails at once, naming the network and why
    /// each node is off it, and never adopts a node's chain.
    #[tokio::test(start_paused = true)]
    async fn every_node_off_the_named_network_fails_at_once() {
        use std::time::Duration;

        let fallback = FallbackBeaconNode::new(vec![
            node().with_genesis_root(Root::repeat_byte(0xbb)),
            node().with_spec(Config::minimal()),
        ]);
        let network = named_network();
        let establish = fallback.establish_on(Some(&network), |reference| {
            panic!("no node is on the network, yet {reference:?} was adopted")
        });
        // Shorter than one startup retry, so a wait fails here.
        let err = tokio::time::timeout(Duration::from_secs(1), establish)
            .await
            .expect("fails without waiting")
            .expect_err("no node is on the network");

        assert!(matches!(err, Error::AllBeaconNodesFailed(_)), "got {err:?}");
        let text = err.to_string();
        assert!(
            text.contains("node 0: not on testnet: genesis_validators_root")
                && text.contains("node 1: not on testnet: PRESET_BASE"),
            "got {text}"
        );
    }

    /// A node off the network beside one that has not answered yet: startup
    /// waits for the second, which comes up on the network and is the
    /// reference.
    #[tokio::test(start_paused = true)]
    async fn startup_waits_for_a_node_on_the_named_network() {
        use std::time::Duration;

        let fallback = FallbackBeaconNode::new(vec![
            node().with_genesis_root(Root::repeat_byte(0xbb)),
            node().failing_call("genesis", "down"),
        ]);
        let comes_up = async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            fallback.nodes()[1].stop_failing("genesis");
        };
        let network = named_network();
        let waited = async {
            let (chain, ()) =
                tokio::join!(fallback.establish_on(Some(&network), |_| Ok(NOW)), comes_up);
            chain
        };
        let chain = tokio::time::timeout(Duration::from_secs(60), waited)
            .await
            .expect("startup ends once the node on the network answers")
            .expect("the second node is on the network");
        assert_eq!(chain.genesis, genesis());
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

    /// A client started beside its beacon nodes waits for one to answer
    /// rather than exiting, asking them all again every two seconds.
    #[tokio::test(start_paused = true)]
    async fn startup_waits_until_a_node_answers() {
        use std::time::Duration;
        use tokio::time::Instant;

        let fallback = FallbackBeaconNode::new(vec![
            node().failing_call("genesis", "down"),
            node().failing_call("genesis", "also down"),
        ]);
        let started = Instant::now();
        let comes_up = async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            fallback.nodes()[1].stop_failing("genesis");
        };
        let waited = async {
            let (chain, ()) = tokio::join!(fallback.establish(|_| Ok(NOW)), comes_up);
            chain
        };
        // Bounded, so a wait that never ends fails here rather than hanging.
        let chain = tokio::time::timeout(Duration::from_secs(60), waited)
            .await
            .expect("startup ends once a node answers")
            .expect("node 1 answers");

        assert_eq!(chain.genesis, genesis());
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_secs(5) && waited < Duration::from_secs(10),
            "waited {waited:?}"
        );
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
        check_once(&fallback, genesis(), &context, &settings(), || NOW, true).await;
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
        check_once(&fallback, genesis(), &context, &settings(), || NOW, true).await;

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

    /// The reference has not been upgraded and another node schedules gloas:
    /// one node alone does not put a fork on the client's schedule, so the
    /// client starts without it, and the node that has it is the one left out
    /// if the reference is still without it when the fork's epoch arrives.
    #[tokio::test]
    async fn a_fork_only_another_node_schedules_is_not_taken_at_startup() {
        let gloas_epoch = NOW + 1;
        let upgraded = node().with_spec(with_gloas(gloas_epoch, [8, 0, 0, 0]));
        let fallback = FallbackBeaconNode::new(vec![node(), upgraded]);

        let chain = fallback.establish(|_| Ok(NOW)).await.expect("answers");

        assert_eq!(chain.config, Config::mainnet());

        let answers = fallback
            .check_nodes(|| chain.clone(), || gloas_epoch, |_| {})
            .await;
        assert!(matches!(answers[0].1, NodeAnswer::Compatible(_)));
        assert!(matches!(answers[1].1, NodeAnswer::Incompatible(_)));
    }

    use crate::beacon_node::fallback::MISSES_BEFORE_SAY_IS_LOST;

    /// Node `position` fails every later check, as a node restarting does.
    fn goes_quiet(fallback: &FallbackBeaconNode<MockBeaconNode>, position: usize) {
        fallback.nodes()[position]
            .failures
            .lock()
            .expect("lock")
            .insert("spec", "restarting".to_string());
    }

    /// The node not yet upgraded goes quiet (restarting for the upgrade, say)
    /// and, once it has missed enough checks in a row, loses its say, so the
    /// fork the other node schedules is taken while it is still ahead.
    #[tokio::test]
    async fn a_fork_is_taken_once_the_node_without_it_goes_quiet() {
        let (context, clock) = context_and_clock();
        let gloas_epoch = NOW + 1;
        let upgraded = node().with_spec(with_gloas(gloas_epoch, [8, 0, 0, 0]));
        let fallback = established(vec![node(), upgraded]).await;
        check_once(&fallback, genesis(), &context, &settings(), || NOW, true).await;
        assert!(!clock.is_gloas(gloas_epoch * slots_per_epoch()));

        goes_quiet(&fallback, 0);
        for _ in 1..MISSES_BEFORE_SAY_IS_LOST {
            check_once(&fallback, genesis(), &context, &settings(), || NOW, true).await;
            assert!(
                !clock.is_gloas(gloas_epoch * slots_per_epoch()),
                "still held off while the quiet node keeps its say"
            );
        }
        check_once(&fallback, genesis(), &context, &settings(), || NOW, true).await;

        assert!(clock.is_gloas(gloas_epoch * slots_per_epoch()));
    }

    /// The review's case: a correct node (no gloas) misses one check, and the
    /// only other node, misconfigured with gloas, does not put the fork on
    /// the client's schedule alone. Taken, it would never be unscheduled, and
    /// the correct node would be refused at the fork's epoch.
    #[tokio::test]
    async fn one_missed_check_does_not_let_another_node_add_a_fork() {
        let (context, clock) = context_and_clock();
        let gloas_epoch = NOW + 10;
        let misconfigured = node().with_spec(with_gloas(gloas_epoch, [8, 0, 0, 0]));
        let fallback = established(vec![node(), misconfigured]).await;
        check_once(&fallback, genesis(), &context, &settings(), || NOW, true).await;

        goes_quiet(&fallback, 0);
        check_once(&fallback, genesis(), &context, &settings(), || NOW, true).await;
        fallback.nodes()[0].failures.lock().expect("lock").clear();
        check_once(&fallback, genesis(), &context, &settings(), || NOW, true).await;

        assert!(!clock.is_gloas(gloas_epoch * slots_per_epoch()));
        assert_eq!(*context.config(), Config::mainnet());
    }

    /// The same for a fork the client already has: one node postponing it
    /// while the other misses a check does not move it.
    #[tokio::test]
    async fn one_missed_check_does_not_let_another_node_postpone_a_fork() {
        let (context, _) = context_and_clock();
        let scheduled = with_gloas(NOW + 10, [8, 0, 0, 0]);
        let fallback = established(vec![
            node().with_spec(scheduled.clone()),
            node().with_spec(with_gloas(NOW + 100, [8, 0, 0, 0])),
        ])
        .await;
        context.replace_config(scheduled);
        check_once(&fallback, genesis(), &context, &settings(), || NOW, true).await;

        goes_quiet(&fallback, 0);
        check_once(&fallback, genesis(), &context, &settings(), || NOW, true).await;

        assert_eq!(context.config().fork_epoch(ForkName::Gloas), NOW + 10);
    }

    /// A node let back in between two epoch checks brings its schedule with
    /// it at once, not at the next epoch, where its fork could be active.
    /// (Node 0, the only other one, has been quiet long enough to lose its
    /// say in that same round.)
    #[tokio::test]
    async fn a_readmitted_node_has_its_schedule_followed_in_the_same_round() {
        let (context, clock) = context_and_clock();
        let late = node();
        late.failures
            .lock()
            .expect("lock")
            .insert("genesis", "booting".to_string());
        let fallback = established(vec![node(), late]).await;
        let gloas_epoch = NOW + 1;

        goes_quiet(&fallback, 0);
        for _ in 1..MISSES_BEFORE_SAY_IS_LOST {
            check_once(&fallback, genesis(), &context, &settings(), || NOW, true).await;
        }
        fallback.nodes()[1].failures.lock().expect("lock").clear();
        fallback.nodes()[1].set_spec(with_gloas(gloas_epoch, [8, 0, 0, 0]));
        check_once(&fallback, genesis(), &context, &settings(), || NOW, true).await;

        assert!(clock.is_gloas(gloas_epoch * slots_per_epoch()));
    }

    /// A usable node that misses the epoch's check is asked again at the next
    /// slot, and the schedule it serves is followed then.
    #[tokio::test]
    async fn a_node_that_missed_the_epoch_check_is_asked_again_the_next_slot() {
        let (context, clock) = context_and_clock();
        let fallback = established(vec![node()]).await;
        let gloas_epoch = NOW + 1;
        fallback.nodes()[0].set_spec(with_gloas(gloas_epoch, [8, 0, 0, 0]));
        fallback.nodes()[0]
            .failures
            .lock()
            .expect("lock")
            .insert("spec", "down".to_string());
        check_once(&fallback, genesis(), &context, &settings(), || NOW, true).await;
        assert!(!clock.is_gloas(gloas_epoch * slots_per_epoch()));

        fallback.nodes()[0].failures.lock().expect("lock").clear();
        check_once(&fallback, genesis(), &context, &settings(), || NOW, true).await;

        assert!(clock.is_gloas(gloas_epoch * slots_per_epoch()));
    }

    /// The duty offsets stay the first node's through a round it does not
    /// answer, rather than flipping to the next node's and back.
    #[tokio::test]
    async fn the_duty_offsets_do_not_move_when_the_first_node_misses_a_round() {
        let (context, _) = context_and_clock();
        let mut other = Config::mainnet();
        other.attestation_due_bps_gloas = 2_000;
        let fallback = established(vec![node(), node().with_spec(other)]).await;
        fallback.nodes()[0]
            .failures
            .lock()
            .expect("lock")
            .insert("spec", "down".to_string());

        check_once(&fallback, genesis(), &context, &settings(), || NOW, true).await;

        assert_eq!(*context.config(), Config::mainnet());
    }

    /// A node that stops answering does not hold a fork at the epoch it last
    /// reported: once it has missed enough checks in a row, a few slots, the
    /// postponement the reachable node serves is followed. Held until its
    /// last answer aged out, the old epoch would arrive first if the
    /// postponement came in the fork's last epoch, and the reachable node
    /// would be refused for following it.
    #[tokio::test]
    async fn an_unreachable_node_does_not_pin_a_postponed_fork() {
        let (context, _) = context_and_clock();
        let scheduled = with_gloas(NOW + 2, [8, 0, 0, 0]);
        let fallback = established(vec![
            node().with_spec(scheduled.clone()),
            node().with_spec(scheduled.clone()),
        ])
        .await;
        context.replace_config(scheduled);

        goes_quiet(&fallback, 1);
        fallback.nodes()[0].set_spec(with_gloas(NOW + 100, [8, 0, 0, 0]));

        // The fork's last epoch before it arrives.
        for _ in 0..MISSES_BEFORE_SAY_IS_LOST {
            check_once(
                &fallback,
                genesis(),
                &context,
                &settings(),
                || NOW + 1,
                true,
            )
            .await;
        }
        assert_eq!(context.config().fork_epoch(ForkName::Gloas), NOW + 100);
    }

    /// At startup a body that is not JSON (a proxy's page while the node
    /// boots) is waited out, while a spec the node itself serves unreadably
    /// fails at once, since asking again gives the same answer.
    #[tokio::test(start_paused = true)]
    async fn startup_waits_out_a_body_that_is_not_json_but_not_an_unreadable_spec() {
        use std::time::Duration;

        let proxied = node();
        *proxied.spec_error.lock().expect("lock") =
            Some(|| Error::Decode("expected value at line 1 column 1".into()));
        let fallback = FallbackBeaconNode::new(vec![proxied]);
        let comes_up = async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            *fallback.nodes()[0].spec_error.lock().expect("lock") = None;
        };
        let waited = async {
            let (chain, ()) = tokio::join!(fallback.establish(|_| Ok(NOW)), comes_up);
            chain
        };
        tokio::time::timeout(Duration::from_secs(60), waited)
            .await
            .expect("startup ends once the node answers")
            .expect("the node answers");

        let unreadable = node();
        *unreadable.spec_error.lock().expect("lock") =
            Some(|| Error::UnreadableSpec("config/spec: SLOT_DURATION_MS is absent".into()));
        let err = FallbackBeaconNode::new(vec![unreadable])
            .establish(|_| Ok(NOW))
            .await
            .expect_err("an unreadable spec is final");
        assert!(matches!(err, Error::AllBeaconNodesFailed(_)), "got {err:?}");
    }

    /// The node that answers first is judged and followed when its answer
    /// arrives, not once a node that hangs until its timeout has answered:
    /// the fork it reports is still ahead then, and taken, where judged
    /// after the hung node's timeout carried the clock past the fork's epoch
    /// it would be refused for it.
    #[tokio::test(start_paused = true)]
    async fn a_hung_node_does_not_hold_back_another_nodes_answer() {
        use std::time::Duration;
        use tokio::time::Instant;

        let (context, clock) = context_and_clock();
        let hung = node().with_spec_delay(Duration::from_secs(8));
        hung.failures
            .lock()
            .expect("lock")
            .insert("genesis", "booting".to_string());
        // Node 1 did not answer at startup, so it has no say yet, and this
        // round it answers only at its timeout.
        let fallback = established(vec![node(), hung]).await;
        fallback.nodes()[1].failures.lock().expect("lock").clear();
        let gloas_epoch = NOW + 1;
        fallback.nodes()[0].set_spec(with_gloas(gloas_epoch, [8, 0, 0, 0]));

        // The fork's epoch arrives four seconds into the round.
        let started = Instant::now();
        let epoch_now = || {
            if started.elapsed() < Duration::from_secs(4) {
                NOW
            } else {
                gloas_epoch
            }
        };
        check_once(&fallback, genesis(), &context, &settings(), epoch_now, true).await;

        assert!(clock.is_gloas(gloas_epoch * slots_per_epoch()));
    }

    /// A gas limit schedule the first node starts serving reaches the
    /// proposer settings as its answer is swapped in, not once a node that
    /// hangs until its timeout has answered: a preference signed in between
    /// carries the new default, as it would after the round.
    #[tokio::test(start_paused = true)]
    async fn a_hung_node_does_not_hold_back_the_gas_limit_schedule() {
        use crate::proposer_settings::DEFAULT_GAS_LIMIT;
        use std::time::Duration;

        let (context, _) = context_and_clock();
        let settings = settings();
        let key = ethlambda_types::beacon::primitives::BlsPubkey([1; 48]);
        let hung = node().with_spec_delay(Duration::from_secs(8));
        hung.failures
            .lock()
            .expect("lock")
            .insert("genesis", "booting".to_string());
        let fallback = established(vec![node(), hung]).await;
        fallback.nodes()[1].failures.lock().expect("lock").clear();
        let scheduled = with_gas_limit_schedule(NOW + 10, 200_000_000);
        fallback.nodes()[0].set_spec(scheduled.clone());
        assert_eq!(settings.gas_limit(&key, NOW + 10), DEFAULT_GAS_LIMIT);

        // One second into the round: node 0 has answered, node 1 is still
        // seven seconds from its own.
        let round = check_once(&fallback, genesis(), &context, &settings, || NOW, true);
        let during = async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            settings.gas_limit(&key, NOW + 10)
        };
        let ((), during) = tokio::join!(round, during);

        assert_eq!(during, 200_000_000);
        assert_eq!(
            context.config().gas_limit_schedule,
            scheduled.gas_limit_schedule
        );
        assert_eq!(settings.gas_limit(&key, NOW + 9), DEFAULT_GAS_LIMIT);
        assert_eq!(settings.gas_limit(&key, NOW + 10), 200_000_000);
    }

    /// A node skipped for being on another chain is not counted against a
    /// send every usable node took, so a caller does not resend and count a
    /// failure every slot for as long as it stays configured. Letting a node
    /// back in moves `readmissions`, which is how such a caller learns to
    /// send it again.
    #[tokio::test]
    async fn a_send_every_usable_node_took_is_delivered_everywhere() {
        use crate::beacon_node::Delivery;
        use ethlambda_types::beacon::containers::gloas::SignedProposerPreferences;

        let late = node();
        late.failures
            .lock()
            .expect("lock")
            .insert("genesis", "booting".to_string());
        let fallback = established(vec![node(), late]).await;
        let preference = SignedProposerPreferences::default();

        let delivery = fallback
            .submit_proposer_preferences(ForkName::Gloas, std::slice::from_ref(&preference))
            .await
            .expect("the usable node accepted");
        assert_eq!(delivery, Delivery::Everywhere);
        assert_eq!(fallback.readmissions(), 0);

        fallback.nodes()[1].failures.lock().expect("lock").clear();
        check_once(
            &fallback,
            genesis(),
            &context_and_clock().0,
            &settings(),
            || NOW,
            true,
        )
        .await;
        assert_eq!(fallback.readmissions(), 1, "node 1 was let back in");

        // A node that was usable all along answering again is no readmission.
        check_once(
            &fallback,
            genesis(),
            &context_and_clock().0,
            &settings(),
            || NOW,
            true,
        )
        .await;
        assert_eq!(fallback.readmissions(), 1);
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

        check_once(&fallback, genesis(), &context, &settings(), || NOW, true).await;

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
        check_once(&fallback, genesis(), &context, &settings(), || NOW, true).await;
        fallback.nodes()[0].failures.lock().expect("lock").clear();

        fallback
            .attester_duties(3, &[])
            .await
            .expect("still usable");
    }

    /// Every round asks every node: one that answered the epoch's first round
    /// and is upgraded later in the epoch, for a fork at the next one, is read
    /// while the fork is still ahead, not at the next epoch's first round,
    /// where it would already be active and the node refused for it.
    #[tokio::test]
    async fn a_node_upgraded_mid_epoch_is_read_at_the_next_round() {
        let (context, clock) = context_and_clock();
        let fallback = established(vec![node()]).await;
        check_once(&fallback, genesis(), &context, &settings(), || NOW, true).await;

        let gloas_epoch = NOW + 1;
        fallback.nodes()[0].set_spec(with_gloas(gloas_epoch, [8, 0, 0, 0]));
        check_once(&fallback, genesis(), &context, &settings(), || NOW, false).await;

        assert!(clock.is_gloas(gloas_epoch * slots_per_epoch()));
    }

    /// The epoch a node's answer is judged at is read once that answer is in.
    /// A node whose answer arrives after the boundary of the epoch it
    /// schedules a fork for has reported the fork at its epoch: it is refused,
    /// and the fork is not adopted late.
    #[tokio::test]
    async fn the_epoch_is_read_once_the_node_has_answered() {
        use std::sync::atomic::Ordering;

        let (context, clock) = context_and_clock();
        let fallback = established(vec![node()]).await;
        let asked_at_startup = fallback.nodes()[0].spec_calls.load(Ordering::SeqCst);
        let gloas_epoch = NOW + 1;
        fallback.nodes()[0].set_spec(with_gloas(gloas_epoch, [8, 0, 0, 0]));

        // The boundary passed while the node was answering.
        let epoch_now = || {
            let asked = fallback.nodes()[0].spec_calls.load(Ordering::SeqCst);
            assert!(asked > asked_at_startup, "read before the node answered");
            gloas_epoch
        };
        check_once(&fallback, genesis(), &context, &settings(), epoch_now, true).await;

        assert!(!clock.is_gloas(gloas_epoch * slots_per_epoch()));
        let err = fallback
            .attester_duties(3, &[])
            .await
            .expect_err("the node is out");
        assert!(
            err.to_string().contains("no configured beacon node is on"),
            "got {err}"
        );
    }
}
