//! Fulu validator custody (`validator.md`, "Validator custody") on a running
//! node.
//!
//! A node with validators attached custodies
//! `get_validators_custody_requirement` groups: one per 32 ETH of their total
//! effective balance, at least `VALIDATOR_CUSTODY_REQUIREMENT` (8) and at most
//! every group. When that balance falls the node keeps its highest count,
//! across restarts too.
//!
//! Once an epoch, [`refresh`] reads the validators a validator client has
//! named to the Beacon API ([`AttachedValidators`]) and hands them to a
//! blocking task ([`compute`]). The task computes their requirement from the
//! latest finalized state's effective balances, as the specification says,
//! and records the highest count ever required in the data directory
//! (`Store::raise_validator_custody_count`). The finalized state, not the
//! head's: the record never falls, so a raise read off a branch that is later
//! reorged out would stay for good. The balances come from the fork choice's
//! snapshot for the finalized checkpoint when it still holds one, which it
//! usually does, since it keeps the last few epoch boundaries; only otherwise
//! is the state read. The work is off the actor because that read may rebuild
//! a mainnet state from disk, which would stall it; the outcome comes back
//! through the actor's mailbox ([`finish`]).
//! Startup custodies and advertises the larger of `--custody-group-count` and
//! that recorded count.
//!
//! What a run can change without a restart is the *advertised* count, and
//! only up to what the node already custodies. The custody set is fixed at
//! startup: the gossip subscriptions, the chain actor's availability check,
//! req/resp serving and the Beacon API all hold a copy of it. It is
//! `sampling_size` of the startup count, so it covers at least
//! `SAMPLES_PER_SLOT` (8) groups, which is exactly what one attached validator
//! requires: a node started at the default `CUSTODY_REQUIREMENT` (4) already
//! holds what a small validator set needs, and only says so later. Raising
//! `MetaData`'s `custody_group_count` to it claims nothing the node does not
//! store and serve. A requirement past the custodied set is recorded and
//! warned about; the next start applies it.
//!
//! The ENR's `cgc` keeps its startup value until a restart, as the `eth2`
//! entry does across a fork boundary: ethrex's `DiscoveryServer` cannot
//! replace the record it serves. That understates this node's custody to a
//! peer reading only the record, which costs that peer nothing it relied on.

use ethlambda_network_api::AttachedValidators;
use ethlambda_state_transition::beacon::das;
use ethlambda_storage::Store;
use ethlambda_types::ShortRoot;
use ethlambda_types::beacon::containers::{BeaconState, Checkpoint};
use ethlambda_types::beacon::fork_choice::JustifiedBalances;
use ethlambda_types::beacon::primitives::{Epoch, ValidatorIndex};
use ethlambda_types::time::unix_now_ms;
use spawned_concurrency::tasks::Context;
use tracing::{debug, info, warn};

use super::BeaconWire;
use super::transition::epoch_at_ms;
use crate::{P2PServer, Wire, p2p_protocol};

/// The validator-custody state the p2p layer keeps between runs.
#[derive(Debug, Clone)]
pub struct ValidatorCustody {
    /// The validators a validator client has named: written by the Beacon
    /// API, read here once an epoch.
    pub attached: AttachedValidators,
    /// How many custody groups' columns this node holds: `sampling_size` of
    /// its startup count, the size of [`BeaconWire::custody_columns`]'s set.
    /// The most a runtime raise may advertise.
    pub custodied_group_count: u64,
    /// The epoch of the last completed run.
    last_run: Option<Epoch>,
    /// The epoch of the run whose blocking task has not reported back yet, so
    /// a slot tick before it does cannot start a second one.
    in_flight: Option<Epoch>,
    /// The highest count a restart warning has named, so a requirement past
    /// the custodied set is warned about once per rise rather than every
    /// epoch.
    warned: u64,
}

impl ValidatorCustody {
    pub fn new(attached: AttachedValidators, custodied_group_count: u64) -> Self {
        Self {
            attached,
            custodied_group_count,
            last_run: None,
            in_flight: None,
            warned: 0,
        }
    }
}

/// What a run's blocking task concluded, handed back to the actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CustodyRun {
    /// The attached validators require `required` groups, and `highest` is
    /// the record after it (never lower than `required`).
    Required { required: u64, highest: u64 },
    /// None of the attached validators is in the finalized state's registry:
    /// no requirement, and nothing recorded.
    NoneAttached,
    /// The finalized state could not be read. The run is retried at the next
    /// slot.
    Unavailable,
}

/// What one run concluded from the highest count attached validators have
/// required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Decision {
    /// The count to advertise from now on, when it rises.
    pub(crate) advertise: Option<u64>,
    /// The required count, when it exceeds what this node custodies: only a
    /// restart applies it.
    pub(crate) needs_restart: Option<u64>,
}

/// The pure half of [`apply`]: `advertised` is the count `MetaData` carries
/// now, `custodied` the groups this node holds, `highest_required` the
/// recorded maximum requirement.
///
/// The advertised count only rises, and never past `custodied`.
pub(crate) fn decide(advertised: u64, custodied: u64, highest_required: u64) -> Decision {
    let reachable = highest_required.min(custodied);
    Decision {
        advertise: (reachable > advertised).then_some(reachable),
        needs_restart: (highest_required > custodied).then_some(highest_required),
    }
}

/// Act on `highest_required`: raise the advertised count as far as the
/// custodied set allows, bumping the `MetaData` sequence number so peers
/// re-read it, and warn when a restart is needed for the rest.
pub(crate) fn apply(wire: &mut BeaconWire, highest_required: u64) -> Decision {
    let custodied = wire.validator_custody.custodied_group_count;
    let decision = decide(wire.custody_group_count, custodied, highest_required);
    if let Some(count) = decision.advertise {
        info!(
            previous = wire.custody_group_count,
            custody_group_count = count,
            "Advertising a higher custody group count for the attached validators; the ENR's cgc \
             keeps its startup value until a restart"
        );
        wire.custody_group_count = count;
        wire.bump_metadata_seq_number();
    }
    if let Some(count) = decision.needs_restart
        && count > wire.validator_custody.warned
    {
        warn!(
            required = count,
            custodied,
            "The attached validators require more custody groups than this node custodies. \
             The count is saved in the data directory; restart the node to custody and advertise it"
        );
        wire.validator_custody.warned = count;
    }
    decision
}

/// The once-an-epoch run. Called every slot; returns at once unless the wall
/// clock has entered an epoch not yet run and no run is in flight.
///
/// A run with no validator attached concludes nothing and records nothing,
/// on the actor: the requirement applies to a node with at least one
/// validator attached, so a plain follower is never raised to
/// `VALIDATOR_CUSTODY_REQUIREMENT`. Otherwise the state read and the
/// computation go to a blocking task ([`compute`]), which sends what it
/// concluded back as `ValidatorCustodyComputed`; [`finish`] acts on it.
pub(crate) fn refresh(server: &mut P2PServer, ctx: &Context<P2PServer>) {
    let Wire::Beacon(wire) = &mut server.wire else {
        return;
    };
    let epoch = epoch_at_ms(&wire.config, wire.genesis_time, unix_now_ms());
    let custody = &mut wire.validator_custody;
    if custody.last_run == Some(epoch) || custody.in_flight.is_some() {
        return;
    }

    let attached = custody.attached.at(epoch);
    if attached.is_empty() {
        custody.last_run = Some(epoch);
        return;
    }

    custody.in_flight = Some(epoch);
    let store = server.store.clone();
    let finalized = store.beacon_finalized_checkpoint();
    let back = ctx.clone();
    tokio::task::spawn_blocking(move || {
        // A panic would otherwise never report back, leaving `in_flight` set
        // and every later epoch unrun until a restart.
        let computed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            compute(&store, finalized, &attached)
        }));
        let run = computed.unwrap_or_else(|_| {
            warn!(
                epoch,
                "Validator custody run panicked; trying again next slot"
            );
            CustodyRun::Unavailable
        });
        let message = p2p_protocol::ValidatorCustodyComputed { epoch, run };
        let _ = back
            .send(message)
            .inspect_err(|err| warn!(%err, "Failed to report a validator custody run"));
    });
}

/// A run's blocking half: the attached validators' effective balances at
/// `finalized`, from the fork choice's balances snapshot for it when one is
/// cached ([`conclude_from_balances`]), else from the state finalized there
/// ([`conclude`]). Reading the state may rebuild it from disk, which is why
/// this is never called on the actor.
pub(crate) fn compute(
    store: &Store,
    finalized: Checkpoint,
    attached: &[ValidatorIndex],
) -> CustodyRun {
    if let Some(balances) = store.justified_balances(&finalized) {
        return conclude_from_balances(store, &balances, attached);
    }
    let finalized_root = finalized.root;
    match store.get_state(&finalized_root) {
        Ok(Some(state)) => conclude(store, &state, attached),
        Ok(None) => {
            debug!(
                finalized_root = %ShortRoot(&finalized_root.0),
                "No finalized state to compute validator custody from"
            );
            CustodyRun::Unavailable
        }
        Err(err) => {
            debug!(%err, "Cannot read the finalized state for validator custody");
            CustodyRun::Unavailable
        }
    }
}

/// The attached validators' requirement off `state`, recorded in `store`
/// when there is one.
pub(crate) fn conclude(
    store: &Store,
    state: &BeaconState,
    attached: &[ValidatorIndex],
) -> CustodyRun {
    let config = store.config();
    let required = das::get_validators_custody_requirement(state, attached, &config);
    record(store, required)
}

/// [`conclude`] off the fork choice's balances snapshot for the finalized
/// checkpoint: the same effective balances, without a state. An index the
/// checkpoint's registry did not hold is skipped, as the state's would be.
pub(crate) fn conclude_from_balances(
    store: &Store,
    balances: &JustifiedBalances,
    attached: &[ValidatorIndex],
) -> CustodyRun {
    let known = attached.iter().filter(|&&index| {
        usize::try_from(index).is_ok_and(|index| index < balances.validator_count())
    });
    let mut any = false;
    let total = known.fold(0u64, |total, &index| {
        any = true;
        total.saturating_add(balances.effective_balance(index))
    });
    let config = store.config();
    let required = any.then(|| das::validators_custody_requirement(total, &config));
    record(store, required)
}

/// Record a requirement, when there is one, as the highest yet.
fn record(store: &Store, required: Option<u64>) -> CustodyRun {
    match required {
        Some(required) => CustodyRun::Required {
            required,
            highest: store.raise_validator_custody_count(required),
        },
        None => CustodyRun::NoneAttached,
    }
}

/// Act on what the run for `epoch` concluded: the actor's half.
///
/// `Unavailable` leaves the epoch unrun, so the next slot's check starts it
/// again; the other two complete it.
pub(crate) fn finish(wire: &mut BeaconWire, epoch: Epoch, run: CustodyRun) {
    let custody = &mut wire.validator_custody;
    custody.in_flight = None;
    match run {
        CustodyRun::Required { required, highest } => {
            custody.last_run = Some(epoch);
            debug!(
                epoch,
                required, highest, "Computed the attached validators' custody requirement"
            );
            apply(wire, highest);
        }
        CustodyRun::NoneAttached => {
            custody.last_run = Some(epoch);
            debug!(
                epoch,
                "No attached validator is in the finalized state's registry"
            );
        }
        CustodyRun::Unavailable => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::fork::ForkName;
    use ethlambda_types::beacon::primitives::Root;

    use crate::beacon::{fork_schedule, topics};

    fn wire(custody_group_count: u64) -> BeaconWire {
        let wire = BeaconWire {
            fork_digest: [0x8c, 0x9f, 0x62, 0xfe],
            fork: ForkName::Fulu,
            schedule: fork_schedule::ForkSchedule::new(&Config::mainnet(), Root::ZERO),
            topics: topics::BeaconTopics::new([0x8c, 0x9f, 0x62, 0xfe], &[], &[]),
            window_topics: Vec::new(),
            config: Config::mainnet(),
            genesis_time: 1_606_824_023,
            genesis_validators_root: Root::ZERO,
            metadata_seq_number: 0,
            metadata: Default::default(),
            custody_columns: Vec::new(),
            custody_group_count,
            custody_since_slot: 0,
            validator_custody: ValidatorCustody::new(
                AttachedValidators::default(),
                das::sampling_size(custody_group_count),
            ),
            attestation_subnets: Vec::new(),
            sync_committee_subnets: Default::default(),
        };
        wire.publish_metadata();
        wire
    }

    #[test]
    fn the_advertised_count_rises_up_to_the_custodied_set() {
        // At the default count of 4 the node holds 8 groups, which is all one
        // attached validator requires.
        assert_eq!(
            decide(4, 8, 8),
            Decision {
                advertise: Some(8),
                needs_restart: None,
            }
        );
        // More than it holds: advertise what it holds, restart for the rest.
        assert_eq!(
            decide(4, 8, 64),
            Decision {
                advertise: Some(8),
                needs_restart: Some(64),
            }
        );
        // Already advertising all it holds: only the restart is left.
        assert_eq!(
            decide(8, 8, 128),
            Decision {
                advertise: None,
                needs_restart: Some(128),
            }
        );
    }

    #[test]
    fn the_advertised_count_never_falls() {
        // Started at 32 by the flag, with validators requiring only 8.
        assert_eq!(
            decide(32, 32, 8),
            Decision {
                advertise: None,
                needs_restart: None,
            }
        );
    }

    /// A raise reaches both `MetaData` and the Beacon API's copy of it, under
    /// a new sequence number so a peer that pings sees the change.
    #[test]
    fn a_raise_is_advertised_under_a_new_sequence_number() {
        let mut wire = wire(4);
        assert_eq!(wire.metadata.get().custody_group_count, 4);

        apply(&mut wire, 8);

        assert_eq!(wire.custody_group_count, 8);
        assert_eq!(wire.metadata_seq_number, 1);
        let published = wire.metadata.get();
        assert_eq!(published.custody_group_count, 8);
        assert_eq!(published.seq_number, 1);
    }

    /// A requirement past the custodied set raises the advertisement only to
    /// the set, and a repeat of the same requirement changes nothing more.
    #[test]
    fn a_raise_past_the_custodied_set_waits_for_a_restart() {
        let mut wire = wire(4);

        let decision = apply(&mut wire, 128);
        assert_eq!(decision.needs_restart, Some(128));
        assert_eq!(wire.custody_group_count, 8);
        assert_eq!(wire.metadata_seq_number, 1);

        let again = apply(&mut wire, 128);
        assert_eq!(again.advertise, None);
        assert_eq!(wire.metadata_seq_number, 1);
        assert_eq!(wire.validator_custody.warned, 128);
    }

    /// A beacon store with no block or state inserted: the finalized root it
    /// names (the zero root) has no state.
    fn empty_store() -> Store {
        Store::init_beacon(
            std::sync::Arc::new(ethlambda_storage::backend::InMemoryBackend::default()),
            1_606_824_023,
            Config::mainnet(),
            Root::ZERO,
            ethlambda_types::checkpoint::Checkpoint::default(),
            0,
        )
    }

    /// The blocking half records the requirement it computes, and the record
    /// keeps the higher of two: a later, lower requirement is answered with
    /// the earlier one.
    #[test]
    fn a_run_records_the_highest_requirement() {
        let store = empty_store();
        let state = ethlambda_state_transition::beacon::helpers::test_state::with_validators(64);

        let ten: Vec<ValidatorIndex> = (0..10).collect();
        assert_eq!(
            conclude(&store, &state, &ten),
            CustodyRun::Required {
                required: 10,
                highest: 10,
            }
        );
        assert_eq!(
            conclude(&store, &state, &[0]),
            CustodyRun::Required {
                required: 8,
                highest: 10,
            }
        );
        assert_eq!(store.validator_custody_count(), Some(10));
    }

    /// Attached validators the finalized state does not know raise nothing.
    #[test]
    fn a_run_with_no_known_validator_records_nothing() {
        let store = empty_store();
        let state = ethlambda_state_transition::beacon::helpers::test_state::with_validators(4);

        assert_eq!(conclude(&store, &state, &[1_000]), CustodyRun::NoneAttached);
        assert_eq!(store.validator_custody_count(), None);
    }

    #[test]
    fn a_run_without_a_finalized_state_is_unavailable() {
        let store = empty_store();
        let finalized = store.beacon_finalized_checkpoint();
        assert_eq!(compute(&store, finalized, &[0]), CustodyRun::Unavailable);
    }

    /// With the fork choice's balances snapshot for the finalized checkpoint
    /// cached, a run reads the effective balances off it and needs no state:
    /// ten validators at 32 ETH require ten groups, an index the snapshot's
    /// registry did not hold is skipped, and none known records nothing.
    #[test]
    fn a_run_reads_the_finalized_balances_snapshot_without_a_state() {
        let store = empty_store();
        let finalized = store.beacon_finalized_checkpoint();
        let validators = 16;
        let total = 32_000_000_000 * validators as u64;
        let balances = JustifiedBalances::new(
            finalized,
            vec![32_000_000_000; validators].into(),
            total,
            vec![32; validators].into(),
            Box::new([]),
            total,
        );
        store.insert_justified_balances(std::sync::Arc::new(balances));

        let attached: Vec<ValidatorIndex> = (0..10).chain([1_000]).collect();
        assert_eq!(
            compute(&store, finalized, &attached),
            CustodyRun::Required {
                required: 10,
                highest: 10,
            }
        );
        assert_eq!(
            compute(&store, finalized, &[1_000]),
            CustodyRun::NoneAttached
        );
    }

    /// The actor's half: a requirement completes the epoch and raises the
    /// advertisement; an unreadable state leaves the epoch to be run again;
    /// either way the run is no longer in flight.
    #[test]
    fn finishing_a_run_completes_its_epoch_unless_the_state_was_unavailable() {
        let mut wire = wire(4);

        wire.validator_custody.in_flight = Some(7);
        finish(&mut wire, 7, CustodyRun::Unavailable);
        assert_eq!(wire.validator_custody.in_flight, None);
        assert_eq!(wire.validator_custody.last_run, None);
        assert_eq!(wire.custody_group_count, 4);

        wire.validator_custody.in_flight = Some(7);
        finish(&mut wire, 7, CustodyRun::NoneAttached);
        assert_eq!(wire.validator_custody.in_flight, None);
        assert_eq!(wire.validator_custody.last_run, Some(7));
        assert_eq!(wire.custody_group_count, 4);

        wire.validator_custody.in_flight = Some(8);
        finish(
            &mut wire,
            8,
            CustodyRun::Required {
                required: 8,
                highest: 8,
            },
        );
        assert_eq!(wire.validator_custody.in_flight, None);
        assert_eq!(wire.validator_custody.last_run, Some(8));
        assert_eq!(wire.custody_group_count, 8);
        assert_eq!(wire.metadata.get().custody_group_count, 8);
    }
}
