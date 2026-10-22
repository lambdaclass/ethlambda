//! Beacon epoch-transition precompute.
//!
//! The first block of an epoch runs `process_epoch` inline on the import path,
//! then pays the post-epoch rehash for its state-root check. Both can be done
//! before the block arrives, since the parent is known by the end of the last
//! slot of the previous epoch: clone the head state, advance it to the epoch's
//! first slot on a blocking worker, hash it, and park it in the store's state
//! cache under [`CacheKey::CheckpointState`]. `fork_choice::on_block` resumes
//! from that entry when it finds one, and falls back to the inline path when it
//! does not, so the precompute is a pure speed trade.
//!
//! Two triggers feed the same worker:
//!
//! | Trigger | When | Covers |
//! |---|---|---|
//! | [`Trigger::Head`] | an import leaves a last-slot block as head | a late last-slot block |
//! | [`Trigger::Timer`] | three quarters into a last slot | a skipped last slot |
//!
//! At most one worker runs at a time, and a key already in the cache is never
//! recomputed. A block that arrives while the worker is still running imports
//! inline; the late result is stored and simply goes unused by that block.

use std::sync::Arc;
use std::time::Duration;

use ethlambda_state_transition::beacon::fork_choice;
use ethlambda_state_transition::beacon::helpers::misc::compute_start_slot_at_epoch;
use ethlambda_state_transition::metrics as stf_metrics;
use ethlambda_storage::{CacheKey, Chain};
use ethlambda_types::ShortRoot;
use ethlambda_types::beacon::containers::BeaconState;
use ethlambda_types::beacon::preset;
use ethlambda_types::primitives::H256;
use spawned_concurrency::message::Message;
use spawned_concurrency::tasks::{Context, Handler, send_after};
use tracing::{debug, info, warn};

use crate::BlockChainServer;

/// What caused a precompute, and the label it is counted under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Trigger {
    /// An import made a last-slot block the head.
    Head,
    /// The three-quarter point of a last slot, carrying that slot.
    Timer { slot: u64 },
}

impl Trigger {
    fn label(self) -> &'static str {
        match self {
            Trigger::Head => "head",
            Trigger::Timer { .. } => "timer",
        }
    }
}

/// The state a precompute produces: the head's post-state advanced to the first
/// slot of `epoch`. The same identity as `CacheKey::CheckpointState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PrecomputeKey {
    pub(crate) epoch: u64,
    pub(crate) root: H256,
}

/// Everything [`decide`] reads, gathered so the decision is a pure function.
pub(crate) struct DecisionInputs {
    pub(crate) trigger: Trigger,
    pub(crate) syncing: bool,
    pub(crate) head_slot: u64,
    pub(crate) head_root: H256,
    /// The wall-clock slot now.
    pub(crate) current_slot: u64,
    /// The worker running right now, if any.
    pub(crate) in_flight: Option<PrecomputeKey>,
    /// Whether the store already holds a state for the candidate key.
    pub(crate) already_cached: bool,
}

fn is_last_slot_of_epoch(slot: u64) -> bool {
    (slot + 1).is_multiple_of(preset::SLOTS_PER_EPOCH)
}

/// Whether to start a precompute, and for which key.
///
/// `None` when the node is syncing, when the trigger does not sit on the last
/// slot of an epoch, when a worker is already running (at most one), or when
/// the store already holds the state. A head trigger also requires the head to
/// be fresh (at most one slot behind the wall clock): the sync tracker moves
/// once per slot, so a follower importing history would otherwise precompute
/// every epoch it replays.
pub(crate) fn decide(inputs: &DecisionInputs) -> Option<PrecomputeKey> {
    if inputs.syncing || inputs.in_flight.is_some() {
        return None;
    }
    let epoch = match inputs.trigger {
        Trigger::Head => {
            if !is_last_slot_of_epoch(inputs.head_slot)
                || inputs.current_slot > inputs.head_slot.saturating_add(1)
            {
                return None;
            }
            inputs.head_slot / preset::SLOTS_PER_EPOCH + 1
        }
        Trigger::Timer { slot } => {
            // A head past the slot would be a stale message racing a newer
            // import; one already at the boundary has nothing left to advance.
            if !is_last_slot_of_epoch(slot) || inputs.head_slot > slot {
                return None;
            }
            slot / preset::SLOTS_PER_EPOCH + 1
        }
    };
    if inputs.head_slot >= compute_start_slot_at_epoch(epoch) {
        return None;
    }
    let key = PrecomputeKey {
        epoch,
        root: inputs.head_root,
    };
    (!inputs.already_cached).then_some(key)
}

/// Delay from the start of a slot to its three-quarter point.
pub(crate) fn three_quarter_slot(slot_duration_ms: u64) -> Duration {
    Duration::from_millis(slot_duration_ms / 4 * 3)
}

/// Self-message armed at a last slot's start, delivered at its three-quarter point.
pub(crate) struct EpochPrecomputeCheck {
    pub(crate) slot: u64,
}
impl Message for EpochPrecomputeCheck {
    type Result = ();
}

/// A worker's result, sent back to the actor.
pub(crate) struct EpochPrecomputed {
    pub(crate) key: PrecomputeKey,
    pub(crate) result: Result<Arc<BeaconState>, String>,
}
impl Message for EpochPrecomputed {
    type Result = ();
}

impl BlockChainServer {
    /// Arm the three-quarter check if `slot` is the last of its epoch.
    ///
    /// Called from the once-per-slot tick, which fires at the slot boundary, so
    /// the delay is the three-quarter point less whatever of the slot the tick
    /// has already consumed (a tick delayed by a long import).
    pub(crate) fn arm_epoch_precompute_check(&self, slot: u64, ctx: &Context<Self>) {
        if self.store.chain() != Chain::Beacon || !is_last_slot_of_epoch(slot) {
            return;
        }
        let slot_duration_ms = self.store.config().time_grid().milliseconds_per_slot;
        let into_slot = Duration::from_millis(self.ms_into_slot(slot).max(0) as u64);
        let delay = three_quarter_slot(slot_duration_ms).saturating_sub(into_slot);
        send_after(delay, ctx.clone(), EpochPrecomputeCheck { slot });
    }

    /// Start a precompute for the current head if [`decide`] allows one.
    pub(crate) fn maybe_start_epoch_precompute(&mut self, trigger: Trigger, ctx: &Context<Self>) {
        if self.store.chain() != Chain::Beacon {
            return;
        }
        let Some((head_slot, head_root)) = self.store.beacon_head() else {
            return;
        };
        let candidate_epoch = match trigger {
            Trigger::Head => head_slot / preset::SLOTS_PER_EPOCH + 1,
            Trigger::Timer { slot } => slot / preset::SLOTS_PER_EPOCH + 1,
        };
        let already_cached = self
            .store
            .cached_state(CacheKey::CheckpointState {
                epoch: candidate_epoch,
                root: head_root,
            })
            .is_some();
        let inputs = DecisionInputs {
            trigger,
            syncing: self.sync_status.is_syncing(),
            head_slot,
            head_root,
            current_slot: self.wall_clock_slot(),
            in_flight: self.epoch_precompute_in_flight,
            already_cached,
        };
        let Some(key) = decide(&inputs) else {
            return;
        };
        // The head's post-state is resident (it was just imported); a read that
        // cannot find it means the head moved to a block this node has no state
        // for, which a later trigger can retry.
        let Ok(Some(head_state)) = self.store.get_state(&head_root) else {
            return;
        };

        self.epoch_precompute_in_flight = Some(key);
        stf_metrics::inc_epoch_precompute_started(trigger.label());
        debug!(
            epoch = key.epoch,
            head_slot,
            head_root = %ShortRoot(&head_root.0),
            trigger = trigger.label(),
            "Starting epoch precompute"
        );

        let config = self.store.config();
        let actor = ctx.actor_ref();
        tokio::task::spawn_blocking(move || {
            let result = {
                let _timing = stf_metrics::time_epoch_precompute();
                fork_choice::advance_to_epoch_start(&head_state, key.epoch, &config)
            };
            let result = result.map(Arc::new).map_err(|err| err.to_string());
            let _ = actor.send(EpochPrecomputed { key, result });
        });
    }
}

impl Handler<EpochPrecomputeCheck> for BlockChainServer {
    async fn handle(&mut self, msg: EpochPrecomputeCheck, ctx: &Context<Self>) {
        self.maybe_start_epoch_precompute(Trigger::Timer { slot: msg.slot }, ctx);
    }
}

impl Handler<EpochPrecomputed> for BlockChainServer {
    async fn handle(&mut self, msg: EpochPrecomputed, _ctx: &Context<Self>) {
        self.epoch_precompute_in_flight = None;
        match msg.result {
            Ok(state) => {
                // Stored even if the block it was meant for already imported
                // inline: attestation targets for the epoch read the same key.
                self.store.cache_state(
                    CacheKey::CheckpointState {
                        epoch: msg.key.epoch,
                        root: msg.key.root,
                    },
                    state,
                );
                info!(
                    epoch = msg.key.epoch,
                    head_root = %ShortRoot(&msg.key.root.0),
                    "Epoch precompute stored"
                );
            }
            Err(err) => warn!(
                epoch = msg.key.epoch,
                head_root = %ShortRoot(&msg.key.root.0),
                %err,
                "Epoch precompute failed"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPE: u64 = preset::SLOTS_PER_EPOCH;

    fn inputs(trigger: Trigger, head_slot: u64) -> DecisionInputs {
        DecisionInputs {
            trigger,
            syncing: false,
            head_slot,
            head_root: H256([7; 32]),
            current_slot: head_slot,
            in_flight: None,
            already_cached: false,
        }
    }

    #[test]
    fn a_last_slot_head_precomputes_the_next_epoch() {
        let key = decide(&inputs(Trigger::Head, 2 * SPE - 1)).expect("starts");
        assert_eq!(key.epoch, 2);
        assert_eq!(key.root, H256([7; 32]));
    }

    #[test]
    fn a_head_elsewhere_in_the_epoch_starts_nothing() {
        assert!(decide(&inputs(Trigger::Head, SPE)).is_none());
        assert!(decide(&inputs(Trigger::Head, 2 * SPE - 2)).is_none());
    }

    #[test]
    fn a_syncing_node_starts_nothing() {
        let mut i = inputs(Trigger::Head, 2 * SPE - 1);
        i.syncing = true;
        assert!(decide(&i).is_none());
    }

    #[test]
    fn a_stale_head_trigger_starts_nothing() {
        let mut i = inputs(Trigger::Head, 2 * SPE - 1);
        i.current_slot = 2 * SPE + 5;
        assert!(decide(&i).is_none());
    }

    #[test]
    fn a_running_worker_blocks_a_second_one() {
        let mut i = inputs(Trigger::Head, 2 * SPE - 1);
        i.in_flight = Some(PrecomputeKey {
            epoch: 2,
            root: H256([7; 32]),
        });
        assert!(decide(&i).is_none());
    }

    #[test]
    fn a_state_already_cached_is_not_recomputed() {
        let mut i = inputs(Trigger::Timer { slot: 2 * SPE - 1 }, 2 * SPE - 3);
        i.already_cached = true;
        assert!(decide(&i).is_none());
    }

    #[test]
    fn the_timer_covers_a_skipped_last_slot() {
        let key =
            decide(&inputs(Trigger::Timer { slot: 2 * SPE - 1 }, 2 * SPE - 3)).expect("starts");
        assert_eq!(key.epoch, 2);
    }

    #[test]
    fn the_timer_ignores_slots_that_are_not_the_last() {
        assert!(decide(&inputs(Trigger::Timer { slot: SPE }, SPE - 1)).is_none());
    }

    #[test]
    fn the_timer_skips_a_head_already_at_the_boundary() {
        assert!(decide(&inputs(Trigger::Timer { slot: 2 * SPE - 1 }, 2 * SPE)).is_none());
    }

    #[test]
    fn three_quarters_follows_the_configured_slot_duration() {
        assert_eq!(three_quarter_slot(12_000), Duration::from_secs(9));
        assert_eq!(three_quarter_slot(6_000), Duration::from_millis(4_500));
    }
}
