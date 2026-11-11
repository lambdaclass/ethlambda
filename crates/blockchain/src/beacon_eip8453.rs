//! The chain actor's half of EIP-8453's fork choice.
//!
//! At EIP-8453 slots the finality gadget and the available chain (the engine in
//! `ethlambda-decoupled`, behind the shared
//! [`SharedEip8453Node`]) replace LMD-GHOST and Casper FFG. The actor:
//!
//! * installs the engine once the clock reaches the fork, or at startup when
//!   the store already holds the fork's blocks ([`BlockChainServer::ensure_eip8453_engine`]);
//! * ticks it every `Δ` (a quarter slot), which runs the protocol's `unlock`
//!   and `update_confirmation` and records the duty inputs of each instant;
//! * feeds it every imported block (after the state transition, with the head
//!   vote committees of the votes it carries recorded first) and every verified
//!   payload;
//! * takes the head and the finality gadget's checkpoints back from it, writes
//!   them to the store (the head, the payload status of the head node, and the
//!   justified and finalized rows that drive pruning), and tells the execution
//!   client.
//!
//! # The fork transition
//!
//! fork.md starts the gadget at height 0 from Casper FFG's last finalized
//! checkpoint, with the latest pre-fork block as the target of height 1. The
//! engine is therefore anchored at the store's finalized block (Casper FFG's,
//! finalized at height 0), and every stored block above it is replayed into
//! it: pre-fork blocks with every checkpoint at height 0 on that block
//! (`eip8453_fork_choice::pre_fork_checkpoints`), EIP-8453 blocks with their
//! post-states' own. The fork choice specification does not say how the head
//! is chosen before the gadget's first votes; with no head votes of the
//! previous slot, the available chain's walk would stop at its anchor, the
//! finalized block, and orphan every block since. So the handover seeds a lock
//! (fork-choice.md's `add_lock` names "a lock seeded at a fork transition" as a
//! producer) on the last LMD-GHOST head node, with the deadline a confirmation
//! of the last pre-fork slot would get. The available chain walks from it until
//! its own confirmations take over (`docs/spec_deviations.md`).
//!
//! # Restart
//!
//! A restarted node anchors a fresh engine at the store's finalized block (the
//! gadget's, or Casper FFG's while the gadget has not finalized) and replays
//! every stored block above it, with each verified payload, as a joining node:
//! its receipt times are the restart's, its locks and saved confirmations start
//! empty, as the lean decoupled mode's do.

use ethlambda_state_transition::beacon::eip8453_fork_choice::{
    self as host, block_input, head_vote_committee, pre_fork_block_input,
};
use ethlambda_state_transition::beacon::eip8453_node::{Eip8453Node, SharedEip8453Node};
use ethlambda_state_transition::beacon::fork_choice::{self, PayloadStatus};
use ethlambda_storage::Store;
use ethlambda_types::ShortRoot;
use ethlambda_types::beacon::containers::{BeaconState, SignedBeaconBlock};
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::decoupled::ForkChoiceNode;
use ethlambda_types::primitives::H256;
use tracing::{debug, info, warn};

use crate::{BlockChainServer, metrics};

/// The chain actor's EIP-8453 state: the shared node (empty until the engine
/// is installed).
#[derive(Debug, Clone, Default)]
pub(crate) struct Eip8453Host {
    pub(crate) node: SharedEip8453Node,
}

impl Eip8453Host {
    pub(crate) fn new(node: SharedEip8453Node) -> Self {
        Self { node }
    }
}

/// The parent payload status a stored block was imported with: its recorded
/// payload link, or `Full` for a block whose link is unknown (the anchor, or a
/// block before gloas, whose payload ran inside it).
fn parent_status_of(store: &Store, root: &H256) -> PayloadStatus {
    store
        .payload_link(root)
        .and_then(|link| link.parent_status())
        .unwrap_or(PayloadStatus::Full)
}

/// Whether `root`'s payload is verified as fork choice reads it: a recorded
/// envelope, or a block from before gloas.
fn payload_verified(store: &Store, root: H256) -> bool {
    fork_choice::is_payload_verified(store, root)
}

/// Build an engine anchored at the store's finalized block and replay every
/// stored block above it, with its verified payload. `None` when the
/// finalized block or its state is missing.
pub(crate) fn rebuild_node(store: &Store, now_ms: u64) -> Option<Eip8453Node> {
    let config = store.config();
    let finalized = store.latest_finalized().ok()?;
    let (anchor_slot, _) = store.block_entry(&finalized.root)?;
    let anchor_state = store.get_state(&finalized.root).ok().flatten()?;
    let anchor = host::anchor(finalized.root, anchor_slot, &anchor_state)
        .inspect_err(|err| warn!(%err, "Cannot anchor the EIP-8453 fork choice"))
        .ok()?;
    let gadget_root = anchor.fg.finalized.root;
    let mut node = Eip8453Node::new(config.as_ref().clone(), host::new_engine(anchor));
    // A never-ticked engine jumps to the present: the replay below stamps
    // every block with the restart's time, as a joining node's would be.
    node.advance_to_ms(now_ms);
    if payload_verified(store, finalized.root) {
        let satisfied = fork_choice::is_payload_inclusion_list_satisfied(store, finalized.root);
        let _ = node.on_payload(&finalized.root, satisfied, now_ms);
    }

    let mut blocks: Vec<(u64, H256, H256)> = store
        .block_index()
        .into_iter()
        .filter(|(root, (slot, _))| *slot > anchor_slot && *root != finalized.root)
        .map(|(root, (slot, parent))| (slot, root, parent))
        .collect();
    blocks.sort();
    let mut replayed = 0usize;
    for (slot, root, parent) in blocks {
        if !store.has_state(&root).unwrap_or(false) {
            continue;
        }
        if feed_stored_block(store, &mut node, root, slot, parent, gadget_root, now_ms) {
            replayed += 1;
        }
    }
    info!(
        anchor_slot,
        anchor_root = %ShortRoot(&finalized.root.0),
        replayed,
        "EIP-8453 fork choice anchored"
    );
    Some(node)
}

/// Hand one stored, imported block to the engine: an EIP-8453 block with its
/// post-state's checkpoints and its head votes' committees, a pre-fork block
/// at height 0 on `gadget_root`; then its payload, if verified. Whether the
/// engine took the block.
fn feed_stored_block(
    store: &Store,
    node: &mut Eip8453Node,
    root: H256,
    slot: u64,
    parent: H256,
    gadget_root: H256,
    now_ms: u64,
) -> bool {
    let parent_status = parent_status_of(store, &root);
    let input = match store.get_signed_block(&root).ok().flatten() {
        Some(block @ SignedBeaconBlock::Eip8453(_)) => {
            let Some(state) = store.get_state(&root).ok().flatten() else {
                return false;
            };
            record_committees(store, node, &block, &state, now_ms);
            match block_input(root, &block, parent_status, &state) {
                Ok(input) => input,
                Err(err) => {
                    warn!(%slot, %err, "Cannot read an EIP-8453 block for the fork choice");
                    return false;
                }
            }
        }
        Some(_) => pre_fork_block_input(root, parent, slot, parent_status, gadget_root),
        None => return false,
    };
    let taken = node.on_block(&input, now_ms).is_ok();
    if taken && payload_verified(store, root) {
        let satisfied = fork_choice::is_payload_inclusion_list_satisfied(store, root);
        let _ = node.on_payload(&root, satisfied, now_ms);
    }
    taken
}

/// Record the head vote committee of every vote `block` carries, read from
/// its post-state, before the engine reads the votes.
fn record_committees(
    store: &Store,
    node: &mut Eip8453Node,
    block: &SignedBeaconBlock,
    state: &BeaconState,
    now_ms: u64,
) {
    let SignedBeaconBlock::Eip8453(signed) = block else {
        return;
    };
    let config = store.config();
    let mut slots: Vec<u64> = signed
        .message
        .body
        .head_votes
        .iter()
        .map(|vote| vote.data.slot)
        .collect();
    slots.sort_unstable();
    slots.dedup();
    for slot in slots {
        match head_vote_committee(state, slot, &config) {
            Ok(committee) => {
                if let Err(err) = node.record_committee(slot, committee, now_ms) {
                    warn!(slot, %err, "A block's head vote committee disagrees with the recorded one");
                }
            }
            Err(err) => debug!(slot, %err, "No head vote committee for a carried vote"),
        }
    }
}

impl BlockChainServer {
    /// Whether the EIP-8453 fork choice runs.
    pub(crate) fn eip8453_active(&self) -> bool {
        self.eip8453.node.is_active()
    }

    /// The Unix millisecond the fork's first slot starts at, when scheduled.
    fn eip8453_fork_start_ms(&self) -> Option<u64> {
        let config = self.store.config();
        host::fork_slot(&config).map(|slot| config.time_at_slot_ms(config.genesis_time_ms(), slot))
    }

    /// Whether the fork choice at `now_ms` is EIP-8453's: the clock has
    /// reached the fork, or the engine already runs (a store past the fork).
    pub(crate) fn eip8453_due(&self, now_ms: u64) -> bool {
        self.eip8453_active()
            || self
                .eip8453_fork_start_ms()
                .is_some_and(|fork_ms| now_ms >= fork_ms)
    }

    /// Move the beacon store's clock to `now_ms` at EIP-8453 time: through
    /// LMD-GHOST's `on_tick` up to the fork's first slot (which finishes the
    /// last epoch's pull-up of Casper FFG's checkpoints, the gadget's
    /// starting point), and as a plain clock past it, where nothing of
    /// LMD-GHOST's per-slot bookkeeping applies.
    pub(crate) fn advance_store_clock_for_eip8453(&mut self, now_ms: u64) {
        let config = self.store.config();
        let store_ms = self.store.time_ms().unwrap_or_default();
        if let Some(fork_ms) = self.eip8453_fork_start_ms()
            && store_ms < fork_ms
        {
            fork_choice::on_tick_ms(&mut self.store, fork_ms.min(now_ms), &config);
        }
        if self.store.time_ms().unwrap_or_default() < now_ms {
            let _ = self.store.set_time_ms(now_ms);
        }
    }

    /// Milliseconds until the next engine tick (a quarter slot), when the
    /// EIP-8453 fork choice runs or its first slot is less than a slot away.
    pub(crate) fn ms_until_next_eip8453_tick(&self, now_ms: u64) -> Option<u64> {
        let config = self.store.config();
        let fork_ms = self.eip8453_fork_start_ms()?;
        let lead_ms = config.slot_duration_ms_at_slot(host::fork_slot(&config)?);
        if !self.eip8453_active() && now_ms.saturating_add(lead_ms) < fork_ms {
            return None;
        }
        let next = host::tick_start_ms(&config, host::tick_at_ms(&config, now_ms) + 1);
        Some(next.saturating_sub(now_ms).max(1))
    }

    /// Install the engine once it is due: the clock has reached the fork's
    /// first slot, or the store's head is already an EIP-8453 block (a resumed
    /// directory, or an anchor past the fork). A no-op once installed, and on
    /// a chain that never schedules the fork.
    ///
    /// At the transition (the head is a pre-fork block) the lock described in
    /// the module documentation is seeded on the head node.
    pub(crate) fn ensure_eip8453_engine(&mut self, now_ms: u64) {
        if self.eip8453_active() {
            return;
        }
        let config = self.store.config();
        let Some(fork_slot) = host::fork_slot(&config) else {
            return;
        };
        let head_root = self.store.head().ok();
        let head_is_eip8453 = head_root
            .and_then(|root| self.store.get_signed_block(&root).ok().flatten())
            .is_some_and(|block| block.fork_name() >= ForkName::Eip8453);
        let current_slot = config.slot_at_time_ms(config.genesis_time_ms(), now_ms);
        if current_slot < fork_slot && !head_is_eip8453 {
            return;
        }
        if let Err(err) = host::check_time_parameters(&config) {
            warn!(%err, "Not running the EIP-8453 fork choice");
            return;
        }
        let Some(mut node) = rebuild_node(&self.store, now_ms) else {
            return;
        };
        if !head_is_eip8453
            && let (Some(head_root), Some(status)) = (head_root, self.store.head_payload_status())
        {
            let lock = ForkChoiceNode {
                root: head_root,
                payload_status: status.into(),
            };
            let deadline = node
                .engine()
                .params()
                .lock_deadline(fork_slot.saturating_sub(1));
            if node.engine().contains(&head_root) {
                node.engine_mut().add_lock(deadline, lock);
                info!(
                    fork_slot,
                    head_root = %ShortRoot(&head_root.0),
                    "Seeded the available chain's lock on the last LMD-GHOST head"
                );
            }
        }
        self.eip8453.node.install(node);
        metrics::set_eip8453_active(true);
    }

    /// Hand a block `fork_choice::on_block` just imported to the engine.
    pub(crate) fn eip8453_on_imported_block(&mut self, root: H256, now_ms: u64) {
        let fork = self
            .store
            .get_signed_block(&root)
            .ok()
            .flatten()
            .map(|block| block.fork_name());
        if fork.is_some_and(|fork| fork >= ForkName::Eip8453) {
            // The first EIP-8453 block may arrive before the tick that would
            // install the engine (an early import at the fork's first slot).
            self.ensure_eip8453_engine(now_ms);
        }
        if !self.eip8453_active() {
            return;
        }
        let Some((slot, parent)) = self.store.block_entry(&root) else {
            return;
        };
        let store = &self.store;
        let _ = self.eip8453.node.with(|node| {
            if node.engine().contains(&root) {
                return;
            }
            let gadget_root = node.engine().finalized_checkpoint().root;
            if !feed_stored_block(store, node, root, slot, parent, gadget_root, now_ms) {
                debug!(
                    %slot,
                    block_root = %ShortRoot(&root.0),
                    "The EIP-8453 fork choice did not take an imported block"
                );
            }
        });
    }

    /// Hand a payload `on_execution_payload_envelope` just verified to the
    /// engine.
    pub(crate) fn eip8453_on_payload(&mut self, root: H256, satisfied: bool, now_ms: u64) {
        let _ = self.eip8453.node.with(|node| {
            let _ = node
                .on_payload(&root, satisfied, now_ms)
                .inspect_err(|err| debug!(%err, "The EIP-8453 fork choice did not take a payload"));
        });
    }

    /// Record an execution client's later verdict on a payload's inclusion
    /// lists.
    pub(crate) fn eip8453_set_inclusion_list_satisfaction(&mut self, root: H256, satisfied: bool) {
        let _ = self.eip8453.node.with(|node| {
            node.engine_mut()
                .set_payload_inclusion_list_satisfaction(&root, satisfied);
        });
    }

    /// Advance the engine to `now_ms`.
    pub(crate) fn eip8453_tick(&mut self, now_ms: u64) {
        self.ensure_eip8453_engine(now_ms);
        let _ = self.eip8453.node.with(|node| node.advance_to_ms(now_ms));
    }

    /// What `forkchoiceUpdated` carries under the EIP-8453 fork choice, or
    /// `None` when the engine does not run. The inner `None` is "nothing to
    /// say yet" (a head with no payload hash).
    ///
    /// * head: the head node's payload hash, `bid.block_hash` when FULL and
    ///   `bid.parent_block_hash` when EMPTY, as gloas's;
    /// * safe: `get_confirmed_execution_block_hash` (fork-choice.md), the
    ///   confirmed node's payload hash the same way;
    /// * finalized: the gadget's finalized block, read as gloas reads a
    ///   checkpoint block (the payload it builds on).
    pub(crate) fn eip8453_forkchoice_plan(
        &self,
    ) -> Option<Option<crate::beacon_payloads::ForkchoicePlan>> {
        let store = &self.store;
        self.eip8453
            .node
            .with(|node| {
                let engine = node.engine();
                let head = engine.get_head();
                let head_block_hash = host::node_execution_block_hash(store, head)?;
                if head_block_hash.is_zero() {
                    return None;
                }
                let safe_block_hash =
                    host::get_confirmed_execution_block_hash(store, engine).unwrap_or_default();
                let finalized_block_hash =
                    host::finalized_execution_block_hash(store, engine.finalized_checkpoint().root)
                        .unwrap_or_default();
                Some(crate::beacon_payloads::ForkchoicePlan {
                    state: ethlambda_engine::ForkchoiceStateV1 {
                        head_block_hash,
                        safe_block_hash,
                        finalized_block_hash,
                    },
                    gloas: true,
                })
            })
            .ok()
    }

    /// The time engine entries use outside a tick: the store's clock, which
    /// the tick and every arrival move (and a caller driving an unspawned
    /// server sets), so the engine never runs ahead of the store.
    pub(crate) fn eip8453_now_ms(&self) -> u64 {
        self.store.time_ms().unwrap_or_default()
    }

    /// Take the head and the finality gadget's checkpoints from the engine and
    /// record them in the store, as of the engine's own clock. `false` when
    /// the engine does not run.
    pub(crate) fn eip8453_update_head(&mut self) -> bool {
        let Ok((head, justified, finalized)) = self.eip8453.node.with(|node| {
            let engine = node.engine();
            let head = engine.get_head();
            let (justified, finalized) = node.checkpoints();
            let slot_of = |root: &H256| engine.block_slot(root);
            (
                head,
                (justified, slot_of(&justified.root)),
                (finalized, slot_of(&finalized.root)),
            )
        }) else {
            return false;
        };
        let slot_of = |checkpoint: (_, Option<u64>), root: &H256, store: &Store| {
            checkpoint
                .1
                .or_else(|| store.block_entry(root).map(|(slot, _)| slot))
                .unwrap_or_default()
        };
        let justified_slot = slot_of(justified, &justified.0.root, &self.store);
        let finalized_slot = slot_of(finalized, &finalized.0.root, &self.store);
        self.store
            .set_head_payload_status(head.root, head.payload_status.into());
        let result = self.store.update_fg_checkpoints(
            head.root,
            (justified.0.into(), justified_slot),
            (finalized.0.into(), finalized_slot),
        );
        if let Err(err) = result {
            warn!(%err, "Failed to record the EIP-8453 head and checkpoints");
        }
        if let Some((head_slot, _)) = self.store.beacon_head() {
            metrics::update_head_slot(head_slot);
        }
        metrics::set_eip8453_heights(justified.0.height, finalized.0.height);
        true
    }
}
