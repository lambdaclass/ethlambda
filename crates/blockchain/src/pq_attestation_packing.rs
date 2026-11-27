//! The attestations a PQ block packs and their proofs merged into the block's
//! one `proof`, prepared ahead of the slot when this node proposes it.
//!
//! # Why ahead of the slot
//!
//! The merge folds the selected aggregates' proofs into one on the proving
//! sidecar: about 0.6 s for two children on pq-devnet-0. Block production used
//! to run it when the validator client asked for the block, at the slot's
//! start, so every block this node proposed waited for it. Its blocks reached
//! the network at about 1.0 to 1.2 s, against 0.15 to 0.4 s for Prysm's,
//! Teku's, Lighthouse's and Silver's, which carry the same merged proof.
//!
//! Nothing the merge reads is new at the slot. A block at slot `S` packs
//! aggregates from `S - MIN_ATTESTATION_INCLUSION_DELAY_PQ` (two slots) and
//! earlier, which this node has held since about half way through `S - 2`,
//! and the state they are selected against is the head's, advanced to `S`. So
//! when the chain actor starts `S`'s payload build, a third of a slot ahead
//! (`crate::payload_attributes`), it starts packing `S`'s attestations too
//! ([`PreparedPqAttestations::start`]). Block production collects the result
//! when it is for the head it builds on, waiting for it if it is still
//! running ([`PreparedPqAttestations::collect`]).
//!
//! Anything else packs at production, as before: another head (the parent
//! arrived after the preparation started, or a reorg), a preparation that did
//! not pack everything it selected, or none at all.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ethlambda_state_transition::beacon::fork_choice::get_attestation_due_ms;
use ethlambda_state_transition::beacon::pq_block_production::{PqPacked, select_pq_attestations};
use ethlambda_storage::Store;
use ethlambda_types::ShortRoot;
use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::containers::{BeaconState, pq};
use ethlambda_types::beacon::preset::MIN_ATTESTATION_INCLUSION_DELAY_PQ;
use ethlambda_types::beacon::primitives::Slot;
use ethlambda_types::beacon::signing::compute_epoch_at_slot;
use ethlambda_types::primitives::H256;
use tokio::sync::{Semaphore, watch};
use tracing::{info, warn};

use crate::payload_attributes::advance_for_proposal;

/// What a PQ block packs: its attestations and the proof of all of them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackedAttestations {
    pub attestations: Vec<pq::Attestation>,
    pub proof: Vec<u8>,
    /// Whether this is everything the selection picked. `false` when the
    /// merge was skipped, failed or ran out of time and one committee's
    /// attestation was packed alone, or when nothing could be selected: a
    /// prepared result like that is not used, and production packs again.
    pub complete: bool,
}

impl PackedAttestations {
    fn complete(attestations: Vec<pq::Attestation>, proof: Vec<u8>) -> Self {
        Self {
            attestations,
            proof,
            complete: true,
        }
    }

    fn partial(attestations: Vec<pq::Attestation>, proof: Vec<u8>) -> Self {
        Self {
            attestations,
            proof,
            complete: false,
        }
    }
}

/// One merge at a time: the sidecar proves one request after another, so a
/// second merge started while one runs would only push both past their
/// deadlines. A merge that missed its deadline keeps the permit until it
/// ends. Shared by the merge ahead of the slot and the one at production.
static MERGE_PERMIT: Semaphore = Semaphore::const_new(1);

/// The attestations a PQ block at `state`'s slot packs and the merged proof
/// of their aggregates. Empty when there are none or the selection fails;
/// one committee's attestation alone when the merge misses its deadline
/// ([`merge_budget`]), fails, or finds another merge running.
pub async fn pack_attestations(
    store: &Store,
    state: &BeaconState,
    config: &Config,
) -> PackedAttestations {
    let slot = state.slot();
    let latest = slot.saturating_sub(MIN_ATTESTATION_INCLUSION_DELAY_PQ);
    let candidates = store.pq_aggregate_pool().candidates(latest);
    if candidates.is_empty() {
        return PackedAttestations::complete(Vec::new(), Vec::new());
    }
    let selected = {
        let (store, state) = (store.clone(), state.clone());
        tokio::task::spawn_blocking(move || {
            select_pq_attestations(&state, candidates, &store.committee_cache())
        })
        .await
    };
    let packed = match selected {
        Ok(Ok(packed)) => packed,
        Ok(Err(err)) => {
            warn!(%slot, %err, "Selecting the PQ attestations failed");
            return PackedAttestations::default();
        }
        Err(err) => {
            warn!(%slot, %err, "The PQ attestation selection task failed");
            return PackedAttestations::default();
        }
    };
    if packed.attestations.is_empty() {
        return PackedAttestations::complete(Vec::new(), Vec::new());
    }
    // One child's proof is the block's as it is; more must be merged.
    let fallback = packed.first_unmerged();
    if packed.children.len() == 1 {
        return unmerged(slot, packed, true);
    }
    let children = packed.children.len();
    let fall_back = |reason: &str| {
        warn!(%slot, children, reason, "Packing one PQ attestation instead of merging every proof");
        fallback
            .clone()
            .map_or_else(PackedAttestations::default, |single| {
                unmerged(slot, single, false)
            })
    };
    let Some(remaining) = merge_budget(config, slot) else {
        return fall_back("no time left to merge");
    };
    let Ok(permit) = MERGE_PERMIT.try_acquire() else {
        return fall_back("a merge is still running");
    };
    let budget_ms = remaining.as_millis() as u64;
    let job = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let started = Instant::now();
        let proof = packed.merge().map_err(|err| err.to_string());
        // Logged when it ends, deadline or not: what a merge costs here, how
        // big it was and how much of the budget it used.
        let signatures: usize = packed
            .children
            .iter()
            .flat_map(|(statements, _)| statements)
            .map(|statement| statement.pubkeys.len())
            .sum();
        info!(
            %slot,
            attestations = packed.attestations.len(),
            children,
            signatures,
            proof_bytes = proof.as_ref().map_or(0, Vec::len),
            took_ms = started.elapsed().as_millis() as u64,
            budget_ms,
            ok = proof.is_ok(),
            "Merged PQ attestation proofs"
        );
        proof.map(|proof| (packed, proof))
    });
    match tokio::time::timeout(remaining, job).await {
        Ok(Ok(Ok((packed, proof)))) => {
            info!(
                %slot,
                attestations = packed.attestations.len(),
                children,
                proof_bytes = proof.len(),
                "Packed PQ attestations"
            );
            PackedAttestations::complete(packed.attestations, proof)
        }
        Ok(Ok(Err(err))) => fall_back(&format!("the merge failed: {err}")),
        Ok(Err(err)) => fall_back(&format!("the merge task failed: {err}")),
        Err(_) => fall_back(&format!(
            "the merge missed its {} ms budget",
            remaining.as_millis()
        )),
    }
}

/// `packed` with its one child's proof as the block's, nothing merged:
/// everything selected when `complete`, a fallback otherwise.
fn unmerged(slot: Slot, packed: PqPacked, complete: bool) -> PackedAttestations {
    match packed.merge() {
        Ok(proof) => {
            info!(
                %slot,
                attestations = packed.attestations.len(),
                proof_bytes = proof.len(),
                "Packed PQ attestations"
            );
            PackedAttestations {
                attestations: packed.attestations,
                proof,
                complete,
            }
        }
        Err(err) => {
            warn!(%slot, %err, "A single PQ proof would not pass through the merge");
            PackedAttestations::partial(Vec::new(), Vec::new())
        }
    }
}

/// How long a merge for a block at `slot` may take: until three quarters of
/// the slot's attestation deadline, so the block still reaches the attesters
/// in time. `None` once that point has passed. A merge started ahead of the
/// slot gets the same deadline, and so the whole lead on top.
pub fn merge_budget(config: &Config, slot: Slot) -> Option<Duration> {
    let due_ms = get_attestation_due_ms(compute_epoch_at_slot(slot), config);
    let deadline_ms = config
        .genesis_time
        .saturating_mul(1000)
        .saturating_add(slot.saturating_mul(config.slot_duration_ms))
        .saturating_add(due_ms.saturating_mul(3) / 4);
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64);
    deadline_ms
        .checked_sub(now_ms)
        .filter(|&left| left > 0)
        .map(Duration::from_millis)
}

/// The packing the chain actor started ahead of the next PQ proposal of this
/// node, shared with block production. Holds one: the latest started.
#[derive(Clone, Default)]
pub struct PreparedPqAttestations(Arc<Mutex<Option<Prepared>>>);

struct Prepared {
    slot: Slot,
    head_root: H256,
    /// `None` until the packing ends. Closed without a value when it could
    /// not start (the head state would not advance to the slot).
    packed: watch::Receiver<Option<Arc<PackedAttestations>>>,
}

impl PreparedPqAttestations {
    /// Start packing, off the caller, the attestations of a block at `slot`
    /// on `head_root`, whose post-state is `head_state`. Nothing happens when
    /// the same packing is already under way or done; a packing for another
    /// slot or head is replaced (one already running finishes, unheard).
    pub fn start(&self, store: Store, head_root: H256, head_state: Arc<BeaconState>, slot: Slot) {
        let Some(sender) = self.claim(slot, head_root) else {
            return;
        };
        tokio::spawn(async move {
            let started = Instant::now();
            let config = store.config();
            let advanced = {
                let (store, config) = (store.clone(), config.clone());
                tokio::task::spawn_blocking(move || {
                    advance_for_proposal(&store, head_root, &head_state, slot, &config)
                })
                .await
            };
            let state = match advanced {
                Ok(Ok(state)) => state,
                Ok(Err(err)) => {
                    warn!(%slot, %err, "Advancing the head state to pack the next PQ block's attestations failed");
                    return;
                }
                Err(err) => {
                    warn!(%slot, %err, "The task advancing the head state to pack the next PQ block's attestations failed");
                    return;
                }
            };
            let packed = pack_attestations(&store, &state, &config).await;
            info!(
                %slot,
                head_root = %ShortRoot(&head_root.0),
                attestations = packed.attestations.len(),
                complete = packed.complete,
                took_ms = started.elapsed().as_millis() as u64,
                "Packed the next PQ block's attestations ahead of its slot"
            );
            let _ = sender.send(Some(Arc::new(packed)));
        });
    }

    /// Register a packing for `slot` on `head_root` and hand back where its
    /// result goes, or `None` when one for those is already registered.
    fn claim(
        &self,
        slot: Slot,
        head_root: H256,
    ) -> Option<watch::Sender<Option<Arc<PackedAttestations>>>> {
        let mut held = self
            .0
            .lock()
            .expect("prepared PQ attestations lock poisoned");
        if held
            .as_ref()
            .is_some_and(|prepared| prepared.slot == slot && prepared.head_root == head_root)
        {
            return None;
        }
        let (sender, receiver) = watch::channel(None);
        *held = Some(Prepared {
            slot,
            head_root,
            packed: receiver,
        });
        Some(sender)
    }

    /// The attestations packed ahead of a block at `slot` on `head_root`,
    /// waiting up to `budget` for a packing still under way. `None` when none
    /// was started for that slot and head, it did not pack everything it
    /// selected, or it did not end in time: block production packs them
    /// itself then.
    pub async fn collect(
        &self,
        slot: Slot,
        head_root: H256,
        budget: Duration,
    ) -> Option<Arc<PackedAttestations>> {
        let mut packed = {
            let held = self
                .0
                .lock()
                .expect("prepared PQ attestations lock poisoned");
            let prepared = held
                .as_ref()
                .filter(|prepared| prepared.slot == slot && prepared.head_root == head_root)?;
            prepared.packed.clone()
        };
        let ready = tokio::time::timeout(budget, packed.wait_for(Option::is_some))
            .await
            .ok()?
            .ok()?
            .clone()?;
        ready.complete.then_some(ready)
    }

    /// Whether a packing for `slot` on `head_root` was started.
    #[cfg(test)]
    fn holds(&self, slot: Slot, head_root: H256) -> bool {
        self.0
            .lock()
            .expect("prepared PQ attestations lock poisoned")
            .as_ref()
            .is_some_and(|prepared| prepared.slot == slot && prepared.head_root == head_root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A preparation stands in place of the packing it holds, under its own
    /// slot and head only.
    fn held(
        slot: Slot,
        head_root: H256,
        packed: Option<PackedAttestations>,
    ) -> PreparedPqAttestations {
        let (sender, receiver) = watch::channel(packed.map(Arc::new));
        // Kept open, as a packing under way keeps its sender.
        std::mem::forget(sender);
        PreparedPqAttestations(Arc::new(Mutex::new(Some(Prepared {
            slot,
            head_root,
            packed: receiver,
        }))))
    }

    fn some_packing(complete: bool) -> PackedAttestations {
        PackedAttestations {
            attestations: Vec::new(),
            proof: vec![1, 2, 3],
            complete,
        }
    }

    #[tokio::test]
    async fn a_complete_packing_is_collected_for_its_own_slot_and_head() {
        let root = H256::repeat_byte(1);
        let prepared = held(10, root, Some(some_packing(true)));
        let budget = Duration::from_millis(50);
        let collected = prepared.collect(10, root, budget).await;
        assert_eq!(collected.as_deref(), Some(&some_packing(true)));
        assert!(prepared.collect(11, root, budget).await.is_none());
        assert!(
            prepared
                .collect(10, H256::repeat_byte(2), budget)
                .await
                .is_none()
        );
        assert!(
            PreparedPqAttestations::default()
                .collect(10, root, budget)
                .await
                .is_none()
        );
    }

    /// A packing that fell back to one committee's attestation is left to
    /// production, which may yet merge everything.
    #[tokio::test]
    async fn a_partial_packing_is_not_collected() {
        let root = H256::repeat_byte(1);
        let prepared = held(10, root, Some(some_packing(false)));
        let collected = prepared.collect(10, root, Duration::from_millis(50)).await;
        assert!(collected.is_none());
    }

    /// A packing still under way is waited for, up to the budget.
    #[tokio::test]
    async fn a_packing_under_way_is_waited_for_up_to_the_budget() {
        let root = H256::repeat_byte(1);
        let (sender, receiver) = watch::channel(None);
        let prepared = PreparedPqAttestations(Arc::new(Mutex::new(Some(Prepared {
            slot: 10,
            head_root: root,
            packed: receiver,
        }))));
        assert!(
            prepared
                .collect(10, root, Duration::from_millis(20))
                .await
                .is_none(),
            "nothing yet, and the budget runs out"
        );
        let waiting = {
            let prepared = prepared.clone();
            tokio::spawn(async move { prepared.collect(10, root, Duration::from_secs(5)).await })
        };
        sender.send(Some(Arc::new(some_packing(true)))).unwrap();
        let collected = waiting.await.unwrap();
        assert_eq!(collected.as_deref(), Some(&some_packing(true)));
    }

    /// A packing that never started (its sender gone without a value) gives
    /// nothing at once rather than holding production to its budget.
    #[tokio::test]
    async fn a_packing_that_never_started_gives_nothing_at_once() {
        let root = H256::repeat_byte(1);
        let (sender, receiver) = watch::channel(None);
        drop(sender);
        let prepared = PreparedPqAttestations(Arc::new(Mutex::new(Some(Prepared {
            slot: 10,
            head_root: root,
            packed: receiver,
        }))));
        let started = Instant::now();
        assert!(
            prepared
                .collect(10, root, Duration::from_secs(5))
                .await
                .is_none()
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /// A packing is claimed once per slot and head: claiming the same again
    /// leaves the first under way, and another head or slot replaces it.
    #[test]
    fn a_packing_is_claimed_once_per_slot_and_head() {
        let (root, other) = (H256::repeat_byte(1), H256::repeat_byte(2));
        let prepared = PreparedPqAttestations::default();
        let first = prepared.claim(10, root);
        assert!(first.is_some());
        assert!(prepared.claim(10, root).is_none(), "already under way");
        assert!(prepared.holds(10, root));
        assert!(prepared.claim(10, other).is_some());
        assert!(prepared.holds(10, other));
        assert!(!prepared.holds(10, root));
        assert!(prepared.claim(11, other).is_some());
        assert!(prepared.holds(11, other));
    }
}
