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
//! ([`PreparedPqAttestations::start`]). Block production takes the result
//! when it is for the head it builds on and the pool still holds what it was
//! packed from, waiting for a packing still running for at most half its
//! merge budget ([`PreparedPqAttestations::take`]).
//!
//! Anything else packs at production, as before: another head (the parent
//! arrived after the preparation started, or a reorg), aggregates that
//! arrived or changed since, a preparation that did not pack everything it
//! selected, or none at all.
//!
//! # One merge at a time
//!
//! The sidecar proves one request after another, so the merges share one
//! permit ([`MERGE_PERMIT`]). A packing replaced by another (the head moved)
//! is abandoned and does not start its merge; one already merging finishes,
//! unheard. A packing ahead of the slot waits for the permit, having seconds
//! to spare; production tries it once and packs one committee's attestation
//! when it is held, as it always has.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ethlambda_state_transition::beacon::fork_choice::get_attestation_due_ms;
use ethlambda_state_transition::beacon::pq_block_production::{PqPacked, select_pq_attestations};
use ethlambda_storage::Store;
use ethlambda_storage::pools::PooledPqAggregate;
use ethlambda_types::ShortRoot;
use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::containers::{BeaconState, pq};
use ethlambda_types::beacon::preset::MIN_ATTESTATION_INCLUSION_DELAY_PQ;
use ethlambda_types::beacon::primitives::Slot;
use ethlambda_types::beacon::signing::compute_epoch_at_slot;
use ethlambda_types::primitives::H256;
use tokio::sync::{Semaphore, SemaphorePermit, watch};
use tracing::{info, warn};

use crate::payload_attributes::advance_for_proposal;

/// What a PQ block packs: its attestations and the proof of all of them.
#[derive(Debug, Clone, Default)]
pub struct PackedAttestations {
    pub attestations: Vec<pq::Attestation>,
    pub proof: Vec<u8>,
    /// Whether this is everything the selection picked. `false` when the
    /// merge was skipped, failed or ran out of time and one committee's
    /// attestation was packed alone, or when nothing could be selected: a
    /// prepared result like that is not used, and production packs again.
    pub complete: bool,
    /// The pool's candidates the selection ran over, held so production can
    /// tell whether the pool changed since: by identity, and holding them
    /// keeps an address from being reused in between.
    candidates: Vec<Arc<PooledPqAggregate>>,
}

impl PackedAttestations {
    fn new(
        attestations: Vec<pq::Attestation>,
        proof: Vec<u8>,
        complete: bool,
        candidates: Vec<Arc<PooledPqAggregate>>,
    ) -> Self {
        Self {
            attestations,
            proof,
            complete,
            candidates,
        }
    }

    /// Whether the pool's `current` candidates are the ones this was packed
    /// from.
    fn packed_from(&self, current: &[Arc<PooledPqAggregate>]) -> bool {
        same_aggregates(&self.candidates, current)
    }
}

/// Whether `a` and `b` hold the same pooled aggregates, in any order.
fn same_aggregates(a: &[Arc<PooledPqAggregate>], b: &[Arc<PooledPqAggregate>]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let addresses = |held: &[Arc<PooledPqAggregate>]| {
        let mut addresses: Vec<usize> = held
            .iter()
            .map(|aggregate| Arc::as_ptr(aggregate) as usize)
            .collect();
        addresses.sort_unstable();
        addresses
    };
    addresses(a) == addresses(b)
}

/// One merge at a time: the sidecar proves one request after another, so a
/// second merge started while one runs would only push both past their
/// deadlines. A merge that missed its deadline keeps the permit until it
/// ends. Shared by the merge ahead of the slot and the one at production.
static MERGE_PERMIT: Semaphore = Semaphore::const_new(1);

/// How [`pack_attestations`] gets the merge permit.
#[derive(Debug, Clone, Copy)]
pub enum PermitWait<'a> {
    /// Try once and pack one committee's attestation when it is held: block
    /// production, which must not hold the block back for another merge.
    TryOnce,
    /// Wait for it within the merge budget, giving up first if `abandoned`
    /// is set: a packing ahead of the slot.
    Wait { abandoned: &'a AtomicBool },
}

/// The pool's candidates for a block at `slot`: aggregates from
/// `slot - MIN_ATTESTATION_INCLUSION_DELAY_PQ` and earlier.
fn candidates_for(store: &Store, slot: Slot) -> Vec<Arc<PooledPqAggregate>> {
    let latest = slot.saturating_sub(MIN_ATTESTATION_INCLUSION_DELAY_PQ);
    store.pq_aggregate_pool().candidates(latest)
}

/// The attestations a PQ block at `state`'s slot packs and the merged proof
/// of their aggregates. Empty when there are none or the selection fails;
/// one committee's attestation alone when the merge misses its deadline
/// ([`merge_budget`]), fails, or does not get the merge permit.
pub async fn pack_attestations(
    store: &Store,
    state: &BeaconState,
    config: &Config,
    permit_wait: PermitWait<'_>,
) -> PackedAttestations {
    let slot = state.slot();
    let candidates = candidates_for(store, slot);
    if candidates.is_empty() {
        return PackedAttestations::new(Vec::new(), Vec::new(), true, candidates);
    }
    let selected = {
        let (store, state, selected_from) = (store.clone(), state.clone(), candidates.clone());
        tokio::task::spawn_blocking(move || {
            select_pq_attestations(&state, selected_from, &store.committee_cache())
        })
        .await
    };
    let packed = match selected {
        Ok(Ok(packed)) => packed,
        Ok(Err(err)) => {
            warn!(%slot, %err, "Selecting the PQ attestations failed");
            return PackedAttestations::new(Vec::new(), Vec::new(), false, candidates);
        }
        Err(err) => {
            warn!(%slot, %err, "The PQ attestation selection task failed");
            return PackedAttestations::new(Vec::new(), Vec::new(), false, candidates);
        }
    };
    if packed.attestations.is_empty() {
        return PackedAttestations::new(Vec::new(), Vec::new(), true, candidates);
    }
    // One child's proof is the block's as it is; more must be merged.
    let fallback = packed.first_unmerged();
    if packed.children.len() == 1 {
        return unmerged(slot, packed, true, candidates);
    }
    let children = packed.children.len();
    let fall_back = |reason: &str| {
        warn!(%slot, children, reason, "Packing one PQ attestation instead of merging every proof");
        match fallback.clone() {
            Some(single) => unmerged(slot, single, false, candidates.clone()),
            None => PackedAttestations::new(Vec::new(), Vec::new(), false, candidates.clone()),
        }
    };
    let Some(remaining) = merge_budget(config, slot) else {
        return fall_back("no time left to merge");
    };
    let permit = match merge_permit(permit_wait, remaining).await {
        Ok(permit) => permit,
        Err(reason) => return fall_back(reason),
    };
    // The wait for the permit came out of the budget.
    let Some(remaining) = merge_budget(config, slot) else {
        return fall_back("no time left to merge");
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
            PackedAttestations::new(packed.attestations, proof, true, candidates)
        }
        Ok(Ok(Err(err))) => fall_back(&format!("the merge failed: {err}")),
        Ok(Err(err)) => fall_back(&format!("the merge task failed: {err}")),
        Err(_) => fall_back(&format!(
            "the merge missed its {} ms budget",
            remaining.as_millis()
        )),
    }
}

/// The merge permit, as `permit_wait` says to get it, or why not.
async fn merge_permit(
    permit_wait: PermitWait<'_>,
    budget: Duration,
) -> Result<SemaphorePermit<'static>, &'static str> {
    match permit_wait {
        PermitWait::TryOnce => MERGE_PERMIT
            .try_acquire()
            .map_err(|_| "a merge is still running"),
        PermitWait::Wait { abandoned } => {
            if abandoned.load(Ordering::Acquire) {
                return Err("the packing was replaced before its merge");
            }
            let permit = tokio::time::timeout(budget, MERGE_PERMIT.acquire())
                .await
                .map_err(|_| "no merge permit within the budget")?
                .map_err(|_| "the merge permit is closed")?;
            // Replaced while it waited: leave the permit to the replacement.
            if abandoned.load(Ordering::Acquire) {
                return Err("the packing was replaced before its merge");
            }
            Ok(permit)
        }
    }
}

/// `packed` with its one child's proof as the block's, nothing merged:
/// everything selected when `complete`, a fallback otherwise.
fn unmerged(
    slot: Slot,
    packed: PqPacked,
    complete: bool,
    candidates: Vec<Arc<PooledPqAggregate>>,
) -> PackedAttestations {
    match packed.merge() {
        Ok(proof) => {
            info!(
                %slot,
                attestations = packed.attestations.len(),
                proof_bytes = proof.len(),
                "Packed PQ attestations"
            );
            PackedAttestations::new(packed.attestations, proof, complete, candidates)
        }
        Err(err) => {
            warn!(%slot, %err, "A single PQ proof would not pass through the merge");
            PackedAttestations::new(Vec::new(), Vec::new(), false, candidates)
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
    /// not start (no head state, or it would not advance to the slot).
    packed: watch::Receiver<Option<Arc<PackedAttestations>>>,
    /// Set when another packing replaces this one, so it does not take the
    /// merge permit from it.
    abandoned: Arc<AtomicBool>,
}

/// What [`PreparedPqAttestations::claim`] hands the packing it registers.
struct Claim {
    packed: watch::Sender<Option<Arc<PackedAttestations>>>,
    abandoned: Arc<AtomicBool>,
}

impl PreparedPqAttestations {
    /// Start packing, off the caller, the attestations of a block at `slot`
    /// on `head_root`. Nothing happens when the same packing is already under
    /// way or done; a packing for another slot or head is replaced and
    /// abandoned (one already merging finishes, unheard).
    pub fn start(&self, store: Store, head_root: H256, slot: Slot) {
        let Some(claim) = self.claim(slot, head_root) else {
            return;
        };
        let prepared = self.clone();
        tokio::spawn(async move {
            let started = Instant::now();
            let config = store.config();
            let advanced = {
                let (store, config) = (store.clone(), config.clone());
                tokio::task::spawn_blocking(move || {
                    let head_state = store
                        .get_state(&head_root)
                        .map_err(|err| err.to_string())?
                        .ok_or_else(|| "the head state is not held".to_string())?;
                    advance_for_proposal(&store, head_root, &head_state, slot, &config)
                        .map_err(|err| err.to_string())
                })
                .await
                .map_err(|err| err.to_string())
                .flatten()
            };
            let state = match advanced {
                Ok(state) => state,
                Err(err) => {
                    warn!(%slot, %err, "Could not advance the head state to pack the next PQ block's attestations ahead");
                    // So a later start for the same slot and head can try
                    // again rather than find this one registered.
                    prepared.release(&claim.abandoned);
                    return;
                }
            };
            let wait = PermitWait::Wait {
                abandoned: &claim.abandoned,
            };
            let packed = pack_attestations(&store, &state, &config, wait).await;
            info!(
                %slot,
                head_root = %ShortRoot(&head_root.0),
                attestations = packed.attestations.len(),
                complete = packed.complete,
                took_ms = started.elapsed().as_millis() as u64,
                "Packed the next PQ block's attestations ahead of its slot"
            );
            let _ = claim.packed.send(Some(Arc::new(packed)));
        });
    }

    /// Takes the attestations packed ahead of a block at `slot` on
    /// `head_root`, waiting up to `budget` for a packing still under way.
    /// `None` when none was started for that slot and head, it did not pack
    /// everything it selected, the pool's candidates changed since, or it did
    /// not end in time: block production packs them itself then. Taken once
    /// either way, as [`crate::PreparedPayloads::take`] is.
    pub async fn take(
        &self,
        store: &Store,
        slot: Slot,
        head_root: H256,
        budget: Duration,
    ) -> Option<PackedAttestations> {
        let mut receiver = {
            let mut held = self
                .0
                .lock()
                .expect("prepared PQ attestations lock poisoned");
            if !held
                .as_ref()
                .is_some_and(|prepared| prepared.slot == slot && prepared.head_root == head_root)
            {
                return None;
            }
            held.take()?.packed
        };
        let ready = tokio::time::timeout(budget, receiver.wait_for(Option::is_some))
            .await
            .ok()?
            .ok()?
            .clone()?;
        // The last holder but this one, once the receiver goes: the sender
        // dropped after sending.
        drop(receiver);
        let packed = Arc::try_unwrap(ready).unwrap_or_else(|shared| (*shared).clone());
        (packed.complete && packed.packed_from(&candidates_for(store, slot))).then_some(packed)
    }

    /// Register a packing for `slot` on `head_root` and hand back what it
    /// sends its result through, or `None` when one for those is already
    /// registered. The packing it replaces, if any, is abandoned.
    fn claim(&self, slot: Slot, head_root: H256) -> Option<Claim> {
        let mut held = self
            .0
            .lock()
            .expect("prepared PQ attestations lock poisoned");
        if let Some(prepared) = held.as_ref() {
            if prepared.slot == slot && prepared.head_root == head_root {
                return None;
            }
            prepared.abandoned.store(true, Ordering::Release);
        }
        let (packed, receiver) = watch::channel(None);
        let abandoned = Arc::new(AtomicBool::new(false));
        *held = Some(Prepared {
            slot,
            head_root,
            packed: receiver,
            abandoned: abandoned.clone(),
        });
        Some(Claim { packed, abandoned })
    }

    /// Forget the packing `abandoned` belongs to, when it is still the one
    /// held.
    fn release(&self, abandoned: &Arc<AtomicBool>) {
        let mut held = self
            .0
            .lock()
            .expect("prepared PQ attestations lock poisoned");
        if held
            .as_ref()
            .is_some_and(|prepared| Arc::ptr_eq(&prepared.abandoned, abandoned))
        {
            *held = None;
        }
    }

    /// Whether a packing for `slot` on `head_root` is registered.
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
    use ethlambda_types::beacon::containers::pq::{AggregationBits, Attestation};
    use ethlambda_types::beacon::containers::shared::AttestationData;

    use super::*;

    fn aggregate() -> Arc<PooledPqAggregate> {
        Arc::new(PooledPqAggregate {
            attestation: Attestation {
                aggregation_bits: AggregationBits::default(),
                data: AttestationData::default(),
                committee_bits: Default::default(),
            },
            committee_index: 0,
            attesting_indices: Vec::new(),
            proof: Default::default(),
        })
    }

    fn packing(complete: bool) -> PackedAttestations {
        PackedAttestations::new(Vec::new(), vec![1, 2, 3], complete, Vec::new())
    }

    /// A preparation holding `packed` (still under way when `None`) for
    /// `slot` on `head_root`, and the sender a packing would answer through.
    fn held(
        slot: Slot,
        head_root: H256,
        packed: Option<PackedAttestations>,
    ) -> (
        PreparedPqAttestations,
        watch::Sender<Option<Arc<PackedAttestations>>>,
    ) {
        let (sender, receiver) = watch::channel(packed.map(Arc::new));
        let prepared = PreparedPqAttestations(Arc::new(Mutex::new(Some(Prepared {
            slot,
            head_root,
            packed: receiver,
            abandoned: Arc::new(AtomicBool::new(false)),
        }))));
        (prepared, sender)
    }

    fn empty_pool_store() -> Store {
        crate::tests::beacon_store(0, 0)
    }

    #[test]
    fn candidates_are_the_same_by_identity_in_any_order() {
        let (a, b) = (aggregate(), aggregate());
        assert!(same_aggregates(
            &[a.clone(), b.clone()],
            &[b.clone(), a.clone()]
        ));
        assert!(
            !same_aggregates(&[a.clone()], &[b.clone()]),
            "equal content, another aggregate"
        );
        assert!(!same_aggregates(&[a.clone()], &[a.clone(), b]));
        assert!(same_aggregates(&[], &[]));
    }

    #[tokio::test]
    async fn a_complete_packing_is_taken_once_for_its_own_slot_and_head() {
        let root = H256::repeat_byte(1);
        let store = empty_pool_store();
        let budget = Duration::from_millis(50);
        let (prepared, _sender) = held(10, root, Some(packing(true)));
        assert!(prepared.take(&store, 11, root, budget).await.is_none());
        assert!(
            prepared
                .take(&store, 10, H256::repeat_byte(2), budget)
                .await
                .is_none()
        );
        let taken = prepared.take(&store, 10, root, budget).await;
        assert_eq!(taken.map(|packed| packed.proof), Some(vec![1, 2, 3]));
        assert!(
            prepared.take(&store, 10, root, budget).await.is_none(),
            "taken once"
        );
        assert!(
            PreparedPqAttestations::default()
                .take(&store, 10, root, budget)
                .await
                .is_none()
        );
    }

    /// A packing that fell back to one committee's attestation is left to
    /// production, which may yet merge everything.
    #[tokio::test]
    async fn a_partial_packing_is_not_taken() {
        let root = H256::repeat_byte(1);
        let (prepared, _sender) = held(10, root, Some(packing(false)));
        let taken = prepared
            .take(&empty_pool_store(), 10, root, Duration::from_millis(50))
            .await;
        assert!(taken.is_none());
    }

    /// A packing made from other candidates than the pool's now is stale: an
    /// aggregate arrived or was replaced since, so production packs again.
    #[tokio::test]
    async fn a_packing_from_other_candidates_is_not_taken() {
        let root = H256::repeat_byte(1);
        let mut stale = packing(true);
        stale.candidates = vec![aggregate()];
        let (prepared, _sender) = held(10, root, Some(stale));
        let taken = prepared
            .take(&empty_pool_store(), 10, root, Duration::from_millis(50))
            .await;
        assert!(taken.is_none(), "the pool is empty now");
    }

    /// A packing still under way is waited for, up to the budget.
    #[tokio::test]
    async fn a_packing_under_way_is_waited_for_up_to_the_budget() {
        let root = H256::repeat_byte(1);
        let store = empty_pool_store();
        let (prepared, _sender) = held(10, root, None);
        assert!(
            prepared
                .take(&store, 10, root, Duration::from_millis(20))
                .await
                .is_none(),
            "nothing yet, and the budget runs out"
        );

        let (prepared, sender) = held(10, root, None);
        let waiting = {
            let (prepared, store) = (prepared.clone(), store.clone());
            tokio::spawn(async move {
                prepared
                    .take(&store, 10, root, Duration::from_secs(5))
                    .await
            })
        };
        sender.send(Some(Arc::new(packing(true)))).unwrap();
        let taken = waiting.await.unwrap();
        assert_eq!(taken.map(|packed| packed.proof), Some(vec![1, 2, 3]));
    }

    /// A packing that never started (its sender gone without a value) gives
    /// nothing at once rather than holding production to its budget.
    #[tokio::test]
    async fn a_packing_that_never_started_gives_nothing_at_once() {
        let root = H256::repeat_byte(1);
        let (prepared, sender) = held(10, root, None);
        drop(sender);
        let started = Instant::now();
        let taken = prepared
            .take(&empty_pool_store(), 10, root, Duration::from_secs(5))
            .await;
        assert!(taken.is_none());
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /// A packing is claimed once per slot and head. Another head or slot
    /// replaces it and abandons it, and one released after failing to start
    /// can be claimed again.
    #[test]
    fn a_packing_is_claimed_once_per_slot_and_head() {
        let (root, other) = (H256::repeat_byte(1), H256::repeat_byte(2));
        let prepared = PreparedPqAttestations::default();
        let first = prepared.claim(10, root).expect("first claim");
        assert!(prepared.claim(10, root).is_none(), "already under way");
        assert!(prepared.holds(10, root));

        let second = prepared.claim(10, other).expect("another head");
        assert!(first.abandoned.load(Ordering::Acquire), "replaced");
        assert!(!second.abandoned.load(Ordering::Acquire));
        assert!(prepared.holds(10, other) && !prepared.holds(10, root));

        // A replaced packing's release leaves its replacement alone.
        prepared.release(&first.abandoned);
        assert!(prepared.holds(10, other));
        prepared.release(&second.abandoned);
        assert!(!prepared.holds(10, other));
        assert!(prepared.claim(10, other).is_some(), "claimable again");
    }

    /// An abandoned packing gives the merge permit up without taking it.
    #[tokio::test]
    async fn an_abandoned_packing_does_not_take_the_merge_permit() {
        let abandoned = AtomicBool::new(true);
        let wait = PermitWait::Wait {
            abandoned: &abandoned,
        };
        assert!(merge_permit(wait, Duration::from_secs(1)).await.is_err());
        assert_eq!(MERGE_PERMIT.available_permits(), 1);
    }
}
