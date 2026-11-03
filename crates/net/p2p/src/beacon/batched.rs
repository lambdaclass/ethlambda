//! Batched stateful checks for the gossip kinds that arrive in bursts and cost
//! a pairing or a KZG proof each: subnet attestations and aggregates, sync
//! committee messages, and data column sidecars.
//!
//! Verifying them one by one pays each pairing's final exponentiation (and
//! each KZG call's fixed work) once per message. Here a message is queued
//! instead, and whichever blocking task is draining takes everything queued
//! and verifies it as one batch: every deferred signature of every message in
//! a single [`bls::verify_signature_sets`] call (one
//! `verify_cell_kzg_proof_batch` call across all the sidecars for columns).
//! Only when the batch fails is each message checked on its own, which yields
//! exactly the verdicts the one-by-one path yields: the batch is an
//! optimization over a pass that is almost always all-valid, never a different
//! rule.
//!
//! # Queue protocol
//!
//! There is no standing worker. A [`Batcher`] holds a queue and a `draining`
//! flag under one lock. The enqueue that finds no drainer running takes a
//! permit from the kind's usual pool and spawns one; every other enqueue just
//! pushes. The drainer loops, taking up to [`BATCH_CAP`] items at a time, and
//! clears the flag under the same lock that observes the queue empty, so a
//! message pushed after that starts a new drainer instead of waiting on one
//! that is already leaving.
//!
//! A drainer holds its permit for its whole run, and the `draining` flag
//! allows one drainer per kind at a time: that single drainer is the batching
//! point, since everything that arrives while it works lands in the next
//! batch. The work inside a batch is not serial, though: preparing each
//! message and, after a failed batch, checking each message on its own are
//! spread across cores with rayon, and the one combined crypto call
//! parallelises internally. A message that cannot be queued
//! (the queue is at [`QUEUE_CAP`], or it needs a drainer and the pool has no
//! permit) is answered `Ignore(Overloaded)` at once, as a message with no
//! permit always was: it is never held past the time gossipsub can wait.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use ethlambda_state_transition::beacon::bls::{self, SignatureSet};
use ethlambda_state_transition::beacon::gossip::column::{self, ColumnPrepared};
use ethlambda_state_transition::beacon::gossip::{self, IgnoreReason, Outcome};
use ethlambda_storage::Store;
use ethlambda_types::beacon::containers::DataColumnSidecar;
use ethlambda_types::beacon::primitives::ValidatorIndex;
use rayon::prelude::*;
use spawned_concurrency::tasks::{ActorRef, Context};
use tracing::warn;

use crate::beacon::verdict::{self, GossipId, GossipVerdict, Validated, guarded_try};
use crate::{P2PServer, metrics};

/// The most messages one drain pass verifies together. Large enough that the
/// fixed cost of a batch is spread thin; small enough that a forged message
/// costs the rest of its batch one fallback pass rather than an unbounded one.
const BATCH_CAP: usize = 1024;

/// The most messages that may wait for a drainer. Past it a message is
/// answered `Ignore(Overloaded)`: a longer queue would only make verdicts
/// later than gossipsub's cache can wait for.
const QUEUE_CAP: usize = 4 * BATCH_CAP;

/// A message waiting to be verified.
pub(crate) struct Queued {
    id: GossipId,
    object: Validated,
}

/// What [`Batcher::push`] decided.
pub(crate) enum Push<T, P> {
    /// Queued behind a drainer that is already running.
    Queued,
    /// Queued, and no drainer was running: the caller spawns one, holding the
    /// permit it was handed.
    StartDrainer(P),
    /// Not queued: the queue is full, or a drainer was needed and no permit
    /// was free. The item comes back so the caller can answer it.
    Overloaded(T),
}

struct QueueState<T> {
    items: VecDeque<T>,
    /// Whether a drainer is running, or about to be (its permit is taken and
    /// its task is being spawned).
    draining: bool,
}

/// A queue plus the "a drainer is running" flag, behind one lock.
pub(crate) struct Batcher<T> {
    state: Mutex<QueueState<T>>,
    queue_cap: usize,
    batch_cap: usize,
}

impl<T> Batcher<T> {
    pub(crate) fn new(queue_cap: usize, batch_cap: usize) -> Self {
        Self {
            state: Mutex::new(QueueState {
                items: VecDeque::new(),
                draining: false,
            }),
            queue_cap,
            batch_cap,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, QueueState<T>> {
        // Nothing under the lock can panic midway, so a poisoned lock still
        // holds a consistent queue.
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Queue `item`. `acquire` takes the permit a new drainer needs, and is
    /// only called when none is running. It runs under the lock, so it must
    /// not block: a semaphore's `try_acquire` is what it is for.
    pub(crate) fn push<P>(&self, item: T, acquire: impl FnOnce() -> Option<P>) -> Push<T, P> {
        let mut state = self.lock();
        if state.items.len() >= self.queue_cap {
            return Push::Overloaded(item);
        }
        if state.draining {
            state.items.push_back(item);
            return Push::Queued;
        }
        let Some(permit) = acquire() else {
            return Push::Overloaded(item);
        };
        state.draining = true;
        state.items.push_back(item);
        Push::StartDrainer(permit)
    }

    /// The next batch, or `None` once the queue is empty, which also marks
    /// the drainer as gone, under the lock the emptiness was seen under.
    pub(crate) fn take_batch(&self) -> Option<Vec<T>> {
        let mut state = self.lock();
        if state.items.is_empty() {
            state.draining = false;
            return None;
        }
        let take = state.items.len().min(self.batch_cap);
        Some(state.items.drain(..take).collect())
    }

    /// Mark the drainer gone without the queue having been seen empty, for a
    /// drainer that is unwinding: the next push then starts a new one, which
    /// takes whatever is still queued.
    fn abandon(&self) {
        self.lock().draining = false;
    }
}

/// Clears the `draining` flag if the drainer unwinds, so a panic cannot leave
/// the queue without a drainer for ever.
struct DrainGuard<'a, T>(&'a Batcher<T>);

impl<T> Drop for DrainGuard<'_, T> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.abandon();
        }
    }
}

/// The three batched kinds' queues, one per permit pool they draw from.
pub(crate) struct Batchers {
    /// Subnet attestations and aggregates, from the attestation pool.
    votes: Batcher<Queued>,
    /// Sync committee messages, from the sync pool.
    sync: Batcher<Queued>,
    /// Data column sidecars, from the gossip pool.
    columns: Batcher<Queued>,
}

impl Default for Batchers {
    fn default() -> Self {
        Self {
            votes: Batcher::new(QUEUE_CAP, BATCH_CAP),
            sync: Batcher::new(QUEUE_CAP, BATCH_CAP),
            columns: Batcher::new(QUEUE_CAP, BATCH_CAP),
        }
    }
}

/// Which batcher an object goes through.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Kind {
    Votes,
    Sync,
    Columns,
}

impl Kind {
    /// `None` for every object that keeps the per-message path.
    pub(crate) fn of(object: &Validated) -> Option<Self> {
        match object {
            Validated::Attestation { .. } | Validated::Aggregate { .. } => Some(Self::Votes),
            Validated::SyncCommitteeMessage { .. } => Some(Self::Sync),
            Validated::Column(_) => Some(Self::Columns),
            Validated::Block { .. }
            | Validated::Envelope(_)
            | Validated::ExecutionPayloadBid { .. }
            | Validated::ProposerPreferences(_)
            | Validated::PayloadAttestation(_)
            | Validated::Operation(_)
            | Validated::SyncContribution(_) => None,
        }
    }

    /// The metric label.
    fn label(self) -> &'static str {
        match self {
            Self::Votes => "votes",
            Self::Sync => "sync_committee",
            Self::Columns => "column",
        }
    }

    fn batcher(self, batchers: &Batchers) -> &Batcher<Queued> {
        match self {
            Self::Votes => &batchers.votes,
            Self::Sync => &batchers.sync,
            Self::Columns => &batchers.columns,
        }
    }
}

/// Queue `object` for batched verification, which the caller has found to be
/// of batched `kind`.
pub(crate) fn enqueue(
    server: &P2PServer,
    ctx: &Context<P2PServer>,
    kind: Kind,
    id: GossipId,
    object: Validated,
) {
    let pool = verdict::pool_of(&object);
    let permits = verdict::permits_for(server, &object).clone();
    let batchers = Arc::clone(&server.batchers);
    let pushed = kind
        .batcher(&batchers)
        .push(Queued { id, object }, || permits.try_acquire_owned().ok());
    match pushed {
        Push::Queued => {}
        Push::Overloaded(Queued { id, object }) => {
            verdict::report_overloaded(server, pool, id, object)
        }
        Push::StartDrainer(permit) => {
            let store = server.store.clone();
            let actor = ctx.actor_ref();
            let in_use = metrics::PoolInUse::new(pool);
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let _in_use = in_use;
                drain(kind.batcher(&batchers), kind, &store, &actor);
            });
        }
    }
}

/// The drainer: verify batches until the queue is empty. It is the only one
/// running for its kind, which is what makes a batch; the per-message work
/// inside [`verify_batch`] is spread across cores with rayon.
fn drain(batcher: &Batcher<Queued>, kind: Kind, store: &Store, actor: &ActorRef<P2PServer>) {
    let _guard = DrainGuard(batcher);
    while let Some(batch) = batcher.take_batch() {
        let (ids, mut objects): (Vec<GossipId>, Vec<Validated>) = batch
            .into_iter()
            .map(|queued| (queued.id, queued.object))
            .unzip();
        let outcomes = verify_batch(store, kind, &mut objects);
        for ((id, object), outcome) in ids.into_iter().zip(objects).zip(outcomes) {
            let _ = actor
                .send(GossipVerdict::new(id, outcome, object))
                .inspect_err(|_| warn!("P2P actor stopped before a gossip verdict arrived"));
        }
    }
}

/// One signature-checked object's stateful checks, evaluated up to its
/// pairings.
enum Prepared {
    Attestation(gossip::Prepared<()>),
    Aggregate(gossip::Prepared<Vec<ValidatorIndex>>),
    Sync(gossip::Prepared<Vec<(u64, usize)>>),
    /// Already decided: the preparation panicked, or the object is of a kind
    /// this batch does not verify.
    Done(Outcome),
}

impl Prepared {
    fn new(store: &Store, object: &Validated) -> Self {
        match object {
            Validated::Attestation {
                attestation,
                subnet_id,
            } => Self::Attestation(gossip::attestation::prepare_stateful_checks(
                store,
                attestation,
                *subnet_id,
            )),
            Validated::Aggregate { aggregate, .. } => {
                Self::Aggregate(gossip::aggregate::prepare_stateful_checks(store, aggregate))
            }
            Validated::SyncCommitteeMessage {
                message, subnet_id, ..
            } => Self::Sync(gossip::sync_committee::prepare_message_stateful_checks(
                store, message, *subnet_id,
            )),
            _ => Self::Done(Outcome::Ignore(IgnoreReason::Internal)),
        }
    }

    /// The pairings this object needs verified for its verdict to be settled.
    fn signature_sets(&self) -> Vec<SignatureSet> {
        match self {
            Self::Attestation(prepared) => prepared.signature_sets(),
            Self::Aggregate(prepared) => prepared.signature_sets(),
            Self::Sync(prepared) => prepared.signature_sets(),
            Self::Done(_) => Vec::new(),
        }
    }

    /// The verdict, writing what `Accept` carries into `object`.
    /// `batch_passed` says every pairing of the batch verified; when it did
    /// not, each pairing is evaluated here, on its own.
    fn resolve(self, batch_passed: bool, object: &mut Validated) -> Outcome {
        match (self, object) {
            (Self::Attestation(prepared), _) => accept_or(resolve(prepared, batch_passed)),
            (
                Self::Aggregate(prepared),
                Validated::Aggregate {
                    attesting_indices, ..
                },
            ) => match resolve(prepared, batch_passed) {
                Ok(indices) => {
                    *attesting_indices = indices;
                    Outcome::Accept
                }
                Err(outcome) => outcome,
            },
            (Self::Sync(prepared), Validated::SyncCommitteeMessage { seats, .. }) => {
                match resolve(prepared, batch_passed) {
                    Ok(resolved) => {
                        *seats = resolved;
                        Outcome::Accept
                    }
                    Err(outcome) => outcome,
                }
            }
            (Self::Done(outcome), _) => outcome,
            // `Prepared::new` built each variant from the object it is now
            // resolved against.
            (Self::Aggregate(_) | Self::Sync(_), _) => Outcome::Ignore(IgnoreReason::Internal),
        }
    }
}

fn accept_or(resolved: Result<(), Outcome>) -> Outcome {
    resolved.map_or_else(|outcome| outcome, |()| Outcome::Accept)
}

fn resolve<T>(prepared: gossip::Prepared<T>, batch_passed: bool) -> Result<T, Outcome> {
    if batch_passed {
        prepared.resolve_batch_passed()
    } else {
        prepared.resolve()
    }
}

/// Verify `objects` as one batch and return one verdict per object, in order,
/// filling in what an `Accept` carries (an aggregate's attesting indices, a
/// sync message's seats).
///
/// Preparation runs per object inside a panic guard, so a panic is
/// `Ignore(Internal)` for that object alone. The batched crypto call is
/// guarded too: a panic in it counts as a failed batch and falls back to
/// per-object checks.
pub(crate) fn verify_batch(store: &Store, kind: Kind, objects: &mut [Validated]) -> Vec<Outcome> {
    metrics::observe_gossip_batch_size(kind.label(), objects.len());
    if kind == Kind::Columns {
        return verify_columns(store, objects);
    }
    let prepared: Vec<Prepared> = objects
        .par_iter()
        .map(|object| guarded_try(|| Prepared::new(store, object)).unwrap_or_else(Prepared::Done))
        .collect();
    let sets: Vec<SignatureSet> = prepared.iter().flat_map(Prepared::signature_sets).collect();
    let batch_passed = guarded_try(|| bls::verify_signature_sets(&sets)).unwrap_or(false);
    if !batch_passed {
        metrics::inc_gossip_batch_fallback(kind.label());
    }
    prepared
        .into_par_iter()
        .zip(objects.par_iter_mut())
        .map(|(item, object)| {
            guarded_try(|| item.resolve(batch_passed, object)).unwrap_or_else(|outcome| outcome)
        })
        .collect()
}

/// The column half of [`verify_batch`]: one `verify_cell_kzg_proof_batch` call
/// over every pending sidecar, per-sidecar verification only if it fails.
fn verify_columns(store: &Store, objects: &[Validated]) -> Vec<Outcome> {
    let sidecars: Vec<Option<&DataColumnSidecar>> = objects
        .iter()
        .map(|object| match object {
            Validated::Column(sidecar) => Some(&**sidecar),
            _ => None,
        })
        .collect();
    let prepared: Vec<ColumnPrepared> = sidecars
        .par_iter()
        .map(|sidecar| match sidecar {
            Some(sidecar) => guarded_try(|| column::prepare_stateful_checks(store, sidecar))
                .unwrap_or_else(ColumnPrepared::Settled),
            None => ColumnPrepared::Settled(Outcome::Ignore(IgnoreReason::Internal)),
        })
        .collect();
    let pending: Vec<(&DataColumnSidecar, &column::PendingKzg)> = prepared
        .iter()
        .zip(&sidecars)
        .filter_map(|(item, sidecar)| Some(((*sidecar)?, item.pending()?)))
        .collect();
    let batch_passed =
        pending.is_empty() || guarded_try(|| column::kzg_batch_verifies(&pending)).unwrap_or(false);
    // A lone sidecar's batch is its own check: a failure needs no second pass.
    let fall_back = !batch_passed && pending.len() > 1;
    if fall_back {
        metrics::inc_gossip_batch_fallback(Kind::Columns.label());
    }
    prepared
        .into_par_iter()
        .zip(sidecars.par_iter())
        .map(|(item, sidecar)| {
            let proofs_verify = match (item.pending(), sidecar) {
                (None, _) => true,
                (Some(_), _) if batch_passed => true,
                (Some(_), _) if !fall_back => false,
                (Some(pending), Some(sidecar)) => {
                    guarded_try(|| column::kzg_proofs_verify(sidecar, pending)).unwrap_or(false)
                }
                (Some(_), None) => false,
            };
            item.settle(proofs_verify)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn batcher(queue_cap: usize, batch_cap: usize) -> Batcher<u32> {
        Batcher::new(queue_cap, batch_cap)
    }

    #[test]
    fn the_first_push_starts_a_drainer_and_later_ones_queue_behind_it() {
        let batcher = batcher(8, 8);
        assert!(matches!(
            batcher.push(1, || Some(())),
            Push::StartDrainer(())
        ));
        assert!(matches!(
            batcher.push(2, || -> Option<()> { panic!("no second permit") }),
            Push::Queued
        ));
        assert_eq!(batcher.take_batch(), Some(vec![1, 2]));
    }

    #[test]
    fn a_push_without_a_permit_is_overloaded_and_queues_nothing() {
        let batcher = batcher(8, 8);
        assert!(matches!(
            batcher.push(1, || None::<()>),
            Push::Overloaded(1)
        ));
        // Nothing was queued and no drainer is recorded: the next push may
        // still start one.
        assert!(matches!(
            batcher.push(2, || Some(())),
            Push::StartDrainer(())
        ));
        assert_eq!(batcher.take_batch(), Some(vec![2]));
    }

    #[test]
    fn a_full_queue_answers_overloaded() {
        let batcher = batcher(2, 8);
        assert!(matches!(
            batcher.push(1, || Some(())),
            Push::StartDrainer(())
        ));
        assert!(matches!(batcher.push(2, || Some(())), Push::Queued));
        assert!(matches!(batcher.push(3, || Some(())), Push::Overloaded(3)));
        // Taking a batch frees room again.
        assert_eq!(batcher.take_batch(), Some(vec![1, 2]));
        assert!(matches!(batcher.push(4, || Some(())), Push::Queued));
    }

    #[test]
    fn a_batch_is_at_most_the_batch_cap_and_keeps_arrival_order() {
        let batcher = batcher(16, 3);
        for item in 0..7 {
            batcher.push(item, || Some(()));
        }
        assert_eq!(batcher.take_batch(), Some(vec![0, 1, 2]));
        assert_eq!(batcher.take_batch(), Some(vec![3, 4, 5]));
        assert_eq!(batcher.take_batch(), Some(vec![6]));
        assert_eq!(batcher.take_batch(), None);
    }

    #[test]
    fn a_message_pushed_after_the_drainer_saw_an_empty_queue_starts_a_new_drainer() {
        let batcher = batcher(8, 8);
        batcher.push(1, || Some(()));
        assert_eq!(batcher.take_batch(), Some(vec![1]));
        assert_eq!(batcher.take_batch(), None);
        // The drainer has left; this one must not wait behind it.
        assert!(matches!(
            batcher.push(2, || Some(())),
            Push::StartDrainer(())
        ));
        assert_eq!(batcher.take_batch(), Some(vec![2]));
    }

    #[test]
    fn an_abandoned_drainer_leaves_its_queue_to_the_next_push() {
        let batcher = batcher(8, 8);
        batcher.push(1, || Some(()));
        batcher.abandon();
        assert!(matches!(
            batcher.push(2, || Some(())),
            Push::StartDrainer(())
        ));
        assert_eq!(batcher.take_batch(), Some(vec![1, 2]));
    }

    /// Hammer one batcher from several producers while drainers come and go:
    /// every item pushed is either rejected on the spot or taken by exactly
    /// one batch, and none is left behind once the producers stop.
    #[test]
    fn every_pushed_item_is_answered_while_drainers_finish_and_restart() {
        let batcher = Arc::new(batcher(64, 5));
        let answered = Arc::new(AtomicUsize::new(0));
        let producers = 4;
        let per_producer = 500;
        let mut handles = Vec::new();
        for producer in 0..producers {
            let batcher = Arc::clone(&batcher);
            let answered = Arc::clone(&answered);
            handles.push(std::thread::spawn(move || {
                let mut drainers = Vec::new();
                for item in 0..per_producer {
                    match batcher.push((producer * per_producer + item) as u32, || Some(())) {
                        Push::Queued => {}
                        Push::Overloaded(_) => {
                            answered.fetch_add(1, Ordering::SeqCst);
                        }
                        Push::StartDrainer(()) => {
                            let batcher = Arc::clone(&batcher);
                            let answered = Arc::clone(&answered);
                            drainers.push(std::thread::spawn(move || {
                                while let Some(batch) = batcher.take_batch() {
                                    answered.fetch_add(batch.len(), Ordering::SeqCst);
                                }
                            }));
                        }
                    }
                }
                for drainer in drainers {
                    drainer.join().expect("drainer");
                }
            }));
        }
        for handle in handles {
            handle.join().expect("producer");
        }
        // Whatever a drainer left queued when it exited is picked up by a
        // push that came after, so nothing is stranded.
        assert_eq!(batcher.take_batch(), None);
        assert_eq!(answered.load(Ordering::SeqCst), producers * per_producer);
    }
}

/// [`verify_batch`] against states that verify real signatures.
#[cfg(test)]
mod verify_tests {
    use ethlambda_state_transition::beacon::constants::DOMAIN_BEACON_ATTESTER;
    use ethlambda_state_transition::beacon::fork::ForkName;
    use ethlambda_state_transition::beacon::gossip::attestation::compute_subnet_for_attestation;
    use ethlambda_state_transition::beacon::gossip::{IgnoreReason, QueueReason, RejectReason};
    use ethlambda_state_transition::beacon::helpers::accessors::{
        CommitteeCacheExt as _, get_beacon_committee,
    };
    use ethlambda_state_transition::beacon::helpers::misc::{
        compute_domain, compute_signing_root, compute_start_slot_at_epoch,
    };
    use ethlambda_state_transition::beacon::helpers::test_state::{
        sign_for, with_signing_validators_at,
    };
    use ethlambda_storage::backend::InMemoryBackend;
    use ethlambda_storage::{CacheKey, Store};
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::containers::electra::{self, SingleAttestation};
    use ethlambda_types::beacon::containers::shared::{AttestationData, Checkpoint, Fork};
    use ethlambda_types::beacon::containers::{DataColumnSidecar, SignedBeaconBlock};
    use ethlambda_types::beacon::primitives::{H256, HashTreeRoot as _, Root};

    use super::*;
    use crate::test_support::valid_shaped_sidecar;

    const FULU_EPOCH: u64 = 2;

    /// A store holding the vote block's state, `attesters` correctly signed
    /// votes from distinct members of one committee, and their subnet. The
    /// vote is cast in a fork's first slot with no block, so it is signed
    /// under the schedule's domain, as the rules' own tests do.
    fn votes(attesters: usize) -> (Store, Vec<SingleAttestation>, u64) {
        let config = Config::mainnet()
            .with_fork_epoch(ForkName::Electra, 0)
            .with_fork_epoch(ForkName::Fulu, FULU_EPOCH);
        let mut state = with_signing_validators_at(ForkName::Electra, 256);
        let pre_fork_slot = compute_start_slot_at_epoch(FULU_EPOCH) - 1;
        *state.slot_mut() = pre_fork_slot;
        *state.fork_mut() = Fork {
            previous_version: config.deneb_fork_version,
            current_version: config.electra_fork_version,
            epoch: 0,
        };
        state.apply_pending_mutations();

        let anchor = ethlambda_types::checkpoint::Checkpoint {
            root: H256::ZERO,
            slot: 0,
        };
        let mut store = Store::init_beacon(
            Arc::new(InMemoryBackend::new()),
            config.genesis_time,
            config.clone(),
            H256::ZERO,
            anchor,
            0,
        );
        let block_root = Root::repeat_byte(7);
        let block = SignedBeaconBlock::Electra(electra::SignedBeaconBlock {
            message: electra::BeaconBlock {
                slot: pre_fork_slot,
                proposer_index: 0,
                parent_root: Root::ZERO,
                state_root: Root::ZERO,
                body: electra::BeaconBlockBody::empty(),
            },
            signature: Default::default(),
        });
        store
            .insert_pending_block(block_root, block)
            .expect("insert the voted block");
        store.cache_state(CacheKey::BlockState(block_root), Arc::new(state.clone()));

        let slot = compute_start_slot_at_epoch(FULU_EPOCH);
        let committee = get_beacon_committee(&state, slot, 0).expect("committee");
        assert!(committee.len() >= attesters, "the committee is big enough");
        let data = AttestationData {
            slot,
            index: 0,
            beacon_block_root: block_root,
            source: Default::default(),
            target: Checkpoint {
                epoch: FULU_EPOCH,
                root: block_root,
            },
        };
        let domain = compute_domain(
            DOMAIN_BEACON_ATTESTER,
            config.fulu_fork_version,
            state.genesis_validators_root(),
        );
        let signing_root = compute_signing_root(data.hash_tree_root(), domain);
        let votes = committee
            .iter()
            .take(attesters)
            .map(|&attester_index| SingleAttestation {
                committee_index: 0,
                attester_index,
                data,
                signature: sign_for(attester_index as usize, signing_root),
            })
            .collect();
        let committees_per_slot = store
            .committee_cache()
            .committees(&state, FULU_EPOCH)
            .committees_per_slot();
        let subnet_id = compute_subnet_for_attestation(committees_per_slot, slot, 0, &config);
        (store, votes, subnet_id)
    }

    fn object(attestation: SingleAttestation, subnet_id: u64) -> Validated {
        Validated::Attestation {
            attestation: Box::new(attestation),
            subnet_id,
        }
    }

    #[test]
    fn a_drain_of_valid_attestations_accepts_every_one() {
        let (store, votes, subnet_id) = votes(6);
        let mut objects: Vec<Validated> = votes
            .into_iter()
            .map(|vote| object(vote, subnet_id))
            .collect();
        let outcomes = verify_batch(&store, Kind::Votes, &mut objects);
        assert_eq!(outcomes, vec![Outcome::Accept; 6]);
    }

    /// The batch fails on the forged signature, and the fallback then settles
    /// each message on its own: only the forged one is rejected.
    #[test]
    fn one_forged_signature_rejects_only_that_attestation() {
        let (store, mut votes, subnet_id) = votes(6);
        let forged = 3;
        votes[forged].signature = sign_for(
            votes[forged].attester_index as usize + 1,
            votes[forged].data.hash_tree_root(),
        );
        let mut objects: Vec<Validated> = votes
            .into_iter()
            .map(|vote| object(vote, subnet_id))
            .collect();
        let outcomes = verify_batch(&store, Kind::Votes, &mut objects);
        for (position, outcome) in outcomes.into_iter().enumerate() {
            if position == forged {
                assert_eq!(outcome, Outcome::Reject(RejectReason::BadSignature));
            } else {
                assert_eq!(outcome, Outcome::Accept, "message {position}");
            }
        }
    }

    /// A message that fails a rule before its signature is judged by that rule
    /// and takes nothing from the batch; one that fails a rule after a good
    /// signature gets that rule's verdict; the rest are accepted.
    #[test]
    fn rule_failures_in_a_batch_keep_their_own_verdicts() {
        let (store, votes, subnet_id) = votes(4);
        let mut objects = vec![
            object(votes[0].clone(), subnet_id),
            // On the wrong subnet.
            object(votes[1].clone(), subnet_id + 1),
            // An unknown block: nothing to verify.
            object(
                {
                    let mut vote = votes[2].clone();
                    vote.data.beacon_block_root = Root::repeat_byte(1);
                    vote
                },
                subnet_id,
            ),
            object(votes[3].clone(), subnet_id),
        ];
        let outcomes = verify_batch(&store, Kind::Votes, &mut objects);
        assert_eq!(
            outcomes,
            vec![
                Outcome::Accept,
                Outcome::Reject(RejectReason::WrongSubnet),
                Outcome::Ignore(IgnoreReason::UnknownBlock),
                Outcome::Accept,
            ]
        );
    }

    #[test]
    fn a_single_message_batch_matches_the_one_by_one_verdict() {
        let (store, votes, subnet_id) = votes(1);
        let mut objects = vec![object(votes[0].clone(), subnet_id)];
        assert_eq!(
            verify_batch(&store, Kind::Votes, &mut objects),
            vec![Outcome::Accept]
        );
    }

    #[test]
    fn an_empty_batch_has_no_verdicts() {
        let (store, _, _) = votes(0);
        assert!(verify_batch(&store, Kind::Votes, &mut []).is_empty());
    }

    /// Columns whose block is unknown are queued by their stateful rules; the
    /// batch has no proofs to verify for them, and each still gets its verdict.
    #[test]
    fn columns_decided_before_their_proofs_get_their_verdicts() {
        let (store, _, _) = votes(0);
        let mut objects: Vec<Validated> = (0..3)
            .map(|index| {
                Validated::Column(Box::new(DataColumnSidecar::Fulu(valid_shaped_sidecar(
                    5, index,
                ))))
            })
            .collect();
        let outcomes = verify_batch(&store, Kind::Columns, &mut objects);
        assert_eq!(
            outcomes,
            vec![Outcome::Queue(QueueReason::ParentUnknown); 3]
        );
    }
}
