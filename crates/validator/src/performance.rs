//! Per-validator outcomes of the duties this client attempted.
//!
//! The series in [`crate::metrics`] say how the client as a whole is doing.
//! These say it per validator: for each attestation, block, sync committee
//! message and payload timeliness committee vote a validator was due, whether
//! a beacon node accepted it, and for each block, whether it was still the
//! canonical one at its slot a few slots later.
//!
//! They record what this client attempted and what the node it reached made
//! of it, nothing more. Whether an accepted attestation was included in a
//! block, and with the right head, is the chain's answer: it needs a beacon
//! node that serves the rewards endpoints, which ethlambda's does not yet.
//!
//! # What counts
//!
//! A duty counts once, from the moment its service takes it up, as one of:
//!
//! - `published`: a beacon node accepted the message;
//! - `failed`: anything else. The node refused it or did not answer, the
//!   signature failed, slashing protection refused it, or the duty ran past
//!   its deadline.
//!
//! Some duties end as neither, as the unlabelled series in [`crate::metrics`]
//! count them: a duty doppelganger protection withholds (dropped before any
//! service sees it), an attestation for a key the keymanager deleted since the
//! schedule was fetched (once the slot's attestation data was fetched: the
//! held keys are read after it, so a failed fetch, or one still out at the
//! end of the slot, counts every duty of the slot as failed), every duty of a
//! slot the per-slot sync check withholds (none reaches a service), a sync
//! committee message or payload vote already served this slot, a sync
//! committee message or payload vote not signed over an optimistic head, a
//! payload vote for a slot the node knows no block for, and a blinded block
//! the node did not confirm. The proposal check below says whether that
//! last one went out. The sync committee and payload vote services do not
//! filter on held keys, so a deleted key's duty there fails to sign and counts
//! as failed. An attestation served twice is refused by slashing protection
//! the second time, and counts as failed, as `attestations_refused_total`
//! counts it.
//!
//! # A batch the node accepted in part
//!
//! The pool endpoints answer a batch they accepted in part with the positions
//! they refused, which the HTTP layer logs and turns into a count (see
//! [`crate::beacon_node::BeaconNodeApi::submit_attestations`]). Nothing here
//! can tell which validators that count covers, so such a batch is counted
//! under `other`, its accepted part as `published` and the rest as `failed`.
//! The client's totals stay right, and no validator is credited with what may
//! have been another's outcome.
//!
//! # The label cap
//!
//! Each series carries a `validator` label. The first [`LABELLED_VALIDATORS`]
//! validators an outcome is recorded for each get their own, their index, and
//! keep it for the life of the process. Every validator after them is counted
//! under `other`, so the series stay bounded with thousands of keys, and
//! `sum without (validator)` is always the whole client's count. Lighthouse
//! caps its validator monitor's per-validator series at the same 64. Which
//! validators get a label depends on which had a duty first, so it can differ
//! from one run to the next once more than the cap are loaded. A label is
//! never given back: a key the keymanager deletes keeps its own, and once the
//! cap is taken, a key imported later is counted under `other` until the
//! client restarts.
//!
//! A validator's children of every series are created at zero when it takes
//! its label, so each outcome after the one that granted it is an increase
//! `rate()` and `increase()` see, its first `orphaned` included.
//!
//! # The epoch summary
//!
//! When the first outcome of a later epoch is recorded, every earlier epoch
//! still open is summarized at info: one line for each labelled validator with
//! an outcome in it, and one for `other` when it has any. Each duty is written
//! as `published/attempted`. The same cap that bounds the series bounds the
//! lines, so a client with thousands of keys writes at most 65 an epoch. An
//! outcome recorded after its epoch's summary (a duty the loop finished late)
//! is counted in the series but left out of the lines.
//!
//! # The proposal check
//!
//! [`CHECK_DELAY_SLOTS`] slots after a block was handed to a beacon node, a
//! spawned task asks `GET /eth/v1/beacon/headers/{slot}` which block the
//! node's canonical chain holds at the block's slot, and counts the answer in
//! `ethlambda_validator_proposal_checks_total`: `canonical` for this block,
//! `replaced` for another one, `orphaned` for none, and `unknown` when no node
//! answered. Off the duty loop, so a slow node never delays a duty.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::SystemTime;

use ethlambda_metrics::{IntCounterVec, register_int_counter_vec};
use ethlambda_types::ShortRoot;
use ethlambda_types::beacon::primitives::{Epoch, Root, Slot, ValidatorIndex};
use ethlambda_types::beacon::signing::compute_epoch_at_slot;
use tracing::{debug, info, warn};

use crate::beacon_node::BeaconNodeApi;

/// How many validators get a `validator` label of their own. Lighthouse's
/// threshold for per-validator series and logs.
pub const LABELLED_VALIDATORS: usize = 64;

/// How many slots after a block's slot the proposal check asks about it.
///
/// Long enough that the reorg a late block usually suffers, one proposer
/// building on its parent in the next slot, has happened; short enough that
/// the answer comes within the epoch.
pub const CHECK_DELAY_SLOTS: u64 = 4;

/// The `validator` label of every validator past the cap, and of outcomes no
/// single validator can be credited with.
const OTHER: &str = "other";

static ATTESTATION_OUTCOMES_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "ethlambda_validator_attestation_outcomes_total",
        "Attestation duties by validator and by whether a beacon node accepted the attestation",
        &["validator", "outcome"]
    )
    .unwrap()
});

static PROPOSAL_OUTCOMES_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "ethlambda_validator_proposal_outcomes_total",
        "Proposal duties by validator and by whether a beacon node accepted the block",
        &["validator", "outcome"]
    )
    .unwrap()
});

static SYNC_COMMITTEE_MESSAGE_OUTCOMES_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "ethlambda_validator_sync_committee_message_outcomes_total",
        "Sync committee message duties by validator and by whether a beacon node accepted the \
         message",
        &["validator", "outcome"]
    )
    .unwrap()
});

static PAYLOAD_ATTESTATION_OUTCOMES_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "ethlambda_validator_payload_attestation_outcomes_total",
        "Payload timeliness committee duties by validator and by whether a beacon node accepted \
         the vote",
        &["validator", "outcome"]
    )
    .unwrap()
});

static PROPOSAL_CHECKS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "ethlambda_validator_proposal_checks_total",
        "Published blocks by validator and by which block the canonical chain held at their slot \
         a few slots later",
        &["validator", "result"]
    )
    .unwrap()
});

/// Register every series, with its `other` children at zero, so the client's
/// totals exist from startup. A labelled validator's children are created at
/// zero when it takes its label (see [`Performance::label`]). Called from
/// [`crate::metrics::init`].
pub(crate) fn init() {
    create_children(OTHER);
}

/// Create `validator`'s child of every series at zero, so that its first
/// `failed` or `orphaned` is an increase `rate()` and `increase()` see rather
/// than the starting value of a new series, which they read as a baseline.
fn create_children(validator: &str) {
    for duty in Duty::ALL {
        for outcome in Outcome::ALL {
            duty.series()
                .with_label_values(&[validator, outcome.as_str()]);
        }
    }
    for check in ProposalCheck::ALL {
        PROPOSAL_CHECKS_TOTAL.with_label_values(&[validator, check.as_str()]);
    }
}

/// A duty whose outcomes are counted per validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Duty {
    Attestation,
    Proposal,
    SyncCommitteeMessage,
    PayloadAttestation,
}

impl Duty {
    const ALL: [Duty; 4] = [
        Duty::Attestation,
        Duty::Proposal,
        Duty::SyncCommitteeMessage,
        Duty::PayloadAttestation,
    ];

    fn series(self) -> &'static IntCounterVec {
        match self {
            Duty::Attestation => &ATTESTATION_OUTCOMES_TOTAL,
            Duty::Proposal => &PROPOSAL_OUTCOMES_TOTAL,
            Duty::SyncCommitteeMessage => &SYNC_COMMITTEE_MESSAGE_OUTCOMES_TOTAL,
            Duty::PayloadAttestation => &PAYLOAD_ATTESTATION_OUTCOMES_TOTAL,
        }
    }
}

/// What became of one duty. See the module doc for what each covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Published,
    Failed,
}

impl Outcome {
    const ALL: [Outcome; 2] = [Outcome::Published, Outcome::Failed];

    fn as_str(self) -> &'static str {
        match self {
            Outcome::Published => "published",
            Outcome::Failed => "failed",
        }
    }
}

/// Which block the node's canonical chain held at a published block's slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalCheck {
    /// The block this client published.
    Canonical,
    /// Another block: one the chain built on instead, or one some other
    /// signer published for the slot.
    Replaced,
    /// None: the chain went past the slot without this block.
    Orphaned,
    /// No node answered, so nothing is known.
    Unknown,
}

impl ProposalCheck {
    const ALL: [ProposalCheck; 4] = [
        ProposalCheck::Canonical,
        ProposalCheck::Replaced,
        ProposalCheck::Orphaned,
        ProposalCheck::Unknown,
    ];

    fn as_str(self) -> &'static str {
        match self {
            ProposalCheck::Canonical => "canonical",
            ProposalCheck::Replaced => "replaced",
            ProposalCheck::Orphaned => "orphaned",
            ProposalCheck::Unknown => "unknown",
        }
    }
}

/// How many of one duty were published and how many failed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub published: u64,
    pub failed: u64,
}

/// `published/attempted`, as the epoch summary writes it.
impl std::fmt::Display for Counts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.published, self.published + self.failed)
    }
}

/// One validator's outcomes in one epoch, or the `other` group's.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Tally {
    pub attestations: Counts,
    pub proposals: Counts,
    pub sync_committee_messages: Counts,
    pub payload_attestations: Counts,
}

impl Tally {
    fn add(&mut self, duty: Duty, outcome: Outcome, count: u64) {
        let counts = match duty {
            Duty::Attestation => &mut self.attestations,
            Duty::Proposal => &mut self.proposals,
            Duty::SyncCommitteeMessage => &mut self.sync_committee_messages,
            Duty::PayloadAttestation => &mut self.payload_attestations,
        };
        match outcome {
            Outcome::Published => counts.published += count,
            Outcome::Failed => counts.failed += count,
        }
    }
}

/// One epoch's tallies, until its summary is logged.
#[derive(Debug, Default)]
struct EpochTally {
    /// Each labelled validator's.
    validators: BTreeMap<ValidatorIndex, Tally>,
    /// Every outcome counted under `other`.
    other: Tally,
    /// The validators those outcomes are of, for the summary to say how many
    /// `other` covers: the ones past the cap, and those of a batch accepted
    /// in part.
    other_validators: BTreeSet<ValidatorIndex>,
}

#[derive(Debug, Default)]
struct Epochs {
    open: BTreeMap<Epoch, EpochTally>,
    /// The last epoch summarized. An outcome for it or one before is counted
    /// in the series only.
    summarized: Option<Epoch>,
}

/// Where each validator's outcomes are counted, shared by every duty service.
#[derive(Debug)]
pub struct Performance {
    /// How many validators get a label of their own.
    cap: usize,
    /// The validators that hold one.
    labelled: Mutex<HashSet<ValidatorIndex>>,
    epochs: Mutex<Epochs>,
}

impl Performance {
    /// `cap` validators get a label of their own; [`LABELLED_VALIDATORS`] is
    /// the client's.
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            labelled: Mutex::default(),
            epochs: Mutex::default(),
        }
    }

    /// Count one of `validator`'s duties at `slot`.
    pub fn record(&self, duty: Duty, slot: Slot, validator: ValidatorIndex, outcome: Outcome) {
        self.count(duty, slot, Some(validator), &[], outcome, 1);
    }

    /// Count `published` and `failed` duties of `validators` at `slot` that
    /// no single one of them can be credited with, under `other`.
    fn record_unattributed(
        &self,
        duty: Duty,
        slot: Slot,
        validators: &[ValidatorIndex],
        published: u64,
        failed: u64,
    ) {
        self.count(duty, slot, None, validators, Outcome::Published, published);
        self.count(duty, slot, None, validators, Outcome::Failed, failed);
    }

    /// Count one proposal check. Not in the epoch summary: each check is
    /// logged on its own when it is made.
    pub fn record_check(&self, validator: ValidatorIndex, check: ProposalCheck) {
        let label = self.label(validator);
        PROPOSAL_CHECKS_TOTAL
            .with_label_values(&[label.as_deref().unwrap_or(OTHER), check.as_str()])
            .inc();
    }

    /// `validator`'s own label, or `None` when it is counted under `other`.
    ///
    /// A validator holding one keeps it; one that does not takes the next
    /// free one, while any is left, and its children of every series are
    /// created at zero then. The outcome that granted the label is counted
    /// right after, so that first one still appears as the series' starting
    /// value; every later one is an increase.
    fn label(&self, validator: ValidatorIndex) -> Option<String> {
        let mut labelled = lock(&self.labelled);
        if labelled.contains(&validator) {
            return Some(validator.to_string());
        }
        if labelled.len() >= self.cap {
            return None;
        }
        labelled.insert(validator);
        let label = validator.to_string();
        create_children(&label);
        Some(label)
    }

    /// Count `count` outcomes, `validator`'s or, for `None`, those of
    /// `unattributed` that none of them is credited with.
    fn count(
        &self,
        duty: Duty,
        slot: Slot,
        validator: Option<ValidatorIndex>,
        unattributed: &[ValidatorIndex],
        outcome: Outcome,
        count: u64,
    ) {
        if count == 0 {
            return;
        }
        let label = validator.and_then(|validator| self.label(validator));
        duty.series()
            .with_label_values(&[label.as_deref().unwrap_or(OTHER), outcome.as_str()])
            .inc_by(count);

        let epoch = compute_epoch_at_slot(slot);
        let summaries = {
            let mut epochs = lock(&self.epochs);
            if epochs
                .summarized
                .is_some_and(|summarized| epoch <= summarized)
            {
                debug!(
                    %slot,
                    ?validator,
                    "Duty outcome recorded after its epoch's summary; counted in the series only"
                );
                return;
            }
            // Every epoch before this one is over: take them out to log.
            let later = epochs.open.split_off(&epoch);
            let earlier = std::mem::replace(&mut epochs.open, later);
            if epoch > 0 {
                epochs.summarized = epochs.summarized.max(Some(epoch - 1));
            }
            let tally = epochs.open.entry(epoch).or_default();
            match (validator, label.is_some()) {
                (Some(validator), true) => {
                    tally
                        .validators
                        .entry(validator)
                        .or_default()
                        .add(duty, outcome, count);
                }
                (validator, _) => {
                    tally.other.add(duty, outcome, count);
                    tally.other_validators.extend(validator);
                    tally.other_validators.extend(unattributed);
                }
            }
            earlier
        };
        // Logged with the lock released.
        log_summaries(summaries);
    }

    /// What `validator` (or `other`, for `None`) has counted in `epoch` so
    /// far, while the epoch is open.
    #[cfg(test)]
    fn tally(&self, epoch: Epoch, validator: Option<ValidatorIndex>) -> Option<Tally> {
        let epochs = lock(&self.epochs);
        let open = epochs.open.get(&epoch)?;
        match validator {
            Some(validator) => open.validators.get(&validator).copied(),
            None => Some(open.other),
        }
    }
}

/// The counts behind a poisoned lock are still counts; a panic elsewhere must
/// not stop them, nor turn a drop during unwinding into an abort.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn log_summaries(summaries: BTreeMap<Epoch, EpochTally>) {
    for (epoch, epoch_tally) in summaries {
        for (validator, tally) in epoch_tally.validators {
            info!(
                %epoch,
                validator,
                attestations = %tally.attestations,
                proposals = %tally.proposals,
                sync_committee_messages = %tally.sync_committee_messages,
                payload_attestations = %tally.payload_attestations,
                "Validator epoch summary"
            );
        }
        let other = epoch_tally.other;
        if other != Tally::default() {
            info!(
                %epoch,
                validator = OTHER,
                validators = epoch_tally.other_validators.len(),
                attestations = %other.attestations,
                proposals = %other.proposals,
                sync_committee_messages = %other.sync_committee_messages,
                payload_attestations = %other.payload_attestations,
                "Validator epoch summary"
            );
        }
    }
}

/// One slot's batch of a duty, counted per validator however the service's
/// call ends.
///
/// Every validator it is handed counts as `failed` unless the service
/// resolves it before the batch is dropped. So a call that returns early
/// through `?`, or one the duty loop drops at the slot's deadline, still
/// counts each of its validators once, and a refusal or a failed signature
/// needs no line of its own. With no [`Performance`] it counts nothing.
///
/// A service creates it before its first request to the node, the fetch of
/// the slot's data included: a fetch still out at the end of the slot is the
/// usual way a hung node costs a duty, and the duty loop then drops the call
/// mid-fetch, with nothing after that point left to count it.
pub(crate) struct Batch {
    performance: Option<Arc<Performance>>,
    duty: Duty,
    slot: Slot,
    pending: BTreeSet<ValidatorIndex>,
}

impl Batch {
    pub(crate) fn new(
        performance: Option<&Arc<Performance>>,
        duty: Duty,
        slot: Slot,
        validators: impl IntoIterator<Item = ValidatorIndex>,
    ) -> Self {
        let pending = match performance {
            Some(_) => validators.into_iter().collect(),
            None => BTreeSet::new(),
        };
        Self {
            performance: performance.cloned(),
            duty,
            slot,
            pending,
        }
    }

    /// Count `validator`'s duty as neither published nor failed: one the
    /// service did not take up.
    pub(crate) fn skip(&mut self, validator: ValidatorIndex) {
        self.pending.remove(&validator);
    }

    /// [`Self::skip`] every validator still unresolved: the slot turned out to
    /// hold nothing to do, such as a head nothing may be signed over.
    pub(crate) fn skip_all(&mut self) {
        self.pending.clear();
    }

    /// What the node made of the messages `sent` carried: every one accepted
    /// when `accepted` covers them all, and otherwise `accepted` of them
    /// without saying which, counted under `other` (see the module doc).
    pub(crate) fn submitted(&mut self, sent: &[ValidatorIndex], accepted: usize) {
        let Some(performance) = &self.performance else {
            return;
        };
        for validator in sent {
            self.pending.remove(validator);
        }
        if accepted >= sent.len() {
            for &validator in sent {
                performance.record(self.duty, self.slot, validator, Outcome::Published);
            }
        } else {
            let failed = sent.len() - accepted;
            let (accepted, failed) = (accepted as u64, failed as u64);
            performance.record_unattributed(self.duty, self.slot, sent, accepted, failed);
        }
    }
}

impl Drop for Batch {
    fn drop(&mut self) {
        let Some(performance) = &self.performance else {
            return;
        };
        for validator in std::mem::take(&mut self.pending) {
            performance.record(self.duty, self.slot, validator, Outcome::Failed);
        }
    }
}

/// Ask `beacon_node` whether the block `validator` published at `slot`,
/// `block_root`, is the one its canonical chain holds there, then log and
/// count the answer.
pub async fn check_proposal<B: BeaconNodeApi + ?Sized>(
    beacon_node: &B,
    performance: &Performance,
    slot: Slot,
    validator: ValidatorIndex,
    block_root: Root,
) -> ProposalCheck {
    let block = ShortRoot(&block_root.0);
    let check = match beacon_node.canonical_block_root(slot).await {
        Ok(Some(root)) if root == block_root => {
            info!(%slot, validator, block_root = %block, "Proposed block is canonical");
            ProposalCheck::Canonical
        }
        Ok(Some(root)) => {
            warn!(
                %slot,
                validator,
                block_root = %block,
                canonical_root = %ShortRoot(&root.0),
                "Proposed block is not canonical: another block holds its slot"
            );
            ProposalCheck::Replaced
        }
        Ok(None) => {
            warn!(
                %slot,
                validator,
                block_root = %block,
                "Proposed block is not canonical: the canonical chain has no block at its slot"
            );
            ProposalCheck::Orphaned
        }
        Err(err) => {
            warn!(
                %slot,
                validator,
                block_root = %block,
                %err,
                "Could not check whether the proposed block is canonical"
            );
            ProposalCheck::Unknown
        }
    };
    performance.record_check(validator, check);
    check
}

/// [`check_proposal`], once `at` comes. What the proposal service spawns.
pub(crate) async fn check_proposal_at<B: BeaconNodeApi>(
    beacon_node: Arc<B>,
    performance: Arc<Performance>,
    slot: Slot,
    validator: ValidatorIndex,
    block_root: Root,
    at: SystemTime,
) {
    let wait = at.duration_since(SystemTime::now()).unwrap_or_default();
    tokio::time::sleep(wait).await;
    check_proposal(&*beacon_node, &performance, slot, validator, block_root).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::attestation::AttestationService;
    use crate::beacon_node::dto::{
        AttesterDutyDto, ProposerDutyDto, PtcDutyDto, SyncDutyDto, encode_hex,
    };
    use crate::beacon_node::fallback::FallbackBeaconNode;
    use crate::beacon_node::mock::MockBeaconNode;
    use crate::payload_attestation::PayloadAttestationService;
    use crate::proposal::ProposalService;
    use crate::signing::SigningContext;
    use crate::slashing_protection::SlashingProtection;
    use crate::sync_committee::SyncCommitteeService;
    use crate::test_support::{settings, store_with_keys};
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::containers::gloas::PayloadAttestationData;
    use ethlambda_types::beacon::preset::slots_per_epoch;
    use ethlambda_types::beacon::primitives::BlsPubkey;
    use tokio::sync::RwLock;

    fn context() -> Arc<SigningContext> {
        Arc::new(SigningContext::new(Config::mainnet(), Root::ZERO))
    }

    fn counts(published: u64, failed: u64) -> Counts {
        Counts { published, failed }
    }

    fn attester_duty(pubkey: &BlsPubkey, validator_index: u64, slot: Slot) -> AttesterDutyDto {
        AttesterDutyDto {
            pubkey: encode_hex(&pubkey.0),
            validator_index,
            committee_index: 3,
            committee_length: 128,
            committees_at_slot: 64,
            validator_committee_index: 7,
            slot,
        }
    }

    /// Up to the cap each validator is its own series and its own summary
    /// line; past it they share `other`. A validator keeps the label it got,
    /// however many come after it.
    #[test]
    fn the_first_validators_get_their_own_label_and_the_rest_share_other() {
        let performance = Performance::new(2);
        let slot = 96;
        let epoch = compute_epoch_at_slot(slot);
        for validator in [5, 9, 11, 5, 12] {
            performance.record(Duty::Attestation, slot, validator, Outcome::Published);
        }

        assert_eq!(performance.label(5).as_deref(), Some("5"));
        assert_eq!(performance.label(9).as_deref(), Some("9"));
        assert_eq!(performance.label(11), None);
        assert_eq!(performance.label(12), None);

        let own = performance.tally(epoch, Some(5)).expect("5 is labelled");
        assert_eq!(own.attestations, counts(2, 0));
        assert_eq!(performance.tally(epoch, Some(11)), None);
        let other = performance.tally(epoch, None).expect("the epoch is open");
        assert_eq!(other.attestations, counts(2, 0), "11 and 12, together");

        for validator in 100..200 {
            performance.record(Duty::Attestation, slot, validator, Outcome::Failed);
        }
        assert_eq!(performance.label(9).as_deref(), Some("9"));
        assert_eq!(performance.label(150), None);
    }

    /// The value of `validator`'s child of the series `family` whose other
    /// label is `value`, or `None` when no such child exists.
    fn child(family: &str, validator: &str, value: &str) -> Option<u64> {
        ethlambda_metrics::gather()
            .iter()
            .filter(|found| found.name() == family)
            .flat_map(|found| found.get_metric())
            .find(|metric| {
                let labels = metric.get_label();
                let holds = |name: &str, wanted: &str| {
                    labels
                        .iter()
                        .any(|label| label.name() == name && label.value() == wanted)
                };
                holds("validator", validator) && (holds("outcome", value) || holds("result", value))
            })
            .map(|metric| metric.get_counter().value() as u64)
    }

    /// A validator's children of every series exist at zero from the moment
    /// it takes its label, so its first `failed` or `orphaned` after that is
    /// an increase rather than a new series' starting value. One past the cap
    /// gets none.
    #[test]
    fn a_labelled_validators_series_start_at_zero() {
        // Indices no other test records: the series are process-wide.
        let (labelled, unlabelled) = (987_654, 987_655);
        let performance = Performance::new(1);
        performance.record(Duty::Attestation, 96, labelled, Outcome::Published);
        performance.record(Duty::Attestation, 96, unlabelled, Outcome::Published);

        let (labelled, unlabelled) = (labelled.to_string(), unlabelled.to_string());
        let attestations = "ethlambda_validator_attestation_outcomes_total";
        assert_eq!(child(attestations, &labelled, "published"), Some(1));
        assert_eq!(child(attestations, &labelled, "failed"), Some(0));
        let checks = "ethlambda_validator_proposal_checks_total";
        assert_eq!(child(checks, &labelled, "orphaned"), Some(0));
        assert_eq!(child(attestations, &unlabelled, "published"), None);
        assert_eq!(child(checks, &unlabelled, "orphaned"), None);
    }

    /// A batch counts each validator once: what the service resolved as it
    /// said, what it skipped not at all, and the rest as failed when it is
    /// dropped, which is what a `?` or the duty loop's deadline does to it.
    #[test]
    fn a_dropped_batch_counts_what_it_left_unresolved_as_failed() {
        let performance = Arc::new(Performance::new(LABELLED_VALIDATORS));
        let slot = 96;
        let epoch = compute_epoch_at_slot(slot);

        let validators = [1, 2, 3, 4];
        let mut batch = Batch::new(
            Some(&performance),
            Duty::SyncCommitteeMessage,
            slot,
            validators,
        );
        batch.skip(2);
        batch.submitted(&[4], 1);
        drop(batch);

        let messages = |validator| {
            performance
                .tally(epoch, Some(validator))
                .map(|tally| tally.sync_committee_messages)
        };
        assert_eq!(messages(1), Some(counts(0, 1)));
        assert_eq!(messages(2), None, "skipped: neither published nor failed");
        assert_eq!(messages(3), Some(counts(0, 1)));
        assert_eq!(messages(4), Some(counts(1, 0)));
    }

    /// A batch the node accepted in part names no validator, so its counts go
    /// to `other` and none of its validators is credited with either.
    #[test]
    fn a_batch_accepted_in_part_is_counted_under_other() {
        let performance = Arc::new(Performance::new(LABELLED_VALIDATORS));
        let slot = 96;
        let epoch = compute_epoch_at_slot(slot);

        let mut batch = Batch::new(Some(&performance), Duty::Attestation, slot, [4, 5, 6]);
        batch.submitted(&[4, 5, 6], 2);
        drop(batch);

        for validator in [4, 5, 6] {
            assert_eq!(performance.tally(epoch, Some(validator)), None);
        }
        let other = performance.tally(epoch, None).expect("the epoch is open");
        assert_eq!(other.attestations, counts(2, 1));
    }

    /// Once a later epoch's first outcome arrives, the earlier epoch is
    /// summarized and closed, and an outcome for it that comes after that is
    /// left out of the summary.
    #[test]
    fn an_epoch_is_summarized_once_the_next_one_starts() {
        let performance = Performance::new(LABELLED_VALIDATORS);
        let first = 3 * slots_per_epoch();

        performance.record(Duty::Attestation, first, 1, Outcome::Published);
        assert!(performance.tally(3, Some(1)).is_some());

        let next_epoch = first + slots_per_epoch();
        performance.record(Duty::Proposal, next_epoch, 1, Outcome::Published);
        assert_eq!(performance.tally(3, Some(1)), None, "summarized");
        let next = performance.tally(4, Some(1)).expect("open");
        assert_eq!(next.proposals, counts(1, 0));

        performance.record(Duty::Attestation, first + 5, 2, Outcome::Failed);
        assert_eq!(
            performance.tally(3, Some(2)),
            None,
            "its epoch was summarized"
        );
    }

    /// Through the attestation service and a mock node: a batch the node took
    /// is published for each of its validators, one it refused is failed for
    /// each, and a duty for a key this client no longer holds is neither.
    #[tokio::test]
    async fn attestations_are_counted_per_validator_as_published_or_failed() {
        let (store, pubkeys) = store_with_keys(4);
        let store = RwLock::new(store);
        let performance = Arc::new(Performance::new(LABELLED_VALIDATORS));
        let protection = SlashingProtection::in_memory();
        let epoch = compute_epoch_at_slot(96);

        let up = Arc::new(MockBeaconNode::new().with_attestation_data(96));
        let service = AttestationService::new(up, context(), protection.clone())
            .with_performance(performance.clone());
        let duties = [
            attester_duty(&pubkeys[0], 10, 96),
            attester_duty(&pubkeys[1], 11, 96),
            attester_duty(&BlsPubkey([7; 48]), 14, 96),
        ];
        let attested = service.attest(96, &duties, &store).await.expect("attests");
        assert_eq!(attested.published, 2);

        let down = Arc::new(
            MockBeaconNode::new()
                .with_attestation_data(97)
                .failing_call("submit_attestations", "node down"),
        );
        let service = AttestationService::new(down, context(), protection)
            .with_performance(performance.clone());
        let duties = [
            attester_duty(&pubkeys[2], 12, 97),
            attester_duty(&pubkeys[3], 13, 97),
        ];
        service
            .attest(97, &duties, &store)
            .await
            .expect_err("the submission fails");

        let attestations = |validator| {
            performance
                .tally(epoch, Some(validator))
                .map(|tally| tally.attestations)
        };
        assert_eq!(attestations(10), Some(counts(1, 0)));
        assert_eq!(attestations(11), Some(counts(1, 0)));
        assert_eq!(attestations(12), Some(counts(0, 1)));
        assert_eq!(attestations(13), Some(counts(0, 1)));
        assert_eq!(attestations(14), None, "not held, so not attempted");
    }

    /// Through the sync committee service and the fallback the client always
    /// talks through: a head every node reports optimistic signs nothing and
    /// counts as neither, while every node down counts the member failed.
    #[tokio::test]
    async fn an_optimistic_head_through_the_fallback_is_no_failed_sync_committee_message() {
        let (store, pubkeys) = store_with_keys(1);
        let store = RwLock::new(store);
        let performance = Arc::new(Performance::new(LABELLED_VALIDATORS));
        let slot = 3200;
        let epoch = compute_epoch_at_slot(slot);
        let duties = [SyncDutyDto {
            pubkey: encode_hex(&pubkeys[0].0),
            validator_index: 21,
            validator_sync_committee_indices: vec![3],
        }];
        let service = |node: MockBeaconNode| {
            let fallback = FallbackBeaconNode::new(vec![node]);
            SyncCommitteeService::new(Arc::new(fallback), context())
                .with_performance(performance.clone())
        };

        let mut optimistic = MockBeaconNode::new().with_head_root(Root::repeat_byte(7));
        optimistic.head_optimistic = true;
        let signed_over = service(optimistic)
            .publish_messages(slot, &duties, &store)
            .await
            .expect("not an error");
        assert_eq!(signed_over, None);
        assert_eq!(performance.tally(epoch, Some(21)), None, "neither");

        let down = MockBeaconNode::new().failing_call("head_block_root", "node down");
        service(down)
            .publish_messages(slot, &duties, &store)
            .await
            .expect_err("every node failed");
        let tally = performance.tally(epoch, Some(21)).expect("counted");
        assert_eq!(tally.sync_committee_messages, counts(0, 1));
    }

    /// A node that has not answered the slot's first request when the duty
    /// loop drops the call at the end of the slot, as a hung node does with
    /// its 8 s request timeout: every duty of the three batch services counts
    /// failed, though none got past its fetch.
    #[tokio::test(start_paused = true)]
    async fn a_fetch_still_out_at_the_end_of_the_slot_counts_every_duty_failed() {
        let (store, pubkeys) = store_with_keys(2);
        let store = RwLock::new(store);
        let performance = Arc::new(Performance::new(LABELLED_VALIDATORS));
        let slot = 96;
        let epoch = compute_epoch_at_slot(slot);
        // The node answers long after the slot's end, which comes first.
        let hung = Duration::from_secs(3600);
        let end_of_slot = Duration::from_secs(8);

        let node = MockBeaconNode::new()
            .with_attestation_data(slot)
            .with_first_call_delay("attestation_data", hung);
        let protection = SlashingProtection::in_memory();
        let attestation = AttestationService::new(Arc::new(node), context(), protection)
            .with_performance(performance.clone());
        let duties = [
            attester_duty(&pubkeys[0], 30, slot),
            attester_duty(&pubkeys[1], 31, slot),
        ];
        let attested = attestation.attest(slot, &duties, &store);
        tokio::time::timeout(end_of_slot, attested)
            .await
            .expect_err("cut at the end of the slot");

        let node = MockBeaconNode::new()
            .with_head_root(Root::repeat_byte(7))
            .with_first_call_delay("head_block_root", hung);
        let sync = SyncCommitteeService::new(Arc::new(node), context())
            .with_performance(performance.clone());
        let duties = [SyncDutyDto {
            pubkey: encode_hex(&pubkeys[0].0),
            validator_index: 32,
            validator_sync_committee_indices: vec![3],
        }];
        let published = sync.publish_messages(slot, &duties, &store);
        tokio::time::timeout(end_of_slot, published)
            .await
            .expect_err("cut at the end of the slot");

        let data = PayloadAttestationData {
            beacon_block_root: Root::repeat_byte(7),
            slot,
            payload_present: true,
            blob_data_available: true,
        };
        let node = MockBeaconNode::new()
            .with_payload_attestation_data(data)
            .with_first_call_delay("payload_attestation_data", hung);
        let payload = PayloadAttestationService::new(Arc::new(node), context())
            .with_performance(performance.clone());
        let duties = [PtcDutyDto {
            pubkey: encode_hex(&pubkeys[1].0),
            validator_index: 33,
            slot,
        }];
        let voted = payload.attest(slot, &duties, &store);
        tokio::time::timeout(end_of_slot, voted)
            .await
            .expect_err("cut at the end of the slot");

        let tally = |validator| performance.tally(epoch, Some(validator)).expect("counted");
        assert_eq!(tally(30).attestations, counts(0, 1));
        assert_eq!(tally(31).attestations, counts(0, 1));
        assert_eq!(tally(32).sync_committee_messages, counts(0, 1));
        assert_eq!(tally(33).payload_attestations, counts(0, 1));
    }

    /// A slot the node knows no block for (its 204) is no vote to count,
    /// though the batch is created before the data is fetched.
    #[tokio::test]
    async fn no_block_for_the_slot_counts_no_payload_vote() {
        let (store, pubkeys) = store_with_keys(1);
        let store = RwLock::new(store);
        let performance = Arc::new(Performance::new(LABELLED_VALIDATORS));
        let slot = 96;
        let payload = PayloadAttestationService::new(Arc::new(MockBeaconNode::new()), context())
            .with_performance(performance.clone());
        let duties = [PtcDutyDto {
            pubkey: encode_hex(&pubkeys[0].0),
            validator_index: 34,
            slot,
        }];

        let published = payload
            .attest(slot, &duties, &store)
            .await
            .expect("a 204 is not an error");
        assert_eq!(published, 0);
        let epoch = compute_epoch_at_slot(slot);
        assert_eq!(performance.tally(epoch, Some(34)), None, "neither");
    }

    /// Through the proposal service and a mock node: a block the node took is
    /// published, one it refused is failed, both for the proposer's index.
    #[tokio::test]
    async fn proposals_are_counted_per_validator_as_published_or_failed() {
        let (store, pubkeys) = store_with_keys(1);
        let store = RwLock::new(store);
        let performance = Arc::new(Performance::new(LABELLED_VALIDATORS));
        // Inside electra, the fork the mock's blocks are built for.
        let slot = Config::mainnet().electra_fork_epoch * slots_per_epoch() + 96;
        let duty = |slot| ProposerDutyDto {
            pubkey: encode_hex(&pubkeys[0].0),
            validator_index: 7,
            slot,
        };
        let service = |node: MockBeaconNode| {
            let protection = SlashingProtection::in_memory();
            ProposalService::new(Arc::new(node), context(), settings(None), protection, None)
                .with_performance(performance.clone())
        };

        service(MockBeaconNode::new().with_block(slot, 7))
            .propose(slot, &duty(slot), &store)
            .await
            .expect("proposes");
        let refusing = MockBeaconNode::new()
            .with_block(slot + 1, 7)
            .failing_call("publish_block", "node down");
        service(refusing)
            .propose(slot + 1, &duty(slot + 1), &store)
            .await
            .expect_err("the publish fails");

        let tally = performance
            .tally(compute_epoch_at_slot(slot), Some(7))
            .expect("7 proposed");
        assert_eq!(tally.proposals, counts(1, 1));
        assert_eq!(tally.attestations, counts(0, 0));
    }

    /// The check reads the node's canonical block at the slot: this block is
    /// canonical, another is a replacement, none is an orphan, and no answer
    /// is unknown rather than any of those.
    #[tokio::test]
    async fn the_proposal_check_compares_the_canonical_block_at_the_slot() {
        let performance = Performance::new(LABELLED_VALIDATORS);
        let ours = Root::from([1; 32]);
        let node = MockBeaconNode::new()
            .with_canonical_block(100, ours)
            .with_canonical_block(101, Root::from([2; 32]));

        let check = |slot| check_proposal(&node, &performance, slot, 7, ours);
        assert_eq!(check(100).await, ProposalCheck::Canonical);
        assert_eq!(check(101).await, ProposalCheck::Replaced);
        assert_eq!(check(102).await, ProposalCheck::Orphaned);

        let down = MockBeaconNode::new()
            .with_canonical_block(100, ours)
            .failing_call("canonical_block_root", "node down");
        let check = check_proposal(&down, &performance, 100, 7, ours).await;
        assert_eq!(check, ProposalCheck::Unknown);
    }
}
