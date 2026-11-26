//! Signing when the slot's block arrives, not only at the clock's deadline.
//!
//! # What the specification asks
//!
//! An attester signs "when either (a) the validator has received a valid
//! block from the expected block proposer for the assigned `slot` or (b)
//! `get_attestation_due_ms()` milliseconds has transpired since the start of
//! the slot -- whichever comes first" (phase0 `validator.md`; gloas moves only
//! the deadline). A sync committee member signs its message on the same two
//! conditions, against its own deadline (altair `validator.md`). A payload
//! timeliness committee member votes "as soon as it has seen the execution
//! payload envelope and blob data for the block, and no later than
//! `get_payload_attestation_due_ms()`" (gloas `validator.md`), and may vote
//! `blob_data_available = False` only once that deadline has passed.
//!
//! The clock alone answers (b). This module answers (a), from the beacon
//! nodes' event streams ([`crate::beacon_node::events`]), so a vote leaves
//! when its block does, and the aggregators publishing at
//! `AGGREGATE_DUE_BPS` (`CONTRIBUTION_DUE_BPS`, and the next proposer, for
//! the other two) have that much longer to receive it.
//!
//! # The triggers
//!
//! - **Attestation and sync committee message:** a `head` event whose slot is
//!   the duty's, and whose head the execution client has validated
//!   (`execution_optimistic` false). `head` rather than `block`: the data a
//!   vote signs names the node's head, and a block imported but not made head
//!   (a late one fork choice passes over) would only give data for its parent.
//!   It is also the event that says whether the head is optimistic.
//!   Lighthouse, Teku, Prysm, Lodestar and Vouch wake on `head` as well.
//! - **Payload timeliness committee vote:** an `execution_payload_available`
//!   event for the slot, read only when the network schedules gloas. Never
//!   the `head`: the block alone is not what the vote is about. On an
//!   ethlambda node the event follows the envelope's import, which waits for
//!   the payload to verify and for every sampled column of its blobs, so it
//!   means the blob data too.
//!
//! # The node's answer has to bear the event out
//!
//! An event only says when to ask. What is signed is still what the node
//! answers, through `FallbackBeaconNode` as at the deadline, and the early
//! attempt signs it only when it is about the event's block:
//!
//! - attestation data whose `beacon_block_root` is the event's block;
//! - a head root that is the event's block;
//! - payload attestation data for the event's block that says both
//!   `payload_present` and `blob_data_available`. An early vote is therefore
//!   always one that saw both.
//!
//! Anything else (another root, a failed request, a 204, a payload not called
//! present, or an answer still outstanding at the deadline, which is dropped
//! there) is a `mismatch`: nothing was recorded and nothing signed. The duty
//! then waits for the next report about the slot that it has not tried
//! (another node's, or another block's), and asks again on it; with none
//! before the deadline it runs at the deadline, exactly as it would have with
//! no event. That is what keeps one signature per duty per slot: another
//! attempt follows only ones that stopped before recording anything, and an
//! attempt that got as far as recording is final for the slot whatever became
//! of it, as [`AttestationService::attest`]'s rule against retrying requires.
//! And no early request outlives the deadline, so an event can make a duty
//! earlier but never later.
//!
//! # Every node's stream
//!
//! Each configured beacon node's stream is read, not only the first's, so
//! the early trigger survives the first node being down. An event from any of
//! them wakes the duty, the first node's report preferred when several are
//! new. The check above is what makes reading all of them safe: when the node
//! that answers has not imported the event's block yet, its answer names the
//! parent (or there is none) and that attempt declines. Its own report of the
//! block, when it comes, is a new one, so the duty asks again then, and only
//! the deadline is left if it never comes in time.
//!
//! # The clock stays the deadline
//!
//! A stream is best-effort (see [`crate::beacon_node::events`]). One that is
//! down, or has said nothing about the slot, leaves each duty to its clock
//! offset, as before this module. Each stream reopens on its own with backoff,
//! and once every reader is gone a duty waits for its deadline, never fires
//! for want of one. `--disable-event-stream` reads no stream at all.
//!
//! # Not here
//!
//! - No wait after the block. Vouch waits 500 ms and Nimbus half the
//!   attestation offset before attesting; Lodestar's default, like this, is
//!   none. The block has reached the node by the time it is head there, and
//!   anything later only shortens what the vote has to reach the aggregators.
//! - Aggregation and sync contributions keep their own offsets: they fold
//!   other validators' votes, which arrive on the clock.
//! - The `head` event's dependent roots are not read. Fetching duties again
//!   when one changes is a separate change.

use std::sync::Arc;
use std::time::Duration;

use ethlambda_types::ShortRoot;
use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::constants::FAR_FUTURE_EPOCH;
use ethlambda_types::beacon::primitives::{Root, Slot};
use tokio::sync::{RwLock, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::attestation::{AttestationService, Attested};
use crate::beacon_node::BeaconNodeApi;
use crate::beacon_node::dto::{AttesterDutyDto, PtcDutyDto, SyncDutyDto};
use crate::beacon_node::events::{EventSource, HttpEventSource, NodeEvent, Topic, is_idle_timeout};
use crate::error::Result;
use crate::keys::ValidatorStore;
use crate::metrics;
use crate::payload_attestation::PayloadAttestationService;
use crate::sync_committee::SyncCommitteeService;

/// The first wait before a stream is opened again.
const RECONNECT_MIN: Duration = Duration::from_secs(1);

/// The longest wait before a stream is opened again, which the wait doubles
/// up to while a node stays unreachable.
///
/// About a mainnet slot, so a node that comes back costs at most a slot or so
/// of early votes, and one that stays down costs a request every twelve
/// seconds. A stream that delivered an event, or stayed open this long, is
/// opened again after [`RECONNECT_MIN`].
const RECONNECT_MAX: Duration = Duration::from_secs(12);

/// A duty an event can start early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Duty {
    Attestation,
    SyncCommitteeMessage,
    PayloadAttestation,
}

impl Duty {
    pub const ALL: [Duty; 3] = [
        Duty::Attestation,
        Duty::SyncCommitteeMessage,
        Duty::PayloadAttestation,
    ];

    /// The `duty` label of `ethlambda_validator_duty_triggers_total`.
    pub fn as_str(self) -> &'static str {
        match self {
            Duty::Attestation => "attestation",
            Duty::SyncCommitteeMessage => "sync_committee_message",
            Duty::PayloadAttestation => "payload_attestation",
        }
    }
}

/// What started one slot's duty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fired {
    /// A node's event for the slot, borne out by the node's answer.
    Event,
    /// The clock's offset, with no event for the slot before it.
    Deadline,
    /// The clock's offset, after an event the node's answer did not bear out.
    Mismatch,
}

impl Fired {
    pub const ALL: [Fired; 3] = [Fired::Event, Fired::Deadline, Fired::Mismatch];

    /// The `trigger` label of `ethlambda_validator_duty_triggers_total`.
    pub fn as_str(self) -> &'static str {
        match self {
            Fired::Event => "event",
            Fired::Deadline => "deadline",
            Fired::Mismatch => "mismatch",
        }
    }
}

/// A block one node reported on one topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Reported {
    slot: Slot,
    root: Root,
}

/// What each node last reported on one topic, by its position in
/// `--beacon-nodes`.
type Reports = Vec<Option<Reported>>;

/// The readers of every node's streams. Dropping it stops them.
pub struct HeadMonitor {
    readers: Vec<JoinHandle<()>>,
}

impl Drop for HeadMonitor {
    fn drop(&mut self) {
        for reader in &self.readers {
            reader.abort();
        }
    }
}

/// Read every beacon node's event stream, or none with `enabled` off.
///
/// `config` is the chain's, from the node's `/eth/v1/config/spec`: a network
/// that schedules gloas also gets the `execution_payload_available` streams.
/// The monitor, when there is one, must be kept for as long as the triggers
/// are used; the triggers outlive it safely, as deadlines alone.
pub fn start(
    beacon_nodes: &[String],
    config: &Config,
    enabled: bool,
) -> Result<(Option<HeadMonitor>, DutyTriggers)> {
    if !enabled {
        info!(
            "Event stream off (--disable-event-stream): attestations, sync committee messages and \
             payload votes wait for their deadlines"
        );
        return Ok((None, DutyTriggers::off()));
    }
    let sources = beacon_nodes
        .iter()
        .map(|url| {
            let source = HttpEventSource::new(url)?;
            let name = source.name().to_string();
            Ok((name, Arc::new(source) as Arc<dyn EventSource>))
        })
        .collect::<Result<Vec<_>>>()?;
    let payloads = config.gloas_fork_epoch != FAR_FUTURE_EPOCH;
    let (monitor, triggers) = HeadMonitor::spawn(sources, payloads);
    Ok((Some(monitor), triggers))
}

impl HeadMonitor {
    /// One reader for each source's `head` stream, and with `payloads` one
    /// for its `execution_payload_available` stream as well.
    ///
    /// A connection per topic rather than one for both: a node that refuses
    /// the gloas topic (one that predates it) then costs the payload trigger
    /// alone, not the head's.
    pub fn spawn(
        sources: Vec<(String, Arc<dyn EventSource>)>,
        payloads: bool,
    ) -> (Self, DutyTriggers) {
        let (heads, head_reports) = watch::channel(vec![None; sources.len()]);
        let (payloads_seen, payload_reports) = watch::channel(vec![None; sources.len()]);
        let mut readers = Vec::new();
        for (position, (name, source)) in sources.into_iter().enumerate() {
            let reader = follow(
                name.clone(),
                source.clone(),
                Topic::Head,
                heads.clone(),
                position,
            );
            readers.push(tokio::spawn(reader));
            if payloads {
                let topic = Topic::ExecutionPayloadAvailable;
                let reader = follow(name, source, topic, payloads_seen.clone(), position);
                readers.push(tokio::spawn(reader));
            }
        }
        let triggers = DutyTriggers {
            heads: Some(head_reports),
            payloads: payloads.then_some(payload_reports),
        };
        (Self { readers }, triggers)
    }
}

/// Read `source`'s `topic` stream into `reports[position]` for the life of
/// the process, opening it again whenever it ends.
async fn follow(
    name: String,
    source: Arc<dyn EventSource>,
    topic: Topic,
    reports: watch::Sender<Reports>,
    position: usize,
) {
    let mut backoff = RECONNECT_MIN;
    // Failures to open in a row, so a node that stays down warns once.
    let mut refused: u32 = 0;
    // Streams in a row that broke or closed before delivering an event, so a
    // node that keeps handing out streams that end at once warns once too.
    let mut fruitless: u32 = 0;
    // The last stream went quiet rather than broke, so opening it again is
    // routine: a stream silent by design, on a node that sends no
    // keep-alives, does it every `IDLE_TIMEOUT`.
    let mut went_quiet = false;
    loop {
        match source.subscribe(&[topic]).await {
            Ok(mut stream) => {
                if went_quiet || fruitless > 1 {
                    debug!(node = %name, topic = topic.as_str(), "Event stream reopened");
                } else {
                    info!(node = %name, topic = topic.as_str(), "Reading the beacon node's event stream");
                }
                refused = 0;
                let open = metrics::OpenEventStream::count();
                let opened = Instant::now();
                let mut delivered = false;
                let broken = loop {
                    match stream.next_event().await {
                        Ok(Some(event)) => {
                            delivered = true;
                            note(&reports, position, topic, event);
                        }
                        Ok(None) => break None,
                        Err(err) => break Some(err),
                    }
                };
                drop(open);
                went_quiet = broken.as_ref().is_some_and(is_idle_timeout);
                fruitless = if delivered || went_quiet {
                    0
                } else {
                    fruitless + 1
                };
                match broken {
                    Some(err) if went_quiet => debug!(
                        node = %name,
                        topic = topic.as_str(),
                        %err,
                        "Event stream went quiet; opening it again"
                    ),
                    Some(err) if fruitless > 1 => debug!(
                        node = %name,
                        topic = topic.as_str(),
                        %err,
                        fruitless,
                        "Event stream broke again before delivering an event"
                    ),
                    None if fruitless > 1 => debug!(
                        node = %name,
                        topic = topic.as_str(),
                        fruitless,
                        "Event stream closed again before delivering an event"
                    ),
                    Some(err) => warn!(
                        node = %name,
                        topic = topic.as_str(),
                        %err,
                        "Beacon node event stream broke; opening it again"
                    ),
                    None => warn!(
                        node = %name,
                        topic = topic.as_str(),
                        "Beacon node closed its event stream; opening it again"
                    ),
                }
                if delivered || opened.elapsed() >= RECONNECT_MAX {
                    backoff = RECONNECT_MIN;
                }
            }
            Err(err) => {
                refused += 1;
                went_quiet = false;
                if refused == 1 {
                    warn!(
                        node = %name,
                        topic = topic.as_str(),
                        %err,
                        "Cannot open the beacon node's event stream; its duties wait for their \
                         deadlines until it opens"
                    );
                } else {
                    debug!(node = %name, topic = topic.as_str(), %err, refused, "Event stream still unavailable");
                }
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RECONNECT_MAX);
    }
}

/// Record `event`, read from `topic`'s stream of the node at `position`.
///
/// A node's report only moves forward: one about an earlier slot than it
/// last reported is not kept, so a reorg back to an older head cannot take
/// back a block already seen for the slot. That is harmless, since the
/// node's own answer is checked before anything is signed. An optimistic
/// head is not a block received in the sense the specification means, and
/// is not kept either.
fn note(reports: &watch::Sender<Reports>, position: usize, topic: Topic, event: NodeEvent) {
    let reported = match (topic, event) {
        (Topic::Head, NodeEvent::Head(head)) => {
            if head.execution_optimistic {
                debug!(
                    slot = head.slot,
                    "Head is optimistic; not a reason to sign early"
                );
                return;
            }
            Reported {
                slot: head.slot,
                root: head.block,
            }
        }
        (Topic::ExecutionPayloadAvailable, NodeEvent::PayloadAvailable(payload)) => Reported {
            slot: payload.slot,
            root: payload.block_root,
        },
        // Not what this stream was opened for.
        _ => return,
    };
    reports.send_if_modified(|reports| match reports.get_mut(position) {
        Some(held) if held.is_none_or(|last| last.slot <= reported.slot && last != reported) => {
            *held = Some(reported);
            true
        }
        _ => false,
    });
}

/// When each early-capable duty may start: the earlier of its clock offset
/// and the event that answers the specification's condition (a). Cheap to
/// clone.
///
/// [`Self::off`] has no events, so every wait is the deadline alone.
#[derive(Debug, Clone, Default)]
pub struct DutyTriggers {
    heads: Option<watch::Receiver<Reports>>,
    payloads: Option<watch::Receiver<Reports>>,
}

impl DutyTriggers {
    /// Triggers that only ever wait for the deadline.
    pub fn off() -> Self {
        Self::default()
    }

    /// Wait at most `wait` for a node to report a head at `slot`, or its
    /// payload available, and answer the reported block, or `None` once
    /// `wait` has passed.
    ///
    /// What the duty loop sleeps on between a slot's proposal and the rest of
    /// its duties, so no early trigger is held back by that sleep. A payload
    /// report ends it too: with a node's head stream down and its payload
    /// stream up, the committee vote then starts on the payload rather than
    /// at the first duty's offset.
    pub async fn report_within(&self, slot: Slot, wait: Duration) -> Option<Root> {
        let deadline = Instant::now() + wait;
        let mut heads = SlotReports::new(self.heads.clone(), slot, deadline);
        let mut payloads = SlotReports::new(self.payloads.clone(), slot, deadline);
        // Each answers `None` only at the deadline, so the first to finish is
        // either a report or the deadline itself.
        tokio::select! {
            block = heads.next() => block,
            block = payloads.next() => block,
        }
    }

    /// Attest for `slot` when a node reports the slot's block as its head, or
    /// once `wait` (the attestation offset, from now) has passed, whichever
    /// comes first; one attempt at most signs. See the module doc.
    pub async fn attest<B: BeaconNodeApi>(
        &self,
        service: &AttestationService<B>,
        slot: Slot,
        wait: Duration,
        duties: &[AttesterDutyDto],
        store: &RwLock<ValidatorStore>,
    ) -> Result<Attested> {
        self.attest_traced(service, slot, wait, duties, store)
            .await
            .1
    }

    /// [`Self::attest`], also saying what started it.
    async fn attest_traced<B: BeaconNodeApi>(
        &self,
        service: &AttestationService<B>,
        slot: Slot,
        wait: Duration,
        duties: &[AttesterDutyDto],
        store: &RwLock<ValidatorStore>,
    ) -> (Fired, Result<Attested>) {
        let deadline = Instant::now() + wait;
        let mut reports = SlotReports::new(self.heads.clone(), slot, deadline);
        let mut fired = Fired::Deadline;
        while let Some(block) = reports.next().await {
            // Bounded by the deadline, so an early request still out then
            // never delays the deadline attempt (see the module doc).
            let early = service.attestation_data(slot);
            let Ok(fetched) = tokio::time::timeout_at(deadline, early).await else {
                debug!(%slot, "Attestation data still outstanding at the deadline; attesting at the deadline instead");
                fired = Fired::Mismatch;
                continue;
            };
            match fetched {
                Ok(data) if data.beacon_block_root == block => {
                    debug!(%slot, block = %ShortRoot(&block.0), "Slot's block is the head; attesting now");
                    metrics::inc_duty_trigger(Duty::Attestation, Fired::Event);
                    let attested = service.attest_with(slot, duties, store, data).await;
                    return (Fired::Event, attested);
                }
                Ok(data) => debug!(
                    %slot,
                    event_block = %ShortRoot(&block.0),
                    data_block = %ShortRoot(&data.beacon_block_root.0),
                    "Attestation data names another block than the head event; waiting for the next report or the deadline"
                ),
                Err(err) => debug!(
                    %slot,
                    %err,
                    "No attestation data on the head event; waiting for the next report or the deadline"
                ),
            }
            fired = Fired::Mismatch;
        }
        metrics::inc_duty_trigger(Duty::Attestation, fired);
        tokio::time::sleep_until(deadline).await;
        (fired, service.attest(slot, duties, store).await)
    }

    /// Sign `slot`'s sync committee messages when a node reports the slot's
    /// block as its head, or once `wait` (the sync message offset, from now)
    /// has passed, whichever comes first; one attempt at most signs. See the
    /// module doc.
    pub async fn publish_sync_messages<B: BeaconNodeApi>(
        &self,
        service: &SyncCommitteeService<B>,
        slot: Slot,
        wait: Duration,
        duties: &[SyncDutyDto],
        store: &RwLock<ValidatorStore>,
    ) -> Result<Option<Root>> {
        self.sync_traced(service, slot, wait, duties, store).await.1
    }

    /// [`Self::publish_sync_messages`], also saying what started it.
    async fn sync_traced<B: BeaconNodeApi>(
        &self,
        service: &SyncCommitteeService<B>,
        slot: Slot,
        wait: Duration,
        duties: &[SyncDutyDto],
        store: &RwLock<ValidatorStore>,
    ) -> (Fired, Result<Option<Root>>) {
        let deadline = Instant::now() + wait;
        let mut reports = SlotReports::new(self.heads.clone(), slot, deadline);
        let mut fired = Fired::Deadline;
        while let Some(block) = reports.next().await {
            let early = service.head_block_root();
            let Ok(fetched) = tokio::time::timeout_at(deadline, early).await else {
                debug!(%slot, "Head root still outstanding at the deadline; signing at the deadline instead");
                fired = Fired::Mismatch;
                continue;
            };
            match fetched {
                Ok(root) if root == block => {
                    debug!(%slot, block = %ShortRoot(&block.0), "Slot's block is the head; signing sync committee messages now");
                    metrics::inc_duty_trigger(Duty::SyncCommitteeMessage, Fired::Event);
                    let published = service
                        .publish_messages_over(slot, duties, store, root)
                        .await;
                    return (Fired::Event, published);
                }
                Ok(root) => debug!(
                    %slot,
                    event_block = %ShortRoot(&block.0),
                    head = %ShortRoot(&root.0),
                    "Head root is another block than the head event; waiting for the next report or the deadline"
                ),
                Err(err) => debug!(
                    %slot,
                    %err,
                    "No head root on the head event; waiting for the next report or the deadline"
                ),
            }
            fired = Fired::Mismatch;
        }
        metrics::inc_duty_trigger(Duty::SyncCommitteeMessage, fired);
        tokio::time::sleep_until(deadline).await;
        (fired, service.publish_messages(slot, duties, store).await)
    }

    /// Cast `slot`'s payload timeliness committee votes when a node reports
    /// the slot's payload and its blob data available, or once `wait` (the
    /// payload attestation offset, from now) has passed, whichever comes
    /// first; one attempt at most signs. The block alone never starts it.
    /// See the module doc.
    pub async fn attest_payload<B: BeaconNodeApi>(
        &self,
        service: &PayloadAttestationService<B>,
        slot: Slot,
        wait: Duration,
        committee: &[PtcDutyDto],
        store: &RwLock<ValidatorStore>,
    ) -> Result<usize> {
        self.payload_traced(service, slot, wait, committee, store)
            .await
            .1
    }

    /// [`Self::attest_payload`], also saying what started it.
    async fn payload_traced<B: BeaconNodeApi>(
        &self,
        service: &PayloadAttestationService<B>,
        slot: Slot,
        wait: Duration,
        committee: &[PtcDutyDto],
        store: &RwLock<ValidatorStore>,
    ) -> (Fired, Result<usize>) {
        let deadline = Instant::now() + wait;
        let mut reports = SlotReports::new(self.payloads.clone(), slot, deadline);
        let mut fired = Fired::Deadline;
        while let Some(block) = reports.next().await {
            let early = service.data(slot);
            let Ok(fetched) = tokio::time::timeout_at(deadline, early).await else {
                debug!(%slot, "Payload attestation data still outstanding at the deadline; voting at the deadline instead");
                fired = Fired::Mismatch;
                continue;
            };
            match fetched {
                Ok(Some(data))
                    if data.beacon_block_root == block
                        && data.payload_present
                        && data.blob_data_available =>
                {
                    debug!(%slot, block = %ShortRoot(&block.0), "Slot's payload is available; voting now");
                    metrics::inc_duty_trigger(Duty::PayloadAttestation, Fired::Event);
                    let voted = service.attest_with(slot, committee, store, data).await;
                    return (Fired::Event, voted);
                }
                Ok(Some(data)) => debug!(
                    %slot,
                    event_block = %ShortRoot(&block.0),
                    data_block = %ShortRoot(&data.beacon_block_root.0),
                    payload_present = data.payload_present,
                    blob_data_available = data.blob_data_available,
                    "Payload attestation data does not bear out the payload event; waiting for the next report or the deadline"
                ),
                Ok(None) => debug!(
                    %slot,
                    "No block known for the payload event's slot; waiting for the next report or the deadline"
                ),
                Err(err) => debug!(
                    %slot,
                    %err,
                    "No payload attestation data on the payload event; waiting for the next report or the deadline"
                ),
            }
            fired = Fired::Mismatch;
        }
        metrics::inc_duty_trigger(Duty::PayloadAttestation, fired);
        tokio::time::sleep_until(deadline).await;
        (fired, service.attest(slot, committee, store).await)
    }
}

/// One duty's view of a topic's reports about its slot, until its deadline.
struct SlotReports {
    /// `None` when the triggers are off.
    receiver: Option<watch::Receiver<Reports>>,
    slot: Slot,
    deadline: Instant,
    /// The reports already handed out, as (node position, block), so each
    /// starts at most one attempt.
    tried: Vec<(usize, Root)>,
}

impl SlotReports {
    fn new(receiver: Option<watch::Receiver<Reports>>, slot: Slot, deadline: Instant) -> Self {
        Self {
            receiver,
            slot,
            deadline,
            tried: Vec::new(),
        }
    }

    /// The block of the next report about the slot not handed out before,
    /// as soon as a node makes one, the first node's when several are new;
    /// `None` at the deadline.
    ///
    /// A report the node's answer did not bear out is not handed out again,
    /// but a later one is: the answering node's own report of the block,
    /// arriving after another node's, or a node's report of another block at
    /// the slot. So an early attempt declined because the answering node had
    /// not imported the block yet is made again once it has.
    ///
    /// With no reports to read (the triggers are off), or once every reader is
    /// gone, this is the deadline alone: a stream that no longer exists never
    /// starts a duty early.
    async fn next(&mut self) -> Option<Root> {
        let Self {
            receiver,
            slot,
            deadline,
            tried,
        } = self;
        let Some(receiver) = receiver.as_mut() else {
            tokio::time::sleep_until(*deadline).await;
            return None;
        };
        // At or past the deadline the clock has already answered, and an event
        // would only add a request before the attempt that is due anyway.
        if Instant::now() >= *deadline {
            return None;
        }
        let slot = *slot;
        let handed_out: &[(usize, Root)] = &tried[..];
        let reported = receiver.wait_for(|reports| untried(reports, slot, handed_out).is_some());
        // The answer is copied out of the channel's guard in the same statement,
        // so the guard is never held across an await.
        let seen = tokio::time::timeout_at(*deadline, reported)
            .await
            .map(|seen| seen.map(|reports| untried(&reports, slot, handed_out)));
        match seen {
            Ok(Ok(Some((position, block)))) => {
                tried.push((position, block));
                Some(block)
            }
            // Every reader is gone: only the clock is left.
            Ok(Err(_)) => {
                tokio::time::sleep_until(*deadline).await;
                None
            }
            // The deadline. (`wait_for` returns only once a report is new, so
            // a `None` there cannot happen; if it did, the deadline attempt
            // is the safe answer.)
            Ok(Ok(None)) | Err(_) => None,
        }
    }
}

/// The first node's report about `slot` that is not in `tried`, with the
/// node's position.
fn untried(reports: &Reports, slot: Slot, tried: &[(usize, Root)]) -> Option<(usize, Root)> {
    reports.iter().enumerate().find_map(|(position, reported)| {
        reported
            .filter(|reported| reported.slot == slot && !tried.contains(&(position, reported.root)))
            .map(|reported| (position, reported.root))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon_node::dto::encode_hex;
    use crate::beacon_node::events::{HeadEvent, PayloadAvailableEvent};
    use crate::beacon_node::mock::{MockBeaconNode, StreamEnd, StreamStep};
    use crate::signing::SigningContext;
    use crate::slashing_protection::SlashingProtection;
    use crate::test_support::store_with_keys;
    use ethlambda_types::beacon::containers::gloas::PayloadAttestationData;
    use ethlambda_types::beacon::fork::ForkName;
    use ethlambda_types::beacon::preset::slots_per_epoch;
    use ethlambda_types::beacon::primitives::BlsPubkey;

    /// The attestation and sync committee tests' slot, in epoch 3.
    const SLOT: Slot = 96;
    /// How long each duty is given before its deadline.
    const WAIT: Duration = Duration::from_secs(4);

    fn block() -> Root {
        Root::repeat_byte(0xb1)
    }

    fn other_block() -> Root {
        Root::repeat_byte(0xb2)
    }

    fn after(millis: u64) -> StreamStep {
        StreamStep::Wait(Duration::from_millis(millis))
    }

    fn head(slot: Slot, block: Root) -> StreamStep {
        StreamStep::Event(NodeEvent::Head(HeadEvent {
            slot,
            block,
            execution_optimistic: false,
        }))
    }

    fn optimistic_head(slot: Slot, block: Root) -> StreamStep {
        StreamStep::Event(NodeEvent::Head(HeadEvent {
            slot,
            block,
            execution_optimistic: true,
        }))
    }

    fn payload(slot: Slot, block_root: Root) -> StreamStep {
        StreamStep::Event(NodeEvent::PayloadAvailable(PayloadAvailableEvent {
            slot,
            block_root,
        }))
    }

    /// The triggers for `nodes`' scripted streams, in order.
    fn read_streams(nodes: &[Arc<MockBeaconNode>], payloads: bool) -> (HeadMonitor, DutyTriggers) {
        let sources = nodes
            .iter()
            .map(|node| ("mock".to_string(), node.clone() as Arc<dyn EventSource>))
            .collect();
        HeadMonitor::spawn(sources, payloads)
    }

    fn key() -> (RwLock<ValidatorStore>, BlsPubkey) {
        let (store, pubkeys) = store_with_keys(1);
        (RwLock::new(store), pubkeys[0])
    }

    // Attestations.

    /// A node whose attestation data for [`SLOT`] names `root`.
    fn attesting(root: Root) -> MockBeaconNode {
        MockBeaconNode::new()
            .with_attestation_data(SLOT)
            .with_attestation_block_root(root)
    }

    fn attester_duty(pubkey: &BlsPubkey) -> AttesterDutyDto {
        AttesterDutyDto {
            pubkey: encode_hex(&pubkey.0),
            validator_index: 1,
            committee_index: 0,
            committee_length: 128,
            committees_at_slot: 1,
            validator_committee_index: 0,
            slot: SLOT,
        }
    }

    fn attestation_service(node: &Arc<MockBeaconNode>) -> AttestationService<MockBeaconNode> {
        let context = SigningContext::new(Config::mainnet(), Root::ZERO);
        AttestationService::new(
            node.clone(),
            Arc::new(context),
            SlashingProtection::in_memory(),
        )
    }

    /// Attest for [`SLOT`] through `triggers`, answering what started it and
    /// how long that took.
    async fn attest(
        triggers: &DutyTriggers,
        node: &Arc<MockBeaconNode>,
    ) -> (Fired, Attested, Duration) {
        let (store, pubkey) = key();
        let service = attestation_service(node);
        let started = Instant::now();
        let (fired, attested) = triggers
            .attest_traced(&service, SLOT, WAIT, &[attester_duty(&pubkey)], &store)
            .await;
        (fired, attested.expect("attests"), started.elapsed())
    }

    /// The head event for the slot starts the attestation then, a second in,
    /// not at the deadline, and nothing asks or signs again after it.
    #[tokio::test(start_paused = true)]
    async fn a_head_event_for_the_slot_attests_then_and_only_once() {
        let node = Arc::new(
            attesting(block())
                .with_event_stream(vec![after(1_000), head(SLOT, block())], StreamEnd::Hang),
        );
        let (_monitor, triggers) = read_streams(std::slice::from_ref(&node), false);

        let (fired, attested, took) = attest(&triggers, &node).await;
        assert_eq!(fired, Fired::Event);
        assert_eq!(attested.published, 1);
        assert!(
            took < WAIT,
            "attested {took:?} in, the deadline is {WAIT:?}"
        );

        tokio::time::sleep(WAIT * 2).await;
        assert_eq!(node.attestation_data_call_count(), 1);
        assert_eq!(node.submitted().len(), 1);
    }

    /// With nothing on the stream, the clock alone starts the duty.
    #[tokio::test(start_paused = true)]
    async fn no_event_attests_at_the_deadline() {
        let node = Arc::new(attesting(block()).with_event_stream(Vec::new(), StreamEnd::Hang));
        let (_monitor, triggers) = read_streams(std::slice::from_ref(&node), false);

        let (fired, attested, took) = attest(&triggers, &node).await;
        assert_eq!(fired, Fired::Deadline);
        assert_eq!(attested.published, 1);
        assert!(took >= WAIT, "attested {took:?} in, before the deadline");
        assert_eq!(node.attestation_data_call_count(), 1);
    }

    /// With the stream off, likewise.
    #[tokio::test(start_paused = true)]
    async fn with_the_stream_off_every_duty_waits_for_its_deadline() {
        let node = Arc::new(attesting(block()));

        let (fired, attested, took) = attest(&DutyTriggers::off(), &node).await;
        assert_eq!(fired, Fired::Deadline);
        assert_eq!(attested.published, 1);
        assert!(took >= WAIT);
        assert!(node.event_subscriptions().is_empty());
    }

    /// A head for the slot before, or the one after, is not this slot's
    /// block arriving.
    #[tokio::test(start_paused = true)]
    async fn a_head_event_for_another_slot_does_not_attest() {
        let node = Arc::new(attesting(block()).with_event_stream(
            vec![
                after(500),
                head(SLOT - 1, block()),
                after(500),
                head(SLOT + 1, block()),
            ],
            StreamEnd::Hang,
        ));
        let (_monitor, triggers) = read_streams(std::slice::from_ref(&node), false);

        let (fired, _, took) = attest(&triggers, &node).await;
        assert_eq!(fired, Fired::Deadline);
        assert!(took >= WAIT);
        assert_eq!(node.attestation_data_call_count(), 1);
    }

    /// A head the execution client has not validated is not a block received.
    #[tokio::test(start_paused = true)]
    async fn an_optimistic_head_does_not_attest() {
        let node = Arc::new(attesting(block()).with_event_stream(
            vec![after(1_000), optimistic_head(SLOT, block())],
            StreamEnd::Hang,
        ));
        let (_monitor, triggers) = read_streams(std::slice::from_ref(&node), false);

        let (fired, _, took) = attest(&triggers, &node).await;
        assert_eq!(fired, Fired::Deadline);
        assert!(took >= WAIT);
    }

    /// The node's data names another block than the event's: nothing is
    /// signed on the event, and the deadline attempt signs once.
    #[tokio::test(start_paused = true)]
    async fn data_for_another_block_waits_for_the_deadline() {
        let node = Arc::new(
            attesting(other_block())
                .with_event_stream(vec![after(1_000), head(SLOT, block())], StreamEnd::Hang),
        );
        let (_monitor, triggers) = read_streams(std::slice::from_ref(&node), false);

        let (fired, attested, took) = attest(&triggers, &node).await;
        assert_eq!(fired, Fired::Mismatch);
        assert!(took >= WAIT, "the mismatch must wait for the deadline");
        assert_eq!(attested.published, 1);
        assert_eq!(
            node.attestation_data_call_count(),
            2,
            "asked on the event and at the deadline"
        );
        assert_eq!(node.submitted().len(), 1, "signed once, at the deadline");
    }

    /// An event that comes once the deadline attempt has started changes
    /// nothing: the duty is not attempted again.
    #[tokio::test(start_paused = true)]
    async fn an_event_after_the_deadline_signs_nothing_twice() {
        let late = WAIT.as_millis() as u64 + 1_000;
        let node = Arc::new(
            attesting(block())
                .with_event_stream(vec![after(late), head(SLOT, block())], StreamEnd::Hang),
        );
        let (_monitor, triggers) = read_streams(std::slice::from_ref(&node), false);

        let (fired, _, _) = attest(&triggers, &node).await;
        assert_eq!(fired, Fired::Deadline);
        tokio::time::sleep(WAIT * 2).await;
        assert_eq!(node.attestation_data_call_count(), 1);
        assert_eq!(node.submitted().len(), 1);
    }

    /// A stream that breaks mid-slot, with the node then unreachable, costs
    /// the early trigger and nothing else.
    #[tokio::test(start_paused = true)]
    async fn a_stream_dropped_mid_slot_still_attests_at_the_deadline() {
        let node = Arc::new(attesting(block()).with_event_stream(
            vec![after(500), head(SLOT - 1, block()), after(500)],
            StreamEnd::Fail,
        ));
        let (_monitor, triggers) = read_streams(std::slice::from_ref(&node), false);

        let (fired, attested, took) = attest(&triggers, &node).await;
        assert_eq!(fired, Fired::Deadline);
        assert_eq!(attested.published, 1);
        assert!(took >= WAIT);
        assert!(
            node.event_subscriptions().len() >= 2,
            "the reader tried to open the stream again"
        );
    }

    /// A stream that breaks and comes back within the slot still delivers
    /// the slot's block in time.
    #[tokio::test(start_paused = true)]
    async fn a_stream_reopened_mid_slot_still_attests_early() {
        let node = Arc::new(
            attesting(block())
                .with_event_stream(vec![after(500)], StreamEnd::Fail)
                .with_event_stream(vec![after(500), head(SLOT, block())], StreamEnd::Hang),
        );
        let (_monitor, triggers) = read_streams(std::slice::from_ref(&node), false);

        let (fired, _, took) = attest(&triggers, &node).await;
        assert_eq!(fired, Fired::Event);
        assert!(took < WAIT);
        assert_eq!(node.event_subscriptions().len(), 2);
    }

    /// Triggers that outlive their monitor are the deadline alone.
    #[tokio::test(start_paused = true)]
    async fn triggers_without_their_readers_wait_for_the_deadline() {
        let node = Arc::new(
            attesting(block())
                .with_event_stream(vec![after(1_000), head(SLOT, block())], StreamEnd::Hang),
        );
        let (monitor, triggers) = read_streams(std::slice::from_ref(&node), false);
        drop(monitor);

        let (fired, _, took) = attest(&triggers, &node).await;
        assert_eq!(fired, Fired::Deadline);
        assert!(took >= WAIT);
    }

    /// Every node's stream is read: the first node saying nothing does not
    /// stop the second's event from starting the duty.
    #[tokio::test(start_paused = true)]
    async fn an_event_from_any_node_starts_the_duty() {
        let silent = Arc::new(MockBeaconNode::new());
        let reporting = Arc::new(
            MockBeaconNode::new()
                .with_event_stream(vec![after(1_000), head(SLOT, block())], StreamEnd::Hang),
        );
        let (_monitor, triggers) = read_streams(&[silent, reporting], false);
        let node = Arc::new(attesting(block()));

        let (fired, _, took) = attest(&triggers, &node).await;
        assert_eq!(fired, Fired::Event);
        assert!(took < WAIT);
    }

    /// A second node reports the block first, while the node that answers
    /// has not imported it: that attempt declines, and the answering node's
    /// own report, a second later, starts the duty after all, still before
    /// the deadline.
    #[tokio::test(start_paused = true)]
    async fn a_declined_attempt_is_made_again_on_the_next_report() {
        let answering = Arc::new(
            MockBeaconNode::new()
                .with_event_stream(vec![after(2_000), head(SLOT, block())], StreamEnd::Hang),
        );
        let ahead = Arc::new(
            MockBeaconNode::new()
                .with_event_stream(vec![after(1_000), head(SLOT, block())], StreamEnd::Hang),
        );
        let (_monitor, triggers) = read_streams(&[answering, ahead], false);
        // Until the answering node has the block, it has no data to give.
        let node = Arc::new(attesting(block()).failing_call("attestation_data", "no block yet"));
        let imports = node.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1_500)).await;
            imports.stop_failing("attestation_data");
        });

        let (fired, attested, took) = attest(&triggers, &node).await;
        assert_eq!(fired, Fired::Event);
        assert_eq!(attested.published, 1);
        assert!(
            took < WAIT,
            "attested {took:?} in, the deadline is {WAIT:?}"
        );
        assert_eq!(
            node.attestation_data_call_count(),
            1,
            "one answer, on the second report: the failed request is not counted"
        );
        assert_eq!(node.submitted().len(), 1);
    }

    /// The duty loop's wait before the slot's duties ends on the slot's block.
    #[tokio::test(start_paused = true)]
    async fn the_wait_before_the_slots_duties_ends_on_its_block() {
        let node = Arc::new(
            MockBeaconNode::new()
                .with_event_stream(vec![after(1_000), head(SLOT, block())], StreamEnd::Hang),
        );
        let (_monitor, triggers) = read_streams(std::slice::from_ref(&node), false);

        let started = Instant::now();
        assert_eq!(triggers.report_within(SLOT, WAIT).await, Some(block()));
        assert!(started.elapsed() < WAIT);
        assert_eq!(triggers.report_within(SLOT + 1, WAIT).await, None);
    }

    /// A payload report ends that wait as well, so a node whose head stream
    /// is down but whose payload stream is up does not hold the committee
    /// vote to the first duty's offset.
    #[tokio::test(start_paused = true)]
    async fn the_wait_before_the_slots_duties_ends_on_its_payload() {
        let node = Arc::new(MockBeaconNode::new().with_topic_stream(
            Topic::ExecutionPayloadAvailable,
            vec![after(1_000), payload(SLOT, block())],
            StreamEnd::Hang,
        ));
        let (_monitor, triggers) = read_streams(std::slice::from_ref(&node), true);

        let started = Instant::now();
        assert_eq!(triggers.report_within(SLOT, WAIT).await, Some(block()));
        assert!(started.elapsed() < WAIT);
    }

    // Sync committee messages.

    fn sync_service(node: &Arc<MockBeaconNode>) -> SyncCommitteeService<MockBeaconNode> {
        let config = Config::mainnet().with_fork_epoch(ForkName::Altair, 0);
        SyncCommitteeService::new(
            node.clone(),
            Arc::new(SigningContext::new(config, Root::ZERO)),
        )
    }

    async fn sign_sync(
        triggers: &DutyTriggers,
        node: &Arc<MockBeaconNode>,
    ) -> (Fired, Option<Root>, Duration) {
        let (store, pubkey) = key();
        let duty = SyncDutyDto {
            pubkey: encode_hex(&pubkey.0),
            validator_index: 1,
            validator_sync_committee_indices: vec![0],
        };
        let service = sync_service(node);
        let started = Instant::now();
        let (fired, signed) = triggers
            .sync_traced(&service, SLOT, WAIT, &[duty], &store)
            .await;
        (fired, signed.expect("signs"), started.elapsed())
    }

    #[tokio::test(start_paused = true)]
    async fn a_head_event_for_the_slot_signs_the_sync_message_then() {
        let node = Arc::new(
            MockBeaconNode::new()
                .with_head_root(block())
                .with_event_stream(vec![after(1_000), head(SLOT, block())], StreamEnd::Hang),
        );
        let (_monitor, triggers) = read_streams(std::slice::from_ref(&node), false);

        let (fired, signed, took) = sign_sync(&triggers, &node).await;
        assert_eq!(fired, Fired::Event);
        assert_eq!(signed, Some(block()));
        assert!(took < WAIT);
        let sent = node.submitted_sync_messages();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].beacon_block_root, block());
    }

    /// A node whose head is not yet the event's block signs at the deadline,
    /// over whatever its head is then, and only then.
    #[tokio::test(start_paused = true)]
    async fn a_head_root_for_another_block_signs_at_the_deadline() {
        let node = Arc::new(
            MockBeaconNode::new()
                .with_head_root(other_block())
                .with_event_stream(vec![after(1_000), head(SLOT, block())], StreamEnd::Hang),
        );
        let (_monitor, triggers) = read_streams(std::slice::from_ref(&node), false);

        let (fired, signed, took) = sign_sync(&triggers, &node).await;
        assert_eq!(fired, Fired::Mismatch);
        assert_eq!(signed, Some(other_block()));
        assert!(took >= WAIT);
        assert_eq!(node.submitted_sync_messages().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn no_event_signs_the_sync_message_at_the_deadline() {
        let node = Arc::new(MockBeaconNode::new().with_head_root(block()));
        let (_monitor, triggers) = read_streams(std::slice::from_ref(&node), false);

        let (fired, _, took) = sign_sync(&triggers, &node).await;
        assert_eq!(fired, Fired::Deadline);
        assert!(took >= WAIT);
        assert_eq!(node.submitted_sync_messages().len(), 1);
    }

    // Payload timeliness committee votes.

    const GLOAS_EPOCH: u64 = 10;

    fn gloas_slot() -> Slot {
        GLOAS_EPOCH * slots_per_epoch() + 4
    }

    fn payload_data(present: bool, blobs: bool) -> PayloadAttestationData {
        PayloadAttestationData {
            beacon_block_root: block(),
            slot: gloas_slot(),
            payload_present: present,
            blob_data_available: blobs,
        }
    }

    async fn vote(triggers: &DutyTriggers, node: &Arc<MockBeaconNode>) -> (Fired, usize, Duration) {
        let (store, pubkey) = key();
        let duty = PtcDutyDto {
            pubkey: encode_hex(&pubkey.0),
            validator_index: 1,
            slot: gloas_slot(),
        };
        let config = Config::mainnet().with_fork_epoch(ForkName::Gloas, GLOAS_EPOCH);
        let context = Arc::new(SigningContext::new(config, Root::ZERO));
        let service = PayloadAttestationService::new(node.clone(), context);
        let started = Instant::now();
        let (fired, voted) = triggers
            .payload_traced(&service, gloas_slot(), WAIT, &[duty], &store)
            .await;
        (fired, voted.expect("votes"), started.elapsed())
    }

    /// The payload, with its blobs, starts the vote early.
    #[tokio::test(start_paused = true)]
    async fn the_payload_event_for_the_slot_votes_then() {
        let node = Arc::new(
            MockBeaconNode::new()
                .with_payload_attestation_data(payload_data(true, true))
                .with_topic_stream(
                    Topic::ExecutionPayloadAvailable,
                    vec![after(2_000), payload(gloas_slot(), block())],
                    StreamEnd::Hang,
                ),
        );
        let (_monitor, triggers) = read_streams(std::slice::from_ref(&node), true);

        let (fired, voted, took) = vote(&triggers, &node).await;
        assert_eq!(fired, Fired::Event);
        assert_eq!(voted, 1);
        assert!(took < WAIT);
        assert_eq!(node.payload_attestation_data_call_count(), 1);
    }

    /// The slot's block, as head, is not its payload: the vote waits.
    #[tokio::test(start_paused = true)]
    async fn the_block_alone_does_not_start_the_vote() {
        let node = Arc::new(
            MockBeaconNode::new()
                .with_payload_attestation_data(payload_data(true, true))
                .with_topic_stream(
                    Topic::Head,
                    vec![after(500), head(gloas_slot(), block())],
                    StreamEnd::Hang,
                )
                .with_topic_stream(
                    Topic::ExecutionPayloadAvailable,
                    Vec::new(),
                    StreamEnd::Hang,
                ),
        );
        let (_monitor, triggers) = read_streams(std::slice::from_ref(&node), true);

        let (fired, voted, took) = vote(&triggers, &node).await;
        assert_eq!(fired, Fired::Deadline);
        assert_eq!(voted, 1);
        assert!(took >= WAIT);
        assert_eq!(node.payload_attestation_data_call_count(), 1);
    }

    /// An event whose data does not call the payload present, or its blob
    /// data available, is not voted on early: such a vote may only be cast
    /// once the deadline has passed.
    #[tokio::test(start_paused = true)]
    async fn a_payload_the_data_does_not_call_present_waits_for_the_deadline() {
        for (present, blobs) in [(false, true), (true, false)] {
            let node = Arc::new(
                MockBeaconNode::new()
                    .with_payload_attestation_data(payload_data(present, blobs))
                    .with_topic_stream(
                        Topic::ExecutionPayloadAvailable,
                        vec![after(1_000), payload(gloas_slot(), block())],
                        StreamEnd::Hang,
                    ),
            );
            let (_monitor, triggers) = read_streams(std::slice::from_ref(&node), true);

            let (fired, voted, took) = vote(&triggers, &node).await;
            assert_eq!(fired, Fired::Mismatch, "present {present}, blobs {blobs}");
            assert_eq!(voted, 1, "voted once, at the deadline");
            assert!(took >= WAIT);
            assert_eq!(node.payload_attestation_data_call_count(), 2);
            let sent = node.submitted_payload_attestations();
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0].data, payload_data(present, blobs));
        }
    }

    /// Without gloas scheduled only `head` is asked for; with it, each topic
    /// gets its own stream.
    #[tokio::test(start_paused = true)]
    async fn the_payload_topic_is_read_only_when_gloas_is_scheduled() {
        let before = Arc::new(MockBeaconNode::new());
        let (_before, _) = read_streams(std::slice::from_ref(&before), false);
        let gloas = Arc::new(MockBeaconNode::new());
        let (_gloas, _) = read_streams(std::slice::from_ref(&gloas), true);
        tokio::time::sleep(Duration::from_millis(10)).await;

        assert_eq!(before.event_subscriptions(), vec![vec![Topic::Head]]);
        let mut asked = gloas.event_subscriptions();
        asked.sort_by_key(|topics| topics.first().map(|topic| topic.as_str()));
        assert_eq!(
            asked,
            vec![vec![Topic::ExecutionPayloadAvailable], vec![Topic::Head]]
        );
    }

    // What each node reports.

    #[test]
    fn a_report_moves_forward_only() {
        let (reports, seen) = watch::channel(vec![None]);
        let at = |slot| {
            NodeEvent::Head(HeadEvent {
                slot,
                block: block(),
                execution_optimistic: false,
            })
        };
        note(&reports, 0, Topic::Head, at(10));
        note(&reports, 0, Topic::Head, at(9));
        assert_eq!(untried(&seen.borrow(), 10, &[]), Some((0, block())));
        assert_eq!(untried(&seen.borrow(), 9, &[]), None);
    }

    /// An event of the other topic, on a stream opened for one, is ignored.
    #[test]
    fn an_event_off_its_topic_is_ignored() {
        let (reports, seen) = watch::channel(vec![None]);
        let event = NodeEvent::PayloadAvailable(PayloadAvailableEvent {
            slot: 10,
            block_root: block(),
        });
        note(&reports, 0, Topic::Head, event);
        assert_eq!(untried(&seen.borrow(), 10, &[]), None);
    }

    /// When two nodes report different blocks for the slot, the first node's
    /// is the one the duty checks the data against, and once it was tried,
    /// the other's comes next.
    #[test]
    fn the_first_nodes_report_wins_and_the_next_follows() {
        let reports = vec![
            Some(Reported {
                slot: 10,
                root: block(),
            }),
            Some(Reported {
                slot: 10,
                root: other_block(),
            }),
        ];
        assert_eq!(untried(&reports, 10, &[]), Some((0, block())));
        assert_eq!(
            untried(&reports, 10, &[(0, block())]),
            Some((1, other_block()))
        );
        assert_eq!(
            untried(&reports, 10, &[(0, block()), (1, other_block())]),
            None
        );
        let reports = vec![
            None,
            Some(Reported {
                slot: 10,
                root: other_block(),
            }),
        ];
        assert_eq!(untried(&reports, 10, &[]), Some((1, other_block())));
    }

    /// The same block reported by a second node is a new report: it is how a
    /// declined attempt is made again once the answering node has the block.
    #[test]
    fn the_same_block_from_another_node_is_a_new_report() {
        let reports = vec![
            Some(Reported {
                slot: 10,
                root: block(),
            }),
            Some(Reported {
                slot: 10,
                root: block(),
            }),
        ];
        assert_eq!(untried(&reports, 10, &[(1, block())]), Some((0, block())));
    }
}
