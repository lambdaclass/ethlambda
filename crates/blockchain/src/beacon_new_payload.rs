//! Asking the execution client about payloads without waiting for the answer.
//!
//! A pre-gloas block, and from gloas on an envelope, enters fork choice as soon
//! as its consensus checks pass, with its payload marked as not yet validated
//! (`optimistic-sync.md`'s `NOT_VALIDATED`). The `engine_newPayload` question
//! goes out first, from a tokio task of its own, and the answer comes back to
//! the actor as a [`NewPayloadAnswered`] message, where it is applied the way
//! the specification applies a `newPayload` verdict:
//!
//! | Answer | Pre-gloas block | Gloas payload |
//! |---|---|---|
//! | `VALID` | validated, with its optimistic ancestors | `VALID`, held children released |
//! | `SYNCING` / `ACCEPTED` | stays optimistic | stays `NOT_VALIDATED`, held children released |
//! | `INVALID` with a hash | removed with its subtree | condemned (see `condemn_payload_chain`) |
//! | `INVALID` with no hash | as above | taken back out: only that envelope is refused |
//! | no answer | kept, asked again next slot | kept, asked again next slot |
//!
//! ```text
//! import ─► queued ─(parent answered, < MAX in flight)─► in flight ─► answered
//!              ▲                                              │ no answer
//!              └──────────────── next slot ── unanswered ◄────┘
//! ```
//!
//! # Order
//!
//! The Engine API orders only `forkchoiceUpdated` (`common.md`, "Message
//! ordering"), and the engine client's connection pool can deliver two
//! in-flight requests in either order. A payload whose parent the execution
//! client has not seen is answered `SYNCING`, and the client may start a sync
//! from its peers for it. So a payload is sent only once no request for the
//! payload it builds on is outstanding, and at most
//! [`MAX_NEW_PAYLOADS_IN_FLIGHT`] at once: siblings and forks go in parallel, a
//! linear chain goes one at a time. For the same reason `forkchoiceUpdated`
//! never names a payload whose request is still queued or in flight: it names
//! the newest one on the head's chain the client was asked about (see
//! [`NewPayloads::forkchoice_head`]), and is sent again when the head's own
//! answer arrives.
//!
//! # Children of a gloas payload
//!
//! A block that builds on a FULL parent waits until the parent payload's
//! answer is in, not merely until its envelope is applied, as Lighthouse and
//! Prysm do (neither applies an envelope before the answer). That is what lets
//! a refused envelope be taken back out without anything built on it.
//!
//! # Bounds
//!
//! At most [`MAX_PAYLOADS_AWAITING_VERDICT`] payloads wait for an answer. Past
//! that the import itself waits: a pre-gloas block in
//! [`NewPayloads::blocks_awaiting_room`], an envelope in `awaiting_engine`,
//! each released as answers free room. That only happens during catch-up,
//! where the execution client is the slower side.
//!
//! # Deviation
//!
//! `optimistic-sync.md` says a block the execution client gave no answer for
//! MUST NOT be applied to fork choice. Here it already is, so it stays,
//! optimistic, and is asked about again once a slot. See
//! `docs/spec_deviations.md`.
//!
//! Without a way to hear back (offline replay builds the server without an
//! actor) the import waits for the answer inline, as it always did.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use ethlambda_engine::types::PayloadStatusValue;
use ethlambda_engine::{EngineError, PayloadStatusV1};
use ethlambda_state_transition::beacon::containers::{SignedBeaconBlock, gloas};
use ethlambda_state_transition::beacon::fork_choice::{self, PayloadStatusEnum, PayloadValidity};
use ethlambda_types::{ShortRoot, primitives::H256};
use spawned_concurrency::message::Message;
use spawned_concurrency::tasks::{ActorRef, Context, Handler};
use tracing::{info, warn};

use crate::import_timing::{ImportTimings, row};
use crate::{BlockChainServer, beacon_engine, metrics, verdict_label};

/// How many `engine_newPayload` requests may be in flight at once.
///
/// The Engine API sets no limit. Execution clients validate one payload at a
/// time on the canonical chain, so more in flight only queues work on their
/// side; a few let side branches and the next request's transfer overlap the
/// current validation.
pub(crate) const MAX_NEW_PAYLOADS_IN_FLIGHT: usize = 4;

/// How many imported payloads may wait for an answer, in flight or not.
///
/// One range-sync batch: enough that catch-up keeps the execution client
/// busy, small enough that the consensus side cannot run unboundedly far
/// ahead of what has been validated.
pub(crate) const MAX_PAYLOADS_AWAITING_VERDICT: usize = 128;

/// What a request is about.
pub(crate) enum PayloadQuestion {
    /// A pre-gloas block, whose payload is in its body.
    Block(SignedBeaconBlock),
    /// A gloas envelope, with the block whose bid it fulfils.
    Envelope {
        block: SignedBeaconBlock,
        envelope: Box<gloas::SignedExecutionPayloadEnvelope>,
        envelope_root: H256,
    },
}

impl PayloadQuestion {
    fn kind(&self) -> PayloadKind {
        match self {
            Self::Block(_) => PayloadKind::Block,
            Self::Envelope { .. } => PayloadKind::Envelope,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PayloadKind {
    Block,
    Envelope,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AskState {
    /// Waiting for its turn: room in flight, and its parent payload answered.
    Queued,
    /// Sent; the task holding it has not reported back.
    InFlight,
    /// The last request got no answer after the whole retry ladder; asked
    /// again on the next slot.
    Unanswered,
}

struct Ask {
    slot: u64,
    block_hash: H256,
    parent_hash: H256,
    state: AskState,
    question: Arc<PayloadQuestion>,
    /// The `block_events` source of the import that asked (`None` for a
    /// source with no rows, and for envelopes, which write none).
    source: Option<&'static str>,
    /// When the last request for it went out.
    sent: Option<Instant>,
}

/// What a block's `el_sent`, `el_verdict` and `attestable` rows need once its
/// answer is applied: the import's slot and source, and when the request went
/// out and its answer came back.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AnswerTelemetry {
    pub(crate) slot: u64,
    pub(crate) source: &'static str,
    pub(crate) sent: Instant,
    pub(crate) answered: Instant,
}

/// The `block_events` rows for a block's answer applied at `applied`:
/// `el_sent` and `el_verdict` at the request's own instants, and, for a
/// `VALID` answer, `attestable` at `applied`, the moment the block stopped
/// being optimistic. The import wrote no `attestable` of its own for it (see
/// `CascadeTelemetry::events_except_awaiting`), and this is always the later
/// of the two moments an attestable block needs: the answer is applied by the
/// actor only after the import that asked, head recomputation included.
pub(crate) fn answer_events(
    root: H256,
    telemetry: AnswerTelemetry,
    validity: &PayloadValidity,
    applied: Instant,
) -> Vec<ethlambda_telemetry::BlockEvent> {
    let AnswerTelemetry {
        slot,
        source,
        sent,
        answered,
    } = telemetry;
    let mut events = vec![
        row("el_sent", sent, slot, root, source),
        ethlambda_telemetry::BlockEvent {
            verdict: Some(verdict_label(validity)),
            ..row("el_verdict", answered, slot, root, source)
        },
    ];
    // The two answers `apply_block_answer` marks the block validated for.
    if matches!(
        validity,
        PayloadValidity::Validated | PayloadValidity::NotRequired
    ) {
        events.push(row("attestable", applied, slot, root, source));
    }
    events
}

/// The execution client's answer, as the task that asked reports it.
pub(crate) enum PayloadAnswer {
    Block(Result<Option<PayloadValidity>, EngineError>),
    /// The raw status: an envelope's hash failure and an executed failure are
    /// handled differently, and only the status tells them apart.
    Envelope {
        envelope_root: H256,
        result: Result<PayloadStatusV1, EngineError>,
    },
}

/// A request task's report to the actor.
pub(crate) struct NewPayloadAnswered {
    pub(crate) root: H256,
    pub(crate) answer: PayloadAnswer,
    /// When the task got the answer, before it waited in the actor's
    /// mailbox: the `el_verdict` row's instant.
    pub(crate) answered_at: Instant,
}

impl Message for NewPayloadAnswered {
    type Result = ();
}

/// Where a request task sends its answer.
#[derive(Clone)]
pub(crate) enum VerdictSink {
    Actor(ActorRef<BlockChainServer>),
    /// Tests drive the actor's methods directly and feed the answers back
    /// themselves.
    #[cfg(test)]
    Channel(tokio::sync::mpsc::UnboundedSender<NewPayloadAnswered>),
}

impl VerdictSink {
    fn send(&self, answered: NewPayloadAnswered) {
        match self {
            Self::Actor(actor) => {
                let _ = actor.send(answered);
            }
            #[cfg(test)]
            Self::Channel(tx) => {
                let _ = tx.send(answered);
            }
        }
    }
}

/// Every payload imported and not yet answered for, and what waits on them.
#[derive(Default)]
pub(crate) struct NewPayloads {
    /// By the root of the block carrying (pre-gloas) or bidding for (gloas)
    /// the payload. A root has at most one payload to ask about.
    asks: HashMap<H256, Ask>,
    /// Queued roots, in the order they were imported.
    queue: VecDeque<H256>,
    /// Roots whose task has not reported back, including ones forgotten since
    /// (their answer is then ignored, but they still occupy a request slot).
    in_flight: HashSet<H256>,
    /// Pre-gloas blocks held because the waiting set was full, oldest first,
    /// with their slots. Written to the store as pending blocks.
    blocks_awaiting_room: VecDeque<(H256, u64)>,
    /// Set when a `forkchoiceUpdated` was skipped because the payload it would
    /// name had not reached the execution client yet.
    forkchoice_deferred: bool,
}

impl NewPayloads {
    /// Whether another payload may be imported before an answer.
    pub(crate) fn has_room(&self) -> bool {
        self.asks.len() < MAX_PAYLOADS_AWAITING_VERDICT
    }

    /// Whether `root` is a pre-gloas block imported before its answer, which
    /// is not in yet (queued, in flight or unanswered).
    pub(crate) fn awaits_block_answer(&self, root: &H256) -> bool {
        self.asks
            .get(root)
            .is_some_and(|ask| ask.question.kind() == PayloadKind::Block)
    }

    /// What `root`'s answer rows need, for an ask that has rows (a block
    /// from a measured source) and whose request went out.
    fn answer_telemetry(&self, root: &H256, answered: Instant) -> Option<AnswerTelemetry> {
        let ask = self.asks.get(root)?;
        Some(AnswerTelemetry {
            slot: ask.slot,
            source: ask.source?,
            sent: ask.sent?,
            answered,
        })
    }

    /// Whether `root`'s gloas payload is applied and its answer not in yet.
    pub(crate) fn awaits_envelope_answer(&self, root: &H256) -> bool {
        self.asks
            .get(root)
            .is_some_and(|ask| ask.question.kind() == PayloadKind::Envelope)
    }

    /// The payload `forkchoiceUpdated` may name as the head, given the head's
    /// own payload `block_hash`: that one, unless its request is queued or in
    /// flight, and then the nearest payload it builds on whose request is not.
    ///
    /// Walks each held-back payload's parent hash, which is the chain the
    /// execution client validates along. During catch-up the newest block's
    /// request always waits behind its parent's, so skipping the call instead
    /// would leave the client without a head for the whole catch-up.
    pub(crate) fn forkchoice_head(&self, block_hash: H256) -> H256 {
        // One that got no answer does not hold the head back: an execution
        // client that cannot be reached answers neither call.
        let mut head = block_hash;
        for _ in 0..=self.asks.len() {
            let Some(ask) = self
                .asks
                .values()
                .find(|ask| ask.block_hash == head && ask.state != AskState::Unanswered)
            else {
                break;
            };
            head = ask.parent_hash;
        }
        head
    }

    pub(crate) fn defer_forkchoice_updated(&mut self) {
        self.forkchoice_deferred = true;
    }

    fn take_deferred_forkchoice_updated(&mut self) -> bool {
        std::mem::take(&mut self.forkchoice_deferred)
    }

    fn insert(
        &mut self,
        root: H256,
        slot: u64,
        block_hash: H256,
        parent_hash: H256,
        question: PayloadQuestion,
        source: Option<&'static str>,
    ) {
        if self.asks.contains_key(&root) {
            return;
        }
        self.queue.push_back(root);
        self.asks.insert(
            root,
            Ask {
                slot,
                block_hash,
                parent_hash,
                state: AskState::Queued,
                question: Arc::new(question),
                source,
                sent: None,
            },
        );
    }

    /// The oldest queued payload that may go now, marked in flight.
    fn next_to_send(&mut self) -> Option<(H256, Arc<PayloadQuestion>)> {
        if self.in_flight.len() >= MAX_NEW_PAYLOADS_IN_FLIGHT {
            return None;
        }
        let position = self.queue.iter().position(|root| {
            let Some(ask) = self.asks.get(root) else {
                return false;
            };
            !self
                .asks
                .values()
                .any(|other| other.block_hash == ask.parent_hash)
        })?;
        let root = self.queue.remove(position)?;
        let ask = self.asks.get_mut(&root)?;
        ask.state = AskState::InFlight;
        // A redrive after no answer overwrites it: `el_sent` is the request
        // whose answer `el_verdict` reports.
        ask.sent = Some(Instant::now());
        self.in_flight.insert(root);
        Some((root, Arc::clone(&ask.question)))
    }

    /// Frees `root`'s request slot. `true` if its ask is still tracked, so the
    /// answer is to be applied.
    fn finish(&mut self, root: &H256) -> bool {
        self.in_flight.remove(root)
            && self
                .asks
                .get(root)
                .is_some_and(|ask| ask.state == AskState::InFlight)
    }

    /// `root` was answered: it no longer waits. Its slot, if it was waiting.
    fn complete(&mut self, root: &H256) -> Option<u64> {
        self.asks.remove(root).map(|ask| ask.slot)
    }

    fn mark_unanswered(&mut self, root: &H256) {
        if let Some(ask) = self.asks.get_mut(root) {
            ask.state = AskState::Unanswered;
        }
    }

    /// Put every unanswered ask back in the queue, oldest slot first.
    fn requeue_unanswered(&mut self) {
        let mut unanswered: Vec<(u64, H256)> = self
            .asks
            .iter()
            .filter(|(_, ask)| ask.state == AskState::Unanswered)
            .map(|(root, ask)| (ask.slot, *root))
            .collect();
        unanswered.sort();
        for (_, root) in unanswered {
            if let Some(ask) = self.asks.get_mut(&root) {
                ask.state = AskState::Queued;
            }
            self.queue.push_back(root);
        }
    }

    /// Stop waiting for `root`. An answer already on its way is ignored.
    pub(crate) fn forget(&mut self, root: &H256) {
        self.asks.remove(root);
        self.queue.retain(|queued| queued != root);
    }

    /// Stop waiting for every payload `keep` says no longer matters, given its
    /// root, its block's slot and what it is.
    fn retain(&mut self, mut keep: impl FnMut(&H256, u64, PayloadKind) -> bool) {
        let dropped: Vec<H256> = self
            .asks
            .iter()
            .filter(|(root, ask)| !keep(root, ask.slot, ask.question.kind()))
            .map(|(root, _)| *root)
            .collect();
        for root in dropped {
            self.forget(&root);
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.asks.len()
    }

    pub(crate) fn in_flight_len(&self) -> usize {
        self.in_flight.len()
    }

    pub(crate) fn is_block_awaiting_room(&self, root: &H256) -> bool {
        self.blocks_awaiting_room
            .iter()
            .any(|(held, _)| held == root)
    }
}

/// `INVALID` with no `latestValidHash`: since `engine_newPayloadV2` this is
/// how a payload whose contents do not hash to its claimed block hash is
/// answered (`INVALID_BLOCK_HASH` is "supplanted by `INVALID`",
/// execution-apis `shanghai.md`), and also an executed failure whose last valid
/// ancestor the client cannot name. Either way nothing says the payload the
/// bid commits to is bad, only this copy of it.
fn refuses_only_this_envelope(status: &PayloadStatusV1) -> bool {
    status.status == PayloadStatusValue::InvalidBlockHash
        || (status.status == PayloadStatusValue::Invalid && status.latest_valid_hash.is_none())
}

impl BlockChainServer {
    /// Whether payloads are imported before their answer: there is an
    /// execution client to ask, and a way for the answer to come back.
    pub(crate) fn answers_payloads_later(&self) -> bool {
        self.engine.is_some() && self.verdict_sink.is_some()
    }

    /// Ask about `block`'s payload without waiting. The caller imports the
    /// block as optimistic right after.
    ///
    /// `source` is the import's `block_events` source, under which the
    /// answer's `el_sent`, `el_verdict` and `attestable` rows are written
    /// (`None` writes none).
    pub(crate) fn ask_about_block_payload(
        &mut self,
        block: &SignedBeaconBlock,
        source: Option<&'static str>,
    ) {
        let Some(request) = beacon_engine::new_payload_request(block) else {
            return;
        };
        let block_hash = request.execution_payload.block_hash;
        let parent_hash = request.execution_payload.parent_hash;
        let root = block.message_hash_tree_root();
        let question = PayloadQuestion::Block(block.clone());
        self.new_payloads.insert(
            root,
            block.slot(),
            block_hash,
            parent_hash,
            question,
            source,
        );
        self.send_new_payloads();
    }

    /// Ask about the payload `envelope` reveals for `block` without waiting.
    /// The caller has checked that the two belong together
    /// ([`beacon_engine::gloas_new_payload_request`]) and applies the envelope
    /// right after.
    pub(crate) fn ask_about_envelope_payload(
        &mut self,
        block: &SignedBeaconBlock,
        envelope: &gloas::SignedExecutionPayloadEnvelope,
        envelope_root: H256,
    ) {
        let root = envelope.message.beacon_block_root;
        let payload = &envelope.message.payload;
        let (block_hash, parent_hash) = (payload.block_hash, payload.parent_hash);
        let question = PayloadQuestion::Envelope {
            block: block.clone(),
            envelope: Box::new(envelope.clone()),
            envelope_root,
        };
        // An envelope writes no block rows.
        self.new_payloads
            .insert(root, block.slot(), block_hash, parent_hash, question, None);
        self.send_new_payloads();
    }

    /// Send every queued request that may go now, each from a task of its own
    /// that reports back with a [`NewPayloadAnswered`].
    fn send_new_payloads(&mut self) {
        let (Some(client), Some(sink)) = (self.engine.clone(), self.verdict_sink.clone()) else {
            return;
        };
        while let Some((root, question)) = self.new_payloads.next_to_send() {
            let client = client.clone();
            let sink = sink.clone();
            tokio::spawn(async move {
                let answer = match &*question {
                    PayloadQuestion::Block(block) => {
                        PayloadAnswer::Block(beacon_engine::ask(&client, block).await)
                    }
                    PayloadQuestion::Envelope {
                        block,
                        envelope,
                        envelope_root,
                    } => PayloadAnswer::Envelope {
                        envelope_root: *envelope_root,
                        result: beacon_engine::ask_envelope_status(&client, block, envelope).await,
                    },
                };
                let answered_at = Instant::now();
                sink.send(NewPayloadAnswered {
                    root,
                    answer,
                    answered_at,
                });
            });
        }
        self.publish_new_payload_gauges();
    }

    fn publish_new_payload_gauges(&self) {
        metrics::set_new_payloads(self.new_payloads.in_flight_len(), self.new_payloads.len());
    }

    /// Apply an answer, then let through whatever it made room for.
    pub(crate) async fn on_new_payload_answered(&mut self, answered: NewPayloadAnswered) {
        let NewPayloadAnswered {
            root,
            answer,
            answered_at,
        } = answered;
        let tracked = self.new_payloads.finish(&root);
        let mut head_moved = false;
        match answer {
            PayloadAnswer::Block(result) if tracked => {
                head_moved = self.apply_block_answer(root, result, answered_at);
            }
            PayloadAnswer::Envelope {
                envelope_root,
                result,
            } if tracked => {
                if self.apply_envelope_answer(root, envelope_root, result) {
                    self.forget_payloads_left_behind();
                }
            }
            PayloadAnswer::Block(_) => metrics::inc_new_payload_answer("block", "stale"),
            PayloadAnswer::Envelope { .. } => metrics::inc_new_payload_answer("envelope", "stale"),
        }
        if head_moved {
            self.forget_payloads_left_behind();
        }

        self.send_new_payloads();
        self.release_blocks_awaiting_engine_room().await;
        if self.new_payloads.has_room() {
            self.release_envelopes_awaiting_engine_room();
        }
        // Releases the children of a gloas payload that was just answered, and
        // recomputes the head when an envelope was taken back out.
        self.settle_envelopes().await;
        if head_moved || self.new_payloads.take_deferred_forkchoice_updated() {
            self.recompute_beacon_head().await;
        }
        self.publish_new_payload_gauges();
    }

    /// Apply the answer for a pre-gloas block already in fork choice. `true`
    /// when blocks left fork choice.
    ///
    /// Writes the block's `el_sent` and `el_verdict` rows, and its
    /// `attestable` when the answer validates it ([`answer_events`]).
    /// Nothing for no answer (the redrive's answer writes them) or for a
    /// block that left fork choice meanwhile.
    fn apply_block_answer(
        &mut self,
        root: H256,
        result: Result<Option<PayloadValidity>, EngineError>,
        answered_at: Instant,
    ) -> bool {
        let validity = match result {
            Ok(validity) => validity,
            Err(err) => {
                warn!(
                    block_root = %ShortRoot(&root.0),
                    %err,
                    "No verdict from the execution client; the block stays optimistic \
                     and is asked about again next slot"
                );
                metrics::inc_engine_no_verdict();
                metrics::inc_new_payload_answer("block", "no_answer");
                self.new_payloads.mark_unanswered(&root);
                return false;
            }
        };
        // Read before `complete` drops the ask.
        let telemetry = self.new_payloads.answer_telemetry(&root, answered_at);
        let slot = self.new_payloads.complete(&root);
        // The block failed its own import after the question went out, or
        // left fork choice since.
        if !slot.is_some_and(|slot| self.store.has_live_chain_entry(slot, &root)) {
            metrics::inc_new_payload_answer("block", "stale");
            return false;
        }
        // No request means no payload to validate, which `on_block` treats
        // as validated too.
        let validity = validity.unwrap_or(PayloadValidity::NotRequired);
        let left_fork_choice = self.apply_block_validity(root, &validity);
        if let Some(telemetry) = telemetry {
            let applied = Instant::now();
            ethlambda_telemetry::emit(|| answer_events(root, telemetry, &validity, applied));
        }
        left_fork_choice
    }

    /// [`Self::apply_block_answer`] once the block is known to be live.
    fn apply_block_validity(&mut self, root: H256, validity: &PayloadValidity) -> bool {
        match *validity {
            PayloadValidity::Validated | PayloadValidity::NotRequired => {
                let head = self.store.beacon_head().map(|(_, head)| head);
                let head_was_optimistic =
                    head.is_some_and(|head| self.store.is_beacon_optimistic(head));
                fork_choice::mark_validated(&mut self.store, root);
                metrics::inc_new_payload_answer("block", "valid");
                if let Some(head) = head
                    && head_was_optimistic
                    && !self.store.is_beacon_optimistic(head)
                {
                    let wall_clock_slot = self.wall_clock_slot();
                    self.events
                        .publish_beacon_head_validated(&self.store, head, wall_clock_slot);
                }
                false
            }
            PayloadValidity::Optimistic => {
                metrics::inc_new_payload_answer("block", "optimistic");
                false
            }
            PayloadValidity::Invalidated { latest_valid_hash } => {
                metrics::inc_new_payload_answer("block", "invalid");
                self.invalidate_block_payload(root, latest_valid_hash) > 0
            }
        }
    }

    /// Apply the answer for a gloas payload whose envelope is already applied.
    /// `true` when payloads or blocks left fork choice.
    fn apply_envelope_answer(
        &mut self,
        root: H256,
        envelope_root: H256,
        result: Result<PayloadStatusV1, EngineError>,
    ) -> bool {
        let status = match result {
            Ok(status) => status,
            Err(err) => {
                warn!(
                    block_root = %ShortRoot(&root.0),
                    %err,
                    "No verdict from the execution client; the payload stays not validated \
                     and is asked about again next slot"
                );
                metrics::inc_engine_no_verdict();
                metrics::inc_new_payload_answer("envelope", "no_answer");
                self.new_payloads.mark_unanswered(&root);
                return false;
            }
        };
        self.new_payloads.complete(&root);
        // Taken back out, or condemned with an ancestor, since it was asked.
        if !self.store.has_verified_payload(&root) {
            metrics::inc_new_payload_answer("envelope", "stale");
            return false;
        }
        let Some((slot, _parent)) = self.store.block_entry(&root) else {
            metrics::inc_new_payload_answer("envelope", "stale");
            return false;
        };

        if refuses_only_this_envelope(&status) {
            metrics::inc_new_payload_answer("envelope", "reverted");
            self.revert_envelope(root, envelope_root);
            return false;
        }
        match beacon_engine::verdict(&status) {
            PayloadValidity::Validated | PayloadValidity::NotRequired => {
                metrics::inc_new_payload_answer("envelope", "valid");
                self.store
                    .insert_beacon_block_payload_status(root, slot, PayloadStatusEnum::Valid);
                crate::beacon_payloads::mark_payloads_validated(&mut self.store, root);
                self.release_children_of_answered_payload(root);
                false
            }
            PayloadValidity::Optimistic => {
                metrics::inc_new_payload_answer("envelope", "optimistic");
                self.release_children_of_answered_payload(root);
                false
            }
            PayloadValidity::Invalidated { latest_valid_hash } => {
                metrics::inc_new_payload_answer("envelope", "invalid");
                warn!(
                    %slot,
                    block_root = %ShortRoot(&root.0),
                    "Execution client found an envelope's payload invalid"
                );
                self.envelopes.head_dirty = true;
                self.condemn_payload_chain(root, latest_valid_hash)
            }
        }
    }

    /// The block at or above `root` on its chain whose payload is
    /// `block_hash`, for a `forkchoiceUpdated` that names an ancestor's payload
    /// instead of the head's (see [`NewPayloads::forkchoice_head`]). Pre-gloas
    /// only: a block's payload is its own there.
    pub(crate) fn ancestor_with_payload(&self, root: H256, block_hash: H256) -> Option<H256> {
        let mut current = root;
        for _ in 0..=self.new_payloads.len() {
            if self.store.beacon_el_block_hash(current) == Some(block_hash) {
                return Some(current);
            }
            current = self.store.block_entry(&current)?.1;
        }
        None
    }

    /// Asks whose block or payload is gone after blocks left fork choice: a
    /// question about them would only be answered to be ignored.
    fn forget_payloads_left_behind(&mut self) {
        let store = &self.store;
        self.new_payloads.retain(|root, slot, kind| match kind {
            PayloadKind::Block => store.has_live_chain_entry(slot, root),
            PayloadKind::Envelope => store.has_verified_payload(root),
        });
    }

    /// Hold a pre-gloas block whose payload there is no room to wait for.
    ///
    /// Written the way a block held for columns is (see
    /// `hold_block_for_columns`): no `LiveChain` entry, so it stays invisible
    /// to fork choice, and readable back by root once room frees.
    pub(crate) fn hold_block_for_engine_room(
        &mut self,
        block: SignedBeaconBlock,
        timings: ImportTimings,
    ) {
        let slot = block.slot();
        let block_root = block.message_hash_tree_root();
        if self.new_payloads.is_block_awaiting_room(&block_root) {
            return;
        }
        info!(
            %slot,
            block_root = %ShortRoot(&block_root.0),
            awaiting = self.new_payloads.len(),
            "Holding block: too many payloads are waiting for the execution client"
        );
        self.store
            .insert_pending_block(block_root, block)
            .expect("DB insert should succeed");
        self.new_payloads
            .blocks_awaiting_room
            .push_back((block_root, slot));
        self.held_timings.insert(block_root, timings);
    }

    /// Import the blocks held for room, oldest first, while there is room.
    async fn release_blocks_awaiting_engine_room(&mut self) {
        while self.new_payloads.has_room() {
            let Some((block_root, slot)) = self.new_payloads.blocks_awaiting_room.pop_front()
            else {
                return;
            };
            let timings = self
                .held_timings
                .remove(&block_root)
                .unwrap_or_else(ImportTimings::starting_now);
            let Ok(Some(block)) = self.store.get_signed_block(&block_root) else {
                warn!(
                    %slot,
                    block_root = %ShortRoot(&block_root.0),
                    "A block held for engine room vanished from the store"
                );
                continue;
            };
            // The import path every block takes, which cascades its pending
            // children and may hold it again if the room is gone by then.
            self.on_block(block, timings).await;
        }
    }

    /// Once a slot: ask again about every payload the execution client did not
    /// answer, and let through what the room allows.
    pub(crate) async fn redrive_new_payloads(&mut self) {
        if self.new_payloads.len() == 0 && self.new_payloads.blocks_awaiting_room.is_empty() {
            return;
        }
        self.new_payloads.requeue_unanswered();
        self.send_new_payloads();
        self.release_blocks_awaiting_engine_room().await;
    }

    /// Stop waiting for payloads at or below the finalized slot, whose verdict
    /// no longer changes what fork choice can pick, and drop the blocks held
    /// for room there.
    pub(crate) fn evict_new_payloads_at_or_below_finality(&mut self) {
        if self.new_payloads.len() == 0 && self.new_payloads.blocks_awaiting_room.is_empty() {
            return;
        }
        let finalized_slot = self
            .store
            .latest_finalized()
            .expect("finalized checkpoint exists")
            .slot;
        let below: Vec<H256> = self
            .new_payloads
            .asks
            .iter()
            .filter(|(_, ask)| ask.slot <= finalized_slot)
            .map(|(root, _)| *root)
            .collect();
        for root in below {
            self.new_payloads.forget(&root);
        }
        let mut dropped = Vec::new();
        self.new_payloads
            .blocks_awaiting_room
            .retain(|(root, slot)| {
                let keep = *slot > finalized_slot;
                if !keep {
                    dropped.push(*root);
                }
                keep
            });
        for root in dropped {
            self.held_timings.remove(&root);
            self.discard_pending_subtree(root);
        }
        self.publish_new_payload_gauges();
    }
}

impl Handler<NewPayloadAnswered> for BlockChainServer {
    async fn handle(&mut self, answered: NewPayloadAnswered, _ctx: &Context<Self>) {
        self.on_new_payload_answered(answered).await;
    }
}

#[cfg(test)]
mod tests {
    use ethlambda_engine::{EngineClient, JwtSecret};
    use tokio::sync::mpsc;

    use super::*;
    use crate::events::ChainEvent;
    use crate::tests::{
        A, B, G, GENESIS_TIME, beacon_server, beacon_store, event_store, fulu_block,
        insert_event_block, set_head,
    };

    fn hash(byte: u8) -> H256 {
        H256::repeat_byte(byte)
    }

    /// A distinct root per `n`, for filling the waiting set.
    fn numbered(n: u64) -> H256 {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&n.to_be_bytes());
        H256(bytes)
    }

    fn question(slot: u64) -> PayloadQuestion {
        PayloadQuestion::Block(fulu_block(H256::ZERO, slot, 0))
    }

    /// `root` asks about payload `block_hash`, built on `parent_hash`.
    fn ask(payloads: &mut NewPayloads, root: u8, block_hash: u8, parent_hash: u8) {
        payloads.insert(
            hash(root),
            1,
            hash(block_hash),
            hash(parent_hash),
            question(1),
            None,
        );
    }

    fn sent(payloads: &mut NewPayloads) -> Option<H256> {
        payloads.next_to_send().map(|(root, _)| root)
    }

    #[test]
    fn a_payload_waits_while_the_one_it_builds_on_is_outstanding() {
        let mut payloads = NewPayloads::default();
        ask(&mut payloads, 1, 0xa1, 0xa0);
        ask(&mut payloads, 2, 0xa2, 0xa1);

        assert_eq!(sent(&mut payloads), Some(hash(1)));
        assert_eq!(sent(&mut payloads), None, "the child's parent is in flight");

        assert!(payloads.finish(&hash(1)));
        payloads.complete(&hash(1));
        assert_eq!(sent(&mut payloads), Some(hash(2)));
    }

    #[test]
    fn siblings_go_in_parallel_up_to_the_cap() {
        let mut payloads = NewPayloads::default();
        for root in 1..=MAX_NEW_PAYLOADS_IN_FLIGHT as u8 + 2 {
            ask(&mut payloads, root, 0xb0 + root, 0xa0);
        }
        for root in 1..=MAX_NEW_PAYLOADS_IN_FLIGHT as u8 {
            assert_eq!(sent(&mut payloads), Some(hash(root)));
        }
        assert_eq!(sent(&mut payloads), None, "the cap is reached");

        assert!(payloads.finish(&hash(1)));
        payloads.complete(&hash(1));
        assert_eq!(
            sent(&mut payloads),
            Some(hash(MAX_NEW_PAYLOADS_IN_FLIGHT as u8 + 1))
        );
    }

    #[test]
    fn an_unanswered_payload_holds_its_children_until_asked_again() {
        let mut payloads = NewPayloads::default();
        ask(&mut payloads, 1, 0xa1, 0xa0);
        ask(&mut payloads, 2, 0xa2, 0xa1);
        assert_eq!(sent(&mut payloads), Some(hash(1)));
        assert!(payloads.finish(&hash(1)));
        payloads.mark_unanswered(&hash(1));

        assert_eq!(sent(&mut payloads), None, "the parent is still unanswered");
        // An unreachable client answers no forkchoiceUpdated either, so the
        // unanswered payload does not hold the head back; the queued one does.
        assert_eq!(payloads.forkchoice_head(hash(0xa1)), hash(0xa1));
        assert_eq!(payloads.forkchoice_head(hash(0xa2)), hash(0xa1));

        payloads.requeue_unanswered();
        assert_eq!(sent(&mut payloads), Some(hash(1)));
    }

    #[test]
    fn forkchoice_updated_names_the_newest_payload_the_client_was_asked_about() {
        let mut payloads = NewPayloads::default();
        ask(&mut payloads, 1, 0xa1, 0xa0);
        ask(&mut payloads, 2, 0xa2, 0xa1);
        ask(&mut payloads, 3, 0xa3, 0xa2);

        // Nothing answered yet: the chain falls back to the payload the first
        // one builds on, which the client already has.
        assert_eq!(payloads.forkchoice_head(hash(0xa3)), hash(0xa0));

        assert_eq!(sent(&mut payloads), Some(hash(1)));
        assert!(payloads.finish(&hash(1)));
        payloads.complete(&hash(1));
        assert_eq!(payloads.forkchoice_head(hash(0xa3)), hash(0xa1));

        // An unanswered request does not hold the head back.
        assert_eq!(sent(&mut payloads), Some(hash(2)));
        assert!(payloads.finish(&hash(2)));
        payloads.mark_unanswered(&hash(2));
        assert_eq!(payloads.forkchoice_head(hash(0xa3)), hash(0xa2));

        // A payload nobody is waiting on is named as it is.
        assert_eq!(payloads.forkchoice_head(hash(0xff)), hash(0xff));
    }

    #[test]
    fn a_forgotten_payload_frees_its_slot_and_its_answer_is_ignored() {
        let mut payloads = NewPayloads::default();
        ask(&mut payloads, 1, 0xa1, 0xa0);
        ask(&mut payloads, 2, 0xa2, 0xa1);
        assert_eq!(sent(&mut payloads), Some(hash(1)));

        payloads.forget(&hash(1));
        assert!(!payloads.finish(&hash(1)), "nothing applies the answer");
        assert_eq!(payloads.in_flight_len(), 0);
        assert_eq!(
            sent(&mut payloads),
            Some(hash(2)),
            "the child is free to go"
        );
    }

    #[test]
    fn the_waiting_set_is_bounded() {
        let mut payloads = NewPayloads::default();
        for root in 0..MAX_PAYLOADS_AWAITING_VERDICT {
            let root = numbered(root as u64 + 1);
            payloads.insert(root, 1, root, H256::ZERO, question(1), None);
        }
        assert!(!payloads.has_room());
        payloads.forget(&numbered(1));
        assert!(payloads.has_room());
    }

    /// `A` (slot 1) and `B` (slot 2, the head) imported optimistically, with
    /// `B`'s question in flight.
    fn server_waiting_on_b() -> BlockChainServer {
        let mut store = event_store(GENESIS_TIME);
        insert_event_block(&mut store, A, 1, G, &[(0, G)]);
        insert_event_block(&mut store, B, 2, A, &[(0, G), (1, A)]);
        set_head(&mut store, B);
        store.insert_beacon_optimistic_root(A, 1);
        store.insert_beacon_optimistic_root(B, 2);
        let mut server = beacon_server(store);
        server
            .new_payloads
            .insert(B, 2, hash(0xb2), hash(0xa1), question(2), Some("gossip"));
        assert_eq!(sent(&mut server.new_payloads), Some(B));
        server
    }

    fn block_answer(validity: Result<Option<PayloadValidity>, EngineError>) -> NewPayloadAnswered {
        NewPayloadAnswered {
            root: B,
            answer: PayloadAnswer::Block(validity),
            answered_at: Instant::now(),
        }
    }

    #[test]
    fn an_answer_writes_its_request_rows_and_a_valid_one_attestable() {
        let sent = Instant::now();
        let answered = sent + std::time::Duration::from_millis(40);
        let applied = answered + std::time::Duration::from_millis(5);
        let telemetry = AnswerTelemetry {
            slot: 2,
            source: "gossip",
            sent,
            answered,
        };
        let stages = |validity: PayloadValidity| -> Vec<(&str, Instant, Option<&str>)> {
            answer_events(B, telemetry, &validity, applied)
                .into_iter()
                .map(|event| {
                    assert_eq!(
                        (event.slot, event.block_root, event.source),
                        (2, B.0, "gossip")
                    );
                    (event.stage, event.at, event.verdict)
                })
                .collect()
        };

        assert_eq!(
            stages(PayloadValidity::Validated),
            vec![
                ("el_sent", sent, None),
                ("el_verdict", answered, Some("Valid")),
                ("attestable", applied, None),
            ]
        );
        assert_eq!(
            stages(PayloadValidity::Optimistic),
            vec![
                ("el_sent", sent, None),
                ("el_verdict", answered, Some("Optimistic")),
            ],
            "still optimistic: not attestable"
        );
        let invalid = PayloadValidity::Invalidated {
            latest_valid_hash: None,
        };
        assert_eq!(
            stages(invalid),
            vec![
                ("el_sent", sent, None),
                ("el_verdict", answered, Some("Invalid")),
            ]
        );
    }

    #[test]
    fn answer_rows_need_a_measured_source_and_a_sent_request() {
        let mut payloads = NewPayloads::default();
        payloads.insert(
            hash(1),
            1,
            hash(0xa1),
            hash(0xa0),
            question(1),
            Some("sync"),
        );
        payloads.insert(hash(2), 1, hash(0xb1), hash(0xb0), question(1), None);
        assert!(
            payloads
                .answer_telemetry(&hash(1), Instant::now())
                .is_none(),
            "not sent yet"
        );
        assert!(payloads.awaits_block_answer(&hash(1)));

        assert_eq!(sent(&mut payloads), Some(hash(1)));
        let answered = Instant::now();
        let telemetry = payloads
            .answer_telemetry(&hash(1), answered)
            .expect("sent, with a source");
        assert_eq!((telemetry.slot, telemetry.source), (1, "sync"));
        assert!(telemetry.sent <= answered);

        assert_eq!(sent(&mut payloads), Some(hash(2)));
        assert!(
            payloads.answer_telemetry(&hash(2), answered).is_none(),
            "no source, no rows"
        );
        payloads.complete(&hash(1));
        assert!(!payloads.awaits_block_answer(&hash(1)));
    }

    #[tokio::test]
    async fn a_valid_answer_validates_the_block_and_its_ancestors() {
        let mut server = server_waiting_on_b();

        server
            .on_new_payload_answered(block_answer(Ok(Some(PayloadValidity::Validated))))
            .await;

        assert!(!server.store.is_beacon_optimistic(B));
        assert!(
            !server.store.is_beacon_optimistic(A),
            "ancestors go with it"
        );
        assert_eq!(server.new_payloads.len(), 0);
    }

    /// The second `head` for a head whose payload was validated after it was
    /// announced. Driven with an explicit wall-clock slot: the handler reads
    /// the real clock, against which this fixture's head is long stale.
    #[tokio::test]
    async fn a_validated_head_is_announced_again_without_the_optimistic_flag() {
        let mut server = server_waiting_on_b();
        let mut events = server.events.subscribe();
        fork_choice::mark_validated(&mut server.store, B);

        server
            .events
            .publish_beacon_head_validated(&server.store, A, 2);
        assert!(events.try_recv().is_err(), "not the announced head");

        server
            .events
            .publish_beacon_head_validated(&server.store, B, 2);
        let heads: Vec<_> = std::iter::from_fn(|| events.try_recv().ok())
            .filter_map(|event| match event {
                ChainEvent::BeaconHead(head) => Some(head),
                _ => None,
            })
            .collect();
        assert_eq!(heads.len(), 1, "{heads:?}");
        assert_eq!(heads[0].block, B);
        assert!(!heads[0].execution_optimistic);
    }

    #[tokio::test]
    async fn a_syncing_answer_leaves_the_block_optimistic() {
        let mut server = server_waiting_on_b();

        server
            .on_new_payload_answered(block_answer(Ok(Some(PayloadValidity::Optimistic))))
            .await;

        assert!(server.store.is_beacon_optimistic(B));
        assert_eq!(server.new_payloads.len(), 0, "answered, no longer waiting");
    }

    #[tokio::test]
    async fn an_invalid_answer_removes_the_block_from_fork_choice() {
        let mut server = server_waiting_on_b();

        server
            .on_new_payload_answered(block_answer(Ok(Some(PayloadValidity::Invalidated {
                latest_valid_hash: None,
            }))))
            .await;

        assert!(!server.store.has_live_chain_entry(2, &B));
        assert!(
            server.store.has_live_chain_entry(1, &A),
            "only B is condemned"
        );
    }

    #[tokio::test]
    async fn no_answer_keeps_the_block_and_asks_again_next_slot() {
        let mut server = server_waiting_on_b();

        server
            .on_new_payload_answered(block_answer(Err(EngineError::Transport("down".into()))))
            .await;

        assert!(server.store.is_beacon_optimistic(B));
        assert!(server.store.has_live_chain_entry(2, &B));
        assert_eq!(server.new_payloads.len(), 1, "still waiting");
        assert_eq!(
            sent(&mut server.new_payloads),
            None,
            "not before the next slot"
        );

        server.new_payloads.requeue_unanswered();
        assert_eq!(sent(&mut server.new_payloads), Some(B));
    }

    #[tokio::test]
    async fn an_answer_for_a_forgotten_payload_changes_nothing() {
        let mut server = server_waiting_on_b();
        server.new_payloads.forget(&B);

        server
            .on_new_payload_answered(block_answer(Ok(Some(PayloadValidity::Invalidated {
                latest_valid_hash: None,
            }))))
            .await;

        assert!(server.store.has_live_chain_entry(2, &B));
        assert_eq!(server.new_payloads.in_flight_len(), 0);
    }

    /// With the waiting set full, a block that would be imported optimistically
    /// is held instead, and goes back to the import path once room frees.
    #[tokio::test]
    async fn a_full_waiting_set_holds_the_import_until_room_frees() {
        let mut server = beacon_server(beacon_store(GENESIS_TIME, 0));
        // Never reached: the set is full, so nothing is sent.
        server.engine = Some(
            EngineClient::new("http://127.0.0.1:1".to_string(), JwtSecret::new([0u8; 32]))
                .expect("client builds"),
        );
        let (tx, _rx) = mpsc::unbounded_channel();
        server.verdict_sink = Some(VerdictSink::Channel(tx));
        // Any parent qualifies as an optimistic candidate.
        server.safe_slots_to_import_optimistically = 0;
        for root in 0..MAX_PAYLOADS_AWAITING_VERDICT {
            let root = numbered(root as u64 + 1);
            server
                .new_payloads
                .insert(root, 1, root, H256::ZERO, question(1), None);
        }

        let block = fulu_block(H256::ZERO, 1, 0);
        let block_root = block.message_hash_tree_root();
        let (_timings, outcome) = server.process_block(block, ImportTimings::default()).await;

        assert!(matches!(outcome, Ok(crate::ImportOutcome::Held)));
        assert!(server.new_payloads.is_block_awaiting_room(&block_root));
        assert!(
            server
                .store
                .get_signed_block(&block_root)
                .unwrap()
                .is_some()
        );

        server.new_payloads.forget(&numbered(1));
        server.release_blocks_awaiting_engine_room().await;
        assert!(!server.new_payloads.is_block_awaiting_room(&block_root));
    }
}
