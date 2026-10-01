//! The client side of the gloas execution payload envelope protocols: asking
//! peers for envelopes by root, and alongside range sync batches by range.
//!
//! The server side is in [`super::envelopes`]. Everything fetched here goes
//! through `beacon::envelope_checks` before the chain actor sees it.

use std::collections::HashSet;
use std::time::Duration;

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::containers::gloas::SignedExecutionPayloadEnvelope;
use ethlambda_types::primitives::H256;
use libp2p::PeerId;
use spawned_concurrency::tasks::{Context, send_after};
use tracing::{debug, error, trace};

use super::Request;
use super::handlers::{choose_fetch_peer, request_next_beacon_range_batch, retire_root_attempt};
use crate::beacon::decode::fork_at_slot;
use crate::beacon::envelope_checks;
use crate::beacon::messages::ExecutionPayloadEnvelopesByRangeRequest;
use crate::beacon::protocols::{MAX_REQUEST_BLOCKS_DENEB, MAX_REQUEST_PAYLOADS};
use crate::{P2PServer, PendingRequest, PendingRequestKind, ReqRespProtocol, p2p_protocol};

// A range request is clamped to the smaller of the two ceilings, so a block
// batch is never wider than its envelope request can answer for.
const _: () = assert!(MAX_REQUEST_PAYLOADS >= MAX_REQUEST_BLOCKS_DENEB);

/// What one failed attempt at an envelope lookup leaves to do.
#[derive(Debug, PartialEq, Eq)]
enum FailedAttempt {
    /// Ask again after the backoff.
    Retry(Duration),
    /// The ladder is exhausted and the lookup is retired.
    GaveUp,
    /// Nothing is waiting on this root: a late or duplicate failure.
    Stale,
}

/// Charge `peer` with a failed attempt at `block_root`'s envelope, retiring the
/// lookup when the ladder runs out.
fn fail_envelope_attempt(server: &mut P2PServer, block_root: H256, peer: PeerId) -> FailedAttempt {
    let Some(pending) = server.pending_envelope_requests.get_mut(&block_root) else {
        return FailedAttempt::Stale;
    };
    let attempts = pending.attempts;
    match retire_root_attempt(pending, peer) {
        Some(backoff) => {
            debug!(%block_root, %peer, attempts, ?backoff, "Envelope fetch failed, scheduling retry");
            FailedAttempt::Retry(backoff)
        }
        None => {
            error!(%block_root, %peer, attempts,
                   "Envelope fetch failed after max retries, giving up");
            server.pending_envelope_requests.remove(&block_root);
            FailedAttempt::GaveUp
        }
    }
}

/// Retire one failed attempt at fetching `block_root`'s envelope.
///
/// [`handle_fetch_failure`]'s counterpart, with the same invariant: every path
/// that ends an attempt comes through here, or the root stays in
/// `pending_envelope_requests` and deduplicates every later ask for it. A
/// lookup that gives up is not lost for good: the chain actor asks again each
/// slot for every parent still missing its envelope.
pub(super) async fn handle_envelope_fetch_failure(
    server: &mut P2PServer,
    block_root: H256,
    peer: PeerId,
    ctx: &Context<P2PServer>,
) {
    if let FailedAttempt::Retry(backoff) = fail_envelope_attempt(server, block_root, peer) {
        send_after(
            backoff,
            ctx.clone(),
            p2p_protocol::RetryEnvelopeFetch { block_root },
        );
    }
}

/// Let range sync go on after a gloas batch's envelopes: whether they were
/// delivered, refused, or never came. Does nothing when no batch is waiting.
pub(crate) async fn release_envelope_gate(server: &mut P2PServer, ctx: &Context<P2PServer>) {
    let Some(state) = &mut server.range_sync_state else {
        return;
    };
    if !std::mem::take(&mut state.envelopes_pending) {
        return;
    }
    request_next_beacon_range_batch(server, ctx).await;
}

/// Fetch the envelope of `block_root` from a random connected peer.
///
/// [`fetch_block_from_peer`]'s counterpart for envelopes: same peer choice, and
/// the `pending_envelope_requests` entry is what dedupes a repeated ask and
/// what the retry path reads. Beacon-only, since the lean wire has no
/// envelopes. Returns whether a request went out.
pub async fn fetch_envelope_from_peer(server: &mut P2PServer, block_root: H256) -> bool {
    if !server.wire.is_beacon() {
        debug!(%block_root, "Cannot fetch an envelope on the lean wire");
        return false;
    }
    if server.connected_peers.is_empty() {
        debug!(%block_root, "Cannot fetch envelope: no connected peers");
        return false;
    }

    let Some((peer, excluded)) = choose_fetch_peer(
        &server.connected_peers,
        server
            .pending_envelope_requests
            .get_mut(&block_root)
            .map(|pending| &mut pending.failed_peers),
        &block_root,
    ) else {
        debug!(%block_root, "Failed to select random peer");
        return false;
    };

    trace!(%peer, %block_root, excluded, "Sending ExecutionPayloadEnvelopesByRoot request");
    let Some(request_id) = server
        .swarm_handle
        .send_request(
            peer,
            Request::ExecutionPayloadEnvelopesByRoot(vec![block_root]),
            ReqRespProtocol::ExecutionPayloadEnvelopesByRoot,
        )
        .await
    else {
        debug!(%block_root, "Failed to send ExecutionPayloadEnvelopesByRoot request (swarm adapter closed)");
        return false;
    };
    server
        .outbound_requests
        .insert(request_id, PendingRequestKind::EnvelopeRoot(block_root));
    server
        .pending_envelope_requests
        .entry(block_root)
        .or_insert(PendingRequest {
            attempts: 1,
            failed_peers: HashSet::new(),
        });
    true
}

/// Keep the envelopes of `envelopes` that answer a by-root request for
/// `block_root`. Returns them with how many were dropped.
///
/// Mirrors [`retain_requested_columns`]: nothing downstream asks whether an
/// envelope was wanted, so an unsolicited one would otherwise be checked and
/// handed to the chain actor on a peer's say-so.
fn retain_requested_envelopes(
    envelopes: Vec<SignedExecutionPayloadEnvelope>,
    block_root: H256,
) -> (Vec<SignedExecutionPayloadEnvelope>, usize) {
    let received = envelopes.len();
    let kept: Vec<_> = envelopes
        .into_iter()
        .filter(|envelope| envelope.message.beacon_block_root == block_root)
        .collect();
    let dropped = received - kept.len();
    (kept, dropped)
}

/// Take delivery of an `ExecutionPayloadEnvelopesByRoot` answer.
///
/// An answer with no envelope for the requested root, an empty one included, is
/// a failed attempt and goes through [`handle_envelope_fetch_failure`], the
/// same way a block-by-root answer does. What does match goes through the
/// envelope checks (`beacon::envelope_checks`), which hand the chain actor the
/// ones that pass.
pub(super) async fn handle_envelopes_by_root_response(
    server: &mut P2PServer,
    peer: PeerId,
    block_root: H256,
    envelopes: Vec<SignedExecutionPayloadEnvelope>,
    ctx: &Context<P2PServer>,
) {
    match settle_by_root_answer(server, peer, block_root, envelopes) {
        ByRootAnswer::Forward(envelopes) => {
            if server.blockchain.is_none() {
                debug!(%peer, %block_root, "No blockchain handler available");
                return;
            }
            envelope_checks::check_and_forward(server, envelopes);
        }
        ByRootAnswer::Failed(FailedAttempt::Retry(backoff)) => {
            send_after(
                backoff,
                ctx.clone(),
                p2p_protocol::RetryEnvelopeFetch { block_root },
            );
        }
        ByRootAnswer::Failed(FailedAttempt::GaveUp | FailedAttempt::Stale) => {}
    }
}

/// What a by-root answer comes to.
#[derive(Debug, PartialEq)]
enum ByRootAnswer {
    /// The envelopes that answer the request; the lookup is retired.
    Forward(Vec<SignedExecutionPayloadEnvelope>),
    /// Nothing answered it: an attempt is spent.
    Failed(FailedAttempt),
}

fn settle_by_root_answer(
    server: &mut P2PServer,
    peer: PeerId,
    block_root: H256,
    envelopes: Vec<SignedExecutionPayloadEnvelope>,
) -> ByRootAnswer {
    let received = envelopes.len();
    trace!(%peer, %block_root, received, "Received ExecutionPayloadEnvelopesByRoot response");

    let (envelopes, unrequested) = retain_requested_envelopes(envelopes, block_root);
    if unrequested > 0 {
        debug!(
            %peer,
            %block_root,
            unrequested,
            "Dropping envelopes the ExecutionPayloadEnvelopesByRoot request did not ask for"
        );
    }

    if envelopes.is_empty() {
        debug!(%peer, %block_root, "ExecutionPayloadEnvelopesByRoot response carried no matching envelope");
        return ByRootAnswer::Failed(fail_envelope_attempt(server, block_root, peer));
    }

    server.pending_envelope_requests.remove(&block_root);
    ByRootAnswer::Forward(envelopes)
}

/// Whether a range sync batch over `span` can contain a gloas block, and so an
/// envelope worth asking for. Earlier forks have no envelopes, and the server
/// answers such a request empty at best.
fn range_reaches_gloas(config: &Config, span: &std::ops::RangeInclusive<u64>) -> bool {
    fork_at_slot(config, *span.end()).has_payload_envelopes()
}

/// Ask `peer` for the envelopes in `[start_slot, start_slot + count)`, the span
/// of a `BeaconBlocksByRange` answer that was just handed to the chain actor.
///
/// Sent after that answer rather than beside the blocks request, so the
/// ordering the chain actor needs does not depend on which of two streams
/// finishes first: the blocks are already in its mailbox when this request
/// goes out, and its answer is forwarded by a task spawned later still, so
/// the actor sees every envelope after the blocks of the batch (its mailbox is
/// FIFO). It never holds the batch's block delivery on this answer.
///
/// The chain actor keeps an envelope whose block has not imported only
/// briefly and in small numbers, so range delivery relies on the batches
/// reaching it in order. A batch's envelopes must therefore land before the
/// next batch's blocks do, and the next request is held back until the answer
/// has been checked and forwarded: this sets
/// `RangeSyncState::envelopes_pending`, and [`release_envelope_gate`] clears
/// it. An envelope the answer lacks is asked for by root once its block is a
/// parent missing one.
///
/// Returns whether a request went out, which is also whether range sync is now
/// waiting on it. Does nothing for a span that ends before gloas.
pub(crate) async fn request_beacon_envelopes_by_range(
    server: &mut P2PServer,
    peer: PeerId,
    start_slot: u64,
    count: u64,
) -> bool {
    let Some(wire) = server.wire.beacon() else {
        return false;
    };
    // The ceiling the server truncates to, so the span recorded below is the
    // one the peer actually answers for.
    let count = count.min(MAX_REQUEST_PAYLOADS);
    if count == 0 {
        return false;
    }
    let end_slot = start_slot.saturating_add(count - 1);
    if !range_reaches_gloas(&wire.config, &(start_slot..=end_slot)) {
        return false;
    }

    trace!(%peer, start_slot, count, "Sending ExecutionPayloadEnvelopesByRange request");
    let request = ExecutionPayloadEnvelopesByRangeRequest { start_slot, count };
    let Some(request_id) = server
        .swarm_handle
        .send_request(
            peer,
            Request::ExecutionPayloadEnvelopesByRange(request),
            ReqRespProtocol::ExecutionPayloadEnvelopesByRange,
        )
        .await
    else {
        debug!(%peer, "Failed to send ExecutionPayloadEnvelopesByRange request (swarm adapter closed)");
        return false;
    };
    server.outbound_requests.insert(
        request_id,
        PendingRequestKind::EnvelopeRange {
            start_slot,
            end_slot,
        },
    );
    if let Some(state) = &mut server.range_sync_state {
        state.envelopes_pending = true;
    }
    true
}

/// Keep the envelopes of a range answer that fall in `[start_slot, end_slot]`,
/// in slot order, with how many were dropped. An envelope outside the span is
/// dropped on its own rather than failing the answer, the way a block outside
/// its range is. The sort is what lets the chain actor see a parent's envelope
/// before its child's.
fn retain_envelopes_in_range(
    envelopes: Vec<SignedExecutionPayloadEnvelope>,
    start_slot: u64,
    end_slot: u64,
) -> (Vec<SignedExecutionPayloadEnvelope>, usize) {
    let received = envelopes.len();
    let mut kept: Vec<_> = envelopes
        .into_iter()
        .filter(|envelope| (start_slot..=end_slot).contains(&envelope.message.payload.slot_number))
        .collect();
    kept.sort_by_key(|envelope| envelope.message.payload.slot_number);
    let dropped = received - kept.len();
    (kept, dropped)
}

/// Take delivery of an `ExecutionPayloadEnvelopesByRange` answer.
///
/// No retry, unlike the by-root path: a short or empty answer is not an
/// attempt spent, and the envelopes it lacks are asked for by root, since the
/// chain actor re-asks every slot for each parent still missing one. Range
/// sync is released once the answer has been forwarded, or at once when there
/// is nothing to forward.
pub(super) async fn handle_envelopes_by_range_response(
    server: &mut P2PServer,
    peer: PeerId,
    start_slot: u64,
    end_slot: u64,
    envelopes: Vec<SignedExecutionPayloadEnvelope>,
    ctx: &Context<P2PServer>,
) {
    let received = envelopes.len();
    trace!(%peer, start_slot, end_slot, received, "Received ExecutionPayloadEnvelopesByRange response");

    if server.blockchain.is_none() {
        debug!(%peer, "No blockchain handler available");
        release_envelope_gate(server, ctx).await;
        return;
    }

    let (envelopes, dropped) = retain_envelopes_in_range(envelopes, start_slot, end_slot);
    if dropped > 0 {
        debug!(%peer, start_slot, end_slot, dropped, "Dropping out-of-range envelopes");
    }
    let resume = ctx.clone();
    let done: envelope_checks::Done = Box::new(move || {
        send_after(
            Duration::ZERO,
            resume,
            p2p_protocol::ResumeRangeAfterEnvelopes,
        );
    });
    envelope_checks::check_and_forward_then(server, envelopes, Some(done));
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    use ethlambda_network_api::{BlockArrival, BlockSource};
    use ethlambda_types::beacon::containers::SignedBeaconBlock;
    use ethlambda_types::beacon::fork::ForkName;

    use super::*;
    use crate::req_resp::handlers::tests::unconnected_server;
    use crate::{BACKOFF_MULTIPLIER, ConnectionDirection, INITIAL_BACKOFF_MS, MAX_FETCH_RETRIES};

    fn envelope_for(slot: u64, block_root: H256) -> SignedExecutionPayloadEnvelope {
        crate::beacon::encoding::test_support::envelope(block_root, slot, H256::ZERO)
    }

    fn fulu_block_at(slot: u64) -> SignedBeaconBlock {
        use ethlambda_types::beacon::containers::electra;
        SignedBeaconBlock::Fulu(electra::SignedBeaconBlock {
            message: electra::BeaconBlock {
                slot,
                proposer_index: 0,
                parent_root: H256::ZERO,
                state_root: H256::ZERO,
                body: electra::BeaconBlockBody::empty(),
            },
            signature: Default::default(),
        })
    }

    #[test]
    fn a_by_root_envelope_answer_keeps_only_the_requested_root() {
        let asked = H256::repeat_byte(1);
        let other = H256::repeat_byte(2);
        let answer = vec![envelope_for(5, other), envelope_for(5, asked)];

        let (kept, dropped) = retain_requested_envelopes(answer, asked);

        assert_eq!(kept, vec![envelope_for(5, asked)]);
        assert_eq!(dropped, 1);
    }

    #[test]
    fn a_range_envelope_answer_keeps_the_span_in_slot_order() {
        let root = H256::repeat_byte(1);
        let answer = vec![
            envelope_for(12, root),
            envelope_for(9, root),
            envelope_for(10, root),
            envelope_for(11, root),
        ];

        let (kept, dropped) = retain_envelopes_in_range(answer, 10, 11);

        let slots: Vec<u64> = kept
            .iter()
            .map(|envelope| envelope.message.payload.slot_number)
            .collect();
        assert_eq!(slots, vec![10, 11]);
        assert_eq!(dropped, 2);
    }

    #[test]
    fn only_a_span_reaching_gloas_asks_for_envelopes() {
        let config = Config::mainnet().with_fork_epoch(ForkName::Gloas, 10);
        let first_gloas_slot = 10 * ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;

        assert!(!range_reaches_gloas(&config, &(0..=first_gloas_slot - 1)));
        // A span that starts before gloas and ends inside it overlaps.
        assert!(range_reaches_gloas(
            &config,
            &(first_gloas_slot - 3..=first_gloas_slot)
        ));
        assert!(range_reaches_gloas(
            &config,
            &(first_gloas_slot + 5..=first_gloas_slot + 9)
        ));
        // A chain with no gloas scheduled never does.
        assert!(!range_reaches_gloas(
            &Config::mainnet(),
            &(0..=u64::MAX / 2)
        ));
    }

    #[test]
    fn an_envelope_lookup_backs_off_by_doubling_then_gives_up() {
        let mut pending = PendingRequest {
            attempts: 1,
            failed_peers: HashSet::new(),
        };
        let peer = PeerId::random();

        let first = retire_root_attempt(&mut pending, peer).expect("first retry");
        let second = retire_root_attempt(&mut pending, peer).expect("second retry");

        assert_eq!(first, Duration::from_millis(INITIAL_BACKOFF_MS));
        assert_eq!(second, first * BACKOFF_MULTIPLIER as u32);
        assert!(pending.failed_peers.contains(&peer));
        assert_eq!(pending.attempts, 3);

        pending.attempts = MAX_FETCH_RETRIES;
        assert_eq!(retire_root_attempt(&mut pending, peer), None);
    }

    #[test]
    fn a_failed_peer_is_skipped_until_every_peer_has_failed() {
        let root = H256::repeat_byte(1);
        let (a, b) = (PeerId::random(), PeerId::random());
        let connected: HashMap<PeerId, ()> = [(a, ()), (b, ())].into();
        let mut failed: HashSet<PeerId> = [a].into();

        for _ in 0..16 {
            assert_eq!(
                choose_fetch_peer(&connected, Some(&mut failed), &root),
                Some((b, 1))
            );
        }

        // With every peer failed the set is cleared, so a new round starts.
        failed.insert(b);
        let (_, excluded) = choose_fetch_peer(&connected, Some(&mut failed), &root).unwrap();
        assert_eq!(excluded, 0);
        assert!(failed.is_empty());

        assert_eq!(choose_fetch_peer::<()>(&HashMap::new(), None, &root), None);
    }

    #[tokio::test]
    async fn an_envelope_fetch_with_nobody_to_ask_leaves_nothing_pending() {
        let mut server = crate::test_support::unconnected_beacon_server(Config::mainnet(), 0).await;

        let sent = fetch_envelope_from_peer(&mut server, H256::repeat_byte(1)).await;

        assert!(!sent);
        assert!(server.pending_envelope_requests.is_empty());
        assert!(server.outbound_requests.is_empty());
    }

    #[tokio::test]
    async fn an_envelope_fetch_on_the_lean_wire_sends_nothing() {
        let mut server = unconnected_server().await;
        server
            .connected_peers
            .insert(PeerId::random(), ConnectionDirection::Inbound);

        assert!(!fetch_envelope_from_peer(&mut server, H256::repeat_byte(1)).await);
        assert!(server.pending_envelope_requests.is_empty());
    }

    /// One request goes out per root however often the chain actor asks, and
    /// it names the root alone.
    #[tokio::test]
    async fn an_envelope_fetch_is_tracked_and_deduplicated() {
        let mut server = crate::test_support::unconnected_beacon_server(Config::mainnet(), 0).await;
        server
            .connected_peers
            .insert(PeerId::random(), ConnectionDirection::Outbound);
        let root = H256::repeat_byte(7);

        crate::fetch_missing_envelope(&mut server, root).await;
        crate::fetch_missing_envelope(&mut server, root).await;

        assert_eq!(server.pending_envelope_requests[&root].attempts, 1);
        let asked: Vec<_> = server.outbound_requests.iter().collect();
        assert_eq!(
            asked.len(),
            1,
            "a duplicate ask must not send a second request"
        );
        let (id, kind) = asked[0];
        assert_eq!(
            id.protocol,
            ReqRespProtocol::ExecutionPayloadEnvelopesByRoot
        );
        assert!(matches!(kind, PendingRequestKind::EnvelopeRoot(r) if *r == root));
    }

    #[tokio::test]
    async fn a_range_batch_asks_for_envelopes_only_where_gloas_overlaps() {
        let config = Config::mainnet().with_fork_epoch(ForkName::Gloas, 10);
        let first_gloas_slot = 10 * ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;
        let mut server = crate::test_support::unconnected_beacon_server(config, 0).await;
        let peer = PeerId::random();
        server
            .connected_peers
            .insert(peer, ConnectionDirection::Outbound);

        server.range_sync_state = Some(crate::RangeSyncState::new(0..100_000, peer, 99_999));

        assert!(!request_beacon_envelopes_by_range(&mut server, peer, 0, 64).await);
        assert!(server.outbound_requests.is_empty());
        // Pre-gloas pacing is unchanged: the next batch is not held back.
        let state = server.range_sync_state.as_ref().unwrap();
        assert!(!state.envelopes_pending);
        assert!(state.next_batch().is_some());

        // The span is clamped to what the peer will answer for.
        assert!(
            request_beacon_envelopes_by_range(&mut server, peer, first_gloas_slot, 1_000).await
        );
        let (id, kind) = server.outbound_requests.iter().next().unwrap();
        assert_eq!(
            id.protocol,
            ReqRespProtocol::ExecutionPayloadEnvelopesByRange
        );
        assert!(matches!(
            kind,
            PendingRequestKind::EnvelopeRange { start_slot, end_slot }
                if *start_slot == first_gloas_slot
                    && *end_slot == first_gloas_slot + MAX_REQUEST_PAYLOADS - 1
        ));
        // A gloas span holds the next batch back until its answer is delivered.
        let state = server.range_sync_state.as_mut().unwrap();
        assert!(state.envelopes_pending);
        assert!(state.next_batch().is_none());
        state.envelopes_pending = false;
        assert!(state.next_batch().is_some());
    }

    /// The release runs the completion callback even with nothing to forward,
    /// or no chain to forward to, so range sync cannot wait forever.
    #[tokio::test]
    async fn the_range_release_fires_when_there_is_nothing_to_forward() {
        use crate::beacon::envelope_checks::tests::Recorder;

        let mut server = crate::test_support::unconnected_beacon_server(Config::mainnet(), 0).await;
        let (done_tx, mut done_rx) = tokio::sync::mpsc::unbounded_channel();
        let callback = |tx: tokio::sync::mpsc::UnboundedSender<()>| -> envelope_checks::Done {
            Box::new(move || {
                let _ = tx.send(());
            })
        };

        // No chain actor.
        envelope_checks::check_and_forward_then(
            &server,
            vec![envelope_for(7, H256::repeat_byte(1))],
            Some(callback(done_tx.clone())),
        );
        assert_eq!(done_rx.recv().await, Some(()));

        // An empty answer.
        let (sender, _received) = tokio::sync::mpsc::unbounded_channel();
        server.blockchain = Some(Arc::new(Recorder(sender)));
        envelope_checks::check_and_forward_then(&server, Vec::new(), Some(callback(done_tx)));
        assert_eq!(done_rx.recv().await, Some(()));
    }

    fn pending_lookup(server: &mut P2PServer, root: H256, attempts: u32) {
        server.pending_envelope_requests.insert(
            root,
            PendingRequest {
                attempts,
                failed_peers: HashSet::new(),
            },
        );
    }

    /// An empty or non-matching by-root answer spends an attempt and schedules
    /// a retry after the first rung of the backoff; a good one retires the
    /// lookup and is forwarded.
    #[tokio::test]
    async fn a_by_root_answer_without_the_envelope_schedules_a_retry() {
        let mut server = crate::test_support::unconnected_beacon_server(Config::mainnet(), 0).await;
        let root = H256::repeat_byte(4);
        let peer = PeerId::random();
        pending_lookup(&mut server, root, 1);

        let empty = settle_by_root_answer(&mut server, peer, root, Vec::new());
        assert_eq!(
            empty,
            ByRootAnswer::Failed(FailedAttempt::Retry(Duration::from_millis(
                INITIAL_BACKOFF_MS
            )))
        );
        assert_eq!(server.pending_envelope_requests[&root].attempts, 2);
        assert!(
            server.pending_envelope_requests[&root]
                .failed_peers
                .contains(&peer)
        );

        // An envelope for another root is as good as none.
        let wrong = settle_by_root_answer(
            &mut server,
            peer,
            root,
            vec![envelope_for(9, H256::repeat_byte(5))],
        );
        assert!(matches!(
            wrong,
            ByRootAnswer::Failed(FailedAttempt::Retry(_))
        ));

        let good = settle_by_root_answer(&mut server, peer, root, vec![envelope_for(9, root)]);
        assert_eq!(good, ByRootAnswer::Forward(vec![envelope_for(9, root)]));
        assert!(server.pending_envelope_requests.is_empty());
    }

    #[tokio::test]
    async fn a_by_root_lookup_gives_up_when_the_ladder_is_spent() {
        let mut server = crate::test_support::unconnected_beacon_server(Config::mainnet(), 0).await;
        let root = H256::repeat_byte(4);
        pending_lookup(&mut server, root, MAX_FETCH_RETRIES);

        let outcome = fail_envelope_attempt(&mut server, root, PeerId::random());

        assert_eq!(outcome, FailedAttempt::GaveUp);
        assert!(server.pending_envelope_requests.is_empty());
        // A late failure for a retired lookup is ignored.
        assert_eq!(
            fail_envelope_attempt(&mut server, root, PeerId::random()),
            FailedAttempt::Stale
        );
    }

    /// The range answer reaches the chain actor after the blocks the batch
    /// handed it, and in slot order, whichever order the peer listed them.
    #[tokio::test]
    async fn range_envelopes_are_forwarded_after_the_batch_blocks_in_slot_order() {
        use crate::beacon::envelope_checks::tests::{Recorder, Seen};

        let mut server = crate::test_support::unconnected_beacon_server(Config::mainnet(), 0).await;
        let (sender, mut received) = tokio::sync::mpsc::unbounded_channel();
        let chain = Arc::new(Recorder(sender));
        server.blockchain = Some(chain.clone());
        let root = H256::repeat_byte(3);

        // What `handle_beacon_blocks_by_range_response` does before it asks
        // for the span's envelopes.
        for slot in [20, 21] {
            let _ = ethlambda_network_api::P2PToBlockChain::new_block(
                chain.as_ref(),
                fulu_block_at(slot),
                BlockSource::Sync,
                BlockArrival::now(),
                ethlambda_network_api::BlockAnnouncement::Silent,
            );
        }
        // The handler's own steps, less the actor `Context` it also needs for
        // the release message: filter to the span in slot order, then check
        // and forward with a completion callback.
        let (answer, _) =
            retain_envelopes_in_range(vec![envelope_for(21, root), envelope_for(20, root)], 20, 21);
        let (done_tx, mut done_rx) = tokio::sync::mpsc::unbounded_channel();
        envelope_checks::check_and_forward_then(
            &server,
            answer,
            Some(Box::new(move || {
                let _ = done_tx.send(());
            })),
        );

        assert_eq!(received.recv().await, Some(Seen::Block(20)));
        assert_eq!(received.recv().await, Some(Seen::Block(21)));
        assert_eq!(received.recv().await, Some(Seen::Envelope(root, 20)));
        assert_eq!(received.recv().await, Some(Seen::Envelope(root, 21)));
        // The release comes only after the last envelope was sent.
        assert_eq!(done_rx.recv().await, Some(()));
    }
}
