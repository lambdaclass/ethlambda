//! Anchor-to-head forward sync for the Beacon Chain.
//!
//! Checkpoint sync anchors the node at a finalized state roughly two epochs
//! behind the live head, and `fork_choice::on_block` rejects a block whose
//! parent is not in the store. So no gossiped block at the head can be imported
//! until the slots between the anchor and that head have been fetched over
//! `beacon_blocks_by_range/2`. Getting this wrong is a failure mode this
//! project has watched other clients hit: the node tracks the tip, every block
//! it "receives" is orphaned, and justification and finalization stay frozen
//! while the head appears to climb.
//!
//! The session state is [`RangeSyncState`], lean's, unchanged except for the
//! batch cap. Only three decisions differ, and they are the functions here: how
//! wide a gap is worth closing, what goes on the wire, and the fact that the
//! session is re-armed from a timer rather than only on a peer's first
//! `Status`. A session that ends with all its peers failed must be reopenable,
//! or one bad minute ends syncing for the life of the process.

// The decisions are written and tested before the actor that drives them, so
// for exactly one commit nothing outside the tests calls into this module.
// Removed as soon as `beacon::sync` wires it up.
#![allow(dead_code)]

use std::collections::HashMap;
use std::ops::Range;
use std::time::Duration;

use libp2p::PeerId;

use crate::RangeSyncState;
use crate::beacon::messages::{BeaconBlocksByRangeRequest, MAX_REQUEST_BLOCKS_DENEB};

/// Widest anchor-to-head gap forward sync will try to close in one session.
///
/// 64 full batches, roughly 27 hours of mainnet slots. Past that the anchor is
/// too old to be worth replaying forward from and the operator wants a fresher
/// checkpoint instead.
pub(crate) const MAX_BEACON_SYNC_RANGE: u64 = MAX_REQUEST_BLOCKS_DENEB * 64;

/// Local head lag, in slots, past which the resync timer opens a session.
///
/// The same number as `ethlambda_blockchain`'s sync-lag threshold, so the node
/// starts fetching at exactly the lag at which it starts reporting itself as
/// syncing.
pub(crate) const BEACON_SYNC_LAG_THRESHOLD: u64 = 4;

/// How often the resync timer re-checks the local head against known peers.
///
/// One mainnet slot.
pub(crate) const BEACON_RESYNC_INTERVAL: Duration = Duration::from_secs(12);

/// The slots to fetch to get from `local_head_slot` to `peer_head_slot`.
///
/// `None` when the peer is at or behind us, which is the common case once the
/// gap is closed. The end is exclusive and equals `peer_head_slot + 1`, so the
/// peer's own head block is included, clamped to [`MAX_BEACON_SYNC_RANGE`].
pub(crate) fn forward_sync_range(local_head_slot: u64, peer_head_slot: u64) -> Option<Range<u64>> {
    let gap = peer_head_slot.checked_sub(local_head_slot)?;
    if gap == 0 {
        return None;
    }
    let start = local_head_slot.saturating_add(1);
    let end = start.saturating_add(gap.min(MAX_BEACON_SYNC_RANGE));
    Some(start..end)
}

/// The known peer with the highest advertised head.
///
/// Ties break on `PeerId` so the choice is deterministic, which a
/// `HashMap`-order maximum would not be.
pub(crate) fn best_peer_head(peer_heads: &HashMap<PeerId, u64>) -> Option<(PeerId, u64)> {
    peer_heads
        .iter()
        .max_by_key(|(peer, head)| (**head, **peer))
        .map(|(peer, head)| (*peer, *head))
}

/// Open a session for this peer's head, or fold the peer into the open one.
///
/// Returns `true` only when this call opened a session that did not exist,
/// which is what the caller logs.
pub(crate) fn start_or_merge(
    session: &mut Option<RangeSyncState>,
    peer: PeerId,
    peer_head_slot: u64,
    local_head_slot: u64,
) -> bool {
    let Some(range) = forward_sync_range(local_head_slot, peer_head_slot) else {
        return false;
    };
    match session {
        Some(state) => {
            state.merge_peer(peer, peer_head_slot, range.end);
            false
        }
        None => {
            *session = Some(RangeSyncState::with_max_batch(
                range,
                peer,
                peer_head_slot,
                MAX_REQUEST_BLOCKS_DENEB,
            ));
            true
        }
    }
}

/// The next request to put on the wire, with the slot range it covers.
///
/// `None` when a batch is already in flight, when the range is closed, or when
/// no remaining peer covers the range's start.
pub(crate) fn next_request(
    session: &RangeSyncState,
) -> Option<(PeerId, BeaconBlocksByRangeRequest, Range<u64>)> {
    let (peer, batch) = session.next_batch()?;
    let request = BeaconBlocksByRangeRequest::new(batch.start, batch.end - batch.start);
    Some((peer, request, batch))
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    fn peer_n(n: u8) -> PeerId {
        // Deterministic ids so the tie-break in `best_peer_head` is
        // reproducible: an ed25519 key from a fixed seed.
        let mut seed = [0u8; 32];
        seed[0] = n;
        let keypair = Keypair::ed25519_from_bytes(seed).expect("32 bytes is a valid ed25519 seed");
        PeerId::from_public_key(&keypair.public())
    }

    #[test]
    fn the_gap_runs_from_the_slot_after_the_anchor_to_the_peers_head() {
        // The anchor is at 64 and the peer's head is at 128, the two-epoch lag
        // a fresh checkpoint sync lands at.
        assert_eq!(forward_sync_range(64, 128), Some(65..129));
    }

    #[test]
    fn a_peer_at_our_head_leaves_nothing_to_fetch() {
        assert_eq!(forward_sync_range(128, 128), None);
    }

    #[test]
    fn a_peer_behind_us_leaves_nothing_to_fetch() {
        assert_eq!(forward_sync_range(128, 100), None);
    }

    #[test]
    fn an_absurd_gap_is_clamped_rather_than_attempted() {
        // A month-old anchor. Fetching it forward would take longer than
        // fetching a new checkpoint, so the session covers what it can and the
        // timer reopens it from the new head afterwards.
        let range = forward_sync_range(0, 1_000_000).expect("there is a gap");
        assert_eq!(range, 1..(1 + MAX_BEACON_SYNC_RANGE));
    }

    #[test]
    fn the_highest_head_wins_and_ties_are_deterministic() {
        let heads = HashMap::from([(peer_n(1), 100), (peer_n(2), 300), (peer_n(3), 300)]);

        let (peer, head) = best_peer_head(&heads).expect("three peers are known");

        assert_eq!(head, 300);
        assert_eq!(peer, peer_n(2).max(peer_n(3)));
    }

    #[test]
    fn no_known_peers_means_no_choice() {
        assert_eq!(best_peer_head(&HashMap::new()), None);
    }

    #[test]
    fn the_first_peer_opens_a_session_and_the_second_extends_it() {
        let mut session = None;

        assert!(start_or_merge(&mut session, peer_n(1), 128, 64));
        assert!(!start_or_merge(&mut session, peer_n(2), 200, 64));

        let state = session.expect("a session is open");
        assert_eq!(state.current_range, 65..201);
        assert_eq!(state.peer_set.len(), 2);
        assert_eq!(state.max_batch, MAX_REQUEST_BLOCKS_DENEB);
    }

    #[test]
    fn a_peer_that_is_not_ahead_never_opens_a_session() {
        let mut session = None;

        assert!(!start_or_merge(&mut session, peer_n(1), 64, 64));

        assert!(session.is_none(), "there is nothing to sync");
    }

    #[test]
    fn a_short_gap_is_one_request_for_exactly_the_gap() {
        let mut session = None;
        start_or_merge(&mut session, peer_n(1), 128, 64);

        let (peer, request, batch) =
            next_request(session.as_ref().unwrap()).expect("a batch is available");

        assert_eq!(peer, peer_n(1));
        assert_eq!(request.start_slot, 65);
        assert_eq!(request.count, 64, "the whole gap fits in one request");
        assert_eq!(request.step, 1, "the spec fixes the deprecated step at 1");
        assert_eq!(batch, 65..129);
    }

    #[test]
    fn a_long_gap_is_capped_at_the_protocol_limit() {
        let mut session = None;
        start_or_merge(&mut session, peer_n(1), 5_000, 64);

        let (_, request, batch) =
            next_request(session.as_ref().unwrap()).expect("a batch is available");

        assert_eq!(request.count, MAX_REQUEST_BLOCKS_DENEB);
        assert_eq!(batch, 65..(65 + MAX_REQUEST_BLOCKS_DENEB));
    }

    #[test]
    fn a_batch_never_reaches_past_the_chosen_peers_own_head() {
        // The high-head peer opened the range; only the low-head peer survives.
        // Asking it for slots it cannot have would waste a round trip.
        let mut session = None;
        start_or_merge(&mut session, peer_n(1), 5_000, 64);
        start_or_merge(&mut session, peer_n(2), 100, 64);
        session.as_mut().unwrap().fail_peer(&peer_n(1));

        let (peer, request, _) =
            next_request(session.as_ref().unwrap()).expect("the surviving peer can serve");

        assert_eq!(peer, peer_n(2));
        assert_eq!(request.start_slot, 65);
        assert_eq!(request.count, 36, "slots 65..=100, and no further");
    }

    #[test]
    fn a_batch_in_flight_blocks_the_next_one() {
        let mut session = None;
        start_or_merge(&mut session, peer_n(1), 5_000, 64);
        session.as_mut().unwrap().in_flight = true;

        assert!(next_request(session.as_ref().unwrap()).is_none());
    }

    #[test]
    fn a_completed_batch_advances_the_range_and_frees_the_next() {
        let mut session = None;
        start_or_merge(&mut session, peer_n(1), 5_000, 64);
        let (_, _, batch) = next_request(session.as_ref().unwrap()).unwrap();
        session.as_mut().unwrap().in_flight = true;

        session.as_mut().unwrap().complete_batch(batch.end - 1);

        let (_, request, _) =
            next_request(session.as_ref().unwrap()).expect("the next batch follows on");
        assert_eq!(request.start_slot, batch.end);
        assert_eq!(request.count, MAX_REQUEST_BLOCKS_DENEB);
    }

    #[test]
    fn a_failed_peer_is_rotated_out_and_the_batch_reissued_to_another() {
        let mut session = None;
        start_or_merge(&mut session, peer_n(1), 5_000, 64);
        start_or_merge(&mut session, peer_n(2), 5_000, 64);
        let (chosen, _, _) = next_request(session.as_ref().unwrap()).unwrap();
        session.as_mut().unwrap().in_flight = true;

        session.as_mut().unwrap().fail_peer(&chosen);

        let (retry_peer, request, _) =
            next_request(session.as_ref().unwrap()).expect("the other peer takes over");
        assert_ne!(retry_peer, chosen);
        assert_eq!(
            request.start_slot, 65,
            "the failed batch is reissued from the same slot, not skipped"
        );
    }

    #[test]
    fn the_last_peer_failing_empties_the_session() {
        let mut session = None;
        start_or_merge(&mut session, peer_n(1), 5_000, 64);

        session.as_mut().unwrap().fail_peer(&peer_n(1));

        assert!(
            session.as_ref().unwrap().peer_set.is_empty(),
            "the caller drops the session on an empty peer set and the resync \
             timer reopens it when a peer reappears"
        );
        assert!(next_request(session.as_ref().unwrap()).is_none());
    }
}
