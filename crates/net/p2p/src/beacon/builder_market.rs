//! Gloas builder market gossip: the `execution_payload_bid` and
//! `proposer_preferences` topics.
//!
//! Neither message type ever reaches the chain actor: the
//! rules live in `ethlambda_state_transition::beacon::gossip::{
//! execution_payload_bid, proposer_preferences}`, and what they accept is
//! recorded in the node's shared `BuilderMarket` by the verdict.

use ethlambda_state_transition::beacon::gossip::{
    self, Outcome, RejectReason, execution_payload_bid::MAX_SIGNED_EXECUTION_PAYLOAD_BID_SIZE_HEZE,
};
use ethlambda_types::beacon::containers::gloas::{
    SignedExecutionPayloadBid, SignedProposerPreferences,
};
use ethlambda_types::beacon::primitives::Slot;
use ethlambda_types::time::unix_now_ms;
use libp2p::gossipsub::IdentTopic;
use libssz::SszEncode;
use tracing::{debug, error, info, warn};

use crate::beacon::verdict::{Dispatch, Validated};
use crate::beacon::{decode as beacon_decode, topics as beacon_topics};
use crate::gossipsub::compress_message;
use crate::{P2PServer, metrics};

/// Decode a gloas execution payload bid and run its cheap gossip checks.
///
/// The size cap is the specification's decompressed bound, applied before any
/// decode so an oversized payload costs nothing. Same shape as the envelope's
/// triage, except the seen state lives in the shared
/// [`BuilderMarket`](ethlambda_state_transition::beacon::builder_market::BuilderMarket),
/// and the object carries the market on to its stateful checks.
pub(crate) fn triage_execution_payload_bid(server: &P2PServer, payload: &[u8]) -> Dispatch {
    const KIND: &str = beacon_topics::EXECUTION_PAYLOAD_BID;
    if payload.len() > MAX_SIGNED_EXECUTION_PAYLOAD_BID_SIZE_HEZE {
        metrics::inc_beacon_gossip(KIND, "decode_failed");
        debug!(
            kind = KIND,
            bytes = payload.len(),
            "Beacon gossip payload over the size cap"
        );
        return Dispatch::Report(Outcome::Reject(RejectReason::Malformed));
    }
    let bid = match beacon_decode::decode_execution_payload_bid(payload) {
        Ok(bid) => bid,
        Err(err) => {
            metrics::inc_beacon_gossip(KIND, "decode_failed");
            debug!(kind = KIND, %err, bytes = payload.len(), "Beacon gossip decode failed");
            return Dispatch::Report(Outcome::Reject(RejectReason::Decode));
        }
    };
    metrics::inc_beacon_gossip(KIND, "decoded");
    debug!(
        slot = bid.message.slot,
        builder_index = bid.message.builder_index,
        value = bid.message.value,
        bytes = payload.len(),
        "Beacon execution payload bid decoded"
    );
    if let Err(outcome) = gossip::execution_payload_bid::cheap_checks(
        &server.builder_market,
        &server.store,
        &bid,
        unix_now_ms(),
    ) {
        return Dispatch::Report(outcome);
    }
    Dispatch::Validate(Validated::ExecutionPayloadBid {
        bid: Box::new(bid),
        market: server.builder_market.clone(),
    })
}

/// As [`triage_execution_payload_bid`], for `proposer_preferences`. The
/// container is fixed-size, so decode is its own size check.
pub(crate) fn triage_proposer_preferences(server: &P2PServer, payload: &[u8]) -> Dispatch {
    const KIND: &str = beacon_topics::PROPOSER_PREFERENCES;
    let preferences = match beacon_decode::decode_proposer_preferences(payload) {
        Ok(preferences) => preferences,
        Err(err) => {
            metrics::inc_beacon_gossip(KIND, "decode_failed");
            debug!(kind = KIND, %err, bytes = payload.len(), "Beacon gossip decode failed");
            return Dispatch::Report(Outcome::Reject(RejectReason::Decode));
        }
    };
    metrics::inc_beacon_gossip(KIND, "decoded");
    debug!(
        proposal_slot = preferences.message.proposal_slot,
        validator_index = preferences.message.validator_index,
        bytes = payload.len(),
        "Beacon proposer preferences decoded"
    );
    if let Err(outcome) = gossip::proposer_preferences::cheap_checks(
        &server.builder_market,
        &server.store,
        &preferences,
        unix_now_ms(),
    ) {
        return Dispatch::Report(outcome);
    }
    Dispatch::Validate(Validated::ProposerPreferences(Box::new(preferences)))
}

/// Where and what to publish for one of this module's messages: the topic of
/// `kind` under the digest `slot` names, and the compressed SSZ. `None` when
/// this node is not on the beacon wire or holds no digest covering `slot`.
///
/// Split from the publish functions so the topic and digest choice can be
/// checked without a swarm to read the command back from.
fn publication(
    server: &P2PServer,
    kind: &'static str,
    slot: Slot,
    ssz: &[u8],
) -> Option<(IdentTopic, Vec<u8>)> {
    let Some(beacon) = server.wire.beacon() else {
        error!(
            kind,
            slot, "A builder market message reached a lean node; dropping it"
        );
        return None;
    };
    let Some(digest) = beacon.publish_digest(slot) else {
        warn!(
            kind,
            slot, "No held fork digest covers this message's slot; not publishing"
        );
        return None;
    };
    let topic = IdentTopic::new(beacon_topics::topic_name(digest, kind));
    Some((topic, compress_message(ssz)))
}

/// Publish on `publish_digest(bid.slot)` / `execution_payload_bid`.
///
/// Precondition: the caller already recorded it in the market, since
/// gossipsub never delivers a node its own messages.
pub(crate) fn publish_execution_payload_bid(
    server: &mut P2PServer,
    bid: SignedExecutionPayloadBid,
) {
    let slot = bid.message.slot;
    let Some((topic, data)) = publication(
        server,
        beacon_topics::EXECUTION_PAYLOAD_BID,
        slot,
        &bid.to_ssz(),
    ) else {
        return;
    };
    server.swarm_handle.publish(topic, data);
    info!(
        slot,
        builder_index = bid.message.builder_index,
        value = bid.message.value,
        "Published execution payload bid to gossipsub"
    );
}

/// Publish on `publish_digest(proposal_slot)`: during the epoch before gloas
/// this is the gloas digest, which is held.
pub(crate) fn publish_proposer_preferences(
    server: &mut P2PServer,
    preferences: SignedProposerPreferences,
) {
    let proposal_slot = preferences.message.proposal_slot;
    let Some((topic, data)) = publication(
        server,
        beacon_topics::PROPOSER_PREFERENCES,
        proposal_slot,
        &preferences.to_ssz(),
    ) else {
        return;
    };
    server.swarm_handle.publish(topic, data);
    info!(
        proposal_slot,
        validator_index = preferences.message.validator_index,
        "Published proposer preferences to gossipsub"
    );
}

/// The wall-clock slot, from the store's config.
pub(crate) fn wall_slot(server: &P2PServer) -> Slot {
    let config = server.store.config();
    let genesis_ms = config.genesis_time_ms();
    unix_now_ms().saturating_sub(genesis_ms) / config.slot_duration_ms.max(1)
}

#[cfg(test)]
mod tests {
    use ethlambda_state_transition::beacon::gossip::{IgnoreReason, Outcome, RejectReason};
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::fork::ForkName;
    use ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;
    use ethlambda_types::beacon::primitives::{Epoch, ExecutionBlockHash};
    use libssz::SszEncode;

    use super::*;
    use crate::beacon::transition::apply;
    use crate::test_support::unconnected_beacon_server;

    const FULU: Epoch = 1_000;
    const GLOAS: Epoch = 5_000;

    /// Fulu, then gloas at [`GLOAS`], so the rollover window can be opened.
    fn rollover_config() -> Config {
        Config::mainnet()
            .with_fork_epoch(ForkName::Altair, 1)
            .with_fork_epoch(ForkName::Bellatrix, 2)
            .with_fork_epoch(ForkName::Capella, 3)
            .with_fork_epoch(ForkName::Deneb, 4)
            .with_fork_epoch(ForkName::Electra, 5)
            .with_fork_epoch(ForkName::Fulu, FULU)
            .with_fork_epoch(ForkName::Gloas, GLOAS)
    }

    fn gloas_from_genesis() -> Config {
        Config::mainnet().with_fork_epoch(ForkName::Gloas, 0)
    }

    /// A bid the cheap checks have nothing to say against at `slot`.
    fn bid_at(slot: Slot) -> SignedExecutionPayloadBid {
        let mut bid = SignedExecutionPayloadBid::default();
        bid.message.slot = slot;
        bid.message.builder_index = 3;
        bid.message.value = 10;
        bid.message.block_hash = ExecutionBlockHash::repeat_byte(1);
        bid
    }

    fn preferences_at(proposal_slot: Slot) -> SignedProposerPreferences {
        let mut preferences = SignedProposerPreferences::default();
        preferences.message.proposal_slot = proposal_slot;
        preferences.message.validator_index = 5;
        preferences
    }

    // -- Triage, independent of the gossip rules --

    #[tokio::test]
    async fn an_oversized_bid_is_malformed_before_it_is_decoded() {
        let server = unconnected_beacon_server(gloas_from_genesis(), 0).await;
        let payload = vec![0xff; MAX_SIGNED_EXECUTION_PAYLOAD_BID_SIZE_HEZE + 1];
        assert!(matches!(
            triage_execution_payload_bid(&server, &payload),
            Dispatch::Report(Outcome::Reject(RejectReason::Malformed))
        ));
    }

    #[tokio::test]
    async fn garbage_on_either_builder_topic_is_undecodable() {
        let server = unconnected_beacon_server(gloas_from_genesis(), 0).await;
        assert!(matches!(
            triage_execution_payload_bid(&server, &[0xff; 3]),
            Dispatch::Report(Outcome::Reject(RejectReason::Decode))
        ));
        assert!(matches!(
            triage_proposer_preferences(&server, &[0xff; 3]),
            Dispatch::Report(Outcome::Reject(RejectReason::Decode))
        ));
        // Preferences are fixed-size, so one byte over is not a preference.
        let mut bytes = preferences_at(1).to_ssz();
        bytes.push(0);
        assert!(matches!(
            triage_proposer_preferences(&server, &bytes),
            Dispatch::Report(Outcome::Reject(RejectReason::Decode))
        ));
    }

    // -- Triage, which needs the real cheap checks (Agent A) --

    #[tokio::test]
    async fn a_far_slot_bid_is_not_current_or_next() {
        let server = unconnected_beacon_server(gloas_from_genesis(), 0).await;
        let bid = bid_at(wall_slot(&server) + 1_000);
        assert!(matches!(
            triage_execution_payload_bid(&server, &bid.to_ssz()),
            Dispatch::Report(Outcome::Ignore(IgnoreReason::NotCurrentOrNextSlot))
        ));
    }

    #[tokio::test]
    async fn a_bid_with_a_nonzero_payment_is_rejected() {
        let server = unconnected_beacon_server(gloas_from_genesis(), 0).await;
        let mut bid = bid_at(wall_slot(&server) + 1);
        bid.message.execution_payment = 1;
        assert!(matches!(
            triage_execution_payload_bid(&server, &bid.to_ssz()),
            Dispatch::Report(Outcome::Reject(RejectReason::ExecutionPaymentNonZero))
        ));
    }

    /// A valid-shaped bid goes on to the stateful checks carrying the shared
    /// market, and once the market holds its builder's key a second is ignored
    /// before them.
    #[tokio::test]
    async fn a_valid_shaped_bid_is_validated_unless_its_builder_key_was_seen() {
        let server = unconnected_beacon_server(gloas_from_genesis(), 0).await;
        let bid = bid_at(wall_slot(&server) + 1);
        let payload = bid.to_ssz();
        match triage_execution_payload_bid(&server, &payload) {
            Dispatch::Validate(Validated::ExecutionPayloadBid {
                bid: decoded,
                market,
            }) => {
                assert_eq!(*decoded, bid);
                assert!(std::sync::Arc::ptr_eq(&market, &server.builder_market));
            }
            _ => panic!("expected the bid to go to its stateful checks"),
        }

        assert!(server.builder_market.record_bid(bid));
        assert!(matches!(
            triage_execution_payload_bid(&server, &payload),
            Dispatch::Report(Outcome::Ignore(IgnoreReason::AlreadySeen))
        ));
    }

    #[tokio::test]
    async fn preferences_are_judged_on_the_clock() {
        let server = unconnected_beacon_server(gloas_from_genesis(), 0).await;
        let wall = wall_slot(&server);
        let past = preferences_at(wall.saturating_sub(5));
        assert!(matches!(
            triage_proposer_preferences(&server, &past.to_ssz()),
            Dispatch::Report(Outcome::Ignore(IgnoreReason::SlotStarted))
        ));
        let two_epochs_ahead = preferences_at((wall / SLOTS_PER_EPOCH + 2) * SLOTS_PER_EPOCH + 1);
        assert!(matches!(
            triage_proposer_preferences(&server, &two_epochs_ahead.to_ssz()),
            Dispatch::Report(Outcome::Ignore(IgnoreReason::BeyondLookahead))
        ));
    }

    #[tokio::test]
    async fn preferences_for_a_cached_key_are_already_seen() {
        let server = unconnected_beacon_server(gloas_from_genesis(), 0).await;
        let wall = wall_slot(&server);
        let preferences = preferences_at(wall + 2);
        let payload = preferences.to_ssz();
        assert!(matches!(
            triage_proposer_preferences(&server, &payload),
            Dispatch::Validate(Validated::ProposerPreferences(decoded)) if *decoded == preferences
        ));
        assert!(server.builder_market.record_preferences(preferences, wall));
        assert!(matches!(
            triage_proposer_preferences(&server, &payload),
            Dispatch::Report(Outcome::Ignore(IgnoreReason::AlreadySeen))
        ));
    }

    // -- Publishing --

    fn topic_of(server: &P2PServer, kind: &'static str, slot: Slot) -> Option<String> {
        publication(server, kind, slot, b"payload").map(|(topic, _)| topic.to_string())
    }

    #[tokio::test]
    async fn a_bid_is_published_on_its_slots_digest_and_compressed() {
        let mut server = unconnected_beacon_server(gloas_from_genesis(), 0).await;
        // The test server starts on a placeholder digest; this is the startup
        // call that puts the schedule's own digest in.
        apply(&mut server, 0);
        let wire = server.wire.beacon().expect("a beacon wire");
        let slot = 7;
        let expected = beacon_topics::topic_name(
            wire.publish_digest(slot).expect("held"),
            beacon_topics::EXECUTION_PAYLOAD_BID,
        );
        let ssz = bid_at(slot).to_ssz();
        let (topic, data) =
            publication(&server, beacon_topics::EXECUTION_PAYLOAD_BID, slot, &ssz).unwrap();
        assert_eq!(topic.to_string(), expected);
        assert_eq!(data, compress_message(&ssz));
        assert!(expected.ends_with("/execution_payload_bid/ssz_snappy"));
    }

    /// During the epoch before gloas, preferences for a gloas slot go out on
    /// the gloas digest the node has already joined, and a slot nobody listens
    /// to is not published at all.
    #[tokio::test]
    async fn preferences_for_a_next_fork_slot_use_the_next_forks_digest() {
        let mut server = unconnected_beacon_server(rollover_config(), 0).await;
        apply(&mut server, GLOAS - 1);
        let wire = server.wire.beacon().expect("a beacon wire");
        let gloas_digest = wire.schedule.digest_at(GLOAS);
        let fulu_digest = wire.schedule.digest_at(GLOAS - 1);
        assert_ne!(gloas_digest, fulu_digest);

        let kind = beacon_topics::PROPOSER_PREFERENCES;
        let first_gloas_slot = GLOAS * SLOTS_PER_EPOCH;
        assert_eq!(
            topic_of(&server, kind, first_gloas_slot),
            Some(beacon_topics::topic_name(gloas_digest, kind))
        );
        assert_eq!(
            topic_of(&server, kind, first_gloas_slot - 1),
            Some(beacon_topics::topic_name(fulu_digest, kind))
        );
        // Long past: its digest is no longer held.
        assert_eq!(topic_of(&server, kind, 0), None);
    }

    /// Before the window opens the gloas digest is not held, so there is
    /// nowhere to publish a bid for a gloas slot.
    #[tokio::test]
    async fn nothing_is_published_for_a_digest_that_is_not_held() {
        let mut server = unconnected_beacon_server(rollover_config(), 0).await;
        apply(&mut server, GLOAS - 3);
        let kind = beacon_topics::EXECUTION_PAYLOAD_BID;
        assert_eq!(topic_of(&server, kind, GLOAS * SLOTS_PER_EPOCH), None);
    }
}
