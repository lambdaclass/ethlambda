//! Gloas builder market gossip: the `execution_payload_bid` and
//! `proposer_preferences` topics.
//!
//! Neither message type ever reaches the chain actor: the
//! rules live in `ethlambda_state_transition::beacon::gossip::{
//! execution_payload_bid, proposer_preferences}`, and what they accept is
//! recorded in the node's shared `BuilderMarket` by the verdict.

use ethlambda_state_transition::beacon::gossip::{
    self, Outcome, RejectReason, execution_payload_bid::MAX_SIGNED_EXECUTION_PAYLOAD_BID_SIZE,
};
use std::time::Duration;

use ethlambda_types::beacon::containers::gloas::{
    SignedExecutionPayloadBid, SignedProposerPreferences,
};
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::preset::slots_per_epoch;
use ethlambda_types::beacon::primitives::{Epoch, Slot};
use ethlambda_types::time::unix_now_ms;
use libp2p::gossipsub::IdentTopic;
use libssz::SszEncode;
use tracing::{debug, error, info, warn};

use crate::beacon::BeaconWire;
use crate::beacon::transition::epoch_at_ms;
use crate::beacon::verdict::{Dispatch, Validated};
use crate::beacon::{decode as beacon_decode, topics as beacon_topics};
use crate::gossipsub::compress_message;
use crate::swarm_adapter::PublishOutcome;
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
    if payload.len() > MAX_SIGNED_EXECUTION_PAYLOAD_BID_SIZE {
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

/// Publish on `publish_digest(bid.slot)` / `execution_payload_bid`, and log
/// how it went: `info` once a peer has it, `warn` when none was handed it.
///
/// Precondition: the caller already recorded it in the market, since
/// gossipsub never delivers a node its own messages.
pub(crate) async fn publish_execution_payload_bid(
    server: &mut P2PServer,
    bid: SignedExecutionPayloadBid,
) {
    let slot = bid.message.slot;
    let builder_index = bid.message.builder_index;
    let value = bid.message.value;
    let Some((topic, data)) = publication(
        server,
        beacon_topics::EXECUTION_PAYLOAD_BID,
        slot,
        &bid.to_ssz(),
    ) else {
        return;
    };
    match server
        .swarm_handle
        .publish_reporting(topic, data)
        .outcome()
        .await
    {
        PublishOutcome::Published => info!(
            slot,
            builder_index, value, "Published execution payload bid to gossipsub"
        ),
        PublishOutcome::Duplicate => debug!(
            slot,
            builder_index,
            value,
            "Gossipsub already holds this execution payload bid; not sent again"
        ),
        PublishOutcome::Failed(err) => warn!(
            slot,
            builder_index,
            value,
            %err,
            "Failed to publish execution payload bid to gossipsub"
        ),
    }
}

/// Tell the chain actor of preferences the Beacon API accepted, then gossip
/// them, or hold them back if they are for the next fork digest's slots (see
/// [`gossip_proposer_preferences`]). The chain actor hears of them either way:
/// they are in the market, which is what it and block production read.
pub(crate) async fn publish_proposer_preferences(
    server: &mut P2PServer,
    preferences: SignedProposerPreferences,
) {
    let proposal_slot = preferences.message.proposal_slot;
    // The Beacon API recorded these in the market before asking for the
    // publication, which gossip never delivers back to this node: the chain
    // actor hears of them here, as it does of gossip's in `forward`.
    if let Some(blockchain) = &server.blockchain {
        let _ = blockchain
            .new_proposer_preferences(proposal_slot)
            .inspect_err(|err| warn!(%err, "Failed to report proposer preferences"));
    }
    gossip_proposer_preferences(server, preferences).await;
}

/// Gossip again preferences the market holds that this node still owes a
/// publish, handed back by the Beacon API when a validator client sends them
/// again. The chain actor is not told a second time: it was when they were
/// first accepted.
pub(crate) async fn republish_proposer_preferences(
    server: &mut P2PServer,
    preferences: SignedProposerPreferences,
) {
    debug!(
        proposal_slot = preferences.message.proposal_slot,
        validator_index = preferences.message.validator_index,
        "Resubmitted proposer preferences are still owed a publish"
    );
    gossip_proposer_preferences(server, preferences).await;
}

/// How many slots before a fork-digest boundary this node gossips the proposer
/// preferences it held back for slots past it.
///
/// Peers join the next digest's topics when their own client decides to:
/// this node an epoch ahead (`SUBSCRIBE_LEAD_EPOCHS`), as Lighthouse does
/// since v8.3.0, while Lighthouse before it joins two slots ahead and
/// Grandine 2.0.6 five. Gossipsub refuses to publish a message again for
/// `seen_ttl` (two epochs) once any peer has it, so preferences gossiped to
/// the early joiners could never reach the late ones. One slot ahead, every client has joined,
/// and the preferences still arrive in time for the boundary's first slot: a
/// bid for a slot is gossiped during that slot or the one before it.
pub(crate) const PREFERENCES_RELEASE_LEAD_SLOTS: Slot = 1;

/// When preferences for slots of the digest that activates at
/// `activation_epoch` may first be gossiped, in wall-clock milliseconds:
/// [`PREFERENCES_RELEASE_LEAD_SLOTS`] before its first slot starts.
fn release_ms(wire: &BeaconWire, activation_epoch: Epoch) -> u64 {
    let release_slot = activation_epoch
        .saturating_mul(slots_per_epoch())
        .saturating_sub(PREFERENCES_RELEASE_LEAD_SLOTS);
    wire.genesis_time
        .saturating_mul(1000)
        .saturating_add(release_slot.saturating_mul(wire.config.slot_duration_ms))
}

/// Whether this node holds back its gossip of preferences for
/// `proposal_slot` at `now_ms`: until [`PREFERENCES_RELEASE_LEAD_SLOTS`]
/// before the boundary of the digest they are published under. For a slot of
/// a digest already current (every slot before the next boundary) that moment
/// has passed, so nothing is held. Nor is anything held for the genesis
/// digest, which has no boundary for a release timer to wait on.
pub(crate) fn is_held_back(wire: &BeaconWire, proposal_slot: Slot, now_ms: u64) -> bool {
    let digest_epoch = wire
        .schedule
        .current_at(proposal_slot / slots_per_epoch())
        .activation_epoch;
    digest_epoch > 0 && now_ms < release_ms(wire, digest_epoch)
}

/// The next boundary whose held-back preferences are still to be gossiped,
/// and how long until then: the next digest, once its topics are joined, if
/// it carries `proposer_preferences` (gloas on). `None` before the window
/// opens (the join's run of the fork schedule asks again) and once the moment
/// has passed (nothing is held then).
pub(crate) fn next_preferences_release(server: &P2PServer) -> Option<(Epoch, Duration)> {
    let wire = server.wire.beacon()?;
    let epoch = epoch_at_ms(&wire.config, wire.genesis_time, unix_now_ms());
    let next = wire.schedule.next_boundary_after(epoch)?;
    if next.fork < ForkName::Gloas || !wire.holds_digest(next.digest) {
        return None;
    }
    let delay = until_preferences_release(server, next.activation_epoch)?;
    Some((next.activation_epoch, delay))
}

/// How long until the preferences held back for the digest that activates at
/// `activation_epoch` are gossiped; `None` once that moment has come.
pub(crate) fn until_preferences_release(
    server: &P2PServer,
    activation_epoch: Epoch,
) -> Option<Duration> {
    let wire = server.wire.beacon()?;
    let remaining = release_ms(wire, activation_epoch).saturating_sub(unix_now_ms());
    (remaining > 0).then(|| Duration::from_millis(remaining))
}

/// Gossip every preference the market still owes a publish whose slot has not
/// started: the ones held back for the next digest, and the ones whose publish
/// reached no peer. Runs [`PREFERENCES_RELEASE_LEAD_SLOTS`] before a boundary,
/// when what was held back is released, and at the boundary itself, when
/// every peer that follows the fork has joined the new digest's topics.
///
/// A publish that found no peer subscribed left no trace in gossipsub's
/// duplicate cache, so its retry goes out. One that reached a peer is owed
/// nothing and is left alone: gossipsub would refuse it as a duplicate until
/// its `seen_ttl` (two epochs) runs out. (One refused because every peer's
/// queue was full did leave its id there; its retry is answered as a
/// duplicate, which ends the retries.)
///
/// At the boundary the new digest's first slot has started, so its
/// preferences are past helping and are not sent.
pub(crate) async fn publish_owed_proposer_preferences(server: &mut P2PServer) {
    let Some(wire) = server.wire.beacon() else {
        return;
    };
    let wall_slot = wire.wall_slot();
    let owed = server.builder_market.preferences_owed_a_publish(wall_slot);
    if owed.is_empty() {
        return;
    }
    info!(
        wall_slot,
        count = owed.len(),
        "Publishing proposer preferences held back for the next fork digest or not yet taken by any peer"
    );
    for preferences in owed {
        gossip_proposer_preferences(server, preferences).await;
    }
}

/// Publish on `publish_digest(proposal_slot)`, unless the preferences are for
/// a digest whose boundary is still more than [`PREFERENCES_RELEASE_LEAD_SLOTS`]
/// away ([`is_held_back`]): those are only marked owed, for
/// [`publish_owed_proposer_preferences`] to send at the release. Records in
/// the market whether a peer was handed them, so preferences that reached none
/// are published again (on a validator client's re-send, and at the release or
/// switch of the next digest), and logs it: `info` once a peer has them, `warn`
/// when none was handed them.
async fn gossip_proposer_preferences(
    server: &mut P2PServer,
    preferences: SignedProposerPreferences,
) {
    let proposal_slot = preferences.message.proposal_slot;
    let validator_index = preferences.message.validator_index;
    if let Some(wire) = server.wire.beacon()
        && is_held_back(wire, proposal_slot, unix_now_ms())
    {
        server
            .builder_market
            .record_preferences_publish(&preferences, true);
        debug!(
            proposal_slot,
            validator_index,
            "Holding proposer preferences back until a slot before their fork digest's boundary"
        );
        return;
    }
    let Some((topic, data)) = publication(
        server,
        beacon_topics::PROPOSER_PREFERENCES,
        proposal_slot,
        &preferences.to_ssz(),
    ) else {
        // Never sent, so owed a publish like one no peer took.
        server
            .builder_market
            .record_preferences_publish(&preferences, true);
        return;
    };
    let outcome = server
        .swarm_handle
        .publish_reporting(topic, data)
        .outcome()
        .await;
    server
        .builder_market
        .record_preferences_publish(&preferences, outcome.failed());
    match outcome {
        PublishOutcome::Published => info!(
            proposal_slot,
            validator_index, "Published proposer preferences to gossipsub"
        ),
        PublishOutcome::Duplicate => debug!(
            proposal_slot,
            validator_index, "Gossipsub already holds these proposer preferences; not sent again"
        ),
        PublishOutcome::Failed(err) => warn!(
            proposal_slot,
            validator_index,
            %err,
            "Failed to publish proposer preferences to gossipsub; publishing them again on the next re-send, release or digest switch"
        ),
    }
}

#[cfg(test)]
mod tests {
    use ethlambda_state_transition::beacon::gossip::{IgnoreReason, Outcome, RejectReason};
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::fork::ForkName;
    use ethlambda_types::beacon::preset::slots_per_epoch;
    use ethlambda_types::beacon::primitives::{Epoch, ExecutionBlockHash};
    use libssz::SszEncode;

    use tokio::sync::mpsc::UnboundedReceiver;

    use super::*;
    use crate::beacon::transition::apply;
    use crate::gossipsub::decompress_message;
    use crate::swarm_adapter::{SwarmCommand, SwarmHandle};
    use crate::test_support::{RecordingChain, unconnected_beacon_server};

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
        let payload = vec![0xff; MAX_SIGNED_EXECUTION_PAYLOAD_BID_SIZE + 1];
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
        let bid = bid_at(crate::wall_clock_slot(&server.store) + 1_000);
        assert!(matches!(
            triage_execution_payload_bid(&server, &bid.to_ssz()),
            Dispatch::Report(Outcome::Ignore(IgnoreReason::NotCurrentOrNextSlot))
        ));
    }

    #[tokio::test]
    async fn a_bid_with_a_nonzero_payment_is_rejected() {
        let server = unconnected_beacon_server(gloas_from_genesis(), 0).await;
        let mut bid = bid_at(crate::wall_clock_slot(&server.store) + 1);
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
        let bid = bid_at(crate::wall_clock_slot(&server.store) + 1);
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
        let wall = crate::wall_clock_slot(&server.store);
        let past = preferences_at(wall.saturating_sub(5));
        assert!(matches!(
            triage_proposer_preferences(&server, &past.to_ssz()),
            Dispatch::Report(Outcome::Ignore(IgnoreReason::SlotStarted))
        ));
        let two_epochs_ahead =
            preferences_at((wall / slots_per_epoch() + 2) * slots_per_epoch() + 1);
        assert!(matches!(
            triage_proposer_preferences(&server, &two_epochs_ahead.to_ssz()),
            Dispatch::Report(Outcome::Ignore(IgnoreReason::BeyondLookahead))
        ));
    }

    #[tokio::test]
    async fn preferences_for_a_cached_key_are_already_seen() {
        let server = unconnected_beacon_server(gloas_from_genesis(), 0).await;
        let wall = crate::wall_clock_slot(&server.store);
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
        let first_gloas_slot = GLOAS * slots_per_epoch();
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
        assert_eq!(topic_of(&server, kind, GLOAS * slots_per_epoch()), None);
    }

    // -- Publish outcomes, and republishing what reached no peer --

    /// Holds the digest of the wall clock's epoch, so preferences for slots
    /// around it have a topic, and returns the wall clock's slot.
    fn hold_the_wall_clock_digest(server: &mut P2PServer) -> Slot {
        let wall = server.wire.beacon().expect("a beacon wire").wall_slot();
        apply(server, wall / slots_per_epoch());
        wall
    }

    /// Swaps in a swarm handle whose commands land in the returned receiver.
    fn capture_commands(server: &mut P2PServer) -> UnboundedReceiver<SwarmCommand> {
        let (swarm_handle, commands) = SwarmHandle::capturing();
        server.swarm_handle = swarm_handle;
        commands
    }

    /// Runs `publish` to completion while answering every publish it hands
    /// the swarm with `outcome`, and returns those publishes' payloads,
    /// decompressed, in order.
    async fn answering(
        commands: &mut UnboundedReceiver<SwarmCommand>,
        outcome: PublishOutcome,
        publish: impl Future<Output = ()>,
    ) -> Vec<Vec<u8>> {
        answering_with_topics(commands, outcome, publish)
            .await
            .into_iter()
            .map(|(_, payload)| payload)
            .collect()
    }

    /// [`answering`], with each publish's topic name next to its payload.
    async fn answering_with_topics(
        commands: &mut UnboundedReceiver<SwarmCommand>,
        outcome: PublishOutcome,
        publish: impl Future<Output = ()>,
    ) -> Vec<(String, Vec<u8>)> {
        let mut published = Vec::new();
        tokio::pin!(publish);
        loop {
            tokio::select! {
                () = &mut publish => break,
                Some(command) = commands.recv() => {
                    if let SwarmCommand::Publish { topic, data, outcome_tx } = command {
                        if let Some(outcome_tx) = outcome_tx {
                            let _ = outcome_tx.send(outcome.clone());
                        }
                        let payload = decompress_message(&data).expect("snappy-compressed");
                        published.push((topic.to_string(), payload));
                    }
                }
            }
        }
        published
    }

    /// The real adapter, with no peer on the topic, answers
    /// `NoPeersSubscribedToTopic`: the market remembers that.
    #[tokio::test]
    async fn preferences_no_peer_took_are_remembered_as_owed() {
        let mut server = unconnected_beacon_server(gloas_from_genesis(), 0).await;
        let wall = hold_the_wall_clock_digest(&mut server);
        let preferences = preferences_at(wall + 40);
        assert!(
            server
                .builder_market
                .record_preferences(preferences.clone(), wall)
        );

        publish_proposer_preferences(&mut server, preferences.clone()).await;

        assert!(server.builder_market.preferences_publish_owed(&preferences));
        assert_eq!(
            server.builder_market.preferences_owed_a_publish(wall),
            vec![preferences]
        );
    }

    /// Whatever went out, or gossipsub refused as a duplicate (it left this
    /// node earlier, or arrived from a peer), is owed nothing more; a failure
    /// is owed a publish again.
    #[tokio::test]
    async fn each_publish_outcome_is_recorded_in_the_market() {
        let mut server = unconnected_beacon_server(gloas_from_genesis(), 0).await;
        let wall = hold_the_wall_clock_digest(&mut server);
        let mut commands = capture_commands(&mut server);
        let preferences = preferences_at(wall + 40);
        assert!(
            server
                .builder_market
                .record_preferences(preferences.clone(), wall)
        );

        let no_peer = PublishOutcome::Failed("NoPeersSubscribedToTopic".to_string());
        for (outcome, owed) in [
            (no_peer.clone(), true),
            (PublishOutcome::Published, false),
            (no_peer, true),
            (PublishOutcome::Duplicate, false),
        ] {
            let published = answering(
                &mut commands,
                outcome.clone(),
                publish_proposer_preferences(&mut server, preferences.clone()),
            )
            .await;
            assert_eq!(published, vec![preferences.to_ssz()]);
            assert_eq!(
                server.builder_market.preferences_publish_owed(&preferences),
                owed,
                "after {outcome:?}"
            );
        }
    }

    /// At a digest switch, only what is owed and still ahead goes out: not
    /// preferences whose slot has started, nor ones that already went out.
    /// What goes out is the held message itself, and once it does, nothing is
    /// owed for it.
    #[tokio::test]
    async fn a_digest_switch_republishes_only_owed_preferences_still_ahead() {
        let mut server = unconnected_beacon_server(gloas_from_genesis(), 0).await;
        let wall = hold_the_wall_clock_digest(&mut server);
        let mut commands = capture_commands(&mut server);
        let started = preferences_at(wall - 1);
        let owed = preferences_at(wall + 40);
        let delivered = preferences_at(wall + 41);
        let market = &server.builder_market;
        for preferences in [&started, &owed, &delivered] {
            assert!(market.record_preferences(preferences.clone(), wall - 1));
        }
        market.record_preferences_publish(&started, true);
        market.record_preferences_publish(&owed, true);
        market.record_preferences_publish(&delivered, false);

        let published = answering(
            &mut commands,
            PublishOutcome::Published,
            publish_owed_proposer_preferences(&mut server),
        )
        .await;

        assert_eq!(published, vec![owed.to_ssz()]);
        assert!(!server.builder_market.preferences_publish_owed(&owed));
        // The stale one is not sent, and stays as it was.
        assert!(server.builder_market.preferences_publish_owed(&started));
        assert!(commands.try_recv().is_err(), "nothing else was sent");
    }

    // -- Holding back the next digest's preferences --

    /// A server on [`rollover_config`] whose wall clock is one second into
    /// `slot` (leaving the rest of the slot for the test), with the fork
    /// schedule applied at that slot's epoch.
    async fn rollover_server_one_second_into(slot: Slot) -> P2PServer {
        let mut config = rollover_config();
        let slot_seconds = config.slot_duration_ms / 1000;
        config.genesis_time = unix_now_ms() / 1000 - slot * slot_seconds - 1;
        let mut server = unconnected_beacon_server(config, 0).await;
        apply(&mut server, slot / slots_per_epoch());
        server
    }

    fn slot_start_ms(wire: &BeaconWire, slot: Slot) -> u64 {
        wire.genesis_time * 1000 + slot * wire.config.slot_duration_ms
    }

    /// Preferences for any slot of the next digest are held back until a slot
    /// before its boundary; those for a slot before the boundary never are, and
    /// nothing is once the digest is current.
    #[tokio::test]
    async fn the_next_digests_preferences_are_held_back_until_a_slot_before_it() {
        let server = unconnected_beacon_server(rollover_config(), 0).await;
        let wire = server.wire.beacon().expect("a beacon wire");
        let boundary = GLOAS * slots_per_epoch();
        let release = slot_start_ms(wire, boundary - PREFERENCES_RELEASE_LEAD_SLOTS);
        assert_eq!(PREFERENCES_RELEASE_LEAD_SLOTS, 1);

        let window_opens = slot_start_ms(wire, boundary - slots_per_epoch());
        for slot in [boundary, boundary + 5, boundary + slots_per_epoch() - 1] {
            assert!(is_held_back(wire, slot, window_opens));
            assert!(is_held_back(wire, slot, release - 1));
            assert!(!is_held_back(wire, slot, release));
            assert!(!is_held_back(wire, slot, slot_start_ms(wire, boundary + 1)));
        }
        // The fork's own epoch before it: unaffected.
        assert!(!is_held_back(wire, boundary - 1, window_opens));
        assert!(!is_held_back(wire, boundary - 2, release - 1));

        // The genesis digest has no boundary to wait for, even before genesis.
        let from_genesis = unconnected_beacon_server(gloas_from_genesis(), 0).await;
        let wire = from_genesis.wire.beacon().expect("a beacon wire");
        assert!(!is_held_back(wire, 5, 0));
    }

    /// Before the release, preferences for the next digest's slots are pooled
    /// and reported to the chain actor at once, but not gossiped, not even on a
    /// re-send; they are owed a publish, and the release is scheduled a slot
    /// before the boundary. A preference for a slot before the boundary goes
    /// out as before.
    #[tokio::test]
    async fn a_held_back_preference_is_pooled_and_reported_but_not_published() {
        let boundary = GLOAS * slots_per_epoch();
        let mut server = rollover_server_one_second_into(boundary - 3).await;
        let chain = std::sync::Arc::new(RecordingChain::default());
        server.blockchain = Some(chain.clone());
        let wire = server.wire.beacon().expect("a beacon wire");
        assert_eq!(wire.wall_slot(), boundary - 3);
        let fulu_topic = beacon_topics::topic_name(
            wire.schedule.digest_at(GLOAS - 1),
            beacon_topics::PROPOSER_PREFERENCES,
        );
        let mut commands = capture_commands(&mut server);
        let held = preferences_at(boundary + 3);
        let pre_fork = preferences_at(boundary - 1);
        for preferences in [&held, &pre_fork] {
            let market = &server.builder_market;
            assert!(market.record_preferences(preferences.clone(), boundary - 3));
        }

        let published = answering_with_topics(
            &mut commands,
            PublishOutcome::Published,
            publish_proposer_preferences(&mut server, held.clone()),
        )
        .await;
        assert!(published.is_empty(), "held back");
        assert!(server.builder_market.preferences_publish_owed(&held));
        assert_eq!(*chain.preference_slots.lock().unwrap(), vec![boundary + 3]);

        let published = answering_with_topics(
            &mut commands,
            PublishOutcome::Published,
            republish_proposer_preferences(&mut server, held.clone()),
        )
        .await;
        assert!(published.is_empty(), "a re-send is held back too");
        assert!(server.builder_market.preferences_publish_owed(&held));

        let published = answering_with_topics(
            &mut commands,
            PublishOutcome::Published,
            publish_proposer_preferences(&mut server, pre_fork.clone()),
        )
        .await;
        assert_eq!(published, vec![(fulu_topic, pre_fork.to_ssz())]);
        assert!(!server.builder_market.preferences_publish_owed(&pre_fork));

        // The release is the start of the boundary's previous slot, a little
        // under two slots from one second into the one before that.
        let (activation_epoch, delay) =
            next_preferences_release(&server).expect("the gloas window is open");
        assert_eq!(activation_epoch, GLOAS);
        let slot = Duration::from_millis(server.wire.beacon().unwrap().config.slot_duration_ms);
        assert!(delay <= 2 * slot - Duration::from_secs(1));
        // Loose below, for a slow runner: more than a slot away is still not
        // the slot two before the boundary, and the bound above is not the
        // boundary itself.
        assert!(delay > slot);
        let until = until_preferences_release(&server, GLOAS).expect("still ahead");
        assert!(until <= delay && delay - until < Duration::from_secs(1));
    }

    /// Before the gloas window opens nothing is held back yet, so there is no
    /// release to schedule.
    #[tokio::test]
    async fn no_release_is_scheduled_before_the_window_opens() {
        let boundary = GLOAS * slots_per_epoch();
        let server = rollover_server_one_second_into(boundary - slots_per_epoch() - 1).await;
        assert!(next_preferences_release(&server).is_none());
    }

    /// At the release, a slot before the boundary, the held-back preferences
    /// go out on the new digest's topic and are owed nothing more; one for the
    /// slot already running is past helping and stays put.
    #[tokio::test]
    async fn held_back_preferences_go_out_at_the_release_on_the_new_digest() {
        let boundary = GLOAS * slots_per_epoch();
        let mut server = rollover_server_one_second_into(boundary - 1).await;
        let wire = server.wire.beacon().expect("a beacon wire");
        assert_eq!(wire.wall_slot(), boundary - 1);
        let gloas_topic = beacon_topics::topic_name(
            wire.schedule.digest_at(GLOAS),
            beacon_topics::PROPOSER_PREFERENCES,
        );
        assert!(until_preferences_release(&server, GLOAS).is_none());
        let mut commands = capture_commands(&mut server);
        let first = preferences_at(boundary);
        let later = preferences_at(boundary + 3);
        let running = preferences_at(boundary - 1);
        for preferences in [&first, &later, &running] {
            let market = &server.builder_market;
            assert!(market.record_preferences(preferences.clone(), boundary - 1));
            market.record_preferences_publish(preferences, true);
        }

        let published = answering_with_topics(
            &mut commands,
            PublishOutcome::Published,
            publish_owed_proposer_preferences(&mut server),
        )
        .await;

        assert_eq!(
            published,
            vec![
                (gloas_topic.clone(), first.to_ssz()),
                (gloas_topic, later.to_ssz())
            ]
        );
        assert!(!server.builder_market.preferences_publish_owed(&first));
        assert!(!server.builder_market.preferences_publish_owed(&later));
        assert!(server.builder_market.preferences_publish_owed(&running));
    }

    /// Across a real boundary, on the clock the switch runs at (just into the
    /// first gloas slot): the last fulu slot's preferences and the first gloas
    /// slot's, which has started, stay owed and unsent, and a later gloas
    /// slot's go out on the gloas digest's topic.
    #[tokio::test]
    async fn at_the_gloas_switch_later_gloas_slots_go_out_on_the_gloas_digest() {
        let first_gloas_slot = GLOAS * slots_per_epoch();
        let mut server = rollover_server_one_second_into(first_gloas_slot).await;
        let wire = server.wire.beacon().expect("a beacon wire");
        assert_eq!(wire.wall_slot(), first_gloas_slot);
        let gloas_topic = beacon_topics::topic_name(
            wire.schedule.digest_at(GLOAS),
            beacon_topics::PROPOSER_PREFERENCES,
        );
        let mut commands = capture_commands(&mut server);
        let last_fulu = preferences_at(first_gloas_slot - 1);
        let first_gloas = preferences_at(first_gloas_slot);
        let later = preferences_at(first_gloas_slot + 5);
        for preferences in [&last_fulu, &first_gloas, &later] {
            let market = &server.builder_market;
            assert!(market.record_preferences(preferences.clone(), first_gloas_slot - 1));
            market.record_preferences_publish(preferences, true);
        }

        let published = answering_with_topics(
            &mut commands,
            PublishOutcome::Published,
            publish_owed_proposer_preferences(&mut server),
        )
        .await;

        assert_eq!(published, vec![(gloas_topic, later.to_ssz())]);
        assert!(server.builder_market.preferences_publish_owed(&last_fulu));
        assert!(server.builder_market.preferences_publish_owed(&first_gloas));
        assert!(!server.builder_market.preferences_publish_owed(&later));
    }

    /// A first publish tells the chain actor; a re-send's republish does not
    /// tell it again, and a failure leaves the preferences owed.
    #[tokio::test]
    async fn a_resubmission_republishes_without_reporting_to_the_chain_again() {
        let mut server = unconnected_beacon_server(gloas_from_genesis(), 0).await;
        let chain = std::sync::Arc::new(RecordingChain::default());
        server.blockchain = Some(chain.clone());
        let wall = hold_the_wall_clock_digest(&mut server);
        let mut commands = capture_commands(&mut server);
        let preferences = preferences_at(wall + 40);
        assert!(
            server
                .builder_market
                .record_preferences(preferences.clone(), wall)
        );
        let no_peer = PublishOutcome::Failed("NoPeersSubscribedToTopic".to_string());

        answering(
            &mut commands,
            no_peer.clone(),
            publish_proposer_preferences(&mut server, preferences.clone()),
        )
        .await;
        assert_eq!(*chain.preference_slots.lock().unwrap(), vec![wall + 40]);
        assert!(server.builder_market.preferences_publish_owed(&preferences));

        let published = answering(
            &mut commands,
            no_peer,
            republish_proposer_preferences(&mut server, preferences.clone()),
        )
        .await;

        assert_eq!(published, vec![preferences.to_ssz()]);
        assert!(server.builder_market.preferences_publish_owed(&preferences));
        assert_eq!(
            chain.preference_slots.lock().unwrap().len(),
            1,
            "the chain actor is told once"
        );
    }
}
