//! Ordered failover across several beacon nodes.
//!
//! First healthy wins, in the order given on the command line. Deliberately not
//! health-scored: Lighthouse ranks its nodes by sync distance and tie-breaks on
//! list order, which is better, and is a refinement this does not need yet.

use std::future::Future;
use std::pin::Pin;

use async_trait::async_trait;
use ethlambda_types::beacon::builder::SignedValidatorRegistrationV1;
use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::containers::altair;
use ethlambda_types::beacon::containers::gloas;
use ethlambda_types::beacon::containers::shared::AttestationData;
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::primitives::{BlsPubkey, Epoch, Root, Slot, ValidatorIndex};
use tracing::{debug, warn};

use crate::beacon_node::block_contents::ProducedBlock;
use crate::beacon_node::dto::{
    CommitteeSubscriptionDto, ProposerPreparationDto, SingleAttestationDto,
    SyncCommitteeSubscriptionDto, SyncDutyDto,
};
use crate::beacon_node::{
    AggregateAttestation, AttesterDuties, BeaconNodeApi, BlockRequest, Genesis, ProposerDuties,
    PtcDuties, Published, SignedAggregates, ValidatorEntry,
};
use crate::error::{Error, Result};

/// The boxed future `#[async_trait]` desugars a trait method call into,
/// borrowed from the receiver (and, for methods that take borrowed arguments,
/// from those too). Naming it lets [`FallbackBeaconNode::try_each`] state that
/// the future it gets back is tied to one caller-chosen lifetime `'p`, shared
/// by the node reference and whatever else the closure captures, rather than
/// to `Self`.
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A `BeaconNodeApi` backed by an ordered list of others, answering from the
/// first one that succeeds.
pub struct FallbackBeaconNode<B> {
    nodes: Vec<B>,
    /// The node that produced the latest blinded block, by slot. A blinded
    /// block can only be published where it was produced: that node's builder
    /// holds the payload, and that node claimed the slot.
    blinded_producer: std::sync::Mutex<Option<(Slot, usize)>>,
}

impl<B: BeaconNodeApi> FallbackBeaconNode<B> {
    pub fn new(nodes: Vec<B>) -> Self {
        assert!(!nodes.is_empty(), "at least one beacon node is required");
        Self {
            nodes,
            blinded_producer: std::sync::Mutex::new(None),
        }
    }

    /// Try each node in order, returning the first success.
    ///
    /// "Success" means the node returned `Ok`, nothing more. That is the right
    /// rule only where an `Ok` is an answer this client can act on, which is
    /// why [`BeaconNodeApi::is_syncing`] does not use this helper: there,
    /// `Ok(true)` is a node reporting itself unusable, and returning it from
    /// the first node would mask every healthy node behind it.
    ///
    /// A node that is syncing is skipped here in practice, because the calls
    /// routed through this helper answer 503 while syncing and 503 is mapped to
    /// an error. That is a property of those endpoints, not something this
    /// function arranges.
    ///
    /// `'p` is a single, caller-inferred lifetime rather than a higher-ranked
    /// `for<'b>` one: a higher-ranked bound would force the closure's future to
    /// be valid for every possible `'b`, including `'static`, which is
    /// impossible once the closure also borrows a method argument (e.g.
    /// `pubkeys` in `validator_indices`) with its own, shorter lifetime. Tying
    /// both `&self` and the future to one named `'p` lets the compiler unify
    /// it with whatever the call site's shortest borrow actually is.
    async fn try_each<'p, T, F>(&'p self, what: &'static str, call: F) -> Result<T>
    where
        F: Fn(&'p B) -> BoxFuture<'p, Result<T>>,
    {
        self.try_each_at(what, call).await.map(|(_, value)| value)
    }

    /// [`Self::try_each`], also returning the position of the node that
    /// answered, for the calls whose follow-up must go to the same node. The
    /// logging and the final `warn!` live here so the two cannot drift.
    async fn try_each_at<'p, T, F>(&'p self, what: &'static str, call: F) -> Result<(usize, T)>
    where
        F: Fn(&'p B) -> BoxFuture<'p, Result<T>>,
    {
        self.try_each_at_inner(what, true, call).await
    }

    /// [`Self::try_each`] without the final `warn!`, for a caller whose own
    /// duty did not depend on the answer and which reports the failure itself
    /// (the counterpart of [`Self::try_all`]'s `all_failed: None`). A node that
    /// is syncing, or lacks the endpoint, would otherwise make this warn on
    /// every call for as long as it lasts.
    async fn try_each_quiet<'p, T, F>(&'p self, what: &'static str, call: F) -> Result<T>
    where
        F: Fn(&'p B) -> BoxFuture<'p, Result<T>>,
    {
        self.try_each_at_inner(what, false, call)
            .await
            .map(|(_, value)| value)
    }

    async fn try_each_at_inner<'p, T, F>(
        &'p self,
        what: &'static str,
        warn_when_all_fail: bool,
        call: F,
    ) -> Result<(usize, T)>
    where
        F: Fn(&'p B) -> BoxFuture<'p, Result<T>>,
    {
        let mut last = None;
        for (position, node) in self.nodes.iter().enumerate() {
            match call(node).await {
                Ok(value) => return Ok((position, value)),
                Err(err) => {
                    // Debug, not warn: with more than one node configured, an
                    // outage on one of them fires this every slot for as long
                    // as it lasts. The event that actually means the client
                    // missed a duty is every node failing, below.
                    debug!(%what, position, %err, "Beacon node request failed; trying the next");
                    last = Some(err);
                }
            }
        }
        let detail = last
            .map(|err| err.to_string())
            .unwrap_or_else(|| "no nodes configured".to_string());
        if warn_when_all_fail {
            warn!(%what, %detail, "All configured beacon nodes failed; duty likely missed");
        }
        Err(Error::AllBeaconNodesFailed(detail))
    }

    /// Send to **every** node, succeeding if any accepted.
    ///
    /// The counterpart to [`Self::try_each`], for the calls where first-success
    /// is the wrong rule. A query has one right answer and any node can give
    /// it; these two calls instead install *state on a node*, and a node that
    /// was never told is a node that cannot serve the duty later.
    ///
    /// That is not hypothetical. With two nodes configured, `try_each` tells
    /// node 1 which committees this client attests in and which it will
    /// aggregate for, and node 2 hears nothing. When node 1 goes down
    /// mid-epoch, every later call fails over to the node least prepared to
    /// answer it: it is not holding those attestation subnets open, and it
    /// collected none of the votes an aggregate is folded from, so it answers
    /// 404 for every committee. The failover node exists for exactly that
    /// moment.
    ///
    /// Succeeding if any node accepted, rather than requiring all, because one
    /// unreachable node must not stop the reachable ones being told. A failure
    /// is logged per node so a partially-registered client is visible rather
    /// than silent.
    ///
    /// `node_effect` says what a refusing node costs (said once per refusal);
    /// `all_failed` says what it costs when none accepts, or is `None` when the
    /// caller reports that itself, so a duty that did not depend on the call is
    /// not claimed missed.
    async fn try_all<'p, F>(
        &'p self,
        what: &'static str,
        node_effect: &'static str,
        all_failed: Option<&'static str>,
        call: F,
    ) -> Result<()>
    where
        F: Fn(&'p B) -> BoxFuture<'p, Result<()>>,
    {
        self.try_all_inner(what, node_effect, all_failed, true, call)
            .await
    }

    /// [`Self::try_all`] logging each node's refusal at `debug!` instead of
    /// `warn!`, for a call the caller retries every slot and reports itself
    /// (once per entry): a per-node warning here would repeat on every retry
    /// for as long as the refusal lasts. Always without an `all_failed`
    /// message, for the same reason.
    async fn try_all_quiet<'p, F>(
        &'p self,
        what: &'static str,
        node_effect: &'static str,
        call: F,
    ) -> Result<()>
    where
        F: Fn(&'p B) -> BoxFuture<'p, Result<()>>,
    {
        self.try_all_inner(what, node_effect, None, false, call)
            .await
    }

    async fn try_all_inner<'p, F>(
        &'p self,
        what: &'static str,
        node_effect: &'static str,
        all_failed: Option<&'static str>,
        warn_per_node: bool,
        call: F,
    ) -> Result<()>
    where
        F: Fn(&'p B) -> BoxFuture<'p, Result<()>>,
    {
        let mut accepted = 0;
        let mut last = None;
        for (position, node) in self.nodes.iter().enumerate() {
            match call(node).await {
                Ok(()) => accepted += 1,
                Err(err) => {
                    if warn_per_node {
                        warn!(%what, position, %err, node_effect, "Beacon node did not accept");
                    } else {
                        debug!(%what, position, %err, node_effect, "Beacon node did not accept");
                    }
                    last = Some(err);
                }
            }
        }
        if accepted > 0 {
            return Ok(());
        }
        let detail = last
            .map(|err| err.to_string())
            .unwrap_or_else(|| "no nodes configured".to_string());
        if let Some(all_failed) = all_failed {
            warn!(%what, %detail, all_failed, "No configured beacon node accepted");
        }
        Err(Error::AllBeaconNodesFailed(detail))
    }
}

#[async_trait]
impl<B: BeaconNodeApi> BeaconNodeApi for FallbackBeaconNode<B> {
    async fn genesis(&self) -> Result<Genesis> {
        self.try_each("genesis", |node| node.genesis()).await
    }

    async fn spec(&self) -> Result<Config> {
        self.try_each("spec", |node| node.spec()).await
    }

    /// Whether *this fallback* has no usable node, rather than whether the
    /// first reachable one happens to be syncing or optimistic.
    ///
    /// Deliberately not a plain `try_each`. A node answering `true` is
    /// answering successfully, so `try_each` would return that `Ok(true)` from
    /// the first node and never consult the rest, and the caller
    /// (`refresh_epoch`) turns `true` into "do not refresh duties". A syncing
    /// node at the head of the list would therefore stop duties from being
    /// refreshed for as long as it was syncing, with a perfectly healthy node
    /// sitting behind it unused, which is the opposite of what configuring a
    /// second node is for.
    ///
    /// So: look for a node that is usable, and report `false` the moment one is
    /// found. `true` means every reachable node said it was syncing or
    /// optimistic, which is the only situation where the caller's decision to
    /// hold off is right.
    ///
    /// A node that fails outright is skipped like any other failure, and only
    /// if none answers at all does this surface an error.
    async fn is_optimistic_or_syncing(&self) -> Result<bool> {
        let mut last = None;
        let mut any_answered = false;
        for (position, node) in self.nodes.iter().enumerate() {
            match node.is_optimistic_or_syncing().await {
                Ok(false) => return Ok(false),
                Ok(true) => {
                    any_answered = true;
                    debug!(
                        position,
                        "Beacon node is syncing or optimistic; trying the next"
                    );
                }
                Err(err) => {
                    debug!(what = "syncing", position, %err, "Beacon node request failed; trying the next");
                    last = Some(err);
                }
            }
        }

        if any_answered {
            // Every node that answered said it was unusable. That is a real
            // answer, not a failure: the caller should hold off, and saying so
            // is more useful than an error claiming nothing could be reached.
            return Ok(true);
        }

        let detail = last
            .map(|err| err.to_string())
            .unwrap_or_else(|| "no nodes configured".to_string());
        warn!(
            what = "syncing",
            %detail, "All configured beacon nodes failed; duty likely missed"
        );
        Err(Error::AllBeaconNodesFailed(detail))
    }

    async fn validator_indices(&self, pubkeys: &[BlsPubkey]) -> Result<Vec<ValidatorEntry>> {
        self.try_each("validator_indices", |node| node.validator_indices(pubkeys))
            .await
    }

    async fn attester_duties(
        &self,
        epoch: Epoch,
        indices: &[ValidatorIndex],
    ) -> Result<AttesterDuties> {
        self.try_each("attester_duties", |node| {
            node.attester_duties(epoch, indices)
        })
        .await
    }

    async fn proposer_duties(&self, epoch: Epoch) -> Result<ProposerDuties> {
        self.try_each("proposer_duties", |node| node.proposer_duties(epoch))
            .await
    }

    async fn proposer_duties_v2(&self, epoch: Epoch) -> Result<ProposerDuties> {
        // Quiet: the preferences service reports its own failure once per
        // epoch, and no duty depends on this answer.
        self.try_each_quiet("proposer_duties_v2", |node| node.proposer_duties_v2(epoch))
            .await
    }

    async fn attestation_data(&self, slot: Slot, fork: ForkName) -> Result<AttestationData> {
        self.try_each("attestation_data", |node| node.attestation_data(slot, fork))
            .await
    }

    /// Remembers which node answered when the block is blinded, and forgets
    /// it when it is not: the record is for the latest block only, so a full
    /// block never leaves a stale claim that a blinded publish could match.
    async fn produce_block(&self, request: &BlockRequest) -> Result<ProducedBlock> {
        let (position, block) = self
            .try_each_at("produce_block", |node| node.produce_block(request))
            .await?;
        let record = block.is_blinded().then(|| (block.slot(), position));
        *self
            .blinded_producer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = record;
        Ok(block)
    }

    /// First node that accepts it wins, rather than a broadcast to every node.
    ///
    /// Publishing is the one call where that choice is not obvious, because
    /// sending to every node would reach more of the network's gossip mesh at
    /// once. It stays first-wins for now because a node that accepts a block
    /// gossips it, so the second node would receive it over the network in any
    /// case, and because a broadcast makes the outcome ambiguous: with three
    /// nodes answering 200, 202 and a timeout, there is no single answer to
    /// report.
    ///
    /// A 202 counts as success and stops the walk. The node could not import
    /// the block, but it did broadcast it, so the network has it and offering
    /// it to another node would not change that.
    async fn publish_block(&self, fork: ForkName, body: &[u8]) -> Result<Published> {
        self.try_each("publish_block", |node| node.publish_block(fork, body))
            .await
    }

    /// Only on the node that produced the block, with no failover.
    ///
    /// Unlike [`Self::publish_block`], offering the block to another node
    /// would not reach the network: only the producing node's builder holds
    /// the payload the header commits to, and only that node claimed the slot
    /// with it. A second node would at best refuse it and at worst hand a
    /// signed block to a builder that never saw the bid. So if the producing
    /// node fails, the publish fails, and the answer is returned unchanged so
    /// the caller can tell a refusal from an unconfirmed send. The proposal
    /// guard has already recorded the slot, so nothing retries it.
    async fn publish_blinded_block(
        &self,
        slot: Slot,
        fork: ForkName,
        body: &[u8],
    ) -> Result<Published> {
        let record = *self
            .blinded_producer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match record {
            Some((produced_slot, position)) if produced_slot == slot => {
                self.nodes[position]
                    .publish_blinded_block(slot, fork, body)
                    .await
            }
            _ => Err(Error::InconsistentResponse(format!(
                "no beacon node produced a blinded block for slot {slot}"
            ))),
        }
    }

    /// To every node, like the other calls that install state on a node: a
    /// node that never heard the registrations cannot serve a builder bid for
    /// these validators after a failover.
    async fn register_validators(
        &self,
        registrations: &[SignedValidatorRegistrationV1],
    ) -> Result<()> {
        self.try_all(
            "register_validators",
            "it will not hold these registrations",
            None,
            |node| node.register_validators(registrations),
        )
        .await
    }

    /// To every node, since each one gossips what it accepts: a preference
    /// only the first node heard reaches the mesh through that node alone, and
    /// builders subscribed elsewhere would ignore the slot.
    async fn submit_proposer_preferences(
        &self,
        fork: ForkName,
        preferences: &[gloas::SignedProposerPreferences],
    ) -> Result<()> {
        // Quiet: the service retries a refused preference every slot and warns
        // once per entry, with what it costs.
        self.try_all_quiet(
            "submit_proposer_preferences",
            "it will not gossip these proposer preferences",
            |node| node.submit_proposer_preferences(fork, preferences),
        )
        .await
    }

    /// Fails over like any query: the envelope the node cached is only on the
    /// node that produced the block, and one that did not answers 404.
    async fn execution_payload_envelope(
        &self,
        slot: Slot,
        block_root: Root,
    ) -> Result<gloas::ExecutionPayloadEnvelope> {
        self.try_each("execution_payload_envelope", |node| {
            node.execution_payload_envelope(slot, block_root)
        })
        .await
    }

    /// First node that accepts it wins, for the reason [`Self::publish_block`]
    /// is: the accepting node gossips it.
    async fn publish_execution_payload_envelope(
        &self,
        body: &[u8],
        blob_data_included: bool,
    ) -> Result<()> {
        self.try_each("publish_execution_payload_envelope", |node| {
            node.publish_execution_payload_envelope(body, blob_data_included)
        })
        .await
    }

    async fn ptc_duties(&self, epoch: Epoch, indices: &[ValidatorIndex]) -> Result<PtcDuties> {
        self.try_each("ptc_duties", |node| node.ptc_duties(epoch, indices))
            .await
    }

    /// A 204 is an answer, so the first node that knows no block ends the
    /// walk, even though another might have one. That is the right trade: PTC
    /// votes are due at three quarters of the slot, and a node that has seen
    /// nothing by then is one this client should not be voting through.
    async fn payload_attestation_data(
        &self,
        slot: Slot,
    ) -> Result<Option<gloas::PayloadAttestationData>> {
        self.try_each("payload_attestation_data", |node| {
            node.payload_attestation_data(slot)
        })
        .await
    }

    async fn submit_payload_attestations(
        &self,
        messages: &[gloas::PayloadAttestationMessage],
    ) -> Result<usize> {
        self.try_each("submit_payload_attestations", |node| {
            node.submit_payload_attestations(messages)
        })
        .await
    }

    async fn submit_attestations(
        &self,
        attestations: &[SingleAttestationDto],
        fork_name: &str,
    ) -> Result<usize> {
        self.try_each("submit_attestations", |node| {
            node.submit_attestations(attestations, fork_name)
        })
        .await
    }

    /// A 404 here is a node with nothing to fold, not a broken node, and it is
    /// the reason this is worth failing over: another node may have been on
    /// the subnet when the votes arrived.
    async fn aggregate_attestation(
        &self,
        slot: Slot,
        attestation_data_root: Root,
        committee_index: u64,
    ) -> Result<AggregateAttestation> {
        self.try_each("aggregate_attestation", |node| {
            node.aggregate_attestation(slot, attestation_data_root, committee_index)
        })
        .await
    }

    async fn publish_aggregates(
        &self,
        fork: ForkName,
        aggregates: &SignedAggregates,
    ) -> Result<()> {
        self.try_each("publish_aggregates", |node| {
            node.publish_aggregates(fork, aggregates)
        })
        .await
    }

    /// Every node, not the first that answers. See [`Self::try_all`]: a node
    /// that was never told where to pay builds a payload paying somewhere else,
    /// and it is the node this client falls over to that needs telling most.
    async fn prepare_beacon_proposer(&self, preparations: &[ProposerPreparationDto]) -> Result<()> {
        self.try_all(
            "prepare_beacon_proposer",
            "it will be unprepared for this duty",
            Some("duty likely missed"),
            |node| node.prepare_beacon_proposer(preparations),
        )
        .await
    }

    /// Every node, for the same reason, and with more at stake. A subscription
    /// is what puts a node on the attestation subnets and what makes it collect
    /// the votes an aggregate is folded from, so a node that never received one
    /// answers 404 for every committee this client asks about.
    async fn subscribe_committees(&self, subscriptions: &[CommitteeSubscriptionDto]) -> Result<()> {
        self.try_all(
            "subscribe_committees",
            "it will be unprepared for this duty",
            Some("duty likely missed"),
            |node| node.subscribe_committees(subscriptions),
        )
        .await
    }

    async fn sync_duties(
        &self,
        epoch: Epoch,
        indices: &[ValidatorIndex],
    ) -> Result<Vec<SyncDutyDto>> {
        self.try_each("sync_duties", |node| node.sync_duties(epoch, indices))
            .await
    }

    /// An optimistic head is an error from each implementation, so a node
    /// tracking an unvalidated head is walked past rather than signed over.
    async fn head_block_root(&self) -> Result<Root> {
        self.try_each("head_block_root", |node| node.head_block_root())
            .await
    }

    async fn submit_sync_committee_messages(
        &self,
        messages: &[altair::SyncCommitteeMessage],
    ) -> Result<usize> {
        self.try_each("submit_sync_committee_messages", |node| {
            node.submit_sync_committee_messages(messages)
        })
        .await
    }

    /// A 404 is a node that holds no messages for this subcommittee; another
    /// node may have been subscribed when they arrived.
    async fn sync_committee_contribution(
        &self,
        slot: Slot,
        subcommittee_index: u64,
        beacon_block_root: Root,
    ) -> Result<altair::SyncCommitteeContribution> {
        self.try_each("sync_committee_contribution", |node| {
            node.sync_committee_contribution(slot, subcommittee_index, beacon_block_root)
        })
        .await
    }

    async fn publish_contribution_and_proofs(
        &self,
        contributions: &[altair::SignedContributionAndProof],
    ) -> Result<()> {
        self.try_each("publish_contribution_and_proofs", |node| {
            node.publish_contribution_and_proofs(contributions)
        })
        .await
    }

    /// Every node, for the reason [`Self::subscribe_committees`] is: a node
    /// that never joined a sync subnet cannot pool the messages a contribution
    /// is folded from.
    async fn subscribe_sync_committees(
        &self,
        subscriptions: &[SyncCommitteeSubscriptionDto],
    ) -> Result<()> {
        self.try_all(
            "subscribe_sync_committees",
            "it will be unprepared for this duty",
            Some("duty likely missed"),
            |node| node.subscribe_sync_committees(subscriptions),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon_node::mock::MockBeaconNode;
    use ethlambda_types::beacon::primitives::Root;

    fn healthy() -> MockBeaconNode {
        let mut node = MockBeaconNode::new();
        node.genesis = Some(Genesis {
            genesis_time: 1_606_824_023,
            genesis_validators_root: Root::ZERO,
        });
        node
    }

    #[tokio::test]
    async fn the_first_healthy_node_answers() {
        let fallback = FallbackBeaconNode::new(vec![healthy(), MockBeaconNode::failing("down")]);
        let genesis = fallback.genesis().await.expect("answers");
        assert_eq!(genesis.genesis_time, 1_606_824_023);
    }

    #[tokio::test]
    async fn a_failing_first_node_falls_through_to_the_second() {
        let fallback = FallbackBeaconNode::new(vec![MockBeaconNode::failing("down"), healthy()]);
        let genesis = fallback.genesis().await.expect("answers");
        assert_eq!(genesis.genesis_time, 1_606_824_023);
    }

    /// The finding this arrangement exists for: a node that is *up* but stuck
    /// on a stale head must be failed over from, not treated as a success.
    ///
    /// Before the contract moved into the implementations, the slot check ran
    /// above `try_each`, so node 1's stale answer was accepted and returned and
    /// node 2 was never asked. The validator then missed every attestation
    /// while both nodes looked healthy, because nothing was ever `Err`.
    #[tokio::test]
    async fn a_node_answering_about_a_stale_slot_is_failed_over_from() {
        // Node 1 answers about slot 90 whatever it is asked; node 2 about 96.
        let stale = MockBeaconNode::new().with_attestation_data(90);
        let fresh = MockBeaconNode::new().with_attestation_data(96);
        let fallback = FallbackBeaconNode::new(vec![stale, fresh]);

        let data = fallback
            .attestation_data(96, ForkName::Electra)
            .await
            .expect("the second node answers correctly");

        assert_eq!(
            data.slot, 96,
            "the stale answer must not be the one returned"
        );
    }

    #[tokio::test]
    async fn every_node_answering_about_a_stale_slot_is_an_error() {
        // With nowhere left to fall through to, this must be a failure rather
        // than a stale answer quietly returned.
        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::new().with_attestation_data(90),
            MockBeaconNode::new().with_attestation_data(91),
        ]);

        let err = fallback
            .attestation_data(96, ForkName::Electra)
            .await
            .expect_err("no node answered about the requested slot");

        assert!(matches!(err, Error::AllBeaconNodesFailed(_)), "got {err:?}");
    }

    /// A syncing node at the head of the list must not stop duties being
    /// refreshed when a healthy node sits behind it.
    ///
    /// `is_syncing` returning `Ok(true)` is a *successful* call, so a plain
    /// `try_each` would return the first node's answer and never look further.
    /// `refresh_epoch` turns `true` into "do not refresh", so the second node
    /// would go unused for as long as the first was syncing.
    #[tokio::test]
    async fn a_syncing_first_node_does_not_mask_a_healthy_second() {
        let syncing = MockBeaconNode {
            syncing: true,
            ..MockBeaconNode::new()
        };
        let fallback = FallbackBeaconNode::new(vec![syncing, healthy()]);

        assert!(
            !fallback.is_optimistic_or_syncing().await.expect("answers"),
            "a healthy node behind a syncing one must be found"
        );
    }

    #[tokio::test]
    async fn every_node_syncing_reports_syncing() {
        // A real answer, not a failure: the caller should hold off, and saying
        // so beats an error claiming nothing could be reached.
        let syncing = || MockBeaconNode {
            syncing: true,
            ..MockBeaconNode::new()
        };
        let fallback = FallbackBeaconNode::new(vec![syncing(), syncing()]);

        assert!(fallback.is_optimistic_or_syncing().await.expect("answers"));
    }

    #[tokio::test]
    async fn a_syncing_node_is_preferred_over_no_answer_at_all() {
        // One node down, one syncing: `true` is the honest report, because a
        // node did answer and it said it was syncing.
        let syncing = MockBeaconNode {
            syncing: true,
            ..MockBeaconNode::new()
        };
        let fallback = FallbackBeaconNode::new(vec![MockBeaconNode::failing("down"), syncing]);

        assert!(fallback.is_optimistic_or_syncing().await.expect("answers"));
    }

    #[tokio::test]
    async fn no_node_answering_syncing_is_an_error() {
        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::failing("first down"),
            MockBeaconNode::failing("second down"),
        ]);

        let err = fallback
            .is_optimistic_or_syncing()
            .await
            .expect_err("nothing answered");
        assert!(matches!(err, Error::AllBeaconNodesFailed(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn every_node_failing_is_reported_as_such() {
        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::failing("first down"),
            MockBeaconNode::failing("second down"),
        ]);
        let err = fallback.genesis().await.expect_err("must fail");
        assert!(matches!(err, Error::AllBeaconNodesFailed(_)), "got {err:?}");
        assert!(err.to_string().contains("second down"), "got {err}");
    }

    /// A node that is up but whose duties poll is failing is a different
    /// shape from a node that is entirely down: `genesis` must still be
    /// served by it, while `attester_duties` must fall through to the next.
    #[tokio::test]
    async fn a_node_failing_one_call_still_serves_the_others() {
        let first = healthy().failing_call("attester_duties", "duties down");
        let second = healthy().with_duties(3, Root::repeat_byte(7), vec![]);

        let fallback = FallbackBeaconNode::new(vec![first, second]);

        let genesis = fallback.genesis().await.expect("first node answers");
        assert_eq!(genesis.genesis_time, 1_606_824_023);

        let duties = fallback
            .attester_duties(3, &[])
            .await
            .expect("second node answers");
        assert_eq!(duties.dependent_root, Root::repeat_byte(7));
    }

    fn request(slot: Slot, proposer_index: ValidatorIndex) -> BlockRequest {
        use ethlambda_types::beacon::primitives::{BlsSignature, Bytes32};
        BlockRequest {
            slot,
            fork: ForkName::Electra,
            proposer_index,
            randao_reveal: BlsSignature([0; 96]),
            graffiti: Bytes32::default(),
            builder_boost_factor: None,
        }
    }

    /// The proposal-shaped version of the stale-head finding above, and the
    /// more expensive one to get wrong: a block signed against a stale node's
    /// answer is a block for the wrong slot, and it burns the proposal guard's
    /// record for that validator on the way out.
    #[tokio::test]
    async fn a_node_producing_a_block_for_the_wrong_slot_is_failed_over_from() {
        let stale = MockBeaconNode::new().with_block(90, 7);
        let fresh = MockBeaconNode::new().with_block(96, 7);
        let fallback = FallbackBeaconNode::new(vec![stale, fresh]);

        let block = fallback
            .produce_block(&request(96, 7))
            .await
            .expect("the second node answers correctly");
        assert_eq!(block.slot(), 96);
    }

    /// A node on a different fork computes a different proposer. Signing its
    /// block would produce a signature the network discards, while the guard
    /// records the slot as proposed and refuses the real duty.
    #[tokio::test]
    async fn a_node_naming_the_wrong_proposer_is_failed_over_from() {
        let wrong = MockBeaconNode::new().with_block(96, 11);
        let right = MockBeaconNode::new().with_block(96, 7);
        let fallback = FallbackBeaconNode::new(vec![wrong, right]);

        let block = fallback
            .produce_block(&request(96, 7))
            .await
            .expect("the second node names the expected proposer");
        assert_eq!(block.proposer_index(), 7);
    }

    #[tokio::test]
    async fn every_node_naming_the_wrong_proposer_is_an_error() {
        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::new().with_block(96, 11),
            MockBeaconNode::new().with_block(96, 12),
        ]);

        let err = fallback
            .produce_block(&request(96, 7))
            .await
            .expect_err("no node produced a block for this proposer");
        assert!(matches!(err, Error::AllBeaconNodesFailed(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn a_block_is_published_to_the_first_node_that_accepts_it() {
        let fallback =
            FallbackBeaconNode::new(vec![MockBeaconNode::failing("down"), MockBeaconNode::new()]);

        let outcome = fallback
            .publish_block(ForkName::Electra, b"body")
            .await
            .expect("the second node accepts it");
        assert_eq!(outcome, Published::Imported);
        assert_eq!(
            fallback.nodes[1].published_blocks(),
            vec![(ForkName::Electra, b"body".to_vec())]
        );
        assert!(
            fallback.nodes[0].published_blocks().is_empty(),
            "the failing node recorded nothing"
        );
    }

    /// 202 means the node broadcast the block but could not import it. It is a
    /// success for the walk, so the second node is never tried, but it must not
    /// be reported to the caller as a clean proposal.
    #[tokio::test]
    async fn a_block_the_first_node_broadcast_but_could_not_import_stops_the_walk() {
        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::new().with_publish_outcome(Published::BroadcastNotImported),
            MockBeaconNode::new(),
        ]);

        let outcome = fallback
            .publish_block(ForkName::Electra, b"body")
            .await
            .expect("202 is not an error");
        assert_eq!(outcome, Published::BroadcastNotImported);
        assert!(
            fallback.nodes[1].published_blocks().is_empty(),
            "the block was already broadcast; the second node must not be asked"
        );
    }

    fn subscription(slot: Slot) -> CommitteeSubscriptionDto {
        CommitteeSubscriptionDto {
            validator_index: 1,
            committee_index: 2,
            committees_at_slot: 64,
            slot,
            is_aggregator: true,
        }
    }

    /// The finding this helper exists for: a subscription is state installed on
    /// a node, not a query with one right answer. Under `try_each` only node 1
    /// ever heard about this client's committees, and node 2 — the one failover
    /// exists to use — was left unable to serve the duty.
    #[tokio::test]
    async fn a_subscription_reaches_every_node_not_just_the_first() {
        let fallback = FallbackBeaconNode::new(vec![MockBeaconNode::new(), MockBeaconNode::new()]);
        fallback
            .subscribe_committees(&[subscription(96)])
            .await
            .expect("subscribes");

        assert_eq!(fallback.nodes[0].subscriptions().len(), 1);
        assert_eq!(
            fallback.nodes[1].subscriptions().len(),
            1,
            "the second node must be told too, or it cannot serve a failover"
        );
    }

    #[tokio::test]
    async fn a_fee_recipient_registration_reaches_every_node() {
        let fallback = FallbackBeaconNode::new(vec![MockBeaconNode::new(), MockBeaconNode::new()]);
        let preparations = [ProposerPreparationDto {
            validator_index: 1,
            fee_recipient: "0xab".to_string(),
        }];
        fallback
            .prepare_beacon_proposer(&preparations)
            .await
            .expect("registers");

        assert_eq!(fallback.nodes[0].preparations().len(), 1);
        assert_eq!(fallback.nodes[1].preparations().len(), 1);
    }

    /// One unreachable node must not stop the reachable ones being told.
    #[tokio::test]
    async fn one_failing_node_does_not_stop_the_others_being_subscribed() {
        let fallback =
            FallbackBeaconNode::new(vec![MockBeaconNode::failing("down"), MockBeaconNode::new()]);
        fallback
            .subscribe_committees(&[subscription(96)])
            .await
            .expect("the healthy node accepted");

        assert!(fallback.nodes[0].subscriptions().is_empty());
        assert_eq!(fallback.nodes[1].subscriptions().len(), 1);
    }

    #[tokio::test]
    async fn no_node_accepting_a_subscription_is_an_error() {
        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::failing("down"),
            MockBeaconNode::failing("also down"),
        ]);
        let err = fallback
            .subscribe_committees(&[subscription(96)])
            .await
            .expect_err("nothing was registered anywhere");
        assert!(matches!(err, Error::AllBeaconNodesFailed(_)), "got {err:?}");
    }

    /// The other direction, stated so the two rules do not drift: a query still
    /// stops at the first node that answers. Asking every node for a block
    /// would make every node build one.
    #[tokio::test]
    async fn a_query_still_stops_at_the_first_node_that_answers() {
        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::new().with_block(96, 7),
            MockBeaconNode::new().with_block(96, 7),
        ]);
        fallback
            .produce_block(&request(96, 7))
            .await
            .expect("the first node answers");

        assert_eq!(fallback.nodes[0].block_requests().len(), 1);
        assert!(
            fallback.nodes[1].block_requests().is_empty(),
            "the second node must not have been asked to build a block too"
        );
    }

    #[tokio::test]
    async fn an_optimistic_head_fails_over_to_the_next_node() {
        let mut optimistic = MockBeaconNode::new().with_head_root(Root::repeat_byte(1));
        optimistic.head_optimistic = true;
        let healthy = MockBeaconNode::new().with_head_root(Root::repeat_byte(2));
        let fallback = FallbackBeaconNode::new(vec![optimistic, healthy]);

        assert_eq!(
            fallback.head_block_root().await.expect("second answers"),
            Root::repeat_byte(2)
        );
    }

    #[tokio::test]
    async fn a_sync_subscription_reaches_every_node() {
        let fallback = FallbackBeaconNode::new(vec![MockBeaconNode::new(), MockBeaconNode::new()]);
        let subscription = SyncCommitteeSubscriptionDto {
            validator_index: 1,
            sync_committee_indices: vec![3],
            until_epoch: 256,
        };
        fallback
            .subscribe_sync_committees(&[subscription])
            .await
            .expect("subscribes");

        assert_eq!(fallback.nodes[0].sync_subscriptions().len(), 1);
        assert_eq!(
            fallback.nodes[1].sync_subscriptions().len(),
            1,
            "try_all, not try_each"
        );
    }

    /// The pair a beacon node can genuinely report and this client must still
    /// refuse: caught up, but tracking a head its execution client has not
    /// validated. The specification makes not signing in that position a MUST,
    /// and checking only `is_syncing` would miss it entirely.
    #[tokio::test]
    async fn a_synced_but_optimistic_node_is_not_usable() {
        let mut node = MockBeaconNode::new();
        node.syncing = false;
        node.optimistic = true;
        let fallback = FallbackBeaconNode::new(vec![node]);

        assert!(
            fallback.is_optimistic_or_syncing().await.expect("answers"),
            "an optimistic node must be refused even though it is not syncing"
        );
    }

    /// And the failover half of the same: an optimistic first node must not
    /// mask a healthy second, exactly as a syncing one must not.
    #[tokio::test]
    async fn an_optimistic_first_node_does_not_mask_a_healthy_second() {
        let mut optimistic = MockBeaconNode::new();
        optimistic.optimistic = true;
        let fallback = FallbackBeaconNode::new(vec![optimistic, MockBeaconNode::new()]);

        assert!(
            !fallback.is_optimistic_or_syncing().await.expect("answers"),
            "the healthy second node must be found"
        );
    }

    fn blinded_request(slot: Slot, proposer_index: ValidatorIndex) -> BlockRequest {
        BlockRequest {
            builder_boost_factor: Some(100),
            ..request(slot, proposer_index)
        }
    }

    fn blinded_node() -> MockBeaconNode {
        MockBeaconNode::new().with_block(5, 7).with_blinded_block()
    }

    /// Node 0 cannot produce, node 1 can and answers blinded: the block must go
    /// back to node 1, and node 0 must never see it.
    #[tokio::test]
    async fn a_blinded_block_is_published_where_it_was_produced() {
        let first = MockBeaconNode::new().failing_call("produce_block", "down");
        let fallback = FallbackBeaconNode::new(vec![first, blinded_node()]);

        let produced = fallback
            .produce_block(&blinded_request(5, 7))
            .await
            .expect("node 1 produces");
        assert!(produced.is_blinded());

        let published = fallback
            .publish_blinded_block(5, ForkName::Electra, &[1, 2, 3])
            .await
            .expect("published");
        assert_eq!(published, Published::HandedToBuilder);

        let first_published = fallback.nodes[0].published_blinded.lock().expect("lock");
        let second_published = fallback.nodes[1].published_blinded.lock().expect("lock");
        assert!(first_published.is_empty(), "node 0 never produced it");
        assert_eq!(
            *second_published,
            vec![(5, ForkName::Electra, vec![1, 2, 3])]
        );
    }

    /// The producing node failing the publish is the end of it: another node's
    /// builder never saw the bid, so it must not be offered the block.
    #[tokio::test]
    async fn a_blinded_publish_does_not_fail_over() {
        let second = blinded_node().with_unconfirmed_blinded_publish("relay timed out");
        let first = MockBeaconNode::new().failing_call("produce_block", "down");
        let fallback = FallbackBeaconNode::new(vec![first, second]);

        fallback
            .produce_block(&blinded_request(5, 7))
            .await
            .expect("node 1 produces");
        let err = fallback
            .publish_blinded_block(5, ForkName::Electra, &[9])
            .await
            .expect_err("node 1 failed to confirm");
        assert!(
            matches!(err, Error::BlindedUnconfirmed { .. }),
            "got {err:?}"
        );
        assert!(
            fallback.nodes[0]
                .published_blinded
                .lock()
                .expect("lock")
                .is_empty(),
            "no failover to node 0"
        );
    }

    #[tokio::test]
    async fn a_blinded_publish_for_another_slot_is_refused() {
        let fallback = FallbackBeaconNode::new(vec![blinded_node()]);
        fallback
            .produce_block(&blinded_request(5, 7))
            .await
            .expect("produces");

        let err = fallback
            .publish_blinded_block(6, ForkName::Electra, &[1])
            .await
            .expect_err("nothing was produced for slot 6");
        assert!(matches!(err, Error::InconsistentResponse(_)), "got {err:?}");
        assert!(
            fallback.nodes[0]
                .published_blinded
                .lock()
                .expect("lock")
                .is_empty()
        );
    }

    /// A full block produced afterwards clears the claim, so an old blinded
    /// block's slot cannot be published against a node that no longer holds it.
    #[tokio::test]
    async fn a_full_block_clears_the_blinded_record() {
        let fallback = FallbackBeaconNode::new(vec![blinded_node()]);
        fallback
            .produce_block(&blinded_request(5, 7))
            .await
            .expect("blinded");
        fallback
            .produce_block(&request(5, 7))
            .await
            .expect("full, since no factor was sent");

        fallback
            .publish_blinded_block(5, ForkName::Electra, &[1])
            .await
            .expect_err("the record is gone");
    }

    #[tokio::test]
    async fn proposer_preferences_reach_every_node_past_a_failing_one() {
        use ethlambda_types::beacon::containers::gloas::{
            ProposerPreferences, SignedProposerPreferences,
        };

        let preference = SignedProposerPreferences {
            message: ProposerPreferences {
                proposal_slot: 70,
                ..Default::default()
            },
            ..Default::default()
        };
        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::new(),
            MockBeaconNode::failing("middle down"),
            MockBeaconNode::new(),
        ]);

        fallback
            .submit_proposer_preferences(ForkName::Fulu, std::slice::from_ref(&preference))
            .await
            .expect("two of three accepted");

        for position in [0, 2] {
            assert_eq!(
                *fallback.nodes[position]
                    .submitted_preferences
                    .lock()
                    .expect("lock"),
                vec![(ForkName::Fulu, vec![preference.clone()])],
                "node {position}"
            );
        }
        assert!(
            fallback.nodes[1]
                .submitted_preferences
                .lock()
                .expect("lock")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn registrations_reach_every_node() {
        use ethlambda_types::beacon::builder::{
            SignedValidatorRegistrationV1, ValidatorRegistrationV1,
        };
        use ethlambda_types::beacon::primitives::{BlsPubkey, BlsSignature, H160};

        let registration = SignedValidatorRegistrationV1 {
            message: ValidatorRegistrationV1 {
                fee_recipient: H160([1; 20]),
                gas_limit: 30_000_000,
                timestamp: 5,
                pubkey: BlsPubkey([2; 48]),
            },
            signature: BlsSignature([3; 96]),
        };
        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::new(),
            MockBeaconNode::failing("middle down"),
            MockBeaconNode::new(),
        ]);

        fallback
            .register_validators(std::slice::from_ref(&registration))
            .await
            .expect("two of three accepted");

        for position in [0, 2] {
            assert_eq!(
                *fallback.nodes[position].registrations.lock().expect("lock"),
                vec![registration.clone()],
                "node {position}"
            );
        }
        assert!(
            fallback.nodes[1]
                .registrations
                .lock()
                .expect("lock")
                .is_empty()
        );
    }
}
