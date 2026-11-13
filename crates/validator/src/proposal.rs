//! Producing, signing and publishing this slot's block.
//!
//! The attestation path's counterpart, and deliberately shaped like it. What
//! differs is the cost of each step and therefore where the checks sit.
//!
//! # Three signatures, one slot
//!
//! A proposal needs two signatures from this client and gets a third thing
//! back from the beacon node in between:
//!
//! 1. The **RANDAO reveal** for the slot's epoch, signed first because the node
//!    cannot build a body without it. It is not slashable and is not checked
//!    against slashing protection.
//! 2. The **block**, built by the beacon node around that reveal. This client
//!    never chooses a block's contents; it asks for one and checks that what
//!    came back is the one it asked for.
//! 3. The **block signature**, which is slashable, and which
//!    [`crate::slashing_protection`] must allow and record first.
//!
//! # Why slashing protection is consulted twice
//!
//! Once before asking for a block, once before signing it.
//!
//! The early check is not about safety, it is about cost. Producing a block
//! makes the beacon node drive an execution-layer payload build, which is the
//! most expensive thing this client can ask of it. Discovering only afterwards
//! that the slot was already proposed wastes that for nothing.
//!
//! The check before signing is the one that matters, and it records, durably,
//! before the signature exists. Recording then rather than after publication is
//! what makes the duty loop's deadline and a crash both safe: a proposal
//! abandoned between signing and publishing cannot be re-signed, because the
//! record already counts that slot as proposed.
//!
//! # Gloas: the block, then its envelope
//!
//! From gloas the block commits to a bid and the payload is revealed in an
//! envelope the builder signs. This client reveals only its own payloads: when
//! the bid names the self-build sentinel, the proposer's own key signs the
//! envelope under the builder domain, and it is published right after the
//! block, in the same budget. A bid naming anyone else is a builder's to
//! reveal, and is left alone.
//!
//! # A builder's bid without `--builder-proposals`
//!
//! Without the flag a gloas block request carries a boost factor of `0`,
//! which beacon-APIs defines as the local payload unless it cannot be built.
//! A node whose execution client fails at the slot may therefore build on a
//! pooled p2p bid, and this client signs that block rather than refusing it.
//! A refusal would cost the slot as well as its payload, where the bid pays
//! the fee recipient this validator's preference named. Lighthouse, Prysm and Teku sign it too, and their nodes
//! fall back the same way; Lodestar refuses it only in its opt-in
//! `executiononly` mode. Before gloas a blinded block is refused instead, but
//! for another reason: without the flag this client has no way to publish
//! one.
//!
//! The envelope is not slashable, so slashing protection is untouched by it.
//!
//! The node pays the fee recipient of the proposer preference it holds for
//! the slot, which names the address in force when it was signed. The check
//! before signing therefore accepts that address as well as the current one.
//!
//! # Blinded blocks
//!
//! With builder proposals on, the node may answer with a blinded block: the
//! payload's header in place of the payload. Its root is the full block's, so
//! slashing protection, the signing root and the signature are exactly what a
//! full block gets, and the same slot-level protections apply.
//!
//! The fee recipient is not compared for a blinded block. The header names the
//! builder's address, and the relay pays the validator inside the payload, so
//! a mismatch there is the flow working rather than a node paying someone else.
//!
//! The signed block goes to `blinded_blocks` on the node that produced it and
//! on no other (the block's [`Producer`]): only that node's builder holds the
//! payload. A publish the node fails to confirm is reported as
//! [`BlindedOutcome::Unconfirmed`] rather than as a missed proposal, since the
//! relay may still publish the block.
//!
//! # The deadline
//!
//! The duty loop gives a proposal until the point attesters stop waiting for
//! the block ([`ProposalService::propose_by`]). Everything up to a full
//! block's publish ends there. A signed blinded block's publish does not: it
//! runs on its own task, since the beacon node waits up to 5 s for the relay,
//! and past the deadline the proposal returns
//! [`BlindedOutcome::StillPublishing`] while the task reports the outcome.
//! The deadline is enforced here rather than by the caller dropping the
//! future, because only here is it known whether a blinded block was signed.
//!
//! # Do not retry this call within a slot
//!
//! For the same reason [`crate::attestation::AttestationService::attest`] must
//! not be: a second call asks the node for a second block, which will differ
//! from the first because the node has packed whatever arrived in between, and
//! two distinct blocks for one slot from one validator is a slashable proposer
//! offence. Slashing protection refuses it, so a retry is merely useless rather
//! than dangerous, but the caller should not be relying on that.

use std::sync::Arc;
use std::time::SystemTime;

use ethlambda_types::beacon::constants::BUILDER_INDEX_SELF_BUILD;
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::primitives::{BlsPubkey, ExecutionAddress, Root, Slot};
use ethlambda_types::beacon::signing::compute_epoch_at_slot;
use tokio::sync::RwLock;
use tokio::time::Instant;
use tracing::{error, info, warn};

use crate::beacon_node::block_contents::{GloasPayload, Producer, signed_envelope_ssz};
use crate::beacon_node::dto::{ProposerDutyDto, encode_hex, parse_pubkey};
use crate::beacon_node::{BeaconNodeApi, BlockRequest, Published, validate_produced_block};
use crate::error::{Error, Result};
use crate::keys::ValidatorStore;
use crate::preferences::PreferencesService;
use crate::proposer_settings::ProposerSettings;
use crate::signing::SigningContext;
use crate::slashing_protection::{Refusal, SharedProtection};
use crate::slot_clock::SlotClock;

/// What became of a proposal, as the duty loop needs it.
///
/// Every outcome here has already been logged and its block counted. What the
/// loop still owes is the publication delay of a block the node confirmed
/// while it was waiting: [`Proposed::Full`] and
/// [`BlindedOutcome::Published`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proposed {
    /// A full block, and what the node made of it.
    Full(Published),
    /// A blinded block, signed and sent to the node that produced it.
    Blinded(BlindedOutcome),
}

/// What became of a signed blinded block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlindedOutcome {
    /// The node confirmed it: handed to its builder, or broadcast but not
    /// imported (a 202).
    Published(Published),
    /// The node did not confirm it, so the relay may still publish it (see
    /// [`Error::BlindedUnconfirmed`]). Logged at error and counted on its own
    /// series: neither a published block nor a failed proposal. Not retried,
    /// since the slot is signed and a second block would be an equivocation.
    Unconfirmed,
    /// The publish outlived the deadline and goes on, on its own task, which
    /// logs and counts the outcome when it comes: a refusal as a failed
    /// proposal, a confirmed block with its publication delay.
    StillPublishing,
}

/// A block signed and ready to publish: what [`ProposalService::produce_and_sign`]
/// hands the publish step.
struct SignedBlock {
    pubkey: BlsPubkey,
    fork: ForkName,
    block_root: Root,
    blinded: bool,
    producer: Producer,
    /// The self-built payload's envelope, taken out before the block was
    /// signed into its body (gloas only).
    payload: Option<GloasPayload>,
    builder_index: Option<u64>,
    body: Vec<u8>,
}

/// `future`'s result, or [`Error::ProposalDeadline`] once `deadline` passes.
/// With no deadline, `future` runs to the end.
///
/// A future that completes is never discarded, even at the deadline: the
/// timeout is checked only after the future has been polled.
async fn before<T>(
    deadline: Option<Instant>,
    slot: Slot,
    future: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    match deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, future)
            .await
            .unwrap_or(Err(Error::ProposalDeadline { slot })),
        None => future.await,
    }
}

pub struct ProposalService<B> {
    beacon_node: Arc<B>,
    context: Arc<SigningContext>,
    /// Each validator's graffiti, sent with its block request, and fee
    /// recipient.
    ///
    /// The fee recipient is held only to check what comes back. The beacon node
    /// is the one that builds the payload, and the specification is explicit
    /// that it need not honour the preparation it was sent.
    settings: Arc<ProposerSettings>,
    /// What every validator has signed, shared with the attestation service
    /// and the keymanager. See [`crate::slashing_protection`].
    protection: SharedProtection,
    /// The `builder_boost_factor` sent with each block request, or `None` when
    /// builder proposals are off, in which case a blinded answer is refused.
    builder_boost_factor: Option<u64>,
    /// The `min_bid` sent with each gloas block request, in gwei: the floor
    /// below which the node takes no p2p bid. `0` unless set.
    builder_min_bid: u64,
    /// Where a slot starts, so a blinded publish that outlives the deadline
    /// can observe its own publication delay. `None` observes nothing.
    clock: Option<SlotClock>,
    /// The proposer preferences a node accepted, whose fee recipient a gloas
    /// block may rightly pay instead of the current one. `None` compares
    /// against the current one alone.
    preferences: Option<Arc<PreferencesService<B>>>,
}

impl<B: BeaconNodeApi + 'static> ProposalService<B> {
    pub fn new(
        beacon_node: Arc<B>,
        context: Arc<SigningContext>,
        settings: Arc<ProposerSettings>,
        protection: SharedProtection,
        builder_boost_factor: Option<u64>,
    ) -> Self {
        Self {
            beacon_node,
            context,
            settings,
            protection,
            builder_boost_factor,
            builder_min_bid: 0,
            clock: None,
            preferences: None,
        }
    }

    /// Send `min_bid` (gwei) with every gloas block request, so the node
    /// takes no p2p bid below it.
    pub fn with_builder_min_bid(mut self, min_bid: u64) -> Self {
        self.builder_min_bid = min_bid;
        self
    }

    /// Give the service the proposer preferences this client published, so
    /// the fee recipient check accepts the address a gloas block's node was
    /// given in them.
    pub fn with_preferences(mut self, preferences: Arc<PreferencesService<B>>) -> Self {
        self.preferences = Some(preferences);
        self
    }

    /// Give the service the slot clock, so a blinded block's publication delay
    /// is observed by the task that publishes it when that outlives
    /// [`Self::propose_by`]'s deadline.
    pub fn with_clock(mut self, clock: SlotClock) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Whether the produced block's fee recipient is this client's to compare.
    ///
    /// Not for a blinded block: its header names the builder's address, and the
    /// relay pays the validator inside the payload it reveals, so a difference
    /// there is the flow working, not a node paying someone else.
    fn compares_fee_recipient(
        produced: &crate::beacon_node::block_contents::ProducedBlock,
    ) -> bool {
        !produced.is_blinded()
    }

    /// Compare the produced block's fee recipient against what was asked for,
    /// and complain loudly if they differ.
    ///
    /// # Why this warns instead of refusing
    ///
    /// The specification requires the check and leaves the response open: a
    /// client "should confirm that it finds the fee recipient within the block
    /// acceptable before signing it". Both answers cost the operator money, and
    /// they are not the same amount.
    ///
    /// Refusing loses the consensus-layer reward *and* the execution-layer one,
    /// and costs the network a slot. Signing loses only the execution-layer
    /// reward, which was already going elsewhere the moment the node built the
    /// payload. So signing is the cheaper of the two for the operator and
    /// strictly better for the network, and the thing that actually fixes it is
    /// the operator noticing.
    ///
    /// Hence `error!` rather than `warn!`, and a counter beside it: this should
    /// never happen, and when it does it is a misconfigured or untrustworthy
    /// beacon node paying someone else, every time this validator proposes.
    ///
    /// With no configured address and no published preference there is
    /// nothing to compare against and this says nothing, which is the same
    /// silence as a matching one; the startup warning is where that case is
    /// reported.
    fn check_fee_recipient(
        produced: &crate::beacon_node::block_contents::ProducedBlock,
        current: Option<ExecutionAddress>,
        preferred: &[ExecutionAddress],
        slot: Slot,
    ) {
        // The payload's before gloas, the bid's from it on: the same address
        // the execution layer is told to pay, read where the block keeps it.
        let actual = produced.fee_recipient();
        if Self::pays_this_validator(actual, current, preferred) != Some(false) {
            return;
        }
        let expected: Vec<String> = current
            .iter()
            .chain(preferred)
            .map(|address| crate::beacon_node::dto::encode_hex(&address.0))
            .collect();
        tracing::error!(
            %slot,
            expected = %expected.join(","),
            actual = %crate::beacon_node::dto::encode_hex(&actual.0),
            "Block pays its execution-layer rewards to an address this client did not ask for; \
             signing it anyway, since refusing would also forfeit the consensus reward and cost \
             the network a slot. Check this beacon node's proposer preparation. A fee recipient \
             changed through the keymanager API reaches the node at the next epoch boundary; \
             from gloas, a proposer preference published before the change (by this process \
             before a restart, say) keeps the old address until the next dependent root."
        );
        crate::metrics::inc_fee_recipient_mismatches();
    }

    /// Whether `actual` is an address this validator asked to be paid at: its
    /// `current` one, or one of the proposer preferences a node accepted for
    /// the slot (`preferred`), which from gloas a node builds with in
    /// preference to the current address, and which name the address in force
    /// when they were signed. `None` when there is nothing to compare against.
    fn pays_this_validator(
        actual: ExecutionAddress,
        current: Option<ExecutionAddress>,
        preferred: &[ExecutionAddress],
    ) -> Option<bool> {
        if current.is_none() && preferred.is_empty() {
            return None;
        }
        Some(current == Some(actual) || preferred.contains(&actual))
    }

    /// Produce, sign and publish the block for `slot`, however long it takes.
    ///
    /// [`Self::propose_by`] with no deadline, so a blinded block's publish is
    /// always waited for and never comes back as
    /// [`BlindedOutcome::StillPublishing`].
    pub async fn propose(
        &self,
        slot: Slot,
        duty: &ProposerDutyDto,
        store: &RwLock<ValidatorStore>,
    ) -> Result<Proposed> {
        self.propose_within(slot, duty, store, None).await
    }

    /// Produce, sign and publish the block for `slot`, giving up at
    /// `deadline`.
    ///
    /// # What the deadline cuts
    ///
    /// Production and signing, and a full block's publish (with its envelope
    /// from gloas), end at the deadline with [`Error::ProposalDeadline`]: a
    /// full block that late has lost most of its value, and every further
    /// second comes out of the slot's attestations.
    ///
    /// A signed blinded block's publish is not cut: the beacon node may wait
    /// several seconds on the relay, and the block may already be out. It runs
    /// on its own task, and at the deadline this returns
    /// [`BlindedOutcome::StillPublishing`] while the task reports the outcome.
    /// Whichever of the two ends up holding the outcome reports it, so a
    /// caller that awaits this to the end, as the duty loop does, sees each
    /// outcome reported once (see [`Self::publish_blinded`] for the edges).
    pub async fn propose_by(
        &self,
        slot: Slot,
        duty: &ProposerDutyDto,
        store: &RwLock<ValidatorStore>,
        deadline: Instant,
    ) -> Result<Proposed> {
        self.propose_within(slot, duty, store, Some(deadline)).await
    }

    async fn propose_within(
        &self,
        slot: Slot,
        duty: &ProposerDutyDto,
        store: &RwLock<ValidatorStore>,
        deadline: Option<Instant>,
    ) -> Result<Proposed> {
        // Nothing awaits between signing and the end of `produce_and_sign`,
        // and a completed future is never discarded at the deadline, so a
        // signed block always reaches the publish step below.
        let signed = before(deadline, slot, self.produce_and_sign(slot, duty, store)).await?;
        let validator = duty.validator_index;
        if signed.blinded {
            return self
                .publish_blinded(
                    slot,
                    validator,
                    signed.producer,
                    signed.fork,
                    signed.body,
                    deadline,
                )
                .await;
        }
        before(
            deadline,
            slot,
            self.publish_full(slot, validator, store, signed),
        )
        .await
        .map(Proposed::Full)
    }

    /// Everything up to and including the block signature: the slashing
    /// protection checks, the RANDAO reveal, the block request and the checks
    /// on what came back.
    async fn produce_and_sign(
        &self,
        slot: Slot,
        duty: &ProposerDutyDto,
        store: &RwLock<ValidatorStore>,
    ) -> Result<SignedBlock> {
        let pubkey = parse_pubkey(&duty.pubkey)?;
        let epoch = compute_epoch_at_slot(slot);

        // Before paying for a block, not after. See the module doc. Off the
        // executor even though it only reads: the record may be mid-write for
        // another caller. A record that cannot be consulted is a refusal, not
        // a crash in the duty path.
        let checked = crate::slashing_protection::blocking(&self.protection, move |protection| {
            Ok(protection.check_block(&pubkey, slot))
        })
        .await;
        refuse_unless_safe(slot, duty.validator_index, "consult", checked)?;

        // Scoped away from every await, the way the attestation path's read
        // guard is, and for the reason spelled out there: a write-preferring
        // lock lets one queued keymanager writer block every reader behind it,
        // so a guard held across the block production round trip below would
        // put the whole duty path behind it.
        let randao_reveal = {
            let store = store.read().await;
            self.context.sign_randao(&store, &pubkey, epoch)?
        };

        // Both read once, before the block is asked for, so the check below
        // compares against the address in force when the request went out.
        let graffiti = self.settings.graffiti(&pubkey);
        let fee_recipient = self.settings.fee_recipient(&pubkey);
        let request = BlockRequest {
            slot,
            fork: self.context.config.fork_at_epoch(epoch),
            proposer_index: duty.validator_index,
            randao_reveal,
            graffiti,
            builder_boost_factor: self.builder_boost_factor,
            builder_min_bid: self.builder_min_bid,
        };
        let mut produced = self.beacon_node.produce_block(&request).await?;

        // Checked again here, having already been checked by the
        // implementation this call went through. Not redundant, and the
        // attestation path does the same for the same reason: the trait is
        // public, so this is the last point at which a wrong answer from an
        // implementation that failed to honour its contract can be stopped
        // before it becomes a signature.
        //
        // It matters more here than it reads. Slashing protection records the
        // *requested* slot while the signature covers the *produced* header's
        // slot. If those ever diverged and both fell in one epoch, the domain
        // would be identical and the result would be a valid, unrecorded
        // second block for a slot already proposed.
        validate_produced_block(&request, &produced)?;

        // Also the implementation's contract, and checked again for the same
        // reason. With builder proposals off this client never publishes a
        // blinded block, so signing one would record the slot in slashing
        // protection for a block that can never be sent. A gloas block built
        // on a builder's bid is not refused here: it is a full block, and the
        // module doc says why it is signed.
        if produced.is_blinded() && self.builder_boost_factor.is_none() {
            return Err(Error::InconsistentResponse(format!(
                "node produced a blinded block for slot {slot}; builder proposals are off, so \
                 this client cannot publish one"
            )));
        }

        // The node's fork and this client's must agree, or the signature is
        // computed under a fork version the network does not accept.
        //
        // The two are separate facts. The block was decoded, and will be
        // published, under the fork the node named in its response header. The
        // signing domain comes from this client's own fork schedule, fetched
        // from `/config/spec` at startup. They normally agree because they came
        // from the same place; when they do not, one of them is wrong about
        // where a fork boundary sits, and signing anyway produces a block that
        // is rejected for a reason nothing in the logs would explain.
        let expected = self.context.config.fork_at_epoch(epoch);
        if produced.fork != expected {
            return Err(Error::InconsistentResponse(format!(
                "node produced a {} block for slot {slot}, but this client's fork schedule puts \
                 epoch {epoch} in {}; signing would use the wrong fork version",
                produced.fork.as_str(),
                expected.as_str()
            )));
        }

        if Self::compares_fee_recipient(&produced) {
            let preferred = self
                .preferences
                .as_ref()
                .map(|preferences| preferences.accepted_fee_recipients(slot, duty.validator_index))
                .unwrap_or_default();
            Self::check_fee_recipient(&produced, fee_recipient, &preferred, slot);
        } else {
            tracing::debug!(
                %slot,
                "Blinded block: its header names the builder's address; the relay pays the \
                 validator in the payload"
            );
        }

        let fork = produced.fork;
        let blinded = produced.is_blinded();
        info!(
            %slot,
            validator = duty.validator_index,
            fork = fork.as_str(),
            blinded,
            blobs = produced.blob_count(),
            "Block produced; signing"
        );

        // The root is taken from the decoded container, never from anything
        // reassembled here, and it is taken once: the same value is what the
        // recorded slot belongs to and what the signature covers.
        let block_root = produced.block_root();

        // The check that matters, and the one that records, durably, before
        // the signature exists. Everything after this point may be abandoned
        // without risk, because the record already counts this slot as
        // proposed. Off the executor, and before the store's read lock below,
        // so the disk flush never holds up a keymanager writer.
        let recorded = crate::slashing_protection::blocking(&self.protection, move |protection| {
            protection.check_and_record_block(&pubkey, slot)
        })
        .await;
        refuse_unless_safe(slot, duty.validator_index, "record", recorded)?;

        let signature = {
            let store = store.read().await;
            self.context.sign_block(&store, &pubkey, block_root, slot)?
        };

        // Nothing below awaits: see `propose_within`.
        //
        // Taken out before the block is signed into its body: the envelope is
        // published on its own, after the block, and the bare gloas block body
        // has no place for it.
        let payload = produced.take_gloas_payload();
        let builder_index = produced.builder_index();
        let producer = produced.producer;
        Ok(SignedBlock {
            pubkey,
            fork,
            block_root,
            blinded,
            producer,
            payload,
            builder_index,
            body: produced.into_signed_ssz(signature),
        })
    }

    /// Publish a signed full block, then, for a self-built gloas payload, its
    /// envelope.
    async fn publish_full(
        &self,
        slot: Slot,
        validator: u64,
        store: &RwLock<ValidatorStore>,
        signed: SignedBlock,
    ) -> Result<Published> {
        let SignedBlock {
            pubkey,
            fork,
            block_root,
            payload,
            builder_index,
            body,
            ..
        } = signed;
        let published = self.publish(fork, &body, slot, validator).await?;
        crate::metrics::inc_blocks_proposed();

        // Only a self-built payload is this client's to reveal.
        if builder_index == Some(BUILDER_INDEX_SELF_BUILD) {
            // Logged and counted rather than propagated. The block is out and
            // the proposal did happen; what failed is the reveal, which has its
            // own series because it is the failure that costs the payload.
            let _ = self
                .publish_envelope(slot, validator, &pubkey, block_root, payload, store)
                .await
                .inspect(|()| crate::metrics::inc_envelopes_published())
                .inspect_err(|err| {
                    tracing::error!(
                        %slot,
                        validator,
                        block_root = %ethlambda_types::ShortRoot(&block_root.0),
                        %err,
                        "Block published but its envelope was not; the slot's payload is withheld"
                    );
                    crate::metrics::inc_envelope_failures();
                });
        } else if let Some(builder_index) = builder_index {
            info!(
                %slot,
                builder_index,
                "Block commits to a builder's bid; leaving the payload reveal to that builder"
            );
        }
        Ok(published)
    }

    /// Reveal the self-built payload of the block just published.
    ///
    /// `payload` is what `produceBlockV4` returned with the block, or `None`
    /// when the node did not include it, in which case it is fetched by
    /// `(slot, block_root)` from the node's cache. Either way it is checked to
    /// be for this block and this self-build before it is signed: the signature
    /// covers the envelope as it stands, so one for another block would be a
    /// valid signature on the wrong payload.
    async fn publish_envelope(
        &self,
        slot: Slot,
        validator: u64,
        pubkey: &BlsPubkey,
        block_root: Root,
        payload: Option<GloasPayload>,
        store: &RwLock<ValidatorStore>,
    ) -> Result<()> {
        let included = payload.is_some();
        let envelope = match &payload {
            Some(payload) => payload.envelope.clone(),
            None => {
                self.beacon_node
                    .execution_payload_envelope(slot, block_root)
                    .await?
            }
        };
        if envelope.beacon_block_root != block_root {
            return Err(Error::InconsistentResponse(format!(
                "envelope for slot {slot} reveals the payload of block {}, not of the block \
                 this client proposed ({})",
                encode_hex(&envelope.beacon_block_root.0),
                encode_hex(&block_root.0)
            )));
        }
        if envelope.builder_index != BUILDER_INDEX_SELF_BUILD {
            return Err(Error::InconsistentResponse(format!(
                "envelope for slot {slot} names builder {}, but the bid was a self-build",
                envelope.builder_index
            )));
        }

        let signature = {
            let store = store.read().await;
            self.context
                .sign_execution_payload_envelope(&store, pubkey, &envelope, slot)?
        };
        let body = match payload {
            Some(payload) => payload.into_signed_contents_ssz(signature),
            None => signed_envelope_ssz(envelope, signature),
        };
        self.beacon_node
            .publish_execution_payload_envelope(&body, included)
            .await?;
        info!(%slot, validator, bytes = body.len(), blob_data_included = included, "Envelope published");
        Ok(())
    }

    /// Send a signed blinded block to the node that produced it.
    ///
    /// # On its own task, reported by whoever holds the outcome
    ///
    /// The request runs on a spawned task, so neither the deadline nor a
    /// dropped proposal cancels it: the beacon node may wait up to 5 s on the
    /// relay, and the block may already be out. The task logs and counts the
    /// node's answer ([`blinded_outcome`]) and hands the outcome back over a
    /// channel. Whoever holds it then does the rest: the duty loop when this
    /// returns it in time, and the task itself when this has stopped waiting
    /// ([`report_unawaited`]). For a caller that awaits this to the end, the
    /// channel decides which, so it is never both and never neither.
    ///
    /// Two edges are not covered. A task that panics after the deadline is
    /// reported by nobody. A caller that drops the proposal after the task
    /// has sent its outcome takes the rest of the reporting (the delay sample,
    /// or a refusal's failure count) with it. The node's answer itself is
    /// logged and counted by the task either way.
    ///
    /// # Why an unconfirmed publish is not an error
    ///
    /// A 5xx or a missing answer once connected does not say the block was not
    /// published: the node may have handed it to the relay, which publishes
    /// regardless of what the node then replied. So that outcome is logged
    /// loudly and counted on its own series, and returned as
    /// [`BlindedOutcome::Unconfirmed`]. It is not retried: the slot is signed,
    /// and a second block for it would be an equivocation. A definite failure
    /// (a 4xx, a 503, a connection never made; see
    /// [`BeaconNodeApi::publish_blinded_block`]) is an error, a failed
    /// proposal.
    async fn publish_blinded(
        &self,
        slot: Slot,
        validator: u64,
        producer: Producer,
        fork: ForkName,
        body: Vec<u8>,
        deadline: Option<Instant>,
    ) -> Result<Proposed> {
        let beacon_node = self.beacon_node.clone();
        let slot_start = self.clock.as_ref().map(|clock| clock.start_of(slot));
        let (handoff, mut outcome) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let bytes = body.len();
            let answer = beacon_node
                .publish_blinded_block(producer, fork, &body)
                .await;
            let outcome = blinded_outcome(slot, validator, bytes, answer);
            // Fails once the receiving side has stopped waiting, which hands
            // the outcome back here to report.
            if let Err(outcome) = handoff.send(outcome) {
                report_unawaited(slot, validator, slot_start, outcome);
            }
        });

        let received = match deadline {
            None => (&mut outcome).await,
            Some(deadline) => match tokio::time::timeout_at(deadline, &mut outcome).await {
                Ok(received) => received,
                Err(_) => {
                    // Stop waiting. After `close`, the task's send fails and
                    // the task reports; an outcome sent before it is still
                    // here, and is taken.
                    outcome.close();
                    match outcome.try_recv() {
                        Ok(sent) => Ok(sent),
                        Err(_) => return Ok(Proposed::Blinded(BlindedOutcome::StillPublishing)),
                    }
                }
            },
        };
        match received {
            Ok(outcome) => outcome.map(Proposed::Blinded),
            // The task ended without sending, so it panicked. The block may or
            // may not have gone out, which is what "unconfirmed" says.
            Err(_) => {
                tracing::error!(%slot, validator, "The blinded publish task failed");
                crate::metrics::inc_blinded_blocks_unconfirmed();
                Ok(Proposed::Blinded(BlindedOutcome::Unconfirmed))
            }
        }
    }

    /// Send the signed body and report what the node made of it.
    ///
    /// Split out so the 202 case has one place to be explained rather than
    /// being an arm of an already long function.
    async fn publish(
        &self,
        fork: ForkName,
        body: &[u8],
        slot: Slot,
        validator: u64,
    ) -> Result<Published> {
        let published = self.beacon_node.publish_block(fork, body).await?;
        match published {
            Published::Imported => {
                info!(%slot, validator, bytes = body.len(), "Block published");
            }
            // Not an error, and not silence either. The block reached the
            // network, so the proposal may well have worked; what failed is the
            // node's own import, which usually means its execution layer is
            // unsynced or the parent is not what this client thought. An
            // operator seeing this repeatedly has a beacon node problem, not a
            // validator one.
            Published::BroadcastNotImported => {
                warn!(
                    %slot,
                    validator,
                    "Block was broadcast but the beacon node could not import it; \
                     check that node's execution layer"
                );
                crate::metrics::inc_blocks_broadcast_not_imported();
            }
            // `publish_block` never answers with this: a blinded block goes
            // through `publish_blinded_block`.
            Published::HandedToBuilder => {}
        }
        Ok(published)
    }
}

/// Log and count a blinded publish's answer, as [`ProposalService::publish`]
/// does a full block's, and turn an unconfirmed send into an outcome. A
/// definite refusal stays an error, for whoever holds the outcome to report.
fn blinded_outcome(
    slot: Slot,
    validator: u64,
    bytes: usize,
    answer: Result<Published>,
) -> Result<BlindedOutcome> {
    match answer {
        Ok(published) => {
            match published {
                Published::HandedToBuilder => {
                    info!(%slot, validator, bytes, "Blinded block handed to the builder");
                }
                Published::BroadcastNotImported => {
                    warn!(
                        %slot,
                        validator,
                        "Block was broadcast but the beacon node could not import it; \
                         check that node's execution layer"
                    );
                    crate::metrics::inc_blocks_broadcast_not_imported();
                }
                // A full block's outcome. Reported rather than assumed away;
                // the block did go out, so it is still counted.
                Published::Imported => warn!(
                    %slot,
                    validator,
                    ?published,
                    "Beacon node API answered a blinded publish with an outcome that belongs to \
                     another call"
                ),
            }
            crate::metrics::inc_blocks_proposed();
            crate::metrics::inc_blinded_blocks_proposed();
            Ok(BlindedOutcome::Published(published))
        }
        Err(err @ Error::BlindedUnconfirmed { .. }) => {
            tracing::error!(
                %slot,
                validator,
                %err,
                "The beacon node did not confirm the blinded block; the relay may still publish \
                 it. Not retried: the slot is signed, and a second block would be an equivocation"
            );
            crate::metrics::inc_blinded_blocks_unconfirmed();
            Ok(BlindedOutcome::Unconfirmed)
        }
        Err(err) => Err(err),
    }
}

/// What the duty loop does with a blinded outcome it receives in time, done by
/// the publish task when nobody is waiting for it any more (past the deadline,
/// or a dropped proposal): the publication delay of a confirmed block, and a
/// refusal counted as a failed proposal.
fn report_unawaited(
    slot: Slot,
    validator: u64,
    slot_start: Option<SystemTime>,
    outcome: Result<BlindedOutcome>,
) {
    match outcome {
        Ok(BlindedOutcome::Published(_)) => {
            if let Some(start) = slot_start {
                let elapsed = SystemTime::now().duration_since(start).unwrap_or_default();
                crate::metrics::observe_block_publication_delay(elapsed.as_secs_f64());
            }
        }
        Ok(BlindedOutcome::Unconfirmed | BlindedOutcome::StillPublishing) => {}
        Err(err) => {
            tracing::error!(
                %slot,
                validator,
                %err,
                "The beacon node refused the blinded block, after the proposal stopped waiting"
            );
            crate::metrics::inc_block_proposal_failures();
        }
    }
}

/// Slashing protection's answer about a block, as the duty's outcome: a judged
/// refusal, or a record that could not be consulted or written (`what` names
/// which), is a counted [`Error::ProposalRefused`].
fn refuse_unless_safe(
    slot: Slot,
    validator: u64,
    what: &'static str,
    outcome: Result<std::result::Result<(), Refusal>>,
) -> Result<()> {
    let reason = match outcome {
        Ok(Ok(())) => return Ok(()),
        Ok(Err(refusal)) => {
            warn!(
                %slot,
                validator,
                %refusal,
                "Refusing to propose: slashing protection judged this block unsafe"
            );
            refusal.to_string()
        }
        Err(err) => {
            error!(
                %slot,
                validator,
                %err,
                "Slashing protection could not {what} this block; refusing to sign"
            );
            err.to_string()
        }
    };
    crate::metrics::inc_blocks_refused();
    Err(Error::ProposalRefused { slot, reason })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon_node::block_contents::SignedBlockContents;
    use crate::beacon_node::mock::MockBeaconNode;
    use crate::slashing_protection::SlashingProtection;
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::primitives::HashTreeRoot as _;
    use ethlambda_types::beacon::primitives::{BlsPubkey, Bytes32, H160, Root};
    use libssz::SszDecode as _;

    fn secret() -> [u8; 32] {
        hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
            .expect("valid hex")
            .try_into()
            .expect("32 bytes")
    }

    fn context() -> Arc<SigningContext> {
        Arc::new(SigningContext {
            config: Config::mainnet(),
            genesis_validators_root: Root::ZERO,
        })
    }

    /// A store holding one key, and the pubkey it resolves to.
    fn store() -> (RwLock<ValidatorStore>, BlsPubkey) {
        let mut store = ValidatorStore::new();
        let pubkey = store.insert_secret("test", &secret()).expect("inserts");
        (RwLock::new(store), pubkey)
    }

    fn duty(pubkey: &BlsPubkey, validator_index: u64, slot: Slot) -> ProposerDutyDto {
        ProposerDutyDto {
            pubkey: crate::beacon_node::dto::encode_hex(&pubkey.0),
            validator_index,
            slot,
        }
    }

    fn service(node: Arc<MockBeaconNode>) -> ProposalService<MockBeaconNode> {
        let settings = ProposerSettings::new(Bytes32::repeat_byte(0xab), None);
        ProposalService::new(
            node,
            context(),
            Arc::new(settings),
            SlashingProtection::in_memory(),
            None,
        )
    }

    fn service_expecting(
        node: Arc<MockBeaconNode>,
        fee_recipient: ExecutionAddress,
    ) -> ProposalService<MockBeaconNode> {
        let settings = ProposerSettings::new(Bytes32::repeat_byte(0xab), Some(fee_recipient));
        ProposalService::new(
            node,
            context(),
            Arc::new(settings),
            SlashingProtection::in_memory(),
            None,
        )
    }

    /// A slot inside mainnet's electra era.
    ///
    /// Not an arbitrary small number: the mock produces an electra-shaped
    /// block and names electra, and `propose` refuses to sign when the node's
    /// fork and this client's schedule disagree. Slot 96 is phase0 on mainnet,
    /// so it would be refused, which is the behaviour these tests want
    /// everywhere except the one that asserts it.
    fn slot() -> Slot {
        use ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;
        Config::mainnet().electra_fork_epoch * SLOTS_PER_EPOCH + 96
    }

    #[tokio::test]
    async fn a_block_is_produced_signed_and_published() {
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_block(slot(), 7));
        let service = service(node.clone());

        let published = service
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect("proposes");
        assert_eq!(published, Proposed::Full(Published::Imported));

        let sent = node.published_blocks();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, ForkName::Electra);
    }

    /// The property the whole path exists to get right: the signature must
    /// cover the block the node produced, and the block must reach the wire
    /// unchanged.
    #[tokio::test]
    async fn the_published_body_carries_the_produced_block_and_a_matching_signature() {
        use blst::min_pk::{PublicKey, Signature};

        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_block(slot(), 7));
        let service = service(node.clone());

        service
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect("proposes");

        let (_, body) = node.published_blocks().remove(0);
        let decoded = SignedBlockContents::from_ssz_bytes(&body).expect("decodes");
        assert_eq!(decoded.signed_block.message.slot, slot());
        assert_eq!(decoded.signed_block.message.proposer_index, 7);

        let root =
            context().block_signing_root(decoded.signed_block.message.hash_tree_root(), slot());
        let pk = PublicKey::from_bytes(&pubkey.0).expect("valid pubkey");
        let sig =
            Signature::from_bytes(&decoded.signed_block.signature.0).expect("valid signature");
        assert_eq!(
            sig.verify(
                true,
                root.as_slice(),
                b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
                &[],
                &pk,
                true
            ),
            blst::BLST_ERROR::BLST_SUCCESS,
            "the published signature must verify over the published block"
        );
    }

    #[tokio::test]
    async fn the_configured_graffiti_reaches_the_block_request() {
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_block(slot(), 7));
        service(node.clone())
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect("proposes");

        // The mock builds its own block rather than echoing the request, so
        // the graffiti is asserted where it is actually carried: on the
        // request the node received.
        let seen = node.block_requests();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].graffiti, Bytes32::repeat_byte(0xab));
    }

    /// A per-validator graffiti replaces the default for that validator's
    /// block, and is read at proposal time, so one set after the service was
    /// built still applies.
    #[tokio::test]
    async fn a_validators_own_graffiti_replaces_the_default() {
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_block(slot(), 7));
        let settings = Arc::new(ProposerSettings::new(Bytes32::repeat_byte(0xab), None));
        let service = ProposalService::new(
            node.clone(),
            context(),
            settings.clone(),
            SlashingProtection::in_memory(),
            None,
        );

        settings.set_graffiti(&pubkey, Bytes32::repeat_byte(0xcd));
        service
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect("proposes");

        assert_eq!(
            node.block_requests()[0].graffiti,
            Bytes32::repeat_byte(0xcd)
        );
    }

    /// The reveal is over the slot's epoch, and it is what the node is given
    /// to build a body around. A client that signed the wrong epoch would get
    /// a block back and only find out when the network rejected it.
    #[tokio::test]
    async fn the_randao_reveal_is_signed_over_the_slots_epoch() {
        use blst::min_pk::{PublicKey, Signature};

        let (store, pubkey) = store();
        let slot = slot();
        let node = Arc::new(MockBeaconNode::new().with_block(slot, 7));
        service(node.clone())
            .propose(slot, &duty(&pubkey, 7, slot), &store)
            .await
            .expect("proposes");

        let reveal = node.block_requests().remove(0).randao_reveal;
        let root = context().randao_signing_root(compute_epoch_at_slot(slot));
        let pk = PublicKey::from_bytes(&pubkey.0).expect("valid pubkey");
        let sig = Signature::from_bytes(&reveal.0).expect("valid signature");
        assert_eq!(
            sig.verify(
                true,
                root.as_slice(),
                b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
                &[],
                &pk,
                true
            ),
            blst::BLST_ERROR::BLST_SUCCESS
        );
    }

    /// Slashing protection is consulted before the block is asked for, not after, so a
    /// slot already proposed costs the beacon node nothing.
    #[tokio::test]
    async fn a_repeated_slot_is_refused_without_asking_for_a_block() {
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_block(slot(), 7));
        let service = service(node.clone());

        service
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect("first");
        let err = service
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect_err("a second block for one slot must be refused");

        assert!(matches!(err, Error::ProposalRefused { .. }), "got {err:?}");
        assert_eq!(
            node.block_requests().len(),
            1,
            "the refused attempt must not have asked the node for a block"
        );
        assert_eq!(node.published_blocks().len(), 1);
    }

    /// The restart shape: a fresh service over the same slashing-protection
    /// directory refuses the slot already proposed, before asking for a block.
    #[tokio::test]
    async fn a_restart_does_not_forget_what_was_proposed() {
        let (store, pubkey) = store();
        let dir = tempfile::tempdir().expect("temp dir");
        let settings = Arc::new(ProposerSettings::new(Bytes32::repeat_byte(0xab), None));
        let protection = || {
            let opened =
                SlashingProtection::open(dir.path(), Root::ZERO, &[pubkey], true).expect("opens");
            Arc::new(std::sync::Mutex::new(opened))
        };

        let node = Arc::new(MockBeaconNode::new().with_block(slot(), 7));
        ProposalService::new(
            node.clone(),
            context(),
            settings.clone(),
            protection(),
            None,
        )
        .propose(slot(), &duty(&pubkey, 7, slot()), &store)
        .await
        .expect("first");
        assert_eq!(node.published_blocks().len(), 1);

        let node_again = Arc::new(MockBeaconNode::new().with_block(slot(), 7));
        let err = ProposalService::new(node_again.clone(), context(), settings, protection(), None)
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect_err("the slot was proposed before the restart");
        assert!(matches!(err, Error::ProposalRefused { .. }), "got {err:?}");
        assert!(node_again.block_requests().is_empty());
        assert!(node_again.published_blocks().is_empty());
    }

    /// A persisted record holding nothing for the key refuses it before a
    /// block is asked for. The in-memory record of the other tests registers
    /// a key on first use; a real one does not.
    #[tokio::test]
    async fn an_unregistered_key_is_refused_before_a_block_is_requested() {
        let (store, pubkey) = store();
        let dir = tempfile::tempdir().expect("temp dir");
        let settings = Arc::new(ProposerSettings::new(Bytes32::repeat_byte(0xab), None));
        let opened = SlashingProtection::open(dir.path(), Root::ZERO, &[], false)
            .expect("opens with no keys");
        let node = Arc::new(MockBeaconNode::new().with_block(slot(), 7));

        let err = ProposalService::new(
            node.clone(),
            context(),
            settings,
            Arc::new(std::sync::Mutex::new(opened)),
            None,
        )
        .propose(slot(), &duty(&pubkey, 7, slot()), &store)
        .await
        .expect_err("the key has no record");
        assert!(
            matches!(&err, Error::ProposalRefused { reason, .. } if reason.contains("no slashing-protection record")),
            "got {err:?}"
        );
        assert!(node.block_requests().is_empty());
        assert!(node.published_blocks().is_empty());
    }

    #[tokio::test]
    async fn a_node_that_cannot_import_the_block_is_reported_rather_than_hidden() {
        let (store, pubkey) = store();
        let node = Arc::new(
            MockBeaconNode::new()
                .with_block(slot(), 7)
                .with_publish_outcome(Published::BroadcastNotImported),
        );

        let published = service(node)
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect("202 is not an error");
        assert_eq!(published, Proposed::Full(Published::BroadcastNotImported));
    }

    fn builder_service(
        node: Arc<MockBeaconNode>,
        fee_recipient: Option<ExecutionAddress>,
    ) -> ProposalService<MockBeaconNode> {
        let settings = ProposerSettings::new(Bytes32::repeat_byte(0xab), fee_recipient);
        ProposalService::new(
            node,
            context(),
            Arc::new(settings),
            SlashingProtection::in_memory(),
            Some(100),
        )
    }

    /// A blinded block takes the `blinded_blocks` route and nothing else. Its
    /// header names the builder's address, so a configured fee recipient that
    /// differs is not a mismatch for it. The mismatch counter is process-global
    /// and shared with the test above, so it cannot be asserted on here; what
    /// is asserted is that the proposal goes through unchanged.
    #[tokio::test]
    async fn a_blinded_block_is_published_to_the_builder_route() {
        use ethlambda_types::beacon::builder::SignedBlindedBeaconBlock;

        let (store, pubkey) = store();
        let node = Arc::new(
            MockBeaconNode::new()
                .with_block(slot(), 7)
                .with_blinded_block(),
        );

        let service = builder_service(node.clone(), Some(H160([0xfe; 20])));
        let published = service
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect("proposes");
        assert_eq!(
            published,
            Proposed::Blinded(BlindedOutcome::Published(Published::HandedToBuilder))
        );

        assert_eq!(node.block_requests()[0].builder_boost_factor, Some(100));
        assert!(node.published_blocks().is_empty());
        let sent = node.published_blinded.lock().expect("lock").clone();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, ForkName::Electra);
        let block = SignedBlindedBeaconBlock::from_ssz_bytes(&sent[0].1).expect("decodes");
        assert_eq!(block.message.slot, slot());
    }

    /// The fee-recipient comparison is for a full block only: a blinded
    /// block's header names the builder's address.
    #[tokio::test]
    async fn only_a_full_block_has_its_fee_recipient_compared() {
        use crate::beacon_node::block_contents::{Contents, ProducedBlock, empty_block_for};
        use ethlambda_types::beacon::builder::BlindedBeaconBlock;

        let blinded = ProducedBlock {
            fork: ForkName::Electra,
            contents: Contents::Blinded {
                block: BlindedBeaconBlock::from(empty_block_for(slot(), 7)),
            },
            producer: Default::default(),
        };
        assert!(!ProposalService::<MockBeaconNode>::compares_fee_recipient(
            &blinded
        ));

        let full = MockBeaconNode::new().with_block(slot(), 7);
        let request = BlockRequest {
            slot: slot(),
            fork: ForkName::Electra,
            proposer_index: 7,
            randao_reveal: Default::default(),
            graffiti: Default::default(),
            builder_boost_factor: None,
            builder_min_bid: 0,
        };
        let full = full.produce_block(&request).await.expect("produces");
        assert!(ProposalService::<MockBeaconNode>::compares_fee_recipient(
            &full
        ));
    }

    /// The current address and every accepted preference's are this
    /// validator's; anything else is a mismatch, and with neither configured
    /// there is nothing to compare.
    #[test]
    fn a_block_may_pay_the_current_address_or_a_published_preferences() {
        let pays = ProposalService::<MockBeaconNode>::pays_this_validator;
        let current = H160([0x01; 20]);
        let preferred = H160([0x02; 20]);
        let stranger = H160([0x03; 20]);

        assert_eq!(pays(current, Some(current), &[]), Some(true));
        assert_eq!(pays(preferred, Some(current), &[preferred]), Some(true));
        assert_eq!(pays(current, Some(current), &[preferred]), Some(true));
        assert_eq!(pays(stranger, Some(current), &[preferred]), Some(false));
        assert_eq!(pays(stranger, Some(current), &[]), Some(false));
        assert_eq!(pays(stranger, None, &[preferred]), Some(false));
        assert_eq!(pays(stranger, None, &[]), None);
    }

    /// The configured floor goes with the block request, beside the factor.
    #[tokio::test]
    async fn the_min_bid_goes_with_every_block_request() {
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_block(slot(), 7));
        let service = builder_service(node.clone(), None).with_builder_min_bid(1_000_000);

        service
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect("proposes");

        let requests = node.block_requests();
        assert_eq!(requests[0].builder_boost_factor, Some(100));
        assert_eq!(requests[0].builder_min_bid, 1_000_000);
    }

    /// A node that does not confirm the publish may still have handed the block
    /// to its relay, so it is not a missed proposal, and the slot is spent: a
    /// second block would be an equivocation.
    #[tokio::test]
    async fn an_unconfirmed_blinded_publish_is_reported_and_the_slot_is_spent() {
        let (store, pubkey) = store();
        let node = Arc::new(
            MockBeaconNode::new()
                .with_block(slot(), 7)
                .with_blinded_block()
                .with_unconfirmed_blinded_publish("relay timed out"),
        );
        let service = builder_service(node.clone(), None);

        let published = service
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect("an unconfirmed publish is not an error");
        assert_eq!(published, Proposed::Blinded(BlindedOutcome::Unconfirmed));

        let err = service
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect_err("slashing protection must refuse a second block for the slot");
        assert!(matches!(err, Error::ProposalRefused { .. }), "got {err:?}");
    }

    /// Wait, up to five seconds, until `node` has recorded a blinded block.
    async fn until_published_blinded(node: &MockBeaconNode) {
        let published = async {
            while node.published_blinded.lock().expect("lock").is_empty() {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), published)
            .await
            .expect("the publish completes on its own task");
    }

    /// The deadline passes while the node waits on the relay. The proposal
    /// returns `StillPublishing` rather than an error, and the publish, on its
    /// own task, still goes out.
    ///
    /// The deadline is moved past by pausing the clock and advancing it once
    /// the publish is at the node, which holds it until the test lets it
    /// answer, rather than by picking a deadline and hoping the signing came
    /// first: the slashing-protection write runs on the blocking pool and can
    /// take longer than any margin on a loaded machine.
    #[tokio::test]
    async fn a_blinded_publish_past_the_deadline_still_goes_out() {
        let (store, pubkey) = store();
        let relay_answers = Arc::new(tokio::sync::Semaphore::new(0));
        let node = Arc::new(
            MockBeaconNode::new()
                .with_block(slot(), 7)
                .with_blinded_block()
                .with_blinded_publish_gate(relay_answers.clone()),
        );
        let service = builder_service(node.clone(), None);

        let at_the_node = node.blinded_publish_entered.clone();
        let this_duty = duty(&pubkey, 7, slot());
        let hour = std::time::Duration::from_secs(3600);
        let proposal = service.propose_by(slot(), &this_duty, &store, Instant::now() + hour);
        tokio::pin!(proposal);
        tokio::select! {
            outcome = &mut proposal => {
                panic!("the node is still waiting on the relay, yet the proposal ended: {outcome:?}")
            }
            () = at_the_node.notified() => {}
        }
        tokio::time::pause();
        tokio::time::advance(hour * 2).await;
        let outcome = proposal
            .await
            .expect("past the deadline is not an error once signed");
        tokio::time::resume();
        assert_eq!(outcome, Proposed::Blinded(BlindedOutcome::StillPublishing));
        assert!(node.published_blinded.lock().expect("lock").is_empty());

        relay_answers.add_permits(1);
        until_published_blinded(&node).await;
        assert_eq!(node.published_blinded.lock().expect("lock").len(), 1);

        // Slashing protection recorded the slot before the publish started, so
        // a retry is refused without asking for a block.
        let err = service
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect_err("the slot is signed");
        assert!(matches!(err, Error::ProposalRefused { .. }), "got {err:?}");
        assert_eq!(node.block_requests().len(), 1);
    }

    /// The duty loop's entry point, with the deadline far off: a full block
    /// and a blinded one both come back confirmed, as from `propose`.
    #[tokio::test]
    async fn a_proposal_within_its_deadline_returns_what_the_node_said() {
        let hour = std::time::Duration::from_secs(3600);

        let (full_store, full_key) = store();
        let node = Arc::new(MockBeaconNode::new().with_block(slot(), 7));
        let full = builder_service(node.clone(), None)
            .propose_by(
                slot(),
                &duty(&full_key, 7, slot()),
                &full_store,
                Instant::now() + hour,
            )
            .await
            .expect("proposes");
        assert_eq!(full, Proposed::Full(Published::Imported));
        assert_eq!(node.published_blocks().len(), 1);

        let (store, pubkey) = store();
        let node = Arc::new(
            MockBeaconNode::new()
                .with_block(slot(), 7)
                .with_blinded_block(),
        );
        let blinded = builder_service(node.clone(), None)
            .propose_by(
                slot(),
                &duty(&pubkey, 7, slot()),
                &store,
                Instant::now() + hour,
            )
            .await
            .expect("proposes");
        assert_eq!(
            blinded,
            Proposed::Blinded(BlindedOutcome::Published(Published::HandedToBuilder))
        );
        assert_eq!(node.published_blinded.lock().expect("lock").len(), 1);
    }

    /// A definite refusal that arrives within the deadline is the proposal's
    /// error, for the duty loop to report, not something the task kept.
    #[tokio::test]
    async fn a_blinded_refusal_within_the_deadline_is_the_proposals_error() {
        let (store, pubkey) = store();
        let node = Arc::new(
            MockBeaconNode::new()
                .with_block(slot(), 7)
                .with_blinded_block()
                .with_refused_blinded_publish(400),
        );
        let hour = std::time::Duration::from_secs(3600);
        let result = builder_service(node, None)
            .propose_by(
                slot(),
                &duty(&pubkey, 7, slot()),
                &store,
                Instant::now() + hour,
            )
            .await;
        assert!(
            matches!(result, Err(Error::BeaconNodeStatus { status: 400, .. })),
            "got {result:?}"
        );
    }

    /// A deadline that passes before anything is signed abandons the proposal:
    /// an error, and nothing published. The node is still building the block
    /// when the clock is moved past the deadline.
    #[tokio::test]
    async fn a_proposal_past_its_deadline_before_signing_is_abandoned() {
        let (store, pubkey) = store();
        let node = Arc::new(
            MockBeaconNode::new()
                .with_block(slot(), 7)
                .with_blinded_block()
                .with_produce_gate(Arc::new(tokio::sync::Semaphore::new(0))),
        );
        let service = builder_service(node.clone(), None);

        let building = node.produce_entered.clone();
        let this_duty = duty(&pubkey, 7, slot());
        let hour = std::time::Duration::from_secs(3600);
        let proposal = service.propose_by(slot(), &this_duty, &store, Instant::now() + hour);
        tokio::pin!(proposal);
        tokio::select! {
            outcome = &mut proposal => panic!("the node is still building, yet: {outcome:?}"),
            () = building.notified() => {}
        }
        tokio::time::pause();
        tokio::time::advance(hour * 2).await;
        let err = proposal.await.expect_err("abandoned at the deadline");
        tokio::time::resume();
        assert!(
            matches!(err, Error::ProposalDeadline { slot: at } if at == slot()),
            "got {err:?}"
        );
        assert!(node.published_blinded.lock().expect("lock").is_empty());
        assert!(node.published_blocks().is_empty());
    }

    /// A caller that drops the proposal while the node waits on the relay does
    /// not cancel the publish: it runs on its own task, which reports the
    /// outcome itself once nobody is waiting for it.
    #[tokio::test]
    async fn a_blinded_publish_survives_a_dropped_proposal() {
        let (store, pubkey) = store();
        let relay_answers = Arc::new(tokio::sync::Semaphore::new(0));
        let node = Arc::new(
            MockBeaconNode::new()
                .with_block(slot(), 7)
                .with_blinded_block()
                .with_blinded_publish_gate(relay_answers.clone()),
        );
        let service = builder_service(node.clone(), None);

        let at_the_node = node.blinded_publish_entered.clone();
        let this_duty = duty(&pubkey, 7, slot());
        tokio::select! {
            outcome = service.propose(slot(), &this_duty, &store) => {
                panic!("the node is still waiting on the relay, yet the proposal ended: {outcome:?}")
            }
            () = at_the_node.notified() => {}
        }
        // The proposal future is dropped here.
        assert!(node.published_blinded.lock().expect("lock").is_empty());

        relay_answers.add_permits(1);
        until_published_blinded(&node).await;
        assert_eq!(node.published_blinded.lock().expect("lock").len(), 1);
    }

    /// A 4xx is a definite refusal: the block was not published, so the
    /// proposal failed.
    #[tokio::test]
    async fn a_definitely_refused_blinded_publish_is_an_error() {
        let (store, pubkey) = store();
        let node = MockBeaconNode::new()
            .with_block(slot(), 7)
            .with_blinded_block()
            .with_refused_blinded_publish(400);

        let result = builder_service(Arc::new(node), None)
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await;
        assert!(
            matches!(result, Err(Error::BeaconNodeStatus { status: 400, .. })),
            "got {result:?}"
        );
    }

    #[tokio::test]
    async fn without_builder_proposals_the_request_carries_no_factor() {
        let (store, pubkey) = store();
        let node = Arc::new(
            MockBeaconNode::new()
                .with_block(slot(), 7)
                .with_blinded_block(),
        );

        let published = service(node.clone())
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect("proposes");
        assert_eq!(published, Proposed::Full(Published::Imported));
        assert_eq!(node.block_requests()[0].builder_boost_factor, None);
        assert!(node.published_blinded.lock().expect("lock").is_empty());
    }

    /// A node breaking its contract with a blinded answer to a request with no
    /// factor is refused before signing. With builder proposals off this client
    /// never publishes a blinded block, so signing would burn the slot for
    /// nothing. The second attempt is refused for the same reason rather than
    /// by slashing protection, which shows nothing was recorded.
    #[tokio::test]
    async fn a_blinded_block_is_refused_before_signing_with_builder_proposals_off() {
        let (store, pubkey) = store();
        let node = Arc::new(
            MockBeaconNode::new()
                .with_block(slot(), 7)
                .with_blinded_block_regardless(),
        );
        let service = service(node.clone());

        for attempt in 0..2 {
            let err = service
                .propose(slot(), &duty(&pubkey, 7, slot()), &store)
                .await
                .expect_err("a blinded block must not be signed");
            assert!(
                matches!(err, Error::InconsistentResponse(_)),
                "attempt {attempt}: got {err:?}"
            );
        }
        assert!(node.published_blinded.lock().expect("lock").is_empty());
        assert!(node.published_blocks().is_empty());
    }

    /// The signature in the published blinded block verifies over the full
    /// block's root. The blinded container's root equals it, which is what lets
    /// the relay put the payload back under a signature over a block the
    /// validator never saw whole.
    #[tokio::test]
    async fn a_blinded_block_is_signed_over_the_full_blocks_root() {
        use crate::beacon_node::block_contents::empty_block_for;
        use blst::min_pk::{PublicKey, Signature};
        use ethlambda_types::beacon::builder::SignedBlindedBeaconBlock;

        let (store, pubkey) = store();
        let node = Arc::new(
            MockBeaconNode::new()
                .with_block(slot(), 7)
                .with_blinded_block(),
        );
        builder_service(node.clone(), None)
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect("proposes");

        let (_, body) = node.published_blinded.lock().expect("lock").remove(0);
        let published = SignedBlindedBeaconBlock::from_ssz_bytes(&body).expect("decodes");
        let full_root = empty_block_for(slot(), 7).hash_tree_root();
        assert_eq!(published.message.hash_tree_root(), full_root);

        let root = context().block_signing_root(full_root, slot());
        let pk = PublicKey::from_bytes(&pubkey.0).expect("valid pubkey");
        let sig = Signature::from_bytes(&published.signature.0).expect("valid signature");
        assert_eq!(
            sig.verify(
                true,
                root.as_slice(),
                b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
                &[],
                &pk,
                true
            ),
            blst::BLST_ERROR::BLST_SUCCESS
        );
    }

    /// A blinded answer is held to what a full one is: the slot and proposer
    /// asked for, and the fork this client's schedule puts the slot in. Each
    /// is refused before signing, so none spends the slot.
    #[tokio::test]
    async fn a_blinded_block_for_another_slot_proposer_or_fork_is_refused() {
        let (store, pubkey) = store();
        // The mock always names electra, and slot 96 is phase0 on mainnet.
        let cases = [
            ("slot", (slot() + 1, 7), slot()),
            ("proposer", (slot(), 8), slot()),
            ("fork", (96, 7), 96),
        ];
        for (what, (block_slot, proposer), requested) in cases {
            let node = Arc::new(
                MockBeaconNode::new()
                    .with_block(block_slot, proposer)
                    .with_blinded_block(),
            );
            let service = builder_service(node.clone(), None);
            let err = service
                .propose(requested, &duty(&pubkey, 7, requested), &store)
                .await
                .expect_err(what);
            assert!(
                matches!(err, Error::InconsistentResponse(_)),
                "{what}: got {err:?}"
            );
            assert!(
                node.published_blinded.lock().expect("lock").is_empty(),
                "{what}"
            );
        }
    }

    /// A duty naming a key this client does not hold must fail before anything
    /// is asked of the beacon node.
    #[tokio::test]
    async fn a_duty_for_an_unknown_validator_is_an_error() {
        let store = RwLock::new(ValidatorStore::new());
        let node = Arc::new(MockBeaconNode::new().with_block(slot(), 7));

        let err = service(node.clone())
            .propose(slot(), &duty(&BlsPubkey([9; 48]), 7, slot()), &store)
            .await
            .expect_err("must fail");
        assert!(matches!(err, Error::UnknownValidator(_)), "got {err:?}");
        assert!(node.block_requests().is_empty());
    }

    /// The mock's block carries a zeroed fee recipient, so an expectation of
    /// anything else is a mismatch. The block must still be signed and
    /// published: refusing would forfeit the consensus reward as well as the
    /// execution one and cost the network a slot, while the execution reward
    /// was already going elsewhere the moment the node built the payload.
    #[tokio::test]
    async fn a_block_paying_the_wrong_address_is_still_published() {
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_block(slot(), 7));

        let published = service_expecting(node.clone(), H160([0xfe; 20]))
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect("a wrong fee recipient must not stop the proposal");

        assert_eq!(published, Proposed::Full(Published::Imported));
        assert_eq!(node.published_blocks().len(), 1);
    }

    #[tokio::test]
    async fn a_block_paying_the_expected_address_is_published_too() {
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_block(slot(), 7));

        // The fixture block's payload is zeroed, so the zero address is the
        // one it actually pays.
        service_expecting(node.clone(), H160([0; 20]))
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect("proposes");
        assert_eq!(node.published_blocks().len(), 1);
    }

    /// The two forks in play must agree before anything is signed.
    ///
    /// The block is decoded and published under the fork the node named; the
    /// signing domain comes from this client's own schedule. A disagreement
    /// means one of them is wrong about where a fork boundary sits, and signing
    /// anyway yields a block rejected for a reason nothing in the logs would
    /// explain.
    ///
    /// The fixture makes them disagree the only way a test can: the mock always
    /// names electra, and slot 96 is phase0 on mainnet's schedule.
    #[tokio::test]
    async fn a_fork_the_client_does_not_expect_is_refused_before_signing() {
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_block(96, 7));

        let err = service(node.clone())
            .propose(96, &duty(&pubkey, 7, 96), &store)
            .await
            .expect_err("a fork mismatch must not be signed");

        assert!(matches!(err, Error::InconsistentResponse(_)), "got {err:?}");
        assert!(
            node.published_blocks().is_empty(),
            "nothing may be published when the forks disagree"
        );
    }

    /// A failed production must leave slashing protection untouched, so the
    /// slot can still be proposed if a later attempt succeeds. Recording on
    /// the early check rather than at signing time would have burned it.
    ///
    /// The same service and the same node throughout, deliberately: a second
    /// service would carry a second, empty record and the test would pass
    /// whether or not the first one recorded.
    #[tokio::test]
    async fn a_failed_production_does_not_burn_the_slot() {
        let (store, pubkey) = store();
        let node = Arc::new(
            MockBeaconNode::new()
                .with_block(slot(), 7)
                .failing_call("produce_block", "node is unhappy"),
        );
        let service = service(node.clone());

        service
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect_err("production failed");

        node.stop_failing("produce_block");
        service
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect("the slot was never recorded, so it can still be proposed");
        assert_eq!(node.published_blocks().len(), 1);
    }
}

#[cfg(test)]
mod gloas_tests {
    use super::*;
    use crate::beacon_node::block_contents::SignedExecutionPayloadEnvelopeContents;
    use crate::beacon_node::mock::MockBeaconNode;
    use crate::slashing_protection::SlashingProtection;
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::containers::gloas;
    use ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;
    use ethlambda_types::beacon::primitives::{BlsPubkey, HashTreeRoot as _};
    use libssz::SszDecode as _;

    const GLOAS_EPOCH: u64 = 10;
    const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    fn secret() -> [u8; 32] {
        hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
            .expect("valid hex")
            .try_into()
            .expect("32 bytes")
    }

    fn context() -> Arc<SigningContext> {
        Arc::new(SigningContext {
            config: Config::mainnet().with_fork_epoch(ForkName::Gloas, GLOAS_EPOCH),
            genesis_validators_root: Root::ZERO,
        })
    }

    fn store() -> (RwLock<ValidatorStore>, BlsPubkey) {
        let mut store = ValidatorStore::new();
        let pubkey = store.insert_secret("test", &secret()).expect("inserts");
        (RwLock::new(store), pubkey)
    }

    fn slot() -> Slot {
        GLOAS_EPOCH * SLOTS_PER_EPOCH + 5
    }

    fn duty(pubkey: &BlsPubkey) -> ProposerDutyDto {
        ProposerDutyDto {
            pubkey: encode_hex(&pubkey.0),
            validator_index: 7,
            slot: slot(),
        }
    }

    fn service(node: Arc<MockBeaconNode>) -> ProposalService<MockBeaconNode> {
        let settings = ProposerSettings::new(
            ethlambda_types::beacon::primitives::Bytes32::repeat_byte(0xab),
            None,
        );
        ProposalService::new(
            node,
            context(),
            Arc::new(settings),
            SlashingProtection::in_memory(),
            None,
        )
    }

    fn verifies(pubkey: &BlsPubkey, signature: &[u8; 96], root: Root) -> bool {
        use blst::min_pk::{PublicKey, Signature};
        let pk = PublicKey::from_bytes(&pubkey.0).expect("valid pubkey");
        let sig = Signature::from_bytes(signature).expect("valid signature");
        sig.verify(true, root.as_slice(), DST, &[], &pk, true) == blst::BLST_ERROR::BLST_SUCCESS
    }

    /// The block goes out bare, under the gloas header, signed over the gloas
    /// block's root, and then the envelope follows with the blobs, signed under
    /// the builder domain by the proposer's own key.
    #[tokio::test]
    async fn a_self_built_block_is_published_and_then_its_envelope() {
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_gloas_block(
            slot(),
            7,
            BUILDER_INDEX_SELF_BUILD,
            true,
        ));

        let published = service(node.clone())
            .propose(slot(), &duty(&pubkey), &store)
            .await
            .expect("proposes");
        assert_eq!(published, Proposed::Full(Published::Imported));

        let request = node.block_requests().remove(0);
        assert_eq!(request.fork, ForkName::Gloas);

        let blocks = node.published_blocks();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].0, ForkName::Gloas);
        let signed = gloas::SignedBeaconBlock::from_ssz_bytes(&blocks[0].1)
            .expect("the body is a bare gloas signed block");
        let block_root = signed.message.hash_tree_root();
        let block_signing_root = context().block_signing_root(block_root, slot());
        assert!(verifies(&pubkey, &signed.signature.0, block_signing_root));

        let envelopes = node.published_envelopes();
        assert_eq!(envelopes.len(), 1);
        let (body, blob_data_included) = &envelopes[0];
        assert!(*blob_data_included, "the contents form carries the blobs");
        let contents = SignedExecutionPayloadEnvelopeContents::from_ssz_bytes(body)
            .expect("the body is the signed envelope contents");
        let envelope = &contents.signed_execution_payload_envelope;
        assert_eq!(envelope.message.beacon_block_root, block_root);
        assert!(
            verifies(
                &pubkey,
                &envelope.signature.0,
                context().envelope_signing_root(&envelope.message, slot())
            ),
            "the envelope must be signed under the builder domain"
        );
        assert!(
            node.envelope_requests().is_empty(),
            "an included payload needs no fetch"
        );
    }

    /// A validator's own graffiti reaches a gloas block request too, as it does
    /// a fulu one: the settings are read before the fork is looked at.
    #[tokio::test]
    async fn a_validators_own_graffiti_reaches_the_gloas_block_request() {
        use ethlambda_types::beacon::primitives::Bytes32;
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_gloas_block(
            slot(),
            7,
            BUILDER_INDEX_SELF_BUILD,
            true,
        ));
        let settings = Arc::new(ProposerSettings::new(Bytes32::repeat_byte(0xab), None));
        settings.set_graffiti(&pubkey, Bytes32::repeat_byte(0xcd));
        ProposalService::new(
            node.clone(),
            context(),
            settings,
            SlashingProtection::in_memory(),
            None,
        )
        .propose(slot(), &duty(&pubkey), &store)
        .await
        .expect("proposes");

        let request = node.block_requests().remove(0);
        assert_eq!(request.fork, ForkName::Gloas);
        assert_eq!(request.graffiti, Bytes32::repeat_byte(0xcd));
    }

    /// The builder domain is not the proposer domain: an envelope signature
    /// must not verify as a block signature over the same root.
    #[tokio::test]
    async fn the_envelope_signature_is_under_the_builder_domain_not_the_proposers() {
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_gloas_block(
            slot(),
            7,
            BUILDER_INDEX_SELF_BUILD,
            true,
        ));
        service(node.clone())
            .propose(slot(), &duty(&pubkey), &store)
            .await
            .expect("proposes");

        let (body, _) = node.published_envelopes().remove(0);
        let contents = SignedExecutionPayloadEnvelopeContents::from_ssz_bytes(&body).expect("ok");
        let envelope = contents.signed_execution_payload_envelope;
        let as_proposer = context().block_signing_root(envelope.message.hash_tree_root(), slot());
        assert!(!verifies(&pubkey, &envelope.signature.0, as_proposer));
    }

    /// Without `Eth-Execution-Payload-Included` the envelope is fetched by
    /// (slot, block root) and published bare, with the blob header false.
    #[tokio::test]
    async fn an_envelope_the_node_did_not_include_is_fetched_and_published_bare() {
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_gloas_block(
            slot(),
            7,
            BUILDER_INDEX_SELF_BUILD,
            false,
        ));

        service(node.clone())
            .propose(slot(), &duty(&pubkey), &store)
            .await
            .expect("proposes");

        let signed = gloas::SignedBeaconBlock::from_ssz_bytes(&node.published_blocks()[0].1)
            .expect("bare block");
        let block_root = signed.message.hash_tree_root();
        assert_eq!(node.envelope_requests(), vec![(slot(), block_root)]);

        let (body, blob_data_included) = node.published_envelopes().remove(0);
        assert!(!blob_data_included);
        let envelope =
            gloas::SignedExecutionPayloadEnvelope::from_ssz_bytes(&body).expect("bare envelope");
        assert_eq!(envelope.message.beacon_block_root, block_root);
        assert!(verifies(
            &pubkey,
            &envelope.signature.0,
            context().envelope_signing_root(&envelope.message, slot())
        ));
    }

    /// A bid naming a builder is that builder's to reveal; this client signs
    /// nothing for it.
    ///
    /// The block itself is signed and published, with builder proposals off
    /// too (this module's service has none): that is the block a node whose
    /// local build failed builds on a pooled bid. See the module doc.
    #[tokio::test]
    async fn a_builders_bid_gets_no_envelope_from_this_client() {
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_gloas_block(slot(), 7, 3, true));

        service(node.clone())
            .propose(slot(), &duty(&pubkey), &store)
            .await
            .expect("proposes");
        assert_eq!(node.published_blocks().len(), 1);
        assert!(node.published_envelopes().is_empty());
        assert!(node.envelope_requests().is_empty());
    }

    /// An envelope for another block must never be signed. The block is out
    /// already, so the proposal still reports it, but nothing is revealed.
    #[tokio::test]
    async fn an_envelope_for_another_block_is_not_signed() {
        let (store, pubkey) = store();
        let node = Arc::new(
            MockBeaconNode::new()
                .with_gloas_block(slot(), 7, BUILDER_INDEX_SELF_BUILD, false)
                .with_envelope_for(Root::repeat_byte(9)),
        );

        let result = service(node.clone())
            .propose(slot(), &duty(&pubkey), &store)
            .await;
        assert!(result.is_ok(), "the block was published");
        assert_eq!(node.published_blocks().len(), 1);
        assert!(node.published_envelopes().is_empty());
    }

    /// Slashing protection's semantics are unchanged at gloas: a second
    /// proposal for the slot is refused before asking for anything, and
    /// reveals no second envelope.
    #[tokio::test]
    async fn a_repeated_gloas_slot_is_refused_and_reveals_nothing_more() {
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_gloas_block(
            slot(),
            7,
            BUILDER_INDEX_SELF_BUILD,
            true,
        ));
        let service = service(node.clone());
        service
            .propose(slot(), &duty(&pubkey), &store)
            .await
            .expect("first");
        let err = service
            .propose(slot(), &duty(&pubkey), &store)
            .await
            .expect_err("a second block for one slot must be refused");
        assert!(matches!(err, Error::ProposalRefused { .. }), "got {err:?}");
        assert_eq!(node.block_requests().len(), 1);
        assert_eq!(node.published_envelopes().len(), 1);
    }

    /// The block is out by the time the envelope fails, so the proposal is
    /// still reported as published; the failure is logged and counted.
    #[tokio::test]
    async fn a_failed_envelope_publication_does_not_fail_the_proposal() {
        let (store, pubkey) = store();
        let node = Arc::new(
            MockBeaconNode::new()
                .with_gloas_block(slot(), 7, BUILDER_INDEX_SELF_BUILD, true)
                .failing_call("publish_execution_payload_envelope", "node is unhappy"),
        );
        let published = service(node.clone())
            .propose(slot(), &duty(&pubkey), &store)
            .await
            .expect("the block was published");
        assert_eq!(published, Proposed::Full(Published::Imported));
        assert!(node.published_envelopes().is_empty());
    }
}
