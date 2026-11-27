//! Everything this client knows about the chain arrives through here.
//!
//! One trait, so the duty services can be driven by a mock with no network and
//! no beacon node. That is the whole reason it exists: the alternative, calling
//! `reqwest` from inside the duty logic, makes the interesting behaviour
//! (a reorg invalidating duties, a node failing mid-slot) untestable.

use std::time::SystemTime;

use async_trait::async_trait;
use ethlambda_types::beacon::builder::SignedValidatorRegistrationV1;
use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::containers::shared::{AttestationData, SignedVoluntaryExit};
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::primitives::{
    BlsPubkey, BlsSignature, Bytes32, Epoch, Root, Slot, ValidatorIndex,
};
use ethlambda_types::beacon::signing::compute_epoch_at_slot;

use crate::beacon_node::block_contents::{ProducedBlock, Producer};
use crate::beacon_node::dto::{
    AttesterDutyDto, CommitteeSubscriptionDto, ProposerDutyDto, ProposerPreparationDto, PtcDutyDto,
    SingleAttestationDto, SyncCommitteeSubscriptionDto, SyncDutyDto,
};
use crate::beacon_node::health::SyncStatus;
use crate::error::{BeaconNodeFailure, Error, Result};
use ethlambda_types::beacon::containers::altair;
use ethlambda_types::beacon::containers::electra;
use ethlambda_types::beacon::containers::gloas;

pub mod block_contents;
pub mod dto;
pub mod events;
pub mod fallback;
pub mod health;
pub mod http;

#[cfg(test)]
pub mod mock;

/// Builder registrations per request. Lighthouse's batch size: large enough
/// that a few thousand validators take a handful of requests, small enough
/// that one request stays well under a node's body limit.
pub const REGISTRATION_BATCH: usize = 500;

/// Check that `data` is an answer about `slot`, which is in `fork`, as the
/// contract on [`BeaconNodeApi::attestation_data`] requires.
///
/// One function rather than two copies, because it is enforced in two places
/// for two different reasons and they must not drift apart. Each
/// implementation calls it so a wrong answer becomes an `Err` that failover
/// can act on, and [`crate::attestation::AttestationService`] calls it again
/// before signing, since the trait is public and nothing stops an
/// implementation from being wrong.
///
/// `slot` and `target.epoch` are checked because both are signable. `slot` is
/// the obvious one. `target.epoch` matters independently: it selects the
/// signing domain (see `SigningContext::attestation_signing_root`), so a node
/// answering with the right slot and a wrong target epoch is a second,
/// distinct way to make this client sign something it should not.
///
/// `index` is checked for liveness rather than safety. A vote whose index
/// cannot be valid at `fork` is one every peer rejects (gossip's
/// `attestation.data.index == 0` from electra, `< 2` from gloas), and by
/// then slashing protection has recorded its target, so the validator has no
/// second vote to cast in that epoch. Refused here, nothing is recorded for
/// it, and the `Err` is one failover moves past to a node that may answer
/// properly. Lodestar's validator client refuses the same before signing
/// (`validateAttestationDuty`).
///
/// `fork` must be the fork `slot` falls in on the caller's schedule, and is
/// taken on trust: an implementation is handed it with the request and holds
/// no schedule to check it against, so the bound on `index` is only as right
/// as the fork it is given. [`crate::attestation::AttestationService`], the
/// caller that signs, derives it from its own `Config` for the slot it asks
/// about, and runs this check again under it.
pub fn validate_attestation_data(slot: Slot, fork: ForkName, data: &AttestationData) -> Result<()> {
    if data.slot != slot {
        return Err(crate::error::Error::InconsistentResponse(format!(
            "requested attestation data for slot {slot}, node answered for slot {}",
            data.slot
        )));
    }
    let expected_target_epoch = compute_epoch_at_slot(slot);
    if data.target.epoch != expected_target_epoch {
        return Err(crate::error::Error::InconsistentResponse(format!(
            "attestation data for slot {slot} carries target epoch {}, expected \
             {expected_target_epoch}",
            data.target.epoch
        )));
    }
    // Signing a source at or past its target would record a source the
    // chain's justified checkpoint cannot have reached, and the record keeps
    // it: every honest attestation afterwards would be refused as a source
    // regression until justification caught up, or forever during
    // non-finality.
    if crate::slashing_protection::is_impossible_source(data.source.epoch, data.target.epoch) {
        return Err(crate::error::Error::InconsistentResponse(format!(
            "attestation data for slot {slot} carries source epoch {} at or past its target \
             epoch {}",
            data.source.epoch, data.target.epoch
        )));
    }
    let highest_index = highest_attestation_index(fork);
    if data.index > highest_index {
        return Err(crate::error::Error::InconsistentResponse(format!(
            "attestation data for slot {slot} carries index {}, and a {} attestation's is at \
             most {highest_index}",
            data.index,
            fork.as_str()
        )));
    }
    Ok(())
}

/// The highest `AttestationData.index` a vote at `fork` can carry.
///
/// Every fork is named rather than compared against, so a fork added after
/// gloas has to say what its index means instead of inheriting gloas's
/// answer.
fn highest_attestation_index(fork: ForkName) -> u64 {
    match fork {
        // A committee, and the one the query names: this client only ever
        // asks about committee 0 (see `BeaconNodeApi::attestation_data`), so
        // any other index is not an answer to its question.
        ForkName::Phase0
        | ForkName::Altair
        | ForkName::Bellatrix
        | ForkName::Capella
        | ForkName::Deneb => 0,
        // EIP-7549 moved the committee out of the signed data and left the
        // field fixed at zero.
        ForkName::Electra | ForkName::Fulu => 0,
        // The payload signal: 0 for a same-slot block or an empty one, 1 for
        // a block whose payload was seen. Which of the two is right depends
        // on the node's view of the block, which this client does not have,
        // so only the range is checked.
        ForkName::Gloas => 1,
        // Not a Beacon Chain fork: `Config::fork_at_epoch` never names it, so
        // a caller that does has a bug of its own. A panic rather than an
        // `Err`, because this runs after the node has answered: an `Err`
        // here is `InconsistentResponse`, which failover blames on the node
        // and retries on every other one, so a local bug would read as every
        // beacon node failing, every slot.
        ForkName::Lean => unreachable!(
            "validate_attestation_data: lean is not a Beacon Chain fork and has no attestation \
             data of this shape"
        ),
    }
}

/// The chain's genesis, as the beacon node reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Genesis {
    pub genesis_time: u64,
    pub genesis_validators_root: Root,
}

/// One epoch's duties of some kind, with the block root the schedule depends
/// on.
///
/// One envelope for both duty kinds, because the API uses one: a duties
/// response is `dependent_root` plus `data`, whatever `data` holds. What
/// differs is what the root *means*, and that difference matters enough to
/// state here.
///
/// For attester duties it is the block at the last slot of `epoch - 2`, so a
/// schedule survives any reorg shallower than two epochs. For proposer duties
/// it is the block at the last slot of `epoch - 1`: the proposer shuffling is
/// fixed a whole epoch later than the committee shuffling, so a proposer
/// schedule is invalidated by far shallower reorgs than an attester one, and a
/// caller must not reason about the two as if they were equally stable.
#[derive(Debug, Clone)]
pub struct Duties<T> {
    pub dependent_root: Root,
    pub duties: Vec<T>,
}

/// One epoch's attester duties. See [`Duties`] for what `dependent_root`
/// means here.
pub type AttesterDuties = Duties<AttesterDutyDto>;

/// One epoch's payload timeliness committee duties for the indices asked
/// about. See [`Duties`] for what `dependent_root` means; for these it is the
/// same kind of root the attester schedule uses, since committee membership is
/// derived from the same shuffling.
pub type PtcDuties = Duties<PtcDutyDto>;

/// Every proposer for one epoch, not only this client's. The endpoint takes no
/// validator list, so the caller filters. See [`Duties`] for what
/// `dependent_root` means here, and why it is the more fragile of the two.
pub type ProposerDuties = Duties<ProposerDutyDto>;

/// Everything `produceBlockV3` needs, and the two facts its answer is checked
/// against.
///
/// A struct rather than four arguments because two of the fields are only
/// there to be checked, not sent. `proposer_index` is not a query parameter at
/// all: the beacon node derives the proposer from the slot and its own head.
/// It is carried here so the check can live in the implementation, where a
/// wrong answer becomes an `Err` that failover acts on, for exactly the reason
/// spelled out on [`BeaconNodeApi::attestation_data`].
#[derive(Debug, Clone)]
pub struct BlockRequest {
    pub slot: Slot,
    /// The fork `slot` is in, by this client's own schedule. Selects the
    /// endpoint version: `produceBlockV3` before gloas, `produceBlockV4` from
    /// it on.
    pub fork: ForkName,
    /// The validator this client believes proposes `slot`.
    pub proposer_index: ValidatorIndex,
    /// This proposer's reveal for the slot's epoch, which the node needs
    /// before it can build a body.
    pub randao_reveal: BlsSignature,
    /// Thirty-two bytes consensus never reads.
    pub graffiti: Bytes32,
    /// The `builder_boost_factor` to send, or `None` when builder proposals are
    /// off before gloas. `None` sends `0` and refuses a blinded answer; `Some`
    /// sends the factor and accepts one. From gloas the factor travels in
    /// `produceBlockV4`'s body instead of the query, and the proposal service
    /// always sets it, builder proposals or not, so a pooled p2p bid can win
    /// on value; a gloas answer is never blinded.
    pub builder_boost_factor: Option<u64>,
    /// The smallest p2p bid, in gwei, the node may take for a gloas block
    /// (`produceBlockV4`'s `min_bid`): `--builder-min-bid`, with or without
    /// builder proposals, or `u64::MAX` with `--self-build-only`. Not sent
    /// before gloas, where no endpoint takes it.
    pub builder_min_bid: u64,
}

/// What became of a published block.
///
/// The distinction exists because `publishBlockV2` answers 202 for something
/// that is neither a success nor a failure: the node broadcast the block but
/// could not import it. Collapsing that into `Ok` would report a proposal as
/// clean when the node that made it cannot follow it, which usually means its
/// execution layer is unsynced or the parent is not what this client thought.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Published {
    /// 200: broadcast, and in the node's own database.
    Imported,
    /// 202: broadcast, but the node could not import it.
    BroadcastNotImported,
    /// 200 from `blinded_blocks`: the node handed the signed blinded block to
    /// its builder, which publishes the block and reveals the payload. Nothing
    /// says the node imported it.
    HandedToBuilder,
}

/// How many of the nodes sent to took something sent to every node.
///
/// The caller needs it when what it sends lives on each node separately and
/// a node that missed it never hears it any other way. Proposer preferences
/// are such a send: each node gossips only what it accepted, and the service
/// sends a preference every node holds only once an epoch more, so "some
/// node accepted" must not be mistaken for "every node did".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Every node it was sent to accepted. The only answer a single node
    /// gives. A fallback sends only to the nodes on this client's chain, so a
    /// node skipped for not being on it does not hold it: see
    /// [`BeaconNodeApi::readmissions`].
    Everywhere,
    /// At least one node accepted and at least one refused or did not answer.
    Partly,
}

/// Check that `block` is the block that was asked for.
///
/// The proposal-shaped counterpart to [`validate_attestation_data`], enforced
/// in the implementations for the same reason and with the same consequence
/// if it is not: [`fallback::FallbackBeaconNode`] wraps the call, so a check
/// above it runs only after one node's answer has been accepted, and a node
/// stuck on a stale head is never failed over from.
///
/// Both fields are checked because both end up signed. The slot selects the
/// signing domain and is the whole of what slashing protection keys a block on. The
/// proposer index is not something this client chooses either: a node on a
/// different fork computes a different proposer, and a block naming someone
/// else is one this client's key can only sign uselessly, while still burning
/// the slot in slashing protection's record.
pub fn validate_produced_block(request: &BlockRequest, block: &ProducedBlock) -> Result<()> {
    if block.slot() != request.slot {
        return Err(crate::error::Error::InconsistentResponse(format!(
            "requested a block for slot {}, node produced one for slot {}",
            request.slot,
            block.slot()
        )));
    }
    if block.proposer_index() != request.proposer_index {
        return Err(crate::error::Error::InconsistentResponse(format!(
            "block for slot {} names proposer {}, expected {}",
            request.slot,
            block.proposer_index(),
            request.proposer_index
        )));
    }
    Ok(())
}

/// An aggregate a beacon node folded together, with the fork it named.
///
/// The fork is carried for the reason [`ProducedBlock`]'s is: publishing has to
/// name the same one back, and with SSZ the response header is the only thing
/// that says which `Attestation` layout the bytes are.
#[derive(Debug, Clone)]
pub struct AggregateAttestation {
    pub fork: ForkName,
    pub attestation: AggregateKind,
}

/// The attestation container an aggregate is, by fork.
///
/// Gloas's `Attestation` is not electra's: its `aggregation_bits` is the
/// unbounded progressive bitlist, so its hash tree root differs and an
/// `AggregateAndProof` wrapping it must be signed over the gloas root.
#[derive(Debug, Clone)]
pub enum AggregateKind {
    /// Electra and fulu share one layout.
    Electra(electra::Attestation),
    Gloas(gloas::Attestation),
}

impl AggregateKind {
    /// The data the aggregate votes on, whichever layout carries it.
    pub fn data(&self) -> &AttestationData {
        match self {
            Self::Electra(attestation) => &attestation.data,
            Self::Gloas(attestation) => &attestation.data,
        }
    }
}

/// A batch of signed aggregates, all of one fork.
#[derive(Debug, Clone)]
pub enum SignedAggregates {
    Electra(Vec<electra::SignedAggregateAndProof>),
    Gloas(Vec<gloas::SignedAggregateAndProof>),
}

impl SignedAggregates {
    pub fn len(&self) -> usize {
        match self {
            Self::Electra(list) => list.len(),
            Self::Gloas(list) => list.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A validator's index and status, as resolved from its public key.
#[derive(Debug, Clone)]
pub struct ValidatorEntry {
    pub index: ValidatorIndex,
    pub pubkey: BlsPubkey,
    pub status: String,
}

/// Whether the node saw one validator act in the epoch asked about. See
/// [`BeaconNodeApi::liveness`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Liveness {
    pub index: ValidatorIndex,
    pub is_live: bool,
}

/// One validator's registry entry, as much of it as a voluntary exit needs.
///
/// `status` is the Beacon API's own string (`active_ongoing`,
/// `active_exiting`, `exited_unslashed`, ...). The three epochs are what the
/// exit command checks eligibility against before signing and reports once the
/// chain has accepted the exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorDetails {
    pub index: ValidatorIndex,
    pub status: String,
    pub activation_epoch: Epoch,
    pub exit_epoch: Epoch,
    pub withdrawable_epoch: Epoch,
}

#[async_trait]
pub trait BeaconNodeApi: Send + Sync {
    /// Who this node is, for a log line that names it: its URL for an HTTP
    /// node, empty for an implementation with nothing to say.
    fn describe(&self) -> String {
        String::new()
    }

    /// A count that grows each time a node calls may go to is added back: a
    /// fallback's node let back in by the chain check. A caller that stops
    /// sending something once every node took it ([`Delivery::Everywhere`])
    /// sends it again when this moves, since the node let back in was skipped
    /// by the sends before. Constant for one node, which is every node there
    /// is.
    fn readmissions(&self) -> u64 {
        0
    }

    /// The chain's genesis time and validators root, needed to compute slots
    /// and signing domains before any duty can be served.
    async fn genesis(&self) -> Result<Genesis>;

    /// The network's fork schedule and slot duration, needed to pick the
    /// right signing domain for a given epoch and to drive the slot clock.
    async fn spec(&self) -> Result<Config>;

    /// Whether the node is in a state this client must not sign against.
    ///
    /// Two states, not one, and the second is the reason this is not called
    /// `is_syncing`. A **syncing** node's head is not the network's head, so
    /// duties derived from it would be for the wrong chain. An **optimistic**
    /// node has a head its execution client has not validated, and the
    /// specification is explicit that a validator in that position must not
    /// sign: an optimistic validator "MUST NOT produce a block" and "MUST NOT
    /// participate in attestation", naming the proposer, attester, selection
    /// and aggregate domains.
    ///
    /// The two are independent. A node can report that it has finished syncing
    /// while still tracking an unvalidated head, so checking only the first
    /// leaves the second unguarded.
    ///
    /// Beacon nodes are separately obliged to answer 503 on the duty endpoints
    /// while optimistic, and this client maps that to
    /// [`crate::error::Error::BeaconNodeSyncing`]. That is a backstop, not the
    /// check: it puts correctness entirely in the node's hands for a rule the
    /// client is the one bound by.
    ///
    /// The duty loop does not call this. It reads the same two flags from the
    /// probe [`health`] takes ahead of every slot, through
    /// [`Self::sync_status`]. This answers the callers outside the loop: the
    /// voluntary-exit command, and a node's own check before
    /// [`Self::liveness`].
    async fn is_optimistic_or_syncing(&self) -> Result<bool>;

    /// The node's `GET /eth/v1/node/syncing` answer in full: the two flags
    /// [`Self::is_optimistic_or_syncing`] reads, `el_offline`, and the head slot
    /// and sync distance it reports. What [`health`]'s per-slot probe asks each
    /// node.
    async fn sync_status(&self) -> Result<SyncStatus>;

    /// [`Self::sync_status`], with the answer's `Date` header when it carried
    /// an IMF-fixdate: what [`health`]'s per-slot probe actually asks, so
    /// [`crate::clock_check`] can compare this client's clock with the node's.
    /// A node with no such header to give answers `None`, which leaves that
    /// node to the slot comparison alone.
    async fn sync_status_with_date(&self) -> Result<(SyncStatus, Option<SystemTime>)> {
        Ok((self.sync_status().await?, None))
    }

    /// Resolves each pubkey to its current validator index and status, so the
    /// rest of the client can address validators by index, as the Beacon API
    /// does everywhere except this one lookup.
    ///
    /// # An empty `pubkeys` must not reach the wire
    ///
    /// The endpoint treats an empty id list as "return **every** validator",
    /// which on mainnet is millions of entries. An implementation must answer
    /// an empty request with an empty result rather than asking, because the
    /// one caller that can pass an empty slice is a client with no keys
    /// loaded, and the answer it wants is "none of them", not "all of them".
    async fn validator_indices(&self, pubkeys: &[BlsPubkey]) -> Result<Vec<ValidatorEntry>>;

    /// The attester duties for `indices` in `epoch`, and the block root the
    /// schedule was computed against. A reorg past that root invalidates the
    /// schedule; the caller is the one that notices, by comparing roots.
    async fn attester_duties(
        &self,
        epoch: Epoch,
        indices: &[ValidatorIndex],
    ) -> Result<AttesterDuties>;

    /// Every proposer duty in `epoch`, and the block root the schedule was
    /// computed against.
    ///
    /// No validator list, unlike [`Self::attester_duties`]: the endpoint has
    /// no request body and answers for the whole epoch, so the caller keeps
    /// only the entries naming a validator it holds.
    ///
    /// The schedule is *not* as durable as an attester one. Its dependent root
    /// is only one epoch back rather than two, so a reorg that leaves attester
    /// duties untouched can still move a proposer between slots. A caller that
    /// treats the two the same way will act on a stale proposer schedule.
    async fn proposer_duties(&self, epoch: Epoch) -> Result<ProposerDuties>;

    /// Every proposer duty in `epoch` with v2's `dependent_root`: the block at
    /// `compute_start_slot_at_epoch(epoch - 1) - 1`, the shuffling dependent
    /// root fulu's proposer lookahead fixes the epoch's proposers from. Signed
    /// proposer preferences must carry exactly this root, which v1's
    /// definition (one epoch later) is not.
    ///
    /// The fallback fails over quietly here: when every node fails it logs
    /// nothing of its own, since both callers report the failure themselves:
    /// the preferences service once per epoch, and the duty loop, whose
    /// proposer schedule comes from here from fulu (see
    /// `duties::ProposerDutiesVersion`), at each fetch. A new caller that
    /// needs the failure seen must log it.
    async fn proposer_duties_v2(&self, epoch: Epoch) -> Result<ProposerDuties>;

    /// Produce the attestation data for `slot`, which is in `fork`.
    ///
    /// No committee index is ever a parameter here. The query carries
    /// `committee_index=0` at every fork, which the specification deprecated
    /// from electra on and nodes ignore, so a caller cannot get it wrong. From
    /// gloas the specification says to omit it, but Lighthouse still requires
    /// it (see `HttpBeaconNode::attestation_data_path`). From gloas the
    /// answer's `index` is no longer a committee but the payload signal (0 for
    /// a same-slot block, 1 when the attested block's payload was seen as
    /// full), and the caller must pass it through unchanged: it is signed.
    ///
    /// # Contract: the answer is for `slot`, or this is an `Err`
    ///
    /// An implementation must reject data whose `slot` is not the one asked
    /// for, and whose `target.epoch` is not that slot's epoch. Both are
    /// signable material, and slashing protection records whatever it allows,
    /// so a node answering about the wrong slot must never reach the signing
    /// path: a target from the future would raise the validator's watermark
    /// and cost it every attestation until the chain caught up.
    ///
    /// It must also reject an `index` that cannot be valid at `fork`: anything
    /// but 0 before gloas, anything above 1 from it. Such a vote is rejected
    /// by every peer, after slashing protection has spent the validator's one
    /// vote for the epoch on it. [`validate_attestation_data`] is every one of
    /// these checks.
    ///
    /// It matters that this is the *implementation's* job rather than the
    /// caller's, because of where failover sits.
    /// [`fallback::FallbackBeaconNode`] wraps this method: a check performed
    /// above it runs after `try_each` has already accepted node 1's answer and
    /// returned, so a node stuck on a stale head is seen as a success every
    /// slot and the next node is never consulted. Enforced here, a wrong
    /// answer is an `Err` that failover treats like any other and moves past.
    async fn attestation_data(&self, slot: Slot, fork: ForkName) -> Result<AttestationData>;

    /// Ask the node to build a block for `request.slot`.
    ///
    /// From gloas the node is asked to include the self-built payload's
    /// envelope in the answer, which saves a round trip inside the proposal's
    /// budget.
    ///
    /// Returns the block and whatever travelled with it, decoded into the
    /// typed container its root is taken from. SSZ is asked for first; before
    /// gloas a JSON answer is decoded too, for a proxy that rewrites the
    /// request's `Accept`. See [`block_contents`] for why either way ends in
    /// the same container, and never in a mapping of this crate's own.
    ///
    /// # Contract: the answer is for this request, or it is an `Err`
    ///
    /// An implementation must call [`validate_produced_block`] before
    /// returning, so that a node answering about the wrong slot or naming the
    /// wrong proposer is failed over from rather than signed for.
    ///
    /// # Contract: a blinded block only when builder proposals are on
    ///
    /// A blinded block is returned only when `request.builder_boost_factor` is
    /// `Some`, since only then does the caller publish one through
    /// [`Self::publish_blinded_block`]. With `None` an implementation must ask
    /// for an unblinded block and reject a blinded answer rather than
    /// returning something the caller will sign and then be unable to send.
    async fn produce_block(&self, request: &BlockRequest) -> Result<ProducedBlock>;

    /// Publish an already-signed block, given the SSZ body and the fork it was
    /// produced under.
    ///
    /// Bytes rather than a container, because the body's shape depends on the
    /// fork and the caller has already built the right one; re-deciding that
    /// here would mean two places that must agree.
    ///
    /// Borrowed rather than owned so failover can offer the same body to the
    /// next node without copying it. A block with blobs runs to megabytes, and
    /// a `Vec` here would be cloned once per configured node on every
    /// proposal, whether or not the first one succeeded.
    async fn publish_block(&self, fork: ForkName, body: &[u8]) -> Result<Published>;

    /// Publish a signed blinded block, produced under `fork` by `producer`
    /// (the [`ProducedBlock::producer`] of the block it was signed from), to
    /// `POST /eth/v2/beacon/blinded_blocks`. The node hands it to its builder.
    ///
    /// # Contract: the node that produced it, and no other
    ///
    /// Only the producing node's builder holds the payload, and only that node
    /// claimed the slot. Failover must not offer it elsewhere: the fallback
    /// sends it to `producer` alone.
    ///
    /// # Contract: which error means what
    ///
    /// The line is whether the node can have handed the block to its builder.
    ///
    /// - **Definite**, an `Err` other than `Error::BlindedUnconfirmed`: the
    ///   block was not published. A 4xx; a 503, which a syncing node answers
    ///   before it hands anything to a builder; and a connection that was never
    ///   established, refused or timed out, since the request never left.
    /// - **Unconfirmed**, `Error::BlindedUnconfirmed`: every other 5xx, and any
    ///   failure once the connection was up (no answer in time, a reset). The
    ///   relay may still publish the block.
    ///
    /// The status cannot always tell, and the HTTP implementation documents the
    /// edges it knowingly reads the wrong way.
    async fn publish_blinded_block(
        &self,
        producer: Producer,
        fork: ForkName,
        body: &[u8],
    ) -> Result<Published>;

    /// Send signed builder registrations to the node in one request, which it
    /// forwards to its builder. JSON, since a node may forward the body
    /// unchanged to MEV-Boost. State installed on the node's builder, so
    /// failover sends it to every node.
    async fn register_validators(
        &self,
        registrations: &[SignedValidatorRegistrationV1],
    ) -> Result<()>;

    /// Send `registrations` in requests of at most [`REGISTRATION_BATCH`], one
    /// after another, and say what became of each batch: one outcome per
    /// batch, in order, `Ok` when the node accepted it.
    ///
    /// Batched here, below the fallback's fan-out, so that each node works
    /// through its own sequence of batches beside the others: a hung node
    /// holds back only its own. Batched above it, every batch would wait for
    /// every node before the next one started.
    ///
    /// Once the node cannot be reached ([`Error::BeaconNode`]) the batches left
    /// are not sent, and fail with that error: each would cost another
    /// timeout, and the send waiting on them holds back the next keymanager
    /// change (see `crate::registration`). A node that answered with an error
    /// status is up, so it is still given the rest.
    ///
    /// [`Error::BeaconNode`]: crate::error::Error::BeaconNode
    async fn register_validators_in_batches(
        &self,
        registrations: &[SignedValidatorRegistrationV1],
    ) -> Vec<Result<()>> {
        let mut outcomes = Vec::new();
        let mut unreachable: Option<(String, BeaconNodeFailure, String)> = None;
        for batch in registrations.chunks(REGISTRATION_BATCH) {
            if let Some((url, failure, detail)) = &unreachable {
                outcomes.push(Err(Error::BeaconNode {
                    url: url.clone(),
                    failure: *failure,
                    detail: format!(
                        "not sent, an earlier batch could not reach the node: {detail}"
                    ),
                }));
                continue;
            }
            let outcome = self.register_validators(batch).await;
            if let Err(Error::BeaconNode {
                url,
                failure,
                detail,
            }) = &outcome
            {
                unreachable = Some((url.clone(), *failure, detail.clone()));
            }
            outcomes.push(outcome);
        }
        outcomes
    }

    /// Submit signed proposer preferences, which the node validates with the
    /// `proposer_preferences` gossip rules and publishes. `fork` is the
    /// `Eth-Consensus-Version`: the fork the preferences belong to, that of
    /// their proposal epoch.
    ///
    /// A 400 naming per-index failures is an `Err`: the whole call failed for
    /// the caller's purposes, although the node may have published the entries
    /// that passed. A node only short-circuits an identical entry, so one it
    /// holds for the same `(slot, dependent_root)` with other content fails
    /// every call that carries it. The caller therefore sends one preference
    /// per call. State on the node's gossip, so failover sends it to every
    /// node, and answers [`Delivery::Partly`] when only some of them accepted
    /// it, so the caller knows to send it again.
    async fn submit_proposer_preferences(
        &self,
        fork: ForkName,
        preferences: &[gloas::SignedProposerPreferences],
    ) -> Result<Delivery>;

    /// The envelope the node cached for the self-built payload of the block
    /// whose root is `block_root`, proposed at `slot`.
    ///
    /// Only needed when `produce_block` came back without its payload
    /// (`Eth-Execution-Payload-Included: false`). An answer whose
    /// `beacon_block_root` is not `block_root` is an `Err`, for the reason
    /// [`validate_produced_block`] is enforced in the implementations.
    async fn execution_payload_envelope(
        &self,
        slot: Slot,
        block_root: Root,
    ) -> Result<gloas::ExecutionPayloadEnvelope>;

    /// Publish a signed envelope, given its SSZ body.
    ///
    /// `blob_data_included` is the `Eth-Blob-Data-Included` header: `true`
    /// when the body is `SignedExecutionPayloadEnvelopeContents`, `false` when
    /// it is the bare signed envelope and the node attaches the blobs it
    /// cached at production time.
    async fn publish_execution_payload_envelope(
        &self,
        body: &[u8],
        blob_data_included: bool,
    ) -> Result<()>;

    /// [`Self::publish_execution_payload_envelope`] for the envelope of a block
    /// `producer` produced (the [`ProducedBlock::producer`] of the block it
    /// reveals the payload of).
    ///
    /// A single node has no one to choose and ignores `producer`, which is
    /// the default. The fallback reads it under `--broadcast blocks`, to send
    /// the envelope to the producing node first, and for a body without its
    /// blobs, with or without the flag, to send it to the producing node
    /// first, the one that cached them, and to the others only if it does not
    /// take it.
    async fn publish_execution_payload_envelope_produced_by(
        &self,
        producer: Producer,
        body: &[u8],
        blob_data_included: bool,
    ) -> Result<()> {
        let _ = producer;
        self.publish_execution_payload_envelope(body, blob_data_included)
            .await
    }

    /// The payload timeliness committee duties for `indices` in `epoch`.
    ///
    /// An epoch before gloas answers with no duties rather than an error.
    async fn ptc_duties(&self, epoch: Epoch, indices: &[ValidatorIndex]) -> Result<PtcDuties>;

    /// What a payload timeliness committee member should vote on at `slot`, or
    /// `None` when the node knows no block for it (204), which is an ordinary
    /// outcome and not an error.
    ///
    /// # Contract: the answer is for `slot`, or this is an `Err`
    ///
    /// For the reason [`Self::attestation_data`] states.
    ///
    /// # Not from a node whose last probe said syncing or optimistic
    ///
    /// The Beacon API asks for a 503 here only while a node syncs, and the
    /// answer carries no `execution_optimistic`, so an optimistic node may hand
    /// out data for a block its execution client has not validated. The
    /// fallback therefore does not ask a node whose last [`health`] probe
    /// reported syncing or optimistic, and answers `Err(BeaconNodeSyncing)`
    /// when that leaves no node to ask.
    async fn payload_attestation_data(
        &self,
        slot: Slot,
    ) -> Result<Option<gloas::PayloadAttestationData>>;

    /// Submit signed payload attestation messages to the node's pool. Returns
    /// how many it accepted, with the same partial-success reading as
    /// [`Self::submit_attestations`].
    async fn submit_payload_attestations(
        &self,
        messages: &[gloas::PayloadAttestationMessage],
    ) -> Result<usize>;

    /// Submits signed attestations to the node's pool, so they reach gossip.
    /// `fork_name` names the fork the attestations were produced under, since
    /// the endpoint requires it as a header rather than inferring it.
    ///
    /// Returns how many of `attestations` the node accepted. This can be
    /// fewer than `attestations.len()` without the call being an `Err`: the
    /// endpoint answers 400 with per-index detail when part of a batch is
    /// rejected, and still stores and gossips the rest, so a partial result
    /// is success for those entries, not failure for the whole batch.
    async fn submit_attestations(
        &self,
        attestations: &[SingleAttestationDto],
        fork_name: &str,
    ) -> Result<usize>;

    /// The best aggregate the node has for one committee's votes on
    /// `attestation_data_root` at `slot`.
    ///
    /// `committee_index` is separate from the root and not derivable from it.
    /// From electra on, `AttestationData.index` no longer names a committee (it
    /// is zero, and from gloas it is the payload signal, 0 or 1), so the root
    /// no longer distinguishes one committee's votes from another's in the
    /// same slot; the committee moved into the attestation's `committee_bits`.
    /// That is exactly why the v1 form of this endpoint was removed rather than
    /// deprecated: it had no way to ask the question.
    ///
    /// A node with nothing to fold answers 404, which the specification makes
    /// normative rather than exceptional. That surfaces here as an ordinary
    /// error so failover tries the next node, which may have seen the votes
    /// this one missed.
    async fn aggregate_attestation(
        &self,
        slot: Slot,
        attestation_data_root: Root,
        committee_index: u64,
    ) -> Result<AggregateAttestation>;

    /// Publish signed aggregates produced under `fork`.
    ///
    /// Typed rather than pre-encoded bytes, unlike [`Self::publish_block`],
    /// because the encoding is the implementation's call here: Lighthouse
    /// refuses an SSZ body on this endpoint with 415, so the HTTP client sends
    /// JSON. A block has no such problem and a block's JSON form is the large
    /// hand-written mapping this crate avoids, which is why the two differ.
    ///
    /// The endpoint takes a list even for one aggregate, so this does too.
    async fn publish_aggregates(&self, fork: ForkName, aggregates: &SignedAggregates)
    -> Result<()>;

    /// Tells the node where to pay each validator's execution-layer block
    /// rewards, so it has somewhere to send them when it builds a payload.
    ///
    /// Must be re-sent periodically. A node keeps a preparation for the epoch
    /// it arrived in and two more, and forgets all of them when it restarts, so
    /// a client that sends this once at startup stops being registered a few
    /// minutes later without anything reporting it.
    ///
    /// The node is not obliged to honour it. The specification says so
    /// outright, which is why a produced block's fee recipient is checked
    /// before it is signed rather than assumed.
    async fn prepare_beacon_proposer(&self, preparations: &[ProposerPreparationDto]) -> Result<()>;

    /// [`Self::prepare_beacon_proposer`] for a caller that sends it again
    /// every slot and reports a failure itself. The same request; what
    /// differs is the logging around it. The fallback logs a refusing node at
    /// `debug!` and says nothing when none accepts, where the plain call warns
    /// for each refusal and then that the duty was likely missed: once a slot,
    /// for as long as a node is down, and on slots with no duty.
    ///
    /// The default is the plain call because the logging is the fallback's
    /// alone: one node (`HttpBeaconNode`) logs nothing about its answer either
    /// way, so it has nothing to quieten.
    async fn prepare_beacon_proposer_quietly(
        &self,
        preparations: &[ProposerPreparationDto],
    ) -> Result<()> {
        self.prepare_beacon_proposer(preparations).await
    }

    /// Tells the node which committees this client's validators care about
    /// this epoch, so it can manage subnet subscriptions on their behalf.
    async fn subscribe_committees(&self, subscriptions: &[CommitteeSubscriptionDto]) -> Result<()>;

    /// The sync committee duties for `indices` in the period `epoch` falls in.
    /// `POST /eth/v1/validator/duties/sync/{epoch}`, whose answer carries no
    /// `dependent_root`: the committee is fixed a period ahead.
    async fn sync_duties(
        &self,
        epoch: Epoch,
        indices: &[ValidatorIndex],
    ) -> Result<Vec<SyncDutyDto>>;

    /// The root of the node's head block, which a sync committee message signs.
    ///
    /// # Contract: an optimistic head is `Err(BeaconNodeSyncing)`
    ///
    /// The answer carries `execution_optimistic`, and the optimistic-sync
    /// specification forbids signing `DOMAIN_SYNC_COMMITTEE` over a head the
    /// execution client has not validated. Mapping it to the same error a 503
    /// gets makes failover try the next node rather than hand this one's root
    /// to the signer.
    ///
    /// # Not from a node whose last probe said syncing
    ///
    /// A syncing node that is not optimistic answers its stale head with
    /// `execution_optimistic: false`, and the Beacon API defines no 503 for this
    /// endpoint. The fallback therefore does not ask a node whose last
    /// [`health`] probe reported syncing or optimistic, and answers
    /// `Err(BeaconNodeSyncing)` when that leaves no node to ask.
    async fn head_block_root(&self) -> Result<Root>;

    /// The root of the block at `slot` on the node's canonical chain, or
    /// `None` when that chain has no block there (the endpoint's 404, or a
    /// node answering with the last block before the slot).
    /// `GET /eth/v1/beacon/headers/{slot}`, which the proposal check in
    /// [`crate::performance`] reads a few slots after a block is published.
    ///
    /// # Contract: the answer is about `slot`, or it is an `Err`
    ///
    /// The header names its own slot. One at an earlier slot says the slot
    /// is empty; one at a later slot is
    /// [`crate::error::Error::InconsistentResponse`] rather than a root to
    /// compare: a block after this slot says nothing about it.
    async fn canonical_block_root(&self, slot: Slot) -> Result<Option<Root>>;

    /// Submit signed sync committee messages to the node's pool. Returns how
    /// many it accepted, with the same partial-success reading as
    /// [`Self::submit_attestations`].
    async fn submit_sync_committee_messages(
        &self,
        messages: &[altair::SyncCommitteeMessage],
    ) -> Result<usize>;

    /// The best contribution the node holds for one subcommittee's messages on
    /// `beacon_block_root` at `slot`. A node with nothing answers 404, which
    /// surfaces as an error so failover tries the next node, as it does for
    /// [`Self::aggregate_attestation`].
    ///
    /// # Contract: the answer is for this request, or it is an `Err`
    ///
    /// `slot`, `subcommittee_index` and `beacon_block_root` must equal the
    /// request, checked by [`validate_sync_contribution`] in the
    /// implementation for the reason [`Self::attestation_data`] states: the
    /// contribution is wrapped in a signature, so a wrong one must be failed
    /// over from rather than signed for.
    async fn sync_committee_contribution(
        &self,
        slot: Slot,
        subcommittee_index: u64,
        beacon_block_root: Root,
    ) -> Result<altair::SyncCommitteeContribution>;

    /// Publish signed contributions. JSON: the endpoint lists no SSZ body.
    async fn publish_contribution_and_proofs(
        &self,
        contributions: &[altair::SignedContributionAndProof],
    ) -> Result<()>;

    /// Tells the node which sync committee subnets this client's validators
    /// sit in, so it joins them. Like [`Self::subscribe_committees`] it is
    /// state installed on a node and must be re-sent, since a node forgets it
    /// on restart.
    async fn subscribe_sync_committees(
        &self,
        subscriptions: &[SyncCommitteeSubscriptionDto],
    ) -> Result<()>;

    /// One validator's registry entry at the node's head, or `None` when the
    /// node knows no validator with that key (404), which is an ordinary
    /// answer for a key whose deposit has not been processed, not an error.
    ///
    /// `GET /eth/v1/beacon/states/head/validators/{pubkey}`. Unlike
    /// [`Self::validator_indices`] this carries the activation and exit
    /// epochs, which is what a voluntary exit is checked against.
    async fn validator(&self, pubkey: &BlsPubkey) -> Result<Option<ValidatorDetails>>;

    /// Hand a signed voluntary exit to the node's pool, which validates it
    /// against its head state and gossips it. A refusal (400) surfaces as
    /// [`crate::error::Error::BeaconNodeStatus`] carrying the node's reason.
    async fn submit_voluntary_exit(&self, exit: &SignedVoluntaryExit) -> Result<()>;

    /// Whether the node saw each of `indices` act in each of `epochs`:
    /// `POST /eth/v1/validator/liveness/{epoch}` once per epoch, which
    /// doppelganger protection reads (see [`crate::doppelganger`]). What
    /// counts as acting is the node's own view; nodes count attestations,
    /// aggregates and blocks, whether seen on gossip or included on chain.
    ///
    /// The answer holds one list per epoch, in the order `epochs` names them.
    /// Every epoch is answered by the same node, so a caller combining them
    /// reads one node's view rather than two nodes' halves; a failure on any
    /// of them fails the whole call, and failover asks the next node about
    /// all of them.
    ///
    /// An empty `indices` answers an empty list per epoch without asking:
    /// some nodes refuse the request.
    ///
    /// # Contract: a syncing node's answer is `Err(BeaconNodeSyncing)`
    ///
    /// A node that has not caught up has not seen what the network did, so
    /// its "nobody is live" would clear a key it should not. An
    /// implementation must ask the node it is about to ask this of whether
    /// it is syncing or optimistic (once for the whole call, not once per
    /// epoch), and answer [`crate::error::Error::BeaconNodeSyncing`] instead
    /// when it is, so failover moves to a node that can answer. Asking any
    /// other node, as [`Self::is_optimistic_or_syncing`] through failover
    /// would, says nothing about the one that answers.
    ///
    /// # Contract: one answer per index asked, and no other
    ///
    /// Checked by [`validate_liveness`] in the implementation, for each
    /// epoch, for the reason [`Self::attestation_data`] states: a key the
    /// answer leaves out has not been shown silent, and must not be read as
    /// if it had.
    async fn liveness(
        &self,
        epochs: &[Epoch],
        indices: &[ValidatorIndex],
    ) -> Result<Vec<Vec<Liveness>>>;
}

/// Check that `answers` names every one of `asked` exactly once and nothing
/// else, as the contract on [`BeaconNodeApi::liveness`] requires.
pub fn validate_liveness(asked: &[ValidatorIndex], answers: &[Liveness]) -> Result<()> {
    let asked: std::collections::HashSet<ValidatorIndex> = asked.iter().copied().collect();
    let mut answered = std::collections::HashSet::with_capacity(answers.len());
    for answer in answers {
        if !asked.contains(&answer.index) {
            return Err(Error::InconsistentResponse(format!(
                "liveness answer names validator {}, which was not asked about",
                answer.index
            )));
        }
        if !answered.insert(answer.index) {
            return Err(Error::InconsistentResponse(format!(
                "liveness answer names validator {} twice",
                answer.index
            )));
        }
    }
    if answered.len() != asked.len() {
        return Err(Error::InconsistentResponse(format!(
            "liveness answer covers {} of the {} validators asked about",
            answered.len(),
            asked.len()
        )));
    }
    Ok(())
}

/// Check that `contribution` is the one asked for, as the contract on
/// [`BeaconNodeApi::sync_committee_contribution`] requires.
pub fn validate_sync_contribution(
    slot: Slot,
    subcommittee_index: u64,
    beacon_block_root: Root,
    contribution: &altair::SyncCommitteeContribution,
) -> Result<()> {
    if contribution.slot != slot
        || contribution.subcommittee_index != subcommittee_index
        || contribution.beacon_block_root != beacon_block_root
    {
        return Err(crate::error::Error::InconsistentResponse(format!(
            "requested a sync contribution for slot {slot} subcommittee {subcommittee_index} \
             root {beacon_block_root:?}, node answered for slot {} subcommittee {} root {:?}",
            contribution.slot, contribution.subcommittee_index, contribution.beacon_block_root
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::beacon::containers::shared::Checkpoint;

    fn data(slot: Slot, source: Epoch, target: Epoch) -> AttestationData {
        AttestationData {
            slot,
            index: 0,
            beacon_block_root: Root::ZERO,
            source: Checkpoint {
                epoch: source,
                root: Root::ZERO,
            },
            target: Checkpoint {
                epoch: target,
                root: Root::ZERO,
            },
        }
    }

    /// Slot 100 is in epoch 3 on the mainnet preset.
    #[test]
    fn attestation_data_with_a_source_at_or_past_its_target_is_refused() {
        let fork = ForkName::Fulu;
        assert!(validate_attestation_data(100, fork, &data(100, 2, 3)).is_ok());
        assert!(validate_attestation_data(100, fork, &data(100, 0, 3)).is_ok());
        let err =
            validate_attestation_data(100, fork, &data(100, 3, 3)).expect_err("source == target");
        assert!(err.to_string().contains("source epoch 3"), "{err}");
        assert!(validate_attestation_data(100, fork, &data(100, 4, 3)).is_err());
    }

    /// At genesis both checkpoints are epoch 0, and that is the one valid
    /// shape where the source does not precede the target.
    #[test]
    fn genesis_attestation_data_is_accepted() {
        let fork = ForkName::Phase0;
        assert!(validate_attestation_data(0, fork, &data(0, 0, 0)).is_ok());
        assert!(
            validate_attestation_data(0, fork, &data(0, 1, 0)).is_err(),
            "a source past a genesis target is not the genesis shape"
        );
    }

    fn with_index(index: u64) -> AttestationData {
        AttestationData {
            index,
            ..data(100, 2, 3)
        }
    }

    /// Before gloas the index is zero: the committee this client asks about
    /// up to deneb, and EIP-7549's fixed zero from electra. Anything else is
    /// a vote no peer accepts.
    #[test]
    fn a_nonzero_index_is_refused_before_gloas() {
        let before_gloas = ForkName::ALL
            .iter()
            .copied()
            .filter(|fork| *fork < ForkName::Gloas);
        for fork in before_gloas {
            assert!(
                validate_attestation_data(100, fork, &with_index(0)).is_ok(),
                "{fork:?} takes index 0"
            );
            let err = validate_attestation_data(100, fork, &with_index(1))
                .expect_err("an index of 1 before gloas");
            assert!(
                matches!(err, crate::error::Error::InconsistentResponse(_)),
                "{fork:?}: failover must be able to move past it, got {err}"
            );
            assert!(err.to_string().contains("carries index 1"), "{err}");
        }
    }

    /// From gloas the index is the payload signal, 0 or 1, and passes through
    /// as the node gave it. Only a value outside that range is refused.
    #[test]
    fn a_gloas_index_is_zero_or_one() {
        let fork = ForkName::Gloas;
        assert!(validate_attestation_data(100, fork, &with_index(0)).is_ok());
        assert!(validate_attestation_data(100, fork, &with_index(1)).is_ok());
        let err = validate_attestation_data(100, fork, &with_index(2)).expect_err("an index of 2");
        assert!(err.to_string().contains("at most 1"), "{err}");
        assert!(validate_attestation_data(100, fork, &with_index(u64::MAX)).is_err());
    }

    /// Lean is not on the Beacon Chain's fork timeline and no schedule names
    /// it, so a caller that does has a bug, reported as one rather than as a
    /// node answering badly.
    #[test]
    #[should_panic(expected = "lean is not a Beacon Chain fork")]
    fn the_lean_fork_is_a_bug_in_the_caller() {
        let _ = validate_attestation_data(100, ForkName::Lean, &with_index(0));
    }

    fn liveness(answers: &[(ValidatorIndex, bool)]) -> Vec<Liveness> {
        answers
            .iter()
            .map(|&(index, is_live)| Liveness { index, is_live })
            .collect()
    }

    /// Every index asked about, once each, in any order, is an answer.
    /// Anything else is a node to fail over from, never a key to clear.
    #[test]
    fn a_liveness_answer_must_cover_exactly_the_indices_asked() {
        let asked = [3, 5];
        assert!(validate_liveness(&asked, &liveness(&[(5, false), (3, true)])).is_ok());
        for wrong in [
            liveness(&[(3, false)]),
            liveness(&[(3, false), (5, false), (9, false)]),
            liveness(&[(3, false), (3, false)]),
            liveness(&[(3, false), (9, false)]),
        ] {
            let err = validate_liveness(&asked, &wrong).expect_err("not an answer");
            assert!(
                matches!(err, crate::error::Error::InconsistentResponse(_)),
                "got {err}"
            );
        }
    }
}
