//! Everything this client knows about the chain arrives through here.
//!
//! One trait, so the duty services can be driven by a mock with no network and
//! no beacon node. That is the whole reason it exists: the alternative, calling
//! `reqwest` from inside the duty logic, makes the interesting behaviour
//! (a reorg invalidating duties, a node failing mid-slot) untestable.

use async_trait::async_trait;
use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::containers::shared::AttestationData;
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::primitives::{
    BlsPubkey, BlsSignature, Bytes32, Epoch, Root, Slot, ValidatorIndex,
};
use ethlambda_types::beacon::signing::compute_epoch_at_slot;

use crate::beacon_node::block_contents::ProducedBlock;
use crate::beacon_node::dto::{
    AttesterDutyDto, CommitteeSubscriptionDto, ProposerDutyDto, ProposerPreparationDto,
    SingleAttestationDto,
};
use crate::error::Result;
use ethlambda_types::beacon::containers::electra::{Attestation, SignedAggregateAndProof};

pub mod block_contents;
pub mod dto;
pub mod fallback;
pub mod http;

#[cfg(test)]
pub mod mock;

/// Check that `data` is an answer about `slot`, as the contract on
/// [`BeaconNodeApi::attestation_data`] requires.
///
/// One function rather than two copies, because it is enforced in two places
/// for two different reasons and they must not drift apart. Each
/// implementation calls it so a wrong answer becomes an `Err` that failover
/// can act on, and [`crate::attestation::AttestationService`] calls it again
/// before signing, since the trait is public and nothing stops an
/// implementation from being wrong.
///
/// Both fields are checked because both are signable. `slot` is the obvious
/// one. `target.epoch` matters independently: it selects the signing domain
/// (see `SigningContext::attestation_signing_root`), so a node answering with
/// the right slot and a wrong target epoch is a second, distinct way to make
/// this client sign something it should not.
pub fn validate_attestation_data(slot: Slot, data: &AttestationData) -> Result<()> {
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
    Ok(())
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
    /// The validator this client believes proposes `slot`.
    pub proposer_index: ValidatorIndex,
    /// This proposer's reveal for the slot's epoch, which the node needs
    /// before it can build a body.
    pub randao_reveal: BlsSignature,
    /// Thirty-two bytes consensus never reads.
    pub graffiti: Bytes32,
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
/// signing domain and is the whole of what the proposal guard keys on. The
/// proposer index is not something this client chooses either: a node on a
/// different fork computes a different proposer, and a block naming someone
/// else is one this client's key can only sign uselessly, while still burning
/// the guard's record for that slot.
pub fn validate_produced_block(request: &BlockRequest, block: &ProducedBlock) -> Result<()> {
    let block = block.block();
    if block.slot != request.slot {
        return Err(crate::error::Error::InconsistentResponse(format!(
            "requested a block for slot {}, node produced one for slot {}",
            request.slot, block.slot
        )));
    }
    if block.proposer_index != request.proposer_index {
        return Err(crate::error::Error::InconsistentResponse(format!(
            "block for slot {} names proposer {}, expected {}",
            request.slot, block.proposer_index, request.proposer_index
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
    pub attestation: Attestation,
}

/// A validator's index and status, as resolved from its public key.
#[derive(Debug, Clone)]
pub struct ValidatorEntry {
    pub index: ValidatorIndex,
    pub pubkey: BlsPubkey,
    pub status: String,
}

#[async_trait]
pub trait BeaconNodeApi: Send + Sync {
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
    async fn is_optimistic_or_syncing(&self) -> Result<bool>;

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

    /// Produce the attestation data for `slot`.
    ///
    /// No committee index: the specification deprecated that parameter, from
    /// Electra on `AttestationData.index` must be zero, and beacon nodes ignore
    /// whatever is supplied. Keeping it out means a caller cannot get it wrong.
    ///
    /// # Contract: the answer is for `slot`, or this is an `Err`
    ///
    /// An implementation must reject data whose `slot` is not the one asked
    /// for, and whose `target.epoch` is not that slot's epoch. Both are
    /// signable material, and this client keeps no slashing-protection record,
    /// so a node answering about the wrong slot must never reach the signing
    /// path.
    ///
    /// It matters that this is the *implementation's* job rather than the
    /// caller's, because of where failover sits.
    /// [`fallback::FallbackBeaconNode`] wraps this method: a check performed
    /// above it runs after `try_each` has already accepted node 1's answer and
    /// returned, so a node stuck on a stale head is seen as a success every
    /// slot and the next node is never consulted. Enforced here, a wrong
    /// answer is an `Err` that failover treats like any other and moves past.
    async fn attestation_data(&self, slot: Slot) -> Result<AttestationData>;

    /// Ask the node to build a block for `request.slot`.
    ///
    /// Returns the block and whatever travelled with it, decoded from SSZ.
    /// JSON is not used here: see [`block_contents`] for why a block, alone
    /// among everything this client handles, cannot go through the JSON path.
    ///
    /// # Contract: the answer is for this request, or it is an `Err`
    ///
    /// An implementation must call [`validate_produced_block`] before
    /// returning, so that a node answering about the wrong slot or naming the
    /// wrong proposer is failed over from rather than signed for.
    ///
    /// # Contract: never a blinded block
    ///
    /// This client does not implement the builder flow, so it cannot publish a
    /// blinded block and must not sign one. An implementation must ask for an
    /// unblinded block and reject a blinded answer rather than returning
    /// something the caller will sign and then be unable to send.
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
    /// From electra on, `AttestationData.index` is required to be zero, so the
    /// root no longer distinguishes one committee's votes from another's in the
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
    async fn publish_aggregates(
        &self,
        fork: ForkName,
        aggregates: &[SignedAggregateAndProof],
    ) -> Result<()>;

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

    /// Tells the node which committees this client's validators care about
    /// this epoch, so it can manage subnet subscriptions on their behalf.
    async fn subscribe_committees(&self, subscriptions: &[CommitteeSubscriptionDto]) -> Result<()>;
}
