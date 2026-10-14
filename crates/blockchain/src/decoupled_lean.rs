//! The chain actor of a lean node running the decoupled consensus protocol.
//!
//! It owns the protocol engine (`ethlambda_decoupled::Store`), this node's
//! validator keys and anti-slashing records, and the signatures that back
//! every object the engine holds. It ticks on the protocol's public grid
//! (`Δ = slot / 4`), runs the duties each tick asks for, and imports blocks,
//! Goldfish votes and attestations from the decoupled topics.
//!
//! Lean specifics, on top of the engine:
//!
//! * every validator weighs one, the slot-`s` committee is a rotating window
//!   of the registry (`lean_decoupled::in_goldfish_committee`; every
//!   validator unless the network sets a size), and the proposer of slot
//!   `s` is `s mod n`, as on 3SF-mini lean;
//! * Goldfish votes carry individual XMSS signatures (see
//!   `ethlambda_types::lean_decoupled` for the epoch grid). Attestations are
//!   signed in subgroups after the action time, travel on subnets and reach
//!   blocks only as leanVM aggregates (see [`crate::decoupled_aggregation`]);
//! * imported blocks and the anti-slashing records are persisted under
//!   prefixed `Metadata` keys and replayed on restart. A replayed node is a
//!   node that joins: it holds no locks until its first confirmation updates.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ethlambda_crypto::signature::{ValidatorPublicKey, ValidatorSignature};
use ethlambda_decoupled::{
    AttestationInput, BlockError, BlockInput, CommitteeSizes, Electorate, Params, Record,
    Store as Engine,
};
use ethlambda_network_api::{
    DecoupledToP2PRef, InitDecoupledP2P, SharedDecoupledBlocks,
    p2p_to_decoupled::{
        NewDecoupledAggregate, NewDecoupledAttestation, NewDecoupledBlock, NewDecoupledVote,
    },
};
use ethlambda_storage::{StorageBackend, Table};
use ethlambda_types::ShortRoot;
use ethlambda_types::attestation::XmssSignature;
use ethlambda_types::decoupled::{
    Attestation, BlockRef, DecoupledStatus, GoldfishVote, SharedDecoupledStatus,
};
use ethlambda_types::lean_decoupled::{
    AggregatedDecoupledAttestation, DecoupledBlock, DecoupledBlockBody, MAX_BLOCK_AGGREGATES,
    SignedDecoupledAttestation, SignedDecoupledBlock, SignedGoldfishVote, attestation_epoch,
    attestation_subgroup, attestation_subnet, goldfish_vote_epoch, in_goldfish_committee,
};
use ethlambda_types::primitives::{H256, HashTreeRoot as _};
use ethlambda_types::time::unix_now_ms;
use libssz::{SszDecode, SszEncode};
use libssz_types::{SszBitlist, SszList};
use serde::{Deserialize, Serialize};
use spawned_concurrency::actor;
use spawned_concurrency::error::ActorError;
use spawned_concurrency::message::Message;
use spawned_concurrency::protocol;
use spawned_concurrency::tasks::{
    Actor, ActorRef, ActorStart, Backend, Context, Handler, send_after,
};
use tracing::{debug, error, info, warn};

use crate::decoupled_aggregation::{
    AggregatePool, AggregationConfig, Child, Job, Pending, Produced, RawPool, Schedule,
    decode_signature, participant_keys, populated_subnets, run_job, validators_on,
    verify_aggregate,
};
use crate::key_manager::{KeyManager, ValidatorKeyPair};

/// `Metadata` key prefix of a persisted block, followed by its root.
const BLOCK_KEY_PREFIX: &[u8] = b"decoupled/block/";
/// `Metadata` key prefix of a validator's persisted record, followed by its
/// index (little-endian).
const RECORD_KEY_PREFIX: &[u8] = b"decoupled/record/";

/// Blocks held while their parent is missing, at most. Past it the oldest
/// parent's children are dropped: they can be fetched again.
const MAX_PARKED_BLOCKS: usize = 1024;

/// How long a by-root lookup is left alone before it is asked again.
const REFETCH_AFTER: Duration = Duration::from_secs(4);

/// Slots after its action time a round's signing and aggregation are kept.
const MAX_ROUND_AGE_SLOTS: u64 = 4;

/// What a lean decoupled chain is: its constants and its validator set.
pub struct DecoupledLeanConfig {
    pub params: Params,
    pub genesis_time_ms: u64,
    pub slot_duration_ms: u64,
    /// The decoupled genesis block (`DecoupledBlock::genesis`).
    pub genesis_root: H256,
    /// `(attestation_pubkey, proposal_pubkey)` of every validator, by index.
    pub validators: Vec<(Vec<u8>, Vec<u8>)>,
    /// `|𝒦_s|`, at most the validator count; see [`in_goldfish_committee`].
    pub goldfish_committee_size: u64,
    /// Attestation subnets, signing subgroups and the aggregator role.
    pub aggregation: AggregationConfig,
}

impl DecoupledLeanConfig {
    /// `Δ`, in milliseconds.
    fn delta_ms(&self) -> u64 {
        self.slot_duration_ms / 4
    }
}

/// A round being signed: the input decided at its action time, and when that
/// was.
#[derive(Debug, Clone, Copy)]
struct Attesting {
    input: AttestationInput,
    action_ms: u64,
}

/// One aggregator's work on one round's attestations.
#[derive(Debug)]
struct Pipeline {
    slot: u64,
    action_ms: u64,
    /// This node's proof per data so far, every batch folded in.
    running: HashMap<H256, AggregatedDecoupledAttestation>,
    /// Validators inside `running`.
    folded: HashSet<u64>,
    batches: u32,
    /// Whether the last batch ran and its proofs went out.
    published: bool,
    /// Whether the cross-subnet merge ran.
    merged: bool,
}

impl Pipeline {
    fn new(slot: u64, action_ms: u64) -> Self {
        Self {
            slot,
            action_ms,
            running: HashMap::new(),
            folded: HashSet::new(),
            batches: 0,
            published: false,
            merged: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunKind {
    Batch { last: bool },
    Merge,
}

/// The proving run in flight. One at a time: every proof queues on leanVM's
/// one prover thread anyway.
#[derive(Debug)]
struct Run {
    id: u64,
    slot: u64,
    kind: RunKind,
}

/// Self-message: sign `subgroup`'s attestations of `slot`'s round.
pub struct SignSubgroup {
    slot: u64,
    subgroup: u64,
}
impl Message for SignSubgroup {
    type Result = ();
}

/// Self-message at an aggregation deadline: look again at what is due.
pub struct AggregationCheck;
impl Message for AggregationCheck {
    type Result = ();
}

/// From the proving worker: everything run `id` produced.
pub struct RunFinished {
    id: u64,
    produced: Vec<Produced>,
    failed: usize,
    elapsed: Duration,
}
impl Message for RunFinished {
    type Result = ();
}

/// One validator's persisted signing state: its anti-slashing record, and
/// the last slots it voted and attested in, so a restart inside a slot never
/// signs a second message at one XMSS epoch.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SigningState {
    record: Record,
    last_vote_slot: Option<u64>,
    #[serde(default)]
    last_attestation_slot: Option<u64>,
}

/// Handle to the running actor.
pub struct DecoupledLean {
    handle: ActorRef<DecoupledLeanServer>,
}

impl DecoupledLean {
    /// Start the actor, replaying any blocks a previous run persisted.
    pub fn spawn(
        config: DecoupledLeanConfig,
        validator_keys: HashMap<u64, ValidatorKeyPair>,
        backend: Arc<dyn StorageBackend>,
        blocks: SharedDecoupledBlocks,
        status: SharedDecoupledStatus,
    ) -> Self {
        let validator_count = config.validators.len();
        let pubkeys: Vec<(ValidatorPublicKey, ValidatorPublicKey)> = config
            .validators
            .iter()
            .map(|(attestation, proposal)| {
                (
                    ValidatorPublicKey::from_bytes(attestation).expect("valid attestation pubkey"),
                    ValidatorPublicKey::from_bytes(proposal).expect("valid proposal pubkey"),
                )
            })
            .collect();
        let attestation_keys = pubkeys.iter().map(|keys| keys.0.clone()).collect();
        let schedule = Schedule::new(&config.aggregation, config.delta_ms());
        info!(
            committee_count = config.aggregation.committee_count,
            duty_subnets = ?config.aggregation.duty_subnets,
            subgroups = schedule.subgroups,
            spacing_ms = schedule.spacing_ms,
            final_deadline_ms = schedule.final_deadline_ms,
            merge_deadline_ms = schedule.merge_deadline_ms,
            max_children = config.aggregation.max_children,
            "Decoupled attestation aggregation schedule"
        );
        let engine = Engine::from_genesis(
            config.params,
            Electorate::uniform(validator_count),
            config.genesis_root,
        )
        .with_committee_sizes(CommitteeSizes::fixed(config.goldfish_committee_size));
        let ours: Vec<u64> = {
            let mut ids: Vec<u64> = validator_keys.keys().copied().collect();
            ids.sort();
            ids
        };
        let mut server = DecoupledLeanServer {
            config,
            engine,
            keys: KeyManager::new(validator_keys),
            ours,
            pubkeys,
            attestation_keys,
            signing: HashMap::new(),
            vote_signatures: HashMap::new(),
            schedule,
            attesting: BTreeMap::new(),
            raw: RawPool::default(),
            aggregates: AggregatePool::default(),
            pipelines: BTreeMap::new(),
            run: None,
            next_run_id: 0,
            verified: HashMap::new(),
            parked: BTreeMap::new(),
            future: Vec::new(),
            requested: HashMap::new(),
            blocks,
            status,
            backend,
            p2p: None,
        };
        server.restore();
        let genesis_ms = server.config.genesis_time_ms;
        let handle = server.start_with_backend(Backend::Thread);
        let until_genesis = genesis_ms.saturating_sub(unix_now_ms());
        send_after(
            Duration::from_millis(until_genesis),
            handle.context(),
            decoupled_lean_protocol::Tick,
        );
        Self { handle }
    }

    pub fn actor_ref(&self) -> &ActorRef<DecoupledLeanServer> {
        &self.handle
    }
}

pub struct DecoupledLeanServer {
    config: DecoupledLeanConfig,
    engine: Engine,
    keys: KeyManager,
    /// This node's validators, ascending.
    ours: Vec<u64>,
    /// `(attestation, proposal)` public keys by validator index.
    pubkeys: Vec<(ValidatorPublicKey, ValidatorPublicKey)>,
    /// The attestation keys alone, which aggregate verification indexes.
    attestation_keys: Vec<ValidatorPublicKey>,
    signing: HashMap<u64, SigningState>,
    /// The signature behind every vote the engine may put in a proposal.
    vote_signatures: HashMap<GoldfishVote, XmssSignature>,
    schedule: Schedule,
    /// The rounds whose subgroups may still be signing, by action slot.
    attesting: BTreeMap<u64, Attesting>,
    /// Individual attestations of the subnets this node aggregates.
    raw: RawPool,
    /// Verified aggregates: what merges and proposals draw on.
    aggregates: AggregatePool,
    /// This aggregator's rounds still in flight, by action slot. Several at
    /// once when a round is shorter than its proving.
    pipelines: BTreeMap<u64, Pipeline>,
    run: Option<Run>,
    next_run_id: u64,
    /// Roots whose signature checked out, with the slot they belong to, so a
    /// vote, attestation or aggregate already verified on gossip is not
    /// verified again when a block carries it. A vote's root is the vote's;
    /// an attestation's or aggregate's is its whole envelope's, which pins
    /// the epoch and signature too.
    verified: HashMap<H256, u64>,
    /// Blocks waiting for their parent, by parent root.
    parked: BTreeMap<H256, Vec<SignedDecoupledBlock>>,
    /// Blocks of a slot the clock has not reached.
    future: Vec<SignedDecoupledBlock>,
    /// Roots asked of peers, and when.
    requested: HashMap<H256, Instant>,
    blocks: SharedDecoupledBlocks,
    status: SharedDecoupledStatus,
    backend: Arc<dyn StorageBackend>,
    p2p: Option<DecoupledToP2PRef>,
}

#[protocol]
pub(crate) trait DecoupledLeanProtocol: Send + Sync {
    #[allow(dead_code)] // invoked via send_after(Tick)
    fn tick(&self) -> Result<(), ActorError>;
}

#[actor(protocol = DecoupledLeanProtocol)]
impl DecoupledLeanServer {
    #[send_handler]
    async fn handle_tick(&mut self, _msg: decoupled_lean_protocol::Tick, ctx: &Context<Self>) {
        self.sync_clock(ctx);
        let delta = self.config.delta_ms();
        let elapsed = unix_now_ms().saturating_sub(self.config.genesis_time_ms);
        let next = delta - elapsed % delta;
        send_after(
            Duration::from_millis(next),
            ctx.clone(),
            decoupled_lean_protocol::Tick,
        );
    }
}

impl Handler<InitDecoupledP2P> for DecoupledLeanServer {
    async fn handle(&mut self, msg: InitDecoupledP2P, _ctx: &Context<Self>) {
        self.p2p = Some(msg.p2p);
        info!("Decoupled chain: P2P protocol ref initialized");
    }
}

impl Handler<NewDecoupledBlock> for DecoupledLeanServer {
    async fn handle(&mut self, msg: NewDecoupledBlock, ctx: &Context<Self>) {
        self.sync_clock(ctx);
        self.on_block(msg.block);
        self.publish_status();
    }
}

impl Handler<NewDecoupledVote> for DecoupledLeanServer {
    async fn handle(&mut self, msg: NewDecoupledVote, ctx: &Context<Self>) {
        self.sync_clock(ctx);
        self.on_vote(msg.vote);
    }
}

impl Handler<NewDecoupledAttestation> for DecoupledLeanServer {
    async fn handle(&mut self, msg: NewDecoupledAttestation, ctx: &Context<Self>) {
        self.sync_clock(ctx);
        self.on_attestation(msg.attestation);
        self.advance_aggregation(ctx);
    }
}

impl Handler<NewDecoupledAggregate> for DecoupledLeanServer {
    async fn handle(&mut self, msg: NewDecoupledAggregate, ctx: &Context<Self>) {
        self.sync_clock(ctx);
        self.on_aggregate(msg.aggregate);
        self.advance_aggregation(ctx);
    }
}

impl Handler<SignSubgroup> for DecoupledLeanServer {
    async fn handle(&mut self, msg: SignSubgroup, ctx: &Context<Self>) {
        self.sync_clock(ctx);
        self.sign_subgroup(msg.slot, msg.subgroup);
        self.advance_aggregation(ctx);
    }
}

impl Handler<AggregationCheck> for DecoupledLeanServer {
    async fn handle(&mut self, _msg: AggregationCheck, ctx: &Context<Self>) {
        self.sync_clock(ctx);
        self.advance_aggregation(ctx);
    }
}

impl Handler<RunFinished> for DecoupledLeanServer {
    async fn handle(&mut self, msg: RunFinished, ctx: &Context<Self>) {
        self.sync_clock(ctx);
        self.on_run_finished(msg);
        self.advance_aggregation(ctx);
    }
}

impl DecoupledLeanServer {
    // ── Clock and duties ───────────────────────────────────────────────────

    /// The current tick on the protocol grid, or `None` before genesis.
    fn now_tick(&self) -> Option<i64> {
        let now = unix_now_ms();
        let elapsed = now.checked_sub(self.config.genesis_time_ms)?;
        Some((elapsed / self.config.delta_ms()) as i64)
    }

    /// Run every tick up to now, and the duties of the current one. Duties of
    /// a tick that is already past are skipped: a late block, vote or
    /// attestation is worth less than none, and an XMSS epoch skipped is
    /// never reused.
    fn sync_clock(&mut self, ctx: &Context<Self>) {
        let Some(now) = self.now_tick() else {
            return;
        };
        let events = self.engine.advance_to(now);
        if events.is_empty() {
            return;
        }
        for event in events {
            if event.tick != now {
                continue;
            }
            if event.propose {
                self.propose(event.slot);
            }
            if event.vote {
                self.vote(event.slot);
                self.warm_keys(event.slot + 1);
            }
            if event.attest {
                let action_ms = self.config.genesis_time_ms
                    + u64::try_from(event.tick).unwrap_or_default() * self.config.delta_ms();
                self.attest(event.slot, action_ms, ctx);
            }
        }
        self.retry_future_blocks();
        self.refetch_missing_parents();
        self.prune();
        self.publish_status();
    }

    fn proposer_of(&self, slot: u64) -> u64 {
        slot % self.pubkeys.len().max(1) as u64
    }

    fn warm_keys(&mut self, slot: u64) {
        let proposer = self.proposer_of(slot);
        let proposal = self
            .ours
            .contains(&proposer)
            .then_some((proposer, slot as u32));
        self.keys
            .prepare_epochs_in_background(goldfish_vote_epoch(slot) as u32, proposal);
    }

    /// `propose_block` at `t_s`, if one of this node's validators proposes.
    fn propose(&mut self, slot: u64) {
        let proposer = self.proposer_of(slot);
        if !self.ours.contains(&proposer) {
            return;
        }
        let proposal = self.engine.proposal();
        let mut votes = Vec::new();
        let mut support = Vec::new();
        for vote in &proposal.votes {
            let Some(signature) = self.vote_signatures.get(vote) else {
                warn!(
                    slot,
                    validator = vote.validator,
                    "No signature for a pooled vote"
                );
                continue;
            };
            votes.push(SignedGoldfishVote {
                vote: *vote,
                signature: signature.clone(),
            });
            support.push(proposal.support_votes.contains(vote));
        }
        // The engine picks attestations; the block carries the fewest held
        // aggregates covering them. One the pool has no proof for waits for
        // its aggregate.
        let attestations = self
            .aggregates
            .pack(&proposal.attestations, slot, MAX_BLOCK_AGGREGATES);
        let covered: usize = attestations
            .iter()
            .map(|aggregate| aggregate.participant_indices().count())
            .sum();
        if !proposal.attestations.is_empty() {
            debug!(
                slot,
                selected = proposal.attestations.len(),
                aggregates = attestations.len(),
                covered,
                "Packed attestations"
            );
        }
        let body = DecoupledBlockBody {
            votes: SszList::try_from(votes).expect("at most two votes per validator"),
            support: SszBitlist::try_from(support).expect("one bit per vote"),
            attestations: SszList::try_from(attestations).expect("capped above"),
        };
        let message = DecoupledBlock {
            slot,
            proposer_index: proposer,
            parent_root: proposal.parent_root,
            body,
        };
        let root = message.hash_tree_root();
        let signature = match self.keys.sign_block_root(proposer, slot as u32, &root) {
            Ok(signature) => signature,
            Err(err) => {
                error!(slot, proposer, %err, "Failed to sign decoupled block");
                return;
            }
        };
        let block = SignedDecoupledBlock { message, signature };
        info!(
            slot,
            proposer,
            block_root = %ShortRoot(&root.0),
            parent_root = %ShortRoot(&proposal.parent_root.0),
            votes = block.message.body.votes.len(),
            attestations = block.message.body.attestations.len(),
            "Proposed decoupled block"
        );
        self.import(block.clone(), root);
        if let Some(p2p) = &self.p2p {
            let _ = p2p
                .publish_decoupled_block(block)
                .inspect_err(|err| error!(%err, "Failed to publish decoupled block"));
        }
    }

    /// `goldfish_vote` at `t_s + Δ`, by this node's members of `𝒦_s`.
    fn vote(&mut self, slot: u64) {
        let head = self.engine.goldfish_vote_head();
        for validator in self.ours.clone() {
            if !self.in_committee(validator, slot) {
                continue;
            }
            let state = self.signing.entry(validator).or_default();
            if state.last_vote_slot.is_some_and(|last| last >= slot) {
                continue;
            }
            state.last_vote_slot = Some(slot);
            self.persist_signing(validator);
            let vote = GoldfishVote {
                validator,
                slot,
                head,
            };
            let epoch = goldfish_vote_epoch(slot) as u32;
            let signature =
                match self
                    .keys
                    .sign_attestation_message(validator, epoch, &vote.hash_tree_root())
                {
                    Ok(signature) => signature,
                    Err(err) => {
                        error!(slot, validator, %err, "Failed to sign Goldfish vote");
                        continue;
                    }
                };
            self.engine.on_goldfish_vote(vote);
            self.vote_signatures.insert(vote, signature.clone());
            if let Some(p2p) = &self.p2p {
                let _ = p2p
                    .publish_decoupled_vote(SignedGoldfishVote { vote, signature })
                    .inspect_err(|err| error!(%err, "Failed to publish Goldfish vote"));
            }
        }
        debug!(slot, head = %ShortRoot(&head.0), "Cast Goldfish votes");
    }

    /// The FG action at `a_r`, once per round. The input is decided now, for
    /// every validator; the signing is staggered: subgroup 0 signs now and
    /// subgroup `g` `g` spacings later, all at this slot's attestation epoch.
    /// An aggregator also opens the round's pipeline and arms its deadlines.
    fn attest(&mut self, slot: u64, action_ms: u64, ctx: &Context<Self>) {
        let input = self.engine.attestation_input();
        self.attesting.insert(slot, Attesting { input, action_ms });
        let now = unix_now_ms();
        for subgroup in 1..self.schedule.subgroups {
            let due = action_ms + self.schedule.sign_offset_ms(subgroup);
            send_after(
                Duration::from_millis(due.saturating_sub(now)),
                ctx.clone(),
                SignSubgroup { slot, subgroup },
            );
        }
        if self.is_aggregating() {
            self.pipelines.insert(slot, Pipeline::new(slot, action_ms));
            for deadline in [
                self.schedule.final_deadline_ms,
                self.schedule.merge_deadline_ms,
            ] {
                send_after(
                    Duration::from_millis((action_ms + deadline).saturating_sub(now)),
                    ctx.clone(),
                    AggregationCheck,
                );
            }
        }
        self.sign_subgroup(slot, 0);
        self.advance_aggregation(ctx);
    }

    /// Sign, through each validator's own record (which releases an
    /// attestation only with a new height pair), the attestations of
    /// `subgroup`'s validators for `slot`'s round, and publish each on its
    /// subnet.
    fn sign_subgroup(&mut self, slot: u64, subgroup: u64) {
        let Some(attesting) = self.attesting.get(&slot).copied() else {
            return;
        };
        let input = attesting.input;
        let epoch = attestation_epoch(slot) as u32;
        let committee_count = self.config.aggregation.committee_count;
        let subgroups = self.schedule.subgroups;
        let aggregating = self.is_aggregating();
        let mut attested = 0;
        let mut released = None;
        for validator in self.ours.clone() {
            if attestation_subgroup(validator, committee_count, subgroups) != subgroup {
                continue;
            }
            let state = self.signing.entry(validator).or_default();
            if state.last_attestation_slot.is_some_and(|last| last >= slot) {
                continue;
            }
            let Some(attestation) = state.record.create_attestation(validator, &input) else {
                continue;
            };
            state.last_attestation_slot = Some(slot);
            state.record.prune_below(input.finalized_height);
            self.persist_signing(validator);
            let root = attestation.data.hash_tree_root();
            let signature = match self.keys.sign_attestation_message(validator, epoch, &root) {
                Ok(signature) => signature,
                Err(err) => {
                    error!(slot, validator, %err, "Failed to sign decoupled attestation");
                    continue;
                }
            };
            // Gossip never hands a node its own message back.
            let subnet = attestation_subnet(validator, committee_count);
            if aggregating && self.config.aggregation.duty_subnets.contains(&subnet) {
                self.raw
                    .insert(&attestation.data, slot, validator, signature.clone());
            }
            attested += 1;
            released = Some(attestation.data.clone());
            if let Some(p2p) = &self.p2p {
                let _ = p2p
                    .publish_decoupled_attestation(SignedDecoupledAttestation {
                        attestation,
                        slot,
                        signature,
                    })
                    .inspect_err(|err| error!(%err, "Failed to publish decoupled attestation"));
            }
        }
        if let Some(data) = released {
            let height = data.height_pair();
            let finality = data.finality_pair();
            let late_ms = unix_now_ms()
                .saturating_sub(attesting.action_ms + self.schedule.sign_offset_ms(subgroup));
            info!(
                slot,
                subgroup,
                validators = attested,
                late_ms,
                height = height.height,
                entry = %ShortRoot(&height.entry.0),
                timeout = height.timeout,
                finality_height = finality.map(|pair| pair.height),
                finality_target = finality.map(|pair| ShortRoot(&pair.target.0).to_string()),
                "Attested"
            );
        }
    }

    // ── Aggregation ────────────────────────────────────────────────────────

    fn is_aggregating(&self) -> bool {
        self.config.aggregation.aggregator.is_enabled()
    }

    /// Start whatever proving a round is due, if nothing is running: a batch
    /// once a subgroup's worth of this node's subnets is pending, the last
    /// batch once everyone signed or the final deadline passed, then the
    /// cross-subnet merge once every populated subnet has a proof out or the
    /// merge deadline passed.
    ///
    /// Rounds can overlap (a round can be shorter than its proving), so each
    /// has its own pipeline, and the oldest round with work due goes first:
    /// its proofs are the ones closest to their blocks.
    fn advance_aggregation(&mut self, ctx: &Context<Self>) {
        if self.run.is_some() || !self.is_aggregating() {
            return;
        }
        let now = unix_now_ms();
        let committee_count = self.config.aggregation.committee_count;
        let validator_count = self.pubkeys.len() as u64;
        let expected = validators_on(
            &self.config.aggregation.duty_subnets,
            validator_count,
            committee_count,
        );
        let quarter = expected.div_ceil(self.schedule.subgroups).max(1);
        let populated = populated_subnets(validator_count, committee_count);
        let due = self.pipelines.values().find_map(|pipeline| {
            if !pipeline.published {
                let pending = self.raw.pending(pipeline.slot, &pipeline.folded) as u64;
                let everyone_in = pipeline.folded.len() as u64 + pending >= expected;
                let last =
                    everyone_in || now >= pipeline.action_ms + self.schedule.final_deadline_ms;
                return (last || pending >= quarter)
                    .then_some((pipeline.slot, RunKind::Batch { last }));
            }
            if !pipeline.merged {
                let covered = self
                    .aggregates
                    .covered_subnets(pipeline.slot, committee_count);
                let merge_due = populated.is_subset(&covered)
                    || now >= pipeline.action_ms + self.schedule.merge_deadline_ms;
                return merge_due.then_some((pipeline.slot, RunKind::Merge));
            }
            None
        });
        match due {
            Some((slot, RunKind::Batch { last })) => self.start_batch(slot, last, ctx),
            Some((slot, RunKind::Merge)) => self.start_merge(slot, ctx),
            None => {}
        }
    }

    /// Fold every pending signature of `slot`'s round into this node's
    /// running proof of its data, one job per data.
    fn start_batch(&mut self, slot: u64, last: bool, ctx: &Context<Self>) {
        let Some(pipeline) = self.pipelines.get(&slot) else {
            return;
        };
        let mut jobs = Vec::new();
        for Pending {
            data_root,
            data,
            signatures,
        } in self.raw.batch(slot, &pipeline.folded)
        {
            let raw: Vec<_> = signatures
                .into_iter()
                .filter_map(|(validator, signature)| {
                    let pubkey = self.attestation_keys.get(validator as usize)?.clone();
                    Some((validator, pubkey, decode_signature(&signature)?))
                })
                .collect();
            let children = pipeline
                .running
                .get(&data_root)
                .and_then(|running| self.child(running))
                .into_iter()
                .collect();
            jobs.push(Job {
                data,
                data_root,
                slot,
                children,
                raw,
            });
        }
        if jobs.is_empty() {
            if last {
                self.publish_running(slot);
                self.advance_aggregation(ctx);
            }
            return;
        }
        self.spawn_run(RunKind::Batch { last }, slot, jobs, ctx);
    }

    /// Merge `slot`'s round's subnet proofs, one job per data that has more
    /// than one disjoint proof and none covering them all.
    fn start_merge(&mut self, slot: u64, ctx: &Context<Self>) {
        let Some(pipeline) = self.pipelines.get_mut(&slot) else {
            return;
        };
        let jobs: Vec<Job> = self
            .aggregates
            .merge_inputs(slot)
            .into_iter()
            .filter_map(|(data_root, data, proofs)| {
                let children: Option<Vec<Child>> = proofs
                    .iter()
                    .map(|held| {
                        Some(Child {
                            pubkeys: participant_keys(&held.participants, &self.attestation_keys)?,
                            proof: held.aggregate.proof.clone(),
                            participants: held.participants.clone(),
                        })
                    })
                    .collect();
                Some(Job {
                    data: data.clone(),
                    data_root,
                    slot,
                    children: children?,
                    raw: Vec::new(),
                })
            })
            .collect();
        if jobs.is_empty() {
            pipeline.merged = true;
            debug!(slot, "Nothing to merge across subnets");
            return;
        }
        self.spawn_run(RunKind::Merge, slot, jobs, ctx);
    }

    /// A held proof as a child of the next one.
    fn child(&self, aggregate: &AggregatedDecoupledAttestation) -> Option<Child> {
        let participants: Vec<u64> = aggregate.participant_indices().collect();
        Some(Child {
            pubkeys: participant_keys(&participants, &self.attestation_keys)?,
            proof: aggregate.proof.clone(),
            participants,
        })
    }

    /// Prove `jobs` on a worker thread; [`RunFinished`] brings the results
    /// back.
    fn spawn_run(&mut self, kind: RunKind, slot: u64, jobs: Vec<Job>, ctx: &Context<Self>) {
        let id = self.next_run_id;
        self.next_run_id += 1;
        let actor = ctx.actor_ref();
        let max_children = self.config.aggregation.max_children;
        let job_count = jobs.len();
        let raw: usize = jobs.iter().map(|job| job.raw.len()).sum();
        let children: usize = jobs.iter().map(|job| job.children.len()).sum();
        let spawned = std::thread::Builder::new()
            .name("decoupled-aggregation".into())
            .spawn(move || {
                let started = Instant::now();
                let mut produced = Vec::with_capacity(jobs.len());
                let mut failed = 0;
                for job in jobs {
                    match run_job(job, max_children) {
                        Ok(output) => produced.push(output),
                        Err(err) => {
                            warn!(%err, "Decoupled attestation aggregation failed");
                            failed += 1;
                        }
                    }
                }
                let _ = actor.send(RunFinished {
                    id,
                    produced,
                    failed,
                    elapsed: started.elapsed(),
                });
            });
        match spawned {
            Ok(_) => {
                debug!(
                    slot,
                    ?kind,
                    jobs = job_count,
                    raw,
                    children,
                    "Aggregation started"
                );
                self.run = Some(Run { id, slot, kind });
            }
            Err(err) => error!(%err, "Failed to start the aggregation worker"),
        }
    }

    fn on_run_finished(&mut self, msg: RunFinished) {
        let Some(run) = self.run.take_if(|run| run.id == msg.id) else {
            return;
        };
        let elapsed_ms = msg.elapsed.as_millis() as u64;
        match run.kind {
            RunKind::Batch { last } => {
                let Some(pipeline) = self.pipelines.get_mut(&run.slot) else {
                    return;
                };
                pipeline.batches += 1;
                let mut folded = 0;
                for produced in msg.produced {
                    folded += produced.folded.len();
                    self.raw
                        .remove(produced.data_root, run.slot, &produced.folded);
                    pipeline.folded.extend(produced.folded.iter().copied());
                    pipeline
                        .running
                        .insert(produced.data_root, produced.aggregate);
                }
                info!(
                    slot = run.slot,
                    batch = pipeline.batches,
                    last,
                    folded,
                    participants = pipeline.folded.len(),
                    failed = msg.failed,
                    elapsed_ms,
                    "Folded a batch of attestations"
                );
                if last {
                    self.publish_running(run.slot);
                }
            }
            RunKind::Merge => {
                if let Some(pipeline) = self.pipelines.get_mut(&run.slot) {
                    pipeline.merged = true;
                }
                for produced in msg.produced {
                    let participants = produced.aggregate.participant_indices().count();
                    info!(
                        slot = run.slot,
                        participants,
                        proof_bytes = produced.aggregate.proof.len(),
                        elapsed_ms,
                        "Merged subnet aggregates"
                    );
                    self.adopt_aggregate(produced.aggregate, true);
                }
            }
        }
    }

    /// Publish `slot`'s round's running proofs: this aggregator's subnet
    /// aggregates.
    fn publish_running(&mut self, slot: u64) {
        let Some(pipeline) = self.pipelines.get_mut(&slot) else {
            return;
        };
        pipeline.published = true;
        let running: Vec<AggregatedDecoupledAttestation> =
            pipeline.running.values().cloned().collect();
        let late_ms = unix_now_ms().saturating_sub(pipeline.action_ms);
        for aggregate in running {
            info!(
                slot,
                participants = aggregate.participant_indices().count(),
                proof_bytes = aggregate.proof.len(),
                late_ms,
                "Published subnet aggregate"
            );
            self.adopt_aggregate(aggregate, true);
        }
    }

    /// Take a verified aggregate in: the pool, the engine (one attestation
    /// per participant), and gossip when this node made it.
    fn adopt_aggregate(&mut self, aggregate: AggregatedDecoupledAttestation, publish: bool) {
        self.verified
            .insert(aggregate.hash_tree_root(), aggregate.slot);
        if !self.aggregates.insert(aggregate.clone()) {
            return;
        }
        for attestation in aggregate.attestations() {
            self.engine.on_attestation(attestation);
        }
        if publish && let Some(p2p) = &self.p2p {
            let _ = p2p
                .publish_decoupled_aggregate(aggregate)
                .inspect_err(|err| error!(%err, "Failed to publish decoupled aggregate"));
        }
    }

    // ── Imports ────────────────────────────────────────────────────────────

    fn on_vote(&mut self, signed: SignedGoldfishVote) {
        let vote = signed.vote;
        if !self.verify_vote(&signed) {
            debug!(
                slot = vote.slot,
                validator = vote.validator,
                "Invalid Goldfish vote"
            );
            return;
        }
        if self.engine.on_goldfish_vote(vote) {
            self.vote_signatures.insert(vote, signed.signature);
        }
    }

    /// An attestation from a subnet. Only an aggregator of that subnet keeps
    /// it, for the round it is folding; everyone else lets gossip carry it
    /// on and waits for the aggregate, which is what blocks carry.
    fn on_attestation(&mut self, signed: SignedDecoupledAttestation) {
        let subnet = attestation_subnet(
            signed.attestation.validator,
            self.config.aggregation.committee_count,
        );
        // A peer's first subgroup can beat this node's own action-time tick,
        // so the round need not be open yet: the slot is what is checked.
        let current = self.engine.current_slot();
        if !self.is_aggregating()
            || !self.config.aggregation.duty_subnets.contains(&subnet)
            || signed.slot + 1 < current
            || signed.slot > current + 1
        {
            return;
        }
        if !self.verify_attestation(&signed) {
            debug!(
                slot = signed.slot,
                validator = signed.attestation.validator,
                "Invalid decoupled attestation"
            );
            return;
        }
        self.raw.insert(
            &signed.attestation.data,
            signed.slot,
            signed.attestation.validator,
            signed.signature,
        );
    }

    /// An aggregate from gossip: a subnet's or a merge.
    fn on_aggregate(&mut self, aggregate: AggregatedDecoupledAttestation) {
        if aggregate.slot > self.engine.current_slot() + 1
            || !self.engine.attestation_is_useful(&aggregate.data)
        {
            return;
        }
        if !self.verify_aggregate_cached(&aggregate) {
            debug!(slot = aggregate.slot, "Invalid decoupled aggregate");
            return;
        }
        self.adopt_aggregate(aggregate, false);
    }

    fn on_block(&mut self, block: SignedDecoupledBlock) {
        let root = block.message.hash_tree_root();
        if self.engine.contains(&root) {
            return;
        }
        if block.message.slot > self.engine.current_slot() {
            if self.future.len() < MAX_PARKED_BLOCKS {
                self.future.push(block);
            }
            return;
        }
        let parent = block.message.parent_root;
        if !self.engine.contains(&parent) {
            self.park(block);
            self.request(parent);
            return;
        }
        if !self.verify_block(&block, root) {
            warn!(
                slot = block.message.slot,
                block_root = %ShortRoot(&root.0),
                "Dropping decoupled block with an invalid signature"
            );
            return;
        }
        self.import(block, root);
    }

    /// Hand a checked block to the engine, then everything that was waiting
    /// on it.
    fn import(&mut self, block: SignedDecoupledBlock, root: H256) {
        let input = block_input(&block, root);
        match self.engine.on_block(&input) {
            Ok(()) => {}
            Err(BlockError::Duplicate) => return,
            Err(BlockError::FutureSlot { .. }) => {
                self.future.push(block);
                return;
            }
            Err(BlockError::UnknownParent(parent)) => {
                self.park(block);
                self.request(parent);
                return;
            }
            Err(err) => {
                warn!(
                    slot = block.message.slot,
                    block_root = %ShortRoot(&root.0),
                    %err,
                    "Decoupled block refused"
                );
                return;
            }
        }
        for signed in block.message.body.votes.iter() {
            self.vote_signatures
                .insert(signed.vote, signed.signature.clone());
        }
        let finalized = self.engine.finalized();
        info!(
            slot = block.message.slot,
            proposer = block.message.proposer_index,
            block_root = %ShortRoot(&root.0),
            parent_root = %ShortRoot(&block.message.parent_root.0),
            votes = block.message.body.votes.len(),
            attestations = block.message.body.attestations.len(),
            finalized_slot = finalized.slot,
            "Imported decoupled block"
        );
        self.persist_block(&block, root);
        self.blocks
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(root, block);
        self.requested.remove(&root);
        if let Some(children) = self.parked.remove(&root) {
            for child in children {
                self.on_block(child);
            }
        }
    }

    fn park(&mut self, block: SignedDecoupledBlock) {
        let parked: usize = self.parked.values().map(Vec::len).sum();
        if parked >= MAX_PARKED_BLOCKS
            && let Some((&oldest, _)) = self.parked.iter().next()
        {
            self.parked.remove(&oldest);
        }
        self.parked
            .entry(block.message.parent_root)
            .or_default()
            .push(block);
    }

    fn request(&mut self, root: H256) {
        let due = self
            .requested
            .get(&root)
            .is_none_or(|asked| asked.elapsed() >= REFETCH_AFTER);
        if !due {
            return;
        }
        self.requested.insert(root, Instant::now());
        if let Some(p2p) = &self.p2p {
            let _ = p2p
                .fetch_decoupled_blocks(vec![root])
                .inspect_err(|err| error!(%err, "Failed to request a decoupled block"));
        }
    }

    fn retry_future_blocks(&mut self) {
        let current = self.engine.current_slot();
        let (due, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.future)
            .into_iter()
            .partition(|block| block.message.slot <= current);
        self.future = later;
        for block in due {
            self.on_block(block);
        }
    }

    fn refetch_missing_parents(&mut self) {
        let missing: Vec<H256> = self
            .parked
            .keys()
            .filter(|root| !self.engine.contains(root))
            .copied()
            .collect();
        for root in missing {
            self.request(root);
        }
    }

    /// Drop signatures no proposal can use any more, and stale bookkeeping.
    fn prune(&mut self) {
        let slot = self.engine.current_slot();
        let oldest_vote_slot = slot.saturating_sub(1);
        self.vote_signatures
            .retain(|vote, _| vote.slot >= oldest_vote_slot);
        let engine = &self.engine;
        self.aggregates
            .retain(|data| engine.attestation_is_useful(data));
        self.raw.prune(slot.saturating_sub(MAX_ROUND_AGE_SLOTS));
        self.attesting
            .retain(|&action_slot, _| action_slot + MAX_ROUND_AGE_SLOTS >= slot);
        // A round is done once merged; one still unfinished this long after
        // its action time has missed every block that would count it.
        self.pipelines.retain(|&action_slot, pipeline| {
            !pipeline.merged && action_slot + MAX_ROUND_AGE_SLOTS >= slot
        });
        // Long enough for a block to carry what gossip delivered: votes are
        // carried one slot later, attestations within a few.
        let oldest_slot = slot.saturating_sub(4 * self.config.params.lock_period);
        self.verified
            .retain(|_, verified_slot| *verified_slot >= oldest_slot);
        self.requested
            .retain(|_, asked| asked.elapsed() < 8 * REFETCH_AFTER);
    }

    // ── Signatures ─────────────────────────────────────────────────────────

    /// Verify `signature` over `root` at `epoch`, remembering a success under
    /// `root`.
    fn check(
        &mut self,
        pubkey: Option<&ValidatorPublicKey>,
        epoch: u64,
        root: H256,
        slot: u64,
        signature: &XmssSignature,
    ) -> bool {
        if self.verified.contains_key(&root) {
            return true;
        }
        let valid = xmss_valid(pubkey, epoch, root, signature);
        if valid {
            self.verified.insert(root, slot);
        }
        valid
    }

    /// Whether `validator` is on slot `slot`'s Goldfish committee.
    fn in_committee(&self, validator: u64, slot: u64) -> bool {
        in_goldfish_committee(
            validator,
            slot,
            self.config.goldfish_committee_size,
            self.pubkeys.len() as u64,
        )
    }

    /// A vote counts only from a member of its slot's committee, checked
    /// before the signature since it costs nothing.
    fn verify_vote(&mut self, signed: &SignedGoldfishVote) -> bool {
        let vote = signed.vote;
        if !self.in_committee(vote.validator, vote.slot) {
            return false;
        }
        let pubkey = self
            .pubkeys
            .get(vote.validator as usize)
            .map(|keys| keys.0.clone());
        self.check(
            pubkey.as_ref(),
            goldfish_vote_epoch(vote.slot),
            vote.hash_tree_root(),
            vote.slot,
            &signed.signature,
        )
    }

    /// The attester's signature at the epoch of the slot the envelope names.
    /// An envelope naming a slot ahead of the clock is refused: no honest
    /// attester signs at an epoch it has not reached.
    fn verify_attestation(&mut self, signed: &SignedDecoupledAttestation) -> bool {
        if signed.slot > self.engine.current_slot() + 1 || !signed.attestation.data.is_well_formed()
        {
            return false;
        }
        let envelope = signed.hash_tree_root();
        if self.verified.contains_key(&envelope) {
            return true;
        }
        let attestation = &signed.attestation;
        let pubkey = self
            .pubkeys
            .get(attestation.validator as usize)
            .map(|keys| &keys.0);
        // Not `check`: the data root is signed by every attester of the
        // round, and again in another slot, so only the whole envelope can
        // stand for a success.
        let valid = xmss_valid(
            pubkey,
            attestation_epoch(signed.slot),
            attestation.data.hash_tree_root(),
            &signed.signature,
        );
        if valid {
            self.verified.insert(envelope, signed.slot);
        }
        valid
    }

    /// [`verify_aggregate`], remembering a success under the aggregate's
    /// root.
    fn verify_aggregate_cached(&mut self, aggregate: &AggregatedDecoupledAttestation) -> bool {
        let root = aggregate.hash_tree_root();
        if self.verified.contains_key(&root) {
            return true;
        }
        let valid = verify_aggregate(aggregate, &self.attestation_keys);
        if valid {
            self.verified.insert(root, aggregate.slot);
        }
        valid
    }

    /// The proposer schedule, the proposer's signature, and every carried
    /// vote's signature and aggregate's proof. An aggregate must have been
    /// signed before the block's slot: attestations are signed after the
    /// slot's proposal.
    fn verify_block(&mut self, block: &SignedDecoupledBlock, root: H256) -> bool {
        let message = &block.message;
        if message.proposer_index != self.proposer_of(message.slot) {
            return false;
        }
        if message.body.support.len() != message.body.votes.len() {
            return false;
        }
        if message
            .body
            .attestations
            .iter()
            .any(|aggregate| aggregate.slot >= message.slot)
        {
            return false;
        }
        let pubkey = self
            .pubkeys
            .get(message.proposer_index as usize)
            .map(|keys| keys.1.clone());
        if !self.check(
            pubkey.as_ref(),
            message.slot,
            root,
            message.slot,
            &block.signature,
        ) {
            return false;
        }
        message.body.votes.iter().all(|vote| self.verify_vote(vote))
            && message
                .body
                .attestations
                .iter()
                .all(|aggregate| self.verify_aggregate_cached(aggregate))
    }

    // ── Persistence ────────────────────────────────────────────────────────

    fn persist(&self, key: Vec<u8>, value: Vec<u8>) {
        let result = self.backend.begin_write().and_then(|mut batch| {
            batch.put_batch(Table::Metadata, vec![(key, value)])?;
            batch.commit()
        });
        let _ = result.inspect_err(|err| error!(%err, "Failed to persist decoupled state"));
    }

    fn persist_block(&self, block: &SignedDecoupledBlock, root: H256) {
        let key = [BLOCK_KEY_PREFIX, root.0.as_slice()].concat();
        self.persist(key, block.to_ssz());
    }

    fn persist_signing(&self, validator: u64) {
        let Some(state) = self.signing.get(&validator) else {
            return;
        };
        let key = [RECORD_KEY_PREFIX, validator.to_le_bytes().as_slice()].concat();
        match serde_json::to_vec(state) {
            Ok(value) => self.persist(key, value),
            Err(err) => error!(%err, validator, "Failed to encode signing state"),
        }
    }

    /// Load the signing records and replay the persisted blocks, oldest slot
    /// first, into a store whose clock is now.
    fn restore(&mut self) {
        let Ok(view) = self.backend.begin_read() else {
            return;
        };
        for &validator in &self.ours {
            let key = [RECORD_KEY_PREFIX, validator.to_le_bytes().as_slice()].concat();
            if let Ok(Some(bytes)) = view.get(Table::Metadata, &key)
                && let Ok(state) = serde_json::from_slice::<SigningState>(&bytes)
            {
                self.signing.insert(validator, state);
            }
        }
        let mut blocks: Vec<SignedDecoupledBlock> =
            match view.prefix_iterator(Table::Metadata, BLOCK_KEY_PREFIX) {
                Ok(entries) => entries
                    .filter_map(Result::ok)
                    .filter_map(|(_, value)| SignedDecoupledBlock::from_ssz_bytes(&value).ok())
                    .collect(),
                Err(_) => Vec::new(),
            };
        drop(view);
        if blocks.is_empty() {
            return;
        }
        blocks.sort_by_key(|block| block.message.slot);
        if let Some(now) = self.now_tick() {
            self.engine.advance_to(now);
        }
        let count = blocks.len();
        for block in blocks {
            let root = block.message.hash_tree_root();
            self.import(block, root);
        }
        info!(
            replayed = count,
            finalized_slot = self.engine.finalized().slot,
            "Replayed persisted decoupled blocks"
        );
    }

    // ── Status ─────────────────────────────────────────────────────────────

    fn publish_status(&self) {
        let engine = &self.engine;
        let head_root = engine.head();
        let (justified, justified_height) = engine.justified();
        let frame = engine.frame();
        let status = DecoupledStatus {
            slot: engine.current_slot(),
            head: engine.block_ref(&head_root).unwrap_or(BlockRef {
                root: head_root,
                slot: 0,
            }),
            confirmed: engine.confirmed(),
            source: engine.source().and_then(|root| engine.block_ref(&root)),
            locks: engine.locks(),
            finalized: engine.finalized(),
            finalized_height: engine.finalized_height(),
            justified,
            justified_height,
            max_height: engine.max_height(),
            fc_root: engine.block_ref(&frame.root).unwrap_or_default(),
            height_floor: frame.floor,
            blocks: engine.blocks().count() as u64,
        };
        *self
            .status
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(status);
    }
}

/// The engine's view of a block: votes and support from the body, and one
/// unsigned attestation per participant of each aggregate, first occurrence
/// kept.
fn block_input(block: &SignedDecoupledBlock, root: H256) -> BlockInput {
    let body = &block.message.body;
    let votes: Vec<GoldfishVote> = body.votes.iter().map(|signed| signed.vote).collect();
    let support_votes = votes
        .iter()
        .enumerate()
        .filter(|(i, _)| body.support.get(*i) == Some(true))
        .map(|(_, vote)| *vote)
        .collect();
    BlockInput {
        root,
        parent_root: block.message.parent_root,
        slot: block.message.slot,
        proposer: block.message.proposer_index,
        votes,
        support_votes,
        attestations: expand(body.attestations.iter()),
    }
}

/// One attestation per participant of each aggregate, first occurrence kept.
fn expand<'a>(
    aggregates: impl Iterator<Item = &'a AggregatedDecoupledAttestation>,
) -> Vec<Attestation> {
    let mut seen = HashSet::new();
    aggregates
        .flat_map(AggregatedDecoupledAttestation::attestations)
        .filter(|attestation| seen.insert(attestation.clone()))
        .collect()
}

fn xmss_valid(
    pubkey: Option<&ValidatorPublicKey>,
    epoch: u64,
    root: H256,
    signature: &XmssSignature,
) -> bool {
    let Some(pubkey) = pubkey else {
        return false;
    };
    let Ok(epoch) = u32::try_from(epoch) else {
        return false;
    };
    ValidatorSignature::from_bytes(&signature.to_ssz())
        .is_ok_and(|signature| signature.is_valid(pubkey, epoch, &root))
}

/// The root of a lean decoupled chain's genesis block for a genesis state.
pub fn genesis_root(genesis_state_root: H256) -> H256 {
    DecoupledBlock::genesis(genesis_state_root).hash_tree_root()
}

/// Every decoupled block the store's backend holds, unordered. For tests and
/// tooling.
pub fn persisted_block_count(backend: &dyn StorageBackend) -> usize {
    backend
        .begin_read()
        .and_then(|view| {
            Ok(view
                .prefix_iterator(Table::Metadata, BLOCK_KEY_PREFIX)?
                .filter(Result::is_ok)
                .count())
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn the_signing_epochs_never_collide() {
        let mut epochs = HashSet::new();
        for slot in 0..200 {
            assert!(epochs.insert(goldfish_vote_epoch(slot)));
            assert!(epochs.insert(attestation_epoch(slot)));
        }
    }
}
