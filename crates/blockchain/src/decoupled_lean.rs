//! The chain actor of a lean node running the decoupled consensus (EIP-8453)
//! protocol.
//!
//! It owns the fork choice engine (`ethlambda_decoupled::Store`), the finality
//! gadget chain state of every held block, this node's validator keys and
//! finality signing records, and the signatures that back every object it may
//! put in a block. It ticks on the protocol's public grid (`Δ = slot / 4`),
//! runs the duties each tick asks for, and imports blocks, head votes and FG
//! attestations from the decoupled topics.
//!
//! Lean specifics, on top of the engine:
//!
//! * every validator weighs one in finality gadget quorums, holds one seat in
//!   every slot's head vote committee, and attests once per round in slot
//!   `v mod SLOTS_PER_ROUND` of the round; the proposer of slot `s` is
//!   `s mod n`, as on 3SF-mini lean;
//! * there are no execution payloads: every block builds on its parent's
//!   `Empty` branch;
//! * signatures are individual XMSS signatures (see
//!   `ethlambda_types::lean_decoupled` for the epoch grid);
//! * gossip keeps the first head vote of a validator per slot and the first
//!   FG attestation per round (p2p-interface.md), so equivocations reach the
//!   fork choice only through blocks;
//! * imported blocks and the signing records are persisted under prefixed
//!   `Metadata` keys and replayed on restart. A replayed node is a node that
//!   joins: its locks and saved confirmations start empty.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ethlambda_crypto::signature::{ValidatorPublicKey, ValidatorSignature};
use ethlambda_decoupled::{
    Anchor, BlockError, BlockInput, ChainState, ChainStates, Electorate, FinalitySigningRecord,
    HeadVote, HeadVoteCommittees, HeadVoteMessage, Params, PayloadStatus, Store as Engine,
    chain_state::{ChainStateError, select_attestations},
    head_vote_data,
};
use ethlambda_network_api::{
    DecoupledToP2PRef, InitDecoupledP2P, SharedDecoupledBlocks,
    p2p_to_decoupled::{NewDecoupledAttestation, NewDecoupledBlock, NewDecoupledVote},
};
use ethlambda_storage::{StorageBackend, Table};
use ethlambda_types::ShortRoot;
use ethlambda_types::attestation::XmssSignature;
use ethlambda_types::decoupled::{BlockRef, DecoupledStatus, SharedDecoupledStatus};
use ethlambda_types::lean_decoupled::{
    DecoupledBlock, DecoupledBlockBody, FinalityAttestation, SignedDecoupledBlock,
    SignedFinalityAttestation, SignedHeadVote, attestation_epoch, attestation_slot,
    head_vote_epoch,
};
use ethlambda_types::primitives::{H256, HashTreeRoot as _};
use ethlambda_types::time::unix_now_ms;
use libssz::{SszDecode, SszEncode};
use libssz_types::{SszBitlist, SszList};
use serde::{Deserialize, Serialize};
use spawned_concurrency::actor;
use spawned_concurrency::error::ActorError;
use spawned_concurrency::protocol;
use spawned_concurrency::tasks::{
    Actor, ActorRef, ActorStart, Backend, Context, Handler, send_after,
};
use tracing::{debug, error, info, warn};

use crate::key_manager::{KeyManager, ValidatorKeyPair};

/// `Metadata` key prefix of a persisted block, followed by its root.
const BLOCK_KEY_PREFIX: &[u8] = b"decoupled/eip8453/block/";
/// `Metadata` key prefix of a validator's persisted signing state, followed by
/// its index (little-endian).
const RECORD_KEY_PREFIX: &[u8] = b"decoupled/eip8453/record/";

/// Blocks held while their parent is missing, at most. Past it the oldest
/// parent's children are dropped: they can be fetched again.
const MAX_PARKED_BLOCKS: usize = 1024;

/// FG attestations held for proposals, at most.
const MAX_POOLED_ATTESTATIONS: usize = 16384;

/// How long a by-root lookup is left alone before it is asked again.
const REFETCH_AFTER: Duration = Duration::from_secs(4);

/// What a lean decoupled chain is: its constants and its validator set.
pub struct DecoupledLeanConfig {
    pub params: Params,
    pub genesis_time_ms: u64,
    pub slot_duration_ms: u64,
    /// The decoupled genesis block (`DecoupledBlock::genesis`).
    pub genesis_root: H256,
    /// `(attestation_pubkey, proposal_pubkey)` of every validator, by index.
    pub validators: Vec<(Vec<u8>, Vec<u8>)>,
}

impl DecoupledLeanConfig {
    /// `Δ`, in milliseconds.
    fn delta_ms(&self) -> u64 {
        self.slot_duration_ms / 4
    }
}

/// One validator's persisted signing state: its finality signing record, and
/// the last slot it voted in and round it attested in, so a restart inside a
/// slot never signs a second message at one XMSS epoch.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SigningState {
    record: FinalitySigningRecord,
    last_vote_slot: Option<u64>,
    last_attest_round: Option<u64>,
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
        let pubkeys = config
            .validators
            .iter()
            .map(|(attestation, proposal)| {
                (
                    ValidatorPublicKey::from_bytes(attestation).expect("valid attestation pubkey"),
                    ValidatorPublicKey::from_bytes(proposal).expect("valid proposal pubkey"),
                )
            })
            .collect();
        let genesis = BlockRef {
            root: config.genesis_root,
            slot: 0,
        };
        let genesis_state = ChainState::initial(genesis, validator_count);
        let engine = Engine::new(
            config.params,
            HeadVoteCommittees::EveryValidator {
                validator_count: validator_count as u64,
            },
            Anchor {
                root: genesis.root,
                slot: genesis.slot,
                fg: genesis_state.checkpoints(),
            },
        );
        let ours: Vec<u64> = {
            let mut ids: Vec<u64> = validator_keys.keys().copied().collect();
            ids.sort();
            ids
        };
        let mut server = DecoupledLeanServer {
            config,
            engine,
            states: ChainStates::new(genesis, genesis_state),
            electorate: Electorate::uniform(validator_count),
            keys: KeyManager::new(validator_keys),
            ours,
            pubkeys,
            signing: HashMap::new(),
            vote_signatures: HashMap::new(),
            seen_votes: HashSet::new(),
            attestations: BTreeMap::new(),
            seen_attestations: HashSet::new(),
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
    /// The finality gadget chain state of every held block.
    states: ChainStates,
    electorate: Electorate,
    keys: KeyManager,
    /// This node's validators, ascending.
    ours: Vec<u64>,
    /// `(attestation, proposal)` public keys by validator index.
    pubkeys: Vec<(ValidatorPublicKey, ValidatorPublicKey)>,
    signing: HashMap<u64, SigningState>,
    /// The signature behind every pooled head vote, which a proposal carries.
    vote_signatures: HashMap<HeadVoteMessage, XmssSignature>,
    /// `(slot, validator)` of every head vote taken from gossip or cast.
    seen_votes: HashSet<(u64, u64)>,
    /// FG attestations a proposal may carry, with their signatures, by round.
    attestations: BTreeMap<u64, HashMap<FinalityAttestation, XmssSignature>>,
    /// `(round, validator)` of every FG attestation taken from gossip or
    /// cast.
    seen_attestations: HashSet<(u64, u64)>,
    /// Message roots whose signature checked out, with the slot they belong
    /// to, so a vote already verified on gossip is not verified again when a
    /// block carries it.
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
        self.sync_clock();
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
    async fn handle(&mut self, msg: NewDecoupledBlock, _ctx: &Context<Self>) {
        self.sync_clock();
        self.on_block(msg.block);
        self.publish_status();
    }
}

impl Handler<NewDecoupledVote> for DecoupledLeanServer {
    async fn handle(&mut self, msg: NewDecoupledVote, _ctx: &Context<Self>) {
        self.sync_clock();
        self.on_vote(msg.vote);
    }
}

impl Handler<NewDecoupledAttestation> for DecoupledLeanServer {
    async fn handle(&mut self, msg: NewDecoupledAttestation, _ctx: &Context<Self>) {
        self.sync_clock();
        self.on_attestation(msg.attestation);
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
    fn sync_clock(&mut self) {
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
            if event.head_vote {
                self.vote(event.slot);
                self.warm_keys(event.slot + 1);
            }
            if event.support_cutoff {
                self.attest(event.slot);
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
            .prepare_epochs_in_background(head_vote_epoch(slot) as u32, proposal);
    }

    /// The block of slot `slot`, at its start, if one of this node's
    /// validators proposes: on `get_ac_proposal`'s head, carrying its view of
    /// the previous slot's head votes and the pooled FG attestations that add
    /// participation on that head.
    fn propose(&mut self, slot: u64) {
        let proposer = self.proposer_of(slot);
        if !self.ours.contains(&proposer) {
            return;
        }
        let proposal = self.engine.get_ac_proposal();
        let parent_root = proposal.head.root;
        let mut head_votes = Vec::new();
        let mut support = Vec::new();
        for (index, message) in proposal.vote_messages.iter().enumerate() {
            let Some(signature) = self.vote_signatures.get(message) else {
                warn!(
                    slot,
                    validator = message.validator_index,
                    "No signature for a pooled head vote"
                );
                continue;
            };
            head_votes.push(SignedHeadVote {
                message: *message,
                signature: signature.clone(),
            });
            support.push(proposal.support_indices.contains(&index));
        }
        let attestations = self.proposal_attestations(&parent_root);
        let body = DecoupledBlockBody {
            head_votes: SszList::try_from(head_votes).expect("one vote per validator"),
            head_vote_support: SszBitlist::try_from(support).expect("one bit per vote"),
            attestations: SszList::try_from(attestations).expect("bounded by the pool"),
        };
        let message = DecoupledBlock {
            slot,
            proposer_index: proposer,
            parent_root,
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
            parent_root = %ShortRoot(&parent_root.0),
            head_votes = block.message.body.head_votes.len(),
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

    /// The pooled FG attestations `process_attestation` accepts on `head`'s
    /// chain state and that add participation there.
    fn proposal_attestations(&self, head: &H256) -> Vec<SignedFinalityAttestation> {
        let Some(state) = self.states.get(head) else {
            return Vec::new();
        };
        let mut pooled: Vec<(&FinalityAttestation, &XmssSignature)> = self
            .attestations
            .values()
            .flat_map(|round| round.iter())
            .collect();
        pooled.sort_by_key(|(attestation, _)| {
            (
                attestation.round,
                attestation.validator_index,
                attestation.data,
            )
        });
        let candidates: Vec<_> = pooled
            .iter()
            .map(|(attestation, _)| (attestation.validator_index, attestation.data))
            .collect();
        select_attestations(state, &candidates)
            .into_iter()
            .map(|index| {
                let (attestation, signature) = pooled[index];
                SignedFinalityAttestation {
                    message: *attestation,
                    signature: signature.clone(),
                }
            })
            .collect()
    }

    /// The head vote of slot `slot`, at its head vote deadline: every one of
    /// this node's validators sits in the committee.
    fn vote(&mut self, slot: u64) {
        let head = self.engine.get_ac_vote_head();
        let data = head_vote_data(&self.engine, slot, head);
        for validator in self.ours.clone() {
            let state = self.signing.entry(validator).or_default();
            if state.last_vote_slot.is_some_and(|last| last >= slot) {
                continue;
            }
            state.last_vote_slot = Some(slot);
            self.persist_signing(validator);
            let message = HeadVoteMessage {
                validator_index: validator,
                data,
            };
            let epoch = head_vote_epoch(slot) as u32;
            let signature = match self.keys.sign_attestation_message(
                validator,
                epoch,
                &message.hash_tree_root(),
            ) {
                Ok(signature) => signature,
                Err(err) => {
                    error!(slot, validator, %err, "Failed to sign head vote");
                    continue;
                }
            };
            self.seen_votes.insert((slot, validator));
            if let Err(err) = self.engine.on_head_vote_message(message) {
                warn!(slot, validator, %err, "Own head vote refused");
                continue;
            }
            self.vote_signatures.insert(message, signature.clone());
            if let Some(p2p) = &self.p2p {
                let _ = p2p
                    .publish_decoupled_vote(SignedHeadVote { message, signature })
                    .inspect_err(|err| error!(%err, "Failed to publish head vote"));
            }
        }
        debug!(
            slot,
            head = %ShortRoot(&head.root.0),
            payload_status = data.payload_status,
            "Cast head votes"
        );
    }

    /// The FG attestations of the validators whose attestation slot is
    /// `slot`, at its support cutoff, after this tick's confirmation: from one
    /// `get_ac_frame` observation, through each validator's signing record.
    fn attest(&mut self, slot: u64) {
        let params = self.config.params;
        let round = params.round_of(slot);
        let due: Vec<u64> = self
            .ours
            .iter()
            .copied()
            .filter(|&v| attestation_slot(round, v, params.slots_per_round) == slot)
            .filter(|v| {
                self.signing
                    .get(v)
                    .and_then(|state| state.last_attest_round)
                    .is_none_or(|last| last < round)
            })
            .collect();
        if due.is_empty() {
            return;
        }
        let frame = self.engine.get_ac_frame();
        let Some(input) = self.engine.finality_attestation_input(&frame) else {
            info!(slot, round, "No FG source: not attesting");
            return;
        };
        for validator in due {
            let state = self.signing.entry(validator).or_default();
            state.last_attest_round = Some(round);
            let data = state.record.attest(&input);
            // The record and the duty are persisted before signing.
            self.persist_signing(validator);
            let Some(data) = data else {
                debug!(
                    slot,
                    validator, "Signing record suppresses the FG attestation"
                );
                continue;
            };
            let message = FinalityAttestation {
                validator_index: validator,
                round,
                data,
            };
            let epoch = attestation_epoch(slot) as u32;
            let root = message.hash_tree_root();
            let signature = match self.keys.sign_attestation_message(validator, epoch, &root) {
                Ok(signature) => signature,
                Err(err) => {
                    error!(round, validator, %err, "Failed to sign FG attestation");
                    continue;
                }
            };
            self.seen_attestations.insert((round, validator));
            self.pool_attestation(message, signature.clone());
            if let Some(p2p) = &self.p2p {
                let _ = p2p
                    .publish_decoupled_attestation(SignedFinalityAttestation { message, signature })
                    .inspect_err(|err| error!(%err, "Failed to publish FG attestation"));
            }
            info!(
                slot,
                round,
                validator,
                target_height = data.target.height,
                target_root = %ShortRoot(&data.target.root.0),
                timeout = data.timeout,
                finality_height = data.finality.height,
                "Attested"
            );
        }
    }

    // ── Imports ────────────────────────────────────────────────────────────

    /// A gossip head vote: the first of its validator for its slot, with a
    /// valid signature.
    fn on_vote(&mut self, signed: SignedHeadVote) {
        let message = signed.message;
        let key = (message.data.slot, message.validator_index);
        if self.seen_votes.contains(&key) {
            return;
        }
        if !self.verify_vote(&signed) {
            debug!(
                slot = message.data.slot,
                validator = message.validator_index,
                "Invalid head vote"
            );
            return;
        }
        match self.engine.on_head_vote_message(message) {
            Ok(()) => {
                self.seen_votes.insert(key);
                self.vote_signatures.insert(message, signed.signature);
            }
            Err(err) => debug!(
                slot = message.data.slot,
                validator = message.validator_index,
                %err,
                "Head vote refused"
            ),
        }
    }

    /// A gossip FG attestation: the first of its validator for its round, of
    /// a round whose attestation slot has started, with a valid signature.
    fn on_attestation(&mut self, signed: SignedFinalityAttestation) {
        let message = signed.message;
        let key = (message.round, message.validator_index);
        let current = self.engine.current_slot();
        let slot = attestation_slot(
            message.round,
            message.validator_index,
            self.config.params.slots_per_round,
        );
        if self.seen_attestations.contains(&key)
            || slot > current
            || message.round + 1 < self.engine.current_round()
        {
            return;
        }
        if !self.verify_attestation(&signed) {
            debug!(
                round = message.round,
                validator = message.validator_index,
                "Invalid FG attestation"
            );
            return;
        }
        self.seen_attestations.insert(key);
        self.pool_attestation(message, signed.signature);
    }

    fn pool_attestation(&mut self, attestation: FinalityAttestation, signature: XmssSignature) {
        let pooled: usize = self.attestations.values().map(HashMap::len).sum();
        if pooled >= MAX_POOLED_ATTESTATIONS {
            return;
        }
        self.attestations
            .entry(attestation.round)
            .or_default()
            .insert(attestation, signature);
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
        if self.states.get(&parent).is_none() {
            self.park(block);
            self.request(parent);
            return;
        }
        if !self.verify_block(&block, root) {
            warn!(
                slot = block.message.slot,
                block_root = %ShortRoot(&root.0),
                "Dropping decoupled block that fails validation"
            );
            return;
        }
        self.import(block, root);
    }

    /// Derive a checked block's chain state, hand it to the engine, then
    /// everything that was waiting on it.
    fn import(&mut self, block: SignedDecoupledBlock, root: H256) {
        let message = &block.message;
        let at = BlockRef {
            root,
            slot: message.slot,
        };
        let attestations = message
            .body
            .attestations
            .iter()
            .map(|signed| (signed.message.validator_index, &signed.message.data));
        let fg = match self.states.import(
            &message.parent_root,
            at,
            attestations,
            &self.config.params,
            &self.electorate,
        ) {
            Ok(fg) => fg,
            Err(ChainStateError::UnknownParent) => {
                let parent = message.parent_root;
                self.park(block);
                self.request(parent);
                return;
            }
            Err(ChainStateError::Attestation(err)) => {
                warn!(
                    slot = message.slot,
                    block_root = %ShortRoot(&root.0),
                    %err,
                    "Decoupled block carries an invalid FG attestation"
                );
                return;
            }
        };
        let input = block_input(&block, root, fg);
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
        for signed in block.message.body.attestations.iter() {
            self.pool_attestation(signed.message, signed.signature.clone());
        }
        let finalized = self.engine.finalized_checkpoint();
        info!(
            slot = block.message.slot,
            proposer = block.message.proposer_index,
            block_root = %ShortRoot(&root.0),
            parent_root = %ShortRoot(&block.message.parent_root.0),
            head_votes = block.message.body.head_votes.len(),
            attestations = block.message.body.attestations.len(),
            target_height = fg.target.height,
            justified_height = fg.justified.height,
            finalized_height = finalized.height,
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

    /// Drop what no duty or check reads any more.
    fn prune(&mut self) {
        let engine = &self.engine;
        self.states.retain(|root| engine.contains(root));
        let slot = engine.current_slot();
        let oldest_vote_slot = slot.saturating_sub(1);
        self.vote_signatures
            .retain(|message, _| message.data.slot >= oldest_vote_slot);
        self.seen_votes
            .retain(|(vote_slot, _)| *vote_slot >= oldest_vote_slot);
        // An attestation stays includable while its target is the current
        // one or its finality pair is pending; two rounds back is plenty.
        let oldest_round = engine.current_round().saturating_sub(2);
        self.attestations = self.attestations.split_off(&oldest_round);
        self.seen_attestations
            .retain(|(round, _)| *round >= oldest_round);
        let oldest_slot = slot.saturating_sub(4 * self.config.params.slots_per_round);
        self.verified
            .retain(|_, verified_slot| *verified_slot >= oldest_slot);
        self.requested
            .retain(|_, asked| asked.elapsed() < 8 * REFETCH_AFTER);
    }

    // ── Signatures ─────────────────────────────────────────────────────────

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
        let Some(pubkey) = pubkey else {
            return false;
        };
        let Ok(epoch) = u32::try_from(epoch) else {
            return false;
        };
        let valid = ValidatorSignature::from_bytes(&signature.to_ssz())
            .is_ok_and(|signature| signature.is_valid(pubkey, epoch, &root));
        if valid {
            self.verified.insert(root, slot);
        }
        valid
    }

    fn verify_vote(&mut self, signed: &SignedHeadVote) -> bool {
        let message = signed.message;
        let pubkey = self
            .pubkeys
            .get(message.validator_index as usize)
            .map(|keys| keys.0.clone());
        self.check(
            pubkey.as_ref(),
            head_vote_epoch(message.data.slot),
            message.hash_tree_root(),
            message.data.slot,
            &signed.signature,
        )
    }

    fn verify_attestation(&mut self, signed: &SignedFinalityAttestation) -> bool {
        let message = signed.message;
        let slot = attestation_slot(
            message.round,
            message.validator_index,
            self.config.params.slots_per_round,
        );
        let pubkey = self
            .pubkeys
            .get(message.validator_index as usize)
            .map(|keys| keys.0.clone());
        self.check(
            pubkey.as_ref(),
            attestation_epoch(slot),
            message.hash_tree_root(),
            slot,
            &signed.signature,
        )
    }

    /// The lean block rules the engine does not check: the proposer schedule
    /// and signature, head votes of the previous slot with a payload status
    /// and a valid signature, one support bit each, and FG attestations cast
    /// before the block's slot with a valid signature.
    fn verify_block(&mut self, block: &SignedDecoupledBlock, root: H256) -> bool {
        let message = &block.message;
        if message.proposer_index != self.proposer_of(message.slot) {
            return false;
        }
        let body = &message.body;
        if body.head_vote_support.len() != body.head_votes.len() {
            return false;
        }
        let votes_ok = body.head_votes.iter().all(|vote| {
            vote.message.data.slot + 1 == message.slot
                && vote.message.data.payload_status().is_some()
        });
        let slots_per_round = self.config.params.slots_per_round;
        let attestations_ok = body.attestations.iter().all(|attestation| {
            let message_slot = attestation_slot(
                attestation.message.round,
                attestation.message.validator_index,
                slots_per_round,
            );
            message_slot < message.slot
        });
        if !votes_ok || !attestations_ok {
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
        body.head_votes.iter().all(|vote| self.verify_vote(vote))
            && body
                .attestations
                .iter()
                .all(|attestation| self.verify_attestation(attestation))
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

    /// Load the signing states and replay the persisted blocks, oldest slot
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
            finalized_height = self.engine.finalized_checkpoint().height,
            "Replayed persisted decoupled blocks"
        );
    }

    // ── Status ─────────────────────────────────────────────────────────────

    fn publish_status(&self) {
        let engine = &self.engine;
        let block_ref = |root: H256| BlockRef {
            root,
            slot: engine.block_slot(&root).unwrap_or_default(),
        };
        let head = engine.get_head();
        let finalized = engine.finalized_checkpoint();
        let justified = engine.justified_checkpoint();
        let status = DecoupledStatus {
            slot: engine.current_slot(),
            round: engine.current_round(),
            head: block_ref(head.root),
            head_payload_status: head.payload_status,
            confirmed: block_ref(engine.get_confirmed_node().root),
            latest_confirmed: block_ref(engine.latest_confirmed().root),
            finalized,
            finalized_slot: engine.block_slot(&finalized.root).unwrap_or_default(),
            justified,
            justified_slot: engine.block_slot(&justified.root).unwrap_or_default(),
            max_height: engine.max_height(),
            fg_contest: engine.is_fg_contest(),
            live_locks: engine.live_locks().len() as u64,
            blocks: engine.blocks().count() as u64,
        };
        *self
            .status
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(status);
    }
}

/// The engine's view of a block: its head votes (one voter each) with their
/// support bits, on the parent's empty branch, with its chain state's
/// checkpoints.
fn block_input(
    block: &SignedDecoupledBlock,
    root: H256,
    fg: ethlambda_decoupled::FgCheckpoints,
) -> BlockInput {
    let body = &block.message.body;
    let head_votes = body
        .head_votes
        .iter()
        .map(|signed| HeadVote {
            voter_indices: vec![signed.message.validator_index],
            data: signed.message.data,
        })
        .collect();
    let head_vote_support = (0..body.head_votes.len())
        .map(|i| vec![body.head_vote_support.get(i) == Some(true)])
        .collect();
    BlockInput {
        root,
        parent_root: block.message.parent_root,
        slot: block.message.slot,
        parent_payload_status: PayloadStatus::Empty,
        head_votes,
        head_vote_support,
        fg,
    }
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
    use super::*;

    #[test]
    fn a_signing_state_survives_its_json_round_trip() {
        let mut state = SigningState::default();
        state.record.targets.insert(3, H256([1; 32]));
        state.record.timeouts.insert(4);
        state.record.finality_locks.insert(2, H256([2; 32]));
        state
            .record
            .entries
            .entry(3)
            .or_default()
            .insert(H256([1; 32]));
        state.last_vote_slot = Some(9);
        state.last_attest_round = Some(2);
        let bytes = serde_json::to_vec(&state).unwrap();
        let back: SigningState = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.record, state.record);
        assert_eq!(back.last_vote_slot, Some(9));
        assert_eq!(back.last_attest_round, Some(2));
    }
}
