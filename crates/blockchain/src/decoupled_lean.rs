//! The chain actor of a lean node running the decoupled consensus protocol.
//!
//! It owns the protocol engine (`ethlambda_decoupled::Store`), this node's
//! validator keys and anti-slashing records, and the signatures that back
//! every object the engine holds. It ticks on the protocol's public grid
//! (`Δ = slot / 4`), runs the duties each tick asks for, and imports blocks,
//! Goldfish votes and combined attestations from the decoupled topics.
//!
//! Lean specifics, on top of the engine:
//!
//! * every validator weighs one, the slot-`s` committee is every validator,
//!   and the proposer of slot `s` is `s mod n`, as on 3SF-mini lean;
//! * signatures are individual XMSS signatures (see
//!   `ethlambda_types::lean_decoupled` for the epoch grid);
//! * imported blocks and the anti-slashing records are persisted under
//!   prefixed `Metadata` keys and replayed on restart. A replayed node is a
//!   node that joins (`§6.2`): its saved grades start empty.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ethlambda_crypto::signature::{ValidatorPublicKey, ValidatorSignature};
use ethlambda_decoupled::{BlockError, BlockInput, Electorate, Params, Record, Store as Engine};
use ethlambda_network_api::{
    DecoupledToP2PRef, InitDecoupledP2P, SharedDecoupledBlocks,
    p2p_to_decoupled::{NewDecoupledAttestation, NewDecoupledBlock, NewDecoupledVote},
};
use ethlambda_storage::{StorageBackend, Table};
use ethlambda_types::ShortRoot;
use ethlambda_types::attestation::XmssSignature;
use ethlambda_types::decoupled::{
    Attestation, BlockRef, DecoupledStatus, GoldfishVote, SharedDecoupledStatus,
};
use ethlambda_types::lean_decoupled::{
    DecoupledBlock, DecoupledBlockBody, SignedDecoupledAttestation, SignedDecoupledBlock,
    SignedGoldfishVote, attestation_epoch, goldfish_vote_epoch,
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
const BLOCK_KEY_PREFIX: &[u8] = b"decoupled/block/";
/// `Metadata` key prefix of a validator's persisted record, followed by its
/// index (little-endian).
const RECORD_KEY_PREFIX: &[u8] = b"decoupled/record/";

/// Blocks held while their parent is missing, at most. Past it the oldest
/// parent's children are dropped: they can be fetched again.
const MAX_PARKED_BLOCKS: usize = 1024;

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

/// One validator's persisted signing state: its anti-slashing record, and
/// the last slot it voted in and round it attested in, so a restart inside a
/// slot never signs a second message at one XMSS epoch.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SigningState {
    record: Record,
    last_vote_slot: Option<u64>,
    last_round: Option<u64>,
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
        let engine = Engine::from_genesis(
            config.params,
            Electorate::uniform(validator_count),
            config.genesis_root,
        );
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
            signing: HashMap::new(),
            vote_signatures: HashMap::new(),
            attestation_signatures: HashMap::new(),
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
    signing: HashMap<u64, SigningState>,
    /// The signature behind every vote and attestation the engine may put in
    /// a proposal.
    vote_signatures: HashMap<GoldfishVote, XmssSignature>,
    attestation_signatures: HashMap<Attestation, XmssSignature>,
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
            if event.vote {
                self.vote(event.slot);
                self.warm_keys(event.slot + 1);
            }
            if let Some(round) = event.attest {
                self.attest(round);
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
        let attestations: Vec<SignedDecoupledAttestation> = proposal
            .attestations
            .iter()
            .filter_map(|attestation| {
                let signature = self.attestation_signatures.get(attestation)?;
                Some(SignedDecoupledAttestation {
                    attestation: attestation.clone(),
                    signature: signature.clone(),
                })
            })
            .collect();
        let body = DecoupledBlockBody {
            votes: SszList::try_from(votes).expect("at most two votes per validator"),
            support: SszBitlist::try_from(support).expect("one bit per vote"),
            attestations: SszList::try_from(attestations).expect("bounded by the SG window"),
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

    /// `goldfish_vote` at `t_s + Δ`: every one of this node's validators is
    /// in the committee.
    fn vote(&mut self, slot: u64) {
        let head = self.engine.goldfish_vote_head();
        for validator in self.ours.clone() {
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

    /// `attest` at `a_r`: every validator, through its own record.
    fn attest(&mut self, round: u64) {
        let input = self.engine.attestation_input();
        let opening = self.config.params.opening_slot(round);
        for validator in self.ours.clone() {
            let state = self.signing.entry(validator).or_default();
            if state.last_round.is_some_and(|last| last >= round) {
                continue;
            }
            let attestation = state.record.create_attestation(validator, &input);
            state.last_round = Some(round);
            self.persist_signing(validator);
            let epoch = attestation_epoch(opening) as u32;
            let root = attestation.hash_tree_root();
            let signature = match self.keys.sign_attestation_message(validator, epoch, &root) {
                Ok(signature) => signature,
                Err(err) => {
                    error!(round, validator, %err, "Failed to sign combined attestation");
                    continue;
                }
            };
            self.engine.on_sg_vote(attestation.clone());
            self.attestation_signatures
                .insert(attestation.clone(), signature.clone());
            if let Some(p2p) = &self.p2p {
                let _ = p2p
                    .publish_decoupled_attestation(SignedDecoupledAttestation {
                        attestation,
                        signature,
                    })
                    .inspect_err(|err| error!(%err, "Failed to publish combined attestation"));
            }
        }
        info!(
            round,
            safe = %ShortRoot(&input.safe.0),
            source_height = input.source.map(|s| s.height),
            justified_height = input.justified_height,
            finalized_height = input.finalized_height,
            "Attested"
        );
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

    fn on_attestation(&mut self, signed: SignedDecoupledAttestation) {
        if !self.verify_attestation(&signed) {
            debug!(
                round = signed.attestation.data.round,
                validator = signed.attestation.validator,
                "Invalid combined attestation"
            );
            return;
        }
        let attestation = signed.attestation;
        if self.engine.on_sg_vote(attestation.clone()) {
            self.attestation_signatures
                .insert(attestation, signed.signature);
        }
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
        for signed in block.message.body.attestations.iter() {
            self.attestation_signatures
                .insert(signed.attestation.clone(), signed.signature.clone());
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
        let round = self.engine.current_round();
        let oldest_round = round.saturating_sub(self.config.params.eta_sg);
        self.attestation_signatures
            .retain(|attestation, _| attestation.round() >= oldest_round);
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

    fn verify_vote(&mut self, signed: &SignedGoldfishVote) -> bool {
        let vote = signed.vote;
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

    fn verify_attestation(&mut self, signed: &SignedDecoupledAttestation) -> bool {
        let attestation = &signed.attestation;
        let opening = self.config.params.opening_slot(attestation.round());
        let pubkey = self
            .pubkeys
            .get(attestation.validator as usize)
            .map(|keys| keys.0.clone());
        self.check(
            pubkey.as_ref(),
            attestation_epoch(opening),
            attestation.hash_tree_root(),
            opening,
            &signed.signature,
        )
    }

    /// The proposer schedule, the proposer's signature, and every carried
    /// vote's and attestation's signature.
    fn verify_block(&mut self, block: &SignedDecoupledBlock, root: H256) -> bool {
        let message = &block.message;
        if message.proposer_index != self.proposer_of(message.slot) {
            return false;
        }
        if message.body.support.len() != message.body.votes.len() {
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
        let status = DecoupledStatus {
            slot: engine.current_slot(),
            round: engine.current_round(),
            head: engine.block_ref(&head_root).unwrap_or(BlockRef {
                root: head_root,
                slot: 0,
            }),
            confirmed: engine.confirmed(),
            stable: engine.stable(),
            finalized: engine.finalized(),
            finalized_height: engine.finalized_height(),
            justified,
            justified_height,
            max_height: engine.max_height(),
            live_confirmed: engine.live_confirmed(),
            blocks: engine.blocks().count() as u64,
        };
        *self
            .status
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(status);
    }
}

/// The engine's view of a block: votes and support from the body, the
/// attestations unsigned.
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
        attestations: body
            .attestations
            .iter()
            .map(|signed| signed.attestation.clone())
            .collect(),
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
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn the_signing_epochs_never_collide() {
        let mut epochs = HashSet::new();
        let params = Params::with_round_length(3);
        for slot in 0..200 {
            assert!(epochs.insert(goldfish_vote_epoch(slot)));
        }
        for round in 0..60 {
            assert!(epochs.insert(attestation_epoch(params.opening_slot(round))));
        }
    }
}
