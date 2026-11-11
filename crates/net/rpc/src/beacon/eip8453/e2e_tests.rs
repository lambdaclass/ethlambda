//! `ethlambda validator`'s EIP-8453 duties against this node's Beacon API,
//! end to end: a beacon chain actor (an unspawned `BlockChainServer` driven on
//! a simulated clock, as the in-process EIP-8453 network test drives its
//! nodes) serves its store and its fork choice node over HTTP, and the
//! validator client's own HTTP client, duty schedule and services, holding
//! every key, fetch their duties, cast every head vote and FG attestation
//! through the endpoints, and the finality gadget finalizes.
//!
//! Blocks are built by the harness from the node's own proposal, as the
//! network test builds them (through `Eip8453Node::proposal` and the pooled
//! attestations the validator client submitted), and imported through the
//! actor's import path. `produceBlockV4` through the validator client is
//! covered by [`the_validator_client_proposes_an_eip8453_block_through_this_node`].

use std::sync::Arc;

use axum::{Extension, Router};
use ethlambda_blockchain::{BlockChainServer, ImportOutcome};
use ethlambda_network_api::RpcToP2PRef;
use ethlambda_state_transition::beacon::config::Config;
use ethlambda_state_transition::beacon::constants::{
    BUILDER_INDEX_SELF_BUILD, DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO,
    SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY,
};
use ethlambda_state_transition::beacon::containers::{
    BeaconState, SignedBeaconBlock, eip8453, gloas, heze,
};
use ethlambda_state_transition::beacon::eip8453_block_production::{
    assemble_block, pack_attestations,
};
use ethlambda_state_transition::beacon::eip8453_fork_choice::tick_start_ms;
use ethlambda_state_transition::beacon::fork::ForkName;
use ethlambda_state_transition::beacon::fork_choice;
use ethlambda_state_transition::beacon::helpers::accessors::{
    get_beacon_proposer_index, get_domain, get_randao_mix,
};
use ethlambda_state_transition::beacon::helpers::test_state::{
    secret_key_for, sign_for, with_signing_validators_at,
};
use ethlambda_state_transition::beacon::preset;
use ethlambda_state_transition::beacon::primitives::{
    BlsSignature, Bytes32, DomainType, Epoch, HashTreeRoot as _, Root, Slot, ValidatorIndex,
};
use ethlambda_state_transition::beacon::stf;
use ethlambda_storage::Store;
use ethlambda_storage::backend::InMemoryBackend;
use ethlambda_types::beacon::signing::{compute_epoch_at_slot, compute_signing_root};
use ethlambda_validator::{
    beacon_node::http::HttpBeaconNode,
    duties::DutiesService,
    eip8453::{FgAttestationService, HeadVoteService},
    finality_record::FinalitySigningRecords,
    keys::ValidatorStore,
    signing::SigningContext,
};
use tokio::sync::RwLock;

use super::NodeClock;
use crate::test_utils::RecordingNetwork;

const GENESIS_TIME: u64 = 1_000_000;
const VALIDATORS: usize = 32;

/// Every fork through heze at genesis, EIP-8453 too: the genesis is the heze
/// genesis upgraded through the fork.
fn config() -> Config {
    let mut config = Config::active();
    for fork in ForkName::ALL {
        if fork != ForkName::Phase0 && fork <= ForkName::Eip8453 {
            config = config.with_fork_epoch(fork, 0);
        }
    }
    config.genesis_time = GENESIS_TIME;
    config
}

fn sign(
    state: &BeaconState,
    validator: ValidatorIndex,
    root: Root,
    domain_type: DomainType,
    epoch: Epoch,
) -> BlsSignature {
    let domain = get_domain(state, domain_type, Some(epoch));
    sign_for(validator as usize, compute_signing_root(root, domain))
}

/// The in-process network test's genesis, upgraded at epoch 0: a heze state
/// with `VALIDATORS` keyed validators at the largest effective balance and
/// their keys holding the sync committees, then `upgrade_to_eip8453`.
fn genesis(config: &Config) -> (BeaconState, SignedBeaconBlock) {
    let mut state = with_signing_validators_at(ForkName::Heze, VALIDATORS);
    *state.slot_mut() = 0;
    *state.genesis_time_mut() = GENESIS_TIME;
    for index in 0..VALIDATORS as u64 {
        state.validator_mut(index).unwrap().effective_balance =
            preset::MAX_EFFECTIVE_BALANCE_ELECTRA;
        *state.balance_mut(index).unwrap() = preset::MAX_EFFECTIVE_BALANCE_ELECTRA;
    }
    let pubkeys: Vec<_> = state.iter_validators().map(|v| v.pubkey).collect();
    let BeaconState::Heze(inner) = &mut state else {
        unreachable!("a heze state")
    };
    for (seat, pubkey) in inner.current_sync_committee.pubkeys.iter_mut().enumerate() {
        *pubkey = pubkeys[seat % pubkeys.len()];
    }
    inner.next_sync_committee = inner.current_sync_committee.clone();
    inner.latest_execution_payload_bid.block_hash = Bytes32::repeat_byte(0xaa);
    let mut state = ethlambda_state_transition::beacon::upgrade::upgrade_to_eip8453(&state, config)
        .expect("a heze genesis upgrades");
    let BeaconState::Eip8453(inner) = &mut state else {
        unreachable!("an EIP-8453 state")
    };
    let mut body = eip8453::BeaconBlockBody::empty();
    body.signed_execution_payload_bid.message = inner.latest_execution_payload_bid.clone();
    inner.latest_block_header.body_root = body.hash_tree_root();
    state.apply_pending_mutations();
    let block = SignedBeaconBlock::Eip8453(eip8453::SignedBeaconBlock {
        message: eip8453::BeaconBlock {
            slot: 0,
            proposer_index: 0,
            parent_root: Root::ZERO,
            state_root: state.hash_tree_root(),
            body,
        },
        signature: Default::default(),
    });
    (state, block)
}

/// A self-built bid for `slot` on the EMPTY branch of `parent_root`.
fn self_built_bid(
    state: &BeaconState,
    slot: Slot,
    parent_root: Root,
) -> gloas::SignedExecutionPayloadBid {
    let mut bid = gloas::SignedExecutionPayloadBid::default();
    bid.message.builder_index = BUILDER_INDEX_SELF_BUILD;
    bid.message.slot = slot;
    bid.message.parent_block_hash = *state.latest_block_hash().unwrap();
    bid.message.block_hash = Bytes32::repeat_byte((slot % 200) as u8 + 1);
    bid.message.parent_block_root = parent_root;
    bid.message.prev_randao = get_randao_mix(state, compute_epoch_at_slot(slot));
    bid.message.inclusion_list_bits = Some(heze::InclusionListBits::new());
    bid.signature = BlsSignature(ethlambda_state_transition::beacon::bls::G2_POINT_AT_INFINITY);
    bid
}

/// The node, its HTTP surface, and a validator client holding every key.
struct World {
    config: Config,
    server: BlockChainServer,
    store: Store,
    clock: NodeClock,
    network: Arc<RecordingNetwork>,
    client: Arc<HttpBeaconNode>,
    context: Arc<SigningContext>,
    keys: RwLock<ValidatorStore>,
    duties: DutiesService<HttpBeaconNode>,
    head_votes: HeadVoteService<HttpBeaconNode>,
    fg_attestations: FgAttestationService<HttpBeaconNode>,
    _records: tempfile::TempDir,
}

impl World {
    async fn new() -> Self {
        Self::with_engine(None).await
    }

    /// With `engine` as the node's execution client, for block production.
    async fn with_engine(engine: Option<ethlambda_engine::EngineClient>) -> Self {
        use ethlambda_state_transition::beacon::{
            builder_market::SharedBuilderMarket,
            payload_attestation_pool::SharedPayloadAttestationPool,
            sync_committee_pool::SharedSyncCommitteePool,
        };
        let config = config();
        let (state, block) = genesis(&config);
        let store = fork_choice::get_forkchoice_store(
            Arc::new(InMemoryBackend::new()),
            state.clone(),
            block,
            &config,
        )
        .expect("the genesis anchors a store");
        let server =
            BlockChainServer::for_replay(store.clone(), None, SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY);
        let clock = NodeClock::fixed(tick_start_ms(&config, 0));

        let network = Arc::new(RecordingNetwork::default());
        let p2p: RpcToP2PRef = network.clone();
        let own_version = ethlambda_engine::types::ClientVersionV1 {
            code: "LA".to_string(),
            name: "ethlambda".to_string(),
            version: "ethlambda/test".to_string(),
            commit: "0x3c4d7e8f".to_string(),
        };
        let synced = ethlambda_blockchain::SyncStatusController::new(
            ethlambda_blockchain::metrics::SyncStatus::Synced,
        );
        let router: Router = crate::build_beacon_api_router(store.clone(), "test", "peer".into())
            .layer(Extension(server.eip8453_node()))
            .layer(Extension(p2p))
            .layer(Extension(clock.clone()))
            .layer(Extension(engine))
            .layer(Extension(synced))
            .layer(Extension(SharedSyncCommitteePool::default()))
            .layer(Extension(SharedPayloadAttestationPool::default()))
            .layer(Extension(SharedBuilderMarket::default()))
            .layer(Extension(crate::CustodyColumns::default()))
            .layer(Extension(crate::beacon::validator::FeeRecipients::default()))
            .layer(Extension(crate::beacon::graffiti::OwnVersion(Arc::new(
                own_version,
            ))));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await });
        let client = Arc::new(HttpBeaconNode::new(format!("http://{address}")).unwrap());

        let mut keys = ValidatorStore::new();
        for index in 0..VALIDATORS {
            keys.insert_secret("test", &secret_key_for(index).to_bytes())
                .expect("the test secret is a valid key");
        }
        let context = Arc::new(SigningContext {
            config: config.clone(),
            genesis_validators_root: state.genesis_validators_root(),
        });
        let records = tempfile::tempdir().unwrap();
        let mut duties = DutiesService::new(client.clone(), Vec::new()).with_eip8453_fork_epoch(0);
        duties.set_indices((0..VALIDATORS as u64).collect());
        Self {
            head_votes: HeadVoteService::new(client.clone(), context.clone()),
            fg_attestations: FgAttestationService::new(
                client.clone(),
                context.clone(),
                Arc::new(FinalitySigningRecords::in_validators_dir(records.path())),
            ),
            config,
            server,
            store,
            clock,
            network,
            client,
            context,
            keys: RwLock::new(keys),
            duties,
            _records: records,
        }
    }

    fn time(&self, slot: Slot, quarter: u64) -> u64 {
        tick_start_ms(&self.config, (4 * slot + quarter) as i64)
    }

    /// The node's tick at `quarter` of `slot`, and the API's clock with it.
    async fn tick(&mut self, slot: Slot, quarter: u64) {
        let now = self.time(slot, quarter);
        self.clock.set(now);
        self.server.tick_at(now).await;
    }

    /// The slot's block, built on the node's proposal and the attestations
    /// the validator client submitted, imported through the actor.
    async fn propose(&mut self, slot: Slot) {
        let now = self.time(slot, 0);
        let node = self.server.eip8453_node();
        let (proposal, pool) = node
            .with(|n| {
                let proposal = n.proposal(slot, now).expect("the slot's proposal");
                let pool: Vec<eip8453::SingleAttestation> =
                    n.all_pooled_attestations().cloned().collect();
                (proposal, pool)
            })
            .expect("the fork choice runs");
        let parent_state = self
            .store
            .get_state(&proposal.head.root)
            .unwrap()
            .expect("the proposal's parent has a state");
        let mut state = (*parent_state).clone();
        stf::process_slots(&mut state, slot, &self.config).unwrap();
        let epoch = compute_epoch_at_slot(slot);
        let proposer = get_beacon_proposer_index(&state).unwrap();
        let randao = sign(
            &state,
            proposer,
            epoch.hash_tree_root(),
            DOMAIN_RANDAO,
            epoch,
        );
        let bid = self_built_bid(&state, slot, proposal.head.root);
        let attestations = pack_attestations(&state, pool.iter());
        let (block, _) = assemble_block(
            &state,
            proposal.head.root,
            slot,
            randao,
            bid,
            proposal.head_votes,
            proposal.head_vote_support,
            attestations,
            &self.config,
        )
        .unwrap();
        let signature = sign(
            &state,
            proposer,
            block.hash_tree_root(),
            DOMAIN_BEACON_PROPOSER,
            epoch,
        );
        let signed = SignedBeaconBlock::Eip8453(eip8453::SignedBeaconBlock {
            message: block,
            signature,
        });
        let outcome = self.server.import_block(signed).await;
        assert_eq!(
            outcome,
            Some(ImportOutcome::Imported),
            "slot {slot}'s block"
        );
    }

    /// One slot: the block at its start, the head votes at its head vote
    /// deadline and the FG attestations at its support cutoff, both through
    /// the validator client.
    async fn run_slot(&mut self, slot: Slot) -> (usize, usize) {
        let epoch = compute_epoch_at_slot(slot);
        if slot % preset::SLOTS_PER_EPOCH == 1 || slot == 1 {
            for target in [epoch, epoch + 1] {
                self.duties
                    .refresh_attestation_committees(target)
                    .await
                    .expect("attestation committee duties");
                self.duties
                    .refresh_head_votes(target)
                    .await
                    .expect("head vote duties");
            }
        }
        self.tick(slot, 0).await;
        self.propose(slot).await;

        self.tick(slot, 1).await;
        let voters = self.duties.head_votes_at_slot(slot, epoch);
        let votes = self
            .head_votes
            .vote(slot, &voters, &self.keys)
            .await
            .expect("head votes through the API");

        self.tick(slot, 2).await;
        let attesters = self.duties.attestation_committees_at_slot(slot, epoch);
        let attestations = self
            .fg_attestations
            .attest(slot, &attesters, &self.keys)
            .await
            .expect("FG attestations through the API");

        self.tick(slot, 3).await;
        (votes, attestations)
    }
}

/// The validator client, through nothing but this node's HTTP API, keeps an
/// EIP-8453 chain finalizing: every head vote committee member votes every
/// slot, every attester attests in its committee's slot each round through
/// its persisted signing record, and the gadget finalizes heights.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_validator_client_keeps_an_eip8453_chain_finalizing_through_this_node() {
    let mut world = World::new().await;
    let end = 5 * preset::SLOTS_PER_ROUND;
    let mut votes = 0;
    let mut attestations = 0;
    for slot in 1..=end {
        let (slot_votes, slot_attestations) = world.run_slot(slot).await;
        assert!(slot_votes > 0, "slot {slot}: some committee member voted");
        votes += slot_votes;
        attestations += slot_attestations;
    }
    // Every validator attests once a round, once the gadget has a source.
    assert!(
        attestations >= 3 * VALIDATORS,
        "attestations: {attestations}"
    );
    assert!(votes >= end as usize * VALIDATORS / 2, "votes: {votes}");
    let finalized = world
        .store
        .fg_finalized_checkpoint()
        .expect("the gadget recorded");
    assert!(finalized.height >= 2, "the gadget finalized: {finalized:?}");
    // The node reports it on the Beacon API as well.
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;
    let request = axum::http::Request::get("/eth/v1/beacon/states/head/finality_checkpoints")
        .body(axum::body::Body::empty())
        .unwrap();
    let router = crate::beacon::states::routes().with_state(world.store.clone());
    let body = router.oneshot(request).await.unwrap().into_body();
    let body = body.collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let reported: u64 = response["data"]["finalized"]["height"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(reported >= 2, "{response}");
}

/// The validator client proposes an EIP-8453 block through `produceBlockV4`:
/// the node builds on its fork choice's proposal with its execution client,
/// the client signs the block and publishes it, the node imports it, and the
/// client's envelope, signed under the builder domain, is accepted and
/// gossiped with the block's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_validator_client_proposes_an_eip8453_block_through_this_node() {
    use ethlambda_validator::beacon_node::{BeaconNodeApi as _, Published};
    use ethlambda_validator::proposal::ProposalService;
    use ethlambda_validator::proposer_settings::ProposerSettings;

    let engine = super::tests::fake_engine().await;
    let mut world = World::with_engine(Some(engine)).await;
    // A slot of head votes first, so the proposal carries some.
    world.run_slot(1).await;
    let slot = 2;
    world.tick(slot, 0).await;

    let duties = world
        .client
        .proposer_duties(0)
        .await
        .expect("proposer duties");
    let duty = duties
        .duties
        .into_iter()
        .find(|duty| duty.slot == slot)
        .expect("the lookahead names the slot's proposer");
    let settings = ProposerSettings::new(Default::default(), None);
    let proposal = ProposalService::new(
        world.client.clone(),
        world.context.clone(),
        Arc::new(settings),
    );

    // The node imports what the client publishes, as its chain actor would,
    // while the client goes on to publish the envelope, which waits for it.
    let network = world.network.clone();
    let server = &mut world.server;
    let import = async {
        loop {
            let published = network.blocks.lock().unwrap().first().cloned();
            if let Some(block) = published {
                return server.import_block(block).await;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    };
    let (proposed, imported) = tokio::join!(proposal.propose(slot, &duty, &world.keys), import);
    assert!(
        matches!(
            proposed,
            Ok(Published::Imported | Published::BroadcastNotImported)
        ),
        "{proposed:?}"
    );
    assert_eq!(imported, Some(ImportOutcome::Imported));

    let blocks = world.network.blocks.lock().unwrap().clone();
    let SignedBeaconBlock::Eip8453(block) = &blocks[0] else {
        panic!("an EIP-8453 block")
    };
    assert_eq!(block.message.slot, slot);
    assert!(
        !block.message.body.head_votes.is_empty(),
        "the previous slot's head votes"
    );
    let envelopes = world.network.envelopes.lock().unwrap().clone();
    assert_eq!(envelopes.len(), 1, "the envelope was accepted and gossiped");
    assert_eq!(
        envelopes[0].0.message.beacon_block_root,
        block.message.hash_tree_root()
    );
    assert_eq!(
        world.store.head().unwrap(),
        block.message.hash_tree_root(),
        "the proposed block is the head"
    );
}
