//! The blockchain actor under Spawned's deterministic simulator.
//!
//! A one-node devnet: the node holds every validator, so its own `Tick`
//! timers drive the whole chain (propose at interval 4, attest at 1,
//! aggregate at 2) and the actor imports what it builds. Under
//! `--cfg spawned_sim` the slot clock (`SystemTime`, `Instant`), the
//! actor's timers, the key-warm helper and the aggregation job all run on
//! virtual time in one seeded schedule, so many slots take seconds and a
//! failing seed replays exactly from its decision tape. Aggregation proofs
//! are the Shadow integration's deterministic stubs (`shadow-integration`);
//! everything else (XMSS signing, state transition, fork choice, the actor's
//! timers and mailbox) is the production code:
//!
//! ```sh
//! RUSTFLAGS="--cfg spawned_sim --cfg tokio_unstable" \
//!   cargo test -p ethlambda-blockchain --profile release-fast --lib \
//!   sim_tests -- --nocapture
//! ```
//!
//! `ETHLAMBDA_SIM_PLANT=1` adds a planted failure that names the run's event
//! trace hash, to show a failing seed replaying from its tape
//! (`SPAWNED_SIM_TAPE=...`) with the same trace.
#![cfg(spawned_sim)]

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ethlambda_crypto::signature::ValidatorSecretKey;
use ethlambda_storage::{Store, backend::InMemoryBackend};
use ethlambda_types::aggregator::AggregatorController;
use ethlambda_types::state::{State, Validator};
use spawned_concurrency::system::ActorSystem;
use tokio::sync::broadcast::error::TryRecvError;

use crate::block_builder::ProposerConfig;
use crate::key_manager::{KeyRole, ValidatorKeyPair};
use crate::{
    BlockChain, BlockChainConfig, ChainEvent, DEFAULT_MILLISECONDS_PER_SLOT, EventBus,
    SyncStatusController,
};

const VALIDATORS: u64 = 4;
/// Slots the devnet runs for.
const SLOTS: u64 = 10;

fn key(id: u64, role: KeyRole) -> ValidatorSecretKey {
    let mut seed = [0; 32];
    seed[..8].copy_from_slice(&id.to_le_bytes());
    seed[8] = role as u8;
    ValidatorSecretKey::generate_from_seed(seed, 0..=(SLOTS as u32 + 2)).expect("key range")
}

fn validator_set() -> (HashMap<u64, ValidatorKeyPair>, Vec<Validator>) {
    let mut keys = HashMap::new();
    let mut validators = Vec::new();
    for id in 0..VALIDATORS {
        let pair = ValidatorKeyPair {
            attestation_key: key(id, KeyRole::Attestation),
            proposal_key: key(id, KeyRole::Proposal),
        };
        let bytes = |k: &ValidatorSecretKey| {
            k.public_key()
                .to_bytes()
                .try_into()
                .expect("public key size")
        };
        validators.push(Validator {
            attestation_pubkey: bytes(&pair.attestation_key),
            proposal_pubkey: bytes(&pair.proposal_key),
            index: id,
        });
        keys.insert(id, pair);
    }
    (keys, validators)
}

fn config() -> BlockChainConfig {
    BlockChainConfig {
        aggregator: AggregatorController::new(true),
        sync_status_controller: SyncStatusController::default(),
        attestation_committee_count: 1,
        // A lone node never sees a peer to sync from: run duties at once.
        gate_duties: false,
        subscribed_subnets: HashSet::from([0]),
        aggregation_duty_subnet: 0,
        skip_redundant_aggregation: false,
        proposer_config: ProposerConfig {
            enable_proposer_aggregation: true,
            max_attestations_per_block: 16,
        },
    }
}

/// What one run saw: the chain's progress and a hash of its event trace.
#[derive(Debug, Default)]
struct Seen {
    head: u64,
    blocks: u64,
    justified: u64,
    finalized: u64,
    events: u64,
    trace: u64,
}

fn summarize(rx: &mut tokio::sync::broadcast::Receiver<ChainEvent>) -> Seen {
    let mut seen = Seen::default();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    loop {
        match rx.try_recv() {
            Ok(event) => {
                seen.events += 1;
                format!("{event:?}").hash(&mut hasher);
                match event {
                    ChainEvent::Head { slot, .. } => seen.head = seen.head.max(slot),
                    ChainEvent::Block { .. } => seen.blocks += 1,
                    ChainEvent::JustifiedCheckpoint { slot, .. } => {
                        seen.justified = seen.justified.max(slot)
                    }
                    ChainEvent::FinalizedCheckpoint { slot, .. } => {
                        seen.finalized = seen.finalized.max(slot)
                    }
                    _ => {}
                }
            }
            Err(TryRecvError::Lagged(n)) => panic!("event bus lagged by {n}"),
            Err(_) => break,
        }
    }
    seen.trace = hasher.finish();
    seen
}

/// A seed sweep (`SPAWNED_SIM_SEEDS`, default 8) through Spawned's harness:
/// a failure prints the seed and writes a decision tape to replay.
#[test]
fn one_node_devnet_builds_justifies_and_finalizes() {
    spawned_rt::tasks::SimTest::new()
        .named(
            env!("CARGO_PKG_NAME"),
            module_path!(),
            "one_node_devnet_builds_justifies_and_finalizes",
        )
        .run(devnet);
}

async fn devnet(seed: u64) {
    // Block import and signing are long synchronous CPU (a second per block
    // in release-fast): production gives the actor a thread of its own for
    // that reason. Turn the simulator's 250 ms turn budget off.
    spawned_rt::tasks::sim::set_turn_budget(None);
    // The aggregation prover takes minutes of CPU per proof: use the
    // deterministic stub proofs ethlambda's Shadow integration uses
    // (XMSS keys and signatures stay real). Process-wide, idempotent.
    let proof_size = ethlambda_crypto::shadow_cost::fake_proof_size();
    ethlambda_crypto::shadow_cost::init(true, None, None, None, proof_size);
    let wall = spawned_rt::tasks::sim::wall_now();
    let (keys, validators) = validator_set();
    // Virtual wall clock: genesis a second after the run starts.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs();
    let state = State::from_genesis(now + 1, validators);
    let store = Store::from_anchor_state(
        Arc::new(InMemoryBackend::default()),
        state,
        DEFAULT_MILLISECONDS_PER_SLOT,
    );

    let system = ActorSystem::new().expect("actor system");
    // Under the simulator every group is the simulated thread; production
    // passes a one-worker thread group (`run_node`).
    let group = system.async_group("chain", 1).expect("chain group");
    let events = EventBus::new(1 << 16);
    let mut rx = events.subscribe();
    let chain = BlockChain::spawn(store, keys, config(), events, &group).expect("spawn");

    spawned_rt::tasks::sleep(Duration::from_millis(
        (SLOTS + 1) * DEFAULT_MILLISECONDS_PER_SLOT,
    ))
    .await;
    let seen = summarize(&mut rx);
    eprintln!(
        "seed {seed}: {seen:?} ({:.1?} wall clock)",
        spawned_rt::tasks::sim::wall_now() - wall
    );

    // A block per slot, imported and made head by fork choice.
    assert!(
        seen.head >= SLOTS - 1,
        "head stuck at slot {}: {seen:?}",
        seen.head
    );
    assert!(seen.blocks >= SLOTS - 1, "{seen:?}");
    // Every validator votes, so 3SF-mini justifies and finalizes.
    assert!(seen.justified > 0, "nothing justified: {seen:?}");
    assert!(seen.finalized > 0, "nothing finalized: {seen:?}");
    assert!(seen.finalized <= seen.justified && seen.justified <= seen.head);

    if std::env::var_os("ETHLAMBDA_SIM_PLANT").is_some() {
        panic!(
            "planted failure: head {}, justified {}, finalized {}, {} events, trace {:#018x}",
            seen.head, seen.justified, seen.finalized, seen.events, seen.trace
        );
    }

    drop(chain);
    system.shutdown(Duration::from_secs(5)).await;
}
