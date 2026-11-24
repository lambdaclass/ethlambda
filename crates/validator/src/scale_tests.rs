//! What the validator client costs as the number of keys it holds grows
//! (lambdaclass/ethlambda#797).
//!
//! Two measurements, `#[ignore]`d like the workspace's other slow ones, so
//! `cargo test` and CI skip them. Each prints what it measured and asserts
//! only that every timed step did its work: a step that was refused or cut
//! short would otherwise read as a fast one.
//!
//! - [`duties_at_scale`] drives the duty services against [`MockBeaconNode`]
//!   with thousands of keys over a few epochs, in the order the duty loop in
//!   [`crate::run`] calls them, with a real slashing-protection file.
//! - [`keystore_startup`] loads EIP-2335 keystores at the default scrypt
//!   parameters through [`ValidatorStore::load`], as startup does.
//!
//! Run each on its own, under the profile the test suite uses, which
//! optimizes as the shipped binary does; an unoptimized `dev` build's figures
//! say little about the client. Load on the machine moves every figure, so
//! `duties_at_scale` also prints what one signature cost before and after
//! each run, to read the rest in signatures:
//!
//! ```text
//! cargo test -p ethlambda-validator --profile release-fast --lib \
//!     scale_tests::duties_at_scale -- --ignored --exact --nocapture
//! cargo test -p ethlambda-validator --profile release-fast --lib \
//!     scale_tests::keystore_startup -- --ignored --exact --nocapture
//! ```
//!
//! `ETHLAMBDA_SCALE_KEYS` (comma-separated, default `1000,10000`) and
//! `ETHLAMBDA_SCALE_KEYSTORES` (default 50) change the sizes. Both read
//! process-wide figures, the metrics registry and the resident memory, so
//! running them together, or beside other tests, mixes their numbers.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::constants::SYNC_COMMITTEE_SUBNET_COUNT;
use ethlambda_types::beacon::containers::altair::SyncCommitteeContribution;
use ethlambda_types::beacon::containers::shared::AttestationData;
use ethlambda_types::beacon::preset;
use ethlambda_types::beacon::primitives::{BlsPubkey, BlsSignature, Epoch, H160, Root, Slot};
use tokio::sync::RwLock;

use crate::aggregation::AggregationService;
use crate::attestation::AttestationService;
use crate::beacon_node::dto::{AttesterDutyDto, ProposerDutyDto, SyncDutyDto, encode_hex};
use crate::beacon_node::mock::MockBeaconNode;
use crate::beacon_node::{REGISTRATION_BATCH, ValidatorEntry};
use crate::duties::{DutiesService, sync_committee_period};
use crate::keys::keystore::Keystore;
use crate::keys::{SigningDefinition, ValidatorDefinition, ValidatorDefinitions, ValidatorStore};
use crate::preferences::PreferencesService;
use crate::proposal::{ProposalService, Proposed};
use crate::proposer_settings::ProposerSettings;
use crate::registration::RegistrationService;
use crate::signing::SigningContext;
use crate::slashing_protection::{SharedProtection, SlashingProtection};
use crate::sync_committee::SyncCommitteeService;
use crate::test_support::{settings, store_with_keys};
use crate::{Preparations, refresh_epoch, subscriptions};

/// The first epoch run: electra on mainnet's schedule. Not fulu, since the
/// mock produces electra blocks and a proposal refuses a block of a fork its
/// own schedule does not put at the slot. Nothing else measured here differs
/// between the two forks.
const START_EPOCH: Epoch = 400_000;

/// How many epochs [`duties_at_scale`] runs: the first, whose refresh, subnet
/// subscriptions and builder registrations start from nothing, and two in a
/// steady state.
const EPOCHS: u64 = 3;

/// The epoch the proposer preferences measurement puts gloas at.
const GLOAS_EPOCH: Epoch = 500_000;

const FEE_RECIPIENT: H160 = H160([0xab; 20]);

/// EIP-2335's default scrypt parameters, which `staking-deposit-cli` and
/// `ethstaker-deposit-cli` write: `n = 2^18`, `r = 8`, `p = 1`. One derivation
/// takes `128 * r * n` bytes, 256 MiB.
const SCRYPT_LOG_N: u8 = 18;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

const KEYSTORE_PASSWORD: &str = "scale-test-password";

const WRITE_SECONDS: &str = "ethlambda_validator_slashing_protection_write_seconds";
const SIGNING_FAILURES: &str = "ethlambda_validator_signing_failures_total";

/// Drive the duty services with each of `ETHLAMBDA_SCALE_KEYS`' key counts,
/// one after the other.
///
/// # The duties
///
/// Those of a network whose every validator this client holds: the worst
/// case for one client, and the shape of a devnet run behind one. Every key
/// attests once an epoch, the keys spread evenly over the epoch's slots and
/// dealt into `max(1, min(64, keys / 32 / 128))` committees per slot, as the
/// specification sizes them; every slot's proposer is one of its keys; and
/// its keys fill the 512 sync committee seats.
///
/// # What is timed
///
/// The client's own work: signing, the slashing-protection record, and
/// building what goes to the node. Slots run back to back with nothing slept,
/// and the mock answers at once and skips HTTP and JSON, which a real node
/// does not. The epoch's subnet subscriptions and builder registrations, which
/// the duty loop spawns beside the slot's duties, are timed on their own here.
///
/// The keys hold small-integer secrets (`test_support::store_with_keys`), so
/// no keystore is decrypted; [`keystore_startup`] measures that.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement: signs hundreds of thousands of BLS messages, a minute or more at 10,000 keys"]
async fn duties_at_scale() {
    for keys in sizes("ETHLAMBDA_SCALE_KEYS", &[1_000, 10_000]) {
        run_with(keys).await;
    }
}

/// Decrypt `ETHLAMBDA_SCALE_KEYSTORES` keystores at EIP-2335's default scrypt
/// parameters, through the path startup takes, then again with one thread per
/// core, for what parallel decryption would buy.
///
/// Every keystore shares one password and salt, so writing them costs one
/// derivation. Loading them still runs one per keystore, since nothing tells
/// the loader they match: the per-key time is a real keystore's.
#[test]
#[ignore = "measurement: decrypts scrypt keystores at EIP-2335's default cost, about half a second each"]
fn keystore_startup() {
    let count = sizes("ETHLAMBDA_SCALE_KEYSTORES", &[50])[0];
    let dir = tempfile::tempdir().expect("temp dir");

    let salt = [0x5a; 32];
    let started = Instant::now();
    let mut derived = [0u8; 32];
    let params =
        scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, 32).expect("EIP-2335's parameters");
    scrypt::scrypt(KEYSTORE_PASSWORD.as_bytes(), &salt, &params, &mut derived).expect("derives");
    let one_derivation = started.elapsed();

    let mut definitions = Vec::with_capacity(count);
    for index in 0..count {
        let secret = small_secret(index);
        let pubkey = ValidatorStore::derive_pubkey(&secret).expect("derives the pubkey");
        let keystore_file = format!("keystore-{index}.json");
        let password_file = format!("password-{index}.txt");
        let json = keystore_json(&derived, &salt, index, &secret, &pubkey);
        std::fs::write(dir.path().join(&keystore_file), json).expect("writes the keystore");
        std::fs::write(dir.path().join(&password_file), KEYSTORE_PASSWORD)
            .expect("writes the password");
        definitions.push(ValidatorDefinition {
            enabled: true,
            voting_public_key: encode_hex(&pubkey.0),
            signing: SigningDefinition::LocalKeystore {
                voting_keystore_path: PathBuf::from(keystore_file),
                voting_keystore_password_path: PathBuf::from(password_file),
            },
            suggested_fee_recipient: None,
            graffiti: None,
            gas_limit: None,
        });
    }
    ValidatorDefinitions(definitions)
        .save(dir.path())
        .expect("saves the definitions");

    let started = Instant::now();
    let store = ValidatorStore::load(dir.path()).expect("loads every keystore");
    let sequential = started.elapsed();
    assert_eq!(store.len(), count, "every keystore loaded");

    let keystores: Vec<Keystore> = (0..count)
        .map(|index| {
            let path = dir.path().join(format!("keystore-{index}.json"));
            let json = std::fs::read_to_string(path).expect("reads the keystore");
            Keystore::from_json(&json).expect("parses the keystore")
        })
        .collect();
    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    let chunks = keystores.chunks(count.div_ceil(cores));
    let threads = chunks.len();
    let started = Instant::now();
    std::thread::scope(|scope| {
        for chunk in chunks {
            scope.spawn(move || {
                for keystore in chunk {
                    keystore.decrypt(KEYSTORE_PASSWORD).expect("decrypts");
                }
            });
        }
    });
    let parallel = started.elapsed();

    let per_key = sequential / count as u32;
    println!();
    println!(
        "keystore startup: {count} EIP-2335 keystores, scrypt n=2^{SCRYPT_LOG_N} r={SCRYPT_R} \
         p={SCRYPT_P} (256 MiB per derivation)"
    );
    println!(
        "  one scrypt derivation:           {}",
        show(one_derivation)
    );
    println!(
        "  ValidatorStore::load, sequential: {} ({} per key)",
        show(sequential),
        show(per_key)
    );
    println!(
        "  extrapolated, sequential:         1,000 keys {}, 10,000 keys {}",
        show(per_key * 1_000),
        show(per_key * 10_000)
    );
    let per_key_parallel = parallel / count as u32;
    println!(
        "  decrypted on {threads} threads ({cores} cores): {} ({} per key; 1,000 keys {}, 10,000 \
         keys {}), holding {} MiB of scrypt buffers at once",
        show(parallel),
        show(per_key_parallel),
        show(per_key_parallel * 1_000),
        show(per_key_parallel * 10_000),
        threads * 256
    );
}

/// One run of [`duties_at_scale`] with `keys` keys.
async fn run_with(keys: usize) {
    let rss_before = resident_mib();
    let started = Instant::now();
    let (store, pubkeys) = store_with_keys(keys);
    let key_setup = started.elapsed();
    let hex: Vec<String> = pubkeys.iter().map(|pubkey| encode_hex(&pubkey.0)).collect();
    let store = Arc::new(RwLock::new(store));
    let context = Arc::new(SigningContext::new(
        Config::mainnet(),
        genesis_validators_root(),
    ));
    let settings = settings(Some(FEE_RECIPIENT));

    // A real record in a directory of its own: the in-memory one the other
    // tests use writes nothing.
    let dir = tempfile::tempdir().expect("temp dir");
    let started = Instant::now();
    let protection =
        SlashingProtection::open(dir.path(), genesis_validators_root(), &pubkeys, true)
            .expect("opens the record");
    let record_open = started.elapsed();
    let protection = SharedProtection::new(protection);
    let record_path = dir.path().join(crate::slashing_protection::file::FILE_NAME);

    let head = Root::repeat_byte(0x77);
    let node = Arc::new(epoch_node(&pubkeys, &hex, head));
    let mut duties = DutiesService::new(node.clone(), Vec::new());
    let registration = Arc::new(RegistrationService::new(
        node.clone(),
        context.clone(),
        settings.clone(),
    ));
    let preparations = Arc::new(Preparations::new(node.clone(), settings.clone()));
    // Kept across slots, as the duty loop's is: it remembers which messages
    // it signed, and that memory is part of the cost.
    let sync_messages = SyncCommitteeService::new(node.clone(), context.clone());
    let rss_setup = resident_mib();
    let signature_before = signature_cost(&store, &context, pubkeys[0]).await;

    let mut timings = Timings::default();
    let mut resolved: Arc<Vec<ValidatorEntry>> = Arc::default();
    let slots = preset::slots_per_epoch();
    for epoch in START_EPOCH..START_EPOCH + EPOCHS {
        for slot in epoch * slots..(epoch + 1) * slots {
            if slot == epoch * slots {
                resolved = Arc::new(
                    epoch_work(
                        &node,
                        &mut duties,
                        &store,
                        &context,
                        &settings,
                        &registration,
                        epoch,
                        &mut timings,
                    )
                    .await,
                );
            }
            let slot_duties = SlotDuties {
                attester: duties.at_slot(slot, epoch),
                proposer: duties.proposer_at_slot(slot, epoch).cloned(),
                sync: duties.sync_at_slot(slot),
            };
            slot_work(
                &node,
                &store,
                &context,
                &settings,
                &protection,
                &sync_messages,
                &registration,
                &preparations,
                &resolved,
                head,
                slot,
                &slot_duties,
                &mut timings,
            )
            .await;
        }
    }

    let started = Instant::now();
    let rendered = protection
        .lock()
        .expect("the record is usable")
        .export(&pubkeys)
        .expect("renders the record");
    let render = started.elapsed();
    let record_bytes = std::fs::metadata(&record_path)
        .expect("the record exists")
        .len();
    let rss_after = resident_mib();

    let polls = preferences_poll(&store, &hex, &settings).await;
    let signature_after = signature_cost(&store, &context, pubkeys[0]).await;

    timings.report(&Report {
        keys,
        signature: [signature_before, signature_after],
        key_setup,
        record_open,
        render,
        rendered_bytes: rendered.len(),
        record_bytes,
        rss: [rss_before, rss_setup, rss_after],
        polls,
    });
}

/// The duties one slot holds, as the duty loop takes them from the schedule.
struct SlotDuties {
    attester: Vec<AttesterDutyDto>,
    proposer: Option<ProposerDutyDto>,
    sync: Vec<SyncDutyDto>,
}

/// What the duty loop does once an epoch, on its first slot: refresh, then
/// the subnet subscriptions and builder registrations it spawns. Returns the
/// validators the refresh resolved, whose preparations every slot re-sends.
#[allow(clippy::too_many_arguments)]
async fn epoch_work(
    node: &Arc<MockBeaconNode>,
    duties: &mut DutiesService<MockBeaconNode>,
    store: &Arc<RwLock<ValidatorStore>>,
    context: &Arc<SigningContext>,
    settings: &Arc<ProposerSettings>,
    registration: &Arc<RegistrationService<MockBeaconNode>>,
    epoch: Epoch,
    timings: &mut Timings,
) -> Vec<ValidatorEntry> {
    let keys = store.read().await.pubkeys();
    let started = Instant::now();
    let refreshed = refresh_epoch(node, duties, &keys, epoch, settings, context)
        .await
        .expect("refreshes the duties");
    timings.refresh.push(started.elapsed());
    assert_eq!(refreshed.resolved.len(), keys.len(), "every key resolved");
    assert!(refreshed.moved, "a new epoch moves the schedule");
    assert_eq!(
        node.preparations.lock().expect("lock").len(),
        keys.len(),
        "one preparation per key"
    );

    // Every held duty, this epoch's and the next's, one selection proof each
    // unless an earlier round already produced it.
    let owed = duties.all();
    let failures = counter(SIGNING_FAILURES);
    let started = Instant::now();
    subscriptions::subscribe(node, &owed, store, context)
        .await
        .expect("subscribes");
    let elapsed = started.elapsed();
    let sent = std::mem::take(&mut *node.subscriptions.lock().expect("lock"));
    assert_eq!(sent.len(), owed.len(), "one subscription per duty");
    timings.subscriptions.push(Subscribed {
        elapsed,
        duties: owed.len(),
        aggregating: sent.iter().filter(|entry| entry.is_aggregator).count(),
        dropped: (counter(SIGNING_FAILURES) - failures) as usize,
    });

    let registrable = refreshed.registrable;
    let started = Instant::now();
    registration
        .clone()
        .register_all(epoch, registrable, store.clone())
        .await;
    let elapsed = started.elapsed();
    let registrations = std::mem::take(&mut *node.registrations.lock().expect("lock"));
    let batches = std::mem::take(&mut *node.registration_batches.lock().expect("lock"));
    assert_eq!(registrations.len(), keys.len(), "every key registered");
    assert_eq!(batches.len(), keys.len().div_ceil(REGISTRATION_BATCH));
    let json = serde_json::to_vec(&registrations).expect("encodes the registrations");
    timings.registrations.push(Registered {
        elapsed,
        batches: batches.len(),
        json_bytes: json.len(),
    });

    clear(node);
    refreshed.resolved
}

/// One slot's work, in the duty loop's order: the proposal, the attestations
/// and their aggregation, the sync committee messages and contributions, the
/// per-slot registration check and the preparations' re-send.
///
/// A node of its own answers the slot's attestation data, aggregates,
/// contributions and block, since the mock answers those for one slot only.
/// The services that call it are built for the slot too, which costs nothing:
/// what they keep across slots, the signing context and its selection
/// proofs, and the slashing-protection record, is shared.
#[allow(clippy::too_many_arguments)]
async fn slot_work(
    node: &Arc<MockBeaconNode>,
    store: &Arc<RwLock<ValidatorStore>>,
    context: &Arc<SigningContext>,
    settings: &Arc<ProposerSettings>,
    protection: &SharedProtection,
    sync_messages: &SyncCommitteeService<MockBeaconNode>,
    registration: &Arc<RegistrationService<MockBeaconNode>>,
    preparations: &Arc<Preparations<MockBeaconNode>>,
    resolved: &Arc<Vec<ValidatorEntry>>,
    head: Root,
    slot: Slot,
    duties: &SlotDuties,
    timings: &mut Timings,
) {
    let proposer = duties.proposer.as_ref().map(|duty| duty.validator_index);
    let (slot_node, data) = slot_node(slot, proposer, head);
    let slot_node = Arc::new(slot_node);
    let (writes_before, write_seconds_before) = histogram(WRITE_SECONDS);
    let mut duty_path = Duration::ZERO;

    if let Some(duty) = &duties.proposer {
        let proposal = ProposalService::new(
            slot_node.clone(),
            context.clone(),
            settings.clone(),
            protection.clone(),
            None,
        );
        let started = Instant::now();
        let proposed = proposal.propose(slot, duty, store).await;
        let elapsed = started.elapsed();
        assert!(
            matches!(proposed, Ok(Proposed::Full(_))),
            "slot {slot}: {proposed:?}"
        );
        timings.proposal.push(elapsed);
        duty_path += elapsed;
    }

    let attestation =
        AttestationService::new(slot_node.clone(), context.clone(), protection.clone());
    let started = Instant::now();
    let attested = attestation
        .attest(slot, &duties.attester, store)
        .await
        .expect("attests");
    let elapsed = started.elapsed();
    assert_eq!(attested.published, duties.attester.len(), "slot {slot}");
    assert_eq!(attested.refused, 0, "slot {slot}");
    timings.attestation.push(elapsed);
    timings.attesters += duties.attester.len();
    duty_path += elapsed;

    let aggregation = AggregationService::new(slot_node.clone(), context.clone());
    let started = Instant::now();
    let aggregated = aggregation
        .aggregate(slot, &data, &duties.attester, store)
        .await
        .expect("aggregates");
    let elapsed = started.elapsed();
    timings.aggregation.push(elapsed);
    timings.aggregates += aggregated;
    duty_path += elapsed;

    let started = Instant::now();
    let signed_over = sync_messages
        .publish_messages(slot, &duties.sync, store)
        .await
        .expect("publishes the sync committee messages");
    let elapsed = started.elapsed();
    assert_eq!(signed_over, Some(head), "slot {slot}");
    let messages = std::mem::take(&mut *node.submitted_sync_messages.lock().expect("lock"));
    assert_eq!(messages.len(), duties.sync.len(), "slot {slot}");
    timings.sync_messages.push(elapsed);
    duty_path += elapsed;

    let contributions = SyncCommitteeService::new(slot_node.clone(), context.clone());
    let started = Instant::now();
    let contributed = contributions
        .aggregate(slot, head, &duties.sync, store)
        .await
        .expect("publishes the sync contributions");
    let elapsed = started.elapsed();
    timings.sync_contributions.push(elapsed);
    timings.contributions += contributed;
    duty_path += elapsed;
    timings.duty_path.push(duty_path);

    let (writes_after, write_seconds_after) = histogram(WRITE_SECONDS);
    let writes = writes_after - writes_before;
    let expected = 1 + usize::from(duties.proposer.is_some());
    assert_eq!(
        writes as usize, expected,
        "slot {slot}: one write per block and per batch"
    );
    timings.writes += writes;
    timings.write_seconds += write_seconds_after - write_seconds_before;
    timings.write_per_slot.push(Duration::from_secs_f64(
        write_seconds_after - write_seconds_before,
    ));

    let started = Instant::now();
    registration
        .clone()
        .register_changed(epoch_of(slot), store.clone())
        .await;
    timings.registration_check.push(started.elapsed());

    let started = Instant::now();
    preparations
        .after_slot(slot, resolved, store)
        .expect("there are validators to prepare")
        .await
        .expect("the re-send ran");
    timings.preparations.push(started.elapsed());
    let prepared = std::mem::take(&mut *node.preparations.lock().expect("lock"));
    assert_eq!(prepared.len(), resolved.len(), "slot {slot}");

    clear(node);
}

/// The mean cost of one local BLS signature through the path every duty
/// signs by, so the other figures can be read in signatures: the same work
/// takes very different times on a loaded machine, or on an efficiency core
/// rather than a performance one.
async fn signature_cost(
    store: &RwLock<ValidatorStore>,
    context: &SigningContext,
    pubkey: BlsPubkey,
) -> Duration {
    const ROUNDS: u32 = 500;
    let data = MockBeaconNode::new()
        .with_attestation_data(START_EPOCH * preset::slots_per_epoch())
        .attestation_data
        .expect("just set");
    let started = Instant::now();
    for _ in 0..ROUNDS {
        context
            .sign_attestation(store, &pubkey, &data)
            .await
            .expect("signs");
    }
    started.elapsed() / ROUNDS
}

/// The gloas proposer preferences poll at every slot of one epoch, with this
/// client's key behind every proposal of that epoch and the next: the first
/// poll signs one preference per slot still ahead in both, the later ones
/// mostly find them sent. Each poll snapshots every loaded pubkey, which is
/// its only per-key cost; the `sent` lock it takes once per proposer duty is
/// bounded by the slots of the two epochs, whatever the key count.
async fn preferences_poll(
    store: &Arc<RwLock<ValidatorStore>>,
    hex: &[String],
    settings: &Arc<ProposerSettings>,
) -> Samples {
    let mut config = Config::mainnet();
    config.gloas_fork_epoch = GLOAS_EPOCH;
    let context = Arc::new(SigningContext::new(config, genesis_validators_root()));
    let mut node = MockBeaconNode::new();
    for epoch in [GLOAS_EPOCH, GLOAS_EPOCH + 1] {
        node = node.with_proposers_v2(epoch, dependent_root(epoch), proposer_duties(epoch, hex));
    }
    let node = Arc::new(node);
    let service = Arc::new(PreferencesService::new(
        node.clone(),
        context,
        settings.clone(),
    ));

    let mut polls = Samples::default();
    let slots = preset::slots_per_epoch();
    for slot in GLOAS_EPOCH * slots..(GLOAS_EPOCH + 1) * slots {
        let started = Instant::now();
        service.clone().poll(slot, store.clone()).await;
        polls.push(started.elapsed());
    }
    let sent = node.submitted_preferences.lock().expect("lock").len();
    // Every slot of both epochs but the first poll's own.
    assert!(sent > 2 * slots as usize - 2, "{sent} preferences sent");
    polls
}

/// The long-lived node: the validators, the attester and proposer schedules,
/// the sync committee, the head, and everything the epoch's sends deliver.
fn epoch_node(pubkeys: &[BlsPubkey], hex: &[String], head: Root) -> MockBeaconNode {
    let mut node = MockBeaconNode::new().with_head_root(head);
    node.validators = pubkeys
        .iter()
        .enumerate()
        .map(|(index, pubkey)| ValidatorEntry {
            index: index as u64,
            pubkey: *pubkey,
            status: "active_ongoing".to_string(),
        })
        .collect();
    // The last epoch's refresh looks one ahead.
    for epoch in START_EPOCH..=START_EPOCH + EPOCHS {
        let root = dependent_root(epoch);
        node = node
            .with_duties(epoch, root, attester_duties(epoch, hex))
            .with_proposers(epoch, root, proposer_duties(epoch, hex));
    }
    let period = sync_committee_period(START_EPOCH);
    for period in [period, period + 1] {
        let epoch = period * preset::epochs_per_sync_committee_period();
        node = node.with_sync_duties(epoch, sync_duties(hex));
    }
    node
}

/// A node for `slot` alone: its attestation data and the aggregate over it,
/// its block when it has a proposer, and a contribution per sync subnet.
fn slot_node(slot: Slot, proposer: Option<u64>, head: Root) -> (MockBeaconNode, AttestationData) {
    let node = MockBeaconNode::new()
        .with_attestation_data(slot)
        .with_head_root(head);
    let data = node.attestation_data.expect("just set");
    let mut node = node.with_aggregate(data);
    if let Some(proposer) = proposer {
        node = node.with_block(slot, proposer);
    }
    for subnet in 0..SYNC_COMMITTEE_SUBNET_COUNT as u64 {
        node = node.with_contribution(SyncCommitteeContribution {
            slot,
            beacon_block_root: head,
            subcommittee_index: subnet,
            aggregation_bits: Default::default(),
            signature: BlsSignature([1; 96]),
        });
    }
    (node, data)
}

/// Forget what the long-lived node was sent, which would otherwise grow by a
/// preparation per key every slot and swamp the memory figures.
fn clear(node: &MockBeaconNode) {
    node.preparations.lock().expect("lock").clear();
    node.subscriptions.lock().expect("lock").clear();
    node.registrations.lock().expect("lock").clear();
    node.registration_batches.lock().expect("lock").clear();
    node.submitted_sync_messages.lock().expect("lock").clear();
    node.sync_subscriptions.lock().expect("lock").clear();
    node.sync_duty_requests.lock().expect("lock").clear();
}

/// Every key's attester duty in `epoch`: key `i` at the epoch's slot `i % 32`,
/// each slot's keys dealt round-robin into its committees.
fn attester_duties(epoch: Epoch, hex: &[String]) -> Vec<AttesterDutyDto> {
    let slots = preset::slots_per_epoch();
    let committees = committees_per_slot(hex.len());
    let committee_length = (hex.len() as u64).div_ceil(slots).div_ceil(committees);
    hex.iter()
        .enumerate()
        .map(|(index, pubkey)| {
            let index = index as u64;
            let position = index / slots;
            AttesterDutyDto {
                pubkey: pubkey.clone(),
                validator_index: index,
                committee_index: position % committees,
                committee_length,
                committees_at_slot: committees,
                validator_committee_index: position / committees,
                slot: epoch * slots + index % slots,
            }
        })
        .collect()
}

/// The specification's `get_committee_count_per_slot` for a network of `keys`
/// active validators.
fn committees_per_slot(keys: usize) -> u64 {
    let committees = keys as u64 / preset::slots_per_epoch() / preset::target_committee_size();
    committees.clamp(1, preset::max_committees_per_slot() as u64)
}

/// A proposer from this client's keys for every slot of `epoch`.
fn proposer_duties(epoch: Epoch, hex: &[String]) -> Vec<ProposerDutyDto> {
    let slots = preset::slots_per_epoch();
    (epoch * slots..(epoch + 1) * slots)
        .map(|slot| {
            let index = (slot % hex.len() as u64) as usize;
            ProposerDutyDto {
                pubkey: hex[index].clone(),
                validator_index: index as u64,
                slot,
            }
        })
        .collect()
}

/// Every sync committee seat held by one of this client's keys, one seat per
/// key when there are enough of them.
fn sync_duties(hex: &[String]) -> Vec<SyncDutyDto> {
    let seats = preset::sync_committee_size() as u64;
    let holders = hex.len().min(seats as usize);
    (0..holders)
        .map(|index| SyncDutyDto {
            pubkey: hex[index].clone(),
            validator_index: index as u64,
            validator_sync_committee_indices: (index as u64..seats).step_by(holders).collect(),
        })
        .collect()
}

fn epoch_of(slot: Slot) -> Epoch {
    slot / preset::slots_per_epoch()
}

fn dependent_root(epoch: Epoch) -> Root {
    Root::repeat_byte((epoch % 251) as u8)
}

fn genesis_validators_root() -> Root {
    Root::repeat_byte(0x42)
}

/// The secret `test_support::store_with_keys` gives its key `index`.
fn small_secret(index: usize) -> [u8; 32] {
    let mut secret = [0u8; 32];
    secret[24..].copy_from_slice(&(index as u64 + 1).to_be_bytes());
    secret
}

/// An EIP-2335 keystore holding `secret` under `derived`, the scrypt key of
/// [`KEYSTORE_PASSWORD`] and `salt`. Each gets its own IV.
fn keystore_json(
    derived: &[u8; 32],
    salt: &[u8; 32],
    index: usize,
    secret: &[u8; 32],
    pubkey: &BlsPubkey,
) -> String {
    use aes::cipher::{KeyIvInit as _, StreamCipher as _};
    use sha2::Digest as _;
    type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

    let mut iv = [0u8; 16];
    iv[8..].copy_from_slice(&(index as u64).to_be_bytes());
    let mut cipher_message = *secret;
    Aes128Ctr::new_from_slices(&derived[..16], &iv)
        .expect("a 16-byte key and IV")
        .apply_keystream(&mut cipher_message);
    let mut hasher = sha2::Sha256::new();
    hasher.update(&derived[16..]);
    hasher.update(cipher_message);
    let checksum = hasher.finalize();

    serde_json::json!({
        "crypto": {
            "kdf": {
                "function": "scrypt",
                "params": {
                    "dklen": 32,
                    "n": 1u64 << SCRYPT_LOG_N,
                    "r": SCRYPT_R,
                    "p": SCRYPT_P,
                    "salt": hex::encode(salt),
                },
                "message": ""
            },
            "checksum": { "function": "sha256", "params": {}, "message": hex::encode(checksum) },
            "cipher": {
                "function": "aes-128-ctr",
                "params": { "iv": hex::encode(iv) },
                "message": hex::encode(cipher_message)
            }
        },
        "pubkey": hex::encode(pubkey.0),
        "path": format!("m/12381/3600/{index}/0/0"),
        "uuid": format!("00000000-0000-4000-8000-{index:012}"),
        "version": 4
    })
    .to_string()
}

/// The sizes `variable` names, comma-separated, or `default`.
fn sizes(variable: &str, default: &[usize]) -> Vec<usize> {
    let Ok(value) = std::env::var(variable) else {
        return default.to_vec();
    };
    value
        .split(',')
        .map(|size| {
            size.trim()
                .replace('_', "")
                .parse()
                .unwrap_or_else(|_| panic!("{variable}: {size:?} is not a count"))
        })
        .collect()
}

/// A histogram's sample count and sum, from the process-wide registry the
/// client's metrics live in. Zero before its first observation.
fn histogram(name: &str) -> (u64, f64) {
    ethlambda_metrics::gather()
        .iter()
        .find(|family| family.name() == name)
        .and_then(|family| family.get_metric().first())
        .map(|metric| {
            let histogram = metric.get_histogram();
            (histogram.get_sample_count(), histogram.get_sample_sum())
        })
        .unwrap_or_default()
}

/// A counter's value, from the same registry.
fn counter(name: &str) -> f64 {
    ethlambda_metrics::gather()
        .iter()
        .find(|family| family.name() == name)
        .and_then(|family| family.get_metric().first())
        .map(|metric| metric.get_counter().value())
        .unwrap_or_default()
}

/// This process's resident memory in MiB, as `ps` reports it (in KiB, on
/// macOS and Linux alike), or `None` without `ps`.
fn resident_mib() -> Option<f64> {
    let pid = std::process::id().to_string();
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid])
        .output()
        .ok()?;
    let kib: f64 = String::from_utf8(output.stdout).ok()?.trim().parse().ok()?;
    Some(kib / 1024.0)
}

fn mib(value: Option<f64>) -> String {
    value.map_or_else(|| "n/a".to_string(), |mib| format!("{mib:.0} MiB"))
}

fn show(duration: Duration) -> String {
    let seconds = duration.as_secs_f64();
    if seconds >= 120.0 {
        format!("{:.1} min", seconds / 60.0)
    } else if seconds >= 1.0 {
        format!("{seconds:.2} s")
    } else if seconds >= 1e-3 {
        format!("{:.1} ms", seconds * 1e3)
    } else {
        format!("{:.0} µs", seconds * 1e6)
    }
}

#[derive(Default)]
struct Samples(Vec<Duration>);

impl Samples {
    fn push(&mut self, sample: Duration) {
        self.0.push(sample);
    }

    fn first(&self) -> Duration {
        self.0.first().copied().unwrap_or_default()
    }

    /// Mean and max of every sample after the first, or of all of them when
    /// `skip_first` is off.
    fn summary(&self, skip_first: bool) -> String {
        let samples = if skip_first && self.0.len() > 1 {
            &self.0[1..]
        } else {
            &self.0[..]
        };
        if samples.is_empty() {
            return "none".to_string();
        }
        let total: Duration = samples.iter().sum();
        let mean = total / samples.len() as u32;
        let max = samples.iter().max().copied().unwrap_or_default();
        format!("mean {}, max {}", show(mean), show(max))
    }
}

struct Subscribed {
    elapsed: Duration,
    duties: usize,
    aggregating: usize,
    /// Selection proofs that missed the round's signing budget, each one a
    /// duty subscribed without the aggregator role.
    dropped: usize,
}

struct Registered {
    elapsed: Duration,
    batches: usize,
    json_bytes: usize,
}

#[derive(Default)]
struct Timings {
    refresh: Samples,
    subscriptions: Vec<Subscribed>,
    registrations: Vec<Registered>,
    proposal: Samples,
    attestation: Samples,
    attesters: usize,
    aggregation: Samples,
    aggregates: usize,
    sync_messages: Samples,
    sync_contributions: Samples,
    contributions: usize,
    duty_path: Samples,
    writes: u64,
    write_seconds: f64,
    write_per_slot: Samples,
    registration_check: Samples,
    preparations: Samples,
}

/// What [`run_with`] measured outside [`Timings`].
struct Report {
    keys: usize,
    /// One signature's cost, before the run and after it.
    signature: [Duration; 2],
    key_setup: Duration,
    record_open: Duration,
    render: Duration,
    rendered_bytes: usize,
    record_bytes: u64,
    /// Before the keys, once everything is set up, and after the run.
    rss: [Option<f64>; 3],
    polls: Samples,
}

impl Timings {
    fn report(&self, report: &Report) {
        let keys = report.keys;
        let slots = self.attestation.0.len();
        println!();
        println!(
            "{keys} keys, {EPOCHS} epochs ({slots} slots): {} committee(s) per slot, a proposal \
             every slot, {} sync committee duties",
            committees_per_slot(keys),
            keys.min(preset::sync_committee_size()),
        );
        let [before, after] = report.signature;
        println!(
            "  one signature:                    {} before the run, {} after",
            show(before),
            show(after)
        );
        println!(
            "  key setup (no keystores):         {}",
            show(report.key_setup)
        );
        println!(
            "  slashing protection open:         {} (writes the {:.1} KiB record)",
            show(report.record_open),
            report.record_bytes as f64 / 1024.0
        );
        println!("epoch, first / then");
        println!(
            "  duty refresh:                     {} / {}",
            show(self.refresh.first()),
            self.refresh.summary(true)
        );
        for (epoch, subscribed) in self.subscriptions.iter().enumerate() {
            println!(
                "  subnet subscriptions, epoch {epoch}:   {} for {} duties ({} aggregating, \
                 {} proofs past the signing budget)",
                show(subscribed.elapsed),
                subscribed.duties,
                subscribed.aggregating,
                subscribed.dropped
            );
        }
        for (epoch, registered) in self.registrations.iter().enumerate() {
            let what = if epoch == 0 {
                "signs and sends"
            } else {
                "sends"
            };
            println!(
                "  builder registrations, epoch {epoch}:  {} ({what}: {} batches, {:.0} KiB of \
                 JSON; at the 12 s timeout per batch a slow node holds it {} s)",
                show(registered.elapsed),
                registered.batches,
                registered.json_bytes as f64 / 1024.0,
                12 * registered.batches
            );
        }
        println!("per slot");
        println!(
            "  proposal:                         {}",
            self.proposal.summary(false)
        );
        println!(
            "  attestations ({} per slot):        {}",
            self.attesters / slots.max(1),
            self.attestation.summary(false)
        );
        println!(
            "    slashing-protection writes:     {} writes, mean {} per write ({} per slot, \
             block and attestations)",
            self.writes,
            show(Duration::from_secs_f64(
                self.write_seconds / self.writes.max(1) as f64
            )),
            self.write_per_slot.summary(false)
        );
        println!(
            "    of which rendering the record:  {} ({:.1} KiB, the export of every key)",
            show(report.render),
            report.rendered_bytes as f64 / 1024.0
        );
        println!(
            "  aggregation ({} aggregates):    {}",
            self.aggregates,
            self.aggregation.summary(false)
        );
        println!(
            "  sync committee messages:          {}",
            self.sync_messages.summary(false)
        );
        println!(
            "  sync contributions ({}):         {}",
            self.contributions,
            self.sync_contributions.summary(false)
        );
        println!(
            "  duty path, the five above:        {}",
            self.duty_path.summary(false)
        );
        println!(
            "  registration check:               {}",
            self.registration_check.summary(false)
        );
        println!(
            "  preparations re-send:             {}",
            self.preparations.summary(false)
        );
        println!(
            "  gloas preferences poll:           first {}, then {}",
            show(report.polls.first()),
            report.polls.summary(true)
        );
        let [before, setup, after] = report.rss;
        println!(
            "resident memory: {} before the keys, {} once set up, {} after the run",
            mib(before),
            mib(setup),
            mib(after)
        );
    }
}
