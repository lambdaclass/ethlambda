//! A beacon-chain validator client.
//!
//! It holds BLS keys, learns its duties from a beacon node over the standard
//! REST Beacon API, and signs and submits what those duties call for:
//! attestations, the blocks its validators are scheduled to propose, and the
//! aggregates they are selected to publish. It is beacon-node-agnostic:
//! everything it knows about the chain arrives through the `BeaconNodeApi`
//! trait, so it runs against any conformant node.
//!
//! # Slashing protection
//!
//! Every block and attestation is checked against a durable, per-validator
//! record before it is signed, and the record is on disk before the signature
//! exists. The record keeps EIP-3076's minimal watermarks, lives next to the
//! keys, names the chain it belongs to, and is locked to one process. See
//! [`crate::slashing_protection`] for the rule and its guarantees, and
//! [`docs/spec_deviations.md`] for where the minimal rule is stricter than the
//! specification.
//!
//! [`docs/spec_deviations.md`]: https://github.com/lambdaclass/ethlambda/blob/main/docs/spec_deviations.md
//!
//! History moves in and out as EIP-3076 interchange files: through the
//! keymanager API's `POST` and `DELETE /eth/v1/keystores`, and offline through
//! `ethlambda slashing-protection`. A key imported with no history is
//! registered as never having signed before it is loaded.

pub mod aggregation;
pub mod aggregation_selection;
pub mod attestation;
pub mod beacon_node;
pub mod chain_check;
pub mod doppelganger;
pub mod duties;
pub mod error;
pub mod exit;
pub mod head_monitor;
pub mod http_api;
pub(crate) mod in_flight;
pub mod keys;
pub mod metrics;
pub mod payload_attestation;
pub mod preferences;
pub mod proposal;
pub mod proposer_settings;
pub mod registration;
#[cfg(test)]
mod scale_tests;
pub mod secure_fs;
pub mod shared_config;
pub mod signing;
pub mod slashing_protection;
pub mod slot_clock;
pub mod subscriptions;
pub mod sync_committee;
#[cfg(test)]
mod test_support;

pub use error::{Error, Result};

/// Run this process on the preset the beacon node reports, before anything
/// reads one.
///
/// A validator client has no network config of its own: the node's
/// `/eth/v1/config/spec` is where it learns the chain, `PRESET_BASE`
/// included. Every container this client decodes, builds or signs is bounded
/// by that preset (a sync committee's bits, an attestation's committee bits,
/// the slots in an epoch), so it is selected here, right after the spec is
/// fetched and before any duty runs.
pub fn adopt_preset(spec: &ethlambda_types::beacon::config::Config) -> Result<()> {
    use ethlambda_types::beacon::preset::Preset;

    let name = spec.preset_base.as_str();
    let preset: Preset = name.parse().map_err(|_| {
        Error::Preset(format!(
            "PRESET_BASE: {name:?} names no preset this client has values for"
        ))
    })?;
    Preset::select(preset).map_err(|err| Error::Preset(err.to_string()))
}

/// Refuse to go on when something in this process read a preset value before
/// the beacon node's was adopted.
///
/// [`adopt_preset`] accepts the preset already in force, so against a mainnet
/// node such a read goes unnoticed and only a minimal one fails. The two
/// commands that own their process call this first, so the ordering bug fails
/// against every node. Kept out of `adopt_preset` itself, which tests sharing
/// one process also reach.
pub(crate) fn require_unread_preset() -> Result<()> {
    ethlambda_types::beacon::preset::Preset::require_unread()
        .map_err(|err| Error::Preset(err.to_string()))
}

use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use ethlambda_types::beacon::primitives::{BlsPubkey, Bytes32, ExecutionAddress, ValidatorIndex};
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, warn};

use crate::aggregation::AggregationService;
use crate::attestation::AttestationService;
use crate::beacon_node::dto::ProposerPreparationDto;
use crate::beacon_node::fallback::FallbackBeaconNode;
use crate::beacon_node::http::HttpBeaconNode;
use crate::beacon_node::{BeaconNodeApi, ValidatorEntry};
use crate::chain_check::ChainId;
use crate::duties::{DutiesService, ProposerDutiesVersion};
use crate::head_monitor::DutyTriggers;
use crate::in_flight::InFlight;
use crate::keys::ValidatorStore;
use crate::payload_attestation::PayloadAttestationService;
use crate::preferences::PreferencesService;
use crate::proposal::{BlindedOutcome, ProposalService, Proposed};
use crate::proposer_settings::ProposerSettings;
use crate::registration::RegistrationService;
use crate::shared_config::SharedConfig;
use crate::signing::SigningContext;
use crate::slot_clock::SlotClock;
use crate::sync_committee::SyncCommitteeService;

/// Everything the client is configured with at startup.
#[derive(Debug, Clone)]
pub struct ValidatorConfig {
    pub beacon_nodes: Vec<String>,
    pub validators_dir: PathBuf,
    pub secrets_dir: PathBuf,
    pub metrics: std::net::SocketAddr,
    /// The graffiti every validator proposes with unless the keymanager API
    /// gives it its own. Consensus never reads it. An ethlambda beacon node
    /// appends both clients' versions to it; other nodes follow their own
    /// policy.
    pub graffiti: Bytes32,
    /// Where execution-layer block rewards should be paid, for every validator
    /// the keymanager API gives no address of its own.
    ///
    /// `None` when the operator named no address, in which case the beacon node
    /// picks one for those validators, and it will not be the operator's.
    pub suggested_fee_recipient: Option<ExecutionAddress>,
    /// Bind address for the keymanager API. `None` when `--enable-keymanager`
    /// was not passed, in which case it is never spawned.
    pub keymanager: Option<std::net::SocketAddr>,
    /// `--keymanager-token-file`: the file the keymanager API's bearer token
    /// is read from, never written. `None` reads, or on first start generates,
    /// [`http_api::API_TOKEN_FILE`] in `validators_dir`.
    pub keymanager_token_file: Option<PathBuf>,
    /// `--web3signer-url`: the remote signer a key imported through
    /// `POST /eth/v1/remotekeys` without a `url` of its own is assigned to.
    /// Keys the definitions file already names a signer for need no default.
    pub web3signer_url: Option<String>,
    /// The gas limit every validator targets unless the keymanager API gives
    /// it its own: its builder registrations' before gloas, and its proposer
    /// preferences' from gloas, which is what the node's own payload is built
    /// toward.
    pub gas_limit: u64,
    /// Builder proposals, or `None` when `--builder-proposals` is off.
    pub builder: Option<BuilderProposals>,
    /// The smallest p2p bid, in gwei, a gloas block may be built on
    /// (`produceBlockV4`'s `min_bid`). `0` takes any bid that wins on value.
    ///
    /// Not part of [`BuilderProposals`]: without them a node whose local build
    /// fails may still build on a pooled bid, and this floor applies to that
    /// bid too.
    pub builder_min_bid: u64,
    /// Register keys that have no slashing-protection record as never having
    /// signed, instead of refusing to start. See
    /// [`slashing_protection::SlashingProtection::open`].
    pub init_slashing_protection: bool,
    /// Withhold every key's attestations and blocks until the beacon network
    /// has seen it stay silent for a full epoch, and stop if it does not. See
    /// [`doppelganger`].
    pub doppelganger_protection: bool,
    /// `--broadcast`: the signed messages sent to every beacon node rather
    /// than the first that accepts them. See [`beacon_node::fallback`].
    pub broadcast: beacon_node::fallback::Broadcast,
    /// Read the beacon nodes' event streams, so attestations and sync
    /// committee messages go out when the slot's block arrives and payload
    /// votes when its payload does, rather than only at their deadlines. See
    /// [`head_monitor`].
    pub event_stream: bool,
}

/// Builder proposals: register each validator with the beacon node's builder
/// and accept a blinded block when the builder's bid wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuilderProposals {
    /// The `builder_boost_factor` sent with every block request (in the query
    /// before gloas, in `produceBlockV4`'s body from gloas): 100 compares the
    /// bid and the local payload as they are; `u64::MAX` takes the builder
    /// whenever there is a bid.
    pub boost_factor: u64,
}

/// Run the validator client until the future `stop` returns resolves, or
/// until something stops it with an error.
///
/// `stop` is called once, when startup is done: after the keystores are
/// decrypted and the slashing-protection record is open, and before the
/// keymanager serves its first request or any duty runs. A caller may read
/// that call as the end of startup: the binary ends the process at once on a
/// signal that comes before it, since nothing is signed and no keymanager
/// request is in flight yet. A client that stops before then drops `stop`
/// uncalled.
///
/// The future it returns resolves with the name of what asked the client to
/// stop, a signal in the binary. Once it does the client starts no other
/// slot, lets the work in flight finish, and returns `Ok(())` (see
/// [`run_until_stopped`]). Every other way the client stops is an `Err`.
pub async fn run<S>(config: ValidatorConfig, stop: impl FnOnce() -> S) -> Result<()>
where
    S: Future<Output = &'static str>,
{
    metrics::init();

    // Said at startup, where an operator reads it: an operator
    // who never sets this proposes blocks that pay their execution-layer
    // rewards to whatever address their beacon node was configured with, which
    // on a default configuration is nobody useful. It is silent money, and
    // nothing later in a normal run mentions it again.
    if config.suggested_fee_recipient.is_none() {
        warn!(
            "No --suggested-fee-recipient was set. Any block this client proposes will pay its \
             execution-layer rewards to an address chosen by the beacon node, which is very \
             unlikely to be yours, unless that validator is given its own address through the \
             keymanager API."
        );
    }
    // Accepted, as every other client's flag accepts it, but said loudly:
    // nobody holds the zero address's key, so what it is paid is burned, and
    // a builder registration or proposer preference signs that into a
    // commitment the builder honours. Only the default can be zero, since the
    // keymanager API refuses it for a single validator.
    if config.suggested_fee_recipient == Some(ExecutionAddress::ZERO) {
        error!(
            "--suggested-fee-recipient is the zero address. Every validator without its own \
             address burns its execution-layer rewards, and builder registrations and proposer \
             preferences sign that address for the builder to pay."
        );
    }
    let settings = Arc::new(
        ProposerSettings::new(config.graffiti, config.suggested_fee_recipient)
            .with_default_gas_limit(config.gas_limit),
    );

    // The directory's lock first, before any key is read: held from here,
    // nothing another process does to the directory can get between what
    // this one loads and what it signs with. See `SlashingProtection::lock`.
    let record_lock = slashing_protection::SlashingProtection::lock(&config.validators_dir)?;

    let discovered = keys::definitions::ValidatorDefinitions::discover_if_absent(
        &config.validators_dir,
        &config.secrets_dir,
    )?;
    if discovered > 0 {
        info!(
            count = discovered,
            "No validator definitions file; wrote one from the keystores found in the validators \
             directory"
        );
    }
    // Checked for shape at startup rather than at the first import that
    // leans on it, which could be days later.
    if let Some(url) = &config.web3signer_url {
        keys::Web3Signer::normalize_url(url)?;
    }

    // Read once, for the settings its entries carry and then for the keys.
    let definitions = keys::ValidatorDefinitions::open(&config.validators_dir)?;
    // The per-validator fee recipients, graffiti and gas limits the keymanager
    // persisted, or the operator wrote by hand. A malformed one is fatal, as a
    // bad keystore is: a validator paying an address the operator did not
    // mean is worse than a refused start. Ahead of the keys, so that refusal
    // comes before every keystore has been decrypted rather than after.
    let seeded = definitions.seed_overrides(&settings)?;
    if seeded > 0 {
        info!(
            count = seeded,
            "Loaded per-validator proposer settings from the definitions file"
        );
    }
    let store = ValidatorStore::from_definitions(&config.validators_dir, &definitions)?;
    if store.is_empty() {
        warn!("No validators loaded; the client will idle");
    }
    metrics::set_validators_loaded(store.len() as u64);
    // The keymanager mutates this at runtime while the duty loop reads it, so
    // it is shared rather than owned outright from here on.
    let store = Arc::new(RwLock::new(store));

    // Bound before any beacon-node network call, deliberately: a validator
    // that cannot reach its beacon node waits for one at startup, for as long
    // as it takes (see `FallbackBeaconNode::establish`), and meanwhile it must
    // expose `/health` and `/metrics`, so an operator can tell "still
    // starting, node unreachable" apart from "crashed with no HTTP surface at
    // all".
    let listener = tokio::net::TcpListener::bind(config.metrics)
        .await
        .map_err(|source| Error::Io {
            path: config.metrics.to_string(),
            source,
        })?;
    info!(address = %config.metrics, "Metrics listening");
    tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, metrics::router()).await {
            error!(%err, "Metrics server stopped");
        }
    });

    let nodes = config
        .beacon_nodes
        .iter()
        .map(HttpBeaconNode::new)
        .collect::<Result<Vec<_>>>()?;
    let beacon_node = Arc::new(FallbackBeaconNode::new(nodes).with_broadcast(config.broadcast));

    // The chain the client runs on is the first node's that answers, waiting
    // for one while none does; every other node is checked against it, and a
    // node on another chain is not used. The schedule is the reference's: a
    // fork another node schedules is taken by the background check once every
    // node answering schedules it alike. See `chain_check`.
    let ChainId {
        genesis,
        config: spec,
    } = beacon_node
        .establish(|reference| {
            // Right after the reference is chosen and before anything reads a
            // preset value, which the epoch below does.
            require_unread_preset()?;
            adopt_preset(&reference.config)?;
            Ok(chain_check::current_epoch_of(reference))
        })
        .await?;
    info!(
        preset = spec.preset_base.as_str(),
        genesis_time = genesis.genesis_time,
        slot_duration_ms = spec.slot_duration_ms,
        attestation_due_bps = spec.attestation_due_bps,
        aggregate_due_bps = spec.aggregate_due_bps,
        validators = store.read().await.len(),
        gas_limit = config.gas_limit,
        "Validator client starting"
    );

    // One handle for the slot clock and every signing domain, so the chain
    // check moves them together when the network schedules a fork.
    let shared_config = SharedConfig::new(spec.clone());
    let clock = SlotClock::from_shared(genesis.genesis_time, shared_config.clone());

    // After the beacon node names the chain, which the record must belong to,
    // and before any service that signs exists. Every loaded key must already
    // have a record, unless the operator said otherwise. That includes a key
    // a remote signer holds: the signer keeps its own record, and this one is
    // kept as well, so a key is covered whichever of the two it meets first.
    let keys = store.read().await.pubkeys();
    let protection = slashing_protection::SlashingProtection::open_locked(
        record_lock,
        &config.validators_dir,
        genesis.genesis_validators_root,
        &keys,
        config.init_slashing_protection,
    )?;
    info!(
        validators = protection.len(),
        path = %protection.path().map(|path| path.display().to_string()).unwrap_or_default(),
        "Slashing protection loaded"
    );
    let protection = slashing_protection::SharedProtection::new(protection);

    // Every key loaded is registered before anything that signs exists, in
    // the epoch the clock is in now, so this process's own activity before a
    // restart within the epoch is never mistaken for a doppelganger.
    let doppelganger = config.doppelganger_protection.then(|| {
        let doppelganger = Arc::new(doppelganger::Doppelganger::new());
        // Epoch 0 before genesis: a key registered then signs at once.
        let epoch = clock.current_epoch().unwrap_or(0);
        doppelganger.register_all(&keys, epoch);
        let withheld = doppelganger.detecting();
        if withheld > 0 {
            info!(
                validators = withheld,
                %epoch,
                earliest_signing_epoch = epoch + doppelganger::DETECTION_EPOCHS + 2,
                "Doppelganger protection on: no attestation or block is signed until the beacon \
                 network has seen none of these validators act for a full epoch"
            );
        } else if !keys.is_empty() {
            info!(
                "Doppelganger protection on; the chain is at genesis, so the loaded validators \
                 sign at once"
            );
        }
        doppelganger
    });

    let mut context = SigningContext::with_shared(shared_config, genesis.genesis_validators_root);
    if let Some(doppelganger) = &doppelganger {
        context = context.with_doppelganger(doppelganger.clone());
    }
    let context = Arc::new(context);

    // Every node's stream, read until `run` returns and `_monitor` with it.
    let (_monitor, triggers) =
        head_monitor::start(&config.beacon_nodes, &context, config.event_stream)?;

    let mut duties = DutiesService::new(beacon_node.clone(), Vec::new());
    let attestation =
        AttestationService::new(beacon_node.clone(), context.clone(), protection.clone());
    let aggregation = AggregationService::new(beacon_node.clone(), context.clone());
    let payload_attestation = PayloadAttestationService::new(beacon_node.clone(), context.clone());
    let sync_committee = SyncCommitteeService::new(beacon_node.clone(), context.clone());

    // Unconditional, as Lighthouse does: from gloas the preferences carry the
    // fee recipient of every proposal, builders or not. See the module doc.
    let preferences = Arc::new(
        PreferencesService::new(beacon_node.clone(), context.clone(), settings.clone())
            .with_clock(clock.clone()),
    );

    // The detached tasks a shutdown signal waits for: a signed blinded
    // block's publish. See `run_until_stopped`.
    let tasks = TaskTracker::new();
    let proposal = ProposalService::new(
        beacon_node.clone(),
        context.clone(),
        settings.clone(),
        protection.clone(),
        config.builder.map(|builder| builder.boost_factor),
    )
    .with_clock(clock.clone())
    .with_builder_min_bid(config.builder_min_bid)
    .with_preferences(preferences.clone())
    .with_tasks(tasks.clone());
    // The proposer preparations' per-slot re-send. The epoch's own send is
    // `refresh_epoch`'s.
    let preparations = Arc::new(Preparations::new(beacon_node.clone(), settings.clone()));
    let registration = config.builder.map(|builder| {
        info!(
            boost_factor = builder.boost_factor,
            min_bid_gwei = config.builder_min_bid,
            "Builder proposals on: registering validators and accepting blinded blocks"
        );
        Arc::new(RegistrationService::new(
            beacon_node.clone(),
            context.clone(),
            settings.clone(),
        ))
    });
    // Logged above when builder proposals are on.
    if config.builder.is_none() && config.builder_min_bid > 0 {
        info!(
            min_bid_gwei = config.builder_min_bid,
            "Builder proposals off; --builder-min-bid still applies to a p2p bid taken when the local \
             payload cannot be built"
        );
    }

    // Startup is done: nothing is signed yet, and the keymanager is not
    // serving. From here a signal stops the client by draining rather than
    // ending the process (see this function's doc), so this comes before the
    // keymanager can take a request that ending the process would cut, such
    // as an import between saving its keys and registering them. A signal
    // that arrives before `run_until_stopped` first polls the future is held
    // for it.
    let stop = stop();

    // Cancelled when the client stops, whatever stopped it: the keymanager
    // server then stops accepting requests and finishes the ones in flight,
    // and `run` waits for it before returning. On a shutdown signal it is
    // cancelled first, and the duty loop then starts no other slot.
    let shutdown = CancellationToken::new();
    // The per-node chain check and the schedule follower, on a task of their
    // own so a node that hangs until its timeout never delays a duty. Its
    // handle is kept: the duties race it below, as they do the doppelganger
    // check.
    let mut chain_check = tokio::spawn(chain_check::run(
        beacon_node.clone(),
        genesis,
        clock.clone(),
        context.clone(),
        shutdown.clone(),
    ));
    let mut keymanager = None;
    if let Some(address) = config.keymanager {
        let token_file = config.keymanager_token_file.as_deref();
        let token = http_api::load_token(&config.validators_dir, token_file)?;
        let context = http_api::KeymanagerContext {
            store: store.clone(),
            settings: settings.clone(),
            validators_dir: config.validators_dir.clone(),
            secrets_dir: config.secrets_dir.clone(),
            definitions_lock: Arc::new(Mutex::new(())),
            default_remote_signer: config.web3signer_url.clone(),
            beacon_node: beacon_node.clone(),
            signing: context.clone(),
            clock: clock.clone(),
            definitions_unflushed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            protection: protection.clone(),
        };
        let router = http_api::router(context, token);
        let listener = tokio::net::TcpListener::bind(address)
            .await
            .map_err(|source| Error::Io {
                path: address.to_string(),
                source,
            })?;
        info!(%address, "Keymanager API listening");
        let shutdown = shutdown.clone();
        keymanager = Some(tokio::spawn(async move {
            if let Err(err) = http_api::serve(listener, router, shutdown).await {
                error!(%err, "Keymanager API stopped");
            }
        }));
    } else if let Some(path) = &config.keymanager_token_file {
        // Accepted, like `--keymanager-port`, but worth saying: tooling holding
        // that token would otherwise find nothing listening and no reason why.
        warn!(
            path = %path.display(),
            "--keymanager-token-file is set without --enable-keymanager; the keymanager API is off and the file is not read"
        );
    }

    // Every beacon node's sync status, probed a sixth of a slot ahead of each
    // boundary on its own clock: the duty loop reads it at the boundary and
    // never waits for it. Aborted once the client stops. See
    // `beacon_node::health`.
    //
    // It loops for the life of the client, so it ends only by panicking. The
    // duties then go on as before the check existed (every slot signs, and
    // requests walk the nodes in command-line order), which is logged here
    // rather than left to pass unnoticed.
    let probes = tokio::spawn(crate::beacon_node::health::run(
        beacon_node.clone(),
        clock.clone(),
    ));
    let stop_probes = probes.abort_handle();
    tokio::spawn(async move {
        let ended = probes.await;
        if !ended
            .as_ref()
            .is_err_and(tokio::task::JoinError::is_cancelled)
        {
            let reason = match ended {
                Err(err) => err.to_string(),
                Ok(()) => "its task returned".to_string(),
            };
            error!(
                %reason,
                "The beacon node sync probe stopped; no slot is withheld for a syncing node from \
                 now on, until the validator client is restarted"
            );
        }
    });

    // The check runs on its own clock, three quarters into each slot, so a
    // slow duty never delays it and a slow liveness query never delays a
    // duty. Its handle is kept: the duties race it below, and it is aborted
    // once the client stops.
    let mut check = doppelganger.as_ref().map(|doppelganger| {
        tokio::spawn(doppelganger::run(
            doppelganger.clone(),
            beacon_node.clone(),
            store.clone(),
            clock.clone(),
        ))
    });

    // The duty loop, as a future that ends with the error that stopped it, or
    // with `Ok` between two slots once `shutdown` is cancelled. Not awaited
    // here: `run_until_stopped` races it against the slashing-protection
    // record becoming unusable and against `stop`.
    let duty_loop = async {
        let mut last_epoch: Option<u64> = None;
        // The slot whose duties were last attempted, so an overrunning slot does
        // not cost the next one as well. See `SlotClock::next_slot_to_serve`.
        let mut served: Option<u64> = None;
        // The validators the last refresh resolved, whose proposer
        // preparations are re-sent every slot (see `Preparations`).
        let mut resolved: Arc<Vec<ValidatorEntry>> = Arc::default();
        // Whether the last refresh attempt found the node syncing or
        // optimistic, until one gets through (see `settle_refresh`).
        let mut node_syncing = false;
        // The beacon node's readmission count, and the schedule's generation,
        // as of the last slot, so a node the chain check let back in since
        // then is sent what it missed, and a schedule it swapped gets the
        // subnet subscriptions sent again.
        let mut readmissions_seen = beacon_node.readmissions();
        let mut schedule_seen = context.schedule_generation();

        loop {
            // One wake per slot, at the slot boundary, rather than one at the
            // attester offset.
            //
            // A slot has more than one thing due in it and they are due at
            // different points: a proposer publishes at the boundary, every
            // attester votes one third in. A loop woken only at the attester
            // offset can never propose, because by the time it runs the slot it
            // would be proposing for is already a third gone.
            //
            // Waking at the boundary and sleeping further in reaches both. The
            // epoch refresh no longer stands between the two (see below).
            let (slot, delay) = clock.next_slot_to_serve(served, SystemTime::now());
            // The one place a shutdown is taken: between slots, so a slot
            // that has started runs to its end, which `run_until_stopped`
            // bounds. Biased, since a slot that overran leaves no delay
            // before the next one, and that one must not start either.
            tokio::select! {
                biased;
                () = shutdown.cancelled() => return Ok(()),
                () = tokio::time::sleep(delay) => {}
            }
            served = Some(slot);

            let epoch = clock.epoch_of(slot);
            let refresh_due = last_epoch != Some(epoch);

            // The slot's sync check, from the probe taken ahead of this
            // boundary. A slot it withholds signs nothing and skips the epoch
            // refresh, which the next slot that passes tries again. Only the
            // fee recipient re-send goes on, since it signs nothing and a node
            // restarted mid-sync must be prepared before its first proposal.
            // Ahead of the readmission read below, so a node let back in
            // during a withheld slot is still sent what it missed at the next
            // slot that passes.
            if !crate::beacon_node::health::slot_signs(beacon_node.health(), slot) {
                preparations.after_slot(slot, &resolved, &store);
                continue;
            }

            // Read before the refresh below, so a node let back in, or a
            // schedule swapped, while it runs is seen at the next slot rather
            // than taken as covered by sends the refresh made before it.
            let readmissions = beacon_node.readmissions();
            let readmitted = readmissions != readmissions_seen;
            readmissions_seen = readmissions;
            let schedule = context.schedule_generation();
            let rescheduled = schedule != schedule_seen;
            schedule_seen = schedule;

            // Snapshot the pubkeys and let the guard drop right here, before
            // `refresh_epoch`'s awaits (the duties fetches, a validator
            // lookup). Passing the guard itself in used to extend it
            // across that whole call, because `&*store.read().await` as a match
            // scrutinee has its temporary lifetime extended to the entire
            // match. Holding a read lock that long lets the keymanager's write
            // lock (`http_api::keystores::import`, held across slow EIP-2335
            // derivation) queue ahead of it, and since `tokio::sync::RwLock` is
            // write-preferring, every read after that point, including this one
            // next epoch, would starve until the import finished.
            let pubkeys = if refresh_due {
                store.read().await.pubkeys()
            } else {
                Vec::new()
            };

            // Only what the slot's block cannot go without, ahead of it: the
            // whole refresh when nothing held says who acts this epoch (the
            // first slot served, or a lookahead that failed), and otherwise at
            // most this epoch's proposers when none are held. From fulu they
            // are fetched an epoch ahead, so an epoch's first slot normally
            // proposes with no request in front of its block. See
            // `ahead_of_block`.
            let early = ahead_of_block(
                &beacon_node,
                &mut duties,
                &pubkeys,
                &clock,
                slot,
                refresh_due,
                &settings,
                &context,
            )
            .await;
            // The refresh still owed this slot: due, and not run above.
            let defer_refresh = refresh_due && early.is_none();
            // What a refresh leaves owing once the slot's block is out.
            let mut owed = None;
            if let Some(outcome) = early {
                let settled = settle_refresh(
                    epoch,
                    outcome,
                    &mut last_epoch,
                    &mut resolved,
                    &mut node_syncing,
                );
                match settled {
                    Ok(settled) => owed = settled,
                    Err(err) => return Err(err),
                }
            }

            // A node the chain check let back in since the last slot was
            // skipped by every send before that: it holds none of the epoch's
            // subnet subscriptions, sync committee subscriptions or builder
            // registrations, and an aggregate or a contribution it is failed
            // over to for needs the votes those subnets carry. All three go to
            // every usable node again, after the block like the refresh's own;
            // a node that has them already takes them again. What a refresh
            // run ahead of the block this slot sends is not sent twice, and
            // before any refresh got through there is nothing held to send. A
            // refresh deferred past the block can still send its own after
            // these, which only repeats them.
            //
            // A schedule the chain check swapped resends the subnet
            // subscriptions too: each one's `is_aggregator` came from a
            // selection proof under the old schedule's domain, and a fork it
            // moved can change which validators aggregate.
            let owed_moved = owed.as_ref().is_some_and(|owed: &Refreshed| owed.moved);
            let resubscribe = (readmitted || rescheduled) && last_epoch.is_some() && !owed_moved;
            let readmission = (readmitted && last_epoch.is_some() && owed.is_none()).then(|| {
                let registrable = resolved
                    .iter()
                    .filter(|entry| is_registrable(&entry.status))
                    .map(|entry| entry.pubkey)
                    .collect::<Vec<_>>();
                (registrable, sync_subscriptions_owed(&duties, epoch))
            });

            // A block is due now, at the boundary this iteration woke on.
            //
            // Cloned out of `duties` so the borrow ends before the await: the duty
            // is three small fields, and holding a borrow of the schedule across
            // the proposal would stop the next epoch's refresh from replacing it.
            //
            // Not while the last refresh attempt found the node syncing or
            // optimistic: a block must not be built on a head it has not
            // validated. The schedule can be held regardless, prefetched a
            // whole epoch ahead from fulu, where a refresh that checked the
            // node first used to be the only source of an epoch's proposers.
            // The slot's own sync check above, from the probe taken ahead of
            // the boundary, already withheld this slot if every node that
            // answered was syncing or optimistic; this is the backstop for a
            // node that refused the last refresh's duties fetch as syncing.
            if let Some(duty) = duties.proposer_at_slot(slot, epoch).cloned() {
                if node_syncing {
                    warn!(
                        %slot,
                        validator = duty.validator_index,
                        "Not proposing: the beacon node was syncing or optimistic at the last \
                         duty refresh"
                    );
                } else if doppelganger_cleared(&context, &duty.pubkey) {
                    propose(&proposal, &clock, slot, &duty, &store).await;
                } else {
                    warn!(
                        %slot,
                        validator = duty.validator_index,
                        "Not proposing: doppelganger protection has not cleared this validator yet"
                    );
                }
            }

            // Right after the proposal and ahead of the slot's other duties: the
            // preferences for the slots after this one must be out before those
            // slots start (gossip IGNOREs a started slot), and the poll's v2 duties
            // fetch for the next epoch can make the node advance a state, which
            // should not compete with it producing this slot's block. Off the slot
            // loop, since it is single-flight and a slow node must not delay this
            // slot's duties.
            tokio::spawn(preferences.clone().poll(slot, store.clone()));

            // What a refresh run ahead of the block left owing, now that the
            // block is out. See `send_owed`.
            if let Some(owed) = owed {
                send_owed(
                    owed,
                    epoch,
                    &beacon_node,
                    &duties,
                    &store,
                    &context,
                    &registration,
                );
            }
            // What a node let back in, or a swapped schedule, left owing (see
            // above), now that the block is out.
            if resubscribe {
                spawn_subscriptions(epoch, &beacon_node, &duties, &store, &context);
            }
            if let Some((registrable, sync_owed)) = readmission {
                let node = beacon_node.clone();
                tokio::spawn(async move { send_sync_subscriptions(&node, &sync_owed).await });
                if let Some(registration) = &registration {
                    let registration = registration.clone();
                    let store = store.clone();
                    tokio::spawn(registration.register_all_again(epoch, registrable, store));
                }
            }

            // This epoch's payload committee schedule, while none is held:
            // the gloas fork epoch's cannot be fetched before the fork (see
            // `refresh_ptc`), and any other epoch's lookahead can have failed.
            // A single request, bounded by the first of the slot's own duties,
            // so it delays none of them, and ahead of the committee lookup
            // below so this slot's vote is not lost to it.
            let budget = clock.until_first_slot_duty(slot, SystemTime::now());
            retry_missing_ptc(&mut duties, epoch, budget, &context).await;

            // Attesting and aggregating both start from these, so a key
            // doppelganger protection still withholds does neither; its sync
            // committee and payload committee duties go on (see
            // `doppelganger`). Read from the schedule held now, which the
            // previous epoch's lookahead filled for an epoch's first slot, so
            // they need nothing from the refresh below. That lookahead was
            // fetched at the previous epoch's first slot, one slot after the
            // block it depends on, so a one-slot reorg of a late block there
            // leaves it stale. From fulu `follow_dependent_roots` refetches it
            // within the previous epoch; before fulu this slot acts on it, and
            // the refresh below corrects it from the next slot only.
            let slot_duties = withhold_uncleared(&context, slot, duties.at_slot(slot, epoch));
            let committee = duties.ptc_at_slot(slot, epoch);
            let sync_duties = duties.sync_at_slot(slot);

            // The epoch's refresh, when it is owed and did not run ahead of
            // the block: after the block, beside the slot's duties rather than
            // in front of them, and bounded by the end of the slot so a slow
            // node holds the loop for one slot at most. A refresh cut off there
            // is retried at the next slot, as a failed one is.
            //
            // Cut off too once the client is stopping: the schedule is for
            // slots it will not serve, and the refresh could use up the stop's
            // wait for nothing (see `run_until_stopped`), while the slot's own
            // duties beside it run to their end.
            let refresh = async {
                if !defer_refresh {
                    return None;
                }
                let budget = clock.remaining_in(slot, SystemTime::now());
                let refreshed = bounded_refresh(
                    &beacon_node,
                    &mut duties,
                    &pubkeys,
                    slot,
                    epoch,
                    &settings,
                    &context,
                    budget,
                );
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => None,
                    outcome = refreshed => Some(outcome),
                }
            };
            let slot_work = async {
                // The rest of the way to the first of the slot's remaining
                // duties: the attester offset, or the sync committee offset
                // when the network puts it earlier, or the slot's block (or
                // its payload) when a beacon node reports it first. Zero if
                // the proposal above already ran past it, in which case the
                // duty is late rather than skipped. Each branch of
                // `serve_slot_duties` waits for its own trigger.
                let first_duty = clock.until_first_slot_duty(slot, SystemTime::now());
                triggers.report_within(slot, first_duty).await;
                serve_slot_duties(
                    &attestation,
                    &aggregation,
                    &payload_attestation,
                    &sync_committee,
                    &triggers,
                    &clock,
                    slot,
                    &slot_duties,
                    &committee,
                    &sync_duties,
                    &store,
                )
                .await;
            };
            let (deferred, ()) = tokio::join!(refresh, slot_work);
            if let Some(outcome) = deferred {
                let settled = settle_refresh(
                    epoch,
                    outcome,
                    &mut last_epoch,
                    &mut resolved,
                    &mut node_syncing,
                );
                match settled {
                    Ok(Some(owed)) => {
                        send_owed(
                            owed,
                            epoch,
                            &beacon_node,
                            &duties,
                            &store,
                            &context,
                            &registration,
                        );
                    }
                    Ok(None) => {}
                    Err(err) => return Err(err),
                }
            }

            // Off the slot loop, like the epoch's full send: a keymanager change
            // to a fee recipient or gas limit reaches the builder within a slot,
            // and a slow node cannot delay the next slot's duties.
            if let Some(registration) = &registration {
                tokio::spawn(registration.clone().register_changed(epoch, store.clone()));
            }

            // The proposer preparations again, for a beacon node that restarted
            // since the refresh sent them and so builds for its fallback fee
            // recipient (the zero address without one) until it hears from
            // this client. Once the slot's duties are done, so they reach the
            // node ahead of the next slot's proposal rather than racing this
            // one's: on the slot's block or a third of the way in on a slot
            // with no duties, after the aggregation or the payload vote on one
            // with them. Off the slot loop like the sends above. The refresh's
            // slot too, although its refresh sent them: see `Preparations`.
            preparations.after_slot(slot, &resolved, &store);

            // Whether a reorg moved a held schedule since it was fetched, so
            // the next slot's duties run on the chain the node follows now.
            // After the slot's duties and bounded by the slot's end, so it
            // delays none of them, and after the sends above, so a slow node
            // cannot hold them to the slot's end either. Not on a slot whose
            // refresh was due: that refresh compared every root itself, or
            // failed and runs again. Not once the client is stopping: the
            // schedule is for slots it will not serve, and the refetch could
            // use up the stop's wait for nothing.
            if !refresh_due && !shutdown.is_cancelled() {
                let budget = clock.remaining_in(slot, SystemTime::now());
                if follow_dependent_roots(&mut duties, epoch, budget, &context.config()).await {
                    metrics::set_duties_held(duties.all().len() as u64);
                    spawn_subscriptions(epoch, &beacon_node, &duties, &store, &context);
                }
            }
        }
    };

    // A doppelganger stops the duties where they stand, as an unusable record
    // does: what is left of them signs nothing slashable anyway (see
    // `Doppelganger::allows_signing`), and the operator has to find the
    // other client before this one runs again.
    //
    // The check's task ending stops them too. It loops for the life of the
    // client, so it ends only by panicking, which would leave every key it
    // had not cleared withheld for good with nothing to say why; stopping
    // hands the supervisor the restart, as an unusable record does.
    let doppelganger_watch = async {
        let (Some(doppelganger), Some(check)) = (&doppelganger, &mut check) else {
            return std::future::pending().await;
        };
        tokio::select! {
            // A sighting is reported as one even when the check's task ends
            // in the same poll.
            biased;
            () = doppelganger.detected() => {
                let validators = doppelganger
                    .sightings()
                    .iter()
                    .map(|sighting| sighting.index)
                    .collect();
                Err(Error::DoppelgangerDetected { validators })
            }
            ended = check => {
                let reason = match ended {
                    Err(err) => err.to_string(),
                    Ok(()) => "its task returned".to_string(),
                };
                let err = Error::DoppelgangerCheckStopped { reason };
                error!(%err, "Stopping so the validator client can be restarted");
                Err(err)
            }
        }
    };
    // The chain check's task ending stops them for the same reason. It runs
    // until `shutdown`, so it ends before that only by panicking. Left
    // running without it, the duties would go on with every node it took out
    // still out, none let back in, and no later fork followed, so the client
    // would stop signing valid messages at the next fork with nothing to say
    // why. A shutdown signal cancels `shutdown` before the duties have
    // stopped, and the check returning then is that stop, not a failure: the
    // slot in flight still runs to its end (see `run_until_stopped`).
    let chain_check_ended = async {
        let ended = (&mut chain_check).await;
        if ended.is_ok() && shutdown.is_cancelled() {
            return std::future::pending().await;
        }
        let reason = match ended {
            Err(err) => err.to_string(),
            Ok(()) => "its task returned".to_string(),
        };
        let err = Error::ChainCheckStopped { reason };
        error!(%err, "Stopping so the validator client can be restarted");
        Err(err)
    };
    let duties = async {
        tokio::select! {
            biased;
            stopped = doppelganger_watch => stopped,
            stopped = chain_check_ended => stopped,
            stopped = duty_loop => stopped,
        }
    };

    let stopped = run_until_stopped(
        duties,
        &protection,
        stop,
        shutdown.clone(),
        keymanager,
        &tasks,
    )
    .await;
    // Whatever stopped the client, the check and the probe stop with it rather
    // than polling the beacon node for a runtime that outlives `run`.
    if let Some(check) = check {
        check.abort();
    }
    stop_probes.abort();
    chain_check.abort();
    stopped
}

/// Whether doppelganger protection lets the validator a duty names act on
/// it. A pubkey that does not parse is not cleared: with the protection on,
/// a key it cannot name is a key it cannot vouch for.
fn doppelganger_cleared(context: &SigningContext, pubkey: &str) -> bool {
    context.doppelganger().is_none()
        || crate::beacon_node::dto::parse_pubkey(pubkey)
            .is_ok_and(|pubkey| context.doppelganger_allows(&pubkey))
}

/// `duties`, less those of validators doppelganger protection has not
/// cleared: dropped before the attestation service records or fetches
/// anything for them.
fn withhold_uncleared(
    context: &SigningContext,
    slot: ethlambda_types::beacon::primitives::Slot,
    duties: Vec<crate::beacon_node::dto::AttesterDutyDto>,
) -> Vec<crate::beacon_node::dto::AttesterDutyDto> {
    if context.doppelganger().is_none() {
        return duties;
    }
    let before = duties.len();
    let cleared: Vec<_> = duties
        .into_iter()
        .filter(|duty| doppelganger_cleared(context, &duty.pubkey))
        .collect();
    if cleared.len() < before {
        tracing::debug!(
            %slot,
            withheld = before - cleared.len(),
            "Attester duties withheld by doppelganger protection"
        );
    }
    cleared
}

/// How long the keymanager gets to finish its requests in flight once the
/// client is stopping.
///
/// Generous on purpose. An import decrypts every keystore of its batch before
/// it registers any, tens of seconds for a full one, and cut short between
/// saving its keys and registering them it leaves keys the next start
/// refuses. Nothing waits this long unless a request really is in flight, and
/// one that never ends must not keep a stopped client from being restarted.
const KEYMANAGER_DRAIN: std::time::Duration = std::time::Duration::from_secs(60);

/// How long a shutdown signal lets the work in flight run before the client
/// stops without it: the slot that has started, and a signed blinded block's
/// publish.
///
/// Every duty in a slot is bounded by the slot's end, and a blinded publish by
/// the HTTP client's 8 s request timeout, but a 12 s slot outlasts the 10 s
/// `docker stop` waits before it kills the container, and an epoch refresh is
/// bounded by neither. 8 s is what Prysm's validator client waits. On a 12 s
/// slot it covers the proposal, which must be out by the attester offset, and
/// the slot's attestations, and cuts at most the duties due two thirds of the
/// way in or later: aggregates, sync committee contributions and the payload
/// timeliness vote. On a shorter slot the slot ends first. Cutting any duty is
/// as safe as abandoning it at its own deadline: a block or attestation is
/// recorded before it is signed, and the rest is not slashable.
const DUTY_DRAIN: std::time::Duration = std::time::Duration::from_secs(8);

/// Run `duties` until they stop on their own, the slashing-protection record
/// becomes unusable or `stop` resolves, then let the keymanager finish, and
/// say why the client stopped: `Ok(())` when `stop` stopped it, the error
/// otherwise.
///
/// # Stopping on a signal
///
/// `stop` resolving cancels `shutdown`, so the duty loop starts no other slot
/// and the keymanager takes no new request. The slot that has started runs
/// on, its proposal, gloas envelope and attestations with it, and so does the
/// publish of a signed blinded block on `tasks`. Dropping either would lose
/// what is signed and not yet out, and the restarted client cannot sign it
/// again, since the record already holds it. Both get until [`DUTY_DRAIN`]
/// after the signal, and the keymanager is then drained as below. Duties that
/// end in an error meanwhile (a doppelganger seen, say) stop the client with
/// that error.
///
/// # Stopping on an unusable record
///
/// A poisoned record signs no attestation and no block for the rest of the
/// process (see [`slashing_protection::SharedProtection`]). Carrying on would
/// leave a client that answers `/health` and does not attest, which nothing
/// that supervises it has a reason to touch; stopping hands systemd or
/// Kubernetes the restart. The duties are dropped where they stand, at once,
/// since the access that poisons the record is the one that raises the
/// signal. Dropping them is safe for the reason abandoning one at its
/// deadline is: whatever was signed was recorded first.
///
/// # The keymanager goes last
///
/// Returning from [`run`] drops the runtime, and a request dropped with it
/// stops at whichever await it was parked on. For an import that can be
/// between saving its keys and registering them, the one place it must not
/// stop (see [`http_api::serve`]). So the server is told to stop and waited
/// for: on a poisoned record the import's registration fails, and it takes
/// its keys off disk again before it answers.
async fn run_until_stopped(
    duties: impl Future<Output = Result<()>>,
    protection: &slashing_protection::SharedProtection,
    stop: impl Future<Output = &'static str>,
    shutdown: CancellationToken,
    keymanager: Option<JoinHandle<()>>,
    tasks: &TaskTracker,
) -> Result<()> {
    // Boxed rather than pinned in place, so the duties can be dropped once
    // the race is decided, whichever arm won, rather than held through the
    // keymanager's drain.
    let mut duties = Box::pin(duties);
    let stopped = tokio::select! {
        stopped = &mut duties => stopped,
        () = protection.unusable() => {
            let err = Error::SlashingProtectionUnusable {
                reason: "an access panicked while holding the record, so no attestation or \
                         block is signed until the validator client is restarted"
                    .to_string(),
            };
            error!(%err, "Stopping so the validator client can be restarted");
            Err(err)
        }
        signal = stop => {
            info!(signal, "Shutdown signal received, finishing the duties in flight");
            shutdown.cancel();
            tasks.close();
            let deadline = tokio::time::Instant::now() + DUTY_DRAIN;
            let finished = tokio::time::timeout_at(deadline, &mut duties).await;
            let finished = finished.inspect_err(|_| {
                warn!(
                    waited_s = DUTY_DRAIN.as_secs(),
                    "The slot in flight is still running; stopping without it"
                )
            });
            let published = tokio::time::timeout_at(deadline, tasks.wait()).await;
            let _ = published.inspect_err(|_| {
                warn!(
                    waited_s = DUTY_DRAIN.as_secs(),
                    "A blinded block's publish is still in flight; stopping without it"
                )
            });
            finished.unwrap_or(Ok(()))
        }
    };
    drop(duties);

    shutdown.cancel();
    if let Some(keymanager) = keymanager {
        match tokio::time::timeout(KEYMANAGER_DRAIN, keymanager).await {
            Ok(joined) => {
                let _ =
                    joined.inspect_err(|err| error!(%err, "Keymanager API failed while stopping"));
            }
            Err(_) => warn!(
                waited_s = KEYMANAGER_DRAIN.as_secs(),
                "Keymanager API still has a request in flight; stopping without it"
            ),
        }
    }
    stopped.inspect(|()| info!("Shutdown complete"))
}

/// Everything a slot owes after its proposal: attest and aggregate, the
/// payload timeliness committee vote, and the sync committee's work.
///
/// The parts are independent on purpose. Committee membership is drawn
/// separately from attester duties, so a client can sit on a slot's committee
/// with no attester duty in it at all, and an early return for "no attester
/// duties" would skip exactly those votes. The committee part is also gated on
/// the slot being a gloas one: before the fork there is no committee and no
/// payload to vote on.
///
/// Each part waits for its own trigger (see [`head_monitor`]): the slot's
/// block or the attester offset, its payload or three quarters into the slot,
/// the block or the sync message offset. They run side by side rather than
/// one after another, so the committee vote, which the payload can start
/// before the aggregation is due, is not held behind it. Each is bounded by
/// the end of the slot.
#[allow(clippy::too_many_arguments)]
async fn serve_slot_duties<B: BeaconNodeApi>(
    attestation: &AttestationService<B>,
    aggregation: &AggregationService<B>,
    payload_attestation: &PayloadAttestationService<B>,
    sync_committee: &SyncCommitteeService<B>,
    triggers: &DutyTriggers,
    clock: &SlotClock,
    slot: u64,
    slot_duties: &[crate::beacon_node::dto::AttesterDutyDto],
    committee: &[crate::beacon_node::dto::PtcDutyDto],
    sync_duties: &[crate::beacon_node::dto::SyncDutyDto],
    store: &RwLock<ValidatorStore>,
) {
    let attest = async {
        if !slot_duties.is_empty() {
            attest_and_aggregate(
                attestation,
                aggregation,
                triggers,
                clock,
                slot,
                slot_duties,
                store,
            )
            .await;
        }
    };
    let vote = async {
        if clock.is_gloas(slot) && !committee.is_empty() {
            payload_attest(payload_attestation, triggers, clock, slot, committee, store).await;
        }
    };
    tokio::join!(
        attest,
        vote,
        sync_committee_duty(sync_committee, triggers, clock, slot, sync_duties, store)
    );
}

/// Run one slot's sync committee duty: sign the head when the slot's block
/// arrives or at the message deadline, whichever comes first, then aggregate
/// at the contribution deadline if a root was signed.
///
/// Each half is bounded by the end of the slot, like the other duties, and
/// failures are logged and counted rather than propagated. Nothing here is
/// slashable, so abandoning a half costs only that half.
async fn sync_committee_duty<B: BeaconNodeApi>(
    service: &SyncCommitteeService<B>,
    triggers: &DutyTriggers,
    clock: &SlotClock,
    slot: u64,
    duties: &[crate::beacon_node::dto::SyncDutyDto],
    store: &RwLock<ValidatorStore>,
) {
    if duties.is_empty() {
        return;
    }
    let now = SystemTime::now();
    let (wait, budget) = (
        clock.until_sync_message(slot, now),
        clock.remaining_in(slot, now),
    );
    let messages = triggers.publish_sync_messages(service, slot, wait, duties, store);
    let root = match tokio::time::timeout(budget, messages).await {
        Ok(Ok(root)) => root,
        Ok(Err(err)) => {
            error!(%slot, %err, "Failed to publish sync committee messages for this slot");
            metrics::inc_sync_committee_failures();
            metrics::set_beacon_node_available(false);
            return;
        }
        Err(_) => {
            warn!(
                %slot,
                budget_ms = budget.as_millis() as u64,
                "Sync committee messages ran past the end of their slot and were abandoned"
            );
            metrics::inc_sync_committee_failures();
            return;
        }
    };
    let Some(root) = root else {
        return;
    };

    tokio::time::sleep(clock.until_contribution(slot, SystemTime::now())).await;
    let budget = clock.remaining_in(slot, SystemTime::now());
    match tokio::time::timeout(budget, service.aggregate(slot, root, duties, store)).await {
        Ok(Ok(_)) => {}
        Ok(Err(err)) => {
            error!(%slot, %err, "Failed to publish this slot's sync contributions");
            metrics::inc_sync_contribution_failures();
        }
        Err(_) => {
            warn!(
                %slot,
                budget_ms = budget.as_millis() as u64,
                "Sync aggregation ran past the end of its slot and was abandoned"
            );
            metrics::inc_sync_contribution_failures();
        }
    }
}

/// Run one slot's attestation duty, when the slot's block arrives or at the
/// attester offset, whichever comes first, and, when it produced data, the
/// aggregation duty that follows it at its own offset.
///
/// Split out of the loop so the loop can go on to the payload committee duty
/// whether or not this client has an attester duty in the slot.
async fn attest_and_aggregate<B: BeaconNodeApi>(
    attestation: &AttestationService<B>,
    aggregation: &AggregationService<B>,
    triggers: &DutyTriggers,
    clock: &SlotClock,
    slot: u64,
    slot_duties: &[crate::beacon_node::dto::AttesterDutyDto],
    store: &RwLock<ValidatorStore>,
) {
    // Bound the slot's work by what is left of the slot.
    //
    // Nothing else does. The per-request timeout in `HttpBeaconNode` is 8
    // seconds, failover tries each node in turn, and `attest` makes two
    // calls, so one hung node can carry a 12-second slot's duty well past
    // the slot itself and into the next one, whose duty is then late in
    // turn. An attestation that misses its slot is worth little; one that
    // also delays the next slot's is worth less than nothing.
    //
    // Dropping the future mid-flight is safe here specifically because of
    // slashing protection: it records before signing, so a duty abandoned
    // between signing and submission cannot be re-signed next slot under
    // the same target. That is the intended outcome and matches `attest`'s
    // own "do not retry within a slot" rule; the attestation is simply
    // lost.
    let now = SystemTime::now();
    let (wait, budget) = (
        clock.until_attestation(slot, now),
        clock.remaining_in(slot, now),
    );
    let attested = triggers.attest(attestation, slot, wait, slot_duties, store);
    let attempt = tokio::time::timeout(budget, attested);
    match attempt.await.unwrap_or_else(|_| {
        warn!(
            %slot,
            budget_ms = budget.as_millis() as u64,
            "Attestation duty ran past the end of its slot and was abandoned"
        );
        metrics::inc_attestation_deadline_missed();
        Err(Error::AttestationDeadline { slot })
    }) {
        // `attest` scopes its own read guard away from every await (see
        // its doc comment), so passing the shared `store` straight
        // through here holds nothing across this call.
        Ok(attested) => {
            if attested.published > 0 {
                let elapsed = SystemTime::now()
                    .duration_since(clock.start_of(slot))
                    .unwrap_or_default();
                metrics::observe_publication_delay(elapsed.as_secs_f64());
            }

            // Aggregation, for whichever of this slot's duties this client
            // was selected for.
            //
            // Reached only when the attestation duty produced data, since
            // that data is what names the aggregate to ask for. It is not
            // gated on anything having been *published*, though: an
            // aggregator collects the whole committee's votes, so the duty
            // is still owed when this client's own signatures were refused.
            if let Some(data) = attested.data {
                let delay = clock.until_aggregation(slot, SystemTime::now());
                tokio::time::sleep(delay).await;
                aggregate(aggregation, clock, slot, &data, slot_duties, store).await;
            }
        }
        Err(err) => {
            error!(%slot, %err, "Failed to publish attestations for this slot");
            metrics::inc_attestation_failures();
            // Every error `attest` can return originates from the beacon
            // node (a failed fetch, a bad or mismatched response, a
            // failed submission), so a failure here is exactly the signal
            // this gauge exists for: `refresh_epoch` only runs once an
            // epoch and would otherwise leave it reporting stale
            // availability for up to that long.
            metrics::set_beacon_node_available(false);
        }
    }
}

/// Run one slot's payload timeliness committee duty, when the slot's payload
/// and its blob data are available or three quarters into the slot,
/// whichever comes first, bounded by what is left of the slot.
///
/// The budget is the end of the slot, like the aggregation's and for the same
/// reason: this is the last duty in its slot, so the only thing past its
/// deadline is the next slot's work. A vote that arrives after its slot is
/// worthless, since the committee's attestations are only counted for the slot
/// they are about.
///
/// Abandoning it is safe: the service records per validator at signing time, so
/// a duty dropped mid-flight is lost rather than re-signed. Failures are logged
/// and counted rather than propagated, like every other duty's.
async fn payload_attest<B: BeaconNodeApi>(
    service: &PayloadAttestationService<B>,
    triggers: &DutyTriggers,
    clock: &SlotClock,
    slot: u64,
    committee: &[crate::beacon_node::dto::PtcDutyDto],
    store: &RwLock<ValidatorStore>,
) {
    let now = SystemTime::now();
    let (wait, budget) = (
        clock.until_payload_attestation(slot, now),
        clock.remaining_in(slot, now),
    );
    let votes = triggers.attest_payload(service, slot, wait, committee, store);
    let attempt = tokio::time::timeout(budget, votes);
    match attempt.await {
        Ok(Ok(_)) => {}
        Ok(Err(err)) => {
            error!(%slot, %err, "Failed to publish payload attestations for this slot");
            metrics::inc_payload_attestation_failures();
            metrics::set_beacon_node_available(false);
        }
        Err(_) => {
            warn!(
                %slot,
                budget_ms = budget.as_millis() as u64,
                "Payload attestation duty ran past the end of its slot and was abandoned"
            );
            metrics::inc_payload_attestation_failures();
        }
    }
}

/// Run one slot's aggregation, bounded by what is left of the slot.
///
/// # The budget is the end of the slot, not the attester offset
///
/// Looser than the proposal's, because the thing it competes with is different.
/// A proposal that overruns eats into this client's own attestations, which are
/// due for every validator it holds. An aggregation is already the last duty in
/// its slot, so the only thing past its deadline is the next slot's work, and
/// the same budget the attestation gets is the right one.
///
/// Abandoning it is cheap and safe. Nothing here is slashable (see
/// [`crate::aggregation`]), so a dropped future costs one aggregate and
/// nothing else, and other aggregators were selected for the same committee.
///
/// Failures are logged and counted rather than propagated, like the proposal's:
/// one slot's aggregate must not stop the client attesting for the rest of the
/// epoch.
async fn aggregate<B: BeaconNodeApi>(
    aggregation: &AggregationService<B>,
    clock: &SlotClock,
    slot: u64,
    data: &ethlambda_types::beacon::containers::shared::AttestationData,
    duties: &[crate::beacon_node::dto::AttesterDutyDto],
    store: &RwLock<ValidatorStore>,
) {
    let budget = clock.remaining_in(slot, SystemTime::now());
    let attempt = tokio::time::timeout(budget, aggregation.aggregate(slot, data, duties, store));
    match attempt.await {
        Ok(Ok(_)) => {}
        Ok(Err(err)) => {
            error!(%slot, %err, "Failed to publish this slot's aggregates");
            metrics::inc_aggregation_failures();
        }
        Err(_) => {
            warn!(
                %slot,
                budget_ms = budget.as_millis() as u64,
                "Aggregation ran past the end of its slot and was abandoned"
            );
            metrics::inc_aggregation_failures();
        }
    }
}

/// Run one slot's proposal, bounded by what is left before the attestation is
/// due.
///
/// Split out of the loop so the deadline's reasoning has somewhere to live, and
/// so the loop body stays readable with two duties in it.
///
/// # The budget is the attester offset, not the end of the slot
///
/// Deliberately tighter than the attestation's own budget. A block published
/// after the attester offset has already lost most of its value, because that
/// is the point at which attesters stop waiting for it and vote for the
/// previous head; the specification defines no block-production deadline of its
/// own, and this is the nearest thing to one that it does define. Meanwhile
/// every second spent here past that point comes straight out of this client's
/// own attestations, which are due for every validator it holds rather than for
/// the one proposing.
///
/// So: a proposal that overruns is abandoned, and the slot's attesters still
/// vote. Dropping the future mid-flight is safe for the same reason it is on
/// the attestation path, and only for that reason: `ProposalService` records
/// the slot in slashing protection before signing, so a block abandoned between
/// signing and publication cannot be signed a second time.
///
/// Failures are logged and counted rather than propagated. A proposal is one
/// slot's work; losing it must not stop the client attesting for the rest of
/// the epoch.
async fn propose<B: BeaconNodeApi + 'static>(
    proposal: &ProposalService<B>,
    clock: &SlotClock,
    slot: u64,
    duty: &crate::beacon_node::dto::ProposerDutyDto,
    store: &RwLock<ValidatorStore>,
) {
    let budget = clock.until_attestation(slot, SystemTime::now());
    let deadline = tokio::time::Instant::now() + budget;
    match proposal.propose_by(slot, duty, store, deadline).await {
        // The service took the delay when the node accepted the block: a
        // full one's before a gloas envelope's publish, a blinded one's in
        // the task that published it.
        Ok(Proposed::Full(_) | Proposed::Blinded(BlindedOutcome::Published(_))) => {}
        // Already logged at error and counted on its own series; the block
        // may well be out, so it is neither a published-in-time delay nor a
        // failure.
        Ok(Proposed::Blinded(BlindedOutcome::Unconfirmed)) => {}
        // The beacon node waits up to 5 s for the relay, which can outlast
        // this budget. Not a missed proposal: the publish goes on, on its own
        // task, which reports and counts the real outcome.
        Ok(Proposed::Blinded(BlindedOutcome::StillPublishing)) => {
            info!(
                %slot,
                validator = duty.validator_index,
                budget_ms = budget.as_millis() as u64,
                "Blinded block signed; its publish outlived the proposal budget and continues"
            );
        }
        Err(Error::ProposalDeadline { .. }) => {
            warn!(
                %slot,
                validator = duty.validator_index,
                budget_ms = budget.as_millis() as u64,
                "Block proposal ran past the point attesters stop waiting and was abandoned"
            );
            metrics::inc_block_proposal_failures();
        }
        Err(err) => {
            error!(%slot, validator = duty.validator_index, %err, "Failed to propose this slot's block");
            metrics::inc_block_proposal_failures();
        }
    }
}

/// What one epoch's [`refresh_epoch`] leaves the duty loop to do.
#[derive(Debug, Default)]
struct Refreshed {
    /// Whether the attester schedule moved, in this refresh or in an earlier
    /// attempt abandoned after it moved it (see
    /// [`DutiesService::take_attesters_moved`]). When it did, the beacon node
    /// is owed this client's subnet subscriptions, which the caller sends once
    /// the slot's block is out rather than having them sent from the refresh:
    /// each needs a selection proof, a round trip per remote key, and the
    /// refresh can run ahead of the proposal. See [`send_owed`].
    moved: bool,
    /// The pubkeys a builder registration is signed for: those the beacon
    /// node resolved to an index whose validator is pending or active (see
    /// [`is_registrable`]).
    registrable: Vec<BlsPubkey>,
    /// Every validator the beacon node resolved to an index, which the duty
    /// loop re-sends the proposer preparations of each slot until the next
    /// refresh (see [`Preparations`]).
    resolved: Vec<ValidatorEntry>,
}

/// What the duty loop runs at a slot boundary before it proposes, which is as
/// little as the slot's block can do with.
///
/// An epoch's refresh is up to a dozen requests, and the block needs one
/// thing from it: whether one of this client's validators proposes. So:
///
/// - **The whole refresh**, when it is due and the schedule held cannot say
///   who acts this epoch: no validator index resolved yet (the first slot
///   served) or no attester schedule for the epoch (its lookahead failed).
///   Returned, for the caller to settle. Not cut off at the end of the slot,
///   unlike the refresh run after a block: with nothing held there is no
///   duty for the loop to get back to, and a refresh that restarted from its
///   first request every slot could never get past a hung first node. Each
///   request is bounded by its own timeout, so the fallback does reach the
///   next node, as it did when every refresh ran this way.
/// - **This epoch's proposers alone**, when no proposer schedule is held for
///   it: before fulu, where they cannot be fetched an epoch ahead, or after a
///   prefetch that failed. Bounded by the proposal's own budget, the
///   attester offset, since a block cannot be proposed past it anyway. A
///   failure is logged, and the next slot asks again.
/// - **Nothing**, otherwise: the case at every fulu epoch's first slot, whose
///   proposers the previous epoch's refresh fetched. The refresh then runs
///   after the block (see the duty loop in [`run`]).
#[allow(clippy::too_many_arguments)]
async fn ahead_of_block<B: BeaconNodeApi>(
    beacon_node: &Arc<B>,
    duties: &mut DutiesService<B>,
    pubkeys: &[BlsPubkey],
    clock: &SlotClock,
    slot: u64,
    refresh_due: bool,
    settings: &ProposerSettings,
    context: &SigningContext,
) -> Option<Result<Refreshed>> {
    let epoch = clock.epoch_of(slot);
    let schedule_held = !duties.indices().is_empty() && duties.holds_attesters(epoch);
    if refresh_due && !schedule_held {
        let refreshed = refresh_epoch(beacon_node, duties, pubkeys, epoch, settings, context);
        return Some(refreshed.await);
    }

    if !duties.holds_proposers(epoch) && !duties.indices().is_empty() {
        let version = ProposerDutiesVersion::for_epoch(&context.config(), epoch);
        let budget = clock.until_attestation(slot, SystemTime::now());
        let fetched = tokio::time::timeout(budget, duties.refresh_proposers(epoch, version));
        match fetched.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                warn!(%slot, %err, "Proposer duties fetch failed; asking again next slot");
                metrics::set_beacon_node_available(false);
            }
            Err(_) => {
                warn!(
                    %slot,
                    budget_ms = budget.as_millis() as u64,
                    "Proposer duties fetch ran past this slot's proposal budget; asking again \
                     next slot"
                );
            }
        }
    }
    None
}

/// [`refresh_epoch`], abandoned once `budget` runs out.
///
/// Dropping it mid-way is safe: every fetch in it answers in full before it
/// changes the schedule it fetched (see [`DutiesService::refresh_around`]), so
/// an abandoned refresh leaves each schedule either refreshed or as it was,
/// never half of one. It is retried at the next slot, as a failed one is, and
/// a move it made to the attester schedule waits on the service for that
/// retry to report, so the subscriptions it owes are not lost with it.
///
/// A retry starts again from the first request. Against a first node that
/// hangs each request to its timeout, a refresh cut off every slot may never
/// complete. The epoch's own schedule stays in use meanwhile, and an epoch
/// that starts with no lookahead held refreshes ahead of its block without
/// this deadline (see [`ahead_of_block`]).
#[allow(clippy::too_many_arguments)]
async fn bounded_refresh<B: BeaconNodeApi>(
    beacon_node: &Arc<B>,
    duties: &mut DutiesService<B>,
    pubkeys: &[BlsPubkey],
    slot: u64,
    epoch: u64,
    settings: &ProposerSettings,
    context: &SigningContext,
    budget: std::time::Duration,
) -> Result<Refreshed> {
    let refreshed = refresh_epoch(beacon_node, duties, pubkeys, epoch, settings, context);
    tokio::time::timeout(budget, refreshed)
        .await
        .unwrap_or(Err(Error::DutyRefreshDeadline { epoch, slot }))
}

/// Record a refresh's outcome in the duty loop's state, and hand back what it
/// leaves owing for [`send_owed`].
///
/// One that got through marks `epoch` refreshed and replaces the validators
/// whose preparations are re-sent every slot. One that failed leaves both as
/// they were, so the held schedule stays in use and the next slot tries again.
/// Only a failure that will not fix itself is returned, to stop the client.
///
/// `node_syncing` is set by a refresh that found the node syncing or
/// optimistic and cleared by one that got through; a failure that says
/// nothing of the node's sync state leaves it. The duty loop proposes no
/// block while it is set (see [`run`]).
fn settle_refresh(
    epoch: u64,
    outcome: Result<Refreshed>,
    last_epoch: &mut Option<u64>,
    resolved: &mut Arc<Vec<ValidatorEntry>>,
    node_syncing: &mut bool,
) -> std::result::Result<Option<Refreshed>, Error> {
    match outcome {
        Ok(mut refreshed) => {
            *last_epoch = Some(epoch);
            *resolved = Arc::new(std::mem::take(&mut refreshed.resolved));
            *node_syncing = false;
            Ok(Some(refreshed))
        }
        Err(Error::BeaconNodeSyncing) => {
            warn!(
                %epoch,
                "Failed to refresh duties: the beacon node is syncing or optimistic; keeping the \
                 previous schedule and proposing no block until a refresh gets through"
            );
            metrics::set_beacon_node_available(false);
            *node_syncing = true;
            Ok(None)
        }
        // A beacon node that is down, syncing, slow or answering badly will
        // likely answer later, so keep the schedule already held and try
        // again. Anything else will not fix itself, and looping on it would
        // hide the cause behind a warning every slot.
        Err(err) if err.is_retryable() => {
            warn!(%epoch, %err, "Failed to refresh duties; keeping the previous schedule");
            metrics::set_beacon_node_available(false);
            Ok(None)
        }
        // Unreachable today: every error `refresh_epoch` can produce comes
        // from a `BeaconNodeApi` call or its deadline, and every variant those
        // raise is classified retryable (see `Error::is_retryable`). Kept
        // rather than deleted, since it is the only thing that would stop the
        // process if a future non-retryable failure (a local config or key
        // problem, say) ever reached this point; do not remove it as
        // unreachable dead code.
        Err(err) => {
            error!(%epoch, %err, "Cannot refresh duties; stopping");
            Err(err)
        }
    }
}

/// Send what a refresh left owing, from tasks of their own, once the slot's
/// block is out: the subnet subscriptions when it moved the attester
/// schedule, and the builder registrations of the validators it resolved.
///
/// Each subscription needs a selection proof, and each registration signed
/// anew a signature: for a remote key, a round trip to its signer. Awaited
/// on the duty loop, a slow signer would stand between the slot boundary and
/// a block, a block from a local key included, for as long as the signing
/// budget lets it; started before the proposal, they would queue ahead of the
/// block's own signatures at the same signer (requests to one signer are
/// capped, see `Web3Signer`).
///
/// Nothing waits on them. The schedule covers this epoch and the next, so the
/// duties that are near were subscribed an epoch ago, and the proofs are
/// remembered for the aggregation whenever they land. A missed registration
/// costs at most a builder block, never a duty. Only a refresh that got all
/// the way through leaves anything owing, so a failing one does not respawn a
/// full registration send every slot.
fn send_owed<B: BeaconNodeApi + 'static>(
    owed: Refreshed,
    epoch: u64,
    beacon_node: &Arc<B>,
    duties: &DutiesService<B>,
    store: &Arc<RwLock<ValidatorStore>>,
    context: &Arc<SigningContext>,
    registration: &Option<Arc<RegistrationService<B>>>,
) {
    if owed.moved {
        spawn_subscriptions(epoch, beacon_node, duties, store, context);
    }
    if let Some(registration) = registration {
        let registration = registration.clone();
        tokio::spawn(registration.register_all(epoch, owed.registrable, store.clone()));
    }
}

/// Send the subnet subscriptions of every attester duty held, from a task of
/// its own: after the attester schedule moved, a node was let back in, or the
/// schedule was swapped. See [`send_owed`] for why nothing waits on it.
fn spawn_subscriptions<B: BeaconNodeApi + 'static>(
    epoch: u64,
    beacon_node: &Arc<B>,
    duties: &DutiesService<B>,
    store: &Arc<RwLock<ValidatorStore>>,
    context: &Arc<SigningContext>,
) {
    let (beacon_node, store, context) = (beacon_node.clone(), store.clone(), context.clone());
    let schedule = duties.all();
    tokio::spawn(async move {
        let subscribed = subscriptions::subscribe(&beacon_node, &schedule, &store, &context);
        let _ = subscribed.await.inspect_err(|err| {
            warn!(%epoch, %err, "Failed to subscribe to attestation subnets");
            metrics::set_beacon_node_available(false);
        });
    });
}

/// Check this epoch's and the next one's held schedules against the node's
/// dependent roots, within `budget`, and refetch those a reorg moved. Returns
/// whether the attester schedule moved, which owes the node this client's
/// subnet subscriptions again. Read off the service
/// ([`DutiesService::take_attesters_moved`]) rather than from each check's
/// answer: a check that replaced the attester schedule and then failed or ran
/// out of budget on the payload committee fetch would lose the move, and the
/// next slot's check finds the roots matching.
///
/// # Why every slot
///
/// The epoch refresh compares roots once an epoch, and nothing else noticed a
/// reorg between two refreshes: the next epoch's attester and payload
/// committee schedules go stale on an ordinary one-slot reorg at the epoch
/// boundary, and the subscriptions computed from them with it; this epoch's,
/// on a reorg deeper than an epoch, which long non-finality makes ordinary.
/// One v2 proposer duties request per epoch checked, and the refetch only
/// when a root moved (see [`DutiesService::follow_dependent_root`]), so a
/// held schedule is never more than a slot behind the chain the node
/// follows. Polled rather than driven by `head` events: no event stream to
/// keep, reconnect and pick a node for, and a node more than 32 slots behind
/// sends no `head` at all.
///
/// # Only from fulu
///
/// Before fulu the next epoch's proposers are not fixed in advance, so no
/// cheap request names the next epoch's root, and this epoch's attester root
/// moves only on a reorg deeper than an epoch. Such an epoch is checked at
/// its refresh alone, as before.
///
/// Failures are logged at debug: this runs every slot, and the slot's duties
/// already report a node that is down. Cut off at `budget` with whatever it
/// had done kept, since each fetch answers in full before it changes its
/// schedule.
async fn follow_dependent_roots<B: BeaconNodeApi>(
    duties: &mut DutiesService<B>,
    epoch: u64,
    budget: std::time::Duration,
    config: &ethlambda_types::beacon::config::Config,
) -> bool {
    use ethlambda_types::beacon::fork::ForkName;

    let probe = async {
        for target in [epoch, epoch + 1] {
            if !ProposerDutiesVersion::fixed_ahead(config, target) {
                continue;
            }
            let ptc = config.fork_at_epoch(target) >= ForkName::Gloas
                && target != config.gloas_fork_epoch;
            let checked = duties.follow_dependent_root(target, ptc).await;
            let _ = checked.inspect_err(|err| {
                debug!(epoch = target, %err, "Dependent root check failed; trying again next slot");
            });
        }
    };
    if tokio::time::timeout(budget, probe).await.is_err() {
        debug!(%epoch, "Dependent root check ran out of slot; trying again next slot");
    }
    duties.take_attesters_moved()
}

/// Resolve any newly activated validators and refresh the duty schedule.
///
/// Sends no subnet subscription and no builder registration itself: both
/// need signatures, so the duty loop sends them from tasks of their own, off
/// the path to the slot's block. See [`Refreshed`].
///
/// Asks no node whether it is syncing: the duty loop runs this only in a slot
/// its per-slot sync check passed (see [`beacon_node::health`]).
async fn refresh_epoch<B: BeaconNodeApi>(
    beacon_node: &Arc<B>,
    duties: &mut DutiesService<B>,
    pubkeys: &[BlsPubkey],
    epoch: u64,
    settings: &ProposerSettings,
    context: &SigningContext,
) -> Result<Refreshed> {
    // Nothing to resolve, nothing to schedule, nothing to register. Returning
    // here also keeps an empty pubkey list away from `validator_indices`, whose
    // endpoint reads one as "every validator on the chain".
    //
    // The indices of keys no longer held are forgotten here too: the duty
    // loop's own fetches between refreshes (the proposers ahead of a block,
    // the payload committee retry) ask for nothing without indices, and
    // would otherwise keep asking for validators whose keys were all deleted.
    if pubkeys.is_empty() {
        duties.set_indices(Vec::new());
        return Ok(Refreshed::default());
    }

    // Re-resolved every epoch, not once at startup: a validator can be
    // deposited but not yet activated, in which case it has no index to ask
    // duties for until it is.
    let entries = beacon_node.validator_indices(pubkeys).await?;
    let indices: Vec<ValidatorIndex> = entries.iter().map(|entry| entry.index).collect();
    if indices.len() != pubkeys.len() {
        info!(
            resolved = indices.len(),
            loaded = pubkeys.len(),
            "Some validators have no index yet; they are not active on chain"
        );
    }
    // Kept as a continuously updated gauge, not just the one-shot warning in
    // `DutiesService::refresh` (which only fires once per empty-to-nonempty
    // transition): an operator needs to see "no validator indices resolved"
    // stay visible in monitoring for as long as it is true, not read it off
    // a single log line from whenever it first happened.
    metrics::set_validators_resolved(indices.len() as u64);
    duties.set_indices(indices);

    // Sent here, with the epoch's duties, and then again every slot by the
    // duty loop (see `Preparations`). Ahead of a block only on the refresh the
    // loop runs before one (see `ahead_of_block`), the first slot served
    // among them, when the node may not have heard from this client yet.
    //
    // A failure is logged rather than propagated. The consequence is a payload
    // built for the wrong address, which the check before signing catches; the
    // consequence of returning here would be losing this epoch's attester
    // duties, which is worse and unrelated. The duty loop sends again once
    // this slot's duties are done.
    let sent = prepare_proposers(beacon_node.as_ref(), &entries, settings).await;
    let _ = sent.inspect_err(|err| {
        warn!(
            %epoch,
            %err,
            "Failed to register this client's fee recipients; a block proposed before the \
             re-send after this slot's duties may pay somewhere else"
        );
    });

    duties.refresh_around(epoch, &context.config()).await?;
    refresh_ptc(duties, epoch, context).await;
    refresh_sync(beacon_node, duties, epoch, context).await;
    metrics::set_duties_held(duties.all().len() as u64);
    metrics::set_beacon_node_available(true);
    let registrable = entries.iter().filter(|entry| is_registrable(&entry.status));
    Ok(Refreshed {
        // Taken here, after the last await, rather than from
        // `refresh_around`'s answer: a refresh abandoned after that answer
        // would lose it, and its retry sees the same roots.
        moved: duties.take_attesters_moved(),
        registrable: registrable.map(|entry| entry.pubkey).collect(),
        resolved: entries,
    })
}

/// Tell the beacon node the address each of `entries`' blocks pays: one
/// `prepare_beacon_proposer` call, or none when no validator has an address.
/// The epoch refresh's send; the duty loop's per-slot one is [`Preparations`].
async fn prepare_proposers<B: BeaconNodeApi>(
    beacon_node: &B,
    entries: &[ValidatorEntry],
    settings: &ProposerSettings,
) -> Result<()> {
    let preparations = preparations(entries, settings);
    if preparations.is_empty() {
        return Ok(());
    }
    beacon_node.prepare_beacon_proposer(&preparations).await
}

/// One preparation for each of `entries` that has an address, its own or the
/// default, as `settings` names it now.
///
/// A validator with neither is left out: there is nothing to tell the node,
/// which then picks an address itself, as the startup warning says.
fn preparations<'a>(
    entries: impl IntoIterator<Item = &'a ValidatorEntry>,
    settings: &ProposerSettings,
) -> Vec<ProposerPreparationDto> {
    entries
        .into_iter()
        .filter_map(|entry| {
            let fee_recipient = settings.fee_recipient(&entry.pubkey)?;
            Some(ProposerPreparationDto {
                validator_index: entry.index,
                fee_recipient: crate::beacon_node::dto::encode_hex(&fee_recipient.0),
            })
        })
        .collect()
}

/// The proposer preparations, sent again once every slot's duties are done.
///
/// # Every slot, not once an epoch
///
/// As Lighthouse's validator client does. A node keeps a preparation for the
/// epoch it arrived in and two more, and loses all of them when it restarts;
/// until the next one arrives it builds its own payloads for its fallback fee
/// recipient, which is the zero address unless its operator set one.
/// Sent only by the epoch refresh, a restart mid-epoch cost the rest of that
/// epoch's local blocks their execution-layer rewards: six blocks on a devnet,
/// from a beacon node killed 14 slots into its epoch. Sent every slot, a
/// restart costs at most a proposal that comes before the first re-send the
/// node is back up for, which is within a slot of its return.
///
/// # What is sent
///
/// The validators the last refresh resolved that the store still holds, each
/// with the address [`ProposerSettings`] gives it at the send, so a
/// keymanager change to a fee recipient reaches the node after the duties of
/// the slot it is made in, or the next slot's while a slow node still holds
/// the last send (see below). Three cases that does not cover:
///
/// - **A key deleted through the keymanager** (`DELETE /eth/v1/keystores` or
///   `/remotekeys`) is not sent again. Its overrides are forgotten with it, so
///   it would otherwise go out with `--suggested-fee-recipient`, overwriting
///   the preparation of a client the key moved to on the same node. The node
///   keeps the address it was last given until it expires it or restarts.
///   Imported again before the next refresh, the key is sent again, with the
///   defaults a key starts on once its overrides are forgotten.
/// - **A `DELETE` of a validator's fee recipient that leaves it no address**
///   (no `--suggested-fee-recipient` either) sends nothing for it, so the node
///   keeps the address it was last given, the same way.
/// - **A key imported mid-epoch** is not sent until the next refresh resolves
///   its index. Nothing is lost: that refresh is also what fetches its
///   proposer duties (they are narrowed to the indices it resolves, see
///   [`DutiesService::set_indices`]), so this client proposes no block for it
///   before the refresh that prepares it.
///
/// # One send at a time
///
/// Each send reads the settings, then waits on every node. Against a slow
/// node a send can outlive the next slot's, and two in flight could land in
/// either order, reverting a fee recipient changed in between. So a send that
/// finds the last one still running skips, and the slot after it sends what
/// is current then (see [`crate::in_flight`]). A node that never answers is
/// cut off by the HTTP client's request timeout, 8 s, so a hung node costs
/// the healthy ones only the re-sends that come due while a send waits on it:
/// at most every other one on 12 s slots, more on shorter ones, never all of
/// them.
///
/// The epoch refresh's send does not take part. It is the first a node hears
/// of a validator the refresh resolved for the first time, and on the first
/// slot served it runs ahead of the slot's block (see `ahead_of_block`), where
/// skipping would cost that proposal its preparation. A re-send still in
/// flight from the slot before can then land after it, which is why the
/// refresh's slot re-sends too, once its duties are done, although its
/// refresh just sent the same: the late send can then cost at most the next
/// proposal. If it is still running at that point, that re-send skips and the
/// next slot's puts the current address back.
///
/// # Quiet on failure
///
/// A node that is down, restarting or refusing costs a `debug!` line, here
/// and per node (see [`BeaconNodeApi::prepare_beacon_proposer_quietly`]): the
/// slot's duties already report a node that is down, and the next slot tries
/// again. The refresh's send still warns.
struct Preparations<B> {
    beacon_node: Arc<B>,
    settings: Arc<ProposerSettings>,
    /// The re-send, while it runs.
    in_flight: InFlight,
}

impl<B: BeaconNodeApi + 'static> Preparations<B> {
    fn new(beacon_node: Arc<B>, settings: Arc<ProposerSettings>) -> Self {
        Self {
            beacon_node,
            settings,
            in_flight: InFlight::default(),
        }
    }

    /// The duty loop's gate, once every slot's duties are done, the
    /// refresh's slot included: spawn the re-send of `resolved`'s
    /// preparations, unless there is nobody to prepare. Returns the spawned
    /// task's handle so a test can await it; the duty loop drops it, as it
    /// does its other sends' handles.
    fn after_slot(
        self: &Arc<Self>,
        slot: u64,
        resolved: &Arc<Vec<ValidatorEntry>>,
        store: &Arc<RwLock<ValidatorStore>>,
    ) -> Option<JoinHandle<()>> {
        if resolved.is_empty() {
            return None;
        }
        let resend = self.clone().resend(slot, resolved.clone(), store.clone());
        Some(tokio::spawn(resend))
    }

    async fn resend(
        self: Arc<Self>,
        slot: u64,
        resolved: Arc<Vec<ValidatorEntry>>,
        store: Arc<RwLock<ValidatorStore>>,
    ) {
        // Before the settings are read, so the sends reach the nodes in the
        // order they read them.
        let Some(_running) = self.in_flight.enter() else {
            debug!(
                %slot,
                "The last fee recipient re-send is still running; skipping this slot's"
            );
            return;
        };
        // Built under the store's read guard, which is released before the
        // send, so a keymanager write waits on no node.
        let preparations = {
            let store = store.read().await;
            let held = resolved
                .iter()
                .filter(|entry| store.contains(&entry.pubkey));
            preparations(held, &self.settings)
        };
        if preparations.is_empty() {
            return;
        }
        let sent = self
            .beacon_node
            .prepare_beacon_proposer_quietly(&preparations)
            .await;
        let _ = sent.inspect_err(|err| {
            debug!(%slot, %err, "Failed to re-send this client's fee recipients");
        });
    }
}

/// Whether a validator whose Beacon API `status` is this one is sent a builder
/// registration: one that is pending or active, not one that exited or was
/// withdrawn.
///
/// The flashbots relay refuses a whole registration request over one key it
/// does not know, and it knows only pending and active validators, so one
/// exited key would cost every other in its batch of up to
/// [`beacon_node::REGISTRATION_BATCH`]. Teku's validator client leaves exited
/// keys out the same way, and Lighthouse's beacon node drops them before
/// forwarding; a node that forwards as it gets would otherwise pass them on.
fn is_registrable(status: &str) -> bool {
    status.starts_with("pending") || status.starts_with("active")
}

/// Fetch the payload timeliness committee schedule for this epoch and the next,
/// each only if it is a gloas epoch, and the gloas fork epoch's only once it
/// has begun.
///
/// Gated per epoch rather than once, because the fork can activate between the
/// two. The fork epoch is no lookahead, though: its committee is computed at
/// the fork from the effective balances the last pre-gloas epoch ends with, so
/// a node serves it only from the fork on (beacon-APIs `ptc.yaml`; Lighthouse
/// answers `400` before). It is fetched at the fork epoch's own first slot,
/// with the epoch after it as the lookahead. A failed fetch is logged and
/// shrugged off, like the proposer and lookahead ones: it must not cost this
/// epoch's attester schedule, which is already in hand. The current epoch's is
/// then fetched again ahead of each slot's duties until one is held
/// ([`retry_missing_ptc`]).
async fn refresh_ptc<B: BeaconNodeApi>(
    duties: &mut DutiesService<B>,
    epoch: u64,
    context: &SigningContext,
) {
    let config = context.config();
    for target in [epoch, epoch + 1] {
        if config.fork_at_epoch(target) < ethlambda_types::beacon::fork::ForkName::Gloas {
            continue;
        }
        if target == config.gloas_fork_epoch && epoch < target {
            continue;
        }
        if let Err(err) = duties.refresh_ptc(target).await {
            warn!(
                epoch = target,
                %err,
                "Payload committee duties fetch failed; this client may miss its votes"
            );
        }
    }
    duties.prune_ptc_before(epoch);
}

/// Fetch this epoch's payload timeliness committee schedule again, within
/// `budget`, when it is a gloas epoch and none is held.
///
/// The duty loop calls it every slot, after the block and ahead of reading the
/// slot's committee, so a failed fetch costs the votes of the slots until the
/// next one succeeds rather than the rest of the epoch. That is also how the
/// gloas fork epoch's first slot gets its committee: the schedule cannot be
/// fetched before the fork, and the epoch's refresh runs beside the slot's
/// duties, too late for their committee lookup. A failure here is logged at
/// debug: `refresh_ptc` already warned once, and this runs again every slot
/// until it succeeds. Dropping the fetch at the deadline is safe, since
/// `DutiesService::refresh_ptc` changes nothing until its request has
/// answered.
async fn retry_missing_ptc<B: BeaconNodeApi>(
    duties: &mut DutiesService<B>,
    epoch: u64,
    budget: std::time::Duration,
    context: &SigningContext,
) {
    if context.config().fork_at_epoch(epoch) < ethlambda_types::beacon::fork::ForkName::Gloas
        || duties.holds_ptc(epoch)
    {
        return;
    }
    match tokio::time::timeout(budget, duties.refresh_ptc(epoch)).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            debug!(%epoch, %err, "Payload committee duties retry failed; trying again next slot");
        }
        Err(_) => {
            debug!(%epoch, "Payload committee duties retry ran out of slot; trying again next slot");
        }
    }
}

/// How many epochs before a period boundary the next period's subnets are
/// joined: lighthouse's lookahead, at the specification's upper bound
/// `SYNC_COMMITTEE_SUBNET_COUNT` for the random early-join window.
const SYNC_SUBSCRIPTION_LOOKAHEAD_EPOCHS: u64 =
    ethlambda_types::beacon::constants::SYNC_COMMITTEE_SUBNET_COUNT as u64;

/// Fetch the sync committee schedule for this period and the next, and ask the
/// node to join the subnets involved.
///
/// Only from altair. Failures are logged and swallowed, like the payload
/// committee's: they must not cost this epoch's attester schedule.
///
/// Subscriptions are sent every epoch because the node forgets them on
/// restart. The current period's run to its end; the next period's are added
/// once the boundary is within [`SYNC_SUBSCRIPTION_LOOKAHEAD_EPOCHS`], so the
/// subnets are already joined when the new committee starts signing.
async fn refresh_sync<B: BeaconNodeApi>(
    beacon_node: &Arc<B>,
    duties: &mut DutiesService<B>,
    epoch: u64,
    context: &SigningContext,
) {
    use ethlambda_types::beacon::fork::ForkName;

    if context.config().fork_at_epoch(epoch) < ForkName::Altair {
        return;
    }
    let period = crate::duties::sync_committee_period(epoch);
    for target in [period, period + 1] {
        if let Err(err) = duties.refresh_sync(target).await {
            warn!(
                period = target,
                %err,
                "Sync committee duties fetch failed; this client may miss its messages"
            );
        }
    }
    duties.prune_sync_before(period);
    metrics::set_sync_duties_held(duties.sync_for_period(period).len() as u64);

    send_sync_subscriptions(beacon_node, &sync_subscriptions_owed(duties, epoch)).await;
}

/// The sync committee subscriptions owed at `epoch`, from the duties held:
/// the current period's seats until the period ends, and the next period's
/// once its boundary is within [`SYNC_SUBSCRIPTION_LOOKAHEAD_EPOCHS`], until
/// that one ends. Each with the epoch it runs until.
///
/// What [`refresh_sync`] sends every epoch, and what the duty loop sends again
/// to a node the chain check let back in.
fn sync_subscriptions_owed<B: BeaconNodeApi>(
    duties: &DutiesService<B>,
    epoch: u64,
) -> Vec<(Vec<crate::beacon_node::dto::SyncDutyDto>, u64)> {
    use ethlambda_types::beacon::preset::epochs_per_sync_committee_period as period_epochs;

    let period = crate::duties::sync_committee_period(epoch);
    let mut owed = vec![(
        duties.sync_for_period(period),
        (period + 1) * period_epochs(),
    )];
    if epoch + SYNC_SUBSCRIPTION_LOOKAHEAD_EPOCHS >= (period + 1) * period_epochs() {
        owed.push((
            duties.sync_for_period(period + 1),
            (period + 2) * period_epochs(),
        ));
    }
    owed
}

/// Send each of `owed` (see [`sync_subscriptions_owed`]), warning about any
/// no node took.
async fn send_sync_subscriptions<B: BeaconNodeApi>(
    beacon_node: &Arc<B>,
    owed: &[(Vec<crate::beacon_node::dto::SyncDutyDto>, u64)],
) {
    for (seats, until_epoch) in owed {
        let subscribed = subscriptions::subscribe_sync(beacon_node, seats, *until_epoch).await;
        let _ = subscribed.inspect_err(|err| {
            warn!(until_epoch, %err, "Failed to subscribe to sync committee subnets");
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon_node::ValidatorEntry;
    use crate::beacon_node::mock::MockBeaconNode;
    use ethlambda_types::beacon::primitives::{H160, Root};

    fn pubkey(byte: u8) -> BlsPubkey {
        BlsPubkey([byte; 48])
    }

    /// A node that resolves two validators and has duties for epoch 3, so
    /// `refresh_epoch` gets all the way through to the preparation.
    fn node() -> MockBeaconNode {
        let mut node = MockBeaconNode::new().with_duties(3, Root::repeat_byte(1), Vec::new());
        node = node.with_duties(4, Root::repeat_byte(2), Vec::new());
        node = node.with_proposers(3, Root::repeat_byte(1), Vec::new());
        node.validators = vec![
            ValidatorEntry {
                index: 11,
                pubkey: pubkey(1),
                status: "active_ongoing".to_string(),
            },
            ValidatorEntry {
                index: 22,
                pubkey: pubkey(2),
                status: "active_ongoing".to_string(),
            },
        ];
        node
    }

    fn context() -> SigningContext {
        SigningContext::new(
            ethlambda_types::beacon::config::Config::mainnet(),
            Root::ZERO,
        )
    }

    fn empty_store() -> RwLock<ValidatorStore> {
        RwLock::new(ValidatorStore::new())
    }

    fn settings(fee_recipient: Option<ExecutionAddress>) -> ProposerSettings {
        ProposerSettings::new(Bytes32::ZERO, fee_recipient)
    }

    async fn refresh(node: Arc<MockBeaconNode>, fee_recipient: Option<ExecutionAddress>) {
        refresh_with(node, &settings(fee_recipient)).await;
    }

    async fn refresh_with(node: Arc<MockBeaconNode>, settings: &ProposerSettings) {
        let mut duties = DutiesService::new(node.clone(), Vec::new());
        let keys = [pubkey(1), pubkey(2)];
        refresh_epoch(&node, &mut duties, &keys, 3, settings, &context())
            .await
            .expect("refreshes");
    }

    /// One preparation per resolved validator from every refresh, ahead of
    /// the epoch's duties. The node keeps a preparation for three epochs and
    /// forgets all of them on restart, so a client that sent this once at
    /// startup would quietly stop being registered; the duty loop also sends
    /// them again after every slot's duties (see
    /// `the_preparations_go_out_again_after_every_slot_the_refreshs_included`).
    #[tokio::test]
    async fn every_resolved_validator_is_registered_for_its_fee_recipient() {
        let node = Arc::new(node());
        refresh(node.clone(), Some(H160([0xab; 20]))).await;

        let sent = node.preparations();
        assert_eq!(sent.len(), 2);
        let indices: Vec<u64> = sent.iter().map(|entry| entry.validator_index).collect();
        assert_eq!(indices, vec![11, 22]);
        assert!(
            sent.iter()
                .all(|entry| entry.fee_recipient == format!("0x{}", "ab".repeat(20))),
            "got {sent:?}"
        );
    }

    /// Re-sent, not sent once. Two refreshes must produce two registrations.
    #[tokio::test]
    async fn the_registration_is_repeated_on_every_refresh() {
        let node = Arc::new(node());
        refresh(node.clone(), Some(H160([0xab; 20]))).await;
        refresh(node.clone(), Some(H160([0xab; 20]))).await;
        assert_eq!(node.preparations().len(), 4);
    }

    /// A store holding `keys`, behind a signer nothing calls: these tests ask
    /// the store which keys it holds, never for a signature.
    fn store_holding(keys: &[BlsPubkey]) -> Arc<RwLock<ValidatorStore>> {
        let mut store = ValidatorStore::new();
        for key in keys {
            store
                .insert_remote(*key, "http://127.0.0.1:9000")
                .expect("inserts");
        }
        Arc::new(RwLock::new(store))
    }

    /// Every preparation `node` was sent, as (index, address), in order.
    fn sent(node: &MockBeaconNode) -> Vec<(u64, String)> {
        node.preparations()
            .into_iter()
            .map(|entry| (entry.validator_index, entry.fee_recipient))
            .collect()
    }

    /// The address whose twenty bytes are all `byte`, as a preparation
    /// carries it.
    fn address(byte: u8) -> String {
        crate::beacon_node::dto::encode_hex(&[byte; 20])
    }

    /// The duty loop's gate: after every slot's duties, the refresh's
    /// included, the refresh's validators again, with the addresses the
    /// settings name by then. That re-send is what a beacon node restarted
    /// mid-epoch hears from first: sent only by the refresh, its local blocks
    /// paid its fallback fee recipient (the zero address without one) for the
    /// rest of the epoch.
    ///
    /// On the refresh's own slot it puts the current address back when the
    /// refresh's send was overtaken, here by the previous slot's re-send
    /// landing late with the address a keymanager change replaced. Skipped
    /// there, that address would stand until after the next slot's duties,
    /// past the next proposal.
    #[tokio::test]
    async fn the_preparations_go_out_again_after_every_slot_the_refreshs_included() {
        let node = Arc::new(node());
        let mut duties = DutiesService::new(node.clone(), Vec::new());
        let settings = Arc::new(settings(Some(H160([0xab; 20]))));
        settings.set_fee_recipient(&pubkey(2), H160([0xcd; 20]));
        let keys = [pubkey(1), pubkey(2)];
        let store = store_holding(&keys);
        let preparations = Arc::new(Preparations::new(node.clone(), settings.clone()));

        let Refreshed { resolved, .. } =
            refresh_epoch(&node, &mut duties, &keys, 3, &settings, &context())
                .await
                .expect("refreshes");
        assert_eq!(sent(&node), [(11, address(0xab)), (22, address(0xcd))]);
        // The previous slot's re-send, which read validator 22's address
        // before the change, reaching the node after the refresh's send.
        let late = ProposerPreparationDto {
            validator_index: 22,
            fee_recipient: address(0xab),
        };
        node.preparations.lock().expect("lock").push(late);

        let resolved = Arc::new(resolved);
        preparations
            .after_slot(96, &resolved, &store)
            .expect("the refresh's slot re-sends too")
            .await
            .expect("the re-send ends");
        assert_eq!(sent(&node)[3..], [(11, address(0xab)), (22, address(0xcd))]);

        settings.set_fee_recipient(&pubkey(2), H160([0xef; 20]));
        preparations
            .after_slot(97, &resolved, &store)
            .expect("and so does every slot after it")
            .await
            .expect("the re-send ends");
        assert_eq!(sent(&node)[5..], [(11, address(0xab)), (22, address(0xef))]);
    }

    /// A key the keymanager deleted after the refresh is not prepared again.
    /// Its overrides went with it, so it would otherwise go out every slot
    /// with the default address, overwriting the preparation of a client the
    /// key moved to on the same node.
    #[tokio::test]
    async fn a_key_deleted_since_the_refresh_is_not_prepared_again() {
        let node = Arc::new(node());
        let settings = Arc::new(settings(Some(H160([0xab; 20]))));
        settings.set_fee_recipient(&pubkey(2), H160([0xcd; 20]));
        let store = store_holding(&[pubkey(1), pubkey(2)]);
        let preparations = Arc::new(Preparations::new(node.clone(), settings.clone()));
        let resolved = Arc::new(node.validators.clone());

        // What a keystore or remote key `DELETE` does to the two.
        store.write().await.remove(&pubkey(2));
        settings.forget(&pubkey(2));
        preparations
            .after_slot(97, &resolved, &store)
            .expect("due")
            .await
            .expect("the re-send ends");

        assert_eq!(sent(&node), [(11, address(0xab))]);
    }

    /// One re-send at a time. A slot whose re-send finds the last one still
    /// waiting on a node skips, so a send that read an older fee recipient
    /// cannot land after one that read the newer; the slot after sends what
    /// is current then.
    #[tokio::test]
    async fn a_re_send_still_waiting_on_a_node_makes_the_next_slot_skip() {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let node = Arc::new(node().with_preparation_gate(gate.clone()));
        let settings = Arc::new(settings(Some(H160([0xab; 20]))));
        let store = store_holding(&[pubkey(1), pubkey(2)]);
        let preparations = Arc::new(Preparations::new(node.clone(), settings.clone()));
        let resolved = Arc::new(node.validators.clone());

        let slow = preparations.after_slot(97, &resolved, &store).expect("due");
        node.preparation_entered.notified().await;
        settings.set_fee_recipient(&pubkey(1), H160([0xcd; 20]));
        let skipped = preparations.after_slot(98, &resolved, &store).expect("due");
        tokio::time::timeout(std::time::Duration::from_secs(5), skipped)
            .await
            .expect("a skipped re-send does not wait on the node")
            .expect("the skipped re-send ends");
        assert!(
            node.preparations().is_empty(),
            "the slow re-send is still parked at the gate, and the skipped one sent nothing"
        );

        gate.add_permits(1);
        slow.await.expect("the slow re-send ends");
        assert_eq!(sent(&node), [(11, address(0xab)), (22, address(0xab))]);

        gate.add_permits(1);
        preparations
            .after_slot(99, &resolved, &store)
            .expect("due")
            .await
            .expect("the re-send ends");
        assert_eq!(sent(&node)[2..], [(11, address(0xcd)), (22, address(0xab))]);
    }

    /// The refresh says when the attester schedule moved, which is what owes
    /// the node its subnet subscriptions, and sends none itself: they wait
    /// for the slot's block, since each costs a remote key a round trip to
    /// its signer.
    #[tokio::test]
    async fn a_refresh_reports_a_moved_schedule_and_leaves_the_subscriptions_to_the_caller() {
        let node = Arc::new(node());
        let mut duties = DutiesService::new(node.clone(), Vec::new());
        let keys = [pubkey(1), pubkey(2)];
        let settings = settings(None);
        let context = context();

        let Refreshed { moved, .. } =
            refresh_epoch(&node, &mut duties, &keys, 3, &settings, &context)
                .await
                .expect("refreshes");
        assert!(moved, "a schedule fetched for the first time is a new one");

        let Refreshed { moved, .. } =
            refresh_epoch(&node, &mut duties, &keys, 3, &settings, &context)
                .await
                .expect("refreshes");
        assert!(!moved, "the same dependent roots are the same schedule");

        assert!(node.subscriptions().is_empty());
    }

    #[tokio::test]
    async fn no_configured_address_sends_no_registration() {
        let node = Arc::new(node());
        refresh(node.clone(), None).await;
        assert!(node.preparations().is_empty());
    }

    /// A validator's own address is the one registered for it, and the
    /// default still covers the rest.
    #[tokio::test]
    async fn a_validators_own_address_is_registered_for_it() {
        let node = Arc::new(node());
        let settings = settings(Some(H160([0xab; 20])));
        settings.set_fee_recipient(&pubkey(2), H160([0xcd; 20]));
        refresh_with(node.clone(), &settings).await;

        let sent: Vec<(u64, String)> = node
            .preparations()
            .into_iter()
            .map(|entry| (entry.validator_index, entry.fee_recipient))
            .collect();
        assert_eq!(
            sent,
            vec![
                (11, format!("0x{}", "ab".repeat(20))),
                (22, format!("0x{}", "cd".repeat(20))),
            ]
        );
    }

    /// With no default, only the validators given an address of their own are
    /// registered. The others have nothing to tell the node.
    #[tokio::test]
    async fn without_a_default_only_validators_with_their_own_address_are_registered() {
        let node = Arc::new(node());
        let settings = settings(None);
        settings.set_fee_recipient(&pubkey(1), H160([0xcd; 20]));
        refresh_with(node.clone(), &settings).await;

        let sent = node.preparations();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].validator_index, 11);
        assert_eq!(sent[0].fee_recipient, format!("0x{}", "cd".repeat(20)));
    }

    /// A failed registration must not cost this epoch's duties. The
    /// consequence of the failure is a payload built for the wrong address,
    /// which the check before signing catches; the consequence of propagating
    /// it would be attesting on last epoch's schedule, which is worse and
    /// unrelated.
    #[tokio::test]
    async fn a_failed_registration_does_not_fail_the_refresh() {
        let node = Arc::new(node().failing_call("prepare_beacon_proposer", "node is unhappy"));
        let mut duties = DutiesService::new(node.clone(), Vec::new());
        let keys = [pubkey(1), pubkey(2)];

        refresh_epoch(
            &node,
            &mut duties,
            &keys,
            3,
            &settings(Some(H160([0xab; 20]))),
            &context(),
        )
        .await
        .expect("the refresh must survive a failed registration");
        assert_eq!(duties.indices(), &[11, 22]);
    }

    /// A client with no keys must not ask the beacon node anything.
    ///
    /// The validators endpoint reads an empty id list as "return every
    /// validator", which on mainnet is millions of entries, fetched every
    /// epoch, and then fed straight into the attester-duties request. A keyless
    /// client is a supported state, so this is reachable by simply starting one
    /// with an empty validators directory.
    #[tokio::test]
    async fn a_client_with_no_keys_asks_the_node_for_nothing() {
        let node = Arc::new(node());
        let mut duties = DutiesService::new(node.clone(), Vec::new());

        refresh_epoch(
            &node,
            &mut duties,
            &[],
            3,
            &settings(Some(H160([0xab; 20]))),
            &context(),
        )
        .await
        .expect("a keyless client idles rather than failing");

        assert_eq!(
            node.validator_indices_call_count(),
            0,
            "an empty id list means every validator on the chain; it must never be sent"
        );
        assert_eq!(node.duties_call_count(), 0);
        assert!(node.preparations().is_empty());
    }

    /// And the implementations answer an empty request themselves, so a caller
    /// that reaches them directly cannot make the same mistake.
    #[tokio::test]
    async fn an_empty_pubkey_list_resolves_to_no_validators() {
        let node = node();
        let resolved = node
            .validator_indices(&[])
            .await
            .expect("an empty request is not an error");
        assert!(
            resolved.is_empty(),
            "the answer to 'resolve nothing' is nothing, not everything"
        );
    }

    /// Only pending and active validators get a builder registration: the
    /// flashbots relay refuses a whole batch over one key it does not know, and
    /// it knows no exited or withdrawn one. Proposer preparations still go to
    /// every resolved validator.
    #[tokio::test]
    async fn only_pending_and_active_validators_are_registered() {
        let mut node = node();
        node.validators[1].status = "exited_unslashed".to_string();
        node.validators.push(ValidatorEntry {
            index: 33,
            pubkey: pubkey(3),
            status: "pending_queued".to_string(),
        });
        node.validators.push(ValidatorEntry {
            index: 44,
            pubkey: pubkey(4),
            status: "withdrawal_done".to_string(),
        });
        // Exiting and slashed are still active: the relay loads validators
        // with `status=active,pending`, which takes in both.
        node.validators.push(ValidatorEntry {
            index: 55,
            pubkey: pubkey(5),
            status: "active_exiting".to_string(),
        });
        node.validators.push(ValidatorEntry {
            index: 66,
            pubkey: pubkey(6),
            status: "active_slashed".to_string(),
        });
        let node = Arc::new(node);
        let mut duties = DutiesService::new(node.clone(), Vec::new());
        let keys = [
            pubkey(1),
            pubkey(2),
            pubkey(3),
            pubkey(4),
            pubkey(5),
            pubkey(6),
        ];
        let settings = settings(Some(H160([0xab; 20])));

        let Refreshed { registrable, .. } =
            refresh_epoch(&node, &mut duties, &keys, 3, &settings, &context())
                .await
                .expect("refreshes");

        assert_eq!(
            registrable,
            vec![pubkey(1), pubkey(3), pubkey(5), pubkey(6)]
        );
        assert_eq!(node.preparations().len(), 6);
    }

    /// With nothing resolved there is nobody to register, and an empty array
    /// must not be posted: it is a request that can only fail or do nothing.
    #[tokio::test]
    async fn nothing_is_registered_when_no_validator_resolved() {
        let mut bare = MockBeaconNode::new().with_duties(3, Root::repeat_byte(1), Vec::new());
        bare = bare.with_duties(4, Root::repeat_byte(2), Vec::new());
        bare = bare.with_proposers(3, Root::repeat_byte(1), Vec::new());
        let node = Arc::new(bare);

        refresh(node.clone(), Some(H160([0xab; 20]))).await;
        assert!(node.preparations().is_empty());
    }

    // ---- what runs ahead of an epoch's first block (#826) -----------------

    /// Mainnet's config with every fork through fulu at genesis, so every
    /// epoch after the first has its proposers fixed an epoch ahead.
    fn fulu_context() -> SigningContext {
        use ethlambda_types::beacon::fork::ForkName;
        let config = [
            ForkName::Altair,
            ForkName::Bellatrix,
            ForkName::Capella,
            ForkName::Deneb,
            ForkName::Electra,
            ForkName::Fulu,
        ]
        .into_iter()
        .fold(
            ethlambda_types::beacon::config::Config::mainnet(),
            |config, fork| config.with_fork_epoch(fork, 0),
        );
        SigningContext::new(config, Root::ZERO)
    }

    /// A clock on `context`'s chain whose `slot` started at most a second ago.
    fn clock_at(slot: u64, context: &SigningContext) -> SlotClock {
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after 1970")
            .as_secs();
        let genesis = now - slot * context.config().slot_duration_ms / 1000;
        SlotClock::from_config(genesis, &context.config())
    }

    fn proposer_duty(index: u64, slot: u64) -> crate::beacon_node::dto::ProposerDutyDto {
        crate::beacon_node::dto::ProposerDutyDto {
            pubkey: crate::beacon_node::dto::encode_hex(&[0u8; 48]),
            validator_index: index,
            slot,
        }
    }

    /// Every duty-related request `node` has answered so far, by kind.
    fn requests(node: &MockBeaconNode) -> [usize; 6] {
        [
            node.validator_indices_call_count(),
            node.duties_call_count(),
            node.proposer_duties_call_count(),
            node.proposer_duties_v2_call_count(),
            node.preparations().len(),
            node.sync_duty_requests().len(),
        ]
    }

    /// From fulu the previous epoch's refresh fetched this epoch's proposers,
    /// so at its first slot nothing stands between the boundary and the
    /// block: the refresh is left for after it.
    #[tokio::test]
    async fn from_fulu_an_epochs_first_slot_asks_nothing_ahead_of_its_block() {
        let node = Arc::new(
            node()
                .with_proposers_v2(3, Root::repeat_byte(1), Vec::new())
                .with_proposers_v2(4, Root::repeat_byte(2), vec![proposer_duty(11, 128)]),
        );
        let context = fulu_context();
        let settings = settings(Some(H160([0xab; 20])));
        let mut duties = DutiesService::new(node.clone(), Vec::new());
        let keys = [pubkey(1), pubkey(2)];
        refresh_epoch(&node, &mut duties, &keys, 3, &settings, &context)
            .await
            .expect("refreshes");
        let before = requests(&node);

        let clock = clock_at(128, &context);
        let early = ahead_of_block(
            &node,
            &mut duties,
            &keys,
            &clock,
            128,
            true,
            &settings,
            &context,
        )
        .await;

        assert!(early.is_none(), "the refresh is left for after the block");
        assert_eq!(
            requests(&node),
            before,
            "nothing is asked ahead of the block"
        );
        assert_eq!(
            duties
                .proposer_at_slot(128, 4)
                .map(|duty| duty.validator_index),
            Some(11)
        );
    }

    /// Before fulu the next epoch's proposers cannot be known an epoch ahead,
    /// so an epoch's first slot asks for them, and for nothing else, before
    /// its block.
    #[tokio::test]
    async fn before_fulu_an_epochs_first_slot_asks_for_its_proposers_alone() {
        let node =
            Arc::new(node().with_proposers(4, Root::repeat_byte(2), vec![proposer_duty(11, 128)]));
        let context = context();
        let settings = settings(Some(H160([0xab; 20])));
        let mut duties = DutiesService::new(node.clone(), Vec::new());
        let keys = [pubkey(1), pubkey(2)];
        refresh_epoch(&node, &mut duties, &keys, 3, &settings, &context)
            .await
            .expect("refreshes");
        assert!(!duties.holds_proposers(4), "not prefetched before fulu");
        let [indices, attesters, v1, v2, preparations, sync] = requests(&node);

        let clock = clock_at(128, &context);
        let early = ahead_of_block(
            &node,
            &mut duties,
            &keys,
            &clock,
            128,
            true,
            &settings,
            &context,
        )
        .await;

        assert!(early.is_none(), "the refresh is left for after the block");
        assert_eq!(
            requests(&node),
            [indices, attesters, v1 + 1, v2, preparations, sync],
            "one v1 proposer request and nothing else"
        );
        assert_eq!(
            duties
                .proposer_at_slot(128, 4)
                .map(|duty| duty.validator_index),
            Some(11)
        );
    }

    /// The first slot served holds no schedule at all, so the whole refresh
    /// runs before its block: nothing else can say whether this client
    /// proposes there.
    #[tokio::test]
    async fn with_nothing_held_the_whole_refresh_runs_ahead_of_the_block() {
        let node = Arc::new(node());
        let context = context();
        let mut duties = DutiesService::new(node.clone(), Vec::new());
        let keys = [pubkey(1), pubkey(2)];

        let clock = clock_at(96, &context);
        let early = ahead_of_block(
            &node,
            &mut duties,
            &keys,
            &clock,
            96,
            true,
            &settings(None),
            &context,
        )
        .await;

        assert!(matches!(early, Some(Ok(_))), "got {early:?}");
        assert_eq!(node.validator_indices_call_count(), 1);
        assert!(duties.holds_attesters(3) && duties.holds_proposers(3));
    }

    /// With nothing held the refresh ahead of the block runs to the end, past
    /// its slot: cut off there, it would start again from its first request
    /// every slot, and a first node that hangs each request to its timeout
    /// would keep it from ever reaching a healthy one.
    #[tokio::test(start_paused = true)]
    async fn with_nothing_held_the_refresh_is_not_cut_off_at_the_slots_end() {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let node = Arc::new(node().with_preparation_gate(gate.clone()));
        let context = context();
        let mut duties = DutiesService::new(node.clone(), Vec::new());
        let keys = [pubkey(1), pubkey(2)];
        let clock = clock_at(96, &context);
        let settings = settings(Some(H160([0xab; 20])));
        let slot = std::time::Duration::from_millis(context.config().slot_duration_ms);

        let started = tokio::time::Instant::now();
        let release = async {
            tokio::time::sleep(slot * 2).await;
            gate.add_permits(1);
        };
        let refresh = ahead_of_block(
            &node,
            &mut duties,
            &keys,
            &clock,
            96,
            true,
            &settings,
            &context,
        );
        let (early, ()) = tokio::join!(refresh, release);

        assert!(matches!(early, Some(Ok(_))), "got {early:?}");
        assert!(started.elapsed() >= slot * 2);
        assert!(duties.holds_attesters(3));
    }

    /// A refresh that finds the node syncing or optimistic stops the
    /// proposals until one gets through: the schedule held, prefetched from
    /// fulu, would otherwise have them built on a head the node has not
    /// validated. `refresh_epoch` no longer asks the node's sync status itself
    /// (the per-slot probe does, see `beacon_node::health`), so what reaches
    /// `settle_refresh` here is a duties fetch every node refused with a 503,
    /// which the HTTP client reads as `BeaconNodeSyncing`.
    #[tokio::test]
    async fn a_refresh_that_finds_the_node_syncing_stops_the_proposals() {
        let outcome = Err(Error::BeaconNodeSyncing);

        let mut last_epoch = Some(2);
        let mut resolved = Arc::default();
        let mut node_syncing = false;
        let owed = settle_refresh(
            3,
            outcome,
            &mut last_epoch,
            &mut resolved,
            &mut node_syncing,
        )
        .expect("a syncing node does not stop the client");
        assert!(owed.is_none());
        assert_eq!(last_epoch, Some(2));
        assert!(node_syncing, "no block until a refresh gets through");
    }

    /// With every key deleted the indices go too, so nothing between
    /// refreshes keeps asking for duties of validators no longer held.
    #[tokio::test]
    async fn with_every_key_deleted_the_indices_are_forgotten() {
        let node = Arc::new(node());
        let mut duties = DutiesService::new(node.clone(), vec![11, 22]);
        let (settings, context) = (settings(None), context());
        let refreshed = refresh_epoch(&node, &mut duties, &[], 3, &settings, &context);
        refreshed.await.expect("refreshes");
        assert!(duties.indices().is_empty());
        assert_eq!(node.validator_indices_call_count(), 0);
    }

    /// A refresh a node holds past the end of its slot is abandoned, so the
    /// loop goes on to the next slot's duties on time, and retried there: the
    /// epoch is not marked refreshed.
    #[tokio::test(start_paused = true)]
    async fn a_refresh_held_past_the_end_of_its_slot_is_abandoned() {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let node = Arc::new(node().with_preparation_gate(gate));
        let mut duties = DutiesService::new(node.clone(), Vec::new());
        let keys = [pubkey(1), pubkey(2)];
        let budget = std::time::Duration::from_secs(12);

        let started = tokio::time::Instant::now();
        let outcome = bounded_refresh(
            &node,
            &mut duties,
            &keys,
            96,
            3,
            &settings(Some(H160([0xab; 20]))),
            &context(),
            budget,
        )
        .await;
        assert_eq!(started.elapsed(), budget);
        assert!(
            matches!(
                outcome,
                Err(Error::DutyRefreshDeadline { epoch: 3, slot: 96 })
            ),
            "got {outcome:?}"
        );

        let mut last_epoch = Some(2);
        let mut resolved = Arc::default();
        let mut node_syncing = false;
        let owed = settle_refresh(
            3,
            outcome,
            &mut last_epoch,
            &mut resolved,
            &mut node_syncing,
        )
        .expect("a deadline does not stop the client");
        assert!(owed.is_none(), "an abandoned refresh owes nothing");
        assert_eq!(last_epoch, Some(2), "the refresh runs again next slot");
        assert!(!node_syncing, "a deadline says nothing of the node's sync");
    }

    /// A refresh that got through marks its epoch done and hands over the
    /// validators whose preparations are re-sent every slot.
    #[tokio::test]
    async fn a_settled_refresh_marks_its_epoch_and_keeps_what_it_resolved() {
        let node = Arc::new(node());
        let mut duties = DutiesService::new(node.clone(), Vec::new());
        let keys = [pubkey(1), pubkey(2)];
        let outcome =
            refresh_epoch(&node, &mut duties, &keys, 3, &settings(None), &context()).await;

        let mut last_epoch = Some(2);
        let mut resolved = Arc::default();
        let mut node_syncing = true;
        let owed = settle_refresh(
            3,
            outcome,
            &mut last_epoch,
            &mut resolved,
            &mut node_syncing,
        )
        .expect("settles")
        .expect("owes its sends");
        assert!(!node_syncing, "a refresh that got through clears it");
        assert_eq!(last_epoch, Some(3));
        assert_eq!(resolved.len(), 2);
        assert!(owed.moved, "the first schedule is a move");
        assert_eq!(owed.registrable.len(), 2);
    }

    /// A refresh abandoned after it moved the attester schedule still owes
    /// the subscriptions. Its retry fetches the same roots, so only the move
    /// kept on the service can tell it so.
    #[tokio::test]
    async fn a_move_an_abandoned_refresh_made_is_reported_by_its_retry() {
        let node = Arc::new(node());
        let context = context();
        let mut duties = DutiesService::new(node.clone(), vec![11, 22]);
        // What the abandoned refresh got through before its deadline.
        duties
            .refresh_around(3, &context.config())
            .await
            .expect("refreshes");

        let keys = [pubkey(1), pubkey(2)];
        let settings = settings(None);
        let retry = refresh_epoch(&node, &mut duties, &keys, 3, &settings, &context);
        assert!(retry.await.expect("retries").moved, "the retry owes them");
        let again = refresh_epoch(&node, &mut duties, &keys, 3, &settings, &context);
        assert!(!again.await.expect("refreshes").moved, "and only once");
    }

    // ---- following dependent roots between refreshes (#827) ---------------

    /// Before fulu no cheap request names the next epoch's root, so nothing
    /// is checked between refreshes.
    #[tokio::test]
    async fn before_fulu_no_root_is_checked_between_refreshes() {
        let node = Arc::new(node());
        let mut duties = DutiesService::new(node.clone(), vec![11]);
        let budget = std::time::Duration::from_secs(1);

        let moved = follow_dependent_roots(&mut duties, 3, budget, &context().config()).await;

        assert!(!moved);
        assert_eq!(requests(&node), [0; 6]);
    }

    /// The lookahead's root moving between two slots is caught within the
    /// slot and reported, which is what makes the duty loop send the
    /// subscriptions again.
    #[tokio::test]
    async fn a_moved_lookahead_is_refetched_and_reported_for_resubscription() {
        let node = Arc::new(
            node()
                .with_proposers_v2(3, Root::repeat_byte(1), Vec::new())
                .with_proposers_v2(4, Root::repeat_byte(2), Vec::new()),
        );
        let context = fulu_context();
        let mut duties = DutiesService::new(node.clone(), Vec::new());
        let keys = [pubkey(1), pubkey(2)];
        refresh_epoch(&node, &mut duties, &keys, 3, &settings(None), &context)
            .await
            .expect("refreshes");
        let budget = std::time::Duration::from_secs(1);
        assert!(!follow_dependent_roots(&mut duties, 3, budget, &context.config()).await);

        node.set_duties(4, Root::repeat_byte(9), Vec::new());
        node.set_proposers_v2(4, Root::repeat_byte(9), Vec::new());
        assert!(follow_dependent_roots(&mut duties, 3, budget, &context.config()).await);
        assert!(
            !follow_dependent_roots(&mut duties, 3, budget, &context.config()).await,
            "once replaced, the schedule matches again"
        );
    }

    /// The gloas fork epoch's payload committee has a dependent root of its
    /// own, so it is never checked against the v2 one (it would never match);
    /// the epoch after it is.
    #[tokio::test]
    async fn the_gloas_fork_epochs_committee_is_not_checked_against_v2() {
        let node = Arc::new(
            MockBeaconNode::new()
                .with_proposers_v2(5, Root::repeat_byte(5), Vec::new())
                .with_proposers_v2(6, Root::repeat_byte(6), Vec::new())
                .with_duties(5, Root::repeat_byte(5), Vec::new())
                .with_duties(6, Root::repeat_byte(6), Vec::new())
                .with_ptc_duties(6, Root::repeat_byte(6), Vec::new()),
        );
        let config = fulu_context()
            .config()
            .as_ref()
            .clone()
            .with_fork_epoch(ethlambda_types::beacon::fork::ForkName::Gloas, 5);
        let mut duties = DutiesService::new(node.clone(), vec![11]);
        let budget = std::time::Duration::from_secs(1);

        follow_dependent_roots(&mut duties, 5, budget, &config).await;

        assert_eq!(node.ptc_requested_epochs(), vec![6]);
    }

    /// A check that replaced the attester schedule still reports the move
    /// when the payload committee fetch after it fails: the next slot's check
    /// finds the roots matching, so nothing else would send the
    /// subscriptions.
    #[tokio::test]
    async fn a_move_is_reported_although_the_committee_fetch_after_it_failed() {
        // No payload committee duties: the mock refuses them.
        let node = Arc::new(
            MockBeaconNode::new()
                .with_proposers_v2(5, Root::repeat_byte(5), Vec::new())
                .with_duties(5, Root::repeat_byte(5), Vec::new()),
        );
        let config = fulu_context()
            .config()
            .as_ref()
            .clone()
            .with_fork_epoch(ethlambda_types::beacon::fork::ForkName::Gloas, 0);
        let mut duties = DutiesService::new(node.clone(), vec![11]);
        let budget = std::time::Duration::from_secs(1);

        assert!(follow_dependent_roots(&mut duties, 5, budget, &config).await);
        assert_eq!(node.ptc_requested_epochs(), vec![5], "and it failed");
        assert!(
            !follow_dependent_roots(&mut duties, 5, budget, &config).await,
            "reported once"
        );
    }

    // ---- gloas ----------------------------------------------------------

    fn gloas_context(epoch: u64) -> SigningContext {
        SigningContext::new(
            ethlambda_types::beacon::config::Config::mainnet()
                .with_fork_epoch(ethlambda_types::beacon::fork::ForkName::Gloas, epoch),
            Root::ZERO,
        )
    }

    fn ptc_duty(index: u64, slot: u64) -> crate::beacon_node::dto::PtcDutyDto {
        crate::beacon_node::dto::PtcDutyDto {
            pubkey: crate::beacon_node::dto::encode_hex(&[0u8; 48]),
            validator_index: index,
            slot,
        }
    }

    /// The committee schedule is fetched for gloas epochs only, so a chain that
    /// has not forked is never asked. The fork epoch's is not fetched as a
    /// lookahead from the last pre-gloas epoch, since a node cannot know it
    /// before the fork, but at the fork epoch itself, with the next as the
    /// lookahead.
    #[tokio::test]
    async fn the_committee_schedule_is_fetched_for_gloas_epochs_only() {
        let node = Arc::new(
            node()
                .with_duties(5, Root::repeat_byte(2), Vec::new())
                .with_proposers(4, Root::repeat_byte(2), Vec::new())
                .with_ptc_duties(4, Root::repeat_byte(1), vec![ptc_duty(11, 130)])
                .with_ptc_duties(5, Root::repeat_byte(1), Vec::new()),
        );
        let mut duties = DutiesService::new(node.clone(), Vec::new());
        let keys = [pubkey(1), pubkey(2)];
        let gloas_at_4 = gloas_context(4);

        // Epoch 3 is the last before gloas at epoch 4: nothing is asked.
        refresh_epoch(&node, &mut duties, &keys, 3, &settings(None), &gloas_at_4)
            .await
            .expect("refreshes");
        assert_eq!(
            node.ptc_requested_epochs(),
            Vec::<u64>::new(),
            "the fork epoch's committee is not known before the fork"
        );
        assert!(duties.ptc_at_slot(130, 4).is_empty());

        // At the fork epoch, both it and the next are asked.
        refresh_epoch(&node, &mut duties, &keys, 4, &settings(None), &gloas_at_4)
            .await
            .expect("refreshes");
        assert_eq!(node.ptc_requested_epochs(), vec![4, 5]);
        assert_eq!(duties.ptc_at_slot(130, 4).len(), 1);

        // A chain with no gloas scheduled is never asked at all.
        let node = Arc::new(node_without_ptc());
        let mut duties = DutiesService::new(node.clone(), Vec::new());
        refresh_epoch(&node, &mut duties, &keys, 3, &settings(None), &context())
            .await
            .expect("refreshes");
        assert_eq!(node.ptc_call_count(), 0);
    }

    fn node_without_ptc() -> MockBeaconNode {
        node()
    }

    /// The fork epoch's committee is fetched once, at its first slot, so a
    /// fetch that failed there is retried after each slot until a schedule is
    /// held, and then no more. A pre-gloas epoch is never asked.
    #[tokio::test]
    async fn a_missing_committee_schedule_is_fetched_again() {
        // No duties stored for epoch 4 yet, so the mock refuses the request.
        let node = Arc::new(node());
        let mut duties = DutiesService::new(node.clone(), Vec::new());
        duties.set_indices(vec![11]);
        let gloas_at_4 = gloas_context(4);
        let budget = std::time::Duration::from_secs(1);

        retry_missing_ptc(&mut duties, 4, budget, &gloas_at_4).await;
        assert_eq!(node.ptc_requested_epochs(), vec![4]);
        assert!(!duties.holds_ptc(4), "a failed retry holds nothing");

        // The node answers now: the next slot's retry gets the schedule.
        node.set_ptc_duties(4, Root::repeat_byte(1), vec![ptc_duty(11, 130)]);
        retry_missing_ptc(&mut duties, 4, budget, &gloas_at_4).await;
        assert_eq!(node.ptc_requested_epochs(), vec![4, 4]);
        assert_eq!(duties.ptc_at_slot(130, 4).len(), 1);

        // Held: no further request.
        retry_missing_ptc(&mut duties, 4, budget, &gloas_at_4).await;
        assert_eq!(node.ptc_requested_epochs(), vec![4, 4]);

        // Before gloas there is no committee to ask about.
        retry_missing_ptc(&mut duties, 3, budget, &gloas_at_4).await;
        assert_eq!(node.ptc_requested_epochs(), vec![4, 4]);
    }

    /// A schedule that came back empty is still a schedule: nothing to retry.
    #[tokio::test]
    async fn an_empty_committee_schedule_is_not_fetched_again() {
        let node = Arc::new(node().with_ptc_duties(4, Root::repeat_byte(1), Vec::new()));
        let mut duties = DutiesService::new(node.clone(), Vec::new());
        duties.set_indices(vec![11]);
        let gloas_at_4 = gloas_context(4);
        let budget = std::time::Duration::from_secs(1);

        retry_missing_ptc(&mut duties, 4, budget, &gloas_at_4).await;
        retry_missing_ptc(&mut duties, 4, budget, &gloas_at_4).await;
        assert_eq!(node.ptc_requested_epochs(), vec![4]);
    }

    /// A failed committee fetch must not cost the epoch's attester schedule.
    #[tokio::test]
    async fn a_failed_committee_fetch_does_not_fail_the_refresh() {
        let node = Arc::new(node().failing_call("ptc_duties", "node is unhappy"));
        let mut duties = DutiesService::new(node.clone(), Vec::new());
        let keys = [pubkey(1), pubkey(2)];
        refresh_epoch(
            &node,
            &mut duties,
            &keys,
            3,
            &settings(None),
            &gloas_context(0),
        )
        .await
        .expect("the refresh survives it");
        assert_eq!(duties.indices(), &[11, 22]);
    }

    /// The restructured loop: a client on a slot's committee with no attester
    /// duty at all must still vote. This is the case the old early `continue`
    /// on "no attester duties" would have skipped.
    #[tokio::test]
    async fn a_committee_member_with_no_attester_duty_still_votes() {
        use crate::beacon_node::mock::MockBeaconNode;
        use ethlambda_types::beacon::containers::gloas::PayloadAttestationData;

        let mut config = ethlambda_types::beacon::config::Config::mainnet()
            .with_fork_epoch(ethlambda_types::beacon::fork::ForkName::Gloas, 0);
        config.slot_duration_ms = 1_000;
        let context = Arc::new(SigningContext::new(config.clone(), Root::ZERO));
        let now_secs = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_secs();
        let clock = SlotClock::from_config(now_secs - 100, &config);
        let slot = clock.now().expect("after genesis") + 1;

        let mut store = ValidatorStore::new();
        let secret: [u8; 32] =
            hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .expect("hex")
                .try_into()
                .expect("32 bytes");
        let key = store.insert_secret("test", &secret).expect("inserts");
        let store = RwLock::new(store);

        let node = Arc::new(MockBeaconNode::new().with_payload_attestation_data(
            PayloadAttestationData {
                beacon_block_root: Root::repeat_byte(5),
                slot,
                payload_present: true,
                blob_data_available: true,
            },
        ));
        let committee = [crate::beacon_node::dto::PtcDutyDto {
            pubkey: crate::beacon_node::dto::encode_hex(&key.0),
            validator_index: 3,
            slot,
        }];

        serve_slot_duties(
            &AttestationService::new(
                node.clone(),
                context.clone(),
                slashing_protection::SlashingProtection::in_memory(),
            ),
            &AggregationService::new(node.clone(), context.clone()),
            &PayloadAttestationService::new(node.clone(), context.clone()),
            &SyncCommitteeService::new(node.clone(), context.clone()),
            &DutyTriggers::off(),
            &clock,
            slot,
            &[],
            &committee,
            &[],
            &store,
        )
        .await;

        assert_eq!(node.attestation_data_call_count(), 0, "no attester duty");
        assert_eq!(node.submitted_payload_attestations().len(), 1);
    }

    /// With live triggers, each of a gloas slot's duties signs once, and the
    /// payload vote, started by its payload event, does not wait behind the
    /// slot's attestation: here that one's early request hangs until its
    /// deadline, and the vote is out before it.
    #[tokio::test]
    async fn with_live_triggers_each_duty_signs_once_and_the_vote_does_not_wait() {
        use crate::beacon_node::events::{
            EventSource, HeadEvent, NodeEvent, PayloadAvailableEvent, Topic,
        };
        use crate::beacon_node::mock::{MockBeaconNode, StreamEnd, StreamStep};
        use crate::head_monitor::HeadMonitor;
        use ethlambda_types::beacon::containers::gloas::PayloadAttestationData;
        use std::time::Duration;

        let mut config = ethlambda_types::beacon::config::Config::mainnet()
            .with_fork_epoch(ethlambda_types::beacon::fork::ForkName::Gloas, 0);
        config.slot_duration_ms = 1_000;
        let context = Arc::new(SigningContext::new(config.clone(), Root::ZERO));
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch");
        let genesis = now.as_secs() - 100;
        let clock = SlotClock::from_config(genesis, &config);
        let slot = clock.now().expect("after genesis") + 1;
        // When the slot starts, from now: its events are scripted from there.
        let slot_start = Duration::from_secs(genesis + slot) - now;
        let at = |millis: u64| StreamStep::Wait(slot_start + Duration::from_millis(millis));

        let (store, pubkeys) = crate::test_support::store_with_keys(1);
        let store = RwLock::new(store);
        let pubkey = crate::beacon_node::dto::encode_hex(&pubkeys[0].0);
        let block = Root::repeat_byte(5);

        let head = NodeEvent::Head(HeadEvent {
            slot,
            block,
            execution_optimistic: false,
        });
        let payload = NodeEvent::PayloadAvailable(PayloadAvailableEvent {
            slot,
            block_root: block,
        });
        let node = Arc::new(
            MockBeaconNode::new()
                .with_attestation_data(slot)
                .with_attestation_block_root(block)
                // The early attestation request hangs past its deadline.
                .with_first_call_delay("attestation_data", Duration::from_secs(10))
                .with_head_root(block)
                .with_payload_attestation_data(PayloadAttestationData {
                    beacon_block_root: block,
                    slot,
                    payload_present: true,
                    blob_data_available: true,
                })
                .with_topic_stream(
                    Topic::Head,
                    vec![at(30), StreamStep::Event(head)],
                    StreamEnd::Hang,
                )
                .with_topic_stream(
                    Topic::ExecutionPayloadAvailable,
                    vec![at(60), StreamStep::Event(payload)],
                    StreamEnd::Hang,
                ),
        );
        let sources = vec![("mock".to_string(), node.clone() as Arc<dyn EventSource>)];
        let (_monitor, triggers) = HeadMonitor::spawn(sources, || true);

        let attester = [crate::beacon_node::dto::AttesterDutyDto {
            pubkey: pubkey.clone(),
            validator_index: 3,
            committee_index: 0,
            committee_length: 128,
            committees_at_slot: 1,
            validator_committee_index: 0,
            slot,
        }];
        let committee = [crate::beacon_node::dto::PtcDutyDto {
            pubkey: pubkey.clone(),
            validator_index: 3,
            slot,
        }];
        let sync = [crate::beacon_node::dto::SyncDutyDto {
            pubkey,
            validator_index: 3,
            validator_sync_committee_indices: vec![0],
        }];

        let attestation = AttestationService::new(
            node.clone(),
            context.clone(),
            slashing_protection::SlashingProtection::in_memory(),
        );
        let aggregation = AggregationService::new(node.clone(), context.clone());
        let payload_attestation = PayloadAttestationService::new(node.clone(), context.clone());
        let sync_committee = SyncCommitteeService::new(node.clone(), context.clone());
        let serve = serve_slot_duties(
            &attestation,
            &aggregation,
            &payload_attestation,
            &sync_committee,
            &triggers,
            &clock,
            slot,
            &attester,
            &committee,
            &sync,
            &store,
        );
        // How many attestations were out when the vote went out.
        let watch = async {
            while node.submitted_payload_attestations().is_empty() {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            node.submitted().len()
        };
        let ((), attested_before_the_vote) = tokio::join!(serve, watch);

        assert_eq!(
            attested_before_the_vote, 0,
            "the vote waited for the attestation"
        );
        assert_eq!(node.submitted().len(), 1, "one attestation");
        assert_eq!(
            node.attestation_data_call_count(),
            2,
            "early, then deadline"
        );
        assert_eq!(node.submitted_sync_messages().len(), 1, "one sync message");
        assert_eq!(node.submitted_payload_attestations().len(), 1, "one vote");
    }

    fn altair_context() -> SigningContext {
        SigningContext::new(
            ethlambda_types::beacon::config::Config::mainnet()
                .with_fork_epoch(ethlambda_types::beacon::fork::ForkName::Altair, 0),
            Root::ZERO,
        )
    }

    fn sync_duty(index: u64, seats: Vec<u64>) -> crate::beacon_node::dto::SyncDutyDto {
        crate::beacon_node::dto::SyncDutyDto {
            pubkey: crate::beacon_node::dto::encode_hex(&[0u8; 48]),
            validator_index: index,
            validator_sync_committee_indices: seats,
        }
    }

    /// Both periods' duties are fetched, and the current period's subnets are
    /// subscribed every refresh, to the period's end.
    #[tokio::test]
    async fn sync_duties_for_both_periods_are_fetched_and_subscribed() {
        use ethlambda_types::beacon::preset::epochs_per_sync_committee_period as period;

        let node = Arc::new(
            node()
                .with_sync_duties(0, vec![sync_duty(11, vec![3, 130])])
                .with_sync_duties(period(), vec![sync_duty(11, vec![200])]),
        );
        let mut duties = DutiesService::new(node.clone(), Vec::new());
        let keys = [pubkey(1), pubkey(2)];
        for _ in 0..2 {
            refresh_epoch(
                &node,
                &mut duties,
                &keys,
                3,
                &settings(None),
                &altair_context(),
            )
            .await
            .expect("refreshes");
        }

        let requested: Vec<u64> = node
            .sync_duty_requests()
            .iter()
            .map(|(epoch, _)| *epoch)
            .collect();
        assert_eq!(requested, vec![0, period(), 0, period()]);
        assert_eq!(duties.sync_for_period(1).len(), 1);

        let sent = node.sync_subscriptions();
        assert_eq!(sent.len(), 2, "re-sent every epoch, current period only");
        assert_eq!(sent[0].sync_committee_indices, vec![3, 130]);
        assert_eq!(sent[0].until_epoch, period());
    }

    /// Not asked before altair.
    #[tokio::test]
    async fn no_sync_duties_are_fetched_before_altair() {
        let node = Arc::new(node());
        refresh(node.clone(), None).await;
        assert!(node.sync_duty_requests().is_empty());
    }

    /// A failed sync fetch must not cost the epoch's attester schedule.
    #[tokio::test]
    async fn a_failed_sync_fetch_does_not_fail_the_refresh() {
        let node = Arc::new(node().failing_call("sync_duties", "node is unhappy"));
        let mut duties = DutiesService::new(node.clone(), Vec::new());
        let keys = [pubkey(1), pubkey(2)];
        refresh_epoch(
            &node,
            &mut duties,
            &keys,
            3,
            &settings(None),
            &altair_context(),
        )
        .await
        .expect("the refresh survives it");
        assert_eq!(duties.indices(), &[11, 22]);
    }

    /// A sync committee member with no other duty in the slot still signs.
    #[tokio::test]
    async fn a_sync_committee_member_with_no_other_duty_still_signs() {
        use crate::beacon_node::mock::MockBeaconNode;

        let mut config = ethlambda_types::beacon::config::Config::mainnet()
            .with_fork_epoch(ethlambda_types::beacon::fork::ForkName::Altair, 0);
        config.slot_duration_ms = 1_000;
        let context = Arc::new(SigningContext::new(config.clone(), Root::ZERO));
        let now_secs = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_secs();
        let clock = SlotClock::from_config(now_secs - 100, &config);
        let slot = clock.now().expect("after genesis") + 1;

        let mut store = ValidatorStore::new();
        let secret: [u8; 32] =
            hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .expect("hex")
                .try_into()
                .expect("32 bytes");
        let key = store.insert_secret("test", &secret).expect("inserts");
        let store = RwLock::new(store);

        let node = Arc::new(MockBeaconNode::new().with_head_root(Root::repeat_byte(5)));
        let duties = [crate::beacon_node::dto::SyncDutyDto {
            pubkey: crate::beacon_node::dto::encode_hex(&key.0),
            validator_index: 3,
            validator_sync_committee_indices: vec![0],
        }];

        serve_slot_duties(
            &AttestationService::new(
                node.clone(),
                context.clone(),
                slashing_protection::SlashingProtection::in_memory(),
            ),
            &AggregationService::new(node.clone(), context.clone()),
            &PayloadAttestationService::new(node.clone(), context.clone()),
            &SyncCommitteeService::new(node.clone(), context.clone()),
            &DutyTriggers::off(),
            &clock,
            slot,
            &[],
            &[],
            &duties,
            &store,
        )
        .await;

        assert_eq!(node.attestation_data_call_count(), 0, "no attester duty");
        let sent = node.submitted_sync_messages();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].slot, slot);
        assert_eq!(sent[0].beacon_block_root, Root::repeat_byte(5));
    }

    /// Before gloas there is no committee: even a stale schedule entry is not
    /// acted on.
    #[tokio::test]
    async fn no_committee_vote_is_cast_before_gloas() {
        use crate::beacon_node::mock::MockBeaconNode;

        let config = ethlambda_types::beacon::config::Config::mainnet();
        let context = Arc::new(SigningContext::new(config.clone(), Root::ZERO));
        let clock = SlotClock::from_config(0, &config);
        let node = Arc::new(MockBeaconNode::new());
        let store = empty_store();

        serve_slot_duties(
            &AttestationService::new(
                node.clone(),
                context.clone(),
                slashing_protection::SlashingProtection::in_memory(),
            ),
            &AggregationService::new(node.clone(), context.clone()),
            &PayloadAttestationService::new(node.clone(), context.clone()),
            &SyncCommitteeService::new(node.clone(), context.clone()),
            &DutyTriggers::off(),
            &clock,
            5,
            &[],
            &[ptc_duty(3, 5)],
            &[],
            &store,
        )
        .await;
        assert_eq!(node.payload_attestation_data_call_count(), 0);
    }

    // Stopping.

    /// Stands in for the keymanager server with a request in flight: told to
    /// stop, it takes `work` to finish, and the flag says when it has.
    fn keymanager_finishing_in(
        shutdown: &CancellationToken,
        work: std::time::Duration,
    ) -> (JoinHandle<()>, Arc<std::sync::atomic::AtomicBool>) {
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handle = tokio::spawn({
            let shutdown = shutdown.clone();
            let finished = finished.clone();
            async move {
                shutdown.cancelled().await;
                tokio::time::sleep(work).await;
                finished.store(true, std::sync::atomic::Ordering::Release);
            }
        });
        (handle, finished)
    }

    /// A record poisoned by one of its accesses stops duties that would
    /// otherwise never end, and the client is not reported stopped until the
    /// keymanager has finished what it had in flight.
    #[tokio::test(start_paused = true)]
    async fn an_unusable_record_stops_the_client_once_the_keymanager_has_finished() {
        let protection = slashing_protection::SlashingProtection::in_memory();
        let shutdown = CancellationToken::new();
        let (keymanager, finished) =
            keymanager_finishing_in(&shutdown, std::time::Duration::from_secs(5));

        slashing_protection::blocking(&protection, |_| -> Result<()> {
            panic!("a bug in the record")
        })
        .await
        .expect_err("the access panicked");

        let stopped = run_until_stopped(
            std::future::pending(),
            &protection,
            std::future::pending(),
            shutdown.clone(),
            Some(keymanager),
            &TaskTracker::new(),
        )
        .await;
        assert!(
            matches!(stopped, Err(Error::SlashingProtectionUnusable { .. })),
            "got {stopped:?}"
        );
        assert!(shutdown.is_cancelled(), "the keymanager was told to stop");
        assert!(
            finished.load(std::sync::atomic::Ordering::Acquire),
            "its request in flight finishes before the client stops"
        );
    }

    /// The duties an unusable record stops are dropped where they stand, and
    /// are gone by the time the keymanager is told to stop, rather than held
    /// suspended through its drain.
    #[tokio::test(start_paused = true)]
    async fn an_unusable_record_drops_the_duties_before_the_keymanager_drains() {
        use std::sync::atomic::{AtomicBool, Ordering};

        /// Sets its flag when the future holding it is dropped.
        struct DropFlag(Arc<AtomicBool>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let protection = slashing_protection::SlashingProtection::in_memory();
        slashing_protection::blocking(&protection, |_| -> Result<()> {
            panic!("a bug in the record")
        })
        .await
        .expect_err("the access panicked");

        let dropped = Arc::new(AtomicBool::new(false));
        let duties = {
            let guard = DropFlag(dropped.clone());
            async move {
                let _guard = guard;
                std::future::pending::<Result<()>>().await
            }
        };
        let shutdown = CancellationToken::new();
        let gone_when_told = Arc::new(AtomicBool::new(false));
        let keymanager = tokio::spawn({
            let (shutdown, dropped, gone_when_told) =
                (shutdown.clone(), dropped.clone(), gone_when_told.clone());
            async move {
                shutdown.cancelled().await;
                let gone = dropped.load(Ordering::Acquire);
                gone_when_told.store(gone, Ordering::Release);
            }
        });

        let stopped = run_until_stopped(
            duties,
            &protection,
            std::future::pending(),
            shutdown,
            Some(keymanager),
            &TaskTracker::new(),
        )
        .await;
        assert!(
            matches!(stopped, Err(Error::SlashingProtectionUnusable { .. })),
            "got {stopped:?}"
        );
        assert!(
            gone_when_told.load(Ordering::Acquire),
            "the duties were dropped before the keymanager was told to stop"
        );
    }

    /// Duties that end on their own leave the same way: with the error that
    /// ended them, after the keymanager has finished.
    #[tokio::test(start_paused = true)]
    async fn duties_that_stop_on_their_own_also_wait_for_the_keymanager() {
        let protection = slashing_protection::SlashingProtection::in_memory();
        let shutdown = CancellationToken::new();
        let (keymanager, finished) =
            keymanager_finishing_in(&shutdown, std::time::Duration::from_secs(5));

        let stopped = run_until_stopped(
            async { Err(Error::BeaconNodeSyncing) },
            &protection,
            std::future::pending(),
            shutdown,
            Some(keymanager),
            &TaskTracker::new(),
        )
        .await;
        assert!(
            matches!(stopped, Err(Error::BeaconNodeSyncing)),
            "got {stopped:?}"
        );
        assert!(finished.load(std::sync::atomic::Ordering::Acquire));
    }

    /// A request that never ends does not keep a stopped client from being
    /// restarted: the wait for the keymanager is bounded.
    #[tokio::test(start_paused = true)]
    async fn a_keymanager_that_never_finishes_does_not_hold_the_client_up() {
        let protection = slashing_protection::SlashingProtection::in_memory();
        let keymanager = tokio::spawn(std::future::pending::<()>());

        let before = tokio::time::Instant::now();
        let stopped = run_until_stopped(
            async { Err(Error::BeaconNodeSyncing) },
            &protection,
            std::future::pending(),
            CancellationToken::new(),
            Some(keymanager),
            &TaskTracker::new(),
        )
        .await;
        assert!(
            matches!(stopped, Err(Error::BeaconNodeSyncing)),
            "got {stopped:?}"
        );
        assert_eq!(before.elapsed(), KEYMANAGER_DRAIN);
    }

    /// Stands in for the duty loop with a slot in flight: told to stop, it
    /// takes `work` to finish the slot and then returns between slots, and
    /// the flag says when it has.
    fn duties_finishing_in(
        shutdown: &CancellationToken,
        work: std::time::Duration,
    ) -> (
        impl Future<Output = Result<()>>,
        Arc<std::sync::atomic::AtomicBool>,
    ) {
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let duties = {
            let shutdown = shutdown.clone();
            let finished = finished.clone();
            async move {
                shutdown.cancelled().await;
                tokio::time::sleep(work).await;
                finished.store(true, std::sync::atomic::Ordering::Release);
                Ok(())
            }
        };
        (duties, finished)
    }

    /// A shutdown signal is a clean stop: the duty loop and the keymanager
    /// are told to stop, and the client returns `Ok` only once the slot in
    /// flight, a blinded block's publish and the keymanager's request have
    /// all finished.
    #[tokio::test(start_paused = true)]
    async fn a_signal_stops_the_client_once_the_work_in_flight_has_finished() {
        let secs = std::time::Duration::from_secs;
        let protection = slashing_protection::SlashingProtection::in_memory();
        let shutdown = CancellationToken::new();
        let (keymanager, keymanager_finished) = keymanager_finishing_in(&shutdown, secs(2));
        let (duties, slot_finished) = duties_finishing_in(&shutdown, secs(3));
        let tasks = TaskTracker::new();
        let published = Arc::new(std::sync::atomic::AtomicBool::new(false));
        tasks.spawn({
            let published = published.clone();
            async move {
                tokio::time::sleep(secs(6)).await;
                published.store(true, std::sync::atomic::Ordering::Release);
            }
        });
        let signal = async {
            tokio::time::sleep(secs(1)).await;
            "SIGTERM"
        };

        let before = tokio::time::Instant::now();
        let stopped = run_until_stopped(
            duties,
            &protection,
            signal,
            shutdown.clone(),
            Some(keymanager),
            &tasks,
        )
        .await;
        assert!(stopped.is_ok(), "a signal is a clean stop, got {stopped:?}");
        assert!(shutdown.is_cancelled(), "the duty loop was told to stop");
        let acquire = std::sync::atomic::Ordering::Acquire;
        assert!(slot_finished.load(acquire), "the slot in flight finished");
        assert!(published.load(acquire), "the blinded publish finished");
        assert!(keymanager_finished.load(acquire), "the request finished");
        // The publish ends last, 6 s in, which is 5 s after the signal and
        // within the drain.
        assert_eq!(before.elapsed(), secs(6));
    }

    /// Work in flight that never finishes does not keep a signalled client
    /// from stopping: the slot and the publish share `DUTY_DRAIN` from the
    /// signal, and the stop is still clean.
    #[tokio::test(start_paused = true)]
    async fn a_signal_stops_the_client_at_the_drain_deadline_whatever_is_left() {
        let protection = slashing_protection::SlashingProtection::in_memory();
        let tasks = TaskTracker::new();
        tasks.spawn(std::future::pending::<()>());

        let before = tokio::time::Instant::now();
        let stopped = run_until_stopped(
            std::future::pending(),
            &protection,
            async { "SIGINT" },
            CancellationToken::new(),
            None,
            &tasks,
        )
        .await;
        assert!(stopped.is_ok(), "got {stopped:?}");
        assert_eq!(before.elapsed(), DUTY_DRAIN);
    }

    /// Duties that end in an error while the slot in flight finishes stop the
    /// client with that error rather than a clean stop.
    #[tokio::test(start_paused = true)]
    async fn an_error_while_the_slot_finishes_is_still_an_error() {
        let protection = slashing_protection::SlashingProtection::in_memory();
        let shutdown = CancellationToken::new();
        let duties = {
            let shutdown = shutdown.clone();
            async move {
                shutdown.cancelled().await;
                Err(Error::BeaconNodeSyncing)
            }
        };

        let stopped = run_until_stopped(
            duties,
            &protection,
            async { "SIGTERM" },
            shutdown,
            None,
            &TaskTracker::new(),
        )
        .await;
        assert!(
            matches!(stopped, Err(Error::BeaconNodeSyncing)),
            "got {stopped:?}"
        );
    }

    fn attester_duty(
        pubkey: &BlsPubkey,
        validator_index: u64,
    ) -> beacon_node::dto::AttesterDutyDto {
        beacon_node::dto::AttesterDutyDto {
            pubkey: beacon_node::dto::encode_hex(&pubkey.0),
            validator_index,
            committee_index: 0,
            committee_length: 128,
            committees_at_slot: 64,
            validator_committee_index: 0,
            slot: 3200,
        }
    }

    /// The duty loop drops a withheld key's attester duties, and with them
    /// its aggregation, before anything is recorded or fetched for it; a
    /// cleared key's duties go through.
    #[test]
    fn only_cleared_keys_keep_their_attester_and_proposer_duties() {
        let doppelganger = Arc::new(doppelganger::Doppelganger::new());
        doppelganger.register(pubkey(1), 0);
        doppelganger.register(pubkey(2), 100);
        let context = context().with_doppelganger(doppelganger);

        let duties = vec![
            attester_duty(&pubkey(1), 11),
            attester_duty(&pubkey(2), 22),
            attester_duty(&pubkey(3), 33),
        ];
        let kept: Vec<u64> = withhold_uncleared(&context, 3200, duties)
            .iter()
            .map(|duty| duty.validator_index)
            .collect();
        assert_eq!(kept, vec![11], "under the check, and never registered");

        assert!(doppelganger_cleared(
            &context,
            &beacon_node::dto::encode_hex(&pubkey(1).0)
        ));
        assert!(!doppelganger_cleared(
            &context,
            &beacon_node::dto::encode_hex(&pubkey(2).0)
        ));
        assert!(!doppelganger_cleared(&context, "not a pubkey"));
    }

    /// With the protection off the filter is not there at all.
    #[test]
    fn without_doppelganger_protection_every_duty_is_kept() {
        let duties = vec![attester_duty(&pubkey(1), 11), attester_duty(&pubkey(2), 22)];
        assert_eq!(withhold_uncleared(&context(), 3200, duties).len(), 2);
        assert!(doppelganger_cleared(&context(), "not a pubkey"));
    }

    /// With no keymanager there is nothing to wait for.
    #[tokio::test(start_paused = true)]
    async fn stopping_without_a_keymanager_waits_for_nothing() {
        let protection = slashing_protection::SlashingProtection::in_memory();
        let before = tokio::time::Instant::now();
        let stopped = run_until_stopped(
            async { Err(Error::BeaconNodeSyncing) },
            &protection,
            std::future::pending(),
            CancellationToken::new(),
            None,
            &TaskTracker::new(),
        )
        .await;
        assert!(
            matches!(stopped, Err(Error::BeaconNodeSyncing)),
            "got {stopped:?}"
        );
        assert_eq!(before.elapsed(), std::time::Duration::ZERO);
    }
}
