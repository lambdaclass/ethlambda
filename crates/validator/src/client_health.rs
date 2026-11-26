//! What `/health` answers: whether this client can do its duties now.
//!
//! # Cheap and local
//!
//! [`ClientHealth::report`] reads state the client already keeps and asks no
//! beacon node anything: each node's latest sync probe
//! ([`crate::beacon_node::health`]), the key store, the last duty refresh and
//! the slashing-protection record's last write. Nothing in it waits on a lock.
//! The key store is read with `try_read`, falling back to the last count read,
//! since a keymanager import holds it while it decrypts a batch. The record's
//! outcome is read from two atomics beside its mutex, which the stuck write
//! being reported would be holding.
//!
//! # The checks
//!
//! - **`beacon_nodes`**: `usable` counts the nodes whose latest probe was
//!   answered, neither syncing nor optimistic, and is at most two slots old,
//!   out of the `configured` ones. One usable node passes. A probe older than
//!   that means the probe task stopped, which leaves nothing to vouch for the
//!   node.
//! - **`validators`**: `loaded` and `resolved`, reported and never failing. A
//!   key waiting for activation has no index, and a client started with no
//!   keys to wait for a keymanager import is idle on purpose; neither is
//!   fixed by restarting it or taking it out of rotation. A key doppelganger
//!   protection still withholds counts as loaded.
//! - **`slashing_protection.last_write_ok`**: the record's last write
//!   succeeded and the last access did not give up waiting for it (see
//!   [`SharedProtection::last_write_ok`]). A failed write fails the check
//!   until a later write succeeds.
//! - **`started`**: a duty refresh has succeeded since the process started.
//! - **`schedule_current`**: the attester schedule the last successful duty
//!   refresh left held reaches the clock's epoch: its own epoch, and the next
//!   when the lookahead fetch went through too. A node can answer its probe
//!   synced and still fail every refresh, or every lookahead; once the
//!   schedule runs out the client has no attestations to make. `true` before
//!   the first refresh, which `started` reports, and before genesis. A
//!   refresh that resolved no validator holds no schedule to run out, and
//!   counts through the next epoch.
//!
//! # Status
//!
//! - `healthy`, `200`: started, at least one usable node, the record's last
//!   write went through, and the schedule is current.
//! - `starting`, `503`: not started yet, and nothing else has failed. A node
//!   not probed yet does not count against the client before it starts, so a
//!   normal startup reads `starting` throughout rather than `unhealthy`. Once
//!   started, a node with no probe counts as unusable: the first refresh runs
//!   at the boundary the first probe was taken ahead of, so a node with no
//!   record by then has not answered it, or the probe task is not running.
//!   Without that, a probe task that never ran would leave the client
//!   `healthy` with nothing to vouch for a node.
//! - `unhealthy`, `503`: anything else.
//!
//! A client with some nodes unusable and at least one usable is `healthy`,
//! with the counts in the body.
//!
//! The same report sets `ethlambda_validator_healthy`,
//! `ethlambda_validator_beacon_node_available` and
//! `ethlambda_validator_validators_loaded` on every scrape of `/metrics` (see
//! [`publish`]), so an alert on a gauge and a probe of the endpoint read one
//! answer.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

use axum::http::StatusCode;
use ethlambda_types::beacon::primitives::Epoch;
use serde::Serialize;
use tokio::sync::RwLock;

use crate::beacon_node::health::{NodeHealth, Probe, Standing};
use crate::keys::ValidatorStore;
use crate::slashing_protection::SharedProtection;
use crate::slot_clock::SlotClock;

/// What every report names as its `service`.
pub const SERVICE: &str = "ethlambda-validator";

/// How many slots a node's latest probe is read for. Probes are a slot
/// apart, so only a probe task that stopped leaves one this old; the same
/// bound the fallback reads probes for when it routes.
const PROBE_READ_SLOTS: u32 = 2;

/// [`ClientHealth::covered_through`] before any refresh has succeeded.
const NOT_REFRESHED: u64 = u64::MAX;

/// The state `/health` reads, shared by the metrics server, which reports it,
/// and the duty loop, which keeps it.
pub struct ClientHealth {
    /// How many beacon nodes were configured, known before any is reached.
    configured: usize,
    store: Arc<RwLock<ValidatorStore>>,
    /// The last count read from `store`, answered while a writer holds it.
    loaded: AtomicU64,
    /// Validators the last successful refresh resolved to an index.
    resolved: AtomicU64,
    /// A duty refresh has succeeded.
    started: AtomicBool,
    /// The last epoch the attester schedule held after the last successful
    /// refresh: [`NOT_REFRESHED`] before the first.
    covered_through: AtomicU64,
    /// Set once the beacon nodes and the record exist, which is after the
    /// metrics server is already answering.
    attached: OnceLock<Attached>,
}

struct Attached {
    nodes: Arc<NodeHealth>,
    /// How old a probe may be and still be read.
    read_for: Duration,
    /// What says which epoch it is, for the schedule check.
    clock: SlotClock,
    protection: SharedProtection,
}

impl ClientHealth {
    /// The state of a client that has done nothing yet: `starting`, with
    /// `configured` beacon nodes none of which is probed, and `store`'s keys.
    pub fn new(configured: usize, store: Arc<RwLock<ValidatorStore>>) -> Self {
        let loaded = store.try_read().map_or(0, |store| store.len() as u64);
        Self {
            configured,
            store,
            loaded: AtomicU64::new(loaded),
            resolved: AtomicU64::new(0),
            started: AtomicBool::new(false),
            covered_through: AtomicU64::new(NOT_REFRESHED),
            attached: OnceLock::new(),
        }
    }

    /// Read the beacon nodes' probes from `nodes`, judging a probe stale past
    /// two of `clock`'s slots, the epoch from `clock`, and the record's last
    /// write from `protection`. Called once, after the preset is adopted,
    /// since an epoch's length is read from it; a second call changes nothing.
    pub fn attach(&self, nodes: Arc<NodeHealth>, clock: SlotClock, protection: SharedProtection) {
        let _ = self.attached.set(Attached {
            nodes,
            read_for: clock.slot_duration() * PROBE_READ_SLOTS,
            clock,
            protection,
        });
    }

    /// A duty refresh succeeded, resolving `resolved` validators to an index
    /// and leaving the attester schedule held through `covered_through`. The
    /// first one is what moves the client from `starting`.
    pub fn epoch_refreshed(&self, resolved: usize, covered_through: Epoch) {
        self.resolved.store(resolved as u64, Ordering::Relaxed);
        self.covered_through
            .store(covered_through, Ordering::Relaxed);
        self.started.store(true, Ordering::Relaxed);
    }

    /// The attester schedule held reaches the epoch `now` is in, or no
    /// refresh has succeeded yet, or it is before genesis.
    fn schedule_current(&self, attached: &Attached, now: SystemTime) -> bool {
        let covered = self.covered_through.load(Ordering::Relaxed);
        covered == NOT_REFRESHED
            || attached
                .clock
                .slot_at(now)
                .is_none_or(|slot| attached.clock.epoch_of(slot) <= covered)
    }

    /// What `/health` answers now.
    pub fn report(&self) -> Report {
        self.report_at(SystemTime::now())
    }

    fn report_at(&self, now: SystemTime) -> Report {
        let attached = self.attached.get();
        let nodes = match attached {
            Some(attached) => tally(&attached.nodes.snapshot(), attached.read_for, now),
            None => NodeTally {
                usable: 0,
                unprobed: self.configured,
            },
        };
        let last_write_ok = attached.is_none_or(|attached| attached.protection.last_write_ok());
        let started = self.started.load(Ordering::Relaxed);
        let schedule_current = attached.is_none_or(|attached| self.schedule_current(attached, now));

        let nodes_ok = nodes.usable > 0;
        let status = if started && nodes_ok && last_write_ok && schedule_current {
            Status::Healthy
        } else if !started && last_write_ok && (nodes_ok || nodes.unprobed > 0) {
            Status::Starting
        } else {
            Status::Unhealthy
        };

        Report {
            status,
            service: SERVICE,
            checks: Checks {
                beacon_nodes: BeaconNodes {
                    usable: nodes.usable,
                    configured: self.configured,
                },
                validators: Validators {
                    loaded: self.loaded(),
                    resolved: self.resolved.load(Ordering::Relaxed),
                },
                slashing_protection: SlashingProtectionCheck { last_write_ok },
                started,
                schedule_current,
            },
        }
    }

    /// How many keys the store holds, or the last count read while a writer
    /// holds it.
    fn loaded(&self) -> u64 {
        match self.store.try_read() {
            Ok(store) => {
                let loaded = store.len() as u64;
                self.loaded.store(loaded, Ordering::Relaxed);
                loaded
            }
            Err(_) => self.loaded.load(Ordering::Relaxed),
        }
    }
}

/// How the configured nodes split, as the report reads them.
#[derive(Debug, Default, PartialEq, Eq)]
struct NodeTally {
    /// Latest probe answered, neither syncing nor optimistic, and readable.
    usable: usize,
    /// No probe recorded yet.
    unprobed: usize,
}

fn tally(probes: &[Option<Probe>], read_for: Duration, now: SystemTime) -> NodeTally {
    let mut tally = NodeTally::default();
    for probe in probes {
        match probe {
            None => tally.unprobed += 1,
            Some(probe) if is_usable(probe, read_for, now) => tally.usable += 1,
            Some(_) => {}
        }
    }
    tally
}

fn is_usable(probe: &Probe, read_for: Duration, now: SystemTime) -> bool {
    let age = now.duration_since(probe.at).unwrap_or_default();
    age <= read_for && probe.standing() == Standing::Synced
}

/// Set the gauges that mirror `report`: `ethlambda_validator_healthy`,
/// `ethlambda_validator_beacon_node_available` and
/// `ethlambda_validator_validators_loaded`. The metrics server calls this on
/// every scrape, before it gathers, so the series read what `/health` would
/// have answered at that moment.
pub fn publish(report: &Report) {
    crate::metrics::set_healthy(report.is_healthy());
    crate::metrics::set_beacon_node_available(report.beacon_node_available());
    crate::metrics::set_validators_loaded(report.checks.validators.loaded);
}

/// `/health`'s body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub status: Status,
    pub service: &'static str,
    pub checks: Checks,
}

impl Report {
    /// The client can do its duties.
    pub fn is_healthy(&self) -> bool {
        self.status == Status::Healthy
    }

    /// `200` when healthy, `503` otherwise, starting included.
    pub fn status_code(&self) -> StatusCode {
        if self.is_healthy() {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        }
    }

    /// At least one configured beacon node is usable: what
    /// `ethlambda_validator_beacon_node_available` reports.
    pub fn beacon_node_available(&self) -> bool {
        self.checks.beacon_nodes.usable > 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Healthy,
    Starting,
    Unhealthy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Checks {
    pub beacon_nodes: BeaconNodes,
    pub validators: Validators,
    pub slashing_protection: SlashingProtectionCheck,
    pub started: bool,
    pub schedule_current: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BeaconNodes {
    pub usable: usize,
    pub configured: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Validators {
    pub loaded: u64,
    pub resolved: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SlashingProtectionCheck {
    pub last_write_ok: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::beacon_node::health::SyncStatus;
    use crate::slashing_protection::SlashingProtection;

    const SLOT: Duration = Duration::from_secs(12);

    fn status(is_syncing: bool, is_optimistic: bool) -> SyncStatus {
        SyncStatus {
            head_slot: Some(100),
            sync_distance: Some(0),
            is_syncing,
            is_optimistic,
            el_offline: false,
        }
    }

    fn probe(outcome: Result<SyncStatus, String>) -> Probe {
        Probe {
            slot: 10,
            at: SystemTime::now(),
            outcome,
        }
    }

    fn synced() -> Probe {
        probe(Ok(status(false, false)))
    }

    fn syncing() -> Probe {
        probe(Ok(status(true, false)))
    }

    fn optimistic() -> Probe {
        probe(Ok(status(false, true)))
    }

    fn down() -> Probe {
        probe(Err("connection refused".to_string()))
    }

    fn store_of(keys: u8) -> Arc<RwLock<ValidatorStore>> {
        let mut store = ValidatorStore::new();
        for key in 1..=keys {
            store
                .insert_secret("test", &[key; 32])
                .expect("a valid secret");
        }
        Arc::new(RwLock::new(store))
    }

    /// Slots of [`SLOT`], with genesis a day from now. Before genesis every
    /// schedule is current, so only the test that sets a clock past genesis
    /// reads the schedule check.
    fn clock() -> SlotClock {
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after 1970")
            .as_secs();
        SlotClock::new(now + 86_400, SLOT.as_millis() as u64, 3_333, 6_667)
    }

    /// A client with `nodes` beacon nodes and `keys` keys, attached to an
    /// in-memory record, before any probe or refresh.
    fn client(nodes: usize, keys: u8) -> (ClientHealth, Arc<NodeHealth>) {
        let health = ClientHealth::new(nodes, store_of(keys));
        let probes = Arc::new(NodeHealth::new(nodes));
        health.attach(probes.clone(), clock(), SlashingProtection::in_memory());
        (health, probes)
    }

    /// The body is the issue's: `status`, `service` and the four checks, each
    /// with exactly the fields it names, plus `schedule_current`.
    #[test]
    fn the_body_has_the_issues_shape() {
        let (health, probes) = client(2, 3);
        probes.record(0, synced());
        probes.record(1, down());
        health.epoch_refreshed(2, 0);

        let body = serde_json::to_value(health.report()).expect("serializes");
        assert_eq!(
            body,
            serde_json::json!({
                "status": "healthy",
                "service": "ethlambda-validator",
                "checks": {
                    "beacon_nodes": { "usable": 1, "configured": 2 },
                    "validators": { "loaded": 3, "resolved": 2 },
                    "slashing_protection": { "last_write_ok": true },
                    "started": true,
                    "schedule_current": true,
                }
            })
        );
    }

    /// The schedule reaches the last epoch the refresh left held, whenever in
    /// its epoch the refresh ran. From the epoch after, the client has no
    /// attestations left to make, whatever its nodes' probes say; and a
    /// refresh whose lookahead failed covers its own epoch alone.
    #[test]
    fn a_schedule_that_ends_before_the_clocks_epoch_is_unhealthy() {
        let clock = SlotClock::new(1_000_000, SLOT.as_millis() as u64, 3_333, 6_667);
        let health = ClientHealth::new(1, store_of(1));
        let probes = Arc::new(NodeHealth::new(1));
        health.attach(
            probes.clone(),
            clock.clone(),
            SlashingProtection::in_memory(),
        );
        let first_slot = |epoch: Epoch| epoch * ethlambda_types::beacon::preset::slots_per_epoch();
        // The report at `slot`'s start, with a fresh synced probe.
        let report_at_slot = |slot| {
            let at = clock.start_of(slot);
            probes.record(0, Probe { at, ..synced() });
            health.report_at(at)
        };

        let epoch = 10;
        health.epoch_refreshed(1, epoch + 1);
        let covered = report_at_slot(first_slot(epoch + 2) - 1);
        assert_eq!(covered.status, Status::Healthy);
        assert!(covered.checks.schedule_current);

        let past = report_at_slot(first_slot(epoch + 2));
        assert_eq!(past.status, Status::Unhealthy);
        assert!(!past.checks.schedule_current);
        assert!(past.beacon_node_available(), "the node still probes usable");

        health.epoch_refreshed(1, epoch);
        let without_lookahead = report_at_slot(first_slot(epoch + 1));
        assert_eq!(without_lookahead.status, Status::Unhealthy);
    }

    /// Until the first refresh the client is `starting`, a `503`, and the
    /// refresh that moves it is a real one, driven through the mock.
    #[tokio::test]
    async fn a_client_is_starting_until_its_first_refresh() {
        use ethlambda_types::beacon::primitives::{BlsPubkey, Bytes32, Root};

        use crate::beacon_node::ValidatorEntry;
        use crate::beacon_node::fallback::FallbackBeaconNode;
        use crate::beacon_node::mock::MockBeaconNode;
        use crate::duties::DutiesService;
        use crate::proposer_settings::ProposerSettings;
        use crate::signing::SigningContext;

        let mut node = MockBeaconNode::new()
            .with_duties(3, Root::repeat_byte(1), Vec::new())
            .with_duties(4, Root::repeat_byte(2), Vec::new())
            .with_proposers(3, Root::repeat_byte(1), Vec::new());
        node.validators = vec![ValidatorEntry {
            index: 11,
            pubkey: BlsPubkey([1; 48]),
            status: "active_ongoing".to_string(),
        }];
        let beacon_node = Arc::new(FallbackBeaconNode::new(vec![node]));
        let health = ClientHealth::new(1, store_of(1));
        health.attach(
            beacon_node.health().clone(),
            clock(),
            SlashingProtection::in_memory(),
        );

        let report = health.report();
        assert_eq!(report.status, Status::Starting, "before the first probe");
        assert_eq!(report.status_code(), StatusCode::SERVICE_UNAVAILABLE);

        let slot = 3 * ethlambda_types::beacon::preset::slots_per_epoch();
        beacon_node.probe(slot, Duration::from_secs(1)).await;
        let report = health.report();
        assert_eq!(report.status, Status::Starting, "probed, not refreshed");
        assert_eq!(report.checks.beacon_nodes.usable, 1);
        assert!(!report.checks.started);

        let context = SigningContext::new(
            ethlambda_types::beacon::config::Config::mainnet(),
            Root::ZERO,
        );
        let settings = ProposerSettings::new(Bytes32::ZERO, None);
        let mut duties = DutiesService::new(beacon_node.clone(), Vec::new());
        let refreshed = crate::refresh_epoch(
            &beacon_node,
            &mut duties,
            &[BlsPubkey([1; 48])],
            3,
            &settings,
            &context,
        )
        .await
        .expect("the refresh passes on a synced node");
        // What the duty loop does with a refresh that succeeded: the mock
        // answers the lookahead too, so the schedule runs through epoch 4.
        assert!(duties.holds_attesters(4));
        health.epoch_refreshed(refreshed.resolved.len(), 4);

        let report = health.report();
        assert_eq!(report.status, Status::Healthy);
        assert_eq!(report.status_code(), StatusCode::OK);
        assert!(report.checks.started);
        assert_eq!(report.checks.validators.resolved, 1);
    }

    /// Nothing probed yet reads `starting`, not `unhealthy`, until the client
    /// has started; and before the nodes are even attached, the same.
    #[test]
    fn startup_before_the_first_probe_is_starting_not_unhealthy() {
        let unattached = ClientHealth::new(2, store_of(1));
        let report = unattached.report();
        assert_eq!(report.status, Status::Starting);
        assert_eq!(report.checks.beacon_nodes.usable, 0);
        assert_eq!(report.checks.beacon_nodes.configured, 2);

        let (health, probes) = client(2, 1);
        assert_eq!(health.report().status, Status::Starting);
        // One node answered unusable, the other has not answered yet.
        probes.record(0, down());
        assert_eq!(health.report().status, Status::Starting);
        // Every node answered, none usable: the nodes are why it has not
        // started.
        probes.record(1, syncing());
        assert_eq!(health.report().status, Status::Unhealthy);
    }

    /// Once started, a node with no probe counts as unusable: the probe task
    /// should have recorded it by then.
    #[test]
    fn a_started_client_with_no_probe_is_unhealthy() {
        let (health, _probes) = client(1, 1);
        health.epoch_refreshed(1, 0);
        let report = health.report();
        assert_eq!(report.status, Status::Unhealthy);
        assert_eq!(report.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Every node unusable (down, syncing or optimistic) turns the client
    /// unhealthy; one coming back turns it healthy again.
    #[test]
    fn no_usable_node_is_unhealthy_until_one_recovers() {
        let (health, probes) = client(3, 1);
        health.epoch_refreshed(1, 0);
        probes.record(0, down());
        probes.record(1, syncing());
        probes.record(2, optimistic());
        let report = health.report();
        assert_eq!(report.status, Status::Unhealthy);
        assert_eq!(report.checks.beacon_nodes.usable, 0);
        assert!(!report.beacon_node_available());

        probes.record(1, synced());
        let report = health.report();
        assert_eq!(report.status, Status::Healthy);
        assert_eq!(report.checks.beacon_nodes.usable, 1);
        assert!(report.beacon_node_available());
    }

    /// A probe past two slots old is not read: the probe task that took it
    /// has stopped.
    #[test]
    fn a_stale_probe_does_not_count_as_usable() {
        let (health, probes) = client(1, 1);
        health.epoch_refreshed(1, 0);
        let taken = SystemTime::now();
        probes.record(
            0,
            Probe {
                at: taken,
                ..synced()
            },
        );

        let fresh = health.report_at(taken + SLOT);
        assert_eq!(fresh.status, Status::Healthy);
        let stale = health.report_at(taken + SLOT * 3);
        assert_eq!(stale.status, Status::Unhealthy);
        assert_eq!(stale.checks.beacon_nodes.usable, 0);
    }

    /// No keys loaded and none resolved are reported, and fail nothing: a
    /// client started empty waits for a keymanager import on purpose.
    #[test]
    fn an_empty_store_reports_zero_loaded_and_stays_healthy() {
        let (health, probes) = client(1, 0);
        probes.record(0, synced());
        health.epoch_refreshed(0, 0);
        let report = health.report();
        assert_eq!(report.status, Status::Healthy);
        assert_eq!(
            report.checks.validators,
            Validators {
                loaded: 0,
                resolved: 0
            }
        );
    }

    /// While a writer holds the store, `loaded` is the last count read
    /// rather than a wait.
    #[tokio::test]
    async fn a_held_store_answers_the_last_count_read() {
        let store = store_of(2);
        let health = ClientHealth::new(1, store.clone());
        assert_eq!(health.report().checks.validators.loaded, 2);

        let mut writer = store.write().await;
        writer
            .insert_secret("test", &[9; 32])
            .expect("a valid secret");
        assert_eq!(health.report().checks.validators.loaded, 2);
        drop(writer);
        assert_eq!(health.report().checks.validators.loaded, 3);
    }

    /// A failed slashing-protection write turns the client unhealthy, and a
    /// later write that succeeds turns it back.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_failed_record_write_is_unhealthy_until_a_write_succeeds() {
        use std::os::unix::fs::PermissionsExt as _;

        use ethlambda_types::beacon::primitives::{BlsPubkey, Root};

        use crate::slashing_protection::blocking;

        // SAFETY: `geteuid` reads a process attribute and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipped: root bypasses directory permissions");
            return;
        }
        let dir = tempfile::tempdir().expect("temp dir");
        let key = BlsPubkey([1; 48]);
        let record = SlashingProtection::open(dir.path(), Root::ZERO, &[key], true).expect("init");
        let protection = crate::slashing_protection::SharedProtection::new(record);
        let health = ClientHealth::new(1, store_of(1));
        let probes = Arc::new(NodeHealth::new(1));
        health.attach(probes.clone(), clock(), protection.clone());
        probes.record(0, synced());
        health.epoch_refreshed(1, 0);
        assert_eq!(health.report().status, Status::Healthy);

        let read_only = std::fs::Permissions::from_mode(0o500);
        std::fs::set_permissions(dir.path(), read_only).expect("chmod");
        let failed = blocking(&protection, move |record| {
            record.check_and_record_block(&key, 10)
        })
        .await;
        let writable = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(dir.path(), writable).expect("chmod back");
        assert!(
            failed.is_err(),
            "the write must fail in a read-only directory"
        );

        let report = health.report();
        assert_eq!(report.status, Status::Unhealthy);
        assert!(!report.checks.slashing_protection.last_write_ok);

        blocking(&protection, move |record| {
            record.check_and_record_block(&key, 10)
        })
        .await
        .expect("written")
        .expect("slot 10 is still signable");
        let report = health.report();
        assert_eq!(report.status, Status::Healthy);
        assert!(report.checks.slashing_protection.last_write_ok);
    }

    /// `/health` and the two gauges a scrape of `/metrics` sets read one
    /// answer, going down and coming back. The only test that touches those
    /// process-wide gauges, so tests running beside it cannot move them.
    #[tokio::test]
    async fn the_gauges_match_the_endpoint() {
        use http_body_util::BodyExt as _;
        use tower::ServiceExt as _;

        async fn get(router: &axum::Router, path: &str) -> (StatusCode, String) {
            let request = axum::http::Request::get(path)
                .body(axum::body::Body::empty())
                .expect("a request");
            let response = router.clone().oneshot(request).await.expect("answered");
            let status = response.status();
            let body = response.into_body().collect().await.expect("a body");
            let body = String::from_utf8(body.to_bytes().to_vec()).expect("utf-8");
            (status, body)
        }

        fn gauge(metrics: &str, name: &str) -> i64 {
            metrics
                .lines()
                .find_map(|line| line.strip_prefix(name)?.strip_prefix(' '))
                .unwrap_or_else(|| panic!("{name} is exposed"))
                .trim()
                .parse()
                .expect("an integer")
        }

        crate::metrics::init();
        let (health, probes) = client(1, 1);
        let health = Arc::new(health);
        let router = crate::metrics::router(health.clone());
        health.epoch_refreshed(1, 0);

        for (probe, code) in [
            (down(), StatusCode::SERVICE_UNAVAILABLE),
            (synced(), StatusCode::OK),
        ] {
            probes.record(0, probe);
            let (status, body) = get(&router, "/health").await;
            assert_eq!(status, code);
            let report: serde_json::Value = serde_json::from_str(&body).expect("json");
            let healthy = i64::from(code == StatusCode::OK);
            assert_eq!(report["status"] == "healthy", healthy == 1);

            let (_, metrics) = get(&router, "/metrics").await;
            assert_eq!(gauge(&metrics, "ethlambda_validator_healthy"), healthy);
            assert_eq!(
                gauge(&metrics, "ethlambda_validator_beacon_node_available"),
                healthy,
                "the one node is the only check that moved"
            );
        }
    }
}
