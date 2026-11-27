//! PQ gossip and proving timings, exported to a local directory in the format
//! the PQ devnets' clients share (`--pq-timing-output`).
//!
//! Schema 1 of Lighthouse's `scripts/pq-measurement`, which Prysm, Teku and
//! Lodestar write too, so one report script draws every client's runs side by
//! side. A run is a directory holding `run.json` (what ran, on what, and the
//! slot's timing) and `events-NNNNNN.jsonl.zst` chunks of JSON lines:
//!
//! - `message_received`: a PQ attestation or aggregate reached this node from
//!   gossip, stamped when gossipsub delivered it.
//! - `validated`: the verdict that message got, and how long after.
//! - `proof_started`, `proof_finished`: one leanVM proof, of a committee's
//!   signatures (`work: "committee"`) or of a block's merged attestation
//!   proofs (`"initial"` ahead of the slot, `"improvement"` at production).
//! - `candidate_ready`: a proof is where its consumer takes it from.
//! - `job_outcome`: a proof that was due and was not made, and why.
//! - `proposal_snapshot`: what block production had when it built the block.
//!
//! Every proof event carries the job's fields ([`Job`]). An event is placed
//! on a timeline by its `reference_slot`, the slot of the votes it is about:
//! a committee's own slot, and two slots before the block a merge is for.
//!
//! Off unless [`install`] ran. Every emitter then returns before it builds
//! anything, so a node that does not record pays one atomic load per call.
//! See `docs/pq_timing.md`.

mod hardware;
mod recorder;

use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use recorder::{Class, Limits, Record, Recorder};
use sha2::{Digest as _, Sha256};

/// Re-exported for the emit sites, whose fields are JSON objects.
pub use serde_json::{Value, json};

/// The schema this module writes: Lighthouse's `scripts/pq-measurement`, 1.
pub const SCHEMA_VERSION: u64 = 1;

/// What a run records about itself in `run.json`.
#[derive(Debug, Clone)]
pub struct Run {
    /// The directory runs are created in, one sub-directory each.
    pub output: PathBuf,
    /// The network's `CONFIG_NAME`.
    pub network: String,
    pub client_version: String,
    /// Seconds since the UNIX epoch.
    pub genesis_time: u64,
    pub genesis_validators_root: [u8; 32],
    pub prover: Prover,
    pub timing: Timing,
}

/// The prover the run's proofs were made with.
#[derive(Debug, Clone)]
pub struct Prover {
    /// `leanvm`, or `reference` on a network that never installed it.
    pub backend: &'static str,
    pub leanvm_revision: &'static str,
    pub leanvm_protocol_version: u32,
    pub log_inv_rate: u8,
    /// The prover's threads, when the operator set them. `None` when leanVM
    /// chose, one per core.
    pub threads: Option<usize>,
    /// What the operator asked for, 0 for one per core.
    pub threads_configured: usize,
}

/// Where in a slot this client does each step, from the start of the vote
/// slot: what a report draws its reference lines at.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    pub slot: Duration,
    /// The attestation deadline.
    pub attestation_due: Duration,
    /// When the first aggregator seat stops collecting signatures.
    pub committee_collection: Duration,
    /// How much later each following seat does.
    pub aggregator_delay: Duration,
    /// When the first seat broadcasts.
    pub aggregate_due: Duration,
    /// When the merge ahead of a proposal starts, counted from the start of
    /// the slot `proposal_lag_slots` before the proposal's.
    pub initial_merge: Duration,
    /// How many slots after its votes a block may first include them.
    pub proposal_lag_slots: u64,
}

/// Where events go: a run on disk, or memory for a test.
#[derive(Debug)]
enum Sink {
    Disk(Recorder),
    #[cfg(any(test, feature = "test-utils"))]
    Memory(std::sync::Mutex<Vec<Value>>),
}

#[derive(Debug)]
struct Session {
    sink: Sink,
    /// What every event's `mono_ns` counts from.
    origin: Instant,
    next_job: AtomicU64,
}

impl Session {
    fn new(sink: Sink) -> Arc<Self> {
        Arc::new(Self {
            sink,
            origin: Instant::now(),
            next_job: AtomicU64::new(0),
        })
    }

    fn healthy(&self) -> bool {
        match &self.sink {
            Sink::Disk(recorder) => recorder.healthy(),
            #[cfg(any(test, feature = "test-utils"))]
            Sink::Memory(_) => true,
        }
    }

    fn emit(&self, class: Class, kind: &'static str, wall_ns: u64, at: Instant, fields: Value) {
        let record = Record {
            kind,
            wall_ns,
            mono_ns: ns(at.saturating_duration_since(self.origin)),
            fields,
        };
        match &self.sink {
            Sink::Disk(recorder) => recorder.emit(class, record),
            #[cfg(any(test, feature = "test-utils"))]
            Sink::Memory(events) => {
                let event = serde_json::to_value(&record).expect("a record is a JSON object");
                events.lock().expect("captured events lock").push(event);
            }
        }
    }

    fn emit_now(&self, class: Class, kind: &'static str, fields: Value) {
        self.emit(class, kind, wall_now_ns(), Instant::now(), fields);
    }
}

/// The session events go to. `ENABLED` is read first, so a node that does
/// not record takes no lock.
static ACTIVE: RwLock<Option<Arc<Session>>> = RwLock::new(None);
static ENABLED: AtomicBool = AtomicBool::new(false);

fn active() -> Option<Arc<Session>> {
    if !ENABLED.load(Ordering::Relaxed) {
        return None;
    }
    let session = ACTIVE.read().expect("PQ timing session lock").clone()?;
    session.healthy().then_some(session)
}

fn activate(session: Arc<Session>) -> bool {
    let mut active = ACTIVE.write().expect("PQ timing session lock");
    if active.is_some() {
        return false;
    }
    *active = Some(session);
    ENABLED.store(true, Ordering::Relaxed);
    true
}

fn deactivate() -> Option<Arc<Session>> {
    let mut active = ACTIVE.write().expect("PQ timing session lock");
    ENABLED.store(false, Ordering::Relaxed);
    active.take()
}

/// Start a run under `run.output` and route every later event to it. Returns
/// the run's directory.
///
/// Fails when the directory cannot be created or written, or a run is
/// already being recorded.
pub fn install(run: Run) -> io::Result<PathBuf> {
    let already = || {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "a PQ timing run is already being recorded",
        )
    };
    // Before a directory is made for a run that would not be recorded.
    if ACTIVE.read().expect("PQ timing session lock").is_some() {
        return Err(already());
    }
    let started = wall_now_ns();
    let id = format!("{started}-{:016x}", random_u64());
    let manifest = metadata(&run, &id, started);
    let recorder = Recorder::open(&run.output, &id, manifest, Limits::DEFAULT)?;
    let directory = recorder.directory().to_path_buf();
    if !activate(Session::new(Sink::Disk(recorder))) {
        return Err(already());
    }
    Ok(directory)
}

/// Finish the run: its last chunk is closed and listed, and `run.json` gets
/// its end. Waits for the writer. Events emitted afterwards go nowhere. A
/// no-op without [`install`].
pub fn close() {
    if let Some(session) = deactivate()
        && let Sink::Disk(recorder) = &session.sink
    {
        recorder.close();
    }
}

/// Whether a run is being recorded. The emitters check it themselves; this
/// is for a caller that would otherwise compute something only they read.
pub fn enabled() -> bool {
    active().is_some()
}

fn metadata(run: &Run, id: &str, started_unix_ns: u64) -> Value {
    let timing = &run.timing;
    json!({
        "schema_version": SCHEMA_VERSION,
        "run_id": id,
        "started_unix_ns": started_unix_ns,
        // No observer mode: every event is this node's own workload.
        "observer": false,
        "network": run.network,
        "genesis_time": run.genesis_time,
        "genesis_slot": 0,
        "genesis_validators_root": hex_0x(&run.genesis_validators_root),
        "client": "ethlambda",
        "ethlambda_version": run.client_version,
        "leanvm_revision": run.prover.leanvm_revision,
        "leanvm_protocol_version": run.prover.leanvm_protocol_version,
        "prover_backend": run.prover.backend,
        "prover_log_inv_rate": run.prover.log_inv_rate,
        // leanVM picks its CPU tier itself and does not report it.
        "prover_cpu_profile": null,
        "prover_cpu_profile_requested": std::env::var("LEANVM_TIER").ok(),
        "prover_threads": run.prover.threads,
        "prover_threads_configured": run.prover.threads_configured,
        "hardware": hardware::hardware(),
        "timing": {
            "slot_ns": ns(timing.slot),
            "attestation_ns": ns(timing.attestation_due),
            "committee_collection_ns": ns(timing.committee_collection),
            "aggregator_position": 0,
            "aggregator_delay_ns": ns(timing.aggregator_delay),
            "aggregate_ns": ns(timing.aggregate_due),
            "initial_merge_ns": ns(timing.initial_merge),
            "proposal_lag_slots": timing.proposal_lag_slots,
        },
        "receive_point": "gossipsub delivery, stamped before Snappy decompression and SSZ \
                          decode and after gossipsub's duplicate cache",
    })
}

/// Which of the two vote messages a receipt is of, as the schema names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    /// A single attestation, from a subnet.
    Individual,
    /// A committee's aggregate and its proof.
    Aggregate,
}

impl MessageKind {
    fn label(self) -> &'static str {
        match self {
            Self::Individual => "individual",
            Self::Aggregate => "aggregate",
        }
    }
}

/// A vote whose receipt was recorded: what its `validated` event names it by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vote {
    kind: MessageKind,
    slot: u64,
}

/// A PQ attestation or aggregate as it arrived.
#[derive(Debug, Clone, Copy)]
pub struct Receipt<'a> {
    pub kind: MessageKind,
    /// The gossipsub message id.
    pub message_id: &'a [u8],
    /// The slot of the vote.
    pub slot: u64,
    pub committee: Option<u64>,
    /// The attestation subnet, for a single attestation.
    pub subnet: Option<u64>,
    /// The decompressed SSZ's length.
    pub message_bytes: usize,
    /// One for a single attestation, the aggregate's attesters otherwise.
    pub signer_count: usize,
    /// `hash_tree_root` of the attestation data.
    pub vote_data_root: [u8; 32],
}

/// Record that the vote `build` describes reached this node at
/// `received_at`. Returns what [`validated`] needs once it has a verdict, or
/// `None` when nothing is recorded, in which case `build` did not run.
pub fn message_received<'a>(
    received_at: Instant,
    build: impl FnOnce() -> Receipt<'a>,
) -> Option<Vote> {
    let session = active()?;
    let receipt = build();
    let wall_ns = wall_now_ns().saturating_sub(ns(received_at.elapsed()));
    let fields = json!({
        "message_kind": receipt.kind.label(),
        "message_id": hex_0x(receipt.message_id),
        "source": "network",
        "reference_slot": receipt.slot,
        "slot": receipt.slot,
        "committee": receipt.committee,
        "subnet": receipt.subnet,
        "message_bytes": receipt.message_bytes,
        "byte_basis": "decoded_ssz",
        "signer_count": receipt.signer_count,
        "vote_data_root": hex_0x(&receipt.vote_data_root),
    });
    session.emit(
        Class::Receipt,
        "message_received",
        wall_ns,
        received_at,
        fields,
    );
    Some(Vote {
        kind: receipt.kind,
        slot: receipt.slot,
    })
}

/// Record the verdict of a vote whose receipt was recorded. `outcome` is one
/// of the schema's: `accepted`, `duplicate`, `rejected`, `ignored`,
/// `queue_dropped`.
pub fn validated(vote: Vote, message_id: &[u8], received_at: Instant, outcome: &'static str) {
    let Some(session) = active() else {
        return;
    };
    let fields = json!({
        "message_kind": vote.kind.label(),
        "message_id": hex_0x(message_id),
        "source": "network",
        "reference_slot": vote.slot,
        "slot": vote.slot,
        "outcome": outcome,
        "receipt_to_validation_ns": ns(received_at.elapsed()),
    });
    session.emit_now(Class::Validation, "validated", fields);
}

/// What a proof is of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    /// One committee's signatures, for an aggregator seat of this node.
    Committee,
    /// A block's attestation proofs merged ahead of its slot: round 1.
    Initial,
    /// The same at block production, when the merge ahead cannot be used:
    /// round 2.
    Improvement,
}

impl Work {
    fn label(self) -> &'static str {
        match self {
            Self::Committee => "committee",
            Self::Initial => "initial",
            Self::Improvement => "improvement",
        }
    }

    fn round(self) -> u64 {
        match self {
            Self::Committee | Self::Initial => 1,
            Self::Improvement => 2,
        }
    }
}

/// One proof this node set out to make, and the events about it. Every
/// method is a no-op, and builds nothing, when no run is being recorded.
#[derive(Debug, Clone)]
pub struct Job {
    session: Option<Arc<Session>>,
    id: u64,
    work: Work,
    slot: u64,
    reference_slot: u64,
    enqueued: Instant,
    enqueued_wall_ns: u64,
}

/// A job of `work` for `slot` (the committee's slot, or the block's), whose
/// votes are of `reference_slot`, wanted since `enqueued`: what its proof's
/// `queue_wait_ns` is counted from.
pub fn job(work: Work, slot: u64, reference_slot: u64, enqueued: Instant) -> Job {
    let session = active();
    let id = session.as_ref().map_or(0, |session| {
        session.next_job.fetch_add(1, Ordering::Relaxed) + 1
    });
    let enqueued_wall_ns = if session.is_some() {
        wall_now_ns().saturating_sub(ns(enqueued.elapsed()))
    } else {
        0
    };
    Job {
        session,
        id,
        work,
        slot,
        reference_slot,
        enqueued,
        enqueued_wall_ns,
    }
}

impl Job {
    /// Emit `kind` with this job's fields over `fields`' (a JSON object).
    fn emit(
        &self,
        class: Class,
        kind: &'static str,
        outcome: &str,
        fields: impl FnOnce() -> Value,
    ) {
        let Some(session) = &self.session else {
            return;
        };
        let mut fields = fields();
        let job = json!({
            "outcome": outcome,
            "job_id": self.id,
            "work": self.work.label(),
            "origin": "production",
            "slot": self.slot,
            "reference_slot": self.reference_slot,
            "round": self.work.round(),
            "previous_recursive_depth": 0,
            "experiment_id": null,
            "sequence_id": format!("production:{}", self.slot),
            "scenario": "production",
            "committee_count": null,
            "active_validators": null,
            "enqueued_wall_ns": self.enqueued_wall_ns,
        });
        if let (Value::Object(fields), Value::Object(job)) = (&mut fields, job) {
            fields.extend(job);
        }
        session.emit_now(class, kind, fields);
    }

    /// `proof_started`: the prover is about to be called.
    pub fn started(&self, fields: impl FnOnce() -> Value) {
        self.emit(Class::Work, "proof_started", "started", || {
            let mut fields = fields();
            fields["queue_wait_ns"] = json!(ns(self.enqueued.elapsed()));
            fields
        });
    }

    /// `proof_finished`: the prover returned after `backend`, with `proof`
    /// or without one. `late` when that was past the job's deadline.
    pub fn finished(
        &self,
        backend: Duration,
        late: bool,
        proof: Option<&[u8]>,
        fields: impl FnOnce() -> Value,
    ) {
        let outcome = if proof.is_some() { "success" } else { "failed" };
        self.emit(Class::Work, "proof_finished", outcome, || {
            let mut fields = fields();
            fields["backend_duration_ns"] = json!(ns(backend));
            fields["late"] = json!(late);
            fields["proof_bytes"] = json!(proof.map(<[u8]>::len));
            fields["proof_id"] = json!(proof.map(proof_id));
            fields
        });
    }

    /// `candidate_ready`: the proof is where its consumer takes it from.
    pub fn ready(&self, fields: impl FnOnce() -> Value) {
        self.emit(Class::Work, "candidate_ready", "ready", fields);
    }

    /// `job_outcome`: the job ended without a proof being made, as `outcome`
    /// says.
    pub fn outcome(&self, outcome: &str, fields: impl FnOnce() -> Value) {
        self.emit(Class::Work, "job_outcome", outcome, fields);
    }
}

/// `proposal_snapshot`: block production took what it has for the block at
/// `slot`, whose newest votes are of `reference_slot`. `outcome` is
/// `candidate` when the block carries attestations and `no_candidate` when
/// it carries none. It ends the sequence the slot's merges belong to.
pub fn proposal_snapshot(
    slot: u64,
    reference_slot: u64,
    outcome: &str,
    fields: impl FnOnce() -> Value,
) {
    let Some(session) = active() else {
        return;
    };
    let mut fields = fields();
    let sequence = json!({
        "outcome": outcome,
        "origin": "production",
        "scenario": "production",
        "sequence_id": format!("production:{slot}"),
        "slot": slot,
        "reference_slot": reference_slot,
        "experiment_id": null,
    });
    if let (Value::Object(fields), Value::Object(sequence)) = (&mut fields, sequence) {
        fields.extend(sequence);
    }
    session.emit_now(Class::Status, "proposal_snapshot", fields);
}

/// What events name a proof by: its SHA-256, so a proof can be followed from
/// the job that made it to the block that carries it without exporting it.
/// Empty for an empty proof.
pub fn proof_id(proof: &[u8]) -> String {
    if proof.is_empty() {
        return String::new();
    }
    hex_0x(&Sha256::digest(proof))
}

fn hex_0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn wall_now_ns() -> u64 {
    ns(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default())
}

/// Sixty-four bits that differ between runs, for the run's name: a fresh
/// `RandomState`'s keys, which the standard library seeds from the operating
/// system. Nothing reads them as secret.
fn random_u64() -> u64 {
    use std::hash::{BuildHasher as _, Hasher as _};
    std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish()
}

/// Recording into memory, for tests of the emit sites.
#[cfg(any(test, feature = "test-utils"))]
pub mod testing {
    use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

    use super::{Session, Sink, Value, activate, deactivate};

    /// One capture at a time: the session is the process's.
    static SERIAL: Mutex<()> = Mutex::new(());

    /// Every event emitted while it lives, by any thread of the process. A
    /// test reads the ones about its own messages and jobs: another test's
    /// emit sites record here too.
    pub struct Capture {
        session: Arc<Session>,
        _serial: MutexGuard<'static, ()>,
    }

    /// Start capturing. Waits for another capture of this process to end.
    pub fn capture() -> Capture {
        let serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        let session = Session::new(Sink::Memory(Mutex::new(Vec::new())));
        assert!(
            activate(session.clone()),
            "a PQ timing run is being recorded"
        );
        Capture {
            session,
            _serial: serial,
        }
    }

    impl Capture {
        /// The events so far, in the order they were emitted.
        pub fn events(&self) -> Vec<Value> {
            let Sink::Memory(events) = &self.session.sink else {
                unreachable!("a capture records into memory");
            };
            events
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        /// The events of `kind` so far.
        pub fn of_kind(&self, kind: &str) -> Vec<Value> {
            let mut events = self.events();
            events.retain(|event| event["kind"] == kind);
            events
        }
    }

    impl Drop for Capture {
        fn drop(&mut self) {
            deactivate();
        }
    }

    /// Hold the capture lock without capturing, for a test that installs a
    /// run on disk.
    #[cfg(test)]
    pub(super) fn serial() -> MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::*;

    fn run(output: &std::path::Path) -> Run {
        Run {
            output: output.to_path_buf(),
            network: "pq-devnet-1".into(),
            client_version: "ethlambda/v1.0.0".into(),
            genesis_time: 1_700_000_000,
            genesis_validators_root: [0xab; 32],
            prover: Prover {
                backend: "leanvm",
                leanvm_revision: "351f7ae4",
                leanvm_protocol_version: 1,
                log_inv_rate: 2,
                threads: Some(8),
                threads_configured: 8,
            },
            timing: Timing {
                slot: Duration::from_secs(12),
                attestation_due: Duration::from_millis(4_000),
                committee_collection: Duration::from_millis(4_800),
                aggregator_delay: Duration::from_millis(600),
                aggregate_due: Duration::from_millis(7_200),
                initial_merge: Duration::from_secs(20),
                proposal_lag_slots: 2,
            },
        }
    }

    /// Nothing is built, and no job is numbered, while no run is recorded.
    #[test]
    fn the_emitters_build_nothing_when_no_run_is_recorded() {
        let _serial = testing::serial();
        assert!(!enabled());
        let received = message_received(Instant::now(), || unreachable!("not recording"));
        assert_eq!(received, None);
        let job = job(Work::Committee, 5, 5, Instant::now());
        assert_eq!(job.id, 0);
        job.started(|| unreachable!("not recording"));
        job.finished(Duration::ZERO, false, None, || {
            unreachable!("not recording")
        });
        job.ready(|| unreachable!("not recording"));
        job.outcome("unproved", || unreachable!("not recording"));
        proposal_snapshot(7, 5, "candidate", || unreachable!("not recording"));
    }

    /// The manifest carries what a report reads: the schema, an id usable as
    /// a file name, genesis, the slot's timing in nanoseconds, the hardware
    /// and the prover.
    #[test]
    fn a_run_describes_itself() {
        let _serial = testing::serial();
        let root = tempfile::tempdir().unwrap();
        let directory = install(run(root.path())).unwrap();
        assert!(enabled());
        // A second run is refused while the first records, and leaves it be.
        let second = install(run(root.path())).unwrap_err();
        assert_eq!(second.kind(), io::ErrorKind::AlreadyExists);
        assert!(enabled());
        close();
        assert!(!enabled());

        let manifest: Value =
            serde_json::from_reader(File::open(directory.join("run.json")).unwrap()).unwrap();
        assert_eq!(manifest["schema_version"], 1);
        let id = manifest["run_id"].as_str().unwrap();
        assert_eq!(directory.file_name().unwrap().to_str(), Some(id));
        assert!(
            id.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        );
        assert_eq!(manifest["client"], "ethlambda");
        assert_eq!(manifest["observer"], false);
        assert_eq!(manifest["genesis_time"], 1_700_000_000u64);
        assert_eq!(manifest["genesis_slot"], 0);
        assert_eq!(
            manifest["genesis_validators_root"],
            format!("0x{}", "ab".repeat(32))
        );
        assert_eq!(
            manifest["timing"],
            json!({
                "slot_ns": 12_000_000_000u64,
                "attestation_ns": 4_000_000_000u64,
                "committee_collection_ns": 4_800_000_000u64,
                "aggregator_position": 0,
                "aggregator_delay_ns": 600_000_000u64,
                "aggregate_ns": 7_200_000_000u64,
                "initial_merge_ns": 20_000_000_000u64,
                "proposal_lag_slots": 2,
            })
        );
        assert_eq!(manifest["prover_threads"], 8);
        assert_eq!(manifest["hardware"]["architecture"], std::env::consts::ARCH);
        assert!(manifest["ended_unix_ns"].is_number());
        assert_eq!(manifest["chunks"], json!([]));
    }

    /// A receipt is stamped when the message arrived, not when it was
    /// recorded, and its verdict is tied to it by kind and message id.
    #[test]
    fn a_vote_is_received_then_validated() {
        let capture = testing::capture();
        let before_ns = wall_now_ns();
        let received_at = Instant::now();
        std::thread::sleep(Duration::from_millis(20));
        let vote = message_received(received_at, || Receipt {
            kind: MessageKind::Aggregate,
            message_id: &[0x01, 0x02],
            slot: 7,
            committee: Some(3),
            subnet: None,
            message_bytes: 4_096,
            signer_count: 120,
            vote_data_root: [0xcd; 32],
        })
        .expect("recording");
        validated(vote, &[0x01, 0x02], received_at, "accepted");

        let events = capture.events();
        assert_eq!(events.len(), 2);
        let received = &events[0];
        assert_eq!(received["kind"], "message_received");
        assert_eq!(received["message_kind"], "aggregate");
        assert_eq!(received["message_id"], "0x0102");
        assert_eq!(received["source"], "network");
        assert_eq!(
            (&received["slot"], &received["reference_slot"]),
            (&json!(7), &json!(7))
        );
        assert_eq!(received["committee"], 3);
        assert_eq!(received["subnet"], Value::Null);
        assert_eq!(received["message_bytes"], 4_096);
        assert_eq!(received["byte_basis"], "decoded_ssz");
        assert_eq!(received["signer_count"], 120);
        assert_eq!(received["vote_data_root"], format!("0x{}", "cd".repeat(32)));
        let stamped = received["wall_ns"].as_u64().unwrap();
        // Within a millisecond of when it arrived, 20 ms before the record.
        assert!(stamped.abs_diff(before_ns) < 5_000_000, "stamped {stamped}");

        let verdict = &events[1];
        assert_eq!(verdict["kind"], "validated");
        assert_eq!(verdict["message_kind"], "aggregate");
        assert_eq!(verdict["message_id"], "0x0102");
        assert_eq!(verdict["outcome"], "accepted");
        assert_eq!(verdict["slot"], 7);
        assert!(verdict["receipt_to_validation_ns"].as_u64().unwrap() >= 20_000_000);
        assert!(verdict["mono_ns"].as_u64() > received["mono_ns"].as_u64());
    }

    /// A job's events share its id and fields; the proof events add the
    /// queue wait, the backend's time and what identifies the proof.
    #[test]
    fn a_jobs_events_carry_its_fields() {
        let capture = testing::capture();
        let enqueued = Instant::now();
        std::thread::sleep(Duration::from_millis(10));
        let merge = job(Work::Improvement, 12, 10, enqueued);
        merge.started(|| json!({"input_proof_count": 3}));
        merge.finished(
            Duration::from_millis(700),
            true,
            Some(&[1, 2, 3]),
            || json!({"input_proof_count": 3}),
        );
        merge.ready(|| json!({"records": 2}));
        proposal_snapshot(12, 10, "candidate", || json!({"records": 2}));
        let committee = job(Work::Committee, 10, 10, enqueued);
        committee.finished(Duration::from_millis(80), false, None, || json!({}));
        committee.outcome("unproved", || json!({"committee": 4}));

        let events = capture.events();
        let kinds: Vec<&str> = events.iter().map(|e| e["kind"].as_str().unwrap()).collect();
        assert_eq!(
            kinds,
            [
                "proof_started",
                "proof_finished",
                "candidate_ready",
                "proposal_snapshot",
                "proof_finished",
                "job_outcome"
            ]
        );
        // The snapshot is the sequence's, not a job's: no work, no job id.
        assert_eq!(events[3]["job_id"], Value::Null);
        assert_eq!(events[3]["work"], Value::Null);
        for event in &events[..3] {
            assert_eq!(event["job_id"], 1);
            assert_eq!(event["work"], "improvement");
            assert_eq!(event["round"], 2);
        }
        for event in &events[..4] {
            assert_eq!(event["origin"], "production");
            assert_eq!(event["scenario"], "production");
            assert_eq!(event["sequence_id"], "production:12");
            assert_eq!(
                (&event["slot"], &event["reference_slot"]),
                (&json!(12), &json!(10))
            );
            assert_eq!(event["experiment_id"], Value::Null);
        }
        assert_eq!(events[0]["outcome"], "started");
        assert_eq!(events[0]["input_proof_count"], 3);
        assert!(events[0]["queue_wait_ns"].as_u64().unwrap() >= 10_000_000);
        let finished = &events[1];
        assert_eq!(finished["outcome"], "success");
        assert_eq!(finished["backend_duration_ns"], 700_000_000u64);
        assert_eq!(finished["late"], true);
        assert_eq!(finished["proof_bytes"], 3);
        assert_eq!(finished["proof_id"], proof_id(&[1, 2, 3]));
        assert_eq!(events[2]["outcome"], "ready");
        assert_eq!(events[3]["outcome"], "candidate");

        assert_eq!(events[4]["job_id"], 2);
        assert_eq!(events[4]["work"], "committee");
        assert_eq!(events[4]["round"], 1);
        assert_eq!(events[4]["outcome"], "failed");
        assert_eq!(events[4]["proof_id"], Value::Null);
        assert_eq!(events[5]["outcome"], "unproved");
        assert_eq!(events[5]["committee"], 4);
    }

    /// A run on disk reads back the way the report script reads one: the
    /// manifest lists a chunk by name, the chunk is a zstd stream of JSON
    /// lines, and every line has its sequence number, kind and both clocks.
    #[test]
    fn a_recorded_run_reads_back_from_its_listed_chunk() {
        let _serial = testing::serial();
        let root = tempfile::tempdir().unwrap();
        let directory = install(run(root.path())).unwrap();
        let received_at = Instant::now();
        let vote = message_received(received_at, || Receipt {
            kind: MessageKind::Individual,
            message_id: &[0xee],
            slot: 3,
            committee: Some(0),
            subnet: Some(1),
            message_bytes: 100,
            signer_count: 1,
            vote_data_root: [0; 32],
        })
        .expect("recording");
        validated(vote, &[0xee], received_at, "accepted");
        let proof = job(Work::Committee, 3, 3, Instant::now());
        proof.started(|| json!({"committee": 0}));
        proof.finished(
            Duration::from_millis(5),
            false,
            Some(&[9; 16]),
            || json!({}),
        );
        proof.ready(|| json!({}));
        proposal_snapshot(5, 3, "candidate", || json!({"records": 1}));
        close();

        let manifest: Value =
            serde_json::from_reader(File::open(directory.join("run.json")).unwrap()).unwrap();
        let chunks = manifest["chunks"].as_array().unwrap();
        assert_eq!(chunks.len(), 1);
        let name = chunks[0]["name"].as_str().unwrap();
        assert!(name.ends_with(".jsonl.zst"));
        let bytes = zstd::stream::decode_all(File::open(directory.join(name)).unwrap()).unwrap();
        let lines: Vec<Value> = bytes
            .split(|&byte| byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        let kinds: Vec<&str> = lines.iter().map(|l| l["kind"].as_str().unwrap()).collect();
        assert_eq!(
            kinds,
            [
                "message_received",
                "validated",
                "proof_started",
                "proof_finished",
                "candidate_ready",
                "proposal_snapshot"
            ]
        );
        for (index, line) in lines.iter().enumerate() {
            assert_eq!(line["seq"], index as u64 + 1);
            assert!(line["wall_ns"].as_u64().unwrap() > 1_700_000_000_000_000_000);
            assert!(line["mono_ns"].is_u64());
            assert!(line["reference_slot"].is_u64());
        }
        assert_eq!(manifest["recorder_status"]["submitted_sequence"], 6);
        assert_eq!(manifest["recorder_status"]["dropped"]["work"], 0);
    }

    #[test]
    fn a_proof_is_named_by_its_sha_256() {
        assert_eq!(proof_id(&[]), "");
        assert_eq!(
            proof_id(b"abc"),
            "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
