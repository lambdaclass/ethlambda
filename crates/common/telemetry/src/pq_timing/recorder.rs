//! The run directory: `run.json` and its `events-NNNNNN.jsonl.zst` chunks.
//!
//! Emitting never waits: an event goes into a bounded queue, and one the
//! queue has no room for is dropped and counted in the manifest. A writer
//! thread serializes and compresses, so neither is paid on the emitting
//! thread, and rewrites the manifest whenever a chunk is finished.

use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{Value, json};

use super::wall_now_ns;

/// What bounds a run on disk and in memory.
#[derive(Debug, Clone, Copy)]
pub(super) struct Limits {
    /// Events waiting for the writer. One more is dropped.
    pub queue: usize,
    /// A chunk is finished once it holds this many uncompressed bytes,
    pub rotate_bytes: usize,
    /// or has been open this long.
    pub rotate_time: Duration,
    /// The oldest chunks are removed while the finished ones exceed this,
    /// down to the newest one.
    pub retain_bytes: u64,
    /// How often the manifest's status is rewritten and the open chunk
    /// flushed, with or without events.
    pub status_interval: Duration,
}

impl Limits {
    /// The other clients' numbers: a 16,384-event queue, chunks of 64 MiB or
    /// five minutes, 8 GiB kept, a status every ten seconds.
    pub(super) const DEFAULT: Self = Self {
        queue: 16_384,
        rotate_bytes: 64 << 20,
        rotate_time: Duration::from_secs(300),
        retain_bytes: 8 << 30,
        status_interval: Duration::from_secs(10),
    };
}

/// What an event is about, for the dropped-event counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Class {
    Receipt,
    Validation,
    Work,
    Status,
}

impl Class {
    const ALL: [Class; 4] = [
        Class::Receipt,
        Class::Validation,
        Class::Work,
        Class::Status,
    ];

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Receipt => "receipt",
            Self::Validation => "validation",
            Self::Work => "work",
            Self::Status => "status",
        }
    }
}

/// One line of a chunk, before its sequence number.
#[derive(Debug, Serialize)]
pub(super) struct Record {
    pub kind: &'static str,
    pub wall_ns: u64,
    pub mono_ns: u64,
    /// A JSON object, whose members become the line's own.
    #[serde(flatten)]
    pub fields: Value,
}

#[derive(Debug, Serialize)]
struct Envelope {
    seq: u64,
    #[serde(flatten)]
    record: Record,
}

/// The first and last events the queue had no room for.
#[derive(Debug, Default)]
struct Dropped {
    first_sequence: Option<u64>,
    last_sequence: u64,
    first_wall_ns: u64,
    last_wall_ns: u64,
}

#[derive(Debug, Default)]
struct Health {
    failed: AtomicBool,
    next_sequence: AtomicU64,
    drops: [AtomicU64; Class::ALL.len()],
    dropped: Mutex<Dropped>,
}

impl Health {
    fn status(&self) -> Value {
        let drops = |class: Class| self.drops[class as usize].load(Ordering::Relaxed);
        let dropped = self.dropped.lock().expect("PQ timing drop record lock");
        json!({
            "disk_failed": self.failed.load(Ordering::Relaxed),
            "dropped": {
                "receipt": drops(Class::Receipt),
                "validation": drops(Class::Validation),
                "work": drops(Class::Work),
                "status": drops(Class::Status),
            },
            "first_dropped_sequence": dropped.first_sequence,
            "last_dropped_sequence": dropped.last_sequence,
            "submitted_sequence": self.next_sequence.load(Ordering::Relaxed),
            "first_dropped_wall_ns": dropped.first_wall_ns,
            "last_dropped_wall_ns": dropped.last_wall_ns,
        })
    }

    fn drop_event(&self, sequence: u64, wall_ns: u64, class: Class) {
        self.drops[class as usize].fetch_add(1, Ordering::Relaxed);
        crate::metrics::inc_pq_timing_dropped(class.label());
        let mut dropped = self.dropped.lock().expect("PQ timing drop record lock");
        if dropped.first_sequence.is_none() {
            dropped.first_sequence = Some(sequence);
            dropped.first_wall_ns = wall_ns;
        }
        dropped.last_sequence = dropped.last_sequence.max(sequence);
        dropped.last_wall_ns = dropped.last_wall_ns.max(wall_ns);
    }
}

/// An open run. Dropping it finishes the last chunk and the manifest.
#[derive(Debug)]
pub(super) struct Recorder {
    /// `None` once closed: the writer ends when its last sender goes.
    sender: Mutex<Option<SyncSender<Envelope>>>,
    writer: Mutex<Option<thread::JoinHandle<()>>>,
    health: Arc<Health>,
    directory: PathBuf,
}

impl Recorder {
    /// Create `root/id`, write its first `run.json` from `metadata` (a JSON
    /// object) and start the writer thread.
    pub(super) fn open(
        root: &Path,
        id: &str,
        mut metadata: Value,
        limits: Limits,
    ) -> io::Result<Self> {
        let directory = root.join(id);
        fs::create_dir_all(root)?;
        fs::create_dir(&directory)?;
        let health = Arc::new(Health::default());
        metadata["recorder_status"] = health.status();
        metadata["chunks"] = json!([]);
        write_metadata(&directory, &metadata)?;
        let (sender, receiver) = sync_channel(limits.queue);
        let writer = {
            let (directory, health) = (directory.clone(), health.clone());
            thread::Builder::new()
                .name("pq-timing-writer".into())
                .spawn(move || {
                    let written =
                        write_events(&directory, &receiver, &health, &mut metadata, limits);
                    if let Err(err) = written {
                        health.failed.store(true, Ordering::Release);
                        tracing::error!(%err, "PQ timing export disabled after a write failed");
                        metadata["recorder_status"] = health.status();
                        let _ = write_metadata(&directory, &metadata).inspect_err(
                            |err| tracing::warn!(%err, "Could not record the PQ timing export's failure"),
                        );
                    }
                })?
        };
        Ok(Self {
            sender: Mutex::new(Some(sender)),
            writer: Mutex::new(Some(writer)),
            health,
            directory,
        })
    }

    pub(super) fn directory(&self) -> &Path {
        &self.directory
    }

    /// Whether events still reach the disk: not after a write failed, and
    /// not once closed.
    pub(super) fn healthy(&self) -> bool {
        !self.health.failed.load(Ordering::Acquire)
    }

    /// Queue `record`, or count it as dropped when the queue is full. One
    /// emitted after [`Self::close`] is neither written nor counted.
    pub(super) fn emit(&self, class: Class, record: Record) {
        let sender = self.sender.lock().expect("PQ timing sender lock");
        let Some(sender) = sender.as_ref() else {
            return;
        };
        let sequence = self.health.next_sequence.fetch_add(1, Ordering::Relaxed) + 1;
        let envelope = Envelope {
            seq: sequence,
            record,
        };
        if let Err(TrySendError::Full(envelope) | TrySendError::Disconnected(envelope)) =
            sender.try_send(envelope)
        {
            self.health
                .drop_event(sequence, envelope.record.wall_ns, class);
        }
    }

    /// Finish the open chunk and the manifest, and wait for the writer.
    pub(super) fn close(&self) {
        self.sender.lock().expect("PQ timing sender lock").take();
        let writer = self.writer.lock().expect("PQ timing writer lock").take();
        if let Some(writer) = writer {
            let _ = writer.join();
        }
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        self.close();
    }
}

#[derive(Debug, Serialize)]
struct ChunkInfo {
    name: String,
    bytes: u64,
    first: u64,
    last: u64,
}

struct Chunk {
    temporary: PathBuf,
    name: String,
    stream: zstd::stream::write::Encoder<'static, BufWriter<File>>,
    started: Instant,
    /// Uncompressed bytes written.
    bytes: usize,
    /// Whether events were written since the last flush.
    unflushed: bool,
    first: u64,
    last: u64,
}

impl Chunk {
    fn new(directory: &Path, number: u64) -> io::Result<Self> {
        let name = format!("events-{number:06}.jsonl.zst");
        let temporary = directory.join(format!("{name}.partial"));
        let file = BufWriter::new(File::create(&temporary)?);
        Ok(Self {
            temporary,
            name,
            stream: zstd::stream::write::Encoder::new(file, 1)?,
            started: Instant::now(),
            bytes: 0,
            unflushed: false,
            first: u64::MAX,
            last: 0,
        })
    }

    fn write(&mut self, envelope: &Envelope, line: &mut Vec<u8>) -> io::Result<()> {
        line.clear();
        serde_json::to_writer(&mut *line, envelope)?;
        line.push(b'\n');
        self.stream.write_all(line)?;
        self.bytes = self.bytes.saturating_add(line.len());
        self.unflushed = true;
        self.first = self.first.min(envelope.seq);
        self.last = self.last.max(envelope.seq);
        Ok(())
    }

    /// End the compressed block and hand it to the file, so the `.partial`
    /// of a node that is killed reads up to here.
    fn flush(&mut self) -> io::Result<()> {
        if self.unflushed {
            self.stream.flush()?;
            self.unflushed = false;
        }
        Ok(())
    }

    fn finish(self, directory: &Path) -> io::Result<ChunkInfo> {
        let mut file = self.stream.finish()?;
        file.flush()?;
        let bytes = file.get_ref().metadata()?.len();
        fs::rename(&self.temporary, directory.join(&self.name))?;
        Ok(ChunkInfo {
            name: self.name,
            bytes,
            first: self.first,
            last: self.last,
        })
    }
}

/// Replace `run.json` whole: a reader never sees half of one.
fn write_metadata(directory: &Path, metadata: &Value) -> io::Result<()> {
    let temporary = directory.join("run.json.partial");
    let mut file = BufWriter::new(File::create(&temporary)?);
    serde_json::to_writer_pretty(&mut file, metadata)?;
    file.write_all(b"\n")?;
    file.flush()?;
    fs::rename(temporary, directory.join("run.json"))
}

/// The writer thread: until every sender is gone, write events into chunks,
/// finish a chunk when it is full or old, remove the oldest past the
/// retention bound, and keep the manifest's chunk list and status current.
fn write_events(
    directory: &Path,
    receiver: &Receiver<Envelope>,
    health: &Health,
    metadata: &mut Value,
    limits: Limits,
) -> io::Result<()> {
    let mut current = None::<Chunk>;
    let mut number = 0u64;
    let mut retained = VecDeque::<ChunkInfo>::new();
    let mut retained_bytes = 0u64;
    let mut evicted_chunks = 0u64;
    let (mut evicted_first, mut evicted_last) = (u64::MAX, 0u64);
    let mut line = Vec::new();
    let mut last_status = Instant::now();
    loop {
        let closing = match receiver.recv_timeout(limits.status_interval) {
            Ok(envelope) => {
                if current.is_none() {
                    number += 1;
                    current = Some(Chunk::new(directory, number)?);
                }
                if let Some(chunk) = current.as_mut() {
                    chunk.write(&envelope, &mut line)?;
                }
                false
            }
            Err(RecvTimeoutError::Timeout) => false,
            Err(RecvTimeoutError::Disconnected) => true,
        };
        let rotate = current.as_ref().is_some_and(|chunk| {
            closing
                || chunk.bytes >= limits.rotate_bytes
                || chunk.started.elapsed() >= limits.rotate_time
        });
        if rotate && let Some(chunk) = current.take() {
            let chunk = chunk.finish(directory)?;
            retained_bytes = retained_bytes.saturating_add(chunk.bytes);
            retained.push_back(chunk);
            while retained_bytes > limits.retain_bytes && retained.len() > 1 {
                let Some(old) = retained.pop_front() else {
                    break;
                };
                fs::remove_file(directory.join(&old.name))?;
                retained_bytes = retained_bytes.saturating_sub(old.bytes);
                evicted_chunks += 1;
                evicted_first = evicted_first.min(old.first);
                evicted_last = evicted_last.max(old.last);
            }
        }
        if rotate || closing || last_status.elapsed() >= limits.status_interval {
            if let Some(chunk) = current.as_mut() {
                chunk.flush()?;
            }
            let mut status = health.status();
            status["evicted_chunks"] = json!(evicted_chunks);
            status["evicted_sequence_bounds"] =
                json!((evicted_chunks != 0).then_some([evicted_first, evicted_last]));
            status["checked_unix_ns"] = json!(wall_now_ns());
            metadata["chunks"] = json!(retained);
            metadata["recorder_status"] = status;
            if closing {
                metadata["ended_unix_ns"] = json!(wall_now_ns());
            }
            write_metadata(directory, metadata)?;
            last_status = Instant::now();
        }
        if closing {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: &'static str, fields: Value) -> Record {
        Record {
            kind,
            wall_ns: 9,
            mono_ns: 8,
            fields,
        }
    }

    fn manifest(directory: &Path) -> Value {
        serde_json::from_reader(File::open(directory.join("run.json")).unwrap()).unwrap()
    }

    /// Every event of `directory`'s listed chunks, in order.
    fn events(directory: &Path) -> Vec<Value> {
        let manifest = manifest(directory);
        let mut events = Vec::new();
        for chunk in manifest["chunks"].as_array().unwrap() {
            let name = chunk["name"].as_str().unwrap();
            let bytes = zstd::stream::decode_all(File::open(directory.join(name)).unwrap());
            for line in bytes.unwrap().split(|&byte| byte == b'\n') {
                if !line.is_empty() {
                    events.push(serde_json::from_slice(line).unwrap());
                }
            }
        }
        events
    }

    /// Closing a run finishes its chunk under its final name, lists it in the
    /// manifest with the sequence numbers it holds, and stamps the end.
    #[test]
    fn closing_a_run_finishes_a_readable_chunk() {
        let root = tempfile::tempdir().unwrap();
        let metadata = json!({"schema_version": 1});
        let recorder = Recorder::open(root.path(), "run", metadata, Limits::DEFAULT).unwrap();
        let directory = recorder.directory().to_path_buf();
        assert_eq!(manifest(&directory)["chunks"], json!([]));
        recorder.emit(
            Class::Status,
            record("proposal_snapshot", json!({"round": 2})),
        );
        recorder.emit(
            Class::Work,
            record("proof_finished", json!({"late": false})),
        );
        recorder.close();

        let manifest = manifest(&directory);
        assert_eq!(manifest["schema_version"], 1);
        assert!(manifest["ended_unix_ns"].is_number());
        let chunk = &manifest["chunks"][0];
        assert_eq!(chunk["name"], "events-000001.jsonl.zst");
        assert_eq!((&chunk["first"], &chunk["last"]), (&json!(1), &json!(2)));
        assert!(!directory.join("events-000001.jsonl.zst.partial").exists());

        let events = events(&directory);
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0],
            json!({"seq": 1, "kind": "proposal_snapshot", "wall_ns": 9, "mono_ns": 8, "round": 2})
        );
        assert_eq!(events[1]["seq"], 2);
        // Nothing after the close is written, or counted as dropped.
        recorder.emit(Class::Work, record("proof_started", json!({})));
        assert_eq!(recorder.health.status()["dropped"]["work"], 0);
    }

    /// A full queue drops the event at once and says so in the status, by
    /// class and by the first and last sequence numbers lost.
    #[test]
    fn a_full_queue_drops_and_counts_without_waiting() {
        let (sender, receiver) = sync_channel(1);
        let recorder = Recorder {
            sender: Mutex::new(Some(sender)),
            writer: Mutex::new(None),
            health: Arc::default(),
            directory: PathBuf::new(),
        };
        for _ in 0..3 {
            recorder.emit(Class::Receipt, record("message_received", json!({})));
        }
        assert_eq!(receiver.try_recv().unwrap().seq, 1);
        let status = recorder.health.status();
        assert_eq!(status["dropped"]["receipt"], 2);
        assert_eq!(status["dropped"]["work"], 0);
        assert_eq!(status["first_dropped_sequence"], 2);
        assert_eq!(status["last_dropped_sequence"], 3);
        assert_eq!(status["submitted_sequence"], 3);
    }

    /// A chunk past its size is finished and the next one started; past the
    /// retention bound the oldest are removed, down to the newest, and the
    /// manifest says how many went and which events they held.
    #[test]
    fn chunks_rotate_by_size_and_the_oldest_are_evicted() {
        let root = tempfile::tempdir().unwrap();
        let limits = Limits {
            rotate_bytes: 1,
            retain_bytes: 1,
            ..Limits::DEFAULT
        };
        let recorder = Recorder::open(root.path(), "run", json!({}), limits).unwrap();
        let directory = recorder.directory().to_path_buf();
        for _ in 0..3 {
            recorder.emit(Class::Work, record("proof_started", json!({})));
        }
        recorder.close();

        let manifest = manifest(&directory);
        let chunks = manifest["chunks"].as_array().unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0]["name"], "events-000003.jsonl.zst");
        assert_eq!(manifest["recorder_status"]["evicted_chunks"], 2);
        assert_eq!(
            manifest["recorder_status"]["evicted_sequence_bounds"],
            json!([1, 2])
        );
        assert!(!directory.join("events-000001.jsonl.zst").exists());
        assert_eq!(events(&directory)[0]["seq"], 3);
    }

    /// With no event for a status interval, the open chunk is flushed: the
    /// `.partial` of a node killed afterwards decodes up to its last event,
    /// though no manifest lists it.
    #[test]
    fn an_open_chunk_is_flushed_with_every_status() {
        let root = tempfile::tempdir().unwrap();
        let limits = Limits {
            status_interval: Duration::from_millis(20),
            ..Limits::DEFAULT
        };
        let recorder = Recorder::open(root.path(), "run", json!({}), limits).unwrap();
        let directory = recorder.directory().to_path_buf();
        recorder.emit(Class::Work, record("proof_started", json!({"job_id": 7})));
        let partial = directory.join("events-000001.jsonl.zst.partial");
        // The frame is still open, so read what it holds so far as a stream.
        let flushed = || {
            use std::io::Read as _;
            let mut decoded = Vec::new();
            let file = File::open(&partial).ok()?;
            let _ = zstd::stream::read::Decoder::new(file)
                .ok()?
                .read_to_end(&mut decoded);
            decoded.ends_with(b"\n").then_some(decoded)
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        let decoded = loop {
            if let Some(decoded) = flushed() {
                break decoded;
            }
            assert!(
                Instant::now() < deadline,
                "the open chunk was never flushed"
            );
            thread::sleep(Duration::from_millis(10));
        };
        let event: Value = serde_json::from_slice(decoded.trim_ascii_end()).unwrap();
        assert_eq!(event["job_id"], 7);
        assert_eq!(manifest(&directory)["chunks"], json!([]));
        recorder.close();
    }

    /// A run directory that already exists is refused, so two runs never
    /// write into one.
    #[test]
    fn an_existing_run_directory_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let open = || Recorder::open(root.path(), "run", json!({}), Limits::DEFAULT);
        let first = open().unwrap();
        assert!(open().is_err());
        first.close();
    }
}
