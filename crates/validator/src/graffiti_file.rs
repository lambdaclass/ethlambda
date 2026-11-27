//! `--graffiti-file`: per-validator graffiti read from a file before every
//! proposal.
//!
//! The format is Lighthouse's, so a file written for Lighthouse's
//! `--graffiti-file` works here unchanged. One entry per line:
//!
//! ```text
//! default: ethlambda
//! 0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007: mr f was here
//! ```
//!
//! - A line splits at its first `:`. The part before it is exactly `default`
//!   or a `0x`-prefixed public key; the part after it, trimmed, is the
//!   graffiti, so the text may hold a `:` of its own
//!   (`graffitiwall:720:641:#ffff00`). An empty graffiti is a graffiti, 32
//!   zero bytes, not an absent one.
//! - A line of whitespace alone is skipped. Every other line must parse, and
//!   there is no comment syntax: a `#` line is refused, as Lighthouse refuses
//!   it.
//! - A key named twice, or `default` twice, takes its last line.
//!
//! # Read before every proposal
//!
//! The file is read again each time a graffiti is needed: for every proposal,
//! and for the keymanager API's `GET graffiti`, which answers what the next
//! proposal would carry. Each read builds its table from nothing, so a line
//! deleted from the file stops applying at the next proposal. (Lighthouse adds
//! each read to the table it loaded at startup, so a deleted line stays in
//! effect there until a restart.)
//!
//! A file that cannot be read or does not parse, a graffiti over 32 bytes
//! among them, refuses startup ([`GraffitiFile::open`]), as an over-long
//! `--graffiti` does. Once running, the same failure costs only the file: the
//! proposal logs a warning and takes its graffiti from the next source. So
//! does a path that is not a regular file, a file over [`MAX_FILE_BYTES`], and
//! a read that has not finished within [`READ_TIMEOUT`], so a stalled mount
//! cannot cost the proposal its slot. See [`ProposerSettings::next_graffiti`]
//! for the order.
//!
//! # A FIFO in the file's place
//!
//! A plain open of a FIFO for reading blocks until something opens it for
//! writing, so a FIFO nothing writes to, put at the path, would be a read
//! that never returns. The file is therefore opened with `O_NONBLOCK` (on
//! unix), which returns from that open at once, and what was opened is
//! checked to be a regular file before it is read; anything else (a FIFO, a
//! directory, a device) is refused as [`GraffitiFileError::NotARegularFile`],
//! at startup and at a proposal alike. The check is of the open handle, not
//! of the path, so nothing can be put at the path between the check and the
//! read, and `O_NONBLOCK` changes nothing for a regular file's reads.
//!
//! # A file that stalls
//!
//! Each read runs on a thread of its own, not on tokio's blocking pool, and
//! only one runs at a time: a caller that comes while one runs waits for that
//! read's answer rather than starting another, since both would read the same
//! file. A read of a stalled mount (an `open`, `fstat` or `read` the
//! filesystem never answers) never returns, and keeps its thread until the
//! mount answers. On the blocking pool, every proposal and `GET graffiti`
//! would strand one more of the threads slashing protection runs on, until
//! none were left for it, and the runtime would wait for the stuck ones
//! forever when the client stops.
//! Here a stalled file holds one thread, and the process exits past it.
//!
//! [`READ_TIMEOUT`] counts from the start of a read, not from each caller's
//! arrival: the caller that starts a read waits for it that long, one that
//! joins it waits only what is left, and one that finds it running longer
//! than that is given up on at once. So a slow or stalled file costs a caller
//! at most [`READ_TIMEOUT`], and nothing to a caller that comes once its read
//! has run that long. A caller that joins a running read takes the file as
//! that read found it: a read begun at most [`READ_TIMEOUT`] before the
//! caller asked. At startup, [`GraffitiFile::open`] gives its read
//! [`OPEN_TIMEOUT`] and refuses startup past it.
//!
//! The price of one read at a time: a read that never returns, as one of a
//! hung network mount does, turns the file off until it returns or the client
//! restarts. Every caller meanwhile joins it and is given up on, so every
//! proposal skips the file with a warning, even once the file is put right,
//! since the stuck read is still the running one. A FIFO cannot cause this,
//! since it is refused without being waited on (above); only a filesystem
//! that never answers can. Starting a second read beside a stuck one would
//! end that, at the cost of a thread per stuck read; one read at a time is the
//! choice made here.
//!
//! [`ProposerSettings::next_graffiti`]: crate::proposer_settings::ProposerSettings::next_graffiti

use std::collections::HashMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use ethlambda_types::beacon::primitives::{BLS_PUBKEY_SIZE, BlsPubkey, Bytes32};
use tokio::sync::watch;
use tokio::time::Instant;
use tracing::{info, warn};

use crate::proposer_settings::{GRAFFITI_BYTES, graffiti_from_text};

/// The key of the line every validator the file does not name gets.
const DEFAULT_KEY: &str = "default";

/// The largest file read. A line is under 200 bytes, so this holds tens of
/// thousands of keys; a file past it is refused rather than read whole into
/// memory ahead of a proposal.
pub const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// How long a read of the file may run, from its start, before its callers
/// are given up on: a proposal waits at most this long for the file, less
/// when it joins a read already running. A local read takes microseconds; a
/// stalled network mount would otherwise hold the block request until the
/// slot is lost, for the sake of a graffiti.
pub const READ_TIMEOUT: Duration = Duration::from_millis(250);

/// How long startup waits for its read of the file ([`GraffitiFile::open`]).
/// Seconds rather than [`READ_TIMEOUT`], so a mount's slow first access or a
/// busy machine does not refuse a file that reads; bounded, so a stalled
/// mount refuses startup naming the file rather than hanging it. (A FIFO is
/// refused at once, without this wait: see the module doc.)
pub const OPEN_TIMEOUT: Duration = Duration::from_secs(5);

/// The read timeout of a test that reads a file whole and compares what it
/// holds ([`GraffitiFile::with_read_timeout`]). Under [`READ_TIMEOUT`], a
/// loaded test runner can take longer than that to start a thread and read a
/// temporary file, and the read would then be skipped, so the test would
/// compare the next source's graffiti. A read that fails answers at once, so
/// this costs a passing test nothing.
#[cfg(test)]
pub(crate) const PATIENT_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Cloneable, so that one read's failure can be every waiting caller's
/// answer.
#[derive(Debug, Clone, thiserror::Error)]
pub enum GraffitiFileError {
    /// The I/O error is in the message and is not also the error's source:
    /// the runtime logs print the message alone, and a startup report prints
    /// the message and then every source, so it would print the I/O error
    /// twice. (A field named `source` is a source whether marked or not.)
    #[error("graffiti file {path}: {error}")]
    Read {
        path: String,
        error: Arc<std::io::Error>,
    },
    /// A FIFO, a directory or a device at the path: anything a read could
    /// block on, or that holds no text, refused before it is read.
    #[error("graffiti file {path} is not a regular file")]
    NotARegularFile { path: String },
    #[error("graffiti file {path} is over {MAX_FILE_BYTES} bytes")]
    TooLarge { path: String },
    #[error("graffiti file {path} was not read within {after:?}")]
    TimedOut { path: String, after: Duration },
    #[error("graffiti file {path}, line {line}: {reason}")]
    Line {
        path: String,
        line: usize,
        reason: String,
    },
}

/// A line the file cannot hold, by its number (from 1) and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadLine {
    pub line: usize,
    pub reason: String,
}

/// One read of the file: the graffiti of each public key it names, and the
/// `default` line's, when it has one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GraffitiTable {
    default: Option<Bytes32>,
    by_key: HashMap<BlsPubkey, Bytes32>,
}

impl GraffitiTable {
    /// The file's text as a table, or the first line that does not parse.
    pub fn parse(text: &str) -> Result<Self, BadLine> {
        let mut table = Self::default();
        // A UTF-8 byte-order mark, which Windows editors write, would
        // otherwise stick to the first line's key.
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        for (index, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let (key, graffiti) = parse_line(line).map_err(|reason| BadLine {
                line: index + 1,
                reason,
            })?;
            match key {
                Some(pubkey) => {
                    table.by_key.insert(pubkey, graffiti);
                }
                None => table.default = Some(graffiti),
            }
        }
        Ok(table)
    }

    /// `pubkey`'s line, else the `default` line, else `None`.
    pub fn graffiti(&self, pubkey: &BlsPubkey) -> Option<Bytes32> {
        self.by_key.get(pubkey).copied().or(self.default)
    }
}

/// One non-blank line: `None` for the `default` key, the public key
/// otherwise, and the graffiti.
fn parse_line(line: &str) -> Result<(Option<BlsPubkey>, Bytes32), String> {
    let Some((key, value)) = line.split_once(':') else {
        return Err("no `:` between a key and a graffiti".to_string());
    };
    let value = value.trim();
    let graffiti = graffiti_from_text(value).ok_or_else(|| {
        format!(
            "the graffiti is {} bytes encoded as UTF-8; the field holds {GRAFFITI_BYTES}",
            value.len()
        )
    })?;
    if key == DEFAULT_KEY {
        return Ok((None, graffiti));
    }
    Ok((Some(parse_key(key)?), graffiti))
}

/// A line's key as a public key: `0x` and 96 hex digits, as Lighthouse reads
/// it. Not checked to be a point on the curve, which Lighthouse does not check
/// either; a key no validator here holds is a line that never applies.
fn parse_key(key: &str) -> Result<BlsPubkey, String> {
    let Some(digits) = key.strip_prefix("0x") else {
        return Err(format!(
            "{key:?} is neither `{DEFAULT_KEY}` nor a 0x-prefixed public key"
        ));
    };
    let bytes =
        hex::decode(digits).map_err(|err| format!("public key {key:?} is not hex: {err}"))?;
    let bytes: [u8; BLS_PUBKEY_SIZE] = bytes.try_into().map_err(|got: Vec<u8>| {
        format!(
            "public key {key:?} is {} bytes, expected {BLS_PUBKEY_SIZE}",
            got.len()
        )
    })?;
    Ok(BlsPubkey(bytes))
}

/// What one read of the file gives: the table, or why there is none.
type ReadAnswer = Result<GraffitiTable, GraffitiFileError>;

/// A read running on its thread.
#[derive(Debug, Clone)]
struct RunningRead {
    /// When it was started, which every caller's wait counts from.
    started: Instant,
    /// The channel its answer comes on (`None` until it does).
    answer: watch::Receiver<Option<ReadAnswer>>,
}

/// Where `--graffiti-file` points. It holds no contents: every read parses
/// the file afresh.
#[derive(Debug, Clone)]
pub struct GraffitiFile {
    path: PathBuf,
    /// How long a read may run before [`Self::read`] gives up on it:
    /// [`READ_TIMEOUT`], except in tests (`with_read_timeout`).
    read_timeout: Duration,
    /// The read running now, if any. A caller that comes while it runs waits
    /// on it rather than starting another read, so a stalled file holds one
    /// thread. The read's thread clears it before answering. Shared by every
    /// clone.
    running: Arc<Mutex<Option<RunningRead>>>,
}

impl GraffitiFile {
    /// The file at `path`, read and parsed once first, so that a file every
    /// proposal would skip refuses startup instead. That read is given up on
    /// after [`OPEN_TIMEOUT`], so a stalled mount refuses startup too rather
    /// than hang it.
    ///
    /// A read that answers within [`OPEN_TIMEOUT`] but takes longer than
    /// [`READ_TIMEOUT`] is accepted with a warning: a proposal gives up on a
    /// read that slow, so a file that always reads so slowly is skipped by
    /// every proposal. Not refused, since a cold cache or a mount's first
    /// access can make one read that slow and the next ones fast.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, GraffitiFileError> {
        let file = Self {
            path: path.into(),
            read_timeout: READ_TIMEOUT,
            running: Arc::default(),
        };
        let started = std::time::Instant::now();
        let (answer, answered) = std::sync::mpsc::channel();
        let reader = file.clone();
        file.spawn(move || {
            let _ = answer.send(reader.read_now());
        })?;
        let table = match answered.recv_timeout(OPEN_TIMEOUT) {
            Ok(table) => table?,
            Err(RecvTimeoutError::Timeout) => return Err(file.timed_out(OPEN_TIMEOUT)),
            Err(RecvTimeoutError::Disconnected) => return Err(file.unanswered()),
        };
        let took = started.elapsed();
        if took > file.read_timeout {
            warn!(
                path = %file.path.display(),
                ?took,
                read_timeout = ?file.read_timeout,
                "Graffiti file was slow to read; a proposal gives up on a read this slow and \
                 skips the file"
            );
        }
        info!(
            path = %file.path.display(),
            validators = table.by_key.len(),
            has_default = table.default.is_some(),
            "Graffiti file read; it is read again before every proposal"
        );
        Ok(file)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// This file with [`Self::read`] waiting `read_timeout` rather than
    /// [`READ_TIMEOUT`]; see [`PATIENT_READ_TIMEOUT`]. Clones share their
    /// running read, so a clone given another timeout still joins it.
    #[cfg(test)]
    pub(crate) fn with_read_timeout(mut self, read_timeout: Duration) -> Self {
        self.read_timeout = read_timeout;
        self
    }

    /// Read and parse the file on the calling thread, refusing one that is
    /// not a regular file or is over [`MAX_FILE_BYTES`].
    ///
    /// The open does not wait for a FIFO's writer (`open_without_blocking`),
    /// and what it opened is checked to be a regular file before a byte is
    /// read, so a FIFO is refused at once rather than read forever. The check
    /// is of the open handle, not of the path, so nothing can be put at the
    /// path between the check and the read.
    pub fn read_now(&self) -> Result<GraffitiTable, GraffitiFileError> {
        let path = || self.path.display().to_string();
        let read = |error| GraffitiFileError::Read {
            path: path(),
            error: Arc::new(error),
        };
        let file = open_without_blocking(&self.path).map_err(read)?;
        if !file.metadata().map_err(read)?.is_file() {
            return Err(GraffitiFileError::NotARegularFile { path: path() });
        }
        let mut bytes = Vec::new();
        // One byte past the limit, to tell a file at it from one over it.
        file.take(MAX_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(read)?;
        if bytes.len() as u64 > MAX_FILE_BYTES {
            return Err(GraffitiFileError::TooLarge { path: path() });
        }
        let text = String::from_utf8(bytes)
            .map_err(|err| read(std::io::Error::new(std::io::ErrorKind::InvalidData, err)))?;
        GraffitiTable::parse(&text).map_err(|BadLine { line, reason }| GraffitiFileError::Line {
            path: path(),
            line,
            reason,
        })
    }

    /// [`Self::read_now`] on a thread of its own, off the runtime's workers
    /// and its blocking pool (see the module doc), or the answer of the read
    /// already running. Given up on once the read has run [`READ_TIMEOUT`]
    /// from its start, so a caller that joins a running read waits only what
    /// is left of it, and one that finds the read past it is given up on at
    /// once. A read given up on keeps its thread until the file answers, and
    /// every caller until then joins it rather than starting another.
    pub async fn read(&self) -> ReadAnswer {
        let RunningRead {
            started,
            mut answer,
        } = self.join_or_start()?;
        let deadline = started + self.read_timeout;
        let answered = tokio::time::timeout_at(deadline, answer.wait_for(Option::is_some)).await;
        match answered {
            Ok(Ok(answer)) => answer.clone().expect("waited for an answer"),
            Ok(Err(_)) => Err(self.unanswered()),
            Err(_) => Err(self.timed_out(self.read_timeout)),
        }
    }

    /// The read running now, or, with none running, one started now on a
    /// thread of its own.
    ///
    /// A running read whose thread ended without answering, which only a
    /// panic in it does, is not waited on: a new read replaces it, however
    /// long ago it started.
    fn join_or_start(&self) -> Result<RunningRead, GraffitiFileError> {
        let mut running = self.running.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(read) = running.as_ref()
            && read.answer.has_changed().is_ok()
        {
            return Ok(read.clone());
        }
        let (answering, answer) = watch::channel(None);
        // Before the thread is spawned, so the time that takes counts too.
        let started = Instant::now();
        let file = self.clone();
        self.spawn(move || {
            let table = file.read_now();
            // Cleared before answering, so a caller from now on reads the
            // file again rather than taking this answer.
            *file.running.lock().unwrap_or_else(PoisonError::into_inner) = None;
            answering.send_replace(Some(table));
        })?;
        let read = RunningRead { started, answer };
        *running = Some(read.clone());
        Ok(read)
    }

    /// Put a read in place of the running one, started now, that answers
    /// only when the returned sender sends, as one of a stalled file never
    /// does. Dropping the sender is a read whose thread ended unanswered.
    #[cfg(test)]
    pub(crate) fn start_stalled_read(&self) -> watch::Sender<Option<ReadAnswer>> {
        let (answering, answer) = watch::channel(None);
        let started = Instant::now();
        let read = RunningRead { started, answer };
        *self.running.lock().unwrap_or_else(PoisonError::into_inner) = Some(read);
        answering
    }

    /// Run `read` on a thread of its own. The caller may have stopped waiting
    /// by the time it ends; the thread ends all the same.
    fn spawn(&self, read: impl FnOnce() + Send + 'static) -> Result<(), GraffitiFileError> {
        std::thread::Builder::new()
            .name("graffiti-file".to_string())
            .spawn(read)
            .map(drop)
            .map_err(|error| GraffitiFileError::Read {
                path: self.path.display().to_string(),
                error: Arc::new(error),
            })
    }

    fn timed_out(&self, after: Duration) -> GraffitiFileError {
        GraffitiFileError::TimedOut {
            path: self.path.display().to_string(),
            after,
        }
    }

    /// A read whose thread ended without an answer, which only a panic in it
    /// does.
    fn unanswered(&self) -> GraffitiFileError {
        GraffitiFileError::Read {
            path: self.path.display().to_string(),
            error: Arc::new(std::io::Error::other("the read ended without an answer")),
        }
    }
}

/// `path` opened for reading with `O_NONBLOCK`, which returns at once from
/// the open of a FIFO that a plain open would block in until something opened
/// it for writing. It changes nothing for a regular file, whose reads never
/// block on it, and [`GraffitiFile::read_now`] refuses anything else before
/// reading. Symlinks are followed, so a link to a regular file reads.
#[cfg(unix)]
fn open_without_blocking(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(unix))]
fn open_without_blocking(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two keys of Lighthouse's own example file
    /// (`book/src/validator_graffiti.md`).
    const PK1: &str = "0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007";
    const PK2: &str = "0xa5566f9ec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477";

    fn key(text: &str) -> BlsPubkey {
        parse_key(text).expect("a public key")
    }

    fn graffiti(text: &str) -> Option<Bytes32> {
        Some(graffiti_from_text(text).expect("fits"))
    }

    fn refusal(text: &str) -> BadLine {
        GraffitiTable::parse(text).expect_err("refused")
    }

    #[test]
    fn lighthouses_example_file_parses() {
        let text = format!("default: Lighthouse\n{PK1}: mr f was here\n{PK2}: mr v was here\n");
        let table = GraffitiTable::parse(&text).expect("parses");
        assert_eq!(table.graffiti(&key(PK1)), graffiti("mr f was here"));
        assert_eq!(table.graffiti(&key(PK2)), graffiti("mr v was here"));
        assert_eq!(
            table.graffiti(&BlsPubkey([7; BLS_PUBKEY_SIZE])),
            graffiti("Lighthouse"),
            "a key the file does not name gets the default line"
        );
    }

    /// The cases Lighthouse's own test file holds: a graffiti with colons in
    /// it, an empty one, and blank lines before, between and after entries.
    #[test]
    fn blank_lines_are_skipped_and_a_graffiti_may_hold_colons_or_be_empty() {
        let text = format!("\n   \n{PK1}: graffitiwall:720:641:#ffff00\n\t\n{PK2}:\n\n   \n");
        let table = GraffitiTable::parse(&text).expect("parses");
        assert_eq!(
            table.graffiti(&key(PK1)),
            graffiti("graffitiwall:720:641:#ffff00")
        );
        assert_eq!(
            table.graffiti(&key(PK2)),
            Some(Bytes32::ZERO),
            "an empty graffiti is set, to zeros, not absent"
        );
    }

    #[test]
    fn without_a_default_line_a_key_the_file_does_not_name_has_none() {
        let table = GraffitiTable::parse(&format!("{PK1}: one\n")).expect("parses");
        assert_eq!(table.graffiti(&key(PK2)), None);
        assert_eq!(
            GraffitiTable::parse("").expect("parses"),
            GraffitiTable::default()
        );
    }

    #[test]
    fn the_last_line_for_a_key_wins() {
        let text = format!("default: first\n{PK1}: first\ndefault: second\n{PK1}: second\n");
        let table = GraffitiTable::parse(&text).expect("parses");
        assert_eq!(table.graffiti(&key(PK1)), graffiti("second"));
        assert_eq!(table.graffiti(&key(PK2)), graffiti("second"));
    }

    /// Windows line endings are lines too, and the value is trimmed of the
    /// spaces around it, so neither counts toward the 32 bytes.
    #[test]
    fn crlf_endings_and_surrounding_spaces_are_not_part_of_the_graffiti() {
        let fits = "a".repeat(GRAFFITI_BYTES);
        let text = format!("default:   {fits}   \r\n{PK1}: two\r\n");
        let table = GraffitiTable::parse(&text).expect("parses");
        assert_eq!(table.graffiti(&key(PK2)), graffiti(&fits));
        assert_eq!(table.graffiti(&key(PK1)), graffiti("two"));
    }

    #[test]
    fn a_line_without_a_colon_is_refused_by_its_number() {
        let bad = refusal(&format!("default: fine\n\n{PK1} no colon\n"));
        assert_eq!(bad.line, 3, "blank lines count toward the number");
        assert!(bad.reason.contains("`:`"), "got {}", bad.reason);
    }

    /// Lighthouse has no comment syntax, and neither does this: a comment line
    /// is refused rather than read as something it is not.
    #[test]
    fn a_comment_is_refused() {
        assert_eq!(refusal("# graffiti for the wall\n").line, 1);
        assert_eq!(refusal("# note: for the wall\n").line, 1);
    }

    #[test]
    fn a_key_that_is_neither_default_nor_a_public_key_is_refused() {
        let short = &PK1[..PK1.len() - 2];
        let long = format!("{PK1}00");
        let not_hex = format!("0x{}", "zz".repeat(BLS_PUBKEY_SIZE));
        // No `0x`, 47 bytes, 49 bytes, not hex; and `default` is matched
        // exactly, neither case-folded nor trimmed.
        let keys = [
            &PK1[2..],
            short,
            long.as_str(),
            not_hex.as_str(),
            "Default",
            " default",
            "default ",
        ];
        for key in keys {
            let bad = refusal(&format!("{key}: text\n"));
            assert_eq!(bad.line, 1, "{key:?}");
        }
    }

    #[test]
    fn a_graffiti_over_32_bytes_is_refused_rather_than_truncated() {
        let over = "a".repeat(GRAFFITI_BYTES + 1);
        let bad = refusal(&format!("{PK1}: fits\ndefault: {over}\n"));
        assert_eq!(bad.line, 2);
        assert!(bad.reason.contains("33 bytes"), "got {}", bad.reason);
        // Sixteen two-byte characters fill the field; seventeen do not.
        GraffitiTable::parse(&format!("default: {}\n", "ñ".repeat(16))).expect("32 bytes");
        refusal(&format!("default: {}\n", "ñ".repeat(17)));
    }

    /// Each read starts from nothing: a line deleted from the file stops
    /// applying, where Lighthouse would keep it until a restart.
    #[test]
    fn each_read_replaces_the_whole_table() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("graffiti.txt");
        std::fs::write(&path, format!("default: wall\n{PK1}: mine\n")).expect("writes");
        let file = GraffitiFile::open(&path).expect("opens");
        assert_eq!(
            file.read_now().expect("reads").graffiti(&key(PK1)),
            graffiti("mine")
        );

        std::fs::write(&path, "default: wall\n").expect("rewrites");
        let table = file.read_now().expect("reads");
        assert_eq!(table.graffiti(&key(PK1)), graffiti("wall"));

        std::fs::write(&path, "").expect("empties");
        let table = file.read_now().expect("reads");
        assert_eq!(table.graffiti(&key(PK1)), None);
    }

    #[test]
    fn open_refuses_a_missing_or_malformed_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("graffiti.txt");
        let err = GraffitiFile::open(&path).expect_err("no file");
        assert!(matches!(err, GraffitiFileError::Read { .. }), "got {err:?}");
        // The I/O error is in the message once, and not also a source that a
        // startup report would print again under it.
        assert!(
            std::error::Error::source(&err).is_none(),
            "got a source under {err}"
        );

        let over = "a".repeat(GRAFFITI_BYTES + 1);
        std::fs::write(&path, format!("default: {over}\n")).expect("writes");
        let err = GraffitiFile::open(&path).expect_err("an over-long graffiti");
        assert!(
            matches!(err, GraffitiFileError::Line { line: 1, .. }),
            "got {err:?}"
        );
        assert!(err.to_string().contains("graffiti.txt"), "got {err}");
    }

    /// A UTF-8 byte-order mark, as Windows Notepad writes one, is not part
    /// of the first line's key.
    #[test]
    fn a_leading_byte_order_mark_is_not_part_of_the_first_key() {
        let table = GraffitiTable::parse("\u{feff}default: wall\n").expect("parses");
        assert_eq!(table.graffiti(&key(PK1)), graffiti("wall"));
    }

    /// A file at the limit is read; one byte over it is refused before it is
    /// parsed, rather than read whole.
    #[test]
    fn a_file_over_the_size_limit_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("graffiti.txt");
        let at_limit = " ".repeat(usize::try_from(MAX_FILE_BYTES).expect("fits"));
        std::fs::write(&path, &at_limit).expect("writes");
        let file = GraffitiFile::open(&path).expect("a file at the limit opens");

        std::fs::write(&path, format!("{at_limit} ")).expect("grows");
        let err = file.read_now().expect_err("over the limit");
        assert!(
            matches!(err, GraffitiFileError::TooLarge { .. }),
            "got {err:?}"
        );
    }

    /// The read the proposal path makes, off the runtime's workers, gives
    /// what the file holds now.
    #[tokio::test]
    async fn the_off_runtime_read_gives_what_the_file_holds() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("graffiti.txt");
        std::fs::write(&path, format!("{PK1}: mine\n")).expect("writes");
        let file = GraffitiFile::open(&path)
            .expect("opens")
            .with_read_timeout(PATIENT_READ_TIMEOUT);
        let table = file.read().await.expect("reads");
        assert_eq!(table.graffiti(&key(PK1)), graffiti("mine"));

        std::fs::remove_file(&path).expect("removes");
        let err = file.read().await.expect_err("gone");
        assert!(matches!(err, GraffitiFileError::Read { .. }), "got {err:?}");
    }

    /// A read running, as one of a stalled file keeps running, is joined
    /// rather than read again, and waited on only until it has run the
    /// timeout from its start: a caller that joins it halfway waits what is
    /// left, and one that comes once it has run longer is given up on at
    /// once. Neither starts a read of its own. Time is paused, so the waits
    /// are measured exactly; the one real read, `open`'s, waits on no tokio
    /// timer.
    #[tokio::test(start_paused = true)]
    async fn a_running_read_is_waited_on_only_until_the_timeout_from_its_start() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("graffiti.txt");
        std::fs::write(&path, format!("{PK1}: mine\n")).expect("writes");
        let file = GraffitiFile::open(&path).expect("opens");
        let _answering = file.start_stalled_read();
        let running_since = || {
            let running = file.running.lock().expect("not poisoned");
            running.as_ref().map(|read| read.started)
        };
        let started = running_since().expect("a read is running");

        tokio::time::advance(READ_TIMEOUT / 2).await;
        let asked = Instant::now();
        let err = file
            .read()
            .await
            .expect_err("the running read has not answered");
        assert!(
            matches!(err, GraffitiFileError::TimedOut { after, .. } if after == READ_TIMEOUT),
            "got {err:?}"
        );
        let waited = asked.elapsed();
        assert!(
            waited >= READ_TIMEOUT / 2 && waited < READ_TIMEOUT,
            "waited {waited:?}, not what was left of {READ_TIMEOUT:?} from the read's start"
        );
        assert_eq!(running_since(), Some(started), "no read of its own");

        tokio::time::advance(Duration::from_secs(1)).await;
        let asked = Instant::now();
        let err = file
            .read()
            .await
            .expect_err("the running read has not answered");
        assert!(
            matches!(err, GraffitiFileError::TimedOut { .. }),
            "got {err:?}"
        );
        assert_eq!(asked.elapsed(), Duration::ZERO, "given up on at once");
        assert_eq!(running_since(), Some(started), "no read of its own");
    }

    /// The running read's answer, when it comes before the timeout, is the
    /// answer of a caller that joined it.
    #[tokio::test(start_paused = true)]
    async fn a_running_reads_answer_is_the_joiners() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("graffiti.txt");
        std::fs::write(&path, format!("{PK1}: mine\n")).expect("writes");
        let file = GraffitiFile::open(&path).expect("opens");
        let answering = file.start_stalled_read();

        let answer_halfway = async move {
            tokio::time::sleep(READ_TIMEOUT / 2).await;
            let stalled = GraffitiTable::parse(&format!("{PK1}: stalled\n")).expect("parses");
            answering.send_replace(Some(Ok(stalled)));
        };
        let (table, ()) = tokio::join!(file.read(), answer_halfway);
        let table = table.expect("the running read's answer");
        assert_eq!(table.graffiti(&key(PK1)), graffiti("stalled"));
    }

    /// A read whose thread ended without answering, which only a panic in it
    /// does, is not waited on, however long ago it started: the next caller
    /// reads the file again rather than being given up on.
    #[tokio::test]
    async fn a_read_that_ended_unanswered_is_not_waited_on() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("graffiti.txt");
        std::fs::write(&path, format!("{PK1}: mine\n")).expect("writes");
        let file = GraffitiFile::open(&path)
            .expect("opens")
            .with_read_timeout(PATIENT_READ_TIMEOUT);

        let (answering, answer) = watch::channel(None);
        drop(answering);
        let started = Instant::now() - 2 * PATIENT_READ_TIMEOUT;
        *file.running.lock().expect("not poisoned") = Some(RunningRead { started, answer });
        let table = file.read().await.expect("a new read");
        assert_eq!(table.graffiti(&key(PK1)), graffiti("mine"));
    }

    /// Callers that come together all get the file's table.
    #[tokio::test]
    async fn callers_that_come_together_all_get_the_table() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("graffiti.txt");
        std::fs::write(&path, format!("{PK1}: mine\n")).expect("writes");
        let file = GraffitiFile::open(&path)
            .expect("opens")
            .with_read_timeout(PATIENT_READ_TIMEOUT);

        let reads = (0..8).map(|_| file.read());
        for table in futures_util::future::join_all(reads).await {
            assert_eq!(table.expect("reads").graffiti(&key(PK1)), graffiti("mine"));
        }
        assert!(
            file.running.lock().expect("not poisoned").is_none(),
            "the read is done, so none is running"
        );
    }

    /// A FIFO at `path`, with nothing writing to it.
    #[cfg(unix)]
    fn make_fifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt as _;
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("no NUL");
        // SAFETY: `c_path` is a NUL-terminated string that outlives the call.
        let made = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(made, 0, "mkfifo: {}", std::io::Error::last_os_error());
    }

    /// A FIFO nothing writes to is refused at startup as not a regular file,
    /// rather than opened and waited on until `OPEN_TIMEOUT` (which would
    /// answer `TimedOut`).
    #[cfg(unix)]
    #[test]
    fn open_refuses_a_fifo_at_once() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("graffiti.fifo");
        make_fifo(&path);
        let err = GraffitiFile::open(&path).expect_err("a FIFO");
        assert!(
            matches!(err, GraffitiFileError::NotARegularFile { .. }),
            "got {err:?}"
        );
        assert!(err.to_string().contains("graffiti.fifo"), "got {err}");
    }

    /// A FIFO put in the file's place once running, opened plainly, would be
    /// a read that never returned, which every later caller would join, so
    /// the file would stay off even once a regular file was back. The read
    /// refuses the FIFO at once instead and leaves no read running, so the
    /// next caller reads the regular file put back in its place.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_fifo_swapped_in_is_refused_and_the_file_put_back_reads() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("graffiti.txt");
        std::fs::write(&path, format!("{PK1}: mine\n")).expect("writes");
        let file = GraffitiFile::open(&path)
            .expect("opens")
            .with_read_timeout(PATIENT_READ_TIMEOUT);

        std::fs::remove_file(&path).expect("removes");
        make_fifo(&path);
        let err = file.read().await.expect_err("a FIFO");
        assert!(
            matches!(err, GraffitiFileError::NotARegularFile { .. }),
            "got {err:?}"
        );
        assert!(
            file.running.lock().expect("not poisoned").is_none(),
            "the read answered, so none is running"
        );

        std::fs::remove_file(&path).expect("removes the FIFO");
        std::fs::write(&path, format!("{PK1}: back\n")).expect("writes");
        let table = file.read().await.expect("a regular file reads");
        assert_eq!(table.graffiti(&key(PK1)), graffiti("back"));
    }

    /// A directory opens for reading on unix, so it is the type check that
    /// refuses it, at startup and once running.
    #[cfg(unix)]
    #[test]
    fn a_directory_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let err = GraffitiFile::open(dir.path()).expect_err("a directory");
        assert!(
            matches!(err, GraffitiFileError::NotARegularFile { .. }),
            "got {err:?}"
        );

        let path = dir.path().join("graffiti.txt");
        std::fs::write(&path, format!("{PK1}: mine\n")).expect("writes");
        let file = GraffitiFile::open(&path).expect("opens");
        std::fs::remove_file(&path).expect("removes");
        std::fs::create_dir(&path).expect("a directory in its place");
        let err = file.read_now().expect_err("a directory");
        assert!(
            matches!(err, GraffitiFileError::NotARegularFile { .. }),
            "got {err:?}"
        );
    }
}
