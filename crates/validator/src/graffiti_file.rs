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
//! does a file over [`MAX_FILE_BYTES`], and a read that has not finished
//! within [`READ_TIMEOUT`], so a stalled mount cannot cost the proposal its
//! slot. See [`ProposerSettings::next_graffiti`] for the order.
//!
//! # A file that stalls
//!
//! Each read runs on a thread of its own, not on tokio's blocking pool, and
//! at most [`MAX_READS`] run at once. A read of a stalled mount, or of a FIFO
//! put in the file's place, never returns, and keeps its thread until the
//! file answers. On the blocking pool, every proposal and `GET graffiti`
//! would strand one more of the threads slashing protection runs on, until
//! none were left for it, and the runtime would wait for the stuck ones
//! forever when the client stops. Here a stalled file holds [`MAX_READS`]
//! threads at most, the process exits past them, and every read meanwhile
//! waits for a free one within [`READ_TIMEOUT`] and is given up on. At
//! startup, [`GraffitiFile::open`] gives its read [`OPEN_TIMEOUT`] and
//! refuses startup past it.
//!
//! [`ProposerSettings::next_graffiti`]: crate::proposer_settings::ProposerSettings::next_graffiti

use std::collections::HashMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::RecvTimeoutError;
use std::time::Duration;

use ethlambda_types::beacon::primitives::{BLS_PUBKEY_SIZE, BlsPubkey, Bytes32};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::info;

use crate::proposer_settings::{GRAFFITI_BYTES, graffiti_from_text};

/// The key of the line every validator the file does not name gets.
const DEFAULT_KEY: &str = "default";

/// The largest file read. A line is under 200 bytes, so this holds tens of
/// thousands of keys; a file past it is refused rather than read whole into
/// memory ahead of a proposal.
pub const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// How long a proposal waits for the file. A local read takes microseconds; a
/// stalled network mount, or a FIFO swapped in for the file, would otherwise
/// hold the block request until the slot is lost, for the sake of a graffiti.
pub const READ_TIMEOUT: Duration = Duration::from_millis(250);

/// How long startup waits for its read of the file ([`GraffitiFile::open`]).
/// Seconds rather than [`READ_TIMEOUT`], so a mount's slow first access or a
/// busy machine does not refuse a file that reads; bounded, so a stalled
/// mount or a FIFO refuses startup naming the file rather than hanging it.
pub const OPEN_TIMEOUT: Duration = Duration::from_secs(5);

/// How many reads of the file run at once, each on a thread of its own: also
/// how many threads a stalled file can hold. More than one, so a burst of
/// `GET graffiti` requests does not queue a proposal past its timeout.
pub const MAX_READS: usize = 4;

#[derive(Debug, thiserror::Error)]
pub enum GraffitiFileError {
    #[error("graffiti file {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
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

/// Where `--graffiti-file` points. It holds no contents: every read parses
/// the file afresh.
#[derive(Debug, Clone)]
pub struct GraffitiFile {
    path: PathBuf,
    /// A permit per read running, held by the read's thread until the read
    /// ends, so a stalled file holds [`MAX_READS`] threads at most. Shared by
    /// every clone.
    readers: Arc<Semaphore>,
}

impl GraffitiFile {
    /// The file at `path`, read and parsed once first, so that a file every
    /// proposal would skip refuses startup instead. That read is given up on
    /// after [`OPEN_TIMEOUT`], so a stalled mount refuses startup too rather
    /// than hang it.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, GraffitiFileError> {
        let file = Self {
            path: path.into(),
            readers: Arc::new(Semaphore::new(MAX_READS)),
        };
        let reader = file
            .readers
            .clone()
            .try_acquire_owned()
            .expect("no read of a file just opened is running");
        let (answer, answered) = std::sync::mpsc::channel();
        file.spawn_read(reader, move |table| {
            let _ = answer.send(table);
        })?;
        let table = match answered.recv_timeout(OPEN_TIMEOUT) {
            Ok(table) => table?,
            Err(RecvTimeoutError::Timeout) => return Err(file.timed_out(OPEN_TIMEOUT)),
            Err(RecvTimeoutError::Disconnected) => return Err(file.unanswered()),
        };
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

    /// Read and parse the file on the calling thread, refusing one over
    /// [`MAX_FILE_BYTES`].
    pub fn read_now(&self) -> Result<GraffitiTable, GraffitiFileError> {
        let path = || self.path.display().to_string();
        let read = |source| GraffitiFileError::Read {
            path: path(),
            source,
        };
        let file = std::fs::File::open(&self.path).map_err(read)?;
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
    /// and its blocking pool (see the module doc), given up after
    /// [`READ_TIMEOUT`], the wait for a free reader included. A read given up
    /// on keeps its thread, and its reader, until the file answers.
    pub async fn read(&self) -> Result<GraffitiTable, GraffitiFileError> {
        let read = async {
            let reader = self
                .readers
                .clone()
                .acquire_owned()
                .await
                .expect("the readers' semaphore is never closed");
            let (answer, answered) = tokio::sync::oneshot::channel();
            self.spawn_read(reader, move |table| {
                let _ = answer.send(table);
            })?;
            answered.await.unwrap_or_else(|_| Err(self.unanswered()))
        };
        tokio::time::timeout(READ_TIMEOUT, read)
            .await
            .unwrap_or_else(|_| Err(self.timed_out(READ_TIMEOUT)))
    }

    /// Start [`Self::read_now`] on a thread of its own, which holds `reader`
    /// until the read ends, then hands the result to `answer`. The caller may
    /// have stopped waiting by then; the thread ends all the same.
    fn spawn_read(
        &self,
        reader: OwnedSemaphorePermit,
        answer: impl FnOnce(Result<GraffitiTable, GraffitiFileError>) + Send + 'static,
    ) -> Result<(), GraffitiFileError> {
        let file = self.clone();
        std::thread::Builder::new()
            .name("graffiti-file".to_string())
            .spawn(move || {
                let table = file.read_now();
                drop(reader);
                answer(table);
            })
            .map(drop)
            .map_err(|source| GraffitiFileError::Read {
                path: self.path.display().to_string(),
                source,
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
            source: std::io::Error::other("the read ended without an answer"),
        }
    }
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
        let file = GraffitiFile::open(&path).expect("opens");
        let table = file.read().await.expect("reads");
        assert_eq!(table.graffiti(&key(PK1)), graffiti("mine"));

        std::fs::remove_file(&path).expect("removes");
        let err = file.read().await.expect_err("gone");
        assert!(matches!(err, GraffitiFileError::Read { .. }), "got {err:?}");
    }

    /// With every reader held, as reads of a stalled file hold them, a read
    /// waits for a free one within its timeout and is given up on, with no
    /// thread started for it; once one is free, the file reads again.
    #[tokio::test]
    async fn a_read_with_no_free_reader_is_given_up_on_in_time() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("graffiti.txt");
        std::fs::write(&path, format!("{PK1}: mine\n")).expect("writes");
        let file = GraffitiFile::open(&path).expect("opens");

        let stalled = file
            .readers
            .clone()
            .acquire_many_owned(MAX_READS as u32)
            .await
            .expect("every reader is free once open returns");
        let err = file.read().await.expect_err("no free reader");
        assert!(
            matches!(err, GraffitiFileError::TimedOut { after, .. } if after == READ_TIMEOUT),
            "got {err:?}"
        );

        drop(stalled);
        let table = file.read().await.expect("reads");
        assert_eq!(table.graffiti(&key(PK1)), graffiti("mine"));
    }
}
