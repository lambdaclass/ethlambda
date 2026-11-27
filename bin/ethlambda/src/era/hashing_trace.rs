//! The state-hashing trace: what replaying real blocks wrote to the five
//! validator-indexed lists of a beacon state, step by step, with each list's
//! root after every step.
//!
//! `replay-era --hashing-trace` writes one (see `hashing_record.rs`), and
//! `tooling/state-hashing-bench` reads it back to replay the same writes
//! through different Merkle-tree libraries. That tool includes this file by
//! path, so it uses nothing beyond `std` and `snap`.
//!
//! # What a step holds
//!
//! A replay alternates two kinds of step: the epoch processing that
//! `process_slots` runs at an epoch boundary, and one block's
//! `process_block`. For each list a step records its new length and the
//! `(index, value)` of every element that changed, plus every element appended
//! past the old length, in index order. The roots are the lists' own
//! `hash_tree_root`s after the step, taken from the replayed state, whose
//! full root the replay has just checked against the block's `state_root`
//! (or, after an epoch step, will check at the next block).
//!
//! Epoch processing rotates the participation lists rather than writing
//! them: previous becomes current, and current becomes all zeros. A diff
//! would show that as most of a million writes per list, which no client
//! performs, so it is recorded as an operation, [`Step::rotation`], and the
//! participation writes of that step are what remains after it.
//!
//! # Layout
//!
//! One snappy frame stream (the framing `.era` records use), little endian:
//!
//! ```text
//! magic[8] | header | lists | roots | step* | 0u8
//! header = string network | string fork | u64 slot
//! string = u16 len | len bytes of UTF-8
//! lists  = 5 × (u32 len | len × value), in LIST_NAMES order
//! roots  = 5 × 32 bytes, in LIST_NAMES order
//! step   = u8 kind (1 epoch, 2 block) | u64 slot | u32 rotation (0 = none)
//!          | 5 × writes | roots
//! writes = u32 len | u32 count | count × u32 index | count × value
//! value  = 121-byte SSZ validator | u64 balance | u8 flags | u8 flags | u64 score
//! ```
//!
//! The trailing zero byte marks a complete trace, so one cut short by a
//! killed recorder fails to read rather than looking like a shorter run.

// Each crate that includes this file uses one half of it: the node writes,
// the bench reads. The round-trip test below covers both halves here.
#![allow(dead_code)]

use std::io::{self, Read, Write};

/// Identifies the format and its version.
pub const MAGIC: [u8; 8] = *b"ETHLHT01";

/// Bytes in a `Validator`'s SSZ encoding: pubkey 48, withdrawal credentials
/// 32, effective balance 8, slashed 1, four epochs at 8 each.
pub const VALIDATOR_LEN: usize = 121;

pub type ValidatorBytes = [u8; VALIDATOR_LEN];

/// A 32-byte Merkle root.
pub type Root = [u8; 32];

/// The lists a trace covers, in the order every section of it lists them.
pub const LIST_NAMES: [&str; 5] = [
    "validators",
    "balances",
    "previous_epoch_participation",
    "current_epoch_participation",
    "inactivity_scores",
];

const STEP_END: u8 = 0;
const STEP_EPOCH: u8 = 1;
const STEP_BLOCK: u8 = 2;

/// An element type a trace stores, with its fixed encoded size.
pub trait TraceValue: Copy {
    const SIZE: usize;
    fn put(&self, out: &mut Vec<u8>);
    fn get(bytes: &[u8]) -> Self;
}

impl TraceValue for u8 {
    const SIZE: usize = 1;
    fn put(&self, out: &mut Vec<u8>) {
        out.push(*self);
    }
    fn get(bytes: &[u8]) -> Self {
        bytes[0]
    }
}

impl TraceValue for u32 {
    const SIZE: usize = 4;
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_le_bytes());
    }
    fn get(bytes: &[u8]) -> Self {
        u32::from_le_bytes(bytes.try_into().expect("four bytes"))
    }
}

impl TraceValue for u64 {
    const SIZE: usize = 8;
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_le_bytes());
    }
    fn get(bytes: &[u8]) -> Self {
        u64::from_le_bytes(bytes.try_into().expect("eight bytes"))
    }
}

impl TraceValue for ValidatorBytes {
    const SIZE: usize = VALIDATOR_LEN;
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
    fn get(bytes: &[u8]) -> Self {
        bytes.try_into().expect("one validator")
    }
}

/// The five lists in full, as the trace's starting point.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lists {
    pub validators: Vec<ValidatorBytes>,
    pub balances: Vec<u64>,
    pub previous_participation: Vec<u8>,
    pub current_participation: Vec<u8>,
    pub inactivity_scores: Vec<u64>,
}

/// Each list's `hash_tree_root`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Roots {
    pub validators: Root,
    pub balances: Root,
    pub previous_participation: Root,
    pub current_participation: Root,
    pub inactivity_scores: Root,
}

impl Roots {
    /// In [`LIST_NAMES`] order.
    pub fn as_array(&self) -> [Root; 5] {
        [
            self.validators,
            self.balances,
            self.previous_participation,
            self.current_participation,
            self.inactivity_scores,
        ]
    }
}

/// What one step wrote to one list: its length afterwards, and every changed
/// or appended element in index order. An index at or past the list's length
/// before the step is an append.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Writes<T> {
    pub len: u32,
    pub indices: Vec<u32>,
    pub values: Vec<T>,
}

impl<T> Writes<T> {
    pub fn count(&self) -> usize {
        self.indices.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepKind {
    /// The epoch processing run on the way into `slot`'s epoch.
    Epoch,
    /// The block at `slot`.
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub kind: StepKind,
    pub slot: u64,
    /// `Some(n)` when the step rotates the participation lists: current is
    /// first extended with zero flags to `n` entries, then previous becomes
    /// current and current becomes `n` zeros. The step's participation writes
    /// apply after that.
    pub rotation: Option<u32>,
    pub validators: Writes<ValidatorBytes>,
    pub balances: Writes<u64>,
    pub previous_participation: Writes<u8>,
    pub current_participation: Writes<u8>,
    pub inactivity_scores: Writes<u64>,
    pub roots: Roots,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub network: String,
    /// The fork of the starting state, e.g. `Fulu`.
    pub fork: String,
    /// The starting state's slot.
    pub slot: u64,
}

pub struct TraceWriter<W: Write> {
    out: snap::write::FrameEncoder<W>,
    buf: Vec<u8>,
}

impl<W: Write> TraceWriter<W> {
    /// Starts a trace with its header and the lists it starts from.
    pub fn new(inner: W, header: &Header, lists: &Lists, roots: &Roots) -> io::Result<Self> {
        let mut writer = Self {
            out: snap::write::FrameEncoder::new(inner),
            buf: Vec::new(),
        };
        writer.out.write_all(&MAGIC)?;
        writer.put_str(&header.network)?;
        writer.put_str(&header.fork)?;
        writer.out.write_all(&header.slot.to_le_bytes())?;
        writer.put_list(&lists.validators)?;
        writer.put_list(&lists.balances)?;
        writer.put_list(&lists.previous_participation)?;
        writer.put_list(&lists.current_participation)?;
        writer.put_list(&lists.inactivity_scores)?;
        writer.put_roots(roots)?;
        Ok(writer)
    }

    pub fn step(&mut self, step: &Step) -> io::Result<()> {
        let kind = match step.kind {
            StepKind::Epoch => STEP_EPOCH,
            StepKind::Block => STEP_BLOCK,
        };
        self.out.write_all(&[kind])?;
        self.out.write_all(&step.slot.to_le_bytes())?;
        self.out
            .write_all(&step.rotation.unwrap_or(0).to_le_bytes())?;
        self.put_writes(&step.validators)?;
        self.put_writes(&step.balances)?;
        self.put_writes(&step.previous_participation)?;
        self.put_writes(&step.current_participation)?;
        self.put_writes(&step.inactivity_scores)?;
        self.put_roots(&step.roots)
    }

    /// Marks the trace complete and returns the underlying writer, flushed.
    pub fn finish(mut self) -> io::Result<W> {
        self.out.write_all(&[STEP_END])?;
        self.out.flush()?;
        self.out
            .into_inner()
            .map_err(|err| io::Error::other(err.to_string()))
    }

    fn put_str(&mut self, value: &str) -> io::Result<()> {
        let len = u16::try_from(value.len()).map_err(io::Error::other)?;
        self.out.write_all(&len.to_le_bytes())?;
        self.out.write_all(value.as_bytes())
    }

    fn put_len(&mut self, len: usize) -> io::Result<()> {
        let len = u32::try_from(len).map_err(io::Error::other)?;
        self.out.write_all(&len.to_le_bytes())
    }

    fn put_values<T: TraceValue>(&mut self, values: &[T]) -> io::Result<()> {
        // In bounded pieces: a mainnet registry is a few hundred megabytes.
        for piece in values.chunks(1 << 16) {
            self.buf.clear();
            for value in piece {
                value.put(&mut self.buf);
            }
            self.out.write_all(&self.buf)?;
        }
        Ok(())
    }

    fn put_list<T: TraceValue>(&mut self, values: &[T]) -> io::Result<()> {
        self.put_len(values.len())?;
        self.put_values(values)
    }

    fn put_writes<T: TraceValue>(&mut self, writes: &Writes<T>) -> io::Result<()> {
        assert_eq!(
            writes.indices.len(),
            writes.values.len(),
            "one value per index"
        );
        self.out.write_all(&writes.len.to_le_bytes())?;
        self.put_len(writes.indices.len())?;
        self.put_values(&writes.indices)?;
        self.put_values(&writes.values)
    }

    fn put_roots(&mut self, roots: &Roots) -> io::Result<()> {
        for root in roots.as_array() {
            self.out.write_all(&root)?;
        }
        Ok(())
    }
}

pub struct TraceReader<R: Read> {
    input: snap::read::FrameDecoder<R>,
    pub header: Header,
}

impl<R: Read> TraceReader<R> {
    /// Reads the header and the starting lists; the steps follow through
    /// [`Self::next_step`].
    pub fn new(inner: R) -> io::Result<(Self, Lists, Roots)> {
        let mut input = snap::read::FrameDecoder::new(inner);
        let mut magic = [0; 8];
        input.read_exact(&mut magic)?;
        if magic != MAGIC {
            return Err(invalid(format!(
                "not a state-hashing trace, or another version of one: magic {magic:?}"
            )));
        }
        let network = get_str(&mut input)?;
        let fork = get_str(&mut input)?;
        let slot = get_u64(&mut input)?;
        let lists = Lists {
            validators: get_list(&mut input)?,
            balances: get_list(&mut input)?,
            previous_participation: get_list(&mut input)?,
            current_participation: get_list(&mut input)?,
            inactivity_scores: get_list(&mut input)?,
        };
        let roots = get_roots(&mut input)?;
        let header = Header {
            network,
            fork,
            slot,
        };
        Ok((Self { input, header }, lists, roots))
    }

    /// The next step, or `None` at the end marker. A stream that stops before
    /// it is an error.
    pub fn next_step(&mut self) -> io::Result<Option<Step>> {
        let mut kind = [0];
        self.input.read_exact(&mut kind).map_err(|err| {
            if err.kind() == io::ErrorKind::UnexpectedEof {
                invalid("the trace ends without its end marker: was the recorder stopped?")
            } else {
                err
            }
        })?;
        let kind = match kind[0] {
            STEP_END => return Ok(None),
            STEP_EPOCH => StepKind::Epoch,
            STEP_BLOCK => StepKind::Block,
            other => return Err(invalid(format!("unknown step kind {other}"))),
        };
        let input = &mut self.input;
        let slot = get_u64(input)?;
        let rotation = get_u32(input)?;
        Ok(Some(Step {
            kind,
            slot,
            rotation: (rotation != 0).then_some(rotation),
            validators: get_writes(input)?,
            balances: get_writes(input)?,
            previous_participation: get_writes(input)?,
            current_participation: get_writes(input)?,
            inactivity_scores: get_writes(input)?,
            roots: get_roots(input)?,
        }))
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn get_u32(input: &mut impl Read) -> io::Result<u32> {
    let mut bytes = [0; 4];
    input.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn get_u64(input: &mut impl Read) -> io::Result<u64> {
    let mut bytes = [0; 8];
    input.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn get_str(input: &mut impl Read) -> io::Result<String> {
    let mut len = [0; 2];
    input.read_exact(&mut len)?;
    let mut bytes = vec![0; u16::from_le_bytes(len) as usize];
    input.read_exact(&mut bytes)?;
    String::from_utf8(bytes).map_err(|err| invalid(err.to_string()))
}

fn get_values<T: TraceValue>(input: &mut impl Read, count: usize) -> io::Result<Vec<T>> {
    let mut values = Vec::with_capacity(count);
    let mut buf = Vec::new();
    let mut left = count;
    while left > 0 {
        let piece = left.min(1 << 16);
        buf.resize(piece * T::SIZE, 0);
        input.read_exact(&mut buf)?;
        values.extend(buf.chunks_exact(T::SIZE).map(T::get));
        left -= piece;
    }
    Ok(values)
}

fn get_list<T: TraceValue>(input: &mut impl Read) -> io::Result<Vec<T>> {
    let len = get_u32(input)? as usize;
    get_values(input, len)
}

fn get_writes<T: TraceValue>(input: &mut impl Read) -> io::Result<Writes<T>> {
    let len = get_u32(input)?;
    let count = get_u32(input)? as usize;
    let indices = get_values(input, count)?;
    let values = get_values(input, count)?;
    Ok(Writes {
        len,
        indices,
        values,
    })
}

fn get_roots(input: &mut impl Read) -> io::Result<Roots> {
    let mut roots = [[0; 32]; 5];
    for root in &mut roots {
        input.read_exact(root)?;
    }
    let [
        validators,
        balances,
        previous_participation,
        current_participation,
        inactivity_scores,
    ] = roots;
    Ok(Roots {
        validators,
        balances,
        previous_participation,
        current_participation,
        inactivity_scores,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_step(kind: StepKind, slot: u64) -> Step {
        Step {
            kind,
            slot,
            rotation: (kind == StepKind::Epoch).then_some(3),
            validators: Writes {
                len: 3,
                indices: vec![2],
                values: vec![[7; VALIDATOR_LEN]],
            },
            balances: Writes {
                len: 3,
                indices: vec![0, 2],
                values: vec![31, 33],
            },
            previous_participation: Writes::default(),
            current_participation: Writes {
                len: 3,
                indices: vec![1],
                values: vec![7],
            },
            inactivity_scores: Writes {
                len: 3,
                indices: vec![],
                values: vec![],
            },
            roots: Roots {
                balances: [9; 32],
                ..Roots::default()
            },
        }
    }

    #[test]
    fn a_trace_reads_back_as_written() {
        let header = Header {
            network: "mainnet".into(),
            fork: "Fulu".into(),
            slot: 64,
        };
        let lists = Lists {
            validators: vec![[1; VALIDATOR_LEN], [2; VALIDATOR_LEN]],
            balances: vec![32, 32],
            previous_participation: vec![7, 0],
            current_participation: vec![3, 1],
            inactivity_scores: vec![0, 4],
        };
        let roots = Roots {
            validators: [5; 32],
            ..Roots::default()
        };
        let steps = [
            sample_step(StepKind::Epoch, 96),
            sample_step(StepKind::Block, 97),
        ];

        let mut writer = TraceWriter::new(Vec::new(), &header, &lists, &roots).unwrap();
        for step in &steps {
            writer.step(step).unwrap();
        }
        let bytes = writer.finish().unwrap();

        let (mut reader, read_lists, read_roots) = TraceReader::new(&bytes[..]).unwrap();
        assert_eq!(reader.header, header);
        assert_eq!(read_lists, lists);
        assert_eq!(read_roots, roots);
        for step in &steps {
            assert_eq!(reader.next_step().unwrap().as_ref(), Some(step));
        }
        assert_eq!(reader.next_step().unwrap(), None);
    }

    #[test]
    fn a_trace_without_its_end_marker_is_an_error() {
        let header = Header {
            network: "mainnet".into(),
            fork: "Fulu".into(),
            slot: 0,
        };
        let mut writer =
            TraceWriter::new(Vec::new(), &header, &Lists::default(), &Roots::default()).unwrap();
        writer.step(&sample_step(StepKind::Block, 1)).unwrap();
        // Flush without the end marker, as a killed recorder would leave it.
        writer.out.flush().unwrap();
        let bytes = writer.out.into_inner().unwrap();

        let (mut reader, _, _) = TraceReader::new(&bytes[..]).unwrap();
        assert!(reader.next_step().unwrap().is_some());
        let err = reader.next_step().unwrap_err();
        assert!(err.to_string().contains("end marker"), "{err}");
    }
}
