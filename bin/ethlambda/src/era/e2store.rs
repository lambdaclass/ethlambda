//! A reader for the e2store container behind `.era` files.
//!
//! An era file is a sequence of records, each an 8-byte header (`type[2]`,
//! `length` u32 little endian, `reserved` u16 that must be zero) followed by
//! `length` bytes. A file holds one group:
//!
//! ```text
//! Version | block* | era-state | other* | slot-index(block)? | slot-index(state)
//! ```
//!
//! Blocks and the state are snappy *framed* SSZ. Neither names its fork, so the
//! caller derives it from the slot. The indices sit at the end of the file and
//! are the only way to a record, so the file is read back to front: the last
//! eight bytes of the final index are its `count`, which gives its start, and
//! every offset in an index is measured from the start of that index's own
//! record (negative, since the data precedes it). A slot with no block is
//! marked in one of two ways: the specification says offset zero, but the files
//! nimbus writes point the entry at byte 0 instead, which is the Version record
//! and never a block. Both are read as empty.
//!
//! Records are read one at a time with a seek, never the whole file: a recent
//! mainnet era is around 800 MB.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use eyre::{WrapErr as _, ensure, eyre};

type Result<T> = eyre::Result<T>;

/// Record types, as the two bytes that appear on disk. Version (`65 32`) and
/// Empty (`00 00`) records are never looked up: records are reached through the
/// indices, which skips them.
pub(crate) const TYPE_BLOCK: [u8; 2] = [0x01, 0x00];
pub(crate) const TYPE_STATE: [u8; 2] = [0x02, 0x00];
pub(crate) const TYPE_SLOT_INDEX: [u8; 2] = [0x69, 0x32];

const HEADER_LEN: u64 = 8;

/// A slot index with more entries than any era could hold is a corrupt tail,
/// not a big file.
const MAX_INDEX_COUNT: u64 = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Header {
    kind: [u8; 2],
    length: u32,
}

/// A `SlotIndex` record: the position of each slot's record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SlotIndex {
    pub(crate) start_slot: u64,
    offsets: Vec<i64>,
    /// File position of the index record's own header, which every offset is
    /// relative to.
    record_start: u64,
}

impl SlotIndex {
    pub(crate) fn count(&self) -> usize {
        self.offsets.len()
    }

    /// File position of the record for `slot`, or `None` if the slot is empty
    /// or outside the index.
    pub(crate) fn position(&self, slot: u64) -> Option<u64> {
        let slot_offset = slot.checked_sub(self.start_slot)?;
        let offset = *self.offsets.get(usize::try_from(slot_offset).ok()?)?;
        if offset == 0 {
            return None;
        }
        // Nimbus marks an empty slot by pointing at the start of the file.
        self.record_start
            .checked_add_signed(offset)
            .filter(|&position| position != 0)
    }

    /// Slots that have a record, in ascending order.
    #[cfg(test)]
    pub(crate) fn present_slots(&self) -> impl Iterator<Item = u64> + '_ {
        (0..self.offsets.len() as u64)
            .map(|i| self.start_slot + i)
            .filter(|&slot| self.position(slot).is_some())
    }
}

/// An open era file with its indices already read.
#[derive(Debug)]
pub(crate) struct EraFile {
    file: File,
    block_index: Option<SlotIndex>,
    state_index: SlotIndex,
}

impl EraFile {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let mut file = File::open(path).wrap_err_with(|| format!("opening {}", path.display()))?;
        let len = file.metadata()?.len();
        Self::from_file(&mut file, len)
            .map(|(block_index, state_index)| Self {
                file,
                block_index,
                state_index,
            })
            .wrap_err_with(|| format!("reading the indices of {}", path.display()))
    }

    fn from_file(file: &mut File, len: u64) -> Result<(Option<SlotIndex>, SlotIndex)> {
        let state_index = read_index_ending_at(file, len)?;
        // An era-0 file has no block index; then the bytes before the state
        // index are the end of a state record, which will not pass as an index.
        let block_index = read_index_ending_at(file, state_index.record_start).ok();
        Ok((block_index, state_index))
    }

    /// The block index: `None` for era 0, which holds a state only.
    pub(crate) fn block_index(&self) -> Option<&SlotIndex> {
        self.block_index.as_ref()
    }

    /// The era's state, decompressed SSZ.
    pub(crate) fn state_bytes(&mut self) -> Result<Vec<u8>> {
        let slot = self.state_index.start_slot;
        let position = self
            .state_index
            .position(slot)
            .ok_or_else(|| eyre!("the state index has no entry for slot {slot}"))?;
        self.read_compressed(position, TYPE_STATE)
    }

    /// The block at `slot`, decompressed SSZ, or `None` for an empty slot.
    pub(crate) fn block_bytes(&mut self, slot: u64) -> Result<Option<Vec<u8>>> {
        let Some(position) = self.block_index.as_ref().and_then(|i| i.position(slot)) else {
            return Ok(None);
        };
        self.read_compressed(position, TYPE_BLOCK).map(Some)
    }

    fn read_compressed(&mut self, position: u64, expected: [u8; 2]) -> Result<Vec<u8>> {
        let header = read_header(&mut self.file, position)?;
        ensure!(
            header.kind == expected,
            "the record at byte {position} has type {:02x?}, expected {expected:02x?}",
            header.kind
        );
        // Positioned just past the header by `read_header`.
        let payload = (&mut self.file).take(u64::from(header.length));
        let mut decoder = snap::read::FrameDecoder::new(payload);
        let mut out = Vec::new();
        decoder
            .read_to_end(&mut out)
            .wrap_err_with(|| format!("decompressing the record at byte {position}"))?;
        Ok(out)
    }
}

fn read_header(file: &mut File, position: u64) -> Result<Header> {
    file.seek(SeekFrom::Start(position))?;
    let mut raw = [0u8; HEADER_LEN as usize];
    file.read_exact(&mut raw)
        .wrap_err_with(|| format!("reading the record header at byte {position}"))?;
    let reserved = u16::from_le_bytes([raw[6], raw[7]]);
    ensure!(
        reserved == 0,
        "the record at byte {position} has a nonzero reserved field"
    );
    Ok(Header {
        kind: [raw[0], raw[1]],
        length: u32::from_le_bytes([raw[2], raw[3], raw[4], raw[5]]),
    })
}

/// Read the slot-index record whose last byte is just before `end`.
fn read_index_ending_at(file: &mut File, end: u64) -> Result<SlotIndex> {
    ensure!(end >= 32, "no room for a slot index before byte {end}");
    file.seek(SeekFrom::Start(end - 8))?;
    let mut raw = [0u8; 8];
    file.read_exact(&mut raw)?;
    let count = i64::from_le_bytes(raw);
    let count = u64::try_from(count)
        .ok()
        .filter(|&c| c <= MAX_INDEX_COUNT)
        .ok_or_else(|| eyre!("implausible slot index count {count} before byte {end}"))?;

    // header (8) + start slot (8) + count offsets + count (8)
    let record_len = count * 8 + 24;
    let record_start = end
        .checked_sub(record_len)
        .ok_or_else(|| eyre!("a slot index of {count} entries does not fit before byte {end}"))?;
    let header = read_header(file, record_start)?;
    ensure!(
        header.kind == TYPE_SLOT_INDEX && u64::from(header.length) == record_len - HEADER_LEN,
        "no slot index of {count} entries at byte {record_start}"
    );

    let mut data = vec![0u8; (record_len - HEADER_LEN) as usize];
    file.read_exact(&mut data)?;
    let start_slot = u64::from_le_bytes(data[..8].try_into().expect("8 bytes"));
    let offsets = data[8..8 + count as usize * 8]
        .chunks_exact(8)
        .map(|c| i64::from_le_bytes(c.try_into().expect("8 bytes")))
        .collect();
    Ok(SlotIndex {
        start_slot,
        offsets,
        record_start,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::Write;

    use super::*;

    const TYPE_VERSION: [u8; 2] = [0x65, 0x32];

    pub(crate) fn record(kind: [u8; 2], data: &[u8]) -> Vec<u8> {
        let mut out = kind.to_vec();
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(data);
        out
    }

    pub(crate) fn framed(payload: &[u8]) -> Vec<u8> {
        let mut encoder = snap::write::FrameEncoder::new(Vec::new());
        encoder.write_all(payload).unwrap();
        encoder.into_inner().unwrap()
    }

    fn index_record(start_slot: u64, offsets: &[i64]) -> Vec<u8> {
        let mut data = start_slot.to_le_bytes().to_vec();
        for offset in offsets {
            data.extend_from_slice(&offset.to_le_bytes());
        }
        data.extend_from_slice(&(offsets.len() as i64).to_le_bytes());
        record(TYPE_SLOT_INDEX, &data)
    }

    /// Build an era-shaped file: `blocks` is `(slot, ssz)` within
    /// `[start_slot, start_slot + count)`; every other slot is empty.
    pub(crate) fn synthetic_file(
        start_slot: u64,
        count: u64,
        blocks: &[(u64, Vec<u8>)],
        state: &[u8],
        with_block_index: bool,
    ) -> Vec<u8> {
        let mut file = record(TYPE_VERSION, &[]);
        let mut positions = vec![None; count as usize];
        for (slot, ssz) in blocks {
            positions[(slot - start_slot) as usize] = Some(file.len() as i64);
            file.extend(record(TYPE_BLOCK, &framed(ssz)));
        }
        let state_pos = file.len() as i64;
        file.extend(record(TYPE_STATE, &framed(state)));
        // An unrelated record between the state and the indices.
        file.extend(record([0x07, 0x07], b"other"));

        if with_block_index {
            let index_start = file.len() as i64;
            // Even slots are marked empty the way the spec says (offset 0), odd
            // ones the way nimbus writes them (a pointer to byte 0).
            let offsets: Vec<i64> = positions
                .iter()
                .enumerate()
                .map(|(i, p)| match p {
                    Some(pos) => pos - index_start,
                    None if i % 2 == 0 => 0,
                    None => -index_start,
                })
                .collect();
            file.extend(index_record(start_slot, &offsets));
        }
        let state_index_start = file.len() as i64;
        file.extend(index_record(
            start_slot + count,
            &[state_pos - state_index_start],
        ));
        file
    }

    fn write(bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("synthetic.era");
        std::fs::write(&path, bytes).unwrap();
        (dir, path)
    }

    #[test]
    fn header_fields_are_little_endian_and_reserved_is_checked() {
        let bytes = record(TYPE_BLOCK, b"abc");
        assert_eq!(&bytes[..8], &[0x01, 0x00, 3, 0, 0, 0, 0, 0]);

        let mut bad = bytes.clone();
        bad[6] = 1;
        let (_dir, path) = write(&bad);
        let mut file = File::open(path).unwrap();
        assert!(read_header(&mut file, 0).is_err());
    }

    #[test]
    fn framed_payloads_round_trip() {
        let block = vec![7u8; 100_000];
        let bytes = synthetic_file(16, 4, &[(17, block.clone())], b"state-bytes", true);
        let (_dir, path) = write(&bytes);
        let mut era = EraFile::open(&path).unwrap();
        assert_eq!(era.block_bytes(17).unwrap().unwrap(), block);
        assert_eq!(era.state_bytes().unwrap(), b"state-bytes");
    }

    #[test]
    fn empty_slots_have_no_record() {
        let blocks = vec![(16, b"first".to_vec()), (19, b"last".to_vec())];
        let bytes = synthetic_file(16, 4, &blocks, b"s", true);
        let (_dir, path) = write(&bytes);
        let mut era = EraFile::open(&path).unwrap();

        let index = era.block_index().unwrap();
        assert_eq!(index.start_slot, 16);
        assert_eq!(index.count(), 4);
        assert_eq!(index.present_slots().collect::<Vec<_>>(), vec![16, 19]);

        assert_eq!(era.block_bytes(17).unwrap(), None);
        assert_eq!(era.block_bytes(18).unwrap(), None);
        assert_eq!(era.block_bytes(99).unwrap(), None);
        assert_eq!(era.block_bytes(19).unwrap().unwrap(), b"last");
    }

    #[test]
    fn the_file_is_read_from_the_back() {
        // The state index's start slot is the era's end slot, and offsets are
        // negative: the data precedes the index.
        let bytes = synthetic_file(8, 2, &[(9, b"b".to_vec())], b"st", true);
        let (_dir, path) = write(&bytes);
        let era = EraFile::open(&path).unwrap();
        assert_eq!(era.state_index.start_slot, 10);
        assert_eq!(era.state_index.count(), 1);
        assert!(era.state_index.offsets[0] < 0);
        assert!(era.block_index().unwrap().offsets[1] < 0);
    }

    #[test]
    fn a_file_without_a_block_index_is_an_era_zero_shaped_one() {
        let bytes = synthetic_file(0, 8192, &[], b"genesis", false);
        let (_dir, path) = write(&bytes);
        let mut era = EraFile::open(&path).unwrap();
        assert!(era.block_index().is_none());
        assert_eq!(era.state_bytes().unwrap(), b"genesis");
    }

    #[test]
    fn a_truncated_file_is_an_error() {
        let bytes = synthetic_file(0, 2, &[], b"s", true);
        let (_dir, path) = write(&bytes[..bytes.len() - 5]);
        assert!(EraFile::open(&path).is_err());
    }
}
