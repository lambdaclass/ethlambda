//! The chunks a PQ aggregate's [`AttestationProof`] is broadcast in over
//! Waggle, from the "Fast leanVM Proof Broadcast" draft EIP
//! (<https://notes.ethereum.org/@kamilsa/rk_I4TMJme>), as Lighthouse's
//! `pq-devnet-0-waggle` image implements it (`kamilsa/lighthouse`,
//! `leanvm-proof-broadcast`, `consensus/types/src/pq/proof_chunk.rs`).
//!
//! The serialized proof is split into [`TOTAL_PROOF_CHUNKS`] contiguous
//! chunks. The leaves of a depth-[`PROOF_CHUNK_INCLUSION_PROOF_DEPTH`] Merkle
//! tree are the chunks' plain SHA-256 hashes (not their `hash_tree_root`), and
//! its root, the `proof_chunks_root` of the [`AggregateHeader`] the aggregator
//! signs, is therefore the `hash_tree_root` of those hashes as a
//! `Vector[Bytes32, TOTAL_PROOF_CHUNKS]`. Each [`ProofChunk`] carries its
//! branch, so a peer can check and forward a chunk before it holds the rest.
//!
//! There is no erasure coding: every chunk is needed.

use libssz_derive::{SszDecode, SszEncode};
use libssz_types::{SszBitvector, SszList, SszVector};
use sha2::{Digest as _, Sha256};

use super::pq::{AggregateHeader, AttestationProof, SignedAggregateHeader};
use crate::beacon::preset;
use crate::beacon::primitives::{Root, Slot, ValidatorIndex};

/// How many chunks every proof is split into.
pub const TOTAL_PROOF_CHUNKS: usize = 64;

/// The depth of the tree over the chunks: `2 ** depth` is
/// [`TOTAL_PROOF_CHUNKS`], so the tree is full and needs no padding leaves.
pub const PROOF_CHUNK_INCLUSION_PROOF_DEPTH: usize = 6;

/// The longest chunk: `MAX_STARK_PROOF_SIZE / TOTAL_PROOF_CHUNKS`.
pub const MAX_PROOF_CHUNK_SIZE: usize = 16_384;

const _: () = assert!(1 << PROOF_CHUNK_INCLUSION_PROOF_DEPTH == TOTAL_PROOF_CHUNKS);
const _: () = assert!(preset::MAX_STARK_PROOF_SIZE / TOTAL_PROOF_CHUNKS == MAX_PROOF_CHUNK_SIZE);

/// The bytes of one chunk (the spec's `Chunk`).
pub type ProofChunkBytes = SszList<u8, MAX_PROOF_CHUNK_SIZE>;

/// One bit per chunk of a proof.
pub type ProofChunkBitmap = SszBitvector<TOTAL_PROOF_CHUNKS>;

/// A chunk's sibling hashes, leaf level first.
pub type ProofChunkInclusionProof = SszVector<Root, PROOF_CHUNK_INCLUSION_PROOF_DEPTH>;

/// A chunk of a proof, with its index (below [`TOTAL_PROOF_CHUNKS`]) and its
/// branch to the `proof_chunks_root` of its aggregate's header.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
pub struct ProofChunk {
    pub index: u8,
    pub chunk: ProofChunkBytes,
    pub chunk_inclusion_proof: ProofChunkInclusionProof,
}

/// What a node tells a peer about one aggregate's chunks: `have`, the chunks
/// it holds (and validated), and `request`, the ones it asks the peer for.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
pub struct ProofChunkMetadata {
    pub have: ProofChunkBitmap,
    pub request: ProofChunkBitmap,
}

/// An aggregate's name on the wire (Waggle's `objectID`): its attestation
/// data's slot, its aggregator, and its header's `hash_tree_root`. 48 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, SszEncode, SszDecode)]
pub struct AggregateId {
    pub slot: Slot,
    pub aggregator_index: ValidatorIndex,
    pub header_root: Root,
}

/// One chunk of an aggregate's proof as sent to a peer, with the signed
/// header when the peer is not known to hold it yet (`signed_header` holds at
/// most one).
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
pub struct AggregatePiece {
    pub signed_header: SszList<SignedAggregateHeader, 1>,
    pub chunk: ProofChunk,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProofChunkError {
    /// The proof does not fit [`TOTAL_PROOF_CHUNKS`] chunks of
    /// [`MAX_PROOF_CHUNK_SIZE`] bytes.
    #[error("a proof of {0} bytes does not fit {TOTAL_PROOF_CHUNKS} chunks")]
    ProofTooLarge(usize),
    /// The chunks are not the ones [`compute_proof_chunks`] splits a proof
    /// into: too few or too many, or of other lengths.
    #[error("the chunks are not a proof's canonical split")]
    NonCanonicalChunks,
}

/// Spec `compute_proof_chunks`: the proof's bytes in [`TOTAL_PROOF_CHUNKS`]
/// contiguous chunks of `ceil(len / TOTAL_PROOF_CHUNKS)` bytes. Nothing is
/// padded: the last non-empty chunk can be shorter, and trailing chunks empty.
pub fn compute_proof_chunks(
    proof: &AttestationProof,
) -> Result<Vec<ProofChunkBytes>, ProofChunkError> {
    split_into_chunks(proof)
}

/// Spec `compute_proof_chunks_root`: the root the aggregator's header commits
/// to.
pub fn compute_proof_chunks_root(proof: &AttestationProof) -> Result<Root, ProofChunkError> {
    let chunks = compute_proof_chunks(proof)?;
    Ok(ChunksTree::new(&chunks).root())
}

/// The [`ProofChunk`]s broadcasting `proof`, one per index, and the
/// `proof_chunks_root` their branches verify against.
pub fn build_proof_chunks(
    proof: &AttestationProof,
) -> Result<(Vec<ProofChunk>, Root), ProofChunkError> {
    let chunks = compute_proof_chunks(proof)?;
    let tree = ChunksTree::new(&chunks);
    let proof_chunks = chunks
        .into_iter()
        .enumerate()
        .map(|(index, chunk)| ProofChunk {
            index: index as u8,
            chunk,
            chunk_inclusion_proof: tree.branch(index),
        })
        .collect();
    Ok((proof_chunks, tree.root()))
}

impl ProofChunk {
    /// Spec `verify_proof_chunk_inclusion_proof`. An index of
    /// [`TOTAL_PROOF_CHUNKS`] or more never verifies, so the caller needs not
    /// check it first.
    pub fn verify_inclusion_proof(&self, proof_chunks_root: Root) -> bool {
        let index = usize::from(self.index);
        if index >= TOTAL_PROOF_CHUNKS {
            return false;
        }
        let mut node = sha256(&self.chunk);
        for (level, sibling) in self.chunk_inclusion_proof.iter().enumerate() {
            node = if (index >> level) & 1 == 1 {
                hash_pair(sibling, &node)
            } else {
                hash_pair(&node, sibling)
            };
        }
        node == proof_chunks_root
    }

    /// The SSZ length of a chunk of [`MAX_PROOF_CHUNK_SIZE`] bytes, the
    /// longest a valid one encodes to: the index, the chunk's offset, the
    /// branch, and the bytes.
    pub const fn max_ssz_len() -> usize {
        1 + 4 + 32 * PROOF_CHUNK_INCLUSION_PROOF_DEPTH + MAX_PROOF_CHUNK_SIZE
    }
}

/// The SSZ length of the largest [`SignedAggregateHeader`]: the largest
/// `SignedAggregateAndProof`, with the 32-byte root where the proof's 4-byte
/// offset and `MAX_STARK_PROOF_SIZE` bytes were. 6,683 bytes on mainnet, as
/// the EIP states.
pub fn max_signed_aggregate_header_size() -> usize {
    preset::max_signed_aggregate_and_proof_size_pq() - preset::MAX_STARK_PROOF_SIZE - 4 + 32
}

impl AggregatePiece {
    /// The SSZ length of the largest valid piece (the spec's
    /// `max_piece_length`): the offsets of both fields and of the header in
    /// its list, the largest header, and the longest chunk. 23,276 bytes on
    /// mainnet.
    pub fn max_ssz_len() -> usize {
        3 * 4 + max_signed_aggregate_header_size() + ProofChunk::max_ssz_len()
    }

    /// The header carried with the chunk, if any.
    pub fn header(&self) -> Option<&SignedAggregateHeader> {
        self.signed_header.first()
    }
}

impl AggregateId {
    /// The id of the aggregate `header` names.
    pub fn of(header: &AggregateHeader) -> Self {
        use crate::primitives::HashTreeRoot as _;
        Self {
            slot: header.aggregate.data.slot,
            aggregator_index: header.aggregator_index,
            header_root: header.hash_tree_root(),
        }
    }
}

/// Reassembles a proof from all of its chunks, in index order.
///
/// Succeeds only for the split [`compute_proof_chunks`] makes. Valid branches
/// alone do not say so: an aggregator can commit to another split of the same
/// bytes, and accepting it would give one proof two sets of valid chunks. So
/// when every chunk verified against a root and this succeeds, that root is
/// the proof's `compute_proof_chunks_root`, without computing it.
pub fn proof_from_chunks<'a>(
    chunks: impl IntoIterator<Item = &'a ProofChunkBytes>,
) -> Result<AttestationProof, ProofChunkError> {
    let chunks: Vec<&ProofChunkBytes> = chunks.into_iter().collect();
    if chunks.len() != TOTAL_PROOF_CHUNKS {
        return Err(ProofChunkError::NonCanonicalChunks);
    }
    let len: usize = chunks.iter().map(|chunk| chunk.len()).sum();
    let chunk_size = len.div_ceil(TOTAL_PROOF_CHUNKS);
    let mut bytes = Vec::with_capacity(len);
    for chunk in chunks {
        let expected = chunk_size.min(len - bytes.len());
        if chunk.len() != expected {
            return Err(ProofChunkError::NonCanonicalChunks);
        }
        bytes.extend_from_slice(chunk);
    }
    AttestationProof::try_from(bytes).map_err(|_| ProofChunkError::ProofTooLarge(len))
}

fn split_into_chunks(bytes: &[u8]) -> Result<Vec<ProofChunkBytes>, ProofChunkError> {
    let chunk_size = bytes.len().div_ceil(TOTAL_PROOF_CHUNKS);
    if chunk_size > MAX_PROOF_CHUNK_SIZE {
        return Err(ProofChunkError::ProofTooLarge(bytes.len()));
    }
    let chunks = (0..TOTAL_PROOF_CHUNKS)
        .map(|index| {
            let start = (index * chunk_size).min(bytes.len());
            let end = (start + chunk_size).min(bytes.len());
            ProofChunkBytes::try_from(bytes[start..end].to_vec())
                .expect("a chunk is at most MAX_PROOF_CHUNK_SIZE bytes")
        })
        .collect();
    Ok(chunks)
}

/// The full binary tree over the chunks' hashes, every level kept so each
/// chunk's branch can be read off it.
struct ChunksTree {
    /// `levels[0]` holds the leaves, the last level the root alone.
    levels: Vec<Vec<Root>>,
}

impl ChunksTree {
    fn new(chunks: &[ProofChunkBytes]) -> Self {
        let leaves: Vec<Root> = chunks.iter().map(|chunk| sha256(chunk)).collect();
        let mut levels = vec![leaves];
        for _ in 0..PROOF_CHUNK_INCLUSION_PROOF_DEPTH {
            let below = levels.last().expect("the leaves are a level");
            let above = below
                .chunks_exact(2)
                .map(|pair| hash_pair(&pair[0], &pair[1]))
                .collect();
            levels.push(above);
        }
        Self { levels }
    }

    fn root(&self) -> Root {
        self.levels[PROOF_CHUNK_INCLUSION_PROOF_DEPTH][0]
    }

    fn branch(&self, index: usize) -> ProofChunkInclusionProof {
        let siblings: Vec<Root> = (0..PROOF_CHUNK_INCLUSION_PROOF_DEPTH)
            .map(|level| self.levels[level][(index >> level) ^ 1])
            .collect();
        ProofChunkInclusionProof::try_from(siblings).expect("one sibling per level")
    }
}

fn sha256(bytes: &[u8]) -> Root {
    crate::primitives::H256(Sha256::digest(bytes).into())
}

fn hash_pair(left: &Root, right: &Root) -> Root {
    let mut hasher = Sha256::new();
    hasher.update(left.0);
    hasher.update(right.0);
    crate::primitives::H256(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use libssz::{SszDecode as _, SszEncode as _};
    use libssz_types::ProgressiveBitlist;

    use super::super::pq::Attestation;
    use super::*;
    use crate::beacon::preset::Preset;
    use crate::primitives::HashTreeRoot as _;

    /// A proof of `len` bytes that vary, so no two chunks are equal.
    fn proof(len: usize) -> AttestationProof {
        AttestationProof::try_from((0..len).map(|i| (i % 251) as u8).collect::<Vec<_>>())
            .expect("within MAX_STARK_PROOF_SIZE")
    }

    fn signed_header(attesters: usize) -> SignedAggregateHeader {
        SignedAggregateHeader {
            message: AggregateHeader {
                aggregator_index: 7,
                aggregate: Attestation {
                    aggregation_bits: ProgressiveBitlist::with_length(attesters),
                    data: Default::default(),
                    committee_bits: Default::default(),
                },
                proof_chunks_root: Root::repeat_byte(3),
            },
            signature: Default::default(),
        }
    }

    fn no_branch() -> ProofChunkInclusionProof {
        vec![Root::ZERO; PROOF_CHUNK_INCLUSION_PROOF_DEPTH]
            .try_into()
            .unwrap()
    }

    fn max_attesters() -> usize {
        preset::MAX_VALIDATORS_PER_COMMITTEE * preset::max_committees_per_slot_pq()
    }

    #[test]
    fn chunks_concatenate_to_the_proof() {
        for len in [0, 1, 63, 64, 65, 200_000, preset::MAX_STARK_PROOF_SIZE] {
            let proof = proof(len);
            let chunks = compute_proof_chunks(&proof).unwrap();
            assert_eq!(chunks.len(), TOTAL_PROOF_CHUNKS);
            let chunk_size = len.div_ceil(TOTAL_PROOF_CHUNKS);
            assert!(chunks.iter().all(|chunk| chunk.len() <= chunk_size));
            let joined: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
            assert_eq!(joined, proof.to_vec());
            assert_eq!(proof_from_chunks(&chunks).unwrap(), proof);
        }
    }

    /// The EIP's example: a 200,000-byte proof is 64 chunks of 3,125 bytes.
    #[test]
    fn the_eip_example_proof_splits_into_3125_byte_chunks() {
        let chunks = compute_proof_chunks(&proof(200_000)).unwrap();
        assert!(chunks.iter().all(|chunk| chunk.len() == 3_125));
    }

    #[test]
    fn chunks_are_unpadded() {
        let total = TOTAL_PROOF_CHUNKS;
        // (length, chunk size, non-empty chunks)
        for (len, chunk_size, non_empty) in [
            (0, 0, 0),
            (1, 1, 1),
            (total - 1, 1, total - 1),
            (total, 1, total),
            (total + 1, 2, total / 2 + 1),
            (10 * total + 3, 11, (10 * total + 3).div_ceil(11)),
        ] {
            let bytes: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let chunks = split_into_chunks(&bytes).unwrap();
            for (index, chunk) in chunks.iter().enumerate() {
                let start = (index * chunk_size).min(len);
                let end = (start + chunk_size).min(len);
                assert_eq!(chunk.to_vec(), bytes[start..end], "length {len}");
                assert_eq!(!chunk.is_empty(), index < non_empty, "length {len}");
            }
        }
    }

    #[test]
    fn only_the_canonical_split_reassembles() {
        let proof = proof(10_000);
        let chunks = compute_proof_chunks(&proof).unwrap();

        // The same bytes, the first chunk's last byte moved to the second.
        let mut moved = chunks.clone();
        let mut first = moved[0].to_vec();
        let mut second = vec![first.pop().unwrap()];
        second.extend_from_slice(&moved[1]);
        moved[0] = first.try_into().unwrap();
        moved[1] = second.try_into().unwrap();
        assert_eq!(
            proof_from_chunks(&moved),
            Err(ProofChunkError::NonCanonicalChunks)
        );

        assert_eq!(
            proof_from_chunks(&chunks[..TOTAL_PROOF_CHUNKS - 1]),
            Err(ProofChunkError::NonCanonicalChunks)
        );
    }

    #[test]
    fn a_proof_too_large_for_the_chunks_is_refused() {
        let bytes = vec![0; MAX_PROOF_CHUNK_SIZE * TOTAL_PROOF_CHUNKS + 1];
        assert_eq!(
            split_into_chunks(&bytes),
            Err(ProofChunkError::ProofTooLarge(bytes.len()))
        );
    }

    /// The root is the `hash_tree_root` of the chunks' SHA-256 hashes as a
    /// `Vector[Bytes32, 64]`, computed here by the SSZ merkleizer instead.
    #[test]
    fn the_root_is_the_hash_tree_root_of_the_chunk_hashes() {
        let proof = proof(10_000);
        let leaves: Vec<Root> = compute_proof_chunks(&proof)
            .unwrap()
            .iter()
            .map(|chunk| sha256(chunk))
            .collect();
        let leaves = SszVector::<Root, TOTAL_PROOF_CHUNKS>::try_from(leaves).unwrap();
        assert_eq!(
            compute_proof_chunks_root(&proof).unwrap(),
            leaves.hash_tree_root()
        );
    }

    #[test]
    fn the_root_commits_to_every_byte() {
        let proof = proof(10_000);
        let root = compute_proof_chunks_root(&proof).unwrap();
        for byte in [0, 5_000, 9_999] {
            let mut bytes = proof.to_vec();
            bytes[byte] ^= 1;
            let changed = AttestationProof::try_from(bytes).unwrap();
            assert_ne!(compute_proof_chunks_root(&changed).unwrap(), root);
        }
    }

    #[test]
    fn built_chunks_verify_at_their_own_index_only() {
        let proof = proof(10_000);
        let (proof_chunks, root) = build_proof_chunks(&proof).unwrap();
        let chunks = compute_proof_chunks(&proof).unwrap();
        assert_eq!(root, compute_proof_chunks_root(&proof).unwrap());
        for (index, proof_chunk) in proof_chunks.iter().enumerate() {
            assert_eq!(usize::from(proof_chunk.index), index);
            assert_eq!(proof_chunk.chunk, chunks[index]);
            assert!(proof_chunk.verify_inclusion_proof(root));
        }

        let mut wrong_bytes = proof_chunks[5].clone();
        wrong_bytes.chunk = proof_chunks[6].chunk.clone();
        assert!(!wrong_bytes.verify_inclusion_proof(root));

        let mut wrong_index = proof_chunks[5].clone();
        wrong_index.index = 6;
        assert!(!wrong_index.verify_inclusion_proof(root));

        // An index past the tree shares its low bits with a real one.
        let mut out_of_range = proof_chunks[5].clone();
        out_of_range.index = 5 + TOTAL_PROOF_CHUNKS as u8;
        assert!(!out_of_range.verify_inclusion_proof(root));

        assert!(!proof_chunks[5].verify_inclusion_proof(Root::repeat_byte(9)));
    }

    #[test]
    fn wire_sizes_match_the_eip() {
        let id = AggregateId {
            slot: 5,
            aggregator_index: 9,
            header_root: Root::repeat_byte(1),
        };
        let bytes = id.to_ssz();
        assert_eq!(bytes.len(), 48);
        assert_eq!(AggregateId::from_ssz_bytes(&bytes).unwrap(), id);

        let metadata = ProofChunkMetadata {
            have: ProofChunkBitmap::new(),
            request: ProofChunkBitmap::new(),
        };
        assert_eq!(metadata.to_ssz().len(), 16);

        let longest = ProofChunk {
            index: 0,
            chunk: vec![0; MAX_PROOF_CHUNK_SIZE].try_into().unwrap(),
            chunk_inclusion_proof: no_branch(),
        };
        assert_eq!(longest.to_ssz().len(), ProofChunk::max_ssz_len());
    }

    #[test]
    fn the_largest_header_and_piece_encode_to_their_bounds() {
        let largest = signed_header(max_attesters());
        assert_eq!(largest.to_ssz().len(), max_signed_aggregate_header_size());

        for with_header in [true, false] {
            let piece = AggregatePiece {
                signed_header: with_header
                    .then(|| largest.clone())
                    .into_iter()
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
                chunk: ProofChunk {
                    index: 63,
                    chunk: vec![0xff; MAX_PROOF_CHUNK_SIZE].try_into().unwrap(),
                    chunk_inclusion_proof: no_branch(),
                },
            };
            let bytes = piece.to_ssz();
            if with_header {
                assert_eq!(bytes.len(), AggregatePiece::max_ssz_len());
            }
            assert_eq!(AggregatePiece::from_ssz_bytes(&bytes).unwrap(), piece);
        }

        // The EIP's and Lighthouse's mainnet values.
        if Preset::active() == Preset::Mainnet {
            assert_eq!(signed_header(2_048).to_ssz().len(), 2_843);
            assert_eq!(max_signed_aggregate_header_size(), 6_683);
            assert_eq!(AggregatePiece::max_ssz_len(), 23_276);
        }
    }

    #[test]
    fn the_header_root_commits_to_the_proof_chunks_root() {
        let header = signed_header(16).message;
        let mut other = header.clone();
        other.proof_chunks_root = Root::repeat_byte(4);
        assert_ne!(header.hash_tree_root(), other.hash_tree_root());
        assert_ne!(AggregateId::of(&header), AggregateId::of(&other));
    }
}
