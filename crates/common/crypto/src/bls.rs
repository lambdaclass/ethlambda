//! The specification's `bls` module: `bls.Verify`, `bls.Aggregate`, and friends.
//!
//! The state transition never touches a BLS library directly; it calls the
//! functions here, named exactly as the spec names them
//! (`specs/phase0/beacon-chain.md`'s "BLS signatures" section, extended by
//! `specs/altair/bls.md`), so a reader can match a call site against the spec
//! line by line.
//!
//! # Which library does what
//!
//! Two libraries sit behind these functions, split by operation rather than
//! behind a trait, since each operation has exactly one implementation:
//!
//! - [`silver_crypto_simd`] decodes and subgroup-checks every point (public
//!   keys and signatures), hashes messages to G2, evaluates every pairing
//!   equation and computes the weighted sums of a batch. On an x86-64
//!   CPU with AVX-512 IFMA it works on eight points or eight Miller loops at a
//!   time; elsewhere it falls back to `blst` and portable Rust through the same
//!   API. Its decoders return `blst`'s own verdict on every input, and its
//!   pairing product checks the same equation `blst`'s pairing context does.
//! - `blst` still adds points (key aggregates, committee sums, signature
//!   aggregates), signs, and generates keys: `silver_crypto_simd` offers no
//!   faster route for those, and its points convert to and from `blst`'s
//!   affine form without a check.
//!
//! The one behavior the two disagree on is the identity in a pairing:
//! `silver_crypto_simd`'s product drops a pair holding it, where `blst` refused
//! an identity public key. [`core_verify`] and the batch check refuse that key
//! themselves before any pairing runs; see there.
//!
//! # Why every function treats its inputs as unvalidated
//!
//! [`ethlambda_types::beacon::primitives::BlsPubkey`] is deliberately *not* validated on
//! construction: deposit processing has to be able to hold a public key that
//! never validates, because a deposit with a bad key is still a real message
//! that changes the state (it is simply never able to sign anything). Nothing
//! upstream of this module guarantees a `BlsPubkey` or `BlsSignature` is a valid,
//! subgroup-correct curve point, so every function below derives that from the
//! raw bytes rather than assuming it from the type. That costs an extra point
//! check per input compared to a backend that validates once at deserialization
//! time and trusts a typed wrapper afterward (the approach Lighthouse's `blst`
//! backend takes, and the approach `blst`'s own `fast_aggregate_verify` helper
//! assumes when it hardcodes its public-key validation flag to skip the check).
//! Here, skipping it would mean a garbage or adversarial byte string could reach
//! a pairing check unchecked.
//!
//! # Why public keys are validated once per byte string, not once per call
//!
//! For a public key, that check is also the expensive half of a signature
//! check: decompressing a G1 point and proving it is in the prime-order
//! subgroup costs far more per key than adding it into an aggregate, and an
//! attestation aggregate carries a whole committee of keys. Re-deriving every
//! key on every call made a mainnet aggregate's verification almost entirely
//! key validation, and because every active validator's key signs again each
//! epoch, almost all of it was repeated work.
//!
//! So the answer to `KeyValidate` is memoized in [`PubkeyCache`],
//! which holds it in two structures. Both are keyed, in the end, by the exact
//! compressed bytes the answer was asked about:
//!
//! - a byte-keyed map, sharded across locks, for a key with no index to its
//!   name (a gossiped aggregate's, a deposit's, a sync committee's);
//! - an index-keyed table for a key a caller read from the registry, given as
//!   an [`IndexedPubkey`]: one set-once slot per validator index, read without
//!   a lock or a hash, holding the bytes next to the point.
//!
//! That keeps the guarantee above intact rather than trading it away:
//! `key_validate` is a pure function of those bytes, so a hit hands back
//! precisely the point a fresh call would have produced, and a byte string only
//! ever enters either structure by passing it. The table does not weaken that
//! by naming slots by index. An index names whatever key the state at hand says
//! it does, which two forks (or two spec-fixture states in one process) need
//! not agree on, so a slot is never trusted for its index alone: a lookup hits
//! only when the bytes stored in the slot equal the bytes the caller just read
//! from its own state, and then the stored point is the point for those bytes.
//! A slot holding other bytes, or an index past the table's bound, sends the
//! lookup to the byte-keyed map, which needs no argument about indices at all.
//! A slot is written once and never replaced, so a reader never sees a torn or
//! changing entry; a key that lost the race for its slot goes to the map.
//! A key first validated through the byte path and later looked up by index is
//! copied into its slot, and stays in the map as well: byte-path callers cannot
//! see the table, so dropping the map entry would make them validate it again.
//! A key reached through both paths is therefore held twice. That is why every
//! caller that read a key from the registry by index passes the index, gossip
//! validation included: the byte path is left to keys with no registry index
//! (deposits, BLS-to-execution changes, builders) and to the sync committee's
//! own key list, so the keys held twice stay few.
//!
//! The table's memory follows the span of indices it serves, not the number of
//! keys in it: a chunk is allocated whole on its first key, and a registry's
//! exited validators are spread through every chunk, so the table costs one
//! slot per registry index, filled or not. A slot is smaller than a map entry,
//! so on a registry where about half the validators have exited the table costs
//! somewhat more than a map of the active keys alone would.
//! A key that fails is never cached in either structure, so an invalid key
//! costs a full check every time, exactly as before, and cannot grow either.
//!
//! # Why a message is hashed once
//!
//! Hashing a signing root to a G2 point costs about as much as a hundred
//! microseconds of pairing work, and the same root is signed by every attester
//! of a slot. [`verify`], [`aggregate_verify`], [`fast_aggregate_verify`] and
//! [`SignatureSet`] therefore do not hash inside a one-shot verifier, which
//! would hash on every call: they take the hash from a small two-generation
//! cache (`hashed_messages`) and run the pairing equation over it themselves
//! (in `primitives`, the one module with `silver_crypto_simd` point and
//! pairing calls). Decoding and validation are unchanged, and the pairing
//! check refuses an identity key explicitly. [`verify_signature_sets`]
//! additionally groups its sets by message, so a batch pays one pairing per
//! distinct message.
//!
//! # `bool` versus `Result`
//!
//! The verification functions ([`verify`], [`aggregate_verify`],
//! [`fast_aggregate_verify`], [`eth_fast_aggregate_verify`], [`key_validate`])
//! return `bool`, matching the spec's own signatures (`bls.Verify(...) -> bool`
//! and so on): they are predicates, and a `false` covers every way a claim can
//! fail to hold, whether the signature does not match, the public key does not
//! decode, or a point is not subgroup-correct. The specification does not
//! distinguish "the key was gibberish" from "the key was valid but the
//! signature was wrong": both mean the check did not pass, so collapsing them
//! into one boolean is what lets a caller use the result directly as a gate
//! (`if !bls::verify(...) { return }`) instead of first deciding which `Err`
//! variants count as "reject" and which count as a bug worth propagating.
//!
//! The aggregation functions ([`aggregate`], [`eth_aggregate_pubkeys`]) return
//! [`Result`] instead, because there is no boolean predicate to collapse
//! to: aggregation either produces a point or it structurally cannot (an empty
//! input, or an element that is not itself a valid point), and that is a
//! different kind of failure than "verification did not pass". Keeping it a
//! `Result` keeps that distinction visible at the call site instead of forcing
//! an aggregation failure to masquerade as a rejected signature.
//!
//! # Why a cache miss is validated in parallel, and a hit is not
//!
//! [`aggregate_verify`] and [`fast_aggregate_verify`] each resolve `pubkeys`
//! to points before the pairing check runs; a single Electra block can carry
//! up to `MAX_ATTESTATIONS_ELECTRA` aggregates, each covering up to a whole
//! committee, so a cold cache (the first blocks after a start) turns that into
//! thousands of independent point checks per block import. The beacon state
//! transition runs on one actor thread (see `BlockChain` in
//! `crates/blockchain/src/lib.rs`), so on a multi-core host every one of those
//! checks but the one currently running would leave a core idle. Validating one
//! key never reads or writes anything another key's validation touches, so
//! nothing depends on which order they run in or finish in: the misses are cut
//! into chunks of [`KEY_DECODE_CHUNK`] keys, each chunk goes to
//! `silver_crypto_simd`'s batch decoder (eight keys per step on an IFMA CPU) on
//! rayon's global thread pool, and the result collapses to `None` if any key
//! fails, without skipping or weakening [`key_validate`] for a single key. Each
//! validated point is written back to its own index, which `aggregate_verify`
//! relies on to keep `points[i]` paired with `messages[i]`.
//!
//! A hit is a hash-map read, far cheaper than handing work to another thread,
//! so hits resolve on the calling thread, and so does a miss set no larger than
//! one chunk. That matters beyond the saving itself: gossip validation runs many
//! signature checks at once on blocking threads, and if every one of them
//! queued its keys on rayon's single global pool, a burst of aggregates would
//! stall there even with the keys already validated.

use std::collections::HashMap;
use std::sync::{LazyLock, OnceLock, RwLock};

use blst::MultiPoint;
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, Signature};
use rayon::prelude::*;
use silver_crypto_simd::bls::{G1Point, G2Point, uncompress_in_g1, uncompress_in_g2};

use ethlambda_types::beacon::error::{Error, Result};
use ethlambda_types::beacon::primitives::{
    BLS_PUBKEY_SIZE, BLS_SIGNATURE_SIZE, BlsPubkey, BlsSignature, Root, ValidatorIndex,
};

mod batch;
pub use batch::{SignatureSet, verify_signature_sets};

mod hashed_messages;
mod primitives;

/// The ciphersuite the specification pins BLS signatures to: the IETF BLS
/// draft's proof-of-possession scheme over BLS12-381's G2, using SHA-256 in
/// the XMD hash-to-curve construction.
///
/// This is the domain separation tag threaded through every hash-to-curve call
/// in this module. Two signatures produced under different DSTs never verify
/// against each other, which is exactly the point: it is what lets the same
/// keys be reused for other purposes (or other chains) without cross-protocol
/// signature reuse.
pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// How many public keys [`PubkeyCache`] has not seen go to one call of
/// `silver_crypto_simd`'s batch decoder when [`aggregate_verify`] and
/// [`fast_aggregate_verify`] validate them in parallel.
///
/// On an IFMA CPU the decoder works on eight keys per step and finishes a
/// partial step one key at a time, so a chunk is a multiple of eight. A chunk
/// is also the unit rayon schedules: this size keeps a task well above rayon's
/// dispatch cost, while a mainnet block's first import, with tens of thousands
/// of keys not yet seen, still splits into far more chunks than the pool has
/// threads. A miss set no larger than one chunk (a fixture's, a devnet's, most
/// gossip's) is decoded on the calling thread.
const KEY_DECODE_CHUNK: usize = 64;

/// The fewest messages one rayon task hashes when [`aggregate_verify`] resolves
/// its messages to G2 points. A hash costs far more than the dispatch of a
/// task, but a handful of messages (a fixture's, a small devnet's) gain nothing
/// from leaving the calling thread; `with_min_len` keeps that decision inside
/// rayon's own splitting.
const HASH_MIN_PAR_LEN: usize = 16;

/// How many shards [`PubkeyCache`] splits its map across.
///
/// Every signature check reads the cache once per signer, from whichever
/// thread runs it: the chain actor, rayon's workers, and every blocking thread
/// gossip validation has running at once. One lock would put every one of
/// those reads on the same cache line; a shard per lock spreads them out.
const PUBKEY_CACHE_SHARDS: usize = 64;

/// The most validated public keys each of [`VALIDATED_PUBKEYS`]'s two
/// structures holds: the map across all of its shards, and the index table,
/// whose bound on indices it serves is this same number.
///
/// Far above any real validator registry: the bound is not there to evict
/// anything a registry needs, but so that inputs which are not a registry
/// (deposits carrying arbitrary keys, or a test run over thousands of
/// generated ones) cannot grow the cache without limit. A key arriving past
/// the bound is still validated, just on every call, as it was before the
/// cache existed.
const MAX_CACHED_PUBKEYS: usize = 1 << 22;

/// Every public key that has passed `KeyValidate`, by its
/// compressed bytes, for the whole process.
///
/// Process-wide rather than owned by a `Store`, because nothing about the
/// answer is per chain or per state: it is a pure function of the bytes (see
/// the module documentation), so one copy serves the state transition, fork
/// choice and gossip validation alike. Lean code never calls into this module,
/// so a lean run never allocates it.
static VALIDATED_PUBKEYS: LazyLock<PubkeyCache> =
    LazyLock::new(|| PubkeyCache::new(MAX_CACHED_PUBKEYS));

/// How many validator indices one lazily allocated chunk of the index table
/// covers.
///
/// Registry indices are dense, so a chunk fills as the registry is walked, and
/// a chunk is the unit of allocation: small enough that a test or a small
/// devnet pays for a few of them, large enough that a mainnet registry is a few
/// hundred.
const INDEX_CHUNK_LEN: usize = 1 << 12;

/// A validated key as the index table stores it: the bytes it was validated
/// from, next to the point, so a lookup can check the bytes before trusting
/// the point.
type IndexedEntry = (BlsPubkey, PublicKey);

/// One lazily allocated run of [`INDEX_CHUNK_LEN`] set-once slots.
type IndexChunk = Box<[OnceLock<IndexedEntry>]>;

/// What a key-taking function accepts: a bare [`BlsPubkey`], resolved through
/// the byte-keyed map, or an [`IndexedPubkey`], resolved through the index
/// table first.
///
/// Sealed, because the cache's soundness argument (see the module
/// documentation) is about exactly these two shapes. Both carry the bytes the
/// caller read; the index is only a hint about where to look for them.
pub trait PubkeySource: sealed::Sealed {}

impl PubkeySource for BlsPubkey {}
impl PubkeySource for IndexedPubkey {}

mod sealed {
    use super::*;

    /// The accessors the cache needs; kept out of [`PubkeySource`] so that
    /// nothing outside this crate can implement it.
    pub trait Sealed: Sync {
        /// The compressed bytes the caller read from its state.
        fn pubkey(&self) -> &BlsPubkey;
        /// The registry index to try first, if the caller knows one.
        fn index(&self) -> Option<ValidatorIndex>;
    }

    impl Sealed for BlsPubkey {
        fn pubkey(&self) -> &BlsPubkey {
            self
        }
        fn index(&self) -> Option<ValidatorIndex> {
            None
        }
    }

    impl Sealed for IndexedPubkey {
        fn pubkey(&self) -> &BlsPubkey {
            &self.pubkey
        }
        fn index(&self) -> Option<ValidatorIndex> {
            Some(self.index)
        }
    }
}

/// A public key together with the validator index the caller read it at.
///
/// The index is a hint that lets the cache answer from its index-keyed table
/// instead of hashing the bytes. It is never trusted on its own: the table
/// hits only when the bytes held for that index equal `pubkey`, so a caller
/// whose state names a different key at that index than another state did
/// still gets the point for the bytes it passed. See the module documentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexedPubkey {
    /// The validator's index in the registry the key was read from.
    pub index: ValidatorIndex,
    /// The key's compressed bytes, as that registry holds them.
    pub pubkey: BlsPubkey,
}

/// Validated, decompressed public keys, by their compressed encoding or by the
/// registry index they were read at.
///
/// A bounded, append-only memo of `KeyValidate`: an entry is
/// only ever added for a key that passed, never changed, and never removed,
/// since its answer can never change. See the module documentation for why
/// that is sound.
///
/// The index table holds a key resolved through an [`IndexedPubkey`] and the
/// map holds every other. A key reached through both paths is held in both,
/// since byte-path callers cannot see the table, which is why registry callers
/// pass the index. The table's memory is its allocated chunks', not its
/// entries'; see the module documentation.
struct PubkeyCache {
    shards: [RwLock<HashMap<BlsPubkey, PublicKey>>; PUBKEY_CACHE_SHARDS],
    /// The most entries one shard takes, so the whole cache stays within the
    /// capacity it was built with.
    shard_capacity: usize,
    /// Set-once slots by validator index, in chunks allocated on first write.
    /// Its length times [`INDEX_CHUNK_LEN`] is the bound on indices it serves.
    chunks: Box<[OnceLock<IndexChunk>]>,
    /// The first index the table does not serve.
    index_bound: usize,
}

impl PubkeyCache {
    fn new(capacity: usize) -> Self {
        Self {
            shards: std::array::from_fn(|_| RwLock::new(HashMap::new())),
            shard_capacity: capacity.div_ceil(PUBKEY_CACHE_SHARDS),
            chunks: (0..capacity.div_ceil(INDEX_CHUNK_LEN))
                .map(|_| OnceLock::new())
                .collect(),
            index_bound: capacity,
        }
    }

    /// The shard `pubkey` lives in, chosen by the last byte of its encoding:
    /// the low byte of the point's x-coordinate, so it spreads keys evenly
    /// without hashing them twice. The flag bits sit in the first byte.
    fn shard(&self, pubkey: &BlsPubkey) -> &RwLock<HashMap<BlsPubkey, PublicKey>> {
        let byte = usize::from(pubkey.0[BLS_PUBKEY_SIZE - 1]);
        &self.shards[byte % PUBKEY_CACHE_SHARDS]
    }

    /// The chunk cell covering `index` and the slot's offset in it, if the
    /// index is inside the bound.
    fn chunk_cell(&self, index: ValidatorIndex) -> Option<(&OnceLock<IndexChunk>, usize)> {
        let index = usize::try_from(index)
            .ok()
            .filter(|&i| i < self.index_bound)?;
        Some((
            &self.chunks[index / INDEX_CHUNK_LEN],
            index % INDEX_CHUNK_LEN,
        ))
    }

    /// The table slot for `index`, if the index is inside the bound and its
    /// chunk exists. A lookup never allocates.
    fn slot(&self, index: ValidatorIndex) -> Option<&OnceLock<IndexedEntry>> {
        let (cell, offset) = self.chunk_cell(index)?;
        Some(&cell.get()?[offset])
    }

    /// The table slot for `index`, allocating its chunk if this is the
    /// chunk's first key, if the index is inside the bound.
    fn slot_or_allocate(&self, index: ValidatorIndex) -> Option<&OnceLock<IndexedEntry>> {
        let (cell, offset) = self.chunk_cell(index)?;
        let chunk = cell.get_or_init(|| {
            crate::metrics::inc_pubkey_cache_index_chunks();
            (0..INDEX_CHUNK_LEN).map(|_| OnceLock::new()).collect()
        });
        Some(&chunk[offset])
    }

    fn get_by_bytes(&self, pubkey: &BlsPubkey) -> Option<PublicKey> {
        self.shard(pubkey).read().unwrap().get(pubkey).copied()
    }

    /// The validated point for `key`, if its bytes have passed before.
    ///
    /// The index table answers only when the slot's stored bytes equal the
    /// bytes in `key`; anything else, including an index outside the bound,
    /// goes to the byte-keyed map.
    fn get<K: PubkeySource>(&self, key: &K) -> Option<PublicKey> {
        let pubkey = key.pubkey();
        if let Some(index) = key.index()
            && let Some((bytes, point)) = self.slot(index).and_then(OnceLock::get)
            && bytes == pubkey
        {
            return Some(*point);
        }
        let point = self.get_by_bytes(pubkey)?;
        // A key first seen through the byte path (gossip, sync committee
        // messages) is copied into its empty slot, so later lookups by index
        // hit the table. The map keeps its entry: byte-path callers cannot see
        // the table and would have to validate again. Set-once, first writer
        // wins; a slot holding other bytes is left alone.
        if let Some(index) = key.index()
            && let Some(slot) = self.slot_or_allocate(index)
            && slot.set((*pubkey, point)).is_ok()
        {
            crate::metrics::inc_pubkey_cache_table_entries();
        }
        Some(point)
    }

    /// Records that `key`'s bytes validated to `point`: in the index table
    /// when `key` has an index whose slot is free (or already holds these
    /// bytes), otherwise in the map, unless that shard is full.
    fn insert<K: PubkeySource>(&self, key: &K, point: PublicKey) {
        let pubkey = *key.pubkey();
        if let Some(index) = key.index()
            && let Some(slot) = self.slot_or_allocate(index)
        {
            match slot.set((pubkey, point)) {
                Ok(()) => {
                    crate::metrics::inc_pubkey_cache_table_entries();
                    return;
                }
                // First writer wins; a racing writer of the same bytes is done.
                Err(_) if slot.get().is_some_and(|(bytes, _)| *bytes == pubkey) => return,
                // The slot holds other bytes: this key lives in the map.
                Err(_) => {}
            }
        }
        let mut shard = self.shard(&pubkey).write().unwrap();
        if shard.len() < self.shard_capacity && shard.insert(pubkey, point).is_none() {
            crate::metrics::inc_pubkey_cache_map_entries();
        }
    }

    /// The number of keys held, across the map and the table.
    #[cfg(test)]
    fn len(&self) -> usize {
        let mapped: usize = self
            .shards
            .iter()
            .map(|shard| shard.read().unwrap().len())
            .sum();
        let indexed: usize = self
            .chunks
            .iter()
            .filter_map(|chunk| chunk.get())
            .map(|chunk| chunk.iter().filter(|slot| slot.get().is_some()).count())
            .sum();
        mapped + indexed
    }
}

/// A decoded G1 point as a public key, or `None` for the identity.
///
/// `silver_crypto_simd`'s decoder admits the identity, since it is a point of
/// the subgroup; `KeyValidate` refuses it, as `blst`'s `key_validate` did.
fn admit_pubkey(point: G1Point) -> Option<PublicKey> {
    (!point.is_infinity()).then(|| PublicKey::from(point.into_blst()))
}

/// `KeyValidate` on one encoding, uncached: the point, or `None` if the bytes
/// do not decode to a subgroup point of G1 or decode to the identity.
fn decode_pubkey(encoding: &[u8; BLS_PUBKEY_SIZE]) -> Option<PublicKey> {
    let mut decoded = [None];
    uncompress_in_g1(std::slice::from_ref(encoding), &mut decoded);
    decoded[0].and_then(admit_pubkey)
}

/// `KeyValidate` on each encoding, uncached and in order.
///
/// Chunks of [`KEY_DECODE_CHUNK`] go to rayon's pool, unless there is only one;
/// see the module documentation.
fn decode_pubkeys(encodings: &[[u8; BLS_PUBKEY_SIZE]]) -> Vec<Option<PublicKey>> {
    let mut decoded = vec![None; encodings.len()];
    if encodings.len() <= KEY_DECODE_CHUNK {
        uncompress_in_g1(encodings, &mut decoded);
    } else {
        encodings
            .par_chunks(KEY_DECODE_CHUNK)
            .zip(decoded.par_chunks_mut(KEY_DECODE_CHUNK))
            .for_each(|(input, output)| uncompress_in_g1(input, output));
    }
    decoded
        .into_iter()
        .map(|point| point.and_then(admit_pubkey))
        .collect()
}

/// `signature` as a subgroup point of G2, or `None` if it does not decode to
/// one. The identity decodes: it is a valid signature encoding (the one an
/// empty aggregate carries), which `blst`'s `sig_validate(_, false)` accepted
/// too.
fn decode_signature(signature: &BlsSignature) -> Option<G2Point> {
    let mut decoded = [None];
    uncompress_in_g2(std::slice::from_ref(&signature.0), &mut decoded);
    decoded[0]
}

/// The pairing equation every single-message check comes down to,
/// `e(pubkey, H(message)) == e(G1, signature)`, with `H(message)` from the
/// hashed-message cache.
///
/// The identity key is refused by [`primitives::core_pairing_check`]: a set of
/// keys that cancel (`P` and `-P`, both valid keys) would otherwise verify
/// under no signature at all. IETF `CoreVerify` runs `KeyValidate` on the key
/// it is given, which for `FastAggregateVerify` is the sum. Only a sum can be
/// the identity: a single key is refused by `KeyValidate` first.
fn core_verify(pubkey: &PublicKey, message: Root, signature: &G2Point) -> bool {
    let hashed = hashed_messages::hashed_message(&message);
    primitives::core_pairing_check(&primitives::g1_point(pubkey), &hashed, signature)
}

/// `pubkey` as a validated point, or `None` if it is not a valid,
/// subgroup-correct, non-identity key: `KeyValidate`, through
/// [`VALIDATED_PUBKEYS`].
fn validated_pubkey<K: PubkeySource>(pubkey: &K) -> Option<PublicKey> {
    if let Some(point) = VALIDATED_PUBKEYS.get(pubkey) {
        crate::metrics::inc_pubkey_cache_lookups(1, 0);
        return Some(point);
    }
    crate::metrics::inc_pubkey_cache_lookups(0, 1);
    let point = decode_pubkey(&pubkey.pubkey().0)?;
    VALIDATED_PUBKEYS.insert(pubkey, point);
    Some(point)
}

/// Every key in `pubkeys` as a validated point, in order, or `None` if any
/// one of them fails to validate.
///
/// Hits resolve on the calling thread and only the misses go to rayon; see
/// the module documentation for why. Each miss that validates is added to
/// [`VALIDATED_PUBKEYS`] before returning.
fn validated_pubkeys<K: PubkeySource>(pubkeys: &[K]) -> Option<Vec<PublicKey>> {
    let mut points: Vec<Option<PublicKey>> = pubkeys
        .iter()
        .map(|pubkey| VALIDATED_PUBKEYS.get(pubkey))
        .collect();
    let misses: Vec<usize> = points
        .iter()
        .enumerate()
        .filter_map(|(index, point)| point.is_none().then_some(index))
        .collect();
    let hits = pubkeys.len() - misses.len();
    crate::metrics::inc_pubkey_cache_lookups(hits as u64, misses.len() as u64);

    if !misses.is_empty() {
        let encodings: Vec<[u8; BLS_PUBKEY_SIZE]> = misses
            .iter()
            .map(|&index| pubkeys[index].pubkey().0)
            .collect();
        let fresh: Vec<PublicKey> = decode_pubkeys(&encodings)
            .into_iter()
            .collect::<Option<_>>()?;
        for (&index, point) in misses.iter().zip(fresh) {
            VALIDATED_PUBKEYS.insert(&pubkeys[index], point);
            points[index] = Some(point);
        }
    }
    points.into_iter().collect()
}

/// The sum of `points` as a projective point, or `None` for an empty slice.
///
/// Every point must already have passed `KeyValidate` (they come
/// from [`validated_pubkeys`]), so the sum skips re-checking them. It goes
/// through blst's `MultiPoint::add`, which hands the whole slice to
/// `blst_p1s_add`: a batched affine addition that shares one field inversion
/// across many additions, instead of paying a projective addition per key the
/// way folding the keys one by one through blst's `AggregatePublicKey::aggregate`
/// does. A committee's key sum is the largest cost left in verifying an
/// attestation once the keys are cached, so this is where the saving is.
///
/// The result stays projective, which is the form `add_aggregate` and
/// `sub_aggregate` take: [`AggregatePubkey`] adds and subtracts such sums and
/// would pay a field inversion per conversion to affine and back. Callers that
/// need an affine key convert once, as [`sum_validated_points`] does.
///
/// The batched routine handles equal points (`P + P` is a doubling, and sync
/// committees are drawn with replacement, so one sum can name the same key
/// twice) and returns the same group element as the sequential sum; only the
/// order of additions differs, and the group is commutative.
///
/// From 384 points up, on a host with two or more CPUs, blst splits the work
/// over its own thread pool, which is separate from rayon's; below that, or on
/// one CPU, it runs on the calling thread. The pool is the one blst's pairing
/// already ran on before this helper existed, so the sums join the same queue
/// rather than adding threads. Either way the answer is the same, so the
/// caller needs no size check.
///
/// The empty slice is guarded here because `MultiPoint::add` indexes the
/// slice's first element and would panic on it.
fn sum_validated_projective(points: &[PublicKey]) -> Option<AggregatePublicKey> {
    if points.is_empty() {
        return None;
    }
    Some(points.add())
}

/// The sum of `points` as one affine public key, or `None` for an empty
/// slice: [`sum_validated_projective`] converted once.
fn sum_validated_points(points: &[PublicKey]) -> Option<PublicKey> {
    sum_validated_projective(points).map(|sum| sum.to_public_key())
}

/// Builds `specs/altair/bls.md`'s `G2_POINT_AT_INFINITY` constant: the
/// compressed encoding of the identity element of G2, which is the
/// specification's sentinel value for "no one signed anything".
///
/// A `const fn` rather than a byte literal so the encoding rule (the
/// compression flag and infinity flag bits set, every other bit zero) reads as
/// what it is instead of as a string of hex digits to take on faith.
const fn g2_point_at_infinity() -> [u8; BLS_SIGNATURE_SIZE] {
    let mut bytes = [0u8; BLS_SIGNATURE_SIZE];
    // The top two bits of the first byte are the compression flag and the
    // infinity flag; setting both and leaving every other bit zero is exactly
    // the encoding of the point at infinity, compressed.
    bytes[0] = 0b1100_0000;
    bytes
}

/// `specs/altair/bls.md`'s `G2_POINT_AT_INFINITY`, the compressed encoding of
/// the identity element of G2.
pub const G2_POINT_AT_INFINITY: [u8; BLS_SIGNATURE_SIZE] = g2_point_at_infinity();

/// The specification's `bls.Verify(pubkey, message, signature) -> bool`.
///
/// Deserializes and fully validates both inputs (subgroup membership for the
/// signature, subgroup membership and non-identity for the public key) before
/// checking the pairing equation, so a `pubkey` that never passed
/// [`key_validate`] and never will (see the module documentation) simply fails
/// here rather than panicking or returning an error: an unparseable or
/// invalid-point key is treated exactly like a valid key over the wrong
/// signature, since the specification never distinguishes the two.
pub fn verify<K: PubkeySource>(pubkey: &K, message: Root, signature: &BlsSignature) -> bool {
    let Some(pubkey) = validated_pubkey(pubkey) else {
        return false;
    };
    let Some(signature) = decode_signature(signature) else {
        return false;
    };
    core_verify(&pubkey, message, &signature)
}

/// The specification's `bls.Aggregate(signatures) -> BLSSignature`.
///
/// Fails on an empty `signatures`, matching the spec's `Aggregate` (there is no
/// meaningful signature aggregating zero signatures), and fails if any element
/// does not deserialize to a subgroup-correct point in G2. Checking every
/// element here, rather than only the final sum, matters because elliptic
/// curve addition of two points outside the prime-order subgroup can still
/// land back inside it: an invalid share could otherwise cancel against
/// another invalid share and slip past a check performed only on the result.
///
/// The shares are decoded together, so an IFMA CPU checks eight per step; the
/// sum is `blst`'s.
pub fn aggregate(signatures: &[BlsSignature]) -> Result<BlsSignature> {
    ethlambda_types::beacon::error::verify(!signatures.is_empty(), "len(signatures) > 0")?;
    let invalid = || Error::InvalidSignature("aggregate: not a valid, subgroup-correct point");
    let encodings: Vec<[u8; BLS_SIGNATURE_SIZE]> =
        signatures.iter().map(|signature| signature.0).collect();
    let mut decoded = vec![None; encodings.len()];
    uncompress_in_g2(&encodings, &mut decoded);
    let shares: Vec<Signature> = decoded
        .into_iter()
        .map(|point| point.map(|point| Signature::from(point.into_blst())))
        .collect::<Option<_>>()
        .ok_or_else(invalid)?;
    let share_refs: Vec<&Signature> = shares.iter().collect();
    // Every share was decoded and subgroup-checked above.
    let aggregated = AggregateSignature::aggregate(&share_refs, false).map_err(|_| invalid())?;
    Ok(BlsSignature(aggregated.to_signature().to_bytes()))
}

/// The specification's
/// `bls.AggregateVerify(pubkeys, messages, signature) -> bool`.
///
/// `pubkeys` and `messages` are matched up positionally, one message per
/// signer; an empty `pubkeys`, or a length mismatch between the two, fails
/// immediately rather than vacuously succeeding. As with [`verify`], every
/// public key and the signature are independently deserialized and validated
/// (subgroup membership, non-identity for the keys) before the pairing check
/// runs, so an invalid key or signature simply fails this predicate. Keys go
/// through [`PubkeyCache`], and the ones it has not seen are validated in
/// parallel; see the module documentation for why both are safe and why
/// `points` still lines up with `messages` afterward.
pub fn aggregate_verify(
    pubkeys: &[BlsPubkey],
    messages: &[Root],
    signature: &BlsSignature,
) -> bool {
    if pubkeys.is_empty() || pubkeys.len() != messages.len() {
        return false;
    }
    let Some(signature) = decode_signature(signature) else {
        return false;
    };
    let Some(points) = validated_pubkeys(pubkeys) else {
        return false;
    };
    // Hashing the distinct messages is the bulk of this check, and the cache
    // is thread-safe, so the hashes (cached or not) fan out across rayon's
    // workers.
    let hashed: Vec<G2Point> = messages
        .par_iter()
        .with_min_len(HASH_MIN_PAR_LEN)
        .map(hashed_messages::hashed_message)
        .collect();
    // Every key passed `KeyValidate`, so none is the identity.
    let pairs: Vec<(G1Point, G2Point)> = points
        .iter()
        .map(primitives::g1_point)
        .zip(hashed)
        .collect();
    primitives::pairing_product_holds(&pairs, &signature)
}

/// The specification's
/// `bls.FastAggregateVerify(pubkeys, message, signature) -> bool`.
///
/// The same check as [`aggregate_verify`] specialized to one shared `message`,
/// which is the shape every attestation aggregate takes. An empty `pubkeys`
/// always fails here: this function has no notion of "no one signed, and that
/// is fine", unlike its eth2-specific wrapper [`eth_fast_aggregate_verify`],
/// which is exactly why that wrapper exists. This is the hot path for a real
/// Electra block's attestations, where a single aggregate can carry
/// thousands of signers behind one shared message; keys go through
/// [`PubkeyCache`], see the module documentation for why that is safe.
pub fn fast_aggregate_verify<K: PubkeySource>(
    pubkeys: &[K],
    message: Root,
    signature: &BlsSignature,
) -> bool {
    if pubkeys.is_empty() {
        return false;
    }
    let Some(signature) = decode_signature(signature) else {
        return false;
    };
    let Some(points) = validated_pubkeys(pubkeys) else {
        return false;
    };
    // `pubkeys` is non-empty, so there is always a sum. It may be the
    // identity, which `core_verify` refuses.
    let Some(aggregated) = sum_validated_points(&points) else {
        return false;
    };
    core_verify(&aggregated, message, &signature)
}

/// `specs/altair/bls.md`'s `eth_aggregate_pubkeys(pubkeys) -> BLSPubkey`.
///
/// Follows the spec's own pseudocode: `assert len(pubkeys) > 0`, then
/// `assert all(bls.KeyValidate(pubkey) for pubkey in pubkeys)` before summing.
/// The `KeyValidate` step is not optional the way it might look from the name:
/// without it, an all-zero or otherwise invalid `pubkey` would silently
/// contribute nothing (or something unintended) to the sum instead of failing
/// the aggregation outright, which is why this returns [`Result`] rather
/// than substituting a default.
pub fn eth_aggregate_pubkeys<K: PubkeySource>(pubkeys: &[K]) -> Result<BlsPubkey> {
    ethlambda_types::beacon::error::verify(!pubkeys.is_empty(), "len(pubkeys) > 0")?;
    let points = validated_pubkeys(pubkeys).ok_or(Error::SpecAssert(
        "all(bls.KeyValidate(pubkey) for pubkey in pubkeys)",
    ))?;
    // Every point above already passed `key_validate`, so the sum skips
    // re-checking them.
    let aggregated = sum_validated_points(&points).ok_or(Error::SpecAssert("len(pubkeys) > 0"))?;
    Ok(BlsPubkey(aggregated.to_bytes()))
}

/// `specs/altair/bls.md`'s
/// `eth_fast_aggregate_verify(pubkeys, message, signature) -> bool`.
///
/// Identical to [`fast_aggregate_verify`] except for one case: an empty
/// `pubkeys` returns `true` exactly when `signature` is
/// [`G2_POINT_AT_INFINITY`], and `false` for every other signature in that
/// case. This carve-out exists because an
/// empty-committee attestation aggregate is a legitimate value on chain (no
/// validators were assigned, or none of them attested), and its signature is
/// the identity element by convention rather than "no signature was
/// provided"; [`fast_aggregate_verify`] itself has no such case, since the
/// underlying IETF ciphersuite it wraps was never given one.
pub fn eth_fast_aggregate_verify<K: PubkeySource>(
    pubkeys: &[K],
    message: Root,
    signature: &BlsSignature,
) -> bool {
    if pubkeys.is_empty() {
        return signature.as_ref() == G2_POINT_AT_INFINITY;
    }
    fast_aggregate_verify(pubkeys, message, signature)
}

/// The specification's `bls.KeyValidate(pubkey) -> bool`.
///
/// A `pubkey` passes when it deserializes to a point on the curve, that point
/// is in the correct prime-order subgroup, and it is not the identity element.
/// Exposed standalone because the spec calls `KeyValidate` directly in more
/// than one place (deposit processing, [`eth_aggregate_pubkeys`]'s own
/// assertion), not only as a step inside a signature check.
pub fn key_validate<K: PubkeySource>(pubkey: &K) -> bool {
    validated_pubkey(pubkey).is_some()
}

mod committee_sums;
pub use committee_sums::{AggregatePubkey, CommitteeKeySums};

mod warm;
pub use warm::warm_pubkeys;

#[cfg(test)]
mod tests {
    use super::*;
    use blst::min_pk::AggregatePublicKey;

    #[test]
    fn aggregate_verify_agrees_with_blst_over_distinct_and_repeated_messages() {
        // 40 signers is past the parallel hashing threshold; messages repeat
        // in the second round.
        for distinct in [40u8, 3] {
            let keys: Vec<blst::min_pk::SecretKey> = (0..40u64)
                .map(|seed| {
                    let mut ikm = [0x3cu8; 32];
                    ikm[..8].copy_from_slice(&seed.to_le_bytes());
                    blst::min_pk::SecretKey::key_gen(&ikm, &[]).unwrap()
                })
                .collect();
            let pubkeys: Vec<BlsPubkey> = keys
                .iter()
                .map(|key| BlsPubkey(key.sk_to_pk().to_bytes()))
                .collect();
            let messages: Vec<Root> = (0..40u8).map(|i| Root::from([i % distinct; 32])).collect();
            let signatures: Vec<BlsSignature> = keys
                .iter()
                .zip(&messages)
                .map(|(key, message)| {
                    BlsSignature(key.sign(message.as_slice(), DST, &[]).to_bytes())
                })
                .collect();
            let aggregated = aggregate(&signatures).unwrap();
            assert!(aggregate_verify(&pubkeys, &messages, &aggregated));
            let mut swapped = messages.clone();
            swapped.swap(0, 1);
            assert_eq!(
                aggregate_verify(&pubkeys, &swapped, &aggregated),
                messages[0] == messages[1]
            );
            assert!(!aggregate_verify(
                &pubkeys[1..],
                &messages[1..],
                &aggregated
            ));
        }
    }

    #[test]
    fn key_validate_rejects_the_all_zero_pubkey() {
        assert!(!key_validate(&BlsPubkey::default()));
    }

    /// A fresh keypair's public key, distinct per `seed` and distinct from
    /// [`build_aggregate`]'s signers (whose seeds start at one).
    fn fresh_pubkey(seed: u64) -> BlsPubkey {
        let mut ikm = [0xa5u8; 32];
        ikm[..8].copy_from_slice(&seed.to_le_bytes());
        let secret = blst::min_pk::SecretKey::key_gen(&ikm, &[])
            .expect("32 bytes of input material is enough for key generation");
        BlsPubkey(secret.sk_to_pk().to_bytes())
    }

    /// The compressed encoding of G1's identity element: a well-formed point,
    /// so it decodes, but one `key_validate` must refuse.
    fn identity_pubkey() -> BlsPubkey {
        let mut bytes = [0u8; BLS_PUBKEY_SIZE];
        bytes[0] = 0b1100_0000;
        BlsPubkey(bytes)
    }

    /// Resolves `pubkey` straight through `blst`, with no cache involved.
    fn uncached(pubkey: &BlsPubkey) -> Option<[u8; BLS_PUBKEY_SIZE]> {
        PublicKey::key_validate(pubkey.as_ref())
            .ok()
            .map(|point| point.to_bytes())
    }

    #[test]
    fn a_warm_cache_verifies_exactly_as_a_cold_one() {
        let (pubkeys, message, signature) = build_aggregate(24);
        assert!(fast_aggregate_verify(&pubkeys, message, &signature));
        for pubkey in &pubkeys {
            let cached = VALIDATED_PUBKEYS.get(pubkey).map(|point| point.to_bytes());
            assert_eq!(
                cached,
                uncached(pubkey),
                "a cached point must be key_validate's own"
            );
        }

        // Every key is a hit now; the answers must not change with that.
        assert!(fast_aggregate_verify(&pubkeys, message, &signature));
        let other_message = ethlambda_types::beacon::primitives::H256([8u8; 32]);
        assert!(!fast_aggregate_verify(&pubkeys, other_message, &signature));
        assert!(!fast_aggregate_verify(&pubkeys[1..], message, &signature));
    }

    #[test]
    fn an_invalid_key_is_never_cached_and_always_refused() {
        let (mut pubkeys, message, signature) = build_aggregate(2);
        for invalid in [BlsPubkey::default(), identity_pubkey()] {
            assert_eq!(
                uncached(&invalid),
                None,
                "fixture assumption: an invalid key"
            );
            pubkeys.push(invalid);
            for _ in 0..2 {
                assert!(!key_validate(&invalid));
                assert!(!verify(&invalid, message, &signature));
                assert!(!fast_aggregate_verify(&pubkeys, message, &signature));
                assert!(eth_aggregate_pubkeys(&pubkeys).is_err());
                assert!(VALIDATED_PUBKEYS.get(&invalid).is_none());
            }
            pubkeys.pop();
        }
    }

    #[test]
    fn mixed_hits_and_misses_keep_their_positions() {
        let warm = [fresh_pubkey(1), fresh_pubkey(2)];
        assert!(warm.iter().all(key_validate));
        // Misses between hits, in a run long enough to go through rayon and to
        // end on a partial chunk.
        let misses = 2 * KEY_DECODE_CHUNK as u64 + 3;
        let mut pubkeys = vec![warm[0]];
        pubkeys.extend((10..10 + misses).map(fresh_pubkey));
        pubkeys.push(warm[1]);

        let points = validated_pubkeys(&pubkeys).expect("every key above is valid");
        assert_eq!(points.len(), pubkeys.len());
        for (pubkey, point) in pubkeys.iter().zip(&points) {
            assert_eq!(Some(point.to_bytes()), uncached(pubkey));
        }
    }

    #[test]
    fn eth_aggregate_pubkeys_matches_blst_s_own_sum() {
        let pubkeys: Vec<BlsPubkey> = (20..25).map(fresh_pubkey).collect();
        let encoded: Vec<&[u8]> = pubkeys.iter().map(|pubkey| pubkey.as_ref()).collect();
        let expected = AggregatePublicKey::aggregate_serialized(&encoded, true)
            .expect("every key above is valid")
            .to_public_key()
            .to_bytes();
        // Once cold, once warm.
        for _ in 0..2 {
            assert_eq!(eth_aggregate_pubkeys(&pubkeys).unwrap().0, expected);
        }
    }

    /// The sequential sum, through blst's own `AggregatePublicKey::aggregate`:
    /// what `sum_validated_points` must equal.
    fn sequential_sum(points: &[PublicKey]) -> [u8; BLS_PUBKEY_SIZE] {
        let refs: Vec<&PublicKey> = points.iter().collect();
        AggregatePublicKey::aggregate(&refs, false)
            .expect("a non-empty run of valid points sums")
            .to_public_key()
            .to_bytes()
    }

    fn validated_run(seeds: impl Iterator<Item = u64>) -> Vec<PublicKey> {
        let pubkeys: Vec<BlsPubkey> = seeds.map(fresh_pubkey).collect();
        validated_pubkeys(&pubkeys).expect("every key above is valid")
    }

    #[test]
    fn the_batched_sum_of_nothing_is_none() {
        assert!(sum_validated_points(&[]).is_none());
    }

    #[test]
    fn the_batched_sum_matches_the_sequential_one_at_every_size() {
        // One point, a pair, then both sides of blst's 384-point thread-pool
        // threshold, then larger runs. Which side of the threshold runs also
        // depends on the host: on one CPU everything stays on the calling
        // thread. On more, every pool worker's chunk stays below
        // `blst_p1s_add`'s scratch stride, so that inner loop is never
        // reached through the safe API.
        for count in [1u64, 2, 3, 17, 383, 384, 385, 767, 2000] {
            let points = validated_run(1000..1000 + count);
            assert_eq!(
                sum_validated_points(&points).map(|sum| sum.to_bytes()),
                Some(sequential_sum(&points)),
                "{count} distinct points"
            );
        }
    }

    #[test]
    fn the_batched_sum_doubles_equal_points() {
        let one = validated_run(5000..5001)[0];
        let pair = [one, one];
        assert_eq!(
            sum_validated_points(&pair).map(|sum| sum.to_bytes()),
            Some(sequential_sum(&pair)),
            "P + P is a doubling"
        );

        // Several repeats scattered through a run, the shape of a committee
        // drawn with replacement, at sizes either side of the threshold.
        for count in [10u64, 400, 1000] {
            let distinct = validated_run(6000..6000 + count);
            let mut points = Vec::new();
            for (index, point) in distinct.iter().enumerate() {
                points.push(*point);
                if index % 3 == 0 {
                    points.push(*point);
                }
                if index % 7 == 0 {
                    points.push(distinct[0]);
                }
            }
            assert_eq!(
                sum_validated_points(&points).map(|sum| sum.to_bytes()),
                Some(sequential_sum(&points)),
                "{count} keys with repeats"
            );
        }
    }

    #[test]
    fn fast_aggregate_verify_with_a_repeated_signer_still_verifies() {
        // Two signatures from the same key over one message aggregate to twice
        // its signature, which only verifies if the doubled key sum is right.
        let message = ethlambda_types::beacon::primitives::H256([9u8; 32]);
        let mut ikm = [0x33u8; 32];
        ikm[..8].copy_from_slice(&7u64.to_le_bytes());
        let secret = blst::min_pk::SecretKey::key_gen(&ikm, &[]).unwrap();
        let pubkey = BlsPubkey(secret.sk_to_pk().to_bytes());
        let one = BlsSignature(secret.sign(message.as_slice(), DST, &[]).to_bytes());
        let signature = aggregate(&[one, one]).unwrap();
        assert!(fast_aggregate_verify(
            &[pubkey, pubkey],
            message,
            &signature
        ));
        assert!(!fast_aggregate_verify(&[pubkey], message, &signature));
    }

    /// `-P`, from `P`'s compressed encoding: flipping the sort flag (bit 5 of
    /// the first byte) picks the other `y` for the same `x`. Both are valid
    /// keys, so a registry can hold both: whoever holds `P`'s secret signs
    /// `-P`'s deposit with its negation.
    fn negated(pubkey: BlsPubkey) -> BlsPubkey {
        let mut bytes = pubkey.0;
        bytes[0] ^= 0b0010_0000;
        BlsPubkey(bytes)
    }

    #[test]
    fn a_key_and_its_negation_sum_to_the_identity_and_never_verify() {
        let pubkey = fresh_pubkey(7000);
        let pair = [pubkey, negated(pubkey)];
        assert!(key_validate(&pair[1]), "-P is a valid key");

        // Both paths sum to the identity, and `eth_aggregate_pubkeys` hands it
        // back as the spec's own pseudocode would.
        let points = validated_pubkeys(&pair).unwrap();
        assert_eq!(sequential_sum(&points), identity_pubkey().0);
        assert_eq!(eth_aggregate_pubkeys(&pair).unwrap(), identity_pubkey());

        // The identity's signature is G2's identity, which blst refuses to pair
        // against an identity key.
        let message = ethlambda_types::beacon::primitives::H256([5u8; 32]);
        let signature = BlsSignature(G2_POINT_AT_INFINITY);
        assert!(!fast_aggregate_verify(&pair, message, &signature));
        assert!(!eth_fast_aggregate_verify(&pair, message, &signature));
    }

    #[test]
    fn the_batched_sum_matches_the_sequential_one_when_keys_cancel() {
        // Cancelling pairs next to each other, and two halves that cancel each
        // other, either side of the thread-pool threshold.
        for count in [8u64, 200, 400, 1100] {
            let pubkeys: Vec<BlsPubkey> = (8000..8000 + count).map(fresh_pubkey).collect();

            let adjacent: Vec<BlsPubkey> = pubkeys
                .iter()
                .flat_map(|&pubkey| [pubkey, negated(pubkey)])
                .chain([pubkeys[0]])
                .collect();
            let halves: Vec<BlsPubkey> = pubkeys
                .iter()
                .copied()
                .chain(pubkeys.iter().map(|&pubkey| negated(pubkey)))
                .chain([pubkeys[1]])
                .collect();

            for (shape, run) in [("adjacent", adjacent), ("halves", halves)] {
                let points = validated_pubkeys(&run).unwrap();
                assert_eq!(
                    sum_validated_points(&points).map(|sum| sum.to_bytes()),
                    Some(sequential_sum(&points)),
                    "{count} cancelling pairs, {shape}"
                );
            }
        }
    }

    #[test]
    fn eth_aggregate_pubkeys_matches_the_sequential_sum_with_repeats() {
        let mut pubkeys: Vec<BlsPubkey> = (30..40).map(fresh_pubkey).collect();
        pubkeys.push(pubkeys[2]);
        pubkeys.push(pubkeys[2]);
        let points = validated_pubkeys(&pubkeys).unwrap();
        assert_eq!(
            eth_aggregate_pubkeys(&pubkeys).unwrap().0,
            sequential_sum(&points)
        );
    }

    #[test]
    fn the_cache_stops_growing_at_its_capacity() {
        // One entry per shard.
        let cache = PubkeyCache::new(PUBKEY_CACHE_SHARDS);
        let pubkeys: Vec<BlsPubkey> = (100..100 + 4 * PUBKEY_CACHE_SHARDS as u64)
            .map(fresh_pubkey)
            .collect();
        for pubkey in &pubkeys {
            let point = PublicKey::key_validate(pubkey.as_ref()).unwrap();
            cache.insert(pubkey, point);
            // Inserting the same key again must not take a second slot.
            cache.insert(pubkey, point);
        }
        assert!(cache.len() <= PUBKEY_CACHE_SHARDS);
        let held = pubkeys
            .iter()
            .filter(|pubkey| cache.get(*pubkey).is_some())
            .count();
        assert_eq!(held, cache.len());
    }

    /// The table slot for `index` in `cache`, if it holds anything.
    fn held_at(cache: &PubkeyCache, index: ValidatorIndex) -> Option<BlsPubkey> {
        cache
            .slot(index)
            .and_then(OnceLock::get)
            .map(|(bytes, _)| *bytes)
    }

    fn indexed(index: ValidatorIndex, seed: u64) -> IndexedPubkey {
        IndexedPubkey {
            index,
            pubkey: fresh_pubkey(seed),
        }
    }

    #[test]
    fn an_indexed_key_hits_the_table_after_warming_and_stays_out_of_the_map() {
        let cache = PubkeyCache::new(2 * INDEX_CHUNK_LEN);
        let key = indexed(INDEX_CHUNK_LEN as u64 + 3, 9001);
        assert!(cache.get(&key).is_none());

        let point = PublicKey::key_validate(key.pubkey.as_ref()).unwrap();
        cache.insert(&key, point);
        assert_eq!(
            cache.get(&key).map(|point| point.to_bytes()),
            Some(point.to_bytes())
        );
        assert_eq!(held_at(&cache, key.index), Some(key.pubkey));
        assert!(cache.get_by_bytes(&key.pubkey).is_none());
        assert_eq!(cache.len(), 1);
        // The same bytes with no index are not in the byte map, and the
        // answer through the global API is the same as a fresh validation.
        assert_eq!(
            validated_pubkey(&key).map(|point| point.to_bytes()),
            uncached(&key.pubkey)
        );
    }

    /// `fresh_pubkey(seed)`'s signature over `message`.
    fn fresh_signature(seed: u64, message: Root) -> BlsSignature {
        let mut ikm = [0xa5u8; 32];
        ikm[..8].copy_from_slice(&seed.to_le_bytes());
        let secret = blst::min_pk::SecretKey::key_gen(&ikm, &[]).unwrap();
        BlsSignature(secret.sign(message.as_slice(), DST, &[]).to_bytes())
    }

    #[test]
    fn a_different_key_at_a_warmed_index_falls_back_and_verifies() {
        let index = 3_000_001;
        let message = ethlambda_types::beacon::primitives::H256([5u8; 32]);
        let first = indexed(index, 9201);
        let second = indexed(index, 9202);
        assert!(key_validate(&first));
        assert_eq!(held_at(&VALIDATED_PUBKEYS, index), Some(first.pubkey));

        // Another state names a different key at the same index: the slot's
        // bytes differ, so it must not answer.
        assert!(VALIDATED_PUBKEYS.get(&second).is_none());
        assert!(verify(&second, message, &fresh_signature(9202, message)));
        assert!(!verify(&second, message, &fresh_signature(9201, message)));
        assert!(verify(&first, message, &fresh_signature(9201, message)));
        assert!(!verify(&first, message, &fresh_signature(9202, message)));

        // The slot kept its first writer; the loser lives in the byte map.
        assert_eq!(held_at(&VALIDATED_PUBKEYS, index), Some(first.pubkey));
        assert!(VALIDATED_PUBKEYS.get_by_bytes(&second.pubkey).is_some());
        assert!(VALIDATED_PUBKEYS.get_by_bytes(&first.pubkey).is_none());

        // An aggregate mixing the two states' keys verifies too.
        let signature = aggregate(&[
            fresh_signature(9201, message),
            fresh_signature(9202, message),
        ])
        .unwrap();
        assert!(fast_aggregate_verify(&[first, second], message, &signature));
    }

    #[test]
    fn a_cold_lookup_allocates_nothing() {
        let cache = PubkeyCache::new(2 * INDEX_CHUNK_LEN);
        let key = indexed(INDEX_CHUNK_LEN as u64 + 5, 9401);
        assert!(cache.get(&key).is_none());
        assert!(cache.chunks.iter().all(|chunk| chunk.get().is_none()));

        // Only a key that validated allocates its chunk, and only that one.
        let point = PublicKey::key_validate(key.pubkey.as_ref()).unwrap();
        cache.insert(&key, point);
        assert!(cache.chunks[0].get().is_none());
        assert!(cache.chunks[1].get().is_some());
    }

    #[test]
    fn a_byte_path_key_is_copied_into_the_table_on_its_first_index_lookup() {
        let cache = PubkeyCache::new(INDEX_CHUNK_LEN);
        let key = indexed(17, 9301);
        let point = PublicKey::key_validate(key.pubkey.as_ref()).unwrap();
        cache.insert(&key.pubkey, point);
        assert!(held_at(&cache, key.index).is_none());

        assert_eq!(
            cache.get(&key).map(|point| point.to_bytes()),
            Some(point.to_bytes())
        );
        assert_eq!(held_at(&cache, key.index), Some(key.pubkey));
        // Held in both: byte-path callers still hit.
        assert!(cache.get_by_bytes(&key.pubkey).is_some());
        assert_eq!(cache.len(), 2);

        // A slot holding other bytes is not overwritten by a promotion.
        let other = indexed(17, 9302);
        let other_point = PublicKey::key_validate(other.pubkey.as_ref()).unwrap();
        cache.insert(&other.pubkey, other_point);
        assert!(cache.get(&other).is_some());
        assert_eq!(held_at(&cache, 17), Some(key.pubkey));
    }

    #[test]
    fn an_index_past_the_bound_uses_the_map() {
        for index in [MAX_CACHED_PUBKEYS as u64, u64::MAX] {
            let key = indexed(index, 9100);
            assert!(VALIDATED_PUBKEYS.slot_or_allocate(index).is_none());
            for _ in 0..2 {
                assert_eq!(
                    validated_pubkey(&key).map(|point| point.to_bytes()),
                    uncached(&key.pubkey)
                );
            }
            assert!(VALIDATED_PUBKEYS.get_by_bytes(&key.pubkey).is_some());
        }
        // The last index inside the bound is served by the table.
        let last = MAX_CACHED_PUBKEYS as u64 - 1;
        let key = indexed(last, 9101);
        assert!(key_validate(&key));
        assert_eq!(held_at(&VALIDATED_PUBKEYS, last), Some(key.pubkey));
    }

    #[test]
    fn an_invalid_indexed_key_is_cached_nowhere() {
        let cache = PubkeyCache::new(INDEX_CHUNK_LEN);
        for (offset, invalid) in [BlsPubkey::default(), identity_pubkey()]
            .into_iter()
            .enumerate()
        {
            let key = IndexedPubkey {
                index: 3_100_000 + offset as u64,
                pubkey: invalid,
            };
            for _ in 0..2 {
                assert!(!key_validate(&key));
                assert!(!verify(
                    &key,
                    ethlambda_types::beacon::primitives::H256([0u8; 32]),
                    &BlsSignature::default()
                ));
                assert!(eth_aggregate_pubkeys(&[key]).is_err());
            }
            assert!(held_at(&VALIDATED_PUBKEYS, key.index).is_none());
            assert!(VALIDATED_PUBKEYS.get_by_bytes(&invalid).is_none());
            assert!(cache.get(&key).is_none());
        }
    }

    #[test]
    fn concurrent_readers_and_writers_agree_with_key_validate() {
        const KEYS: u64 = 48;
        const BASE: u64 = 3_200_000;
        let pubkeys: Vec<BlsPubkey> = (0..KEYS).map(|seed| fresh_pubkey(20_000 + seed)).collect();
        let expected: Vec<_> = pubkeys.iter().map(uncached).collect();

        std::thread::scope(|scope| {
            for thread in 0..8u64 {
                let pubkeys = &pubkeys;
                let expected = &expected;
                scope.spawn(move || {
                    for round in 0..20 {
                        for (position, pubkey) in pubkeys.iter().enumerate() {
                            // Even threads agree on one index per key; odd
                            // threads rotate, so every slot is contested by
                            // different bytes, and some pass no index at all.
                            let index = BASE + (position as u64 + thread * (thread % 2)) % KEYS;
                            let got = match (thread + round) % 3 {
                                0 => validated_pubkey(pubkey),
                                _ => validated_pubkey(&IndexedPubkey {
                                    index,
                                    pubkey: *pubkey,
                                }),
                            };
                            assert_eq!(got.map(|point| point.to_bytes()), expected[position]);
                        }
                    }
                });
            }
        });

        // Whoever won each slot, it holds a key that validates to its own point.
        for index in BASE..BASE + KEYS {
            if let Some(bytes) = held_at(&VALIDATED_PUBKEYS, index) {
                assert_eq!(
                    VALIDATED_PUBKEYS
                        .get(&IndexedPubkey {
                            index,
                            pubkey: bytes
                        })
                        .map(|point| point.to_bytes()),
                    uncached(&bytes)
                );
            }
        }
    }

    /// Builds a realistic attestation aggregate of `count` independent
    /// signers over one shared message: each signer gets its own
    /// `key_gen`-derived keypair and signs [`message`](Root) under this
    /// module's own [`DST`], the same DST [`fast_aggregate_verify`] checks
    /// against, and the resulting signatures are folded together with this
    /// module's own [`aggregate`], the same call a real caller makes to
    /// produce one. This mirrors the shape of an Electra attestation
    /// aggregate, where every attester signs identical attestation data.
    fn build_aggregate(count: usize) -> (Vec<BlsPubkey>, Root, BlsSignature) {
        let message = ethlambda_types::beacon::primitives::H256([7u8; 32]);
        let mut pubkeys = Vec::with_capacity(count);
        let mut signatures = Vec::with_capacity(count);
        for index in 0..count {
            // `key_gen` requires at least 32 bytes of input key material;
            // seeding it with the signer's index keeps every key distinct
            // and the whole aggregate reproducible run to run.
            let mut ikm = [0u8; 32];
            ikm[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
            let secret = blst::min_pk::SecretKey::key_gen(&ikm, &[])
                .expect("32 bytes of input material is enough for key generation");
            pubkeys.push(BlsPubkey(secret.sk_to_pk().to_bytes()));
            let signature = secret.sign(message.as_slice(), DST, &[]);
            signatures.push(BlsSignature(signature.to_bytes()));
        }
        let aggregated = aggregate(&signatures)
            .expect("every signature above comes from a fresh, valid keypair");
        (pubkeys, message, aggregated)
    }

    /// Wall-clock timing for [`fast_aggregate_verify`] at the scale a real
    /// Electra attestation aggregate reaches: hundreds to thousands of
    /// attesters behind one shared message. Prints, for each size, the time
    /// with every key a cache miss (validated in parallel) and then with every
    /// key a hit, so the two paths (or two machines) can be compared by hand;
    /// the `assert!`s also make this a correctness check, not only a
    /// stopwatch, since a bug that dropped or misaligned a key on either path
    /// would make the aggregate fail to verify.
    ///
    /// `#[ignore]`d for the same reason the crate's other slow crypto tests
    /// are: generating and signing thousands of real BLS keypairs, twice,
    /// dominates the run time and has no place in a default `cargo test`.
    #[test]
    #[ignore = "slow: generates and signs thousands of real BLS keypairs"]
    fn fast_aggregate_verify_key_validation_timing() {
        for count in [512usize, 2048] {
            let (pubkeys, message, signature) = build_aggregate(count);
            for pass in ["cold", "warm"] {
                let start = std::time::Instant::now();
                let result = fast_aggregate_verify(&pubkeys, message, &signature);
                let elapsed = start.elapsed();
                println!("fast_aggregate_verify, {count} signers, {pass} cache: {elapsed:?}");
                assert!(
                    result,
                    "a correctly-aggregated signature over {count} signers must verify ({pass})"
                );
            }
        }
    }

    /// Encodings `KeyValidate` must judge, with every way to fail: valid keys,
    /// the same keys with each flag bit flipped (no compression flag, a
    /// spurious infinity flag, the other `y`), the identity and malformed
    /// identities, an `x` at or past the field modulus, and random `x`
    /// coordinates, about half of which are on the curve and almost none of
    /// those in the subgroup.
    fn key_encodings_to_judge() -> Vec<[u8; BLS_PUBKEY_SIZE]> {
        use rand::RngExt;
        let mut rng = rand::rng();
        let mut encodings = Vec::new();
        for seed in 0..40 {
            let valid = fresh_pubkey(5000 + seed).0;
            encodings.push(valid);
            for flag in [0x80, 0x40, 0x20] {
                let mut flipped = valid;
                flipped[0] ^= flag;
                encodings.push(flipped);
            }
            let mut last = valid;
            last[BLS_PUBKEY_SIZE - 1] ^= 1;
            encodings.push(last);
        }
        encodings.push(identity_pubkey().0);
        let mut noisy_identity = identity_pubkey().0;
        noisy_identity[BLS_PUBKEY_SIZE - 1] = 1;
        encodings.push(noisy_identity);
        encodings.push([0; BLS_PUBKEY_SIZE]);
        encodings.push([0xff; BLS_PUBKEY_SIZE]);
        let mut past_modulus = [0xff; BLS_PUBKEY_SIZE];
        past_modulus[0] = 0x9f;
        encodings.push(past_modulus);
        for _ in 0..200 {
            let mut random = [0u8; BLS_PUBKEY_SIZE];
            rng.fill(&mut random[..]);
            random[0] = (random[0] & 0x1f) | 0x80;
            encodings.push(random);
        }
        encodings
    }

    /// The batch decoder, with its chunking and (on an IFMA CPU) its eight-lane
    /// kernel, gives `blst`'s `key_validate` verdict on every encoding, and so
    /// does the single-key path.
    #[test]
    fn key_decoding_agrees_with_blst_on_valid_and_corrupt_encodings() {
        let encodings = key_encodings_to_judge();
        assert!(encodings.len() > 2 * KEY_DECODE_CHUNK);
        let reference: Vec<Option<[u8; BLS_PUBKEY_SIZE]>> = encodings
            .iter()
            .map(|bytes| PublicKey::key_validate(bytes).ok().map(|p| p.to_bytes()))
            .collect();
        assert!(reference.iter().any(Option::is_some));
        assert!(reference.iter().filter(|r| r.is_none()).count() > encodings.len() / 2);

        let batch = decode_pubkeys(&encodings);
        for (index, bytes) in encodings.iter().enumerate() {
            let batched = batch[index].map(|p| p.to_bytes());
            let single = decode_pubkey(bytes).map(|p| p.to_bytes());
            assert_eq!(
                batched, reference[index],
                "batch, encoding {index}: {bytes:02x?}"
            );
            assert_eq!(
                single, reference[index],
                "single, encoding {index}: {bytes:02x?}"
            );
        }
    }

    /// The G2 decoder gives `blst`'s `sig_validate(_, false)` verdict on valid
    /// signatures, corrupted ones, the identity and random `x` coordinates,
    /// alone and in batches long enough for the eight-lane kernel.
    #[test]
    fn signature_decoding_agrees_with_blst_on_valid_and_corrupt_encodings() {
        use rand::RngExt;
        let mut rng = rand::rng();
        let (_, _, aggregate) = build_aggregate(3);
        let mut encodings = Vec::new();
        for seed in 0..24u8 {
            let ikm = [seed.wrapping_add(7); 32];
            let secret = blst::min_pk::SecretKey::key_gen(&ikm, &[]).unwrap();
            let valid = secret.sign(&[seed; 32], DST, &[]).to_bytes();
            encodings.push(valid);
            for flag in [0x80, 0x40, 0x20] {
                let mut flipped = valid;
                flipped[0] ^= flag;
                encodings.push(flipped);
            }
            let mut last = valid;
            last[BLS_SIGNATURE_SIZE - 1] ^= 1;
            encodings.push(last);
        }
        encodings.push(aggregate.0);
        encodings.push(G2_POINT_AT_INFINITY);
        let mut noisy_infinity = G2_POINT_AT_INFINITY;
        noisy_infinity[BLS_SIGNATURE_SIZE - 1] = 1;
        encodings.push(noisy_infinity);
        encodings.push([0; BLS_SIGNATURE_SIZE]);
        for _ in 0..64 {
            let mut random = [0u8; BLS_SIGNATURE_SIZE];
            rng.fill(&mut random[..]);
            random[0] = (random[0] & 0x1f) | 0x80;
            encodings.push(random);
        }
        let reference: Vec<Option<[u8; BLS_SIGNATURE_SIZE]>> = encodings
            .iter()
            .map(|bytes| {
                Signature::sig_validate(bytes, false)
                    .ok()
                    .map(|s| s.to_bytes())
            })
            .collect();
        assert!(reference.iter().any(Option::is_some));
        assert!(reference.iter().any(Option::is_none));

        let to_bytes = |point: G2Point| Signature::from(point.into_blst()).to_bytes();
        let mut batch = vec![None; encodings.len()];
        uncompress_in_g2(&encodings, &mut batch);
        for (index, bytes) in encodings.iter().enumerate() {
            let single = decode_signature(&BlsSignature(*bytes)).map(to_bytes);
            let batched = batch[index].map(to_bytes);
            assert_eq!(batched, reference[index], "batch, encoding {index}");
            assert_eq!(single, reference[index], "single, encoding {index}");
        }
    }

    /// `n` keypairs, distinct per `(tag, n)`, as secrets and as encodings.
    fn keypairs(tag: u64, n: usize) -> (Vec<blst::min_pk::SecretKey>, Vec<BlsPubkey>) {
        let secrets: Vec<blst::min_pk::SecretKey> = (0..n as u64)
            .map(|i| {
                let mut ikm = [0x3cu8; 32];
                ikm[..8].copy_from_slice(&(tag * 1000 + i).to_le_bytes());
                blst::min_pk::SecretKey::key_gen(&ikm, &[]).unwrap()
            })
            .collect();
        let pubkeys = secrets
            .iter()
            .map(|secret| BlsPubkey(secret.sk_to_pk().to_bytes()))
            .collect();
        (secrets, pubkeys)
    }

    fn sign(secret: &blst::min_pk::SecretKey, message: Root) -> BlsSignature {
        BlsSignature(secret.sign(message.as_slice(), DST, &[]).to_bytes())
    }

    /// `verify`, `fast_aggregate_verify` and `aggregate_verify` give the answer
    /// `blst`'s own checks give, over valid inputs, wrong messages, short
    /// aggregates, the identity signature, and signer counts on both sides of
    /// the pairing kernel's eight lanes.
    #[test]
    fn verification_agrees_with_blst() {
        use blst::BLST_ERROR::BLST_SUCCESS;
        use ethlambda_types::beacon::primitives::H256;

        let message = H256([0x51; 32]);
        let other = H256([0x52; 32]);
        let infinity = BlsSignature(G2_POINT_AT_INFINITY);
        let blst_sig = |s: &BlsSignature| Signature::sig_validate(s.as_ref(), false).unwrap();
        for count in [1usize, 2, 7, 8, 9, 17] {
            let (secrets, pubkeys) = keypairs(count as u64, count);
            let blst_keys: Vec<PublicKey> = secrets.iter().map(|s| s.sk_to_pk()).collect();
            let key_refs: Vec<&PublicKey> = blst_keys.iter().collect();
            let shares: Vec<BlsSignature> = secrets.iter().map(|s| sign(s, message)).collect();
            let good = aggregate(&shares).unwrap();
            let short = match count {
                1 => infinity,
                _ => aggregate(&shares[1..]).unwrap(),
            };

            let cases = [
                (good, message),
                (good, other),
                (short, message),
                (infinity, message),
            ];
            for (signature, msg) in cases {
                let theirs = blst_sig(&signature).fast_aggregate_verify(
                    false,
                    msg.as_slice(),
                    DST,
                    &key_refs,
                ) == BLST_SUCCESS;
                let ours = fast_aggregate_verify(&pubkeys, msg, &signature);
                assert_eq!(ours, theirs, "fast_aggregate_verify, {count} signers");
            }
            for ((pubkey, secret), point) in pubkeys.iter().zip(&secrets).zip(&blst_keys) {
                let own = sign(secret, message);
                for (signature, msg) in [(own, message), (own, other), (infinity, message)] {
                    let theirs =
                        blst_sig(&signature).verify(false, msg.as_slice(), DST, &[], point, false)
                            == BLST_SUCCESS;
                    assert_eq!(verify(pubkey, msg, &signature), theirs, "verify");
                }
            }

            // Distinct messages, one per signer, and the same messages rotated.
            let messages: Vec<Root> = (0..count).map(|i| H256([i as u8; 32])).collect();
            let distinct: Vec<BlsSignature> = secrets
                .iter()
                .zip(&messages)
                .map(|(secret, msg)| sign(secret, *msg))
                .collect();
            let combined = aggregate(&distinct).unwrap();
            let mut rotated = messages.clone();
            rotated.rotate_left(1);
            for msgs in [&messages, &rotated] {
                let message_refs: Vec<&[u8]> = msgs.iter().map(Root::as_slice).collect();
                let theirs = blst_sig(&combined).aggregate_verify(
                    false,
                    &message_refs,
                    DST,
                    &key_refs,
                    false,
                ) == BLST_SUCCESS;
                let ours = aggregate_verify(&pubkeys, msgs, &combined);
                assert_eq!(ours, theirs, "aggregate_verify, {count} signers");
            }
        }
    }
}
