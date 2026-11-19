//! leanXMSS, the hash-based signature scheme the Beacon Chain's PQ fork signs
//! with (the specification's `xmss` module: `Sign`, `Verify`, `GetLeafIndex`).
//!
//! **Not** the XMSS that lean consensus signs with ([`crate::signature`]). That
//! one is leanVM's own scheme over BLAKE2s, with 1208-byte signatures. This one
//! is the note "leanXMSS for Ethereum PQ-Consensus" over Keccak-256, with 32-byte
//! public keys and 2404-byte signatures, which is what consensus-specs' `pq`
//! feature names, through EthLib's `EthLib/Cryptography/Xmss`.
//!
//! Ported from leanVM's Rust implementation of that note,
//! `crates/signatures/src/lean_xmss` and `crates/signatures/src/tweak.rs` at
//! `4af2cdddd7cd41b9df2cc7e123e314a91b0b4462` (MIT), the commit EthLib's README
//! cites as the note's source. Ported rather than depended on: this workspace's
//! `leanvm` pin predates that crate, and a second leanVM revision in the graph
//! would bring a second copy of its proving stack along for ~300 lines of hashing.
//! The known-answer tests below pin the bytes against both leanVM's and
//! consensus-specs' own vectors, so a drift in either copy shows up here.
//!
//! # The scheme
//!
//! A key is two layers of Merkle trees of height 16 whose leaves are WOTS+C
//! one-time keys. The top layer is one tree, whose root is the public key; the
//! bottom layer is `2^16` trees, and top key `b` signs the root of bottom tree
//! `b`. A message is signed by a key of a bottom tree, so a key signs at `2^32`
//! leaf indices, each at most once, ever. A signature carries its leaf index in
//! its first four bytes, little endian.
//!
//! Every hash is the tweakable hash `Th(P, A, M) = Keccak256(P | A | M)`
//! truncated to 16 bytes, `P` the key's 16-byte public parameter and `A` a
//! 16-byte address naming where in the key the call happens.
//!
//! # Signing twice at one leaf breaks the key
//!
//! Nothing here records which leaf indices a key has signed at. The PQ fork
//! assigns every message type its own leaf (`compute_xmss_leaf_index`), and the
//! caller must never sign two different messages at one leaf.

use std::sync::{Arc, Mutex};

use rayon::prelude::*;
use sha3::{Digest as _, Keccak256};

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

/// `n`: hash value and Merkle node length, in bytes.
const N: usize = 16;
type Digest = [u8; N];

const PUBLIC_PARAM_LEN: usize = 16;
type PublicParam = [u8; PUBLIC_PARAM_LEN];

const ADDRESS_LEN: usize = 16;

/// The seed every secret is derived from: the whole secret key.
pub const SEED_LEN: usize = 32;
pub type Seed = [u8; SEED_LEN];

/// Hashed before the seed, so no other scheme derives from the same bytes.
const SEED_TAG: &[u8] = b"leanXMSS";

/// The randomizer a layer's message digest is computed under.
const RANDOMIZER_LEN: usize = 16;
type Randomizer = [u8; RANDOMIZER_LEN];

/// The message a key signs: a 32-byte signing root.
pub const MESSAGE_LEN: usize = 32;
pub type Message = [u8; MESSAGE_LEN];

/// The leaf a signature uses: its top 16 bits name the bottom tree, its low 16
/// bits the leaf in it.
pub type LeafIndex = u32;

/// `w`: digit size in bits.
const W: usize = 2;
/// `2^w`: one more than the steps of a hash chain.
const CHAIN_LEN: usize = 1 << W;
/// The digest's digits: 128 bits of base `2^w`.
const DIGITS: usize = 8 * N / W;
/// The last digits, which the signer grinds to zero, so they have no chain.
const ZERO_DIGITS: usize = 6;
/// `v`: the chains of a one-time key.
const V: usize = DIGITS - ZERO_DIGITS;
/// `T`: the sum of every codeword's `v` digits.
const TARGET_SUM: usize = 106;
/// Randomizers tried per layer signature before signing gives up.
const MAX_RANDOMIZER_TRIALS: u64 = 1 << 32;
/// Randomizer trials searched per parallel dispatch: the first hit is expected
/// after about `2^20`, and a batch has to be small for the search to stop near it.
const GRIND_BATCH: u64 = 1 << 14;

/// Height of each layer's tree.
const LAYER_HEIGHT: usize = 16;

/// The encoded public key: the top tree's root, then the public parameter.
pub const PUBKEY_SIZE: usize = N + PUBLIC_PARAM_LEN;
/// The encoded leaf index a signature starts with.
pub const LEAF_INDEX_SIZE: usize = size_of::<LeafIndex>();
/// One layer's signature: the randomizer, the chain values and the path.
const LAYER_SIG_SIZE: usize = RANDOMIZER_LEN + V * N + LAYER_HEIGHT * N;
/// The leaf index, then the bottom layer's signature, then the top one's.
pub const SIGNATURE_SIZE: usize = LEAF_INDEX_SIZE + 2 * LAYER_SIG_SIZE;

const _: () = assert!(V == 58 && TARGET_SUM < V * (CHAIN_LEN - 1));
const _: () = assert!(PUBKEY_SIZE == 32 && LAYER_SIG_SIZE == 1200 && SIGNATURE_SIZE == 2404);
const _: () = assert!(2 * LAYER_HEIGHT == 8 * LEAF_INDEX_SIZE);

// ---------------------------------------------------------------------------
// The tweakable hash
// ---------------------------------------------------------------------------

// Hash types: the low five bits of an address's eighth byte.
const TWEAK_PRF: u8 = 0;
const TWEAK_CHAIN: u8 = 1;
const TWEAK_LEAF: u8 = 2;
const TWEAK_NODE: u8 = 3;
const TWEAK_PARAMETER: u8 = 5;
const TWEAK_RANDOMIZER: u8 = 7;
const TWEAK_MSG: u8 = 12;
/// A node outside a range key's leaves (see [`range_key`]).
const TWEAK_FILLER: u8 = 13;

/// The top layer's flag in an address's `hi` field: the two layers share one
/// public parameter, so the address is what separates them.
const TOP: u32 = 1 << 23;

/// The address of a hash call: its type, a chain step, and two fields,
/// `hi < 2^24` and `lo`.
#[derive(Clone, Copy)]
struct Tweak {
    t: u8,
    step: u8,
    hi: u32,
    lo: u32,
}

fn tweak(t: u8, hi: u32, lo: u32) -> Tweak {
    debug_assert!(t < 32 && hi < 1 << 24);
    Tweak { t, step: 0, hi, lo }
}

impl Tweak {
    /// The same address at chain step `step < 8`.
    fn step(self, step: usize) -> Self {
        debug_assert!(step < 8);
        Self {
            step: step as u8,
            ..self
        }
    }

    /// `[lo:4 | hi:3 | t + 32 step:1 | zero:8]`, the fields little endian.
    fn address(self) -> [u8; ADDRESS_LEN] {
        let mut out = [0u8; ADDRESS_LEN];
        out[..4].copy_from_slice(&self.lo.to_le_bytes());
        out[4..7].copy_from_slice(&self.hi.to_le_bytes()[..3]);
        out[7] = self.t | (self.step << 5);
        out
    }
}

/// `hi` for `field` on `layer` (0 the bottom, 1 the top).
fn layer_hi(layer: usize, field: u32) -> u32 {
    field | (layer as u32 * TOP)
}

/// A Keccak-256 hasher that has absorbed `P | A`.
fn hasher(pp: &PublicParam, tw: Tweak) -> Keccak256 {
    let mut hasher = Keccak256::new();
    hasher.update(pp);
    hasher.update(tw.address());
    hasher
}

fn truncate(output: &[u8]) -> Digest {
    output[..N]
        .try_into()
        .expect("a Keccak-256 output is 32 bytes")
}

/// `Th` over a byte payload.
fn th(pp: &PublicParam, tw: Tweak, payload: &[u8]) -> Digest {
    let mut hasher = hasher(pp, tw);
    hasher.update(payload);
    truncate(&hasher.finalize())
}

/// `Th` over a concatenation of digests: a Merkle node or a leaf.
fn th_digests(pp: &PublicParam, tw: Tweak, values: &[Digest]) -> Digest {
    th(pp, tw, values.as_flattened())
}

/// Two secrets for one hash: the two halves of the untruncated hash of the seed.
fn th_pair(pp: &PublicParam, tw: Tweak, seed: &Seed) -> [Digest; 2] {
    let mut hasher = hasher(pp, tw);
    hasher.update(seed);
    let output = hasher.finalize();
    [truncate(&output[..N]), truncate(&output[N..])]
}

/// The seed every secret derives from: `H("leanXMSS" | S_0)`.
fn scheme_seed(seed: &Seed) -> Seed {
    let mut hasher = Keccak256::new();
    hasher.update(SEED_TAG);
    hasher.update(seed);
    hasher.finalize().into()
}

/// The public parameter, derived from the scheme seed under `P = 0`.
fn public_param(seed: &Seed) -> PublicParam {
    th(&[0; PUBLIC_PARAM_LEN], tweak(TWEAK_PARAMETER, 0, 0), seed)
}

// ---------------------------------------------------------------------------
// WOTS+C
// ---------------------------------------------------------------------------

/// The index of `leaf_index`'s one-time key on `layer`: the leaf index itself at
/// the bottom, the bottom tree's index at the top.
fn layer_index(leaf_index: LeafIndex, layer: usize) -> u32 {
    (u64::from(leaf_index) >> (layer * LAYER_HEIGHT)) as u32
}

/// `leaf_index`'s leaf within its bottom tree.
fn tree_leaf(leaf_index: LeafIndex) -> u32 {
    leaf_index & ((1 << LAYER_HEIGHT) - 1)
}

/// The starts of the `v` chains of key `e` on `layer`. One hash of the seed gives
/// two of them: chains `2t` and `2t + 1` are its two halves.
fn wots_secrets(pp: &PublicParam, seed: &Seed, layer: usize, e: u32) -> [Digest; V] {
    let mut secrets = [[0u8; N]; V];
    for (t, pair) in secrets.as_chunks_mut::<2>().0.iter_mut().enumerate() {
        *pair = th_pair(pp, tweak(TWEAK_PRF, layer_hi(layer, t as u32), e), seed);
    }
    secrets
}

/// `steps` steps of chain `i` from position `start`. A step's address carries the
/// position it leaves, and the chain index rides after the value, so the address
/// is the same for every chain of a key.
fn chain(
    pp: &PublicParam,
    layer: usize,
    e: u32,
    i: usize,
    start: usize,
    steps: usize,
    value: Digest,
) -> Digest {
    debug_assert!(start + steps < CHAIN_LEN);
    let address = tweak(TWEAK_CHAIN, layer_hi(layer, 0), e);
    (start..start + steps).fold(value, |current, from| {
        th_digests(
            pp,
            address.step(from),
            &[current, (i as u128).to_le_bytes()],
        )
    })
}

/// The Merkle leaf of a one-time key: `Th` over its `v` chain ends.
fn wots_leaf_hash(pp: &PublicParam, layer: usize, e: u32, ends: &[Digest; V]) -> Digest {
    th_digests(pp, tweak(TWEAK_LEAF, layer_hi(layer, 0), e), ends)
}

/// `P | A | M`, the hasher a randomizer trial continues.
fn digest_prefix(pp: &PublicParam, layer: usize, e: u32, message: &[u8]) -> Keccak256 {
    let mut prefix = hasher(pp, tweak(TWEAK_MSG, layer_hi(layer, 0), e));
    prefix.update(message);
    prefix
}

/// The digest key `e` on `layer` signs: `Th(P, A, M | R)`, `M` the message at the
/// bottom and the bottom root at the top.
fn message_digest(
    pp: &PublicParam,
    layer: usize,
    e: u32,
    randomizer: &Randomizer,
    message: &[u8],
) -> Digest {
    let mut hasher = digest_prefix(pp, layer, e, message);
    hasher.update(randomizer);
    truncate(&hasher.finalize())
}

/// The digest's first `v` digits, if it is a codeword: its last `ZERO_DIGITS`
/// digits zero and the other `v` summing to `T`.
fn codeword(digest: &Digest) -> Option<[u8; V]> {
    let d = u128::from_le_bytes(*digest);
    let x: [u8; V] = std::array::from_fn(|i| ((d >> (W * i)) & (CHAIN_LEN as u128 - 1)) as u8);
    let sum: usize = x.iter().map(|&digit| usize::from(digit)).sum();
    (d >> (W * V) == 0 && sum == TARGET_SUM).then_some(x)
}

/// `Ots.sign`: the randomizer of the least admissible trial `R_0 + c`, `R_0` a
/// hash of the seed and the message, and the chain value each digit opens.
/// Deterministic in its inputs, so signing one message again gives the same
/// signature and a key never opens two codewords.
fn wots_sign(
    pp: &PublicParam,
    seed: &Seed,
    layer: usize,
    e: u32,
    message: &[u8],
) -> Option<(Randomizer, [Digest; V])> {
    let base = {
        let mut hasher = hasher(pp, tweak(TWEAK_RANDOMIZER, layer_hi(layer, 0), e));
        hasher.update(seed);
        hasher.update(message);
        u128::from_le_bytes(truncate(&hasher.finalize()))
    };
    let trial = |c: u64| base.wrapping_add(u128::from(c)).to_le_bytes();
    let prefix = digest_prefix(pp, layer, e, message);
    let admits = |c: u64| {
        let mut hasher = prefix.clone();
        hasher.update(trial(c));
        codeword(&truncate(&hasher.finalize())).is_some()
    };
    let c = (0..MAX_RANDOMIZER_TRIALS)
        .step_by(GRIND_BATCH as usize)
        .find_map(|start| {
            (start..start + GRIND_BATCH)
                .into_par_iter()
                .find_first(|&c| admits(c))
        })?;
    let randomizer = trial(c);
    let x = codeword(&message_digest(pp, layer, e, &randomizer, message))?;
    let secrets = wots_secrets(pp, seed, layer, e);
    let values = std::array::from_fn(|i| chain(pp, layer, e, i, 0, usize::from(x[i]), secrets[i]));
    Some((randomizer, values))
}

/// `Ots.leaf`: the leaf a claimed signature recovers, or `None` if the digest is
/// not a codeword.
fn wots_leaf(
    pp: &PublicParam,
    layer: usize,
    e: u32,
    message: &[u8],
    randomizer: &Randomizer,
    values: &[Digest; V],
) -> Option<Digest> {
    let x = codeword(&message_digest(pp, layer, e, randomizer, message))?;
    let ends = std::array::from_fn(|i| {
        let start = usize::from(x[i]);
        chain(pp, layer, e, i, start, CHAIN_LEN - 1 - start, values[i])
    });
    Some(wots_leaf_hash(pp, layer, e, &ends))
}

/// The leaf of key `e` on `layer`, from the seed: what key generation spends its
/// hashes on.
fn wots_public_leaf(pp: &PublicParam, seed: &Seed, layer: usize, e: u32) -> Digest {
    let secrets = wots_secrets(pp, seed, layer, e);
    let ends = std::array::from_fn(|i| chain(pp, layer, e, i, 0, CHAIN_LEN - 1, secrets[i]));
    wots_leaf_hash(pp, layer, e, &ends)
}

// ---------------------------------------------------------------------------
// Trees
// ---------------------------------------------------------------------------

/// The Merkle parent at `level` and index `j` of `layer`.
fn node(pp: &PublicParam, layer: usize, level: usize, j: u32, children: &[Digest; 2]) -> Digest {
    th_digests(
        pp,
        tweak(TWEAK_NODE, layer_hi(layer, level as u32), j),
        children,
    )
}

fn filler(pp: &PublicParam, seed: &Seed, layer: usize, level: usize, j: u32) -> Digest {
    th(
        pp,
        tweak(TWEAK_FILLER, layer_hi(layer, level as u32), j),
        seed,
    )
}

/// One layer's Merkle tree, over the leaves `first..=last` of its `2^16`. A full
/// key's trees hold every leaf; a range key's hold its range, every node outside
/// it a pseudorandom filler.
struct LayerTree {
    layer: usize,
    /// The index of leaf 0 on its layer: the bottom tree's first leaf index, or 0.
    base: u32,
    first: u32,
    last: u32,
    /// Level `l` holds the nodes `first >> l ..= last >> l`.
    levels: Vec<Vec<Digest>>,
}

impl LayerTree {
    fn build(
        pp: &PublicParam,
        seed: &Seed,
        layer: usize,
        base: u32,
        first: u32,
        last: u32,
    ) -> Self {
        debug_assert!(first <= last && last >> LAYER_HEIGHT == 0);
        let leaves = (0..=(last - first))
            .into_par_iter()
            .map(|j| wots_public_leaf(pp, seed, layer, base + first + j))
            .collect();
        let mut tree = Self {
            layer,
            base,
            first,
            last,
            levels: vec![leaves],
        };
        for level in 1..=LAYER_HEIGHT {
            let start = first >> level;
            let up = (start..=(last >> level))
                .into_par_iter()
                .map(|j| {
                    let children = [
                        tree.at(pp, seed, level - 1, 2 * j),
                        tree.at(pp, seed, level - 1, 2 * j + 1),
                    ];
                    node(pp, layer, level, (base >> level) + j, &children)
                })
                .collect();
            tree.levels.push(up);
        }
        tree
    }

    /// Node `j` of `level`, stored if it is over a leaf in range, else a filler.
    fn at(&self, pp: &PublicParam, seed: &Seed, level: usize, j: u32) -> Digest {
        if (self.first >> level..=self.last >> level).contains(&j) {
            self.levels[level][(j - (self.first >> level)) as usize]
        } else {
            filler(pp, seed, self.layer, level, (self.base >> level) + j)
        }
    }

    fn root(&self) -> Digest {
        self.levels[LAYER_HEIGHT][0]
    }

    fn path(&self, pp: &PublicParam, seed: &Seed, leaf: u32) -> [Digest; LAYER_HEIGHT] {
        debug_assert!((self.first..=self.last).contains(&leaf));
        std::array::from_fn(|level| self.at(pp, seed, level, (leaf >> level) ^ 1))
    }
}

// ---------------------------------------------------------------------------
// Keys and signatures
// ---------------------------------------------------------------------------

/// A public key: the top tree's root followed by the public parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey {
    merkle_root: Digest,
    public_param: PublicParam,
}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8; PUBKEY_SIZE]) -> Self {
        let (merkle_root, public_param) = bytes.split_at(N);
        Self {
            merkle_root: merkle_root.try_into().expect("split at N"),
            public_param: public_param.try_into().expect("the rest is N bytes"),
        }
    }

    pub fn to_bytes(&self) -> [u8; PUBKEY_SIZE] {
        let mut out = [0u8; PUBKEY_SIZE];
        out[..N].copy_from_slice(&self.merkle_root);
        out[N..].copy_from_slice(&self.public_param);
        out
    }
}

/// One layer's signature: the randomizer, the value each digit opens, and the
/// authentication path.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LayerSignature {
    randomizer: Randomizer,
    chain_values: [Digest; V],
    path: [Digest; LAYER_HEIGHT],
}

impl LayerSignature {
    fn append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.randomizer);
        for value in self.chain_values.iter().chain(&self.path) {
            buf.extend_from_slice(value);
        }
    }
}

/// A signature. It carries the leaf index it was made at, so a verifier needs
/// only the key and the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    leaf_index: LeafIndex,
    bottom: LayerSignature,
    top: LayerSignature,
}

/// Peels fixed-size fields off a buffer whose length was checked up front.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take<const L: usize>(&mut self) -> [u8; L] {
        let (head, tail) = self.0.split_at(L);
        self.0 = tail;
        head.try_into().expect("split at L")
    }

    fn layer(&mut self) -> LayerSignature {
        LayerSignature {
            randomizer: self.take(),
            chain_values: std::array::from_fn(|_| self.take()),
            path: std::array::from_fn(|_| self.take()),
        }
    }
}

impl Signature {
    /// Decodes a signature. Every string of exactly [`SIGNATURE_SIZE`] bytes is
    /// one, since all its fields are fixed-size; any other length is `None`.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SIGNATURE_SIZE {
            return None;
        }
        let mut reader = Reader(bytes);
        Some(Self {
            leaf_index: LeafIndex::from_le_bytes(reader.take()),
            bottom: reader.layer(),
            top: reader.layer(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SIGNATURE_SIZE);
        buf.extend_from_slice(&self.leaf_index.to_le_bytes());
        self.bottom.append(&mut buf);
        self.top.append(&mut buf);
        buf
    }

    pub fn leaf_index(&self) -> LeafIndex {
        self.leaf_index
    }
}

/// The root `signature`'s layer reaches from key `e`, or `None` if its digest is
/// not a codeword.
fn layer_root(
    pp: &PublicParam,
    layer: usize,
    e: u32,
    message: &[u8],
    signature: &LayerSignature,
) -> Option<Digest> {
    let leaf = wots_leaf(
        pp,
        layer,
        e,
        message,
        &signature.randomizer,
        &signature.chain_values,
    )?;
    let root = signature
        .path
        .iter()
        .enumerate()
        .fold(leaf, |current, (level, sibling)| {
            let children = if (e >> level) & 1 == 0 {
                [current, *sibling]
            } else {
                [*sibling, current]
            };
            node(pp, layer, level + 1, e >> (level + 1), &children)
        });
    Some(root)
}

/// Whether `signature` signs `message` under `pubkey`, at the leaf index the
/// signature itself carries.
pub fn verify_signature(pubkey: &PublicKey, message: &Message, signature: &Signature) -> bool {
    let pp = &pubkey.public_param;
    let leaf_index = signature.leaf_index;
    let Some(bottom_root) = layer_root(
        pp,
        0,
        layer_index(leaf_index, 0),
        message,
        &signature.bottom,
    ) else {
        return false;
    };
    layer_root(
        pp,
        1,
        layer_index(leaf_index, 1),
        &bottom_root,
        &signature.top,
    )
    .is_some_and(|root| root == pubkey.merkle_root)
}

/// The specification's `xmss.Verify(pubkey, leaf_index, message, signature)`:
/// `true` only if `signature` signs `message` under `pubkey` and was made at
/// `leaf_index`.
///
/// A leaf index past `u32::MAX` never verifies: a signature carries four bytes
/// of it. Neither does a signature of the wrong length, the way the reference
/// implementation's decoding failure reads as `False`.
pub fn verify(
    pubkey: &[u8; PUBKEY_SIZE],
    leaf_index: u64,
    message: &Message,
    signature: &[u8],
) -> bool {
    let Some(signature) = Signature::from_bytes(signature) else {
        return false;
    };
    if u64::from(signature.leaf_index) != leaf_index {
        return false;
    }
    verify_signature(&PublicKey::from_bytes(pubkey), message, &signature)
}

/// The specification's `xmss.GetLeafIndex(signature)`: the leaf index a
/// signature carries, its first four bytes as a little-endian integer, read
/// without verifying anything else.
///
/// `None` for fewer than four bytes; the fork's `XMSSSignature` is a fixed
/// 2404-byte vector, so a consensus caller never sees it.
pub fn signature_index(signature: &[u8]) -> Option<u64> {
    let bytes = signature.get(..LEAF_INDEX_SIZE)?;
    let bytes: [u8; LEAF_INDEX_SIZE] = bytes.try_into().expect("sliced to LEAF_INDEX_SIZE");
    Some(u64::from(LeafIndex::from_le_bytes(bytes)))
}

/// Why signing failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignError {
    /// No randomizer within the trial limit made a layer's digest a codeword.
    /// The note bounds the probability of this below `exp(-4000)`.
    #[error("no admissible encoding within the randomizer trial limit")]
    NoAdmissibleEncoding,
    /// The leaf index is outside the leaves a range key covers.
    #[error("leaf index {0} is outside the key's range")]
    OutOfRange(LeafIndex),
}

struct BottomTree {
    index: u32,
    tree: LayerTree,
    top_signature: LayerSignature,
}

/// How many bottom trees a key keeps built. Two: a validator on the PQ fork
/// signs its attestations in one bottom tree (leaves `2^15 + epoch`) and its
/// per-slot messages (proposals, aggregates, payload attestations) in another,
/// so one cached tree would be rebuilt, about a second and a half of hashing,
/// on nearly every signature.
const BOTTOM_TREES_CACHED: usize = 2;

/// A secret key: the seed, the top tree, and the bottom trees it last signed in.
///
/// Holding the top tree is what makes signing cost one bottom tree rather than
/// both layers: key generation builds `2^16` one-time keys, about a second of
/// hashing, so a key is generated once per process and kept.
pub struct SecretKey {
    /// [`scheme_seed`] of the key's seed, which every secret derives from.
    seed: Seed,
    public_param: PublicParam,
    /// The leaf indices the key's trees hold: every one for a full key.
    leaves: std::ops::RangeInclusive<LeafIndex>,
    top: LayerTree,
    /// Most recently used last, at most [`BOTTOM_TREES_CACHED`].
    bottom: Mutex<Vec<Arc<BottomTree>>>,
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretKey")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

/// The key over the leaf indices `leaves`; nodes over no leaf in it are fillers.
fn generate(key_seed: &Seed, leaves: std::ops::RangeInclusive<LeafIndex>) -> SecretKey {
    let seed = scheme_seed(key_seed);
    let public_param = public_param(&seed);
    let first = layer_index(*leaves.start(), 1);
    let last = layer_index(*leaves.end(), 1);
    let top = LayerTree::build(&public_param, &seed, 1, 0, first, last);
    SecretKey {
        seed,
        public_param,
        leaves,
        top,
        bottom: Mutex::new(Vec::new()),
    }
}

/// The key a seed grows into: what EthLib's `xmss.key_gen` returns. Generates the
/// whole top tree.
pub fn key_gen(seed: &Seed) -> SecretKey {
    generate(seed, 0..=LeafIndex::MAX)
}

/// A key that signs like the full key only over the leaf indices
/// `first..=last`, every node outside them a pseudorandom filler, for a fraction
/// of [`key_gen`]'s cost. For tests: its public key is not the full key's.
///
/// A seed must back **one** key: never a range key and the full key, nor two
/// range keys over different ranges. They share every one-time key but not
/// their bottom roots, so one top one-time key would sign two roots, and its
/// signatures would forge others.
pub fn range_key(seed: &Seed, first: LeafIndex, last: LeafIndex) -> SecretKey {
    assert!(first <= last, "an empty range");
    generate(seed, first..=last)
}

impl SecretKey {
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            merkle_root: self.top.root(),
            public_param: self.public_param,
        }
    }

    /// Signs `message` at `leaf_index`. Deterministic.
    ///
    /// Never sign two different messages at one leaf index. The first signature
    /// in a bottom tree builds that tree with rayon, so never sign from inside a
    /// rayon task.
    pub fn sign(&self, message: &Message, leaf_index: LeafIndex) -> Result<Signature, SignError> {
        if !self.leaves.contains(&leaf_index) {
            return Err(SignError::OutOfRange(leaf_index));
        }
        let bottom = self.bottom_tree(leaf_index)?;
        let (randomizer, chain_values) =
            wots_sign(&self.public_param, &self.seed, 0, leaf_index, message)
                .ok_or(SignError::NoAdmissibleEncoding)?;
        Ok(Signature {
            leaf_index,
            bottom: LayerSignature {
                randomizer,
                chain_values,
                path: bottom
                    .tree
                    .path(&self.public_param, &self.seed, tree_leaf(leaf_index)),
            },
            top: bottom.top_signature.clone(),
        })
    }

    /// The bottom tree `leaf_index` is in, with the top layer's signature of its
    /// root: the cached one, or built and cached.
    fn bottom_tree(&self, leaf_index: LeafIndex) -> Result<Arc<BottomTree>, SignError> {
        let index = layer_index(leaf_index, 1);
        {
            let mut cache = self
                .bottom
                .lock()
                .expect("the bottom-tree cache is never poisoned");
            if let Some(position) = cache.iter().position(|bottom| bottom.index == index) {
                let bottom = cache.remove(position);
                cache.push(Arc::clone(&bottom));
                return Ok(bottom);
            }
        }
        let (pp, seed) = (&self.public_param, &self.seed);
        let base = index << LAYER_HEIGHT;
        let first = (*self.leaves.start()).max(base) - base;
        let last = (*self.leaves.end()).min(base | tree_leaf(LeafIndex::MAX)) - base;
        let tree = LayerTree::build(pp, seed, 0, base, first, last);
        let (randomizer, chain_values) =
            wots_sign(pp, seed, 1, index, &tree.root()).ok_or(SignError::NoAdmissibleEncoding)?;
        let bottom = Arc::new(BottomTree {
            index,
            top_signature: LayerSignature {
                randomizer,
                chain_values,
                path: self.top.path(pp, seed, index),
            },
            tree,
        });
        let mut cache = self
            .bottom
            .lock()
            .expect("the bottom-tree cache is never poisoned");
        if cache.len() >= BOTTOM_TREES_CACHED {
            cache.remove(0);
        }
        cache.push(Arc::clone(&bottom));
        Ok(bottom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_bytes(text: &str) -> Vec<u8> {
        hex::decode(text).expect("valid hex in a test vector")
    }

    /// consensus-specs' `tests/core/pyspec/eth_consensus_specs/utils/xmss_kat.json`
    /// at the `pq` pin `ee867e912a7c4c47229e08332db7c5c9c4f4b129`: the vector its
    /// `test_xmss.py` checks EthLib's `xmss.verify` against.
    const KAT_LEAF_INDEX: u64 = 1;
    const KAT_MESSAGE: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
    const KAT_PUBKEY: &str = "3ae358d01b96d7ca6dd9dd5bc7683b860111dafedf7a9be6717c2100d622acf0";
    const KAT_SIGNATURE: &str = include_str!("../tests/fixtures/xmss_kat_signature.hex");

    fn kat() -> ([u8; PUBKEY_SIZE], Message, Vec<u8>) {
        let pubkey = hex_bytes(KAT_PUBKEY).try_into().unwrap();
        let message = hex_bytes(KAT_MESSAGE).try_into().unwrap();
        (pubkey, message, hex_bytes(KAT_SIGNATURE.trim()))
    }

    #[test]
    fn consensus_specs_known_answer_verifies() {
        let (pubkey, message, signature) = kat();
        assert_eq!(signature.len(), SIGNATURE_SIZE);
        assert!(verify(&pubkey, KAT_LEAF_INDEX, &message, &signature));
        assert_eq!(signature_index(&signature), Some(KAT_LEAF_INDEX));
    }

    /// The four negative cases of consensus-specs' `test_xmss.py`.
    #[test]
    fn consensus_specs_known_answer_rejections() {
        let (pubkey, message, signature) = kat();
        assert!(!verify(&pubkey, KAT_LEAF_INDEX + 1, &message, &signature));
        assert!(!verify(&pubkey, KAT_LEAF_INDEX, &[0; 32], &signature));
        let other: [u8; PUBKEY_SIZE] = [7; PUBKEY_SIZE];
        assert!(!verify(&other, KAT_LEAF_INDEX, &message, &signature));
        assert!(!verify(
            &pubkey,
            KAT_LEAF_INDEX,
            &message,
            &signature[..SIGNATURE_SIZE - 1]
        ));
    }

    /// leanVM's own known answer (`tests/signatures/lean_xmss.rs`,
    /// `known_answer`), the vector EthLib's README pins too: the seed
    /// `37 i + 11`, the message `7 i + 3`, the leaf `0xA5C37E19`. Generates the
    /// full key (2^16 one-time keys) and a bottom tree: under a second and a half
    /// of hashing across cores in the `release-fast` profile `make test` uses.
    #[test]
    fn lean_vm_known_answer() {
        let seed: Seed = std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
        let key = key_gen(&seed);
        let message: Message = std::array::from_fn(|i| (i * 7 + 3) as u8);
        let signature = key.sign(&message, 0xA5C3_7E19).unwrap();
        assert_eq!(
            hex::encode(key.public_key().to_bytes()),
            "4066673001949b6ff8b9299fd4ea17d28787ad501aafe4b64e2488107b5e3ec3"
        );
        let digest = Keccak256::digest(signature.to_bytes());
        assert_eq!(
            hex::encode(digest),
            "f10d62beec95e64e1477028252c2c8683695eab9d8787ad8fa722f47b5fd5234"
        );
        assert!(verify_signature(&key.public_key(), &message, &signature));
    }

    /// consensus-specs' known answer from the signing side: the seed
    /// `00 01 .. 1f` grows into the vector's public key, and signs its message
    /// at leaf 1 into its signature byte for byte.
    #[test]
    fn consensus_specs_known_answer_signs() {
        let (pubkey, message, signature) = kat();
        let seed: Seed = std::array::from_fn(|i| i as u8);
        let key = key_gen(&seed);
        assert_eq!(key.public_key().to_bytes(), pubkey);
        let signed = key.sign(&message, KAT_LEAF_INDEX as LeafIndex).unwrap();
        assert_eq!(signed.to_bytes(), signature);
    }

    /// The key ethpandaops' genesis tooling and Lighthouse give validator 0 of
    /// ethereum-package's default mnemonic: the seed is
    /// `sha256("leanxmss-seed" || sk)` of its EIP-2333 signing key
    /// (`m/12381/3600/0/0/0`), and the public key is the first 32 bytes of
    /// ethereum-package's `static_files/xmss-keys/e383db4eb96b6f02.bin`.
    #[test]
    fn ethereum_package_validator_zero() {
        let seed: Seed =
            hex_bytes("6d78e7072bfcbde1a75261f6e16772ea352de90462819cdc53e05f10d4700ad1")
                .try_into()
                .unwrap();
        let expected =
            hex_bytes("d7792e263b94cf0b7a9f70d8374c6d34a600b4247057d4079f810caff711c632");
        assert_eq!(key_gen(&seed).public_key().to_bytes().to_vec(), expected);
    }

    /// Alternating between two bottom trees keeps both built: after the first
    /// signature in each, signing costs one one-time key, not a tree.
    #[test]
    fn two_bottom_trees_stay_built() {
        let key = key_gen(&[3; SEED_LEN]);
        let message: Message = [9; 32];
        let attestation_leaf: LeafIndex = (1 << 15) + 7;
        let slot_leaf: LeafIndex = (1 << 30) + (1 << 16) + 8 * 100;
        let started = std::time::Instant::now();
        key.sign(&message, attestation_leaf).unwrap();
        key.sign(&message, slot_leaf).unwrap();
        let building = started.elapsed();
        let started = std::time::Instant::now();
        for offset in 0..4 {
            key.sign(&message, attestation_leaf + offset).unwrap();
            key.sign(&message, slot_leaf + offset).unwrap();
        }
        let cached = started.elapsed();
        assert!(
            cached < building / 4,
            "{cached:?} signing eight vs {building:?} building two"
        );
    }

    #[test]
    fn range_keys_sign_in_range() {
        let message: Message = std::array::from_fn(|i| (i * 3 + 7) as u8);
        // A range across two bottom trees.
        let start = (3 << LAYER_HEIGHT) - 2;
        let key = range_key(&[2; SEED_LEN], start, start + 5);
        let pubkey = key.public_key().to_bytes();
        for leaf_index in start..=start + 5 {
            let signature = key.sign(&message, leaf_index).unwrap().to_bytes();
            assert!(verify(&pubkey, u64::from(leaf_index), &message, &signature));
        }
        assert_eq!(
            key.sign(&message, start + 6),
            Err(SignError::OutOfRange(start + 6))
        );
        assert_eq!(
            range_key(&[2; SEED_LEN], start, start + 5).public_key(),
            key.public_key()
        );
    }

    /// The leaf index rides the signature, so the verifier hashes at it: moved
    /// to a neighbour, or the message changed, the signature no longer verifies.
    #[test]
    fn signature_is_bound_to_its_leaf_index_and_message() {
        let key = range_key(&[4; SEED_LEN], 0, 7);
        let pubkey = key.public_key();
        let message: Message = std::array::from_fn(|i| i as u8);
        let signature = key.sign(&message, 5).unwrap();
        let mut moved = signature.clone();
        moved.leaf_index = 4;
        assert!(!verify_signature(&pubkey, &message, &moved));
        let mut other = message;
        other[0] ^= 1;
        assert!(!verify_signature(&pubkey, &other, &signature));
        assert!(verify_signature(&pubkey, &message, &signature));
    }

    #[test]
    fn encoding_round_trips_and_is_exact() {
        let key = range_key(&[7; SEED_LEN], 290, 310);
        let message: Message = [9; MESSAGE_LEN];
        let signature = key.sign(&message, 300).unwrap();
        let bytes = signature.to_bytes();
        assert_eq!(bytes.len(), SIGNATURE_SIZE);
        assert_eq!(bytes[..LEAF_INDEX_SIZE], 300u32.to_le_bytes());
        assert_eq!(Signature::from_bytes(&bytes), Some(signature));
        assert_eq!(Signature::from_bytes(&bytes[1..]), None);
        let pubkey = key.public_key();
        assert_eq!(PublicKey::from_bytes(&pubkey.to_bytes()), pubkey);
    }

    #[test]
    fn a_leaf_index_past_32_bits_never_verifies() {
        let (pubkey, message, signature) = kat();
        assert!(!verify(
            &pubkey,
            KAT_LEAF_INDEX + (1 << 32),
            &message,
            &signature
        ));
    }
}
