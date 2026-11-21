//! The validator client on the PQ fork (`specs/_features/pq/validator.md`).
//!
//! At PQ a validator signs with leanXMSS and reveals RANDAO with a VRF proof,
//! both derived from its BLS signing key the way the PQ devnet's genesis
//! tooling registered them (`ethlambda_crypto::pq_keys`), so a keystore is
//! still all a validator needs. This module holds that material per key,
//! translates between a validator's BLS key and the form the PQ registry names
//! it by, and signs at the leaf each message is assigned.
//!
//! **The VRF tree.** The specification's tree has a leaf for each of `2^31`
//! slots, and every one must be hashed to reach the root a validator
//! registered: minutes of every core per key (`ethlambda_crypto::vrf`). Only
//! proposing needs it, so a key is registered and attests without one, and
//! [`prepare_vrf_tree`] hashes each tree afterwards, off the duty path. A
//! proposal that falls before its key's tree is ready is missed. The nodes a
//! tree keeps (1 MiB, commitments only) are written under
//! [`VRF_TREE_DIRECTORY`] in the validators directory, so a tree is hashed
//! once per key, not once per start.
//!
//! **The registry's form.** A PQ state names each validator by its 32-byte
//! XMSS key in the 48-byte form an execution-layer request names one: 16 zero
//! bytes, then the key. Duty responses carry that form, and no BLS key starts
//! with 16 zero bytes (its first byte carries the compression flag), so
//! [`bls_for_request_key`] maps one back to the local key that owns it, and
//! the client keeps working with BLS keys everywhere else.
//!
//! **Leaves.** XMSS is stateful: signing two messages at one leaf exposes it.
//! Every message has a leaf of its own (an attestation one per target epoch,
//! everything else one per slot and kind), so the slashing protection record
//! already covers blocks (one per slot) and attestations (one per target).
//! The other per-slot messages (payload attestations, aggregates, proposer
//! preferences, envelopes) are guarded here: one signing root per leaf, kept
//! in [`LEAF_RECORD_FILE`] under the validators directory and flushed to disk
//! before the signature exists, so a restart, however quick, cannot sign a
//! second message at a leaf (see [`open_leaf_record`]).

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use ethlambda_crypto::leanvm_lean_xmss::{self, LeanXmssExpandedSecretKey};
use ethlambda_crypto::{pq_keys, vrf};
use ethlambda_types::beacon::constants::{
    XMSS_ATTESTATION_LEAVES, XMSS_BUILDER_BID_LEAVES, XMSS_LEAVES_PER_SLOT, XMSS_RESERVED_LEAVES,
};
use ethlambda_types::beacon::primitives::{BlsPubkey, Epoch, Root, Slot, XmssSignature};
use tracing::warn;

pub use ethlambda_types::beacon::constants::{
    LEAF_OFFSET_AGGREGATE_AND_PROOF, LEAF_OFFSET_BEACON_PROPOSER,
    LEAF_OFFSET_EXECUTION_PAYLOAD_ENVELOPE, LEAF_OFFSET_PTC_ATTESTER,
};

/// The file under the validators directory that keeps every leaf this
/// client signed at and the root it signed there: [`LEAF_RECORD_SIZE`]-byte
/// records (the 48-byte BLS key, the leaf as a little-endian `u64`, the
/// signing root), appended and flushed before each first signature at a
/// leaf.
pub const LEAF_RECORD_FILE: &str = "pq_signed_leaves.bin";

const LEAF_RECORD_SIZE: usize = 48 + 8 + 32;

/// How many slots back [`open_leaf_record`] keeps a leaf. The client signs
/// only for the current slot, the next epoch's proposals' preferences and the
/// current target epoch, so a leaf two epochs old is never asked for again.
fn leaf_record_keep_slots() -> Slot {
    2 * ethlambda_types::beacon::preset::slots_per_epoch()
}

/// The directory under the validators directory that holds each key's VRF
/// tree nodes, one file per validator, named by its BLS public key.
pub const VRF_TREE_DIRECTORY: &str = "pq_vrf_trees";

/// A validator's PQ key material.
pub struct PqKey {
    /// leanVM's key: it caches the last few bottom trees it signed in.
    xmss: LeanXmssExpandedSecretKey,
    vrf_seed: vrf::Node,
    /// Empty until [`prepare_vrf_tree`] has read or hashed the tree.
    vrf: OnceLock<vrf::VrfTree>,
    /// The 48-byte form the PQ registry names the validator by.
    pub request_key: [u8; 48],
}

#[derive(Default)]
struct Registry {
    by_bls: HashMap<BlsPubkey, Arc<PqKey>>,
    by_request: HashMap<[u8; 48], BlsPubkey>,
}

fn registry() -> &'static RwLock<Registry> {
    static REGISTRY: OnceLock<RwLock<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}

/// Every leaf signed at, with its root, and the file that keeps them.
#[derive(Default)]
struct LeafRecord {
    roots: HashMap<(BlsPubkey, u64), Root>,
    /// `None` until [`open_leaf_record`]: the record is then in memory only,
    /// as in tests.
    file: Option<std::fs::File>,
}

impl LeafRecord {
    /// The record at `path`, without the leaves of slots before `keep_from`,
    /// rewritten that way so it does not grow without bound, and open for
    /// appending. A torn trailing record is dropped: it was never flushed, so
    /// no signature at its leaf left the process.
    fn open(path: &Path, keep_from: Slot) -> std::io::Result<(Self, usize)> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(err) => return Err(err),
        };
        let mut roots = HashMap::new();
        let mut kept = Vec::with_capacity(bytes.len());
        for record in bytes.chunks_exact(LEAF_RECORD_SIZE) {
            let pubkey = BlsPubkey(record[..48].try_into().expect("48 bytes"));
            let leaf = u64::from_le_bytes(record[48..56].try_into().expect("8 bytes"));
            let root = Root::from(<[u8; 32]>::try_from(&record[56..]).expect("32 bytes"));
            if leaf_slot(leaf).is_some_and(|slot| slot < keep_from) {
                continue;
            }
            if roots.insert((pubkey, leaf), root).is_none() {
                kept.extend_from_slice(record);
            }
        }
        crate::secure_fs::write_private_durably(path, &kept).map_err(std::io::Error::other)?;
        let file = std::fs::OpenOptions::new().append(true).open(path)?;
        let count = roots.len();
        Ok((
            Self {
                roots,
                file: Some(file),
            },
            count,
        ))
    }

    /// Claims `leaf` of `pubkey` for `root`: refused when the leaf already
    /// signed another root, and recorded durably the first time.
    fn claim(&mut self, pubkey: &BlsPubkey, leaf: u64, root: Root) -> Result<(), PqSignError> {
        match self.roots.get(&(*pubkey, leaf)) {
            Some(previous) if *previous != root => return Err(PqSignError::LeafUsed(leaf)),
            Some(_) => return Ok(()),
            None => {}
        }
        if let Some(file) = &mut self.file {
            let mut record = Vec::with_capacity(LEAF_RECORD_SIZE);
            record.extend_from_slice(&pubkey.0);
            record.extend_from_slice(&leaf.to_le_bytes());
            record.extend_from_slice(&root.0);
            file.write_all(&record)
                .and_then(|()| file.sync_data())
                .map_err(PqSignError::Record)?;
        }
        self.roots.insert((*pubkey, leaf), root);
        Ok(())
    }
}

/// The slot a leaf belongs to (the target epoch's first slot for an
/// attestation's), or `None` for the reserved and builder leaves, which the
/// record keeps for good.
fn leaf_slot(leaf: u64) -> Option<Slot> {
    let per_slot = XMSS_RESERVED_LEAVES + XMSS_ATTESTATION_LEAVES + XMSS_BUILDER_BID_LEAVES;
    if leaf >= per_slot {
        return Some((leaf - per_slot) / XMSS_LEAVES_PER_SLOT);
    }
    let attestations = XMSS_RESERVED_LEAVES..XMSS_RESERVED_LEAVES + XMSS_ATTESTATION_LEAVES;
    attestations
        .contains(&leaf)
        .then(|| (leaf - XMSS_RESERVED_LEAVES) * ethlambda_types::beacon::preset::slots_per_epoch())
}

fn signed_leaves() -> &'static Mutex<LeafRecord> {
    static SIGNED: OnceLock<Mutex<LeafRecord>> = OnceLock::new();
    SIGNED.get_or_init(Default::default)
}

/// Opens `validators_dir`'s leaf record and takes it as this process's: the
/// leaves signed before a restart stay spent. Leaves of slots more than
/// [`leaf_record_keep_slots`] before `current_slot` are dropped from it.
/// Returns how many leaves it holds. Call it once, before any PQ signature.
pub fn open_leaf_record(validators_dir: &Path, current_slot: Slot) -> std::io::Result<usize> {
    let keep_from = current_slot.saturating_sub(leaf_record_keep_slots());
    let (mut record, count) = LeafRecord::open(&validators_dir.join(LEAF_RECORD_FILE), keep_from)?;
    let mut global = signed_leaves().lock().expect("PQ leaf record poisoned");
    // Anything this process signed before opening is kept, and written
    // through so the next start sees it too.
    for ((pubkey, leaf), root) in std::mem::take(&mut global.roots) {
        record.claim(&pubkey, leaf, root).map_err(|err| match err {
            PqSignError::Record(io) => io,
            other => std::io::Error::other(other.to_string()),
        })?;
    }
    *global = record;
    Ok(count)
}

/// The size of one record of ethereum-package's leanXMSS cache file
/// (`xmss_cache_url`): what leanVM's `cache_to_bytes` writes for a key holding
/// two bottom trees, its top tree's cached level (4096 bytes) then, for each
/// bottom tree, its index, its top-layer signature and its cached level (5300
/// bytes). leanVM keeps those sizes private; a record of another length is
/// refused by `from_cache_bytes` anyway.
pub const XMSS_CACHE_RECORD_SIZE: usize = 4096 + 2 * 5300;

/// A key's record in the leanXMSS cache, with the public key the registry
/// holds for the validator it was looked up by.
pub struct XmssCacheRecord {
    pub registered: [u8; leanvm_lean_xmss::PUB_KEY_SIZE],
    pub bytes: Vec<u8>,
}

/// Where [`derive_and_register`] got a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// Loaded from its leanXMSS cache record.
    Cached,
    /// Built from its seed; no cache record was offered.
    Built,
    /// Built from its seed after its cache record was refused: not this
    /// key's, or damaged.
    CacheRefused,
}

/// Derives and registers the PQ key of the validator whose BLS key is
/// `pubkey` and secret key `secret` (32 bytes, big-endian, as a keystore
/// holds it).
///
/// With a `cached` record that is this key's, the key loads from it in
/// milliseconds. Otherwise it is built: slow, and on the calling thread
/// alone, leanVM's key generation (about 2.4 s). Either way the bottom trees
/// its next attestation and per-slot signatures fall in are then built if the
/// key lacks them (about 2.5 s each). Run it off the async runtime, and
/// spread many keys across cores.
///
/// The key signs from here on. Its VRF tree, which only a proposal reads, is
/// [`prepare_vrf_tree`]'s to supply.
pub fn derive_and_register(
    pubkey: BlsPubkey,
    secret: &[u8; 32],
    current_slot: Slot,
    cached: Option<&XmssCacheRecord>,
) -> KeySource {
    let loaded = cached.map(|record| {
        let registered = leanvm_lean_xmss::LeanXmssPublicKey::from_bytes(&record.registered);
        let seed = pq_keys::xmss_seed(secret);
        LeanXmssExpandedSecretKey::from_cache_bytes(&seed, &registered, &record.bytes)
    });
    let (xmss, source) = match loaded {
        Some(Some(xmss)) => (xmss, KeySource::Cached),
        Some(None) => (pq_keys::xmss_key(secret), KeySource::CacheRefused),
        None => (pq_keys::xmss_key(secret), KeySource::Built),
    };
    let mut request_key = [0u8; 48];
    request_key[16..].copy_from_slice(&xmss.public_key().to_bytes());
    // Warm the two bottom trees duties sign in, so the first signature of each
    // kind does not pay for one at its deadline. Later ones are
    // `prepare_bottom_tree`'s.
    for leaf in duty_leaves(current_slot) {
        if let Ok(leaf) = u32::try_from(leaf) {
            xmss.prepare(leaf);
        }
    }
    let key = Arc::new(PqKey {
        xmss,
        vrf_seed: pq_keys::vrf_seed(secret),
        vrf: OnceLock::new(),
        request_key,
    });
    let mut registry = registry().write().expect("PQ key registry poisoned");
    registry.by_request.insert(request_key, pubkey);
    registry.by_bls.insert(pubkey, key);
    source
}

/// The index of each of `keys`' registry entries: the one whose XMSS key's
/// public parameter (its request form's last 16 bytes) is the one the key's
/// seed gives. What the leanXMSS cache is looked up by, before any key is
/// built. A key with no such entry is left out.
pub fn indices_by_public_param(
    keys: &[(BlsPubkey, [u8; 32])],
    registry: &[(u64, [u8; 48])],
) -> HashMap<BlsPubkey, (u64, [u8; leanvm_lean_xmss::PUB_KEY_SIZE])> {
    let wanted: HashMap<[u8; 16], BlsPubkey> = keys
        .iter()
        .map(|(pubkey, secret)| (pq_keys::xmss_public_param(secret), *pubkey))
        .collect();
    registry
        .iter()
        .filter(|(_, request)| request[..16] == [0; 16])
        .filter_map(|(index, request)| {
            let param: [u8; 16] = request[32..].try_into().expect("16 bytes");
            let pubkey = wanted.get(&param)?;
            let registered = request[16..].try_into().expect("32 bytes");
            Some((*pubkey, (*index, registered)))
        })
        .collect()
}

/// Whether any key is registered: the network schedules PQ and this client
/// derived its keys.
pub fn enabled() -> bool {
    !registry()
        .read()
        .expect("PQ key registry poisoned")
        .by_bls
        .is_empty()
}

/// The local BLS key whose PQ key `request_key` names, if any.
pub fn bls_for_request_key(request_key: &[u8; 48]) -> Option<BlsPubkey> {
    if request_key[..16] != [0; 16] {
        return None;
    }
    registry()
        .read()
        .expect("PQ key registry poisoned")
        .by_request
        .get(request_key)
        .copied()
}

/// The request-key form of `pubkey`'s PQ key, if it has one.
pub fn request_key(pubkey: &BlsPubkey) -> Option<[u8; 48]> {
    key(pubkey).map(|key| key.request_key)
}

fn key(pubkey: &BlsPubkey) -> Option<Arc<PqKey>> {
    registry()
        .read()
        .expect("PQ key registry poisoned")
        .by_bls
        .get(pubkey)
        .cloned()
}

/// The bottom tree `leaf` is in: a leanXMSS layer holds `2^16` leaves.
pub fn bottom_tree_of(leaf: u64) -> u64 {
    leaf >> 16
}

/// The leaves whose bottom trees a validator signs in at `slot`: the
/// attestation leaf of its epoch and its first per-slot leaf. Every per-slot
/// leaf of a slot is in one bottom tree, since a slot's
/// [`XMSS_LEAVES_PER_SLOT`] start at a multiple of it.
pub fn duty_leaves(slot: Slot) -> [u64; 2] {
    let epoch = slot / ethlambda_types::beacon::preset::slots_per_epoch();
    [attestation_leaf(epoch), slot_leaf(slot, 0)]
}

/// Builds the bottom tree `leaf` is in for every registered key that does
/// not hold it yet, so no duty pays for one at its deadline (the per-slot
/// leaves move to a new tree at slot 4096 and every 8192 slots after).
///
/// Blocking: about 2.5 s for each key that builds, single-threaded, the keys
/// across the current rayon pool. A key that holds the tree costs a lookup.
pub fn prepare_bottom_tree(leaf: u64) {
    use rayon::prelude::*;
    let Ok(leaf) = u32::try_from(leaf) else {
        return;
    };
    let keys: Vec<Arc<PqKey>> = registry()
        .read()
        .expect("PQ key registry poisoned")
        .by_bls
        .values()
        .cloned()
        .collect();
    keys.par_iter().for_each(|key| key.xmss.prepare(leaf));
}

/// `compute_xmss_attestation_leaf_index`.
pub fn attestation_leaf(target_epoch: Epoch) -> u64 {
    XMSS_RESERVED_LEAVES + target_epoch
}

/// `compute_xmss_leaf_index`.
pub fn slot_leaf(slot: Slot, offset: u64) -> u64 {
    XMSS_RESERVED_LEAVES
        + XMSS_ATTESTATION_LEAVES
        + XMSS_BUILDER_BID_LEAVES
        + slot * XMSS_LEAVES_PER_SLOT
        + offset
}

#[derive(Debug, thiserror::Error)]
pub enum PqSignError {
    #[error("no PQ key for this validator")]
    UnknownValidator,
    #[error("leaf {0} already signed a different message")]
    LeafUsed(u64),
    #[error("leaf {0} is past the key's last leaf")]
    LeafOutOfRange(u64),
    #[error("the VRF tree is still being hashed")]
    VrfTreeNotReady,
    #[error("slot {0} is past the VRF tree's last leaf")]
    SlotPastVrfTree(Slot),
    #[error("could not record the leaf before signing: {0}")]
    Record(std::io::Error),
}

/// Where [`prepare_vrf_tree`] got a key's VRF tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VrfTreeSource {
    /// Already in memory.
    Held,
    /// Read from the key's file under [`VRF_TREE_DIRECTORY`].
    Stored,
    /// Hashed in full, and written for the next start.
    Hashed,
}

/// Why [`adopt_vrf_state`] did not give a key a tree.
#[derive(Debug, thiserror::Error)]
pub enum VrfStateError {
    #[error("no PQ key for this validator")]
    UnknownValidator,
    #[error("the state is not this key's: {0}")]
    Invalid(vrf::VrfTreeError),
}

fn vrf_tree_path(validators_dir: &Path, pubkey: &BlsPubkey) -> PathBuf {
    validators_dir
        .join(VRF_TREE_DIRECTORY)
        .join(format!("0x{}.bin", hex::encode(pubkey.0)))
}

/// The tree stored at `path`, if the file is `vrf_seed`'s tree, whole. A
/// missing file is the ordinary first start; any other failure is logged, and
/// either way the caller hashes the tree.
fn stored_vrf_tree(path: &Path, vrf_seed: vrf::Node) -> Option<vrf::VrfTree> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return None,
        Err(err) => {
            warn!(path = %path.display(), %err, "Could not read a stored VRF tree; hashing it again");
            return None;
        }
    };
    vrf::VrfTree::from_bytes(vrf_seed, &bytes)
        .inspect_err(|err| {
            warn!(path = %path.display(), %err, "A stored VRF tree is unusable; hashing it again")
        })
        .ok()
}

/// Writes `tree` where the next start reads it. A tree that cannot be stored
/// is still used: logged, and obtained again at the next start.
fn store_vrf_tree(path: &Path, tree: &vrf::VrfTree) {
    let stored = path
        .parent()
        .map_or(Ok(()), std::fs::create_dir_all)
        .map_err(|err| err.to_string())
        .and_then(|()| {
            crate::secure_fs::write_private_durably(path, tree.to_bytes())
                .map_err(|err| err.to_string())
        });
    if let Err(err) = stored {
        warn!(path = %path.display(), %err, "Could not store a VRF tree; it will be obtained again at the next start");
    }
}

/// Gives `pubkey`'s registered key the VRF tree it already has in memory or
/// under `validators_dir`. `None` when there is none to restore (or the key
/// is not registered): the caller then loads a precomputed state for it
/// ([`adopt_vrf_state`]) or hashes it ([`prepare_vrf_tree`]).
///
/// Blocking: checking a stored tree hashes one `2^16`-leaf subtree.
pub fn restore_vrf_tree(pubkey: &BlsPubkey, validators_dir: &Path) -> Option<VrfTreeSource> {
    let key = key(pubkey)?;
    if key.vrf.get().is_some() {
        return Some(VrfTreeSource::Held);
    }
    let tree = stored_vrf_tree(&vrf_tree_path(validators_dir, pubkey), key.vrf_seed)?;
    let _ = key.vrf.set(tree);
    Some(VrfTreeSource::Stored)
}

/// Gives `pubkey`'s registered key the tree one precomputed state record
/// restores (`vrf::VrfTree::from_state_record`, ethereum-package's
/// `vrf_state_url` format), and stores it under `validators_dir` for the
/// next start. The record must fold the key's own leaf 0 to its root, so a
/// record of another validator's, or a damaged one, is refused rather than
/// leaving the key with proofs no state accepts.
pub fn adopt_vrf_state(
    pubkey: &BlsPubkey,
    record: &[u8],
    validators_dir: &Path,
) -> Result<(), VrfStateError> {
    let key = key(pubkey).ok_or(VrfStateError::UnknownValidator)?;
    let tree =
        vrf::VrfTree::from_state_record(key.vrf_seed, record).map_err(VrfStateError::Invalid)?;
    store_vrf_tree(&vrf_tree_path(validators_dir, pubkey), &tree);
    let _ = key.vrf.set(tree);
    Ok(())
}

/// A file of fixed-size records indexed by validator index, read one record
/// at a time: ethereum-package's `vrf_state_url` ([`vrf::STATE_RECORD_SIZE`])
/// and `xmss_cache_url` ([`XMSS_CACHE_RECORD_SIZE`]) files. The source is an
/// HTTP(S) URL, asked for each record by range, or a path.
///
/// A local file is read once. So is a remote one whose server ignores the
/// range and sends the whole file: kept and sliced from then on, rather than
/// downloaded again per key. Callers fetch one record before fetching the
/// rest concurrently, so a whole-file answer is downloaded once.
pub struct RecordFile {
    client: reqwest::Client,
    source: String,
    record_size: usize,
    whole: tokio::sync::Mutex<Option<Arc<Vec<u8>>>>,
}

impl RecordFile {
    pub fn new(client: reqwest::Client, source: String, record_size: usize) -> Self {
        Self {
            client,
            source,
            record_size,
            whole: tokio::sync::Mutex::new(None),
        }
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    fn slice(&self, whole: &[u8], index: u64) -> Option<Vec<u8>> {
        let first = usize::try_from(index).ok()?.checked_mul(self.record_size)?;
        whole
            .get(first..first.checked_add(self.record_size)?)
            .map(<[u8]>::to_vec)
    }

    /// Record `index`. `None` when the file does not reach it.
    pub async fn fetch(&self, index: u64) -> Result<Option<Vec<u8>>, String> {
        if let Some(whole) = self.whole.lock().await.clone() {
            return Ok(self.slice(&whole, index));
        }
        let remote = self.source.starts_with("http://") || self.source.starts_with("https://");
        if !remote {
            let mut whole = self.whole.lock().await;
            if whole.is_none() {
                let bytes = tokio::fs::read(&self.source)
                    .await
                    .map_err(|err| format!("{}: {err}", self.source))?;
                *whole = Some(Arc::new(bytes));
            }
            let bytes = whole.clone().expect("just read");
            return Ok(self.slice(&bytes, index));
        }
        let size = self.record_size as u64;
        let first = index * size;
        let response = self
            .client
            .get(&self.source)
            .header(
                reqwest::header::RANGE,
                format!("bytes={first}-{}", first + size - 1),
            )
            .timeout(std::time::Duration::from_secs(120))
            .send()
            .await
            .map_err(|err| err.to_string())?;
        let status = response.status();
        if status == reqwest::StatusCode::RANGE_NOT_SATISFIABLE {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(format!("{} answered {status}", self.source));
        }
        let body = response.bytes().await.map_err(|err| err.to_string())?;
        if status == reqwest::StatusCode::PARTIAL_CONTENT {
            return Ok(body.get(..self.record_size).map(<[u8]>::to_vec));
        }
        // The server ignored the range and sent the whole file: keep it.
        let whole = Arc::new(body.to_vec());
        let record = self.slice(&whole, index);
        *self.whole.lock().await = Some(whole);
        Ok(record)
    }
}

/// Gives `pubkey`'s registered key its VRF tree: the one stored under
/// `validators_dir` if there is one, else hashed in full and stored. `None`
/// for a key that is not registered.
///
/// Blocking, for minutes when it hashes, on every core (rayon's pool): run it
/// off the async runtime and one key at a time. A tree that cannot be stored
/// is still used; it is hashed again at the next start.
pub fn prepare_vrf_tree(pubkey: &BlsPubkey, validators_dir: &Path) -> Option<VrfTreeSource> {
    if let Some(source) = restore_vrf_tree(pubkey, validators_dir) {
        return Some(source);
    }
    let key = key(pubkey)?;
    let tree = vrf::VrfTree::build(key.vrf_seed);
    store_vrf_tree(&vrf_tree_path(validators_dir, pubkey), &tree);
    // A concurrent call for the same key hashed the same tree: either copy
    // serves.
    let _ = key.vrf.set(tree);
    Some(VrfTreeSource::Hashed)
}

/// Signs `root` at `leaf` with `pubkey`'s leanXMSS key. Refuses a leaf this
/// process already signed a different root at; the same root again is
/// re-signed, which yields the same bytes (signing is deterministic).
/// Blocking: building a bottom tree takes about 2.5 s, single-threaded.
pub fn sign(pubkey: &BlsPubkey, leaf: u64, root: Root) -> Result<XmssSignature, PqSignError> {
    let key = key(pubkey).ok_or(PqSignError::UnknownValidator)?;
    // Checked before the claim, so an unsignable leaf is not recorded as spent.
    let leaf_index = u32::try_from(leaf).map_err(|_| PqSignError::LeafOutOfRange(leaf))?;
    signed_leaves()
        .lock()
        .expect("PQ leaf record poisoned")
        .claim(pubkey, leaf, root)?;
    let signature = leanvm_lean_xmss::sign(&key.xmss, &root.0, leaf_index);
    Ok(XmssSignature(signature.to_bytes()))
}

const _: () =
    assert!(leanvm_lean_xmss::SIG_SIZE == ethlambda_types::beacon::constants::XMSS_SIGNATURE_SIZE);

/// `pubkey`'s VRF proof for `slot`, its RANDAO reveal at PQ
/// (`compute_vrf_proof`): the slot's secret, then its leaf's branch. Blocking
/// for the tens of milliseconds one subtree takes to hash.
pub fn vrf_proof(pubkey: &BlsPubkey, slot: Slot) -> Result<Vec<Root>, PqSignError> {
    let key = key(pubkey).ok_or(PqSignError::UnknownValidator)?;
    let tree = key.vrf.get().ok_or(PqSignError::VrfTreeNotReady)?;
    let proof = tree.proof(slot).ok_or(PqSignError::SlotPastVrfTree(slot))?;
    Ok(proof.into_iter().map(Root::from).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaves_follow_the_specification() {
        assert_eq!(attestation_leaf(3), (1 << 15) + 3);
        assert_eq!(
            slot_leaf(10, LEAF_OFFSET_PTC_ATTESTER),
            (1 << 15) + (1 << 29) + (1 << 30) + 80 + 2
        );
        // The slot leaves start halfway into a bottom tree, so the first 4096
        // slots share one (and every later 8192 another), attestations another.
        assert_eq!(slot_leaf(0, 0) >> 16, slot_leaf(4095, 7) >> 16);
        assert_ne!(slot_leaf(0, 0) >> 16, slot_leaf(4096, 0) >> 16);
        assert_ne!(attestation_leaf(0) >> 16, slot_leaf(0, 0) >> 16);
    }

    #[test]
    fn a_request_key_maps_back_and_a_leaf_signs_once() {
        let secret = [7u8; 32];
        let pubkey = BlsPubkey([9; 48]);
        derive_and_register(pubkey, &secret, 0, None);
        let request = request_key(&pubkey).unwrap();
        assert_eq!(request[..16], [0; 16]);
        assert_eq!(bls_for_request_key(&request), Some(pubkey));
        assert_eq!(bls_for_request_key(&pubkey.0), None);

        let leaf = slot_leaf(5, LEAF_OFFSET_PTC_ATTESTER);
        let first = sign(&pubkey, leaf, Root::from([1; 32])).unwrap();
        assert_eq!(sign(&pubkey, leaf, Root::from([1; 32])).unwrap(), first);
        assert!(matches!(
            sign(&pubkey, leaf, Root::from([2; 32])),
            Err(PqSignError::LeafUsed(_))
        ));
        let public = request[16..].try_into().unwrap();
        assert!(ethlambda_crypto::lean_xmss::verify(
            &public, leaf, &[1; 32], &first.0
        ));
        assert!(matches!(
            sign(&pubkey, 1 << 32, Root::from([1; 32])),
            Err(PqSignError::LeafOutOfRange(_))
        ));
    }

    /// What ethereum-package's leanXMSS cache file holds for the key `secret`
    /// grows: leanVM's `cache_to_bytes` of it holding the bottom trees of the
    /// first attestation and slot leaves. With the key's public key.
    fn cache_record(secret: &[u8; 32]) -> ([u8; 32], Vec<u8>) {
        let key = pq_keys::xmss_key(secret);
        key.prepare(attestation_leaf(0) as u32);
        key.prepare(slot_leaf(0, 0) as u32);
        let bytes = key.cache_to_bytes();
        assert_eq!(bytes.len(), XMSS_CACHE_RECORD_SIZE);
        (key.public_key().to_bytes(), bytes)
    }

    #[test]
    fn a_key_is_found_by_its_public_parameter_and_loads_from_its_cache_record() {
        let secret = [15u8; 32];
        let pubkey = BlsPubkey([15; 48]);
        let (public, bytes) = cache_record(&secret);

        // Found in the registry with no tree built: by its public parameter,
        // past a BLS entry and an XMSS entry with another parameter.
        let mut request = [0u8; 48];
        request[16..].copy_from_slice(&public);
        let mut other = request;
        other[47] ^= 1;
        let mut bls = [0u8; 48];
        bls[0] = 0xa0;
        let registry = [(0, bls), (1, other), (2, request)];
        let found = indices_by_public_param(&[(pubkey, secret)], &registry);
        assert_eq!(found, HashMap::from([(pubkey, (2, public))]));

        let record = XmssCacheRecord {
            registered: public,
            bytes: bytes.clone(),
        };
        assert_eq!(
            derive_and_register(pubkey, &secret, 0, Some(&record)),
            KeySource::Cached
        );
        assert_eq!(request_key(&pubkey), Some(request));
        let leaf = slot_leaf(3, LEAF_OFFSET_PTC_ATTESTER);
        let signature = sign(&pubkey, leaf, Root::from([4; 32])).unwrap();
        assert!(ethlambda_crypto::lean_xmss::verify(
            &public,
            leaf,
            &[4; 32],
            &signature.0
        ));
        // A loaded key signs what a built one does.
        let built = pq_keys::xmss_key(&secret);
        let expected = leanvm_lean_xmss::sign(&built, &[4; 32], leaf as u32);
        assert_eq!(signature.0, expected.to_bytes());

        // A damaged record, or one under another public key, is refused and
        // the key built.
        let mut damaged = bytes.clone();
        damaged[100] ^= 1;
        let damaged = XmssCacheRecord {
            registered: public,
            bytes: damaged,
        };
        assert_eq!(
            derive_and_register(BlsPubkey([16; 48]), &secret, 0, Some(&damaged)),
            KeySource::CacheRefused
        );
        let mut elsewhere = public;
        elsewhere[0] ^= 1;
        let misregistered = XmssCacheRecord {
            registered: elsewhere,
            bytes,
        };
        assert_eq!(
            derive_and_register(BlsPubkey([17; 48]), &secret, 0, Some(&misregistered)),
            KeySource::CacheRefused
        );
    }

    /// A server that ignores `Range` sends the whole file each time: it is
    /// downloaded once and sliced from then on.
    #[tokio::test]
    async fn a_whole_file_answer_is_downloaded_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = Arc::new(AtomicUsize::new(0));
        let file: Vec<u8> = (0..30u8).collect();
        let app = {
            let hits = hits.clone();
            axum::Router::new().route(
                "/records",
                axum::routing::get(move || {
                    hits.fetch_add(1, Ordering::SeqCst);
                    let file = file.clone();
                    async move { file }
                }),
            )
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let records = RecordFile::new(
            reqwest::Client::new(),
            format!("http://{address}/records"),
            10,
        );
        assert_eq!(records.fetch(1).await.unwrap(), Some((10..20).collect()));
        assert_eq!(records.fetch(0).await.unwrap(), Some((0..10).collect()));
        assert_eq!(records.fetch(3).await.unwrap(), None);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    /// The bytes of a tree for `vrf_seed` that `from_bytes` accepts. A whole
    /// tree takes minutes to hash, so the nodes past the first are arbitrary:
    /// the file's own checks do not rehash them, and its proofs fold to the
    /// root those nodes give.
    fn stand_in_tree_bytes(vrf_seed: vrf::Node) -> Vec<u8> {
        let mut nodes = vec![[7u8; 32]; 1 << 15];
        nodes[0] = vrf::compute_vrf_node(&vrf_seed, 16, 0);
        let mut layer = nodes.clone();
        while layer.len() > 1 {
            layer = layer
                .chunks_exact(2)
                .map(|pair| {
                    use sha3::Digest as _;
                    let mut hasher = sha3::Keccak256::new();
                    hasher.update(pair[0]);
                    hasher.update(pair[1]);
                    hasher.finalize().into()
                })
                .collect();
        }
        let mut bytes = nodes.concat();
        bytes.extend_from_slice(&layer[0]);
        bytes
    }

    #[test]
    fn a_key_signs_before_its_vrf_tree_and_proves_once_it_is_stored() {
        let secret = [8u8; 32];
        let pubkey = BlsPubkey([10; 48]);
        derive_and_register(pubkey, &secret, 0, None);
        // Registered and signing, with no tree yet: a proposal is refused.
        assert!(sign(&pubkey, attestation_leaf(0), Root::from([1; 32])).is_ok());
        assert!(matches!(
            vrf_proof(&pubkey, 5),
            Err(PqSignError::VrfTreeNotReady)
        ));

        // A stored tree is read back instead of hashed.
        let directory = tempfile::tempdir().unwrap();
        let path = vrf_tree_path(directory.path(), &pubkey);
        let vrf_seed = pq_keys::vrf_seed(&secret);
        let bytes = stand_in_tree_bytes(vrf_seed);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(
            prepare_vrf_tree(&pubkey, directory.path()),
            Some(VrfTreeSource::Stored)
        );
        assert_eq!(
            prepare_vrf_tree(&pubkey, directory.path()),
            Some(VrfTreeSource::Held)
        );

        let proof = vrf_proof(&pubkey, 5).unwrap();
        assert_eq!(proof.len(), 32);
        assert_eq!(proof[0].0, vrf::compute_vrf_leaf(&vrf_seed, 5));
        let branch = proof[1..].iter().map(|node| &node.0);
        let root: [u8; 32] = bytes[bytes.len() - 32..].try_into().unwrap();
        assert_eq!(vrf::fold_vrf_branch(&proof[0].0, branch, 5), root);
        assert!(matches!(
            vrf_proof(&pubkey, 1 << 31),
            Err(PqSignError::SlotPastVrfTree(_))
        ));
        assert_eq!(
            prepare_vrf_tree(&BlsPubkey([11; 48]), directory.path()),
            None
        );
    }

    /// A record of a `vrf_state_url` file for `vrf_seed`: leaf 0's true
    /// branch in its first subtree and arbitrary siblings above, which is all
    /// a record's own check (folding leaf 0 to the root) reads.
    fn stand_in_state_record(vrf_seed: vrf::Node) -> Vec<u8> {
        let mut branch = vrf::VrfTree::with_depth(vrf_seed, 16).compact_state().1;
        branch.extend((16..31).map(|height| [height as u8; 32]));
        let root = vrf::fold_vrf_branch(&vrf::compute_vrf_leaf(&vrf_seed, 0), &branch, 0);
        vrf::VrfTree::from_compact_state(vrf_seed, root, branch)
            .unwrap()
            .to_state_record()
    }

    #[tokio::test]
    async fn a_precomputed_state_gives_a_key_its_tree_for_this_and_the_next_start() {
        let secret = [12u8; 32];
        let pubkey = BlsPubkey([13; 48]);
        derive_and_register(pubkey, &secret, 0, None);
        let vrf_seed = pq_keys::vrf_seed(&secret);
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(restore_vrf_tree(&pubkey, directory.path()), None);

        // A file of two records, this key's second: it is read by index.
        let ours = stand_in_state_record(vrf_seed);
        let theirs = stand_in_state_record([3; 32]);
        let file = directory.path().join("states.vrf");
        std::fs::write(&file, [theirs.clone(), ours.clone()].concat()).unwrap();
        let states = RecordFile::new(
            reqwest::Client::new(),
            file.to_str().unwrap().to_string(),
            vrf::STATE_RECORD_SIZE,
        );
        assert_eq!(states.fetch(1).await.unwrap(), Some(ours.clone()));
        assert_eq!(states.fetch(2).await.unwrap(), None);

        // Another validator's record is refused, ours adopted and stored.
        assert!(matches!(
            adopt_vrf_state(&pubkey, &theirs, directory.path()),
            Err(VrfStateError::Invalid(_))
        ));
        adopt_vrf_state(&pubkey, &ours, directory.path()).unwrap();
        let root: [u8; 32] = ours[..32].try_into().unwrap();
        let proof = vrf_proof(&pubkey, 9).unwrap();
        let branch = proof[1..].iter().map(|node| &node.0);
        assert_eq!(vrf::fold_vrf_branch(&proof[0].0, branch, 9), root);

        // The next start reads the compact tree back from the directory.
        let stored = stored_vrf_tree(&vrf_tree_path(directory.path(), &pubkey), vrf_seed).unwrap();
        assert_eq!(stored.root(), root);
        assert_eq!(
            stored.proof(9).unwrap(),
            proof.iter().map(|node| node.0).collect::<Vec<_>>()
        );
    }

    /// A leaf claimed for one root stays claimed across a reopening of the
    /// record, which drops only the leaves of slots before its window and a
    /// torn trailing record.
    #[test]
    fn the_leaf_record_survives_a_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(LEAF_RECORD_FILE);
        let pubkey = BlsPubkey([14; 48]);
        let recent = slot_leaf(100, LEAF_OFFSET_PTC_ATTESTER);
        let old = slot_leaf(10, LEAF_OFFSET_PTC_ATTESTER);
        let reserved = 7;
        {
            let (mut record, count) = LeafRecord::open(&path, 0).unwrap();
            assert_eq!(count, 0);
            for leaf in [recent, old, reserved] {
                record.claim(&pubkey, leaf, Root::from([1; 32])).unwrap();
            }
            record.claim(&pubkey, recent, Root::from([1; 32])).unwrap();
            assert!(matches!(
                record.claim(&pubkey, recent, Root::from([2; 32])),
                Err(PqSignError::LeafUsed(_))
            ));
        }
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            3 * LEAF_RECORD_SIZE as u64
        );
        // A write torn by a crash: never flushed, never signed.
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(&[9; LEAF_RECORD_SIZE - 1]).unwrap();
        drop(file);

        let (mut record, count) = LeafRecord::open(&path, 50).unwrap();
        assert_eq!(
            count, 2,
            "the old slot's leaf is dropped, the reserved one kept"
        );
        assert!(matches!(
            record.claim(&pubkey, recent, Root::from([2; 32])),
            Err(PqSignError::LeafUsed(_))
        ));
        assert!(matches!(
            record.claim(&pubkey, reserved, Root::from([2; 32])),
            Err(PqSignError::LeafUsed(_))
        ));
        record.claim(&pubkey, old, Root::from([2; 32])).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            3 * LEAF_RECORD_SIZE as u64
        );
        assert_eq!(leaf_slot(attestation_leaf(3)), Some(96));
    }

    #[test]
    fn a_stored_vrf_tree_of_another_seed_or_a_damaged_one_is_not_used() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("tree.bin");
        assert!(stored_vrf_tree(&path, [1; 32]).is_none());

        let bytes = stand_in_tree_bytes([1; 32]);
        std::fs::write(&path, &bytes).unwrap();
        assert!(stored_vrf_tree(&path, [1; 32]).is_some());
        assert!(stored_vrf_tree(&path, [2; 32]).is_none());

        let mut damaged = bytes.clone();
        damaged[40_000] ^= 1;
        std::fs::write(&path, &damaged).unwrap();
        assert!(stored_vrf_tree(&path, [1; 32]).is_none());
        std::fs::write(&path, &bytes[..bytes.len() - 1]).unwrap();
        assert!(stored_vrf_tree(&path, [1; 32]).is_none());
    }
}
