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
//! XMSS key, which duty and validator responses carry as it is (a node from
//! before the Beacon API's switch to 32 bytes sends the 48-byte form an
//! execution-layer request names one by: 16 zero bytes, then the key). The
//! client reads either into that 48-byte form
//! (`beacon_node::dto::parse_registry_key`), and no BLS key starts with 16
//! zero bytes (its first byte carries the compression flag), so
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
//!
//! **Signing.** A duty signs its keys as one batch ([`sign_all`]): every
//! leaf the batch spends is recorded with one flush, then the keys sign in
//! parallel on rayon's global pool, on tokio's blocking pool rather than the
//! duty's task.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use ethlambda_crypto::leanvm_lean_xmss::{self, LeanXmssExpandedSecretKey};
use ethlambda_crypto::{pq_keys, vrf};
use ethlambda_types::beacon::constants::{
    XMSS_ATTESTATION_LEAVES, XMSS_BUILDER_BID_LEAVES, XMSS_LEAVES_PER_SLOT, XMSS_RESERVED_LEAVES,
};
use ethlambda_types::beacon::primitives::{BlsPubkey, Epoch, Root, Slot, XmssSignature};
use tracing::{debug, warn};

pub use ethlambda_types::beacon::constants::{
    LEAF_OFFSET_AGGREGATE_AND_PROOF, LEAF_OFFSET_BEACON_PROPOSER,
    LEAF_OFFSET_EXECUTION_PAYLOAD_ENVELOPE, LEAF_OFFSET_PTC_ATTESTER,
};

/// The file under the validators directory that keeps every leaf this
/// client signed at and the root it signed there: [`LEAF_RECORD_SIZE`]-byte
/// records (the 48-byte BLS key, the leaf as a little-endian `u64`, the
/// signing root), appended and flushed before each first signature at a
/// leaf, a batch's records with one flush.
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

/// The directory under the validators directory that holds each key's
/// leanXMSS trees, one file per validator, named by its BLS public key:
/// [`TREE_FILE_MAGIC`], the key's public key, leanVM's `cache_to_bytes` (the
/// top tree's cached level and that of every bottom tree the key holds, at
/// most `MAX_CACHED_BOTTOM_TREES`; about 25 KB), then an HMAC-SHA256 tag over
/// all of it under a key derived from the XMSS seed ([`tree_mac_key`]), so
/// only a file this client wrote for this seed loads. Lighthouse's and
/// Teku's PQ branches keep the same thing the same way. Written whenever a
/// key builds a bottom tree, and read first at startup.
///
/// A bottom tree is `2^16` leaves, seconds of hashing per key, and nothing
/// lets a key skip one: every duty's leaf is fixed by the specification, and
/// the path from a leaf needs all the leaves of its tree. The per-slot leaves
/// take eight leaves a slot whatever the validator's duties, so they need a
/// new tree every 8192 slots (the first after 4096), past the two genesis-era
/// trees ethereum-package's `xmss_cache_url` holds. Without this store every
/// restart built the current one again for every key before any duty ran:
/// thirteen minutes for 625 keys on the PQ devnet.
pub const XMSS_TREE_DIRECTORY: &str = "pq_xmss_trees";

/// Where [`store_trees`] writes and [`derive_and_register`] reads: the
/// validators directory given to [`use_tree_store`], or nowhere, as in tests.
fn tree_store() -> Option<&'static Path> {
    TREE_STORE.get().map(PathBuf::as_path)
}

static TREE_STORE: OnceLock<PathBuf> = OnceLock::new();

/// Keep each key's leanXMSS trees under `validators_dir`
/// ([`XMSS_TREE_DIRECTORY`]). Call once at startup, before
/// [`derive_and_register`]; a second call is ignored.
pub fn use_tree_store(validators_dir: &Path) {
    let _ = TREE_STORE.set(validators_dir.to_path_buf());
}

/// Whether `pubkey` has a stored tree file under `validators_dir`, so that
/// its `xmss_cache_url` record need not be fetched. Whether the file is
/// usable is only known when [`derive_and_register`] loads it.
pub fn has_stored_trees(validators_dir: &Path, pubkey: &BlsPubkey) -> bool {
    xmss_tree_path(validators_dir, pubkey).is_file()
}

fn xmss_tree_path(validators_dir: &Path, pubkey: &BlsPubkey) -> PathBuf {
    validators_dir
        .join(XMSS_TREE_DIRECTORY)
        .join(format!("0x{}.bin", hex::encode(pubkey.0)))
}

/// The first bytes of every [`XMSS_TREE_DIRECTORY`] file, naming its format
/// and version: a later layout gets a new version, and a file of another one
/// is rebuilt rather than misread.
const TREE_FILE_MAGIC: &[u8; 8] = b"ELXMSS\x00\x01";

/// The size of a tree file's HMAC-SHA256 tag.
const TREE_FILE_TAG_SIZE: usize = 32;

type TreeMac = hmac::Hmac<sha2::Sha256>;

/// The key a tree file's tag is made under: derived from the XMSS seed with a
/// domain of its own, so the tag says the file was written for this seed,
/// and the seed itself never keys anything but leanVM.
fn tree_mac_key(secret: &[u8; 32]) -> [u8; 32] {
    use hmac::Mac as _;
    let mut mac =
        TreeMac::new_from_slice(&pq_keys::xmss_seed(secret)).expect("HMAC takes any key length");
    mac.update(b"ethlambda leanXMSS tree store v1");
    mac.finalize().into_bytes().into()
}

fn tree_file_tag(mac_key: &[u8; 32], content: &[u8]) -> TreeMac {
    use hmac::Mac as _;
    let mut mac = TreeMac::new_from_slice(mac_key).expect("HMAC takes any key length");
    mac.update(content);
    mac
}

/// The key stored at `path`, if the file is one this client wrote for this
/// seed (its tag) and holds the key with its cached levels whole (leanVM's
/// `from_cache_bytes` checks them against the public key, and the public
/// key's parameter against the seed). When the registry's key for the
/// validator is known (`registered`), the file must be for it too. A missing
/// file is an ordinary first start; any other failure is logged, and the
/// caller loads or builds the key instead.
fn stored_key(
    path: &Path,
    secret: &[u8; 32],
    registered: Option<&[u8; leanvm_lean_xmss::PUB_KEY_SIZE]>,
) -> Option<LeanXmssExpandedSecretKey> {
    use hmac::Mac as _;
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return None,
        Err(err) => {
            warn!(path = %path.display(), %err, "Could not read a key's stored leanXMSS trees; building them again");
            return None;
        }
    };
    let Some((content, tag)) = bytes.split_last_chunk::<TREE_FILE_TAG_SIZE>() else {
        warn!(path = %path.display(), "A key's stored leanXMSS trees are truncated; building them again");
        return None;
    };
    let Some(payload) = content.strip_prefix(TREE_FILE_MAGIC) else {
        warn!(path = %path.display(), "A key's stored leanXMSS trees are in another format; building them again");
        return None;
    };
    if tree_file_tag(&tree_mac_key(secret), content)
        .verify_slice(tag)
        .is_err()
    {
        warn!(path = %path.display(), "A key's stored leanXMSS trees were not written for this key, or are damaged; building them again");
        return None;
    }
    let Some((public, cache)) = payload.split_first_chunk::<{ leanvm_lean_xmss::PUB_KEY_SIZE }>()
    else {
        warn!(path = %path.display(), "A key's stored leanXMSS trees are truncated; building them again");
        return None;
    };
    if registered.is_some_and(|registered| registered != public) {
        warn!(path = %path.display(), "A key's stored leanXMSS trees are not for its registered key; building them again");
        return None;
    }
    let public_key = leanvm_lean_xmss::LeanXmssPublicKey::from_bytes(public);
    let seed = pq_keys::xmss_seed(secret);
    let key = LeanXmssExpandedSecretKey::from_cache_bytes(&seed, &public_key, cache);
    if key.is_none() {
        warn!(path = %path.display(), "A key's stored leanXMSS trees are not this key's, or damaged; building them again");
    }
    key
}

/// Writes `key`'s trees where the next start reads them, when a store is in
/// use ([`use_tree_store`]). A file that cannot be written is logged: the
/// next start builds those trees again.
fn store_trees(pubkey: &BlsPubkey, key: &PqKey) {
    if let Some(validators_dir) = tree_store() {
        store_trees_at(&xmss_tree_path(validators_dir, pubkey), key);
    }
}

fn store_trees_at(path: &Path, key: &PqKey) {
    // One writer per key at a time: the durable write stages through a fixed
    // sibling file, and the startup, the lookahead and a signature can all
    // build one key's trees.
    let mac_key = key
        .storing
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut bytes = TREE_FILE_MAGIC.to_vec();
    bytes.extend(key.xmss.public_key().to_bytes());
    bytes.extend(key.xmss.cache_to_bytes());
    let tag = {
        use hmac::Mac as _;
        tree_file_tag(&mac_key, &bytes).finalize().into_bytes()
    };
    bytes.extend(tag);
    let stored = path
        .parent()
        .map_or(Ok(()), std::fs::create_dir_all)
        .map_err(|err| err.to_string())
        .and_then(|()| {
            crate::secure_fs::write_private_durably(path, bytes).map_err(|err| err.to_string())
        });
    if let Err(err) = stored {
        warn!(path = %path.display(), %err, "Could not store a key's leanXMSS trees; the next start builds them again");
    }
}

/// A validator's PQ key material.
pub struct PqKey {
    /// leanVM's key: it caches the last few bottom trees it signed in.
    xmss: LeanXmssExpandedSecretKey,
    vrf_seed: vrf::Node,
    /// Empty until [`prepare_vrf_tree`] has read or hashed the tree.
    vrf: OnceLock<vrf::VrfTree>,
    /// The 48-byte form the PQ registry names the validator by.
    pub request_key: [u8; 48],
    /// The key the tree file's tag is made under ([`tree_mac_key`]), held
    /// while the key's trees are written ([`store_trees`]).
    storing: Mutex<[u8; 32]>,
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

    /// Claims `leaf` of `pubkey` for `root`: [`Self::claim_all`] of one.
    fn claim(&mut self, pubkey: &BlsPubkey, leaf: u64, root: Root) -> Result<(), PqSignError> {
        let request = SignRequest {
            pubkey: *pubkey,
            leaf,
            root,
        };
        self.claim_all(&[request])
            .pop()
            .expect("one outcome per claim")
    }

    /// Claims each request's leaf for its root, in order, answering in the
    /// same order: refused when the leaf already signed another root, before
    /// this call or earlier in `requests`, so a batch cannot spend one leaf
    /// on two roots either. The leaves claimed for the first time are
    /// recorded together, one write and one flush; when that fails, every
    /// one of them fails with it and none is kept.
    fn claim_all(&mut self, requests: &[SignRequest]) -> Vec<Result<(), PqSignError>> {
        let mut fresh: HashMap<(BlsPubkey, u64), Root> = HashMap::new();
        let mut record = Vec::new();
        // `None` for a request whose leaf the write below claims.
        let mut outcomes = Vec::with_capacity(requests.len());
        for request in requests {
            let at = (request.pubkey, request.leaf);
            let held = match self.roots.get(&at) {
                Some(root) => Some((*root, true)),
                None => fresh.get(&at).map(|root| (*root, false)),
            };
            outcomes.push(match held {
                Some((root, _)) if root != request.root => {
                    Some(Err(PqSignError::LeafUsed(request.leaf)))
                }
                Some((_, durable)) => durable.then_some(Ok(())),
                None => {
                    fresh.insert(at, request.root);
                    record.extend_from_slice(&request.pubkey.0);
                    record.extend_from_slice(&request.leaf.to_le_bytes());
                    record.extend_from_slice(&request.root.0);
                    None
                }
            });
        }
        let written = match &mut self.file {
            Some(file) if !record.is_empty() => {
                file.write_all(&record).and_then(|()| file.sync_data())
            }
            _ => Ok(()),
        };
        if written.is_ok() {
            self.roots.extend(fresh);
        }
        outcomes
            .into_iter()
            .map(|outcome| match (outcome, &written) {
                (Some(outcome), _) => outcome,
                (None, Ok(())) => Ok(()),
                (None, Err(err)) => Err(PqSignError::Record(std::io::Error::new(
                    err.kind(),
                    err.to_string(),
                ))),
            })
            .collect()
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
    /// Loaded from the trees an earlier start stored ([`XMSS_TREE_DIRECTORY`]).
    Stored,
    /// Loaded from its leanXMSS cache record.
    Cached,
    /// Built from its seed; no cache record was offered.
    Built,
    /// Built from its seed after its cache record was refused: not this
    /// key's, or damaged.
    CacheRefused,
}

/// What [`derive_and_register`] did for one key, for the startup log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Derived {
    pub source: KeySource,
    /// Loading the key from its cache record, or generating it.
    pub key_time: Duration,
    /// The bottom trees the key had to build to warm its duties' trees (a
    /// cache record may already hold them), and the time they took.
    pub trees_built: usize,
    pub tree_time: Duration,
}

/// Derives and registers the PQ key of the validator whose BLS key is
/// `pubkey` and secret key `secret` (32 bytes, big-endian, as a keystore
/// holds it).
///
/// With trees an earlier start stored ([`use_tree_store`]), or a `cached`
/// record that is this key's, the key loads in milliseconds; stored trees
/// come first, since they hold the bottom trees the key built since genesis.
/// Otherwise it is built: slow, and on the calling thread alone, leanVM's key
/// generation (about 2.4 s). Either way the bottom trees its next attestation
/// and per-slot signatures fall in are then built if the key lacks them
/// (about 2.5 s each), and the key's trees are stored when anything was
/// loaded from elsewhere or built. Run it off the async runtime, and spread
/// many keys across cores.
///
/// The key signs from here on. Its VRF tree, which only a proposal reads, is
/// [`prepare_vrf_tree`]'s to supply.
pub fn derive_and_register(
    pubkey: BlsPubkey,
    secret: &[u8; 32],
    current_slot: Slot,
    cached: Option<&XmssCacheRecord>,
) -> Derived {
    let started = Instant::now();
    let stored = tree_store().and_then(|validators_dir| {
        let registered = cached.map(|record| &record.registered);
        stored_key(&xmss_tree_path(validators_dir, &pubkey), secret, registered)
    });
    let (xmss, source) = match stored {
        Some(xmss) => (xmss, KeySource::Stored),
        None => {
            let loaded = cached.map(|record| {
                let registered =
                    leanvm_lean_xmss::LeanXmssPublicKey::from_bytes(&record.registered);
                let seed = pq_keys::xmss_seed(secret);
                LeanXmssExpandedSecretKey::from_cache_bytes(&seed, &registered, &record.bytes)
            });
            match loaded {
                Some(Some(xmss)) => (xmss, KeySource::Cached),
                Some(None) => (pq_keys::xmss_key(secret), KeySource::CacheRefused),
                None => (pq_keys::xmss_key(secret), KeySource::Built),
            }
        }
    };
    let key_time = started.elapsed();
    let mut request_key = [0u8; 48];
    request_key[16..].copy_from_slice(&xmss.public_key().to_bytes());
    // Warm the two bottom trees duties sign in, so the first signature of each
    // kind does not pay for one at its deadline. Later ones are
    // `prepare_bottom_tree`'s.
    let mut trees_built = 0;
    let mut tree_time = Duration::ZERO;
    for leaf in duty_leaves(current_slot) {
        let Ok(leaf_index) = u32::try_from(leaf) else {
            continue;
        };
        if let Some(elapsed) = prepare_tree(&xmss, leaf_index) {
            debug!(
                pubkey = %encode_pubkey(&pubkey),
                tree = bottom_tree_of(leaf),
                leaf,
                elapsed_ms = elapsed.as_millis() as u64,
                "Built a leanXMSS bottom tree for the current duties"
            );
            trees_built += 1;
            tree_time += elapsed;
        }
    }
    debug!(
        pubkey = %encode_pubkey(&pubkey),
        ?source,
        key_ms = key_time.as_millis() as u64,
        trees_built,
        tree_ms = tree_time.as_millis() as u64,
        "Derived a validator's PQ key"
    );
    let key = Arc::new(PqKey {
        xmss,
        vrf_seed: pq_keys::vrf_seed(secret),
        vrf: OnceLock::new(),
        request_key,
        storing: Mutex::new(tree_mac_key(secret)),
    });
    if source != KeySource::Stored || trees_built > 0 {
        store_trees(&pubkey, &key);
    }
    let mut registry = registry().write().expect("PQ key registry poisoned");
    registry.by_request.insert(request_key, pubkey);
    registry.by_bls.insert(pubkey, key);
    Derived {
        source,
        key_time,
        trees_built,
        tree_time,
    }
}

/// The longest [`prepare_tree`] can take and still have found the tree in
/// the key's cache: a hit is a lock and a scan of four entries, a build
/// seconds of hashing. leanVM does not say which it was, so the time does.
/// Only a log line rests on it: a hit slowed past this by a starved core
/// costs one misleading line, never a signature.
const TREE_BUILD_THRESHOLD: Duration = Duration::from_millis(50);

/// Prepares `xmss`'s bottom tree for `leaf_index`, and how long that took
/// when the key had to build it (`None` when it held it already).
fn prepare_tree(xmss: &LeanXmssExpandedSecretKey, leaf_index: u32) -> Option<Duration> {
    let started = Instant::now();
    xmss.prepare(leaf_index);
    let elapsed = started.elapsed();
    (elapsed >= TREE_BUILD_THRESHOLD).then_some(elapsed)
}

fn encode_pubkey(pubkey: &BlsPubkey) -> String {
    crate::beacon_node::dto::encode_hex(&pubkey.0)
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
pub fn prepare_bottom_tree(leaf: u64) -> TreeBuilds {
    use rayon::prelude::*;
    let Ok(leaf_index) = u32::try_from(leaf) else {
        return TreeBuilds::default();
    };
    let keys: Vec<(BlsPubkey, Arc<PqKey>)> = registry()
        .read()
        .expect("PQ key registry poisoned")
        .by_bls
        .iter()
        .map(|(pubkey, key)| (*pubkey, Arc::clone(key)))
        .collect();
    let built: Vec<Duration> = keys
        .par_iter()
        .filter_map(|(pubkey, key)| {
            let elapsed = prepare_tree(&key.xmss, leaf_index)?;
            debug!(
                pubkey = %encode_pubkey(pubkey),
                tree = bottom_tree_of(leaf),
                elapsed_ms = elapsed.as_millis() as u64,
                "Built a validator's next leanXMSS bottom tree"
            );
            store_trees(pubkey, key);
            Some(elapsed)
        })
        .collect();
    TreeBuilds {
        keys: keys.len(),
        built: built.len(),
        slowest: built.iter().copied().max().unwrap_or_default(),
    }
}

/// What [`prepare_bottom_tree`] did across the keys.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TreeBuilds {
    /// The keys registered.
    pub keys: usize,
    /// The keys that had to build the tree; the others held it.
    pub built: usize,
    /// The longest one key's build took.
    pub slowest: Duration,
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
    #[error("the signing task failed: {0}")]
    Task(String),
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

/// One leanXMSS signature to make: `root` at `leaf` with `pubkey`'s key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignRequest {
    pub pubkey: BlsPubkey,
    pub leaf: u64,
    pub root: Root,
}

/// Signs each request, answering in the same order. A leaf this process
/// already signed a different root at is refused; the same root again is
/// re-signed, which yields the same bytes (signing is deterministic).
///
/// Every leaf the batch spends is recorded with one write and one flush
/// before any of its signatures exists, then the keys sign in parallel on
/// rayon's global pool (leanVM signs on one thread, and different keys share
/// nothing). One signature recomputes a `2^8`-leaf subtree of its bottom
/// tree, a 256th of building the tree: roughly 10 ms on a core.
///
/// Blocking, for the batch's slowest signature: [`sign_all`] runs it off
/// the async runtime.
pub fn sign_batch(requests: &[SignRequest]) -> Vec<Result<XmssSignature, PqSignError>> {
    use rayon::prelude::*;
    let mut checked: Vec<Result<(Arc<PqKey>, u32), PqSignError>> = requests
        .iter()
        .map(|request| {
            let key = key(&request.pubkey).ok_or(PqSignError::UnknownValidator)?;
            let leaf_index = u32::try_from(request.leaf)
                .map_err(|_| PqSignError::LeafOutOfRange(request.leaf))?;
            Ok((key, leaf_index))
        })
        .collect();
    // Checked before the claim, so an unsignable leaf is not recorded as spent.
    let claimable: Vec<SignRequest> = requests
        .iter()
        .zip(&checked)
        .filter(|(_, checked)| checked.is_ok())
        .map(|(request, _)| *request)
        .collect();
    let claims = signed_leaves()
        .lock()
        .expect("PQ leaf record poisoned")
        .claim_all(&claimable);
    let signable = checked.iter_mut().filter(|checked| checked.is_ok());
    for (checked, claim) in signable.zip(claims) {
        if let Err(err) = claim {
            *checked = Err(err);
        }
    }
    requests
        .par_iter()
        .zip(checked)
        .map(|(request, checked)| {
            let (key, leaf_index) = checked?;
            Ok(sign_claimed(request, &key, leaf_index))
        })
        .collect()
}

/// [`sign_batch`] on tokio's blocking pool, so neither the flush nor the
/// hashing holds the task that awaits it.
pub async fn sign_all(requests: Vec<SignRequest>) -> Vec<Result<XmssSignature, PqSignError>> {
    if requests.is_empty() {
        return Vec::new();
    }
    let count = requests.len();
    tokio::task::spawn_blocking(move || sign_batch(&requests))
        .await
        .unwrap_or_else(|err| {
            let reason = err.to_string();
            (0..count)
                .map(|_| Err(PqSignError::Task(reason.clone())))
                .collect()
        })
}

/// One [`sign_all`] signature.
pub async fn sign(pubkey: &BlsPubkey, leaf: u64, root: Root) -> Result<XmssSignature, PqSignError> {
    let request = SignRequest {
        pubkey: *pubkey,
        leaf,
        root,
    };
    sign_all(vec![request])
        .await
        .pop()
        .expect("one answer per request")
}

/// The signature at a leaf already claimed for `request.root`.
fn sign_claimed(request: &SignRequest, key: &PqKey, leaf_index: u32) -> XmssSignature {
    // Signing builds the leaf's bottom tree if the key lacks it, seconds on
    // the duty's own deadline; `prepare_bottom_tree` exists so that it never
    // does. Prepared first, timed, so a build that still lands here is seen.
    if let Some(elapsed) = prepare_tree(&key.xmss, leaf_index) {
        warn!(
            pubkey = %encode_pubkey(&request.pubkey),
            tree = bottom_tree_of(request.leaf),
            leaf = request.leaf,
            elapsed_ms = elapsed.as_millis() as u64,
            "Built a leanXMSS bottom tree at signing time"
        );
        store_trees(&request.pubkey, key);
    }
    let signature = leanvm_lean_xmss::sign(&key.xmss, &request.root.0, leaf_index);
    XmssSignature(signature.to_bytes())
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

    /// One signature, on this thread.
    fn sign_now(pubkey: &BlsPubkey, leaf: u64, root: Root) -> Result<XmssSignature, PqSignError> {
        let request = SignRequest {
            pubkey: *pubkey,
            leaf,
            root,
        };
        sign_batch(&[request]).pop().unwrap()
    }

    fn request(pubkey: BlsPubkey, leaf: u64, root: u8) -> SignRequest {
        SignRequest {
            pubkey,
            leaf,
            root: Root::from([root; 32]),
        }
    }

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
        let first = sign_now(&pubkey, leaf, Root::from([1; 32])).unwrap();
        assert_eq!(sign_now(&pubkey, leaf, Root::from([1; 32])).unwrap(), first);
        assert!(matches!(
            sign_now(&pubkey, leaf, Root::from([2; 32])),
            Err(PqSignError::LeafUsed(_))
        ));
        let public = request[16..].try_into().unwrap();
        assert!(ethlambda_crypto::lean_xmss::verify(
            &public, leaf, &[1; 32], &first.0
        ));
        assert!(matches!(
            sign_now(&pubkey, 1 << 32, Root::from([1; 32])),
            Err(PqSignError::LeafOutOfRange(_))
        ));
    }

    /// A batch answers each request in its place: a refused one costs only
    /// itself, and a leaf is claimed only for a request that can sign.
    #[test]
    fn a_batch_signs_each_request_in_its_place() {
        let pubkey = BlsPubkey([23; 48]);
        let unknown = BlsPubkey([24; 48]);
        derive_and_register(pubkey, &[23; 32], 0, None);
        // Slot 0's bottom tree, which registering built.
        let spent = slot_leaf(1, LEAF_OFFSET_PTC_ATTESTER);
        let free = slot_leaf(2, LEAF_OFFSET_PTC_ATTESTER);
        let other = slot_leaf(3, LEAF_OFFSET_AGGREGATE_AND_PROOF);
        sign_now(&pubkey, spent, Root::from([1; 32])).unwrap();

        let requests = [
            request(pubkey, free, 1),
            request(pubkey, spent, 2),
            request(unknown, free, 1),
            request(pubkey, other, 3),
            request(pubkey, 1 << 32, 1),
        ];
        let signed = sign_batch(&requests);
        assert_eq!(signed.len(), requests.len());
        assert!(matches!(signed[1], Err(PqSignError::LeafUsed(_))));
        assert!(matches!(signed[2], Err(PqSignError::UnknownValidator)));
        assert!(matches!(signed[4], Err(PqSignError::LeafOutOfRange(_))));
        let public = request_key(&pubkey).unwrap()[16..].try_into().unwrap();
        for at in [0, 3] {
            let signature = signed[at].as_ref().unwrap();
            let SignRequest { leaf, root, .. } = requests[at];
            assert!(ethlambda_crypto::lean_xmss::verify(
                &public,
                leaf,
                &root.0,
                &signature.0
            ));
        }
        let record = signed_leaves().lock().unwrap();
        assert!(!record.roots.contains_key(&(unknown, free)));
        assert!(!record.roots.contains_key(&(pubkey, 1 << 32)));
        assert_eq!(
            record.roots.get(&(pubkey, spent)),
            Some(&Root::from([1; 32]))
        );
    }

    /// A batch cannot spend one leaf on two roots, and what it claims is
    /// written once and found again after a restart.
    #[test]
    fn a_batch_claims_each_leaf_once_and_records_it_in_one_write() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(LEAF_RECORD_FILE);
        let (pubkey, other) = (BlsPubkey([15; 48]), BlsPubkey([16; 48]));
        let (held, fresh) = (
            slot_leaf(100, LEAF_OFFSET_PTC_ATTESTER),
            slot_leaf(101, LEAF_OFFSET_PTC_ATTESTER),
        );
        {
            let (mut record, _) = LeafRecord::open(&path, 0).unwrap();
            record.claim(&pubkey, held, Root::from([1; 32])).unwrap();
            let claims = record.claim_all(&[
                request(pubkey, fresh, 1),
                request(pubkey, fresh, 2),
                request(pubkey, held, 2),
                request(pubkey, held, 1),
                request(other, fresh, 2),
                request(pubkey, fresh, 1),
            ]);
            let refused: Vec<bool> = claims
                .iter()
                .map(|claim| matches!(claim, Err(PqSignError::LeafUsed(_))))
                .collect();
            assert_eq!(refused, [false, true, true, false, false, false]);
            assert!(
                claims
                    .iter()
                    .all(|claim| matches!(claim, Ok(()) | Err(PqSignError::LeafUsed(_))))
            );
        }
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            3 * LEAF_RECORD_SIZE as u64,
            "the held leaf, then the batch's two new ones"
        );
        let (mut record, count) = LeafRecord::open(&path, 0).unwrap();
        assert_eq!(count, 3);
        let claims = record.claim_all(&[request(pubkey, fresh, 2), request(other, fresh, 1)]);
        assert!(
            claims
                .iter()
                .all(|claim| matches!(claim, Err(PqSignError::LeafUsed(_))))
        );
    }

    /// When the batch's write fails, every leaf it claimed for the first
    /// time fails with it and none is kept, so none is signed.
    #[test]
    fn a_failed_write_fails_every_new_leaf_of_the_batch() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(LEAF_RECORD_FILE);
        std::fs::write(&path, []).unwrap();
        let pubkey = BlsPubkey([17; 48]);
        let held = slot_leaf(100, LEAF_OFFSET_PTC_ATTESTER);
        let mut record = LeafRecord::default();
        record.claim(&pubkey, held, Root::from([1; 32])).unwrap();
        // Read-only: the write is refused.
        record.file = Some(std::fs::File::open(&path).unwrap());

        let claims = record.claim_all(&[
            request(pubkey, slot_leaf(101, LEAF_OFFSET_PTC_ATTESTER), 1),
            request(pubkey, held, 1),
            request(pubkey, slot_leaf(102, LEAF_OFFSET_PTC_ATTESTER), 1),
        ]);
        assert!(matches!(claims[0], Err(PqSignError::Record(_))));
        assert!(matches!(claims[1], Ok(())), "already recorded");
        assert!(matches!(claims[2], Err(PqSignError::Record(_))));
        assert_eq!(record.roots.len(), 1);
    }

    /// A key's stored trees load back holding every bottom tree it built,
    /// past the genesis-era ones, and sign what the key signs; a file for
    /// another registered key or another seed, a damaged or truncated one,
    /// and a missing one are not used.
    #[test]
    fn stored_trees_load_back_and_a_bad_file_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let secret = [31u8; 32];
        let pubkey = BlsPubkey([31; 48]);
        let xmss = pq_keys::xmss_key(&secret);
        // The PQ devnet's per-slot tree at slot 9400, which no cache record holds.
        let leaf = slot_leaf(9_400, LEAF_OFFSET_PTC_ATTESTER) as u32;
        xmss.prepare(leaf);
        let public = xmss.public_key().to_bytes();
        let key = PqKey {
            xmss,
            vrf_seed: pq_keys::vrf_seed(&secret),
            vrf: OnceLock::new(),
            request_key: [0; 48],
            storing: Mutex::new(tree_mac_key(&secret)),
        };
        let path = xmss_tree_path(directory.path(), &pubkey);
        store_trees_at(&path, &key);
        assert!(has_stored_trees(directory.path(), &pubkey));

        let loaded = stored_key(&path, &secret, Some(&public)).expect("the stored trees load");
        assert_eq!(loaded.cache_to_bytes(), key.xmss.cache_to_bytes());
        assert!(
            prepare_tree(&loaded, leaf).is_none(),
            "the loaded key holds the tree"
        );
        let expected = leanvm_lean_xmss::sign(&key.xmss, &[4; 32], leaf);
        let signed = leanvm_lean_xmss::sign(&loaded, &[4; 32], leaf);
        assert_eq!(signed.to_bytes(), expected.to_bytes());

        let mut elsewhere = public;
        elsewhere[0] ^= 1;
        assert!(stored_key(&path, &secret, Some(&elsewhere)).is_none());
        assert!(stored_key(&path, &[32u8; 32], None).is_none());
        let mut bytes = std::fs::read(&path).unwrap();
        let mut retagged = bytes.clone();
        *retagged.last_mut().unwrap() ^= 1;
        std::fs::write(&path, &retagged).unwrap();
        assert!(stored_key(&path, &secret, None).is_none(), "a bad tag");
        let untagged = &bytes[TREE_FILE_MAGIC.len()..bytes.len() - TREE_FILE_TAG_SIZE];
        std::fs::write(&path, untagged).unwrap();
        assert!(stored_key(&path, &secret, None).is_none(), "no header");
        bytes[TREE_FILE_MAGIC.len() + leanvm_lean_xmss::PUB_KEY_SIZE + 100] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        assert!(stored_key(&path, &secret, None).is_none());
        std::fs::write(&path, &bytes[..10]).unwrap();
        assert!(stored_key(&path, &secret, None).is_none());
        let missing = directory.path().join("missing.bin");
        assert!(stored_key(&missing, &secret, None).is_none());
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
            derive_and_register(pubkey, &secret, 0, Some(&record)).source,
            KeySource::Cached
        );
        assert_eq!(request_key(&pubkey), Some(request));
        let leaf = slot_leaf(3, LEAF_OFFSET_PTC_ATTESTER);
        let signature = sign_now(&pubkey, leaf, Root::from([4; 32])).unwrap();
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
            derive_and_register(BlsPubkey([16; 48]), &secret, 0, Some(&damaged)).source,
            KeySource::CacheRefused
        );
        let mut elsewhere = public;
        elsewhere[0] ^= 1;
        let misregistered = XmssCacheRecord {
            registered: elsewhere,
            bytes,
        };
        assert_eq!(
            derive_and_register(BlsPubkey([17; 48]), &secret, 0, Some(&misregistered)).source,
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
        assert!(sign_now(&pubkey, attestation_leaf(0), Root::from([1; 32])).is_ok());
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
