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
//! The other per-slot messages (payload attestations, aggregates,
//! envelopes) are guarded here, in memory: one signing root per leaf. The
//! specification asks for that record to persist across restarts; this one
//! does not, so a client restarted within a slot could sign a second
//! different message at one of those leaves.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use ethlambda_crypto::{lean_xmss, pq_keys, vrf};
use ethlambda_types::beacon::constants::{
    XMSS_ATTESTATION_LEAVES, XMSS_BUILDER_BID_LEAVES, XMSS_LEAVES_PER_SLOT, XMSS_RESERVED_LEAVES,
};
use ethlambda_types::beacon::primitives::{BlsPubkey, Epoch, Root, Slot, XmssSignature};
use tracing::warn;

pub use ethlambda_types::beacon::constants::{
    LEAF_OFFSET_AGGREGATE_AND_PROOF, LEAF_OFFSET_BEACON_PROPOSER,
    LEAF_OFFSET_EXECUTION_PAYLOAD_ENVELOPE, LEAF_OFFSET_PTC_ATTESTER,
};

/// The directory under the validators directory that holds each key's VRF
/// tree nodes, one file per validator, named by its BLS public key.
pub const VRF_TREE_DIRECTORY: &str = "pq_vrf_trees";

/// A validator's PQ key material.
pub struct PqKey {
    xmss: lean_xmss::SecretKey,
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

fn signed_leaves() -> &'static Mutex<HashMap<(BlsPubkey, u64), Root>> {
    static SIGNED: OnceLock<Mutex<HashMap<(BlsPubkey, u64), Root>>> = OnceLock::new();
    SIGNED.get_or_init(Default::default)
}

/// Derives and registers the PQ key of the validator whose BLS key is
/// `pubkey` and secret key `secret` (32 bytes, big-endian, as a keystore
/// holds it). Slow: a leanXMSS key generation (about a second and a half
/// across cores), plus building the bottom trees its next attestation and
/// per-slot signatures fall in. Run it off the async runtime.
///
/// The key signs from here on. Its VRF tree, which only a proposal reads, is
/// [`prepare_vrf_tree`]'s to supply.
pub fn derive_and_register(pubkey: BlsPubkey, secret: &[u8; 32], current_slot: Slot) {
    let xmss = pq_keys::xmss_key(secret);
    let mut request_key = [0u8; 48];
    request_key[16..].copy_from_slice(&xmss.public_key().to_bytes());
    // Warm the two bottom trees duties sign in, so the first signature of each
    // kind does not pay for one at its deadline.
    let epoch = current_slot / ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;
    let _ = xmss.prepare(attestation_leaf(epoch) as u32);
    let _ = xmss.prepare(slot_leaf(current_slot, 0) as u32);
    let key = Arc::new(PqKey {
        xmss,
        vrf_seed: pq_keys::vrf_seed(secret),
        vrf: OnceLock::new(),
        request_key,
    });
    let mut registry = registry().write().expect("PQ key registry poisoned");
    registry.by_request.insert(request_key, pubkey);
    registry.by_bls.insert(pubkey, key);
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
    #[error("leanXMSS: {0:?}")]
    Sign(lean_xmss::SignError),
    #[error("the VRF tree is still being hashed")]
    VrfTreeNotReady,
    #[error("slot {0} is past the VRF tree's last leaf")]
    SlotPastVrfTree(Slot),
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

/// The precomputed VRF state record of validator `index` from `source`: an
/// HTTP(S) URL of a whole file of [`vrf::STATE_RECORD_SIZE`]-byte records,
/// asked for the one record by range, or a path to such a file. `None` when
/// the file does not reach that index.
pub async fn fetch_vrf_state(
    client: &reqwest::Client,
    source: &str,
    index: u64,
) -> Result<Option<Vec<u8>>, String> {
    let size = vrf::STATE_RECORD_SIZE as u64;
    let first = index * size;
    if !(source.starts_with("http://") || source.starts_with("https://")) {
        // Read whole: such a file is about a kilobyte per validator, and this
        // runs once per key, off the duty path.
        let bytes = std::fs::read(source).map_err(|err| err.to_string())?;
        let end = (first + size) as usize;
        return Ok(bytes.get(first as usize..end).map(<[u8]>::to_vec));
    }
    let response = client
        .get(source)
        .header(
            reqwest::header::RANGE,
            format!("bytes={first}-{}", first + size - 1),
        )
        .timeout(std::time::Duration::from_secs(60))
        .send()
        .await
        .map_err(|err| err.to_string())?;
    let status = response.status();
    if status == reqwest::StatusCode::RANGE_NOT_SATISFIABLE {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(format!("{source} answered {status}"));
    }
    let body = response.bytes().await.map_err(|err| err.to_string())?;
    // A server that ignores the range sends the whole file.
    let record = if status == reqwest::StatusCode::PARTIAL_CONTENT {
        body.get(..size as usize)
    } else {
        body.get(first as usize..(first + size) as usize)
    };
    Ok(record.map(<[u8]>::to_vec))
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
/// Blocking: building a bottom tree takes about a second and a half.
pub fn sign(pubkey: &BlsPubkey, leaf: u64, root: Root) -> Result<XmssSignature, PqSignError> {
    let key = key(pubkey).ok_or(PqSignError::UnknownValidator)?;
    {
        let mut signed = signed_leaves().lock().expect("PQ leaf record poisoned");
        match signed.get(&(*pubkey, leaf)) {
            Some(previous) if *previous != root => return Err(PqSignError::LeafUsed(leaf)),
            Some(_) => {}
            None => {
                signed.insert((*pubkey, leaf), root);
            }
        }
    }
    let leaf_index = u32::try_from(leaf).map_err(|_| PqSignError::LeafUsed(leaf))?;
    let signature = key
        .xmss
        .sign(&root.0, leaf_index)
        .map_err(PqSignError::Sign)?;
    let bytes: [u8; ethlambda_types::beacon::constants::XMSS_SIGNATURE_SIZE] = signature
        .to_bytes()
        .try_into()
        .expect("a leanXMSS signature is XMSS_SIGNATURE_SIZE bytes");
    Ok(XmssSignature(bytes))
}

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
        derive_and_register(pubkey, &secret, 0);
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
        assert!(lean_xmss::verify(&public, leaf, &[1; 32], &first.0));
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
        derive_and_register(pubkey, &secret, 0);
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
        assert_eq!(proof[0].0, vrf::compute_vrf_secret(&vrf_seed, 5));
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
        let root = vrf::fold_vrf_branch(&vrf::compute_vrf_secret(&vrf_seed, 0), &branch, 0);
        vrf::VrfTree::from_compact_state(vrf_seed, root, branch)
            .unwrap()
            .to_state_record()
    }

    #[tokio::test]
    async fn a_precomputed_state_gives_a_key_its_tree_for_this_and_the_next_start() {
        let secret = [12u8; 32];
        let pubkey = BlsPubkey([13; 48]);
        derive_and_register(pubkey, &secret, 0);
        let vrf_seed = pq_keys::vrf_seed(&secret);
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(restore_vrf_tree(&pubkey, directory.path()), None);

        // A file of two records, this key's second: it is read by index.
        let ours = stand_in_state_record(vrf_seed);
        let theirs = stand_in_state_record([3; 32]);
        let file = directory.path().join("states.vrf");
        std::fs::write(&file, [theirs.clone(), ours.clone()].concat()).unwrap();
        let client = reqwest::Client::new();
        let source = file.to_str().unwrap();
        assert_eq!(
            fetch_vrf_state(&client, source, 1).await.unwrap(),
            Some(ours.clone())
        );
        assert_eq!(fetch_vrf_state(&client, source, 2).await.unwrap(), None);

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
