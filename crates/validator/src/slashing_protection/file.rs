//! The slashing-protection file: its format, a strict reader, a durable
//! writer, and the lock that keeps a second process away from it.
//!
//! # Format
//!
//! The file is an EIP-3076 version 5 interchange in its minimal form: per
//! validator, at most one `signed_blocks` entry (the highest slot) and at most
//! one `signed_attestations` entry (the highest source and the highest target).
//! Storing the interchange format itself means the record a validator is
//! protected by and the record it would be exported with are the same bytes,
//! with no second encoding to drift from the first.
//!
//! # Reading fails closed
//!
//! Anything other than a well-formed file is an error, never an empty record.
//! An empty record would let every validator sign anything, so a file that is
//! empty, truncated, of another version, or names one validator twice must stop
//! the client rather than be taken as "nothing signed yet". Prysm's minimal
//! store reads an empty file as exactly that.
//!
//! # Writing is durable before it returns
//!
//! Every write goes to a temporary sibling, is flushed to disk, renamed over
//! the real file, and then the directory is flushed so the rename itself
//! survives a power loss. A reader therefore sees the old file or the new one,
//! never a mixture, and a write that returned `Ok` is on disk.

use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

use ethlambda_types::beacon::primitives::{BlsPubkey, Epoch, Root, Slot};
use ethlambda_types::beacon::serde_helpers::{hex_array, quoted_or_bare};
use serde::{Deserialize, Serialize};

use super::{Record, Signed};
use crate::error::{Error, Result};

/// The record's file name inside the validators directory.
pub const FILE_NAME: &str = "slashing_protection.json";

/// The lock's file name, next to the record.
///
/// A file of its own rather than a lock on the record: the record is replaced
/// by a rename on every write, and a lock held on the old inode would not stop
/// a second process from opening the new one.
pub const LOCK_FILE_NAME: &str = "slashing_protection.lock";

/// The only EIP-3076 interchange version this client reads or writes.
pub const INTERCHANGE_VERSION: &str = "5";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Interchange {
    metadata: Metadata,
    data: Vec<Entry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    interchange_format_version: String,
    #[serde(with = "hex_array")]
    genesis_validators_root: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    #[serde(with = "hex_array")]
    pubkey: [u8; 48],
    signed_blocks: Vec<SignedBlock>,
    signed_attestations: Vec<SignedAttestation>,
}

/// `signing_root` is optional in EIP-3076 and never written here: the minimal
/// rule does not compare roots. It is still accepted on read, so a file another
/// tool wrote in this shape is not rejected for carrying one.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedBlock {
    #[serde(with = "quoted_or_bare")]
    slot: Slot,
    #[serde(default, skip_serializing)]
    #[allow(dead_code)]
    signing_root: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedAttestation {
    #[serde(with = "quoted_or_bare")]
    source_epoch: Epoch,
    #[serde(with = "quoted_or_bare")]
    target_epoch: Epoch,
    #[serde(default, skip_serializing)]
    #[allow(dead_code)]
    signing_root: Option<String>,
}

/// Read and validate the record at `path`.
pub(crate) fn read(path: &Path) -> Result<(Root, HashMap<BlsPubkey, Record>)> {
    let invalid = |reason: String| Error::SlashingProtection {
        path: path.display().to_string(),
        reason,
    };

    let text = std::fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.display().to_string(),
        source,
    })?;
    if text.trim().is_empty() {
        return Err(invalid(
            "the file is empty; refusing to treat it as \"nothing signed\"".to_string(),
        ));
    }
    let interchange: Interchange =
        serde_json::from_str(&text).map_err(|err| invalid(format!("malformed: {err}")))?;
    if interchange.metadata.interchange_format_version != INTERCHANGE_VERSION {
        return Err(invalid(format!(
            "interchange format version {:?}, expected {INTERCHANGE_VERSION:?}",
            interchange.metadata.interchange_format_version
        )));
    }

    let mut records = HashMap::with_capacity(interchange.data.len());
    for entry in interchange.data {
        let pubkey = BlsPubkey(entry.pubkey);
        let record = record_of(&entry).map_err(|reason| {
            invalid(format!(
                "validator {}: {reason}",
                crate::beacon_node::dto::encode_hex(&pubkey.0)
            ))
        })?;
        if records.insert(pubkey, record).is_some() {
            return Err(invalid(format!(
                "validator {} appears more than once",
                crate::beacon_node::dto::encode_hex(&pubkey.0)
            )));
        }
    }
    Ok((
        Root::from(interchange.metadata.genesis_validators_root),
        records,
    ))
}

/// The watermarks one entry stands for: the highest slot, source and target it
/// lists. More than one entry of a kind is reduced rather than refused, since
/// taking the maximum is never less strict than any one of them.
fn record_of(entry: &Entry) -> std::result::Result<Record, String> {
    let block_slot = entry.signed_blocks.iter().map(|block| block.slot).max();

    let mut attestation: Option<Signed> = None;
    for signed in &entry.signed_attestations {
        if signed.source_epoch > signed.target_epoch {
            return Err(format!(
                "attestation source epoch {} is after its target epoch {}",
                signed.source_epoch, signed.target_epoch
            ));
        }
        let next = Signed {
            source: signed.source_epoch,
            target: signed.target_epoch,
        };
        attestation = Some(match attestation {
            Some(current) => current.max_with(next),
            None => next,
        });
    }
    Ok(Record {
        block_slot,
        attestation,
    })
}

/// Whether the record at `path` exists, failing closed.
///
/// Only "no such file" is absence. Anything else that is not a regular file
/// (a symlink, perhaps to a volume that is not mounted, or a directory), and
/// any error reading its metadata, is an error: taking any of them for absence
/// would create a fresh record and orphan the real one.
pub(crate) fn exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => Err(Error::SlashingProtection {
            path: path.display().to_string(),
            reason: "is not a regular file (a symlink or a directory); refusing to read or \
                     replace it"
                .to_string(),
        }),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(Error::Io {
            path: path.display().to_string(),
            source,
        }),
    }
}

/// Durably replace the record at `path` with `records`.
///
/// Compact rather than pretty: the file is rewritten once per slot and per
/// block, and its size grows with the number of validators. Entries are
/// written in pubkey order so the bytes depend only on the content, which
/// keeps a diff of two files meaningful.
pub(crate) fn write<'a>(
    path: &Path,
    genesis_validators_root: Root,
    records: impl Iterator<Item = (&'a BlsPubkey, &'a Record)>,
) -> Result<()> {
    let mut data: Vec<Entry> = records
        .map(|(pubkey, record)| Entry {
            pubkey: pubkey.0,
            signed_blocks: record
                .block_slot
                .map(|slot| SignedBlock {
                    slot,
                    signing_root: None,
                })
                .into_iter()
                .collect(),
            signed_attestations: record
                .attestation
                .map(|signed| SignedAttestation {
                    source_epoch: signed.source,
                    target_epoch: signed.target,
                    signing_root: None,
                })
                .into_iter()
                .collect(),
        })
        .collect();
    data.sort_by_key(|entry| entry.pubkey);

    let interchange = Interchange {
        metadata: Metadata {
            interchange_format_version: INTERCHANGE_VERSION.to_string(),
            genesis_validators_root: genesis_validators_root.0,
        },
        data,
    };
    let contents = serde_json::to_vec(&interchange).map_err(|err| Error::SlashingProtection {
        path: path.display().to_string(),
        reason: format!("could not encode the record: {err}"),
    })?;
    crate::secure_fs::write_private_durably(path, contents).map_err(|source| Error::Io {
        path: path.display().to_string(),
        source,
    })
}

/// Take the exclusive lock in `directory`, held until the returned file is
/// dropped.
pub(crate) fn lock(directory: &Path) -> Result<File> {
    let path = directory.join(LOCK_FILE_NAME);
    let io_error = |source| Error::Io {
        path: path.display().to_string(),
        source,
    };
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(io_error)?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(Error::SlashingProtection {
            path: path.display().to_string(),
            reason: "in use by another process; two processes must never sign with the same keys"
                .to_string(),
        }),
        Err(std::fs::TryLockError::Error(source)) => Err(io_error(source)),
    }
}
