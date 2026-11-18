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

/// The only EIP-3076 interchange version this client reads or writes.
pub const INTERCHANGE_VERSION: &str = "5";

/// An EIP-3076 version 5 interchange: the shape of this client's own record
/// and of every file it imports. The record reader ([`read`]) and the
/// importer ([`parse`], which `SlashingProtection::stage` calls) share these
/// types, and both read strictly: a field the format does not define is an
/// error rather than ignored, as it is in Lighthouse's EIP-3076 types, so a
/// file that is not the interchange it claims to be is refused whole instead
/// of half read.
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

/// Parse an EIP-3076 version 5 interchange, complete or minimal, into its
/// chain and each entry's watermarks, in file order.
///
/// A pubkey listed more than once is returned more than once: an import merges
/// them, while the record this client writes must never contain one twice.
/// The error is a reason, for the caller to attach to whatever it was reading.
pub(crate) fn parse(text: &str) -> std::result::Result<(Root, Vec<(BlsPubkey, Record)>), String> {
    if text.trim().is_empty() {
        return Err("empty; refusing to treat it as \"nothing signed\"".to_string());
    }
    let interchange: Interchange =
        serde_json::from_str(text).map_err(|err| format!("malformed: {err}"))?;
    if interchange.metadata.interchange_format_version != INTERCHANGE_VERSION {
        return Err(format!(
            "interchange format version {:?}, expected {INTERCHANGE_VERSION:?}",
            interchange.metadata.interchange_format_version
        ));
    }
    let mut entries = Vec::with_capacity(interchange.data.len());
    for entry in &interchange.data {
        let record = record_of(entry).map_err(|reason| {
            format!(
                "validator {}: {reason}",
                crate::beacon_node::dto::encode_hex(&entry.pubkey)
            )
        })?;
        entries.push((BlsPubkey(entry.pubkey), record));
    }
    Ok((
        Root::from(interchange.metadata.genesis_validators_root),
        entries,
    ))
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
    let (root, entries) = parse(&text).map_err(invalid)?;

    let mut records = HashMap::with_capacity(entries.len());
    for (pubkey, record) in entries {
        if records.insert(pubkey, record).is_some() {
            return Err(invalid(format!(
                "validator {} appears more than once",
                crate::beacon_node::dto::encode_hex(&pubkey.0)
            )));
        }
    }
    Ok((root, records))
}

/// The watermarks one entry stands for: the highest slot, source and target it
/// lists. More than one entry of a kind is reduced rather than refused, since
/// taking the maximum is never less strict than any one of them.
///
/// An attestation whose source is at or past its target is refused outside
/// genesis, the one shape the importer does not absorb: it is never valid, and
/// read into the record it would refuse every honest attestation after it
/// until the chain justified past that source.
fn record_of(entry: &Entry) -> std::result::Result<Record, String> {
    let block_slot = entry.signed_blocks.iter().map(|block| block.slot).max();

    let mut attestation: Option<Signed> = None;
    for signed in &entry.signed_attestations {
        // The same shape the record and the attestation-data check refuse.
        // Read into the record, it would refuse every honest attestation
        // after it.
        if super::is_impossible_source(signed.source_epoch, signed.target_epoch) {
            return Err(format!(
                "attestation source epoch {} is at or after its target epoch {}",
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

/// `records` as a minimal EIP-3076 interchange for the chain named by
/// `genesis_validators_root`.
///
/// Compact rather than pretty: the record is rewritten once per slot and per
/// block, and its size grows with the number of validators. Entries are
/// written in pubkey order so the bytes depend only on the content, which
/// keeps a diff of two files meaningful.
pub(crate) fn render<'a>(
    genesis_validators_root: Root,
    records: impl Iterator<Item = (&'a BlsPubkey, &'a Record)>,
) -> serde_json::Result<String> {
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
    serde_json::to_string(&interchange)
}

/// Durably replace the record at `path` with `records`.
pub(crate) fn write<'a>(
    path: &Path,
    genesis_validators_root: Root,
    records: impl Iterator<Item = (&'a BlsPubkey, &'a Record)>,
) -> Result<()> {
    let contents =
        render(genesis_validators_root, records).map_err(|err| Error::SlashingProtection {
            path: path.display().to_string(),
            reason: format!("could not encode the record: {err}"),
        })?;
    crate::secure_fs::write_private_durably(path, contents).map_err(|err| {
        let path = path.display().to_string();
        if err.after_rename {
            Error::Unflushed {
                path,
                source: err.source,
            }
        } else {
            Error::Io {
                path,
                source: err.source,
            }
        }
    })
}

/// Take the exclusive lock in `directory`, held until the returned file is
/// dropped.
pub(crate) fn lock(directory: &Path) -> Result<File> {
    let io_error = |source| Error::Io {
        path: directory.display().to_string(),
        source,
    };
    // The directory itself, not a lock file beside the record: the record is
    // replaced by a rename on every write, so a lock on it would be on a
    // stale inode; and a lock file can be deleted, after which a second
    // process locks a fresh one and both sign. The directory is the one
    // inode nothing here replaces, and `flock` takes a directory descriptor.
    let file = File::open(directory).map_err(io_error)?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(Error::SlashingProtection {
            path: directory.display().to_string(),
            reason: "in use by another process; two processes must never sign with the same keys"
                .to_string(),
        }),
        Err(std::fs::TryLockError::Error(source)) => Err(io_error(source)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A source at its target, outside genesis, is refused on read as it is
    /// on write: loaded, it would refuse every honest attestation after it.
    #[test]
    fn an_entry_with_a_source_at_its_target_is_refused() {
        let entry = Entry {
            pubkey: [1; 48],
            signed_blocks: vec![],
            signed_attestations: vec![SignedAttestation {
                source_epoch: 5,
                target_epoch: 5,
                signing_root: None,
            }],
        };
        let err = record_of(&entry).expect_err("source at target");
        assert!(err.contains("at or after"), "{err}");

        let genesis = Entry {
            pubkey: [1; 48],
            signed_blocks: vec![],
            signed_attestations: vec![SignedAttestation {
                source_epoch: 0,
                target_epoch: 0,
                signing_root: None,
            }],
        };
        assert!(record_of(&genesis).is_ok());
    }

    /// Several entries of a kind for one validator reduce to their maxima:
    /// what keeps a file holding more than one from lowering a watermark.
    #[test]
    fn several_entries_of_a_kind_reduce_to_their_maxima() {
        let entry = Entry {
            pubkey: [1; 48],
            signed_blocks: vec![
                SignedBlock {
                    slot: 7,
                    signing_root: None,
                },
                SignedBlock {
                    slot: 3,
                    signing_root: None,
                },
            ],
            signed_attestations: vec![
                SignedAttestation {
                    source_epoch: 5,
                    target_epoch: 9,
                    signing_root: None,
                },
                SignedAttestation {
                    source_epoch: 2,
                    target_epoch: 4,
                    signing_root: None,
                },
            ],
        };

        let record = record_of(&entry).expect("valid");

        assert_eq!(
            record,
            Record {
                block_slot: Some(7),
                attestation: Some(Signed {
                    source: 5,
                    target: 9
                }),
            }
        );
    }
}
