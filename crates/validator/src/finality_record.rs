//! Each key's EIP-8453 `FinalitySigningRecord`, persisted before every FG
//! attestation it allows.
//!
//! validator.md keeps one record per validator key (the first target voted
//! at each height, the heights timed out, the finality locks, the entries
//! named) and requires that "the record persists across restarts" and that
//! "the record and selected data must be persisted before signing". This is
//! protocol state as much as slashing protection: the record decides whether
//! the next vote at a height is a target vote or a timeout, so a client that
//! forgot it would not only risk a slashable double vote but vote differently
//! from what the protocol prescribes. It is kept apart from the client's
//! EIP-3076 slashing-protection record, which covers Casper FFG attestations
//! and blocks, and is not part of its interchange.
//!
//! The selection and recording rules are `ethlambda-decoupled`'s
//! ([`FinalitySigningRecord::attest`]); this module owns the storage:
//!
//! - one JSON file per key, `<dir>/0x<pubkey>.json`, written atomically and
//!   flushed to disk at mode `0600` ([`crate::secure_fs::write_private_durably`])
//!   before [`FinalitySigningRecords::attest`] returns the data to sign;
//! - a record is read from its file the first time its key attests in a run
//!   (a key imported at runtime starts from its file, or empty);
//! - a file that does not parse refuses the key rather than starting it
//!   empty, since an empty record would allow exactly the votes the lost one
//!   forbade;
//! - one lock over every key, held from selection through the write, which
//!   serializes selecting and recording per key as validator.md requires.
//!
//! A failed write leaves the in-memory record as it was and returns an error:
//! nothing is signed for data that is not on disk.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use ethlambda_decoupled::{FinalityAttestationInput, FinalitySigningRecord};
use ethlambda_types::beacon::containers::eip8453;
use ethlambda_types::beacon::primitives::BlsPubkey;
use tokio::sync::Mutex;

use crate::error::{Error, Result};

/// The directory, under the validators directory, the records are kept in.
pub const RECORDS_DIR: &str = "finality_signing";

/// Every key's finality signing record, loaded on first use and written
/// through on every change.
#[derive(Debug)]
pub struct FinalitySigningRecords {
    dir: PathBuf,
    records: Mutex<HashMap<BlsPubkey, FinalitySigningRecord>>,
}

impl FinalitySigningRecords {
    /// Records kept in `dir`, created on the first write.
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            records: Mutex::new(HashMap::new()),
        }
    }

    /// The records of a client whose validators directory is
    /// `validators_dir`.
    pub fn in_validators_dir(validators_dir: &Path) -> Self {
        Self::new(validators_dir.join(RECORDS_DIR))
    }

    fn path(&self, pubkey: &BlsPubkey) -> PathBuf {
        self.dir.join(format!("0x{}.json", hex::encode(pubkey.0)))
    }

    /// `get_finality_attestation_data` for `pubkey`'s record and `input`,
    /// then `record_finality_attestation`, then the record written to disk:
    /// the data to sign, or `None` when the record suppresses the vote. An
    /// `Err` (an unreadable record, a failed write) means nothing may be
    /// signed.
    pub async fn attest(
        &self,
        pubkey: &BlsPubkey,
        input: &FinalityAttestationInput,
    ) -> Result<Option<eip8453::AttestationData>> {
        let mut records = self.records.lock().await;
        let record = match records.get(pubkey) {
            Some(record) => record.clone(),
            None => self.load(pubkey)?,
        };
        let mut updated = record.clone();
        let Some(data) = updated.attest(input) else {
            records.insert(*pubkey, record);
            return Ok(None);
        };
        self.persist(pubkey, &updated)?;
        records.insert(*pubkey, updated);
        Ok(Some(data.into()))
    }

    /// `pubkey`'s record as last written, for inspection.
    pub async fn record(&self, pubkey: &BlsPubkey) -> Result<FinalitySigningRecord> {
        let records = self.records.lock().await;
        match records.get(pubkey) {
            Some(record) => Ok(record.clone()),
            None => self.load(pubkey),
        }
    }

    fn load(&self, pubkey: &BlsPubkey) -> Result<FinalitySigningRecord> {
        let path = self.path(pubkey);
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|err| {
                Error::Decode(format!(
                    "finality signing record {} is unreadable ({err}); refusing to attest with \
                     this key rather than starting it empty",
                    path.display()
                ))
            }),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                Ok(FinalitySigningRecord::default())
            }
            Err(source) => Err(Error::Io {
                path: path.display().to_string(),
                source,
            }),
        }
    }

    fn persist(&self, pubkey: &BlsPubkey, record: &FinalitySigningRecord) -> Result<()> {
        let io = |source| Error::Io {
            path: self.dir.display().to_string(),
            source,
        };
        if !self.dir.exists() {
            std::fs::create_dir_all(&self.dir).map_err(io)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let permissions = std::fs::Permissions::from_mode(0o700);
                std::fs::set_permissions(&self.dir, permissions).map_err(io)?;
            }
        }
        let bytes = serde_json::to_vec_pretty(record)
            .map_err(|err| Error::Decode(format!("encoding a finality signing record: {err}")))?;
        let path = self.path(pubkey);
        // Either error leaves the in-memory record as it was and signs
        // nothing. After an `Unflushed` one the file may already hold the
        // new record, which only forbids a vote that was never signed.
        crate::secure_fs::write_private_durably(&path, bytes).map_err(|err| {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::decoupled::HeightCheckpoint;
    use ethlambda_types::primitives::H256;

    fn pubkey(byte: u8) -> BlsPubkey {
        BlsPubkey([byte; 48])
    }

    fn cp(height: u64, byte: u8) -> HeightCheckpoint {
        HeightCheckpoint::new(height, H256([byte; 32]))
    }

    fn input(target: HeightCheckpoint) -> FinalityAttestationInput {
        FinalityAttestationInput {
            target,
            justified: HeightCheckpoint::empty(),
            finalized_height: 0,
        }
    }

    #[tokio::test]
    async fn a_record_survives_a_restart_and_forbids_a_second_target_vote() {
        let dir = tempfile::tempdir().unwrap();
        let records = FinalitySigningRecords::in_validators_dir(dir.path());
        let key = pubkey(1);
        let first = records.attest(&key, &input(cp(3, 0xaa))).await.unwrap();
        let first = first.expect("a fresh key votes for the target");
        assert!(!first.timeout);
        assert_eq!(first.target.height, 3);

        // A restart: a fresh store over the same directory reads the record.
        let restarted = FinalitySigningRecords::in_validators_dir(dir.path());
        let stored = restarted.record(&key).await.unwrap();
        assert_eq!(stored.targets.get(&3), Some(&H256([0xaa; 32])));
        // The same entry is never named twice at a height.
        assert_eq!(
            restarted.attest(&key, &input(cp(3, 0xaa))).await.unwrap(),
            None
        );
        // Another root at the height is a timeout, not a second target vote.
        let other = restarted
            .attest(&key, &input(cp(3, 0xbb)))
            .await
            .unwrap()
            .expect("a timeout");
        assert!(other.timeout);
        // And the timeout is on disk too.
        let again = FinalitySigningRecords::in_validators_dir(dir.path());
        assert!(again.record(&key).await.unwrap().timeouts.contains(&3));
        // Another key is untouched.
        assert_eq!(
            again.record(&pubkey(2)).await.unwrap(),
            FinalitySigningRecord::default()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_record_file_is_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let records = FinalitySigningRecords::in_validators_dir(dir.path());
        let key = pubkey(1);
        records.attest(&key, &input(cp(1, 0xaa))).await.unwrap();
        let mode = std::fs::metadata(records.path(&key))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let dir_mode = std::fs::metadata(dir.path().join(RECORDS_DIR))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700);
    }

    #[tokio::test]
    async fn an_unreadable_record_refuses_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let records = FinalitySigningRecords::in_validators_dir(dir.path());
        let key = pubkey(1);
        std::fs::create_dir_all(dir.path().join(RECORDS_DIR)).unwrap();
        std::fs::write(records.path(&key), b"{ not json").unwrap();
        assert!(records.attest(&key, &input(cp(1, 0xaa))).await.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_failed_write_signs_nothing_and_changes_nothing() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        // A records directory this process may read but not write: the
        // record loads (empty), and its write fails.
        let records_dir = dir.path().join(RECORDS_DIR);
        std::fs::create_dir_all(&records_dir).unwrap();
        std::fs::set_permissions(&records_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let records = FinalitySigningRecords::in_validators_dir(dir.path());
        let key = pubkey(1);
        let attempt = records.attest(&key, &input(cp(1, 0xaa))).await;
        std::fs::set_permissions(&records_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(attempt, Err(Error::Io { .. })), "{attempt:?}");
        assert_eq!(
            records.records.lock().await.get(&key),
            None,
            "nothing recorded in memory either"
        );
    }
}
