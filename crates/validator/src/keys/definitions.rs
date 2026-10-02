//! The validator definitions file: which validators this client signs for.
//!
//! One YAML-free, JSON-Lines-free plain list, deliberately separate from the
//! keystores themselves. It is what the keymanager API mutates, so a key
//! imported at runtime is still there after a restart.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::secure_fs;

/// The file's name inside the validators directory.
pub const DEFINITIONS_FILE: &str = "validator_definitions.yml";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorDefinition {
    /// Whether this validator should perform duties. A disabled entry keeps its
    /// keystore on disk and is simply not loaded.
    pub enabled: bool,
    /// The validator's BLS public key, `0x`-prefixed hex.
    pub voting_public_key: String,
    /// Path to the EIP-2335 keystore.
    pub voting_keystore_path: PathBuf,
    /// Path to the file holding that keystore's password.
    pub voting_keystore_password_path: PathBuf,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ValidatorDefinitions(pub Vec<ValidatorDefinition>);

impl ValidatorDefinitions {
    /// Read the definitions file from a validators directory, returning an empty
    /// set if it does not exist yet.
    pub fn open(validators_dir: &Path) -> Result<Self> {
        let path = validators_dir.join(DEFINITIONS_FILE);
        match std::fs::read_to_string(&path) {
            Ok(contents) => serde_yaml_ng::from_str(&contents).map_err(|err| Error::Keystore {
                path: path.display().to_string(),
                reason: err.to_string(),
            }),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(err) => Err(Error::Io {
                path: path.display().to_string(),
                source: err,
            }),
        }
    }

    /// Write the definitions back, replacing the file.
    ///
    /// Writes to a sibling temporary file and renames it over the target
    /// rather than truncating in place. The keymanager API calls this while
    /// validators are signing, and a crash partway through an in-place write
    /// would leave a truncated file that stops the client booting, losing every
    /// validator rather than the one being changed. `rename` within one
    /// directory is atomic, so a reader sees the old file or the new one.
    pub fn save(&self, validators_dir: &Path) -> Result<()> {
        let path = validators_dir.join(DEFINITIONS_FILE);
        let contents = serde_yaml_ng::to_string(self).map_err(|err| Error::Keystore {
            path: path.display().to_string(),
            reason: err.to_string(),
        })?;

        // Mode set on the temporary file, not the final path: `rename`
        // preserves it, and setting it here means the file is never
        // world-readable even for the instant between creation and rename.
        let temporary = validators_dir.join(format!("{DEFINITIONS_FILE}.tmp"));
        secure_fs::write_private(&temporary, contents).map_err(|source| Error::Io {
            path: temporary.display().to_string(),
            source,
        })?;
        std::fs::rename(&temporary, &path).map_err(|source| Error::Io {
            path: path.display().to_string(),
            source,
        })
    }

    /// The entries that should be loaded and signed with.
    /// Write a definitions file for a validators directory that has none, by
    /// discovering the keystores laid out the way Lighthouse lays them out:
    /// `<validators_dir>/<0xpubkey>/voting-keystore.json`, each with its
    /// password in `<secrets_dir>/<0xpubkey>`. This is the layout
    /// `eth2-val-tools`, `staking-deposit-cli` imports and ethereum-package
    /// produce, and what Lighthouse's own client discovers without a
    /// definitions file.
    ///
    /// Does nothing when the file already exists: it is the operator's (and the
    /// keymanager's) record of which validators run, and rescanning would
    /// resurrect a key the keymanager deleted. The public key is read from each
    /// keystore; `ValidatorStore::load` then checks it against the decrypted
    /// secret as it does for every definition. Returns how many were written.
    pub fn discover_if_absent(validators_dir: &Path, secrets_dir: &Path) -> Result<usize> {
        if validators_dir.join(DEFINITIONS_FILE).exists() {
            return Ok(0);
        }
        let entries = std::fs::read_dir(validators_dir).map_err(|source| Error::Io {
            path: validators_dir.display().to_string(),
            source,
        })?;
        let mut definitions = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| Error::Io {
                path: validators_dir.display().to_string(),
                source,
            })?;
            let keystore_path = entry.path().join("voting-keystore.json");
            if !keystore_path.is_file() {
                continue;
            }
            let json = std::fs::read_to_string(&keystore_path).map_err(|source| Error::Io {
                path: keystore_path.display().to_string(),
                source,
            })?;
            let pubkey = crate::keys::keystore::Keystore::from_json(&json)
                .ok()
                .and_then(|keystore| keystore.pubkey)
                .ok_or_else(|| Error::Keystore {
                    path: keystore_path.display().to_string(),
                    reason: "a discovered keystore must name its public key".to_string(),
                })?;
            let pubkey = format!("0x{}", pubkey.trim_start_matches("0x"));
            definitions.push(ValidatorDefinition {
                enabled: true,
                voting_keystore_password_path: secrets_dir.join(&pubkey),
                voting_public_key: pubkey,
                voting_keystore_path: keystore_path,
            });
        }
        // Directory order is not stable across filesystems; sorting makes the
        // written file reproducible.
        definitions.sort_by(|a, b| a.voting_public_key.cmp(&b.voting_public_key));
        let count = definitions.len();
        if count > 0 {
            Self(definitions).save(validators_dir)?;
        }
        Ok(count)
    }

    pub fn enabled(&self) -> impl Iterator<Item = &ValidatorDefinition> {
        self.0.iter().filter(|definition| definition.enabled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A keystore file naming `pubkey`, in the minimal shape discovery reads.
    fn write_keystore(dir: &Path, pubkey: &str) {
        let key_dir = dir.join(format!("0x{pubkey}"));
        std::fs::create_dir_all(&key_dir).unwrap();
        let json = serde_json::json!({
            "crypto": {
                "kdf": { "function": "pbkdf2", "params": { "dklen": 32, "c": 1, "prf": "hmac-sha256", "salt": "00" }, "message": "" },
                "checksum": { "function": "sha256", "params": {}, "message": "00" },
                "cipher": { "function": "aes-128-ctr", "params": { "iv": "00" }, "message": "00" }
            },
            "pubkey": pubkey,
            "path": "",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "version": 4
        });
        std::fs::write(key_dir.join("voting-keystore.json"), json.to_string()).unwrap();
    }

    #[test]
    fn keystores_in_the_lighthouse_layout_are_discovered_when_no_file_exists() {
        let validators = tempfile::tempdir().unwrap();
        let secrets = tempfile::tempdir().unwrap();
        write_keystore(validators.path(), "bb");
        write_keystore(validators.path(), "aa");
        std::fs::create_dir(validators.path().join("not-a-key")).unwrap();

        let written =
            ValidatorDefinitions::discover_if_absent(validators.path(), secrets.path()).unwrap();
        assert_eq!(written, 2);
        let definitions = ValidatorDefinitions::open(validators.path()).unwrap();
        assert_eq!(definitions.0[0].voting_public_key, "0xaa");
        assert_eq!(
            definitions.0[0].voting_keystore_password_path,
            secrets.path().join("0xaa")
        );
        assert!(definitions.0.iter().all(|definition| definition.enabled));
    }

    #[test]
    fn an_existing_definitions_file_is_never_rescanned() {
        let validators = tempfile::tempdir().unwrap();
        let secrets = tempfile::tempdir().unwrap();
        write_keystore(validators.path(), "aa");
        ValidatorDefinitions(Vec::new())
            .save(validators.path())
            .unwrap();

        let written =
            ValidatorDefinitions::discover_if_absent(validators.path(), secrets.path()).unwrap();
        assert_eq!(written, 0);
        assert!(
            ValidatorDefinitions::open(validators.path())
                .unwrap()
                .0
                .is_empty()
        );
    }

    fn definition(pubkey: &str, enabled: bool) -> ValidatorDefinition {
        ValidatorDefinition {
            enabled,
            voting_public_key: pubkey.to_string(),
            voting_keystore_path: PathBuf::from("keystore.json"),
            voting_keystore_password_path: PathBuf::from("password.txt"),
        }
    }

    #[test]
    fn a_missing_file_is_an_empty_set_not_an_error() {
        let dir = tempfile::tempdir().expect("temp dir");
        let definitions = ValidatorDefinitions::open(dir.path()).expect("opens");
        assert!(definitions.0.is_empty());
    }

    #[test]
    fn round_trips_through_the_file() {
        let dir = tempfile::tempdir().expect("temp dir");

        let written =
            ValidatorDefinitions(vec![definition("0xaa", true), definition("0xbb", false)]);
        written.save(dir.path()).expect("saves");

        let read = ValidatorDefinitions::open(dir.path()).expect("opens");
        assert_eq!(read.0, written.0);
    }

    #[test]
    fn saving_over_an_existing_file_exercises_the_rename_path() {
        let dir = tempfile::tempdir().expect("temp dir");

        let first = ValidatorDefinitions(vec![definition("0xaa", true)]);
        first.save(dir.path()).expect("saves");

        let second = ValidatorDefinitions(vec![definition("0xaa", true), definition("0xbb", true)]);
        second
            .save(dir.path())
            .expect("saves again, renaming over the existing file");

        let read = ValidatorDefinitions::open(dir.path()).expect("opens");
        assert_eq!(read.0, second.0);
    }

    #[test]
    fn only_enabled_entries_are_loaded() {
        let definitions =
            ValidatorDefinitions(vec![definition("0xaa", true), definition("0xbb", false)]);
        let enabled: Vec<_> = definitions.enabled().collect();
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0].voting_public_key, "0xaa");
    }

    #[cfg(unix)]
    #[test]
    fn the_saved_file_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("temp dir");
        ValidatorDefinitions(vec![definition("0xaa", true)])
            .save(dir.path())
            .expect("saves");

        let mode = std::fs::metadata(dir.path().join(DEFINITIONS_FILE))
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "got {mode:o}");
    }
}
