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
    pub fn enabled(&self) -> impl Iterator<Item = &ValidatorDefinition> {
        self.0.iter().filter(|definition| definition.enabled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
