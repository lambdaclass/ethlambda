//! The validator definitions file: which validators this client signs for.
//!
//! One YAML-free, JSON-Lines-free plain list, deliberately separate from the
//! keystores themselves. It is what the keymanager API mutates, so a key
//! imported at runtime is still there after a restart, and so are the fee
//! recipient, graffiti and gas limit it was given.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::beacon_node::dto::parse_pubkey;
use crate::error::{Error, Result};
use crate::proposer_settings::{
    GRAFFITI_BYTES, Overrides, ProposerSettings, SettingChange, fee_recipient_from_text,
    fee_recipient_to_text, graffiti_from_text, graffiti_to_text,
};
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
    /// This validator's own fee recipient, `0x`-prefixed hex, in place of
    /// `--suggested-fee-recipient`. The three fields below are Lighthouse's,
    /// name for name and form for form, so its file reads here and this one
    /// reads there. Each is absent from the file, not `null`, when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested_fee_recipient: Option<String>,
    /// This validator's own graffiti, as text, in place of `--graffiti`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graffiti: Option<String>,
    /// This validator's own gas limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gas_limit: Option<u64>,
}

impl ValidatorDefinition {
    /// The entry's three overrides, parsed. A value the file holds in the
    /// wrong form is an error naming the entry and the field: a validator
    /// proposing to an address the operator did not mean is worse than a
    /// refused start.
    pub fn overrides(&self) -> Result<Overrides> {
        let reject = |field: &str, reason: String| Error::Keystore {
            path: format!("validator_definitions.yml entry {}", self.voting_public_key),
            reason: format!("{field} {reason}"),
        };
        let fee_recipient = self
            .suggested_fee_recipient
            .as_deref()
            .map(|text| {
                fee_recipient_from_text(text).map_err(|why| reject("suggested_fee_recipient", why))
            })
            .transpose()?;
        let graffiti = self
            .graffiti
            .as_deref()
            .map(|text| {
                graffiti_from_text(text).ok_or_else(|| {
                    reject(
                        "graffiti",
                        format!(
                            "is {} bytes encoded as UTF-8; the field holds {GRAFFITI_BYTES}",
                            text.len()
                        ),
                    )
                })
            })
            .transpose()?;
        Ok(Overrides {
            fee_recipient,
            graffiti,
            gas_limit: self.gas_limit,
        })
    }

    /// Write one change into the entry, in the form the file carries.
    pub fn apply(&mut self, change: SettingChange) {
        match change {
            SettingChange::FeeRecipient(address) => {
                self.suggested_fee_recipient = address.as_ref().map(fee_recipient_to_text);
            }
            SettingChange::Graffiti(graffiti) => {
                self.graffiti = graffiti.as_ref().map(graffiti_to_text);
            }
            SettingChange::GasLimit(gas_limit) => self.gas_limit = gas_limit,
        }
    }

    /// Carry another entry's overrides onto this one, for a re-imported key
    /// whose entry is rebuilt from the new keystore.
    pub fn with_overrides_of(mut self, other: &ValidatorDefinition) -> Self {
        self.suggested_fee_recipient = other.suggested_fee_recipient.clone();
        self.graffiti = other.graffiti.clone();
        self.gas_limit = other.gas_limit;
        self
    }
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
    ///
    /// That holds across a power loss too, not only a crash of this process:
    /// `write_private` flushes the temporary file before the rename, so the
    /// name never points at data that has not reached the device. Without it
    /// the rename can survive and the data not, and an empty definitions file
    /// is not an error: it parses as no validators at all, so the client would
    /// start, idle, and say so in one warning. The directory is flushed after
    /// the rename so that a change the keymanager has answered for is not
    /// undone by one either.
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
        })?;

        // Logged, not returned. The rename above is the commit: the new file
        // is already what every reader sees, and every caller takes an error
        // from here to mean the file is unchanged (an import undoes its entry,
        // a settings route leaves memory alone). Failing now would make that
        // false, to report a rename that is in place but not yet flushed.
        let _ = secure_fs::sync_dir(validators_dir).inspect_err(|err| {
            warn!(
                path = %validators_dir.display(),
                %err,
                "Wrote the validator definitions file but could not flush its directory; the \
                 change is in place and may not survive a power loss"
            )
        });
        Ok(())
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
                suggested_fee_recipient: None,
                graffiti: None,
                gas_limit: None,
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

    /// Install every enabled entry's overrides into `settings`, returning how
    /// many entries carried one. What startup does once the keys are loaded.
    /// A disabled entry keeps its fields in the file for when it is enabled
    /// again, and is skipped here as its key is skipped by `load`.
    pub fn seed_overrides(&self, settings: &ProposerSettings) -> Result<usize> {
        let mut seeded = 0;
        for definition in self.enabled() {
            let overrides = definition.overrides()?;
            if overrides.is_empty() {
                continue;
            }
            let pubkey =
                parse_pubkey(&definition.voting_public_key).map_err(|err| Error::Keystore {
                    path: format!(
                        "validator_definitions.yml entry {}",
                        definition.voting_public_key
                    ),
                    reason: format!("the voting_public_key is unreadable: {err}"),
                })?;
            settings.seed(&pubkey, overrides);
            seeded += 1;
        }
        Ok(seeded)
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
            suggested_fee_recipient: None,
            graffiti: None,
            gas_limit: None,
        }
    }

    /// An entry with no overrides is written exactly as it always was: the
    /// three fields are absent, not `null`, so a file this client writes
    /// stays readable by a reader that predates them.
    #[test]
    fn an_entry_without_overrides_is_written_without_the_fields() {
        let yaml = serde_yaml_ng::to_string(&ValidatorDefinitions(vec![definition("0xaa", true)]))
            .expect("serializes");
        assert!(!yaml.contains("suggested_fee_recipient"), "{yaml}");
        assert!(!yaml.contains("graffiti"), "{yaml}");
        assert!(!yaml.contains("gas_limit"), "{yaml}");
    }

    #[test]
    fn overrides_round_trip_through_the_file() {
        use ethlambda_types::beacon::primitives::H160;

        let dir = tempfile::tempdir().expect("temp dir");
        let mut entry = definition("0xaa", true);
        entry.apply(SettingChange::FeeRecipient(Some(H160([0xbb; 20]))));
        entry.apply(SettingChange::Graffiti(Some(
            graffiti_from_text("hello").expect("fits"),
        )));
        entry.apply(SettingChange::GasLimit(Some(30_000_000)));
        ValidatorDefinitions(vec![entry.clone(), definition("0xbb", true)])
            .save(dir.path())
            .expect("saves");

        let read = ValidatorDefinitions::open(dir.path()).expect("opens");
        assert_eq!(read.0[0], entry);
        assert_eq!(
            read.0[0].overrides().expect("parses"),
            Overrides {
                fee_recipient: Some(H160([0xbb; 20])),
                graffiti: Some(graffiti_from_text("hello").expect("fits")),
                gas_limit: Some(30_000_000),
            }
        );
        assert_eq!(read.0[1].overrides().expect("parses"), Overrides::default());
    }

    /// Lighthouse's own file, fields it writes that this client does not
    /// included, reads here with the three overrides picked up.
    #[test]
    fn a_lighthouse_written_entry_parses_with_its_overrides() {
        use ethlambda_types::beacon::primitives::H160;

        let yaml = format!(
            "- enabled: true
  voting_public_key: 0x{}
  description: \"\"
  \
             graffiti: from lighthouse
  suggested_fee_recipient: 0x{}
  gas_limit: 36000000
  \
             builder_proposals: false
  type: local_keystore
  \
             voting_keystore_path: /keys/voting-keystore.json
  \
             voting_keystore_password_path: /secrets/password
",
            "ab".repeat(48),
            "cd".repeat(20)
        );
        let definitions: ValidatorDefinitions = serde_yaml_ng::from_str(&yaml).expect("parses");
        let overrides = definitions.0[0].overrides().expect("valid");
        assert_eq!(overrides.fee_recipient, Some(H160([0xcd; 20])));
        assert_eq!(
            overrides.graffiti,
            Some(graffiti_from_text("from lighthouse").expect("fits"))
        );
        assert_eq!(overrides.gas_limit, Some(36_000_000));
    }

    #[test]
    fn a_malformed_override_is_an_error_naming_the_field() {
        let mut entry = definition("0xaa", true);
        entry.suggested_fee_recipient = Some("0x1234".to_string());
        let err = entry.overrides().expect_err("two bytes is not an address");
        assert!(
            err.to_string().contains("suggested_fee_recipient") && err.to_string().contains("0xaa"),
            "got {err}"
        );

        let mut entry = definition("0xaa", true);
        entry.graffiti = Some("a".repeat(GRAFFITI_BYTES + 1));
        let err = entry.overrides().expect_err("33 bytes does not fit");
        assert!(err.to_string().contains("graffiti"), "got {err}");
    }

    /// Startup seeding: enabled entries' overrides land in the settings, a
    /// disabled entry's do not.
    #[test]
    fn seeding_installs_enabled_entries_overrides_only() {
        use ethlambda_types::beacon::primitives::{BlsPubkey, Bytes32, H160};

        let enabled_key = format!("0x{}", "11".repeat(48));
        let disabled_key = format!("0x{}", "22".repeat(48));
        let mut enabled = definition(&enabled_key, true);
        enabled.apply(SettingChange::FeeRecipient(Some(H160([0xbb; 20]))));
        let mut disabled = definition(&disabled_key, false);
        disabled.apply(SettingChange::GasLimit(Some(1)));
        let definitions = ValidatorDefinitions(vec![enabled, disabled, definition("0xcc", true)]);

        let settings = ProposerSettings::new(Bytes32::ZERO, None);
        let seeded = definitions.seed_overrides(&settings).expect("seeds");
        assert_eq!(seeded, 1);
        assert_eq!(
            settings.fee_recipient(&BlsPubkey([0x11; 48])),
            Some(H160([0xbb; 20]))
        );
        assert_eq!(
            settings.overrides(&BlsPubkey([0x22; 48])),
            Overrides::default()
        );
    }

    #[test]
    fn clearing_an_override_removes_the_field() {
        let mut entry = definition("0xaa", true);
        entry.apply(SettingChange::GasLimit(Some(1)));
        entry.apply(SettingChange::GasLimit(None));
        assert_eq!(entry, definition("0xaa", true));
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
