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
#[serde(try_from = "RawDefinition", into = "RawDefinition")]
pub struct ValidatorDefinition {
    /// Whether this validator should perform duties. A disabled entry keeps its
    /// keystore on disk and is simply not loaded.
    pub enabled: bool,
    /// The validator's BLS public key, `0x`-prefixed hex.
    pub voting_public_key: String,
    /// Where the key is and how it signs. Kept at the top level of the entry
    /// in the file, beside a `type` naming it; see [`RawDefinition`].
    pub signing: SigningDefinition,
}

/// How one definition's key signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningDefinition {
    /// An EIP-2335 keystore on disk, decrypted into this process at startup.
    LocalKeystore {
        /// Path to the EIP-2335 keystore.
        voting_keystore_path: PathBuf,
        /// Path to the file holding that keystore's password.
        voting_keystore_password_path: PathBuf,
    },
    /// A Web3Signer holding the key; `url` is the signer's base URL.
    Web3Signer { url: String },
}

/// The `type` of an entry, under the names Lighthouse's definitions file uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SigningKind {
    LocalKeystore,
    Web3signer,
}

/// One entry exactly as the file holds it.
///
/// Every entry is written with a `type`, and one that has a `type` must carry
/// that method's fields and no other's. An entry without one, which is every
/// entry written before remote signers existed, is read by its fields, and is
/// refused when it names both a keystore and a `url`: loading that as either
/// would silently ignore half of what the operator wrote, and loading it as
/// local would bypass the remote signer and its slashing protection.
///
/// Unknown fields are refused rather than skipped, so a Lighthouse field this
/// client does not implement (`root_certificate_path`, say) is reported at
/// startup instead of quietly having no effect.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDefinition {
    enabled: bool,
    voting_public_key: String,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    kind: Option<SigningKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    voting_keystore_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    voting_keystore_password_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    url: Option<String>,
}

impl TryFrom<RawDefinition> for ValidatorDefinition {
    type Error = String;

    fn try_from(raw: RawDefinition) -> std::result::Result<Self, String> {
        let names_keystore =
            raw.voting_keystore_path.is_some() || raw.voting_keystore_password_path.is_some();
        let names_url = raw.url.is_some();
        let kind = match raw.kind {
            Some(SigningKind::LocalKeystore) if names_url => {
                return Err(format!(
                    "{}: a local_keystore entry must not carry a url",
                    raw.voting_public_key
                ));
            }
            Some(SigningKind::Web3signer) if names_keystore => {
                return Err(format!(
                    "{}: a web3signer entry must not carry keystore paths",
                    raw.voting_public_key
                ));
            }
            Some(kind) => kind,
            None if names_keystore && names_url => {
                return Err(format!(
                    "{}: the entry names both a keystore and a url; remove one, or set \
                     `type: local_keystore` or `type: web3signer`",
                    raw.voting_public_key
                ));
            }
            None if names_url => SigningKind::Web3signer,
            None if names_keystore => SigningKind::LocalKeystore,
            None => {
                return Err(format!(
                    "{}: the entry names no way to sign: it needs keystore paths or a url",
                    raw.voting_public_key
                ));
            }
        };
        let missing = |field: &str| format!("{}: missing field `{field}`", raw.voting_public_key);
        let signing = match kind {
            SigningKind::LocalKeystore => SigningDefinition::LocalKeystore {
                voting_keystore_path: raw
                    .voting_keystore_path
                    .clone()
                    .ok_or_else(|| missing("voting_keystore_path"))?,
                voting_keystore_password_path: raw
                    .voting_keystore_password_path
                    .clone()
                    .ok_or_else(|| missing("voting_keystore_password_path"))?,
            },
            SigningKind::Web3signer => SigningDefinition::Web3Signer {
                url: raw.url.clone().ok_or_else(|| missing("url"))?,
            },
        };
        Ok(Self {
            enabled: raw.enabled,
            voting_public_key: raw.voting_public_key,
            signing,
        })
    }
}

impl From<ValidatorDefinition> for RawDefinition {
    fn from(definition: ValidatorDefinition) -> Self {
        let (kind, voting_keystore_path, voting_keystore_password_path, url) =
            match definition.signing {
                SigningDefinition::LocalKeystore {
                    voting_keystore_path,
                    voting_keystore_password_path,
                } => (
                    SigningKind::LocalKeystore,
                    Some(voting_keystore_path),
                    Some(voting_keystore_password_path),
                    None,
                ),
                SigningDefinition::Web3Signer { url } => {
                    (SigningKind::Web3signer, None, None, Some(url))
                }
            };
        Self {
            enabled: definition.enabled,
            voting_public_key: definition.voting_public_key,
            kind: Some(kind),
            voting_keystore_path,
            voting_keystore_password_path,
            url,
        }
    }
}

impl SigningDefinition {
    pub fn is_remote(&self) -> bool {
        matches!(self, Self::Web3Signer { .. })
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
                signing: SigningDefinition::LocalKeystore {
                    voting_keystore_path: keystore_path,
                    voting_keystore_password_path: secrets_dir.join(&pubkey),
                },
                voting_public_key: pubkey,
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
            definitions.0[0].signing,
            SigningDefinition::LocalKeystore {
                voting_keystore_path: validators.path().join("0xaa").join("voting-keystore.json"),
                voting_keystore_password_path: secrets.path().join("0xaa"),
            }
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
            signing: SigningDefinition::LocalKeystore {
                voting_keystore_path: PathBuf::from("keystore.json"),
                voting_keystore_password_path: PathBuf::from("password.txt"),
            },
        }
    }

    fn remote_definition(pubkey: &str, url: &str) -> ValidatorDefinition {
        ValidatorDefinition {
            enabled: true,
            voting_public_key: pubkey.to_string(),
            signing: SigningDefinition::Web3Signer {
                url: url.to_string(),
            },
        }
    }

    /// A file written before remote signers existed has no `url` and no tag,
    /// and must read back as the local entry it always was.
    #[test]
    fn a_pre_remote_signer_file_still_parses() {
        let dir = tempfile::tempdir().expect("temp dir");
        let legacy = "- enabled: true\n  voting_public_key: '0xaa'\n  \
                      voting_keystore_path: keystore.json\n  \
                      voting_keystore_password_path: password.txt\n";
        std::fs::write(dir.path().join(DEFINITIONS_FILE), legacy).expect("writes");

        let read = ValidatorDefinitions::open(dir.path()).expect("opens");
        assert_eq!(read.0, vec![definition("0xaa", true)]);
    }

    #[test]
    fn remote_and_local_entries_round_trip_together() {
        let dir = tempfile::tempdir().expect("temp dir");
        let written = ValidatorDefinitions(vec![
            definition("0xaa", true),
            remote_definition("0xbb", "https://signer:9000"),
        ]);
        written.save(dir.path()).expect("saves");

        let text = std::fs::read_to_string(dir.path().join(DEFINITIONS_FILE)).expect("reads");
        assert!(text.contains("url: https://signer:9000"), "{text}");
        assert!(text.contains("type: web3signer"), "{text}");
        assert!(text.contains("type: local_keystore"), "{text}");

        let read = ValidatorDefinitions::open(dir.path()).expect("opens");
        assert_eq!(read.0, written.0);
        assert!(read.0[1].signing.is_remote());
        assert!(!read.0[0].signing.is_remote());
    }

    /// An entry with neither a keystore nor a URL describes no way to sign,
    /// and must be refused rather than read as one of the variants.
    #[test]
    fn an_entry_with_no_signing_method_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(
            dir.path().join(DEFINITIONS_FILE),
            "- enabled: true\n  voting_public_key: '0xaa'\n",
        )
        .expect("writes");
        assert!(ValidatorDefinitions::open(dir.path()).is_err());
    }

    /// Open a definitions file holding `yaml`, rendering a refusal as text.
    fn open_text(yaml: &str) -> std::result::Result<ValidatorDefinitions, String> {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(dir.path().join(DEFINITIONS_FILE), yaml).expect("writes");
        ValidatorDefinitions::open(dir.path()).map_err(|err| err.to_string())
    }

    /// An entry naming both a keystore and a url must not load as either:
    /// read as local, it would sign in this process and bypass the remote
    /// signer's slashing protection without a word.
    #[test]
    fn an_untyped_entry_with_two_signing_methods_is_refused() {
        let err = open_text(
            "- enabled: true\n  voting_public_key: '0xaa'\n  \
             voting_keystore_path: keystore.json\n  \
             voting_keystore_password_path: password.txt\n  \
             url: https://signer:9000\n",
        )
        .expect_err("ambiguous entry");
        assert!(err.contains("both a keystore and a url"), "{err}");
    }

    #[test]
    fn a_typed_entry_must_carry_only_its_own_fields() {
        let local_with_url = open_text(
            "- enabled: true\n  voting_public_key: '0xaa'\n  type: local_keystore\n  \
             voting_keystore_path: keystore.json\n  \
             voting_keystore_password_path: password.txt\n  \
             url: https://signer:9000\n",
        );
        assert!(local_with_url.is_err());
        let remote_with_keystore = open_text(
            "- enabled: true\n  voting_public_key: '0xaa'\n  type: web3signer\n  \
             url: https://signer:9000\n  voting_keystore_path: keystore.json\n",
        );
        assert!(remote_with_keystore.is_err());
        let remote = open_text(
            "- enabled: true\n  voting_public_key: '0xaa'\n  type: web3signer\n  \
             url: https://signer:9000\n",
        )
        .expect("a well-formed remote entry");
        assert_eq!(
            remote.0,
            vec![remote_definition("0xaa", "https://signer:9000")]
        );
    }

    /// The refusal names what is missing, rather than serde's generic "did
    /// not match any variant".
    #[test]
    fn a_local_entry_missing_its_password_path_names_the_field() {
        let err = open_text(
            "- enabled: true\n  voting_public_key: '0xaa'\n  \
             voting_keystore_path: keystore.json\n",
        )
        .expect_err("incomplete entry");
        assert!(err.contains("voting_keystore_password_path"), "{err}");
    }

    /// A field this client does not implement is reported, not ignored: an
    /// operator who set `root_certificate_path` expects it to take effect.
    #[test]
    fn an_unknown_field_is_refused() {
        let err = open_text(
            "- enabled: true\n  voting_public_key: '0xaa'\n  type: web3signer\n  \
             url: https://signer:9000\n  root_certificate_path: ca.pem\n",
        )
        .expect_err("unknown field");
        assert!(err.contains("root_certificate_path"), "{err}");
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
