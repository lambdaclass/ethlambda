//! The set of validators this client can sign for, and how each one signs.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Weak};

use blst::min_pk::SecretKey;
use ethlambda_types::beacon::primitives::{BLS_PUBKEY_SIZE, BlsPubkey};
use tracing::info;
use zeroize::Zeroizing;

use crate::beacon_node::dto::{encode_hex, parse_pubkey};
use crate::error::{Error, Result};
use crate::keys::definitions::{DEFINITIONS_FILE, SigningDefinition, ValidatorDefinitions};
use crate::keys::keystore::Keystore;
use crate::keys::web3signer::Web3Signer;

/// How one validator produces a signature.
///
/// Cheap to clone: both arms are an `Arc`, so a signing path can take a copy
/// out of the store under a short read guard and sign after releasing it,
/// which matters for the remote arm, whose signature is an HTTP round trip.
///
/// **Never derive `Debug` on this type, or on anything holding it.**
/// `blst::min_pk::SecretKey` zeroizes on drop but still derives a plain
/// `Debug` that prints the raw scalar, so a derived `Debug` anywhere up the
/// chain would put a validator's signing key into a log line. `Zeroizing`
/// is no protection either: it forwards `Debug` to the type it wraps, so it
/// controls the key's lifetime in memory, not whether it can be printed.
#[derive(Clone)]
pub enum SigningMethod {
    /// The secret key is held in this process, decrypted from a local keystore.
    LocalKeystore { secret_key: Arc<SecretKey> },
    /// The key is held by a Web3Signer, which signs on this client's behalf.
    Web3Signer { signer: Arc<Web3Signer> },
}

impl SigningMethod {
    pub fn is_remote(&self) -> bool {
        matches!(self, Self::Web3Signer { .. })
    }
}

/// Every validator this client signs for, keyed by public key.
pub struct ValidatorStore {
    validators: HashMap<BlsPubkey, SigningMethod>,
    /// One client per remote signer URL, shared by every validator on it, so
    /// a hundred keys behind one signer are one connection pool rather than a
    /// hundred.
    ///
    /// Weak: the validators using a client hold it, and so does any signature
    /// in flight through it. A client stops being reachable here once the
    /// last of those lets go, with no pruning pass having to guess whether an
    /// in-flight request still counts as a user.
    signers: HashMap<String, Weak<Web3Signer>>,
}

impl ValidatorStore {
    pub fn new() -> Self {
        Self {
            validators: HashMap::new(),
            signers: HashMap::new(),
        }
    }

    /// Load every enabled definition from a validators directory.
    ///
    /// A keystore that fails to decrypt aborts startup rather than being
    /// skipped: a validator that silently does not attest looks exactly like a
    /// healthy one from inside this process, and the operator finds out from
    /// missed-attestation penalties days later. A remote entry is registered
    /// without contacting its signer: the signer may well start after this
    /// process does, and a key it turns out not to hold fails at its first
    /// signature, where it is logged and counted, rather than at startup.
    pub fn load(validators_dir: &Path) -> Result<Self> {
        let definitions = ValidatorDefinitions::open(validators_dir)?;
        let mut store = Self::new();

        let entries = definitions.0.iter().enumerate();
        for (position, definition) in entries.filter(|(_, definition)| definition.enabled) {
            let (voting_keystore_path, voting_keystore_password_path) = match &definition.signing {
                SigningDefinition::Web3Signer { url } => {
                    // Named by its place in the file, never by its `url`. The
                    // URL here is as the operator wrote it: `Web3Signer::new`
                    // has not seen it yet, so it may still carry the
                    // credentials that would be refused there, and this
                    // error is logged as startup aborts. The position also
                    // tells entries apart, which a URL shared by every key
                    // on one signer does not.
                    let pubkey = parse_pubkey(&definition.voting_public_key).map_err(|err| {
                        Error::Keystore {
                            path: validators_dir.join(DEFINITIONS_FILE).display().to_string(),
                            reason: format!(
                                "entry {} (a web3signer entry): its voting_public_key is \
                                 unreadable: {err}",
                                position + 1
                            ),
                        }
                    })?;
                    store.insert_remote(pubkey, url)?;
                    continue;
                }
                SigningDefinition::LocalKeystore {
                    voting_keystore_path,
                    voting_keystore_password_path,
                } => (voting_keystore_path, voting_keystore_password_path),
            };
            let keystore_path = resolve(validators_dir, voting_keystore_path);
            let password_path = resolve(validators_dir, voting_keystore_password_path);

            let derived = store.insert_keystore_file(&keystore_path, &password_path)?;

            // The definitions file's `voting_public_key` is a claim about what
            // is inside the keystore, and until here nothing checked it. Every
            // signing path uses `derived`, so a mismatch cannot produce a wrong
            // signature; what it does produce is a validator this client signs
            // for under one key while the definitions file names another.
            //
            // The keymanager's delete is where that becomes dangerous. It
            // removes from the store by the derived key but removes from the
            // definitions file by the *declared* one
            // (`http_api::keystores::delete_keys`), so a mismatch makes the
            // file retain the entry while the response reports `deleted`. The
            // next restart loads the keystore again and the validator signs
            // again, which is exactly the shape that produces a double vote
            // when the operator deleted the key because they moved it
            // elsewhere. Refusing here makes that path's assumption true by
            // construction rather than by hope.
            //
            // Fatal rather than skipped, consistent with every other failure in
            // this loop: a definitions file that does not describe its own
            // keystores is a configuration error to fix, not one to run half of.
            let declared =
                parse_pubkey(&definition.voting_public_key).map_err(|err| Error::Keystore {
                    path: keystore_path.display().to_string(),
                    reason: format!(
                        "the definitions entry's voting_public_key is unreadable: {err}"
                    ),
                })?;
            if declared != derived {
                return Err(Error::Keystore {
                    path: keystore_path.display().to_string(),
                    reason: format!(
                        "the definitions entry declares {} but the keystore holds {}; \
                         correct the definitions file before starting",
                        encode_hex(&declared.0),
                        encode_hex(&derived.0)
                    ),
                });
            }
        }

        info!(
            count = store.len(),
            remote = store.remote_entries().len(),
            "Loaded validator keys"
        );
        Ok(store)
    }

    /// Decrypt the keystore at `keystore_path` with the password in
    /// `password_path` and add its key, answering the public key it holds.
    ///
    /// The one place a keystore and its password file are read from disk, for
    /// [`Self::load`] and the `voluntary-exit` command alike, so the two cannot
    /// come to read a password differently. The password file is read whole,
    /// with a trailing newline trimmed: an editor leaves one, and a password
    /// ending in a newline is not something anyone chose.
    pub fn insert_keystore_file(
        &mut self,
        keystore_path: &Path,
        password_path: &Path,
    ) -> Result<BlsPubkey> {
        let json = std::fs::read_to_string(keystore_path).map_err(|source| Error::Io {
            path: keystore_path.display().to_string(),
            source,
        })?;
        let keystore = Keystore::from_json(&json).map_err(|err| Error::Keystore {
            path: keystore_path.display().to_string(),
            reason: err.to_string(),
        })?;
        let password = std::fs::read_to_string(password_path).map_err(|source| Error::Io {
            path: password_path.display().to_string(),
            source,
        })?;
        // Scrubbed on drop, like the secret `decrypt` yields from it.
        let password = Zeroizing::new(password);
        // `normalize_password` inside `decrypt` already strips every C0
        // control code, newlines included, so this trim is redundant today.
        // It stays anyway: trimming at the file-reading boundary is
        // defensible on its own and does not depend on a deeper
        // implementation detail continuing to hold. Do not delete it as dead
        // code, and do not treat it as the only thing standing between a
        // saved password file and a working decrypt.
        //
        // `decrypt` yields a `Zeroizing<[u8; 32]>`, scrubbed on drop. Deref
        // it at the call below rather than copying it out.
        let secret = keystore
            .decrypt(password.trim_end_matches(['\n', '\r']))
            .map_err(|err| Error::Keystore {
                path: keystore_path.display().to_string(),
                reason: err.to_string(),
            })?;
        self.insert_secret(&keystore_path.display().to_string(), &secret)
    }

    /// Add one secret key, deriving its public key.
    ///
    /// `origin` names where the key came from, a keystore path or the
    /// keymanager API, purely so a rejection can say which one was bad. The
    /// failure is reported as a keystore error rather than a signing one:
    /// `Error::Signing` carries the validator's public key, and here the bytes
    /// were rejected before a public key could be derived from them.
    pub fn insert_secret(&mut self, origin: &str, secret: &[u8; 32]) -> Result<BlsPubkey> {
        let secret_key = parse_secret_key(origin, secret)?;
        let pubkey = pubkey_of(&secret_key);
        self.validators.insert(
            pubkey,
            SigningMethod::LocalKeystore {
                secret_key: Arc::new(secret_key),
            },
        );
        Ok(pubkey)
    }

    /// Add a validator whose key a Web3Signer at `url` holds, replacing any
    /// method the store had for it, building the signer's client if no other
    /// validator already shares one.
    ///
    /// Nothing is asked of the signer here; see [`Self::load`] for why. The
    /// URL is checked for shape, which is the one failure worth refusing up
    /// front: an entry nobody could ever reach.
    ///
    /// For startup only. Building a client is not cheap, so a caller holding
    /// the store behind a lock uses [`Self::signer_for_url`] and
    /// [`Self::insert_remote_signer`] instead, and builds any missing client
    /// before taking the write lock.
    pub fn insert_remote(&mut self, pubkey: BlsPubkey, url: &str) -> Result<()> {
        let signer = match self.signer_for_url(url) {
            Some(signer) => signer,
            None => Arc::new(Web3Signer::new(url)?),
        };
        self.insert_remote_signer(pubkey, signer);
        Ok(())
    }

    /// The client already serving `url`, if any validator still uses one.
    /// Keyed by the URL as the client normalizes it, so `.../` and `...` name
    /// one signer rather than two.
    pub fn signer_for_url(&self, url: &str) -> Option<Arc<Web3Signer>> {
        self.signers
            .get(url.trim_end_matches('/'))
            .and_then(Weak::upgrade)
    }

    /// Every client some validator still uses, by URL. Lets a caller that
    /// builds clients outside the store's lock reuse these instead.
    pub fn remote_signers(&self) -> HashMap<String, Arc<Web3Signer>> {
        self.signers
            .iter()
            .filter_map(|(url, signer)| Some((url.clone(), signer.upgrade()?)))
            .collect()
    }

    /// Add a validator signing through an already-built `signer`, replacing
    /// any method the store had for it. A map insert and nothing more, so it
    /// is cheap enough to run under the store's write lock.
    pub fn insert_remote_signer(&mut self, pubkey: BlsPubkey, signer: Arc<Web3Signer>) {
        // Entries whose client nobody holds any more are dropped here rather
        // than on every mutation: they are a URL and a dead pointer, and a
        // lookup already treats one as absent.
        self.signers.retain(|_, signer| signer.strong_count() > 0);
        self.signers
            .insert(signer.url().to_string(), Arc::downgrade(&signer));
        self.validators
            .insert(pubkey, SigningMethod::Web3Signer { signer });
    }

    /// Derive a validator's public key from its raw secret, without adding it
    /// to the store.
    ///
    /// The keymanager API needs the pubkey to name an import's on-disk files
    /// before deciding whether to activate it, so this exists to let a
    /// handler learn that without a `&mut self` it does not have yet.
    /// Duplicating the cheap scalar validation `insert_secret` also does is
    /// simpler than splitting that method's contract in two.
    pub fn derive_pubkey(secret: &[u8; 32]) -> Result<BlsPubkey> {
        let secret_key = parse_secret_key("keymanager import", secret)?;
        Ok(pubkey_of(&secret_key))
    }

    pub fn remove(&mut self, pubkey: &BlsPubkey) -> bool {
        self.validators.remove(pubkey).is_some()
    }

    pub fn contains(&self, pubkey: &BlsPubkey) -> bool {
        self.validators.contains_key(pubkey)
    }

    /// How `pubkey` signs, as a copy the caller can hold after releasing
    /// whatever lock guards this store. `None` for a validator it does not
    /// hold.
    pub fn signer(&self, pubkey: &BlsPubkey) -> Option<SigningMethod> {
        self.validators.get(pubkey).cloned()
    }

    /// The remote signer's URL for `pubkey`, or `None` when the key is local
    /// or unknown.
    pub fn remote_url(&self, pubkey: &BlsPubkey) -> Option<String> {
        match self.validators.get(pubkey)? {
            SigningMethod::Web3Signer { signer } => Some(signer.url().to_string()),
            SigningMethod::LocalKeystore { .. } => None,
        }
    }

    pub fn pubkeys(&self) -> Vec<BlsPubkey> {
        self.validators.keys().copied().collect()
    }

    /// The validators whose key is in this process.
    pub fn local_pubkeys(&self) -> Vec<BlsPubkey> {
        self.validators
            .iter()
            .filter(|(_, method)| !method.is_remote())
            .map(|(pubkey, _)| *pubkey)
            .collect()
    }

    /// The validators a remote signer signs for, each with its signer's URL.
    pub fn remote_entries(&self) -> Vec<(BlsPubkey, String)> {
        self.validators
            .iter()
            .filter_map(|(pubkey, method)| match method {
                SigningMethod::Web3Signer { signer } => Some((*pubkey, signer.url().to_string())),
                SigningMethod::LocalKeystore { .. } => None,
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.validators.len()
    }

    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }
}

impl Default for ValidatorStore {
    fn default() -> Self {
        Self::new()
    }
}

fn resolve(base: &Path, path: &Path) -> std::path::PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

/// Validate a raw secret and parse it into a signing key. Shared by
/// `insert_secret` and `derive_pubkey` so the error message and the
/// `origin`-carrying `Error::Keystore` it produces stay in one place.
fn parse_secret_key(origin: &str, secret: &[u8; 32]) -> Result<SecretKey> {
    SecretKey::from_bytes(secret).map_err(|err| Error::Keystore {
        path: origin.to_string(),
        reason: format!("invalid secret key: {err:?}"),
    })
}

fn pubkey_of(secret_key: &SecretKey) -> BlsPubkey {
    let pubkey_bytes: [u8; BLS_PUBKEY_SIZE] = secret_key.sk_to_pk().to_bytes();
    BlsPubkey(pubkey_bytes)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::keys::definitions::{SigningDefinition, ValidatorDefinition, ValidatorDefinitions};

    /// The secret from the EIP-2335 test vectors.
    fn test_secret() -> [u8; 32] {
        let bytes = hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
            .expect("valid hex");
        bytes.try_into().expect("32 bytes")
    }

    /// The password from the EIP-2335 test vectors, copied from
    /// `keys::keystore`'s tests since its constants are private to that module.
    const PASSWORD: &str = "\u{1d531}\u{1d522}\u{1d530}\u{1d531}\u{1d52d}\u{1d51e}\u{1d530}\u{1d530}\u{1d534}\u{1d52c}\u{1d52f}\u{1d521}\u{1f511}";

    /// The PBKDF2 keystore from the EIP-2335 test vectors, copied from
    /// `keys::keystore`'s tests for the same reason.
    const PBKDF2_KEYSTORE: &str = r#"{
        "crypto": {
            "kdf": {
                "function": "pbkdf2",
                "params": {
                    "dklen": 32, "c": 262144, "prf": "hmac-sha256",
                    "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                },
                "message": ""
            },
            "checksum": {
                "function": "sha256", "params": {},
                "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"
            },
            "cipher": {
                "function": "aes-128-ctr",
                "params": { "iv": "264daa3f303d7259501c93d997d84fe6" },
                "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"
            }
        },
        "description": "This is a test keystore that uses PBKDF2 to secure the secret.",
        "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
        "path": "m/12381/60/0/0",
        "uuid": "64625def-3331-4eea-ab6f-782f3ed16a83",
        "version": 4
    }"#;

    /// A password file saved with a trailing newline, the way an editor or a
    /// shell redirect commonly leaves one, must not stop the keystore behind
    /// it from decrypting. This is the failure mode the task called
    /// "miserable to debug": the password itself is right, but a stray
    /// newline byte makes the checksum comparison fail with no indication why.
    #[test]
    fn load_tolerates_a_trailing_newline_in_the_password_file() {
        let dir = tempfile::tempdir().expect("temp dir");

        std::fs::write(dir.path().join("keystore.json"), PBKDF2_KEYSTORE).expect("writes keystore");
        std::fs::write(dir.path().join("password.txt"), format!("{PASSWORD}\n"))
            .expect("writes password");

        let definitions = ValidatorDefinitions(vec![ValidatorDefinition {
            enabled: true,
            voting_public_key: "0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07".to_string(),
            signing: SigningDefinition::LocalKeystore {
                voting_keystore_path: PathBuf::from("keystore.json"),
                voting_keystore_password_path: PathBuf::from("password.txt"),
            },
        }]);
        definitions.save(dir.path()).expect("saves definitions");

        let store = ValidatorStore::load(dir.path()).expect("loads");
        assert_eq!(store.len(), 1);
        let pubkey = store.pubkeys()[0];
        assert_eq!(
            hex::encode(pubkey.0),
            "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07"
        );
    }

    /// The real key behind `PBKDF2_KEYSTORE`, as the EIP-2335 vectors record it.
    const VECTOR_PUBKEY: &str = "0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07";

    /// Write the vector keystore and password into `dir`, with a definitions
    /// file declaring `voting_public_key`. Declaring the wrong one is the
    /// point of the tests below, so it is a parameter rather than fixed.
    fn write_definitions(dir: &std::path::Path, voting_public_key: &str) {
        std::fs::write(dir.join("keystore.json"), PBKDF2_KEYSTORE).expect("writes keystore");
        std::fs::write(dir.join("password.txt"), PASSWORD).expect("writes password");
        ValidatorDefinitions(vec![ValidatorDefinition {
            enabled: true,
            voting_public_key: voting_public_key.to_string(),
            signing: SigningDefinition::LocalKeystore {
                voting_keystore_path: PathBuf::from("keystore.json"),
                voting_keystore_password_path: PathBuf::from("password.txt"),
            },
        }])
        .save(dir)
        .expect("saves definitions");
    }

    #[test]
    fn a_remote_definition_loads_without_contacting_its_signer() {
        let dir = tempfile::tempdir().expect("temp dir");
        // A URL nothing listens on: loading must not care.
        let url = "http://127.0.0.1:9";
        ValidatorDefinitions(vec![ValidatorDefinition {
            enabled: true,
            voting_public_key: VECTOR_PUBKEY.to_string(),
            signing: SigningDefinition::Web3Signer {
                url: url.to_string(),
            },
        }])
        .save(dir.path())
        .expect("saves definitions");

        let store = ValidatorStore::load(dir.path()).expect("loads");
        let pubkey = parse_pubkey(VECTOR_PUBKEY).expect("pubkey");
        assert_eq!(store.len(), 1);
        assert_eq!(store.remote_url(&pubkey).as_deref(), Some(url));
        assert!(store.signer(&pubkey).expect("held").is_remote());
        assert!(store.local_pubkeys().is_empty());
        assert_eq!(store.remote_entries(), vec![(pubkey, url.to_string())]);
    }

    #[test]
    fn a_remote_definition_with_a_bad_url_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        ValidatorDefinitions(vec![ValidatorDefinition {
            enabled: true,
            voting_public_key: VECTOR_PUBKEY.to_string(),
            signing: SigningDefinition::Web3Signer {
                url: "not a url".to_string(),
            },
        }])
        .save(dir.path())
        .expect("saves definitions");

        assert!(ValidatorStore::load(dir.path()).is_err());
    }

    /// A remote entry's `url` is as the operator wrote it until
    /// `Web3Signer::new` has judged it, so an error raised before that names
    /// the entry by its place in the file and never echoes the URL, which
    /// may carry credentials.
    #[test]
    fn an_unreadable_pubkey_on_a_remote_entry_does_not_echo_its_url() {
        let dir = tempfile::tempdir().expect("temp dir");
        let remote = |voting_public_key: &str, url: &str| ValidatorDefinition {
            enabled: true,
            voting_public_key: voting_public_key.to_string(),
            signing: SigningDefinition::Web3Signer {
                url: url.to_string(),
            },
        };
        ValidatorDefinitions(vec![
            remote(VECTOR_PUBKEY, "http://127.0.0.1:9"),
            remote("0xnothex", "https://admin:s3cret@signer:9000"),
        ])
        .save(dir.path())
        .expect("saves definitions");

        let Err(err) = ValidatorStore::load(dir.path()) else {
            panic!("an entry with an unreadable pubkey must refuse the load");
        };
        let message = err.to_string();
        assert!(message.contains("entry 2"), "{message}");
        assert!(
            !message.contains("s3cret") && !message.contains("admin"),
            "the error must not carry the URL's credentials: {message}"
        );
    }

    /// How many validators' worth of clients the store can still hand out.
    fn live_signers(store: &ValidatorStore) -> usize {
        store
            .signers
            .values()
            .filter(|signer| signer.strong_count() > 0)
            .count()
    }

    #[test]
    fn remote_validators_on_one_url_share_a_client_and_release_it_together() {
        let mut store = ValidatorStore::new();
        let first = BlsPubkey([1; BLS_PUBKEY_SIZE]);
        let second = BlsPubkey([2; BLS_PUBKEY_SIZE]);
        store
            .insert_remote(first, "http://signer:9000")
            .expect("inserts");
        store
            .insert_remote(second, "http://signer:9000/")
            .expect("inserts");
        assert_eq!(live_signers(&store), 1, "one URL, one client");

        assert!(store.remove(&first));
        assert_eq!(live_signers(&store), 1, "still in use by the second key");
        assert!(store.remove(&second));
        assert_eq!(live_signers(&store), 0, "nobody uses it any more");
        assert!(store.signer_for_url("http://signer:9000").is_none());
    }

    /// A signature in flight holds the client, and must not keep it alive in
    /// the store after it finishes: removal and the request's end can come in
    /// either order.
    #[test]
    fn a_client_held_by_an_in_flight_signature_is_released_when_it_ends() {
        let mut store = ValidatorStore::new();
        let pubkey = BlsPubkey([1; BLS_PUBKEY_SIZE]);
        store
            .insert_remote(pubkey, "http://signer:9000")
            .expect("inserts");
        let in_flight = store.signer(&pubkey).expect("held");

        assert!(store.remove(&pubkey));
        assert_eq!(live_signers(&store), 1, "the request still holds it");
        drop(in_flight);
        assert_eq!(live_signers(&store), 0, "released with the request");
    }

    #[test]
    fn inserting_a_local_key_over_a_remote_one_replaces_it() {
        let mut store = ValidatorStore::new();
        let pubkey = parse_pubkey(VECTOR_PUBKEY).expect("pubkey");
        store
            .insert_remote(pubkey, "http://signer:9000")
            .expect("inserts");
        let derived = store
            .insert_secret("test", &test_secret())
            .expect("inserts");
        assert_eq!(derived, pubkey);
        assert_eq!(store.len(), 1);
        assert!(store.remote_url(&pubkey).is_none());
        assert_eq!(live_signers(&store), 0);
    }

    /// A definitions entry declaring a key its keystore does not hold must not
    /// load.
    ///
    /// Left unchecked, this is what makes the keymanager's delete report
    /// `deleted` while removing nothing: the store is keyed by the derived key
    /// and the definitions file is filtered by the declared one, so the entry
    /// survives and the next restart brings the validator back signing.
    #[test]
    fn a_definitions_entry_declaring_the_wrong_pubkey_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        // A well-formed pubkey of the right length that is simply not this
        // keystore's: the check must be about the value, not the shape.
        let wrong = format!("0x{}", "ab".repeat(BLS_PUBKEY_SIZE));
        write_definitions(dir.path(), &wrong);

        // `let else` rather than `expect_err`: the latter needs `Debug` on the
        // `Ok` type, and `ValidatorStore` deliberately has none because it
        // holds secret keys.
        let Err(err) = ValidatorStore::load(dir.path()) else {
            panic!("a definitions entry declaring the wrong pubkey must not load");
        };

        let rendered = err.to_string();
        assert!(
            rendered.contains("declares") && rendered.contains("keystore holds"),
            "the error should name both keys: {rendered}"
        );
    }

    #[test]
    fn a_definitions_entry_with_an_unreadable_pubkey_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        write_definitions(dir.path(), "0xnot-hex");

        assert!(ValidatorStore::load(dir.path()).is_err());
    }

    #[test]
    fn a_matching_definitions_entry_loads() {
        // The other side of the check: the correct declaration must still
        // load, or the guard would lock out every well-formed configuration.
        let dir = tempfile::tempdir().expect("temp dir");
        write_definitions(dir.path(), VECTOR_PUBKEY);

        let store = ValidatorStore::load(dir.path()).expect("loads");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn inserting_a_secret_derives_the_expected_pubkey() {
        let mut store = ValidatorStore::new();
        let pubkey = store
            .insert_secret("test", &test_secret())
            .expect("inserts");
        // The pubkey the EIP-2335 vectors record for this secret.
        assert_eq!(
            hex::encode(pubkey.0),
            "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07"
        );
        assert!(store.contains(&pubkey));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn removing_a_validator_takes_it_out_of_the_set() {
        let mut store = ValidatorStore::new();
        let pubkey = store
            .insert_secret("test", &test_secret())
            .expect("inserts");
        assert!(store.remove(&pubkey));
        assert!(!store.contains(&pubkey));
        assert!(store.is_empty());
    }

    #[test]
    fn an_unknown_pubkey_has_no_signing_method() {
        let store = ValidatorStore::new();
        assert!(store.signer(&BlsPubkey([7; BLS_PUBKEY_SIZE])).is_none());
        assert!(store.remote_url(&BlsPubkey([7; BLS_PUBKEY_SIZE])).is_none());
    }
}
