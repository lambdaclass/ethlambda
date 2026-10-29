//! `GET`, `POST` and `DELETE /eth/v1/keystores`.
//!
//! # Slashing protection
//!
//! The specification lets these routes carry a validator's EIP-3076 history in
//! and out, and both do:
//!
//! - `POST` judges the request's `slashing_protection` before touching
//!   anything: one that does not parse, or is for another chain, fails every
//!   key in the request and imports none of them. It is written once the keys
//!   are saved, together with their registration and before any is loaded, so
//!   a key never starts signing ahead of its history and a key that failed to
//!   import leaves none behind. A key with no history at all is registered as
//!   of the current slot and epoch, with a warning.
//! - `DELETE` returns the deleted keys' records as a minimal interchange,
//!   taken after the keys are out of the store, so it covers every signature
//!   this process made with them. A key that is gone but still has a record is
//!   reported `not_active`, and its record is kept, so importing it back later
//!   stays protected.
//!
//! The history is this client's EIP-3076 minimal watermarks (see
//! [`crate::slashing_protection`]), so an export lists, per validator, its
//! highest slot and its highest source and target rather than every message.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::{Json, extract::State};
use ethlambda_types::beacon::primitives::BlsPubkey;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::Error;
use crate::beacon_node::dto::{encode_hex, parse_pubkey};
use crate::http_api::KeymanagerContext;
use crate::keys::keystore::Keystore;
use crate::keys::{ValidatorDefinition, ValidatorDefinitions, ValidatorStore};
use crate::secure_fs;

/// The most keystores accepted in a single import request.
///
/// Each one costs a deliberately slow EIP-2335 key derivation (scrypt at the
/// parameters staking tools commonly emit runs on the order of 100-300ms),
/// run synchronously inside this handler while `definitions_lock` is held.
/// With no cap, one request could tie up that lock, and the worker thread
/// running it, for as long as the caller likes. 100 keys is far beyond a
/// normal runtime import (adding or rotating a handful of validators) while
/// keeping a single request's worst case in the tens of seconds rather than
/// unbounded.
const MAX_KEYSTORES_PER_IMPORT: usize = 100;

pub type SharedStore = Arc<RwLock<ValidatorStore>>;

#[derive(Debug, Serialize)]
pub struct ListResponse {
    pub data: Vec<ListedKeystore>,
}

#[derive(Debug, Serialize)]
pub struct ListedKeystore {
    pub validating_pubkey: String,
    pub derivation_path: Option<String>,
    pub readonly: bool,
}

#[derive(Deserialize)]
pub struct ImportRequest {
    pub keystores: Vec<String>,
    /// Zeroized on drop, the same guarantee `Keystore::decrypt`'s output
    /// already gets: this holds every plaintext password in the request in
    /// memory until decryption runs, and a plain `Vec<String>` would leave
    /// those bytes sitting in the allocator's freed memory afterwards.
    pub passwords: Zeroizing<Vec<String>>,
    /// An EIP-3076 interchange, imported before any of the keys.
    #[serde(default)]
    pub slashing_protection: Option<String>,
}

/// Hand-written rather than derived: `passwords` holds every plaintext
/// password in this request, and a derived `Debug` would print them verbatim
/// into any log line that ever dumps this struct. The standing rule in this
/// crate is that nothing carrying secrets is printable; see `keys::store`.
impl std::fmt::Debug for ImportRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportRequest")
            .field("keystores", &self.keystores.len())
            .field("passwords", &"<redacted>")
            .field("slashing_protection", &self.slashing_protection.is_some())
            .finish()
    }
}

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub data: Vec<KeyStatus>,
}

#[derive(Debug, Serialize)]
pub struct KeyStatus {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl KeyStatus {
    fn error(message: impl std::fmt::Display) -> Self {
        Self {
            status: "error".to_string(),
            message: Some(message.to_string()),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct DeleteRequest {
    pub pubkeys: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DeleteResponse {
    pub data: Vec<KeyStatus>,
    /// The deleted keys' records, as a minimal EIP-3076 interchange. See the
    /// module documentation.
    pub slashing_protection: String,
}

pub async fn list(State(context): State<KeymanagerContext>) -> Json<ListResponse> {
    let store = context.store.read().await;
    Json(ListResponse {
        data: store
            .pubkeys()
            .into_iter()
            .map(|pubkey| ListedKeystore {
                validating_pubkey: encode_hex(&pubkey.0),
                derivation_path: None,
                readonly: false,
            })
            .collect(),
    })
}

pub async fn import(
    State(context): State<KeymanagerContext>,
    Json(request): Json<ImportRequest>,
) -> Json<StatusResponse> {
    if request.keystores.len() > MAX_KEYSTORES_PER_IMPORT {
        let message = format!(
            "request carries {} keystores, more than the limit of {MAX_KEYSTORES_PER_IMPORT}",
            request.keystores.len()
        );
        warn!(
            count = request.keystores.len(),
            "Rejecting oversized import request"
        );
        let data = request
            .keystores
            .iter()
            .map(|_| KeyStatus::error(&message))
            .collect();
        return Json(StatusResponse { data });
    }

    // The history is judged before anything is touched, so a request whose
    // history would be refused imports no key at all, rather than some keys
    // without it. It is written later, together with the keys' registration,
    // once the keys it came with are known to be saved: written now, a key
    // that then failed to import would leave history behind for nothing.
    if let Some(interchange) = &request.slashing_protection {
        let interchange = interchange.clone();
        let judged = crate::slashing_protection::blocking(&context.protection, move |protection| {
            protection.check_import(&interchange)
        })
        .await;
        if let Err(err) = judged {
            let message = format!("slashing_protection was not imported: {err}");
            warn!(%err, "Refusing an import whose slashing-protection history was refused");
            let data = request
                .keystores
                .iter()
                .map(|_| KeyStatus::error(&message))
                .collect();
            return Json(StatusResponse { data });
        }
    }

    // Held across this whole function: the entire open-mutate-save cycle
    // over the definitions file, including the slow decrypt-and-persist loop
    // below. This is what actually serializes concurrent import/delete
    // requests; see `KeymanagerContext::definitions_lock`. Taken before
    // `store`'s write lock, never the other way around, so the two locks
    // never deadlock against each other.
    let _definitions_guard = context.definitions_lock.lock().await;

    // Read only now, after taking the guard above: a snapshot taken before
    // it could already be stale by the time this request's own writes land,
    // which is exactly the race the guard exists to close. Every key that
    // persists successfully appends to this and re-saves it, so later keys
    // in the same request see earlier ones. A failure here (a definitions
    // file that exists but is corrupt) is not something any individual key's
    // error can fix, so it fails the whole batch rather than pretending a
    // per-key retry would help.
    let mut definitions = match ValidatorDefinitions::open(&context.validators_dir) {
        Ok(definitions) => definitions,
        Err(err) => {
            let message = err.to_string();
            let data = request
                .keystores
                .iter()
                .map(|_| KeyStatus::error(&message))
                .collect();
            return Json(StatusResponse { data });
        }
    };

    // The entries the file held before this request touches it, by key. A
    // failed registration below removes what the request added and puts back
    // what it replaced: a disabled entry, which was never loaded and so may
    // have no record, must not be left enabled on disk, or the next start
    // refuses the whole client for it.
    let before: std::collections::HashMap<BlsPubkey, ValidatorDefinition> = definitions
        .0
        .iter()
        .filter_map(|definition| {
            parse_pubkey(&definition.voting_public_key)
                .ok()
                .map(|pubkey| (pubkey, definition.clone()))
        })
        .collect();

    // Decrypt (deliberately slow: EIP-2335 key derivation) and persist every
    // key to disk before ever touching the store's write lock. The duty
    // loop's `attest` only ever holds a read lock across a short, synchronous
    // signing loop (see `attestation.rs`'s doc comment on that block), but
    // `tokio::sync::RwLock` is write-preferring: a write lock queued here
    // while this loop ran would jump that queue and stall every signature
    // due for as long as the whole batch takes, rather than just for the
    // instant the inserts below actually need. `definitions_lock` above has
    // no such reader/writer to starve: only import and delete ever take it.
    let mut prepared = Vec::with_capacity(request.keystores.len());
    for (position, json) in request.keystores.iter().enumerate() {
        let password = request.passwords.get(position).map(String::as_str);
        prepared.push(prepare_import(&context, &mut definitions, json, password));
    }

    // Every persisted key is registered in the slashing-protection record in
    // one write, before any of them is loaded: the duty path must never meet a
    // key with no record. After persisting rather than before, so a key whose
    // persist failed leaves no record behind to let a hand-copied keystore
    // past the startup check later. Still under the definitions guard, so a
    // concurrent delete cannot interleave.
    let persisted: Vec<BlsPubkey> = prepared
        .iter()
        .filter_map(|result| result.as_ref().ok().map(|(pubkey, _, _)| *pubkey))
        .collect();
    // The request's history goes in first, in the same critical section, so
    // a key it covers is registered with that history rather than as never
    // having signed.
    let history = request.slashing_protection.clone();
    let registration = if persisted.is_empty() {
        Ok(0)
    } else {
        let registering = persisted.clone();
        crate::slashing_protection::blocking(&context.protection, move |protection| {
            if let Some(history) = &history {
                let validators = protection.import(history)?;
                info!(validators, "Imported slashing-protection history");
            }
            protection.register(&registering)
        })
        .await
    };
    // The records are on disk and in memory (see `SlashingProtection::commit`),
    // only their survival of a power loss is in doubt, and a registration lost
    // that way is refused at the next start: closed. So the keys are loaded,
    // rather than rolled back to leave records behind for keys never imported.
    let registration = match registration {
        Err(Error::Unflushed { path, source }) => {
            warn!(
                %path,
                %source,
                "Slashing-protection records written, but the directory could not be flushed; \
                 the imported keys are registered"
            );
            Ok(0)
        }
        other => other,
    };
    if let Ok(registered) = registration
        && registered > 0
    {
        warn!(
            registered,
            "Imported validator keys with no slashing-protection history; each starts as never \
             having signed"
        );
    }

    // A key on disk with no record is refused at the next start, and
    // `SlashingProtection::open` then refuses the whole client, not the one
    // key. A crash between persisting and registering leaves exactly that,
    // which is the closed side to fail on. Here the write is known to have
    // failed, so the keys this request added are taken off disk again, the
    // entries it replaced are put back as they were, and the failure costs
    // this request only. The keystore and password files go back to what was
    // at their paths before, as a pair, or are removed where there was
    // nothing.
    let rolled_back = match &registration {
        Ok(_) => Ok(()),
        Err(_) => {
            let mut added = Vec::new();
            let mut replaced = Vec::new();
            for pubkey in &persisted {
                match before.get(pubkey) {
                    Some(previous) => replaced.push((*pubkey, previous.clone())),
                    None => added.push(*pubkey),
                }
            }
            let files: Vec<(BlsPubkey, &Overwritten)> = prepared
                .iter()
                .filter_map(|result| {
                    result
                        .as_ref()
                        .ok()
                        .map(|(pubkey, _, overwritten)| (*pubkey, overwritten))
                })
                .collect();
            undo_import(&context, &mut definitions, &added, &replaced, &files)
        }
    };
    if let Err(err) = &rolled_back {
        tracing::error!(
            %err,
            "Could not undo a failed import; the next start refuses its keys until they have a \
             slashing-protection record"
        );
    }

    // The definitions guard stays held across the store lock, in the order
    // `delete` takes the two. Released before it, a delete of the same key
    // could run in between: it would find the key on disk but not in memory,
    // remove it and answer `deleted`, and the insert below would then load a
    // key the operator was told is gone.
    let mut store = context.store.write().await;
    let data = prepared
        .into_iter()
        .map(|result| match (result, &registration) {
            (Ok((_, secret, _)), Ok(_)) => finish_import(&mut store, &secret),
            (Ok((pubkey, _, _)), Err(err)) => {
                if before.contains_key(&pubkey) {
                    // Its keystore was rewritten; its entry is back as it was
                    // and nothing about it changed in memory, so it stays
                    // whatever it was, loaded since startup in the ordinary
                    // case.
                    let entry = if rolled_back.is_ok() {
                        "its definitions entry is back as it was"
                    } else {
                        "its definitions entry could not be put back"
                    };
                    KeyStatus::error(format!(
                        "keystore rewritten, but the slashing-protection record could not be \
                         written: {err}; {entry}"
                    ))
                } else if rolled_back.is_err() {
                    // Still on disk, not loaded now, and refused at the next
                    // start until it has a record.
                    KeyStatus::error(format!(
                        "saved, but not loaded: its slashing-protection record could not be \
                         written: {err}"
                    ))
                } else {
                    KeyStatus::error(format!(
                        "not imported: its slashing-protection record could not be written: {err}"
                    ))
                }
            }
            (Err(status), _) => status,
        })
        .collect();
    drop(store);
    drop(_definitions_guard);

    Json(StatusResponse { data })
}

/// Undo what a failed import did: the definitions entries it added are
/// removed and the ones it replaced put back, in one save, then every
/// keystore and password file it wrote goes back to what was at its path
/// before, as a pair, or is removed where there was nothing. The file goes
/// first, since it is what the next start loads from, so a crash in between
/// leaves orphan files and never a key that would be loaded without a
/// record. A file that is already gone is not an error.
fn undo_import(
    context: &KeymanagerContext,
    definitions: &mut ValidatorDefinitions,
    added: &[BlsPubkey],
    replaced: &[(BlsPubkey, ValidatorDefinition)],
    files: &[(BlsPubkey, &Overwritten)],
) -> crate::Result<()> {
    if added.is_empty() && replaced.is_empty() {
        return Ok(());
    }
    definitions.0.retain(|definition| {
        parse_pubkey(&definition.voting_public_key)
            .map(|parsed| !added.contains(&parsed))
            .unwrap_or(true)
    });
    for definition in &mut definitions.0 {
        if let Some((_, previous)) = replaced.iter().find(|(pubkey, _)| {
            parse_pubkey(&definition.voting_public_key).is_ok_and(|parsed| parsed == *pubkey)
        }) {
            *definition = previous.clone();
        }
    }
    save_definitions(context, definitions)?;
    // Newest first: a key listed twice in one request snapshotted, the second
    // time, what the first time wrote, so the earliest snapshot must be the
    // one that lands last.
    for (pubkey, overwritten) in files.iter().rev() {
        let [keystore, password] = written_paths(context, pubkey)?;
        put_back(&keystore, overwritten.keystore.as_deref())?;
        put_back(
            &password,
            overwritten.password.as_deref().map(|bytes| &bytes[..]),
        )?;
    }
    Ok(())
}

/// Put `path` back to `previous`: its former bytes, or nothing.
fn put_back(path: &Path, previous: Option<&[u8]>) -> crate::Result<()> {
    match previous {
        Some(bytes) => {
            secure_fs::write_private_no_symlink(path, bytes).map_err(|source| Error::Io {
                path: path.display().to_string(),
                source,
            })
        }
        None => remove_if_present(path),
    }
}

/// Save the definitions file, keeping `definitions_unflushed` true from an
/// after-rename flush failure until a later save flushes the directory, which
/// makes every earlier rename in it durable too.
fn save_definitions(
    context: &KeymanagerContext,
    definitions: &ValidatorDefinitions,
) -> crate::Result<()> {
    let saved = definitions.save(&context.validators_dir);
    match &saved {
        Ok(()) => context
            .definitions_unflushed
            .store(false, std::sync::atomic::Ordering::Release),
        Err(Error::Unflushed { .. }) => context
            .definitions_unflushed
            .store(true, std::sync::atomic::Ordering::Release),
        Err(_) => {}
    }
    saved
}

/// The keystore and password paths `persist_import` writes `pubkey` to.
fn written_paths(context: &KeymanagerContext, pubkey: &BlsPubkey) -> crate::Result<[PathBuf; 2]> {
    let base = encode_hex(&pubkey.0);
    Ok([
        absolute(context.validators_dir.join(format!("{base}.json")))?,
        absolute(context.secrets_dir.join(&base))?,
    ])
}

/// Remove `path`; one that is already gone is not an error.
fn remove_if_present(path: &Path) -> crate::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(Error::Io {
            path: path.display().to_string(),
            source,
        }),
    }
}

/// Decrypt one keystore and persist it to disk: everything an import can do
/// before it needs the store's write lock and its slashing-protection record.
fn prepare_import(
    context: &KeymanagerContext,
    definitions: &mut ValidatorDefinitions,
    json: &str,
    password: Option<&str>,
) -> std::result::Result<(BlsPubkey, Zeroizing<[u8; 32]>, Overwritten), KeyStatus> {
    let Some(password) = password else {
        return Err(KeyStatus::error("no password supplied for this keystore"));
    };

    let keystore = Keystore::from_json(json).map_err(KeyStatus::error)?;
    let secret = keystore.decrypt(password).map_err(KeyStatus::error)?;
    let pubkey = ValidatorStore::derive_pubkey(&secret).map_err(KeyStatus::error)?;

    // Persisted before the key is reachable through the store: a validator
    // this process is willing to sign with must already be durable, or a
    // crash right after "imported" is reported silently loses it, with
    // nothing about a live, signing validator hinting that it is about to
    // vanish on the next restart.
    let overwritten =
        persist_import(context, definitions, &pubkey, json, password).map_err(KeyStatus::error)?;

    Ok((pubkey, secret, overwritten))
}

/// What `persist_import` found at the two paths it writes, so an undone
/// import can put it back: the bytes of a regular file that was there, or
/// `None` for nothing. Restored as a pair, so a keystore never ends up next
/// to a password it was not encrypted under.
struct Overwritten {
    keystore: Option<Vec<u8>>,
    password: Option<Zeroizing<Vec<u8>>>,
}

/// The bytes of the regular file at `path`, or `None` when there is none. A
/// symlink or a directory reads as `None` too: the write that follows refuses
/// those, so nothing of theirs is overwritten.
fn regular_file_bytes(path: &Path) -> crate::Result<Option<Vec<u8>>> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => {
            std::fs::read(path).map(Some).map_err(|source| Error::Io {
                path: path.display().to_string(),
                source,
            })
        }
        Ok(_) => Ok(None),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(Error::Io {
            path: path.display().to_string(),
            source,
        }),
    }
}

/// Add an already-decrypted, already-persisted key to the live store. The
/// only step of an import that needs the write lock: a cheap, synchronous
/// scalar validation and hashmap insert, never an await.
fn finish_import(store: &mut ValidatorStore, secret: &[u8; 32]) -> KeyStatus {
    match store.insert_secret("keymanager import", secret) {
        Ok(pubkey) => {
            info!(pubkey = %encode_hex(&pubkey.0), "Imported validator key");
            KeyStatus {
                status: "imported".to_string(),
                message: None,
            }
        }
        Err(err) => KeyStatus::error(err),
    }
}

/// Write an imported keystore and password to disk and record them in the
/// definitions file, so the key survives a restart.
fn persist_import(
    context: &KeymanagerContext,
    definitions: &mut ValidatorDefinitions,
    pubkey: &BlsPubkey,
    keystore_json: &str,
    password: &str,
) -> crate::Result<Overwritten> {
    // Named after the pubkey, the convention staking tools use, so an
    // operator can tell which file backs which validator without opening it.
    // That predictability is exactly why the writes below refuse to follow a
    // symlink already sitting at either path: an attacker who can guess a
    // validator's pubkey (public by definition) can guess these paths too.
    let base = encode_hex(&pubkey.0);

    // `ValidatorStore::load` resolves a relative definition path against the
    // validators directory only (see `keys::store::resolve`), which would
    // silently mis-locate a password file that actually lives under a
    // separate secrets directory. Absolutizing both here sidesteps that:
    // `resolve` passes an absolute path through unchanged regardless of
    // which directory it names.
    let keystore_path = absolute(context.validators_dir.join(format!("{base}.json")))?;
    let password_path = absolute(context.secrets_dir.join(&base))?;

    // `write_private_no_symlink` still overwrites an existing *regular*
    // file, so re-importing the same key (rotating its password, or simply
    // retrying) behaves exactly as a plain `std::fs::write` would; it only
    // refuses to follow a symlink planted at the path ahead of time.
    // Taken before the writes, to be put back if this import is undone.
    let overwritten = Overwritten {
        keystore: regular_file_bytes(&keystore_path)?,
        password: regular_file_bytes(&password_path)?.map(Zeroizing::new),
    };
    // Both files, or neither: a failure after the first write puts both back
    // as they were, so a re-import that fails on its second file does not
    // leave the previous keystore destroyed under the previous entry.
    let restore = |overwritten: &Overwritten| -> crate::Result<()> {
        put_back(&keystore_path, overwritten.keystore.as_deref())?;
        put_back(
            &password_path,
            overwritten.password.as_deref().map(|bytes| &bytes[..]),
        )
    };
    let written = secure_fs::write_private_no_symlink(&keystore_path, keystore_json)
        .map_err(|source| Error::Io {
            path: keystore_path.display().to_string(),
            source,
        })
        .and_then(|()| {
            secure_fs::write_private_no_symlink(&password_path, password).map_err(|source| {
                Error::Io {
                    path: password_path.display().to_string(),
                    source,
                }
            })
        });
    if let Err(err) = written {
        restore(&overwritten).inspect_err(
            |undo| tracing::error!(%undo, "Could not put a half-written keystore back"),
        )?;
        return Err(err);
    }

    let definition = ValidatorDefinition {
        enabled: true,
        voting_public_key: base.clone(),
        voting_keystore_path: keystore_path.clone(),
        voting_keystore_password_path: password_path.clone(),
    };
    // How to put `definitions` back if the save below fails.
    //
    // One vector is shared by every key in the batch, and each key mutates it
    // and re-saves it. Leaving a failed key's mutation in place would let the
    // *next* key's successful save write it to disk, so a key this request
    // reports as `error` would be enabled on the next restart and start
    // signing. A validator the operator believes was never imported is exactly
    // the kind that ends up running in two places, which no local record can
    // see.
    enum Undo {
        Appended,
        Replaced {
            index: usize,
            previous: ValidatorDefinition,
        },
    }

    // Re-importing an already-known key updates its entry in place instead
    // of appending a duplicate: `voting_public_key` is this file's natural
    // key, and a duplicate would make `ValidatorStore::load` process the
    // same keystore twice on the next restart.
    let undo = match definitions
        .0
        .iter()
        .position(|existing| existing.voting_public_key == base)
    {
        Some(index) => Undo::Replaced {
            index,
            previous: std::mem::replace(&mut definitions.0[index], definition),
        },
        None => {
            definitions.0.push(definition);
            Undo::Appended
        }
    };

    match save_definitions(context, definitions) {
        Ok(()) => Ok(overwritten),
        // The entry is on disk and every reader sees it; only its survival
        // of a power loss is in doubt, and an entry lost that way only
        // removes a key. Counted as persisted, and kept in memory, so what
        // this request holds matches the file.
        Err(Error::Unflushed { path, source }) => {
            warn!(
                %path,
                %source,
                "Validator definitions written, but the directory could not be flushed"
            );
            Ok(overwritten)
        }
        Err(err) => {
            // `Appended` pops rather than removing by index because this
            // function pushes and saves with nothing in between, so the
            // entry it added is still the last one. The files go back too.
            match undo {
                Undo::Appended => {
                    definitions.0.pop();
                }
                Undo::Replaced { index, previous } => definitions.0[index] = previous,
            }
            restore(&overwritten).inspect_err(|undo| {
                tracing::error!(%undo, "Could not put a keystore whose entry failed to save back")
            })?;
            Err(err)
        }
    }
}

fn absolute(path: PathBuf) -> crate::Result<PathBuf> {
    std::path::absolute(&path).map_err(|source| Error::Io {
        path: path.display().to_string(),
        source,
    })
}

pub async fn delete(
    State(context): State<KeymanagerContext>,
    Json(request): Json<DeleteRequest>,
) -> Json<DeleteResponse> {
    // Taken before `store`'s write lock below, the same order `import` uses,
    // so the two handlers never deadlock against each other. See
    // `KeymanagerContext::definitions_lock`: this is what makes `persist_delete`
    // below and a concurrent import's own open-mutate-save cycle mutually
    // exclusive, rather than racing to overwrite the definitions file.
    let _definitions_guard = context.definitions_lock.lock().await;

    let mut store = context.store.write().await;
    let results: Vec<(Option<BlsPubkey>, KeyStatus)> = request
        .pubkeys
        .iter()
        .map(|text| match parse_pubkey(text) {
            Ok(pubkey) => (Some(pubkey), delete_one(&context, &mut store, &pubkey)),
            Err(err) => (None, KeyStatus::error(err)),
        })
        .collect();
    drop(store);

    // Exported only now, with the keys out of the store: a signature with one
    // of them either finished before the write lock above was granted, and is
    // in the record, or can no longer happen.
    let requested: Vec<Option<BlsPubkey>> = results.iter().map(|(pubkey, _)| *pubkey).collect();
    let exported = crate::slashing_protection::blocking(&context.protection, move |protection| {
        let pubkeys: Vec<BlsPubkey> = requested.iter().flatten().copied().collect();
        let interchange = protection.export(&pubkeys)?;
        let recorded: Vec<bool> = requested
            .iter()
            .map(|pubkey| pubkey.is_some_and(|pubkey| protection.contains(&pubkey)))
            .collect();
        Ok((interchange, recorded))
    })
    .await;
    let (slashing_protection, recorded) = match exported {
        Ok(exported) => exported,
        Err(err) => {
            // A key that was deleted, or is gone with a record, cannot have its
            // history handed over, so no caller may treat it as safe to move:
            // it becomes an error. Every other status (`not_found`, a malformed
            // pubkey) was decided before the export and still stands.
            warn!(%err, "Deleted keys whose slashing-protection history could not be exported");
            let message = format!("deleted, but slashing_protection could not be exported: {err}");
            let data = results
                .into_iter()
                .map(|(_, status)| match status.status.as_str() {
                    "deleted" => KeyStatus::error(&message),
                    _ => status,
                })
                .collect();
            return Json(DeleteResponse {
                data,
                slashing_protection: String::new(),
            });
        }
    };

    // `not_active`: not held here, but with a record, which the response
    // carries. The specification's word for "gone, history attached".
    let data = results
        .into_iter()
        .zip(recorded)
        .map(|((_, status), recorded)| {
            if status.status == "not_found" && recorded {
                KeyStatus {
                    status: "not_active".to_string(),
                    message: None,
                }
            } else {
                status
            }
        })
        .collect();

    Json(DeleteResponse {
        data,
        slashing_protection,
    })
}

fn delete_one(
    context: &KeymanagerContext,
    store: &mut ValidatorStore,
    pubkey: &BlsPubkey,
) -> KeyStatus {
    // Whether this key is on disk, read before the in-memory removal makes the
    // store an unreliable witness. `not_found` has to mean "this client has no
    // definitions entry for it", not "it is not in memory right now": a key
    // removed from memory by an earlier failed attempt is still very much
    // present on disk, and reporting `not_found` for it tells an operator the
    // key is gone when a restart will bring it back signing.
    let on_disk = match definitions_contain(context, pubkey) {
        Ok(present) => present,
        // Cannot tell. Report the failure rather than guessing either way: a
        // wrong `not_found` here is the dangerous direction.
        Err(err) => return KeyStatus::error(err),
    };
    let in_memory = store.remove(pubkey);
    // Whatever becomes of the definitions file below, this process no longer
    // signs with the key, so its overrides have nothing left to apply to. A key
    // imported again starts on the defaults.
    context.settings.forget(pubkey);

    if !on_disk && !in_memory {
        // A removal whose directory flush failed is on disk but may not
        // survive a power loss, and a retry lands here. Answering `not_found`
        // then would tell the operator the key is gone for good; flush first,
        // by saving the file again, and keep the error until that works.
        if context
            .definitions_unflushed
            .load(std::sync::atomic::Ordering::Acquire)
        {
            let definitions = match ValidatorDefinitions::open(&context.validators_dir) {
                Ok(definitions) => definitions,
                Err(err) => return KeyStatus::error(err),
            };
            if let Err(err) = save_definitions(context, &definitions) {
                return KeyStatus::error(format!(
                    "an earlier removal is on disk but the directory could not be flushed: \
                     {err}; the key may come back after a power loss"
                ));
            }
        }
        return KeyStatus {
            status: "not_found".to_string(),
            message: None,
        };
    }

    // The in-memory store has already stopped signing with this key, which is
    // the safety-relevant effect and happens first, the opposite order from
    // import. If persisting the removal below fails, this process will not
    // sign with the key again this run, but the definitions file still lists
    // it, so a restart would reactivate it.
    //
    // That is why the error is returned rather than swallowed, and why
    // `not_found` above is gated on the file rather than on memory. An
    // operator who retries after this error must get the same error again, not
    // a `not_found` that reads as "already gone": acting on that, by importing
    // the key elsewhere, is what turns a failed delete into two hosts signing
    // for one validator.
    match persist_delete(context, pubkey) {
        Ok(()) => {}
        // The removal is on disk but may not survive a power loss, and the
        // keystore stays, so the key could come back enabled, with its
        // record, while the operator runs it elsewhere. An error, so no
        // caller takes the key for gone; this process does not sign with it.
        Err(Error::Unflushed { path, source }) => {
            return KeyStatus::error(format!(
                "removed from {path}, but the directory could not be flushed: {source}; the key \
                 may come back after a power loss"
            ));
        }
        Err(err) => return KeyStatus::error(err),
    }

    info!(pubkey = %encode_hex(&pubkey.0), "Deleted validator key");
    KeyStatus {
        status: "deleted".to_string(),
        message: None,
    }
}

/// Whether the definitions file currently holds an entry for `pubkey`.
///
/// Read from disk rather than from the in-memory store, because the two can
/// disagree and it is the file that decides what the next restart loads. A
/// disabled entry counts as present: it is still there, `delete` is still what
/// removes it, and reporting `not_found` for one would leave the operator
/// believing a key is gone while its entry waits to be re-enabled.
///
/// An unparseable `voting_public_key` cannot match, matching the filter in
/// [`persist_delete`]: if that entry will not be removed, this must not claim
/// it was found, or a delete would report success having removed nothing.
fn definitions_contain(context: &KeymanagerContext, pubkey: &BlsPubkey) -> crate::Result<bool> {
    let definitions = ValidatorDefinitions::open(&context.validators_dir)?;
    Ok(definitions.0.iter().any(|definition| {
        parse_pubkey(&definition.voting_public_key)
            .map(|parsed| parsed == *pubkey)
            .unwrap_or(false)
    }))
}

/// Drop a deleted key's entry from the definitions file.
///
/// Deliberately leaves the keystore and password files on disk: `deleted`
/// means this client has stopped using the key, not that it destroys operator
/// key material on an HTTP call. A definitions file with no entry for them is
/// enough to keep them from being loaded again.
fn persist_delete(context: &KeymanagerContext, pubkey: &BlsPubkey) -> crate::Result<()> {
    let mut definitions = ValidatorDefinitions::open(&context.validators_dir)?;
    definitions.0.retain(|definition| {
        parse_pubkey(&definition.voting_public_key)
            .map(|parsed| parsed != *pubkey)
            .unwrap_or(true)
    });
    save_definitions(context, &definitions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_api::router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    const TOKEN: &str = "test-token";

    /// The scrypt keystore from the EIP-2335 vectors, as a single-line string.
    fn keystore_json() -> String {
        serde_json::json!({
            "crypto": {
                "kdf": {
                    "function": "scrypt",
                    "params": { "dklen": 32, "n": 262144, "p": 1, "r": 8,
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3" },
                    "message": ""
                },
                "checksum": { "function": "sha256", "params": {},
                    "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484" },
                "cipher": { "function": "aes-128-ctr",
                    "params": { "iv": "264daa3f303d7259501c93d997d84fe6" },
                    "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f" }
            },
            "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
            "path": "m/12381/60/3141592653/589793238",
            "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
            "version": 4
        })
        .to_string()
    }

    const PASSWORD: &str = "\u{1d531}\u{1d522}\u{1d530}\u{1d531}\u{1d52d}\u{1d51e}\u{1d530}\u{1d530}\u{1d534}\u{1d52c}\u{1d52f}\u{1d521}\u{1f511}";

    fn context_with_dirs(store: SharedStore, dir: &std::path::Path) -> KeymanagerContext {
        KeymanagerContext {
            store,
            settings: Arc::new(crate::proposer_settings::ProposerSettings::new(
                ethlambda_types::beacon::primitives::Bytes32::ZERO,
                None,
            )),
            validators_dir: dir.to_path_buf(),
            secrets_dir: dir.to_path_buf(),
            definitions_lock: Arc::new(tokio::sync::Mutex::new(())),
            definitions_unflushed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            protection: crate::slashing_protection::SlashingProtection::in_memory(),
        }
    }

    /// A context whose directories are never created. Fine for tests that
    /// never reach a successful import or delete, since `ValidatorDefinitions`
    /// treats a missing directory the same as a missing file: an empty set.
    fn app() -> axum::Router {
        let placeholder = std::env::temp_dir().join("ethlambda-validator-keymanager-tests-absent");
        router(
            context_with_dirs(Arc::new(RwLock::new(ValidatorStore::new())), &placeholder),
            TOKEN.to_string(),
        )
    }

    async fn send(app: axum::Router, request: Request<Body>) -> (StatusCode, serde_json::Value) {
        let response = app.oneshot(request).await.expect("responds");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    fn authed(method: &str, uri: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {TOKEN}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request")
    }

    #[tokio::test]
    async fn a_request_without_a_token_is_rejected() {
        let request = Request::builder()
            .uri("/eth/v1/keystores")
            .body(Body::empty())
            .expect("request");
        let (status, _) = send(app(), request).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_request_with_the_wrong_token_is_rejected() {
        let request = Request::builder()
            .uri("/eth/v1/keystores")
            .header("authorization", "Bearer wrong")
            .body(Body::empty())
            .expect("request");
        let (status, _) = send(app(), request).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// Defence in depth for the empty-token bypass.
    ///
    /// `load_or_create_token` now refuses to return an empty token, so this
    /// router should be unreachable in practice. But `router` takes the token
    /// from its caller, so the comparison must refuse an empty one on its own:
    /// `subtle`'s `ct_eq` reports two empty slices as equal, and
    /// `Authorization: Bearer ` with a trailing space presents exactly that.
    #[tokio::test]
    async fn an_empty_configured_token_authenticates_nobody() {
        let placeholder = std::env::temp_dir().join("ethlambda-validator-keymanager-tests-absent");
        let app = router(
            context_with_dirs(Arc::new(RwLock::new(ValidatorStore::new())), &placeholder),
            String::new(),
        );

        // The exact header that made empty match empty: "Bearer " strips to "".
        let request = Request::builder()
            .uri("/eth/v1/keystores")
            .header("authorization", "Bearer ")
            .body(Body::empty())
            .expect("request");

        let (status, _) = send(app, request).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// A key whose persist fails must not be left in the shared definitions
    /// vector for the next key in the batch to write out.
    ///
    /// One `ValidatorDefinitions` is threaded through every key in an import,
    /// and each mutates it and re-saves it. Without a rollback, key 7's failed
    /// save leaves its entry in the vector and key 8's successful save commits
    /// it: key 7 is reported `error` to the caller and is enabled on disk. A
    /// validator the operator believes was never imported is exactly the kind
    /// that ends up running in two places.
    ///
    /// The save is made to fail by putting a *directory* where the definitions
    /// file goes: the keystore and password writes still succeed, so the
    /// mutation is reached, and only the final rename fails.
    #[test]
    fn a_failed_persist_leaves_the_definitions_untouched() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::create_dir(dir.path().join(crate::keys::definitions::DEFINITIONS_FILE))
            .expect("occupies the definitions path with a directory");

        let context = context_with_dirs(Arc::new(RwLock::new(ValidatorStore::new())), dir.path());
        let mut definitions = ValidatorDefinitions::default();

        let secret = Keystore::from_json(&keystore_json())
            .expect("valid keystore")
            .decrypt(PASSWORD)
            .expect("decrypts");
        let pubkey = ValidatorStore::derive_pubkey(&secret).expect("derives");

        let result = persist_import(
            &context,
            &mut definitions,
            &pubkey,
            &keystore_json(),
            PASSWORD,
        );

        assert!(
            result.is_err(),
            "the save must fail for this test to mean anything"
        );
        assert!(
            definitions.0.is_empty(),
            "a failed save must not leave the entry behind for the next key to commit"
        );
    }

    /// The same rollback for the replace path: re-importing a known key whose
    /// save then fails must leave the *previous* entry intact, not a
    /// half-applied update.
    #[test]
    fn a_failed_persist_restores_a_replaced_entry() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::create_dir(dir.path().join(crate::keys::definitions::DEFINITIONS_FILE))
            .expect("occupies the definitions path with a directory");

        let context = context_with_dirs(Arc::new(RwLock::new(ValidatorStore::new())), dir.path());

        let secret = Keystore::from_json(&keystore_json())
            .expect("valid keystore")
            .decrypt(PASSWORD)
            .expect("decrypts");
        let pubkey = ValidatorStore::derive_pubkey(&secret).expect("derives");

        // An existing entry for the same key, marked disabled so the restored
        // value is distinguishable from what the import would have written.
        let existing = ValidatorDefinition {
            enabled: false,
            voting_public_key: encode_hex(&pubkey.0),
            voting_keystore_path: PathBuf::from("old.json"),
            voting_keystore_password_path: PathBuf::from("old.txt"),
        };
        let mut definitions = ValidatorDefinitions(vec![existing.clone()]);

        let result = persist_import(
            &context,
            &mut definitions,
            &pubkey,
            &keystore_json(),
            PASSWORD,
        );

        assert!(result.is_err());
        assert_eq!(
            definitions.0,
            vec![existing],
            "a failed save must restore the entry it replaced"
        );
    }

    /// A key whose definitions entry is still on disk must not be reported
    /// `not_found` just because it is absent from memory.
    ///
    /// This is the state a failed delete leaves behind: the in-memory removal
    /// already happened, the persist failed, and the entry survives. An
    /// operator who retries and reads `not_found` concludes the key is gone
    /// and imports it on another host; this one brings it back on its next
    /// restart, and two hosts sign for one validator.
    #[tokio::test]
    async fn a_key_still_on_disk_is_not_reported_not_found() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = Arc::new(RwLock::new(ValidatorStore::new()));
        let app = router(
            context_with_dirs(store.clone(), dir.path()),
            TOKEN.to_string(),
        );

        // Import so the definitions entry exists on disk.
        let (status, body) = send(
            app.clone(),
            authed(
                "POST",
                "/eth/v1/keystores",
                serde_json::json!({
                    "keystores": [keystore_json()],
                    "passwords": [PASSWORD],
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"][0]["status"], "imported", "got {body}");

        let (_, listed) = send(
            app.clone(),
            Request::builder()
                .uri("/eth/v1/keystores")
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        let pubkey = listed["data"][0]["validating_pubkey"]
            .as_str()
            .expect("string")
            .to_string();

        // Now reproduce the post-failed-delete state: drop it from memory
        // only, leaving the definitions entry in place.
        {
            let parsed = parse_pubkey(&pubkey).expect("valid pubkey");
            assert!(store.write().await.remove(&parsed), "was in memory");
        }

        let (_, body) = send(
            app,
            authed(
                "DELETE",
                "/eth/v1/keystores",
                serde_json::json!({ "pubkeys": [pubkey] }),
            ),
        )
        .await;

        assert_ne!(
            body["data"][0]["status"], "not_found",
            "a key whose definitions entry is still on disk is not gone: {body}"
        );
        assert_eq!(body["data"][0]["status"], "deleted", "got {body}");
    }

    #[tokio::test]
    async fn import_list_delete_round_trip() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = Arc::new(RwLock::new(ValidatorStore::new()));
        let app = router(
            context_with_dirs(store.clone(), dir.path()),
            TOKEN.to_string(),
        );

        let (status, body) = send(
            app.clone(),
            authed(
                "POST",
                "/eth/v1/keystores",
                serde_json::json!({
                    "keystores": [keystore_json()],
                    "passwords": [PASSWORD],
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"][0]["status"], "imported", "got {body}");

        let (_, body) = send(
            app.clone(),
            Request::builder()
                .uri("/eth/v1/keystores")
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        let listed = body["data"].as_array().expect("array");
        assert_eq!(listed.len(), 1);
        let pubkey = listed[0]["validating_pubkey"]
            .as_str()
            .expect("string")
            .to_string();

        let (_, body) = send(
            app,
            authed(
                "DELETE",
                "/eth/v1/keystores",
                serde_json::json!({ "pubkeys": [pubkey] }),
            ),
        )
        .await;
        assert_eq!(body["data"][0]["status"], "deleted", "got {body}");
        assert!(
            body["slashing_protection"].is_string(),
            "the field is required even when empty"
        );
        assert!(store.read().await.is_empty());
    }

    /// The regression test for the gap that let the keymanager mutate only
    /// the in-memory store: a fresh `ValidatorStore::load` from the same
    /// directory, independent of the one the API mutated, is the only way to
    /// prove an import reached disk rather than just the running process.
    #[tokio::test]
    async fn an_imported_key_survives_a_fresh_load_from_disk() {
        let dir = tempfile::tempdir().expect("temp dir");
        let app = router(
            context_with_dirs(Arc::new(RwLock::new(ValidatorStore::new())), dir.path()),
            TOKEN.to_string(),
        );

        let (status, body) = send(
            app,
            authed(
                "POST",
                "/eth/v1/keystores",
                serde_json::json!({
                    "keystores": [keystore_json()],
                    "passwords": [PASSWORD],
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"][0]["status"], "imported", "got {body}");

        let reloaded = ValidatorStore::load(dir.path()).expect("loads");
        assert_eq!(reloaded.len(), 1);
        assert_eq!(
            hex::encode(reloaded.pubkeys()[0].0),
            "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07"
        );
    }

    /// An imported key is registered in the slashing-protection record before
    /// it is loaded, so the next start finds a record for it instead of
    /// refusing it.
    #[tokio::test]
    async fn an_imported_key_is_registered_for_slashing_protection() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = ethlambda_types::beacon::primitives::Root::ZERO;
        let protection = crate::slashing_protection::SlashingProtection::open(
            dir.path(),
            root,
            &[],
            false,
            None,
        )
        .expect("opens with no keys");
        let mut context =
            context_with_dirs(Arc::new(RwLock::new(ValidatorStore::new())), dir.path());
        context.protection = Arc::new(std::sync::Mutex::new(protection));
        let protection = context.protection.clone();

        let (_, body) = send(
            router(context, TOKEN.to_string()),
            authed(
                "POST",
                "/eth/v1/keystores",
                serde_json::json!({
                    "keystores": [keystore_json()],
                    "passwords": [PASSWORD],
                }),
            ),
        )
        .await;
        assert_eq!(body["data"][0]["status"], "imported", "got {body}");
        assert_eq!(protection.lock().expect("not poisoned").len(), 1);

        // The next start: same directory, the imported key loaded, no
        // --init-slashing-protection. It must open, because the key is
        // registered.
        drop(protection);
        let keys = ValidatorStore::load(dir.path()).expect("loads").pubkeys();
        crate::slashing_protection::SlashingProtection::open(dir.path(), root, &keys, false, None)
            .expect("the imported key has a record");
    }

    /// A key whose registration fails is taken off disk again, so the failed
    /// write costs this request only and the next start loads nothing it
    /// would refuse.
    #[tokio::test]
    async fn a_failed_registration_rolls_the_import_back() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = ethlambda_types::beacon::primitives::Root::ZERO;
        let protection =
            crate::slashing_protection::SlashingProtection::open(dir.path(), root, &[], false)
                .expect("opens with no keys");
        // A directory in the record's place makes the registration's rename
        // fail, whoever runs the test.
        let record = protection.path().expect("persisted").to_path_buf();
        std::fs::remove_file(&record).expect("removes the record");
        std::fs::create_dir(&record).expect("a directory in its place");
        let mut context =
            context_with_dirs(Arc::new(RwLock::new(ValidatorStore::new())), dir.path());
        context.protection = Arc::new(std::sync::Mutex::new(protection));
        let store = context.store.clone();

        let (_, body) = send(
            router(context, TOKEN.to_string()),
            authed(
                "POST",
                "/eth/v1/keystores",
                serde_json::json!({
                    "keystores": [keystore_json()],
                    "passwords": [PASSWORD],
                }),
            ),
        )
        .await;
        assert_eq!(body["data"][0]["status"], "error", "got {body}");
        assert!(
            body["data"][0]["message"]
                .as_str()
                .unwrap_or_default()
                .starts_with("not imported"),
            "got {body}"
        );
        assert!(store.read().await.pubkeys().is_empty(), "not loaded");
        assert!(
            ValidatorStore::load(dir.path())
                .expect("loads")
                .pubkeys()
                .is_empty(),
            "the next start finds no key to refuse"
        );
        let leftovers: Vec<String> = std::fs::read_dir(dir.path())
            .expect("lists")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| {
                !name.starts_with("slashing_protection")
                    && name != crate::keys::definitions::DEFINITIONS_FILE
            })
            .collect();
        assert!(
            leftovers.is_empty(),
            "keystore and password removed: {leftovers:?}"
        );
    }

    /// A failed registration puts back the definitions entry the request
    /// replaced: a disabled entry, which was never loaded and has no record,
    /// stays disabled rather than enabled on disk, which would refuse the
    /// whole client at the next start.
    #[tokio::test]
    async fn a_failed_registration_restores_a_replaced_definitions_entry() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = ethlambda_types::beacon::primitives::Root::ZERO;
        let protection =
            crate::slashing_protection::SlashingProtection::open(dir.path(), root, &[], false)
                .expect("opens with no keys");
        let record = protection.path().expect("persisted").to_path_buf();
        std::fs::remove_file(&record).expect("removes the record");
        std::fs::create_dir(&record).expect("a directory in its place");
        let keystore: serde_json::Value =
            serde_json::from_str(&keystore_json()).expect("the vector is json");
        let previous = ValidatorDefinition {
            enabled: false,
            voting_public_key: format!("0x{}", keystore["pubkey"].as_str().expect("pubkey")),
            voting_keystore_path: dir.path().join("old.json"),
            voting_keystore_password_path: dir.path().join("old"),
        };
        ValidatorDefinitions(vec![previous.clone()])
            .save(dir.path())
            .expect("saves");
        let mut context =
            context_with_dirs(Arc::new(RwLock::new(ValidatorStore::new())), dir.path());
        context.protection = Arc::new(std::sync::Mutex::new(protection));

        let (_, body) = send(
            router(context, TOKEN.to_string()),
            authed(
                "POST",
                "/eth/v1/keystores",
                serde_json::json!({
                    "keystores": [keystore_json()],
                    "passwords": [PASSWORD],
                }),
            ),
        )
        .await;
        assert_eq!(body["data"][0]["status"], "error", "got {body}");
        assert!(
            body["data"][0]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("back as it was"),
            "got {body}"
        );
        let definitions = ValidatorDefinitions::open(dir.path()).expect("opens");
        assert_eq!(definitions.0, vec![previous], "the disabled entry is back");
        let json_files: Vec<String> = std::fs::read_dir(dir.path())
            .expect("lists")
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().is_file())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".json"))
            .collect();
        assert!(
            json_files.is_empty(),
            "the keystore this request wrote goes back to what was there, nothing: {json_files:?}"
        );
    }

    /// A failed registration puts the keystore and password files a re-import
    /// overwrote back as they were, as a pair, so the restored entry never
    /// points at a keystore encrypted under a password that is gone.
    #[tokio::test]
    async fn a_failed_registration_restores_the_overwritten_files() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = ethlambda_types::beacon::primitives::Root::ZERO;
        let protection =
            crate::slashing_protection::SlashingProtection::open(dir.path(), root, &[], false)
                .expect("opens with no keys");
        let record = protection.path().expect("persisted").to_path_buf();
        std::fs::remove_file(&record).expect("removes the record");
        std::fs::create_dir(&record).expect("a directory in its place");
        let keystore: serde_json::Value =
            serde_json::from_str(&keystore_json()).expect("the vector is json");
        let pubkey = parse_pubkey(keystore["pubkey"].as_str().expect("pubkey")).expect("parses");
        let base = encode_hex(&pubkey.0);
        let keystore_path = dir.path().join(format!("{base}.json"));
        let password_path = dir.path().join(&base);
        std::fs::write(&keystore_path, b"old keystore").expect("writes");
        std::fs::write(&password_path, b"old password").expect("writes");
        let previous = ValidatorDefinition {
            enabled: true,
            voting_public_key: base.clone(),
            voting_keystore_path: keystore_path.clone(),
            voting_keystore_password_path: password_path.clone(),
        };
        ValidatorDefinitions(vec![previous.clone()])
            .save(dir.path())
            .expect("saves");
        let mut context =
            context_with_dirs(Arc::new(RwLock::new(ValidatorStore::new())), dir.path());
        context.protection = Arc::new(std::sync::Mutex::new(protection));

        let (_, body) = send(
            router(context, TOKEN.to_string()),
            authed(
                "POST",
                "/eth/v1/keystores",
                serde_json::json!({
                    "keystores": [keystore_json()],
                    "passwords": [PASSWORD],
                }),
            ),
        )
        .await;
        assert_eq!(body["data"][0]["status"], "error", "got {body}");
        assert_eq!(
            std::fs::read(&keystore_path).expect("still there"),
            b"old keystore"
        );
        assert_eq!(
            std::fs::read(&password_path).expect("still there"),
            b"old password"
        );
        let definitions = ValidatorDefinitions::open(dir.path()).expect("opens");
        assert_eq!(definitions.0, vec![previous]);
    }

    /// A re-import whose password write fails puts the keystore it had already
    /// replaced back, so the previous entry never points at a keystore
    /// encrypted under a password that was never written.
    #[tokio::test]
    async fn a_failed_password_write_puts_the_replaced_keystore_back() {
        let dir = tempfile::tempdir().expect("temp dir");
        let keystore: serde_json::Value =
            serde_json::from_str(&keystore_json()).expect("the vector is json");
        let pubkey = parse_pubkey(keystore["pubkey"].as_str().expect("pubkey")).expect("parses");
        let base = encode_hex(&pubkey.0);
        let keystore_path = dir.path().join(format!("{base}.json"));
        let password_path = dir.path().join(&base);
        std::fs::write(&keystore_path, b"old keystore").expect("writes");
        // A directory at the password's path makes its write fail, after the
        // keystore's succeeded.
        std::fs::create_dir(&password_path).expect("a directory in its place");
        let previous = ValidatorDefinition {
            enabled: true,
            voting_public_key: base.clone(),
            voting_keystore_path: keystore_path.clone(),
            voting_keystore_password_path: dir.path().join("old"),
        };
        ValidatorDefinitions(vec![previous.clone()])
            .save(dir.path())
            .expect("saves");
        let context = context_with_dirs(Arc::new(RwLock::new(ValidatorStore::new())), dir.path());

        let (_, body) = send(
            router(context, TOKEN.to_string()),
            authed(
                "POST",
                "/eth/v1/keystores",
                serde_json::json!({
                    "keystores": [keystore_json()],
                    "passwords": [PASSWORD],
                }),
            ),
        )
        .await;
        assert_eq!(body["data"][0]["status"], "error", "got {body}");
        assert_eq!(
            std::fs::read(&keystore_path).expect("still there"),
            b"old keystore"
        );
        let definitions = ValidatorDefinitions::open(dir.path()).expect("opens");
        assert_eq!(definitions.0, vec![previous]);
    }

    /// A request that carries history is refused whole, importing nothing.
    #[tokio::test]
    async fn an_import_carrying_history_is_refused_whole() {
        let dir = tempfile::tempdir().expect("temp dir");
        let context = context_with_dirs(Arc::new(RwLock::new(ValidatorStore::new())), dir.path());
        let store = context.store.clone();

        let (_, body) = send(
            router(context, TOKEN.to_string()),
            authed(
                "POST",
                "/eth/v1/keystores",
                serde_json::json!({
                    "keystores": [keystore_json()],
                    "passwords": [PASSWORD],
                    "slashing_protection": "{}",
                }),
            ),
        )
        .await;
        assert_eq!(body["data"][0]["status"], "error", "got {body}");
        assert!(store.read().await.pubkeys().is_empty());
        assert!(
            ValidatorDefinitions::open(dir.path())
                .expect("opens")
                .0
                .is_empty()
        );
    }

    /// The same keystore twice in one request, with the registration failing:
    /// the second copy snapshotted what the first one wrote, and the undo must
    /// still end with what was there before the request.
    #[tokio::test]
    async fn a_failed_registration_restores_the_state_before_a_duplicated_import() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = ethlambda_types::beacon::primitives::Root::ZERO;
        let protection =
            crate::slashing_protection::SlashingProtection::open(dir.path(), root, &[], false)
                .expect("opens with no keys");
        let record = protection.path().expect("persisted").to_path_buf();
        std::fs::remove_file(&record).expect("removes the record");
        std::fs::create_dir(&record).expect("a directory in its place");
        let mut context =
            context_with_dirs(Arc::new(RwLock::new(ValidatorStore::new())), dir.path());
        context.protection = Arc::new(std::sync::Mutex::new(protection));

        let (_, body) = send(
            router(context, TOKEN.to_string()),
            authed(
                "POST",
                "/eth/v1/keystores",
                serde_json::json!({
                    "keystores": [keystore_json(), keystore_json()],
                    "passwords": [PASSWORD, PASSWORD],
                }),
            ),
        )
        .await;
        assert_eq!(body["data"][0]["status"], "error", "got {body}");
        assert_eq!(body["data"][1]["status"], "error", "got {body}");
        assert!(
            ValidatorDefinitions::open(dir.path())
                .expect("opens")
                .0
                .is_empty()
        );
        let leftovers: Vec<String> = std::fs::read_dir(dir.path())
            .expect("lists")
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().is_file())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| {
                !name.starts_with("slashing_protection")
                    && name != crate::keys::definitions::DEFINITIONS_FILE
            })
            .collect();
        assert!(
            leftovers.is_empty(),
            "nothing was there before: {leftovers:?}"
        );
    }

    /// A key that fails to persist must leave no slashing-protection record
    /// behind: a record would later let the same keystore, copied in by hand,
    /// past the startup check as if it had been registered on purpose.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_failed_import_leaves_no_slashing_protection_record() {
        let dir = tempfile::tempdir().expect("temp dir");
        // A symlink at the keystore's path makes `persist_import` refuse.
        let target = dir.path().join("elsewhere");
        std::fs::write(&target, "untouched").expect("writes target");
        let pubkey = "0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07";
        std::os::unix::fs::symlink(&target, dir.path().join(format!("{pubkey}.json")))
            .expect("symlinks");

        let root = ethlambda_types::beacon::primitives::Root::ZERO;
        let protection = crate::slashing_protection::SlashingProtection::open(
            dir.path(),
            root,
            &[],
            false,
            None,
        )
        .expect("opens with no keys");
        let mut context =
            context_with_dirs(Arc::new(RwLock::new(ValidatorStore::new())), dir.path());
        context.protection = Arc::new(std::sync::Mutex::new(protection));
        let protection = context.protection.clone();

        let (_, body) = send(
            router(context, TOKEN.to_string()),
            authed(
                "POST",
                "/eth/v1/keystores",
                serde_json::json!({ "keystores": [keystore_json()], "passwords": [PASSWORD] }),
            ),
        )
        .await;
        assert_eq!(body["data"][0]["status"], "error", "got {body}");
        assert!(
            protection.lock().expect("not poisoned").is_empty(),
            "the failed key must not have been registered"
        );
    }

    const KEYSTORE_PUBKEY: &str = "0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07";

    /// A context over `dir` whose slashing protection is a real record there,
    /// for the chain `0x00..00`, and the handle to inspect it with.
    fn context_with_record(
        dir: &std::path::Path,
    ) -> (
        KeymanagerContext,
        crate::slashing_protection::SharedProtection,
    ) {
        let protection = crate::slashing_protection::SlashingProtection::open(
            dir,
            ethlambda_types::beacon::primitives::Root::ZERO,
            &[],
            false,
            None,
        )
        .expect("opens with no keys");
        let mut context = context_with_dirs(Arc::new(RwLock::new(ValidatorStore::new())), dir);
        context.protection = Arc::new(std::sync::Mutex::new(protection));
        let protection = context.protection.clone();
        (context, protection)
    }

    /// A minimal interchange for `KEYSTORE_PUBKEY` on the chain `root`.
    fn history(root: &str, slot: u64, source: u64, target: u64) -> String {
        serde_json::json!({
            "metadata": { "interchange_format_version": "5", "genesis_validators_root": root },
            "data": [{
                "pubkey": KEYSTORE_PUBKEY,
                "signed_blocks": [{ "slot": slot.to_string() }],
                "signed_attestations": [{
                    "source_epoch": source.to_string(),
                    "target_epoch": target.to_string()
                }]
            }]
        })
        .to_string()
    }

    const ZERO_ROOT: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

    /// History that arrives with a key is in force before the key can sign.
    #[tokio::test]
    async fn an_import_brings_its_slashing_protection_history() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (context, protection) = context_with_record(dir.path());

        let (_, body) = send(
            router(context, TOKEN.to_string()),
            authed(
                "POST",
                "/eth/v1/keystores",
                serde_json::json!({
                    "keystores": [keystore_json()],
                    "passwords": [PASSWORD],
                    "slashing_protection": history(ZERO_ROOT, 100, 5, 10),
                }),
            ),
        )
        .await;
        assert_eq!(body["data"][0]["status"], "imported", "got {body}");

        let pubkey = parse_pubkey(KEYSTORE_PUBKEY).expect("pubkey");
        let protection = protection.lock().expect("not poisoned");
        assert!(
            protection.check_block(&pubkey, 100).is_err(),
            "slot 100 was signed elsewhere"
        );
        assert!(protection.check_block(&pubkey, 101).is_ok());
    }

    /// History for another chain is refused, and with it every key in the
    /// request: none may start signing without the history it came with.
    #[tokio::test]
    async fn an_import_whose_history_is_for_another_chain_imports_nothing() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (context, _) = context_with_record(dir.path());
        let store = context.store.clone();
        let other_chain = "0x0000000000000000000000000000000000000000000000000000000000000001";

        let (_, body) = send(
            router(context, TOKEN.to_string()),
            authed(
                "POST",
                "/eth/v1/keystores",
                serde_json::json!({
                    "keystores": [keystore_json()],
                    "passwords": [PASSWORD],
                    "slashing_protection": history(other_chain, 100, 5, 10),
                }),
            ),
        )
        .await;
        assert_eq!(body["data"][0]["status"], "error", "got {body}");
        assert!(store.read().await.is_empty(), "the key must not be loaded");
    }

    /// A delete hands over the record the key was protected by, so it can be
    /// imported elsewhere, and keeps it here.
    #[tokio::test]
    async fn a_delete_returns_the_keys_history() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (context, protection) = context_with_record(dir.path());
        let app = router(context, TOKEN.to_string());

        let (_, body) = send(
            app.clone(),
            authed(
                "POST",
                "/eth/v1/keystores",
                serde_json::json!({ "keystores": [keystore_json()], "passwords": [PASSWORD] }),
            ),
        )
        .await;
        assert_eq!(body["data"][0]["status"], "imported", "got {body}");
        // Imported with no history, so the key starts at the current slot;
        // a proposal must come after it.
        const SLOT: u64 = 1 << 40;
        let pubkey = parse_pubkey(KEYSTORE_PUBKEY).expect("pubkey");
        protection
            .lock()
            .expect("not poisoned")
            .check_and_record_block(&pubkey, SLOT)
            .expect("written")
            .expect("allowed");

        let (_, body) = send(
            app.clone(),
            authed(
                "DELETE",
                "/eth/v1/keystores",
                serde_json::json!({ "pubkeys": [KEYSTORE_PUBKEY] }),
            ),
        )
        .await;
        assert_eq!(body["data"][0]["status"], "deleted", "got {body}");
        let interchange: serde_json::Value =
            serde_json::from_str(body["slashing_protection"].as_str().expect("a string"))
                .expect("json");
        assert_eq!(
            interchange["metadata"]["genesis_validators_root"],
            ZERO_ROOT
        );
        assert_eq!(interchange["data"][0]["pubkey"], KEYSTORE_PUBKEY);
        assert_eq!(
            interchange["data"][0]["signed_blocks"][0]["slot"],
            SLOT.to_string()
        );

        // Gone from this client, but its record is still here and still
        // returned: the specification's `not_active`.
        let (_, body) = send(
            app,
            authed(
                "DELETE",
                "/eth/v1/keystores",
                serde_json::json!({ "pubkeys": [KEYSTORE_PUBKEY] }),
            ),
        )
        .await;
        assert_eq!(body["data"][0]["status"], "not_active", "got {body}");
        assert!(
            protection
                .lock()
                .expect("not poisoned")
                .check_block(&pubkey, SLOT)
                .is_err()
        );
    }

    /// History that came with a key that then failed to import is not
    /// written: nothing it describes is held here.
    #[cfg(unix)]
    #[tokio::test]
    async fn history_whose_key_failed_to_import_is_not_written() {
        let dir = tempfile::tempdir().expect("temp dir");
        // A symlink at the keystore's path makes `persist_import` refuse.
        let target = dir.path().join("elsewhere");
        std::fs::write(&target, "untouched").expect("writes target");
        std::os::unix::fs::symlink(&target, dir.path().join(format!("{KEYSTORE_PUBKEY}.json")))
            .expect("symlinks");
        let (context, protection) = context_with_record(dir.path());

        let (_, body) = send(
            router(context, TOKEN.to_string()),
            authed(
                "POST",
                "/eth/v1/keystores",
                serde_json::json!({
                    "keystores": [keystore_json()],
                    "passwords": [PASSWORD],
                    "slashing_protection": history(ZERO_ROOT, 100, 5, 10),
                }),
            ),
        )
        .await;
        assert_eq!(body["data"][0]["status"], "error", "got {body}");
        assert!(protection.lock().expect("not poisoned").is_empty());
    }

    #[tokio::test]
    async fn deleting_an_unknown_key_reports_not_found() {
        let (_, body) = send(
            app(),
            authed(
                "DELETE",
                "/eth/v1/keystores",
                serde_json::json!({ "pubkeys": [encode_hex(&[0x11; 48])] }),
            ),
        )
        .await;
        assert_eq!(body["data"][0]["status"], "not_found", "got {body}");
    }

    #[tokio::test]
    async fn a_wrong_password_is_reported_per_key_not_as_a_failure() {
        let (status, body) = send(
            app(),
            authed(
                "POST",
                "/eth/v1/keystores",
                serde_json::json!({
                    "keystores": [keystore_json()],
                    "passwords": ["wrong"],
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"][0]["status"], "error", "got {body}");
    }

    #[test]
    fn import_request_debug_redacts_passwords() {
        let request = ImportRequest {
            keystores: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            passwords: Zeroizing::new(vec!["super-secret".to_string()]),
            slashing_protection: None,
        };
        let rendered = format!("{request:?}");
        assert!(rendered.contains("keystores: 3"), "got {rendered}");
        assert!(rendered.contains("<redacted>"), "got {rendered}");
        assert!(
            !rendered.contains("super-secret"),
            "password leaked into Debug output: {rendered}"
        );
    }

    /// Finding 1: every file this handler writes must land at `0600`, not
    /// whatever the platform default (typically `0644`) gives it. Checked
    /// through the real HTTP path rather than by calling `secure_fs`
    /// directly, so a future refactor that swapped back to a bare
    /// `std::fs::write` at a call site would be caught here too.
    #[cfg(unix)]
    #[tokio::test]
    async fn imported_keystore_and_password_files_are_mode_0600() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("temp dir");
        let app = router(
            context_with_dirs(Arc::new(RwLock::new(ValidatorStore::new())), dir.path()),
            TOKEN.to_string(),
        );

        let (status, body) = send(
            app,
            authed(
                "POST",
                "/eth/v1/keystores",
                serde_json::json!({
                    "keystores": [keystore_json()],
                    "passwords": [PASSWORD],
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"][0]["status"], "imported", "got {body}");

        // The definitions file names on-disk files after `encode_hex`'s
        // output, which is `0x`-prefixed (see `persist_import`'s `base`).
        let pubkey = "0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07";
        for path in [
            dir.path().join(format!("{pubkey}.json")),
            dir.path().join(pubkey),
        ] {
            let mode = std::fs::metadata(&path)
                .unwrap_or_else(|err| panic!("metadata for {}: {err}", path.display()))
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{} got {mode:o}", path.display());
        }
    }

    /// Finding 4: a batch larger than the limit is rejected outright, per
    /// key, rather than run through the slow KDF at all.
    #[tokio::test]
    async fn an_oversized_import_batch_is_rejected() {
        let oversized = MAX_KEYSTORES_PER_IMPORT + 1;
        let (status, body) = send(
            app(),
            authed(
                "POST",
                "/eth/v1/keystores",
                serde_json::json!({
                    "keystores": vec![keystore_json(); oversized],
                    "passwords": vec![PASSWORD; oversized],
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let data = body["data"].as_array().expect("array");
        assert_eq!(data.len(), oversized);
        assert!(
            data.iter().all(|status| status["status"] == "error"),
            "got {body}"
        );
    }

    /// Finding 5: a symlink planted at the predictable, pubkey-derived
    /// keystore path ahead of an import must not be followed. The write is
    /// reported as a per-key error, not a crash, and the symlink's target is
    /// left untouched.
    #[cfg(unix)]
    #[tokio::test]
    async fn import_refuses_to_follow_a_symlink_at_the_keystore_path() {
        let dir = tempfile::tempdir().expect("temp dir");
        let target = dir.path().join("attacker-target");
        std::fs::write(&target, "untouched").expect("writes target");

        // `0x`-prefixed to match `encode_hex`'s output, which is what
        // `persist_import` actually names files after.
        let pubkey = "0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07";
        let keystore_link = dir.path().join(format!("{pubkey}.json"));
        std::os::unix::fs::symlink(&target, &keystore_link).expect("symlinks");

        let app = router(
            context_with_dirs(Arc::new(RwLock::new(ValidatorStore::new())), dir.path()),
            TOKEN.to_string(),
        );
        let (status, body) = send(
            app,
            authed(
                "POST",
                "/eth/v1/keystores",
                serde_json::json!({
                    "keystores": [keystore_json()],
                    "passwords": [PASSWORD],
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"][0]["status"], "error", "got {body}");
        assert_eq!(
            std::fs::read_to_string(&target).expect("reads"),
            "untouched",
            "the symlink target must not be overwritten"
        );
    }

    /// Finding 2's fallback test: two sequential requests, so this does not
    /// by itself exercise the race (the bug needed a concurrent import whose
    /// definitions snapshot was taken *before* a delete's save landed; two
    /// requests run one after the other each open the file fresh regardless
    /// of any locking). What it does check, deterministically: the dedup fix
    /// in `persist_import` and a plain delete-then-import sequence do not
    /// themselves reintroduce a deleted key by any other means, e.g. an
    /// import that matched on the wrong key or clobbered the whole file
    /// instead of one entry. `import_waits_for_an_in_flight_holder_of_the_definitions_lock`
    /// below is the actual proof that concurrent requests cannot interleave;
    /// a genuine two-request race is not reachable through the public API
    /// once that guard is real, which makes it untestable without adding a
    /// test-only delay inside production code, which did not seem worth it
    /// for this one assertion.
    #[tokio::test]
    async fn a_delete_survives_a_subsequent_import_of_a_different_key() {
        let dir = tempfile::tempdir().expect("temp dir");
        let app = router(
            context_with_dirs(Arc::new(RwLock::new(ValidatorStore::new())), dir.path()),
            TOKEN.to_string(),
        );

        let (_, body) = send(
            app.clone(),
            authed(
                "POST",
                "/eth/v1/keystores",
                serde_json::json!({
                    "keystores": [keystore_json()],
                    "passwords": [PASSWORD],
                }),
            ),
        )
        .await;
        assert_eq!(body["data"][0]["status"], "imported", "got {body}");
        // `0x`-prefixed to match how `voting_public_key` is actually stored
        // (see `persist_import`'s `base`), since the assertion below compares
        // against it directly rather than going through `parse_pubkey`.
        let pubkey = "0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07";

        let (_, body) = send(
            app.clone(),
            authed(
                "DELETE",
                "/eth/v1/keystores",
                serde_json::json!({ "pubkeys": [pubkey] }),
            ),
        )
        .await;
        assert_eq!(body["data"][0]["status"], "deleted", "got {body}");

        // A second, unrelated key. Its import must not resurrect the one
        // just deleted by re-saving a stale definitions snapshot.
        let other_secret = {
            let mut bytes = [0u8; 32];
            bytes[31] = 7;
            bytes
        };
        let other_password = "other-password";
        let other_keystore = build_test_keystore_json(&other_secret, other_password);

        let (_, body) = send(
            app,
            authed(
                "POST",
                "/eth/v1/keystores",
                serde_json::json!({
                    "keystores": [other_keystore],
                    "passwords": [other_password],
                }),
            ),
        )
        .await;
        assert_eq!(body["data"][0]["status"], "imported", "got {body}");

        let definitions =
            ValidatorDefinitions::open(dir.path()).expect("opens the definitions file");
        assert!(
            definitions
                .0
                .iter()
                .all(|definition| definition.voting_public_key != pubkey),
            "the deleted key must not reappear: {definitions:?}"
        );
        let reloaded = ValidatorStore::load(dir.path()).expect("loads");
        assert_eq!(
            reloaded.len(),
            1,
            "only the second import's key should be active"
        );
    }

    /// Proves `definitions_lock` is real, not decorative: a second request
    /// that needs it must actually wait for an in-flight one to release it,
    /// rather than run its own open-mutate-save cycle concurrently. This is
    /// the mechanism the test above relies on to be deterministic.
    #[tokio::test]
    async fn import_waits_for_an_in_flight_holder_of_the_definitions_lock() {
        let dir = tempfile::tempdir().expect("temp dir");
        let context = context_with_dirs(Arc::new(RwLock::new(ValidatorStore::new())), dir.path());

        let guard = context.definitions_lock.clone().lock_owned().await;

        let request = ImportRequest {
            keystores: vec![keystore_json()],
            passwords: Zeroizing::new(vec![PASSWORD.to_string()]),
            slashing_protection: None,
        };
        let handle = tokio::spawn(import(State(context.clone()), Json(request)));

        // Give the spawned task every chance to run up to the point where it
        // blocks on the lock. It has no other await point before that: if it
        // were not actually waiting on `definitions_lock`, it would complete
        // well within this many yields.
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        assert!(
            !handle.is_finished(),
            "import must block while definitions_lock is held elsewhere"
        );

        drop(guard);
        let Json(response) = handle.await.expect("import task did not panic");
        assert_eq!(response.data[0].status, "imported", "got {response:?}");
    }

    /// Build a keystore JSON string (not written to disk; `import` is what
    /// writes it) that decrypts `secret` under `password`, so a test can
    /// hand `import` a second, distinct key without hardcoding another
    /// EIP-2335 vector.
    ///
    /// Kept simple rather than general: this crate has no keystore *encoder*
    /// (only `Keystore::decrypt`), so this reaches into the cipher directly
    /// with fixed, already-tested-elsewhere parameters.
    fn build_test_keystore_json(secret: &[u8; 32], password: &str) -> String {
        use aes::cipher::{KeyIvInit as _, StreamCipher as _};
        use sha2::Digest as _;

        let salt = [0x11u8; 32];
        let iv = [0x22u8; 16];
        let mut derived = [0u8; 32];
        scrypt::scrypt(
            password.as_bytes(),
            &salt,
            &scrypt::Params::new(14, 8, 1, 32).expect("valid params"),
            &mut derived,
        )
        .expect("scrypt");

        let mut cipher_message = *secret;
        type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;
        let mut cipher = Aes128Ctr::new_from_slices(&derived[..16], &iv).expect("valid key/iv");
        cipher.apply_keystream(&mut cipher_message);

        let mut hasher = sha2::Sha256::new();
        hasher.update(&derived[16..32]);
        hasher.update(cipher_message);
        let checksum = hasher.finalize();

        serde_json::json!({
            "crypto": {
                "kdf": {
                    "function": "scrypt",
                    "params": { "dklen": 32, "n": 16384, "p": 1, "r": 8, "salt": hex::encode(salt) },
                    "message": ""
                },
                "checksum": { "function": "sha256", "params": {}, "message": hex::encode(checksum) },
                "cipher": { "function": "aes-128-ctr",
                    "params": { "iv": hex::encode(iv) },
                    "message": hex::encode(cipher_message) }
            },
            "pubkey": encode_hex(&ValidatorStore::derive_pubkey(secret).expect("derives").0),
            "path": "m/12381/60/0/0",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "version": 4
        })
        .to_string()
    }

    /// Finding 3: `require_bearer` must reject a wrong token of a different
    /// length too, not just one that fails a byte comparison partway
    /// through. Not a timing assertion (this crate has no timing harness),
    /// but it does cover the length-mismatch branch of `ConstantTimeEq`'s
    /// slice impl, which returns early on differing lengths before ever
    /// comparing bytes.
    #[tokio::test]
    async fn a_token_of_a_different_length_is_rejected() {
        let request = Request::builder()
            .uri("/eth/v1/keystores")
            .header("authorization", "Bearer short")
            .body(Body::empty())
            .expect("request");
        let (status, _) = send(app(), request).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}
