//! `GET`, `POST` and `DELETE /eth/v1/remotekeys`: the validators a Web3Signer
//! signs for.
//!
//! The counterpart of `/eth/v1/keystores`, and shaped like it, with the key
//! material replaced by a URL. The two routes partition the store: this one
//! lists and deletes remote keys only, that one local keys only, and a key
//! asked of the wrong route is `not_found`. An import here of a key the
//! other route holds is `duplicate`, since the specification's word for "the
//! pubkey is already known to the validator client" covers both.
//!
//! Nothing is asked of the signer at import. The signer may start after this
//! client, or hold the key only later, and a key it turns out not to have
//! fails at its first signature, where it is logged and counted, the same way
//! an unreachable signer is.
//!
//! `readonly` is always `false`: this client has no keys it cannot delete.
//!
//! # Slashing protection
//!
//! A remote key is registered in this client's slashing-protection record
//! before it is loaded, as a local one is, and is checked against it before
//! every block and attestation: the signer keeps a record of its own, and
//! this one is kept as well, so the key is covered whichever of the two a
//! message meets first. Unlike `/eth/v1/keystores`, these routes carry no
//! history in or out, since the specification gives them no
//! `slashing_protection` field. A key imported with no record here starts as
//! never having signed, with a warning, and `DELETE` leaves the record where
//! it is, so a key imported again continues from it.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::{Json, extract::State};
use ethlambda_types::beacon::primitives::BlsPubkey;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::Error;
use crate::beacon_node::dto::{encode_hex, parse_pubkey};
use crate::http_api::KeymanagerContext;
use crate::http_api::keystores::{
    DeleteRequest, Judged, KeyStatus, Origin, StatusResponse, delete_keys, save_definitions,
};
use crate::keys::{
    SigningDefinition, ValidatorDefinition, ValidatorDefinitions, ValidatorStore, Web3Signer,
};

#[derive(Debug, Serialize)]
pub struct ListResponse {
    pub data: Vec<RemoteKey>,
}

#[derive(Debug, Serialize)]
pub struct RemoteKey {
    pub pubkey: String,
    pub url: String,
    pub readonly: bool,
}

#[derive(Debug, Deserialize)]
pub struct ImportRequest {
    pub remote_keys: Vec<ImportRemoteKey>,
}

#[derive(Debug, Deserialize)]
pub struct ImportRemoteKey {
    pub pubkey: String,
    /// The signer's base URL. Absent means `--web3signer-url`, and an import
    /// with neither is an error for that key.
    #[serde(default)]
    pub url: Option<String>,
}

pub async fn list(State(context): State<KeymanagerContext>) -> Json<ListResponse> {
    let store = context.store.read().await;
    let mut data: Vec<RemoteKey> = store
        .remote_entries()
        .into_iter()
        .map(|(pubkey, url)| RemoteKey {
            pubkey: encode_hex(&pubkey.0),
            url,
            readonly: false,
        })
        .collect();
    // The store is a hash map; a stable order makes the answer diffable.
    data.sort_by(|a, b| a.pubkey.cmp(&b.pubkey));
    Json(ListResponse { data })
}

/// The most keys one `POST /eth/v1/remotekeys` may carry. Larger than the
/// keystores route's cap, since a remote import does no key derivation, but
/// still bounded: the whole batch is judged and persisted while
/// `definitions_lock` is held, and a migration of thousands of keys is a few
/// requests rather than one unbounded one.
pub const MAX_REMOTE_KEYS_PER_IMPORT: usize = 1000;

/// One key of an import, judged: the key and its signer's client to insert,
/// `None` for a duplicate, or the status to answer with instead.
type Prepared = std::result::Result<Option<(BlsPubkey, Arc<Web3Signer>)>, KeyStatus>;

pub async fn import(
    State(context): State<KeymanagerContext>,
    Json(request): Json<ImportRequest>,
) -> Json<StatusResponse> {
    let fail_all = |message: &str| {
        let data = request
            .remote_keys
            .iter()
            .map(|_| KeyStatus::error(message))
            .collect();
        Json(StatusResponse { data })
    };

    if request.remote_keys.len() > MAX_REMOTE_KEYS_PER_IMPORT {
        warn!(
            count = request.remote_keys.len(),
            "Rejecting oversized remote key import request"
        );
        return fail_all(&format!(
            "request carries {} remote keys, more than the limit of \
             {MAX_REMOTE_KEYS_PER_IMPORT}",
            request.remote_keys.len()
        ));
    }

    // Held until the keys are in the store, not just until they are on disk.
    // Every keymanager writer takes this first, so while it is held nothing
    // else can change the file or the store: what is judged below against
    // the two is still true at the insert, and no re-check is needed there.
    // See `KeymanagerContext::definitions_lock` for the lock order.
    let _definitions_guard = context.definitions_lock.lock().await;

    let mut definitions = match ValidatorDefinitions::open(&context.validators_dir) {
        Ok(definitions) => definitions,
        Err(err) => return fail_all(&err.to_string()),
    };

    // What the store holds, read under a guard released at once: nothing
    // below holds the store across file I/O or client construction, so a
    // duty's per-signature read never waits on this request.
    let (mut known, mut signers) = {
        let store = context.store.read().await;
        let known: HashSet<BlsPubkey> = store.pubkeys().into_iter().collect();
        (known, store.remote_signers())
    };
    // And what the file names, each entry decoded once for the request
    // rather than once for every key in it. A disabled local entry, or one
    // left behind by a failed delete, is still "already known": overwriting
    // it would turn a key the operator disabled into a signing one.
    known.extend(definitions.keyed().map(|(pubkey, _)| pubkey));

    let mut prepared: Vec<Prepared> = request
        .remote_keys
        .iter()
        .map(|key| prepare_import(&context, &mut known, &mut signers, &mut definitions, key))
        .collect();

    // One save for the whole batch rather than one per key. A failure fails
    // every key that would have been added, and none is put in the store:
    // a key this process signs with must already be durable.
    let staged: Vec<BlsPubkey> = prepared
        .iter()
        .filter_map(|result| match result {
            Ok(Some((pubkey, _))) => Some(*pubkey),
            _ => None,
        })
        .collect();
    let mut failure = None;
    if !staged.is_empty() {
        match save_definitions(&context, &definitions) {
            Ok(()) => {}
            // The entries are on disk and every reader sees them; only their
            // survival of a power loss is in doubt, and an entry lost that way
            // only removes a key. Counted as persisted, as a local import is.
            Err(Error::Unflushed { path, source }) => warn!(
                %path,
                %source,
                "Validator definitions written, but the directory could not be flushed"
            ),
            Err(err) => failure = Some(err.to_string()),
        }
    }

    // Every key is registered in the slashing-protection record, in one
    // durable write, before any of them is loaded: the duty path must never
    // meet a key with no record. After the save rather than before, for the
    // reason `keystores::import` gives: a key whose save failed leaves no
    // record behind to let a hand-written entry past the startup check later.
    if failure.is_none() && !staged.is_empty() {
        let registering = staged.clone();
        let registration =
            crate::slashing_protection::blocking(&context.protection, move |protection| {
                protection.absorb(None, &registering)
            })
            .await;
        match registration {
            Ok(absorbed) => {
                if absorbed.registered > 0 {
                    warn!(
                        registered = absorbed.registered,
                        "Imported remote validator keys with no slashing-protection record \
                         here; each starts as never having signed"
                    );
                }
            }
            // On disk and in memory, with only a power loss in doubt, and a
            // registration lost that way is refused at the next start. So the
            // keys are loaded, as `keystores::import` loads its own.
            Err(Error::Unflushed { path, source }) => warn!(
                %path,
                %source,
                "Slashing-protection records written, but the directory could not be flushed; \
                 the imported keys are registered"
            ),
            // The write is known to have failed, so the entries this request
            // added come off the file again: left there, the next start would
            // refuse the whole client for a key with no record.
            Err(err) => {
                let added: HashSet<BlsPubkey> = staged.iter().copied().collect();
                definitions.remove_where(|pubkey, _| added.contains(pubkey));
                failure = Some(match save_definitions(&context, &definitions) {
                    Ok(()) | Err(Error::Unflushed { .. }) => format!(
                        "not imported: its slashing-protection record could not be written: {err}"
                    ),
                    Err(undo) => {
                        tracing::error!(
                            %undo,
                            "Could not undo a failed remote import; the next start refuses its \
                             keys until they have a slashing-protection record"
                        );
                        format!(
                            "saved, but not loaded: its slashing-protection record could not be \
                             written: {err}"
                        )
                    }
                });
            }
        }
    }
    if let Some(message) = &failure {
        for result in &mut prepared {
            if matches!(result, Ok(Some(_))) {
                *result = Err(KeyStatus::error(message));
            }
        }
    }

    // The write lock covers map inserts and nothing else: every client was
    // built above.
    let mut store = context.store.write().await;
    let data = prepared
        .into_iter()
        .map(|result| match result {
            Ok(Some((pubkey, signer))) => {
                info!(pubkey = %encode_hex(&pubkey.0), url = signer.url(), "Imported remote validator key");
                store.insert_remote_signer(pubkey, signer);
                KeyStatus {
                    status: "imported".to_string(),
                    message: None,
                }
            }
            Ok(None) => KeyStatus::duplicate(),
            Err(status) => status,
        })
        .collect();
    drop(store);

    Json(StatusResponse { data })
}

/// Judge one key of an import and stage its definition: resolve the URL,
/// refuse a key already known, build (or reuse) the signer's client, and
/// append the entry to `definitions`, which the caller saves once for the
/// whole batch.
///
/// `Ok(None)` is a duplicate. `known` is every key the store holds or the
/// file names, and gains each key staged here, so a key named twice in one
/// request is a duplicate the second time.
fn prepare_import(
    context: &KeymanagerContext,
    known: &mut HashSet<BlsPubkey>,
    signers: &mut HashMap<String, Arc<Web3Signer>>,
    definitions: &mut ValidatorDefinitions,
    key: &ImportRemoteKey,
) -> Prepared {
    let pubkey = parse_pubkey(&key.pubkey).map_err(KeyStatus::error)?;
    let url = match key
        .url
        .as_deref()
        .or(context.default_remote_signer.as_deref())
    {
        Some(url) => url.trim_end_matches('/').to_string(),
        None => {
            return Err(KeyStatus::error(
                "no url supplied for this key and no --web3signer-url to default to",
            ));
        }
    };

    // Known to the store, or to the file. Judged before anything is built or
    // staged.
    if known.contains(&pubkey) {
        return Ok(None);
    }

    // Built here, outside the store's lock, and once per URL: the client is
    // the one the store will keep, so the URL's shape is checked by building
    // the thing that will use it, and an unusable URL is refused before it
    // is persisted and refuses the next startup.
    let signer = match signers.get(&url) {
        Some(signer) => signer.clone(),
        None => {
            let signer = Arc::new(Web3Signer::new(&url).map_err(KeyStatus::error)?);
            signers.insert(url.clone(), signer.clone());
            signer
        }
    };

    definitions.0.push(ValidatorDefinition {
        enabled: true,
        voting_public_key: encode_hex(&pubkey.0),
        signing: SigningDefinition::Web3Signer { url },
    });
    known.insert(pubkey);
    Ok(Some((pubkey, signer)))
}

pub async fn delete(
    State(context): State<KeymanagerContext>,
    Json(request): Json<DeleteRequest>,
) -> Json<StatusResponse> {
    let _definitions_guard = context.definitions_lock.lock().await;

    // Uncapped, and a migration off a signer deletes hundreds of keys in one
    // request. `delete_keys` reads the file once, holds the store's write
    // lock only to take the keys out of memory, and saves once, so a request
    // that size does not stand between the duties and their signatures.
    let data = delete_keys(&context, &request.pubkeys, Origin::Remote, judge_delete)
        .await
        .into_iter()
        .map(|(_, status)| status)
        .collect();

    Json(StatusResponse { data })
}

/// The keystores route's judgement, gated the other way: only a remote key is
/// this route's to remove, and a local one is `not_found` here whatever its
/// state. The file decides `not_found`, for the reason spelled out on
/// `keystores::delete_keys`.
fn judge_delete(
    context: &KeymanagerContext,
    store: &mut ValidatorStore,
    pubkey: &BlsPubkey,
    entry: Option<Origin>,
) -> Judged {
    let on_disk = entry == Some(Origin::Remote);
    let in_memory = store.remote_url(pubkey).is_some();
    if !on_disk && !in_memory {
        return Judged::Absent;
    }

    if in_memory {
        store.remove(pubkey);
    }
    // The key's overrides go with it, unless the store still holds it. That
    // is the file listing a remote entry for a key this process runs as a
    // local one, which only a hand edit under a running client produces: the
    // entry comes off the file, but the local key is the keystores route's
    // and keeps proposing, so its fee recipient, graffiti and gas limit stay
    // or its next blocks would pay the default address.
    if !store.contains(pubkey) {
        context.settings.forget(pubkey);
    }
    // The mirror of the keystores route's case: the store held the key
    // remotely while the file lists it as a local keystore, an entry this
    // route leaves alone and the next start would load.
    Judged::Removed {
        stranded: in_memory && entry == Some(Origin::Local),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_api::{SharedStore, router};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt as _;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use tower::ServiceExt as _;

    const TOKEN: &str = "test-token";
    const SIGNER: &str = "https://signer.example:9000";

    fn pubkey_hex(byte: u8) -> String {
        format!("0x{}", hex::encode([byte; 48]))
    }

    fn context_with_dirs(
        store: SharedStore,
        dir: &std::path::Path,
        default_remote_signer: Option<&str>,
    ) -> KeymanagerContext {
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
            default_remote_signer: default_remote_signer.map(str::to_string),
        }
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

    fn statuses(body: &serde_json::Value) -> Vec<String> {
        body["data"]
            .as_array()
            .expect("data array")
            .iter()
            .map(|entry| entry["status"].as_str().expect("status").to_string())
            .collect()
    }

    #[tokio::test]
    async fn the_route_is_behind_the_bearer_token() {
        let dir = tempfile::tempdir().expect("temp dir");
        let app = router(
            context_with_dirs(
                Arc::new(RwLock::new(ValidatorStore::new())),
                dir.path(),
                None,
            ),
            TOKEN.to_string(),
        );
        let request = Request::builder()
            .uri("/eth/v1/remotekeys")
            .body(Body::empty())
            .expect("request");
        let (status, _) = send(app, request).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn import_list_delete_round_trip() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = Arc::new(RwLock::new(ValidatorStore::new()));
        let app = router(
            context_with_dirs(store.clone(), dir.path(), None),
            TOKEN.to_string(),
        );

        let (status, body) = send(
            app.clone(),
            authed(
                "POST",
                "/eth/v1/remotekeys",
                serde_json::json!({ "remote_keys": [
                    { "pubkey": pubkey_hex(1), "url": SIGNER },
                    { "pubkey": pubkey_hex(2), "url": format!("{SIGNER}/") },
                ] }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(statuses(&body), ["imported", "imported"]);

        let (status, body) = send(
            app.clone(),
            authed("GET", "/eth/v1/remotekeys", serde_json::json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let listed = body["data"].as_array().expect("data");
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0]["pubkey"], pubkey_hex(1));
        assert_eq!(listed[0]["url"], SIGNER, "the trailing slash is normalized");
        assert_eq!(listed[1]["url"], SIGNER);
        assert_eq!(listed[0]["readonly"], false);

        // Persisted: a fresh load from the directory holds both as remote.
        let reloaded = ValidatorStore::load(dir.path()).expect("loads");
        assert_eq!(reloaded.remote_entries().len(), 2);
        assert!(reloaded.local_pubkeys().is_empty());

        // The keystores route does not list them.
        let (_, body) = send(
            app.clone(),
            authed("GET", "/eth/v1/keystores", serde_json::json!({})),
        )
        .await;
        assert!(body["data"].as_array().expect("data").is_empty());

        let (status, body) = send(
            app.clone(),
            authed(
                "DELETE",
                "/eth/v1/remotekeys",
                serde_json::json!({ "pubkeys": [pubkey_hex(1), pubkey_hex(3)] }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(statuses(&body), ["deleted", "not_found"]);
        assert!(
            body.get("slashing_protection").is_none(),
            "the remote route has no interchange to report"
        );

        assert_eq!(store.read().await.len(), 1);
        let reloaded = ValidatorStore::load(dir.path()).expect("loads");
        assert_eq!(reloaded.len(), 1, "the delete is persisted");
    }

    #[tokio::test]
    async fn a_missing_url_falls_back_to_the_configured_signer_or_errors() {
        let dir = tempfile::tempdir().expect("temp dir");
        let with_default = router(
            context_with_dirs(
                Arc::new(RwLock::new(ValidatorStore::new())),
                dir.path(),
                Some(SIGNER),
            ),
            TOKEN.to_string(),
        );
        let (_, body) = send(
            with_default.clone(),
            authed(
                "POST",
                "/eth/v1/remotekeys",
                serde_json::json!({ "remote_keys": [{ "pubkey": pubkey_hex(1) }] }),
            ),
        )
        .await;
        assert_eq!(statuses(&body), ["imported"]);
        let (_, body) = send(
            with_default,
            authed("GET", "/eth/v1/remotekeys", serde_json::json!({})),
        )
        .await;
        assert_eq!(body["data"][0]["url"], SIGNER);

        let other = tempfile::tempdir().expect("temp dir");
        let without_default = router(
            context_with_dirs(
                Arc::new(RwLock::new(ValidatorStore::new())),
                other.path(),
                None,
            ),
            TOKEN.to_string(),
        );
        let (_, body) = send(
            without_default,
            authed(
                "POST",
                "/eth/v1/remotekeys",
                serde_json::json!({ "remote_keys": [{ "pubkey": pubkey_hex(1) }] }),
            ),
        )
        .await;
        assert_eq!(statuses(&body), ["error"]);
        assert!(
            body["data"][0]["message"]
                .as_str()
                .expect("message")
                .contains("--web3signer-url")
        );
        assert!(
            ValidatorStore::load(other.path())
                .expect("loads")
                .is_empty(),
            "an errored import persists nothing"
        );
    }

    #[tokio::test]
    async fn an_already_held_key_is_a_duplicate_whichever_route_holds_it() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut store = ValidatorStore::new();
        let local = store
            .insert_secret(
                "test",
                &hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                    .expect("hex")
                    .try_into()
                    .expect("32 bytes"),
            )
            .expect("inserts");
        let store = Arc::new(RwLock::new(store));
        let app = router(
            context_with_dirs(store.clone(), dir.path(), None),
            TOKEN.to_string(),
        );

        let import = |pubkey: String| {
            authed(
                "POST",
                "/eth/v1/remotekeys",
                serde_json::json!({ "remote_keys": [{ "pubkey": pubkey, "url": SIGNER }] }),
            )
        };
        let (_, body) = send(app.clone(), import(pubkey_hex(1))).await;
        assert_eq!(statuses(&body), ["imported"]);
        let (_, body) = send(app.clone(), import(pubkey_hex(1))).await;
        assert_eq!(statuses(&body), ["duplicate"]);
        let (_, body) = send(app.clone(), import(encode_hex(&local.0))).await;
        assert_eq!(statuses(&body), ["duplicate"]);

        assert!(
            store.read().await.remote_url(&local).is_none(),
            "a duplicate must not replace the local key with a remote one"
        );
    }

    #[tokio::test]
    async fn a_bad_pubkey_or_url_is_an_error_for_that_key_alone() {
        let dir = tempfile::tempdir().expect("temp dir");
        let app = router(
            context_with_dirs(
                Arc::new(RwLock::new(ValidatorStore::new())),
                dir.path(),
                None,
            ),
            TOKEN.to_string(),
        );
        let (_, body) = send(
            app,
            authed(
                "POST",
                "/eth/v1/remotekeys",
                serde_json::json!({ "remote_keys": [
                    { "pubkey": "0xnope", "url": SIGNER },
                    { "pubkey": pubkey_hex(1), "url": "ftp://signer" },
                    { "pubkey": pubkey_hex(2), "url": SIGNER },
                ] }),
            ),
        )
        .await;
        assert_eq!(statuses(&body), ["error", "error", "imported"]);
    }

    /// The two routes partition the store: a key each one holds is
    /// `not_found` to the other's delete, and only its own route removes it.
    #[tokio::test]
    async fn each_route_deletes_only_its_own_keys() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = Arc::new(RwLock::new(ValidatorStore::new()));
        let app = router(
            context_with_dirs(store.clone(), dir.path(), None),
            TOKEN.to_string(),
        );
        let (_, body) = send(
            app.clone(),
            authed(
                "POST",
                "/eth/v1/remotekeys",
                serde_json::json!({ "remote_keys": [{ "pubkey": pubkey_hex(1), "url": SIGNER }] }),
            ),
        )
        .await;
        assert_eq!(statuses(&body), ["imported"]);

        let (_, body) = send(
            app.clone(),
            authed(
                "DELETE",
                "/eth/v1/keystores",
                serde_json::json!({ "pubkeys": [pubkey_hex(1)] }),
            ),
        )
        .await;
        // `not_found`, not `not_active`: the key has a slashing-protection
        // record, but it is held, by the other route, and still signing. Its
        // record is not handed over as though the key were gone.
        assert_eq!(statuses(&body), ["not_found"]);
        let exported: serde_json::Value =
            serde_json::from_str(body["slashing_protection"].as_str().expect("a string"))
                .expect("an interchange");
        assert_eq!(exported["data"], serde_json::json!([]), "got {exported}");
        assert_eq!(
            store.read().await.len(),
            1,
            "the keystores route left it alone"
        );
        assert_eq!(ValidatorStore::load(dir.path()).expect("loads").len(), 1);

        let (_, body) = send(
            app,
            authed(
                "DELETE",
                "/eth/v1/remotekeys",
                serde_json::json!({ "pubkeys": [pubkey_hex(1)] }),
            ),
        )
        .await;
        assert_eq!(statuses(&body), ["deleted"]);
        assert!(store.read().await.is_empty());
    }

    /// One request, many keys: each is judged against a single read of the
    /// file and comes off it in a single save. A key named twice is `deleted`
    /// the first time and gone the second, and a key this client never had
    /// is `not_found`.
    #[tokio::test]
    async fn a_delete_of_several_keys_judges_each_and_saves_once() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = Arc::new(RwLock::new(ValidatorStore::new()));
        let app = router(
            context_with_dirs(store.clone(), dir.path(), Some(SIGNER)),
            TOKEN.to_string(),
        );
        let (_, body) = send(
            app.clone(),
            authed(
                "POST",
                "/eth/v1/remotekeys",
                serde_json::json!({ "remote_keys": [
                    { "pubkey": pubkey_hex(1) },
                    { "pubkey": pubkey_hex(2) },
                    { "pubkey": pubkey_hex(3) },
                ] }),
            ),
        )
        .await;
        assert_eq!(statuses(&body), ["imported", "imported", "imported"]);

        let (_, body) = send(
            app,
            authed(
                "DELETE",
                "/eth/v1/remotekeys",
                serde_json::json!({ "pubkeys": [
                    pubkey_hex(1), pubkey_hex(9), pubkey_hex(2), "0xnothex", pubkey_hex(1),
                ] }),
            ),
        )
        .await;
        assert_eq!(
            statuses(&body),
            ["deleted", "not_found", "deleted", "error", "not_found"],
            "got {body}"
        );

        let kept = parse_pubkey(&pubkey_hex(3)).expect("pubkey");
        assert_eq!(store.read().await.pubkeys(), vec![kept]);
        let on_disk = ValidatorDefinitions::open(dir.path()).expect("opens");
        assert_eq!(on_disk.0.len(), 1);
        assert_eq!(on_disk.0[0].voting_public_key, pubkey_hex(3));
    }

    /// The file listing a remote entry for a key this process runs as a local
    /// one, which only a hand edit under a running client produces. The
    /// entry is this route's to remove, but the local key is not: it keeps
    /// signing, and it keeps the settings it proposes with.
    #[tokio::test]
    async fn a_delete_leaves_a_local_key_under_the_same_pubkey_its_settings() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut store = ValidatorStore::new();
        let mut secret = [0u8; 32];
        secret[31] = 1;
        let pubkey = store.insert_secret("test", &secret).expect("inserts");
        let hex = encode_hex(&pubkey.0);
        ValidatorDefinitions(vec![ValidatorDefinition {
            enabled: true,
            voting_public_key: hex.clone(),
            signing: SigningDefinition::Web3Signer {
                url: SIGNER.to_string(),
            },
        }])
        .save(dir.path())
        .expect("saves");
        let store = Arc::new(RwLock::new(store));
        let context = context_with_dirs(store.clone(), dir.path(), None);
        let settings = context.settings.clone();
        let fee_recipient = ethlambda_types::beacon::primitives::H160([0xcd; 20]);
        settings.set_fee_recipient(&pubkey, fee_recipient);

        let (_, body) = send(
            router(context, TOKEN.to_string()),
            authed(
                "DELETE",
                "/eth/v1/remotekeys",
                serde_json::json!({ "pubkeys": [hex] }),
            ),
        )
        .await;
        assert_eq!(statuses(&body), ["deleted"], "got {body}");

        let on_disk = ValidatorDefinitions::open(dir.path()).expect("opens");
        assert!(on_disk.0.is_empty(), "the remote entry is off the file");
        assert!(
            store.read().await.contains(&pubkey),
            "the local key is the other route's and still signs"
        );
        assert_eq!(
            settings.fee_recipient(&pubkey),
            Some(fee_recipient),
            "a key that keeps proposing keeps its fee recipient"
        );
    }

    /// The mirror of the keystores route's case: the store holds the key
    /// through a signer while the file lists it as a local keystore. The
    /// delete stops the key signing and leaves the other route's entry
    /// alone, and since that entry would bring the key back at the next
    /// start, the answer is an error rather than `deleted`.
    #[tokio::test]
    async fn a_delete_does_not_report_gone_a_key_the_file_lists_as_local() {
        let dir = tempfile::tempdir().expect("temp dir");
        let pubkey = parse_pubkey(&pubkey_hex(1)).expect("pubkey");
        let mut store = ValidatorStore::new();
        store.insert_remote(pubkey, SIGNER).expect("inserts");
        ValidatorDefinitions(vec![ValidatorDefinition {
            enabled: true,
            voting_public_key: pubkey_hex(1),
            signing: SigningDefinition::LocalKeystore {
                voting_keystore_path: "keystore.json".into(),
                voting_keystore_password_path: "password.txt".into(),
            },
        }])
        .save(dir.path())
        .expect("saves");
        let store = Arc::new(RwLock::new(store));
        let app = router(
            context_with_dirs(store.clone(), dir.path(), None),
            TOKEN.to_string(),
        );

        let (_, body) = send(
            app,
            authed(
                "DELETE",
                "/eth/v1/remotekeys",
                serde_json::json!({ "pubkeys": [pubkey_hex(1)] }),
            ),
        )
        .await;
        assert_eq!(statuses(&body), ["error"], "got {body}");
        let message = body["data"][0]["message"].as_str().expect("a message");
        assert!(message.contains("/eth/v1/keystores"), "{message}");
        assert!(
            store.read().await.is_empty(),
            "the remote key stops signing"
        );
        let on_disk = ValidatorDefinitions::open(dir.path()).expect("opens");
        assert_eq!(on_disk.0.len(), 1, "the local entry is not this route's");
        assert!(!on_disk.0[0].signing.is_remote());
    }

    /// A context over `dir` whose slashing protection is a real record there,
    /// for the chain `0x00..00`, and the handle to inspect it with.
    fn context_with_record(
        store: SharedStore,
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
        )
        .expect("opens with no keys");
        let mut context = context_with_dirs(store, dir, None);
        context.protection = Arc::new(std::sync::Mutex::new(protection));
        let protection = context.protection.clone();
        (context, protection)
    }

    /// A remote key is registered in this client's slashing-protection record
    /// before it is loaded, as a local one is: the duty path checks every key
    /// against the record, and the next start refuses one that has none.
    #[tokio::test]
    async fn an_imported_remote_key_is_registered_for_slashing_protection() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = Arc::new(RwLock::new(ValidatorStore::new()));
        let (context, protection) = context_with_record(store.clone(), dir.path());

        let (_, body) = send(
            router(context, TOKEN.to_string()),
            authed(
                "POST",
                "/eth/v1/remotekeys",
                serde_json::json!({ "remote_keys": [{ "pubkey": pubkey_hex(1), "url": SIGNER }] }),
            ),
        )
        .await;
        assert_eq!(statuses(&body), ["imported"]);

        let pubkey = parse_pubkey(&pubkey_hex(1)).expect("valid");
        assert!(store.read().await.contains(&pubkey), "loaded");
        assert!(
            protection.lock().expect("lock").contains(&pubkey),
            "and registered"
        );
    }

    /// A registration that fails costs the request only: the entries it added
    /// come off the file again and no key is loaded. Left on the file, a key
    /// with no record would have the next start refuse the whole client.
    #[tokio::test]
    async fn a_failed_registration_rolls_the_remote_import_back() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = Arc::new(RwLock::new(ValidatorStore::new()));
        let (context, protection) = context_with_record(store.clone(), dir.path());
        // A directory in the record's place makes the registration's rename
        // fail, whoever runs the test.
        let record = protection
            .lock()
            .expect("lock")
            .path()
            .expect("persisted")
            .to_path_buf();
        std::fs::remove_file(&record).expect("removes the record");
        std::fs::create_dir(&record).expect("a directory in its place");

        let (_, body) = send(
            router(context, TOKEN.to_string()),
            authed(
                "POST",
                "/eth/v1/remotekeys",
                serde_json::json!({ "remote_keys": [
                    { "pubkey": pubkey_hex(1), "url": SIGNER },
                    { "pubkey": pubkey_hex(2), "url": SIGNER },
                ] }),
            ),
        )
        .await;
        assert_eq!(statuses(&body), ["error", "error"], "got {body}");
        assert!(
            body["data"][0]["message"]
                .as_str()
                .unwrap_or_default()
                .starts_with("not imported"),
            "got {body}"
        );
        assert!(store.read().await.is_empty(), "not loaded");
        assert!(
            ValidatorDefinitions::open(dir.path())
                .expect("opens")
                .0
                .is_empty(),
            "the next start finds no key to refuse"
        );
    }

    /// A remote entry still on disk after a failed delete must not be
    /// `not_found`, for the reason the keystores route's is not: an operator
    /// who reads `not_found` moves the key elsewhere, and the next restart
    /// brings it back here too.
    #[tokio::test]
    async fn a_remote_key_still_on_disk_is_not_reported_not_found() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = Arc::new(RwLock::new(ValidatorStore::new()));
        let app = router(
            context_with_dirs(store.clone(), dir.path(), None),
            TOKEN.to_string(),
        );
        let (_, body) = send(
            app.clone(),
            authed(
                "POST",
                "/eth/v1/remotekeys",
                serde_json::json!({ "remote_keys": [{ "pubkey": pubkey_hex(1), "url": SIGNER }] }),
            ),
        )
        .await;
        assert_eq!(statuses(&body), ["imported"]);

        // Gone from memory, still on disk.
        let pubkey = parse_pubkey(&pubkey_hex(1)).expect("pubkey");
        assert!(store.write().await.remove(&pubkey));

        let (_, body) = send(
            app,
            authed(
                "DELETE",
                "/eth/v1/remotekeys",
                serde_json::json!({ "pubkeys": [pubkey_hex(1)] }),
            ),
        )
        .await;
        assert_eq!(statuses(&body), ["deleted"]);
        assert!(ValidatorStore::load(dir.path()).expect("loads").is_empty());
    }
}
