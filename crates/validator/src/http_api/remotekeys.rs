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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::{Json, extract::State};
use ethlambda_types::beacon::primitives::BlsPubkey;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::beacon_node::dto::{encode_hex, parse_pubkey};
use crate::http_api::KeymanagerContext;
use crate::http_api::keystores::{
    DeleteRequest, KeyStatus, Origin, StatusResponse, definitions_entry, persist_delete,
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
    let (known, mut signers) = {
        let store = context.store.read().await;
        let known: HashSet<BlsPubkey> = store.pubkeys().into_iter().collect();
        (known, store.remote_signers())
    };

    let mut prepared: Vec<Prepared> = request
        .remote_keys
        .iter()
        .map(|key| prepare_import(&context, &known, &mut signers, &mut definitions, key))
        .collect();

    // One save for the whole batch rather than one per key. A failure fails
    // every key that would have been added, and none is put in the store:
    // a key this process signs with must already be durable.
    if prepared.iter().any(|result| matches!(result, Ok(Some(_))))
        && let Err(err) = definitions.save(&context.validators_dir)
    {
        let message = err.to_string();
        for result in &mut prepared {
            if matches!(result, Ok(Some(_))) {
                *result = Err(KeyStatus::error(&message));
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
/// `Ok(None)` is a duplicate. `known` is the store's keys; `definitions`
/// already holds the entries staged for earlier keys in the batch, so a key
/// named twice in one request is a duplicate the second time.
fn prepare_import(
    context: &KeymanagerContext,
    known: &HashSet<BlsPubkey>,
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

    // Known to the store, or to the file: a disabled local entry, or one
    // left behind by a failed delete, is still "already known", and
    // overwriting it would turn a key the operator disabled into a signing
    // one. Judged before anything is built or staged.
    let on_disk = definitions.0.iter().any(|definition| {
        parse_pubkey(&definition.voting_public_key)
            .map(|parsed| parsed == pubkey)
            .unwrap_or(false)
    });
    if on_disk || known.contains(&pubkey) {
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
    Ok(Some((pubkey, signer)))
}

pub async fn delete(
    State(context): State<KeymanagerContext>,
    Json(request): Json<DeleteRequest>,
) -> Json<StatusResponse> {
    let _definitions_guard = context.definitions_lock.lock().await;

    let mut store = context.store.write().await;
    let data = request
        .pubkeys
        .iter()
        .map(|text| match parse_pubkey(text) {
            Ok(pubkey) => delete_one(&context, &mut store, &pubkey),
            Err(err) => KeyStatus::error(err),
        })
        .collect();
    drop(store);

    Json(StatusResponse { data })
}

/// The keystores route's delete, gated the other way: only a remote key is
/// this route's to remove, and a local one is `not_found` here whatever its
/// state. The on-disk check comes first and decides `not_found`, for the
/// reason spelled out on `keystores::delete_one`.
fn delete_one(
    context: &KeymanagerContext,
    store: &mut ValidatorStore,
    pubkey: &ethlambda_types::beacon::primitives::BlsPubkey,
) -> KeyStatus {
    let on_disk = match definitions_entry(context, pubkey) {
        Ok(entry) => entry.is_some_and(|signing| signing.is_remote()),
        Err(err) => return KeyStatus::error(err),
    };
    let in_memory = store.remote_url(pubkey).is_some();
    if !on_disk && !in_memory {
        return KeyStatus {
            status: "not_found".to_string(),
            message: None,
        };
    }

    // The in-memory removal first, so this process stops signing with the
    // key whatever becomes of the file; a failed persist is reported, not
    // swallowed, so a retry gets the same error rather than a `not_found`
    // that reads as "already gone".
    if in_memory {
        store.remove(pubkey);
    }
    context.settings.forget(pubkey);
    if let Err(err) = persist_delete(context, pubkey, Origin::Remote) {
        return KeyStatus::error(err);
    }

    info!(pubkey = %encode_hex(&pubkey.0), "Deleted remote validator key");
    KeyStatus {
        status: "deleted".to_string(),
        message: None,
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
        assert_eq!(statuses(&body), ["not_found"]);
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
