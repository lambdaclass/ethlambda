//! `GET`, `POST` and `DELETE /eth/v1/validator/{pubkey}/feerecipient`,
//! `/graffiti` and `/gas_limit`.
//!
//! Each overrides one validator's setting in [`ProposerSettings`], and first
//! writes it onto that validator's entry in `validator_definitions.yml`, so a
//! restart runs with it. See [`crate::proposer_settings`] for when a change
//! takes effect.
//!
//! `GET` answers the validator's own value, or the process-wide default when it
//! has none, as the specification asks. `DELETE` drops the validator's own
//! value, so it is back on the default; it answers 204 whether or not there was
//! one to drop.
//!
//! Every route answers 404 for a key this client does not hold. The check and
//! the change happen under one read of the validator store, so a keystore
//! delete, which takes that store's write lock and then forgets the key's
//! settings, cannot land between them and leave an override behind for a key
//! that is gone. The file is written under the same `definitions_lock` the
//! keystore routes take, and before memory changes: a failed write is a 500
//! that changes nothing, so what the operator sees is what the next restart
//! loads.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use ethlambda_types::beacon::primitives::BlsPubkey;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::beacon_node::dto::{encode_hex, parse_pubkey};
use crate::http_api::KeymanagerContext;
use crate::keys::{ValidatorDefinitions, ValidatorStore};
use crate::proposer_settings::{
    GRAFFITI_BYTES, SettingChange, fee_recipient_from_text, graffiti_from_text, graffiti_to_text,
};

/// The keymanager API's error body, `{"message": ...}`.
#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    NotFound(String),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::BadRequest(message) => (StatusCode::BAD_REQUEST, message),
            ApiError::NotFound(message) => (StatusCode::NOT_FOUND, message),
            ApiError::Internal(message) => (StatusCode::INTERNAL_SERVER_ERROR, message),
        };
        (status, Json(serde_json::json!({ "message": message }))).into_response()
    }
}

impl From<JsonRejection> for ApiError {
    /// A body that is not the request's JSON is a 400, as every route here
    /// declares, rather than axum's own 415 or 422.
    fn from(rejection: JsonRejection) -> Self {
        ApiError::BadRequest(rejection.body_text())
    }
}

#[derive(Debug, Serialize)]
pub struct Data<T> {
    pub data: T,
}

#[derive(Debug, Serialize)]
pub struct FeeRecipientEntry {
    pub pubkey: String,
    pub ethaddress: String,
}

#[derive(Debug, Serialize)]
pub struct GraffitiEntry {
    pub pubkey: String,
    pub graffiti: String,
}

#[derive(Debug, Serialize)]
pub struct GasLimitEntry {
    pub pubkey: String,
    /// A decimal string, the specification's `Uint64`.
    pub gas_limit: String,
}

#[derive(Debug, Deserialize)]
pub struct SetFeeRecipientRequest {
    pub ethaddress: String,
}

#[derive(Debug, Deserialize)]
pub struct SetGraffitiRequest {
    pub graffiti: String,
}

#[derive(Debug, Deserialize)]
pub struct SetGasLimitRequest {
    pub gas_limit: String,
}

/// The key in the path, or a 400 when it is not one.
fn parse_path_key(text: &str) -> Result<BlsPubkey, ApiError> {
    parse_pubkey(text).map_err(|err| ApiError::BadRequest(err.to_string()))
}

/// A 404 unless the store holds `pubkey`.
fn require_held(store: &ValidatorStore, pubkey: &BlsPubkey) -> Result<(), ApiError> {
    if store.contains(pubkey) {
        Ok(())
    } else {
        Err(ApiError::NotFound(format!(
            "no validator with pubkey {} is held by this client",
            encode_hex(&pubkey.0)
        )))
    }
}

/// Persist `change` on `pubkey`'s definitions entry, then apply it in memory.
///
/// Locks in the order the keystore routes take them: `definitions_lock`
/// first, which serialises this open-mutate-save cycle against a concurrent
/// import or delete, then `store`'s read lock for the held check, kept until
/// the change is applied so a delete cannot land in between.
///
/// A held key with no entry in the file can only mean the file was edited
/// under a running client. That is a 500 naming the file rather than a
/// memory-only change the operator would believe persisted.
async fn persist_and_apply(
    context: &KeymanagerContext,
    pubkey: &BlsPubkey,
    change: SettingChange,
) -> Result<(), ApiError> {
    let _definitions_guard = context.definitions_lock.lock().await;
    let store = context.store.read().await;
    require_held(&store, pubkey)?;

    let path = context
        .validators_dir
        .join(crate::keys::definitions::DEFINITIONS_FILE);
    let mut definitions = ValidatorDefinitions::open(&context.validators_dir)
        .map_err(|err| ApiError::Internal(format!("could not read {}: {err}", path.display())))?;
    let entry = definitions
        .0
        .iter_mut()
        .find(|definition| {
            parse_pubkey(&definition.voting_public_key)
                .map(|parsed| parsed == *pubkey)
                .unwrap_or(false)
        })
        .ok_or_else(|| {
            ApiError::Internal(format!(
                "validator {} is loaded but has no entry in {}; the file was changed under a \
                 running client, so the change was not made",
                encode_hex(&pubkey.0),
                path.display()
            ))
        })?;
    entry.apply(change);
    definitions
        .save(&context.validators_dir)
        .map_err(|err| ApiError::Internal(format!("could not write {}: {err}", path.display())))?;

    context.settings.apply(pubkey, change);
    Ok(())
}

/// A decimal `u64` with no sign and no leading zero, the specification's
/// `Uint64` pattern. Stricter than `str::parse`, which takes a leading `+`.
fn parse_uint64(text: &str) -> Result<u64, ApiError> {
    let well_formed = !text.is_empty()
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    if !well_formed {
        return Err(ApiError::BadRequest(format!(
            "gas_limit {text:?} is not a decimal unsigned integer"
        )));
    }
    text.parse()
        .map_err(|_| ApiError::BadRequest(format!("gas_limit {text} does not fit in 64 bits")))
}

pub async fn get_fee_recipient(
    State(context): State<KeymanagerContext>,
    Path(pubkey): Path<String>,
) -> Result<Json<Data<FeeRecipientEntry>>, ApiError> {
    let pubkey = parse_path_key(&pubkey)?;
    require_held(&*context.store.read().await, &pubkey)?;
    // No address at all, neither the validator's own nor a default, is a
    // configuration the specification does not describe. Answered as
    // Lighthouse answers it, since the zero address would read as a real
    // answer and this client never sends one to the beacon node.
    let Some(address) = context.settings.fee_recipient(&pubkey) else {
        return Err(ApiError::Internal(
            "no fee recipient is set for this validator and there is no \
             --suggested-fee-recipient default"
                .to_string(),
        ));
    };
    Ok(Json(Data {
        data: FeeRecipientEntry {
            pubkey: encode_hex(&pubkey.0),
            ethaddress: encode_hex(&address.0),
        },
    }))
}

pub async fn set_fee_recipient(
    State(context): State<KeymanagerContext>,
    Path(pubkey): Path<String>,
    body: Result<Json<SetFeeRecipientRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let pubkey = parse_path_key(&pubkey)?;
    let Json(request) = body?;
    let address = fee_recipient_from_text(&request.ethaddress)
        .map_err(|why| ApiError::BadRequest(format!("ethaddress {why}")))?;

    persist_and_apply(
        &context,
        &pubkey,
        SettingChange::FeeRecipient(Some(address)),
    )
    .await?;

    info!(
        pubkey = %encode_hex(&pubkey.0),
        fee_recipient = %encode_hex(&address.0),
        "Fee recipient set; registered with the beacon node at the next epoch"
    );
    Ok(StatusCode::ACCEPTED)
}

pub async fn delete_fee_recipient(
    State(context): State<KeymanagerContext>,
    Path(pubkey): Path<String>,
) -> Result<StatusCode, ApiError> {
    let pubkey = parse_path_key(&pubkey)?;
    persist_and_apply(&context, &pubkey, SettingChange::FeeRecipient(None)).await?;

    info!(pubkey = %encode_hex(&pubkey.0), "Fee recipient reset to the default");
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_graffiti(
    State(context): State<KeymanagerContext>,
    Path(pubkey): Path<String>,
) -> Result<Json<Data<GraffitiEntry>>, ApiError> {
    let pubkey = parse_path_key(&pubkey)?;
    require_held(&*context.store.read().await, &pubkey)?;
    let graffiti = context.settings.graffiti(&pubkey);
    Ok(Json(Data {
        data: GraffitiEntry {
            pubkey: encode_hex(&pubkey.0),
            graffiti: graffiti_to_text(&graffiti),
        },
    }))
}

pub async fn set_graffiti(
    State(context): State<KeymanagerContext>,
    Path(pubkey): Path<String>,
    body: Result<Json<SetGraffitiRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let pubkey = parse_path_key(&pubkey)?;
    let Json(request) = body?;
    let Some(graffiti) = graffiti_from_text(&request.graffiti) else {
        return Err(ApiError::BadRequest(format!(
            "graffiti is {} bytes encoded as UTF-8; the field holds {GRAFFITI_BYTES}",
            request.graffiti.len()
        )));
    };

    persist_and_apply(&context, &pubkey, SettingChange::Graffiti(Some(graffiti))).await?;

    info!(pubkey = %encode_hex(&pubkey.0), graffiti = ?request.graffiti, "Graffiti set");
    Ok(StatusCode::ACCEPTED)
}

pub async fn delete_graffiti(
    State(context): State<KeymanagerContext>,
    Path(pubkey): Path<String>,
) -> Result<StatusCode, ApiError> {
    let pubkey = parse_path_key(&pubkey)?;
    persist_and_apply(&context, &pubkey, SettingChange::Graffiti(None)).await?;

    info!(pubkey = %encode_hex(&pubkey.0), "Graffiti reset to the default");
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_gas_limit(
    State(context): State<KeymanagerContext>,
    Path(pubkey): Path<String>,
) -> Result<Json<Data<GasLimitEntry>>, ApiError> {
    let pubkey = parse_path_key(&pubkey)?;
    require_held(&*context.store.read().await, &pubkey)?;
    let gas_limit = context.settings.gas_limit(&pubkey);
    Ok(Json(Data {
        data: GasLimitEntry {
            pubkey: encode_hex(&pubkey.0),
            gas_limit: gas_limit.to_string(),
        },
    }))
}

pub async fn set_gas_limit(
    State(context): State<KeymanagerContext>,
    Path(pubkey): Path<String>,
    body: Result<Json<SetGasLimitRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let pubkey = parse_path_key(&pubkey)?;
    let Json(request) = body?;
    let gas_limit = parse_uint64(&request.gas_limit)?;

    persist_and_apply(&context, &pubkey, SettingChange::GasLimit(Some(gas_limit))).await?;

    info!(pubkey = %encode_hex(&pubkey.0), gas_limit, "Gas limit set");
    Ok(StatusCode::ACCEPTED)
}

pub async fn delete_gas_limit(
    State(context): State<KeymanagerContext>,
    Path(pubkey): Path<String>,
) -> Result<StatusCode, ApiError> {
    let pubkey = parse_path_key(&pubkey)?;
    persist_and_apply(&context, &pubkey, SettingChange::GasLimit(None)).await?;

    info!(pubkey = %encode_hex(&pubkey.0), "Gas limit reset to the default");
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::Request;
    use ethlambda_types::beacon::primitives::{Bytes32, ExecutionAddress, H160};
    use http_body_util::BodyExt as _;
    use tokio::sync::RwLock;
    use tower::ServiceExt as _;

    use super::*;
    use crate::http_api::router;
    use crate::keys::ValidatorDefinition;
    use crate::proposer_settings::{ADDRESS_BYTES, DEFAULT_GAS_LIMIT, ProposerSettings};

    const TOKEN: &str = "test-token";

    struct Harness {
        app: axum::Router,
        settings: Arc<ProposerSettings>,
        pubkey: BlsPubkey,
        /// The validators directory, holding the definitions file the routes
        /// write through.
        dir: tempfile::TempDir,
    }

    impl Harness {
        /// The key's entry as the file holds it now.
        fn entry(&self) -> ValidatorDefinition {
            ValidatorDefinitions::open(self.dir.path())
                .expect("opens")
                .0
                .into_iter()
                .find(|entry| entry.voting_public_key == encode_hex(&self.pubkey.0))
                .expect("the key's entry")
        }
    }

    fn secret() -> [u8; 32] {
        hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
            .expect("valid hex")
            .try_into()
            .expect("32 bytes")
    }

    fn default_graffiti() -> Bytes32 {
        graffiti_from_text("default").expect("fits")
    }

    /// A router over a store holding one key, with a default graffiti of
    /// `default` and, when `fee_recipient` is `Some`, a default address. The
    /// definitions file names the key, as it would for any loaded key.
    fn harness(fee_recipient: Option<ExecutionAddress>) -> Harness {
        let harness = harness_without_definitions(fee_recipient);
        ValidatorDefinitions(vec![ValidatorDefinition {
            enabled: true,
            voting_public_key: encode_hex(&harness.pubkey.0),
            voting_keystore_path: harness.dir.path().join("voting-keystore.json"),
            voting_keystore_password_path: harness.dir.path().join("password"),
            suggested_fee_recipient: None,
            graffiti: None,
            gas_limit: None,
        }])
        .save(harness.dir.path())
        .expect("writes the definitions file");
        harness
    }

    /// [`harness`] with no definitions file at all: a key in memory the file
    /// does not describe.
    fn harness_without_definitions(fee_recipient: Option<ExecutionAddress>) -> Harness {
        let mut store = ValidatorStore::new();
        let pubkey = store.insert_secret("test", &secret()).expect("inserts");
        let settings = Arc::new(ProposerSettings::new(default_graffiti(), fee_recipient));
        let dir = tempfile::tempdir().expect("temp dir");
        let context = KeymanagerContext {
            store: Arc::new(RwLock::new(store)),
            settings: settings.clone(),
            validators_dir: dir.path().to_path_buf(),
            secrets_dir: dir.path().to_path_buf(),
            definitions_lock: Arc::new(tokio::sync::Mutex::new(())),
        };
        Harness {
            app: router(context, TOKEN.to_string()),
            settings,
            pubkey,
            dir,
        }
    }

    fn default_address() -> ExecutionAddress {
        H160([0xaa; ADDRESS_BYTES])
    }

    fn uri(pubkey: &BlsPubkey, setting: &str) -> String {
        format!("/eth/v1/validator/{}/{setting}", encode_hex(&pubkey.0))
    }

    fn request(method: &str, uri: &str, body: Option<serde_json::Value>) -> Request<Body> {
        let builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {TOKEN}"));
        match body {
            Some(body) => builder
                .header("content-type", "application/json")
                .body(Body::from(body.to_string())),
            None => builder.body(Body::empty()),
        }
        .expect("request")
    }

    async fn send(app: &axum::Router, request: Request<Body>) -> (StatusCode, serde_json::Value) {
        let response = app.clone().oneshot(request).await.expect("responds");
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

    /// The blanket bearer layer covers these routes too.
    #[tokio::test]
    async fn a_settings_route_without_the_token_is_rejected() {
        let harness = harness(None);
        let request = Request::builder()
            .uri(uri(&harness.pubkey, "graffiti"))
            .body(Body::empty())
            .expect("request");
        let (status, _) = send(&harness.app, request).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_fee_recipient_is_set_read_back_and_reset_to_the_default() {
        let harness = harness(Some(default_address()));
        let path = uri(&harness.pubkey, "feerecipient");
        let default = encode_hex(&default_address().0);
        let own = format!("0x{}", "bb".repeat(ADDRESS_BYTES));

        let (status, body) = send(&harness.app, request("GET", &path, None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["ethaddress"], default);
        assert_eq!(body["data"]["pubkey"], encode_hex(&harness.pubkey.0));

        let set = serde_json::json!({ "ethaddress": own });
        let (status, _) = send(&harness.app, request("POST", &path, Some(set))).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let (_, body) = send(&harness.app, request("GET", &path, None)).await;
        assert_eq!(body["data"]["ethaddress"], own);
        assert_eq!(
            harness.settings.fee_recipient(&harness.pubkey),
            Some(H160([0xbb; ADDRESS_BYTES]))
        );

        let (status, _) = send(&harness.app, request("DELETE", &path, None)).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, body) = send(&harness.app, request("GET", &path, None)).await;
        assert_eq!(body["data"]["ethaddress"], default);
    }

    #[tokio::test]
    async fn the_zero_address_is_refused() {
        let harness = harness(None);
        let path = uri(&harness.pubkey, "feerecipient");
        let zero = format!("0x{}", "00".repeat(ADDRESS_BYTES));
        let set = serde_json::json!({ "ethaddress": zero });
        let (status, body) = send(&harness.app, request("POST", &path, Some(set))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["message"].is_string(), "got {body}");
        assert_eq!(harness.settings.fee_recipient(&harness.pubkey), None);
    }

    #[tokio::test]
    async fn a_malformed_address_is_refused() {
        let harness = harness(None);
        let path = uri(&harness.pubkey, "feerecipient");
        for address in [
            "bb".repeat(ADDRESS_BYTES),
            format!("0x{}", "bb".repeat(ADDRESS_BYTES - 1)),
            format!("0x{}", "zz".repeat(ADDRESS_BYTES)),
        ] {
            let set = serde_json::json!({ "ethaddress": address });
            let (status, _) = send(&harness.app, request("POST", &path, Some(set))).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{address}");
        }
    }

    /// No address anywhere is answered as Lighthouse answers it, rather than
    /// with the zero address, which would read as a real one.
    #[tokio::test]
    async fn no_fee_recipient_at_all_is_an_error_not_the_zero_address() {
        let harness = harness(None);
        let path = uri(&harness.pubkey, "feerecipient");
        let (status, body) = send(&harness.app, request("GET", &path, None)).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body["message"].is_string(), "got {body}");
    }

    #[tokio::test]
    async fn graffiti_is_set_read_back_and_reset_to_the_default() {
        let harness = harness(None);
        let path = uri(&harness.pubkey, "graffiti");

        let (status, body) = send(&harness.app, request("GET", &path, None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["graffiti"], "default");

        let set = serde_json::json!({ "graffiti": "hello" });
        let (status, _) = send(&harness.app, request("POST", &path, Some(set))).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let (_, body) = send(&harness.app, request("GET", &path, None)).await;
        assert_eq!(body["data"]["graffiti"], "hello");

        let (status, _) = send(&harness.app, request("DELETE", &path, None)).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, body) = send(&harness.app, request("GET", &path, None)).await;
        assert_eq!(body["data"]["graffiti"], "default");
    }

    /// Refused rather than truncated, as the command-line flag is.
    #[tokio::test]
    async fn graffiti_longer_than_the_field_is_refused() {
        let harness = harness(None);
        let path = uri(&harness.pubkey, "graffiti");
        let set = serde_json::json!({ "graffiti": "a".repeat(GRAFFITI_BYTES + 1) });
        let (status, _) = send(&harness.app, request("POST", &path, Some(set))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            harness.settings.graffiti(&harness.pubkey),
            default_graffiti()
        );
    }

    #[tokio::test]
    async fn a_gas_limit_is_set_read_back_and_reset_to_the_default() {
        let harness = harness(None);
        let path = uri(&harness.pubkey, "gas_limit");

        let (status, body) = send(&harness.app, request("GET", &path, None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["gas_limit"], DEFAULT_GAS_LIMIT.to_string());

        let set = serde_json::json!({ "gas_limit": "30000000" });
        let (status, _) = send(&harness.app, request("POST", &path, Some(set))).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let (_, body) = send(&harness.app, request("GET", &path, None)).await;
        assert_eq!(body["data"]["gas_limit"], "30000000");

        let (status, _) = send(&harness.app, request("DELETE", &path, None)).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, body) = send(&harness.app, request("GET", &path, None)).await;
        assert_eq!(body["data"]["gas_limit"], DEFAULT_GAS_LIMIT.to_string());
    }

    /// The specification's `Uint64` is a decimal string with no sign and no
    /// leading zero; a JSON number is not one.
    #[tokio::test]
    async fn a_gas_limit_that_is_not_a_uint64_string_is_refused() {
        let harness = harness(None);
        let path = uri(&harness.pubkey, "gas_limit");
        for gas_limit in [
            serde_json::json!("+30000000"),
            serde_json::json!("030000000"),
            serde_json::json!("-1"),
            serde_json::json!(""),
            serde_json::json!("18446744073709551616"),
            serde_json::json!(30000000),
        ] {
            let set = serde_json::json!({ "gas_limit": gas_limit });
            let (status, _) = send(&harness.app, request("POST", &path, Some(set))).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{gas_limit}");
        }
        assert_eq!(
            harness.settings.gas_limit(&harness.pubkey),
            DEFAULT_GAS_LIMIT
        );
    }

    #[tokio::test]
    async fn a_key_this_client_does_not_hold_is_not_found() {
        let harness = harness(Some(default_address()));
        let stranger = BlsPubkey([9; 48]);
        for setting in ["feerecipient", "graffiti", "gas_limit"] {
            let path = uri(&stranger, setting);
            let (status, _) = send(&harness.app, request("GET", &path, None)).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "GET {setting}");
            let (status, _) = send(&harness.app, request("DELETE", &path, None)).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "DELETE {setting}");
        }
        let set = serde_json::json!({ "graffiti": "hello" });
        let path = uri(&stranger, "graffiti");
        let (status, _) = send(&harness.app, request("POST", &path, Some(set))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            harness.settings.graffiti(&stranger),
            default_graffiti(),
            "a refused key must not get an override"
        );
    }

    #[tokio::test]
    async fn a_malformed_pubkey_is_a_bad_request() {
        let harness = harness(None);
        let path = "/eth/v1/validator/0x1234/graffiti";
        let (status, _) = send(&harness.app, request("GET", path, None)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// A body of the wrong shape is a 400, as every route here declares,
    /// rather than axum's own 422.
    #[tokio::test]
    async fn a_body_of_the_wrong_shape_is_a_bad_request() {
        let harness = harness(None);
        let path = uri(&harness.pubkey, "graffiti");
        let set = serde_json::json!({ "not_graffiti": "hello" });
        let (status, body) = send(&harness.app, request("POST", &path, Some(set))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["message"].is_string(), "got {body}");
    }

    /// Every change lands on the key's entry in the definitions file before
    /// it is answered, and a delete takes the field out again.
    #[tokio::test]
    async fn a_change_is_written_to_the_definitions_file_and_a_delete_removes_it() {
        let harness = harness(Some(default_address()));
        let own = format!("0x{}", "bb".repeat(ADDRESS_BYTES));

        let set = serde_json::json!({ "ethaddress": own });
        let path = uri(&harness.pubkey, "feerecipient");
        let (status, _) = send(&harness.app, request("POST", &path, Some(set))).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(
            harness.entry().suggested_fee_recipient.as_deref(),
            Some(own.as_str())
        );

        let set = serde_json::json!({ "graffiti": "hello" });
        let path = uri(&harness.pubkey, "graffiti");
        send(&harness.app, request("POST", &path, Some(set))).await;
        assert_eq!(harness.entry().graffiti.as_deref(), Some("hello"));

        let set = serde_json::json!({ "gas_limit": "30000000" });
        let path = uri(&harness.pubkey, "gas_limit");
        send(&harness.app, request("POST", &path, Some(set))).await;
        assert_eq!(harness.entry().gas_limit, Some(30_000_000));

        for setting in ["feerecipient", "graffiti", "gas_limit"] {
            let request = request("DELETE", &uri(&harness.pubkey, setting), None);
            let (status, _) = send(&harness.app, request).await;
            assert_eq!(status, StatusCode::NO_CONTENT, "DELETE {setting}");
        }
        let entry = harness.entry();
        assert_eq!(entry.suggested_fee_recipient, None);
        assert_eq!(entry.graffiti, None);
        assert_eq!(entry.gas_limit, None);
    }

    /// What a restart does with the file: the overrides a previous run
    /// persisted are the ones the next run proposes with.
    #[tokio::test]
    async fn persisted_overrides_survive_a_restart() {
        let harness = harness(Some(default_address()));
        let own = format!("0x{}", "bb".repeat(ADDRESS_BYTES));
        let set = serde_json::json!({ "ethaddress": own });
        let path = uri(&harness.pubkey, "feerecipient");
        send(&harness.app, request("POST", &path, Some(set))).await;
        let set = serde_json::json!({ "graffiti": "persisted" });
        let path = uri(&harness.pubkey, "graffiti");
        send(&harness.app, request("POST", &path, Some(set))).await;

        // A fresh `ProposerSettings`, as a restart builds, seeded as startup
        // seeds it.
        let restarted = ProposerSettings::new(default_graffiti(), Some(default_address()));
        let seeded = ValidatorDefinitions::open(harness.dir.path())
            .expect("opens")
            .seed_overrides(&restarted)
            .expect("seeds");
        assert_eq!(seeded, 1);
        assert_eq!(
            restarted.fee_recipient(&harness.pubkey),
            Some(H160([0xbb; ADDRESS_BYTES]))
        );
        assert_eq!(
            restarted.graffiti(&harness.pubkey),
            graffiti_from_text("persisted").expect("fits")
        );
        assert_eq!(restarted.gas_limit(&harness.pubkey), DEFAULT_GAS_LIMIT);
    }

    /// A loaded key the file does not describe means the file was changed
    /// under the client. The change is refused rather than kept in memory
    /// alone, where the operator would believe it persisted.
    #[tokio::test]
    async fn a_key_missing_from_the_definitions_file_is_a_500_and_memory_is_unchanged() {
        let harness = harness_without_definitions(None);
        let set = serde_json::json!({ "graffiti": "hello" });
        let path = uri(&harness.pubkey, "graffiti");
        let (status, body) = send(&harness.app, request("POST", &path, Some(set))).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            body["message"]
                .as_str()
                .is_some_and(|message| message.contains("validator_definitions.yml")),
            "got {body}"
        );
        assert_eq!(
            harness.settings.graffiti(&harness.pubkey),
            default_graffiti(),
            "a change that was not persisted must not take effect"
        );
        let (status, _) = send(&harness.app, request("DELETE", &path, None)).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// A file that cannot be written is a 500 that changes nothing.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_file_that_cannot_be_written_is_a_500_and_memory_is_unchanged() {
        use std::os::unix::fs::PermissionsExt as _;

        let harness = harness(None);
        // Saving writes a sibling temporary file, which a read-only directory
        // refuses. Root is exempt from permission bits, so the test is moot
        // there rather than wrong.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        std::fs::set_permissions(harness.dir.path(), std::fs::Permissions::from_mode(0o500))
            .expect("chmod");

        let set = serde_json::json!({ "graffiti": "hello" });
        let path = uri(&harness.pubkey, "graffiti");
        let (status, _) = send(&harness.app, request("POST", &path, Some(set))).await;
        std::fs::set_permissions(harness.dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod back, so the directory can be removed");
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            harness.settings.graffiti(&harness.pubkey),
            default_graffiti()
        );
        assert_eq!(harness.entry().graffiti, None, "the file is unchanged too");
    }

    /// A deleted key's overrides go with it, so the same key imported again
    /// starts on the defaults.
    #[tokio::test]
    async fn deleting_a_keystore_forgets_its_overrides() {
        let harness = harness(Some(default_address()));
        let own_address = H160([0xbb; ADDRESS_BYTES]);
        harness
            .settings
            .set_graffiti(&harness.pubkey, Bytes32::repeat_byte(b'x'));
        harness
            .settings
            .set_fee_recipient(&harness.pubkey, own_address);

        let delete = serde_json::json!({ "pubkeys": [encode_hex(&harness.pubkey.0)] });
        let request = request("DELETE", "/eth/v1/keystores", Some(delete));
        let (status, body) = send(&harness.app, request).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"][0]["status"], "deleted", "got {body}");

        assert_eq!(
            harness.settings.graffiti(&harness.pubkey),
            default_graffiti()
        );
        assert_eq!(
            harness.settings.fee_recipient(&harness.pubkey),
            Some(default_address())
        );
    }
}
