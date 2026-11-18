//! `POST /eth/v1/validator/{pubkey}/voluntary_exit`.
//!
//! Signs a voluntary exit for one validator this client holds and answers
//! with the `SignedVoluntaryExit`. It does **not** publish it: the keymanager
//! specification leaves that to the caller, who hands the message to a beacon
//! node's `POST /eth/v1/beacon/pool/voluntary_exits`. That split is what lets
//! an operator pre-sign an exit for a later epoch and hold on to it.
//!
//! The exit epoch is the `epoch` query parameter, or the current epoch by the
//! client's own clock when none is given. Whatever epoch it names, the exit is
//! signed for the fork that will process it (see
//! [`crate::signing::SigningContext::voluntary_exit_signing_root`]), so
//! `?epoch=0` on a chain past deneb is as valid as the current epoch.
//!
//! The validator index is asked of the beacon node on every call rather than
//! cached: a key whose deposit has not been processed has no index yet, and a
//! 404 saying so is the honest answer until it does.
//!
//! Every route answers 404 for a key this client does not hold, as the
//! settings routes do.

use axum::Json;
use axum::extract::{Path, Query, State};
use ethlambda_types::beacon::constants::GENESIS_EPOCH;
use ethlambda_types::beacon::containers::shared::{SignedVoluntaryExit, VoluntaryExit};
use serde::Deserialize;
use tracing::info;

use crate::beacon_node::dto::encode_hex;
use crate::http_api::KeymanagerContext;
use crate::http_api::proposer::{ApiError, Data, parse_path_key, parse_uint64, require_held};

#[derive(Debug, Deserialize)]
pub struct VoluntaryExitQuery {
    /// The specification's `Uint64`: a decimal string, which [`parse_uint64`]
    /// checks the shape of. Read as text so a malformed value is this
    /// module's 400 rather than axum's own rejection.
    pub epoch: Option<String>,
}

pub async fn create_signed_voluntary_exit(
    State(context): State<KeymanagerContext>,
    Path(pubkey): Path<String>,
    Query(query): Query<VoluntaryExitQuery>,
) -> Result<Json<Data<SignedVoluntaryExit>>, ApiError> {
    let pubkey = parse_path_key(&pubkey)?;
    let current_epoch = context.clock.now().map(|slot| context.clock.epoch_of(slot));
    let epoch = match &query.epoch {
        Some(text) => parse_uint64("epoch", text)?,
        None => current_epoch.ok_or_else(|| {
            ApiError::Internal("the chain's genesis is in the future".to_string())
        })?,
    };
    // The domain follows the fork that will process the exit, which is the
    // chain's present one for an exit naming a past epoch. Before genesis
    // the chain's first state is the earliest that can.
    let current_epoch = current_epoch.unwrap_or(GENESIS_EPOCH);

    // The key is checked before the beacon node is asked, so a key this
    // client does not hold costs no round trip and is answered the same way
    // whether or not a node is reachable.
    require_held(&*context.store.read().await, &pubkey)?;

    // The same lookup the `voluntary-exit` command makes, so the two ways to
    // sign an exit cannot disagree about a validator's index. Here it goes
    // through the client's failover list, where the first node to answer is
    // final, a 404 included: see `FallbackBeaconNode::validator`.
    let entry = context
        .beacon_node
        .validator(&pubkey)
        .await
        .map_err(|err| {
            ApiError::Internal(format!("could not resolve the validator index: {err}"))
        })?;
    let Some(entry) = entry else {
        return Err(ApiError::NotFound(format!(
            "the validator index for {} is not known yet; the beacon node has no \
             validator with that key, so its deposit may not have been processed",
            encode_hex(&pubkey.0)
        )));
    };

    let exit = VoluntaryExit {
        epoch,
        validator_index: entry.index,
    };
    // No guard on the store is held here or across the round trip to the
    // beacon node above: the signing path takes its own for the lookup alone,
    // since for a key in a remote signer the signature is a round trip too.
    // So a delete can land between the check above and here. Signing then
    // finds no key, which is the same 404 the check gives.
    let signature = context
        .signing
        .sign_voluntary_exit(&context.store, &pubkey, &exit, current_epoch)
        .await
        .map_err(|err| match err {
            crate::Error::UnknownValidator(_) => ApiError::NotFound(format!(
                "no validator with pubkey {} is held by this client",
                encode_hex(&pubkey.0)
            )),
            other => ApiError::Internal(format!("signing failed: {other}")),
        })?;

    info!(
        pubkey = %encode_hex(&pubkey.0),
        validator_index = exit.validator_index,
        epoch,
        "Signed a voluntary exit; it is not published until the caller submits it"
    );
    Ok(Json(Data {
        data: SignedVoluntaryExit {
            message: exit,
            signature,
        },
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::constants::FAR_FUTURE_EPOCH;
    use ethlambda_types::beacon::primitives::{BlsPubkey, BlsSignature, Bytes32, Root};
    use http_body_util::BodyExt as _;
    use tokio::sync::RwLock;
    use tower::ServiceExt as _;

    use super::*;
    use crate::beacon_node::ValidatorDetails;
    use crate::beacon_node::mock::MockBeaconNode;
    use crate::http_api::router;
    use crate::keys::ValidatorStore;
    use crate::proposer_settings::ProposerSettings;
    use crate::signing::SigningContext;
    use crate::slot_clock::SlotClock;

    const TOKEN: &str = "test-token";
    const INDEX: u64 = 1234;

    fn secret() -> [u8; 32] {
        hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
            .expect("valid hex")
            .try_into()
            .expect("32 bytes")
    }

    struct Harness {
        app: axum::Router,
        pubkey: BlsPubkey,
        signing: Arc<SigningContext>,
        clock: SlotClock,
        _dir: tempfile::TempDir,
    }

    /// A router over a store holding one key, a beacon node that resolves it
    /// to `INDEX` when `resolves` is set, and a clock a few epochs past
    /// genesis.
    fn harness(resolves: bool) -> Harness {
        harness_at(10, resolves)
    }

    /// [`harness`] with the clock `epochs` epochs past genesis.
    fn harness_at(epochs: u64, resolves: bool) -> Harness {
        let mut store = ValidatorStore::new();
        let pubkey = store.insert_secret("test", &secret()).expect("inserts");
        let node = MockBeaconNode::new();
        if resolves {
            node.set_validator_details(Some(ValidatorDetails {
                index: INDEX,
                status: "active_ongoing".to_string(),
                activation_epoch: 0,
                exit_epoch: FAR_FUTURE_EPOCH,
                withdrawable_epoch: FAR_FUTURE_EPOCH,
            }));
        }
        let config = Config::mainnet();
        let genesis_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_secs()
            - epochs * 32 * 12;
        let clock = SlotClock::from_config(genesis_time, &config);
        let signing = Arc::new(SigningContext::new(config, Root::repeat_byte(3)));
        let dir = tempfile::tempdir().expect("temp dir");
        let context = KeymanagerContext {
            store: Arc::new(RwLock::new(store)),
            settings: Arc::new(ProposerSettings::new(Bytes32::ZERO, None)),
            validators_dir: dir.path().to_path_buf(),
            secrets_dir: dir.path().to_path_buf(),
            definitions_lock: Arc::new(tokio::sync::Mutex::new(())),
            definitions_unflushed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            protection: crate::slashing_protection::SlashingProtection::in_memory(),
            default_remote_signer: None,
            beacon_node: Arc::new(node),
            signing: signing.clone(),
            clock: clock.clone(),
        };
        Harness {
            app: router(context, TOKEN.to_string()),
            pubkey,
            signing,
            clock,
            _dir: dir,
        }
    }

    fn uri(pubkey: &BlsPubkey, query: &str) -> String {
        format!(
            "/eth/v1/validator/{}/voluntary_exit{query}",
            encode_hex(&pubkey.0)
        )
    }

    fn post(uri: &str, token: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().method("POST").uri(uri);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        builder.body(Body::empty()).expect("request")
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

    fn verify(pubkey: &BlsPubkey, signature: &BlsSignature, root: Root) -> bool {
        use blst::min_pk::{PublicKey, Signature};
        const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

        let pk = PublicKey::from_bytes(&pubkey.0).expect("valid pubkey");
        let sig = Signature::from_bytes(&signature.0).expect("valid signature");
        sig.verify(true, root.as_slice(), DST, &[], &pk, true) == blst::BLST_ERROR::BLST_SUCCESS
    }

    #[tokio::test]
    async fn a_signed_exit_for_the_current_epoch_is_returned_and_verifies() {
        let harness = harness(true);
        let (status, body) = send(&harness.app, post(&uri(&harness.pubkey, ""), Some(TOKEN))).await;
        assert_eq!(status, StatusCode::OK, "got {body}");

        let signed: SignedVoluntaryExit =
            serde_json::from_value(body["data"].clone()).expect("a SignedVoluntaryExit");
        let now = harness
            .clock
            .epoch_of(harness.clock.now().expect("after genesis"));
        assert_eq!(signed.message.epoch, now);
        assert_eq!(signed.message.validator_index, INDEX);
        assert!(verify(
            &harness.pubkey,
            &signed.signature,
            harness
                .signing
                .voluntary_exit_signing_root(&signed.message, now)
        ));
        // The wire form quotes its integers, as every Beacon API container does.
        assert!(body["data"]["message"]["epoch"].is_string(), "got {body}");
        assert!(
            body["data"]["message"]["validator_index"].is_string(),
            "got {body}"
        );
    }

    #[tokio::test]
    async fn the_epoch_query_parameter_is_honoured() {
        let harness = harness(true);
        let request = post(&uri(&harness.pubkey, "?epoch=999999"), Some(TOKEN));
        let (status, body) = send(&harness.app, request).await;
        assert_eq!(status, StatusCode::OK, "got {body}");
        assert_eq!(body["data"]["message"]["epoch"], "999999");
    }

    /// An exit naming a past epoch is signed for the chain as it is now, not
    /// as it was then: here a chain past deneb, whose nodes verify every exit
    /// under the capella version, one naming epoch 0 included.
    #[tokio::test]
    async fn an_exit_naming_a_past_epoch_is_signed_for_the_chains_present_fork() {
        use ethlambda_types::beacon::constants::DOMAIN_VOLUNTARY_EXIT;
        use ethlambda_types::beacon::primitives::HashTreeRoot as _;
        use ethlambda_types::beacon::signing::{compute_domain, compute_signing_root};

        let harness = harness_at(Config::mainnet().electra_fork_epoch + 10, true);
        let request = post(&uri(&harness.pubkey, "?epoch=0"), Some(TOKEN));
        let (status, body) = send(&harness.app, request).await;
        assert_eq!(status, StatusCode::OK, "got {body}");

        let signed: SignedVoluntaryExit =
            serde_json::from_value(body["data"].clone()).expect("a SignedVoluntaryExit");
        assert_eq!(signed.message.epoch, 0);
        let capella = compute_domain(
            DOMAIN_VOLUNTARY_EXIT,
            harness.signing.config.capella_fork_version,
            harness.signing.genesis_validators_root,
        );
        assert!(verify(
            &harness.pubkey,
            &signed.signature,
            compute_signing_root(signed.message.hash_tree_root(), capella)
        ));
    }

    #[tokio::test]
    async fn a_malformed_epoch_is_a_bad_request() {
        let harness = harness(true);
        for epoch in ["abc", "-1", "+5", "05", ""] {
            let request = post(
                &uri(&harness.pubkey, &format!("?epoch={epoch}")),
                Some(TOKEN),
            );
            let (status, body) = send(&harness.app, request).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{epoch:?}: {body}");
        }
    }

    #[tokio::test]
    async fn a_key_this_client_does_not_hold_is_not_found() {
        let harness = harness(true);
        let stranger = BlsPubkey([9; 48]);
        let (status, _) = send(&harness.app, post(&uri(&stranger, ""), Some(TOKEN))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_key_with_no_index_yet_is_not_found() {
        let harness = harness(false);
        let (status, body) = send(&harness.app, post(&uri(&harness.pubkey, ""), Some(TOKEN))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(
            body["message"]
                .as_str()
                .is_some_and(|message| message.contains("not known yet")),
            "got {body}"
        );
    }

    #[tokio::test]
    async fn a_malformed_pubkey_is_a_bad_request() {
        let harness = harness(true);
        let request = post("/eth/v1/validator/0x1234/voluntary_exit", Some(TOKEN));
        let (status, _) = send(&harness.app, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// The blanket bearer layer covers this route too.
    #[tokio::test]
    async fn the_route_without_the_token_is_rejected() {
        let harness = harness(true);
        let (status, _) = send(&harness.app, post(&uri(&harness.pubkey, ""), None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}
