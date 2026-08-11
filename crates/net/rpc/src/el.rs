//! Execution-layer endpoints.
//!
//! Transaction submission into the embedded ethrex mempool. This is the only way
//! transactions can enter the system: the node links ethrex as a library and
//! deliberately does not depend on `ethrex-rpc`, so there is no `eth_sendRawTransaction`.
//!
//! Routed under `/lean/v0/admin/` because it is a node-operator affordance, not
//! part of the Lean consensus API — nothing in leanSpec describes it.

use axum::{
    Extension, Json, Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use ethlambda_ethrex_engine::EthrexEngine;
use ethlambda_storage::Store;
use ethlambda_types::primitives::H256;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::json_response;

pub(crate) fn routes() -> Router<Store> {
    Router::new().route("/lean/v0/admin/el/tx", post(post_transaction))
}

#[derive(Serialize)]
struct SubmitResponse {
    tx_hash: H256,
}

/// POST /lean/v0/admin/el/tx — submit an RLP-encoded transaction.
///
/// Body: `{"raw": "0x02f8..."}` (the `0x` prefix is optional). Returns
/// `{"tx_hash": "0x..."}` once the mempool has accepted it.
///
/// Acceptance means the transaction is a *candidate*, not that it is included:
/// it lands in a block when some proposer next fills one. Without execution-layer
/// gossip that means the next slot **this** node proposes, so a submitter that
/// wants prompt inclusion should submit to every node.
///
/// - 400 — no body, malformed JSON, missing/non-string `raw`, bad hex,
///   undecodable transaction, or a mempool rejection (bad nonce, insufficient
///   balance, wrong chain id, duplicate, unreplaceable). The mempool's own
///   message is passed through, since it is the useful part.
/// - 501 — this node has no execution layer (started without `--el-genesis`).
///   Deliberately not the 503 the aggregator endpoints use for a missing
///   controller: that suggests "retry later", whereas an execution layer is
///   configured at startup and will never appear.
///
/// `Option<Extension<_>>` keeps the extractor infallible, so a missing engine
/// yields a clean 501 rather than axum short-circuiting with a 500.
pub(crate) async fn post_transaction(
    engine: Option<Extension<Arc<EthrexEngine>>>,
    body: Option<Json<Value>>,
) -> Response {
    let Some(Extension(engine)) = engine else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "No execution layer on this node; start it with --el-genesis",
        )
            .into_response();
    };

    // `Option<Json<Value>>` distinguishes "no body / malformed JSON" from
    // "valid JSON of the wrong shape", matching the admin handlers.
    let Some(Json(payload)) = body else {
        return bad_request("Invalid or missing JSON body".into());
    };

    let Some(raw_value) = payload.get("raw") else {
        return bad_request("Missing 'raw' field in body".into());
    };

    let Some(raw_hex) = raw_value.as_str() else {
        return bad_request("'raw' must be a hex string".into());
    };

    let raw = match hex::decode(raw_hex.strip_prefix("0x").unwrap_or(raw_hex)) {
        Ok(raw) => raw,
        Err(err) => return bad_request(format!("'raw' is not valid hex: {err}")),
    };

    match engine.submit_raw_transaction(&raw).await {
        Ok(tx_hash) => {
            debug!(%tx_hash, bytes = raw.len(), "Transaction accepted into the EL mempool");
            json_response(SubmitResponse { tx_hash })
        }
        Err(err) => {
            warn!(%err, bytes = raw.len(), "Transaction rejected by the EL");
            bad_request(err.to_string())
        }
    }
}

fn bad_request(reason: String) -> Response {
    (StatusCode::BAD_REQUEST, reason).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// Same Cancun genesis the engine tests use, so the prefunded account and
    /// chain id line up with the transaction fixtures below.
    const GENESIS_PATH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../ethrex-engine/tests/fixtures/genesis.json"
    );

    /// A signed EIP-1559 transfer of 1 wei from the genesis-funded
    /// `0xf39f...2266` (nonce 0, chain id 3503995874084926). Checked in rather
    /// than signed here so this crate needs no secp256k1 dependency; regenerate
    /// with `ethlambda-ethrex-engine`'s ignored `regenerate_rpc_fixtures` test.
    const TX_NONCE_0: &str = include_str!("../tests/fixtures/signed_transfer_nonce_0.hex");

    async fn engine() -> Arc<EthrexEngine> {
        Arc::new(
            EthrexEngine::from_genesis_path(GENESIS_PATH)
                .await
                .expect("bootstrap engine"),
        )
    }

    fn router(engine: Option<Arc<EthrexEngine>>) -> Router {
        let mut router = Router::new().route("/lean/v0/admin/el/tx", post(post_transaction));
        if let Some(engine) = engine {
            router = router.layer(Extension(engine));
        }
        router
    }

    async fn submit(engine: Option<Arc<EthrexEngine>>, body: &str) -> Response {
        router(engine)
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/lean/v0/admin/el/tx")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn body_json(resp: Response) -> Value {
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    async fn body_text(resp: Response) -> String {
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8_lossy(&body).into_owned()
    }

    #[tokio::test]
    async fn accepts_a_signed_transaction_and_returns_its_hash() {
        let raw = TX_NONCE_0.trim();
        let resp = submit(Some(engine().await), &format!(r#"{{"raw": "{raw}"}}"#)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let tx_hash = body_json(resp).await["tx_hash"]
            .as_str()
            .expect("tx_hash is a string")
            .to_string();
        assert!(
            tx_hash.starts_with("0x") && tx_hash.len() == 66,
            "expected a 0x-prefixed 32-byte hash, got {tx_hash}"
        );
    }

    /// The `0x` prefix is conventional but optional, so both spellings work.
    #[tokio::test]
    async fn accepts_raw_hex_without_the_0x_prefix() {
        let raw = TX_NONCE_0.trim().trim_start_matches("0x");
        let resp = submit(Some(engine().await), &format!(r#"{{"raw": "{raw}"}}"#)).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Resubmitting is a no-op rather than an error: ethrex treats an
    /// already-pooled hash as accepted, which keeps a retrying client simple.
    #[tokio::test]
    async fn resubmitting_the_same_transaction_succeeds() {
        let engine = engine().await;
        let raw = TX_NONCE_0.trim();
        let body = format!(r#"{{"raw": "{raw}"}}"#);
        assert_eq!(
            submit(Some(engine.clone()), &body).await.status(),
            StatusCode::OK
        );
        assert_eq!(submit(Some(engine), &body).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn returns_501_without_an_execution_layer() {
        let raw = TX_NONCE_0.trim();
        let resp = submit(None, &format!(r#"{{"raw": "{raw}"}}"#)).await;
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        assert!(body_text(resp).await.contains("--el-genesis"));
    }

    #[tokio::test]
    async fn rejects_missing_raw_field() {
        let resp = submit(Some(engine().await), r#"{"other": "0x00"}"#).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(resp).await.contains("'raw'"));
    }

    #[tokio::test]
    async fn rejects_non_string_raw() {
        let resp = submit(Some(engine().await), r#"{"raw": 42}"#).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn rejects_malformed_json() {
        let resp = submit(Some(engine().await), "not json").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn rejects_invalid_hex() {
        let resp = submit(Some(engine().await), r#"{"raw": "0xzz"}"#).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(resp).await.contains("hex"));
    }

    /// Well-formed hex that is not a transaction: the decoder rejects it, and
    /// the client gets 400 rather than a 500 from an unwrap somewhere.
    #[tokio::test]
    async fn rejects_hex_that_is_not_a_transaction() {
        let resp = submit(Some(engine().await), r#"{"raw": "0xdeadbeef"}"#).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// A validly signed transaction from an account with no funds is rejected by
    /// the mempool, and its reason reaches the caller.
    #[tokio::test]
    async fn surfaces_the_mempool_rejection_reason() {
        let raw = include_str!("../tests/fixtures/signed_transfer_unfunded.hex").trim();
        let resp = submit(Some(engine().await), &format!(r#"{{"raw": "{raw}"}}"#)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let text = body_text(resp).await;
        assert!(
            text.to_lowercase().contains("balance"),
            "expected the mempool's balance complaint, got: {text}"
        );
    }
}
