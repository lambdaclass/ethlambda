//! The execution JSON-RPC server: `eth_*`, `net_*` and `web3_*` for wallets and
//! tooling, answered by the embedded node.
//!
//! ethrex's own server (`bind_api`) builds a second RPC context of its own,
//! with its own sync manager and block executor, so it cannot share the one the
//! beacon node drives. This is the thin part of that server rebuilt over the
//! shared context: parse the JSON-RPC body, hand each request to ethrex's
//! public `map_http_requests`, and wrap the answer with its `rpc_response`.
//! Namespace gating lives in `map_http_requests` itself, which also refuses
//! every `engine_*` method on this port.
//!
//! Left out, compared with ethrex's server: WebSocket subscriptions and the
//! heap-profiling routes.

use std::net::SocketAddr;

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use ethrex_rpc::utils::RpcRequestId;
use ethrex_rpc::{
    RpcApiContext, RpcErr, RpcErrorMetadata, RpcRequestWrapper, map_http_requests, rpc_response,
};
use serde_json::Value;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

/// The most requests one batch may carry: ethrex's own cap, so a client sees
/// the same limit either way.
const MAX_BATCH_SIZE: usize = 1000;

/// Binds `addr` and serves the execution JSON-RPC API on it until `cancel`
/// fires.
///
/// The bind happens here, before the serve task is spawned, so a port that is
/// taken fails node startup with a clear error instead of dying in the
/// background.
pub(crate) async fn spawn(
    addr: SocketAddr,
    context: RpcApiContext,
    tracker: &tokio_util::task::TaskTracker,
    cancel: CancellationToken,
) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    let router = router(context);
    info!(%bound, "Execution JSON-RPC server listening");
    tracker.spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(cancel.cancelled_owned())
            .await
            .inspect_err(|err| error!(%err, "Execution JSON-RPC server failed"))
    });
    Ok(bound)
}

fn router(context: RpcApiContext) -> Router {
    Router::new().route("/", post(handle)).with_state(context)
}

async fn handle(State(context): State<RpcApiContext>, body: String) -> Json<Value> {
    let wrapper: RpcRequestWrapper = match serde_json::from_str(&body) {
        Ok(wrapper) => wrapper,
        Err(_) => {
            return Json(envelope(
                RpcRequestId::String(String::new()),
                Err(RpcErr::BadParams("Invalid request body".to_string())),
            ));
        }
    };

    match wrapper {
        RpcRequestWrapper::Single(request) => {
            let answer = map_http_requests(&request, context).await;
            Json(envelope(request.id, answer))
        }
        RpcRequestWrapper::Multiple(requests) => {
            if requests.is_empty() {
                return Json(null_id_error(RpcErr::InvalidRequest(
                    "empty batch is not a valid Request".to_string(),
                )));
            }
            if requests.len() > MAX_BATCH_SIZE {
                return Json(null_id_error(RpcErr::InvalidRequest(format!(
                    "batch too large: {} > {MAX_BATCH_SIZE}",
                    requests.len()
                ))));
            }
            let mut answers = Vec::with_capacity(requests.len());
            for request in requests {
                let answer = map_http_requests(&request, context.clone()).await;
                answers.push(envelope(request.id, answer));
            }
            Json(Value::Array(answers))
        }
    }
}

/// A JSON-RPC response object for one request.
fn envelope(id: RpcRequestId, answer: Result<Value, RpcErr>) -> Value {
    // `rpc_response` only fails to serialize its own envelope types, which hold
    // nothing that cannot be serialized.
    rpc_response(id, answer).expect("a JSON-RPC envelope always serializes")
}

/// An error object with a `null` id, for a batch refused as a whole.
fn null_id_error(err: RpcErr) -> Value {
    let metadata: RpcErrorMetadata = err.into();
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": Value::Null,
        "error": metadata,
    })
}
