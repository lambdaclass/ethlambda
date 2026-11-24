//! The execution JSON-RPC server: `eth_*`, `net_*` and `web3_*` for wallets and
//! tooling, answered by the embedded node.
//!
//! ethrex's own server (`bind_api`) builds a second RPC context of its own,
//! with its own sync manager and block executor, so it cannot share the one the
//! beacon node drives. This is the thin part of that server rebuilt over the
//! shared context: parse the JSON-RPC body, refuse a batch through ethrex's own
//! `validate_batch`, hand each request to its public `map_http_requests`, and
//! wrap the answer with its `rpc_response`. Namespace gating lives in
//! `map_http_requests` itself, which also refuses every `engine_*` method on
//! this port.
//!
//! Left out, compared with ethrex's server: WebSocket subscriptions, the
//! heap-profiling routes, and its permissive CORS layer, so a page in a
//! browser (a dapp, a web wallet) cannot call this server. Allowing every
//! origin on a node's RPC port is a choice for the operator to make, not one to
//! inherit silently.
//!
//! Added: once shutdown begins, no request reaches the node. One arriving after
//! it (a body that finishes uploading late, say) is refused without dispatch,
//! and one still running is dropped, as it is when its client disconnects.
//! Graceful shutdown waits for open connections, but the store is flushed
//! without waiting for this server, so without this a stalled connection could
//! dispatch a request against a store that has already shut down.
//!
//! Kept: a server that fails stops the node, as ethrex's own does.

use std::net::SocketAddr;

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use ethrex_rpc::utils::{RpcRequest, RpcRequestId};
use ethrex_rpc::{
    RpcApiContext, RpcErr, RpcRequestWrapper, map_http_requests, rpc_response, validate_batch,
};
use serde_json::Value;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

/// Binds `addr` and serves the execution JSON-RPC API on it until `cancel`
/// fires, or cancels it on failing (see the module docs).
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
    let router = router(context, cancel.clone());
    info!(%bound, "Execution JSON-RPC server listening");
    tracker.spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(cancel.clone().cancelled_owned())
            .await
            .inspect_err(|err| {
                error!(%err, "Execution JSON-RPC server failed; stopping the node");
                cancel.cancel();
            })
    });
    Ok(bound)
}

/// What every request handler gets: the node's context, and the token whose
/// cancellation starts its shutdown.
#[derive(Clone)]
struct ServerState {
    context: RpcApiContext,
    shutdown: CancellationToken,
}

fn router(context: RpcApiContext, shutdown: CancellationToken) -> Router {
    let state = ServerState { context, shutdown };
    Router::new().route("/", post(handle)).with_state(state)
}

async fn handle(State(state): State<ServerState>, body: String) -> Json<Value> {
    let wrapper: RpcRequestWrapper = match serde_json::from_str(&body) {
        Ok(wrapper) => wrapper,
        Err(_) => {
            return Json(envelope(
                RpcRequestId::String(String::new()),
                Err(RpcErr::ServerError("Invalid request body".to_string())),
            ));
        }
    };

    // An empty batch, one past ethrex's size cap (which the wrapper stops
    // parsing at), or one asking for too many `eth_getProof` keys in total: the
    // same refusals, with the same errors, as ethrex's own server.
    if let Some(refusal) = validate_batch(&wrapper) {
        return Json(refusal);
    }

    match wrapper {
        RpcRequestWrapper::Single(request) => {
            let answer = dispatch(&request, &state).await;
            Json(envelope(request.id, answer))
        }
        RpcRequestWrapper::Multiple(requests) => {
            let mut answers = Vec::with_capacity(requests.len());
            for request in requests {
                let answer = dispatch(&request, &state).await;
                answers.push(envelope(request.id, answer));
            }
            Json(Value::Array(answers))
        }
    }
}

/// Answers one request, unless shutdown has begun: then the request is refused
/// without reaching the node, and a handler still running when it begins is
/// dropped (see the module docs).
async fn dispatch(request: &RpcRequest, state: &ServerState) -> Result<Value, RpcErr> {
    let refusal = || Err(RpcErr::ServerError("the node is shutting down".to_string()));
    if state.shutdown.is_cancelled() {
        return refusal();
    }
    let call = map_http_requests(request, state.context.clone());
    state
        .shutdown
        .run_until_cancelled(call)
        .await
        .unwrap_or_else(refusal)
}

/// A JSON-RPC response object for one request.
fn envelope(id: RpcRequestId, answer: Result<Value, RpcErr>) -> Value {
    // `rpc_response` only fails to serialize its own envelope types, which hold
    // nothing that cannot be serialized.
    rpc_response(id, answer).expect("a JSON-RPC envelope always serializes")
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use clap::Parser;

    use super::*;
    use crate::EthrexArgs;

    #[derive(Parser)]
    struct Harness {
        #[command(flatten)]
        ethrex: EthrexArgs,
    }

    /// The refusal itself, with no socket and no timing: a request is
    /// dispatched until the token is cancelled, and refused from then on.
    #[tokio::test(flavor = "multi_thread")]
    async fn dispatch_refuses_once_shutdown_has_begun() {
        let genesis =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/genesis-osaka.json");
        let genesis = genesis.to_str().expect("a UTF-8 fixture path");
        let argv = [
            "ethlambda",
            "--ethrex.datadir",
            "memory",
            "--ethrex.network",
            genesis,
            "--ethrex.syncmode",
            "full",
        ];
        let args = Harness::try_parse_from(argv).expect("valid flags").ethrex;
        let mut config = args
            .resolve(Path::new("unused"), "unused")
            .expect("the flags name every derived value");
        config.options.p2p_disabled = true;
        let node = crate::start(config)
            .await
            .expect("the embedded node starts");

        let state = ServerState {
            context: node.rpc_context(),
            shutdown: CancellationToken::new(),
        };
        let request: RpcRequest = serde_json::from_value(serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": [],
        }))
        .expect("a request");

        let answer = dispatch(&request, &state).await;
        assert!(answer.is_ok(), "dispatched before shutdown begins");

        state.shutdown.cancel();
        let refused = dispatch(&request, &state).await;
        assert!(
            matches!(
                &refused,
                Err(RpcErr::ServerError(message)) if message == "the node is shutting down"
            ),
            "refused once shutdown has begun"
        );

        node.shutdown().await.expect("the store flushes");
    }
}
