//! End-to-end round trips against a hand-rolled mock execution client.
//!
//! A `TcpListener` on an ephemeral port rather than a mocking library: the thing
//! under test is the bytes on the wire, and a library that intercepts before
//! serialization would test the interception instead.
//!
//! These bind a socket. Under a sandbox that forbids it they fail with
//! `PermissionDenied`; they pass in a normal shell.

use std::sync::Arc;

use ethlambda_engine::types::{ForkchoiceStateV1, PayloadStatusValue};
use ethlambda_engine::{EngineClient, EngineError, JwtSecret};
use ethlambda_types::beacon::primitives::ExecutionBlockHash;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

/// Serves exactly one request, answering with `body`, and hands the caller the
/// request it saw.
async fn serve_once(body: &'static str) -> (String, Arc<Mutex<Option<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("an ephemeral loopback port");
    let addr = listener.local_addr().expect("the bound address");
    let seen = Arc::new(Mutex::new(None));
    let seen_writer = Arc::clone(&seen);

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("one connection");
        let mut buffer = vec![0u8; 64 * 1024];
        let read = socket.read(&mut buffer).await.expect("the request bytes");
        *seen_writer.lock().await = Some(String::from_utf8_lossy(&buffer[..read]).to_string());

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        socket
            .write_all(response.as_bytes())
            .await
            .expect("the response bytes");
        socket.flush().await.expect("flush");
    });

    (format!("http://{addr}"), seen)
}

fn client(endpoint: String) -> EngineClient {
    EngineClient::new(endpoint, JwtSecret::new([0x0f; 32])).expect("a client")
}

#[tokio::test]
async fn forkchoice_updated_sends_the_wire_shape_and_parses_syncing() {
    let (endpoint, seen) = serve_once(
        r#"{"jsonrpc":"2.0","id":1,"result":{"payloadStatus":{"status":"SYNCING","latestValidHash":null,"validationError":null},"payloadId":null}}"#,
    )
    .await;

    let state = ForkchoiceStateV1 {
        head_block_hash: ExecutionBlockHash::repeat_byte(1),
        safe_block_hash: ExecutionBlockHash::repeat_byte(2),
        finalized_block_hash: ExecutionBlockHash::repeat_byte(3),
    };
    let status = client(endpoint)
        .forkchoice_updated(&state)
        .await
        .expect("the mock answers");

    assert_eq!(status.status, PayloadStatusValue::Syncing);
    assert_eq!(status.latest_valid_hash, None);

    let request = seen.lock().await.clone().expect("the mock saw a request");
    assert!(request.contains("engine_forkchoiceUpdatedV3"));
    assert!(request.contains("headBlockHash"));
    assert!(request.contains("0x0101010101010101010101010101010101010101010101010101010101010101"));
    // A follower never asks for a build.
    assert!(request.contains("null"));
    // The JWT is present as a bearer token.
    assert!(request.to_lowercase().contains("authorization: bearer "));
}

#[tokio::test]
async fn an_invalid_verdict_carries_its_latest_valid_hash() {
    let (endpoint, _seen) = serve_once(
        r#"{"jsonrpc":"2.0","id":1,"result":{"payloadStatus":{"status":"INVALID","latestValidHash":"0x0404040404040404040404040404040404040404040404040404040404040404","validationError":"bad"},"payloadId":null}}"#,
    )
    .await;

    let state = ForkchoiceStateV1 {
        head_block_hash: ExecutionBlockHash::ZERO,
        safe_block_hash: ExecutionBlockHash::ZERO,
        finalized_block_hash: ExecutionBlockHash::ZERO,
    };
    let status = client(endpoint)
        .forkchoice_updated(&state)
        .await
        .expect("the mock answers");

    assert_eq!(status.status, PayloadStatusValue::Invalid);
    assert_eq!(
        status.latest_valid_hash,
        Some(ExecutionBlockHash::repeat_byte(4))
    );
    assert_eq!(status.validation_error.as_deref(), Some("bad"));
}

#[tokio::test]
async fn an_rpc_error_envelope_surfaces_typed_and_is_not_retried() {
    // The mock answers exactly once. A retried call would hang and time out
    // instead of returning promptly, so a fast typed error is itself the
    // assertion that `Rpc` short-circuits the ladder.
    let (endpoint, _seen) = serve_once(
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-38005,"message":"Unsupported fork"}}"#,
    )
    .await;

    let state = ForkchoiceStateV1 {
        head_block_hash: ExecutionBlockHash::ZERO,
        safe_block_hash: ExecutionBlockHash::ZERO,
        finalized_block_hash: ExecutionBlockHash::ZERO,
    };
    let err = client(endpoint)
        .forkchoice_updated(&state)
        .await
        .expect_err("the mock answered with an error envelope");

    match err {
        EngineError::Rpc { code, message } => {
            assert_eq!(code, -38005);
            assert_eq!(message, "Unsupported fork");
        }
        other => panic!("expected an Rpc error, got {other:?}"),
    }
}
