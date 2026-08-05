//! End-to-end wire smoke test.
//!
//! Spawns a minimal HTTP/1.1 server on a random localhost port, has the
//! `EngineClient` call `engine_forkchoiceUpdatedV3` against it, and
//! verifies:
//!  - the request body shape (jsonrpc envelope + camelCase params),
//!  - the `Authorization: Bearer <jwt>` header is present,
//!  - the typed `ForkChoiceUpdatedResponse` parses correctly from the
//!    `SYNCING` canned reply.
//!
//! No external mock server crate; just `tokio::net::TcpListener` and a
//! hand-rolled HTTP/1.1 response.

use std::sync::Arc;
use std::sync::Mutex;

use ethlambda_ethrex_client::{EngineClient, ForkChoiceState, JwtSecret, PayloadStatusKind};
use ethlambda_types::primitives::H256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const JWT_HEX: &str = "0x0102030405060708091011121314151617181920212223242526272829303132";

#[tokio::test]
async fn forkchoice_updated_v3_round_trip() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");

    let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let captured_for_server = captured.clone();

    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        // Read until we have headers + body (request is small).
        let mut buf = vec![0u8; 8192];
        let n = sock.read(&mut buf).await.unwrap();
        let raw = String::from_utf8_lossy(&buf[..n]).into_owned();
        *captured_for_server.lock().unwrap() = Some(raw);

        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"payloadStatus":{"status":"SYNCING","latestValidHash":null,"validationError":null},"payloadId":null}}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        sock.write_all(resp.as_bytes()).await.unwrap();
        sock.shutdown().await.unwrap();
    });

    let secret = JwtSecret::from_hex(JWT_HEX).unwrap();
    let client = EngineClient::new(&url, secret).unwrap();

    let state = ForkChoiceState {
        head_block_hash: H256([0xaa; 32]),
        safe_block_hash: H256([0xbb; 32]),
        finalized_block_hash: H256([0xcc; 32]),
    };
    let resp = client
        .forkchoice_updated_v3(state, None)
        .await
        .expect("FCU should succeed against mock");
    assert_eq!(resp.payload_status.status, PayloadStatusKind::Syncing);
    assert!(resp.payload_id.is_none());

    let raw_req = captured.lock().unwrap().clone().expect("request captured");
    let lower = raw_req.to_lowercase();
    assert!(
        lower.contains("authorization: bearer "),
        "missing JWT header in:\n{raw_req}"
    );
    assert!(
        raw_req.contains(r#""method":"engine_forkchoiceUpdatedV3""#),
        "wrong method name in body: {raw_req}"
    );
    assert!(raw_req.contains("headBlockHash"), "params not camelCase");
    assert!(
        raw_req.contains("0xaaaaaa"),
        "head hash not encoded in body"
    );
}

#[tokio::test]
async fn rpc_error_surfaces_typed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");

    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 8192];
        let _ = sock.read(&mut buf).await.unwrap();
        let body = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32700,"message":"parse error"}}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        sock.write_all(resp.as_bytes()).await.unwrap();
        sock.shutdown().await.unwrap();
    });

    let secret = JwtSecret::from_hex(JWT_HEX).unwrap();
    let client = EngineClient::new(&url, secret).unwrap();
    let err = client
        .exchange_capabilities(&["engine_forkchoiceUpdatedV3"])
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("-32700"), "expected RPC code in error: {msg}");
    assert!(
        msg.contains("parse error"),
        "expected RPC message in error: {msg}"
    );
}
