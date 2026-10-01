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

#[tokio::test]
async fn new_payload_v5_sends_four_params_under_its_own_method() {
    use ethlambda_types::beacon::containers::{bellatrix, gloas};
    use ethlambda_types::beacon::preset;
    use ethlambda_types::beacon::primitives::{Bytes32, ExecutionAddress, Root, Uint256};

    let (endpoint, seen) = serve_once(
        r#"{"jsonrpc":"2.0","id":1,"result":{"status":"VALID","latestValidHash":"0x0505050505050505050505050505050505050505050505050505050505050505","validationError":null}}"#,
    )
    .await;

    let payload = gloas::ExecutionPayload {
        parent_hash: ExecutionBlockHash::ZERO,
        fee_recipient: ExecutionAddress::ZERO,
        state_root: Bytes32::ZERO,
        receipts_root: Bytes32::ZERO,
        logs_bloom: bellatrix::LogsBloom::try_from(vec![0u8; preset::BYTES_PER_LOGS_BLOOM])
            .expect("built at exactly BYTES_PER_LOGS_BLOOM"),
        prev_randao: Bytes32::ZERO,
        block_number: 1,
        gas_limit: 1,
        gas_used: 0,
        timestamp: 1,
        extra_data: Default::default(),
        base_fee_per_gas: Uint256::ZERO,
        block_hash: ExecutionBlockHash::repeat_byte(5),
        transactions: Default::default(),
        withdrawals: Default::default(),
        blob_gas_used: 0,
        excess_blob_gas: 0,
        // 0xc0 is the RLP of an empty list, the smallest BAL an execution
        // client accepts as well-formed.
        block_access_list: vec![0xc0u8].try_into().expect("fits"),
        slot_number: 77,
    };
    let status = client(endpoint)
        .new_payload_v5(
            &payload,
            &[Bytes32::repeat_byte(1)],
            Root::repeat_byte(2),
            &[vec![0x00, 0xaa]],
        )
        .await
        .expect("the mock answers");

    assert_eq!(status.status, PayloadStatusValue::Valid);

    let request = seen.lock().await.clone().expect("the mock saw a request");
    let (_, body) = request.split_once("\r\n\r\n").expect("a request body");
    let body: serde_json::Value = serde_json::from_str(body).expect("a JSON body");
    assert_eq!(body["method"], "engine_newPayloadV5");
    let params = body["params"].as_array().expect("an array of params");
    assert_eq!(params.len(), 4);
    assert_eq!(params[0]["slotNumber"], "0x4d");
    assert_eq!(params[0]["blockAccessList"], "0xc0");
    assert_eq!(params[1][0], format!("0x{}", "01".repeat(32)));
    assert_eq!(params[2], format!("0x{}", "02".repeat(32)));
    assert_eq!(params[3][0], "0x00aa");
}
