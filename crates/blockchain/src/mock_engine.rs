//! A mock execution client for the chain actor's tests: a hand-rolled JSON-RPC
//! server over a loopback socket, like `ethlambda-engine`'s wire smoke tests
//! but for many requests, answering by method name or by the payload hash a
//! request names.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ethlambda_engine::{EngineClient, JwtSecret};
use ethlambda_types::primitives::H256;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

/// What the mock execution client answers and has been asked.
#[derive(Default)]
pub(crate) struct MockState {
    /// The `payloadStatus` object `engine_newPayload*` answers with.
    pub(crate) new_payload: String,
    /// The `payloadStatus` object `engine_forkchoiceUpdated*` answers with.
    pub(crate) forkchoice: String,
    /// Answers to `engine_newPayload*` for a payload whose `blockHash` is the
    /// key, ahead of [`Self::new_payload`].
    pub(crate) new_payload_by_hash: HashMap<H256, String>,
    /// Answers to `engine_forkchoiceUpdated*` whose `headBlockHash` is the
    /// key, ahead of [`Self::forkchoice`].
    pub(crate) forkchoice_by_hash: HashMap<H256, String>,
    /// Request bodies, in arrival order.
    pub(crate) requests: Vec<String>,
}

impl MockState {
    fn answer(&self, body: &str) -> String {
        let named = |key: &str, hash: &H256| body.contains(&format!("\"{key}\":\"{hash:?}\""));
        if body.contains("engine_newPayload") {
            self.new_payload_by_hash
                .iter()
                .find(|(hash, _)| named("blockHash", hash))
                .map_or_else(|| self.new_payload.clone(), |(_, answer)| answer.clone())
        } else {
            self.forkchoice_by_hash
                .iter()
                .find(|(hash, _)| named("headBlockHash", hash))
                .map_or_else(|| self.forkchoice.clone(), |(_, answer)| answer.clone())
        }
    }
}

/// A `payloadStatus` object.
pub(crate) fn status_json(status: &str, latest_valid_hash: Option<H256>) -> String {
    let hash = latest_valid_hash.map_or("null".to_string(), |hash| format!("\"{hash:?}\""));
    format!(r#"{{"status":"{status}","latestValidHash":{hash},"validationError":null}}"#)
}

/// Start a mock execution client answering `engine_newPayload*` with
/// `new_payload` and `engine_forkchoiceUpdated*` with `forkchoice` (each a
/// `payloadStatus` object, or `"ERROR"` for a JSON-RPC error).
pub(crate) async fn mock_engine(
    new_payload: String,
    forkchoice: String,
) -> (EngineClient, Arc<Mutex<MockState>>) {
    let state = Arc::new(Mutex::new(MockState {
        new_payload,
        forkchoice,
        ..MockState::default()
    }));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let addr = listener.local_addr().expect("bound address");
    let shared = Arc::clone(&state);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let shared = Arc::clone(&shared);
            tokio::spawn(async move {
                let mut pending: Vec<u8> = Vec::new();
                loop {
                    // One request: headers up to the blank line, then
                    // `Content-Length` bytes of body.
                    let (head_end, body_len) = loop {
                        if let Some(end) =
                            pending.windows(4).position(|window| window == b"\r\n\r\n")
                        {
                            let head = String::from_utf8_lossy(&pending[..end]).to_lowercase();
                            let len = head
                                .lines()
                                .find_map(|line| line.strip_prefix("content-length:"))
                                .and_then(|value| value.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            break (end + 4, len);
                        }
                        let mut chunk = [0u8; 16 * 1024];
                        match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(read) => pending.extend_from_slice(&chunk[..read]),
                        }
                    };
                    while pending.len() < head_end + body_len {
                        let mut chunk = [0u8; 16 * 1024];
                        match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(read) => pending.extend_from_slice(&chunk[..read]),
                        }
                    }
                    let body = String::from_utf8_lossy(&pending[head_end..head_end + body_len])
                        .to_string();
                    pending.drain(..head_end + body_len);

                    let result = {
                        let mut state = shared.lock().unwrap();
                        state.requests.push(body.clone());
                        state.answer(&body)
                    };
                    let result = if body.contains("engine_newPayload") {
                        result
                    } else {
                        format!(r#"{{"payloadStatus":{result},"payloadId":null}}"#)
                    };
                    let payload = if result == "ERROR" {
                        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"mock failure"}}"#.to_string()
                    } else {
                        format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#)
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{payload}",
                        payload.len()
                    );
                    if socket.write_all(response.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    let client =
        EngineClient::new(format!("http://{addr}"), JwtSecret::new([0x0f; 32])).expect("a client");
    (client, state)
}

/// The JSON-RPC methods the mock was asked, in order.
pub(crate) fn methods(state: &Arc<Mutex<MockState>>) -> Vec<String> {
    state
        .lock()
        .unwrap()
        .requests
        .iter()
        .map(|body| {
            let rest = body.split("\"method\":\"").nth(1).expect("a method");
            rest.split('"').next().expect("closing quote").to_string()
        })
        .collect()
}
