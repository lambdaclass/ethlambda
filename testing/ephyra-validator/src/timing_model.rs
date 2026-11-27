//! Delayed beacon-node answers, checked without ephyra-specific types.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::primitives::{Epoch, Root};
use ethlambda_validator::beacon_node::Genesis;
use ethlambda_validator::beacon_node::fallback::FallbackBeaconNode;
use ethlambda_validator::beacon_node::http::HttpBeaconNode;
use ethlambda_validator::chain_check::check_once;
use ethlambda_validator::signing::SigningContext;
use serde_json::{Map, Value, json};

use crate::chain_model::NOW;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimingCase {
    pub fork_delta: u8,
    pub answer_after_fork: bool,
    pub delay_ms: u8,
    pub version: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RaceCase {
    pub fast_delay_ms: u8,
    pub slow_delay_ms: u8,
    pub version: u8,
}

pub fn valid_race_case(case: &RaceCase) -> bool {
    (1..=5).contains(&case.fast_delay_ms)
        && (20..=100).contains(&case.slow_delay_ms)
        && (1..=3).contains(&case.version)
}

pub fn valid_timing_case(case: &TimingCase) -> bool {
    (1..=5).contains(&case.fork_delta)
        && (1..=20).contains(&case.delay_ms)
        && (1..=3).contains(&case.version)
}

fn genesis() -> Genesis {
    Genesis {
        genesis_time: 1_606_824_023,
        genesis_validators_root: Root::repeat_byte(0xaa),
    }
}

fn hex(bytes: &[u8]) -> String {
    format!(
        "0x{}",
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn spec_body(config: &Config) -> Vec<u8> {
    let mut data = Map::new();
    data.insert(
        "SLOT_DURATION_MS".into(),
        json!(config.slot_duration_ms.to_string()),
    );
    data.insert(
        "GENESIS_FORK_VERSION".into(),
        json!(hex(&config.fork_version(ForkName::Phase0))),
    );
    for fork in ForkName::ALL
        .into_iter()
        .filter(|fork| *fork != ForkName::Phase0)
    {
        let name = fork.as_str().to_uppercase();
        data.insert(
            format!("{name}_FORK_EPOCH"),
            json!(config.fork_epoch(fork).to_string()),
        );
        data.insert(
            format!("{name}_FORK_VERSION"),
            json!(hex(&config.fork_version(fork))),
        );
    }
    serde_json::to_vec(&json!({"data": Value::Object(data)})).expect("spec JSON")
}

fn answer(mut stream: TcpStream, baseline: &[u8], upgraded: &[u8], state: &ServerState) {
    stream
        .set_nonblocking(false)
        .expect("blocking accepted stream");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");
    let mut request = Vec::new();
    let mut chunk = [0u8; 512];
    while !request.windows(4).any(|part| part == b"\r\n\r\n") {
        let read = match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return, // The client may cancel an in-flight request.
            Ok(read) => read,
        };
        request.extend_from_slice(&chunk[..read]);
        assert!(request.len() < 16_384, "unexpectedly large request");
    }
    let request = String::from_utf8(request).expect("HTTP request is ASCII");
    let path = request.split_whitespace().nth(1).expect("request path");
    let unavailable = state.startup_down && !state.checking.load(Ordering::SeqCst);
    let (status, body) = match path {
        "/eth/v1/beacon/genesis" | "/eth/v1/config/spec" if unavailable => {
            ("503 Service Unavailable", b"{}".to_vec())
        }
        "/eth/v1/beacon/genesis" => serde_json::to_vec(&json!({"data": {
            "genesis_time": genesis().genesis_time.to_string(),
            "genesis_validators_root": hex(&genesis().genesis_validators_root.0)
        }}))
        .map(|body| ("200 OK", body))
        .expect("genesis JSON"),
        "/eth/v1/config/spec" if state.checking.load(Ordering::SeqCst) => {
            thread::sleep(state.delay);
            state.epoch.store(state.answer_epoch, Ordering::SeqCst);
            ("200 OK", upgraded.to_vec())
        }
        "/eth/v1/config/spec" => ("200 OK", baseline.to_vec()),
        _ => panic!("unexpected Beacon API path: {path}"),
    };
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).expect("write headers");
    stream.write_all(&body).expect("write body");
}

struct ServerState {
    checking: AtomicBool,
    stop: AtomicBool,
    epoch: Arc<AtomicU64>,
    answer_epoch: Epoch,
    delay: Duration,
    startup_down: bool,
}

struct Server {
    url: String,
    state: Arc<ServerState>,
    thread: Option<JoinHandle<()>>,
}

impl Server {
    fn start(
        baseline: &Config,
        upgraded: &Config,
        epoch: Arc<AtomicU64>,
        answer_epoch: Epoch,
        delay_ms: u8,
        startup_down: bool,
    ) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind mock Beacon API");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let url = format!(
            "http://{}",
            listener.local_addr().expect("listener address")
        );
        let state = Arc::new(ServerState {
            checking: AtomicBool::new(false),
            stop: AtomicBool::new(false),
            epoch,
            answer_epoch,
            delay: Duration::from_millis(u64::from(delay_ms)),
            startup_down,
        });
        let baseline = spec_body(baseline);
        let upgraded = spec_body(upgraded);
        let thread_state = Arc::clone(&state);
        let thread = thread::spawn(move || {
            while !thread_state.stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => answer(stream, &baseline, &upgraded, &thread_state),
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(err) => panic!("mock Beacon API accept failed: {err}"),
                }
            }
        });
        Self {
            url,
            state,
            thread: Some(thread),
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.state.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            thread.join().expect("mock Beacon API thread");
        }
    }
}

pub async fn check_timing(case: &TimingCase) {
    assert!(valid_timing_case(case));
    let baseline = Config::mainnet();
    let fork_epoch = NOW + u64::from(case.fork_delta);
    let upgraded = baseline
        .clone()
        .with_fork_epoch(ForkName::Gloas, fork_epoch)
        .with_fork_version(ForkName::Gloas, [case.version, 0, 0, 0]);
    let answer_epoch = if case.answer_after_fork {
        fork_epoch
    } else {
        fork_epoch - 1
    };
    let server = Server::start(
        &baseline,
        &upgraded,
        Arc::new(AtomicU64::new(NOW)),
        answer_epoch,
        case.delay_ms,
        false,
    );
    let node = HttpBeaconNode::new(&server.url).expect("HTTP client");
    let fallback = FallbackBeaconNode::new(vec![node]);
    let chain = fallback
        .establish(|_| Ok(NOW))
        .await
        .expect("establish baseline");
    assert_eq!(
        chain.config, baseline,
        "startup did not use baseline spec: {case:?}"
    );
    let context = SigningContext::new(baseline.clone(), genesis().genesis_validators_root);
    server.state.checking.store(true, Ordering::SeqCst);
    check_once(
        &fallback,
        genesis(),
        &context,
        || server.state.epoch.load(Ordering::SeqCst),
        false,
    )
    .await;
    let actual = context.config();
    if case.answer_after_fork {
        assert_eq!(*actual, baseline, "late fork was adopted: {case:?}");
    } else {
        assert_eq!(*actual, upgraded, "prompt fork was missed: {case:?}");
    }
}

pub async fn check_fast_answer_beats_slow_timeout(case: &RaceCase) {
    assert!(valid_race_case(case));
    let baseline = Config::mainnet();
    let gloas_epoch = NOW + 1;
    let upgraded = baseline
        .clone()
        .with_fork_epoch(ForkName::Gloas, gloas_epoch)
        .with_fork_version(ForkName::Gloas, [case.version, 0, 0, 0]);
    let epoch = Arc::new(AtomicU64::new(NOW));
    let fast = Server::start(
        &baseline,
        &upgraded,
        Arc::clone(&epoch),
        NOW,
        case.fast_delay_ms,
        false,
    );
    let slow = Server::start(
        &baseline,
        &baseline,
        Arc::clone(&epoch),
        gloas_epoch,
        case.slow_delay_ms,
        true,
    );
    let fallback = FallbackBeaconNode::new(vec![
        HttpBeaconNode::new(&fast.url).expect("fast HTTP client"),
        HttpBeaconNode::new(&slow.url).expect("slow HTTP client"),
    ]);
    let chain = fallback
        .establish(|_| Ok(NOW))
        .await
        .expect("establish fast node");
    assert_eq!(chain.config, baseline);
    assert_eq!(fallback.served_configs(NOW).say, vec![0]);
    let context = SigningContext::new(baseline, genesis().genesis_validators_root);
    fast.state.checking.store(true, Ordering::SeqCst);
    slow.state.checking.store(true, Ordering::SeqCst);
    check_once(
        &fallback,
        genesis(),
        &context,
        || epoch.load(Ordering::SeqCst),
        false,
    )
    .await;
    assert_eq!(
        epoch.load(Ordering::SeqCst),
        gloas_epoch,
        "slow node never crossed boundary"
    );
    assert_eq!(
        *context.config(),
        upgraded,
        "slow answer held back a prompt one: {case:?}"
    );
}
