use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use axum::http::header::ACCEPT;
use ethlambda_types::beacon::builder::BuilderBid;
use ethlambda_types::beacon::containers::deneb::{ExecutionPayloadHeader, KzgCommitments};
use ethlambda_types::beacon::containers::electra::{self, ExecutionRequests};
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::primitives::{BlsPubkey, ExecutionBlockHash, Uint256, Version};

use super::mock_relay::{MockRelay, signed_registration};
use super::{BuilderClient, BuilderError, VersionedBid};

/// Any version will do: the relay and the signers only have to agree on it.
const GENESIS_FORK_VERSION: Version = [0x10, 0x00, 0x00, 0x38];
const HEADER_TIMEOUT: Duration = Duration::from_millis(1000);
const SLOT: u64 = 12_345;

fn client_for(relay: &MockRelay) -> BuilderClient {
    BuilderClient::new(relay.url.clone(), HEADER_TIMEOUT, "ethlambda/test").unwrap()
}

/// A bid on the empty payload, signed by `relay`, for `fork`.
fn bid_from(relay: &MockRelay, fork: ForkName) -> VersionedBid {
    let payload = electra::BeaconBlockBody::empty().execution_payload;
    let message = BuilderBid {
        header: ExecutionPayloadHeader::from(&payload),
        blob_kzg_commitments: KzgCommitments::default(),
        execution_requests: ExecutionRequests::default(),
        value: Uint256::from(1_000_000_000u64),
        pubkey: BlsPubkey([0; 48]),
    };
    VersionedBid {
        fork,
        bid: relay.sign_bid(message),
    }
}

async fn get_header(client: &BuilderClient) -> Result<Option<VersionedBid>, BuilderError> {
    let parent_hash = ExecutionBlockHash::repeat_byte(0xab);
    let proposer = BlsPubkey([0xcd; 48]);
    client.get_header(SLOT, parent_hash, &proposer).await
}

fn accept_headers(relay: &MockRelay) -> Vec<String> {
    relay
        .header_requests()
        .iter()
        .map(|request| request.headers[ACCEPT].to_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn no_bid_is_none() {
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    assert_eq!(get_header(&client_for(&relay)).await.unwrap(), None);
}

#[tokio::test]
async fn a_bid_arrives_in_ssz() {
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    let bid = bid_from(&relay, ForkName::Fulu);
    relay.offer(bid.clone());
    assert_eq!(get_header(&client_for(&relay)).await.unwrap(), Some(bid));
    assert!(accept_headers(&relay)[0].starts_with("application/octet-stream"));
}

#[tokio::test]
async fn a_relay_that_ignores_accept_still_delivers_its_bid() {
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    relay.ignore_accept();
    let bid = bid_from(&relay, ForkName::Electra);
    relay.offer(bid.clone());
    assert_eq!(get_header(&client_for(&relay)).await.unwrap(), Some(bid));
}

#[tokio::test]
async fn a_relay_that_refuses_ssz_is_asked_for_json_from_then_on() {
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    relay.refuse_ssz();
    let bid = bid_from(&relay, ForkName::Fulu);
    relay.offer(bid.clone());
    let client = client_for(&relay);

    // The refusal is not retried, since a retry would restart the clock the
    // proposer is waiting on; it is only remembered.
    assert!(matches!(
        get_header(&client).await,
        Err(BuilderError::Status { status: 406, .. })
    ));
    assert_eq!(get_header(&client).await.unwrap(), Some(bid));

    // The first request asks for SSZ and is refused; every later one asks
    // for JSON only.
    let accepts = accept_headers(&relay);
    assert_eq!(accepts.len(), 2);
    assert!(accepts[0].starts_with("application/octet-stream"));
    assert_eq!(accepts[1], "application/json");
}

#[tokio::test]
async fn get_header_names_the_slot_parent_and_proposer() {
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    get_header(&client_for(&relay)).await.unwrap();

    let request = &relay.header_requests()[0];
    assert_eq!(request.slot, "12345");
    assert_eq!(request.parent_hash, format!("0x{}", "ab".repeat(32)));
    assert_eq!(request.pubkey, format!("0x{}", "cd".repeat(48)));
    assert_eq!(request.headers["x-timeout-ms"], "1000");
    assert_eq!(request.headers["user-agent"], "ethlambda/test");
    let sent: u128 = request.headers["date-milliseconds"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    assert!(
        now.abs_diff(sent) < 60_000,
        "Date-Milliseconds is the current time"
    );
}

#[tokio::test]
async fn a_trailing_slash_on_the_url_is_harmless() {
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    let client =
        BuilderClient::new(format!("{}/", relay.url), HEADER_TIMEOUT, "ethlambda/test").unwrap();
    assert_eq!(get_header(&client).await.unwrap(), None);
}

#[tokio::test]
async fn a_slow_relay_times_out() {
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    relay.delay(Duration::from_millis(500));
    let deadline = Duration::from_millis(100);
    let client = BuilderClient::new(relay.url.clone(), deadline, "ethlambda/test").unwrap();
    assert!(matches!(
        get_header(&client).await,
        Err(BuilderError::Timeout(waited)) if waited == deadline
    ));
}

#[tokio::test]
async fn a_bid_for_another_fork_is_refused() {
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    relay.offer(bid_from(&relay, ForkName::Deneb));
    assert!(matches!(
        get_header(&client_for(&relay)).await,
        Err(BuilderError::UnsupportedFork(fork)) if fork == "deneb"
    ));
}

#[tokio::test]
async fn an_ssz_bid_must_name_its_fork() {
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    relay.omit_consensus_version();
    relay.offer(bid_from(&relay, ForkName::Fulu));
    assert!(matches!(
        get_header(&client_for(&relay)).await,
        Err(BuilderError::Incomplete(_))
    ));
}

#[tokio::test]
async fn an_unreachable_relay_is_reported_as_such() {
    let client =
        BuilderClient::new("http://127.0.0.1:1", HEADER_TIMEOUT, "ethlambda/test").unwrap();
    assert!(matches!(
        get_header(&client).await,
        Err(BuilderError::Transport(_))
    ));
}

const JSON: &str = "application/json";
const TEXT: &str = "text/plain";
const SSZ: &str = "application/octet-stream";

#[tokio::test]
async fn a_400_carries_the_builders_message() {
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    let body = br#"{"code":400,"message":"Unknown hash"}"#.to_vec();
    relay.answer_headers_with(StatusCode::BAD_REQUEST, JSON, body, None);
    assert!(matches!(
        get_header(&client_for(&relay)).await,
        Err(BuilderError::BadRequest(message)) if message == "Unknown hash"
    ));
}

#[tokio::test]
async fn a_400_without_json_carries_its_body() {
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    relay.answer_headers_with(StatusCode::BAD_REQUEST, TEXT, b"nope".to_vec(), None);
    assert!(matches!(
        get_header(&client_for(&relay)).await,
        Err(BuilderError::BadRequest(message)) if message == "nope"
    ));
}

#[tokio::test]
async fn a_long_error_is_cut_short() {
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    relay.answer_headers_with(StatusCode::BAD_REQUEST, TEXT, vec![b'x'; 5000], None);
    let Err(BuilderError::BadRequest(message)) = get_header(&client_for(&relay)).await else {
        panic!("expected a bad request");
    };
    assert_eq!(message.len(), 1024);
}

#[tokio::test]
async fn a_server_error_is_an_unexpected_status() {
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    relay.answer_headers_with(
        StatusCode::INTERNAL_SERVER_ERROR,
        TEXT,
        b"boom".to_vec(),
        None,
    );
    assert!(matches!(
        get_header(&client_for(&relay)).await,
        Err(BuilderError::Status { status: 500, .. })
    ));
}

#[tokio::test]
async fn garbage_ssz_does_not_decode() {
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    relay.answer_headers_with(StatusCode::OK, SSZ, vec![1, 2, 3], Some("fulu"));
    assert!(matches!(
        get_header(&client_for(&relay)).await,
        Err(BuilderError::Decode(_))
    ));
}

#[tokio::test]
async fn malformed_json_does_not_decode() {
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    let body = br#"{"version":"fulu","data":"#.to_vec();
    relay.answer_headers_with(StatusCode::OK, JSON, body, None);
    assert!(matches!(
        get_header(&client_for(&relay)).await,
        Err(BuilderError::Decode(_))
    ));
}

#[tokio::test]
async fn an_uppercase_version_is_read() {
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    let bid = bid_from(&relay, ForkName::Fulu);
    let body = serde_json::json!({ "version": "FULU", "data": bid.bid }).to_string();
    relay.answer_headers_with(StatusCode::OK, JSON, body.into_bytes(), None);
    let got = get_header(&client_for(&relay)).await.unwrap().unwrap();
    assert_eq!(got.fork, ForkName::Fulu);
    assert_eq!(got, bid);
}

#[tokio::test]
async fn a_json_bid_for_another_fork_is_refused() {
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    relay.ignore_accept();
    relay.offer(bid_from(&relay, ForkName::Deneb));
    assert!(matches!(
        get_header(&client_for(&relay)).await,
        Err(BuilderError::UnsupportedFork(fork)) if fork == "deneb"
    ));
}

#[tokio::test]
async fn an_oversized_answer_is_refused() {
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    relay.answer_headers_with(StatusCode::OK, SSZ, vec![0; 9 * 1024 * 1024], Some("fulu"));
    assert!(matches!(
        get_header(&client_for(&relay)).await,
        Err(BuilderError::TooLarge { .. })
    ));
}

#[tokio::test]
async fn an_invalid_url_is_refused_up_front() {
    assert!(matches!(
        BuilderClient::new("not a url", HEADER_TIMEOUT, "ethlambda/test"),
        Err(BuilderError::InvalidUrl(_))
    ));
}

#[tokio::test]
async fn a_url_without_a_scheme_is_refused_up_front() {
    assert!(matches!(
        BuilderClient::new("localhost:18550", HEADER_TIMEOUT, "ethlambda/test"),
        Err(BuilderError::InvalidUrl(_))
    ));
}

#[tokio::test]
async fn registrations_reach_the_relay_in_json() {
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    let registrations = vec![
        signed_registration(0, GENESIS_FORK_VERSION),
        signed_registration(1, GENESIS_FORK_VERSION),
    ];
    client_for(&relay)
        .register_validators(&registrations)
        .await
        .unwrap();
    // The relay refuses SSZ registrations, so arriving at all means JSON.
    assert_eq!(relay.registrations(), registrations);
}

#[tokio::test]
async fn a_registration_the_relay_refuses_is_a_bad_request() {
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    let mut registration = signed_registration(0, GENESIS_FORK_VERSION);
    registration.signature = signed_registration(1, GENESIS_FORK_VERSION).signature;
    assert!(matches!(
        client_for(&relay).register_validators(&[registration]).await,
        Err(BuilderError::BadRequest(message)) if message == "invalid signature"
    ));
    assert!(relay.registrations().is_empty());
}
