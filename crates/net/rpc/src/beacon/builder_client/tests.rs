use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use axum::http::header::ACCEPT;
use ethlambda_types::beacon::builder::{BlindedBeaconBlock, BuilderBid, SignedBlindedBeaconBlock};
use ethlambda_types::beacon::containers::deneb::{ExecutionPayloadHeader, KzgCommitments};
use ethlambda_types::beacon::containers::electra::{self, ExecutionRequests};
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::primitives::{
    BlsPubkey, BlsSignature, ExecutionBlockHash, Root, Uint256, Version,
};
use reqwest::Url;

use super::error::shown_target;
use super::mock_relay::{MockRelay, signed_registration, unreachable_url};
use super::{BuilderClient, BuilderError, VersionedBid, follows};

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
    let client = BuilderClient::new(unreachable_url(), HEADER_TIMEOUT, "ethlambda/test").unwrap();
    assert!(matches!(
        get_header(&client).await,
        Err(BuilderError::Transport(_))
    ));
}

#[tokio::test]
async fn a_redirect_is_refused_and_names_its_target() {
    let moved = MockRelay::start(GENESIS_FORK_VERSION).await;
    let target = MockRelay::start(GENESIS_FORK_VERSION).await;
    moved.redirect_to(&target.url);
    let registrations = vec![signed_registration(0, GENESIS_FORK_VERSION)];

    let err = client_for(&moved)
        .register_validators(&registrations)
        .await
        .unwrap_err();

    let location = format!("{}/eth/v1/builder/validators", target.url);
    assert!(
        matches!(&err, BuilderError::Redirected { status: 307, location: shown } if *shown == location),
        "{err:?}"
    );
    let message = err.to_string();
    assert!(message.contains(&location), "{message}");
    assert!(message.contains("--builder-follow-redirects"), "{message}");
    assert_eq!(err.label(), "redirected");
    assert_eq!(target.registration_calls(), 0);
}

fn following_client_for(relay: &MockRelay) -> BuilderClient {
    BuilderClient::with_redirects(relay.url.clone(), HEADER_TIMEOUT, "ethlambda/test", true)
        .unwrap()
}

#[tokio::test]
async fn a_307_or_308_is_followed_when_asked() {
    for status in [
        StatusCode::TEMPORARY_REDIRECT,
        StatusCode::PERMANENT_REDIRECT,
    ] {
        let moved = MockRelay::start(GENESIS_FORK_VERSION).await;
        let target = MockRelay::start(GENESIS_FORK_VERSION).await;
        moved.redirect_with(status, &target.url);
        let registrations = vec![signed_registration(0, GENESIS_FORK_VERSION)];

        following_client_for(&moved)
            .register_validators(&registrations)
            .await
            .unwrap();

        // Both keep the POST and its body, so the target got them whole.
        assert_eq!(target.registrations(), registrations, "{status}");
    }
}

#[tokio::test]
async fn a_301_302_or_303_is_not_followed_even_when_asked() {
    for status in [
        StatusCode::MOVED_PERMANENTLY,
        StatusCode::FOUND,
        StatusCode::SEE_OTHER,
    ] {
        let moved = MockRelay::start(GENESIS_FORK_VERSION).await;
        let target = MockRelay::start(GENESIS_FORK_VERSION).await;
        moved.redirect_with(status, &target.url);
        let registrations = vec![signed_registration(0, GENESIS_FORK_VERSION)];

        let err = following_client_for(&moved)
            .register_validators(&registrations)
            .await
            .unwrap_err();

        // Followed, the POST would have reached the target as an empty GET,
        // and the call would have failed on the target's 405 instead.
        let answered = status.as_u16();
        assert!(
            matches!(err, BuilderError::Redirected { status, .. } if status == answered),
            "{err:?}"
        );
        assert_eq!(target.registration_calls(), 0, "{status}");
    }
}

#[tokio::test]
async fn a_redirect_loop_stops_after_ten_hops() {
    let looping = MockRelay::start(GENESIS_FORK_VERSION).await;
    looping.redirect_to(&looping.url);

    let err = following_client_for(&looping).status().await.unwrap_err();

    // The first request and ten followed redirects; the eleventh redirect is
    // the answer, named rather than failed as a transport error.
    assert!(
        matches!(err, BuilderError::Redirected { status: 307, .. }),
        "{err:?}"
    );
    assert_eq!(looping.redirects_served(), 11);
}

fn url(value: &str) -> Url {
    Url::parse(value).unwrap()
}

#[test]
fn only_a_307_or_308_is_followed() {
    let next = url("https://relay.example/eth/v1/builder/validators");
    let previous = [url("https://mev-boost.example/eth/v1/builder/validators")];
    for status in [
        StatusCode::TEMPORARY_REDIRECT,
        StatusCode::PERMANENT_REDIRECT,
    ] {
        assert!(follows(status, &next, &previous), "{status}");
    }
    for status in [
        StatusCode::MOVED_PERMANENTLY,
        StatusCode::FOUND,
        StatusCode::SEE_OTHER,
    ] {
        assert!(!follows(status, &next, &previous), "{status}");
    }
}

#[test]
fn a_downgrade_from_https_to_http_is_refused() {
    // The mock relay serves plain http, so the downgrade is checked here
    // rather than end to end.
    let status = StatusCode::TEMPORARY_REDIRECT;
    let https = url("https://relay.example/eth/v1/builder/status");
    let http = url("http://relay.example/eth/v1/builder/status");

    assert!(!follows(status, &http, std::slice::from_ref(&https)));
    // Whatever came before: one https hop is enough to rule out http after it.
    assert!(!follows(status, &http, &[http.clone(), https.clone()]));
    // An upgrade, or staying on one scheme, is fine.
    assert!(follows(status, &https, std::slice::from_ref(&http)));
    assert!(follows(status, &https, std::slice::from_ref(&https)));
    assert!(follows(status, &http, std::slice::from_ref(&http)));
}

#[test]
fn a_redirect_to_a_scheme_other_than_http_is_not_followed() {
    let previous = [url("http://relay.example/")];
    let ftp = url("ftp://relay.example/eth/v1/builder/status");
    assert!(!follows(StatusCode::TEMPORARY_REDIRECT, &ftp, &previous));
}

#[test]
fn at_most_ten_redirects_are_followed() {
    let status = StatusCode::TEMPORARY_REDIRECT;
    let next = url("http://relay.example/next");
    // `previous` starts with the URL the call was sent to, so ten URLs in it
    // means nine redirects followed so far, and this one is the tenth.
    let mut previous: Vec<Url> = (0..10)
        .map(|hop| url(&format!("http://relay.example/{hop}")))
        .collect();
    assert!(follows(status, &next, &previous));
    previous.push(url("http://relay.example/10"));
    assert!(!follows(status, &next, &previous));
}

#[tokio::test]
async fn a_redirect_target_is_shown_without_its_credentials() {
    let moved = MockRelay::start(GENESIS_FORK_VERSION).await;
    moved.redirect_to("http://operator:hunter2@127.0.0.1:9");

    let err = client_for(&moved).status().await.unwrap_err();

    let message = err.to_string();
    assert!(
        message.contains("http://127.0.0.1:9/eth/v1/builder/status"),
        "{message}"
    );
    assert!(!message.contains("hunter2"), "{message}");
    assert!(!message.contains("operator"), "{message}");
}

#[tokio::test]
async fn a_scheme_relative_target_is_shown_absolute_without_its_credentials() {
    // `//user:pass@host/x` does not parse as a URL on its own; it is only
    // stripped once resolved against the URL that answered.
    let moved = MockRelay::start(GENESIS_FORK_VERSION).await;
    moved.redirect_to("//operator:hunter2@127.0.0.1:9");

    let err = client_for(&moved).status().await.unwrap_err();

    let message = err.to_string();
    assert!(
        message.contains("http://127.0.0.1:9/eth/v1/builder/status"),
        "{message}"
    );
    assert!(!message.contains("hunter2"), "{message}");
    assert!(!message.contains("operator"), "{message}");
}

#[tokio::test]
async fn a_relative_target_is_shown_resolved_against_the_builder() {
    let moved = MockRelay::start(GENESIS_FORK_VERSION).await;
    moved.redirect_to("/moved");

    let err = client_for(&moved).status().await.unwrap_err();

    let location = format!("{}/moved/eth/v1/builder/status", moved.url);
    assert!(
        matches!(&err, BuilderError::Redirected { location: shown, .. } if *shown == location),
        "{err:?}"
    );
}

#[tokio::test]
async fn an_unparsable_target_is_not_shown() {
    // An unterminated IPv6 host: not a URL, resolved or not.
    let moved = MockRelay::start(GENESIS_FORK_VERSION).await;
    moved.redirect_to("http://operator:hunter2@[::1");

    let err = client_for(&moved).status().await.unwrap_err();

    let BuilderError::Redirected { location, .. } = &err else {
        panic!("expected a redirect, got {err:?}");
    };
    assert_eq!(
        location,
        "a Location that does not resolve to a URL with a host"
    );
    let message = err.to_string();
    assert!(!message.contains("hunter2"), "{message}");
    assert!(!message.contains("operator"), "{message}");
}

#[test]
fn a_relative_target_does_not_inherit_the_builders_credentials() {
    let base = url("http://operator:hunter2@relay.example/eth/v1/builder/status");
    assert_eq!(shown_target(&base, b"/moved"), "http://relay.example/moved");
}

#[test]
fn a_target_with_no_host_is_not_shown() {
    // It resolves, but to a URL with no host, so it has no user or password
    // to remove and is not shown at all.
    let base = url("http://relay.example/eth/v1/builder/status");
    assert_eq!(
        shown_target(&base, b"mailto:operator:hunter2@relay.example"),
        "a Location that does not resolve to a URL with a host"
    );
}

#[tokio::test]
async fn a_3xx_that_is_not_a_redirect_is_an_unexpected_status() {
    for status in [StatusCode::MULTIPLE_CHOICES, StatusCode::NOT_MODIFIED] {
        let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
        relay.answer_headers_with(status, TEXT, Vec::new(), None);
        let answered = status.as_u16();
        let result = get_header(&client_for(&relay)).await;
        assert!(
            matches!(&result, Err(BuilderError::Status { status, .. }) if *status == answered),
            "{result:?}"
        );
    }
}

#[test]
fn debug_does_not_show_the_urls_credentials() {
    let client = BuilderClient::new(
        "http://operator:hunter2@127.0.0.1:18550",
        HEADER_TIMEOUT,
        "ethlambda/test",
    )
    .unwrap();

    let shown = format!("{client:?}");

    assert!(shown.contains("http://127.0.0.1:18550/"), "{shown}");
    assert!(!shown.contains("hunter2"), "{shown}");
    assert!(!shown.contains("operator"), "{shown}");
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
    assert_eq!(message, format!("{}...", "x".repeat(1021)));
}

/// Line breaks are written out, so a builder's text cannot start a log line of
/// its own, and the escaped text is what the length cap applies to: 510 of
/// the two-byte escapes, then the marker.
#[tokio::test]
async fn line_breaks_in_an_error_are_written_out() {
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    let body = b"bad block\r\nINFO forged line".to_vec();
    relay.answer_headers_with(StatusCode::BAD_REQUEST, TEXT, body, None);
    let Err(BuilderError::BadRequest(message)) = get_header(&client_for(&relay)).await else {
        panic!("expected a bad request");
    };
    assert_eq!(message, r"bad block\r\nINFO forged line");

    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    relay.answer_headers_with(StatusCode::BAD_REQUEST, TEXT, vec![b'\n'; 1000], None);
    let Err(BuilderError::BadRequest(message)) = get_header(&client_for(&relay)).await else {
        panic!("expected a bad request");
    };
    assert_eq!(message, format!("{}...", r"\n".repeat(510)));
}

/// Every other control character is written out too (an ESC would start an
/// ANSI sequence in a terminal), and so are the Unicode line and paragraph
/// separators, which `char::is_control` does not cover. Quotes and
/// backslashes pass through.
#[tokio::test]
async fn control_characters_in_an_error_are_written_out() {
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    let body = "\x1b[31mred\x1b[0m\ttab\x07bell\u{85}nel\u{2028}ls\u{2029}ps \"q\" \\ ok";
    relay.answer_headers_with(StatusCode::BAD_REQUEST, TEXT, body.into(), None);
    let Err(BuilderError::BadRequest(message)) = get_header(&client_for(&relay)).await else {
        panic!("expected a bad request");
    };
    assert_eq!(
        message,
        r#"\u{1b}[31mred\u{1b}[0m\ttab\u{7}bell\u{85}nel\u{2028}ls\u{2029}ps "q" \ ok"#
    );

    // The same escapes reach a JSON error's message, where the builder can
    // send them as `\u001b`.
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    let body = br#"{"code":400,"message":"\u001b[2Jcleared"}"#.to_vec();
    relay.answer_headers_with(StatusCode::BAD_REQUEST, JSON, body, None);
    let Err(BuilderError::BadRequest(message)) = get_header(&client_for(&relay)).await else {
        panic!("expected a bad request");
    };
    assert_eq!(message, r"\u{1b}[2Jcleared");
}

/// The cap never leaves half an escape behind.
#[test]
fn the_cap_never_cuts_an_escape_in_two() {
    // 1020 bytes, then a six-byte escape that would end past the cap: it is
    // left out whole, and the marker ends the text.
    let text = format!("{}\x1b", "x".repeat(1020));
    assert_eq!(super::error_text(text), format!("{}...", "x".repeat(1020)));
    let text = format!("{}\x1b", "x".repeat(1018));
    assert_eq!(
        super::error_text(text),
        format!("{}\\u{{1b}}", "x".repeat(1018))
    );
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

fn blinded_block() -> SignedBlindedBeaconBlock {
    let block = electra::BeaconBlock {
        slot: SLOT,
        proposer_index: 3,
        parent_root: Root::repeat_byte(1),
        state_root: Root::repeat_byte(2),
        body: electra::BeaconBlockBody::empty(),
    };
    SignedBlindedBeaconBlock {
        message: BlindedBeaconBlock::from(block),
        signature: BlsSignature::default(),
    }
}

#[tokio::test]
async fn a_blinded_block_reaches_the_relay_in_ssz_with_its_fork() {
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    let block = blinded_block();
    client_for(&relay)
        .submit_blinded_block(&block, ForkName::Fulu)
        .await
        .unwrap();
    // The relay refuses an SSZ submission that does not name its fork.
    assert_eq!(relay.blinded_blocks(), [block]);
    assert_eq!(relay.ssz_submissions(), 1);
}

#[tokio::test]
async fn a_relay_that_refuses_ssz_blocks_is_sent_json_from_then_on() {
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    relay.refuse_ssz();
    let client = client_for(&relay);
    let block = blinded_block();

    client
        .submit_blinded_block(&block, ForkName::Fulu)
        .await
        .unwrap();
    client
        .submit_blinded_block(&block, ForkName::Fulu)
        .await
        .unwrap();

    assert_eq!(relay.blinded_blocks(), [block.clone(), block]);
    // The first submission tried SSZ, was refused and went again in JSON;
    // the second went straight to JSON.
    assert_eq!(relay.ssz_submissions(), 1);
}

#[tokio::test]
async fn a_relay_that_refuses_a_block_says_why() {
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    relay.answer_submissions_with(StatusCode::BAD_REQUEST);
    assert!(matches!(
        client_for(&relay).submit_blinded_block(&blinded_block(), ForkName::Fulu).await,
        Err(BuilderError::BadRequest(message)) if message == "block refused"
    ));
}

#[tokio::test]
async fn only_202_is_a_successful_submission() {
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    relay.answer_submissions_with(StatusCode::INTERNAL_SERVER_ERROR);
    assert!(matches!(
        client_for(&relay)
            .submit_blinded_block(&blinded_block(), ForkName::Fulu)
            .await,
        Err(BuilderError::Status { status: 500, .. })
    ));
}

/// Another 2xx is still a failure, but one of its own, labelled apart from a
/// refusal or a server error.
#[tokio::test]
async fn a_2xx_other_than_202_is_an_unexpected_success() {
    for status in [StatusCode::OK, StatusCode::NO_CONTENT] {
        let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
        relay.answer_submissions_with(status);
        let result = client_for(&relay)
            .submit_blinded_block(&blinded_block(), ForkName::Fulu)
            .await;
        let Err(err @ BuilderError::UnexpectedSuccess { status: answered }) = result else {
            panic!("{status}: expected an unexpected success, got {result:?}");
        };
        assert_eq!(answered, status.as_u16());
        assert_eq!(err.label(), "unexpected_success");
        assert!(err.to_string().contains("202 Accepted"), "{err}");
    }
}

#[tokio::test]
async fn a_running_builder_reports_its_status() {
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    client_for(&relay).status().await.unwrap();
}

#[tokio::test]
async fn an_unavailable_builder_reports_its_503() {
    let relay = MockRelay::start(GENESIS_FORK_VERSION).await;
    relay.make_unavailable();
    assert!(matches!(
        client_for(&relay).status().await,
        Err(BuilderError::Status { status: 503, .. })
    ));
}
