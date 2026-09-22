//! What [`ethlambda_rpc::start_http_servers`] serves when it is given no API
//! router.
//!
//! The difference from the `Some(api_router)` case has to be exactly "the lean
//! API is absent", with the metrics and debug routers still up: a chain with no
//! lean `Store` to answer from would otherwise have a lean route reachable on
//! its listener, answering for the wrong chain. `ethlambda beacon` used to be
//! that caller and reaches `start_rpc_server` today, off placeholder state, so
//! that one HTTP call site serves both chains; this is the shape it goes back
//! to once the beacon follower has a surface of its own. These tests bind a
//! real socket, because binding is the part that differs and a router-level
//! `oneshot` would not exercise it.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use ethlambda_rpc::{RpcConfig, start_http_servers};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// A port nothing is listening on, from an ephemeral bind that is then
/// released. Racy in principle; the window is one test's worth of microseconds
/// and the alternative is threading the bound address back out of
/// `start_http_servers` for the tests' sake alone.
async fn free_port() -> u16 {
    let probe = TcpListener::bind(SocketAddr::new(LOCALHOST, 0))
        .await
        .expect("an ephemeral port is available");
    probe
        .local_addr()
        .expect("the probe socket has an addr")
        .port()
}

/// GET `path`, retrying the connect until the server is accepting.
///
/// `start_http_servers` binds inside the spawned task, so there is no moment
/// the caller can await before the socket exists.
async fn get(port: u16, path: &str) -> String {
    for _ in 0..100 {
        let Ok(mut stream) = TcpStream::connect(SocketAddr::new(LOCALHOST, port)).await else {
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        };
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("the request writes");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("the response reads");
        return String::from_utf8_lossy(&response).to_string();
    }
    panic!("the server never accepted a connection on port {port}");
}

/// The status line of an HTTP response, e.g. `HTTP/1.1 200 OK`.
fn status_line(response: &str) -> &str {
    response.lines().next().unwrap_or("").trim_end()
}

#[tokio::test]
async fn with_no_api_router_metrics_and_debug_are_served_on_the_metrics_port() {
    let port = free_port().await;
    let shutdown = CancellationToken::new();
    let config = RpcConfig {
        http_address: LOCALHOST,
        // Deliberately different from `metrics_port`: with no API router this
        // must not be bound at all, which the assertion below pins.
        api_port: free_port().await,
        metrics_port: port,
        version: "ethlambda/test",
    };

    let served = tokio::spawn(start_http_servers(config.clone(), None, shutdown.clone()));

    // Metrics: the whole reason `beacon` serves anything at all.
    assert!(
        status_line(&get(port, "/metrics").await).contains("200"),
        "/metrics must be served"
    );
    // Debug: `beacon` gains these by going through the shared entry point.
    // Heap profiling was previously node-only.
    assert!(
        !status_line(&get(port, "/debug/pprof/allocs").await).contains("404"),
        "the debug router must be mounted"
    );
    // The lean API must not be reachable: there is no `Store` behind it here.
    assert!(
        status_line(&get(port, "/lean/v0/health").await).contains("404"),
        "no lean route may be served without an API router"
    );

    // `api_port` is not merely unused, it is never bound: a fresh listener on
    // it must succeed.
    TcpListener::bind(SocketAddr::new(LOCALHOST, config.api_port))
        .await
        .expect("api_port must be free when no API router is supplied");

    shutdown.cancel();
    served
        .await
        .expect("the server task joins")
        .expect("the server exits cleanly on shutdown");
}

#[tokio::test]
async fn a_cancelled_token_stops_the_server() {
    let port = free_port().await;
    let shutdown = CancellationToken::new();
    let config = RpcConfig {
        http_address: LOCALHOST,
        api_port: port,
        metrics_port: port,
        version: "ethlambda/test",
    };

    let served = tokio::spawn(start_http_servers(config, None, shutdown.clone()));
    assert!(status_line(&get(port, "/metrics").await).contains("200"));

    shutdown.cancel();
    // Without graceful shutdown wired up this hangs rather than failing, so
    // bound it: `run_beacon` parking on `pending()` is what this guards.
    tokio::time::timeout(Duration::from_secs(5), served)
        .await
        .expect("the server stops within five seconds of cancellation")
        .expect("the server task joins")
        .expect("the server exits cleanly");
}

/// The beacon router answers where the lean one used to, and does **not**
/// serve `/lean/v0`.
///
/// That absence is the point of the whole surface: the lean handlers read
/// metadata keys and state variants a beacon directory never carries, so
/// before this existed a beacon node's `--api-port` answered lean questions
/// by panicking the request. A 404 is the honest answer for a chain that is
/// not running.
#[tokio::test]
async fn the_beacon_router_replaces_the_lean_one() {
    use axum::{body::Body, http::Request};
    use ethlambda_types::beacon::{
        config::Config,
        containers::{SignedBeaconBlock, phase0},
        primitives::Root,
    };
    use tower::ServiceExt as _;

    const GENESIS_TIME: u64 = 1_606_824_023;
    let slot = 64;

    let block = SignedBeaconBlock::Phase0(phase0::SignedBeaconBlock {
        message: phase0::BeaconBlock {
            slot,
            proposer_index: 0,
            parent_root: Root::ZERO,
            state_root: Root::ZERO,
            body: phase0::BeaconBlockBody::default(),
        },
        signature: Default::default(),
    });
    let root = block.message_hash_tree_root();

    let mut store = ethlambda_storage::Store::init_beacon(
        std::sync::Arc::new(ethlambda_storage::backend::InMemoryBackend::default()),
        GENESIS_TIME,
        Config::mainnet(),
        root,
        ethlambda_types::checkpoint::Checkpoint { root, slot },
        slot,
    );
    store
        .insert_signed_block(root, block)
        .expect("insert anchor block");

    let router = ethlambda_rpc::build_beacon_api_router(store, "ethlambda/test", "peer".into())
        .layer(axum::Extension(
            ethlambda_blockchain::SyncStatusController::default(),
        ));

    let beacon = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/eth/v1/node/version")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(beacon.status(), axum::http::StatusCode::OK);

    let lean = router
        .oneshot(
            Request::builder()
                .uri("/lean/v0/node/syncing")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        lean.status(),
        axum::http::StatusCode::NOT_FOUND,
        "a beacon node must not serve the lean surface off a beacon store"
    );
}
