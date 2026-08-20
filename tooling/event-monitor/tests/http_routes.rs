//! Integration test: the routing table built by [`server::build_router`].
//!
//! Asserts the two things a single-page dashboard needs from it — `/` serves
//! `index.html`, and anything unmatched 404s rather than being answered with
//! `index.html`. A catch-all HTML fallback turns a typo'd asset path into a
//! mystery JS parse error and a typo'd API path into a silent `200`.

use std::path::Path;

use tokio::net::TcpListener;
use tokio::sync::watch;

use event_monitor::config::{Config, NodeConfig};
use event_monitor::hub::Hub;
use event_monitor::server::{self, MetaConfig};
use event_monitor::timing::Timing;

/// The real `web/` directory, by absolute path, so the test does not depend on
/// the test process's working directory.
fn web_dir() -> String {
    format!("{}/web", env!("CARGO_MANIFEST_DIR"))
}

fn test_config() -> Config {
    let toml_str = format!(
        r#"
        listen = "127.0.0.1:0"
        static_dir = {:?}

        [[nodes]]
        name = "node-2"
        url = "http://127.0.0.1:5052"
        "#,
        web_dir()
    );
    toml::from_str(&toml_str).expect("fixture should parse")
}

/// Serves the real router on an ephemeral port. Returns its base URL plus the
/// geometry sender, which the caller holds so the channel stays open for the
/// lifetime of the test.
async fn spawn_server() -> (String, watch::Sender<Timing>) {
    let config = test_config();
    let (timing_tx, timing_rx) = watch::channel(Timing {
        genesis_time: 1_770_407_233,
        ms_per_slot: 4_000,
        intervals_per_slot: 5,
    });

    let app = server::build_router(
        Hub::new(64),
        MetaConfig::new(&config),
        timing_rx,
        Path::new(&web_dir()),
    );
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind test server");
    let addr = listener.local_addr().expect("server has no local addr");
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("test server crashed");
    });
    (format!("http://{addr}"), timing_tx)
}

#[tokio::test]
async fn known_routes_answer_and_unknown_ones_404() {
    let (base, _timing_tx) = spawn_server().await;
    let client = reqwest::Client::new();

    let get = |path: &str| {
        let url = format!("{base}{path}");
        let client = client.clone();
        async move { client.get(url).send().await.expect("request failed") }
    };

    // `/` is the dashboard.
    let index = get("/").await;
    assert_eq!(index.status(), 200);
    let content_type = index
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        content_type.starts_with("text/html"),
        "unexpected content-type: {content_type}"
    );
    assert!(index.text().await.unwrap().contains("event-monitor"));

    // Real assets are served from `static_dir`.
    assert_eq!(get("/app.js").await.status(), 200);
    assert_eq!(get("/style.css").await.status(), 200);

    // The JSON endpoints answer on their exact paths.
    assert_eq!(get("/api/meta").await.status(), 200);
    assert_eq!(get("/api/history").await.status(), 200);

    // Regression: each of these used to come back `200 text/html`, hiding the
    // typo behind a JS parse error or a JSON decode failure.
    for wrong in ["/api/typo", "/nonexistent.js", "/api/meta/extra", "/nope"] {
        assert_eq!(get(wrong).await.status(), 404, "{wrong} should 404");
    }
}

#[tokio::test]
async fn meta_reports_the_live_slot_geometry() {
    let (base, _timing_tx) = spawn_server().await;
    let meta: serde_json::Value = reqwest::get(format!("{base}/api/meta"))
        .await
        .expect("request failed")
        .json()
        .await
        .expect("meta should be JSON");

    assert_eq!(meta["genesis_time"], 1_770_407_233_u64);
    assert_eq!(meta["ms_per_slot"], 4_000);
    assert_eq!(meta["intervals_per_slot"], 5);
    assert_eq!(meta["nodes"][0]["name"], "node-2");
}

#[tokio::test]
async fn node_config_endpoint_joins_paths_without_doubling_slashes() {
    let node = NodeConfig {
        name: "node-2".to_string(),
        url: "http://127.0.0.1:5052/".to_string(),
    };
    assert_eq!(
        node.endpoint("/lean/v0/events"),
        "http://127.0.0.1:5052/lean/v0/events"
    );
}
