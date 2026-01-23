use std::net::SocketAddr;

use axum::{Router, routing::get};

pub mod metrics;

pub async fn start_rpc_server(address: SocketAddr) -> Result<(), std::io::Error> {
    let metrics_router = metrics::start_prometheus_metrics_api();

    let app = Router::new()
        .merge(metrics_router)
        .route("/lean/states/finalized", get(get_latest_finalized_state))
        .route("/lean/states/justified", get(get_latest_justified_state));

    // Start the axum app
    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn get_latest_finalized_state() {}

async fn get_latest_justified_state() {}
