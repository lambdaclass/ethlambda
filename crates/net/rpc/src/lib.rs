use std::net::SocketAddr;

use axum::{Json, Router, response::IntoResponse, routing::get};
use ethlambda_blockchain::store::Store;

pub mod metrics;

pub async fn start_rpc_server(address: SocketAddr, store: Store) -> Result<(), std::io::Error> {
    let metrics_router = metrics::start_prometheus_metrics_api();

    // Create stateful routes first, then convert to stateless by applying state
    let api_routes = Router::new()
        .route("/lean/v0/states/finalized", get(get_latest_finalized_state))
        .route(
            "/lean/v0/checkpoints/justified",
            get(get_latest_justified_state),
        )
        .with_state(store);

    // Merge stateless routers
    let app = Router::new().merge(metrics_router).merge(api_routes);

    // Start the axum app
    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn get_latest_finalized_state(
    axum::extract::State(store): axum::extract::State<Store>,
) -> impl IntoResponse {
    let finalized = store.latest_finalized();
    let state = store
        .get_state(finalized.root)
        .expect("finalized state exists");
    Json(state.clone())
}

async fn get_latest_justified_state(
    axum::extract::State(store): axum::extract::State<Store>,
) -> impl IntoResponse {
    let checkpoint = *store.latest_justified();
    Json(checkpoint)
}
