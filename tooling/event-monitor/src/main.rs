use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::Parser;
use tokio::net::TcpListener;

use event_monitor::config::Config;
use event_monitor::hub::Hub;
use event_monitor::{collector, server, timing};

/// Live arrival-time monitor for lean-consensus (ethlambda) nodes.
#[derive(Parser, Debug)]
#[command(name = "event-monitor")]
struct Args {
    /// Path to the TOML config file.
    #[arg(long, default_value = "config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    let config = Config::load(&args.config).inspect_err(|err| {
        tracing::error!(%err, config = %args.config.display(), "failed to load config");
    })?;

    let client = reqwest::Client::new();
    let timing = timing::bootstrap(&config.nodes, config.timing_overrides(), &client)
        .await
        .inspect_err(|err| tracing::error!(%err, "failed to bootstrap slot timing"))?;
    tracing::info!(
        genesis_time = timing.genesis_time,
        ms_per_slot = timing.ms_per_slot,
        intervals_per_slot = timing.intervals_per_slot,
        "resolved slot geometry"
    );
    let timing = Arc::new(timing);

    let hub = Hub::new(config.history_slots as u64);
    for node in &config.nodes {
        tokio::spawn(collector::run_collector(
            node.clone(),
            config.topics.clone(),
            timing.clone(),
            hub.clone(),
            client.clone(),
        ));
    }

    let meta = server::Meta::new(&config, &timing);
    let static_dir = Path::new(&config.static_dir).to_path_buf();
    let app = server::build_router(hub, meta, &static_dir);

    let listen_addr = config.listen;
    let listener = TcpListener::bind(listen_addr).await?;
    tracing::info!(%listen_addr, "event-monitor dashboard ready; open this address in a browser");
    axum::serve(listener, app).await?;

    Ok(())
}
