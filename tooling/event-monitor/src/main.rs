use std::path::{Path, PathBuf};

use clap::Parser;
use tokio::net::TcpListener;
use tokio::sync::watch;

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

    // Carries the connect/read timeouts every SSE subscription depends on to
    // fail rather than hang; see `collector::build_client`.
    let client = collector::build_client()?;
    let timing = timing::bootstrap(&config.nodes, config.timing_overrides(), &client)
        .await
        .inspect_err(|err| tracing::error!(%err, "failed to bootstrap slot timing"))?;
    tracing::info!(
        genesis_time = timing.genesis_time,
        ms_per_slot = timing.ms_per_slot,
        intervals_per_slot = timing.intervals_per_slot,
        "resolved slot geometry"
    );
    // Geometry is shared by watch channel rather than a plain Arc so a
    // regenerated genesis can be picked up without a restart: the refresher
    // publishes, collectors re-read per frame, and `/api/meta` reads per request.
    let (timing_tx, timing_rx) = watch::channel(timing);

    let hub = Hub::new(config.history_slots as u64);
    for node in &config.nodes {
        tokio::spawn(collector::run_collector(
            node.clone(),
            config.topics.clone(),
            timing_rx.clone(),
            hub.clone(),
            client.clone(),
        ));
    }
    tokio::spawn(timing::run_refresher(
        config.nodes.clone(),
        config.timing_overrides(),
        client.clone(),
        timing_tx,
        hub.clone(),
    ));

    let meta = server::MetaConfig::new(&config);
    let static_dir = Path::new(&config.static_dir).to_path_buf();
    let app = server::build_router(hub, meta, timing_rx, &static_dir);

    let listen_addr = config.listen;
    let listener = TcpListener::bind(listen_addr).await?;
    tracing::info!(%listen_addr, "event-monitor dashboard ready; open this address in a browser");
    axum::serve(listener, app).await?;

    Ok(())
}
