mod fetcher;
mod run;

use clap::{Parser, Subcommand, ValueEnum};

/// Replay real ethlambda state transitions through the STF prover.
#[derive(Parser)]
#[command(name = "replay")]
struct Cli {
    /// RPC URL of a running ethlambda node.
    #[arg(long, env = "REPLAY_RPC_URL", default_value = "http://127.0.0.1:5052")]
    rpc_url: String,
    /// Guest path per transition (SP1 backend only; the exec backend always executes).
    #[arg(long, value_enum, default_value_t = Action::Execute)]
    action: Action,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Replay a single block, addressed by slot or root.
    Block { id: String },
    /// Replay an inclusive range of slots.
    Blocks { from: u64, to: u64 },
}

#[derive(Clone, Copy, ValueEnum)]
enum Action {
    Execute,
    Prove,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let cli = Cli::parse();
    let client = reqwest::Client::new();

    let ids: Vec<String> = match &cli.command {
        Command::Block { id } => vec![id.clone()],
        Command::Blocks { from, to } => (*from..=*to).map(|slot| slot.to_string()).collect(),
    };

    println!("Fetching {} block(s) from {}", ids.len(), cli.rpc_url);
    let mut transitions = Vec::with_capacity(ids.len());
    for id in &ids {
        transitions.push(fetcher::fetch_transition(&client, &cli.rpc_url, id).await?);
    }

    run::run(cli.action, &transitions).await
}
