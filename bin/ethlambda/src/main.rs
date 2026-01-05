use clap::Parser;
use ethlambda_p2p::{parse_validators_file, start_p2p};
use ethlambda_types::{genesis::Genesis, state::State};

const ASCII_ART: &str = r#"
      _   _     _                 _         _
  ___| |_| |__ | | __ _ _ __ ___ | |__   __| | __ _
 / _ \ __| '_ \| |/ _` | '_ ` _ \| '_ \ / _` |/ _` |
|  __/ |_| | | | | (_| | | | | | | |_) | (_| | (_| |
 \___|\__|_| |_|_|\__,_|_| |_| |_|_.__/ \__,_|\__,_|
"#;

#[derive(Debug, clap::Parser)]
struct CliOptions {
    #[arg(long)]
    custom_genesis_json_file: String,
    #[arg(long)]
    validators_file: String,
    #[arg(long)]
    gossipsub_port: u16,
}

#[tokio::main]
async fn main() {
    let options = CliOptions::parse();

    println!("{ASCII_ART}");

    let genesis_json = std::fs::read_to_string(&options.custom_genesis_json_file)
        .expect("Failed to read genesis.json");
    let genesis: Genesis =
        serde_json::from_str(&genesis_json).expect("Failed to parse genesis.json");

    let initial_state = State::from_genesis(&genesis);

    let bootnodes = parse_validators_file(&options.validators_file);

    start_p2p(bootnodes, options.gossipsub_port);

    tokio::signal::ctrl_c()
        .await
        .expect("Failed to listen for ctrl-c signal");

    println!("Shutting down...");
}
