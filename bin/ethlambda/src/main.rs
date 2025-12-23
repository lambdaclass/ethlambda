use clap::Parser;
use ethereum_types::{H256, U256};
use serde::{Deserialize, Serialize};

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
}

fn main() {
    let options = CliOptions::parse();
    println!("{ASCII_ART}");
    let genesis_json = std::fs::read_to_string(&options.custom_genesis_json_file)
        .expect("Failed to read genesis.json");
    let genesis: Genesis =
        serde_json::from_str(&genesis_json).expect("Failed to parse genesis.json");

    println!("Shutting down...");
}
