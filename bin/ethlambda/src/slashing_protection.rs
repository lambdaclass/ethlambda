//! `ethlambda slashing-protection`: move a validator client's EIP-3076 history
//! in and out of its `--validators-dir`.
//!
//! Offline on purpose. It takes the same lock the validator client holds while
//! it runs, so it refuses while one is running there: history imported under a
//! running client could arrive after the client had already signed past it.
//! No beacon node is needed either: the record names its own chain, and an
//! import into a directory with no record yet creates one for the chain the
//! interchange names, which the client checks against its beacon node at its
//! next start.

use std::io::Write as _;
use std::path::PathBuf;

use ethlambda_validator::beacon_node::dto::parse_pubkey;
use ethlambda_validator::slashing_protection::SlashingProtection;
use tracing::info;

#[derive(Debug, clap::Args)]
pub(crate) struct SlashingProtectionOptions {
    #[command(subcommand)]
    pub(crate) action: Action,
}

#[derive(Debug, clap::Subcommand)]
pub(crate) enum Action {
    /// Merge an EIP-3076 interchange file (complete or minimal, version 5) into
    /// the record, never lowering what is already there.
    Import {
        /// The validator client's `--validators-dir`.
        #[arg(long)]
        validators_dir: PathBuf,
        /// The interchange file, as exported by this or another client.
        file: PathBuf,
    },
    /// Write the record as a minimal EIP-3076 interchange file (version 5).
    Export {
        /// The validator client's `--validators-dir`.
        #[arg(long)]
        validators_dir: PathBuf,
        /// Only these validators, `0x`-prefixed, comma-separated or repeated.
        /// Every validator with a record when omitted.
        #[arg(long, value_delimiter = ',')]
        pubkeys: Vec<String>,
        /// Where to write it. Refused if it exists, rather than overwritten.
        file: PathBuf,
    },
}

pub(crate) fn run(options: SlashingProtectionOptions) -> eyre::Result<()> {
    match options.action {
        Action::Import {
            validators_dir,
            file,
        } => {
            let interchange = std::fs::read_to_string(&file)
                .map_err(|err| eyre::eyre!("{}: {err}", file.display()))?;
            let chain = SlashingProtection::interchange_chain(&interchange)?;
            let mut protection = SlashingProtection::open_offline(&validators_dir, Some(chain))?;
            let validators = protection.import(&interchange)?;
            info!(
                validators,
                file = %file.display(),
                "Imported slashing-protection history"
            );
        }
        Action::Export {
            validators_dir,
            pubkeys,
            file,
        } => {
            let protection = SlashingProtection::open_offline(&validators_dir, None)?;
            let pubkeys = if pubkeys.is_empty() {
                protection.pubkeys()
            } else {
                pubkeys
                    .iter()
                    .map(|text| parse_pubkey(text))
                    .collect::<Result<Vec<_>, _>>()?
            };
            let interchange = protection.export(&pubkeys)?;
            let mut output = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&file)
                .map_err(|err| eyre::eyre!("{}: {err}", file.display()))?;
            output
                .write_all(interchange.as_bytes())
                .and_then(|()| output.sync_all())
                .map_err(|err| eyre::eyre!("{}: {err}", file.display()))?;
            info!(
                validators = pubkeys.len(),
                file = %file.display(),
                "Exported slashing-protection history"
            );
        }
    }
    Ok(())
}
