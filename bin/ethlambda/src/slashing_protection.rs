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

use ethlambda_validator::beacon_node::dto::{encode_hex, parse_pubkey};
use ethlambda_validator::slashing_protection::SlashingProtection;
use tracing::{info, warn};

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
                    .map(|text| {
                        parse_pubkey(text).map_err(|err| eyre::eyre!("--pubkeys {text}: {err}"))
                    })
                    .collect::<Result<Vec<_>, _>>()?
            };
            // A requested key with no record is left out of the file rather
            // than listed as never having signed, so say so: an operator
            // moving that key would otherwise find out at the other end.
            let mut exported = 0;
            for pubkey in &pubkeys {
                if protection.contains(pubkey) {
                    exported += 1;
                } else {
                    warn!(
                        pubkey = %encode_hex(&pubkey.0),
                        "No slashing-protection record for this validator; it is not in the export"
                    );
                }
            }
            let interchange = protection.export(&pubkeys)?;
            write_export(&file, &interchange)
                .map_err(|err| eyre::eyre!("{}: {err}", file.display()))?;
            info!(
                validators = exported,
                file = %file.display(),
                "Exported slashing-protection history"
            );
        }
    }
    Ok(())
}

/// Write `interchange` to a new file at `path`, refusing an existing one.
///
/// Private to the owner, like the record it was taken from. A write that
/// fails partway removes what it left, so the retry is not refused for a file
/// this run created and never finished.
fn write_export(path: &std::path::Path, interchange: &str) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut output = options.open(path)?;
    output
        .write_all(interchange.as_bytes())
        .and_then(|()| output.sync_all())
        .inspect_err(|_| {
            let _ = std::fs::remove_file(path);
        })
}
