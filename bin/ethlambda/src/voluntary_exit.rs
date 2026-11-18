//! `ethlambda voluntary-exit`: sign one validator's voluntary exit and hand it
//! to a beacon node.
//!
//! A command of its own rather than part of `ethlambda validator`: it takes a
//! single keystore and none of the client's flags, and it runs once and ends.
//! Like the client it talks to a beacon node over the standard REST Beacon
//! API and depends on nothing else in this binary, so it runs against any
//! conformant node.

use std::path::PathBuf;

use ethlambda_validator::exit::{self, CONFIRMATION_PHRASE, ExitConfig, ExitOptions, Outcome};

#[derive(Debug, clap::Args)]
pub(crate) struct VoluntaryExitOptions {
    /// Path to the validator's EIP-2335 voting keystore.
    #[arg(long)]
    pub(crate) keystore: PathBuf,

    /// Path to the file holding the keystore's password.
    #[arg(long)]
    pub(crate) password_file: PathBuf,

    /// Base URL of the beacon node's HTTP API.
    #[arg(long, default_value = "http://localhost:5052")]
    pub(crate) beacon_node: String,

    /// The exit's epoch, before which the chain refuses it. Defaults to the
    /// current one. A later epoch needs --presign, since a node refuses an
    /// exit whose epoch has not come.
    #[arg(long)]
    pub(crate) epoch: Option<u64>,

    /// Sign the exit and print it as JSON on stdout without publishing it.
    #[arg(long, default_value = "false")]
    pub(crate) presign: bool,

    /// Publish without asking for the confirmation phrase. Use with care.
    #[arg(long, default_value = "false")]
    pub(crate) no_confirmation: bool,

    /// Return as soon as the beacon node has accepted the exit, without
    /// waiting for the chain to process it.
    #[arg(long, default_value = "false")]
    pub(crate) no_wait: bool,
}

/// Sign and publish one validator's voluntary exit, on a runtime of its own:
/// each sub-command picks its concurrency model, and `main` stays synchronous.
///
/// A run that did not get the confirmation phrase ends with a failing status.
/// Nothing went wrong, but nothing was published either, and that is what a
/// script reading the status asked about: one run without `--no-confirmation`
/// and with nobody at stdin reads an empty line, and must not look like an
/// exit that went out.
#[tokio::main]
pub(crate) async fn run(options: VoluntaryExitOptions) -> eyre::Result<()> {
    let outcome = exit::run(ExitConfig {
        keystore: options.keystore,
        password_file: options.password_file,
        beacon_node: options.beacon_node,
        options: ExitOptions {
            epoch: options.epoch,
            presign: options.presign,
            no_confirmation: options.no_confirmation,
            no_wait: options.no_wait,
        },
    })
    .await?;
    match outcome {
        Outcome::Presigned(signed) => exit::print_presigned(&signed)?,
        Outcome::NotConfirmed => eyre::bail!(
            "the voluntary exit was not published: the confirmation phrase is \
             \"{CONFIRMATION_PHRASE}\""
        ),
        Outcome::Published { .. } => {}
    }
    Ok(())
}
