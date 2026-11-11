//! `ethlambda validator`: the beacon-chain validator client, and
//! `ethlambda validator exit`, which signs and publishes one validator's
//! voluntary exit.
//!
//! Both talk to a beacon node over the standard REST Beacon API and depend on
//! nothing else in this binary, so they run against any conformant node.

use std::path::PathBuf;

use ethlambda_types::beacon::primitives::{Bytes32, ExecutionAddress, H160};
use ethlambda_validator::ValidatorConfig;
use ethlambda_validator::exit::{self, CONFIRMATION_PHRASE, ExitConfig, Outcome};
use ethlambda_validator::proposer_settings::{GRAFFITI_BYTES, graffiti_from_text};

/// An execution address is exactly this wide.
const ADDRESS_BYTES: usize = 20;

// The three required flags are `Option`s that clap still marks `required`.
// `subcommand_negates_reqs` on `Command::Validator` lets `validator exit` omit
// them, and clap's derive builds this struct for that invocation too, which a
// plain `PathBuf` field refuses with its own "required argument was not
// provided". Clap still refuses a client run without them, so `None` never
// reaches [`run`]; [`ValidatorOptions::required`] says so rather than unwrap.
#[derive(Debug, clap::Args)]
pub(crate) struct ValidatorOptions {
    /// `None` runs the client. See `Command::Validator` for why the client's
    /// required flags are not demanded of, nor accepted beside, a sub-command.
    #[command(subcommand)]
    pub(crate) command: Option<ValidatorCommand>,

    /// Base URL(s) of the beacon node's HTTP API (e.g. http://localhost:5052).
    ///
    /// Several may be supplied, comma-separated or by repeating the flag. They
    /// are tried in order and the first that answers is used, so the order is
    /// a preference, not a load-balancing policy.
    #[arg(long, value_delimiter = ',', required = true)]
    pub(crate) beacon_nodes: Option<Vec<String>>,

    /// Directory holding the EIP-2335 keystores and `validator_definitions.yml`.
    /// Without that file, keystores in the Lighthouse layout
    /// (`<0xpubkey>/voting-keystore.json`, password in
    /// `--secrets-dir/<0xpubkey>`) are discovered and the file is written.
    #[arg(long, required = true)]
    pub(crate) validators_dir: Option<PathBuf>,

    /// Directory holding one password file per keystore.
    #[arg(long, required = true)]
    pub(crate) secrets_dir: Option<PathBuf>,

    /// Bind address for the metrics and keymanager servers.
    #[arg(long, default_value = "127.0.0.1")]
    pub(crate) http_address: std::net::IpAddr,

    /// Port for the keymanager API. Only bound with `--enable-keymanager`.
    #[arg(long, default_value = "5062")]
    pub(crate) keymanager_port: u16,

    /// Port for the Prometheus metrics server.
    #[arg(long, default_value = "5064")]
    pub(crate) metrics_port: u16,

    /// Text to put in the graffiti field of every block this client proposes,
    /// unless the keymanager API gives a validator its own.
    ///
    /// At most 32 bytes once encoded as UTF-8, right-padded with zeros.
    /// Consensus never reads it.
    ///
    /// Empty by default. An ethlambda beacon node appends its own and its
    /// execution client's codes and commits to whatever this is, so an empty
    /// graffiti still names both clients; other beacon nodes apply their own
    /// policy.
    #[arg(long, default_value = "")]
    pub(crate) graffiti: String,

    /// Execution address to receive block rewards from blocks this client
    /// proposes, as `0x`-prefixed hex, for every validator the keymanager API
    /// gives no address of its own.
    ///
    /// Optional, and it should not be. Without it the beacon node picks an
    /// address of its own, which will not be yours, and every block this client
    /// proposes pays its execution-layer rewards there. It stays optional
    /// because a client running only attester duties has no use for it, and
    /// startup warns loudly when it is absent.
    #[arg(long)]
    pub(crate) suggested_fee_recipient: Option<String>,

    /// Serve the keymanager API: keystores, plus each validator's own fee
    /// recipient, graffiti and gas limit, which are held in memory only.
    ///
    /// Off by default because it mutates key material. It binds to
    /// `--http-address` with bearer-token auth; a deployment that exposes it
    /// beyond localhost must front it with TLS.
    #[arg(long, default_value = "false")]
    pub(crate) enable_keymanager: bool,

    /// Register every loaded key that has no slashing-protection record,
    /// instead of refusing to start.
    ///
    /// DANGEROUS. Use it only for keys that are brand new, or that have signed
    /// nothing anywhere for at least two epochs. A key is registered as never
    /// having signed, so nothing here stops it from signing again what it
    /// signed elsewhere a moment ago; and two idle epochs rule out a double
    /// vote, not a surround of an older vote, which only the key's own history
    /// can. Keys that already have a record keep it, so the flag never lowers
    /// one; remove it once the keys are registered.
    #[arg(long, default_value = "false")]
    pub(crate) init_slashing_protection: bool,
}

/// What `ethlambda validator` can do besides run as a client.
#[derive(Debug, clap::Subcommand)]
pub(crate) enum ValidatorCommand {
    /// Sign a voluntary exit for one validator and publish it to a beacon node.
    ///
    /// Irreversible once the chain processes it. Asks for a confirmation phrase
    /// before publishing unless --no-confirmation is given.
    Exit(ExitOptions),
}

#[derive(Debug, clap::Args)]
pub(crate) struct ExitOptions {
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

impl ValidatorOptions {
    /// The flags clap requires of a client run, which only `validator exit`
    /// may omit (see the struct's comment). A `None` here is a bug in the
    /// command-line wiring, reported as such rather than unwrapped.
    fn required(self) -> eyre::Result<(Vec<String>, PathBuf, PathBuf)> {
        match (self.beacon_nodes, self.validators_dir, self.secrets_dir) {
            (Some(beacon_nodes), Some(validators_dir), Some(secrets_dir)) => {
                Ok((beacon_nodes, validators_dir, secrets_dir))
            }
            _ => eyre::bail!(
                "--beacon-nodes, --validators-dir and --secrets-dir are required to run the \
                 validator client"
            ),
        }
    }

    /// The graffiti bytes, or an error naming the limit if the text is too
    /// long.
    ///
    /// Truncating instead would be worse than refusing: the operator asked for
    /// a string, and a silently clipped one appears in every block they
    /// propose, where they are least likely to be looking for it.
    ///
    /// Measured in bytes rather than characters, because that is what the field
    /// holds. A 32-character string of anything outside ASCII does not fit, and
    /// saying so in bytes is the only way the message helps.
    pub(crate) fn graffiti(&self) -> eyre::Result<Bytes32> {
        graffiti_from_text(&self.graffiti).ok_or_else(|| {
            eyre::eyre!(
                "--graffiti is {} bytes encoded as UTF-8; the field holds {GRAFFITI_BYTES}",
                self.graffiti.len()
            )
        })
    }

    /// The configured fee recipient, or `None` if the operator named none.
    ///
    /// Rejected here rather than at first use: a malformed address is a startup
    /// mistake, and finding out about it when a proposal duty finally arrives,
    /// possibly days later, is the worst possible time.
    pub(crate) fn suggested_fee_recipient(&self) -> eyre::Result<Option<ExecutionAddress>> {
        let Some(text) = &self.suggested_fee_recipient else {
            return Ok(None);
        };
        let digits = text.strip_prefix("0x").unwrap_or(text);
        let bytes = hex::decode(digits)
            .map_err(|err| eyre::eyre!("--suggested-fee-recipient is not hex: {err}"))?;
        let bytes: [u8; ADDRESS_BYTES] = bytes.try_into().map_err(|got: Vec<u8>| {
            eyre::eyre!(
                "--suggested-fee-recipient is {} bytes, expected {ADDRESS_BYTES}",
                got.len()
            )
        })?;
        Ok(Some(H160(bytes)))
    }

    /// Reject a port clash before anything binds, the way the node's own
    /// options do.
    pub(crate) fn validate_ports(&self) -> eyre::Result<()> {
        if self.enable_keymanager && self.keymanager_port == self.metrics_port {
            eyre::bail!(
                "--keymanager-port and --metrics-port are both {}; they must differ",
                self.keymanager_port
            );
        }
        Ok(())
    }
}

/// Boot its own tokio runtime and run until the process is stopped.
///
/// `main` stays synchronous, the same way it does for the `node` sub-command:
/// each sub-command picks its own concurrency model rather than being forced
/// onto one runtime shared with the others.
#[tokio::main]
pub(crate) async fn run(options: ValidatorOptions) -> eyre::Result<()> {
    options.validate_ports()?;
    let graffiti = options.graffiti()?;
    let suggested_fee_recipient = options.suggested_fee_recipient()?;
    let metrics = std::net::SocketAddr::new(options.http_address, options.metrics_port);
    let keymanager = options
        .enable_keymanager
        .then(|| std::net::SocketAddr::new(options.http_address, options.keymanager_port));
    let init_slashing_protection = options.init_slashing_protection;
    let (beacon_nodes, validators_dir, secrets_dir) = options.required()?;
    ethlambda_validator::run(ValidatorConfig {
        beacon_nodes,
        graffiti,
        suggested_fee_recipient,
        validators_dir,
        secrets_dir,
        metrics,
        keymanager,
        init_slashing_protection,
    })
    .await
    .map_err(Into::into)
}

/// Sign and publish one validator's voluntary exit, on its own runtime like
/// [`run`].
///
/// A run that did not get the confirmation phrase ends with a failing status.
/// Nothing went wrong, but nothing was published either, and that is what a
/// script reading the status asked about: one run without `--no-confirmation`
/// and with nobody at stdin reads an empty line, and must not look like an
/// exit that went out.
#[tokio::main]
pub(crate) async fn exit(options: ExitOptions) -> eyre::Result<()> {
    let outcome = exit::run(ExitConfig {
        keystore: options.keystore,
        password_file: options.password_file,
        beacon_node: options.beacon_node,
        options: exit::ExitOptions {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn options(graffiti: &str) -> ValidatorOptions {
        ValidatorOptions {
            command: None,
            beacon_nodes: Some(vec!["http://localhost:5052".to_string()]),
            validators_dir: Some(PathBuf::from("/tmp/validators")),
            secrets_dir: Some(PathBuf::from("/tmp/secrets")),
            http_address: "127.0.0.1".parse().expect("valid address"),
            keymanager_port: 5062,
            metrics_port: 5064,
            graffiti: graffiti.to_string(),
            suggested_fee_recipient: None,
            enable_keymanager: false,
            init_slashing_protection: false,
        }
    }

    #[test]
    fn the_default_graffiti_is_empty() {
        let bytes = options("").graffiti().expect("valid");
        assert_eq!(bytes, Bytes32::ZERO);
    }

    #[test]
    fn graffiti_text_is_right_padded_with_zeros() {
        let bytes = options("hello").graffiti().expect("valid");
        assert_eq!(&bytes.0[..5], b"hello");
        assert!(
            bytes.0[5..].iter().all(|byte| *byte == 0),
            "the rest of the field must be zero"
        );
    }

    #[test]
    fn graffiti_of_exactly_the_field_width_is_accepted() {
        let text = "a".repeat(GRAFFITI_BYTES);
        let bytes = options(&text).graffiti().expect("32 bytes fits exactly");
        assert_eq!(bytes.0, text.as_bytes());
    }

    #[test]
    fn graffiti_one_byte_too_long_is_refused_rather_than_truncated() {
        let text = "a".repeat(GRAFFITI_BYTES + 1);
        let err = options(&text)
            .graffiti()
            .expect_err("a clipped graffiti in every block is worse than a refusal at startup");
        assert!(
            err.to_string().contains("33 bytes"),
            "the message must say how long the input actually was, got {err}"
        );
    }

    fn with_fee_recipient(text: &str) -> ValidatorOptions {
        ValidatorOptions {
            suggested_fee_recipient: Some(text.to_string()),
            ..options("")
        }
    }

    #[test]
    fn no_fee_recipient_flag_means_none() {
        assert_eq!(
            options("").suggested_fee_recipient().expect("valid"),
            None,
            "an absent flag is not an error; startup warns instead"
        );
    }

    #[test]
    fn a_fee_recipient_is_read_with_or_without_the_hex_prefix() {
        let expected = H160([0xab; ADDRESS_BYTES]);
        let prefixed = format!("0x{}", "ab".repeat(ADDRESS_BYTES));
        assert_eq!(
            with_fee_recipient(&prefixed)
                .suggested_fee_recipient()
                .expect("valid"),
            Some(expected)
        );
        assert_eq!(
            with_fee_recipient(&"ab".repeat(ADDRESS_BYTES))
                .suggested_fee_recipient()
                .expect("valid"),
            Some(expected)
        );
    }

    /// A truncated or over-long address is refused at startup rather than at
    /// first use. A proposal duty can be days away, which is the worst moment
    /// to discover a typo in a flag.
    #[test]
    fn a_fee_recipient_of_the_wrong_length_is_refused_at_startup() {
        let err = with_fee_recipient("0xabab")
            .suggested_fee_recipient()
            .expect_err("two bytes is not an address");
        assert!(err.to_string().contains("2 bytes"), "got {err}");
    }

    #[test]
    fn a_fee_recipient_that_is_not_hex_is_refused() {
        let err = with_fee_recipient("0xzz")
            .suggested_fee_recipient()
            .expect_err("not hex");
        assert!(err.to_string().contains("not hex"), "got {err}");
    }

    /// The limit is bytes, not characters. Thirty-two multi-byte characters
    /// look like they fit and do not, and an operator told "32 characters"
    /// would have no way to work out why.
    #[test]
    fn a_multibyte_string_is_measured_in_bytes() {
        let text = "\u{00e9}".repeat(17); // 17 characters, 34 bytes.
        assert_eq!(text.chars().count(), 17);
        assert!(text.len() > GRAFFITI_BYTES);
        let err = options(&text)
            .graffiti()
            .expect_err("34 bytes does not fit");
        assert!(
            err.to_string().contains("34 bytes"),
            "the message must count bytes, not characters, got {err}"
        );
    }
}
