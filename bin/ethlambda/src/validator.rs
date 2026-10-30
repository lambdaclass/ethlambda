//! `ethlambda validator`: the beacon-chain validator client.
//!
//! It talks to a beacon node over the standard REST Beacon API and depends on
//! nothing else in this binary, so it runs against any conformant node.

use std::path::PathBuf;

use ethlambda_types::beacon::primitives::{Bytes32, ExecutionAddress, H160};
use ethlambda_validator::proposer_settings::{GRAFFITI_BYTES, graffiti_from_text};
use ethlambda_validator::{BuilderProposals, ValidatorConfig};

/// An execution address is exactly this wide.
const ADDRESS_BYTES: usize = 20;

#[derive(Debug, clap::Args)]
pub(crate) struct ValidatorOptions {
    /// Base URL(s) of the beacon node's HTTP API (e.g. http://localhost:5052).
    ///
    /// Several may be supplied, comma-separated or by repeating the flag. They
    /// are tried in order and the first that answers is used, so the order is
    /// a preference, not a load-balancing policy.
    #[arg(long, value_delimiter = ',', required = true)]
    pub(crate) beacon_nodes: Vec<String>,

    /// Directory holding the EIP-2335 keystores and `validator_definitions.yml`.
    /// Without that file, keystores in the Lighthouse layout
    /// (`<0xpubkey>/voting-keystore.json`, password in
    /// `--secrets-dir/<0xpubkey>`) are discovered and the file is written.
    #[arg(long)]
    pub(crate) validators_dir: PathBuf,

    /// Directory holding one password file per keystore.
    #[arg(long)]
    pub(crate) secrets_dir: PathBuf,

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

    /// Propose builder blocks: register each validator with the beacon node's
    /// builder and accept a blinded block when the builder's bid wins. Requires
    /// a beacon node started with a builder (ethlambda: `--builder`). Fulu and
    /// earlier only; from gloas the builder market works through proposer
    /// preferences instead.
    #[arg(long, default_value = "false")]
    pub(crate) builder_proposals: bool,

    /// How a builder's bid is weighed against the local payload: the local
    /// payload wins iff `local >= factor * bid / 100`. 100 compares them as
    /// they are; 0 prefers the local payload unless it cannot be built.
    #[arg(
        long,
        default_value = "100",
        requires = "builder_proposals",
        conflicts_with = "prefer_builder_proposals"
    )]
    pub(crate) builder_boost_factor: u64,

    /// Take the builder's block whenever there is a valid bid, unless the
    /// execution client asks to override the builder (sends
    /// `builder_boost_factor = u64::MAX`).
    #[arg(long, default_value = "false", requires = "builder_proposals")]
    pub(crate) prefer_builder_proposals: bool,
}

impl ValidatorOptions {
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

    /// The builder configuration these flags describe, or `None` when builder
    /// proposals are off.
    ///
    /// `--prefer-builder-proposals` wins over the factor by construction:
    /// clap refuses the two together, so at most one is ever set.
    pub(crate) fn builder(&self) -> Option<BuilderProposals> {
        self.builder_proposals.then_some(BuilderProposals {
            boost_factor: if self.prefer_builder_proposals {
                u64::MAX
            } else {
                self.builder_boost_factor
            },
        })
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
    let builder = options.builder();
    ethlambda_validator::run(ValidatorConfig {
        beacon_nodes: options.beacon_nodes,
        graffiti,
        suggested_fee_recipient,
        validators_dir: options.validators_dir,
        secrets_dir: options.secrets_dir,
        metrics: std::net::SocketAddr::new(options.http_address, options.metrics_port),
        keymanager: options
            .enable_keymanager
            .then(|| std::net::SocketAddr::new(options.http_address, options.keymanager_port)),
        builder,
    })
    .await
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(graffiti: &str) -> ValidatorOptions {
        ValidatorOptions {
            beacon_nodes: vec!["http://localhost:5052".to_string()],
            validators_dir: PathBuf::from("/tmp/validators"),
            secrets_dir: PathBuf::from("/tmp/secrets"),
            http_address: "127.0.0.1".parse().expect("valid address"),
            keymanager_port: 5062,
            metrics_port: 5064,
            graffiti: graffiti.to_string(),
            suggested_fee_recipient: None,
            enable_keymanager: false,
            builder_proposals: false,
            builder_boost_factor: 100,
            prefer_builder_proposals: false,
        }
    }

    /// Parse a command line the way the binary does, so `requires` and
    /// `conflicts_with` are exercised rather than assumed.
    fn parse(extra: &[&str]) -> Result<ValidatorOptions, clap::Error> {
        use clap::Parser as _;

        #[derive(clap::Parser)]
        struct Cli {
            #[command(flatten)]
            options: ValidatorOptions,
        }
        let base = [
            "ethlambda",
            "--beacon-nodes",
            "http://localhost:5052",
            "--validators-dir",
            "/tmp/v",
            "--secrets-dir",
            "/tmp/s",
        ];
        Cli::try_parse_from(base.iter().chain(extra)).map(|cli| cli.options)
    }

    #[test]
    fn builder_proposals_are_off_by_default() {
        assert_eq!(parse(&[]).expect("parses").builder(), None);
    }

    #[test]
    fn builder_proposals_default_to_a_factor_of_100() {
        let options = parse(&["--builder-proposals"]).expect("parses");
        assert_eq!(
            options.builder(),
            Some(BuilderProposals { boost_factor: 100 })
        );
    }

    #[test]
    fn an_explicit_factor_is_used() {
        let options =
            parse(&["--builder-proposals", "--builder-boost-factor", "250"]).expect("parses");
        assert_eq!(
            options.builder(),
            Some(BuilderProposals { boost_factor: 250 })
        );
    }

    #[test]
    fn preferring_the_builder_sends_the_maximum_factor() {
        let options =
            parse(&["--builder-proposals", "--prefer-builder-proposals"]).expect("parses");
        assert_eq!(
            options.builder(),
            Some(BuilderProposals {
                boost_factor: u64::MAX
            })
        );
    }

    #[test]
    fn the_factor_and_the_preference_need_builder_proposals() {
        parse(&["--builder-boost-factor", "250"])
            .expect_err("a factor with builder proposals off is a mistake");
        parse(&["--prefer-builder-proposals"])
            .expect_err("a preference with builder proposals off is a mistake");
    }

    #[test]
    fn the_factor_and_the_preference_conflict() {
        parse(&[
            "--builder-proposals",
            "--builder-boost-factor",
            "250",
            "--prefer-builder-proposals",
        ])
        .expect_err("the two say different things");
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
