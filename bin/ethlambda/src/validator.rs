//! `ethlambda validator`: the beacon-chain validator client.
//!
//! It talks to a beacon node over the standard REST Beacon API and depends on
//! nothing else in this binary, so it runs against any conformant node.

use std::path::PathBuf;

use ethlambda_types::beacon::primitives::{Bytes32, ExecutionAddress, H160};
use ethlambda_validator::proposer_settings::{
    DEFAULT_GAS_LIMIT, GRAFFITI_BYTES, graffiti_from_text,
};
use ethlambda_validator::{BuilderProposals, ValidatorConfig};
use eyre::WrapErr as _;
use tokio::sync::oneshot;
use tracing::info;

use crate::shutdown::ShutdownSignals;

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

    /// The gas limit every validator targets, unless the keymanager API gives
    /// it its own.
    ///
    /// Before gloas it goes into builder registrations (with
    /// `--builder-proposals`). From gloas it goes into the proposer
    /// preferences, published for every proposal, and the beacon node builds
    /// this client's own payloads toward it too, so on a network whose gas
    /// limit is not the default, set it or every proposal pulls the limit
    /// toward 60M. Sepolia and Platåberget schedule 200000000: pass
    /// `--gas-limit 200000000` there. The network config's
    /// `GAS_LIMIT_SCHEDULE` is not read yet (#795).
    #[arg(
        long,
        default_value_t = DEFAULT_GAS_LIMIT,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub(crate) gas_limit: u64,

    /// Serve the keymanager API: keystores, remote keys, plus each validator's
    /// own fee recipient, graffiti and gas limit.
    ///
    /// Off by default because it mutates key material. It binds to
    /// `--http-address` with bearer-token auth; a deployment that exposes it
    /// beyond localhost must front it with TLS.
    #[arg(long, default_value = "false")]
    pub(crate) enable_keymanager: bool,

    /// Base URL of a Web3Signer remote signer (e.g. https://signer:9000),
    /// the default for remote keys imported through the keymanager API's
    /// `POST /eth/v1/remotekeys` without a `url` of their own.
    ///
    /// Optional: a remote key may name its own signer in that request or in
    /// `validator_definitions.yml`, and local keystores never need one.
    #[arg(long)]
    pub(crate) web3signer_url: Option<String>,

    /// Propose builder blocks: register each validator with the beacon node's
    /// builder and accept a blinded block when the builder's bid wins. Requires
    /// a beacon node started with a builder (ethlambda: `--builder`). The
    /// registrations and blinded blocks are fulu and earlier only. From gloas
    /// the builder market works through proposer preferences, which are
    /// published with or without this flag; there it only sets the boost
    /// factor that weighs p2p bids in `produceBlockV4`. Without it the factor
    /// is 0, the local payload unless it cannot be built: a node whose
    /// execution client fails at the slot may still build on a p2p bid, and
    /// that block is signed.
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

    /// Take the builder's block whenever there is a valid bid: this client
    /// sends `builder_boost_factor = u64::MAX`. The beacon node still keeps
    /// its local payload when its execution client sets
    /// `shouldOverrideBuilder`.
    #[arg(long, default_value = "false", requires = "builder_proposals")]
    pub(crate) prefer_builder_proposals: bool,

    /// The smallest builder bid, in gwei, a gloas block may be built on: the
    /// beacon node takes no p2p bid whose value plus execution payment is
    /// below it, however the boost factor weighs it.
    ///
    /// Sent as `produceBlockV4`'s `min_bid`, so gloas only. A bid floor
    /// matters most with `--prefer-builder-proposals`, which otherwise takes
    /// a 1-gwei bid over the local payload. `0` sets no floor.
    ///
    /// Taken with or without `--builder-proposals`: without it, a node whose
    /// execution client fails at the slot may still build on a pooled bid,
    /// and this is the floor that bid must clear.
    #[arg(long, default_value_t = 0)]
    pub(crate) builder_min_bid: u64,

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

    /// Doppelganger protection: sign no attestation or block for a validator
    /// until the beacon node has seen it stay silent for a full epoch, and
    /// stop if it sees one of them act meanwhile, since that is another
    /// client running the same key.
    ///
    /// Applies at every start and to every key the keymanager API imports.
    /// The price is two to three epochs of missed attestations each time; at
    /// genesis keys sign at once. Needs a beacon node serving
    /// `/eth/v1/validator/liveness`.
    #[arg(long, default_value = "false")]
    pub(crate) enable_doppelganger_protection: bool,
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
///
/// SIGINT and SIGTERM are listened for from the first line on
/// ([`listen_for_stop`]). Before the duties start, either one ends the
/// process at once; from then on it stops the client cleanly (see
/// `ethlambda_validator::run`), and three more end it at once, as they end
/// the node ([`ShutdownSignals::force_exit_on_repeats`]).
#[tokio::main]
pub(crate) async fn run(options: ValidatorOptions) -> eyre::Result<()> {
    // First, so that no point of startup leaves a signal its default action,
    // which for a container's PID 1 is to be ignored.
    let stop = listen_for_stop();
    options.validate_ports()?;
    // The same raise `run_node` makes, and for a like reason: with remote
    // keys every signing request in flight is a socket (capped per signer,
    // see `Web3Signer`), next to the beacon nodes', the metrics server's and
    // the keymanager's. On a default soft limit `connect` starts failing
    // with `EMFILE` once several signers are busy at once, and every
    // signature those requests were for fails with it.
    crate::fd_limit::raise_fd_limit().wrap_err("failed to raise RLIMIT_NOFILE")?;
    let graffiti = options.graffiti()?;
    let suggested_fee_recipient = options.suggested_fee_recipient()?;
    let builder = options.builder();
    let config = ValidatorConfig {
        beacon_nodes: options.beacon_nodes,
        graffiti,
        suggested_fee_recipient,
        validators_dir: options.validators_dir,
        secrets_dir: options.secrets_dir,
        metrics: std::net::SocketAddr::new(options.http_address, options.metrics_port),
        keymanager: options
            .enable_keymanager
            .then(|| std::net::SocketAddr::new(options.http_address, options.keymanager_port)),
        web3signer_url: options.web3signer_url,
        gas_limit: options.gas_limit,
        builder,
        builder_min_bid: options.builder_min_bid,
        init_slashing_protection: options.init_slashing_protection,
        doppelganger_protection: options.enable_doppelganger_protection,
    };
    ethlambda_validator::run(config, stop)
        .await
        .map_err(Into::into)
}

/// Listen for SIGINT and SIGTERM from here on, and return the `stop` future
/// `ethlambda_validator::run` takes.
///
/// A task of its own waits for the first signal. What it does with it
/// depends on whether the client's duties have started, which the client
/// marks by first polling `stop` (see [`Handoff`]):
///
/// - Before, it ends the process at once, with exit code 0. Nothing needs
///   draining yet: no duty has run, so nothing is signed, and the client is
///   still decrypting its keystores or first asking its beacon node for the
///   chain. Ending there is what the signal's default action did outside a
///   container, and still does for the node until it has started (see the
///   `shutdown` module). As a container's PID 1, where the default action is
///   to ignore the signal, it is what lets `docker stop` work during startup.
/// - After, it hands the signal to `stop`: the client finishes the work in
///   flight and `run` returns `Ok(())`. Three more signals end the process
///   with exit code 1 ([`ShutdownSignals::force_exit_on_repeats`]).
///
/// The task ends the process itself, rather than `run` racing startup
/// against the signal: startup decrypts the keystores inline, so `run` polls
/// nothing until that is done. The task runs meanwhile on a worker thread of
/// this multi-threaded runtime, since `run` blocks only the main one.
fn listen_for_stop() -> impl Future<Output = &'static str> {
    let mut signals = ShutdownSignals::listen();
    let (stop, handoff) = Handoff::new();
    tokio::spawn(async move {
        if let Some(signal) = handoff.route(signals.recv()).await {
            info!(
                signal,
                "Shutdown signal received before the duties started; exiting"
            );
            std::process::exit(0);
        }
        signals.force_exit_on_repeats();
    });
    stop
}

/// The signal listener's side of the client's `stop` future.
struct Handoff {
    /// Resolves once the client first polls `stop`, which it does when its
    /// duties start, or drops it unpolled, which it does when it stops before
    /// that.
    started: oneshot::Receiver<()>,
    /// Where a signal goes once the duties have started.
    stop: oneshot::Sender<&'static str>,
}

impl Handoff {
    /// A `stop` future for `ethlambda_validator::run`, and the handoff that
    /// feeds it.
    fn new() -> (impl Future<Output = &'static str>, Self) {
        let (mark_started, started) = oneshot::channel();
        let (stop, signal) = oneshot::channel();
        let stop_future = async move {
            let _ = mark_started.send(());
            match signal.await {
                Ok(signal) => signal,
                // The listener is gone without handing one on: it ended the
                // process, or the runtime is shutting down.
                Err(_) => std::future::pending().await,
            }
        };
        (stop_future, Self { started, stop })
    }

    /// Wait for `signal`, and return it if the client's duties have not
    /// started, for the caller to end the process. Once they have, it is
    /// handed to `stop` instead, and `None` is returned.
    ///
    /// A client that dropped `stop` unpolled counts as started: it is already
    /// stopping on an error, and may be letting a keymanager request finish,
    /// which an exit would cut and report as a clean stop. Such a signal goes
    /// nowhere and is only logged.
    async fn route(self, signal: impl Future<Output = &'static str>) -> Option<&'static str> {
        let Self { started, stop } = self;
        let mut signal = std::pin::pin!(signal);
        tokio::select! {
            // A start and a signal seen in the same poll count as a start:
            // the duties have started by now, so the signal is theirs to
            // drain.
            biased;
            _ = started => {}
            signal = &mut signal => return Some(signal),
        }
        let signal = signal.await;
        if stop.send(signal).is_err() {
            info!(
                signal,
                "Shutdown signal received while the client is already stopping"
            );
        }
        None
    }
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
            gas_limit: DEFAULT_GAS_LIMIT,
            enable_keymanager: false,
            web3signer_url: None,
            builder_proposals: false,
            builder_boost_factor: 100,
            prefer_builder_proposals: false,
            builder_min_bid: 0,
            init_slashing_protection: false,
            enable_doppelganger_protection: false,
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

    /// A signal before the client first polls `stop`, so before its duties
    /// start, is returned for the listener to end the process with, and
    /// `stop` never hears of it.
    #[tokio::test(start_paused = true)]
    async fn a_signal_before_the_duties_start_ends_the_process_instead_of_reaching_stop() {
        let (stop, handoff) = Handoff::new();
        let routed = handoff.route(async { "SIGTERM" }).await;
        assert_eq!(routed, Some("SIGTERM"), "the listener ends the process");
        let heard = tokio::time::timeout(std::time::Duration::from_secs(60), stop).await;
        assert!(heard.is_err(), "stop never resolves on that signal");
    }

    /// Once the client has polled `stop`, which it does when its duties
    /// start, a signal is handed to `stop`, for the client to drain, rather
    /// than ending the process.
    #[tokio::test]
    async fn a_signal_once_the_duties_have_started_is_handed_to_stop() {
        let (stop, handoff) = Handoff::new();
        let (send_signal, signal) = oneshot::channel();
        let signal = async move { signal.await.expect("one is sent") };
        let routed = tokio::spawn(handoff.route(signal));
        let mut stop = std::pin::pin!(stop);
        // The client's first poll: its duties start.
        let first = std::future::poll_fn(|cx| std::task::Poll::Ready(stop.as_mut().poll(cx))).await;
        assert!(first.is_pending(), "no signal yet");
        // Possibly before the listener has seen the start: a start and a
        // signal seen together count as a start.
        send_signal.send("SIGINT").expect("the listener waits");
        assert_eq!(stop.await, "SIGINT");
        assert_eq!(routed.await.expect("the listener ends"), None);
    }

    /// A client that drops `stop` unpolled is stopping on its own, with an
    /// error, so a signal then does not end the process as if nothing had
    /// started.
    #[tokio::test]
    async fn a_signal_once_the_client_dropped_stop_unpolled_does_not_end_the_process() {
        let (stop, handoff) = Handoff::new();
        drop(stop);
        assert_eq!(handoff.route(async { "SIGTERM" }).await, None);
    }

    #[test]
    fn the_gas_limit_defaults_to_60m_and_takes_any_positive_value() {
        assert_eq!(parse(&[]).expect("parses").gas_limit, DEFAULT_GAS_LIMIT);
        let options = parse(&["--gas-limit", "200000000"]).expect("parses");
        assert_eq!(options.gas_limit, 200_000_000);
        parse(&["--gas-limit", "0"]).expect_err("a zero gas limit is a mistake");
    }

    /// From gloas the gas limit is published whether or not builder proposals
    /// are on, so it does not require them.
    #[test]
    fn the_gas_limit_does_not_need_builder_proposals() {
        parse(&["--gas-limit", "30000000"]).expect("parses alone");
    }

    #[test]
    fn builder_proposals_are_off_by_default() {
        assert_eq!(parse(&[]).expect("parses").builder(), None);
    }

    /// Opt-in, as in Lighthouse and Prysm: it costs every start two to three
    /// epochs of attestations.
    #[test]
    fn doppelganger_protection_is_off_unless_asked_for() {
        assert!(!parse(&[]).expect("parses").enable_doppelganger_protection);
        let options = parse(&["--enable-doppelganger-protection"]).expect("parses");
        assert!(options.enable_doppelganger_protection);
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
                boost_factor: u64::MAX,
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

    /// The floor travels with either way of weighing bids, in gwei as given,
    /// and without builder proposals too: a node whose local build fails may
    /// still build on a pooled bid, which the floor then applies to.
    #[test]
    fn a_min_bid_is_taken_with_or_without_builder_proposals() {
        let options =
            parse(&["--builder-proposals", "--builder-min-bid", "1000000"]).expect("parses");
        assert_eq!(options.builder_min_bid, 1_000_000);
        assert_eq!(
            options.builder(),
            Some(BuilderProposals { boost_factor: 100 })
        );
        let options = parse(&[
            "--builder-proposals",
            "--prefer-builder-proposals",
            "--builder-min-bid",
            "5",
        ])
        .expect("parses");
        assert_eq!(options.builder_min_bid, 5);
        assert_eq!(
            options.builder(),
            Some(BuilderProposals {
                boost_factor: u64::MAX
            })
        );
        let options = parse(&["--builder-min-bid", "1000000"]).expect("parses");
        assert_eq!(options.builder_min_bid, 1_000_000);
        assert_eq!(options.builder(), None);
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
