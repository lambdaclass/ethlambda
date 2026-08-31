//! Sub-command definition and dispatch.
//!
//! `node` and `benchmark` are ordinary clap sub-commands, so clap owns their
//! help, usage lines and error messages. The one thing clap cannot express is a
//! *default* sub-command, and the node needs one: the Dockerfile,
//! lean-quickstart, the hive shim and the devnet skills all invoke the binary as
//! a bare list of node flags, from before there was anything else to run. That
//! form keeps working because a missing sub-command is filled in as `node`
//! before parsing — see [`default_subcommand`].

use std::ffi::OsString;

use clap::Parser;

use crate::benchmark::BenchmarkOptions;
use crate::cli::NodeOptions;
use crate::version;

/// Tokens that already say what to run, so no default is inserted ahead of
/// them. `help` is clap's own generated sub-command (`ethlambda help node`).
const EXPLICIT: &[&str] = &[NODE, BENCHMARK, "help", "-h", "--help", "-V", "--version"];

const NODE: &str = "node";
const BENCHMARK: &str = "benchmark";

#[derive(Debug, clap::Parser)]
#[command(
    name = "ethlambda",
    author = "LambdaClass",
    version = version::CLIENT_VERSION,
    about = "ethlambda consensus client",
    // `--version` used to sit on the node options, so it was accepted after
    // node flags; `ethereum/hive` builds its image that way. Propagating it to
    // the sub-commands keeps those invocations working.
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// What the command line asked the binary to do.
///
/// The variants are lopsided — the node options are far larger than the
/// benchmark's — but exactly one is built per process and consumed immediately
/// by `main`, so the imbalance costs nothing worth a `Box` at every use site.
#[derive(Debug, clap::Subcommand)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Command {
    /// Run the consensus node (default when no sub-command is given).
    ///
    /// `ethlambda --genesis ...` and `ethlambda node --genesis ...` are the
    /// same invocation.
    //
    // Deliberately not part of the doc comment above, which clap renders as
    // this sub-command's `long_about`: `display_name` keeps `--version`
    // printing `ethlambda <version>` after node flags, as it did when the node
    // flags were the whole command line. It is still listed and invoked as
    // `node`.
    #[command(display_name = "ethlambda")]
    Node(NodeOptions),
    /// Benchmark block building offline against a controlled workload.
    Benchmark(BenchmarkOptions),
}

/// Parse the process arguments, exiting the way clap does on a parse error,
/// `--help` or `--version`.
pub(crate) fn parse() -> Command {
    try_parse_from(std::env::args_os()).unwrap_or_else(|err| err.exit())
}

pub(crate) fn try_parse_from<I>(args: I) -> Result<Command, clap::Error>
where
    I: IntoIterator,
    I::Item: Into<OsString>,
{
    let mut args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    if let Some(token) = default_subcommand(&args) {
        args.insert(1, token.into());
    }
    Cli::try_parse_from(args).map(|cli| cli.command)
}

/// The sub-command to insert, if the arguments do not name one.
///
/// `NodeOptions` declares no positional arguments, so the first token after
/// the program name is either a flag or a sub-command — a flag *value* never
/// lands there and is never mistaken for one. A leading flag therefore means
/// the flat node form, and gets `node` inserted ahead of it; a bare invocation
/// is left alone so clap prints its own "requires a subcommand" help.
fn default_subcommand(args: &[OsString]) -> Option<&'static str> {
    let first = args.get(1)?.to_str()?;
    (!EXPLICIT.contains(&first)).then_some(NODE)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::error::ErrorKind;

    use super::*;

    /// The flat invocation shape used by the Dockerfile, lean-quickstart, the
    /// hive shim and the devnet skills. It must keep parsing unchanged.
    const FLAT: &[&str] = &[
        "ethlambda",
        "--genesis",
        "config.yaml",
        "--validators",
        "annotated_validators.yaml",
        "--bootnodes",
        "nodes.yaml",
        "--validator-config",
        "validator-config.yaml",
        "--hash-sig-keys-dir",
        "hash-sig-keys/",
        "--node-key",
        "node.key",
        "--node-id",
        "ethlambda_0",
        "--gossipsub-port",
        "9001",
        "--is-aggregator",
    ];

    /// `FLAT` with an explicit `node` sub-command token.
    fn with_node_token() -> Vec<&'static str> {
        let mut args = vec!["ethlambda", NODE];
        args.extend_from_slice(&FLAT[1..]);
        args
    }

    fn node_options(args: &[&str]) -> NodeOptions {
        match try_parse_from(args.iter().map(OsString::from)).expect("invocation parses") {
            Command::Node(options) => options,
            other => panic!("expected a node invocation, got {other:?}"),
        }
    }

    #[test]
    fn flat_invocation_parses_unchanged() {
        let options = node_options(FLAT);
        assert_eq!(options.genesis, PathBuf::from("config.yaml"));
        assert_eq!(options.hash_sig_keys_dir, PathBuf::from("hash-sig-keys/"));
        assert_eq!(options.node_id, "ethlambda_0");
        assert_eq!(options.gossipsub_port, 9001);
        assert!(options.is_aggregator);
    }

    #[test]
    fn node_sub_command_accepts_the_same_flags_as_the_flat_form() {
        let flat = node_options(FLAT);
        let scoped = node_options(&with_node_token());
        // Compared through `Debug`, which the derive prints field by field,
        // because `NodeOptions` derives no `PartialEq` — and deriving one for
        // a test would touch the parser this module deliberately leaves alone.
        assert_eq!(format!("{flat:?}"), format!("{scoped:?}"));
    }

    #[test]
    fn a_flag_value_of_node_is_not_taken_for_the_sub_command() {
        let mut args: Vec<&str> = FLAT.to_vec();
        let value = args
            .iter()
            .position(|arg| *arg == "ethlambda_0")
            .expect("node id value present");
        args[value] = NODE;
        assert_eq!(node_options(&args).node_id, NODE);
    }

    #[test]
    fn a_node_token_after_the_flags_is_still_rejected() {
        // The default is inserted at the front or not at all, so a later token
        // stays the stray positional argument it has always been.
        let mut args: Vec<&str> = FLAT.to_vec();
        args.push(NODE);
        let err = try_parse_from(args.iter().map(OsString::from))
            .expect_err("a trailing token must not be swallowed");
        assert_eq!(err.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn a_second_node_token_is_rejected_by_clap() {
        let mut args = with_node_token();
        args.insert(1, NODE);
        let err = try_parse_from(args.iter().map(OsString::from))
            .expect_err("only one sub-command is accepted");
        assert_eq!(err.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn missing_required_flag_keeps_the_clap_error_in_both_forms() {
        // `--genesis config.yaml` dropped from the front of the flag list.
        let flat: Vec<&str> = std::iter::once("ethlambda")
            .chain(FLAT[3..].iter().copied())
            .collect();
        let mut scoped = vec!["ethlambda", NODE];
        scoped.extend_from_slice(&flat[1..]);

        for args in [flat, scoped] {
            let err = try_parse_from(args.iter().map(OsString::from))
                .expect_err("a missing required flag must error");
            assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
        }
    }

    #[test]
    fn bare_invocation_asks_for_a_sub_command() {
        // Nothing to default: clap prints the top-level help, which lists the
        // sub-commands, rather than a missing-argument list for one of them.
        let err = try_parse_from(["ethlambda"].iter().map(OsString::from))
            .expect_err("an argument-less invocation must not start a node");
        assert_eq!(
            err.kind(),
            ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
        assert_ne!(err.exit_code(), 0, "a bare invocation must not exit 0");
    }

    #[test]
    fn help_and_version_stay_top_level_flags() {
        // `ethereum/hive` builds its ethlambda image by piping
        // `ethlambda --version` into a file, with and without flags in front.
        let mut version_after_flags: Vec<&str> = FLAT.to_vec();
        version_after_flags.push("--version");

        for (args, expected) in [
            (vec!["ethlambda", "--help"], ErrorKind::DisplayHelp),
            (vec!["ethlambda", "--version"], ErrorKind::DisplayVersion),
            (version_after_flags, ErrorKind::DisplayVersion),
        ] {
            let err = try_parse_from(args.iter().map(OsString::from))
                .expect_err("help and version short-circuit parsing");
            assert_eq!(err.kind(), expected);
        }
    }

    #[test]
    fn version_output_is_identical_for_every_form() {
        // `--version` moved from the node options to the top-level command, so
        // pin that it still prints one string: `ethereum/hive` records this
        // output as the client version.
        let mut after_flags: Vec<&str> = FLAT.to_vec();
        after_flags.push("--version");
        let printed: Vec<String> = [
            vec!["ethlambda", "--version"],
            vec!["ethlambda", NODE, "--version"],
            after_flags,
        ]
        .into_iter()
        .map(|args| {
            try_parse_from(args.iter().map(OsString::from))
                .expect_err("--version short-circuits parsing")
                .to_string()
        })
        .collect();
        assert_eq!(printed[0], printed[1]);
        assert_eq!(printed[0], printed[2]);
    }

    #[test]
    fn help_lists_the_sub_commands() {
        // Listed by clap itself, because they are real sub-commands.
        let err = try_parse_from(["ethlambda", "--help"].iter().map(OsString::from))
            .expect_err("--help short-circuits parsing");
        assert!(err.to_string().contains(NODE), "{err}");
    }
}
