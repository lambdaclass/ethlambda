//! Sub-command handling.
//!
//! `node` is the default sub-command: it can be named explicitly
//! (`ethlambda node --genesis ...`) or left out entirely
//! (`ethlambda --genesis ...`). Leaving it out is what the Dockerfile,
//! lean-quickstart, the hive shim and the devnet skills all do, so that form
//! stays the one this module is careful about: the token is simply removed
//! before parsing, and the very same [`CliOptions`] parser then sees the very
//! same arguments it saw before this module existed. Its error messages, exit
//! codes and `--version` output are therefore unchanged by construction rather
//! than by test; only `--help` differs, by the [`HELP_NOTE`] it appends.
//!
//! `benchmark` parses through [`BenchmarkCommand`] instead, so the harness
//! arguments stay out of `CliOptions` entirely: nothing the benchmark needs can
//! reshape the parser the node depends on.

use std::ffi::OsString;

use clap::Parser;

use crate::benchmark::BenchmarkOptions;
use crate::cli::CliOptions;

/// The sub-command tokens accepted in first position.
///
/// `CliOptions` declares no positional arguments, so the first token after the
/// program name is either a flag or one of these: a flag *value* never lands
/// there and is never mistaken for a sub-command.
const NODE: &str = "node";
const BENCHMARK: &str = "benchmark";

/// Appended to `--help` by `CliOptions`. The tokens never reach clap, so
/// without this the sub-commands would be undiscoverable from the help output.
pub(crate) const HELP_NOTE: &str = "Sub-commands:\n  \
     node       Run the consensus node (assumed when omitted)\n  \
     benchmark  Benchmark block building offline \
                (see `ethlambda benchmark --help`)";

/// What the command line asked the binary to do.
///
/// `Node` is ~312 bytes against `Benchmark`'s ~80, but exactly one of these is
/// built per process and consumed immediately by `main`, so boxing would buy an
/// allocation and nothing else.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Invocation {
    /// Run the consensus node.
    Node(CliOptions),
    /// Run the offline block-building benchmark.
    Benchmark(BenchmarkOptions),
}

/// The `benchmark` sub-command, parsed on its own so that its arguments never
/// enter `CliOptions`.
#[derive(Debug, clap::Parser)]
#[command(about = "Benchmark block building offline against a controlled workload")]
struct BenchmarkCommand {
    #[command(flatten)]
    options: BenchmarkOptions,
}

/// Parse the process arguments, exiting the way clap does on a parse error,
/// `--help` or `--version`.
pub(crate) fn parse() -> Invocation {
    try_parse_from(std::env::args_os()).unwrap_or_else(|err| err.exit())
}

fn try_parse_from<I>(args: I) -> Result<Invocation, clap::Error>
where
    I: IntoIterator,
    I::Item: Into<OsString>,
{
    let mut args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    match args.get(1).and_then(|arg| arg.to_str()) {
        Some(NODE) => {
            args.remove(1);
            CliOptions::try_parse_from(args).map(Invocation::Node)
        }
        Some(BENCHMARK) => {
            // clap renders usage from argv[0], so the two tokens collapse into
            // one program name and its usage lines read `ethlambda benchmark
            // <COMMAND>` rather than dropping the sub-command they belong to.
            args.drain(..2);
            let argv = std::iter::once(OsString::from("ethlambda benchmark")).chain(args);
            BenchmarkCommand::try_parse_from(argv).map(|cmd| Invocation::Benchmark(cmd.options))
        }
        // No sub-command named: the flat node form, byte for byte as before.
        _ => CliOptions::try_parse_from(args).map(Invocation::Node),
    }
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

    fn node_options(args: &[&str]) -> CliOptions {
        let invocation =
            try_parse_from(args.iter().map(OsString::from)).expect("invocation parses");
        match invocation {
            Invocation::Node(options) => options,
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
        // because `CliOptions` derives no `PartialEq` — and deriving one for a
        // test would touch the parser this module deliberately leaves alone.
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
        // Only a leading token is a sub-command; anywhere else it stays the
        // stray positional argument it has always been.
        let mut args: Vec<&str> = FLAT.to_vec();
        args.push(NODE);
        let err = try_parse_from(args.iter().map(OsString::from))
            .expect_err("a trailing token must not be swallowed");
        assert_eq!(err.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn only_the_leading_node_token_is_stripped() {
        // `ethlambda node node --genesis ...`: the second token is left for
        // clap, which rejects it like any other stray positional.
        let mut args = with_node_token();
        args.insert(1, NODE);
        let err = try_parse_from(args.iter().map(OsString::from))
            .expect_err("only one leading token is a sub-command");
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
    fn bare_invocation_still_errors_on_the_required_flags() {
        for args in [vec!["ethlambda"], vec!["ethlambda", NODE]] {
            let err = try_parse_from(args.iter().map(OsString::from))
                .expect_err("an argument-less invocation must not start a node");
            assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
        }
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
    fn help_documents_the_sub_commands() {
        let err = try_parse_from(["ethlambda", "--help"].iter().map(OsString::from))
            .expect_err("--help short-circuits parsing");
        let help = err.to_string();
        assert!(help.contains(NODE), "{help}");
        assert!(help.contains(BENCHMARK), "{help}");
    }

    #[test]
    fn benchmark_parses_without_any_node_argument() {
        // The point of parsing the harness separately: none of --genesis,
        // --validators, --node-key … is required, or even accepted, here.
        let args = ["ethlambda", BENCHMARK, "synthetic", "--num-validators", "4"];
        let invocation = try_parse_from(args.iter().map(OsString::from)).expect("benchmark parses");
        let Invocation::Benchmark(options) = invocation else {
            panic!("expected a benchmark invocation, got {invocation:?}");
        };
        assert!(
            format!("{options:?}").contains("num_validators: 4"),
            "{options:?}"
        );
    }

    #[test]
    fn benchmark_rejects_node_arguments() {
        let args = [
            "ethlambda",
            BENCHMARK,
            "synthetic",
            "--genesis",
            "config.yaml",
        ];
        let err = try_parse_from(args.iter().map(OsString::from))
            .expect_err("node flags are not benchmark flags");
        assert_eq!(err.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn benchmark_usage_names_the_sub_command() {
        // The token never reaches clap, so without `name` the usage line would
        // read `ethlambda synthetic …` and mislead.
        let err = try_parse_from(
            ["ethlambda", BENCHMARK, "--help"]
                .iter()
                .map(OsString::from),
        )
        .expect_err("--help short-circuits parsing");
        assert!(err.to_string().contains("ethlambda benchmark"), "{err}");
    }
}
