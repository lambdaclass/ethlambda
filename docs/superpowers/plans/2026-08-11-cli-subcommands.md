# CLI Subcommands Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split the `ethlambda` binary into `lean` and `beacon` subcommands with `lean` as the default, so `ethlambda beacon` has somewhere to live and every existing bare-flag caller keeps working untouched.

**Architecture:** Three moves, each green on its own. First the flags shared by both chains come out of today's `CliOptions` into a flattened `CommonOptions`, and `main`'s body becomes `run_lean`. Then a `Cli` wrapper with a `Command` enum lands, plus `inject_default_subcommand`, a pure argv rewriter that inserts `lean` when the first argument is not a subcommand or a top-level help/version flag: clap has no native default subcommand, and argv preprocessing keeps `--help` free of the duplicated argument groups that `args_conflicts_with_subcommands` produces. Finally `beacon` gets its own discovery defaults. `ethlambda beacon` parses, logs its resolved configuration, and exits with an error until plans 4 and 5 give it a chain to follow.

**Tech Stack:** Rust 1.97.1 (edition 2024), clap 4.6 with the `derive` feature, `eyre`, `tracing`.

---

## Plan series

This is plan 2 of 5 for sub-projects A1 and A2 of
`docs/superpowers/specs/2026-08-10-mainnet-network-design.md`. Each plan ends
with a working, testable tree.

| # | Plan | Ends when |
|---|---|---|
| 1 | Beacon type unification | Types live in `ethlambda-types`, `BeaconState::Lean` exists, every fixture suite green |
| 2 | **CLI subcommands** (this plan) | `ethlambda lean` and `ethlambda beacon` parse, bare flags still resolve to `lean`, devnet unchanged |
| 3 | Beacon handlers on the DB-backed `Store`, and the `BlockChainServer` variant dispatch (spec §4, §5) | `fork_choice::Store` deleted, all 150 `fork_choice` fixture cases green against `ethlambda_storage::Store` |
| 4 | Mainnet wire | Node peers with mainnet, decodes a `beacon_block` within ~30s |
| 5 | Anchor and follow | Checkpoint sync, anchor-to-head range fetch, head tracks wall clock |

Plan 1 is complete (commits `0386c82` through `c4f0ea2`, plus `ba3b35b` and
`1b911cb`). This plan touches no beacon type, so it is independent of plan 3;
plans 4 and 5 fill in `run_beacon`.

**Gates for every task in this plan**, all green on `feat/mainnet-network` at
`1b911cb`:

| Command | Expected |
|---|---|
| `make fmt` | no diff |
| `make lint` | no warnings |
| `make test` | PASS |
| `make test-beacon` | PASS, mainnet 5705 cases / 152 ignored, minimal 40009 / 3692 |

Do **not** substitute the scoped `--exclude ethlambda-p2p` variants that plan 1's
tasks used. They were a workaround for a broken ethrex path dependency, fixed in
`ba3b35b`, and they no longer test what they claim to.

`make test-beacon` is listed because it is a repository gate, not because this
plan can move it: nothing here touches `crates/beacon` or `crates/common/types`.
Run it once, in Task 5.

---

## The invocation sites this plan must not break

`lean` is the default subcommand because of this list. Every one of these passes
bare flags with no subcommand, and none of them is edited by this plan:

| Site | Shape |
|---|---|
| `Dockerfile:83` | `ENTRYPOINT ["/usr/local/bin/ethlambda"]`, flags appended by whoever runs the image |
| `lean-quickstart/client-cmds/ethlambda-cmd.sh` | `docker run ... ghcr.io/lambdaclass/ethlambda:<tag> --genesis ...`; cloned by `make lean-quickstart` and rewritten by `make run-devnet`'s `sed`. Lives in the external `blockblaz/lean-quickstart` repo |
| Hive lean client shim | `ethereum/hive` at `master`; boots the image with bare flags plus `HIVE_LEAN_TEST_DRIVER` |
| `preview-config.nix:92-105` | systemd `ExecStart` = `${appDir}/target/release/ethlambda --genesis ... --node-id ...` |
| `.claude/skills/devnet-runner/references/long-lived-devnet.md:53-100,157-170` | five `docker run` blocks passing bare flags |
| `docs/checkpoint_sync.md:14-23` | documented `ethlambda --checkpoint-sync-url ... --genesis ...` |
| `docs/fork_choice_visualization.md:30-40` | documented `cargo run --release -- --genesis ...` |
| `shadow/` fuzzer runs | the Shadow binary is the same `--bin ethlambda`, driven through the image entrypoint by `kamilsa/lean-shadow-fuzzer` |

`HIVE_LEAN_TEST_DRIVER` deserves its own note. It is read *after* parsing, in
`main.rs:121`, before any file is opened, and the shim already has to pass
today's seven required flags or clap would reject the invocation before the
environment variable is ever consulted. Injection therefore resolves the shim to
`lean` and the check keeps its position inside `run_lean`. Task 2 Step 8 pins
that ordering.

---

## Flag placement: one stated decision per flag

The spec's §10 table puts `--node-id` and `--bootnodes` in the common group.
**The code disagrees with the spec on both**, and this plan follows the code:

| Flag | Placement | Why |
|---|---|---|
| `--node-key`, `--data-dir`, `--gossipsub-port`, `--http-address`, `--api-port`, `--metrics-port` | `CommonOptions`, flattened into both subcommands | Same meaning, same requiredness, same defaults on both chains |
| `--node-id` | `lean` only | **Deviates from the spec table.** `main.rs:195` is the only reader: it indexes `annotated_validators.yaml` to find this node's validator keys. A mainnet follower has no such file and no validators, and the flag is required, so putting it in the common group would force an invented value on every `ethlambda beacon` invocation |
| `--bootnodes` | Declared per subcommand | **Deviates from the spec table.** Required `PathBuf` on `lean`; `Option<PathBuf>` on `beacon`, which has a built-in mainnet ENR list (spec §7). One flattened struct cannot be required in one subcommand and optional in the other |
| `--checkpoint-sync-url` | Declared per subcommand | Spec §10: an optional fallback on `lean`, the mandatory anchor source on `beacon` |
| `--discovery.*` | Declared per subcommand | Spec §10's defaults differ (`enable` forced true on `beacon`, `port` derived from `--gossipsub-port`), and a clap default belongs to the declaration |
| every other `lean` flag | `lean` only | Unchanged from today |

The rule behind the deviations is the spec's own, stated one paragraph below its
table: a flag whose meaning or requiredness differs between the two chains is
declared twice rather than made `Option<T>` and validated by hand.

---

## File structure

| File | Responsibility |
|---|---|
| `bin/ethlambda/src/cli.rs` | **Modify.** `Cli` + `Command`, `CommonOptions`, `LeanOptions` (today's `CliOptions`), `BeaconOptions`, `BeaconDiscoveryConfig`, and `inject_default_subcommand` with its tests |
| `bin/ethlambda/src/main.rs` | **Modify.** `main` shrinks to tracing setup plus a two-arm dispatch; today's body becomes `run_lean`; `run_beacon` is added |
| `docs/cli.md` | **Create.** The subcommand contract: what each one takes, and why a bare invocation is `lean` |
| `docs/SUMMARY.md` | **Modify.** One entry for `docs/cli.md` under Operations |

Nothing else changes. `Dockerfile`, `preview-config.nix`, the devnet-runner
skill, `docs/checkpoint_sync.md`, and `docs/fork_choice_visualization.md` all
keep working *because* they are untouched, which is the point of the default
subcommand.

---

## Task 1: Split the common flags out and extract `run_lean`

**Files:**
- Modify: `bin/ethlambda/src/cli.rs:8-166`
- Modify: `bin/ethlambda/src/main.rs:35,83-399`
- Test: `bin/ethlambda/src/cli.rs` (the existing `mod tests`)

No subcommands yet. This task does all the field-path churn, so Task 2's move of
`main`'s body is a pure cut and paste with zero edits inside it.

- [ ] **Step 1: Point the existing tests at the new names**

The seven tests in `cli.rs`'s `mod tests` are the gate for this refactor: they
already cover every discovery flag and the port-collision check.

```bash
sed -i '' 's/CliOptions::parse_from/LeanOptions::parse_from/g; s/opts\.gossipsub_port/opts.common.gossipsub_port/g' bin/ethlambda/src/cli.rs
```

That rewrites 7 `parse_from` call sites and the 2 `opts.gossipsub_port` reads in
`discovery_port_may_equal_gossipsub_port_until_validated` and
`colliding_ports_are_fine_while_discovery_is_off`. It deliberately does not
touch `self.gossipsub_port` inside `validate_discovery`; Step 3 handles that.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ethlambda --bin ethlambda --profile release-fast cli::tests`
Expected: FAIL to compile, `error[E0433]: failed to resolve: use of undeclared type 'LeanOptions'`.

- [ ] **Step 3: Extract `CommonOptions` and rename the struct**

In `bin/ethlambda/src/cli.rs`, replace the `#[derive(Debug, clap::Parser)]`
attribute block and the struct header at lines 8-10 with the common struct
followed by the renamed lean struct. Concretely, the file's first struct becomes:

```rust
/// Flags every subcommand takes, with the same meaning and the same
/// requiredness on each.
///
/// `--node-id`, `--bootnodes`, `--checkpoint-sync-url`, and `--discovery.*` are
/// deliberately not here even though the design document groups them as common:
/// each of them is required on one subcommand and optional or absent on the
/// other, and a flattened struct has one requiredness.
#[derive(Debug, clap::Args)]
pub(crate) struct CommonOptions {
    #[arg(long, default_value = "9000")]
    pub(crate) gossipsub_port: u16,
    #[arg(long, default_value = "127.0.0.1")]
    pub(crate) http_address: IpAddr,
    #[arg(long, default_value = "5052")]
    pub(crate) api_port: u16,
    #[arg(long, default_value = "5054")]
    pub(crate) metrics_port: u16,
    #[arg(long)]
    pub(crate) node_key: PathBuf,
    /// Directory for RocksDB storage
    #[arg(long, default_value = "./data")]
    pub(crate) data_dir: PathBuf,
}

/// Flags for the lean consensus client.
#[derive(Debug, clap::Parser)]
#[command(name = "ethlambda", author = "LambdaClass", version = version::CLIENT_VERSION, about = "ethlambda consensus client")]
pub(crate) struct LeanOptions {
    #[command(flatten)]
    pub(crate) common: CommonOptions,
```

Then delete these six fields from the body of `LeanOptions`, since they now live
in `CommonOptions`: `gossipsub_port`, `http_address`, `api_port`,
`metrics_port`, `node_key`, `data_dir`. Keep every other field, its doc comment,
and its `#[arg(...)]` attribute exactly as it is, including
`#[command(flatten)] pub(crate) discovery: DiscoveryConfig` and the
`#[cfg(feature = "shadow-integration")]` block.

Finally, in `impl CliOptions` at line 151, rename the impl and reach through
`common`:

```rust
impl LeanOptions {
    /// Reject a discovery port that collides with the QUIC port.
    ///
    /// Both are UDP. Without this the collision surfaces at bind time as an
    /// opaque `EADDRINUSE` on whichever socket loses the race.
    pub(crate) fn validate_discovery(&self) -> Result<(), String> {
        if self.discovery.enable && self.discovery.port == self.common.gossipsub_port {
            return Err(format!(
                "--discovery.port ({}) must differ from --gossipsub-port ({}): \
                 both bind UDP and cannot share a port",
                self.discovery.port, self.common.gossipsub_port
            ));
        }
        Ok(())
    }
}
```

- [ ] **Step 4: Update `main.rs`'s field paths**

Six edits, all mechanical. In `bin/ethlambda/src/main.rs`:

Line 35, the import:

```rust
use cli::LeanOptions;
```

Lines 96-101, the RPC config:

```rust
    let rpc_config = RpcConfig {
        http_address: options.common.http_address,
        api_port: options.common.api_port,
        metrics_port: options.common.metrics_port,
        version: version::CLIENT_VERSION,
    };
```

Lines 126-134, the node key and the two ports:

```rust
    let node_p2p_key = read_hex_file_bytes(&options.common.node_key).wrap_err_with(|| {
        format!(
            "failed to load node key from {}",
            options.common.node_key.display()
        )
    })?;
    let p2p_socket = SocketAddr::new(IpAddr::from([0, 0, 0, 0]), options.common.gossipsub_port);
```

Line 141, the log line:

```rust
    info!(node_key=?options.common.node_key, "got node key");
```

Lines 198-199, the data directory:

```rust
    let data_dir = std::path::absolute(&options.common.data_dir)
        .unwrap_or_else(|_| options.common.data_dir.clone());
```

`options.discovery.enable`, `options.discovery.port`, and
`options.discovery.advertise_ip` are unchanged: `discovery` stays on
`LeanOptions`.

- [ ] **Step 5: Extract `run_lean`**

Still in `bin/ethlambda/src/main.rs`. Cut everything from line 83
(`let options = CliOptions::parse();`) through the `Ok(())` that closes `main` at
line 398, drop the `let options = ...` line itself, and paste the remainder into
a new function placed immediately after `main`. `main` then ends like this:

```rust
    tracing::subscriber::set_global_default(subscriber)
        .wrap_err("failed to set global tracing subscriber")?;

    run_lean(LeanOptions::parse()).await
}

/// Boot the lean consensus client.
///
/// Everything `main` did after parsing, moved verbatim, so that the subcommand
/// dispatch added next has a single function to call and the lean startup order
/// is provably unchanged.
async fn run_lean(options: LeanOptions) -> eyre::Result<()> {
    options
        .validate_discovery()
        .map_err(|err| eyre::eyre!(err))?;

    #[cfg(feature = "shadow-integration")]
    init_shadow_cost(&options.shadow);
```

Nothing inside the moved block changes: Step 4 already rewrote every field path.
The moved block still ends with `Ok(())`, which is now `run_lean`'s.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p ethlambda --bin ethlambda --profile release-fast cli::tests`
Expected: PASS, `test result: ok. 7 passed; 0 failed`.

- [ ] **Step 7: Verify the binary still parses a real invocation**

Run:

```bash
cargo run --profile release-fast --bin ethlambda -- --help
```

Expected: the usage block lists `--genesis`, `--node-key`, `--gossipsub-port`,
and `--data-dir` together, with no subcommand section. The flag set is identical
to before the split; only its declaration moved.

- [ ] **Step 8: Run the gates**

Run: `make fmt`
Expected: no diff.

Run: `make lint`
Expected: PASS with no warnings.

Run: `make test`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add bin/ethlambda/src/cli.rs bin/ethlambda/src/main.rs
git commit -S -m "refactor(cli): split the shared flags out and extract run_lean

The flags both chains take move into a flattened CommonOptions, and main's
body becomes run_lean. Doing the field-path churn here means the subcommand
dispatch added next moves the lean startup path without editing a line of
it, so 'ethlambda lean' is the same code path a bare invocation runs today."
```

---

## Task 2: Add the `lean` and `beacon` subcommands, with `lean` as the default

**Files:**
- Modify: `bin/ethlambda/src/cli.rs`
- Modify: `bin/ethlambda/src/main.rs`
- Test: `bin/ethlambda/src/cli.rs` (`mod tests`)

The types, the argv injector, and `main`'s dispatch land together. They have to:
a new item that nothing calls is a `dead_code` warning, and `make lint` runs
`cargo clippy --workspace --all-targets -- -D warnings`.

- [ ] **Step 1: Replace the test helpers**

`LeanOptions` stops deriving `Parser` in Step 5, so `LeanOptions::parse_from`
disappears. Replace the top of `mod tests` in `bin/ethlambda/src/cli.rs` (the
`use` lines and `base_args`) with:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// The smallest argv that satisfies every required `lean` flag, with no
    /// subcommand: exactly the shape every existing caller uses.
    fn base_args() -> Vec<&'static str> {
        vec![
            "ethlambda",
            "--genesis",
            "config.yaml",
            "--validators",
            "validators.yaml",
            "--bootnodes",
            "nodes.yaml",
            "--validator-config",
            "validator-config.yaml",
            "--hash-sig-keys-dir",
            "keys",
            "--node-key",
            "node.key",
            "--node-id",
            "ethlambda_0",
        ]
    }

    /// Parse a bare-flag argv exactly the way `main` does.
    fn parse_lean(args: Vec<&str>) -> LeanOptions {
        match Cli::parse_from(inject_default_subcommand(args)).command {
            Command::Lean(options) => *options,
            Command::Beacon(_) => panic!("bare flags must resolve to the lean subcommand"),
        }
    }

    /// Render an injector result for comparison against a plain string list.
    fn as_strings(args: &[OsString]) -> Vec<&str> {
        args.iter()
            .map(|arg| arg.to_str().expect("test argv is utf-8"))
            .collect()
    }
```

Then change the seven existing tests' parse calls from
`LeanOptions::parse_from(...)` to `parse_lean(...)`:

```bash
sed -i '' 's/LeanOptions::parse_from(\(.*\))/parse_lean(\1)/g' bin/ethlambda/src/cli.rs
```

The seven assertions themselves are unchanged, and they now prove the injection
path as well as the flags.

- [ ] **Step 2: Write the failing injector tests**

Append to `mod tests` in `bin/ethlambda/src/cli.rs`:

```rust
    /// The contract every existing caller depends on: the Docker ENTRYPOINT,
    /// lean-quickstart's ethlambda-cmd.sh, the Hive client shim,
    /// preview-config.nix, and the devnet-runner `docker run` blocks all pass
    /// bare flags with no subcommand.
    #[test]
    fn bare_flags_get_the_lean_subcommand() {
        let args = inject_default_subcommand(["ethlambda", "--genesis", "config.yaml"]);
        assert_eq!(
            as_strings(&args),
            ["ethlambda", "lean", "--genesis", "config.yaml"]
        );
    }

    #[test]
    fn an_explicit_lean_subcommand_is_left_alone() {
        let args = inject_default_subcommand(["ethlambda", "lean", "--genesis", "config.yaml"]);
        assert_eq!(
            as_strings(&args),
            ["ethlambda", "lean", "--genesis", "config.yaml"]
        );
    }

    #[test]
    fn an_explicit_beacon_subcommand_is_left_alone() {
        let args = inject_default_subcommand([
            "ethlambda",
            "beacon",
            "--checkpoint-sync-url",
            "https://checkpointz.example",
        ]);
        assert_eq!(
            as_strings(&args),
            [
                "ethlambda",
                "beacon",
                "--checkpoint-sync-url",
                "https://checkpointz.example"
            ]
        );
    }

    #[test]
    fn the_generated_help_subcommand_is_left_alone() {
        // clap adds a `help` subcommand of its own as soon as subcommands
        // exist. Injecting ahead of it would turn `ethlambda help beacon` into
        // `ethlambda lean help beacon`, which prints the wrong page.
        let args = inject_default_subcommand(["ethlambda", "help", "beacon"]);
        assert_eq!(as_strings(&args), ["ethlambda", "help", "beacon"]);
    }

    #[test]
    fn help_and_version_flags_are_left_alone() {
        // These four belong to the top-level command. `--version` is not
        // propagated to subcommands, so injecting would turn it into an
        // "unexpected argument" error.
        for flag in ["-h", "--help", "-V", "--version"] {
            let args = inject_default_subcommand(["ethlambda", flag]);
            assert_eq!(
                as_strings(&args),
                ["ethlambda", flag],
                "{flag} must reach the top-level command"
            );
        }
    }

    #[test]
    fn an_argv_with_only_the_program_name_is_left_alone() {
        // A bare `ethlambda` then prints clap's subcommand listing, which is
        // the right answer now that there are two chains to choose from.
        // Nothing regresses: today's binary already exits non-zero there,
        // because --genesis and six other flags are required.
        let args = inject_default_subcommand(["ethlambda"]);
        assert_eq!(as_strings(&args), ["ethlambda"]);
    }

    #[test]
    fn an_empty_argv_is_left_alone() {
        // `execve` can hand a process an argv with no program name at all.
        // Indexing instead of checking would panic here.
        let args = inject_default_subcommand(Vec::<&str>::new());
        assert!(args.is_empty());
    }

    #[test]
    fn a_leading_double_dash_gets_the_lean_subcommand() {
        // `--` is not special-cased: it is not a subcommand name, so it takes
        // the default like any other first token. Neither subcommand accepts
        // positional arguments, so this argv is an error either way; the
        // injection only decides which command the error names.
        let args = inject_default_subcommand(["ethlambda", "--", "--genesis"]);
        assert_eq!(
            as_strings(&args),
            ["ethlambda", "lean", "--", "--genesis"]
        );
    }

    #[test]
    fn a_help_flag_after_the_first_argument_is_not_special() {
        // Only the first argument is classified, so this `--help` is lean's.
        let args =
            inject_default_subcommand(["ethlambda", "--genesis", "config.yaml", "--help"]);
        assert_eq!(
            as_strings(&args),
            ["ethlambda", "lean", "--genesis", "config.yaml", "--help"]
        );
    }
```

- [ ] **Step 3: Write the failing subcommand parse tests**

Append to the same `mod tests`:

```rust
    #[test]
    fn bare_flags_parse_as_the_lean_subcommand() {
        let options = parse_lean(base_args());
        assert_eq!(options.genesis, PathBuf::from("config.yaml"));
        assert_eq!(options.node_id, "ethlambda_0");
        assert_eq!(options.common.api_port, 5052);
    }

    #[test]
    fn an_explicit_lean_subcommand_parses_the_same_flags() {
        let mut args = vec!["ethlambda", "lean"];
        args.extend(base_args().into_iter().skip(1));
        let Command::Lean(options) = Cli::parse_from(args).command else {
            panic!("`lean` must resolve to the lean subcommand");
        };
        assert_eq!(options.genesis, PathBuf::from("config.yaml"));
        assert_eq!(options.node_id, "ethlambda_0");
    }

    #[test]
    fn the_beacon_subcommand_parses() {
        let Command::Beacon(options) = Cli::parse_from([
            "ethlambda",
            "beacon",
            "--node-key",
            "node.key",
            "--checkpoint-sync-url",
            "https://checkpointz.example",
        ])
        .command
        else {
            panic!("`beacon` must resolve to the beacon subcommand");
        };
        assert_eq!(options.checkpoint_sync_url, ["https://checkpointz.example"]);
        assert_eq!(options.common.node_key, PathBuf::from("node.key"));
        // No flag given, so the built-in mainnet ENR list applies.
        assert_eq!(options.bootnodes, None);
    }

    #[test]
    fn beacon_requires_a_checkpoint_sync_url() {
        // The anchor state is the only source of genesis_validators_root, and
        // therefore of the fork digest every topic and the ENR are keyed on.
        let result = Cli::try_parse_from(["ethlambda", "beacon", "--node-key", "node.key"]);
        assert!(
            result.is_err(),
            "--checkpoint-sync-url must be required on beacon"
        );
    }

    #[test]
    fn beacon_requires_a_node_key() {
        let result = Cli::try_parse_from([
            "ethlambda",
            "beacon",
            "--checkpoint-sync-url",
            "https://checkpointz.example",
        ]);
        assert!(
            result.is_err(),
            "--node-key is common and required on both subcommands"
        );
    }

    #[test]
    fn beacon_rejects_lean_only_flags() {
        let result = Cli::try_parse_from([
            "ethlambda",
            "beacon",
            "--node-key",
            "node.key",
            "--checkpoint-sync-url",
            "https://checkpointz.example",
            "--genesis",
            "config.yaml",
        ]);
        assert!(
            result.is_err(),
            "--genesis is a lean flag and must not parse under beacon"
        );
    }

    #[test]
    fn beacon_has_no_discovery_enable_flag() {
        // Mainnet bootnode ENRs carry no `quic` entry, so none of them is
        // statically dialable and a crawl is the only way to find a peer.
        // Discovery is forced on, which means there is nothing to toggle.
        let result = Cli::try_parse_from([
            "ethlambda",
            "beacon",
            "--node-key",
            "node.key",
            "--checkpoint-sync-url",
            "https://checkpointz.example",
            "--discovery.enable",
        ]);
        assert!(
            result.is_err(),
            "beacon must not accept --discovery.enable"
        );
    }

    #[test]
    fn lean_still_requires_its_own_flags() {
        // The subcommand split is what makes this a clap error rather than a
        // hand-written check over Option fields.
        let result = Cli::try_parse_from(["ethlambda", "lean", "--node-key", "node.key"]);
        assert!(
            result.is_err(),
            "lean must still require --genesis and the rest"
        );
    }

    #[test]
    fn the_command_tree_is_well_formed() {
        // clap's own assertions: duplicate argument ids, dangling `requires`
        // targets, defaults that conflict with a value parser. Flattening one
        // struct into two subcommands is exactly the shape that trips them.
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `cargo test -p ethlambda --bin ethlambda --profile release-fast cli::tests`
Expected: FAIL to compile, `error[E0433]: failed to resolve: use of undeclared type 'Cli'`, plus the same for `Command` and `cannot find function 'inject_default_subcommand' in this scope`.

- [ ] **Step 5: Add the subcommand types**

The boxed payloads are safe with this clap: `clap_builder` 4.6.0 implements
`Args`, `FromArgMatches`, and `Subcommand` for `Box<T>` (`src/derive.rs:351-375`),
so the derive forwards through the box.

At the top of `bin/ethlambda/src/cli.rs`, extend the imports:

```rust
use std::ffi::{OsStr, OsString};
use std::net::IpAddr;
use std::path::PathBuf;
```

Insert above `CommonOptions`:

```rust
/// The subcommand a bare invocation resolves to.
const DEFAULT_SUBCOMMAND: &str = "lean";

/// Every first-position token that must reach clap untouched: the two
/// subcommands, clap's generated `help` subcommand, and the top-level help and
/// version flags.
const PASSTHROUGH: [&str; 7] = [
    "lean", "beacon", "help", "-h", "--help", "-V", "--version",
];

#[derive(Debug, clap::Parser)]
#[command(name = "ethlambda", author = "LambdaClass", version = version::CLIENT_VERSION, about = "ethlambda consensus client")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

/// The chain this process follows.
///
/// Both payloads are boxed. `LeanOptions` carries a dozen more fields than
/// `BeaconOptions`, and an unboxed enum is as large as its largest variant
/// everywhere it is moved.
#[derive(Debug, clap::Subcommand)]
pub(crate) enum Command {
    /// Run the lean consensus client. This is the default: an invocation whose
    /// first argument is not a subcommand has `lean` inserted ahead of it, so
    /// every existing bare-flag caller keeps working.
    Lean(Box<LeanOptions>),
    /// Follow the Ethereum Beacon Chain.
    Beacon(Box<BeaconOptions>),
}

/// Insert the default `lean` subcommand when argv does not start with one.
///
/// clap has no native default subcommand, and every existing caller passes bare
/// flags: the Docker `ENTRYPOINT`, `lean-quickstart`'s `ethlambda-cmd.sh`, the
/// Hive client shim, `preview-config.nix`, and the `docker run` blocks in
/// `.claude/skills/devnet-runner/`. Rewriting argv is what keeps all of them
/// working unedited, and it keeps `--help` free of the duplicated argument
/// groups that clap's `args_conflicts_with_subcommands` pattern produces.
///
/// The rule is one line: pass through if the first argument is in
/// [`PASSTHROUGH`], otherwise insert [`DEFAULT_SUBCOMMAND`] ahead of it. `--` is
/// not special-cased, so `ethlambda -- x` becomes `ethlambda lean -- x`; neither
/// subcommand takes positional arguments, so both spellings end in a clap error
/// and the injection only decides which command it names.
///
/// An argv with nothing past the program name is left alone, so a bare
/// `ethlambda` prints the subcommand listing rather than `lean`'s
/// missing-flag error.
pub(crate) fn inject_default_subcommand<I, T>(args: I) -> Vec<OsString>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let mut args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let Some(first) = args.get(1) else {
        return args;
    };
    let passes_through = PASSTHROUGH
        .iter()
        .copied()
        .any(|name| first.as_os_str() == OsStr::new(name));
    if !passes_through {
        args.insert(1, OsString::from(DEFAULT_SUBCOMMAND));
    }
    args
}
```

Change `LeanOptions` from a `Parser` to an `Args`, since `Cli` now owns the
command metadata. Replace its `#[derive(Debug, clap::Parser)]` line and delete
its `#[command(name = "ethlambda", author = ..., version = ..., about = ...)]`
line, which moved to `Cli` above, so the struct opens with:

```rust
/// Flags for the lean consensus client.
#[derive(Debug, clap::Args)]
pub(crate) struct LeanOptions {
```

Add the beacon structs immediately after `LeanOptions`'s `impl` block:

```rust
/// Flags for `ethlambda beacon`, the Ethereum Beacon Chain follower.
#[derive(Debug, clap::Args)]
pub(crate) struct BeaconOptions {
    #[command(flatten)]
    pub(crate) common: CommonOptions,
    /// Base URL(s) of Beacon API servers to take the anchor from, e.g.
    /// `https://checkpointz.example`.
    ///
    /// Required, unlike lean's flag of the same name. The anchor state is the
    /// only source of `genesis_validators_root` and `genesis_time`, and the
    /// fork digest that keys every gossip topic, the ENR `eth2` entry, and
    /// discv5 admission is computed from them. Multiple URLs may be supplied
    /// comma-separated or by repeating the flag; they are tried in order.
    #[arg(long, value_delimiter = ',', required = true)]
    pub(crate) checkpoint_sync_url: Vec<String>,
    /// Path to a bootnode list (ENRs, one per YAML entry) replacing the
    /// built-in mainnet list.
    #[arg(long)]
    pub(crate) bootnodes: Option<PathBuf>,
    #[command(flatten)]
    pub(crate) discovery: BeaconDiscoveryConfig,
}

/// discv5 peer discovery for `ethlambda beacon`.
///
/// There is no `--discovery.enable` here, by design: published mainnet bootnode
/// ENRs carry no `quic` entry, so none of them is statically dialable and a
/// crawl is the only way to reach a peer. Discovery is always on for this
/// subcommand.
#[derive(Debug, clap::Args)]
pub(crate) struct BeaconDiscoveryConfig {
    /// UDP port for the discv5 socket. Defaults to `--gossipsub-port` + 1,
    /// which keeps it off the QUIC port without the operator picking a number.
    #[arg(long = "discovery.port")]
    pub(crate) port: Option<u16>,
    /// IP address to advertise in the ENR.
    ///
    /// Defaults to the bind address, which is the wildcard `0.0.0.0` and is not
    /// dialable as published. discv5's PONG-based IP voting may still replace
    /// it at runtime.
    #[arg(long = "discovery.advertise-ip")]
    pub(crate) advertise_ip: Option<IpAddr>,
}
```

- [ ] **Step 6: Dispatch in `main`**

In `bin/ethlambda/src/main.rs`, widen the import at line 35:

```rust
use cli::{BeaconOptions, Cli, Command, LeanOptions};
```

and replace `run_lean(LeanOptions::parse()).await` at the end of `main` with:

```rust
    let cli = Cli::parse_from(cli::inject_default_subcommand(std::env::args_os()));

    match cli.command {
        Command::Lean(options) => run_lean(*options).await,
        Command::Beacon(options) => run_beacon(*options).await,
    }
}
```

- [ ] **Step 7: Add `run_beacon`**

Immediately after `run_lean` in `bin/ethlambda/src/main.rs`:

```rust
/// Boot the Ethereum Beacon Chain follower.
///
/// The subcommand exists before the chain does: the mainnet wire lands in plan
/// 4 of the series and the anchor and fork choice in plan 5. Until then every
/// parsed flag is logged, so an operator can see the configuration that was
/// resolved, and startup stops rather than running a node that follows nothing.
async fn run_beacon(options: BeaconOptions) -> eyre::Result<()> {
    info!(
        checkpoint_sync_url = ?options.checkpoint_sync_url,
        bootnodes = ?options.bootnodes,
        node_key = ?options.common.node_key,
        data_dir = ?options.common.data_dir,
        gossipsub_port = options.common.gossipsub_port,
        http_address = %options.common.http_address,
        api_port = options.common.api_port,
        metrics_port = options.common.metrics_port,
        discovery_port = ?options.discovery.port,
        advertise_ip = ?options.discovery.advertise_ip,
        "Resolved beacon configuration"
    );
    eyre::bail!(
        "`ethlambda beacon` is not implemented yet: the mainnet wire and the \
         anchor land in plans 4 and 5 of \
         docs/superpowers/specs/2026-08-10-mainnet-network-design.md"
    )
}
```

Every field is read here on purpose. A `pub(crate)` field that nothing reads is
a `dead_code` warning, and `make lint` denies warnings; a derived `Debug` does
not count as a read.

- [ ] **Step 8: Verify the test-driver check kept its position**

`HIVE_LEAN_TEST_DRIVER` has to be consulted before any file is opened, because
the Hive shim provisions none of the paths it passes.

Run:

```bash
grep -n "test_driver_enabled()\|read_hex_file_bytes(&options.common.node_key)" bin/ethlambda/src/main.rs
```

Expected: two matches, and the `test_driver_enabled()` line number is the
smaller of the two.

- [ ] **Step 9: Run the tests to verify they pass**

Run: `cargo test -p ethlambda --bin ethlambda --profile release-fast cli::tests`
Expected: PASS, `test result: ok. 25 passed; 0 failed` (7 kept from Task 1, 9 injector, 9 parse).

- [ ] **Step 10: Check the three shapes by hand**

Run:

```bash
cargo run --profile release-fast --bin ethlambda -- --help
```

Expected: a `Commands:` section listing `lean`, `beacon`, and `help`, and no
`--genesis` in the top-level options.

Run:

```bash
cargo run --profile release-fast --bin ethlambda -- beacon --help
```

Expected: usage `ethlambda beacon [OPTIONS] --checkpoint-sync-url <CHECKPOINT_SYNC_URL> --node-key <NODE_KEY>`, with no `--genesis` and no `--discovery.enable`.

Run:

```bash
cargo run --profile release-fast --bin ethlambda -- --genesis /nonexistent.yaml --validators v.yaml --bootnodes n.yaml --validator-config vc.yaml --hash-sig-keys-dir keys --node-key node.key --node-id ethlambda_0
```

Expected: the run reaches the lean startup path and fails on the missing file,
`failed to read genesis config from /nonexistent.yaml`. A clap parse error here
would mean injection is broken.

- [ ] **Step 11: Run the gates**

Run: `make fmt`
Expected: no diff.

Run: `make lint`
Expected: PASS with no warnings.

Run: `make test`
Expected: PASS.

- [ ] **Step 12: Commit**

```bash
git add bin/ethlambda/src/cli.rs bin/ethlambda/src/main.rs
git commit -S -m "feat(cli): add the lean and beacon subcommands, lean by default

clap has no default subcommand, so main rewrites argv: unless the first
argument is a subcommand or a top-level help/version flag, 'lean' is
inserted ahead of it. That is what keeps the Docker entrypoint, the
lean-quickstart command file, the Hive shim, preview-config.nix and the
devnet-runner docker run blocks working with no edit.

beacon parses and logs its configuration, then stops: the wire and the
anchor land in the next two plans of the mainnet series."
```

---

## Task 3: Beacon discovery defaults

**Files:**
- Modify: `bin/ethlambda/src/cli.rs`
- Modify: `bin/ethlambda/src/main.rs`
- Test: `bin/ethlambda/src/cli.rs` (`mod tests`)

Spec §10: on `beacon`, `--discovery.port` defaults to `--gossipsub-port` + 1.
clap cannot default one flag from another, so the derivation is a method, and it
subsumes the collision check that `validate_discovery` performs for `lean`.

- [ ] **Step 1: Write the failing tests**

Append to `mod tests` in `bin/ethlambda/src/cli.rs`:

```rust
    /// The smallest argv that satisfies every required `beacon` flag.
    fn beacon_args() -> Vec<&'static str> {
        vec![
            "ethlambda",
            "beacon",
            "--node-key",
            "node.key",
            "--checkpoint-sync-url",
            "https://checkpointz.example",
        ]
    }

    fn parse_beacon(args: Vec<&str>) -> BeaconOptions {
        match Cli::parse_from(args).command {
            Command::Beacon(options) => *options,
            Command::Lean(_) => panic!("the beacon argv must resolve to the beacon subcommand"),
        }
    }

    #[test]
    fn the_beacon_discovery_port_defaults_to_one_above_gossipsub() {
        // Both sockets are UDP. Sharing the default would make every
        // out-of-the-box `ethlambda beacon` fail the collision check, since
        // discovery is forced on here.
        let options = parse_beacon(beacon_args());
        assert_eq!(options.common.gossipsub_port, 9000);
        assert_eq!(options.resolve_discovery_port(), Ok(9001));
    }

    #[test]
    fn the_beacon_discovery_port_follows_the_gossipsub_port() {
        let mut args = beacon_args();
        args.extend(["--gossipsub-port", "9500"]);
        assert_eq!(parse_beacon(args).resolve_discovery_port(), Ok(9501));
    }

    #[test]
    fn an_explicit_beacon_discovery_port_wins() {
        let mut args = beacon_args();
        args.extend(["--discovery.port", "9100"]);
        assert_eq!(parse_beacon(args).resolve_discovery_port(), Ok(9100));
    }

    #[test]
    fn a_beacon_discovery_port_equal_to_gossipsub_is_rejected() {
        let mut args = beacon_args();
        args.extend(["--discovery.port", "9000"]);
        assert!(parse_beacon(args).resolve_discovery_port().is_err());
    }

    #[test]
    fn a_gossipsub_port_at_the_top_of_the_range_has_no_derived_default() {
        // 65535 + 1 does not exist, so the operator has to pick a port rather
        // than have the derivation wrap or panic.
        let mut args = beacon_args();
        args.extend(["--gossipsub-port", "65535"]);
        assert!(parse_beacon(args).resolve_discovery_port().is_err());
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ethlambda --bin ethlambda --profile release-fast cli::tests`
Expected: FAIL to compile, `error[E0599]: no method named 'resolve_discovery_port' found for struct 'BeaconOptions'`.

- [ ] **Step 3: Implement the derivation**

Add to `bin/ethlambda/src/cli.rs`, immediately after the `BeaconOptions` struct:

```rust
impl BeaconOptions {
    /// The UDP port the discv5 socket binds.
    ///
    /// `--discovery.port` when given, otherwise `--gossipsub-port` + 1.
    /// Discovery cannot be turned off on this subcommand, so unlike lean's
    /// [`LeanOptions::validate_discovery`] the collision check is
    /// unconditional: both sockets are UDP, and a shared port surfaces at bind
    /// time as an opaque `EADDRINUSE` on whichever one loses the race.
    pub(crate) fn resolve_discovery_port(&self) -> Result<u16, String> {
        let gossipsub_port = self.common.gossipsub_port;
        match self.discovery.port {
            Some(port) if port == gossipsub_port => Err(format!(
                "--discovery.port ({port}) must differ from --gossipsub-port ({gossipsub_port}): \
                 both bind UDP and cannot share a port"
            )),
            Some(port) => Ok(port),
            None => gossipsub_port.checked_add(1).ok_or_else(|| {
                format!(
                    "--gossipsub-port ({gossipsub_port}) leaves no port above it for the discv5 \
                     socket; pass --discovery.port explicitly"
                )
            }),
        }
    }
}
```

- [ ] **Step 4: Resolve the port in `run_beacon`**

In `bin/ethlambda/src/main.rs`, replace `run_beacon`'s body up to and including
the `info!` call with:

```rust
async fn run_beacon(options: BeaconOptions) -> eyre::Result<()> {
    let discovery_port = options
        .resolve_discovery_port()
        .map_err(|err| eyre::eyre!(err))?;
    info!(
        checkpoint_sync_url = ?options.checkpoint_sync_url,
        bootnodes = ?options.bootnodes,
        node_key = ?options.common.node_key,
        data_dir = ?options.common.data_dir,
        gossipsub_port = options.common.gossipsub_port,
        http_address = %options.common.http_address,
        api_port = options.common.api_port,
        metrics_port = options.common.metrics_port,
        discovery_port,
        advertise_ip = ?options.discovery.advertise_ip,
        "Resolved beacon configuration"
    );
```

The `eyre::bail!` below it is unchanged.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p ethlambda --bin ethlambda --profile release-fast cli::tests`
Expected: PASS, `test result: ok. 30 passed; 0 failed` (25 from Task 2, 5 new).

- [ ] **Step 6: Check the resolved value by hand**

Run:

```bash
cargo run --profile release-fast --bin ethlambda -- beacon --node-key node.key --checkpoint-sync-url https://checkpointz.example
```

Expected: one `Resolved beacon configuration` line carrying
`discovery_port=9001`, then the process exits non-zero with
`` `ethlambda beacon` is not implemented yet ``.

Run:

```bash
cargo run --profile release-fast --bin ethlambda -- beacon --node-key node.key --checkpoint-sync-url https://checkpointz.example --discovery.port 9000
```

Expected: exit non-zero with
`--discovery.port (9000) must differ from --gossipsub-port (9000)`, and no
`Resolved beacon configuration` line.

- [ ] **Step 7: Run the gates**

Run: `make fmt`
Expected: no diff.

Run: `make lint`
Expected: PASS with no warnings.

Run: `make test`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add bin/ethlambda/src/cli.rs bin/ethlambda/src/main.rs
git commit -S -m "feat(cli): derive the beacon discv5 port from the gossipsub port

Discovery cannot be turned off on beacon, so the two UDP sockets must not
share the 9000 default: the collision check that lean applies only when
discovery is enabled would otherwise reject every out-of-the-box run.
clap cannot default one flag from another, so the derivation is a method,
and it refuses 65535 rather than wrapping."
```

---

## Task 4: Document the two subcommands

**Files:**
- Create: `docs/cli.md`
- Modify: `docs/SUMMARY.md`

The flags are discoverable through `--help`; the *default subcommand rule* is
not, and neither is the reason `beacon` forces discovery on.

- [ ] **Step 1: Write the page**

Create `docs/cli.md`:

````markdown
# Command line

`ethlambda` follows one of two chains, selected by a subcommand:

| Invocation | Chain |
|---|---|
| `ethlambda lean <flags>` | The lean consensus protocol this repository implements |
| `ethlambda beacon <flags>` | The Ethereum Beacon Chain, as a follower |
| `ethlambda <flags>` | `lean`: the subcommand is injected |

## `lean` is the default

clap has no native default subcommand, so the binary rewrites its own argv
before parsing. If the first argument is not `lean`, `beacon`, `help`, `-h`,
`--help`, `-V`, or `--version`, then `lean` is inserted ahead of it. The
function is `inject_default_subcommand` in `bin/ethlambda/src/cli.rs`.

```
ethlambda --genesis c.yaml ...              ->  ethlambda lean --genesis c.yaml ...
ethlambda lean --genesis c.yaml ...         ->  unchanged
ethlambda beacon --checkpoint-sync-url ...  ->  unchanged
ethlambda --help | --version | -h | -V      ->  unchanged, no injection
```

This is what keeps every existing caller working with no edit: the Docker
`ENTRYPOINT`, `lean-quickstart`'s `client-cmds/ethlambda-cmd.sh`, the Hive lean
client shim, `preview-config.nix`, and the `docker run` blocks in the
devnet-runner skill all pass bare flags.

`ethlambda` with no arguments at all is left alone, so it prints the subcommand
listing rather than a missing-flag error for `lean`.

## Common flags

Taken by both subcommands, with the same meaning and the same defaults.

| Flag | Default | Meaning |
|---|---|---|
| `--node-key` | required | Hex file holding the secp256k1 key that is this node's libp2p and discv5 identity |
| `--data-dir` | `./data` | RocksDB directory |
| `--gossipsub-port` | `9000` | UDP port for libp2p QUIC |
| `--http-address` | `127.0.0.1` | Bind address for both HTTP servers |
| `--api-port` | `5052` | API server port |
| `--metrics-port` | `5054` | Metrics and debug server port. Equal to `--api-port` merges the routers onto one listener |

## `lean` flags

| Flag | Default | Meaning |
|---|---|---|
| `--genesis` | required | Chain genesis config, e.g. `config.yaml` |
| `--validators` | required | Validator registry, e.g. `annotated_validators.yaml` |
| `--bootnodes` | required | YAML list of bootnode ENRs |
| `--validator-config` | required | `validator-config.yaml`, the node-name registry |
| `--hash-sig-keys-dir` | required | Directory of per-validator XMSS keys |
| `--node-id` | required | The key in `annotated_validators.yaml` naming this node, e.g. `ethlambda_0` |
| `--checkpoint-sync-url` | none | Peer API base URLs, used only when there is no resumable state on disk. See [Checkpoint Sync](./checkpoint_sync.md) |
| `--is-aggregator` | `false` | Seed the runtime aggregator flag |
| `--aggregate-subnet-ids` | this node's subnets | Subnets to aggregate on; requires `--is-aggregator` |
| `--attestation-committee-count` | from `validator-config.yaml`, else `1` | Committees per slot |
| `--enable-proposer-aggregation` | `false` | Merge same-data proofs when building a block |
| `--max-attestations-per-block` | `3` | Proposer-side self-limit |
| `--disable-duty-sync-gate` | `false` | Track sync state without suppressing duties |
| `--discovery.enable` | `false` | Enable discv5. See [Peer discovery](./discovery.md) |
| `--discovery.port` | `9000` | discv5 UDP port; must differ from `--gossipsub-port` when discovery is on |
| `--discovery.advertise-ip` | bind address | IP published in the ENR |

A `shadow-integration` build adds the `--shadow-xmss-*` flags; they are absent
from a normal build.

## `beacon` flags

| Flag | Default | Meaning |
|---|---|---|
| `--checkpoint-sync-url` | required | Beacon API base URLs supplying the anchor state |
| `--bootnodes` | built-in mainnet ENRs | Override the built-in list |
| `--discovery.port` | `--gossipsub-port` + 1 | discv5 UDP port |
| `--discovery.advertise-ip` | bind address | IP published in the ENR |

`--checkpoint-sync-url` is required here, unlike on `lean`, because the anchor
state is the only source of `genesis_validators_root` and `genesis_time`, and
the fork digest that keys every gossip topic, the ENR `eth2` entry, and discv5
admission is computed from them.

There is no `--discovery.enable`: published mainnet bootnode ENRs carry no
`quic` entry, so none of them is statically dialable and a discv5 crawl is the
only way to reach a peer. Discovery is always on, which is also why the discv5
port defaults one above the QUIC port instead of colliding with it.

## What `ethlambda beacon` does today

It parses its flags, logs the resolved configuration, and exits with an error.
The mainnet wire, the checkpoint-synced anchor, and the fork choice arrive in
later plans of `docs/superpowers/specs/2026-08-10-mainnet-network-design.md`.
````

- [ ] **Step 2: Add the page to the book**

In `docs/SUMMARY.md`, add the entry as the first item under `# Operations`:

```markdown
# Operations

- [Command line](./cli.md)
- [HTTP API](./rpc.md)
```

- [ ] **Step 3: Build the book**

Run: `make docs`
Expected: `mdbook` finishes with no broken-link errors. If the binary is
missing, run `make docs-deps` first.

- [ ] **Step 4: Commit**

```bash
git add docs/cli.md docs/SUMMARY.md
git commit -S -m "docs: describe the lean and beacon subcommands

--help lists the flags but cannot explain the argv rewrite that makes a
bare invocation mean lean, which is the contract every devnet script,
the Docker entrypoint and the Hive shim rely on."
```

---

## Task 5: Verify the invocation contract end to end

**Files:** none modified. This task only runs things.

- [ ] **Step 1: Run every gate**

Run: `make fmt`
Expected: no diff.

Run: `make lint`
Expected: PASS with no warnings.

Run: `make test`
Expected: PASS.

Run: `make test-beacon`
Expected: PASS for both presets, mainnet 5705 fixture cases / 152 ignored,
minimal 40009 / 3692. Nothing in this plan touches those crates, so a change
here means something unrelated moved.

- [ ] **Step 2: Build the image**

Run: `make docker-build`
Expected: `ghcr.io/lambdaclass/ethlambda:local` built.

- [ ] **Step 3: Check the entrypoint contract**

Run:

```bash
docker run --rm ghcr.io/lambdaclass/ethlambda:local --version
```

Expected: the version string, no injection, exit 0.

Run:

```bash
docker run --rm ghcr.io/lambdaclass/ethlambda:local --help
```

Expected: a `Commands:` section listing `lean` and `beacon`, exit 0.

Run:

```bash
docker run --rm ghcr.io/lambdaclass/ethlambda:local --genesis /nope.yaml --validators /v.yaml --bootnodes /n.yaml --validator-config /vc.yaml --hash-sig-keys-dir /keys --node-key /node.key --node-id ethlambda_0
```

Expected: the ASCII banner, then
`failed to read genesis config from /nope.yaml`. This is the entrypoint contract:
bare flags reached the lean startup path through the image, not a clap error.

Run:

```bash
docker run --rm ghcr.io/lambdaclass/ethlambda:local beacon --node-key /node.key --checkpoint-sync-url https://checkpointz.example
```

Expected: one `Resolved beacon configuration` line with `discovery_port=9001`,
then `` `ethlambda beacon` is not implemented yet ``.

- [ ] **Step 4: Run a devnet with the unmodified scripts**

Run: `make run-devnet`

This clones `lean-quickstart` if needed, rewrites only the image tag in
`client-cmds/ethlambda-cmd.sh`, and starts four nodes with bare flags. Leave it
running for two minutes, then in another shell:

```bash
grep -c "Block imported successfully" devnet.log
```

Expected: a non-zero count that grows between two invocations.

```bash
grep -o "finalized_slot=[0-9]*" devnet.log | tail -1
```

Expected: `finalized_slot=` with a non-zero slot. If it stays at 0, check that
`lean-quickstart/local-devnet/genesis/validator-config.yaml` marks a node
`isAggregator: true`: without an aggregator the chain produces blocks and never
finalizes, which is a devnet configuration issue rather than a regression from
this plan.

Stop the devnet with Ctrl-C.

- [ ] **Step 5: Commit nothing, and record the result**

There is nothing to commit. If any step above failed, fix it under the task that
introduced the behavior rather than patching around it here.

---

## Done when

- [ ] `make fmt` produces no diff
- [ ] `make lint` passes with no warnings
- [ ] `make test` passes
- [ ] `make test-beacon` passes both presets with mainnet 5705/152 and minimal 40009/3692
- [ ] `ethlambda lean <bare lean flags>` and `ethlambda <bare lean flags>` reach the same startup path
- [ ] `ethlambda beacon --node-key k --checkpoint-sync-url u` parses, logs `Resolved beacon configuration` with `discovery_port=9001`, and exits with the not-implemented error
- [ ] `ethlambda --help`, `-h`, `--version`, and `-V` are never rewritten, and `ethlambda help beacon` prints beacon's page
- [ ] `ethlambda` with no arguments prints the subcommand listing
- [ ] `ethlambda beacon --genesis c.yaml` and `ethlambda lean --node-key k` are both clap errors
- [ ] `make docker-build` then a bare-flag `docker run` reaches the lean startup path
- [ ] `make run-devnet` produces blocks and a non-zero `finalized_slot` with no script edited
- [ ] `docs/cli.md` is in the book and `make docs` builds clean

Then start plan 3, the beacon handlers on the DB-backed `Store`.
