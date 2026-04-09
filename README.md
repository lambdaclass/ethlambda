# ethlambda

Minimalist, fast and modular implementation of the Lean Ethereum client written in Rust.

## Getting started

### Prerequisites

**Using [Nix](https://github.com/DeterminateSystems/nix-installer?tab=readme-ov-file#install-determinate-nix) (recommended):**

```sh
nix develop                  # interactive shell (bash)
nix develop -c zsh           # interactive shell (zsh)
nix develop -c cargo build   # run a single command
```

This provides Rust, Lean 4, and all other dependencies. No manual installation needed.

**Manual installation:**

- [Rust](https://rust-lang.org/tools/install)
- [Git](https://git-scm.com/install)
- [Docker](https://www.docker.com/get-started)
- [yq](https://github.com/mikefarah/yq#install)
- [elan](https://github.com/leanprover/elan) (for formal verification / `--features lean-ffi`)

### Building and testing

We use `cargo` as our build system, but prefer `make` as a convenient wrapper for common tasks. These are some common targets:

```sh
# Formats all code
make fmt
# Checks and lints the code
make lint
# Runs all tests
make test
# Builds a docker image tagged as "ghcr.io/lambdaclass/ethlambda:local"
make docker-build DOCKER_TAG=local
```

Run `make help` or take a look at our [`Makefile`](./Makefile) for other useful commands.

### Formal verification

Key consensus functions have been [formally verified in Lean 4](./formal/README.md).
The verified implementations can be compiled into the binary via FFI:

```sh
cargo build --features lean-ffi   # use verified Lean implementation
cargo test --features lean-ffi    # run tests through Lean
```

This requires Lean 4 (provided by `nix develop` or [elan](https://github.com/leanprover/elan)).
Without the feature flag, the native Rust implementation is used.

### Running in a devnet

To run a local devnet with multiple clients using [lean-quickstart](https://github.com/blockblaz/lean-quickstart):

```sh
# This will clone lean-quickstart, build the docker image, and start a local devnet
make run-devnet
```

This generates fresh genesis files and starts all configured clients with metrics enabled.
Press `Ctrl+C` to stop all nodes.

> **Important:** When running nodes manually (outside `make run-devnet`), at least one node must be started with `--is-aggregator` for attestations to be aggregated and included in blocks. Without this flag, the network will produce blocks but never finalize.

For custom devnet configurations, go to `lean-quickstart/local-devnet/genesis/validator-config.yaml` and edit the file before running the command above. See `lean-quickstart`'s documentation for more details on how to configure the devnet.

## Contributing

We welcome contributions! Please read our [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines on how to get involved.

## Philosophy

Many long-established clients accumulate bloat over time. This often occurs due to the need to support legacy features for existing users or through attempts to implement overly ambitious software. The result is often complex, difficult-to-maintain, and error-prone systems.

In contrast, our philosophy is rooted in simplicity. We strive to write minimal code, prioritize clarity, and embrace simplicity in design. We believe this approach is the best way to build a client that is both fast and resilient. By adhering to these principles, we will be able to iterate fast and explore next-generation features early.

Read more about our engineering philosophy [in this post of our blog](https://blog.lambdaclass.com/lambdas-engineering-philosophy/).

## Design principles

- Ensure effortless setup and execution across all target environments.
- Be vertically integrated. Have the minimal amount of dependencies.
- Be structured in a way that makes it easy to build on top of it.
- Have a simple type system. Avoid having generics leaking all over the codebase.
- Have few abstractions. Do not generalize until you absolutely need it. Repeating code two or three times can be fine.
- Prioritize code readability and maintainability over premature optimizations.
- Avoid concurrency split all over the codebase. Concurrency adds complexity. Only use where strictly necessary.

## 📚 References and acknowledgements

The following links, repos, companies and projects have been important in the development of this repo, we have learned a lot from them and want to thank and acknowledge them.

- [Ethereum](https://ethereum.org/en/)
- [LeanEthereum](https://github.com/leanEthereum)
- [Zeam](https://github.com/blockblaz/zeam)
- [Lantern](https://github.com/Pier-Two/lantern)

If we forgot to include anyone, please file an issue so we can add you. We always strive to reference the inspirations and code we use, but as an organization with multiple people, mistakes can happen, and someone might forget to include a reference.

## Current status

The client implements the core features of a Lean Ethereum consensus client:

- **Networking** — libp2p peer connections, STATUS message handling, gossipsub for blocks and attestations
- **State management** — genesis state generation, state transition function, block processing
- **Fork choice** — 3SF-mini fork choice rule implementation with attestation-based head selection
- **Validator duties** — attestation production and broadcasting, block building

Additional features:

- [leanMetrics](docs/metrics.md) support for monitoring and observability
- [lean-quickstart](https://github.com/blockblaz/lean-quickstart) integration for easier devnet running

### pq-devnet-3

We are running the [pq-devnet-3 spec](https://github.com/leanEthereum/pm/blob/main/breakout-rooms/leanConsensus/pq-interop/pq-devnet-3.md). A Docker tag `devnet3` is available for this version.

### pq-devnet-4

We are working on adding support for the [pq-devnet-4 spec](https://github.com/leanEthereum/pm/blob/main/breakout-rooms/leanConsensus/pq-interop/pq-devnet-4.md). A Docker tag `devnet4` will be published for this version.

### Older devnets

Docker tags for each devnet are released, with format `devnetX` (i.e. `devnet1`, `devnet2`, `devnet3`).

Support for older devnet releases is discontinued when the next devnet version is released.

## Incoming features

Some features we are looking to implement in the near future, in order of priority:

- [Add support for pq-devnet-4](https://github.com/lambdaclass/ethlambda/issues/155)
- [RPC endpoints for chain data consumption](https://github.com/lambdaclass/ethlambda/issues/75)
- [Add guest program and ZK proving of the STF](https://github.com/lambdaclass/ethlambda/issues/156)
