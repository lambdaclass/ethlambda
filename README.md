# ethlambda

Minimalist, fast and modular implementation of the Lean Ethereum client written in Rust.

## Getting started

We use `cargo` as our build system. To build and run the client, simply run:

```sh
cargo run
```

Run `make help` or take a look at our [`Makefile`](./Makefile) for other useful commands.

## Running in a devnet

To run a local devnet with multiple clients using [lean-quickstart](https://github.com/blockblaz/lean-quickstart):

```sh
# Clone lean-quickstart (if not already present)
git clone https://github.com/blockblaz/lean-quickstart.git

# Build the ethlambda Docker image
make docker-build

# Run a 3-client devnet (zeam, ream, ethlambda)
cd lean-quickstart
NETWORK_DIR=local-devnet ./spin-node.sh --node zeam_0,ream_0,ethlambda_0 --generateGenesis --metrics
```

This generates fresh genesis files and starts all three clients with metrics enabled.
Press `Ctrl+C` to stop all nodes.

## Philosophy

Many long-established clients accumulate bloat over time. This often occurs due to the need to support legacy features for existing users or through attempts to implement overly ambitious software. The result is often complex, difficult-to-maintain, and error-prone systems.

In contrast, our philosophy is rooted in simplicity. We strive to write minimal code, prioritize clarity, and embrace simplicity in design. We believe this approach is the best way to build a client that is both fast and resilient. By adhering to these principles, we will be able to iterate fast and explore next-generation features early.

Read more about our engineering philosophy [in this post of our blog](https://blog.lambdaclass.com/lambdas-engineering-philosophy/).

## Design Principles

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

If we forgot to include anyone, please file an issue so we can add you. We always strive to reference the inspirations and code we use, but as an organization with multiple people, mistakes can happen, and someone might forget to include a reference.

## Current Status

The client implements the core features of a Lean Ethereum consensus client:

- **Networking** — libp2p peer connections, STATUS message handling, gossipsub for blocks and attestations
- **State management** — genesis state generation, state transition function, block processing
- **Fork choice** — 3SF-mini fork choice rule implementation with attestation-based head selection
- **Validator duties** — attestation production and broadcasting, block building

Additional features:

- [leanMetrics](docs/metrics.md) support for monitoring and observability
- [lean-quickstart](https://github.com/blockblaz/lean-quickstart) integration for easier devnet running

### pq-devnet-1

We support the [pq-devnet-1 spec](https://github.com/leanEthereum/pm/blob/main/breakout-rooms/leanConsensus/pq-interop/pq-devnet-1.md). A dedicated git branch and docker tag `devnet1` are available for this version.

## Incoming features

Some features we are looking to implement in the near future, in order of priority:

- [pq-devnet-2](https://github.com/leanEthereum/pm/blob/main/breakout-rooms/leanConsensus/pq-interop/pq-devnet-2.md) support: signature aggregation with leanMultisig
- Data persistence: DB-backed Store
- Historical syncing from genesis for existing devnets
- Checkpoint sync for long-lived networks
- Observability: more metrics from leanMetrics and better logs
- RPC endpoints for chain data consumption
