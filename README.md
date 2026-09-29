<p align="center">
  <img src="assets/ethlambda_banner.png" alt="ethlambda banner" width="300">
</p>

# ethlambda

Minimalist, fast and modular implementation of the Lean Ethereum client written in Rust.

🌐 Visit our website at [**ethlambda.xyz**](https://ethlambda.xyz) to learn more about the project.

## Getting started

### Prerequisites

- [Rust](https://rust-lang.org/tools/install)
- [Git](https://git-scm.com/install)
- [Docker](https://www.docker.com/get-started)
- [yq](https://github.com/mikefarah/yq#install)

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

### Running the node

The binary follows one of two chains, chosen by a sub-command:

```sh
cargo build --release
./target/release/ethlambda <node|beacon> [flags]
```

[`docs/cli.md`](./docs/cli.md) is the full flag reference for both.

#### `ethlambda node` — the Lean consensus chain

This is what the rest of this README is about, and it is the default: a bare
flag list with no sub-command still runs the node, so existing scripts and
Docker entrypoints keep working unchanged.

It needs a genesis config, a validator registry, a bootnode list and this
node's own keys, all of which a devnet generates for you:

```sh
./target/release/ethlambda node \
  --genesis            config/config.yaml \
  --validators         config/annotated_validators.yaml \
  --bootnodes          config/nodes.yaml \
  --validator-config   config/validator-config.yaml \
  --hash-sig-keys-dir  config/hash-sig-keys \
  --node-key           config/ethlambda_0.key \
  --node-id            ethlambda_0 \
  --data-dir           ./data \
  --is-aggregator
```

`--node-id` picks this node's entry out of `annotated_validators.yaml`, so it
is what decides which validators this process runs.

The easiest way to get those files is `make run-devnet`, which generates them
under `lean-quickstart/local-devnet/genesis/`. See
[Running in a devnet](#running-in-a-devnet) below.

> **Important:** at least one node on the network must run with
> `--is-aggregator`, or attestations are never aggregated into blocks and the
> chain produces blocks but never finalizes.

#### `ethlambda beacon` — the Ethereum Beacon Chain

A beacon chain follower. It anchors at a finalized checkpoint fetched from a
Beacon API, then follows the chain to its tip: blocks arriving over gossip and
range sync are imported through fork choice, and it custodies its slice of the
fulu data column matrix. What it stores it serves back, to peers over
`beacon_blocks_by_{range,root}` and to anyone over the standard Beacon API on
`--api-port`. It has no validator duties: it publishes nothing and subscribes to
no attestation or sync committee subnet.

```sh
./target/release/ethlambda beacon \
  --network             mainnet \
  --checkpoint-sync-url <beacon-api-url> \
  --node-key            ./node-key \
  --data-dir            ./data
```

| Flag | Meaning |
|---|---|
| `--network` | `mainnet` (default), `sepolia`, `hoodi`, or a path to a directory of network files (`config.yaml`, `genesis.ssz`, optionally `bootstrap_nodes.yaml`), the layout `eth-clients` publishes and kurtosis mounts |
| `--checkpoint-sync-url` | Where the anchor comes from. Required on a fresh data directory for a built-in network, since those never start from genesis. A resumable data directory is used before it; a network loaded from a directory anchors at its own `genesis.ssz` when no URL is given |
| `--node-key` | Optional, but worth persisting: the columns this node custodies are a function of its node id, so without a key file it changes identity, and custody set, on every restart |
| `--execution-endpoint`, `--execution-jwt-secret` | Optional Engine API pairing, given together. Without them, blocks import without payload validation |

A built-in network needs nothing else on disk. Its `eth-clients` `config.yaml`
and bootnode list, and the two genesis values the fork digest is computed from,
are compiled into the binary, so deriving the wire parameters touches no
network.

A healthy run logs its anchor, then imports each new block within a couple of
seconds of its slot starting (from a Sepolia run):

```
Beacon checkpoint sync complete slot=11197376 fork=fulu validators=1997 finalized_epoch=349916 anchor_block_slot=11197376
Beacon block decoded slot=11197516 proposer=834 fork="fulu" block_root=c44ad3d8 bytes=92333
Block imported successfully slot=11197516 proposer=834 block_root=c44ad3d8 parent_root=4397e224
Beacon aggregate attestation decoded slot=11197516 aggregator=574 attesters=53 target_epoch=349922 …
```

See [`docs/beacon_wire.md`](./docs/beacon_wire.md) for what goes on the wire,
[`docs/checkpoint_sync.md`](./docs/checkpoint_sync.md) for how the anchor is
chosen and verified, and [`docs/rpc.md`](./docs/rpc.md) for the Beacon API
endpoints.

### Running in a devnet

To run a local devnet with multiple clients using [lean-quickstart](https://github.com/blockblaz/lean-quickstart):

```sh
# This will clone lean-quickstart, build the docker image, and start a local devnet
make run-devnet
```

This generates fresh genesis files and starts all configured clients with metrics enabled.
Press `Ctrl+C` to stop all nodes.

> **Note:** On Linux, QUIC performance benefits from larger UDP receive buffers. If you see warnings about buffer sizes, increase the kernel limit:
> ```sh
> sudo sysctl -w net.core.rmem_max=7340032
> sudo sysctl -w net.core.wmem_max=7340032
> ```
> To persist across reboots, add to `/etc/sysctl.conf`. For Docker, pass `--sysctl net.core.rmem_max=7340032 --sysctl net.core.wmem_max=7340032`.

For custom devnet configurations, go to `lean-quickstart/local-devnet/genesis/validator-config.yaml` and edit the file before running the command above. See `lean-quickstart`'s documentation for more details on how to configure the devnet.

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

## 📖 Documentation

Full documentation is available in the [`docs/`](./docs) directory. Please refer to it for setup, usage, and development details. For better viewing, we have it hosted in [docs.ethlambda.xyz](https://docs.ethlambda.xyz).

## Current status

The client implements the core features of a Lean Ethereum consensus client:

- **Networking** — libp2p peer connections, STATUS message handling, gossipsub for blocks and attestations
- **State management** — genesis state generation, state transition function, block processing
- **Fork choice** — 3SF-mini fork choice rule implementation with attestation-based head selection
- **Validator duties** — attestation production and broadcasting, block building

Additional features:

- [leanMetrics](docs/metrics.md) support for monitoring and observability
- [lean-quickstart](https://github.com/blockblaz/lean-quickstart) integration for easier devnet running

### Container Releases

Docker images are published to `ghcr.io/lambdaclass/ethlambda` with the following tags:

| Tag | Description |
|-----|-------------|
| `devnetX` | Stable image for a specific devnet (e.g. `devnet4`) |
| `latest` | Alias for the latest stable image of the currently running devnet |
| `unstable` | Built from the latest main commit; promoted to `devnetX`/`latest` once tested |
| `sha-XXXXXXX` | Specific commit |

[`RELEASE.md`](./RELEASE.md) has more details on our release process and how to tag new images.

### pq-devnet-5

We are running the `pq-devnet-5` spec. A Docker tag `devnet5` is available for this version.

### pq-devnet-6

`pq-devnet-6` is in a planning phase; no features have been specified yet. Likely candidates are replacing [LMD-GHOST](docs/lmd_ghost.md) and [3SF-mini](docs/3sf_mini.md), or [execution layer integration](https://github.com/lambdaclass/ethlambda/pull/367).

### Older devnets

Docker tags for each devnet are released, with format `devnetX` (i.e. `devnet1`, `devnet2`, `devnet3`, `devnet4`).

Support for older devnet releases is discontinued when the next devnet version is released.

## Incoming features / Roadmap

We wrote a [blogpost](https://blog.lambdaclass.com/ethlambda-devnet-5-and-beyond/) about what we think should be included in the near future.

Some features we are looking to implement in the near future, in order of priority:

- [Optimize block building](https://github.com/lambdaclass/ethlambda/issues/465)
- [Use state-diffs for storing states in the database](https://github.com/lambdaclass/ethlambda/issues/238)
- [Prototype Goldfish + RLMD GHOST + BFT — devnet-6](https://github.com/lambdaclass/ethlambda/pull/434)
- [Integrate with execution clients](https://github.com/lambdaclass/ethlambda/pull/367), in particular [ethrex](https://github.com/lambdaclass/ethrex) — devnet-7
- Replace libp2p with the experimental [ethp2p](https://github.com/ethp2p/ethp2p), which we are porting to Rust
- [Add a guest program and ZK proving of the STF](https://github.com/lambdaclass/ethlambda/issues/156)
- Rewrite the STF in the concrete programming language to enable formal verification

### Experimental features

We have a proof-of-concept formalization of a part of the state transition function in Lean4 in PR [#269](https://github.com/lambdaclass/ethlambda/pull/269).

## Community

- **Telegram**: [ethlambda group](https://t.me/ethlambda_client), where we post daily updates; drop by to ask questions or chat about anything Lean-related.
- **X (Twitter)**: [@ethlambda_lean](https://twitter.com/ethlambda_lean) for occasional updates.
- **Weekly community call**: every Friday, streamed live on [@class_lambda](https://x.com/class_lambda); the call link is posted on Telegram beforehand.
- **Ecosystem coordination**: the [PQ Interop calls](https://github.com/ethereum/pm/issues?q=is%3Aissue+%22PQ+Interop%22+in%3Atitle) on `ethereum/pm` cover cross-client Lean Ethereum work and related updates; the meeting links are posted on each issue.

## Security

We take security seriously. If you discover a vulnerability in this project, please report it responsibly.

- You can report vulnerabilities directly via the **[GitHub "Report a Vulnerability" feature](../../security/advisories/new)**.
- Alternatively, send an email to **[security@lambdaclass.com](mailto:security@lambdaclass.com)**.

For more details, please refer to our [Security Policy](./.github/SECURITY.md).

## Contributing

We welcome contributions! Please read our [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines on how to get involved.
